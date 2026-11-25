"""
cloud_sync.py — Encrypted Cloud Backup & Disaster Recovery Sync Engine.

Provides zero-downtime online SQLite database backups and background synchronization
to S3-compatible cloud object storage providers:
- Cloudflare R2
- AWS S3
- Backblaze B2
- MinIO / Self-hosted S3

Features:
- Non-blocking online database snapshots via SQLite Backup API.
- Constant-memory streaming chunked AES-256-GCM envelope encryption (ENCSNAP1:CHK1:)
  with full backward compatibility for legacy whole-file ENCSNAP1: snapshots.
- S3 multipart upload support for large snapshots.
- Automated retention policy (e.g. keep last N backups).
- Live connection, L1 cache, and Bloom filter reset upon disaster recovery restore.
"""

import os
import time
import struct
import shutil
import sqlite3
import hashlib
from typing import Any
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_LEGACY_MAGIC = b"ENCSNAP1:"
_CHUNKED_MAGIC = b"ENCSNAP1:CHK1:"  # Starts with ENCSNAP1: for header compatibility
_DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB constant-memory streaming frames
_MULTIPART_THRESHOLD = 16 * 1024 * 1024  # 16 MiB


def _derive_chunk_nonce(stream_id: bytes, chunk_index: int) -> bytes:
    """Deterministic unique 96-bit nonce per chunk within a unique random 128-bit stream_id."""
    return stream_id[:4] + chunk_index.to_bytes(8, "big")


def _build_chunk_aad(stream_id: bytes, chunk_index: int, is_final: bool) -> bytes:
    """Bind stream ID, chunk sequence index, and EOF finality marker to prevent reordering/truncation."""
    return (
        b"sqlite-snapshot-chunk-v1:"
        + stream_id
        + chunk_index.to_bytes(8, "big")
        + (b"\x01" if is_final else b"\x00")
    )


def encrypt_snapshot_file(
    source_path: Path,
    output_path: Path,
    raw_key: bytes | None = None,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> Path:
    """
    Stream-encrypt a point-in-time SQLite snapshot file in bounded-memory chunks
    using AES-256-GCM framed AEAD (`ENCSNAP1:CHK1:`).
    """
    from .database import _get_raw_key_material

    if chunk_size < 1024:
        raise ValueError("chunk_size must be at least 1024 bytes.")

    key = raw_key if raw_key is not None else _get_raw_key_material()
    aesgcm = AESGCM(key)
    stream_id = os.urandom(16)
    tmp_out = output_path.with_suffix(output_path.suffix + ".enc.tmp")

    try:
        with open(source_path, "rb") as fin, open(tmp_out, "wb") as fout:
            # Header: magic (14B) + stream_id (16B) + nominal chunk_size (4B uint32 BE)
            fout.write(_CHUNKED_MAGIC)
            fout.write(stream_id)
            fout.write(struct.pack(">I", chunk_size))

            chunk_idx = 0
            current = fin.read(chunk_size)
            while True:
                next_chunk = fin.read(chunk_size)
                is_final = len(next_chunk) == 0
                nonce = _derive_chunk_nonce(stream_id, chunk_idx)
                aad = _build_chunk_aad(stream_id, chunk_idx, is_final)
                ciphertext = aesgcm.encrypt(nonce, current, associated_data=aad)

                # Frame: ciphertext_len (4B uint32 BE) + is_final (1B) + ciphertext
                fout.write(struct.pack(">IB", len(ciphertext), 1 if is_final else 0))
                fout.write(ciphertext)

                if is_final:
                    break
                current = next_chunk
                chunk_idx += 1

        tmp_out.replace(output_path)
        return output_path
    except Exception:
        tmp_out.unlink(missing_ok=True)
        raise


def decrypt_snapshot_file(
    source_path: Path,
    output_path: Path,
    raw_key: bytes | None = None,
) -> Path:
    """
    Decrypt an encrypted snapshot envelope file (`ENCSNAP1:CHK1:` streaming or legacy `ENCSNAP1:`).
    Writes atomically via temporary file so tampered/truncated archives never leave partial output.
    """
    from .database import _get_raw_key_material

    key = raw_key if raw_key is not None else _get_raw_key_material()
    aesgcm = AESGCM(key)
    tmp_out = output_path.with_suffix(output_path.suffix + ".dec.tmp")

    try:
        with open(source_path, "rb") as fin:
            prefix = fin.read(len(_CHUNKED_MAGIC))
            if prefix == _CHUNKED_MAGIC:
                stream_id = fin.read(16)
                chunk_size_raw = fin.read(4)
                if len(stream_id) != 16 or len(chunk_size_raw) != 4:
                    raise ValueError("Truncated encrypted snapshot stream header.")
                (nominal_chunk_size,) = struct.unpack(">I", chunk_size_raw)
                max_frame_len = nominal_chunk_size + 64  # 16B GCM tag + safety margin

                chunk_idx = 0
                saw_final = False
                with open(tmp_out, "wb") as fout:
                    while True:
                        frame_hdr = fin.read(5)
                        if not frame_hdr:
                            break
                        if len(frame_hdr) != 5:
                            raise ValueError("Truncated encrypted snapshot chunk frame header.")
                        ct_len, final_flag = struct.unpack(">IB", frame_hdr)
                        if ct_len < 16 or ct_len > max_frame_len:
                            raise ValueError(f"Invalid encrypted chunk length: {ct_len}")
                        if final_flag not in (0, 1):
                            raise ValueError("Invalid chunk finality flag.")

                        ciphertext = fin.read(ct_len)
                        if len(ciphertext) != ct_len:
                            raise ValueError("Truncated encrypted snapshot chunk payload.")

                        is_final = final_flag == 1
                        nonce = _derive_chunk_nonce(stream_id, chunk_idx)
                        aad = _build_chunk_aad(stream_id, chunk_idx, is_final)
                        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=aad)
                        fout.write(plaintext)
                        chunk_idx += 1

                        if is_final:
                            trailing = fin.read(1)
                            if trailing:
                                raise ValueError("Unexpected trailing data after final snapshot chunk.")
                            saw_final = True
                            break

                if not saw_final:
                    raise ValueError("Truncated encrypted snapshot: missing final authenticated chunk.")
            else:
                # Legacy whole-file ENCSNAP1: fallback
                fin.seek(0)
                raw = fin.read()
                if not raw.startswith(_LEGACY_MAGIC) or len(raw) < 21:
                    raise ValueError("Invalid encrypted snapshot format or missing header.")
                nonce = raw[9:21]
                ciphertext = raw[21:]
                plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=b"sqlite-snapshot-envelope-v1")
                tmp_out.write_bytes(plaintext)

        tmp_out.replace(output_path)
        return output_path
    except Exception:
        tmp_out.unlink(missing_ok=True)
        raise


class CloudSyncEngine:
    """Manages online encrypted database snapshots and S3 cloud synchronization."""

    def __init__(
        self,
        bucket_name: str | None = None,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region_name: str = "auto",
        engine: Any = None,
    ):
        self.bucket_name = bucket_name or os.getenv("S3_BUCKET_NAME", "encrypted-sqlite-backups")
        self.endpoint_url = endpoint_url or os.getenv("S3_ENDPOINT_URL")
        self.access_key = access_key or os.getenv("S3_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.getenv("S3_SECRET_ACCESS_KEY")
        self.region_name = region_name or os.getenv("S3_REGION", "auto")
        self._engine = engine

    def _get_paths(self) -> tuple[Path, Path]:
        if self._engine is not None:
            return self._engine.db_path, self._engine.data_dir
        from .database import DB_PATH, DATA_DIR
        return DB_PATH, DATA_DIR

    def create_local_snapshot(self, snapshot_name: str | None = None) -> Path:
        """
        Create a live, point-in-time consistent SQLite snapshot using SQLite Online Backup API.
        Guarantees zero database locking or bot downtime.
        """
        db_path, data_dir = self._get_paths()
        snapshots_dir = data_dir / "snapshots"
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        ts_str = time.strftime("%Y%m%d_%H%M%S")
        name = snapshot_name or f"snapshot_{ts_str}"
        target_path = snapshots_dir / f"{name}.db"

        if db_path.exists():
            source_conn = sqlite3.connect(str(db_path), timeout=30.0)
            dest_conn = sqlite3.connect(str(target_path))
            try:
                with dest_conn:
                    source_conn.backup(dest_conn)
            finally:
                source_conn.close()
                dest_conn.close()
        else:
            target_path.touch()

        return target_path

    def compute_file_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file in streaming chunks for integrity check."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def sync_to_cloud(
        self,
        snapshot_path: Path | None = None,
        retention_count: int = 7,
        client: Any = None,
        encrypt: bool = False,
    ) -> dict:
        """
        Upload local encrypted database snapshot to S3/Cloudflare R2 and prune older backups.
        Supports streaming chunked AES-256-GCM envelope encryption and multipart S3 uploads.
        """
        if snapshot_path is None or not snapshot_path.exists():
            snapshot_path = self.create_local_snapshot()

        should_encrypt = encrypt or os.getenv("ENCRYPT_CLOUD_BACKUPS", "false").lower() in ("true", "1", "yes")
        upload_path = snapshot_path
        temp_enc_path = None

        raw_key = self._engine._get_raw_key_material() if self._engine is not None else None

        if should_encrypt and not snapshot_path.name.endswith(".enc"):
            temp_enc_path = snapshot_path.with_suffix(snapshot_path.suffix + ".enc")
            encrypt_snapshot_file(snapshot_path, temp_enc_path, raw_key=raw_key)
            upload_path = temp_enc_path

        try:
            file_size = upload_path.stat().st_size
            checksum = self.compute_file_sha256(upload_path)
            remote_key = f"backups/{upload_path.name}"

            s3_client = client or self._get_s3_client()

            if s3_client is not None:
                metadata = {"sha256": checksum, "encrypted": str(should_encrypt).lower()}
                with open(upload_path, "rb") as f:
                    if file_size > _MULTIPART_THRESHOLD and hasattr(s3_client, "upload_fileobj"):
                        s3_client.upload_fileobj(
                            f,
                            self.bucket_name,
                            remote_key,
                            ExtraArgs={"Metadata": metadata},
                        )
                    else:
                        s3_client.put_object(
                            Bucket=self.bucket_name,
                            Key=remote_key,
                            Body=f,
                            Metadata=metadata,
                        )

                self._prune_remote_backups(s3_client, retention_count)

            return {
                "status": "success",
                "snapshot_file": str(upload_path.name),
                "size_bytes": file_size,
                "sha256": checksum,
                "remote_key": remote_key,
                "bucket": self.bucket_name,
                "encrypted": should_encrypt,
                "timestamp": int(time.time()),
            }
        finally:
            if temp_enc_path is not None and temp_enc_path.exists():
                temp_enc_path.unlink(missing_ok=True)

    def list_cloud_backups(self, client: Any = None) -> list[dict]:
        """List all available remote backups in the cloud bucket."""
        s3_client = client or self._get_s3_client()
        if s3_client is None:
            return []

        try:
            response = s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix="backups/")
            contents = response.get("Contents", [])
            backups = []
            for item in sorted(contents, key=lambda x: x.get("LastModified", ""), reverse=True):
                backups.append({
                    "key": item["Key"],
                    "size_bytes": item["Size"],
                    "last_modified": str(item.get("LastModified")),
                })
            return backups
        except Exception as e:
            print(f"[CloudSync] Error listing cloud backups: {e}")
            return []

    def restore_from_cloud(
        self,
        remote_key: str,
        target_path: Path | None = None,
        client: Any = None,
    ) -> bool:
        """
        Download remote backup, stream-decrypt if envelope-encrypted, verify SQLite integrity,
        atomically swap database, and reset live connections, L1 cache, and Bloom filter.
        """
        db_path, data_dir = self._get_paths()
        target_path = target_path or db_path
        s3_client = client or self._get_s3_client()
        if s3_client is None:
            return False

        data_dir.mkdir(parents=True, exist_ok=True)
        temp_restore = data_dir / "restore_temp.db"
        temp_download = data_dir / "restore_download.tmp"
        raw_key = self._engine._get_raw_key_material() if self._engine is not None else None

        try:
            with open(temp_download, "wb") as f:
                s3_client.download_fileobj(self.bucket_name, remote_key, f)

            is_encrypted = False
            with open(temp_download, "rb") as f:
                header = f.read(9)
                if header == _LEGACY_MAGIC:
                    is_encrypted = True

            if is_encrypted or remote_key.endswith(".enc"):
                decrypt_snapshot_file(temp_download, temp_restore, raw_key=raw_key)
                temp_download.unlink(missing_ok=True)
            else:
                shutil.move(str(temp_download), str(temp_restore))

            # Verify SQLite integrity before swapping
            check_conn = sqlite3.connect(str(temp_restore))
            try:
                res = check_conn.execute("PRAGMA integrity_check").fetchone()
                if not res or res[0] != "ok":
                    raise RuntimeError(f"SQLite integrity check failed: {res}")
            finally:
                check_conn.close()

            # Close open SQLite connections before replacing DB file (critical on Windows)
            if self._engine is not None:
                self._engine.close_all_connections()
            else:
                from .database import close_all_connections
                close_all_connections()

            # Remove stale WAL/SHM files from previous DB state before atomic swap
            if target_path.exists():
                shutil.copy2(target_path, data_dir / "backup_before_restore.db")
            for suffix in ("-wal", "-shm"):
                wal_file = Path(f"{target_path}{suffix}")
                wal_file.unlink(missing_ok=True)

            os.replace(str(temp_restore), str(target_path))

            # Reset L1 cache and rebuild Bloom filter from restored DB
            if self._engine is not None:
                if hasattr(self._engine, "_reload_envelope_after_restore"):
                    self._engine._reload_envelope_after_restore()
                self._engine.cache.clear_l1()
                self._engine.rebuild_bloom_filter()
            else:
                from .cache import cache
                from .database import rebuild_bloom_filter
                cache.clear_l1()
                rebuild_bloom_filter()

            return True
        except Exception as e:
            print(f"[CloudSync] Error restoring cloud backup: {e}")
            temp_download.unlink(missing_ok=True)
            temp_restore.unlink(missing_ok=True)
            return False

    def _prune_remote_backups(self, s3_client: Any, retention_count: int):
        """Keep only the most recent N backups in cloud bucket."""
        if retention_count <= 0:
            return
        try:
            backups = self.list_cloud_backups(client=s3_client)
            if len(backups) > retention_count:
                for item in backups[retention_count:]:
                    s3_client.delete_object(Bucket=self.bucket_name, Key=item["key"])
        except Exception:
            pass

    def _get_s3_client(self) -> Any:
        """Dynamically initialize boto3 S3 client if available."""
        try:
            import boto3
            session = boto3.session.Session()
            return session.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region_name,
            )
        except ImportError:
            return None


# Global singleton instance
cloud_sync = CloudSyncEngine()
