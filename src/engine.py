"""
engine.py — Instantiable, Isolated Encrypted SQLite & Two-Tier Caching Engine.

Allows opening multiple independent encrypted databases in the same Python process,
each with its own encryption key, algorithm, compression codec, L1 cache, Bloom filter,
blind index fields, event bus, and WAL connection pool.
"""

from __future__ import annotations

import os
import time
import zlib
import hmac
import base64
import fnmatch
import hashlib
import sqlite3
import asyncio
import threading
from pathlib import Path
from typing import Any, Callable, TypeVar
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .bloom_filter import BloomFilter
from .adapters import BaseL1Adapter, MemoryL1Adapter
from .events import EventDispatcher
from .keyring_manager import KeyManager
from .envelope import EnvelopeKeyring, unwrap_dek
from .collection import Collection
from .models import IntegrityReport, RotationReport, EngineStats
from . import serializers
from .database import (
    ConcurrentModificationError,
    derive_key_from_passphrase,
    derive_indexing_key,
    derive_key_encryption_subkeys,
    get_active_kdf_algorithm,
    _extract_field_values,
    _get_decrypt_executor,
    _PREFIX_GCM,
    _PREFIX_FERNET,
    _PREFIX_CHACHA,
    _PREFIX_ENC_KEY,
    _MAGIC_COMPRESSED_ZSTD,
    _MAGIC_COMPRESSED_ZL,
    _MAGIC_RAW,
    _HAS_ZSTD,
    _zstd_compressor,
    _zstd_decompressor,
    _SQLITE_MAX_VARS,
)

T = TypeVar("T")

_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MiB decompression bomb cap


def _derive_cipher_subkey(raw_key: bytes, context: bytes) -> bytes:
    """Derive an isolated 32-byte subkey per cipher algorithm via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"encrypted-sqlite-cipher-subkey-v2",
        info=context,
    ).derive(raw_key)


class _EngineTransaction:
    """Isolated atomic multi-key transaction scoped to a specific EncryptedSQLite instance."""

    def __init__(self, engine: "EncryptedSQLite"):
        self._engine = engine
        self._staged_writes: dict[str, tuple[Any, float | None]] = {}
        self._staged_deletes: set[str] = set()
        self._read_versions: dict[str, int] = {}
        self._active = True

    @property
    def is_active(self) -> bool:
        return self._active

    def set(self, key: str, value: Any, ttl: float | None = None):
        if not self._active:
            raise RuntimeError("Transaction is closed.")
        self._staged_deletes.discard(key)
        self._staged_writes[key] = (serializers.loads(serializers.dumps(value)), ttl)

    def delete(self, key: str):
        if not self._active:
            raise RuntimeError("Transaction is closed.")
        self._staged_writes.pop(key, None)
        self._staged_deletes.add(key)

    def get(self, key: str, default: Any = None) -> Any:
        if not self._active:
            raise RuntimeError("Transaction is closed.")
        if key in self._staged_deletes:
            return default
        if key in self._staged_writes:
            return serializers.loads(serializers.dumps(self._staged_writes[key][0]))
        val, ver = self._engine.get_versioned(key, default=default)
        if key not in self._read_versions and ver > 0:
            self._read_versions[key] = ver
        return val

    def commit(self):
        if not self._active:
            raise RuntimeError("Transaction is already closed.")
        if not self._staged_writes and not self._staged_deletes:
            self._active = False
            return

        conn = self._engine.get_connection()
        now_ts = int(time.time())

        # Pre-encrypt outside write lock for minimal lock contention
        prepared = []
        for key, (data, ttl) in self._staged_writes.items():
            blob = self._engine.pack_and_encrypt(data, associated_data=key.encode("utf-8"))
            exp = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
            s_key = self._engine._to_storage_key(key)
            prepared.append((s_key, key, blob, exp, now_ts, data, ttl))

        conn.execute("BEGIN IMMEDIATE")
        try:
            for r_key, expected_ver in self._read_versions.items():
                if r_key in self._staged_writes or r_key in self._staged_deletes:
                    row = self._engine._lookup_row(conn, r_key, "version")
                    cur_ver = row["version"] if row else 0
                    if cur_ver != expected_ver:
                        raise ConcurrentModificationError(
                            f"Optimistic lock conflict on key '{r_key}': expected {expected_ver}, got {cur_ver}."
                        )

            for d_key in self._staged_deletes:
                s_key = self._engine._to_storage_key(d_key)
                cands = [s_key] if s_key == d_key else [s_key, d_key]
                for ck in cands:
                    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (ck,))
                    conn.execute("DELETE FROM kv_store WHERE key = ?", (ck,))

            for s_key, plain_key, blob, exp, ts, data, _ in prepared:
                if s_key != plain_key:
                    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (plain_key,))
                    conn.execute("DELETE FROM kv_store WHERE key = ?", (plain_key,))
                conn.execute(
                    """
                    INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        version = version + 1,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at;
                    """,
                    (s_key, blob, exp, ts),
                )
                self._engine._update_blind_indexes(conn, s_key, data)

            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            self.rollback()
            raise

        for d_key in self._staged_deletes:
            self._engine._l1_delete(d_key)
            self._engine.events.emit("delete", key=d_key)

        for _, plain_key, _, _, _, data, ttl in prepared:
            self._engine._l1_set(plain_key, data, ttl)
            self._engine.bloom.add(plain_key)
            self._engine.events.emit("write", key=plain_key, value=data)

        self._active = False

    def rollback(self):
        self._staged_writes.clear()
        self._staged_deletes.clear()
        self._active = False

    def __enter__(self) -> "_EngineTransaction":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
            return False
        if self._active:
            self.commit()
        return True


class EncryptedSQLite:
    """
    Production-ready, isolated Encrypted SQLite & Two-Tier Caching Engine instance.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        key: str | bytes | None = None,
        passphrase: str | None = None,
        algorithm: str = "AES-256-GCM",
        compression: str = "AUTO",
        encrypt_keys: bool = False,
        indexed_fields: list[str] | set[str] | None = None,
        max_l1_items: int = 1000,
        default_l1_ttl: float = 86400.0,
        l1_adapter: BaseL1Adapter | None = None,
        envelope_encryption: bool = True,
        slot_id: str | None = None,
    ):
        if db_path is None:
            env_db = os.getenv("ENCRYPTED_SQLITE_DB_PATH")
            resolved_db = Path(env_db) if env_db else (Path.cwd() / "data" / "app_database.db")
        else:
            resolved_db = Path(db_path)

        self.db_path: Path = resolved_db
        self.data_dir: Path = resolved_db.parent
        self.algorithm: str = algorithm.upper()
        self.compression: str = compression.upper()
        self.encrypt_keys: bool = encrypt_keys
        self.default_l1_ttl: float = default_l1_ttl
        self._envelope_requested: bool = envelope_encryption
        self.envelope_enabled: bool = envelope_encryption
        self._active_slot_id: str = slot_id or EnvelopeKeyring.PRIMARY_SLOT
        self._passphrase_mode: bool = passphrase is not None

        self._indexed_fields: set[str] = (
            {str(f).strip() for f in indexed_fields if str(f).strip()} if indexed_fields else set()
        )
        self._local = threading.local()
        self._active_connections: set[sqlite3.Connection] = set()
        self._conn_lock = threading.RLock()
        self._cache_lock = threading.RLock()
        self._initialized = False

        self._adapter: BaseL1Adapter = l1_adapter or MemoryL1Adapter(max_capacity=max_l1_items)
        self.bloom = BloomFilter(expected_elements=max(5000, max_l1_items * 10), false_positive_rate=0.01)
        self.events = EventDispatcher()
        self._hits = 0
        self._misses = 0
        self._writes = 0

        # Ensure SQLite tables (including vault_key_slots) exist before unlocking KEK/DEK
        self._ensure_tables()
        self._unlock_vault_keys(key=key, passphrase=passphrase, slot_id=slot_id, envelope_encryption=envelope_encryption)
        self.rebuild_bloom_filter()
        self._initialized = True

    def _ensure_tables(self):
        conn = self.get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    expires_at INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv_store (expires_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_kv_expires_updated ON kv_store (expires_at, updated_at DESC);")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blind_indexes (
                    key TEXT NOT NULL,
                    field_name TEXT NOT NULL,
                    field_hash TEXT NOT NULL,
                    PRIMARY KEY (key, field_name, field_hash)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blind_hash ON blind_indexes (field_name, field_hash);")
            EnvelopeKeyring.ensure_schema(conn)

    def _unlock_vault_keys(
        self,
        key: str | bytes | None = None,
        passphrase: str | None = None,
        slot_id: str | None = None,
        envelope_encryption: bool = True,
    ):
        conn = self.get_connection()
        has_slots = EnvelopeKeyring.has_slots(conn)
        use_envelope = envelope_encryption or has_slots
        self.envelope_enabled = use_envelope

        if passphrase is not None:
            slot_rows = EnvelopeKeyring.get_all_slot_rows(conn) if has_slots else []
            ordered_slots = (
                [r for r in slot_rows if r["slot_id"] == slot_id] + [r for r in slot_rows if r["slot_id"] != slot_id]
                if slot_id
                else slot_rows
            )
            # First try unlocking any existing passphrase-derived slot (e.g. primary or recovery slot)
            for row in ordered_slots:
                salt = row["kdf_salt"]
                algo = row["kdf_algo"]
                if salt and algo and algo != "RAW":
                    try:
                        cand_kek, _ = derive_key_from_passphrase(passphrase, salt=bytes(salt), algorithm=algo)
                        dek = unwrap_dek(row["wrapped_dek"], cand_kek, row["slot_id"])
                        self._kek = cand_kek
                        self._active_slot_id = row["slot_id"]
                        self._set_raw_key(dek)
                        return
                    except Exception:
                        continue

            salt_file = self.data_dir / f".{self.db_path.stem}.salt"
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if salt_file.exists() and len(salt_file.read_bytes()) >= 16:
                salt = salt_file.read_bytes()[:16]
            else:
                salt = os.urandom(16)
                salt_file.write_bytes(salt)
            kdf_algo = get_active_kdf_algorithm()
            kek, _ = derive_key_from_passphrase(passphrase, salt=salt, algorithm=kdf_algo)
            self._kek = kek
            if use_envelope:
                dek = EnvelopeKeyring.initialize_or_unlock(
                    conn, kek=kek, slot_id=slot_id, kdf_algo=kdf_algo, kdf_salt=salt
                )
                self._set_raw_key(dek)
            else:
                self._set_raw_key(kek)
            return

        kek = self._normalize_key(key) if key is not None else self._load_or_create_key()
        self._kek = kek
        if use_envelope:
            dek = EnvelopeKeyring.initialize_or_unlock(conn, kek=kek, slot_id=slot_id, kdf_algo="RAW")
            self._set_raw_key(dek)
        else:
            self._set_raw_key(kek)

    def _reload_envelope_after_restore(self):
        """Re-unlock DEK from restored database slots if envelope encryption is active."""
        conn = self.get_connection()
        if EnvelopeKeyring.has_slots(conn) and hasattr(self, "_kek"):
            try:
                dek = EnvelopeKeyring.initialize_or_unlock(conn, kek=self._kek, slot_id=self._active_slot_id)
                self._set_raw_key(dek)
                self.envelope_enabled = True
            except Exception:
                pass

    @staticmethod
    def _normalize_key(raw_key: str | bytes) -> bytes:
        if isinstance(raw_key, str):
            raw_key = raw_key.encode("utf-8")
        try:
            decoded = base64.urlsafe_b64decode(raw_key)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        if len(raw_key) == 32:
            return raw_key
        return hashlib.sha256(raw_key).digest()

    def _load_or_create_key(self) -> bytes:
        env_key = os.getenv("ENCRYPTION_KEY")
        if env_key:
            return self._normalize_key(env_key)

        account_id = f"db:{self.db_path.stem}"
        stored = KeyManager.get_master_key(username=account_id, storage_dir=self.data_dir)
        if stored:
            return self._normalize_key(stored)

        generated_raw = AESGCM.generate_key(bit_length=256)
        generated_b64 = base64.urlsafe_b64encode(generated_raw).decode("ascii")
        KeyManager.save_master_key(generated_b64, username=account_id, storage_dir=self.data_dir)
        return generated_raw

    def _set_raw_key(self, raw_32: bytes):
        self._raw_key = raw_32
        # HKDF domain-separated subkeys per algorithm
        self._gcm_v2 = AESGCM(_derive_cipher_subkey(raw_32, b"aes-256-gcm-v2"))
        self._chacha_v2 = ChaCha20Poly1305(_derive_cipher_subkey(raw_32, b"chacha20-poly1305-v2"))
        self._fernet_v2 = Fernet(base64.urlsafe_b64encode(_derive_cipher_subkey(raw_32, b"fernet-aes-128-v2")))
        # Legacy v1 ciphers for backward-compatible reads
        self._gcm_v1 = AESGCM(raw_32)
        self._chacha_v1 = ChaCha20Poly1305(raw_32)
        self._fernet_v1 = Fernet(base64.urlsafe_b64encode(raw_32))

        self._index_key = derive_indexing_key(raw_32)
        self._key_siv_mac, self._key_siv_enc = derive_key_encryption_subkeys(raw_32)

    def _get_raw_key_material(self) -> bytes:
        return getattr(self, "_kek", self._raw_key)

    @property
    def cache(self):
        return self

    def clear_l1(self):
        with self._cache_lock:
            self._adapter.clear()

    def _l1_get(self, key: str) -> tuple[Any, bool]:
        with self._cache_lock:
            val, hit = self._adapter.get(key)
            if hit:
                self._hits += 1
                return val, True
            self._misses += 1
            return None, False

    def _l1_set(self, key: str, value: Any, ttl: float | None = None):
        eff = ttl if (ttl is not None and ttl > 0) else self.default_l1_ttl
        with self._cache_lock:
            self._adapter.set(key, value, ttl_seconds=eff)

    def _l1_delete(self, key: str):
        with self._cache_lock:
            self._adapter.delete(key)

    def get_connection(self) -> sqlite3.Connection:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            with self._conn_lock:
                if self._local.conn in self._active_connections:
                    return self._local.conn
            self._local.conn = None

        self.data_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA cache_size = -32000;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA wal_autocheckpoint = 1000;")

        with self._conn_lock:
            self._active_connections.add(conn)
        self._local.conn = conn
        return conn

    def close_all_connections(self):
        with self._conn_lock:
            for c in list(self._active_connections):
                try:
                    c.close()
                except Exception:
                    pass
            self._active_connections.clear()
        self._local.conn = None

    def close(self):
        """Close all database connections and clear in-memory cache."""
        self.clear_l1()
        self.close_all_connections()

    def __enter__(self) -> "EncryptedSQLite":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _init_schema(self):
        if self._initialized:
            return
        self._ensure_tables()
        self.rebuild_bloom_filter()
        self._initialized = True

    def _encrypt_key(self, plain_key: str) -> str:
        if plain_key.startswith(_PREFIX_ENC_KEY):
            return plain_key
        key_bytes = plain_key.encode("utf-8")
        siv = hmac.new(self._key_siv_mac, key_bytes, hashlib.sha256).digest()[:12]
        ct = AESGCM(self._key_siv_enc).encrypt(siv, key_bytes, associated_data=b"sqlite-key-siv-v1")
        tok = base64.urlsafe_b64encode(siv + ct).decode("ascii").rstrip("=")
        return f"{_PREFIX_ENC_KEY}{tok}"

    def _decrypt_key(self, stored_key: str, custom_raw_key: bytes | None = None) -> str:
        if not stored_key.startswith(_PREFIX_ENC_KEY):
            return stored_key
        if custom_raw_key is not None:
            mac_k, enc_k = derive_key_encryption_subkeys(custom_raw_key)
        else:
            mac_k, enc_k = self._key_siv_mac, self._key_siv_enc
        b64_part = stored_key[len(_PREFIX_ENC_KEY):]
        pad = "=" * ((4 - len(b64_part) % 4) % 4)
        raw = base64.urlsafe_b64decode(b64_part + pad)
        siv, ct = raw[:12], raw[12:]
        plain = AESGCM(enc_k).decrypt(siv, ct, associated_data=b"sqlite-key-siv-v1")
        if not hmac.compare_digest(siv, hmac.new(mac_k, plain, hashlib.sha256).digest()[:12]):
            raise ValueError("Synthetic-IV mismatch on encrypted key.")
        return plain.decode("utf-8")

    def _to_storage_key(self, plain_key: str) -> str:
        return self._encrypt_key(plain_key) if self.encrypt_keys else plain_key

    def rebuild_bloom_filter(self):
        conn = self.get_connection()
        now_ts = int(time.time())
        rows = conn.execute("SELECT key FROM kv_store WHERE expires_at == 0 OR expires_at > ?", (now_ts,)).fetchall()
        keys = []
        for r in rows:
            try:
                keys.append(self._decrypt_key(r["key"]))
            except Exception:
                keys.append(r["key"])
        self.bloom.clear()
        self.bloom.populate_from_keys(keys)

    def pack_and_encrypt(self, data: Any, associated_data: bytes | None = None) -> bytes:
        raw_bytes = serializers.dumps(data)
        comp = self.compression
        if comp == "AUTO":
            comp = "ZSTD" if _HAS_ZSTD else "ZLIB"

        if len(raw_bytes) > 128 and comp != "NONE":
            if comp == "ZSTD" and _HAS_ZSTD and _zstd_compressor is not None:
                payload = _MAGIC_COMPRESSED_ZSTD + _zstd_compressor.compress(raw_bytes)
            else:
                payload = _MAGIC_COMPRESSED_ZL + zlib.compress(raw_bytes, level=6)
        else:
            payload = _MAGIC_RAW + raw_bytes

        if self.algorithm == "AES-128-FERNET":
            return _PREFIX_FERNET + b"v2:" + self._fernet_v2.encrypt(payload)
        elif self.algorithm in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
            nonce = os.urandom(12)
            return _PREFIX_CHACHA + b"v2:" + nonce + self._chacha_v2.encrypt(nonce, payload, associated_data=associated_data)
        else:
            nonce = os.urandom(12)
            return _PREFIX_GCM + b"v2:" + nonce + self._gcm_v2.encrypt(nonce, payload, associated_data=associated_data)

    def decrypt_and_unpack(self, encrypted_blob: bytes, associated_data: bytes | None = None) -> Any:
        if len(encrypted_blob) < 5:
            raise ValueError("Encrypted payload too short.")

        if encrypted_blob.startswith(_PREFIX_GCM):
            body = encrypted_blob[5:]
            if body.startswith(b"v2:"):
                b2 = body[3:]
                decrypted = self._gcm_v2.decrypt(b2[:12], b2[12:], associated_data=associated_data)
            else:
                decrypted = self._gcm_v1.decrypt(body[:12], body[12:], associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_CHACHA):
            body = encrypted_blob[5:]
            if body.startswith(b"v2:"):
                b2 = body[3:]
                decrypted = self._chacha_v2.decrypt(b2[:12], b2[12:], associated_data=associated_data)
            else:
                decrypted = self._chacha_v1.decrypt(body[:12], body[12:], associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_FERNET):
            body = encrypted_blob[5:]
            if body.startswith(b"v2:"):
                decrypted = self._fernet_v2.decrypt(body[3:])
            else:
                decrypted = self._fernet_v1.decrypt(body)
        else:
            decrypted = self._fernet_v1.decrypt(encrypted_blob)

        if decrypted.startswith(_MAGIC_COMPRESSED_ZSTD):
            comp_body = decrypted[len(_MAGIC_COMPRESSED_ZSTD):]
            if _HAS_ZSTD and _zstd_decompressor is not None:
                raw_bytes = _zstd_decompressor.decompress(comp_body, max_output_size=_MAX_DECOMPRESSED_BYTES)
            else:
                import zstandard as zstd
                raw_bytes = zstd.ZstdDecompressor().decompress(comp_body, max_output_size=_MAX_DECOMPRESSED_BYTES)
        elif decrypted.startswith(_MAGIC_COMPRESSED_ZL):
            dobj = zlib.decompressobj()
            raw_bytes = dobj.decompress(decrypted[len(_MAGIC_COMPRESSED_ZL):], _MAX_DECOMPRESSED_BYTES)
            if dobj.unconsumed_tail:
                raise ValueError("Decompressed payload exceeds maximum allowed size.")
        elif decrypted.startswith(_MAGIC_RAW):
            raw_bytes = decrypted[len(_MAGIC_RAW):]
        else:
            raw_bytes = decrypted

        return serializers.loads(raw_bytes)

    def set_indexed_fields(self, fields: list[str] | set[str]):
        self._indexed_fields = {str(f).strip() for f in fields if str(f).strip()}

    def _update_blind_indexes(self, conn: sqlite3.Connection, storage_key: str, data: Any, idx_key: bytes | None = None):
        conn.execute("DELETE FROM blind_indexes WHERE key = ?", (storage_key,))
        if not isinstance(data, dict) or not self._indexed_fields:
            return
        use_key = idx_key or self._index_key
        records = set()
        for field in self._indexed_fields:
            for val in _extract_field_values(data, field):
                h = hmac.new(use_key, str(val).strip().encode("utf-8"), hashlib.sha256).hexdigest()
                records.add((storage_key, field, h))
        if records:
            conn.executemany(
                "INSERT OR REPLACE INTO blind_indexes (key, field_name, field_hash) VALUES (?, ?, ?)",
                list(records),
            )

    def _lookup_row(self, conn: sqlite3.Connection, plain_key: str, cols: str = "key, value, expires_at"):
        s_key = self._to_storage_key(plain_key)
        row = conn.execute(f"SELECT {cols} FROM kv_store WHERE key = ?", (s_key,)).fetchone()
        if row is None and s_key != plain_key:
            row = conn.execute(f"SELECT {cols} FROM kv_store WHERE key = ?", (plain_key,)).fetchone()
        return row

    def get(self, key: str, default: Any = None) -> Any:
        val, hit = self._l1_get(key)
        if hit:
            return val
        if not self.bloom.contains(key):
            return default

        conn = self.get_connection()
        row = self._lookup_row(conn, key, "key, value, expires_at")
        if row is None:
            return default

        now_ts = int(time.time())
        exp = row["expires_at"]
        if exp > 0 and exp <= now_ts:
            self.delete(key)
            return default

        try:
            data = self.decrypt_and_unpack(row["value"], associated_data=key.encode("utf-8"))
            rem_ttl = (exp - time.time()) if exp > 0 else None
            if rem_ttl is not None and rem_ttl <= 0:
                return default
            self._l1_set(key, data, ttl=rem_ttl)
            return data
        except Exception:
            return default

    def set(self, key: str, value: Any, ttl: float | None = None, db_ttl: float | None = None):
        eff_db_ttl = db_ttl if db_ttl is not None else ttl
        now_ts = int(time.time())
        exp = int(now_ts + eff_db_ttl) if (eff_db_ttl is not None and eff_db_ttl > 0) else 0
        blob = self.pack_and_encrypt(value, associated_data=key.encode("utf-8"))
        s_key = self._to_storage_key(key)

        conn = self.get_connection()
        with conn:
            if s_key != key:
                conn.execute("DELETE FROM blind_indexes WHERE key = ?", (key,))
                conn.execute("DELETE FROM kv_store WHERE key = ?", (key,))
            conn.execute(
                """
                INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    version = version + 1,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at;
                """,
                (s_key, blob, exp, now_ts),
            )
            self._update_blind_indexes(conn, s_key, value)

        self.bloom.add(key)
        self._l1_set(key, value, ttl=ttl if ttl is not None else eff_db_ttl)
        with self._cache_lock:
            self._writes += 1
        self.events.emit("write", key=key, value=value)

    def get_versioned(self, key: str, default: Any = None) -> tuple[Any, int]:
        if not self.bloom.contains(key):
            return default, 0
        conn = self.get_connection()
        row = self._lookup_row(conn, key, "key, value, version, expires_at")
        if row is None:
            return default, 0
        if row["expires_at"] > 0 and row["expires_at"] <= int(time.time()):
            self.delete(key)
            return default, 0
        try:
            return self.decrypt_and_unpack(row["value"], associated_data=key.encode("utf-8")), row["version"]
        except Exception:
            return default, 0

    def set_versioned(self, key: str, value: Any, expected_version: int, ttl: float | None = None) -> int:
        conn = self.get_connection()
        now_ts = int(time.time())
        exp = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
        blob = self.pack_and_encrypt(value, associated_data=key.encode("utf-8"))
        s_key = self._to_storage_key(key)

        with conn:
            if expected_version == 0:
                try:
                    conn.execute(
                        "INSERT INTO kv_store (key, value, version, expires_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                        (s_key, blob, exp, now_ts),
                    )
                    self._update_blind_indexes(conn, s_key, value)
                    new_ver = 1
                except sqlite3.IntegrityError:
                    raise ConcurrentModificationError(f"Key '{key}' already exists.")
            else:
                cur = conn.execute(
                    "UPDATE kv_store SET value = ?, version = version + 1, expires_at = ?, updated_at = ? WHERE key = ? AND version = ?",
                    (blob, exp, now_ts, s_key, expected_version),
                )
                if cur.rowcount == 0:
                    raise ConcurrentModificationError(f"Version conflict on key '{key}' (expected {expected_version}).")
                self._update_blind_indexes(conn, s_key, value)
                new_ver = expected_version + 1

        self.bloom.add(key)
        self._l1_set(key, value, ttl=ttl)
        self.events.emit("write", key=key, value=value)
        return new_ver

    def delete(self, key: str) -> bool:
        s_key = self._to_storage_key(key)
        cands = [s_key] if s_key == key else [s_key, key]
        conn = self.get_connection()
        with conn:
            for ck in cands:
                conn.execute("DELETE FROM blind_indexes WHERE key = ?", (ck,))
            placeholders = ",".join("?" * len(cands))
            cur = conn.execute(f"DELETE FROM kv_store WHERE key IN ({placeholders})", cands)
            deleted = cur.rowcount > 0

        self._l1_delete(key)
        if deleted:
            self.events.emit("delete", key=key)
        return deleted

    def mget(self, keys: list[str]) -> dict[str, Any]:
        if not keys:
            return {}
        results: dict[str, Any] = {}
        missing: list[str] = []
        for k in keys:
            val, hit = self._l1_get(k)
            if hit:
                results[k] = val
            elif self.bloom.contains(k):
                missing.append(k)

        if not missing:
            return results

        conn = self.get_connection()
        now_ts = int(time.time())
        s_to_p: dict[str, str] = {}
        q_keys: list[str] = []
        for pk in missing:
            s_to_p[pk] = pk
            if self.encrypt_keys:
                ek = self._encrypt_key(pk)
                s_to_p[ek] = pk
                q_keys.append(ek)
            q_keys.append(pk)

        uniq = list(dict.fromkeys(q_keys))
        rows = []
        for i in range(0, len(uniq), _SQLITE_MAX_VARS):
            chunk = uniq[i:i + _SQLITE_MAX_VARS]
            ph = ",".join("?" * len(chunk))
            rows.extend(conn.execute(f"SELECT key, value, expires_at FROM kv_store WHERE key IN ({ph})", chunk).fetchall())

        active = []
        for r in rows:
            if r["expires_at"] == 0 or r["expires_at"] > now_ts:
                pk = s_to_p.get(r["key"]) or self._decrypt_key(r["key"])
                active.append((pk, r["value"], r["expires_at"]))

        if len(active) > 8:
            executor = _get_decrypt_executor()
            def _dec(item):
                pk, blob, exp = item
                return pk, self.decrypt_and_unpack(blob, associated_data=pk.encode("utf-8")), exp
            for pk, val, exp in executor.map(_dec, active):
                rem = (exp - time.time()) if exp > 0 else None
                results[pk] = val
                self._l1_set(pk, val, ttl=rem)
        else:
            for pk, blob, exp in active:
                val = self.decrypt_and_unpack(blob, associated_data=pk.encode("utf-8"))
                rem = (exp - time.time()) if exp > 0 else None
                results[pk] = val
                self._l1_set(pk, val, ttl=rem)

        return results

    def mset(self, mapping: dict[str, Any], ttl: float | None = None, db_ttl: float | None = None):
        if not mapping:
            return
        eff_db_ttl = db_ttl if db_ttl is not None else ttl
        now_ts = int(time.time())
        exp = int(now_ts + eff_db_ttl) if (eff_db_ttl is not None and eff_db_ttl > 0) else 0
        records = []
        items = []
        for k, val in mapping.items():
            s_key = self._to_storage_key(k)
            blob = self.pack_and_encrypt(val, associated_data=k.encode("utf-8"))
            records.append((s_key, blob, exp, now_ts))
            items.append((s_key, k, val))

        conn = self.get_connection()
        with conn:
            conn.executemany(
                """
                INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    version = version + 1,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at;
                """,
                records,
            )
            for s_key, pk, val in items:
                self._update_blind_indexes(conn, s_key, val)
                self.bloom.add(pk)
                self._l1_set(pk, val, ttl=ttl if ttl is not None else eff_db_ttl)

        for _, pk, val in items:
            self.events.emit("write", key=pk, value=val)

    def search(self, pattern: str = "*", limit: int | None = None) -> list[str]:
        conn = self.get_connection()
        now_ts = int(time.time())
        if not self.encrypt_keys:
            if limit and limit > 0:
                rows = conn.execute(
                    "SELECT key FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?",
                    (pattern, now_ts, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT key FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC",
                    (pattern, now_ts),
                ).fetchall()
            return [r["key"] for r in rows]

        rows = conn.execute(
            "SELECT key FROM kv_store WHERE (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC",
            (now_ts,),
        ).fetchall()
        out = []
        for r in rows:
            pk = self._decrypt_key(r["key"])
            if pattern == "*" or fnmatch.fnmatchcase(pk, pattern):
                out.append(pk)
                if limit and len(out) >= limit:
                    break
        return out

    def find(self, predicate: Callable[[Any], bool], pattern: str = "*", limit: int | None = None) -> list[Any]:
        keys = self.search(pattern=pattern)
        matches = []
        for i in range(0, len(keys), _SQLITE_MAX_VARS):
            chunk = keys[i:i + _SQLITE_MAX_VARS]
            docs = self.mget(chunk)
            for k in chunk:
                if k in docs and predicate(docs[k]):
                    matches.append(docs[k])
                    if limit and len(matches) >= limit:
                        return matches
        return matches

    def find_by_index(self, field_name: str, value: Any) -> dict[str, Any]:
        h = hmac.new(self._index_key, str(value).strip().encode("utf-8"), hashlib.sha256).hexdigest()
        conn = self.get_connection()
        now_ts = int(time.time())
        rows = conn.execute(
            """
            SELECT DISTINCT b.key FROM blind_indexes b
            JOIN kv_store k ON b.key = k.key
            WHERE b.field_name = ? AND b.field_hash = ? AND (k.expires_at == 0 OR k.expires_at > ?)
            """,
            (field_name, h, now_ts),
        ).fetchall()
        pks = [self._decrypt_key(r["key"]) for r in rows]
        return self.mget(pks) if pks else {}

    def count(self, pattern: str | None = None) -> int:
        if pattern:
            return len(self.search(pattern=pattern))
        conn = self.get_connection()
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM kv_store WHERE (expires_at == 0 OR expires_at > ?)",
            (int(time.time()),),
        ).fetchone()
        return row["total"] if row else 0

    def purge_expired(self) -> int:
        conn = self.get_connection()
        now_ts = int(time.time())
        with conn:
            rows = conn.execute("SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,)).fetchall()
            if not rows:
                return 0
            pks = [self._decrypt_key(r["key"]) for r in rows]
            conn.execute("DELETE FROM blind_indexes WHERE key IN (SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?)", (now_ts,))
            cur = conn.execute("DELETE FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))
        for pk in pks:
            self._l1_delete(pk)
            self.events.emit("expire", key=pk)
        self.rebuild_bloom_filter()
        return cur.rowcount

    def rotate_kek(self, new_key: str | bytes, slot_id: str = EnvelopeKeyring.PRIMARY_SLOT) -> RotationReport:
        """O(1) instant KEK rotation: re-wraps the 32-byte DEK without re-encrypting rows."""
        if not self.envelope_enabled:
            raise RuntimeError("rotate_kek() requires envelope_encryption=True.")
        new_kek = self._normalize_key(new_key)
        conn = self.get_connection()
        EnvelopeKeyring.rotate_kek(conn, self._raw_key, new_kek, slot_id=slot_id, kdf_algo="RAW")
        if slot_id == self._active_slot_id:
            self._kek = new_kek
        return RotationReport(
            status="ok",
            mode="kek_envelope_o1",
            rotated_count=0,
            failed_count=0,
            failed_keys=[],
            message=f"O(1) KEK rotation completed for slot '{slot_id}'.",
        )

    def add_recovery_slot(
        self,
        slot_id: str,
        recovery_key: str | bytes | None = None,
        recovery_passphrase: str | None = None,
    ) -> dict[str, Any]:
        """Wrap the active DEK under an additional recovery key or Argon2id/PBKDF2 passphrase slot."""
        if not self.envelope_enabled:
            raise RuntimeError("Recovery slots require envelope_encryption=True.")
        if recovery_key is None and recovery_passphrase is None:
            raise ValueError("Provide either recovery_key or recovery_passphrase.")

        conn = self.get_connection()
        if recovery_passphrase is not None:
            salt = os.urandom(16)
            kdf_algo = get_active_kdf_algorithm()
            slot_kek, _ = derive_key_from_passphrase(recovery_passphrase, salt=salt, algorithm=kdf_algo)
            EnvelopeKeyring.add_slot(conn, self._raw_key, slot_id, slot_kek, kdf_algo=kdf_algo, kdf_salt=salt)
            return {"status": "ok", "slot_id": slot_id, "kdf_algo": kdf_algo}

        assert recovery_key is not None
        slot_kek = self._normalize_key(recovery_key)
        EnvelopeKeyring.add_slot(conn, self._raw_key, slot_id, slot_kek, kdf_algo="RAW")
        return {"status": "ok", "slot_id": slot_id, "kdf_algo": "RAW"}

    def remove_recovery_slot(self, slot_id: str) -> bool:
        """Remove a recovery key slot from vault_key_slots."""
        return EnvelopeKeyring.remove_slot(self.get_connection(), slot_id)

    def list_key_slots(self) -> list[dict[str, Any]]:
        """List configured KEK unlock slots (metadata only)."""
        return EnvelopeKeyring.list_slots(self.get_connection())

    def rotate_key(self, new_key: str | bytes, strict: bool = True, deep_rekey: bool = False) -> RotationReport:
        """
        Rotate the vault key.
        - By default when envelope encryption is active, performs O(1) KEK re-wrapping (`mode="kek_envelope_o1"`).
        - With `deep_rekey=True` (or when envelope encryption is disabled), re-encrypts every row under a fresh DEK.
        """
        if self.envelope_enabled and not deep_rekey:
            return self.rotate_kek(new_key, slot_id=self._active_slot_id)

        conn = self.get_connection()
        rows = conn.execute("SELECT key, value, version, expires_at, updated_at FROM kv_store").fetchall()
        old_raw = self._raw_key
        new_kek = self._normalize_key(new_key)
        new_dek = AESGCM.generate_key(bit_length=256) if self.envelope_enabled else new_kek

        decoded_rows = []
        failed_keys = []
        for r in rows:
            s_key = r["key"]
            try:
                pk = self._decrypt_key(s_key, custom_raw_key=old_raw)
                data = self.decrypt_and_unpack(r["value"], associated_data=pk.encode("utf-8"))
                decoded_rows.append((s_key, pk, data, r["version"], r["expires_at"], r["updated_at"]))
            except Exception as e:
                failed_keys.append(s_key)
                if strict:
                    raise RuntimeError(f"Key rotation aborted on '{s_key}': {e}") from e

        self._set_raw_key(new_dek)
        self._kek = new_kek
        with conn:
            for old_s_key, pk, data, ver, exp, ts in decoded_rows:
                new_s_key = self._to_storage_key(pk)
                new_blob = self.pack_and_encrypt(data, associated_data=pk.encode("utf-8"))
                if new_s_key != old_s_key:
                    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (old_s_key,))
                    conn.execute("DELETE FROM kv_store WHERE key = ?", (old_s_key,))
                    conn.execute(
                        "INSERT OR REPLACE INTO kv_store (key, value, version, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (new_s_key, new_blob, ver, exp, ts),
                    )
                else:
                    conn.execute(
                        "UPDATE kv_store SET value = ?, version = ?, expires_at = ?, updated_at = ? WHERE key = ?",
                        (new_blob, ver, exp, ts, new_s_key),
                    )
                self._update_blind_indexes(conn, new_s_key, data)

        if self.envelope_enabled:
            EnvelopeKeyring.rotate_kek(conn, new_dek, new_kek, slot_id=self._active_slot_id, kdf_algo="RAW")

        self.rebuild_bloom_filter()
        return RotationReport(
            status="ok",
            mode="deep_dek_rekey",
            rotated_count=len(decoded_rows),
            failed_count=len(failed_keys),
            failed_keys=failed_keys,
            message=f"Deep DEK re-key completed for {len(decoded_rows)} record(s).",
        )

    def collection(
        self,
        name: str,
        schema: type[T] | None = None,
        indexes: list[str] | set[str] | None = None,
    ) -> Collection[T]:
        """Return a typed, namespaced Collection[T] backed by this EncryptedSQLite instance."""
        return Collection(self, name=name, schema=schema, indexes=indexes)

    def verify_integrity(self) -> IntegrityReport:
        """Perform a cryptographic AEAD integrity audit across all records in this database."""
        conn = self.get_connection()
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
        total = len(rows)
        valid_count = 0
        corrupted_keys: list[dict[str, str]] = []

        for row in rows:
            stored_key = row["key"]
            try:
                plain_key = self._decrypt_key(stored_key)
                data = self.decrypt_and_unpack(row["value"], associated_data=plain_key.encode("utf-8"))
                if data is not None:
                    valid_count += 1
                else:
                    corrupted_keys.append({"key": plain_key, "reason": "Decoded payload is None"})
            except Exception as e:
                corrupted_keys.append({"key": stored_key, "reason": f"Decryption/verification failed: {e}"})

        is_clean = len(corrupted_keys) == 0
        return IntegrityReport(
            status="clean" if is_clean else "corrupted",
            total_records=total,
            valid_records=valid_count,
            corrupted_records=len(corrupted_keys),
            corrupted_keys=corrupted_keys,
            message=(
                "All records passed 100% cryptographic integrity verification."
                if is_clean
                else f"Found {len(corrupted_keys)} corrupted/tampered records!"
            ),
        )

    def transaction(self) -> _EngineTransaction:
        return _EngineTransaction(self)

    def on(self, event: str, callback: Callable | None = None, pattern: str = "*"):
        return self.events.on(event, callback=callback, pattern=pattern)

    def off(self, event: str, callback: Callable) -> bool:
        return self.events.off(event, callback)

    def stats(self) -> EngineStats:
        slot_count = len(self.list_key_slots()) if self.envelope_enabled else 0
        with self._cache_lock:
            total = self._hits + self._misses
            ratio = (self._hits / total * 100.0) if total > 0 else 100.0
            return EngineStats(
                db_path=str(self.db_path),
                algorithm=self.algorithm,
                encrypt_keys=self.encrypt_keys,
                envelope_enabled=self.envelope_enabled,
                key_slots=slot_count,
                l1_items_cached=self._adapter.size(),
                hits=self._hits,
                misses=self._misses,
                writes=self._writes,
                hit_ratio_percent=round(ratio, 2),
                stored_documents=self.count(),
            )

    # Async convenience wrappers
    async def aget(self, key: str, default: Any = None) -> Any:
        val, hit = self._l1_get(key)
        if hit:
            return val
        return await asyncio.to_thread(self.get, key, default)

    async def aset(self, key: str, value: Any, ttl: float | None = None, db_ttl: float | None = None):
        await asyncio.to_thread(self.set, key, value, ttl, db_ttl)

    async def adelete(self, key: str) -> bool:
        return await asyncio.to_thread(self.delete, key)

    async def afind_by_index(self, field_name: str, value: Any) -> dict[str, Any]:
        return await asyncio.to_thread(self.find_by_index, field_name, value)
