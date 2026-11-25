"""
envelope.py — Two-Layer KEK/DEK Envelope Encryption & Multi-Slot Key Management.

Architecture:
- A random 256-bit Data Encryption Key (DEK) encrypts database rows (via HKDF subkeys).
- The DEK is stored wrapped (AES-256-GCM) inside the `vault_key_slots` SQLite table under
  one or more Key Encryption Keys (KEKs), such as a primary service key and an offline
  recovery passphrase.
- Routine KEK / passphrase rotation is O(1) (< 1 ms): only the 32-byte DEK is re-wrapped!
- Full deep re-keying (generating a brand-new DEK and re-encrypting every row) remains
  available for emergency compromise scenarios.
"""

import os
import time
import sqlite3
from typing import Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_WRAP_PREFIX = b"DEKW1:"


def _derive_kek_wrap_key(raw_kek: bytes) -> bytes:
    """Derive a dedicated 32-byte AES-256-GCM key-wrapping key from a KEK via HKDF."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"encrypted-sqlite-kek-wrap-v3",
        info=b"vault-dek-wrapping-key",
    ).derive(raw_kek)


def wrap_dek(dek: bytes, kek: bytes, slot_id: str) -> bytes:
    """Wrap a 32-byte DEK using AES-256-GCM bound to slot_id via AAD."""
    if len(dek) != 32:
        raise ValueError("DEK must be exactly 32 bytes.")
    wrap_key = _derive_kek_wrap_key(kek)
    nonce = os.urandom(12)
    aad = f"vault-dek-wrap-v3:{slot_id}".encode("utf-8")
    ct = AESGCM(wrap_key).encrypt(nonce, dek, associated_data=aad)
    return _WRAP_PREFIX + nonce + ct


def unwrap_dek(wrapped_blob: bytes, kek: bytes, slot_id: str) -> bytes:
    """Unwrap a 32-byte DEK using AES-256-GCM, verifying slot_id AAD."""
    if not wrapped_blob.startswith(_WRAP_PREFIX) or len(wrapped_blob) < len(_WRAP_PREFIX) + 12 + 16:
        raise ValueError("Invalid wrapped DEK format.")
    body = wrapped_blob[len(_WRAP_PREFIX):]
    nonce, ct = body[:12], body[12:]
    wrap_key = _derive_kek_wrap_key(kek)
    aad = f"vault-dek-wrap-v3:{slot_id}".encode("utf-8")
    dek = AESGCM(wrap_key).decrypt(nonce, ct, associated_data=aad)
    if len(dek) != 32:
        raise ValueError("Unwrapped DEK has invalid length.")
    return dek


class EnvelopeKeyring:
    """Manages SQLite `vault_key_slots` table for O(1) KEK rotation and multi-slot unlocking."""

    PRIMARY_SLOT = "primary"

    @staticmethod
    def ensure_schema(conn: sqlite3.Connection):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_key_slots (
                slot_id TEXT PRIMARY KEY,
                wrapped_dek BLOB NOT NULL,
                kdf_algo TEXT NOT NULL DEFAULT 'RAW',
                kdf_salt BLOB,
                created_at INTEGER NOT NULL,
                rotated_at INTEGER NOT NULL
            );
        """)

    @classmethod
    def has_slots(cls, conn: sqlite3.Connection) -> bool:
        cls.ensure_schema(conn)
        row = conn.execute("SELECT 1 FROM vault_key_slots LIMIT 1").fetchone()
        return row is not None

    @classmethod
    def get_all_slot_rows(cls, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        cls.ensure_schema(conn)
        return conn.execute(
            "SELECT slot_id, wrapped_dek, kdf_algo, kdf_salt, created_at, rotated_at FROM vault_key_slots"
        ).fetchall()

    @classmethod
    def initialize_or_unlock(
        cls,
        conn: sqlite3.Connection,
        kek: bytes,
        slot_id: str | None = None,
        kdf_algo: str = "RAW",
        kdf_salt: bytes | None = None,
    ) -> bytes:
        """
        Unlock an existing DEK from `vault_key_slots` using `kek`, or generate & wrap a fresh
        256-bit DEK if the vault has no slots yet.
        """
        cls.ensure_schema(conn)
        rows = cls.get_all_slot_rows(conn)

        if not rows:
            dek = AESGCM.generate_key(bit_length=256)
            sid = slot_id or cls.PRIMARY_SLOT
            wrapped = wrap_dek(dek, kek, sid)
            now_ts = int(time.time())
            with conn:
                conn.execute(
                    """
                    INSERT INTO vault_key_slots (slot_id, wrapped_dek, kdf_algo, kdf_salt, created_at, rotated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (sid, wrapped, kdf_algo, kdf_salt, now_ts, now_ts),
                )
            return dek

        ordered_rows = (
            [r for r in rows if r["slot_id"] == slot_id] + [r for r in rows if r["slot_id"] != slot_id]
            if slot_id
            else rows
        )
        for row in ordered_rows:
            try:
                return unwrap_dek(row["wrapped_dek"], kek, row["slot_id"])
            except Exception:
                continue

        raise ValueError("Unable to unlock vault DEK with the provided key or passphrase.")

    @classmethod
    def rotate_kek(
        cls,
        conn: sqlite3.Connection,
        dek: bytes,
        new_kek: bytes,
        slot_id: str = PRIMARY_SLOT,
        kdf_algo: str = "RAW",
        kdf_salt: bytes | None = None,
    ) -> None:
        """O(1) instant KEK rotation: re-wrap the existing 32-byte DEK under a new KEK."""
        cls.ensure_schema(conn)
        wrapped = wrap_dek(dek, new_kek, slot_id)
        now_ts = int(time.time())
        with conn:
            conn.execute(
                """
                INSERT INTO vault_key_slots (slot_id, wrapped_dek, kdf_algo, kdf_salt, created_at, rotated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(slot_id) DO UPDATE SET
                    wrapped_dek = excluded.wrapped_dek,
                    kdf_algo = excluded.kdf_algo,
                    kdf_salt = excluded.kdf_salt,
                    rotated_at = excluded.rotated_at;
                """,
                (slot_id, wrapped, kdf_algo, kdf_salt, now_ts, now_ts),
            )

    @classmethod
    def add_slot(
        cls,
        conn: sqlite3.Connection,
        dek: bytes,
        slot_id: str,
        slot_kek: bytes,
        kdf_algo: str = "RAW",
        kdf_salt: bytes | None = None,
    ) -> None:
        """Add an additional unlock slot (e.g., offline emergency recovery key/passphrase)."""
        if not slot_id or not slot_id.strip():
            raise ValueError("slot_id must be a non-empty string.")
        cls.rotate_kek(conn, dek, slot_kek, slot_id=slot_id.strip(), kdf_algo=kdf_algo, kdf_salt=kdf_salt)

    @classmethod
    def remove_slot(cls, conn: sqlite3.Connection, slot_id: str) -> bool:
        """Remove a key slot (refuses to delete the last remaining slot to prevent lockout)."""
        cls.ensure_schema(conn)
        count = conn.execute("SELECT COUNT(*) FROM vault_key_slots").fetchone()[0]
        if count <= 1:
            raise RuntimeError("Cannot remove the last remaining vault key slot.")
        with conn:
            cur = conn.execute("DELETE FROM vault_key_slots WHERE slot_id = ?", (slot_id,))
            return cur.rowcount > 0

    @classmethod
    def list_slots(cls, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        """List metadata of all configured unlock slots (never exposes key bytes)."""
        cls.ensure_schema(conn)
        rows = conn.execute(
            "SELECT slot_id, kdf_algo, created_at, rotated_at FROM vault_key_slots ORDER BY created_at ASC"
        ).fetchall()
        return [dict(r) for r in rows]
