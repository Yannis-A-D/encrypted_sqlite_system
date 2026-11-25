"""
integrity.py — Cryptographic Integrity Verification & Anti-Tamper Audit Engine.

Mathematically verifies that stored encrypted records have not suffered from:
- Hardware disk corruption / bit rot
- Incomplete write transactions
- Offline file tampering or unauthorized modifications
- Encryption key mismatches
"""

import hmac
import hashlib
from typing import Any
from .database import get_db_connection, decrypt_and_unpack, _get_cipher, _get_integrity_key
from .models import IntegrityReport
from cryptography.fernet import InvalidToken


def compute_record_checksum(key: str, val_bytes: bytes, updated_at: int, secret_key: bytes | None = None) -> str:
    """Compute an HMAC-SHA256 signature for a database record."""
    if secret_key is None:
        secret_key = _get_integrity_key()

    h = hmac.new(secret_key, digestmod=hashlib.sha256)
    h.update(key.encode("utf-8"))
    h.update(str(updated_at).encode("utf-8"))
    h.update(val_bytes)
    return h.hexdigest()


def verify_database_integrity() -> IntegrityReport:
    """
    Perform a complete cryptographic integrity audit across all records in the database.

    Returns:
        IntegrityReport containing total_records, valid_records, corrupted_records, and status.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value, updated_at FROM kv_store")
    rows = cursor.fetchall()

    total = len(rows)
    valid_count = 0
    corrupted_keys: list[dict[str, str]] = []

    for row in rows:
        stored_key = row["key"]
        val_blob = row["value"]

        try:
            from .database import decrypt_db_key
            plain_key = decrypt_db_key(stored_key)
            # Cryptographic AEAD tag / Fernet HMAC verification & decryption
            data = decrypt_and_unpack(val_blob, associated_data=plain_key.encode("utf-8"))
            if data is not None:
                valid_count += 1
            else:
                corrupted_keys.append({"key": plain_key, "reason": "Decoded payload is None"})
        except InvalidToken:
            corrupted_keys.append({"key": stored_key, "reason": "Cryptographic signature mismatch (InvalidToken / Tampered)"})
        except Exception as e:
            corrupted_keys.append({"key": stored_key, "reason": f"Decryption/Decompression failed: {e}"})

    is_clean = len(corrupted_keys) == 0
    return IntegrityReport(
        status="clean" if is_clean else "corrupted",
        total_records=total,
        valid_records=valid_count,
        corrupted_records=len(corrupted_keys),
        corrupted_keys=corrupted_keys,
        message="All records passed 100% cryptographic integrity verification." if is_clean else f"Found {len(corrupted_keys)} corrupted/tampered records!",
    )
