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
from .database import get_db_connection, decrypt_and_unpack, _get_cipher
from cryptography.fernet import InvalidToken


def compute_record_checksum(key: str, val_bytes: bytes, updated_at: int, secret_key: bytes | None = None) -> str:
    """Compute an HMAC-SHA256 signature for a database record."""
    if secret_key is None:
        cipher = _get_cipher()
        # Derive signing key from fernet key
        secret_key = cipher._signing_key if hasattr(cipher, "_signing_key") else b"default_secret_seed"

    h = hmac.new(secret_key, digestmod=hashlib.sha256)
    h.update(key.encode("utf-8"))
    h.update(str(updated_at).encode("utf-8"))
    h.update(val_bytes)
    return h.hexdigest()


def verify_database_integrity() -> dict[str, Any]:
    """
    Perform a complete cryptographic integrity audit across all records in the database.
    
    Returns:
        dict containing total_records, valid_records, corrupted_records, and status.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value, updated_at FROM kv_store")
    rows = cursor.fetchall()

    cipher = _get_cipher()
    total = len(rows)
    valid_count = 0
    corrupted_keys = []

    for row in rows:
        key = row["key"]
        val_blob = row["value"]
        updated_at = row["updated_at"]

        try:
            # 1. Cryptographic HMAC verification & Fernet AES decryption
            data = decrypt_and_unpack(val_blob, cipher=cipher)
            if data is not None:
                valid_count += 1
            else:
                corrupted_keys.append({"key": key, "reason": "Decoded payload is None"})
        except InvalidToken:
            corrupted_keys.append({"key": key, "reason": "Cryptographic signature mismatch (InvalidToken / Tampered)"})
        except Exception as e:
            corrupted_keys.append({"key": key, "reason": f"Decryption/Decompression failed: {e}"})

    is_clean = len(corrupted_keys) == 0
    return {
        "status": "clean" if is_clean else "corrupted",
        "total_records": total,
        "valid_records": valid_count,
        "corrupted_records": len(corrupted_keys),
        "corrupted_keys": corrupted_keys,
        "message": "All records passed 100% cryptographic integrity verification." if is_clean else f"Found {len(corrupted_keys)} corrupted/tampered records!"
    }
