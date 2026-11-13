"""
test_security_improvements.py — Tests for AAD binding, strict key rotation,
tamper rejection in secure_json, and ChaCha20 disk persistence.
"""

import os
import pytest
from cryptography.fernet import Fernet
from src.database import (
    kv_set,
    kv_get,
    get_db_connection,
    rotate_encryption_key,
    set_cipher_key,
    _PREFIX_CHACHA,
)
from src.secure_json import load_json, save_json, DATA_DIR
from src.cache import cache


def test_aead_aad_prevents_blob_swapping():
    """Swapping encrypted blobs between two keys must fail AAD verification."""
    os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
    kv_set("aad_key_a", {"owner": "alice"})
    kv_set("aad_key_b", {"owner": "bob"})

    conn = get_db_connection()
    blob_a = conn.execute("SELECT value FROM kv_store WHERE key = ?", ("aad_key_a",)).fetchone()["value"]

    # Overwrite aad_key_b's ciphertext with aad_key_a's ciphertext
    with conn:
        conn.execute("UPDATE kv_store SET value = ? WHERE key = ?", (blob_a, "aad_key_b"))

    cache.clear_l1()
    assert kv_get("aad_key_b", default=None) is None


def test_secure_json_rejects_tampered_ciphertext(tmp_path):
    """Tampered encrypted files on disk must return fallback, never fall through."""
    target = DATA_DIR / "tamper_test_sec.json"
    save_json(target, {"secret": "ok"})

    # Evict from L1 and L2 so load_json reads from the disk file
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM kv_store WHERE key = ?", (target.name,))
    cache.clear_l1()

    raw = bytearray(target.read_bytes())
    raw[-1] ^= 0xFF
    target.write_bytes(bytes(raw))

    res = load_json(target, default={"tampered": True})
    assert res == {"tampered": True}

    if target.exists():
        target.unlink()


def test_secure_json_chacha20_roundtrip():
    """save_json and load_json must support ChaCha20-Poly1305 on disk."""
    old_algo = os.getenv("ENCRYPTION_ALGORITHM")
    os.environ["ENCRYPTION_ALGORITHM"] = "CHACHA20-POLY1305"
    target = DATA_DIR / "chacha_disk_test.json"
    try:
        save_json(target, {"cipher": "chacha20"})
        assert target.read_bytes().startswith(_PREFIX_CHACHA)

        cache.clear_l1()
        # Evict from L2 so load_json reads directly from the encrypted disk file
        from src.database import kv_delete
        # Keep disk file by reading after deleting only SQLite row
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store WHERE key = ?", (target.name,))
        cache.clear_l1()

        loaded = load_json(target)
        assert loaded == {"cipher": "chacha20"}
    finally:
        if old_algo is None:
            os.environ.pop("ENCRYPTION_ALGORITHM", None)
        else:
            os.environ["ENCRYPTION_ALGORITHM"] = old_algo
        if target.exists():
            target.unlink()


def test_rotate_encryption_key_strict_raises_on_unreadable():
    """rotate_encryption_key(..., strict=True) must abort if any row fails to decrypt."""
    k1 = Fernet.generate_key().decode()
    k2 = Fernet.generate_key().decode()
    set_cipher_key(k1)
    kv_set("strict_rot_ok", {"ok": 1})

    conn = get_db_connection()
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, version, expires_at, updated_at) VALUES (?, ?, 1, 0, 1)",
            ("strict_rot_bad", b"G256:corrupted_bytes_here"),
        )

    with pytest.raises(RuntimeError, match="Key rotation aborted"):
        rotate_encryption_key(k1, k2, strict=True)

    with conn:
        conn.execute("DELETE FROM kv_store WHERE key IN (?, ?)", ("strict_rot_ok", "strict_rot_bad"))
