"""
test_integrity.py — Tests for cryptographic integrity verification and tamper detection.
"""

from src.integrity import verify_database_integrity, compute_record_checksum
from src.database import kv_set, get_db_connection


def test_verify_database_clean():
    """Verify integrity audit passes on clean database."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM kv_store")

    kv_set("clean_item_1.json", {"key": "val1", "num": 100})
    kv_set("clean_item_2.json", {"key": "val2", "num": 200})

    audit = verify_database_integrity()
    assert audit["status"] == "clean"
    assert audit["total_records"] == 2
    assert audit["valid_records"] == 2
    assert audit["corrupted_records"] == 0


def test_verify_database_tampering_detection():
    """Verify integrity audit detects corrupted/tampered bytes."""
    kv_set("tampered_item.json", {"secret": "original"})

    # Intentionally inject bad corrupted ciphertext into SQLite
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE kv_store SET value = ? WHERE key = ?", (b"corrupted_tampered_payload", "tampered_item.json"))

    audit = verify_database_integrity()
    assert audit["status"] == "corrupted"
    assert audit["corrupted_records"] >= 1
    assert any(item["key"] == "tampered_item.json" for item in audit["corrupted_keys"])


def test_compute_record_checksum():
    """Test HMAC-SHA256 checksum generation."""
    sig1 = compute_record_checksum("user.json", b"test_bytes", 123456789)
    sig2 = compute_record_checksum("user.json", b"test_bytes", 123456789)
    sig3 = compute_record_checksum("user.json", b"tampered_bytes", 123456789)

    assert sig1 == sig2
    assert sig1 != sig3
    assert len(sig1) == 64  # SHA-256 hex string
