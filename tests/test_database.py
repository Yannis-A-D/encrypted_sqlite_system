"""
test_database.py — Tests for SQLite engine, encryption at rest, WAL mode, and concurrency.
"""

import threading
from src.database import kv_set, kv_get, kv_delete, db_maintenance, get_db_connection


def test_kv_set_get():
    """Test basic AES encryption and retrieval."""
    test_payload = {"user_id": 12345, "username": "Tester", "scores": [10, 20, 30]}
    kv_set("user_test.json", test_payload)

    result = kv_get("user_test.json")
    assert result == test_payload
    assert result["username"] == "Tester"
    assert result["scores"] == [10, 20, 30]


def test_kv_encryption_at_rest():
    """Verify that data in raw SQLite is ciphertext and not plaintext."""
    secret_text = "HighlyConfidentialSecret12345"
    kv_set("secret.json", {"secret": secret_text})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM kv_store WHERE key = ?", ("secret.json",))
    row = cursor.fetchone()
    raw_blob = row["value"]

    # Plaintext must NOT appear in raw database bytes
    assert secret_text.encode("utf-8") not in raw_blob
    assert raw_blob.startswith(b"gAAAAA")  # Fernet AES token prefix


def test_kv_delete():
    """Test document deletion."""
    kv_set("temp.json", {"temp": True})
    assert kv_get("temp.json") is not None

    deleted = kv_delete("temp.json")
    assert deleted is True
    assert kv_get("temp.json") is None


def test_concurrent_multithread_writes():
    """Verify WAL mode handles concurrent multi-threaded writes with zero lock errors."""
    threads = []
    errors = []

    def worker(thread_id):
        try:
            for i in range(25):
                key = f"thread_{thread_id}_item_{i}.json"
                kv_set(key, {"thread": thread_id, "index": i, "status": "active"})
                val = kv_get(key)
                assert val["index"] == i
        except Exception as e:
            errors.append(e)

    for t in range(10):  # 10 threads doing 250 total writes
        thread = threading.Thread(target=worker, args=(t,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(errors) == 0, f"Concurrent write errors occurred: {errors}"


def test_db_maintenance():
    """Test WAL checkpoint truncation and optimization."""
    stats = db_maintenance()
    assert stats["status"] == "ok"
    assert "size_mb" in stats


def test_payload_compression():
    """Verify large JSON payloads are compressed with zlib."""
    from src.database import pack_and_encrypt, decrypt_and_unpack
    import json

    # Create a repetitive 5 KB dictionary (highly compressible)
    large_payload = {"logs": ["User executed action at timestamp" for _ in range(150)]}
    raw_bytes = json.dumps(large_payload).encode("utf-8")
    assert len(raw_bytes) > 4000

    encrypted_blob = pack_and_encrypt(large_payload)
    # Encrypted compressed blob should be less than 50% of raw size
    assert len(encrypted_blob) < len(raw_bytes) * 0.40

    recovered = decrypt_and_unpack(encrypted_blob)
    assert recovered == large_payload


def test_rotate_encryption_key():
    """Test atomic key rotation across multiple database records."""
    from src.database import rotate_encryption_key, set_cipher_key
    from cryptography.fernet import Fernet

    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()

    set_cipher_key(old_key)
    kv_set("item_a.json", {"name": "Alpha", "secret": 123})
    kv_set("item_b.json", {"name": "Beta", "secret": 456})

    # Rotate keys
    res = rotate_encryption_key(old_key, new_key)
    assert res["status"] == "ok"
    assert res["rotated_count"] >= 2

    # Verify records can be read cleanly with new key
    assert kv_get("item_a.json") == {"name": "Alpha", "secret": 123}
    assert kv_get("item_b.json") == {"name": "Beta", "secret": 456}
