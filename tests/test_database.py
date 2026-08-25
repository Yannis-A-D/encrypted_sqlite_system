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
