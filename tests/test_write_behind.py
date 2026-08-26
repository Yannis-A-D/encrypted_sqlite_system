"""
test_write_behind.py — Tests for asynchronous write-behind batch journaling.
"""

import time
from src.write_behind import WriteBehindEngine
from src.database import kv_get, init_db
from src.cache import TwoTierCache


def test_write_behind_flush():
    """Verify write-behind coalesces writes and flushes correctly to SQLite."""
    init_db()
    engine = WriteBehindEngine(flush_interval=0.05, max_batch_size=10)

    # Queue 5 writes
    for i in range(5):
        engine.queue_write(f"wb_test_{i}.json", {"val": i * 100})

    # Flush manually
    engine.flush()
    time.sleep(0.02)

    # Verify records exist in SQLite
    for i in range(5):
        val = kv_get(f"wb_test_{i}.json")
        assert val == {"val": i * 100}

    engine.close()


def test_two_tier_cache_with_write_behind():
    """Test TwoTierCache with write-behind enabled."""
    c = TwoTierCache(write_behind=True)
    assert c.get_stats()["write_behind_enabled"] is True

    c.set("wb_user.json", {"username": "FastUser", "speed": "ultra"})
    # Immediate L1 hit
    assert c.get("wb_user.json") == {"username": "FastUser", "speed": "ultra"}

    # Flush to SQLite
    c.flush()
    time.sleep(0.05)

    # Clear L1 to test L2 fallback
    c.clear_l1()
    loaded_from_l2 = c.get("wb_user.json")
    assert loaded_from_l2 == {"username": "FastUser", "speed": "ultra"}

    c.disable_write_behind()
