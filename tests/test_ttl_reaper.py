import time
import unittest
from src.database import kv_set, kv_get, kv_get_with_expiry, kv_delete, get_db_connection
from src.cache import cache
from src.ttl_reaper import TTLReaper, start_ttl_reaper, stop_ttl_reaper


class TestTTLReaperAndSync(unittest.TestCase):
    def setUp(self):
        cache.clear_l1()
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")

    def tearDown(self):
        cache.clear_l1()
        stop_ttl_reaper()

    def test_l1_l2_ttl_synchronization(self):
        """Verify that L1 cache inherits the remaining TTL from L2 SQLite on cache miss."""
        key = "sync_ttl_test.json"
        data = {"hello": "world"}
        # Store in DB with 1.5s TTL
        kv_set(key, data, ttl=1.5)

        # Clear L1 to force L1 miss
        cache.clear_l1()

        # Fetch via cache.get -> should fetch from L2 and set remaining TTL in L1
        val = cache.get(key)
        self.assertEqual(val, data)

        # Sleep past 1.5s
        time.sleep(1.8)

        # Cache get should now return None because L1 expired alongside L2!
        expired_val = cache.get(key)
        self.assertIsNone(expired_val)

    def test_reaper_lifecycle_and_purge(self):
        """Test starting, stopping, and running the background TTL reaper."""
        reaper = start_ttl_reaper(interval_seconds=0.5)
        self.assertTrue(reaper.is_running())

        # Store an expired key
        kv_set("expired_soon.json", {"foo": "bar"}, ttl=0.2)
        time.sleep(0.5)

        # Trigger purge_now (background sweep may have already purged it)
        reaper.purge_now()
        self.assertGreaterEqual(reaper.total_purged, 1)

        stop_ttl_reaper()
        self.assertFalse(reaper.is_running())


if __name__ == "__main__":
    unittest.main()
