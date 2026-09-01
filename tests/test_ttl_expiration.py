import os
import time
import base64
import unittest
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    kv_set, kv_get, kv_get_versioned, kv_set_versioned,
    kv_mset, kv_mget, kv_delete, kv_search, kv_count,
    kv_find_by_index, set_indexed_fields,
    purge_expired_records, rotate_encryption_key,
    get_db_connection, save_json, load_json,
    async_save_json, async_load_json, async_purge_expired,
    async_kv_get_versioned, async_kv_set_versioned,
    cache
)
from src.database import ROOT_DIR, set_cipher_key


class TestTTLExpiration(unittest.TestCase):
    def setUp(self):
        # Setup clean test key
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

        cache.clear_l1()
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

        set_indexed_fields(["email", "session_id"])

    def tearDown(self):
        cache.clear_l1()
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_lazy_expiration_on_get(self):
        """Verify that expired records return default on kv_get and get lazily cleaned."""
        # Permanent record
        kv_set("perm.json", {"role": "admin"})
        # 1-second TTL record
        kv_set("temp_session.json", {"token": "xyz123"}, ttl=1)

        # Before expiry
        self.assertEqual(kv_get("temp_session.json"), {"token": "xyz123"})
        self.assertEqual(kv_get("perm.json"), {"role": "admin"})

        # Wait for TTL to elapse
        time.sleep(1.2)

        # After expiry
        self.assertIsNone(kv_get("temp_session.json"))
        self.assertEqual(kv_get("perm.json"), {"role": "admin"})

    def test_versioned_write_with_ttl(self):
        """Verify kv_get_versioned and kv_set_versioned with TTL."""
        v1 = kv_set_versioned("temp_otp.json", {"otp": 9999}, expected_version=0, ttl=1)
        self.assertEqual(v1, 1)

        val, ver = kv_get_versioned("temp_otp.json")
        self.assertEqual(val, {"otp": 9999})
        self.assertEqual(ver, 1)

        time.sleep(1.2)

        val_after, ver_after = kv_get_versioned("temp_otp.json")
        self.assertIsNone(val_after)
        self.assertEqual(ver_after, 0)

    def test_batch_mset_and_mget_ttl(self):
        """Verify kv_mset and kv_mget with TTL filtering."""
        docs = {
            "s1.json": {"user": "Alice"},
            "s2.json": {"user": "Bob"}
        }
        kv_mset(docs, ttl=1)
        kv_set("keep.json", {"user": "Charlie"})

        fetched = kv_mget(["s1.json", "s2.json", "keep.json"])
        self.assertEqual(len(fetched), 3)

        time.sleep(1.2)

        fetched_after = kv_mget(["s1.json", "s2.json", "keep.json"])
        self.assertEqual(len(fetched_after), 1)
        self.assertIn("keep.json", fetched_after)
        self.assertNotIn("s1.json", fetched_after)

    def test_search_and_count_filter_expired(self):
        """Verify kv_search and kv_count exclude expired keys."""
        kv_set("item_1.json", {"name": "item1"}, ttl=1)
        kv_set("item_2.json", {"name": "item2"}, ttl=1)
        kv_set("item_3.json", {"name": "item3"})

        self.assertEqual(kv_count("item_*.json"), 3)
        self.assertEqual(len(kv_search("item_*.json")), 3)

        time.sleep(1.2)

        self.assertEqual(kv_count("item_*.json"), 1)
        active_keys = kv_search("item_*.json")
        self.assertEqual(active_keys, ["item_3.json"])

    def test_blind_indexing_filters_expired(self):
        """Verify kv_find_by_index does not return expired records."""
        kv_set("user_temp.json", {"email": "temp@example.com", "name": "Temp"}, ttl=1)
        kv_set("user_perm.json", {"email": "perm@example.com", "name": "Perm"})

        res_temp = kv_find_by_index("email", "temp@example.com")
        self.assertEqual(len(res_temp), 1)

        time.sleep(1.2)

        res_expired = kv_find_by_index("email", "temp@example.com")
        self.assertEqual(len(res_expired), 0)

        res_perm = kv_find_by_index("email", "perm@example.com")
        self.assertEqual(len(res_perm), 1)

    def test_purge_expired_records(self):
        """Verify purge_expired_records removes all expired records and blind indexes."""
        kv_set("e1.json", {"email": "e1@a.com"}, ttl=1)
        kv_set("e2.json", {"email": "e2@a.com"}, ttl=1)
        kv_set("e3.json", {"email": "e3@a.com"})

        # Before expiration
        purged = purge_expired_records()
        self.assertEqual(purged, 0)

        time.sleep(1.2)

        purged = purge_expired_records()
        self.assertEqual(purged, 2)

        # Raw SQLite check to verify rows are truly deleted
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM kv_store")
        self.assertEqual(cur.fetchone()["c"], 1)

        cur.execute("SELECT COUNT(*) AS c FROM blind_indexes")
        self.assertEqual(cur.fetchone()["c"], 1)

    def test_rotation_preserves_ttl(self):
        """Verify that key rotation maintains expires_at timestamps."""
        future_ttl = 100
        kv_set("future_exp.json", {"data": 123}, ttl=future_ttl)

        # Rotate key
        new_raw_key = AESGCM.generate_key(bit_length=256)
        new_key_str = base64.urlsafe_b64encode(new_raw_key).decode("utf-8")
        result = rotate_encryption_key(self.test_key, new_key_str)
        self.assertEqual(result["rotated_count"], 1)

        self.key_file.write_text(new_key_str)

        # Check raw DB expires_at
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT expires_at FROM kv_store WHERE key = 'future_exp.json'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertGreater(row["expires_at"], int(time.time()))

    def test_save_and_load_json_with_ttl(self):
        """Verify high-level save_json and load_json with TTL."""
        save_json("session_token.json", {"token": "abc_xyz"}, ttl=1)
        self.assertEqual(load_json("session_token.json")["token"], "abc_xyz")

        time.sleep(1.2)
        cache.clear_l1()  # Clear L1 to test L2 database expiration
        self.assertEqual(load_json("session_token.json", default={"token": "expired"}), {"token": "expired"})

    def test_async_ttl_operations(self):
        """Verify async TTL methods."""
        async def _run():
            await async_save_json("async_otp.json", {"code": 1234}, ttl=1)
            loaded = await async_load_json("async_otp.json")
            self.assertEqual(loaded, {"code": 1234})

            time.sleep(1.2)
            cache.clear_l1()
            loaded_exp = await async_load_json("async_otp.json", default=None)
            self.assertIsNone(loaded_exp)

            purged = await async_purge_expired()
            self.assertIsInstance(purged, int)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
