import os
import unittest
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    kv_set, kv_get, kv_get_versioned, kv_set_versioned,
    ConcurrentModificationError, rotate_encryption_key,
    get_db_connection, async_kv_get_versioned, async_kv_set_versioned
)
from src.database import ROOT_DIR, set_cipher_key

class TestConcurrencyControl(unittest.TestCase):
    def setUp(self):
        # Save key file and config
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        # Generate standard key for GCM
        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

        # Clear key from database to ensure fresh slate
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")

    def tearDown(self):
        # Restore backup key
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_standard_write_versioning(self):
        """Verify that standard kv_set writes automatically initialize and increment versions."""
        # 1. First write (initial creation)
        kv_set("item_v.json", {"a": 1})
        data, version = kv_get_versioned("item_v.json")
        self.assertEqual(data, {"a": 1})
        self.assertEqual(version, 1)

        # 2. Second write (update)
        kv_set("item_v.json", {"a": 2})
        data, version = kv_get_versioned("item_v.json")
        self.assertEqual(data, {"a": 2})
        self.assertEqual(version, 2)

    def test_versioned_write_success(self):
        """Verify versioned updates succeed when the version matches expected_version."""
        kv_set("item_succ.json", {"count": 10})
        
        # Current version is 1. Increment to version 2.
        new_version = kv_set_versioned("item_succ.json", {"count": 11}, expected_version=1)
        self.assertEqual(new_version, 2)
        
        data, version = kv_get_versioned("item_succ.json")
        self.assertEqual(data, {"count": 11})
        self.assertEqual(version, 2)

    def test_versioned_write_conflict(self):
        """Verify versioned writes raise ConcurrentModificationError on version mismatch."""
        kv_set("item_conflict.json", {"val": 100})
        
        # Try updating with incorrect expected_version (e.g. 5 instead of 1)
        with self.assertRaises(ConcurrentModificationError) as ctx:
            kv_set_versioned("item_conflict.json", {"val": 101}, expected_version=5)
            
        self.assertIn("Conflict detected", str(ctx.exception))
        self.assertIn("current version is 1, but expected 5", str(ctx.exception))

        # Try updating non-existent key with a non-zero version
        with self.assertRaises(ConcurrentModificationError) as ctx:
            kv_set_versioned("non_existent.json", {"val": 5}, expected_version=1)
        self.assertIn("record does not exist", str(ctx.exception))

    def test_expected_version_zero_creation(self):
        """Verify that expected_version=0 restricts writes strictly to new creations."""
        # 1. Succeeded creation
        new_ver = kv_set_versioned("item_new.json", {"x": 10}, expected_version=0)
        self.assertEqual(new_ver, 1)

        # 2. Failure because document already exists
        with self.assertRaises(ConcurrentModificationError) as ctx:
            kv_set_versioned("item_new.json", {"x": 20}, expected_version=0)
        self.assertIn("record already exists", str(ctx.exception))

    def test_rotation_preserves_version(self):
        """Verify that rotating key does not alter or reset document versions."""
        kv_set("doc_rot.json", {"d": "some info"})
        kv_set("doc_rot.json", {"d": "updated info"}) # version is 2
        
        # Verify version is 2
        _, ver = kv_get_versioned("doc_rot.json")
        self.assertEqual(ver, 2)

        # Rotate key
        new_raw_key = AESGCM.generate_key(bit_length=256)
        new_key_str = base64.urlsafe_b64encode(new_raw_key).decode("utf-8")
        result = rotate_encryption_key(self.test_key, new_key_str)
        self.assertEqual(result["rotated_count"], 1)

        # Write new key to file
        self.key_file.write_text(new_key_str)

        # Verify version remains 2
        data, ver = kv_get_versioned("doc_rot.json")
        self.assertEqual(data, {"d": "updated info"})
        self.assertEqual(ver, 2)

    def test_async_versioned_operations(self):
        """Verify that async_kv_get_versioned and async_kv_set_versioned work correctly."""
        import asyncio
        
        async def run_async_test():
            # 1. Write an item
            kv_set("async_item.json", {"v": 100})
            
            # 2. Get versioned
            data, version = await async_kv_get_versioned("async_item.json")
            self.assertEqual(data, {"v": 100})
            self.assertEqual(version, 1)
            
            # 3. Set versioned
            new_ver = await async_kv_set_versioned("async_item.json", {"v": 101}, expected_version=1)
            self.assertEqual(new_ver, 2)
            
            # 4. Check updated values
            data, version = await async_kv_get_versioned("async_item.json")
            self.assertEqual(data, {"v": 101})
            self.assertEqual(version, 2)
            
            # 5. Expect conflict
            with self.assertRaises(ConcurrentModificationError):
                await async_kv_set_versioned("async_item.json", {"v": 102}, expected_version=5)

        asyncio.run(run_async_test())

if __name__ == "__main__":
    unittest.main()
