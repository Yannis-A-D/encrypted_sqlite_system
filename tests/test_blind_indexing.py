import os
import unittest
import base64
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    kv_set, kv_get, kv_delete, kv_find_by_index, async_kv_find_by_index,
    set_indexed_fields, get_indexed_fields, rotate_encryption_key,
    get_db_connection
)
from src.database import ROOT_DIR, set_cipher_key

class TestBlindIndexing(unittest.TestCase):
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

        # Clear tables
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

        # Configure fields to index
        set_indexed_fields(["email", "username"])

    def tearDown(self):
        # Restore backup key
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

        # Reset indexed fields
        set_indexed_fields([])

    def test_indexed_fields_configuration(self):
        """Verify getter and setter configuration for blind indexing fields."""
        set_indexed_fields(["  name  ", "email", "username"])
        self.assertEqual(get_indexed_fields(), ["email", "name", "username"])

    def test_blind_indexing_write_and_find(self):
        """Verify blind indexing successfully queries exact match values."""
        user_a = {"username": "alex123", "email": "alex@gmail.com", "role": "admin"}
        user_b = {"username": "bob456", "email": "bob@yahoo.com", "role": "user"}

        kv_set("alex.json", user_a)
        kv_set("bob.json", user_b)

        # Query using blind index
        results = kv_find_by_index("email", "alex@gmail.com")
        self.assertEqual(len(results), 1)
        self.assertIn("alex.json", results)
        self.assertEqual(results["alex.json"], user_a)

        # Query Bob
        results_bob = kv_find_by_index("username", "bob456")
        self.assertEqual(len(results_bob), 1)
        self.assertEqual(results_bob["bob.json"], user_b)

        # Query non-existent or unindexed field
        self.assertEqual(kv_find_by_index("role", "admin"), {})
        self.assertEqual(kv_find_by_index("email", "unknown@gmail.com"), {})

    def test_blind_indexing_updates(self):
        """Verify that updating a document updates its blind indexes accordingly."""
        user = {"username": "alex123", "email": "alex@gmail.com"}
        kv_set("alex.json", user)

        # Verify initial query works
        self.assertEqual(len(kv_find_by_index("email", "alex@gmail.com")), 1)

        # Update document email
        user_updated = {"username": "alex123", "email": "alex_new@gmail.com"}
        kv_set("alex.json", user_updated)

        # Old email search should return nothing
        self.assertEqual(kv_find_by_index("email", "alex@gmail.com"), {})

        # New email search should return updated document
        results = kv_find_by_index("email", "alex_new@gmail.com")
        self.assertEqual(len(results), 1)
        self.assertEqual(results["alex.json"], user_updated)

    def test_blind_indexing_deletions(self):
        """Verify deleting a document cleans up its index records."""
        user = {"username": "alex123", "email": "alex@gmail.com"}
        kv_set("alex.json", user)

        # Assert index exists
        self.assertEqual(len(kv_find_by_index("email", "alex@gmail.com")), 1)

        # Delete document
        kv_delete("alex.json")

        # Query should now return empty dict
        self.assertEqual(kv_find_by_index("email", "alex@gmail.com"), {})

    def test_blind_indexing_rotation(self):
        """Verify index hashes are correctly re-computed using the new index key on key rotation."""
        user = {"username": "alex123", "email": "alex@gmail.com"}
        kv_set("alex.json", user)

        # Generate new key and rotate
        new_raw_key = AESGCM.generate_key(bit_length=256)
        new_key_str = base64.urlsafe_b64encode(new_raw_key).decode("utf-8")
        
        # Rotate key
        result = rotate_encryption_key(self.test_key, new_key_str)
        self.assertEqual(result["rotated_count"], 1)

        # Set new key active
        self.key_file.write_text(new_key_str)

        # Search should still succeed because rotation recomputed hashes with new derived index key!
        results = kv_find_by_index("email", "alex@gmail.com")
        self.assertEqual(len(results), 1)
        self.assertEqual(results["alex.json"], user)

    def test_async_find_by_index(self):
        """Verify the async version of blind indexing lookups."""
        user = {"username": "alex123", "email": "alex@gmail.com"}
        kv_set("alex.json", user)

        async def run_async_test():
            res = await async_kv_find_by_index("email", "alex@gmail.com")
            self.assertEqual(len(res), 1)
            self.assertEqual(res["alex.json"], user)

        asyncio.run(run_async_test())

if __name__ == "__main__":
    unittest.main()
