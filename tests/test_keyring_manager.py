import unittest
import tempfile
import shutil
from pathlib import Path
from src.keyring_manager import KeyManager


class TestKeyringManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_get_master_key(self):
        """Test round-trip save, retrieve, and delete of master key."""
        test_key = "test_super_secret_master_key_1234567890="
        backend = KeyManager.save_master_key(test_key, username="test_user", storage_dir=self.test_dir)
        self.assertIsNotNone(backend)

        retrieved = KeyManager.get_master_key(username="test_user", storage_dir=self.test_dir)
        self.assertEqual(retrieved, test_key)

        deleted = KeyManager.delete_master_key(username="test_user", storage_dir=self.test_dir)
        self.assertTrue(deleted)

        after_delete = KeyManager.get_master_key(username="test_user", storage_dir=self.test_dir)
        self.assertIsNone(after_delete)

    def test_get_backend_name(self):
        """Verify get_backend_name returns non-empty descriptive string."""
        backend_name = KeyManager.get_backend_name()
        self.assertIsInstance(backend_name, str)
        self.assertTrue(len(backend_name) > 0)


if __name__ == "__main__":
    unittest.main()
