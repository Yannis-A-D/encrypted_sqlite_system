import os
import time
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
from src.database import kv_set, kv_get, ROOT_DIR, set_cipher_key, _get_cipher
from src.key_rotation import BackgroundKeyRotator

class TestKeyRotation(unittest.TestCase):
    def setUp(self):
        # Setup test keys and clean data
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()
        
        # Write initial key
        self.initial_key = Fernet.generate_key().decode("utf-8")
        self.key_file.write_text(self.initial_key)
        set_cipher_key(self.initial_key)

    def tearDown(self):
        # Revert to backup key if existed
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_rotator_start_stop(self):
        """Test background thread rotator start and stop methods."""
        rotator = BackgroundKeyRotator(rotation_interval_days=1, check_interval_seconds=0.1)
        try:
            rotator.start()
            self.assertIsNotNone(rotator._thread)
            self.assertTrue(rotator._thread.is_alive())
        finally:
            rotator.stop()
            self.assertFalse(rotator._thread and rotator._thread.is_alive())

    def test_no_rotation_if_not_expired(self):
        """Test that rotation is skipped if the key file is fresh."""
        # Key is 0 seconds old, rotation interval is 90 days
        rotator = BackgroundKeyRotator(rotation_interval_days=90.0)
        rotated = rotator.check_and_rotate()
        self.assertFalse(rotated)
        
        # Verify key hasn't changed
        current_key = self.key_file.read_text().strip()
        self.assertEqual(current_key, self.initial_key)

    def test_rotation_on_expiration(self):
        """Test that re-encryption is executed and new key is stored when key expires."""
        # Write some data with initial key
        kv_set("test_rotate_k1", {"msg": "secret data 1"})
        kv_set("test_rotate_k2", [1, 2, 3])

        # Verify reading data works
        self.assertEqual(kv_get("test_rotate_k1")["msg"], "secret data 1")
        self.assertEqual(kv_get("test_rotate_k2"), [1, 2, 3])

        # Fake the file modification time to be 100 days ago
        old_time = time.time() - (100 * 86400)
        os.utime(str(self.key_file), (old_time, old_time))

        # Run rotation check with 90 days interval
        rotator = BackgroundKeyRotator(rotation_interval_days=90.0)
        rotated = rotator.check_and_rotate()
        
        self.assertTrue(rotated)

        # Verify key has changed
        new_key = self.key_file.read_text().strip()
        self.assertNotEqual(new_key, self.initial_key)

        # Verify we can read the old data decrypted using the new key
        self.assertEqual(kv_get("test_rotate_k1")["msg"], "secret data 1")
        self.assertEqual(kv_get("test_rotate_k2"), [1, 2, 3])

if __name__ == "__main__":
    unittest.main()
