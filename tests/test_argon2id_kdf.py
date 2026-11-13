import os
import unittest
from src.database import derive_key_from_passphrase, get_active_kdf_algorithm


class TestKDFKeyDerivation(unittest.TestCase):
    def test_pbkdf2_derivation(self):
        """Test standard PBKDF2-HMAC-SHA256 key derivation."""
        salt = b"test_salt_123456"
        key1, salt1 = derive_key_from_passphrase("my_secure_passphrase", salt=salt, algorithm="PBKDF2")
        self.assertEqual(len(key1), 32)
        self.assertEqual(salt1, salt)

        # Deterministic check
        key2, salt2 = derive_key_from_passphrase("my_secure_passphrase", salt=salt, algorithm="PBKDF2")
        self.assertEqual(key1, key2)

    def test_auto_or_argon2_fallback(self):
        """Test auto algorithm selection and fallback mechanism."""
        algo = get_active_kdf_algorithm()
        self.assertIn(algo, ("ARGON2ID", "PBKDF2"))

        salt = b"test_salt_123456"
        key, salt_out = derive_key_from_passphrase("another_passphrase", salt=salt)
        self.assertEqual(len(key), 32)
        self.assertEqual(salt_out, salt)


if __name__ == "__main__":
    unittest.main()
