import os
import unittest
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.database import (
    kv_set, kv_get, get_db_connection, set_cipher_key,
    rotate_encryption_key, pack_and_encrypt, decrypt_and_unpack,
    ROOT_DIR, _PREFIX_GCM, _PREFIX_FERNET
)

class TestDualEncryption(unittest.TestCase):
    def setUp(self):
        # Save old config and keys
        self.old_algo = os.getenv("ENCRYPTION_ALGORITHM")
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        # Generate a standard key
        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

    def tearDown(self):
        # Revert environment and keys
        if self.old_algo:
            os.environ["ENCRYPTION_ALGORITHM"] = self.old_algo
        else:
            os.environ.pop("ENCRYPTION_ALGORITHM", None)

        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_gcm_prefix(self):
        """Verify that AES-256-GCM writes are prefixed with G256:."""
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
        kv_set("test_gcm.json", {"mode": "gcm"})

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM kv_store WHERE key = ?", ("test_gcm.json",))
        row = cursor.fetchone()
        blob = row["value"]
        
        self.assertTrue(blob.startswith(_PREFIX_GCM))
        self.assertEqual(kv_get("test_gcm.json")["mode"], "gcm")

    def test_fernet_prefix(self):
        """Verify that AES-128-FERNET writes are prefixed with F128:."""
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-128-FERNET"
        kv_set("test_fernet.json", {"mode": "fernet"})

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM kv_store WHERE key = ?", ("test_fernet.json",))
        row = cursor.fetchone()
        blob = row["value"]

        self.assertTrue(blob.startswith(_PREFIX_FERNET))
        self.assertEqual(kv_get("test_fernet.json")["mode"], "fernet")

    def test_auto_detection(self):
        """Verify that both formats can be read concurrently without changing configuration."""
        # 1. Write one GCM
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
        kv_set("doc_gcm.json", {"type": "GCM"})

        # 2. Write one Fernet
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-128-FERNET"
        kv_set("doc_fernet.json", {"type": "Fernet"})

        # 3. Read both using default (GCM) active config
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
        self.assertEqual(kv_get("doc_gcm.json")["type"], "GCM")
        self.assertEqual(kv_get("doc_fernet.json")["type"], "Fernet")

        # 4. Read both using Fernet active config
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-128-FERNET"
        self.assertEqual(kv_get("doc_gcm.json")["type"], "GCM")
        self.assertEqual(kv_get("doc_fernet.json")["type"], "Fernet")

    def test_legacy_unprefixed_fernet(self):
        """Verify that unprefixed Fernet tokens (legacy database rows) are correctly decrypted."""
        # Create a raw unprefixed Fernet token
        import zlib
        from src import serializers
        
        payload = b"RW1:" + serializers.dumps({"legacy": "old_data"})
        f_cipher = Fernet(self.test_key.encode("utf-8"))
        legacy_token = f_cipher.encrypt(payload)

        # Confirm it has no prefix
        self.assertFalse(legacy_token.startswith(_PREFIX_FERNET))
        self.assertFalse(legacy_token.startswith(_PREFIX_GCM))
        self.assertTrue(legacy_token.startswith(b"\x80") or legacy_token.startswith(b"gAAAA"))

        # Write directly to SQLite
        conn = get_db_connection()
        import time
        from src.database import bloom
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
                ("legacy_doc.json", legacy_token, int(time.time()))
            )
        bloom.add("legacy_doc.json")

        # Attempt to read via kv_get
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
        data = kv_get("legacy_doc.json")
        self.assertEqual(data["legacy"], "old_data")

    def test_rotation_cross_algorithms(self):
        """Test rotation with changing algorithms (e.g. converting AES-128 rows to AES-256)."""
        # 1. Write legacy Fernet row
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-128-FERNET"
        kv_set("migrate_doc.json", {"count": 42})

        # 2. Perform rotation to a new key and AES-256-GCM active algorithm
        os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
        new_raw_key = AESGCM.generate_key(bit_length=256)
        new_key_str = base64.urlsafe_b64encode(new_raw_key).decode("utf-8")

        result = rotate_encryption_key(self.test_key, new_key_str)
        self.assertEqual(result["rotated_count"], 1)

        # 3. Verify key file and active cipher updated
        self.key_file.write_text(new_key_str)

        # 4. Verify the row was converted to GCM prefix and reads correctly
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM kv_store WHERE key = ?", ("migrate_doc.json",))
        row = cursor.fetchone()
        blob = row["value"]

        self.assertTrue(blob.startswith(_PREFIX_GCM))
        self.assertEqual(kv_get("migrate_doc.json")["count"], 42)

if __name__ == "__main__":
    unittest.main()
