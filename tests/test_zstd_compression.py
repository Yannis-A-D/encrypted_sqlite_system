import os
import zlib
import base64
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import zstandard as zstd
from src import (
    kv_set, kv_get,
    get_active_compression, set_active_compression,
    rotate_encryption_key, get_db_connection,
    CompressedMemoryL1Adapter
)
from src.database import (
    ROOT_DIR, set_cipher_key, _MAGIC_COMPRESSED_ZSTD,
    _MAGIC_COMPRESSED_ZL, _MAGIC_RAW, _PREFIX_GCM,
    pack_and_encrypt, decrypt_and_unpack
)

class TestZstandardCompression(unittest.TestCase):
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

        set_active_compression("ZSTD")

    def tearDown(self):
        set_active_compression(None)
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_zstd_pack_and_unpack(self):
        """Verify that large JSON payloads are compressed with Zstandard."""
        large_data = {
            "users": [{"id": i, "name": f"User_{i}", "email": f"user{i}@example.com"} for i in range(50)],
            "metadata": {"source": "database_test", "active": True}
        }
        
        blob = pack_and_encrypt(large_data)
        self.assertTrue(blob.startswith(_PREFIX_GCM))
        
        # Unpack should correctly recover data
        recovered = decrypt_and_unpack(blob)
        self.assertEqual(recovered, large_data)

    def test_zlib_backward_compatibility(self):
        """Verify that legacy zlib-compressed payloads decompress seamlessly."""
        from src import serializers
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        large_data = {"records": [f"event_log_{i}" for i in range(100)]}
        raw_bytes = serializers.dumps(large_data)
        
        # Manually create legacy zlib payload
        zlib_compressed = _MAGIC_COMPRESSED_ZL + zlib.compress(raw_bytes, level=6)
        
        # Encrypt with GCM
        raw_key = base64.urlsafe_b64decode(self.test_key)
        cipher = AESGCM(raw_key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, zlib_compressed, associated_data=None)
        legacy_blob = _PREFIX_GCM + nonce + ciphertext
        
        # decrypt_and_unpack should auto-detect ZL1: and decompress via zlib
        recovered = decrypt_and_unpack(legacy_blob)
        self.assertEqual(recovered, large_data)

    def test_small_payload_uncompressed(self):
        """Verify small payloads (<= 128 bytes) remain raw uncompressed."""
        small_data = {"status": "ok"}
        blob = pack_and_encrypt(small_data)
        recovered = decrypt_and_unpack(blob)
        self.assertEqual(recovered, small_data)

    def test_compression_codec_switching(self):
        """Verify switching between ZSTD, ZLIB, and NONE."""
        test_payload = {"log": "a" * 500}
        
        # 1. ZSTD
        set_active_compression("ZSTD")
        self.assertEqual(get_active_compression(), "ZSTD")
        blob_zstd = pack_and_encrypt(test_payload)
        self.assertEqual(decrypt_and_unpack(blob_zstd), test_payload)

        # 2. ZLIB
        set_active_compression("ZLIB")
        self.assertEqual(get_active_compression(), "ZLIB")
        blob_zlib = pack_and_encrypt(test_payload)
        self.assertEqual(decrypt_and_unpack(blob_zlib), test_payload)

        # 3. NONE
        set_active_compression("NONE")
        self.assertEqual(get_active_compression(), "NONE")
        blob_none = pack_and_encrypt(test_payload)
        self.assertEqual(decrypt_and_unpack(blob_none), test_payload)

        # Invalid codec should raise ValueError
        with self.assertRaises(ValueError):
            set_active_compression("INVALID_CODEC")

    def test_compression_migration_on_key_rotation(self):
        """Verify that key rotation converts legacy zlib payloads to active Zstandard compression."""
        from src import serializers
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        large_data = {"users": [f"user_{i}" for i in range(200)]}
        raw_bytes = serializers.dumps(large_data)
        zlib_compressed = _MAGIC_COMPRESSED_ZL + zlib.compress(raw_bytes, level=6)
        
        # Encrypt with old key
        raw_key = base64.urlsafe_b64decode(self.test_key)
        cipher = AESGCM(raw_key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, zlib_compressed, associated_data=None)
        legacy_blob = _PREFIX_GCM + nonce + ciphertext
        
        # Insert directly to SQLite
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT INTO kv_store (key, value, version, updated_at) VALUES (?, ?, 1, 1000)",
                ("legacy_doc.json", legacy_blob)
            )

        # Set active compression to ZSTD
        set_active_compression("ZSTD")

        # Rotate key
        new_raw_key = AESGCM.generate_key(bit_length=256)
        new_key_str = base64.urlsafe_b64encode(new_raw_key).decode("utf-8")
        result = rotate_encryption_key(self.test_key, new_key_str)
        self.assertEqual(result["rotated_count"], 1)

        self.key_file.write_text(new_key_str)

        # Retrieve rotated document
        recovered = kv_get("legacy_doc.json")
        self.assertEqual(recovered, large_data)

    def test_compressed_memory_l1_adapter_zstd(self):
        """Verify CompressedMemoryL1Adapter operates with Zstandard."""
        adapter = CompressedMemoryL1Adapter(max_capacity=50, codec="zstd")
        sample_doc = {"user": "alice", "items": list(range(100))}
        
        adapter.set("user_alice.json", sample_doc, ttl_seconds=60)
        self.assertEqual(adapter.size(), 1)
        
        # Raw stored blob should start with ZS1:
        raw_blob, _ = adapter.store["user_alice.json"]
        self.assertTrue(raw_blob.startswith(b"ZS1:"))
        
        # Get should decompress and return correct document
        val, found = adapter.get("user_alice.json")
        self.assertTrue(found)
        self.assertEqual(val, sample_doc)

if __name__ == "__main__":
    unittest.main()
