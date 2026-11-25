"""
test_v2_improvements_suite.py — Comprehensive tests for Phase 1, 2, and 3 upgrades:
- Scalable BLAKE2b Bloom filter auto-slicing
- Streaming chunked AEAD snapshot encryption, truncation/tamper detection & legacy ENCSNAP1 compatibility
- Cloud restore live connection/L1/Bloom reset
- Nested dot-path & list blind indexing
- Deterministic Synthetic-IV primary key encryption (ENCK1:) + rotation + search
- Chunked kv_mget (>999 SQL variables)
- Configurable save_json(mirror_to_disk=False)
- Proper `encrypted_sqlite` package namespace & multi-instance `EncryptedSQLite` engine isolation
- Zero-knowledge encrypted RedisL1Adapter & copy-isolated MemoryL1Adapter
- HKDF v2 cipher subkey domain separation & legacy v1 backward compatibility
- Path traversal protection, keyed HMAC PII hashing, WriteBehind re-queueing & mset db_ttl
- Format-tagged MP1: serializer cross-decoding
"""

import os
import time
import base64
import struct
import sqlite3
import asyncio
import hashlib
from unittest.mock import MagicMock, patch
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import encrypted_sqlite as es
from encrypted_sqlite import (
    EncryptedSQLite,
    BloomFilter,
    MemoryL1Adapter,
    RedisL1Adapter,
    TwoTierCache,
    WriteBehindEngine,
    Transaction,
    ConcurrentModificationError,
    kv_get,
    kv_set,
    kv_mget,
    kv_mset,
    kv_delete,
    kv_search,
    kv_find,
    kv_find_by_index,
    set_indexed_fields,
    set_key_encryption,
    get_key_encryption,
    rotate_encryption_key,
    verify_database_integrity,
    purge_expired_records,
    save_json,
    load_json,
    mask_pii,
    serializers,
)
from src.cloud_sync import encrypt_snapshot_file, decrypt_snapshot_file, CloudSyncEngine, _LEGACY_MAGIC
from src.database import get_db_connection, set_cipher_key, DATA_DIR, _PREFIX_GCM, _SUBKEY_V2_TAG


class _MockRedis:
    def __init__(self):
        self.data = {}
        self.ttls = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, val):
        self.data[key] = val

    def setex(self, key, ttl, val):
        self.data[key] = val
        self.ttls[key] = ttl

    def delete(self, *keys):
        for k in keys:
            self.data.pop(k, None)

    def scan_iter(self, match="*", count=100):
        prefix = match.rstrip("*")
        for k in list(self.data.keys()):
            if k.startswith(prefix):
                yield k


# ─── Phase 3 Tests: Performance & Query Upgrades ──────────────────────────────


def test_scalable_blake2b_bloom_filter_slices():
    """Bloom filter must automatically add slices past initial capacity with zero false negatives."""
    bf = BloomFilter(expected_elements=1000, false_positive_rate=0.01)
    assert bf.slice_count == 1

    keys = [f"item_{i}.json" for i in range(2500)]
    for k in keys:
        bf.add(k)

    assert bf.slice_count >= 2
    for k in keys:
        assert bf.contains(k) is True
    assert bf.contains("never_inserted_xyz_999999") is False


def test_streaming_chunked_snapshot_and_legacy_compat(tmp_path):
    """Streaming chunked AEAD snapshot must support multi-chunk files, reject truncation, and read legacy ENCSNAP1."""
    raw_key = AESGCM.generate_key(bit_length=256)
    src = tmp_path / "large.db"
    # 10 KB across 1 KB streaming chunks -> 10 authenticated chunks
    payload = os.urandom(10 * 1024 + 333)
    src.write_bytes(payload)

    enc = tmp_path / "large.db.enc"
    dec = tmp_path / "large.db.dec"

    encrypt_snapshot_file(src, enc, raw_key=raw_key, chunk_size=1024)
    assert enc.read_bytes().startswith(b"ENCSNAP1:CHK1:")

    decrypt_snapshot_file(enc, dec, raw_key=raw_key)
    assert dec.read_bytes() == payload

    # Truncating the last chunk must raise ValueError (truncation attack protection)
    truncated = tmp_path / "truncated.db.enc"
    enc_bytes = enc.read_bytes()
    truncated.write_bytes(enc_bytes[:-40])
    with pytest.raises(Exception):
        decrypt_snapshot_file(truncated, tmp_path / "out_bad.db", raw_key=raw_key)
    assert not (tmp_path / "out_bad.db").exists()

    # Legacy whole-file ENCSNAP1: compatibility
    legacy_file = tmp_path / "legacy.db.enc"
    nonce = os.urandom(12)
    legacy_ct = AESGCM(raw_key).encrypt(nonce, b"legacy-sqlite-bytes", associated_data=b"sqlite-snapshot-envelope-v1")
    legacy_file.write_bytes(_LEGACY_MAGIC + nonce + legacy_ct)

    legacy_dec = tmp_path / "legacy_out.db"
    decrypt_snapshot_file(legacy_file, legacy_dec, raw_key=raw_key)
    assert legacy_dec.read_bytes() == b"legacy-sqlite-bytes"


def test_cloud_restore_resets_live_connections_and_cache(tmp_path):
    """restore_from_cloud on an EncryptedSQLite engine must swap DB, reset connections, and clear L1."""
    db_file = tmp_path / "live.db"
    key = AESGCM.generate_key(bit_length=256)
    with EncryptedSQLite(db_path=db_file, key=key) as eng:
        eng.set("doc_before", {"state": "v1"})
        sync = CloudSyncEngine(bucket_name="bkt", engine=eng)
        snap = sync.create_local_snapshot("snap_v1")
        enc_snap = tmp_path / "snap_v1.db.enc"
        encrypt_snapshot_file(snap, enc_snap, raw_key=key)

        # Mutate live DB after snapshot
        eng.set("doc_before", {"state": "v2_mutated"})
        eng.set("doc_extra", {"extra": True})
        assert eng.get("doc_before")["state"] == "v2_mutated"

        mock_s3 = MagicMock()
        def _fake_download(bucket, rkey, fileobj):
            fileobj.write(enc_snap.read_bytes())
        mock_s3.download_fileobj.side_effect = _fake_download

        assert sync.restore_from_cloud("backups/snap_v1.db.enc", client=mock_s3) is True
        assert eng.get("doc_before") == {"state": "v1"}
        assert eng.get("doc_extra") is None


def test_nested_dot_path_and_list_blind_indexing():
    """Blind indexing must index nested dot paths and multi-value array elements."""
    try:
        set_indexed_fields(["profile.email", "tags", "accounts.provider"])
        kv_set("nested_u1", {
            "profile": {"email": "nested@domain.io"},
            "tags": ["gold", "beta_tester"],
            "accounts": [{"provider": "github"}, {"provider": "discord"}],
        })
        kv_set("nested_u2", {
            "profile": {"email": "other@domain.io"},
            "tags": ["beta_tester", "staff"],
            "accounts": [{"provider": "gitlab"}],
        })

        by_email = kv_find_by_index("profile.email", "nested@domain.io")
        assert list(by_email.keys()) == ["nested_u1"]

        by_tag = kv_find_by_index("tags", "beta_tester")
        assert set(by_tag.keys()) == {"nested_u1", "nested_u2"}

        by_provider = kv_find_by_index("accounts.provider", "discord")
        assert list(by_provider.keys()) == ["nested_u1"]
    finally:
        set_indexed_fields([])
        kv_delete("nested_u1")
        kv_delete("nested_u2")


def test_deterministic_siv_key_encryption_and_rotation():
    """When key encryption is enabled, SQLite keys must be ENCK1: ciphertexts while all operations work."""
    old_k = Fernet.generate_key().decode()
    new_k = Fernet.generate_key().decode()
    set_cipher_key(old_k)
    set_key_encryption(True)
    set_indexed_fields(["role"])
    try:
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

        kv_set("secret_user_alpha.json", {"role": "architect", "clearance": 5})
        kv_set("secret_user_beta.json", {"role": "operator", "clearance": 3})

        # Verify raw SQLite table has NO plaintext key names
        raw_rows = conn.execute("SELECT key FROM kv_store").fetchall()
        assert len(raw_rows) == 2
        for r in raw_rows:
            assert r["key"].startswith("ENCK1:")
            assert "secret_user" not in r["key"]

        # Lookups, wildcard search, blind index, integrity audit, and key rotation all work
        assert kv_get("secret_user_alpha.json")["clearance"] == 5
        found_keys = kv_search("secret_user_*.json")
        assert set(found_keys) == {"secret_user_alpha.json", "secret_user_beta.json"}
        assert "secret_user_alpha.json" in kv_find_by_index("role", "architect")
        assert verify_database_integrity()["status"] == "clean"

        rot = rotate_encryption_key(old_k, new_k, strict=True)
        assert rot["rotated_count"] == 2
        assert kv_get("secret_user_alpha.json")["clearance"] == 5
        assert "secret_user_beta.json" in kv_find_by_index("role", "operator")
    finally:
        set_key_encryption(None)
        set_indexed_fields([])


def test_chunked_kv_mget_exceeding_sqlite_var_limit():
    """kv_mget must handle >1,100 keys without hitting SQLite's 999 parameter limit."""
    batch = {f"bulk_k_{i}": {"idx": i} for i in range(1150)}
    kv_mset(batch)
    fetched = kv_mget(list(batch.keys()))
    assert len(fetched) == 1150
    assert fetched["bulk_k_0"] == {"idx": 0}
    assert fetched["bulk_k_1149"] == {"idx": 1149}


def test_save_json_mirror_to_disk_false():
    """save_json(..., mirror_to_disk=False) must skip writing flat disk mirror files."""
    key = "no_mirror_doc.json"
    disk_file = DATA_DIR / key
    disk_file.unlink(missing_ok=True)

    save_json(key, {"fast": True}, mirror_to_disk=False)
    assert not disk_file.exists()
    assert load_json(key) == {"fast": True}
    kv_delete(key)


# ─── Phase 2 Tests: Package Namespace & Multi-Instance Engine ─────────────────


def test_package_namespace_and_isolated_engines(tmp_path):
    """encrypted_sqlite namespace must alias src and EncryptedSQLite instances must be fully isolated."""
    from src import cache as src_cache
    assert es.cache is src_cache

    k_a = AESGCM.generate_key(bit_length=256)
    k_b = AESGCM.generate_key(bit_length=256)

    with (
        EncryptedSQLite(
            db_path=tmp_path / "vault_a.db",
            key=k_a,
            algorithm="AES-256-GCM",
            encrypt_keys=True,
            indexed_fields=["dept"],
        ) as db_a,
        EncryptedSQLite(
            db_path=tmp_path / "vault_b.db",
            key=k_b,
            algorithm="CHACHA20-POLY1305",
            encrypt_keys=False,
            indexed_fields=["tags"],
        ) as db_b,
    ):
        db_a.set("shared_name", {"vault": "A", "dept": "crypto"})
        db_b.set("shared_name", {"vault": "B", "tags": ["infra", "ops"]})

        assert db_a.get("shared_name")["vault"] == "A"
        assert db_b.get("shared_name")["vault"] == "B"
        assert "shared_name" in db_a.find_by_index("dept", "crypto")
        assert "shared_name" in db_b.find_by_index("tags", "ops")

        # Transaction + OCC on isolated instance
        with db_a.transaction() as tx:
            cur = tx.get("shared_name")
            tx.set("shared_name", {**cur, "level": 2})
        assert db_a.get("shared_name")["level"] == 2

        # Async API on isolated instance
        async def _check_async():
            await db_b.aset("async_k", {"ok": 123})
            return await db_b.aget("async_k")

        assert asyncio.run(_check_async()) == {"ok": 123}


# ─── Phase 1 Tests: Security Hardening & Concurrency Bug Fixes ────────────────


def test_redis_l1_adapter_encrypts_payloads_and_binds_aad():
    """RedisL1Adapter must store ENC1: ciphertext in Redis and reject cross-key ciphertext swaps."""
    mock_r = _MockRedis()
    c = TwoTierCache()
    c.use_redis(mock_r, prefix="sec:l1:")

    secret_doc = {"ssn": "999-00-1234", "token": "super_secret_token"}
    c.set("u1", secret_doc, ttl=60)
    c.set("u2", {"other": 1}, ttl=60)

    raw_stored = mock_r.data["sec:l1:u1"]
    assert isinstance(raw_stored, str) and raw_stored.startswith("ENC1:")
    assert "super_secret_token" not in raw_stored
    assert "999-00-1234" not in raw_stored
    assert c.get("u1") == secret_doc

    # Swapping Redis ciphertext from u1 onto u2 must fail AAD check on L1 and fall back cleanly to L2
    mock_r.data["sec:l1:u2"] = raw_stored
    assert c.get("u2") == {"other": 1}


def test_memory_l1_adapter_mutable_reference_isolation():
    """Mutating dicts before or after L1 cache get/set must never corrupt cached values."""
    adapter = MemoryL1Adapter(max_capacity=10)
    original = {"wallet": 100, "items": ["sword"]}
    adapter.set("p1", original)

    # Mutate input dict after set
    original["wallet"] = 0
    original["items"].append("hacked")

    fetched, hit = adapter.get("p1")
    assert hit is True
    assert fetched == {"wallet": 100, "items": ["sword"]}

    # Mutate returned dict after get
    fetched["wallet"] = -9999
    fetched_again, _ = adapter.get("p1")
    assert fetched_again == {"wallet": 100, "items": ["sword"]}


def test_hkdf_v2_subkey_domain_separation_and_legacy_v1_fallback():
    """New writes must use v2: HKDF subkeys while legacy v1 ciphertexts still decrypt seamlessly."""
    raw_k = AESGCM.generate_key(bit_length=256)
    b64_k = base64.urlsafe_b64encode(raw_k).decode("ascii")
    set_cipher_key(b64_k)

    os.environ["ENCRYPTION_ALGORITHM"] = "AES-256-GCM"
    kv_set("v2_subkey_doc", {"gen": 2})
    conn = get_db_connection()
    blob = conn.execute("SELECT value FROM kv_store WHERE key = ?", ("v2_subkey_doc",)).fetchone()["value"]
    assert blob.startswith(_PREFIX_GCM + _SUBKEY_V2_TAG)

    # Raw master key AESGCM cannot directly decrypt v2 subkey ciphertext (proving domain separation)
    nonce = blob[8:20]
    ct = blob[20:]
    with pytest.raises(Exception):
        AESGCM(raw_k).decrypt(nonce, ct, associated_data=b"v2_subkey_doc")

    # Legacy v1 GCM blob written with raw key still decrypts seamlessly
    legacy_nonce = os.urandom(12)
    legacy_ct = AESGCM(raw_k).encrypt(legacy_nonce, b'RW1:{"gen":1}', associated_data=b"v1_legacy_doc")
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, version, expires_at, updated_at) VALUES (?, ?, 1, 0, 1)",
            ("v1_legacy_doc", _PREFIX_GCM + legacy_nonce + legacy_ct),
        )
    es.bloom.add("v1_legacy_doc")
    assert kv_get("v1_legacy_doc") == {"gen": 1}


def test_path_traversal_blocked_in_secure_json_and_kv_delete(tmp_path):
    """Relative traversal keys must raise ValueError in secure_json and never unlink outside DATA_DIR."""
    outside_victim = DATA_DIR.parent / "do_not_delete_test_victim.txt"
    outside_victim.write_text("safe", encoding="utf-8")
    try:
        with pytest.raises(ValueError):
            save_json("../do_not_delete_test_victim.txt", {"bad": 1})
        with pytest.raises(ValueError):
            load_json("../do_not_delete_test_victim.txt")

        kv_delete("../do_not_delete_test_victim.txt")
        assert outside_victim.exists()
    finally:
        outside_victim.unlink(missing_ok=True)


def test_keyed_hmac_gdpr_hash_masking():
    """GDPR hash strategy must use keyed HMAC-SHA256 rather than unsalted rainbow-vulnerable SHA-256."""
    email = "alice@example.com"
    unsalted_sha = f"hash:{hashlib.sha256(email.encode('utf-8')).hexdigest()[:12]}"
    masked_1 = mask_pii({"email": email}, strategy="hash", secret_key=b"key-one-32-bytes-000000000000000")["email"]
    masked_2 = mask_pii({"email": email}, strategy="hash", secret_key=b"key-two-32-bytes-111111111111111")["email"]

    assert masked_1.startswith("hash:")
    assert masked_1 != unsalted_sha
    assert masked_1 != masked_2


def test_write_behind_requeues_on_sqlite_failure_and_mset_preserves_db_ttl():
    """WriteBehindEngine must re-queue failed flushes without data loss and honor db_ttl in mset."""
    wb = WriteBehindEngine(flush_interval=10.0, max_batch_size=100)
    try:
        wb.queue_write("wb_durable_1", {"v": 1})

        # Simulate transient SQLite lock failure during _upsert_kv_batch
        with patch("src.database._upsert_kv_batch", side_effect=sqlite3.OperationalError("database is locked")):
            with pytest.raises(sqlite3.OperationalError):
                wb.flush()

        # Item must still be queued and succeed on the next flush!
        assert wb.get_stats()["pending_writes"] == 1
        wb.flush()
        assert wb.get_stats()["pending_writes"] == 0
        assert kv_get("wb_durable_1") == {"v": 1}
    finally:
        wb.close()

    # Verify TwoTierCache.mset passes db_ttl in write_behind mode
    c = TwoTierCache(write_behind=True)
    try:
        c.mset({"wb_ttl_item": {"temp": True}}, ttl=0.3, db_ttl=1.0)
        c.flush()
        conn = get_db_connection()
        row = conn.execute("SELECT expires_at FROM kv_store WHERE key = 'wb_ttl_item'").fetchone()
        assert row is not None and row["expires_at"] > 0
    finally:
        c.disable_write_behind()


def test_msgpack_tagged_payload_loads_cleanly():
    """Payloads prefixed with MP1: must decode cleanly even if orjson/json is active."""
    try:
        import msgpack
        tagged = b"MP1:" + msgpack.packb({"format": "msgpack", "items": [1, 2, 3]}, use_bin_type=True)
        assert serializers.loads(tagged) == {"format": "msgpack", "items": [1, 2, 3]}
    except ImportError:
        pass
