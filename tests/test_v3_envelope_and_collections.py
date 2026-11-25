"""
test_v3_envelope_and_collections.py — Tests for v3.0 architectural upgrades:
- Two-layer KEK/DEK envelope encryption & O(1) instant KEK rotation
- Multi-slot emergency recovery passphrases & slot lifecycle management
- Emergency deep DEK re-keying (`deep_rekey=True`)
- Typed `Collection[T]` API with @dataclass hydration, scoped blind indexes, and OCC
- Strongly-typed `IntegrityReport`, `RotationReport`, and `EngineStats` models
"""

import asyncio
from dataclasses import dataclass
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encrypted_sqlite import (
    EncryptedSQLite,
    Collection,
    ConcurrentModificationError,
    IntegrityReport,
    RotationReport,
    EngineStats,
    verify_database_integrity,
    kv_set,
)


@dataclass
class UserProfile:
    username: str
    email: str
    roles: list[str]
    level: int = 1


@dataclass
class AuditEntry:
    actor: str
    email: str
    action: str


def test_kek_dek_envelope_instant_o1_rotation(tmp_path):
    """O(1) KEK rotation must re-wrap DEK without re-encrypting rows, and reject the old KEK."""
    db_file = tmp_path / "envelope_vault.db"
    kek_1 = AESGCM.generate_key(bit_length=256)
    kek_2 = AESGCM.generate_key(bit_length=256)

    with EncryptedSQLite(db_path=db_file, key=kek_1, encrypt_keys=True) as db:
        db.set("user:1", {"name": "Alice", "balance": 500})
        db.set("user:2", {"name": "Bob", "balance": 250})

        conn = db.get_connection()
        raw_blob_before = conn.execute("SELECT value FROM kv_store").fetchone()["value"]

        report = db.rotate_kek(kek_2)
        assert isinstance(report, RotationReport)
        assert report.status == "ok"
        assert report.mode == "kek_envelope_o1"
        assert report["rotated_count"] == 0

        # Row ciphertext on disk is untouched (O(1) rotation)
        raw_blob_after = conn.execute("SELECT value FROM kv_store").fetchone()["value"]
        assert raw_blob_before == raw_blob_after

    # Old KEK must be rejected on reopen
    with pytest.raises(ValueError, match="Unable to unlock vault DEK"):
        EncryptedSQLite(db_path=db_file, key=kek_1)

    # New KEK unlocks and decrypts all existing records
    with EncryptedSQLite(db_path=db_file, key=kek_2, encrypt_keys=True) as db2:
        assert db2.get("user:1") == {"name": "Alice", "balance": 500}
        assert db2.get("user:2") == {"name": "Bob", "balance": 250}


def test_deep_dek_rekey_reencrypts_all_rows(tmp_path):
    """deep_rekey=True must generate a brand-new DEK and re-encrypt every row ciphertext."""
    db_file = tmp_path / "deep_rekey.db"
    kek_1 = AESGCM.generate_key(bit_length=256)
    kek_2 = AESGCM.generate_key(bit_length=256)

    with EncryptedSQLite(db_path=db_file, key=kek_1) as db:
        db.set("k1", {"secret": "alpha"})
        db.set("k2", {"secret": "beta"})
        conn = db.get_connection()
        old_blobs = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM kv_store").fetchall()}

        report = db.rotate_key(kek_2, deep_rekey=True)
        assert report.mode == "deep_dek_rekey"
        assert report.rotated_count == 2

        new_blobs = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM kv_store").fetchall()}
        for k in old_blobs:
            assert new_blobs[k] != old_blobs[k]

    with EncryptedSQLite(db_path=db_file, key=kek_2) as db2:
        assert db2.get("k1") == {"secret": "alpha"}
        assert db2.get("k2") == {"secret": "beta"}


def test_multi_slot_recovery_passphrase_and_removal(tmp_path):
    """Adding an offline passphrase recovery slot must allow unlocking without the primary key."""
    db_file = tmp_path / "multi_slot.db"
    primary_key = AESGCM.generate_key(bit_length=256)
    recovery_phrase = "correct-horse-battery-recovery-2026!"

    with EncryptedSQLite(db_path=db_file, key=primary_key) as db:
        db.set("vault_secret", {"api_token": "tok_live_999"})
        slot_info = db.add_recovery_slot("offline_recovery", recovery_passphrase=recovery_phrase)
        assert slot_info["slot_id"] == "offline_recovery"
        slots = db.list_key_slots()
        assert {s["slot_id"] for s in slots} == {"primary", "offline_recovery"}

    # Wrong passphrase must fail
    with pytest.raises(ValueError, match="Unable to unlock vault DEK"):
        EncryptedSQLite(db_path=db_file, passphrase="wrong-passphrase-attempt")

    # Correct recovery passphrase unlocks the exact same vault!
    with EncryptedSQLite(db_path=db_file, passphrase=recovery_phrase) as db_rec:
        assert db_rec.get("vault_secret") == {"api_token": "tok_live_999"}
        assert db_rec.remove_recovery_slot("offline_recovery") is True
        # Removing the final remaining slot ('primary') must be blocked to prevent lockout
        with pytest.raises(RuntimeError, match="last remaining"):
            db_rec.remove_recovery_slot("primary")


def test_typed_collection_api_and_scoped_indexes(tmp_path):
    """Collection[T] must hydrate dataclasses, enforce OCC, and scope blind-index queries."""
    db_file = tmp_path / "collections.db"
    key = AESGCM.generate_key(bit_length=256)

    with EncryptedSQLite(db_path=db_file, key=key, encrypt_keys=True) as db:
        users: Collection[UserProfile] = db.collection(
            "users", schema=UserProfile, indexes=["email", "roles"]
        )
        audits: Collection[AuditEntry] = db.collection(
            "audits", schema=AuditEntry, indexes=["email"]
        )

        alice = UserProfile(username="alex", email="alex@example.com", roles=["admin", "dev"], level=42)
        bob = UserProfile(username="bob", email="bob@example.com", roles=["member"], level=7)
        users.put("u1", alice)
        users.put("u2", bob)

        # Store an audit entry with the SAME email to prove find_by is collection-scoped
        audits.put("a1", AuditEntry(actor="alex", email="alex@example.com", action="login"))

        loaded = users.get("u1")
        assert isinstance(loaded, UserProfile)
        assert loaded == alice

        # Scoped blind index lookup
        user_hits = users.find_by("email", "alex@example.com")
        assert list(user_hits.keys()) == ["u1"]
        assert isinstance(user_hits["u1"], UserProfile)

        role_hits = users.find_by("roles", "admin")
        assert list(role_hits.keys()) == ["u1"]

        # OCC versioned update + conflict detection
        doc, ver = users.get_versioned("u2")
        assert ver == 1
        new_ver = users.put_versioned("u2", UserProfile("bob", "bob@example.com", ["vip"], level=8), expected_version=ver)
        assert new_ver == 2
        with pytest.raises(ConcurrentModificationError):
            users.put_versioned("u2", bob, expected_version=ver)

        # Batch mput/mget, all(), ids(), count(), delete()
        users.mput({
            "u3": UserProfile("carol", "carol@example.com", ["dev"], 15),
        })
        assert users.count() == 3
        assert set(users.ids()) == {"u1", "u2", "u3"}
        assert len(users.all()) == 3
        assert users.find(lambda u: u.level >= 15) == [alice, UserProfile("carol", "carol@example.com", ["dev"], 15)]

        assert users.delete("u3") is True
        assert users.count() == 2

        # Async collection helpers
        async def _async_check():
            await users.aput("u4", UserProfile("dave", "dave@example.com", ["guest"], 3))
            got = await users.aget("u4")
            found = await users.afind_by("email", "dave@example.com")
            return got, found

        got_u4, found_u4 = asyncio.run(_async_check())
        assert isinstance(got_u4, UserProfile) and got_u4.username == "dave"
        assert "u4" in found_u4


def test_typed_result_models_backward_compatibility(tmp_path):
    """IntegrityReport, RotationReport, and EngineStats must support both attributes and dict access."""
    global_report = verify_database_integrity()
    assert isinstance(global_report, IntegrityReport)
    assert "status" in global_report

    with EncryptedSQLite(db_path=tmp_path / "stats.db", key=AESGCM.generate_key(256)) as db:
        db.set("doc1", {"a": 1})
        report = db.verify_integrity()
        assert isinstance(report, IntegrityReport)
        assert report.status == "clean"
        assert report["status"] == "clean"
        assert report.get("valid_records") == 1
        assert "total_records" in report

        st = db.stats()
        assert isinstance(st, EngineStats)
        assert st.envelope_enabled is True
        assert st.key_slots == 1
        assert st["stored_documents"] == 1
        assert st.get("algorithm") == "AES-256-GCM"
