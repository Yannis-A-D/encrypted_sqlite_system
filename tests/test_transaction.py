import base64
import unittest
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    cache, kv_get, kv_set,
    transaction, async_transaction,
    ChangeEvent, get_db_connection, events
)
from src.database import ROOT_DIR, set_cipher_key


class TestTransactionManager(unittest.TestCase):
    def setUp(self):
        # Clean test key setup
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

        cache.clear_l1()
        events.clear()
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

    def tearDown(self):
        cache.clear_l1()
        events.clear()
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_successful_commit(self):
        """Verify atomic commit persists all documents to SQLite and L1 cache."""
        with cache.transaction() as tx:
            tx.set("wallet:alice", {"balance": 100})
            tx.set("wallet:bob", {"balance": 200})

        # Check L1 cache
        self.assertEqual(cache.get("wallet:alice"), {"balance": 100})
        self.assertEqual(cache.get("wallet:bob"), {"balance": 200})

        # Check L2 SQLite directly by clearing L1
        cache.clear_l1()
        self.assertEqual(kv_get("wallet:alice"), {"balance": 100})
        self.assertEqual(kv_get("wallet:bob"), {"balance": 200})

    def test_rollback_on_exception(self):
        """Verify all staged writes are discarded if an exception is raised."""
        try:
            with cache.transaction() as tx:
                tx.set("wallet:alice", {"balance": 50})
                tx.set("wallet:bob", {"balance": 250})
                raise RuntimeError("Simulated transaction failure!")
        except RuntimeError:
            pass

        # Neither key should exist in L1 or L2
        self.assertIsNone(cache.get("wallet:alice"))
        self.assertIsNone(cache.get("wallet:bob"))

        cache.clear_l1()
        self.assertIsNone(kv_get("wallet:alice"))
        self.assertIsNone(kv_get("wallet:bob"))

    def test_read_your_own_writes(self):
        """Verify reading staged uncommitted writes within the transaction block."""
        cache.set("item.json", {"stock": 10})

        with cache.transaction() as tx:
            # Before staging, sees current value
            self.assertEqual(tx.get("item.json"), {"stock": 10})

            # Stage modification
            tx.set("item.json", {"stock": 9})
            # Staged write is immediately visible inside tx
            self.assertEqual(tx.get("item.json"), {"stock": 9})

            # Outside transaction still sees unmodified value
            self.assertEqual(cache.get("item.json"), {"stock": 10})

        # After commit, new value is visible globally
        self.assertEqual(cache.get("item.json"), {"stock": 9})

    def test_read_your_own_deletes(self):
        """Verify reading staged uncommitted deletes within the transaction block."""
        cache.set("item_del.json", {"active": True})

        with cache.transaction() as tx:
            self.assertEqual(tx.get("item_del.json"), {"active": True})
            tx.delete("item_del.json")

            # Staged delete returns default inside tx
            self.assertIsNone(tx.get("item_del.json"))

            # Outside tx, item is still present until commit
            self.assertEqual(cache.get("item_del.json"), {"active": True})

        # After commit, item is deleted globally
        self.assertIsNone(cache.get("item_del.json"))

    def test_mixed_writes_and_deletes(self):
        """Verify atomic commit with both sets and deletes in a single transaction."""
        cache.set("del_me.json", {"to_delete": True})

        with cache.transaction() as tx:
            tx.delete("del_me.json")
            tx.set("new_1.json", {"n": 1})
            tx.set("new_2.json", {"n": 2})

        self.assertIsNone(cache.get("del_me.json"))
        self.assertEqual(cache.get("new_1.json"), {"n": 1})
        self.assertEqual(cache.get("new_2.json"), {"n": 2})

    def test_cdc_events_only_on_commit(self):
        """Verify that reactive CDC events are only emitted if transaction succeeds."""
        emitted_writes = []

        @cache.on("write")
        def on_write(event: ChangeEvent):
            emitted_writes.append(event.key)

        # 1. Rollback case: events should NOT be emitted
        try:
            with cache.transaction() as tx:
                tx.set("fail_tx.json", {"x": 1})
                raise ValueError("Crash")
        except ValueError:
            pass

        self.assertEqual(len(emitted_writes), 0)

        # 2. Commit case: events should be emitted
        with cache.transaction() as tx:
            tx.set("success_tx.json", {"x": 2})

        self.assertEqual(emitted_writes, ["success_tx.json"])

    def test_async_transaction(self):
        """Verify async transaction context manager."""
        async def _run():
            async with async_transaction() as tx:
                await tx.set("async:tx1", {"data": 123})
                val = await tx.get("async:tx1")
                self.assertEqual(val, {"data": 123})

            # Verify persisted
            self.assertEqual(cache.get("async:tx1"), {"data": 123})

            # Test async rollback
            try:
                async with async_transaction() as tx:
                    await tx.set("async:tx2", {"data": 456})
                    raise RuntimeError("Async rollback")
            except RuntimeError:
                pass

            self.assertIsNone(cache.get("async:tx2"))

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
