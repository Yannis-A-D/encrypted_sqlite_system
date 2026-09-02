import time
import base64
import unittest
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    kv_set, kv_delete, purge_expired_records,
    cache, events, ChangeEvent, get_db_connection
)
from src.database import ROOT_DIR, set_cipher_key


class TestEventsAndCDC(unittest.TestCase):
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

    def test_write_event_on_cache_set(self):
        """Verify that cache.set triggers write event."""
        captured = []

        @cache.on("write")
        def on_write(event: ChangeEvent):
            captured.append(event)

        cache.set("profile.json", {"name": "Alice"})

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].event_type, "write")
        self.assertEqual(captured[0].key, "profile.json")
        self.assertEqual(captured[0].value, {"name": "Alice"})

    def test_write_event_on_kv_set(self):
        """Verify that low-level kv_set also triggers write event."""
        captured = []

        def on_write(key, value):
            captured.append((key, value))

        events.on("write", on_write)
        kv_set("config.json", {"theme": "dark"})

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0], ("config.json", {"theme": "dark"}))

    def test_delete_event_on_kv_delete(self):
        """Verify delete event is emitted on deletion."""
        captured = []

        @cache.on("delete")
        def on_delete(event: ChangeEvent):
            captured.append(event.key)

        kv_set("doc_to_delete.json", {"data": 123})
        deleted = kv_delete("doc_to_delete.json")
        self.assertTrue(deleted)

        self.assertEqual(captured, ["doc_to_delete.json"])

    def test_pattern_filtering(self):
        """Verify glob pattern matching only triggers on matching keys."""
        user_events = []
        order_events = []

        @cache.on("write", pattern="user_*.json")
        def on_user(event: ChangeEvent):
            user_events.append(event.key)

        @cache.on("write", pattern="order_*.json")
        def on_order(event: ChangeEvent):
            order_events.append(event.key)

        cache.set("user_1.json", {"name": "Bob"})
        cache.set("order_99.json", {"total": 50})
        cache.set("system_settings.json", {"maintenance": False})

        self.assertEqual(user_events, ["user_1.json"])
        self.assertEqual(order_events, ["order_99.json"])

    def test_wildcard_change_event(self):
        """Verify 'change' event captures both writes and deletes."""
        changes = []

        @cache.on("change")
        def on_change(event: ChangeEvent):
            changes.append((event.event_type, event.key))

        cache.set("item.json", {"val": 1})
        kv_delete("item.json")

        self.assertEqual(changes, [("write", "item.json"), ("delete", "item.json")])

    def test_expire_event_on_purge(self):
        """Verify expire events are dispatched when TTL records are purged."""
        expired_keys = []

        @cache.on("expire")
        def on_expire(event: ChangeEvent):
            expired_keys.append(event.key)

        kv_set("temp1.json", {"t": 1}, ttl=1)
        kv_set("temp2.json", {"t": 2}, ttl=1)
        kv_set("perm.json", {"p": 3})

        time.sleep(1.2)
        purged = purge_expired_records()
        self.assertEqual(purged, 2)

        self.assertIn("temp1.json", expired_keys)
        self.assertIn("temp2.json", expired_keys)
        self.assertNotIn("perm.json", expired_keys)

    def test_unsubscribe(self):
        """Verify events.off() stops callbacks."""
        calls = []

        def my_listener(evt):
            calls.append(evt.key)

        cache.on("write", my_listener)
        cache.set("k1.json", {"v": 1})
        self.assertEqual(len(calls), 1)

        unsub_ok = cache.off("write", my_listener)
        self.assertTrue(unsub_ok)

        cache.set("k2.json", {"v": 2})
        self.assertEqual(len(calls), 1)  # No new call

    def test_listener_exception_isolation(self):
        """Verify that an exception in a listener does not abort database write."""
        @cache.on("write")
        def buggy_listener(evt):
            raise RuntimeError("Listener bug!")

        # Write should succeed despite buggy listener
        cache.set("safe.json", {"safe": True})
        self.assertEqual(cache.get("safe.json"), {"safe": True})

    def test_async_listener(self):
        """Verify async coroutine functions work as event listeners."""
        async_events = []

        async def async_on_write(event: ChangeEvent):
            await asyncio.sleep(0.01)
            async_events.append(event.key)

        cache.on("write", async_on_write)

        async def _run():
            cache.set("async_doc.json", {"status": "ok"})
            await asyncio.sleep(0.05)  # Yield for task execution
            self.assertIn("async_doc.json", async_events)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
