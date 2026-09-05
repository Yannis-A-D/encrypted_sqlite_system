"""
transaction.py — Atomic Multi-Key Transaction Manager.

Provides ACID multi-key transactions across L1 in-memory cache and L2 SQLite
with Read-Your-Own-Writes and automatic rollback on failure.
"""

import time
import asyncio
from typing import Any
from .cache import cache as default_cache, TwoTierCache


class Transaction:
    """Synchronous Multi-Key Atomic Transaction Context."""

    def __init__(self, cache_instance: TwoTierCache | None = None):
        self._cache = cache_instance or default_cache
        self._staged_writes: dict[str, tuple[Any, float | None]] = {}
        self._staged_deletes: set[str] = set()
        self._active: bool = True
        self._committed: bool = False
        self._rolled_back: bool = False

    @property
    def is_active(self) -> bool:
        return self._active

    def set(self, key: str, value: Any, ttl: float | None = None):
        """Stage a document write within the transaction buffer."""
        if not self._active:
            raise RuntimeError("Transaction is closed and cannot accept new writes.")
        self._staged_deletes.discard(key)
        self._staged_writes[key] = (value, ttl)

    def delete(self, key: str):
        """Stage a document deletion within the transaction buffer."""
        if not self._active:
            raise RuntimeError("Transaction is closed and cannot accept deletions.")
        self._staged_writes.pop(key, None)
        self._staged_deletes.add(key)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Read-Your-Own-Writes:
        1. If key was staged for deletion in this tx, return default.
        2. If key was staged for write in this tx, return staged value.
        3. Otherwise, fetch current value from underlying cache / SQLite.
        """
        if not self._active:
            raise RuntimeError("Transaction is closed.")
        if key in self._staged_deletes:
            return default
        if key in self._staged_writes:
            return self._staged_writes[key][0]
        return self._cache.get(key, default=default)

    def commit(self):
        """Atomically commit all staged writes and deletes to SQLite and L1 cache."""
        if not self._active:
            raise RuntimeError("Transaction is already closed.")

        if not self._staged_writes and not self._staged_deletes:
            self._active = False
            self._committed = True
            return

        from .database import (
            get_db_connection,
            pack_and_encrypt,
            _update_blind_indexes,
            bloom,
            init_db
        )
        from .metrics import metrics
        from .events import events

        init_db()
        conn = get_db_connection()
        now_ts = int(time.time())

        # Prepare batch writes
        batch_records = []
        for key, (data, ttl) in self._staged_writes.items():
            encrypted_blob = pack_and_encrypt(data)
            expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
            batch_records.append((key, encrypted_blob, expires_at, now_ts))

        # Single atomic SQL transaction
        with conn:
            if self._staged_deletes:
                delete_keys = list(self._staged_deletes)
                conn.executemany("DELETE FROM blind_indexes WHERE key = ?", [(k,) for k in delete_keys])
                conn.executemany("DELETE FROM kv_store WHERE key = ?", [(k,) for k in delete_keys])

            if batch_records:
                conn.executemany("""
                    INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        version = version + 1,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at;
                """, batch_records)
                for key, (data, _) in self._staged_writes.items():
                    _update_blind_indexes(conn, key, data)

        # Synchronize L1 RAM cache and Bloom Filter
        for key in self._staged_deletes:
            self._cache._adapter.delete(key)

        for key, (data, ttl) in self._staged_writes.items():
            self._cache.set_l1_only(key, data, ttl)
            bloom.add(key)

        # Telemetry & Metrics
        try:
            if self._staged_writes:
                metrics.record_operation("write", count=len(self._staged_writes))
            if self._staged_deletes:
                metrics.record_operation("delete", count=len(self._staged_deletes))
        except Exception:
            pass

        # Reactive Event Dispatching
        try:
            for key in self._staged_deletes:
                events.emit("delete", key=key)
            for key, (data, _) in self._staged_writes.items():
                events.emit("write", key=key, value=data)
        except Exception:
            pass

        self._active = False
        self._committed = True

    def rollback(self):
        """Discard all uncommitted staged operations."""
        self._staged_writes.clear()
        self._staged_deletes.clear()
        self._active = False
        self._rolled_back = True

    def __enter__(self) -> "Transaction":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
            return False  # Re-raise exception
        else:
            if self._active:
                self.commit()
            return True


class AsyncTransaction:
    """Asynchronous Multi-Key Atomic Transaction Context."""

    def __init__(self, cache_instance: TwoTierCache | None = None):
        self._tx = Transaction(cache_instance=cache_instance)

    @property
    def is_active(self) -> bool:
        return self._tx.is_active

    async def set(self, key: str, value: Any, ttl: float | None = None):
        self._tx.set(key, value, ttl=ttl)

    async def delete(self, key: str):
        self._tx.delete(key)

    async def get(self, key: str, default: Any = None) -> Any:
        return await asyncio.to_thread(self._tx.get, key, default)

    async def commit(self):
        await asyncio.to_thread(self._tx.commit)

    async def rollback(self):
        self._tx.rollback()

    async def __aenter__(self) -> "AsyncTransaction":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.rollback()
            return False
        else:
            if self._tx.is_active:
                await self.commit()
            return True


def transaction(cache_instance: TwoTierCache | None = None) -> Transaction:
    """Create a new synchronous atomic multi-key transaction."""
    return Transaction(cache_instance=cache_instance)


def async_transaction(cache_instance: TwoTierCache | None = None) -> AsyncTransaction:
    """Create a new asynchronous atomic multi-key transaction."""
    return AsyncTransaction(cache_instance=cache_instance)
