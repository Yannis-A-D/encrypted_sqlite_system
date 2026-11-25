"""
transaction.py — Atomic Multi-Key Transaction Manager.

Provides serializable ACID multi-key transactions across L1 in-memory cache and L2 SQLite
with Read-Your-Own-Writes, BEGIN IMMEDIATE write-lock OCC verification (eliminating TOCTOU
races), mutation isolation, and automatic rollback on failure.
"""

import copy
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
        self._read_versions: dict[str, int] = {}
        self._active: bool = True
        self._committed: bool = False
        self._rolled_back: bool = False

    @property
    def is_active(self) -> bool:
        return self._active

    def set(self, key: str, value: Any, ttl: float | None = None):
        """Stage a document write within the transaction buffer (copy-isolated)."""
        if not self._active:
            raise RuntimeError("Transaction is closed and cannot accept new writes.")
        self._staged_deletes.discard(key)
        self._staged_writes[key] = (copy.deepcopy(value), ttl)

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
        2. If key was staged for write in this tx, return deep-copied staged value.
        3. Otherwise, fetch current value & version from underlying SQLite store.
        """
        if not self._active:
            raise RuntimeError("Transaction is closed.")
        if key in self._staged_deletes:
            return default
        if key in self._staged_writes:
            return copy.deepcopy(self._staged_writes[key][0])

        from .database import kv_get_versioned
        val, ver = kv_get_versioned(key, default=default)
        if key not in self._read_versions:
            self._read_versions[key] = ver
        return copy.deepcopy(val)

    def commit(self):
        """Atomically verify read versions under BEGIN IMMEDIATE and commit all staged mutations."""
        if not self._active:
            raise RuntimeError("Transaction is already closed.")

        if not self._staged_writes and not self._staged_deletes:
            self._active = False
            self._committed = True
            return

        from .database import (
            get_db_connection,
            pack_and_encrypt,
            _upsert_kv_batch,
            _lookup_storage_row,
            _to_storage_key,
            bloom,
            init_db,
            ConcurrentModificationError,
        )
        from .metrics import metrics
        from .events import events

        init_db()
        conn = get_db_connection()
        now_ts = int(time.time())

        # Pre-encrypt staged writes before acquiring the SQLite RESERVED lock
        batch_records = []
        raw_items = []
        for key, (data, ttl) in self._staged_writes.items():
            encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
            expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
            storage_key = _to_storage_key(key)
            batch_records.append((storage_key, encrypted_blob, expires_at, now_ts))
            raw_items.append((key, data))

        # Acquire SQLite RESERVED write lock immediately so version checks + writes are atomic (zero TOCTOU)
        conn.execute("BEGIN IMMEDIATE")
        try:
            if self._read_versions:
                for r_key, expected_ver in self._read_versions.items():
                    if r_key in self._staged_writes or r_key in self._staged_deletes:
                        row = _lookup_storage_row(conn, r_key, "version")
                        current_ver = row["version"] if row else 0
                        if current_ver != expected_ver:
                            raise ConcurrentModificationError(
                                f"Optimistic lock conflict on key '{r_key}': version was {expected_ver} at read time, but is now {current_ver}."
                            )

            if self._staged_deletes:
                delete_candidates = []
                for dk in self._staged_deletes:
                    sk = _to_storage_key(dk)
                    delete_candidates.append((sk,))
                    if sk != dk:
                        delete_candidates.append((dk,))
                conn.executemany("DELETE FROM blind_indexes WHERE key = ?", delete_candidates)
                conn.executemany("DELETE FROM kv_store WHERE key = ?", delete_candidates)

            if batch_records:
                _upsert_kv_batch(conn, batch_records, raw_items)

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            self.rollback()
            raise

        # Synchronize L1 RAM cache and Bloom Filter after durable commit
        for key in self._staged_deletes:
            self._cache._adapter.delete(key)

        for key, (data, ttl) in self._staged_writes.items():
            self._cache.set_l1_only(key, data, ttl)
            bloom.add(key)

        try:
            if self._staged_writes:
                metrics.record_operation("write", count=len(self._staged_writes))
            if self._staged_deletes:
                metrics.record_operation("delete", count=len(self._staged_deletes))
        except Exception:
            pass

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
            return False
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
