"""
write_behind.py — High-Throughput Asynchronous Write-Behind Journaling Engine.

Coalesces high-frequency writes in an in-memory queue and flushes them to SQLite
in atomic batch transactions via a background daemon worker thread.

Durability & Isolation:
- Copy-isolates queued payloads at enqueue time.
- Re-queues uncommitted items automatically if SQLite raises a transient lock/IO error,
  without clobbering newer writes to the same key.
- Supports deterministic key encryption (ENCK1:).
"""

import copy
import time
import atexit
import threading
from typing import Any
from collections import OrderedDict


class WriteBehindEngine:
    """Asynchronous Write-Behind Batch Journal for SQLite."""

    def __init__(self, flush_interval: float = 0.1, max_batch_size: int = 250):
        self.flush_interval = flush_interval
        self.max_batch_size = max_batch_size
        self._queue: OrderedDict[str, tuple[Any, float | None]] = OrderedDict()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._last_flush = time.time()
        self._flushes_count = 0
        self._items_flushed_count = 0
        self._failed_flushes_count = 0

        # Background worker thread
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="WriteBehind-Worker"
        )
        self._worker_thread.start()

        # Register auto-flush on application exit
        atexit.register(self.flush)

    def queue_write(self, key: str, data: Any, ttl: float | None = None):
        """Enqueue a document write with optional TTL (coalesces duplicate writes to the same key)."""
        cloned = copy.deepcopy(data)
        with self._lock:
            self._queue[key] = (cloned, ttl)
            needs_immediate_flush = len(self._queue) >= self.max_batch_size

        if needs_immediate_flush:
            self.flush()

    def _requeue_failed(self, failed_items: list[tuple[str, tuple[Any, float | None]]]):
        """Restore failed batch entries without overwriting newer concurrent writes."""
        with self._lock:
            restored: OrderedDict[str, tuple[Any, float | None]] = OrderedDict()
            for key, entry in failed_items:
                if key not in self._queue:
                    restored[key] = entry
            restored.update(self._queue)
            self._queue = restored

    def flush(self):
        """Atomically flush all queued writes to SQLite in a single transaction."""
        with self._flush_lock:
            with self._lock:
                if not self._queue:
                    return
                items = list(self._queue.items())
                self._queue.clear()

            if not items:
                return

            from .database import (
                init_db,
                get_db_connection,
                pack_and_encrypt,
                _upsert_kv_batch,
                _to_storage_key,
            )
            init_db()
            conn = get_db_connection()
            now_ts = int(time.time())

            batch_records = []
            raw_items = []
            for key, entry in items:
                if isinstance(entry, tuple) and len(entry) == 2:
                    val, ttl = entry
                else:
                    val, ttl = entry, None
                try:
                    encrypted_blob = pack_and_encrypt(val, associated_data=key.encode("utf-8"))
                    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
                    storage_key = _to_storage_key(key)
                    batch_records.append((storage_key, encrypted_blob, expires_at, now_ts))
                    raw_items.append((key, val))
                except Exception as e:
                    print(f"[WriteBehind] Error encrypting key '{key}': {e}")

            if batch_records:
                try:
                    with conn:
                        _upsert_kv_batch(conn, batch_records, raw_items)
                except Exception as e:
                    self._failed_flushes_count += 1
                    self._requeue_failed(items)
                    print(f"[WriteBehind] Transient SQLite commit error, re-queued {len(items)} item(s): {e}")
                    raise

                self._flushes_count += 1
                self._items_flushed_count += len(batch_records)
                self._last_flush = time.time()

                try:
                    from .metrics import metrics
                    metrics.record_operation("write", count=len(batch_records))
                except Exception:
                    pass

                try:
                    from .events import events
                    for key, val in raw_items:
                        events.emit("write", key=key, value=val)
                except Exception:
                    pass

    def _worker_loop(self):
        """Background loop flushing batches periodically."""
        while not self._stop_event.wait(self.flush_interval):
            try:
                self.flush()
            except Exception as e:
                print(f"[WriteBehind] Worker flush error: {e}")

    def get_stats(self) -> dict:
        """Return write-behind queue and throughput metrics."""
        with self._lock:
            queued = len(self._queue)
        return {
            "pending_writes": queued,
            "batches_flushed": self._flushes_count,
            "failed_flushes": self._failed_flushes_count,
            "total_items_persisted": self._items_flushed_count,
            "flush_interval_sec": self.flush_interval,
            "max_batch_size": self.max_batch_size,
        }

    def close(self):
        """Stop worker and flush remaining items."""
        self._stop_event.set()
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        try:
            atexit.unregister(self.flush)
        except Exception:
            pass
        self.flush()
