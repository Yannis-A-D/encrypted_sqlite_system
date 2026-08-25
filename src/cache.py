"""
cache.py — Two-Tier (L1 RAM + L2 Encrypted SQLite) High-Speed Caching Engine.

Features:
- Tier 1 (L1 RAM): Thread-safe Least-Recently-Used (LRU) cache (<0.01ms lookup time).
- Tier 2 (L2 Storage): AES-128 Fernet encrypted SQLite database with WAL mode.
- Policy: Write-Through caching with automatic LRU capacity eviction and hit ratio telemetry.
"""

import time
import threading
from typing import Any
from collections import OrderedDict

_lock = threading.RLock()


class TwoTierCache:
    """Thread-safe Two-Tier (L1 RAM + L2 Encrypted SQLite) Cache Manager."""

    def __init__(self, max_l1_items: int = 1000, default_ttl_seconds: float = 3600.0 * 24):
        self._max_items = max_l1_items
        self._default_ttl = default_ttl_seconds
        # L1 Memory Store: key -> (data, expire_at)
        self._l1_store: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        
        # Telemetry
        self._hits = 0
        self._misses = 0
        self._writes = 0

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve item using L1 (RAM) -> L2 (Encrypted SQLite) fallback.
        Returns decrypted, deserialized Python object.
        """
        now = time.time()
        
        with _lock:
            # 1. Check L1 Memory Cache
            if key in self._l1_store:
                data, expire_at = self._l1_store[key]
                if expire_at == 0 or now < expire_at:
                    self._l1_store.move_to_end(key)
                    self._hits += 1
                    return data
                else:
                    # Expired from L1
                    del self._l1_store[key]

            self._misses += 1

        # 2. L1 Miss -> Fetch from L2 (Encrypted SQLite)
        from .database import kv_get
        data = kv_get(key, default=None)

        if data is not None:
            # Populate L1 Memory Cache
            self.set_l1_only(key, data)
            return data

        return default

    def set(self, key: str, data: Any, ttl: float | None = None):
        """
        Write-Through: Update L1 Memory AND immediately persist encrypted to L2 SQLite.
        """
        self.set_l1_only(key, data, ttl)

        # Persist to L2 (Encrypted SQLite Database)
        from .database import kv_set
        try:
            kv_set(key, data)
        except Exception as e:
            print(f"[TwoTierCache] Error persisting '{key}' to L2 SQLite: {e}")

        with _lock:
            self._writes += 1

    def set_l1_only(self, key: str, data: Any, ttl: float | None = None):
        """Store into L1 Memory Cache with LRU eviction."""
        expire_at = 0.0
        if ttl is not None and ttl > 0:
            expire_at = time.time() + ttl
        elif self._default_ttl > 0:
            expire_at = time.time() + self._default_ttl

        with _lock:
            if key in self._l1_store:
                self._l1_store.move_to_end(key)
            self._l1_store[key] = (data, expire_at)

            # Evict oldest items if exceeding maximum capacity
            while len(self._l1_store) > self._max_items:
                self._l1_store.popitem(last=False)

    def invalidate(self, key: str):
        """Purge item from L1 Memory and delete from L2 SQLite."""
        with _lock:
            if key in self._l1_store:
                del self._l1_store[key]

        from .database import kv_delete
        try:
            kv_delete(key)
        except Exception:
            pass

    def clear_l1(self):
        """Clear all in-memory L1 cache entries."""
        with _lock:
            self._l1_store.clear()

    def get_stats(self) -> dict:
        """Return cache hit/miss, efficiency, and capacity metrics."""
        with _lock:
            total_reads = self._hits + self._misses
            hit_ratio = (self._hits / total_reads * 100) if total_reads > 0 else 100.0
            return {
                "l1_items_cached": len(self._l1_store),
                "l1_max_capacity": self._max_items,
                "hits": self._hits,
                "misses": self._misses,
                "writes": self._writes,
                "hit_ratio_percent": round(hit_ratio, 2),
                "hit_ratio_str": f"{hit_ratio:.1f}%",
            }


# Global Two-Tier Cache Singleton Instance
cache = TwoTierCache(max_l1_items=1000, default_ttl_seconds=3600.0 * 24)
