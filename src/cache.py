"""
cache.py — Two-Tier (L1 RAM/Redis + L2 Encrypted SQLite) High-Speed Caching Engine.

Features:
- Tier 1 (L1 Cache): Pluggable Memory (<0.01ms) or Redis distributed adapter.
- Tier 2 (L2 Storage): AES-128 Fernet encrypted SQLite database with WAL mode.
- Policy: Write-Through caching with automatic LRU capacity eviction and hit ratio telemetry.
"""

import time
import threading
from typing import Any
from collections import OrderedDict
from .adapters import BaseL1Adapter, MemoryL1Adapter, RedisL1Adapter

_lock = threading.RLock()


class TwoTierCache:
    """Thread-safe Two-Tier (L1 RAM/Redis + L2 Encrypted SQLite) Cache Manager."""

    def __init__(
        self,
        max_l1_items: int = 1000,
        default_ttl_seconds: float = 3600.0 * 24,
        adapter: BaseL1Adapter | None = None
    ):
        self._max_items = max_l1_items
        self._default_ttl = default_ttl_seconds
        self._adapter: BaseL1Adapter = adapter or MemoryL1Adapter(max_capacity=max_l1_items)
        # Compatibility reference for legacy direct access
        if isinstance(self._adapter, MemoryL1Adapter):
            self._l1_store = self._adapter.store
        else:
            self._l1_store = OrderedDict()

        # Telemetry
        self._hits = 0
        self._misses = 0
        self._writes = 0

    def use_redis(self, redis_client_or_url: Any, prefix: str = "enc_sqlite:l1:"):
        """Switch Tier 1 to a distributed Redis cache layer."""
        with _lock:
            self._adapter = RedisL1Adapter(redis_client_or_url, prefix=prefix)

    def use_memory(self, max_capacity: int = 1000):
        """Switch Tier 1 back to local in-memory LRU cache."""
        with _lock:
            self._adapter = MemoryL1Adapter(max_capacity=max_capacity)
            self._l1_store = self._adapter.store

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve item using L1 -> L2 (Encrypted SQLite) fallback.
        Returns decrypted, deserialized Python object.
        """
        with _lock:
            val, hit = self._adapter.get(key)
            if hit:
                self._hits += 1
                return val
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
        Write-Through: Update L1 AND immediately persist encrypted to L2 SQLite.
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
        """Store into L1 Cache with LRU eviction."""
        effective_ttl = ttl if (ttl is not None and ttl > 0) else self._default_ttl
        with _lock:
            self._adapter.set(key, data, ttl_seconds=effective_ttl)

    def invalidate(self, key: str):
        """Purge item from L1 Cache and delete from L2 SQLite."""
        with _lock:
            self._adapter.delete(key)

        from .database import kv_delete
        try:
            kv_delete(key)
        except Exception:
            pass

    def clear_l1(self):
        """Clear all entries in L1 cache."""
        with _lock:
            self._adapter.clear()

    def get_stats(self) -> dict:
        """Return cache hit/miss, efficiency, and capacity metrics."""
        with _lock:
            total_reads = self._hits + self._misses
            hit_ratio = (self._hits / total_reads * 100) if total_reads > 0 else 100.0
            adapter_type = "Redis" if isinstance(self._adapter, RedisL1Adapter) else "Memory (LRU)"
            return {
                "l1_adapter": adapter_type,
                "l1_items_cached": self._adapter.size(),
                "l1_max_capacity": self._max_items if adapter_type == "Memory (LRU)" else "Dynamic (Redis)",
                "hits": self._hits,
                "misses": self._misses,
                "writes": self._writes,
                "hit_ratio_percent": round(hit_ratio, 2),
                "hit_ratio_str": f"{hit_ratio:.1f}%",
            }


# Global Two-Tier Cache Singleton Instance
cache = TwoTierCache(max_l1_items=1000, default_ttl_seconds=3600.0 * 24)
