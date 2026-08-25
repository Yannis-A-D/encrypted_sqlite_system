"""
test_cache.py — Tests for Two-Tier L1 (RAM) and L2 (SQLite) caching, LRU eviction, and TTL.
"""

import time
from src.cache import TwoTierCache, cache


def test_l1_cache_hit():
    """Verify L1 in-memory hits bypass L2 storage."""
    cache.clear_l1()
    cache.set("cache_hit.json", {"active": True})

    # First get -> L1 hit
    val = cache.get("cache_hit.json")
    assert val == {"active": True}

    stats = cache.get_stats()
    assert stats["hits"] >= 1
    assert stats["l1_items_cached"] >= 1


def test_l2_fallback_on_l1_miss():
    """Verify that when L1 is purged, L2 SQLite automatically recovers the item."""
    cache.set("fallback.json", {"recovered": True})

    # Clear L1 RAM cache
    cache.clear_l1()
    assert len(cache._l1_store) == 0

    # Get -> L1 Miss, but L2 Hit & repopulates L1
    val = cache.get("fallback.json")
    assert val == {"recovered": True}
    assert "fallback.json" in cache._l1_store


def test_lru_capacity_eviction():
    """Test Least-Recently-Used eviction when capacity is exceeded."""
    small_cache = TwoTierCache(max_l1_items=3)

    small_cache.set("item1.json", {"id": 1})
    small_cache.set("item2.json", {"id": 2})
    small_cache.set("item3.json", {"id": 3})

    assert len(small_cache._l1_store) == 3

    # Access item1 to mark it as recently used
    _ = small_cache.get("item1.json")

    # Add item4 -> item2 (least recently used) must be evicted from L1
    small_cache.set("item4.json", {"id": 4})

    assert len(small_cache._l1_store) == 3
    assert "item1.json" in small_cache._l1_store
    assert "item4.json" in small_cache._l1_store
    assert "item2.json" not in small_cache._l1_store  # Evicted from L1


def test_ttl_expiration():
    """Test Time-To-Live expiration."""
    small_cache = TwoTierCache(default_ttl_seconds=0.1)  # 100ms TTL
    small_cache.set("expire_soon.json", {"ttl": True}, ttl=0.1)

    # Immediate access -> alive
    assert small_cache.get("expire_soon.json") == {"ttl": True}

    # Wait for TTL to expire
    time.sleep(0.15)

    # Access after expiration -> L1 miss, refetched from L2
    val = small_cache.get("expire_soon.json")
    assert val == {"ttl": True}
