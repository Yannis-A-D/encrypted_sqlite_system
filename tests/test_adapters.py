"""
test_adapters.py — Tests for pluggable L1 Cache adapters (Memory and Redis).
"""

from src.adapters import MemoryL1Adapter, RedisL1Adapter
from src.cache import TwoTierCache


class MockRedisClient:
    """In-memory mock for Redis client to test RedisL1Adapter without external server."""
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, val):
        self.data[key] = val

    def setex(self, key, ttl, val):
        self.data[key] = val

    def delete(self, *keys):
        for k in keys:
            self.data.pop(k, None)

    def keys(self, pattern):
        prefix = pattern.replace("*", "")
        return [k for k in self.data.keys() if k.startswith(prefix)]


def test_memory_l1_adapter():
    """Test standard MemoryL1Adapter operations and LRU capacity."""
    adapter = MemoryL1Adapter(max_capacity=3)
    adapter.set("k1", "v1")
    adapter.set("k2", "v2")
    adapter.set("k3", "v3")

    val, hit = adapter.get("k1")
    assert hit is True
    assert val == "v1"

    # Overflow capacity
    adapter.set("k4", "v4")
    assert adapter.size() == 3
    _, k2_hit = adapter.get("k2")
    assert k2_hit is False  # Evicted


def test_redis_l1_adapter_with_mock():
    """Test RedisL1Adapter operations with Mock Redis."""
    mock_client = MockRedisClient()
    adapter = RedisL1Adapter(redis_client_or_url=mock_client, prefix="test:l1:")

    adapter.set("user_101", {"name": "Alice", "score": 99})
    val, hit = adapter.get("user_101")

    assert hit is True
    assert val == {"name": "Alice", "score": 99}
    assert adapter.size() == 1

    adapter.delete("user_101")
    val_after, hit_after = adapter.get("user_101")
    assert hit_after is False
    assert val_after is None


def test_two_tier_cache_switching():
    """Test dynamic switching between Memory and Redis adapters."""
    c = TwoTierCache(max_l1_items=500)
    assert c.get_stats()["l1_adapter"] == "Memory (LRU)"

    mock_client = MockRedisClient()
    c.use_redis(mock_client)
    assert c.get_stats()["l1_adapter"] == "Redis"

    c.set("shared_key", {"msg": "hello distributed world"})
    assert c.get("shared_key") == {"msg": "hello distributed world"}

    c.use_memory(max_capacity=100)
    assert c.get_stats()["l1_adapter"] == "Memory (LRU)"
