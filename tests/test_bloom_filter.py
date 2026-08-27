"""
test_bloom_filter.py — Tests for in-memory Bloom filter.
"""

from src.bloom_filter import BloomFilter
from src.database import kv_set, kv_get, bloom


def test_bloom_filter_basic():
    """Test standard bloom filter add and contains operations."""
    bf = BloomFilter(expected_elements=1000, false_positive_rate=0.01)

    bf.add("user_101.json")
    bf.add("user_102.json")

    assert bf.contains("user_101.json") is True
    assert bf.contains("user_102.json") is True
    assert bf.contains("definitely_non_existent_key_99999.json") is False


def test_database_bloom_filter_zero_disk_miss():
    """Verify that querying a non-existent key returns None via Bloom filter."""
    kv_set("real_user.json", {"active": True})

    assert bloom.contains("real_user.json") is True
    assert kv_get("real_user.json") == {"active": True}

    # Query key never added
    non_existent = "random_fake_document_xyz_123.json"
    assert bloom.contains(non_existent) is False
    assert kv_get(non_existent) is None
