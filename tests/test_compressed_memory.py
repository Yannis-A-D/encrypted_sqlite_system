"""
test_compressed_memory.py — Tests for CompressedMemoryL1Adapter in RAM.
"""

from src.adapters import CompressedMemoryL1Adapter
from src.cache import TwoTierCache


def test_compressed_memory_l1_adapter():
    """Verify CompressedMemoryL1Adapter stores compressed bytes in RAM."""
    adapter = CompressedMemoryL1Adapter(max_capacity=5)

    sample_doc = {"logs": [f"Log event #{i} for user action" for i in range(50)]}
    adapter.set("compressed_user.json", sample_doc)

    # Verify underlying storage holds bytes and not raw dict
    raw_bytes, _ = adapter.store["compressed_user.json"]
    assert isinstance(raw_bytes, bytes)
    assert len(raw_bytes) < 300  # Highly compressed

    # Retrieve and verify decompression
    recovered, hit = adapter.get("compressed_user.json")
    assert hit is True
    assert recovered == sample_doc


def test_two_tier_cache_use_compressed_memory():
    """Verify TwoTierCache switching to compressed memory."""
    c = TwoTierCache()
    c.use_compressed_memory(max_capacity=2000)
    assert c.get_stats()["l1_adapter"] == "Compressed Memory (LZ/Zlib)"

    c.set("big_profile.json", {"username": "Gamer", "history": [1, 2, 3, 4, 5]})
    assert c.get("big_profile.json") == {"username": "Gamer", "history": [1, 2, 3, 4, 5]}
