"""
test_batch_ops.py — Tests for multi-key batch operations and parallel multi-core decryption.
"""

from src.database import kv_mset, kv_mget
from src.cache import cache


def test_kv_mset_and_kv_mget():
    """Test batch writing and parallel batch reading across multiple keys."""
    batch_data = {f"batch_user_{i}.json": {"id": i, "score": i * 50} for i in range(15)}

    # Batch save
    kv_mset(batch_data)

    # Batch get
    keys = list(batch_data.keys())
    results = kv_mget(keys)

    assert len(results) == 15
    for k in keys:
        assert results[k] == batch_data[k]


def test_cache_mget_and_mset():
    """Test TwoTierCache mget and mset methods."""
    data = {
        "team_a.json": {"name": "Alpha", "members": 5},
        "team_b.json": {"name": "Bravo", "members": 8},
        "team_c.json": {"name": "Charlie", "members": 12},
    }

    cache.mset(data)
    fetched = cache.mget(["team_a.json", "team_b.json", "team_c.json"])

    assert fetched["team_a.json"]["name"] == "Alpha"
    assert fetched["team_b.json"]["name"] == "Bravo"
    assert fetched["team_c.json"]["name"] == "Charlie"
