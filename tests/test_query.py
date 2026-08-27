"""
test_query.py — Tests for fast document search, predicate filtering, and document counting.
"""

import asyncio
from src.database import kv_set, kv_search, kv_find, kv_count
from src.async_engine import async_search, async_find, async_count


def test_kv_search_and_count():
    """Test wildcard search and counting."""
    kv_set("test_search_user_1.json", {"role": "admin", "score": 100})
    kv_set("test_search_user_2.json", {"role": "member", "score": 40})
    kv_set("test_search_ticket_1.json", {"status": "open"})

    # Wildcard search
    user_keys = kv_search("test_search_user_*")
    assert len(user_keys) >= 2
    assert "test_search_user_1.json" in user_keys
    assert "test_search_user_2.json" in user_keys
    assert "test_search_ticket_1.json" not in user_keys

    # Count
    total_users = kv_count("test_search_user_*")
    assert total_users >= 2
    assert kv_count("test_search_ticket_*") >= 1


def test_kv_find_predicate():
    """Test filtering decrypted documents with custom lambda conditions."""
    kv_set("hero_1.json", {"name": "Warrior", "level": 80, "gold": 500})
    kv_set("hero_2.json", {"name": "Mage", "level": 30, "gold": 1200})
    kv_set("hero_3.json", {"name": "Paladin", "level": 95, "gold": 300})

    # Find high-level heroes (level >= 80)
    high_level = kv_find(lambda doc: doc.get("level", 0) >= 80, pattern="hero_*")
    assert len(high_level) == 2
    names = [h["name"] for h in high_level]
    assert "Warrior" in names
    assert "Paladin" in names
    assert "Mage" not in names


def test_async_query_functions():
    """Test async query, search, and count API."""
    async def _run():
        await async_search("hero_*")
        matches = await async_find(lambda d: d.get("gold", 0) > 400, pattern="hero_*")
        assert len(matches) >= 2

        count = await async_count("hero_*")
        assert count == 3

    asyncio.run(_run())
