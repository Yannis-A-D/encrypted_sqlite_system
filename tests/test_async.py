"""
test_async.py — Tests for non-blocking asynchronous load, save, delete, and concurrency.
"""

import asyncio
from src.async_engine import async_load_json, async_save_json, async_delete_json, async_db_maintenance


def test_async_save_and_load():
    """Test basic async saving and loading."""
    async def _run():
        key = "async_user_1.json"
        data = {"user_id": 999, "name": "AsyncTester", "active": True}

        saved = await async_save_json(key, data)
        assert saved is True

        loaded = await async_load_json(key)
        assert loaded == data
        assert loaded["name"] == "AsyncTester"

    asyncio.run(_run())


def test_async_concurrent_gather():
    """Test concurrent async writes and reads using asyncio.gather."""
    async def _run():
        keys = [f"async_item_{i}.json" for i in range(20)]

        # Concurrent saves
        save_coros = [async_save_json(k, {"index": i, "val": i * 10}) for i, k in enumerate(keys)]
        results = await asyncio.gather(*save_coros)
        assert all(r is True for r in results)

        # Concurrent reads
        load_coros = [async_load_json(k) for k in keys]
        docs = await asyncio.gather(*load_coros)
        for i, doc in enumerate(docs):
            assert doc["index"] == i
            assert doc["val"] == i * 10

    asyncio.run(_run())


def test_async_delete():
    """Test async document deletion."""
    async def _run():
        key = "async_temp.json"
        await async_save_json(key, {"temp": True})
        assert await async_load_json(key) is not None

        deleted = await async_delete_json(key)
        assert deleted is True
        assert await async_load_json(key) == {}

    asyncio.run(_run())


def test_async_db_maintenance():
    """Test async WAL checkpointing."""
    async def _run():
        res = await async_db_maintenance()
        assert res["status"] == "ok"
        assert "size_mb" in res

    asyncio.run(_run())
