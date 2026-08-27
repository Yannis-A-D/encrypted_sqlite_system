"""
async_engine.py — High-Throughput Asynchronous API for Two-Tier Encrypted SQLite.

Provides non-blocking async/await functions for asyncio event loops (Discord.py, FastAPI, AIOHTTP, Tornado).
Offloads cryptographic encryption/decryption and SQLite disk transactions to worker threads.
"""

import time
import asyncio
from typing import Any
from pathlib import Path
from .secure_json import load_json, save_json, DATA_DIR
from .database import kv_delete, db_maintenance, rotate_encryption_key, kv_search, kv_find, kv_count
from .cache import cache, _lock


async def async_load_json(file_or_key: str | Path, default: Any = None) -> Any:
    """
    Asynchronously load and decrypt a JSON document without blocking the asyncio loop.
    Returns immediately if cached in L1 RAM; otherwise reads and decrypts on a worker thread.
    """
    key = Path(file_or_key).name if isinstance(file_or_key, (str, Path)) else str(file_or_key)
    now = time.time()

    # Fast L1 check
    with _lock:
        if key in cache._l1_store:
            val, exp = cache._l1_store[key]
            if exp == 0 or exp > now:
                cache._l1_store.move_to_end(key)
                cache._hits += 1
                return val

    # L1 Miss: Offload L2 SQLite read & AES decryption to worker thread
    return await asyncio.to_thread(load_json, file_or_key, default)


async def async_save_json(file_or_key: str | Path, data: Any, ttl: int | None = None) -> bool:
    """
    Asynchronously compress, encrypt, and commit a document to SQLite & L1 RAM.
    """
    await asyncio.to_thread(save_json, file_or_key, data, ttl)
    return True


async def async_delete_json(file_or_key: str | Path) -> bool:
    """
    Asynchronously delete a document from L1 RAM, L2 SQLite, and disk backup snapshot.
    """
    key = Path(file_or_key).name if isinstance(file_or_key, (str, Path)) else str(file_or_key)
    with _lock:
        cache._l1_store.pop(key, None)

    def _sync_delete():
        res = kv_delete(key)
        target = DATA_DIR / key
        if target.exists():
            target.unlink()
        return res

    return await asyncio.to_thread(_sync_delete)


async def async_search(pattern: str = "*", limit: int | None = None) -> list[str]:
    """Asynchronously search for keys matching a wildcard pattern."""
    return await asyncio.to_thread(kv_search, pattern, limit)


async def async_find(predicate: Any, pattern: str = "*", limit: int | None = None) -> list[dict[str, Any]]:
    """Asynchronously filter decrypted documents matching a condition."""
    return await asyncio.to_thread(kv_find, predicate, pattern, limit)


async def async_count(pattern: str | None = None) -> int:
    """Asynchronously count documents in SQLite."""
    return await asyncio.to_thread(kv_count, pattern)


async def async_db_maintenance() -> dict:
    """
    Asynchronously execute WAL checkpoint truncation and SQLite optimization.
    """
    return await asyncio.to_thread(db_maintenance)


async def async_rotate_encryption_key(old_key: str | bytes, new_key: str | bytes) -> dict:
    """
    Asynchronously re-encrypt all records with a new encryption key.
    """
    return await asyncio.to_thread(rotate_encryption_key, old_key, new_key)
