"""
Encrypted SQLite JSON & Two-Tier Caching Engine
A high-performance, AES-128 encrypted, thread-safe SQLite & in-memory caching system for Python applications.
"""

from .database import (
    init_db,
    get_db_connection,
    kv_get,
    kv_set,
    kv_delete,
    rotate_encryption_key,
    db_maintenance,
)
from .cache import TwoTierCache, cache
from .secure_json import load_json, save_json
from .masking import mask_pii, mask_sensitive
from .async_engine import (
    async_load_json,
    async_save_json,
    async_delete_json,
    async_db_maintenance,
    async_rotate_encryption_key,
)

__version__ = "1.0.0"
__all__ = [
    "init_db",
    "get_db_connection",
    "kv_get",
    "kv_set",
    "kv_delete",
    "rotate_encryption_key",
    "db_maintenance",
    "TwoTierCache",
    "cache",
    "load_json",
    "save_json",
    "mask_pii",
    "mask_sensitive",
    "async_load_json",
    "async_save_json",
    "async_delete_json",
    "async_db_maintenance",
    "async_rotate_encryption_key",
]
