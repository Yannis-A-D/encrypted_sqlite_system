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
    db_maintenance,
)
from .cache import TwoTierCache, cache
from .secure_json import load_json, save_json

__version__ = "1.0.0"
__all__ = [
    "init_db",
    "get_db_connection",
    "kv_get",
    "kv_set",
    "kv_delete",
    "db_maintenance",
    "TwoTierCache",
    "cache",
    "load_json",
    "save_json",
]
