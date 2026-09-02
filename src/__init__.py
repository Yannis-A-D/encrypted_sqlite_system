"""
Encrypted SQLite JSON & Two-Tier Caching Engine
A high-performance, AES-128 encrypted, thread-safe SQLite & in-memory caching system for Python applications.
"""

from .database import (
    init_db,
    get_db_connection,
    kv_get,
    kv_set,
    kv_get_versioned,
    kv_set_versioned,
    ConcurrentModificationError,
    kv_mget,
    kv_mset,
    kv_delete,
    kv_search,
    kv_find,
    kv_find_by_index,
    set_indexed_fields,
    get_indexed_fields,
    get_active_compression,
    set_active_compression,
    kv_count,
    purge_expired_records,
    scavenger,
    TTLScavenger,
    rotate_encryption_key,
    db_maintenance,
    bloom,
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
    async_search,
    async_find,
    async_count,
    async_cloud_backup,
    async_cloud_restore,
    async_kv_get_versioned,
    async_kv_set_versioned,
    async_kv_find_by_index,
    async_purge_expired,
)
from .integrity import verify_database_integrity, compute_record_checksum
from .adapters import BaseL1Adapter, MemoryL1Adapter, CompressedMemoryL1Adapter, RedisL1Adapter
from .write_behind import WriteBehindEngine
from .bloom_filter import BloomFilter
from .cloud_sync import CloudSyncEngine, cloud_sync
from .events import events, EventDispatcher, ChangeEvent
from . import serializers

__version__ = "1.0.0"
__all__ = [
    "init_db",
    "get_db_connection",
    "kv_get",
    "kv_set",
    "kv_get_versioned",
    "kv_set_versioned",
    "ConcurrentModificationError",
    "kv_mget",
    "kv_mset",
    "kv_delete",
    "kv_search",
    "kv_find",
    "kv_find_by_index",
    "set_indexed_fields",
    "get_indexed_fields",
    "get_active_compression",
    "set_active_compression",
    "kv_count",
    "purge_expired_records",
    "scavenger",
    "TTLScavenger",
    "rotate_encryption_key",
    "db_maintenance",
    "bloom",
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
    "async_search",
    "async_find",
    "async_count",
    "async_cloud_backup",
    "async_cloud_restore",
    "async_kv_get_versioned",
    "async_kv_set_versioned",
    "async_kv_find_by_index",
    "async_purge_expired",
    "verify_database_integrity",
    "compute_record_checksum",
    "BaseL1Adapter",
    "MemoryL1Adapter",
    "CompressedMemoryL1Adapter",
    "RedisL1Adapter",
    "WriteBehindEngine",
    "BloomFilter",
    "CloudSyncEngine",
    "cloud_sync",
    "events",
    "EventDispatcher",
    "ChangeEvent",
    "serializers",
]
