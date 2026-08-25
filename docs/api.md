# 📚 Python API Reference

## Drop-In JSON Functions

### `load_json(path, default=None)`
Load and decrypt a JSON document using Two-Tier Caching (L1 RAM ➔ L2 SQLite fallback).

* **Arguments**:
    * `path` (`str | Path`): File name or path (e.g. `"settings.json"`).
    * `default` (`Any`, optional): Value returned if key is not found (default: `{}`).
* **Returns**: Decrypted Python dictionary or list.

---

### `save_json(path, data, indent=2)`
Encrypt and persist data to L1 RAM, L2 SQLite, and atomic disk backup.

* **Arguments**:
    * `path` (`str | Path`): File name or path.
    * `data` (`Any`): JSON-serializable Python object.
    * `indent` (`int`, optional): JSON indentation formatting (default: `2`).

---

## Two-Tier Cache API (`src.cache`)

### `cache.get(key, default=None)`
Retrieve a document from L1 RAM cache (or fall back to L2 SQLite).

### `cache.set(key, data, ttl=None)`
Store an item with optional Time-To-Live expiration in seconds.

### `cache.invalidate(key)`
Purge key from L1 RAM and delete from L2 SQLite.

### `cache.get_stats()`
Returns live cache metrics:
```python
{
    "l1_items_cached": 42,
    "l1_max_capacity": 1000,
    "hits": 1420,
    "misses": 31,
    "hit_ratio_str": "97.8%"
}
```

---

## Database Operations (`src.database`)

### `db_maintenance()`
Executes SQLite WAL checkpoint truncation and index optimization:
* `PRAGMA wal_checkpoint(TRUNCATE);`
* `PRAGMA optimize;`
