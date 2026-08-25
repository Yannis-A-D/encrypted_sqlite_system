# 🔐 Encrypted SQLite JSON & Two-Tier Caching Engine

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Encryption](https://img.shields.io/badge/encryption-AES--128%20Fernet-brightgreen.svg)](https://cryptography.io/)
[![Database](https://img.shields.io/badge/storage-SQLite%20WAL-orange.svg)](https://sqlite.org/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

A high-performance, thread-safe, **AES-128 encrypted SQLite document store and Two-Tier caching engine** for Python applications, bots, and microservices.

Serves as a transparent, high-speed drop-in replacement for standard flat `.json` file storage with sub-millisecond memory caching and zero-lock concurrency.

---

## 🌟 Key Features

* 🔒 **AES-128 Fernet Encryption at Rest**: All JSON documents and database tables are encrypted before touching physical storage.
* ⚡ **Two-Tier (L1/L2) Caching**:
  * **Tier 1 (L1 RAM)**: Thread-safe Least-Recently-Used (LRU) in-memory cache delivering **`< 0.01ms` read latency** with zero disk I/O.
  * **Tier 2 (L2 Storage)**: High-concurrency **SQLite in WAL (Write-Ahead Logging) mode** with atomic transactions.
* 🔄 **Write-Through Synchronization**: Automatically keeps in-memory state, SQLite database, and optional disk backups in 100% sync.
* 🛡️ **Zero Thread Locks**: Fully concurrent multi-threaded reads and writes using SQLite WAL mode and thread-local connection pooling.
* 🧹 **Automated Checkpointing & Vacuuming**: Built-in maintenance engine flushes WAL write journals and optimizes B-tree storage.
* 📦 **Zero-Config Drop-in**: Replace `json.load()` and `json.dump()` with `load_json()` and `save_json()` without refactoring your codebase.

---

## 🏛️ Architecture

```
 Application / Bot Layer
            │
            ▼
 ┌────────────────────────────────────────┐
 │ Tier 1: L1 Memory Cache (RAM)          │ <── Read in < 0.01ms (Zero Disk Access)
 └──────────────────┬─────────────────────┘
          │ (On L1 Miss or Write)
          ▼
 ┌────────────────────────────────────────┐
 │ Tier 2: L2 Encrypted SQLite Database   │ <── 100% Encrypted at Rest (AES-128)
 └──────────────────┬─────────────────────┘
                    │ (Optional Fallback)
                    ▼
 ┌────────────────────────────────────────┐
 │ Atomic Encrypted Disk File Snapshot    │ <── Safety Fallback Backup
 └────────────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### 1. Installation

```bash
git clone https://github.com/yourusername/encrypted-sqlite-json.git
cd encrypted-sqlite-json
pip install -r requirements.txt
```

### 2. Generate an Encryption Key

```bash
python generate_key.py
```

Set the generated key in your `.env` file or environment:
```env
ENCRYPTION_KEY=HKr7gXhnXjBOQLJiURjJiyHxvQuqEVk7SXra4ClbWtQ=
```

---

## 💻 Usage Examples

### 1. Drop-in JSON Replacement (`load_json` / `save_json`)

```python
from src.secure_json import load_json, save_json

# 1. Save any Python dictionary (Write-Through to RAM + Encrypted SQLite)
user_profile = {
    "username": "Alex",
    "level": 42,
    "xp": 189343,
    "inventory": ["sword", "shield", "elytra"]
}
save_json("user_101.json", user_profile)

# 2. Instant Load (Retrieved from L1 RAM in <0.01ms)
data = load_json("user_101.json")
print(data["username"], data["level"])
```

---

### 2. Direct Two-Tier Cache API

```python
from src.cache import cache

# Store with custom Time-To-Live (TTL in seconds)
cache.set("leaderboard_top10", [{"user": "Notch", "score": 9999}], ttl=300)

# Retrieve from L1/L2
leaderboard = cache.get("leaderboard_top10")

# Telemetry stats
stats = cache.get_stats()
print(f"Cache Hit Ratio: {stats['hit_ratio_str']} | Cached Items: {stats['l1_items_cached']}")
```

---

### 3. Database Checkpointing & Maintenance

```python
from src.database import db_maintenance

# Runs PRAGMA wal_checkpoint(TRUNCATE) and PRAGMA optimize
maintenance_stats = db_maintenance()
print(f"Database Size: {maintenance_stats['size_mb']} MB")
```

---

## 📁 Project Structure

```
encrypted_sqlite_system/
├── src/
│   ├── __init__.py         # Package entry point
│   ├── database.py         # Encrypted SQLite engine & connection pool
│   ├── cache.py            # Two-Tier L1 RAM + L2 SQLite caching engine
│   └── secure_json.py      # Drop-in load_json / save_json API
├── examples/
│   └── quickstart_demo.py  # Interactive runnable demonstration
├── data/                   # Encrypted app_database.db location
├── generate_key.py         # Fernet key generator utility
├── migrate.py              # Migrates existing flat JSON files to SQLite
├── requirements.txt        # Python dependencies (cryptography)
├── .gitignore              # Ignores secret keys and database binaries
├── LICENSE                 # MIT Open-Source License
└── README.md               # Documentation
```

---

## 🧪 Run the Demo

```bash
python examples/quickstart_demo.py
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
