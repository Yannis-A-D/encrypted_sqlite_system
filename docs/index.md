# 🔐 Encrypted SQLite JSON & Two-Tier Caching Engine

A high-performance, thread-safe, **AES-128 encrypted SQLite document store and Two-Tier (L1/L2) caching engine** for Python applications, Discord bots, and microservices.

Serves as a transparent, high-speed drop-in replacement for standard flat `.json` file storage with sub-millisecond memory caching and zero-lock concurrency.

---

## 🌟 Highlights

* 🔒 **AES-128 Fernet Encryption at Rest**: All documents are encrypted before touching disk.
* ⚡ **Two-Tier (L1/L2) Caching**:
    * **Tier 1 (L1 RAM)**: Thread-safe LRU cache (`< 0.01ms` read latency).
    * **Tier 2 (L2 Storage)**: SQLite in WAL (Write-Ahead Logging) mode.
* 🔄 **Write-Through Synchronization**: Keeps RAM and encrypted SQLite in 100% sync.
* 🛡️ **Zero Thread Contention**: Fully multi-threaded with thread-local connections.
* 📦 **Zero-Config Drop-in**: Replace `json.load()` and `json.dump()` with `load_json()` and `save_json()`.

---

## 🚀 Quickstart

### Installation

```bash
pip install -r requirements.txt
```

### Generate an Encryption Key

```bash
python generate_key.py
```

Set the key in your `.env` or environment:
```env
ENCRYPTION_KEY=your_fernet_encryption_key_here=
```

### Basic Usage

```python
from src.secure_json import load_json, save_json

# 1. Save data (Write-Through to RAM + Encrypted SQLite)
save_json("user_101.json", {"username": "Alex", "level": 42, "xp": 189343})

# 2. Instant Load (<0.01ms from RAM)
data = load_json("user_101.json")
print(data["username"], data["level"])
```
