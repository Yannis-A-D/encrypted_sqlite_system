# 🏛️ Architecture & Caching Design

The system implements a formal **Two-Tier (L1/L2) Hierarchical Caching Engine** combined with **AES-128 Fernet Encryption at Rest**.

---

## 📊 Latency & Storage Hierarchy

| Tier | Layer | Media | Typical Latency | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1 (L1)** | Application Cache | System RAM | **`< 0.01 ms`** | Thread-safe LRU in-memory cache |
| **Tier 2 (L2)** | Persistent Store | SSD / NVMe | **`~ 1.00 ms`** | AES-128 Encrypted SQLite Database |
| **Fallback** | Safety Snapshot | Local Disk | **`~ 2.50 ms`** | Atomic encrypted `.json` file backup |

---

## 🔄 Read Flow

```mermaid
sequenceDiagram
    autonumber
    actor App as Application / Bot
    participant L1 as Tier 1: L1 RAM (LRU)
    participant L2 as Tier 2: L2 SQLite (WAL)
    participant Cipher as AES-128 Cipher

    App->>L1: load_json("user_101.json")
    alt L1 Cache Hit (<0.01ms)
        L1-->>App: Return deserialized dict immediately
    else L1 Cache Miss
        L1->>L2: SELECT value FROM kv_store WHERE key=?
        L2->>Cipher: Decrypt raw bytes
        Cipher-->>L2: Plaintext JSON string
        L2->>L1: Store into L1 RAM (warm up cache)
        L1-->>App: Return deserialized dict
    end
```

---

## 💾 Write Flow (Write-Through)

```mermaid
sequenceDiagram
    autonumber
    actor App as Application / Bot
    participant L1 as Tier 1: L1 RAM (LRU)
    participant Cipher as AES-128 Cipher
    participant L2 as Tier 2: L2 SQLite (WAL)
    participant Disk as Encrypted Disk File

    App->>L1: save_json("user_101.json", data)
    L1->>L1: Update in-memory LRU cache
    L1->>Cipher: Encrypt JSON to ciphertext
    Cipher->>L2: INSERT INTO kv_store (key, value, ts) ON CONFLICT DO UPDATE
    Cipher->>Disk: Atomic write to user_101.json.tmp -> replace
    Disk-->>App: Write complete & synchronized
```
