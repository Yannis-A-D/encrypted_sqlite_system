# 🏛️ Architecture & Caching Design (v3.0)

The system implements a **Two-Tier (L1/L2) Hierarchical Caching Engine** backed by **Two-Layer KEK/DEK Envelope Encryption**, **HKDF-SHA256 Domain-Separated AEAD (AES-256-GCM / ChaCha20-Poly1305)**, and **SQLite WAL Mode**.

<p align="center">
  <img src="../images/architecture_v3.png" alt="Encrypted SQLite System v3.0 Architecture" width="100%" />
</p>

---

## 📊 Latency & Storage Hierarchy

| Tier | Layer | Media | Typical Latency | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Bloom Filter** | Negative Cache | System RAM | **`< 0.0001 ms`** | Auto-scaling BLAKE2b double-hash filter for 0-disk misses |
| **Tier 1 (L1)** | Application Cache | System RAM / Redis | **`< 0.01 ms`** | Copy-isolated LRU RAM, Zstd compressed RAM, or `ENC1:` encrypted Redis |
| **Tier 2 (L2)** | Persistent Store | SSD / NVMe | **`~ 0.03–1.00 ms`** | SQLite WAL + MMAP with AEAD payloads & optional `ENCK1:` SIV keys |
| **Cloud Sync** | Disaster Recovery | S3 / Cloudflare R2 | Async Background | Streaming `ENCSNAP1:CHK1:` 4 MiB chunked AEAD snapshots |

---

## 🔐 Two-Layer KEK/DEK Envelope & Multi-Slot Recovery

<p align="center">
  <img src="../images/envelope_kek_dek.png" alt="KEK/DEK Envelope & HKDF Key Hierarchy" width="100%" />
</p>

* **Data Encryption Key (DEK):** A random 256-bit key generated per vault that derives isolated HKDF-SHA256 subkeys (`aes-256-gcm-v2`, `chacha20-poly1305-v2`, `sqlite-key-siv`, `sqlite-blind-indexing`, `sqlite-gdpr-pseudonym`).
* **Key Encryption Key (KEK) Slots (`vault_key_slots`):** One or more KEKs (e.g., DPAPI/OS Keyring primary key + offline Argon2id recovery passphrase) wrap the DEK with `AES-256-GCM`.
* **O(1) Routine Key Rotation (`rotate_kek()`):** Re-wraps only the 32-byte DEK in `< 1 ms` without decrypting/re-encrypting rows. Full `deep_rekey=True` remains available for emergency DEK replacement.

---

## 🔄 Read Flow

```mermaid
sequenceDiagram
    autonumber
    actor App as Application / Collection[T]
    participant L1 as Tier 1: L1 (Copy-Isolated / ENC1 Redis)
    participant Bloom as BLAKE2b Bloom Filter
    participant L2 as Tier 2: SQLite WAL (ENCK1 Keys)
    participant Cipher as HKDF v2 AEAD Cipher

    App->>L1: get(key)
    alt L1 Cache Hit (<0.01ms)
        L1-->>App: Return isolated / hydrated object
    else L1 Cache Miss
        L1->>Bloom: contains(key)?
        alt Guaranteed Absent
            Bloom-->>App: Return default (0 disk I/O)
        else Might Exist
            Bloom->>L2: SELECT value FROM kv_store WHERE key=?
            L2->>Cipher: Decrypt + Verify AAD (key) + Decompress
            Cipher-->>L2: Plaintext payload
            L2->>L1: Warm L1 with synced remaining TTL
            L1-->>App: Return hydrated object
        end
    end
```

---

## 💾 Write Flow (ACID Transaction & Write-Through)

```mermaid
sequenceDiagram
    autonumber
    actor App as Application / Collection[T]
    participant L1 as Tier 1: L1 RAM / Redis
    participant Cipher as HKDF v2 AEAD Cipher
    participant L2 as Tier 2: SQLite WAL (BEGIN IMMEDIATE)

    App->>Cipher: Encrypt value (AAD=key) + SIV-encrypt key (ENCK1:)
    Cipher->>L2: BEGIN IMMEDIATE -> OCC version check -> UPSERT kv_store + blind_indexes -> COMMIT
    L2->>L1: Update L1 cache + BLAKE2b Bloom filter
    L1-->>App: Emit CDC event & return version
```
