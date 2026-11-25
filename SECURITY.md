# 🛡️ Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |

## 🔒 Cryptographic Architecture & Standards

This package implements defense-in-depth authenticated encryption and key isolation:

- **Authenticated Encryption at Rest (AEAD)**:
  - **AES-256-GCM** (default, 96-bit CSPRNG nonces, 128-bit authentication tags)
  - **ChaCha20-Poly1305** (96-bit CSPRNG nonces, 128-bit Poly1305 tags)
  - **AES-128-CBC + HMAC-SHA256 (Fernet)** (supported for legacy compatibility)
  - All AEAD records bind the document key name as **Additional Authenticated Data (AAD)** to prevent cross-row ciphertext swapping.
- **HKDF-SHA256 Key Domain Separation**:
  - Distinct 256-bit subkeys are derived via `HKDF-SHA256` for each cipher (`aes-256-gcm-v2`, `chacha20-poly1305-v2`, `fernet-aes-128-v2`), blind-index HMAC (`sqlite-blind-indexing`), Synthetic-IV key-name encryption (`sqlite-key-siv-*`), and GDPR pseudonymization (`sqlite-gdpr-pseudonymization`).
- **Memory-Hard Passphrase KDF**:
  - Supports **Argon2id** (`argon2-cffi`, 64 MiB memory cost) with automatic fallback to **PBKDF2-HMAC-SHA256** (600,000 iterations).
- **OS-Native Master Key Protection**:
  - Integrates with **Windows DPAPI** (`CryptProtectData`), **macOS Keychain / Linux Secret Service** (`keyring`), and `0600` restricted file fallbacks via `KeyManager`.
- **Optional Deterministic Key-Name Encryption (`ENCK1:`)**:
  - Encrypts SQLite primary keys using Synthetic-IV AES-256-GCM (`ENCRYPT_KEYS=true`) so key names are hidden on disk while preserving O(1) B-tree lookups.
- **Zero-Knowledge Distributed L1 & Streaming Cloud Backups**:
  - `RedisL1Adapter` encrypts cached entries (`ENC1:`) with key-bound AAD before transmitting over the network.
  - Cloud snapshots use constant-memory framed AEAD streaming (`ENCSNAP1:CHK1:`) with sequence-number and finality AAD binding against chunk reordering and truncation.
- **Decompression & Path Traversal Protections**:
  - Bounded Zstandard and Zlib decompression (`MAX_DECOMPRESSED_SIZE_MB`, default 256 MiB) mitigates decompression bombs, and strict `Path.is_relative_to` checks block path traversal.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw, please **do NOT open a public GitHub issue**.

Instead, please report security vulnerabilities responsibly by:
1. Opening a **Private Security Advisory** on GitHub: [Report a Vulnerability](https://github.com/Yannis-A-D/encrypted_sqlite_system/security/advisories/new)
2. Or contacting the maintainer directly.

We take security seriously and will acknowledge receipt within 48 hours with a resolution timeline.
