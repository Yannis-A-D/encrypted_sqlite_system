# 🛡️ Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## 🔒 Cryptographic Standards
This package implements:
- **AES-128 Fernet Encryption**: Cryptographically authenticated tokens using 128-bit AES in CBC mode with PKCS7 padding and HMAC-SHA256 authentication.
- **Zero-Plaintext at Rest**: No unencrypted application data is written to disk or database logs.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw, please **do NOT open a public GitHub issue**.

Instead, please report security vulnerabilities responsibly by:
1. Opening a **Private Security Advisory** on GitHub: [Report a Vulnerability](https://github.com/Yannis-A-D/encrypted_sqlite_system/security/advisories/new)
2. Or contacting the maintainer directly.

We take security seriously and will acknowledge receipt within 48 hours with a resolution timeline.
