"""
secure_json.py — Drop-in replacement for standard json.load() and json.dump().

Features:
- Seamless Two-Tier Caching (L1 RAM + L2 SQLite + Local Disk Backup).
- Reads in <0.01ms from RAM cache.
- Writes atomically to disk with AES-128 Fernet encryption.
- Backwards compatible with legacy unencrypted JSON files.
"""

import os
import json
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidTag
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from .database import (
    _get_cipher, _get_ciphers, get_active_algorithm, DATA_DIR,
    _PREFIX_GCM, _PREFIX_FERNET
)
from .cache import cache


def _resolve_path(path: str | Path) -> Path:
    """Resolve file path relative to data directory if not absolute."""
    p = Path(path)
    if p.is_absolute():
        return p
    return DATA_DIR / p.name


def load_json(path: str | Path, default: Any = None) -> Any:
    """
    Load and decrypt data using Two-Tier Caching (L1 RAM -> L2 SQLite).
    Falls back gracefully to disk if not yet in cache.
    """
    if default is None:
        default = {}

    path = _resolve_path(path)
    key_name = path.name

    # 1. Try Two-Tier Cache (L1 Memory / L2 SQLite)
    cached_val = cache.get(key_name, default=None)
    if cached_val is not None:
        return cached_val

    # 2. Fallback to reading encrypted file on disk
    if not path.exists():
        return default

    raw = path.read_bytes()
    if not raw:
        return default

    # Try decryption first
    try:
        decrypted = None
        if raw.startswith(_PREFIX_GCM):
            cipher_gcm, _ = _get_ciphers()
            actual_blob = raw[5:]
            if len(actual_blob) < 12:
                raise ValueError("Missing GCM nonce.")
            nonce = actual_blob[:12]
            ciphertext = actual_blob[12:]
            decrypted = cipher_gcm.decrypt(nonce, ciphertext, associated_data=None)
        elif raw.startswith(_PREFIX_FERNET):
            _, cipher_fernet = _get_ciphers()
            actual_blob = raw[5:]
            decrypted = cipher_fernet.decrypt(actual_blob)
        elif raw[0] == 0x80 or raw.startswith(b"gAAAA"):
            # Legacy unprefixed Fernet token
            _, cipher_fernet = _get_ciphers()
            decrypted = cipher_fernet.decrypt(raw)
        else:
            # Fallback to active cipher
            cipher_active = _get_cipher()
            if isinstance(cipher_active, AESGCM):
                if len(raw) < 12:
                    raise ValueError("Missing GCM nonce.")
                nonce = raw[:12]
                ciphertext = raw[12:]
                decrypted = cipher_active.decrypt(nonce, ciphertext, associated_data=None)
            else:
                decrypted = cipher_active.decrypt(raw)

        data = json.loads(decrypted)
        cache.set_l1_only(key_name, data)
        return data
    except (InvalidTag, InvalidToken, Exception):
        pass

    # Fall back to plain-text JSON (legacy files)
    try:
        data = json.loads(raw.decode("utf-8"))
        cache.set_l1_only(key_name, data)
        return data
    except Exception:
        return default


def save_json(path: str | Path, data: Any, indent: int = 2):
    """
    Serialise data to JSON, encrypt it, and write to:
    1. L1 Memory Cache (<0.01ms access)
    2. L2 Encrypted SQLite Database (bot_database.db)
    3. Atomically to encrypted disk file
    """
    path = _resolve_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_name = path.name

    # 1. Update Two-Tier Cache (L1 RAM + L2 SQLite)
    try:
        cache.set(key_name, data)
    except Exception as e:
        print(f"[TwoTierCache] Write warning on {key_name}: {e}")

    # 2. Atomic write to encrypted disk file for backup safety
    plaintext = json.dumps(data, indent=indent, ensure_ascii=False).encode("utf-8")
    
    algo = get_active_algorithm()
    if algo == "AES-128-FERNET":
        _, cipher_fernet = _get_ciphers()
        ciphertext = cipher_fernet.encrypt(plaintext)
        payload = _PREFIX_FERNET + ciphertext
    else:
        # Default to AES-256-GCM
        cipher_gcm, _ = _get_ciphers()
        nonce = os.urandom(12)
        ciphertext = cipher_gcm.encrypt(nonce, plaintext, associated_data=None)
        payload = _PREFIX_GCM + nonce + ciphertext

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(path)
