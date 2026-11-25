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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from .database import (
    _get_cipher, _get_ciphers, _get_ciphers_v2, _get_chacha_cipher, get_active_algorithm, DATA_DIR,
    _PREFIX_GCM, _PREFIX_FERNET, _PREFIX_CHACHA, _SUBKEY_V2_TAG
)
from .cache import cache


def _resolve_path(path: str | Path) -> Path:
    """Resolve file path relative to data directory safely (rejecting path traversal on relative keys)."""
    p = Path(path)
    if p.is_absolute():
        return p
    if ".." in p.parts:
        raise ValueError(f"Unsafe relative key path containing traversal segments: {path}")
    base = DATA_DIR.resolve()
    resolved = (DATA_DIR / p.name).resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(f"Resolved path escapes DATA_DIR: {path}")
    return DATA_DIR / p.name


_DEFAULT_UNSET = object()


def load_json(path: str | Path, default: Any = _DEFAULT_UNSET) -> Any:
    """
    Load and decrypt data using Two-Tier Caching (L1 RAM -> L2 SQLite).
    Falls back gracefully to disk if not yet in cache.
    """
    fallback = {} if default is _DEFAULT_UNSET else default

    path = _resolve_path(path)
    key_name = path.name

    # 1. Try Two-Tier Cache (L1 Memory / L2 SQLite)
    cached_val = cache.get(key_name, default=None)
    if cached_val is not None:
        return cached_val

    # 2. Fallback to reading encrypted file on disk
    if not path.exists():
        return fallback

    raw = path.read_bytes()
    if not raw:
        return fallback

    is_encrypted_prefix = (
        raw.startswith(_PREFIX_GCM)
        or raw.startswith(_PREFIX_FERNET)
        or raw.startswith(_PREFIX_CHACHA)
        or raw[0] == 0x80
        or raw.startswith(b"gAAAA")
    )
    aad = key_name.encode("utf-8")

    # Try decryption first (supporting both HKDF v2 subkeys and legacy v1 keys)
    try:
        decrypted = None
        gcm_v1, fernet_v1 = _get_ciphers()
        gcm_v2, fernet_v2, chacha_v2 = _get_ciphers_v2()

        if raw.startswith(_PREFIX_GCM):
            actual_blob = raw[5:]
            use_gcm = gcm_v2 if actual_blob.startswith(_SUBKEY_V2_TAG) else gcm_v1
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                actual_blob = actual_blob[len(_SUBKEY_V2_TAG):]
            if len(actual_blob) < 12:
                raise ValueError("Missing GCM nonce.")
            decrypted = use_gcm.decrypt(actual_blob[:12], actual_blob[12:], associated_data=aad)
        elif raw.startswith(_PREFIX_CHACHA):
            actual_blob = raw[5:]
            use_chacha = chacha_v2 if actual_blob.startswith(_SUBKEY_V2_TAG) else _get_chacha_cipher()
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                actual_blob = actual_blob[len(_SUBKEY_V2_TAG):]
            if len(actual_blob) < 12:
                raise ValueError("Missing ChaCha20 nonce.")
            decrypted = use_chacha.decrypt(actual_blob[:12], actual_blob[12:], associated_data=aad)
        elif raw.startswith(_PREFIX_FERNET):
            actual_blob = raw[5:]
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                decrypted = fernet_v2.decrypt(actual_blob[len(_SUBKEY_V2_TAG):])
            else:
                decrypted = fernet_v1.decrypt(actual_blob)
        elif raw[0] == 0x80 or raw.startswith(b"gAAAA"):
            decrypted = fernet_v1.decrypt(raw)
        else:
            cipher_active = _get_cipher()
            if isinstance(cipher_active, (AESGCM, ChaCha20Poly1305)):
                if len(raw) < 12:
                    raise ValueError("Missing AEAD nonce.")
                decrypted = cipher_active.decrypt(raw[:12], raw[12:], associated_data=aad)
            else:
                decrypted = cipher_active.decrypt(raw)

        data = json.loads(decrypted)
        cache.set_l1_only(key_name, data)
        return data
    except (InvalidTag, InvalidToken):
        if is_encrypted_prefix:
            return fallback
    except Exception:
        if is_encrypted_prefix:
            return fallback

    # Fall back to plain-text JSON only for unprefixed legacy files
    try:
        data = json.loads(raw.decode("utf-8"))
        cache.set_l1_only(key_name, data)
        return data
    except Exception:
        return fallback


def save_json(
    path: str | Path,
    data: Any,
    indent: int = 2,
    ttl: float | None = None,
    mirror_to_disk: bool | None = None,
):
    """
    Serialise data to JSON, encrypt it, and write to:
    1. L1 Memory Cache (<0.01ms access)
    2. L2 Encrypted SQLite Database
    3. Optionally atomically to an encrypted disk mirror file (configurable via mirror_to_disk or MIRROR_JSON_TO_DISK)
    """
    path = _resolve_path(path)
    key_name = path.name

    # 1. Update Two-Tier Cache (L1 RAM + L2 SQLite)
    try:
        cache.set(key_name, data, ttl=ttl, db_ttl=ttl)
    except Exception as e:
        print(f"[TwoTierCache] Write warning on {key_name}: {e}")

    should_mirror = (
        mirror_to_disk
        if mirror_to_disk is not None
        else os.getenv("MIRROR_JSON_TO_DISK", "true").lower() in ("true", "1", "yes")
    )

    # 2. For temporary TTL records or when disk mirroring is disabled, skip static disk file write
    if ttl is not None or not should_mirror:
        if ttl is not None and path.exists():
            try:
                path.unlink()
            except Exception:
                pass
        return

    path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Atomic write to encrypted disk file using HKDF domain-separated v2 subkeys
    plaintext = json.dumps(data, indent=indent, ensure_ascii=False).encode("utf-8")
    aad = key_name.encode("utf-8")
    gcm_v2, fernet_v2, chacha_v2 = _get_ciphers_v2()

    algo = get_active_algorithm()
    if algo == "AES-128-FERNET":
        ciphertext = fernet_v2.encrypt(plaintext)
        payload = _PREFIX_FERNET + _SUBKEY_V2_TAG + ciphertext
    elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
        nonce = os.urandom(12)
        ciphertext = chacha_v2.encrypt(nonce, plaintext, associated_data=aad)
        payload = _PREFIX_CHACHA + _SUBKEY_V2_TAG + nonce + ciphertext
    else:
        nonce = os.urandom(12)
        ciphertext = gcm_v2.encrypt(nonce, plaintext, associated_data=aad)
        payload = _PREFIX_GCM + _SUBKEY_V2_TAG + nonce + ciphertext

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(path)
