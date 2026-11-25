"""
database.py — High-Performance Encrypted & Compressed SQLite Database Engine.

Features:
- AES-128 Fernet encryption at rest.
- Automatic zlib payload compression (75%-90% size reduction on large JSONs).
- High-concurrency WAL (Write-Ahead Logging) mode.
- Key rotation utility with atomic multi-row re-encryption.
- Automated WAL checkpointing and database maintenance.
"""

import os
import json
import zlib
import sqlite3
import threading
import base64
import time
from pathlib import Path
from typing import Any
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag

try:
    import zstandard as zstd
    _HAS_ZSTD = True
    _zstd_compressor = zstd.ZstdCompressor(level=3)
    _zstd_decompressor = zstd.ZstdDecompressor()
except ImportError:
    _HAS_ZSTD = False
    _zstd_compressor = None
    _zstd_decompressor = None

try:
    import argon2.low_level
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False

class ConcurrentModificationError(Exception):
    """Raised when a concurrent write occurs and version numbers do not match."""
    pass


# Blind indexing configuration
_indexed_fields: set[str] = set()
env_fields = os.getenv("BLIND_INDEX_FIELDS")
if env_fields:
    _indexed_fields = {f.strip() for f in env_fields.split(",") if f.strip()}


def set_indexed_fields(fields: list[str] | set[str]):
    """Configure which JSON fields are dynamically indexed in SQLite."""
    global _indexed_fields
    _indexed_fields = {str(f).strip() for f in fields if str(f).strip()}


def get_indexed_fields() -> list[str]:
    """Retrieve the currently configured blind indexed fields."""
    return sorted(list(_indexed_fields))

# Thread-local storage for SQLite connections
_local = threading.local()
_active_connections: set[sqlite3.Connection] = set()
_conn_lock = threading.Lock()
_db_initialized = False
_init_lock = threading.Lock()
_decrypt_executor = None
_executor_lock = threading.Lock()
_SQLITE_MAX_VARS = 900
_key_encryption_override: bool | None = None
_PREFIX_ENC_KEY = "ENCK1:"

# Base paths (avoids writing inside read-only site-packages when installed via pip)
_PKG_PARENT = Path(__file__).resolve().parent.parent
if any(part in ("site-packages", "dist-packages") for part in _PKG_PARENT.parts):
    ROOT_DIR = Path(os.getenv("ENCRYPTED_SQLITE_ROOT_DIR", Path.cwd()))
else:
    ROOT_DIR = Path(__file__).parent.parent

DATA_DIR = Path(os.getenv("ENCRYPTED_SQLITE_DATA_DIR", ROOT_DIR / "data"))
DB_PATH = Path(os.getenv("ENCRYPTED_SQLITE_DB_PATH", DATA_DIR / "app_database.db"))

# Encryption Key setup and prefixes
_cipher_aesgcm: AESGCM | None = None
_cipher_fernet: Fernet | None = None
_cipher_chacha: ChaCha20Poly1305 | None = None
_cipher_aesgcm_v2: AESGCM | None = None
_cipher_fernet_v2: Fernet | None = None
_cipher_chacha_v2: ChaCha20Poly1305 | None = None

_PREFIX_GCM = b"G256:"
_PREFIX_FERNET = b"F128:"
_PREFIX_CHACHA = b"C256:"
_SUBKEY_V2_TAG = b"v2:"
_MAGIC_COMPRESSED_ZL = b"ZL1:"
_MAGIC_COMPRESSED_ZSTD = b"ZS1:"
_MAGIC_COMPRESSED = _MAGIC_COMPRESSED_ZL
_MAGIC_RAW = b"RW1:"

_compression_override: str | None = None
SALT_FILE = DATA_DIR / ".db.salt"


def get_or_create_db_salt() -> bytes:
    """Retrieve or generate a 16-byte cryptographically secure salt for PBKDF2 passphrase derivation."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SALT_FILE.exists():
        try:
            salt = SALT_FILE.read_bytes()
            if len(salt) >= 16:
                return salt[:16]
        except Exception:
            pass
    salt = os.urandom(16)
    try:
        SALT_FILE.write_bytes(salt)
    except Exception:
        pass
    return salt


def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes | None = None,
    algorithm: str | None = None
) -> tuple[bytes, bytes]:
    """
    Derive a 256-bit encryption key from a human passphrase.
    Supports Argon2id (memory-hard, recommended) or PBKDF2-HMAC-SHA256 (600,000 rounds).
    Returns (raw_32_bytes, salt).
    """
    if salt is None:
        salt = get_or_create_db_salt()

    chosen_algo = (algorithm or os.getenv("KDF_ALGORITHM", "AUTO")).upper()
    if chosen_algo == "AUTO":
        chosen_algo = "ARGON2ID" if _HAS_ARGON2 else "PBKDF2"

    if chosen_algo == "ARGON2ID":
        if not _HAS_ARGON2:
            import warnings
            warnings.warn("Argon2id requested but argon2-cffi is not installed. Falling back to PBKDF2-HMAC-SHA256.")
            chosen_algo = "PBKDF2"
        else:
            key_material = argon2.low_level.hash_secret_raw(
                secret=passphrase.encode("utf-8"),
                salt=salt,
                time_cost=2,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            return key_material, salt

    # PBKDF2-HMAC-SHA256 (600,000 rounds)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key_material = kdf.derive(passphrase.encode("utf-8"))
    return key_material, salt


def get_active_kdf_algorithm() -> str:
    """Get the currently configured or active KDF algorithm ('ARGON2ID' or 'PBKDF2')."""
    env_algo = os.getenv("KDF_ALGORITHM", "AUTO").upper()
    if env_algo == "AUTO":
        return "ARGON2ID" if _HAS_ARGON2 else "PBKDF2"
    return env_algo


def set_cipher_passphrase(passphrase: str, salt: bytes | None = None):
    """Set active database cipher using a human passphrase."""
    key_bytes, _ = derive_key_from_passphrase(passphrase, salt=salt)
    set_cipher_key(key_bytes)


def get_active_compression() -> str:
    """Get the currently active compression algorithm ('ZSTD', 'ZLIB', or 'NONE')."""
    global _compression_override
    if _compression_override is not None:
        return _compression_override.upper()
    env_comp = os.getenv("COMPRESSION_ALGORITHM", "AUTO").upper()
    if env_comp == "AUTO" or env_comp == "":
        return "ZSTD" if _HAS_ZSTD else "ZLIB"
    return env_comp


def set_active_compression(codec: str | None):
    """Set the active compression algorithm ('ZSTD', 'ZLIB', 'NONE', or None for auto)."""
    global _compression_override
    if codec is not None:
        codec_up = codec.upper()
        if codec_up not in ("ZSTD", "ZLIB", "NONE", "AUTO"):
            raise ValueError(f"Unsupported compression codec: {codec}. Must be 'ZSTD', 'ZLIB', 'NONE', or 'AUTO'.")
        if codec_up == "AUTO":
            _compression_override = None
        else:
            _compression_override = codec_up
    else:
        _compression_override = None


def get_active_algorithm() -> str:
    """Get the currently configured encryption algorithm."""
    return os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM").upper()


def derive_cipher_subkey(raw_key: bytes, context: bytes) -> bytes:
    """Derive a domain-separated 32-byte encryption subkey per cipher algorithm via HKDF-SHA256."""
    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            raw_key = decoded
    except Exception:
        pass
    if len(raw_key) != 32:
        raw_key = hashlib.sha256(raw_key).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"encrypted-sqlite-cipher-subkey-v2",
        info=context,
    ).derive(raw_key)


def _build_v2_ciphers(key_material: bytes) -> tuple[AESGCM, Fernet, ChaCha20Poly1305]:
    """Construct HKDF-isolated AESGCM, Fernet, and ChaCha20Poly1305 ciphers from 32-byte key material."""
    gcm_sub = derive_cipher_subkey(key_material, b"aes-256-gcm-v2")
    fernet_sub = derive_cipher_subkey(key_material, b"fernet-aes-128-v2")
    chacha_sub = derive_cipher_subkey(key_material, b"chacha20-poly1305-v2")
    return (
        AESGCM(gcm_sub),
        Fernet(base64.urlsafe_b64encode(fernet_sub)),
        ChaCha20Poly1305(chacha_sub),
    )


def _get_max_decompressed_bytes() -> int:
    """Maximum allowed uncompressed payload size (default 256 MiB) to block decompression bombs."""
    try:
        mb = float(os.getenv("MAX_DECOMPRESSED_SIZE_MB", "256"))
        return max(1024 * 1024, int(mb * 1024 * 1024))
    except ValueError:
        return 256 * 1024 * 1024


def _get_raw_key_material() -> bytes:
    """
    Retrieve raw 32 bytes of the active master key.
    Order: ENCRYPTION_KEY env -> legacy secret.key (if present) -> OS KeyManager (DPAPI/Keyring) -> generate via KeyManager.
    """
    raw_key = os.getenv("ENCRYPTION_KEY")

    if not raw_key:
        key_file = ROOT_DIR / "secret.key"
        if key_file.exists():
            raw_key = key_file.read_text().strip()

    if not raw_key:
        try:
            from .keyring_manager import KeyManager
            raw_key = KeyManager.get_master_key(storage_dir=DATA_DIR)
        except Exception:
            raw_key = None

    if not raw_key:
        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        new_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        try:
            from .keyring_manager import KeyManager
            backend = KeyManager.save_master_key(new_key, storage_dir=DATA_DIR)
            print(f"[Database] Generated new encryption key and stored via KeyManager ({backend}).")
        except Exception:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            fallback_file = DATA_DIR / ".master_key.key"
            fallback_file.write_text(new_key, encoding="utf-8")
            try:
                os.chmod(fallback_file, 0o600)
            except Exception:
                pass
        raw_key = new_key

    if isinstance(raw_key, str):
        raw_key = raw_key.encode("utf-8")

    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    if len(raw_key) == 32:
        return raw_key

    return hashlib.sha256(raw_key).digest()


def _get_ciphers() -> tuple[AESGCM, Fernet]:
    """Retrieve or generate legacy v1 AESGCM and Fernet cipher instances (and warm v2 subkeys)."""
    global _cipher_aesgcm, _cipher_fernet, _cipher_chacha
    global _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2
    if _cipher_aesgcm is not None and _cipher_fernet is not None:
        return _cipher_aesgcm, _cipher_fernet

    key_material = _get_raw_key_material()

    _cipher_fernet = Fernet(base64.urlsafe_b64encode(key_material))
    _cipher_aesgcm = AESGCM(key_material)
    _cipher_chacha = ChaCha20Poly1305(key_material)
    _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2 = _build_v2_ciphers(key_material)

    return _cipher_aesgcm, _cipher_fernet


def _get_ciphers_v2() -> tuple[AESGCM, Fernet, ChaCha20Poly1305]:
    """Retrieve HKDF domain-separated v2 ciphers for AES-256-GCM, Fernet, and ChaCha20-Poly1305."""
    global _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2
    if _cipher_aesgcm_v2 is None or _cipher_fernet_v2 is None or _cipher_chacha_v2 is None:
        _get_ciphers()
    assert _cipher_aesgcm_v2 is not None and _cipher_fernet_v2 is not None and _cipher_chacha_v2 is not None
    return _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2


def _get_chacha_cipher() -> ChaCha20Poly1305:
    """Retrieve or initialize legacy v1 ChaCha20Poly1305 cipher."""
    global _cipher_chacha
    if _cipher_chacha is not None:
        return _cipher_chacha
    _get_ciphers()
    assert _cipher_chacha is not None
    return _cipher_chacha


def _get_cipher() -> Any:
    """Retrieve the global active cipher instance based on current algorithm (for backward compatibility)."""
    aesgcm_cipher, fernet_cipher = _get_ciphers()
    algo = get_active_algorithm()
    if algo == "AES-128-FERNET":
        return fernet_cipher
    elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
        return _get_chacha_cipher()
    return aesgcm_cipher


def set_cipher_key(new_key: str | bytes):
    """Update active in-memory cipher keys (both HKDF v2 subkeys and legacy v1 ciphers)."""
    global _cipher_aesgcm, _cipher_fernet, _cipher_chacha
    global _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2
    if isinstance(new_key, str):
        new_key = new_key.encode("utf-8")

    try:
        key_material = base64.urlsafe_b64decode(new_key)
        if len(key_material) == 32:
            _cipher_aesgcm = AESGCM(key_material)
            _cipher_fernet = Fernet(new_key)
            _cipher_chacha = ChaCha20Poly1305(key_material)
            _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2 = _build_v2_ciphers(key_material)
            os.environ["ENCRYPTION_KEY"] = new_key.decode("utf-8")
            return
    except Exception:
        pass

    if len(new_key) == 32:
        _cipher_aesgcm = AESGCM(new_key)
        _cipher_fernet = Fernet(base64.urlsafe_b64encode(new_key))
        _cipher_chacha = ChaCha20Poly1305(new_key)
        _cipher_aesgcm_v2, _cipher_fernet_v2, _cipher_chacha_v2 = _build_v2_ciphers(new_key)
        os.environ["ENCRYPTION_KEY"] = base64.urlsafe_b64encode(new_key).decode("utf-8")
    else:
        raise ValueError("Key must be 32 bytes or 44-character URL-safe Base64 encoded key.")


def derive_indexing_key(raw_key: bytes) -> bytes:
    """Derive a secure 32-byte blind indexing key from master key using HKDF domain separation."""
    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            raw_key = decoded
    except Exception:
        pass
    if len(raw_key) != 32:
        raw_key = hashlib.sha256(raw_key).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sqlite-blind-index-salt-v1",
        info=b"sqlite-blind-indexing",
    )
    return hkdf.derive(raw_key)


def derive_integrity_key(raw_key: bytes) -> bytes:
    """Derive a secure 32-byte record integrity signing key from master key using HKDF domain separation."""
    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            raw_key = decoded
    except Exception:
        pass
    if len(raw_key) != 32:
        raw_key = hashlib.sha256(raw_key).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sqlite-integrity-salt-v1",
        info=b"sqlite-integrity-hmac",
    )
    return hkdf.derive(raw_key)


def _get_indexing_key() -> bytes:
    """Derive a secure 32-byte indexing key from the master encryption key."""
    return derive_indexing_key(_get_raw_key_material())


def _get_integrity_key() -> bytes:
    """Derive a secure 32-byte integrity key from the master encryption key."""
    return derive_integrity_key(_get_raw_key_material())


def compute_blind_index(value: Any, custom_derived_key: bytes | None = None) -> str:
    """Compute a secure, deterministic blind index hash for a queryable value."""
    if value is None:
        return ""
    val_str = str(value).strip()
    idx_key = custom_derived_key if custom_derived_key is not None else _get_indexing_key()
    return hmac.new(idx_key, val_str.encode("utf-8"), hashlib.sha256).hexdigest()


def _extract_field_values(obj: Any, field_path: str) -> list[Any]:
    """
    Extract scalar values from a document using dot-notation paths (e.g. 'profile.email', 'tags').
    Automatically traverses nested dicts and lists/tuples of values or objects.
    """
    parts = [p for p in field_path.split(".") if p]
    if not parts:
        return []

    def _walk(current: Any, idx: int) -> list[Any]:
        if current is None:
            return []
        if idx == len(parts):
            if isinstance(current, (list, tuple, set)):
                out = []
                for item in current:
                    out.extend(_walk(item, idx))
                return out
            if isinstance(current, dict):
                return []
            return [current]
        if isinstance(current, (list, tuple)):
            out = []
            for item in current:
                out.extend(_walk(item, idx))
            return out
        if isinstance(current, dict):
            part = parts[idx]
            if part in current:
                return _walk(current[part], idx + 1)
        return []

    return _walk(obj, 0)


def derive_key_encryption_subkeys(raw_key: bytes) -> tuple[bytes, bytes]:
    """Derive deterministic Synthetic-IV MAC and AES-256 keys from master key via HKDF."""
    try:
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) == 32:
            raw_key = decoded
    except Exception:
        pass
    if len(raw_key) != 32:
        raw_key = hashlib.sha256(raw_key).digest()
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sqlite-key-siv-salt-v1",
        info=b"sqlite-key-siv-mac",
    ).derive(raw_key)
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sqlite-key-siv-salt-v1",
        info=b"sqlite-key-siv-aes",
    ).derive(raw_key)
    return mac_key, enc_key


def set_key_encryption(enabled: bool | None):
    """Enable or disable deterministic Synthetic-IV encryption of SQLite primary keys."""
    global _key_encryption_override
    _key_encryption_override = enabled


def get_key_encryption() -> bool:
    """Return True if deterministic key-name encryption is currently active."""
    if _key_encryption_override is not None:
        return _key_encryption_override
    return os.getenv("ENCRYPT_KEYS", "false").lower() in ("true", "1", "yes")


def encrypt_db_key(plain_key: str, raw_key: bytes | None = None) -> str:
    """Deterministically encrypt a document key name using Synthetic-IV AES-256-GCM."""
    if plain_key.startswith(_PREFIX_ENC_KEY):
        return plain_key
    key_mat = raw_key if raw_key is not None else _get_raw_key_material()
    mac_key, enc_key = derive_key_encryption_subkeys(key_mat)
    key_bytes = plain_key.encode("utf-8")
    siv = hmac.new(mac_key, key_bytes, hashlib.sha256).digest()[:12]
    ct = AESGCM(enc_key).encrypt(siv, key_bytes, associated_data=b"sqlite-key-siv-v1")
    token = base64.urlsafe_b64encode(siv + ct).decode("ascii").rstrip("=")
    return f"{_PREFIX_ENC_KEY}{token}"


def decrypt_db_key(stored_key: str, raw_key: bytes | None = None) -> str:
    """Decrypt an ENCK1: deterministic key name, or return plaintext keys unchanged."""
    if not stored_key.startswith(_PREFIX_ENC_KEY):
        return stored_key
    key_mat = raw_key if raw_key is not None else _get_raw_key_material()
    mac_key, enc_key = derive_key_encryption_subkeys(key_mat)
    b64_part = stored_key[len(_PREFIX_ENC_KEY):]
    pad = "=" * ((4 - len(b64_part) % 4) % 4)
    raw = base64.urlsafe_b64decode(b64_part + pad)
    if len(raw) < 28:
        raise ValueError("Invalid encrypted key token.")
    siv, ct = raw[:12], raw[12:]
    plain_bytes = AESGCM(enc_key).decrypt(siv, ct, associated_data=b"sqlite-key-siv-v1")
    expected_siv = hmac.new(mac_key, plain_bytes, hashlib.sha256).digest()[:12]
    if not hmac.compare_digest(siv, expected_siv):
        raise ValueError("Synthetic-IV mismatch on encrypted key.")
    return plain_bytes.decode("utf-8")


def _to_storage_key(plain_key: str) -> str:
    """Convert plaintext key to storage key when key encryption is enabled."""
    if get_key_encryption():
        return encrypt_db_key(plain_key)
    return plain_key


def _update_blind_indexes(conn, storage_key: str, data: Any, custom_derived_key: bytes | None = None):
    """Index configured top-level, nested dot-path, and list fields for the given key/document."""
    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (storage_key,))

    if not isinstance(data, dict) or not _indexed_fields:
        return

    index_records = set()
    idx_key = custom_derived_key if custom_derived_key is not None else _get_indexing_key()

    for field in _indexed_fields:
        extracted = _extract_field_values(data, field)
        for val in extracted:
            val_str = str(val).strip()
            val_hash = hmac.new(idx_key, val_str.encode("utf-8"), hashlib.sha256).hexdigest()
            index_records.add((storage_key, field, val_hash))

    if index_records:
        conn.executemany("""
            INSERT OR REPLACE INTO blind_indexes (key, field_name, field_hash)
            VALUES (?, ?, ?)
        """, list(index_records))


from . import serializers


def pack_and_encrypt(data: Any, cipher: Any = None, associated_data: bytes | None = None) -> bytes:
    """Serialize, compress, encrypt, and prefix with algorithm identifier."""
    t0 = time.perf_counter()
    raw_bytes = serializers.dumps(data)

    # Compress if payload is larger than 128 bytes and compression is enabled
    comp_algo = get_active_compression()
    if len(raw_bytes) > 128 and comp_algo != "NONE":
        if comp_algo == "ZSTD" and _HAS_ZSTD and _zstd_compressor is not None:
            payload = _MAGIC_COMPRESSED_ZSTD + _zstd_compressor.compress(raw_bytes)
        else:
            payload = _MAGIC_COMPRESSED_ZL + zlib.compress(raw_bytes, level=6)
    else:
        payload = _MAGIC_RAW + raw_bytes

    # Handle explicit custom cipher instance
    if cipher is not None:
        if isinstance(cipher, AESGCM):
            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_GCM + nonce + ciphertext
        elif isinstance(cipher, ChaCha20Poly1305):
            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_CHACHA + nonce + ciphertext
        elif isinstance(cipher, Fernet):
            ciphertext = cipher.encrypt(payload)
            res = _PREFIX_FERNET + ciphertext
        else:
            raise TypeError("Cipher must be an instance of AESGCM, ChaCha20Poly1305, or Fernet.")
    else:
        # Encrypt using HKDF domain-separated v2 subkeys for the active algorithm
        gcm_v2, fernet_v2, chacha_v2 = _get_ciphers_v2()
        algo = get_active_algorithm()

        if algo == "AES-128-FERNET":
            ciphertext = fernet_v2.encrypt(payload)
            res = _PREFIX_FERNET + _SUBKEY_V2_TAG + ciphertext
        elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
            nonce = os.urandom(12)
            ciphertext = chacha_v2.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_CHACHA + _SUBKEY_V2_TAG + nonce + ciphertext
        else:
            nonce = os.urandom(12)
            ciphertext = gcm_v2.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_GCM + _SUBKEY_V2_TAG + nonce + ciphertext

    try:
        from .metrics import metrics
        metrics.record_latency("encrypt", time.perf_counter() - t0)
    except Exception:
        pass

    return res


def decrypt_and_unpack(encrypted_blob: bytes, cipher: Any = None, associated_data: bytes | None = None) -> Any:
    """Decrypt, decompress (with decompression-bomb cap), and deserialize payload."""
    t0 = time.perf_counter()
    if len(encrypted_blob) < 5:
        raise ValueError("Encrypted payload too short.")

    decrypted = None

    # Handle explicit custom cipher instance
    if cipher is not None:
        actual_blob = encrypted_blob
        if (
            encrypted_blob.startswith(_PREFIX_GCM)
            or encrypted_blob.startswith(_PREFIX_FERNET)
            or encrypted_blob.startswith(_PREFIX_CHACHA)
        ):
            actual_blob = encrypted_blob[5:]
        if actual_blob.startswith(_SUBKEY_V2_TAG):
            actual_blob = actual_blob[len(_SUBKEY_V2_TAG):]

        if isinstance(cipher, AESGCM):
            if len(actual_blob) < 12:
                raise ValueError("Payload missing GCM nonce.")
            nonce = actual_blob[:12]
            ciphertext = actual_blob[12:]
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
        elif isinstance(cipher, ChaCha20Poly1305):
            if len(actual_blob) < 12:
                raise ValueError("Payload missing ChaCha20 nonce.")
            nonce = actual_blob[:12]
            ciphertext = actual_blob[12:]
            decrypted = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
        elif isinstance(cipher, Fernet):
            decrypted = cipher.decrypt(actual_blob)
        else:
            raise TypeError("Cipher must be an instance of AESGCM, ChaCha20Poly1305, or Fernet.")
    else:
        # Auto-detect using prefixes + HKDF subkey generation (v2 vs legacy v1)
        aesgcm_v1, fernet_v1 = _get_ciphers()
        gcm_v2, fernet_v2, chacha_v2 = _get_ciphers_v2()

        if encrypted_blob.startswith(_PREFIX_GCM):
            actual_blob = encrypted_blob[5:]
            use_gcm = gcm_v2 if actual_blob.startswith(_SUBKEY_V2_TAG) else aesgcm_v1
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                actual_blob = actual_blob[len(_SUBKEY_V2_TAG):]
            if len(actual_blob) < 12:
                raise ValueError("Payload missing GCM nonce.")
            decrypted = use_gcm.decrypt(actual_blob[:12], actual_blob[12:], associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_CHACHA):
            actual_blob = encrypted_blob[5:]
            use_chacha = chacha_v2 if actual_blob.startswith(_SUBKEY_V2_TAG) else _get_chacha_cipher()
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                actual_blob = actual_blob[len(_SUBKEY_V2_TAG):]
            if len(actual_blob) < 12:
                raise ValueError("Payload missing ChaCha20 nonce.")
            decrypted = use_chacha.decrypt(actual_blob[:12], actual_blob[12:], associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_FERNET):
            actual_blob = encrypted_blob[5:]
            if actual_blob.startswith(_SUBKEY_V2_TAG):
                decrypted = fernet_v2.decrypt(actual_blob[len(_SUBKEY_V2_TAG):])
            else:
                decrypted = fernet_v1.decrypt(actual_blob)
        elif encrypted_blob[0] == 0x80 or encrypted_blob.startswith(b"gAAAA"):
            try:
                decrypted = fernet_v1.decrypt(encrypted_blob)
            except Exception:
                algo = get_active_algorithm()
                if algo == "AES-128-FERNET":
                    decrypted = fernet_v1.decrypt(encrypted_blob)
                else:
                    if len(encrypted_blob) < 12:
                        raise ValueError("Payload missing GCM nonce.")
                    decrypted = aesgcm_v1.decrypt(encrypted_blob[:12], encrypted_blob[12:], associated_data=associated_data)
        else:
            algo = get_active_algorithm()
            if algo == "AES-128-FERNET":
                decrypted = fernet_v1.decrypt(encrypted_blob)
            else:
                if len(encrypted_blob) < 12:
                    raise ValueError("Payload missing GCM nonce.")
                decrypted = aesgcm_v1.decrypt(encrypted_blob[:12], encrypted_blob[12:], associated_data=associated_data)

    # Bounded decompression to prevent zip/zstd memory exhaustion bombs
    max_out = _get_max_decompressed_bytes()
    if decrypted.startswith(_MAGIC_COMPRESSED_ZSTD):
        comp_body = decrypted[len(_MAGIC_COMPRESSED_ZSTD):]
        if _HAS_ZSTD and _zstd_decompressor is not None:
            raw_bytes = _zstd_decompressor.decompress(comp_body, max_output_size=max_out)
        else:
            import zstandard as zstd
            raw_bytes = zstd.ZstdDecompressor().decompress(comp_body, max_output_size=max_out)
    elif decrypted.startswith(_MAGIC_COMPRESSED_ZL):
        dobj = zlib.decompressobj()
        raw_bytes = dobj.decompress(decrypted[len(_MAGIC_COMPRESSED_ZL):], max_out)
        if dobj.unconsumed_tail:
            raise ValueError(f"Decompressed zlib payload exceeds maximum allowed size ({max_out} bytes).")
    elif decrypted.startswith(_MAGIC_RAW):
        raw_bytes = decrypted[len(_MAGIC_RAW):]
        if len(raw_bytes) > max_out:
            raise ValueError(f"Uncompressed payload exceeds maximum allowed size ({max_out} bytes).")
    else:
        raw_bytes = decrypted

    result = serializers.loads(raw_bytes)
    try:
        from .metrics import metrics
        metrics.record_latency("decrypt", time.perf_counter() - t0)
    except Exception:
        pass

    return result


from .bloom_filter import BloomFilter

# In-Memory Bloom Filter for 0-Disk Misses
bloom = BloomFilter(expected_elements=50000, false_positive_rate=0.01)


def _get_decrypt_executor():
    """Return a shared persistent ThreadPoolExecutor for parallel batch decryption."""
    global _decrypt_executor
    if _decrypt_executor is None:
        with _executor_lock:
            if _decrypt_executor is None:
                from concurrent.futures import ThreadPoolExecutor
                _decrypt_executor = ThreadPoolExecutor(
                    max_workers=min(16, os.cpu_count() or 4),
                    thread_name_prefix="EncryptedSQLite-Decrypt",
                )
    return _decrypt_executor


def close_all_connections():
    """Close all tracked SQLite connections across threads (e.g. prior to DB restore or shutdown)."""
    global _db_initialized
    with _conn_lock:
        for c in list(_active_connections):
            try:
                c.close()
            except Exception:
                pass
        _active_connections.clear()
    _local.conn = None
    _db_initialized = False


def get_db_connection() -> sqlite3.Connection:
    """Obtain a thread-local SQLite connection configured with WAL and MMAP mode."""
    if hasattr(_local, "conn") and _local.conn is not None:
        with _conn_lock:
            if _local.conn in _active_connections:
                return _local.conn
        _local.conn = None

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=30.0,
        check_same_thread=False,
        isolation_level=None
    )
    conn.row_factory = sqlite3.Row

    # Performance, MMAP & Concurrency PRAGMAs
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.execute("PRAGMA cache_size = -64000;")         # 64 MB Page Cache
    conn.execute("PRAGMA mmap_size = 268435456;")       # 256 MB Direct Kernel Memory-Mapped I/O
    conn.execute("PRAGMA temp_store = MEMORY;")         # RAM-based temporary structures
    conn.execute("PRAGMA wal_autocheckpoint = 1000;")

    with _conn_lock:
        _active_connections.add(conn)
    _local.conn = conn
    return conn


def rebuild_bloom_filter():
    """Rebuild the in-memory Bloom filter from active non-expired keys in SQLite."""
    conn = get_db_connection()
    now_ts = int(time.time())
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM kv_store WHERE expires_at == 0 OR expires_at > ?", (now_ts,))
    keys = []
    for r in cursor.fetchall():
        raw_k = r["key"]
        try:
            keys.append(decrypt_db_key(raw_k))
        except Exception:
            keys.append(raw_k)
    bloom.clear()
    bloom.populate_from_keys(keys)


def init_db():
    """Idempotently initialize database tables, indexes, and populate bloom filter."""
    global _db_initialized
    if _db_initialized:
        return

    with _init_lock:
        if _db_initialized:
            return

        conn = get_db_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    expires_at INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
            """)

            # Migration: Add version and expires_at columns to existing databases
            try:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(kv_store)")
                columns = [col["name"] for col in cursor.fetchall()]
                if "version" not in columns:
                    conn.execute("ALTER TABLE kv_store ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
                if "expires_at" not in columns:
                    conn.execute("ALTER TABLE kv_store ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0")
            except Exception:
                pass

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv_store (expires_at);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_kv_expires_updated ON kv_store (expires_at, updated_at DESC);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blind_indexes (
                    key TEXT NOT NULL,
                    field_name TEXT NOT NULL,
                    field_hash TEXT NOT NULL,
                    PRIMARY KEY (key, field_name, field_hash)
                );
            """)
            # Migrate legacy 2-column PK blind_indexes (key, field_name) -> 3-column PK (key, field_name, field_hash)
            try:
                idx_cols = conn.execute("PRAGMA table_info(blind_indexes)").fetchall()
                pk_cols = [c["name"] for c in idx_cols if c["pk"] > 0]
                if len(pk_cols) < 3:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS blind_indexes_v2 (
                            key TEXT NOT NULL,
                            field_name TEXT NOT NULL,
                            field_hash TEXT NOT NULL,
                            PRIMARY KEY (key, field_name, field_hash)
                        );
                    """)
                    conn.execute("""
                        INSERT OR IGNORE INTO blind_indexes_v2 (key, field_name, field_hash)
                        SELECT key, field_name, field_hash FROM blind_indexes;
                    """)
                    conn.execute("DROP TABLE blind_indexes;")
                    conn.execute("ALTER TABLE blind_indexes_v2 RENAME TO blind_indexes;")
            except Exception:
                pass
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_blind_hash ON blind_indexes (field_name, field_hash);
            """)

        # Populate in-memory bloom filter from existing non-expired keys
        try:
            rebuild_bloom_filter()
        except Exception:
            pass

        # Check if auto key rotation is enabled in env
        auto_rotate = os.getenv("AUTO_KEY_ROTATION", "false").lower() in ("true", "1", "yes")
        if auto_rotate:
            try:
                from .key_rotation import rotator
                interval_days_str = os.getenv("KEY_ROTATION_INTERVAL_DAYS", "90")
                try:
                    interval_days = float(interval_days_str)
                except ValueError:
                    interval_days = 90.0
                rotator.rotation_interval = interval_days * 86400.0
                rotator.start()
            except Exception as e:
                print(f"[Database] Failed to start auto-key rotation: {e}")

        # Check if auto TTL scavenger is enabled in env (default: true)
        auto_scavenger = os.getenv("AUTO_TTL_SCAVENGER", "true").lower() in ("true", "1", "yes")
        if auto_scavenger:
            try:
                scavenger.start()
            except Exception:
                pass

        _db_initialized = True


# ─── Key-Value Store Operations ───────────────────────────────────────────────

def _lookup_storage_row(conn: sqlite3.Connection, plain_key: str, columns: str = "key, value, expires_at"):
    """Fetch a row by encrypted storage key (if enabled) with seamless fallback to plaintext key."""
    cursor = conn.cursor()
    storage_key = _to_storage_key(plain_key)
    cursor.execute(f"SELECT {columns} FROM kv_store WHERE key = ?", (storage_key,))
    row = cursor.fetchone()
    if row is None and storage_key != plain_key:
        cursor.execute(f"SELECT {columns} FROM kv_store WHERE key = ?", (plain_key,))
        row = cursor.fetchone()
    return row


def kv_get_with_expiry(key: str, default: Any = None) -> tuple[Any, float | None]:
    """Retrieve decrypted document alongside its expiration timestamp (or None)."""
    init_db()
    plain_key = decrypt_db_key(key) if key.startswith(_PREFIX_ENC_KEY) else key

    # Fast Bloom filter check: if definitely not in database, return 0-disk miss immediately
    if not bloom.contains(plain_key):
        return default, None

    conn = get_db_connection()
    row = _lookup_storage_row(conn, plain_key, "key, value, expires_at")
    if row is None:
        return default, None

    # Check database-level TTL
    now_ts = int(time.time())
    expires_at = row["expires_at"]
    if expires_at > 0 and expires_at <= now_ts:
        try:
            kv_delete(plain_key)
        except Exception:
            pass
        return default, None

    try:
        from .metrics import metrics
        metrics.record_operation("read")
    except Exception:
        pass

    try:
        data = decrypt_and_unpack(row["value"], associated_data=plain_key.encode("utf-8"))
        return data, (float(expires_at) if expires_at > 0 else None)
    except Exception as e:
        print(f"[Database] Error decrypting kv '{plain_key}': {e}")
        return default, None


def kv_get(key: str, default: Any = None) -> Any:
    """Retrieve, decrypt, and decompress a JSON document from kv_store with TTL check."""
    data, _ = kv_get_with_expiry(key, default=default)
    return data


def _upsert_kv_batch(
    conn: sqlite3.Connection,
    batch_records: list[tuple[str, bytes, int, int]],
    raw_items: list[tuple[str, Any]],
):
    """Shared atomic upsert for kv_store, blind_indexes, and bloom filter."""
    if not batch_records:
        return
    key_enc_active = get_key_encryption()
    prepared_records = []
    legacy_plain_keys_to_clean = []
    for storage_or_plain_key, blob, expires_at, now_ts in batch_records:
        if key_enc_active and not storage_or_plain_key.startswith(_PREFIX_ENC_KEY):
            s_key = encrypt_db_key(storage_or_plain_key)
            legacy_plain_keys_to_clean.append((storage_or_plain_key,))
        else:
            s_key = storage_or_plain_key
        prepared_records.append((s_key, blob, expires_at, now_ts))

    if legacy_plain_keys_to_clean:
        conn.executemany("DELETE FROM blind_indexes WHERE key = ?", legacy_plain_keys_to_clean)
        conn.executemany("DELETE FROM kv_store WHERE key = ?", legacy_plain_keys_to_clean)

    conn.executemany("""
        INSERT INTO kv_store (key, value, version, expires_at, updated_at)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            version = version + 1,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at;
    """, prepared_records)
    for (s_key, _, _, _), (plain_key, data) in zip(prepared_records, raw_items):
        _update_blind_indexes(conn, s_key, data)
        bloom.add(decrypt_db_key(plain_key) if plain_key.startswith(_PREFIX_ENC_KEY) else plain_key)


def kv_set(key: str, data: Any, ttl: int | float | None = None):
    """Compress, encrypt, and store any Python dict/list into kv_store with optional TTL (seconds)."""
    init_db()
    conn = get_db_connection()
    encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
    storage_key = _to_storage_key(key)

    with conn:
        _upsert_kv_batch(conn, [(storage_key, encrypted_blob, expires_at, now_ts)], [(key, data)])

    try:
        from .metrics import metrics
        metrics.record_operation("write")
    except Exception:
        pass
    try:
        from .events import events
        events.emit("write", key=key, value=data)
    except Exception:
        pass


def kv_get_versioned(key: str, default: Any = None) -> tuple[Any, int]:
    """Retrieve both the decrypted payload and its current version number with TTL check."""
    init_db()
    plain_key = decrypt_db_key(key) if key.startswith(_PREFIX_ENC_KEY) else key

    # Fast Bloom filter check: if definitely not in database, return 0-disk miss immediately
    if not bloom.contains(plain_key):
        return default, 0

    conn = get_db_connection()
    row = _lookup_storage_row(conn, plain_key, "key, value, version, expires_at")
    if row is None:
        return default, 0

    now_ts = int(time.time())
    if row["expires_at"] > 0 and row["expires_at"] <= now_ts:
        try:
            kv_delete(plain_key)
        except Exception:
            pass
        return default, 0

    try:
        data = decrypt_and_unpack(row["value"], associated_data=plain_key.encode("utf-8"))
        return data, row["version"]
    except Exception as e:
        print(f"[Database] Error decrypting versioned kv '{plain_key}': {e}")
        return default, 0


def kv_set_versioned(key: str, data: Any, expected_version: int, ttl: int | float | None = None) -> int:
    """
    Atomically write a JSON document only if its current database version matches expected_version.
    Increments and returns the new version number upon success.
    Raises ConcurrentModificationError on mismatch.
    """
    init_db()
    conn = get_db_connection()
    encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0
    storage_key = _to_storage_key(key)

    with conn:
        if expected_version == 0:
            # Also reject if plaintext legacy key exists while key encryption is active
            if storage_key != key:
                exists_legacy = conn.execute("SELECT 1 FROM kv_store WHERE key = ?", (key,)).fetchone()
                if exists_legacy is not None:
                    raise ConcurrentModificationError(
                        f"Cannot write key '{key}' with expected_version=0: record already exists."
                    )
            try:
                conn.execute("""
                    INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                    VALUES (?, ?, 1, ?, ?)
                """, (storage_key, encrypted_blob, expires_at, now_ts))
                _update_blind_indexes(conn, storage_key, data)
                bloom.add(key)
                new_ver = 1
            except sqlite3.IntegrityError:
                raise ConcurrentModificationError(
                    f"Cannot write key '{key}' with expected_version=0: record already exists."
                )
        else:
            cursor = conn.execute("""
                UPDATE kv_store
                SET value = ?, version = version + 1, expires_at = ?, updated_at = ?
                WHERE key = ? AND version = ?
            """, (encrypted_blob, expires_at, now_ts, storage_key, expected_version))

            target_storage_key = storage_key
            if cursor.rowcount == 0 and storage_key != key:
                # Fallback check for pre-encryption plaintext key
                cursor = conn.execute("""
                    UPDATE kv_store
                    SET key = ?, value = ?, version = version + 1, expires_at = ?, updated_at = ?
                    WHERE key = ? AND version = ?
                """, (storage_key, encrypted_blob, expires_at, now_ts, key, expected_version))
                if cursor.rowcount > 0:
                    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (key,))

            if cursor.rowcount == 0:
                row = _lookup_storage_row(conn, key, "version")
                if row is None:
                    raise ConcurrentModificationError(
                        f"Cannot update key '{key}': record does not exist (expected version {expected_version})."
                    )
                else:
                    actual_version = row["version"]
                    raise ConcurrentModificationError(
                        f"Conflict detected on key '{key}': current version is {actual_version}, but expected {expected_version}."
                    )
            _update_blind_indexes(conn, target_storage_key, data)
            new_ver = expected_version + 1

    try:
        from .metrics import metrics
        metrics.record_operation("write")
    except Exception:
        pass

    try:
        from .events import events
        events.emit("write", key=key, value=data)
    except Exception:
        pass

    return new_ver


def _safe_data_file_path(data_dir: Path, key: str) -> Path | None:
    """Resolve key inside data_dir safely, rejecting path traversal outside data_dir."""
    base = data_dir.resolve()
    candidate = (data_dir / key).resolve()
    if candidate == base or not candidate.is_relative_to(base):
        return None
    return candidate


def kv_delete(key: str) -> bool:
    """Delete a document by key from kv_store, clear its blind indexes, and remove disk backup if present."""
    init_db()
    plain_key = decrypt_db_key(key) if key.startswith(_PREFIX_ENC_KEY) else key
    storage_key = _to_storage_key(plain_key)
    candidate_keys = [storage_key] if storage_key == plain_key else [storage_key, plain_key]

    conn = get_db_connection()
    with conn:
        for ck in candidate_keys:
            conn.execute("DELETE FROM blind_indexes WHERE key = ?", (ck,))
        placeholders = ",".join("?" * len(candidate_keys))
        cur = conn.execute(f"DELETE FROM kv_store WHERE key IN ({placeholders})", candidate_keys)
        deleted = cur.rowcount > 0

        # Prevent zombie resurrects in load_json by cleaning up fallback disk file safely
        try:
            target = _safe_data_file_path(DATA_DIR, plain_key)
            if target is not None and target.exists():
                target.unlink()
            tmp_target = _safe_data_file_path(DATA_DIR, f"{plain_key}.tmp")
            if tmp_target is not None and tmp_target.exists():
                tmp_target.unlink()
        except Exception:
            pass

        if deleted:
            try:
                from .cache import cache
                cache._adapter.delete(plain_key)
            except Exception:
                pass
            try:
                from .metrics import metrics
                metrics.record_operation("delete")
            except Exception:
                pass
            try:
                from .events import events
                events.emit("delete", key=plain_key)
            except Exception:
                pass
        return deleted


def kv_search(pattern: str = "*", limit: int | None = None) -> list[str]:
    """
    Search all non-expired keys matching a wildcard glob pattern (e.g. 'user_*', 'ticket_*.json').
    Supports both standard SQLite GLOB and deterministic encrypted keys (ENCK1:).
    """
    import fnmatch
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_ts = int(time.time())

    # Check if encrypted keys are active or present
    has_enc_keys = get_key_encryption()
    if not has_enc_keys:
        chk = cursor.execute("SELECT 1 FROM kv_store WHERE key LIKE 'ENCK1:%' LIMIT 1").fetchone()
        has_enc_keys = chk is not None

    if not has_enc_keys:
        if limit is not None and limit > 0:
            cursor.execute(
                "SELECT key FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?",
                (pattern, now_ts, limit)
            )
        else:
            cursor.execute(
                "SELECT key FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC",
                (pattern, now_ts)
            )
        return [row["key"] for row in cursor.fetchall()]

    # Encrypted keys mode: decrypt active keys and match glob in Python
    cursor.execute(
        "SELECT key FROM kv_store WHERE (expires_at == 0 OR expires_at > ?) ORDER BY updated_at DESC",
        (now_ts,)
    )
    matched: list[str] = []
    for row in cursor.fetchall():
        raw_k = row["key"]
        try:
            plain_k = decrypt_db_key(raw_k)
        except Exception:
            continue
        if pattern == "*" or fnmatch.fnmatchcase(plain_k, pattern):
            matched.append(plain_k)
            if limit is not None and limit > 0 and len(matched) >= limit:
                break
    return matched


def kv_find(
    predicate: Any,
    pattern: str = "*",
    limit: int | None = None
) -> list[dict[str, Any]]:
    """
    Search and filter decrypted documents matching a custom Python condition.
    """
    keys = kv_search(pattern=pattern)
    if not keys:
        return []

    matches = []
    # Process in bounded chunks to avoid large memory spikes when limit is small
    chunk_size = _SQLITE_MAX_VARS
    for idx in range(0, len(keys), chunk_size):
        batch_keys = keys[idx:idx + chunk_size]
        batch_docs = kv_mget(batch_keys)
        for k in batch_keys:
            if k not in batch_docs:
                continue
            doc = batch_docs[k]
            try:
                if predicate(doc):
                    matches.append(doc)
                    if limit is not None and len(matches) >= limit:
                        return matches
            except Exception:
                continue

    return matches


def kv_find_by_index(field_name: str, value: Any) -> dict[str, Any]:
    """
    Find and decrypt all documents where the specified field (including dot-paths or list items) matches value.
    Uses blind indexes for fast O(1) SQL-side lookups while filtering out expired records.
    """
    init_db()
    val_hash = compute_blind_index(value)
    conn = get_db_connection()
    cursor = conn.cursor()
    now_ts = int(time.time())
    cursor.execute("""
        SELECT DISTINCT b.key FROM blind_indexes b
        JOIN kv_store k ON b.key = k.key
        WHERE b.field_name = ? AND b.field_hash = ? AND (k.expires_at == 0 OR k.expires_at > ?)
    """, (field_name, val_hash, now_ts))
    plain_keys = []
    for row in cursor.fetchall():
        try:
            plain_keys.append(decrypt_db_key(row["key"]))
        except Exception:
            plain_keys.append(row["key"])
    if not plain_keys:
        return {}
    return kv_mget(plain_keys)


def kv_count(pattern: str | None = None) -> int:
    """Return total number of non-expired stored documents, optionally matching a pattern."""
    init_db()
    if pattern:
        # Delegate pattern matching to kv_search when encrypted keys may exist
        conn = get_db_connection()
        has_enc = get_key_encryption() or (
            conn.execute("SELECT 1 FROM kv_store WHERE key LIKE 'ENCK1:%' LIMIT 1").fetchone() is not None
        )
        if has_enc:
            return len(kv_search(pattern=pattern))
        now_ts = int(time.time())
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?)",
            (pattern, now_ts)
        ).fetchone()
        return row["total"] if row else 0

    conn = get_db_connection()
    now_ts = int(time.time())
    row = conn.execute(
        "SELECT COUNT(*) AS total FROM kv_store WHERE (expires_at == 0 OR expires_at > ?)",
        (now_ts,)
    ).fetchone()
    return row["total"] if row else 0


def kv_mget(keys: list[str]) -> dict[str, Any]:
    """
    Retrieve and decrypt multiple JSON documents using chunked SQL batch queries
    and a persistent multi-core thread pool with TTL filtering.
    """
    if not keys:
        return {}

    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_ts = int(time.time())

    # Map storage keys -> plaintext keys (supporting mixed encrypted/plaintext DBs)
    storage_to_plain: dict[str, str] = {}
    query_keys: list[str] = []
    key_enc = get_key_encryption()

    for k in keys:
        plain_k = decrypt_db_key(k) if k.startswith(_PREFIX_ENC_KEY) else k
        storage_to_plain[plain_k] = plain_k
        if key_enc:
            enc_k = encrypt_db_key(plain_k)
            storage_to_plain[enc_k] = plain_k
            query_keys.append(enc_k)
        query_keys.append(plain_k)

    # Deduplicate while preserving order, then execute in SQLite-safe chunks of 900
    unique_query_keys = list(dict.fromkeys(query_keys))
    rows = []
    for i in range(0, len(unique_query_keys), _SQLITE_MAX_VARS):
        chunk = unique_query_keys[i:i + _SQLITE_MAX_VARS]
        placeholders = ",".join("?" * len(chunk))
        cursor.execute(f"SELECT key, value, expires_at FROM kv_store WHERE key IN ({placeholders})", chunk)
        rows.extend(cursor.fetchall())

    if not rows:
        return {}

    active_items: list[tuple[str, bytes]] = []
    for r in rows:
        if r["expires_at"] == 0 or r["expires_at"] > now_ts:
            stored_k = r["key"]
            plain_k = storage_to_plain.get(stored_k)
            if plain_k is None:
                try:
                    plain_k = decrypt_db_key(stored_k)
                except Exception:
                    plain_k = stored_k
            active_items.append((plain_k, r["value"]))

    if not active_items:
        return {}

    results: dict[str, Any] = {}
    if len(active_items) > 8:
        def _decrypt_item(item: tuple[str, bytes]):
            pk, blob = item
            try:
                return pk, decrypt_and_unpack(blob, associated_data=pk.encode("utf-8"))
            except Exception:
                return pk, None

        executor = _get_decrypt_executor()
        for k, val in executor.map(_decrypt_item, active_items):
            if val is not None:
                results[k] = val
    else:
        for pk, blob in active_items:
            try:
                results[pk] = decrypt_and_unpack(blob, associated_data=pk.encode("utf-8"))
            except Exception:
                pass

    return results


def kv_mset(mapping: dict[str, Any], ttl: int | float | None = None):
    """
    Compress, encrypt, and commit multiple JSON documents in a single atomic SQL transaction with optional TTL.
    """
    if not mapping:
        return

    init_db()
    conn = get_db_connection()
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0

    batch_records = []
    raw_items = []
    for key, data in mapping.items():
        encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
        storage_key = _to_storage_key(key)
        batch_records.append((storage_key, encrypted_blob, expires_at, now_ts))
        raw_items.append((key, data))

    with conn:
        _upsert_kv_batch(conn, batch_records, raw_items)

    try:
        from .metrics import metrics
        metrics.record_operation("write", count=len(mapping))
    except Exception:
        pass

    try:
        from .events import events
        for key, data in mapping.items():
            events.emit("write", key=key, value=data)
    except Exception:
        pass


def purge_expired_records() -> int:
    """
    Purge all expired records from SQLite, clear their blind indexes, and evict from L1 cache.
    Returns the count of purged documents.
    """
    init_db()
    conn = get_db_connection()
    now_ts = int(time.time())
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))
        rows = cursor.fetchall()
        if not rows:
            return 0

        plain_expired_keys = []
        for r in rows:
            try:
                plain_expired_keys.append(decrypt_db_key(r["key"]))
            except Exception:
                plain_expired_keys.append(r["key"])

        conn.execute("DELETE FROM blind_indexes WHERE key IN (SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?)", (now_ts,))
        cur = conn.execute("DELETE FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))

        try:
            from .cache import cache
            for pk in plain_expired_keys:
                cache._adapter.delete(pk)
        except Exception:
            pass

        try:
            from .metrics import metrics
            metrics.record_operation("purge", count=cur.rowcount)
        except Exception:
            pass

        try:
            from .events import events
            for pk in plain_expired_keys:
                events.emit("expire", key=pk)
        except Exception:
            pass

        try:
            rebuild_bloom_filter()
        except Exception:
            pass

        return cur.rowcount


class TTLScavenger:
    """Unified TTL Scavenger delegating to the global TTLReaper so only one background daemon runs."""
    def __init__(self, interval_seconds: float = 60.0):
        self.interval = interval_seconds

    def start(self):
        from .ttl_reaper import start_ttl_reaper
        start_ttl_reaper(interval_seconds=self.interval)

    def stop(self):
        from .ttl_reaper import stop_ttl_reaper
        stop_ttl_reaper()


scavenger = TTLScavenger(interval_seconds=60.0)


def rotate_encryption_key(old_key: str | bytes, new_key: str | bytes, strict: bool = False) -> dict:
    """
    Re-encrypt all records in SQLite (and static .json mirror files) using a new encryption key atomically.
    Supports both HKDF v2 subkeys and legacy v1 keys.
    When strict=True, raises RuntimeError if any record fails to decrypt.
    """
    init_db()
    if isinstance(old_key, str):
        old_key = old_key.encode("utf-8")
    if isinstance(new_key, str):
        new_key = new_key.encode("utf-8")

    try:
        old_key_decoded = base64.urlsafe_b64decode(old_key)
        old_key_raw = old_key_decoded if len(old_key_decoded) == 32 else hashlib.sha256(old_key).digest()
    except Exception:
        old_key_raw = old_key if len(old_key) == 32 else hashlib.sha256(old_key).digest()

    try:
        new_key_decoded = base64.urlsafe_b64decode(new_key)
        new_key_raw = new_key_decoded if len(new_key_decoded) == 32 else hashlib.sha256(new_key).digest()
    except Exception:
        new_key_raw = new_key if len(new_key) == 32 else hashlib.sha256(new_key).digest()

    # Legacy v1 ciphers + HKDF v2 subkey ciphers for old and new keys
    old_gcm_v1 = AESGCM(old_key_raw)
    old_chacha_v1 = ChaCha20Poly1305(old_key_raw)
    old_fernet_v1 = Fernet(base64.urlsafe_b64encode(old_key_raw))
    old_gcm_v2, old_fernet_v2, old_chacha_v2 = _build_v2_ciphers(old_key_raw)

    new_gcm_v2, new_fernet_v2, new_chacha_v2 = _build_v2_ciphers(new_key_raw)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value, version, expires_at, updated_at FROM kv_store")
    rows = cursor.fetchall()

    re_encrypted_records = []
    failed_keys = []
    key_enc_active = get_key_encryption()
    algo = get_active_algorithm()

    for row in rows:
        stored_key = row["key"]
        old_blob = row["value"]
        ver = row["version"]
        exp = row["expires_at"]
        ts = row["updated_at"]
        try:
            plain_key = decrypt_db_key(stored_key, raw_key=old_key_raw) if stored_key.startswith(_PREFIX_ENC_KEY) else stored_key
            aad = plain_key.encode("utf-8")

            def _decrypt_for_rotation(blob: bytes, c: Any, use_aad: bytes | None) -> Any:
                return decrypt_and_unpack(blob, cipher=c, associated_data=use_aad)

            if old_blob.startswith(_PREFIX_GCM):
                is_v2 = old_blob[5:].startswith(_SUBKEY_V2_TAG)
                c_gcm = old_gcm_v2 if is_v2 else old_gcm_v1
                try:
                    data = _decrypt_for_rotation(old_blob, c_gcm, aad)
                except InvalidTag:
                    data = _decrypt_for_rotation(old_blob, c_gcm, None)
            elif old_blob.startswith(_PREFIX_CHACHA):
                is_v2 = old_blob[5:].startswith(_SUBKEY_V2_TAG)
                c_cc = old_chacha_v2 if is_v2 else old_chacha_v1
                try:
                    data = _decrypt_for_rotation(old_blob, c_cc, aad)
                except InvalidTag:
                    data = _decrypt_for_rotation(old_blob, c_cc, None)
            elif old_blob.startswith(_PREFIX_FERNET) or old_blob.startswith(b"gAAAA") or (len(old_blob) > 0 and old_blob[0] == 0x80):
                is_v2 = old_blob.startswith(_PREFIX_FERNET) and old_blob[5:].startswith(_SUBKEY_V2_TAG)
                c_fn = old_fernet_v2 if is_v2 else old_fernet_v1
                data = _decrypt_for_rotation(old_blob, c_fn, None)
            else:
                try:
                    data = _decrypt_for_rotation(old_blob, old_gcm_v2, aad)
                except Exception:
                    try:
                        data = _decrypt_for_rotation(old_blob, old_gcm_v1, aad)
                    except Exception:
                        try:
                            data = _decrypt_for_rotation(old_blob, old_chacha_v1, aad)
                        except Exception:
                            data = _decrypt_for_rotation(old_blob, old_fernet_v1, None)

            # Re-encrypt into HKDF v2 format under new key
            raw_bytes = serializers.dumps(data)
            comp_algo = get_active_compression()
            if len(raw_bytes) > 128 and comp_algo != "NONE":
                if comp_algo == "ZSTD" and _HAS_ZSTD and _zstd_compressor is not None:
                    payload = _MAGIC_COMPRESSED_ZSTD + _zstd_compressor.compress(raw_bytes)
                else:
                    payload = _MAGIC_COMPRESSED_ZL + zlib.compress(raw_bytes, level=6)
            else:
                payload = _MAGIC_RAW + raw_bytes

            if algo == "AES-128-FERNET":
                new_blob = _PREFIX_FERNET + _SUBKEY_V2_TAG + new_fernet_v2.encrypt(payload)
            elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
                nonce = os.urandom(12)
                new_blob = _PREFIX_CHACHA + _SUBKEY_V2_TAG + nonce + new_chacha_v2.encrypt(nonce, payload, associated_data=aad)
            else:
                nonce = os.urandom(12)
                new_blob = _PREFIX_GCM + _SUBKEY_V2_TAG + nonce + new_gcm_v2.encrypt(nonce, payload, associated_data=aad)

            new_storage_key = encrypt_db_key(plain_key, raw_key=new_key_raw) if (key_enc_active or stored_key.startswith(_PREFIX_ENC_KEY)) else plain_key
            re_encrypted_records.append((stored_key, new_storage_key, plain_key, new_blob, ver, exp, ts, data))
        except Exception as e:
            failed_keys.append(stored_key)
            if strict:
                raise RuntimeError(f"Key rotation aborted: failed to decrypt record '{stored_key}': {e}") from e

    if failed_keys:
        print(f"[Database] Key rotation warning: {len(failed_keys)} record(s) could not be decrypted with the old key.")

    new_idx_key = derive_indexing_key(new_key_raw)

    with conn:
        for old_storage_key, new_storage_key, plain_key, new_blob, ver, exp, ts, data in re_encrypted_records:
            if new_storage_key != old_storage_key:
                conn.execute("DELETE FROM blind_indexes WHERE key = ?", (old_storage_key,))
                conn.execute("DELETE FROM kv_store WHERE key = ?", (old_storage_key,))
                conn.execute(
                    "INSERT OR REPLACE INTO kv_store (key, value, version, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (new_storage_key, new_blob, ver, exp, ts),
                )
            else:
                conn.execute(
                    "UPDATE kv_store SET value = ?, version = ?, expires_at = ?, updated_at = ? WHERE key = ?",
                    (new_blob, ver, exp, ts, new_storage_key),
                )
            _update_blind_indexes(conn, new_storage_key, data, custom_derived_key=new_idx_key)
            bloom.add(plain_key)

    # Update active in-memory cipher keys and persist into KeyManager if active
    set_cipher_key(new_key)
    try:
        from .keyring_manager import KeyManager
        new_b64 = base64.urlsafe_b64encode(new_key_raw).decode("utf-8")
        if KeyManager.get_master_key(storage_dir=DATA_DIR) is not None:
            KeyManager.save_master_key(new_b64, storage_dir=DATA_DIR)
    except Exception:
        pass

    # Re-encrypt static mirror .json files in DATA_DIR for rotated records
    for _, _, plain_key, _, _, exp, _, data in re_encrypted_records:
        if exp == 0:
            mirror_file = _safe_data_file_path(DATA_DIR, plain_key)
            if mirror_file is not None and mirror_file.exists() and mirror_file.is_file():
                try:
                    plaintext_json = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
                    aad = plain_key.encode("utf-8")
                    if algo == "AES-128-FERNET":
                        disk_payload = _PREFIX_FERNET + _SUBKEY_V2_TAG + new_fernet_v2.encrypt(plaintext_json)
                    elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
                        n = os.urandom(12)
                        disk_payload = _PREFIX_CHACHA + _SUBKEY_V2_TAG + n + new_chacha_v2.encrypt(n, plaintext_json, associated_data=aad)
                    else:
                        n = os.urandom(12)
                        disk_payload = _PREFIX_GCM + _SUBKEY_V2_TAG + n + new_gcm_v2.encrypt(n, plaintext_json, associated_data=aad)
                    tmp_m = mirror_file.with_suffix(mirror_file.suffix + ".tmp")
                    tmp_m.write_bytes(disk_payload)
                    tmp_m.replace(mirror_file)
                except Exception:
                    pass

    try:
        rebuild_bloom_filter()
    except Exception:
        pass

    try:
        from .metrics import metrics
        metrics.record_operation("rotate")
    except Exception:
        pass

    return {
        "status": "ok",
        "rotated_count": len(re_encrypted_records),
        "failed_count": len(failed_keys),
        "failed_keys": failed_keys,
        "message": f"Successfully rotated encryption key for {len(re_encrypted_records)} records."
    }


def db_maintenance() -> dict:
    """Run database optimization, WAL checkpoint truncation, bloom rebuild, and maintenance."""
    init_db()
    conn = get_db_connection()
    stats = {"status": "ok"}
    try:
        with conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.execute("PRAGMA optimize;")
        try:
            rebuild_bloom_filter()
        except Exception:
            pass
        if DB_PATH.exists():
            size = DB_PATH.stat().st_size
            stats["size_kb"] = round(size / 1024, 2)
            stats["size_mb"] = round(size / (1024 * 1024), 2)
        print(f"[Database] Maintenance completed. Database size: {stats.get('size_mb', 0)} MB")
    except Exception as e:
        stats["status"] = f"error: {e}"
        print(f"[Database] Maintenance error: {e}")
    return stats
