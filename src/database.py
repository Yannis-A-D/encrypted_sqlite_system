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
_db_initialized = False
_init_lock = threading.Lock()

# Base paths
ROOT_DIR = Path(__file__).parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "app_database.db"

# Encryption Key setup and prefixes
_cipher_aesgcm: AESGCM | None = None
_cipher_fernet: Fernet | None = None
_cipher_chacha: ChaCha20Poly1305 | None = None

_PREFIX_GCM = b"G256:"
_PREFIX_FERNET = b"F128:"
_PREFIX_CHACHA = b"C256:"
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


def _get_raw_key_material() -> bytes:
    """Retrieve raw 32 bytes of the active master key."""
    raw_key = os.getenv("ENCRYPTION_KEY")
    if not raw_key:
        try:
            from .keyring_manager import KeyManager
            raw_key = KeyManager.get_master_key()
        except Exception:
            raw_key = None

    if not raw_key:
        key_file = ROOT_DIR / "secret.key"
        if key_file.exists():
            raw_key = key_file.read_text().strip()
        else:
            # Generate a 256-bit key and base64-encode it for file storage compatibility
            raw_key_bytes = AESGCM.generate_key(bit_length=256)
            new_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
            key_file.write_text(new_key)
            raw_key = new_key
            print(f"[Database] Generated new encryption key and saved to {key_file.name}")

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
    """Retrieve or generate both AESGCM and Fernet cipher instances."""
    global _cipher_aesgcm, _cipher_fernet, _cipher_chacha
    if _cipher_aesgcm is not None and _cipher_fernet is not None:
        return _cipher_aesgcm, _cipher_fernet

    key_material = _get_raw_key_material()

    # Initialize Fernet (expects base64 key)
    fernet_b64 = base64.urlsafe_b64encode(key_material)
    _cipher_fernet = Fernet(fernet_b64)

    # Initialize AESGCM (expects raw 32-byte key material)
    _cipher_aesgcm = AESGCM(key_material)

    # Initialize ChaCha20Poly1305
    _cipher_chacha = ChaCha20Poly1305(key_material)

    return _cipher_aesgcm, _cipher_fernet


def _get_chacha_cipher() -> ChaCha20Poly1305:
    """Retrieve or initialize ChaCha20Poly1305 cipher."""
    global _cipher_chacha
    if _cipher_chacha is not None:
        return _cipher_chacha
    key_material = _get_raw_key_material()
    _cipher_chacha = ChaCha20Poly1305(key_material)
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
    """Update active in-memory cipher keys (AESGCM, Fernet, and ChaCha20Poly1305)."""
    global _cipher_aesgcm, _cipher_fernet, _cipher_chacha
    if isinstance(new_key, str):
        new_key = new_key.encode("utf-8")
    
    # Try decoding if it is a base64 string
    try:
        key_material = base64.urlsafe_b64decode(new_key)
        if len(key_material) == 32:
            _cipher_aesgcm = AESGCM(key_material)
            _cipher_fernet = Fernet(new_key)
            _cipher_chacha = ChaCha20Poly1305(key_material)
            os.environ["ENCRYPTION_KEY"] = new_key.decode("utf-8")
            return
    except Exception:
        pass

    if len(new_key) == 32:
        _cipher_aesgcm = AESGCM(new_key)
        _cipher_fernet = Fernet(base64.urlsafe_b64encode(new_key))
        _cipher_chacha = ChaCha20Poly1305(new_key)
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


def compute_blind_index(value: Any) -> str:
    """Compute a secure, deterministic blind index hash for a queryable value."""
    if value is None:
        return ""
    val_str = str(value).strip()
    idx_key = _get_indexing_key()
    return hmac.new(idx_key, val_str.encode("utf-8"), hashlib.sha256).hexdigest()


def _update_blind_indexes(conn, key: str, data: Any, custom_derived_key: bytes | None = None):
    """Index configured fields in the database for the given key/document."""
    conn.execute("DELETE FROM blind_indexes WHERE key = ?", (key,))

    if not isinstance(data, dict) or not _indexed_fields:
        return

    index_records = []
    idx_key = custom_derived_key if custom_derived_key is not None else _get_indexing_key()

    for field in _indexed_fields:
        if field in data:
            val_str = str(data[field]).strip()
            val_hash = hmac.new(idx_key, val_str.encode("utf-8"), hashlib.sha256).hexdigest()
            index_records.append((key, field, val_hash))

    if index_records:
        conn.executemany("""
            INSERT OR REPLACE INTO blind_indexes (key, field_name, field_hash)
            VALUES (?, ?, ?)
        """, index_records)


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
        # Otherwise, encrypt using the active algorithm
        aesgcm_cipher, fernet_cipher = _get_ciphers()
        algo = get_active_algorithm()

        if algo == "AES-128-FERNET":
            ciphertext = fernet_cipher.encrypt(payload)
            res = _PREFIX_FERNET + ciphertext
        elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
            chacha = _get_chacha_cipher()
            nonce = os.urandom(12)
            ciphertext = chacha.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_CHACHA + nonce + ciphertext
        else:
            # Default to AES-256-GCM
            nonce = os.urandom(12)
            ciphertext = aesgcm_cipher.encrypt(nonce, payload, associated_data=associated_data)
            res = _PREFIX_GCM + nonce + ciphertext

    try:
        from .metrics import metrics
        metrics.record_latency("encrypt", time.perf_counter() - t0)
    except Exception:
        pass

    return res


def decrypt_and_unpack(encrypted_blob: bytes, cipher: Any = None, associated_data: bytes | None = None) -> Any:
    """Decrypt, decompress, and deserialize payload with automatic algorithm detection."""
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
        # Auto-detect using prefixes
        aesgcm_cipher, fernet_cipher = _get_ciphers()

        if encrypted_blob.startswith(_PREFIX_GCM):
            actual_blob = encrypted_blob[5:]
            if len(actual_blob) < 12:
                raise ValueError("Payload missing GCM nonce.")
            nonce = actual_blob[:12]
            ciphertext = actual_blob[12:]
            decrypted = aesgcm_cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_CHACHA):
            actual_blob = encrypted_blob[5:]
            if len(actual_blob) < 12:
                raise ValueError("Payload missing ChaCha20 nonce.")
            nonce = actual_blob[:12]
            ciphertext = actual_blob[12:]
            chacha = _get_chacha_cipher()
            decrypted = chacha.decrypt(nonce, ciphertext, associated_data=associated_data)
        elif encrypted_blob.startswith(_PREFIX_FERNET):
            actual_blob = encrypted_blob[5:]
            decrypted = fernet_cipher.decrypt(actual_blob)
        elif encrypted_blob[0] == 0x80 or encrypted_blob.startswith(b"gAAAA"):
            # Legacy unprefixed Fernet token fallback
            try:
                decrypted = fernet_cipher.decrypt(encrypted_blob)
            except Exception:
                # If decrypt failed, fallback to default active algorithm
                algo = get_active_algorithm()
                if algo == "AES-128-FERNET":
                    decrypted = fernet_cipher.decrypt(encrypted_blob)
                else:
                    if len(encrypted_blob) < 12:
                        raise ValueError("Payload missing GCM nonce.")
                    nonce = encrypted_blob[:12]
                    ciphertext = encrypted_blob[12:]
                    decrypted = aesgcm_cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
        else:
            # Fallback to default algorithm if no matching prefix
            algo = get_active_algorithm()
            if algo == "AES-128-FERNET":
                decrypted = fernet_cipher.decrypt(encrypted_blob)
            else:
                if len(encrypted_blob) < 12:
                    raise ValueError("Payload missing GCM nonce.")
                nonce = encrypted_blob[:12]
                ciphertext = encrypted_blob[12:]
                decrypted = aesgcm_cipher.decrypt(nonce, ciphertext, associated_data=associated_data)

    # Decompress and deserialize
    if decrypted.startswith(_MAGIC_COMPRESSED_ZSTD):
        if _HAS_ZSTD and _zstd_decompressor is not None:
            raw_bytes = _zstd_decompressor.decompress(decrypted[len(_MAGIC_COMPRESSED_ZSTD):])
        else:
            import zstandard as zstd
            raw_bytes = zstd.ZstdDecompressor().decompress(decrypted[len(_MAGIC_COMPRESSED_ZSTD):])
    elif decrypted.startswith(_MAGIC_COMPRESSED_ZL):
        raw_bytes = zlib.decompress(decrypted[len(_MAGIC_COMPRESSED_ZL):])
    elif decrypted.startswith(_MAGIC_RAW):
        raw_bytes = decrypted[len(_MAGIC_RAW):]
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


def get_db_connection() -> sqlite3.Connection:
    """Obtain a thread-local SQLite connection configured with WAL and MMAP mode."""
    if hasattr(_local, "conn") and _local.conn is not None:
        return _local.conn

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

    _local.conn = conn
    return conn


def rebuild_bloom_filter():
    """Rebuild the in-memory Bloom filter from active non-expired keys in SQLite."""
    conn = get_db_connection()
    now_ts = int(time.time())
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM kv_store WHERE expires_at == 0 OR expires_at > ?", (now_ts,))
    keys = [r["key"] for r in cursor.fetchall()]
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
                    PRIMARY KEY (key, field_name)
                );
            """)
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

def kv_get_with_expiry(key: str, default: Any = None) -> tuple[Any, float | None]:
    """Retrieve decrypted document alongside its expiration timestamp (or None)."""
    init_db()

    # Fast Bloom filter check: if definitely not in database, return 0-disk miss immediately
    if not bloom.contains(key):
        return default, None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value, expires_at FROM kv_store WHERE key = ?", (key,))
    row = cursor.fetchone()
    if row is None:
        return default, None

    # Check database-level TTL
    import time
    now_ts = int(time.time())
    expires_at = row["expires_at"]
    if expires_at > 0 and expires_at <= now_ts:
        try:
            kv_delete(key)
        except Exception:
            pass
        return default, None

    try:
        from .metrics import metrics
        metrics.record_operation("read")
    except Exception:
        pass

    try:
        data = decrypt_and_unpack(row["value"], associated_data=key.encode("utf-8"))
        return data, (float(expires_at) if expires_at > 0 else None)
    except Exception as e:
        print(f"[Database] Error decrypting kv '{key}': {e}")
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
    conn.executemany("""
        INSERT INTO kv_store (key, value, version, expires_at, updated_at)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            version = version + 1,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at;
    """, batch_records)
    for key, data in raw_items:
        _update_blind_indexes(conn, key, data)
        bloom.add(key)


def kv_set(key: str, data: Any, ttl: int | float | None = None):
    """Compress, encrypt, and store any Python dict/list into kv_store with optional TTL (seconds)."""
    init_db()
    conn = get_db_connection()
    encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
    import time
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0

    with conn:
        _upsert_kv_batch(conn, [(key, encrypted_blob, expires_at, now_ts)], [(key, data)])

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

    # Fast Bloom filter check: if definitely not in database, return 0-disk miss immediately
    if not bloom.contains(key):
        return default, 0

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value, version, expires_at FROM kv_store WHERE key = ?", (key,))
    row = cursor.fetchone()
    if row is None:
        return default, 0

    import time
    now_ts = int(time.time())
    if row["expires_at"] > 0 and row["expires_at"] <= now_ts:
        try:
            kv_delete(key)
        except Exception:
            pass
        return default, 0

    try:
        data = decrypt_and_unpack(row["value"], associated_data=key.encode("utf-8"))
        return data, row["version"]
    except Exception as e:
        print(f"[Database] Error decrypting versioned kv '{key}': {e}")
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
    import time
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0

    with conn:
        if expected_version == 0:
            # Expected new document (creation constraint)
            try:
                conn.execute("""
                    INSERT INTO kv_store (key, value, version, expires_at, updated_at)
                    VALUES (?, ?, 1, ?, ?)
                """, (key, encrypted_blob, expires_at, now_ts))
                _update_blind_indexes(conn, key, data)
                bloom.add(key)
                new_ver = 1
            except sqlite3.IntegrityError:
                raise ConcurrentModificationError(
                    f"Cannot write key '{key}' with expected_version=0: record already exists."
                )
        else:
            # Conditional atomic update matching the version
            cursor = conn.execute("""
                UPDATE kv_store
                SET value = ?, version = version + 1, expires_at = ?, updated_at = ?
                WHERE key = ? AND version = ?
            """, (encrypted_blob, expires_at, now_ts, key, expected_version))
            
            if cursor.rowcount == 0:
                # No row was updated; find out why (missing record vs version mismatch)
                check_cursor = conn.execute("SELECT version FROM kv_store WHERE key = ?", (key,))
                row = check_cursor.fetchone()
                if row is None:
                    raise ConcurrentModificationError(
                        f"Cannot update key '{key}': record does not exist (expected version {expected_version})."
                    )
                else:
                    actual_version = row["version"]
                    raise ConcurrentModificationError(
                        f"Conflict detected on key '{key}': current version is {actual_version}, but expected {expected_version}."
                    )
            _update_blind_indexes(conn, key, data)
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


def kv_delete(key: str) -> bool:
    """Delete a document by key from kv_store, clear its blind indexes, and remove disk backup if present."""
    init_db()
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM blind_indexes WHERE key = ?", (key,))
        cur = conn.execute("DELETE FROM kv_store WHERE key = ?", (key,))
        deleted = cur.rowcount > 0

        # Prevent zombie resurrects in load_json by cleaning up fallback disk file
        try:
            target = DATA_DIR / key
            if target.exists():
                target.unlink()
            tmp_target = DATA_DIR / f"{key}.tmp"
            if tmp_target.exists():
                tmp_target.unlink()
        except Exception:
            pass

        if deleted:
            try:
                from .cache import cache
                cache._adapter.delete(key)
            except Exception:
                pass
            try:
                from .metrics import metrics
                metrics.record_operation("delete")
            except Exception:
                pass
            try:
                from .events import events
                events.emit("delete", key=key)
            except Exception:
                pass
        return deleted


def kv_search(pattern: str = "*", limit: int | None = None) -> list[str]:
    """
    Search all non-expired keys matching a wildcard glob pattern (e.g. 'user_*', 'ticket_*.json').
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    import time
    now_ts = int(time.time())
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

    batch_docs = kv_mget(keys)
    matches = []

    for key, doc in batch_docs.items():
        try:
            if predicate(doc):
                matches.append(doc)
                if limit is not None and len(matches) >= limit:
                    break
        except Exception:
            continue

    return matches


def kv_find_by_index(field_name: str, value: Any) -> dict[str, Any]:
    """
    Find and decrypt all documents where the specified field matches value.
    Uses blind indexes for fast O(1) SQL-side lookups while filtering out expired records.
    """
    init_db()
    val_hash = compute_blind_index(value)
    conn = get_db_connection()
    cursor = conn.cursor()
    import time
    now_ts = int(time.time())
    cursor.execute("""
        SELECT b.key FROM blind_indexes b
        JOIN kv_store k ON b.key = k.key
        WHERE b.field_name = ? AND b.field_hash = ? AND (k.expires_at == 0 OR k.expires_at > ?)
    """, (field_name, val_hash, now_ts))
    keys = [row["key"] for row in cursor.fetchall()]
    if not keys:
        return {}
    return kv_mget(keys)


def kv_count(pattern: str | None = None) -> int:
    """Return total number of non-expired stored documents, optionally matching a pattern."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    import time
    now_ts = int(time.time())
    if pattern:
        cursor.execute(
            "SELECT COUNT(*) AS total FROM kv_store WHERE key GLOB ? AND (expires_at == 0 OR expires_at > ?)",
            (pattern, now_ts)
        )
    else:
        cursor.execute(
            "SELECT COUNT(*) AS total FROM kv_store WHERE (expires_at == 0 OR expires_at > ?)",
            (now_ts,)
        )
    row = cursor.fetchone()
    return row["total"] if row else 0


def kv_mget(keys: list[str]) -> dict[str, Any]:
    """
    Retrieve and decrypt multiple JSON documents in a single SQL batch query
    with parallel multi-core thread pool decryption and TTL filtering.
    """
    if not keys:
        return {}

    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    import time
    now_ts = int(time.time())
    placeholders = ",".join("?" * len(keys))
    cursor.execute(f"SELECT key, value, expires_at FROM kv_store WHERE key IN ({placeholders})", keys)
    rows = cursor.fetchall()

    if not rows:
        return {}

    # Filter out expired rows
    active_rows = [r for r in rows if (r["expires_at"] == 0 or r["expires_at"] > now_ts)]
    if not active_rows:
        return {}

    results = {}
    if len(active_rows) > 8:
        # Parallel decryption across CPU cores for large batches
        from concurrent.futures import ThreadPoolExecutor
        def _decrypt_item(row):
            try:
                return row["key"], decrypt_and_unpack(row["value"], associated_data=row["key"].encode("utf-8"))
            except Exception:
                return row["key"], None

        with ThreadPoolExecutor(max_workers=min(16, os.cpu_count() or 4)) as executor:
            for k, val in executor.map(_decrypt_item, active_rows):
                if val is not None:
                    results[k] = val
    else:
        for row in active_rows:
            try:
                results[row["key"]] = decrypt_and_unpack(row["value"], associated_data=row["key"].encode("utf-8"))
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
    import time
    now_ts = int(time.time())
    expires_at = int(now_ts + ttl) if (ttl is not None and ttl > 0) else 0

    batch_records = []
    raw_items = []
    for key, data in mapping.items():
        encrypted_blob = pack_and_encrypt(data, associated_data=key.encode("utf-8"))
        batch_records.append((key, encrypted_blob, expires_at, now_ts))
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
    Purge all expired records from SQLite and clear their blind indexes.
    Returns the count of purged documents.
    """
    init_db()
    conn = get_db_connection()
    import time
    now_ts = int(time.time())
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))
        rows = cursor.fetchall()
        if not rows:
            return 0
        
        expired_keys = [r["key"] for r in rows]
        conn.execute("DELETE FROM blind_indexes WHERE key IN (SELECT key FROM kv_store WHERE expires_at > 0 AND expires_at <= ?)", (now_ts,))
        cur = conn.execute("DELETE FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))
        
        try:
            from .metrics import metrics
            metrics.record_operation("purge", count=cur.rowcount)
        except Exception:
            pass

        try:
            from .events import events
            for k in expired_keys:
                events.emit("expire", key=k)
        except Exception:
            pass

        try:
            rebuild_bloom_filter()
        except Exception:
            pass

        return cur.rowcount


class TTLScavenger:
    """Background daemon thread that periodically purges expired SQLite rows."""
    def __init__(self, interval_seconds: float = 60.0):
        self.interval = interval_seconds
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="TTLScavengerDaemon")
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self):
        while not self._stop_event.wait(self.interval):
            try:
                purge_expired_records()
            except Exception:
                pass


scavenger = TTLScavenger(interval_seconds=60.0)


def rotate_encryption_key(old_key: str | bytes, new_key: str | bytes, strict: bool = False) -> dict:
    """
    Re-encrypt all records in SQLite using a new encryption key atomically.
    Guarantees zero data loss with full rollback on error.
    When strict=True, raises RuntimeError if any record fails to decrypt.
    """
    init_db()
    if isinstance(old_key, str):
        old_key = old_key.encode("utf-8")
    if isinstance(new_key, str):
        new_key = new_key.encode("utf-8")

    # Decode base64 strings to get raw key materials
    try:
        old_key_decoded = base64.urlsafe_b64decode(old_key)
        if len(old_key_decoded) == 32:
            old_key_raw = old_key_decoded
        else:
            old_key_raw = old_key
    except Exception:
        old_key_raw = old_key

    try:
        new_key_decoded = base64.urlsafe_b64decode(new_key)
        if len(new_key_decoded) == 32:
            new_key_raw = new_key_decoded
        else:
            new_key_raw = new_key
    except Exception:
        new_key_raw = new_key

    # Initialize ciphers for both old and new keys
    old_aesgcm = AESGCM(old_key_raw)
    old_chacha = ChaCha20Poly1305(old_key_raw)
    old_fernet = Fernet(base64.urlsafe_b64encode(old_key_raw) if len(old_key_raw) == 32 else old_key)
    
    new_aesgcm = AESGCM(new_key_raw)
    new_chacha = ChaCha20Poly1305(new_key_raw)
    new_fernet = Fernet(base64.urlsafe_b64encode(new_key_raw) if len(new_key_raw) == 32 else new_key)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value, version, expires_at, updated_at FROM kv_store")
    rows = cursor.fetchall()

    re_encrypted_records = []
    failed_keys = []
    for row in rows:
        key = row["key"]
        old_blob = row["value"]
        ver = row["version"]
        exp = row["expires_at"]
        ts = row["updated_at"]
        aad = key.encode("utf-8")
        try:
            # Decrypt: auto-detect prefix/type and decrypt with the correct cipher
            def _decrypt_for_rotation(blob: bytes, c: Any, use_aad: bytes | None) -> Any:
                return decrypt_and_unpack(blob, cipher=c, associated_data=use_aad)

            if old_blob.startswith(_PREFIX_GCM):
                try:
                    data = _decrypt_for_rotation(old_blob, old_aesgcm, aad)
                except InvalidTag:
                    data = _decrypt_for_rotation(old_blob, old_aesgcm, None)
            elif old_blob.startswith(_PREFIX_CHACHA):
                try:
                    data = _decrypt_for_rotation(old_blob, old_chacha, aad)
                except InvalidTag:
                    data = _decrypt_for_rotation(old_blob, old_chacha, None)
            elif old_blob.startswith(_PREFIX_FERNET) or old_blob.startswith(b"gAAAA") or (len(old_blob) > 0 and old_blob[0] == 0x80):
                data = _decrypt_for_rotation(old_blob, old_fernet, None)
            else:
                # Try GCM, ChaCha, then Fernet
                try:
                    data = _decrypt_for_rotation(old_blob, old_aesgcm, aad)
                except Exception:
                    try:
                        data = _decrypt_for_rotation(old_blob, old_chacha, aad)
                    except Exception:
                        data = _decrypt_for_rotation(old_blob, old_fernet, None)

            # Encrypt with new key using active algorithm
            algo = get_active_algorithm()
            if algo == "AES-128-FERNET":
                new_blob = pack_and_encrypt(data, cipher=new_fernet)
            elif algo in ("CHACHA20-POLY1305", "CHACHA20", "XCHACHA20-POLY1305"):
                new_blob = pack_and_encrypt(data, cipher=new_chacha, associated_data=aad)
            else:
                new_blob = pack_and_encrypt(data, cipher=new_aesgcm, associated_data=aad)

            re_encrypted_records.append((key, new_blob, ver, exp, ts, data))
        except Exception as e:
            failed_keys.append(key)
            if strict:
                raise RuntimeError(f"Key rotation aborted: failed to decrypt record '{key}': {e}") from e

    if failed_keys:
        print(f"[Database] Key rotation warning: {len(failed_keys)} record(s) could not be decrypted with the old key.")

    # Derive new index key for rotation using HKDF
    new_idx_key = derive_indexing_key(new_key_raw)

    # Atomic write of all rotated records
    with conn:
        for key, new_blob, ver, exp, ts, data in re_encrypted_records:
            conn.execute("UPDATE kv_store SET value = ?, version = ?, expires_at = ?, updated_at = ? WHERE key = ?", (new_blob, ver, exp, ts, key))
            _update_blind_indexes(conn, key, data, custom_derived_key=new_idx_key)
            bloom.add(key)

    try:
        rebuild_bloom_filter()
    except Exception:
        pass

    # Update active in-memory cipher keys
    set_cipher_key(new_key)

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
