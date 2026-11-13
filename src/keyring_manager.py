"""
keyring_manager.py — OS-Native Secure Key & Secret Storage.

Supports:
1. Windows DPAPI (Data Protection API) via ctypes.windll.crypt32 (Zero third-party dependencies on Windows)
2. Python `keyring` library (macOS Keychain, Linux Freedesktop Secret Service / KWallet) if installed
3. Restricted-permission filesystem fallback (.secret.enc / chmod 600)
"""

import os
import sys
from pathlib import Path
from typing import Optional

# Detection flags
_HAS_KEYRING = False
try:
    import keyring
    _HAS_KEYRING = True
except ImportError:
    keyring = None

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte))
        ]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    def _dpapi_protect(data: bytes, entropy: bytes = b"encrypted_sqlite") -> bytes:
        """Encrypts data using Windows DPAPI (CryptProtectData)."""
        data_bytes = (ctypes.c_ubyte * len(data))(*data)
        blob_in = _DATA_BLOB(len(data), data_bytes)
        blob_out = _DATA_BLOB()

        p_entropy = None
        if entropy:
            ent_bytes = (ctypes.c_ubyte * len(entropy))(*entropy)
            blob_entropy = _DATA_BLOB(len(entropy), ent_bytes)
            p_entropy = ctypes.byref(blob_entropy)

        # CRYPTPROTECT_UI_FORBIDDEN = 0x01
        ret = _crypt32.CryptProtectData(
            ctypes.byref(blob_in),
            "encrypted_sqlite_master_key",
            p_entropy,
            None,
            None,
            0x01,
            ctypes.byref(blob_out)
        )
        if not ret:
            raise ctypes.WinError()
        try:
            return bytes(ctypes.string_at(blob_out.pbData, blob_out.cbData))
        finally:
            _kernel32.LocalFree(blob_out.pbData)

    def _dpapi_unprotect(encrypted: bytes, entropy: bytes = b"encrypted_sqlite") -> bytes:
        """Decrypts data using Windows DPAPI (CryptUnprotectData)."""
        data_bytes = (ctypes.c_ubyte * len(encrypted))(*encrypted)
        blob_in = _DATA_BLOB(len(encrypted), data_bytes)
        blob_out = _DATA_BLOB()

        p_entropy = None
        if entropy:
            ent_bytes = (ctypes.c_ubyte * len(entropy))(*entropy)
            blob_entropy = _DATA_BLOB(len(entropy), ent_bytes)
            p_entropy = ctypes.byref(blob_entropy)

        # CRYPTPROTECT_UI_FORBIDDEN = 0x01
        ret = _crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            p_entropy,
            None,
            None,
            0x01,
            ctypes.byref(blob_out)
        )
        if not ret:
            raise ctypes.WinError()
        try:
            return bytes(ctypes.string_at(blob_out.pbData, blob_out.cbData))
        finally:
            _kernel32.LocalFree(blob_out.pbData)


class KeyManager:
    """Manages persistent encryption keys securely across platforms."""

    SERVICE_NAME = "encrypted-sqlite-system"
    DEFAULT_USERNAME = "master_key"

    @classmethod
    def get_backend_name(cls) -> str:
        """Returns the active backend name."""
        if _IS_WINDOWS:
            return "Windows DPAPI (Hardware/User Bound)"
        elif _HAS_KEYRING:
            return f"OS Keyring ({keyring.get_keyring().name})"
        else:
            return "File Fallback (Protected)"

    @classmethod
    def save_master_key(cls, key: str, username: str = DEFAULT_USERNAME, storage_dir: Optional[Path] = None) -> str:
        """
        Store the encryption key in the OS keyring or DPAPI encrypted file.
        Returns the backend used.
        """
        if _HAS_KEYRING:
            try:
                keyring.set_password(cls.SERVICE_NAME, username, key)
                return "keyring"
            except Exception:
                pass  # Fallback to DPAPI or file

        if _IS_WINDOWS:
            target_dir = storage_dir or (Path(__file__).parent.parent / "data")
            target_dir.mkdir(parents=True, exist_ok=True)
            key_file = target_dir / f".{username}.dpapi"
            encrypted = _dpapi_protect(key.encode("utf-8"))
            key_file.write_bytes(encrypted)
            return "windows_dpapi"

        # Unix / Fallback
        target_dir = storage_dir or (Path(__file__).parent.parent / "data")
        target_dir.mkdir(parents=True, exist_ok=True)
        key_file = target_dir / f".{username}.key"
        key_file.write_text(key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)  # User read/write only
        except Exception:
            pass
        return "file"

    @classmethod
    def get_master_key(cls, username: str = DEFAULT_USERNAME, storage_dir: Optional[Path] = None) -> Optional[str]:
        """
        Retrieve master encryption key from OS keyring, Windows DPAPI, or secure file.
        """
        if _HAS_KEYRING:
            try:
                val = keyring.get_password(cls.SERVICE_NAME, username)
                if val:
                    return val
            except Exception:
                pass

        if _IS_WINDOWS:
            target_dir = storage_dir or (Path(__file__).parent.parent / "data")
            key_file = target_dir / f".{username}.dpapi"
            if key_file.exists():
                try:
                    encrypted = key_file.read_bytes()
                    decrypted = _dpapi_unprotect(encrypted)
                    return decrypted.decode("utf-8")
                except Exception:
                    pass

        # Check file fallback
        target_dir = storage_dir or (Path(__file__).parent.parent / "data")
        key_file = target_dir / f".{username}.key"
        if key_file.exists():
            try:
                return key_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass

        return None

    @classmethod
    def delete_master_key(cls, username: str = DEFAULT_USERNAME, storage_dir: Optional[Path] = None) -> bool:
        """Deletes master key from all persistent stores."""
        deleted = False
        if _HAS_KEYRING:
            try:
                keyring.delete_password(cls.SERVICE_NAME, username)
                deleted = True
            except Exception:
                pass

        target_dir = storage_dir or (Path(__file__).parent.parent / "data")
        dpapi_file = target_dir / f".{username}.dpapi"
        if dpapi_file.exists():
            try:
                dpapi_file.unlink()
                deleted = True
            except Exception:
                pass

        key_file = target_dir / f".{username}.key"
        if key_file.exists():
            try:
                key_file.unlink()
                deleted = True
            except Exception:
                pass

        return deleted
