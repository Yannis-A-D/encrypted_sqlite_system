"""
key_rotation.py — Automated Background Encryption Key Rotation Daemon.

Supports rotating keys managed either via OS-native KeyManager (DPAPI / Keyring)
or legacy secret.key files, updating active ciphers and re-encrypting SQLite + mirror files.
"""

import os
import json
import time
import base64
import threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .database import rotate_encryption_key, ROOT_DIR, DATA_DIR
from .keyring_manager import KeyManager


class BackgroundKeyRotator:
    """Manages automated background key rotation based on key age."""

    def __init__(self, rotation_interval_days: float = 90.0, check_interval_seconds: float = 3600.0 * 24):
        self.rotation_interval = rotation_interval_days * 86400.0
        self.check_interval = check_interval_seconds
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self):
        """Start the background checking thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="KeyRotatorThread", daemon=True)
        self._thread.start()
        print("[KeyRotator] Background auto-rotation thread started.")

    def stop(self):
        """Stop the background checking thread."""
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=5.0)
        self._thread = None
        print("[KeyRotator] Background auto-rotation thread stopped.")

    def _run(self):
        while not self._stop_event.is_set():
            try:
                self.check_and_rotate()
            except Exception as e:
                print(f"[KeyRotator] Error during background check: {e}")

            if self._stop_event.wait(min(5.0, self.check_interval)):
                break
            remaining = self.check_interval - 5.0
            if remaining > 0 and self._stop_event.wait(remaining):
                break

    def _get_key_age_and_material(self) -> tuple[float | None, bytes | None, Path | None]:
        """Resolve active key age and raw encoded bytes from secret.key or KeyManager metadata."""
        key_file = ROOT_DIR / "secret.key"
        if key_file.exists():
            age = time.time() - key_file.stat().st_mtime
            return age, key_file.read_text().strip().encode("utf-8"), key_file

        km_key = KeyManager.get_master_key(storage_dir=DATA_DIR)
        if km_key:
            meta_file = DATA_DIR / ".key_meta.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    created_at = float(meta.get("rotated_at", time.time()))
                except Exception:
                    created_at = meta_file.stat().st_mtime
            else:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                created_at = time.time()
                meta_file.write_text(json.dumps({"rotated_at": created_at}), encoding="utf-8")
            return time.time() - created_at, km_key.encode("utf-8"), None

        return None, None, None

    def check_and_rotate(self) -> bool:
        """Check the age of the active key and rotate if expired. Returns True if rotated."""
        age, old_key, key_file = self._get_key_age_and_material()
        if age is None or old_key is None or age < self.rotation_interval:
            return False

        print(
            f"[KeyRotator] Active key is {age / 86400.0:.2f} days old "
            f"(exceeds {self.rotation_interval / 86400.0:.1f} days). Initiating auto-rotation..."
        )

        new_key_bytes = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256))
        new_key_str = new_key_bytes.decode("utf-8")

        try:
            result = rotate_encryption_key(old_key, new_key_bytes)
            print(f"[KeyRotator] Database rotation result: {result}")
        except Exception as e:
            print(f"[KeyRotator] Failed to rotate database encryption: {e}")
            return False

        # Persist rotated key to legacy secret.key (if used) or KeyManager + metadata timestamp
        if key_file is not None:
            try:
                key_file.write_text(new_key_str, encoding="utf-8")
                os.utime(str(key_file), None)
            except Exception as e:
                print(f"[KeyRotator] Failed to save rotated key to {key_file.name}: {e}")
                return False
        else:
            try:
                KeyManager.save_master_key(new_key_str, storage_dir=DATA_DIR)
                meta_file = DATA_DIR / ".key_meta.json"
                meta_file.write_text(json.dumps({"rotated_at": time.time()}), encoding="utf-8")
            except Exception as e:
                print(f"[KeyRotator] Failed to save rotated key in KeyManager: {e}")
                return False

        if os.getenv("ENCRYPTION_KEY"):
            os.environ["ENCRYPTION_KEY"] = new_key_str

        # Update .env / bot.env if they already explicitly define ENCRYPTION_KEY
        for env_name in ("bot.env", ".env"):
            env_file = ROOT_DIR / env_name
            if env_file.exists():
                try:
                    lines = env_file.read_text(encoding="utf-8").splitlines()
                    updated = False
                    for idx, line in enumerate(lines):
                        if line.strip().startswith("ENCRYPTION_KEY="):
                            lines[idx] = f"ENCRYPTION_KEY={new_key_str}"
                            updated = True
                            break
                    if updated:
                        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
                except Exception as e:
                    print(f"[KeyRotator] Failed to update key in {env_name}: {e}")

        return True


rotator = BackgroundKeyRotator()
