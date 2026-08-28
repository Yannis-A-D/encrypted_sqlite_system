import os
import time
import threading
from pathlib import Path
from cryptography.fernet import Fernet
from .database import rotate_encryption_key, ROOT_DIR

class BackgroundKeyRotator:
    """Manages automated background key rotation based on key age."""
    def __init__(self, rotation_interval_days: float = 90.0, check_interval_seconds: float = 3600.0 * 24):
        self.rotation_interval = rotation_interval_days * 86400.0
        self.check_interval = check_interval_seconds
        self._thread = None
        self._stop_event = threading.Event()

    def start(self):
        """Start the background checking thread."""
        if self._thread is not None:
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
            
            # Sleep in 5-second increments to remain responsive to stop events
            sleep_chunks = max(1, int(self.check_interval / 5.0))
            for _ in range(sleep_chunks):
                if self._stop_event.is_set():
                    break
                time.sleep(5)

    def check_and_rotate(self) -> bool:
        """Check the age of the active key file and rotate if expired. Returns True if rotated."""
        key_file = ROOT_DIR / "secret.key"
        if not key_file.exists():
            return False

        file_stat = key_file.stat()
        age = time.time() - file_stat.st_mtime
        if age < self.rotation_interval:
            return False

        print(f"[KeyRotator] Key file is {age / 86400.0:.2f} days old (exceeds {self.rotation_interval / 86400.0:.1f} days). Initiating auto-rotation...")
        
        # Read old key
        try:
            old_key = key_file.read_text().strip().encode("utf-8")
        except Exception as e:
            print(f"[KeyRotator] Error reading old key file: {e}")
            return False
        
        # Generate new key
        new_key_bytes = Fernet.generate_key()
        new_key_str = new_key_bytes.decode("utf-8")

        # Perform re-encryption of all database records
        try:
            result = rotate_encryption_key(old_key, new_key_bytes)
            print(f"[KeyRotator] Database rotation result: {result}")
        except Exception as e:
            print(f"[KeyRotator] Failed to rotate database encryption: {e}")
            return False

        # Write new key to secret.key
        try:
            key_file.write_text(new_key_str)
            # Reset modification time to current time
            os.utime(str(key_file), None)
            print(f"[KeyRotator] Saved new encryption key to {key_file.name}")
        except Exception as e:
            print(f"[KeyRotator] Failed to save rotated key to file: {e}")
            return False

        # Update environment variable if set
        if os.getenv("ENCRYPTION_KEY"):
            os.environ["ENCRYPTION_KEY"] = new_key_str

        # Attempt to update .env / bot.env files if they exist in the root directory
        for env_name in ("bot.env", ".env"):
            env_file = ROOT_DIR / env_name
            if env_file.exists():
                try:
                    content = env_file.read_text()
                    lines = content.splitlines()
                    updated = False
                    for idx, line in enumerate(lines):
                        if line.strip().startswith("ENCRYPTION_KEY="):
                            lines[idx] = f"ENCRYPTION_KEY={new_key_str}"
                            updated = True
                            break
                    if not updated:
                        lines.append(f"ENCRYPTION_KEY={new_key_str}")
                    env_file.write_text("\n".join(lines) + "\n")
                    print(f"[KeyRotator] Updated key in config: {env_name}")
                except Exception as e:
                    print(f"[KeyRotator] Failed to update key in {env_name}: {e}")

        return True

# Global rotator instance
rotator = BackgroundKeyRotator()
