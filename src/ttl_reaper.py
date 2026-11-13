"""
ttl_reaper.py — Background Autonomous Reaper for Expired TTL Records.

Periodically purges dead documents, blind indexes, and memory cache references
at a configurable interval without blocking application threads.
"""

import threading
import time
import logging
from typing import Optional

logger = logging.getLogger("encrypted_sqlite.reaper")

_reaper_instance: Optional["TTLReaper"] = None
_reaper_lock = threading.Lock()


class TTLReaper:
    """Daemon thread for automatic background garbage collection of expired records."""

    def __init__(self, interval_seconds: float = 60.0):
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._total_purged = 0

    def start(self):
        """Starts the background reaper thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="EncryptedSQLite-TTLReaper", daemon=True)
        self._thread.start()
        logger.info(f"TTL Reaper background daemon started (interval: {self.interval_seconds}s).")

    def stop(self, timeout: float = 5.0):
        """Stops the background reaper thread gracefully."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("TTL Reaper background daemon stopped.")

    def is_running(self) -> bool:
        """Returns True if the reaper daemon is active."""
        return self._thread is not None and self._thread.is_alive()

    def purge_now(self) -> int:
        """Triggers an immediate purge run."""
        from .database import purge_expired_records
        from .cache import cache
        purged = purge_expired_records()
        self._total_purged += purged
        if purged > 0:
            logger.info(f"TTL Reaper: Purged {purged} expired record(s).")
        return purged

    @property
    def total_purged(self) -> int:
        """Total number of records purged during this reaper's lifetime."""
        return self._total_purged

    def _run(self):
        while not self._stop_event.is_set():
            # Wait for interval or stop signal
            if self._stop_event.wait(self.interval_seconds):
                break
            try:
                self.purge_now()
            except Exception as e:
                logger.error(f"Error during TTL Reaper purge cycle: {e}")


def start_ttl_reaper(interval_seconds: float = 60.0) -> TTLReaper:
    """Convenience helper to start the global background TTL reaper."""
    global _reaper_instance
    with _reaper_lock:
        if _reaper_instance is None or not _reaper_instance.is_running():
            _reaper_instance = TTLReaper(interval_seconds=interval_seconds)
            _reaper_instance.start()
        return _reaper_instance


def stop_ttl_reaper():
    """Convenience helper to stop the global background TTL reaper."""
    global _reaper_instance
    with _reaper_lock:
        if _reaper_instance is not None:
            _reaper_instance.stop()
            _reaper_instance = None


def get_ttl_reaper() -> Optional[TTLReaper]:
    """Returns the active global TTL reaper instance, if running."""
    return _reaper_instance
