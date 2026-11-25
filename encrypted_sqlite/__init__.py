"""
encrypted_sqlite — Proper top-level Python package namespace for Encrypted SQLite System.

Aliases all submodules to `src.*` so `from encrypted_sqlite import ...` and legacy
`from src import ...` share identical module instances, connections, and caches.
"""

import sys
import importlib

_SUBMODULES = (
    "adapters",
    "async_engine",
    "bloom_filter",
    "cache",
    "cli",
    "cloud_sync",
    "collection",
    "database",
    "engine",
    "envelope",
    "events",
    "integrity",
    "key_rotation",
    "keyring_manager",
    "masking",
    "metrics",
    "models",
    "secure_json",
    "serializers",
    "transaction",
    "ttl_reaper",
    "tui",
    "write_behind",
)

for _sub in _SUBMODULES:
    _mod = importlib.import_module(f"src.{_sub}")
    sys.modules[f"{__name__}.{_sub}"] = _mod
    globals()[_sub] = _mod

from src import *  # noqa: F401,F403
from src import __all__, __version__  # noqa: F401
