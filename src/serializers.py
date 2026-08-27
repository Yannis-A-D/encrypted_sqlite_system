"""
serializers.py — High-Performance Zero-Copy Serialization Engine.

Automatically selects the fastest available serialization backend:
1. orjson (Rust-accelerated, 6x-10x faster, zero-copy byte outputs)
2. msgpack (Binary packed serialization, ultra-compact)
3. standard json (Pure Python standard library fallback)
"""

import json
from typing import Any

_BACKEND = "json"
_orjson = None
_msgpack = None

# Attempt dynamic load of high-speed Rust/C serializers
try:
    import orjson
    _orjson = orjson
    _BACKEND = "orjson"
except ImportError:
    try:
        import msgpack
        _msgpack = msgpack
        _BACKEND = "msgpack"
    except ImportError:
        _BACKEND = "json"


def get_active_backend() -> str:
    """Return the name of the currently active serialization backend."""
    return _BACKEND


def dumps(obj: Any) -> bytes:
    """Serialize a Python object to UTF-8 / binary bytes using the fastest backend."""
    if _orjson is not None:
        # orjson dumps directly to bytes in Rust
        return _orjson.dumps(obj)
    elif _msgpack is not None:
        return _msgpack.packb(obj, use_bin_type=True)
    else:
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def loads(data: bytes | str) -> Any:
    """Deserialize UTF-8 / binary bytes back into a Python object."""
    if _orjson is not None:
        return _orjson.loads(data)
    elif _msgpack is not None and isinstance(data, (bytes, bytearray)):
        try:
            return _msgpack.unpackb(data, raw=False)
        except Exception:
            # Fallback to standard json for backwards compatibility
            pass
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data)
