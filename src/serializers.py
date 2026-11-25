"""
serializers.py — High-Performance Format-Tagged Serialization Engine.

Automatically selects the fastest available serialization backend while tagging
binary formats so databases remain 100% portable across environments:
1. orjson (Rust-accelerated, 6x-10x faster, zero-copy UTF-8 JSON bytes)
2. msgpack (Binary packed serialization tagged with MP1: magic header)
3. standard json (Pure Python standard library UTF-8 JSON fallback)
"""

import json
from typing import Any

_MAGIC_MSGPACK = b"MP1:"
_MAGIC_JSON = b"JS1:"

_BACKEND = "json"
_orjson = None
_msgpack = None

try:
    import orjson
    _orjson = orjson
except ImportError:
    pass

try:
    import msgpack
    _msgpack = msgpack
except ImportError:
    pass

if _orjson is not None:
    _BACKEND = "orjson"
elif _msgpack is not None:
    _BACKEND = "msgpack"
else:
    _BACKEND = "json"


def get_active_backend() -> str:
    """Return the name of the currently active serialization backend."""
    return _BACKEND


def dumps(obj: Any) -> bytes:
    """Serialize a Python object to tagged binary or UTF-8 JSON bytes."""
    if _BACKEND == "orjson" and _orjson is not None:
        return _orjson.dumps(obj)
    elif _BACKEND == "msgpack" and _msgpack is not None:
        return _MAGIC_MSGPACK + _msgpack.packb(obj, use_bin_type=True)
    else:
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def loads(data: bytes | bytearray | str) -> Any:
    """Deserialize tagged binary or UTF-8 JSON bytes back into a Python object."""
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        if raw.startswith(_MAGIC_MSGPACK):
            if _msgpack is None:
                import msgpack as mp
                return mp.unpackb(raw[len(_MAGIC_MSGPACK):], raw=False)
            return _msgpack.unpackb(raw[len(_MAGIC_MSGPACK):], raw=False)
        if raw.startswith(_MAGIC_JSON):
            raw = raw[len(_MAGIC_JSON):]

        # Try fast UTF-8 JSON first
        try:
            if _orjson is not None:
                return _orjson.loads(raw)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            # Backward-compatible fallback for legacy untagged MessagePack payloads
            if _msgpack is not None:
                return _msgpack.unpackb(raw, raw=False)
            raise

    if _orjson is not None:
        return _orjson.loads(data)
    return json.loads(data)
