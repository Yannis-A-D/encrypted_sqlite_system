"""
test_serializers.py — Tests for zero-copy high-performance serializer engine.
"""

from src import serializers


def test_serializers_roundtrip():
    """Test serialization and deserialization across types."""
    sample = {
        "user_id": 12345,
        "name": "RustSpeedUser",
        "scores": [10.5, 20.2, 30.1],
        "meta": {"nested": True, "tags": ["fast", "crypto"]}
    }

    raw_bytes = serializers.dumps(sample)
    assert isinstance(raw_bytes, (bytes, bytearray))

    recovered = serializers.loads(raw_bytes)
    assert recovered == sample


def test_active_backend():
    """Verify active backend is identified."""
    backend = serializers.get_active_backend()
    assert backend in ["orjson", "msgpack", "json"]
