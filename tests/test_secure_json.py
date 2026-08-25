"""
test_secure_json.py — Tests for drop-in load_json() and save_json() API.
"""

from src.secure_json import load_json, save_json
from src.cache import cache


def test_save_and_load_json(tmp_path):
    """Test full roundtrip save_json and load_json."""
    data = {
        "bot_name": "SchematicBot",
        "version": "2.0.0",
        "features": ["caching", "encryption", "wal_sqlite"],
        "nested": {"count": 100, "active": True}
    }

    save_json("app_settings.json", data)

    # 1. Load from L1 RAM cache
    loaded_data = load_json("app_settings.json")
    assert loaded_data == data
    assert loaded_data["bot_name"] == "SchematicBot"
    assert loaded_data["nested"]["count"] == 100

    # 2. Clear RAM and load from L2 SQLite
    cache.clear_l1()
    reloaded_data = load_json("app_settings.json")
    assert reloaded_data == data


def test_load_non_existent_key():
    """Test graceful default fallback when key is not found."""
    res = load_json("non_existent_file.json", default={"default_key": "fallback"})
    assert res == {"default_key": "fallback"}
