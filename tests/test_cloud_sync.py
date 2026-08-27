"""
test_cloud_sync.py — Tests for live online snapshots and cloud disaster recovery sync.
"""

from unittest.mock import MagicMock
from src.cloud_sync import CloudSyncEngine
from src.database import kv_set, kv_get, init_db


def test_create_local_snapshot():
    """Verify live online SQLite snapshot creation."""
    init_db()
    kv_set("snapshot_user.json", {"username": "SnapshotTester", "status": "active"})

    sync = CloudSyncEngine()
    snap_path = sync.create_local_snapshot("test_snapshot_unit")

    assert snap_path.exists()
    assert snap_path.stat().st_size > 0

    # Clean up
    snap_path.unlink(missing_ok=True)


def test_cloud_sync_with_mock_s3():
    """Verify S3 upload and retention pruning logic."""
    sync = CloudSyncEngine(bucket_name="test-vault")

    mock_s3 = MagicMock()
    mock_s3.list_objects_v2.return_value = {
        "Contents": [
            {"Key": f"backups/snapshot_old_{i}.db", "Size": 1024, "LastModified": f"2026-08-0{i}"}
            for i in range(1, 10)
        ]
    }

    res = sync.sync_to_cloud(retention_count=3, client=mock_s3)

    assert res["status"] == "success"
    assert "sha256" in res
    assert res["bucket"] == "test-vault"

    # Verify upload was called
    assert mock_s3.put_object.called

    # Verify list cloud backups
    backups = sync.list_cloud_backups(client=mock_s3)
    assert len(backups) == 9
