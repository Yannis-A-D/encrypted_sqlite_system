"""
quickstart_demo.py — Interactive demo of Encrypted SQLite + Two-Tier Caching.
"""

import time
import sys
from pathlib import Path

# Ensure package is in sys.path
pkg_root = Path(__file__).parent.parent
sys.path.insert(0, str(pkg_root))

from src.secure_json import load_json, save_json
from src.cache import cache
from src.database import db_maintenance, DB_PATH


def main():
    print("=" * 65)
    print(" ENCRYPTED SQLITE & TWO-TIER CACHE DEMO")
    print("=" * 65)

    # 1. Save data (Write-Through: L1 RAM + L2 Encrypted SQLite + Encrypted File)
    sample_data = {
        "server_name": "DonutSMP Community",
        "settings": {"maintenance_mode": False, "tax_rate": 0.15},
        "stats": {"total_tickets": 147, "active_users": 2172},
        "tags": ["minecraft", "schematics", "production"]
    }

    print("\n1. Writing data with save_json()...")
    start = time.perf_counter()
    save_json("config.json", sample_data)
    duration_ms = (time.perf_counter() - start) * 1000
    print(f"   Saved 'config.json' in {duration_ms:.2f}ms")

    # 2. Read from L1 Memory Cache (<0.01ms)
    print("\n2. Reading from Tier 1 (L1 RAM Cache)...")
    start = time.perf_counter()
    cached_data = load_json("config.json")
    duration_l1_ms = (time.perf_counter() - start) * 1000
    print(f"   Retrieved from RAM in {duration_l1_ms:.4f}ms! (0 Disk I/O)")
    print(f"   Data: {cached_data['server_name']} | Tickets: {cached_data['stats']['total_tickets']}")

    # 3. Simulate L1 Cache Eviction and read from Tier 2 (L2 Encrypted SQLite)
    print("\n3. Purging RAM to test Tier 2 (Encrypted SQLite Fallback)...")
    cache.clear_l1()
    start = time.perf_counter()
    db_data = load_json("config.json")
    duration_l2_ms = (time.perf_counter() - start) * 1000
    print(f"   Retrieved & Decrypted from SQLite in {duration_l2_ms:.2f}ms!")

    # 4. Check Cache Telemetry
    print("\n4. Cache Telemetry Stats:")
    stats = cache.get_stats()
    for k, v in stats.items():
        print(f"   - {k}: {v}")

    # 5. Database Maintenance
    print("\n5. Running Database Checkpointing & Maintenance:")
    m_stats = db_maintenance()
    print(f"   Database Path: {DB_PATH}")
    print(f"   Size: {m_stats.get('size_mb', 'N/A')} MB | Status: {m_stats.get('status')}")

    print("\n" + "=" * 65)
    print(" [OK] DEMO COMPLETE - All data encrypted with AES-128 at rest!")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
