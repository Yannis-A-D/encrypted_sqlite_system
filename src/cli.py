"""
cli.py — Command Line Interface for Encrypted SQLite System.

Usage:
  encrypted-sqlite keygen
  encrypted-sqlite stats [db_path]
  encrypted-sqlite export --out ./decrypted_folder/
  encrypted-sqlite import ./json_folder/
  encrypted-sqlite vacuum [db_path]
  encrypted-sqlite get <key>
"""

import sys
import json
import argparse
from pathlib import Path
from cryptography.fernet import Fernet


def cmd_keygen(args):
    """Generate a new Fernet encryption key."""
    key = Fernet.generate_key().decode()
    print("\n" + "=" * 60)
    print(" [KEY] NEW ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print(f"\nENCRYPTION_KEY={key}\n")
    print("Add this key to your .env file: ENCRYPTION_KEY=<key>")
    print("=" * 60 + "\n")


def cmd_stats(args):
    """Display database statistics and telemetry."""
    from .database import DB_PATH, get_db_connection
    from .cache import cache

    db_file = Path(args.path) if args.path else DB_PATH
    print("\n" + "=" * 60)
    print(" DATABASE & CACHE TELEMETRY")
    print("=" * 60)
    print(f" Database Path : {db_file}")

    if not db_file.exists():
        print(" Status        : Database file does not exist yet.")
        print("=" * 60 + "\n")
        return

    size_mb = round(db_file.stat().st_size / (1024 * 1024), 2)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) as cnt FROM kv_store")
    total_docs = cursor.fetchone()["cnt"]

    print(f" Database Size : {size_mb} MB")
    print(f" Stored Keys   : {total_docs} documents")

    # Cache Stats
    stats = cache.get_stats()
    print("\n Tier 1 (L1 RAM Cache):")
    print(f" - Cached Items : {stats['l1_items_cached']} / {stats['l1_max_capacity']}")
    print(f" - Cache Hits   : {stats['hits']}")
    print(f" - Cache Misses : {stats['misses']}")
    print(f" - Hit Ratio    : {stats['hit_ratio_str']}")
    print("=" * 60 + "\n")


def cmd_export(args):
    """Export all decrypted documents to a folder."""
    from .database import get_db_connection, _get_cipher
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    cipher = _get_cipher()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM kv_store")
    rows = cursor.fetchall()

    if not rows:
        print("No records found in database to export.")
        return

    print(f"\nExporting {len(rows)} documents to {out_dir}...")
    success = 0
    for row in rows:
        key = row["key"]
        val_bytes = row["value"]
        try:
            plaintext = cipher.decrypt(val_bytes)
            data = json.loads(plaintext)
            target_file = out_dir / (key if key.endswith(".json") else f"{key}.json")
            target_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            success += 1
        except Exception as e:
            print(f" [!] Failed to decrypt '{key}': {e}")

    print(f"Export complete: {success}/{len(rows)} files saved.\n")


def cmd_import(args):
    """Import a folder of JSON files into the database."""
    from ..migrate import migrate_folder
    folder = Path(args.folder)
    migrate_folder(folder)


def cmd_vacuum(args):
    """Run database maintenance and checkpointing."""
    from .database import db_maintenance, DB_PATH
    print(f"\nRunning database maintenance on {DB_PATH}...")
    res = db_maintenance()
    print(f"Result: {res}\n")


def cmd_rotate_key(args):
    """Rotate encryption key across all database records atomically."""
    from .database import rotate_encryption_key, _get_cipher
    import os

    old_key = args.old_key or os.getenv("ENCRYPTION_KEY")
    if not old_key:
        print("Error: Old encryption key not specified. Provide --old-key or set ENCRYPTION_KEY.")
        return

    new_key = args.new_key
    if not new_key:
        # Generate a new key if not provided
        new_key = Fernet.generate_key().decode()
        print(f"Generated new Fernet key: {new_key}")

    print("\nStarting atomic key rotation...")
    try:
        res = rotate_encryption_key(old_key, new_key)
        print(f"✅ Success! {res['message']}")
        print(f"\nIMPORTANT: Update your .env file with the new key:")
        print(f"ENCRYPTION_KEY={new_key}\n")
    except Exception as e:
        print(f"❌ Key rotation failed: {e}")


def cmd_get(args):
    """Fetch and print a decrypted JSON document by key."""
    from .database import kv_get
    key = args.key
    data = kv_get(key, default=None)
    if data is None:
        print(f"Key '{key}' not found in database.")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(
        prog="encrypted-sqlite",
        description="CLI tool for Encrypted SQLite Document Store & Two-Tier Cache"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # keygen
    subparsers.add_parser("keygen", help="Generate a new AES encryption key")

    # stats
    p_stats = subparsers.add_parser("stats", help="Show database & cache telemetry")
    p_stats.add_argument("path", nargs="?", default=None, help="Optional database file path")

    # export
    p_export = subparsers.add_parser("export", help="Export all decrypted documents to a folder")
    p_export.add_argument("--out", "-o", default="./decrypted_export", help="Output directory")

    # import
    p_import = subparsers.add_parser("import", help="Import JSON files into SQLite database")
    p_import.add_argument("folder", help="Folder containing .json files")

    # vacuum
    subparsers.add_parser("vacuum", help="Run WAL checkpoint truncation and DB optimization")

    # rotate-key
    p_rot = subparsers.add_parser("rotate-key", help="Re-encrypt all records with a new encryption key")
    p_rot.add_argument("--new-key", "-n", default=None, help="New Fernet encryption key")
    p_rot.add_argument("--old-key", "-o", default=None, help="Old Fernet encryption key (defaults to ENCRYPTION_KEY env)")

    # get
    p_get = subparsers.add_parser("get", help="Retrieve and print a decrypted document by key")
    p_get.add_argument("key", help="Key name (e.g. user_101.json)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "keygen": cmd_keygen,
        "stats": cmd_stats,
        "export": cmd_export,
        "import": cmd_import,
        "vacuum": cmd_vacuum,
        "rotate-key": cmd_rotate_key,
        "get": cmd_get,
    }

    cmd_fn = dispatch.get(args.command)
    if cmd_fn:
        cmd_fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
