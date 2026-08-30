"""
cli.py — Command Line Interface for Encrypted SQLite System.

Usage:
  encrypted-sqlite keygen
  encrypted-sqlite stats [db_path]
  encrypted-sqlite export --out ./decrypted_folder/
  encrypted-sqlite import ./json_folder/
  encrypted-sqlite vacuum [db_path]
  encrypted-sqlite get <key>
  encrypted-sqlite find --pattern "user_*"
  encrypted-sqlite count
  encrypted-sqlite cloud-backup
  encrypted-sqlite cloud-list
  encrypted-sqlite cloud-restore <key>
"""

import sys
import json
import os
import argparse
from pathlib import Path
from cryptography.fernet import Fernet

# Enable UTF-8 encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure parent directory is in sys.path when invoked directly as a standalone script
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

try:
    from src.database import (
        DB_PATH,
        get_db_connection,
        decrypt_and_unpack,
        db_maintenance,
        rotate_encryption_key,
        kv_get,
        kv_set,
        kv_delete,
        kv_search,
        kv_find_by_index,
        kv_count,
    )
    from src.cache import cache
    from src.masking import mask_pii
    from src.integrity import verify_database_integrity
    from src.cloud_sync import cloud_sync
except ImportError:
    from .database import (
        DB_PATH,
        get_db_connection,
        decrypt_and_unpack,
        db_maintenance,
        rotate_encryption_key,
        kv_get,
        kv_set,
        kv_delete,
        kv_search,
        kv_find_by_index,
        kv_count,
    )
    from .cache import cache
    from .masking import mask_pii
    from .integrity import verify_database_integrity
    from .cloud_sync import cloud_sync


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
    """Export decrypted (and optionally sanitized) documents to a folder."""
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM kv_store")
    rows = cursor.fetchall()

    if not rows:
        print("No records found in database to export.")
        return

    sanitize_mode = getattr(args, "sanitize", False)
    strategy = getattr(args, "strategy", "partial")
    custom_fields = args.fields.split(",") if getattr(args, "fields", None) else None

    print(f"\nExporting {len(rows)} documents to {out_dir} (Sanitized: {sanitize_mode})...")
    success = 0
    for row in rows:
        key = row["key"]
        val_bytes = row["value"]
        try:
            data = decrypt_and_unpack(val_bytes)
            if sanitize_mode:
                data = mask_pii(data, fields=custom_fields, strategy=strategy)
            target_file = out_dir / (key if key.endswith(".json") else f"{key}.json")
            target_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            success += 1
        except Exception as e:
            print(f" [!] Failed to process '{key}': {e}")

    print(f"Export complete: {success}/{len(rows)} files saved.\n")


def cmd_import(args):
    """Import a folder of JSON files into the database."""
    try:
        from migrate import migrate_folder
    except ImportError:
        from ..migrate import migrate_folder
    folder = Path(args.path)
    migrate_folder(folder)


def cmd_vacuum(args):
    """Run database maintenance and checkpointing."""
    print(f"\nRunning database maintenance on {DB_PATH}...")
    res = db_maintenance()
    print(f"Result: {res}\n")


def cmd_rotate_key(args):
    """Rotate encryption key across all database records atomically."""
    old_key = args.old_key or os.getenv("ENCRYPTION_KEY")
    if not old_key:
        print("Error: Old encryption key not specified. Provide --old-key or set ENCRYPTION_KEY.")
        return

    new_key = args.new_key
    if not new_key:
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
    key = args.key
    data = kv_get(key, default=None)
    if data is None:
        print(f"Key '{key}' not found in database.")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_verify(args):
    """Run a complete cryptographic integrity and anti-tamper audit."""
    print("\n" + "=" * 60)
    print(" 🛡️ CRYPTOGRAPHIC DATABASE INTEGRITY AUDIT")
    print("=" * 60)

    res = verify_database_integrity()
    print(f" - Status            : {res['status'].upper()}")
    print(f" - Total Inspected   : {res['total_records']} records")
    print(f" - Cryptographically Valid : {res['valid_records']}")
    print(f" - Corrupted/Tampered      : {res['corrupted_records']}")

    if res['corrupted_records'] > 0:
        print("\n [!] CORRUPTED RECORDS DETECTED:")
        for item in res['corrupted_keys']:
            print(f"   - {item['key']}: {item['reason']}")
        print("\n [ALERT] Database has failed cryptographic integrity check!")
    else:
        print("\n ✅ 100% CLEAN: All records passed cryptographic signature verification.")
    print("=" * 60 + "\n")


def cmd_find(args):
    """Search and list keys matching a wildcard pattern."""
    pattern = args.pattern
    limit = args.limit
    keys = kv_search(pattern=pattern, limit=limit)
    print(f"\n🔍 Found {len(keys)} matching key(s) for pattern '{pattern}':")
    for k in keys:
        print(f"  - {k}")
    print()


def cmd_count(args):
    """Print total document count."""
    pattern = args.pattern
    count = kv_count(pattern=pattern)
    if pattern:
        print(f"Total documents matching '{pattern}': {count:,}")
    else:
        print(f"Total stored documents: {count:,}")


def cmd_cloud_backup(args):
    """Create a live online snapshot and upload to S3/Cloudflare R2."""
    print("\n📦 Creating live online database snapshot...")
    res = cloud_sync.sync_to_cloud(retention_count=args.retention)
    print(f"✅ Snapshot created: {res['snapshot_file']} ({res['size_bytes']:,} bytes)")
    print(f"🔒 SHA-256 Checksum: {res['sha256']}")
    if cloud_sync._get_s3_client() is not None:
        print(f"☁️ Successfully synced to cloud bucket: {res['bucket']} ({res['remote_key']})\n")
    else:
        print(f"📁 Saved locally to data/snapshots/ (To enable cloud S3 sync, set S3_BUCKET_NAME / S3_ENDPOINT_URL env vars).\n")


def cmd_cloud_list(args):
    """List available backups in cloud bucket."""
    backups = cloud_sync.list_cloud_backups()
    if not backups:
        print(f"\nNo cloud backups found in bucket '{cloud_sync.bucket_name}'.")
    else:
        print(f"\n☁️ Remote Cloud Backups in '{cloud_sync.bucket_name}':")
        for b in backups:
            print(f"  - {b['key']} ({b['size_bytes']:,} bytes) — {b['last_modified']}")
    print()


def cmd_cloud_restore(args):
    """Restore database from a remote cloud backup."""
    print(f"\n⏳ Restoring database from cloud backup: '{args.key}'...")
    success = cloud_sync.restore_from_cloud(args.key)
    if success:
        print("✅ Database successfully restored from cloud backup!\n")
    else:
        print("❌ Cloud restore failed. Check S3 credentials and backup key name.\n")


def cmd_shell(args):
    """Enter the interactive encrypted-sqlite shell."""
    import shlex
    print("\n" + "=" * 60)
    print(" 🔐 ENCRYPTED SQLITE INTERACTIVE SHELL")
    print("=" * 60)
    print(" Type 'help' to see list of commands, or 'exit'/'quit' to exit.")
    print("=" * 60 + "\n")

    # Read-Eval-Print Loop (REPL)
    while True:
        try:
            line = input("encrypted-sqlite> ").strip()
            if not line:
                continue

            parts = shlex.split(line)
            cmd = parts[0].lower()

            if cmd in ("exit", "quit"):
                print("Goodbye!")
                break
            elif cmd == "help":
                print("\nAvailable Commands:")
                print("  get <key>             : Retrieve and print a decrypted document")
                print("  set <key> <json>      : Store a document (e.g. set user.json '{\"level\": 1}')")
                print("  delete <key>          : Delete a document by key")
                print("  keys [<pattern>]      : List keys, optionally matching a glob pattern")
                print("  find <field> <value>  : Query documents by blind index (e.g. find username 'Alex')")
                print("  stats                 : Display database stats")
                print("  exit / quit           : Exit the shell\n")
            elif cmd == "get":
                if len(parts) < 2:
                    print("Usage: get <key>")
                    continue
                key = parts[1]
                data = kv_get(key)
                if data is None:
                    print(f"Key '{key}' not found.")
                else:
                    print(json.dumps(data, indent=2, ensure_ascii=False))
            elif cmd == "set":
                if len(parts) < 3:
                    print("Usage: set <key> <json_data>")
                    continue
                key = parts[1]
                json_str = parts[2]
                try:
                    data = json.loads(json_str)
                    kv_set(key, data)
                    print(f"Success: Key '{key}' stored.")
                except json.JSONDecodeError as je:
                    print(f"Error: Invalid JSON data: {je}")
                except Exception as e:
                    print(f"Error: Failed to store key '{key}': {e}")
            elif cmd == "delete":
                if len(parts) < 2:
                    print("Usage: delete <key>")
                    continue
                key = parts[1]
                res = kv_delete(key)
                if res:
                    print(f"Success: Key '{key}' deleted.")
                else:
                    print(f"Key '{key}' not found or could not be deleted.")
            elif cmd == "keys":
                pattern = parts[1] if len(parts) > 1 else "*"
                keys = kv_search(pattern=pattern)
                print(f"Found {len(keys)} key(s):")
                for k in keys:
                    print(f"  - {k}")
            elif cmd == "find":
                if len(parts) < 3:
                    print("Usage: find <field_name> <value>")
                    continue
                field = parts[1]
                val = parts[2]
                if val.isdigit():
                    val = int(val)
                else:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
                res = kv_find_by_index(field, val)
                if not res:
                    print(f"No records found matching {field} = {val}.")
                else:
                    print(f"Found {len(res)} record(s):")
                    print(json.dumps(res, indent=2, ensure_ascii=False))
            elif cmd == "stats":
                class MockArgs:
                    path = None
                cmd_stats(MockArgs())
            else:
                print(f"Unknown command: '{cmd}'. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except EOFError:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="encrypted-sqlite",
        description="Encrypted SQLite JSON & Two-Tier Caching CLI Utility"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # keygen
    subparsers.add_parser("keygen", help="Generate a new cryptographic AES-256 Fernet key")

    # stats
    p_stats = subparsers.add_parser("stats", help="Display storage, telemetry, and L1 cache hit metrics")
    p_stats.add_argument("path", nargs="?", default=None, help="Optional database file path")

    # export
    p_export = subparsers.add_parser("export", help="Export all decrypted documents to a folder")
    p_export.add_argument("--out", "-o", default="./decrypted_export", help="Output directory")
    p_export.add_argument("--sanitize", "-s", action="store_true", help="Redact/mask sensitive PII fields (GDPR/privacy)")
    p_export.add_argument("--strategy", choices=["partial", "full", "hash"], default="partial", help="Masking strategy (default: partial)")
    p_export.add_argument("--fields", default=None, help="Comma-separated list of custom field names to mask")

    # import
    p_import = subparsers.add_parser("import", help="Import JSON files into SQLite database")
    p_import.add_argument("path", help="Path to a JSON file or directory of JSON files")

    # vacuum
    subparsers.add_parser("vacuum", help="Run WAL checkpoint truncation and DB optimization")

    # rotate-key
    p_rot = subparsers.add_parser("rotate-key", help="Re-encrypt all records with a new encryption key")
    p_rot.add_argument("--new-key", "-n", default=None, help="New Fernet encryption key")
    p_rot.add_argument("--old-key", "-o", default=None, help="Old Fernet encryption key (defaults to ENCRYPTION_KEY env)")

    # verify
    subparsers.add_parser("verify", help="Run cryptographic integrity check against bit-rot and tampering")

    # get
    p_get = subparsers.add_parser("get", help="Retrieve and print a decrypted document by key")
    p_get.add_argument("key", help="Key name (e.g. user_101.json)")

    # find
    p_find = subparsers.add_parser("find", help="Search keys matching a wildcard pattern")
    p_find.add_argument("--pattern", "-p", default="*", help="Glob pattern (e.g. 'user_*', '*.json')")
    p_find.add_argument("--limit", "-l", type=int, default=None, help="Maximum number of keys to return")

    # count
    p_count = subparsers.add_parser("count", help="Count total stored documents in the database")
    p_count.add_argument("--pattern", "-p", default=None, help="Optional glob pattern filter")

    # cloud-backup
    p_cb = subparsers.add_parser("cloud-backup", help="Create live snapshot and sync to Cloudflare R2 / AWS S3")
    p_cb.add_argument("--retention", "-r", type=int, default=7, help="Number of recent backups to retain (default: 7)")

    # cloud-list
    subparsers.add_parser("cloud-list", help="List remote backups available in S3 / R2 bucket")

    # cloud-restore
    p_cr = subparsers.add_parser("cloud-restore", help="Restore database from a remote cloud backup key")
    p_cr.add_argument("key", help="Remote backup key (e.g. backups/snapshot_20260827.db)")

    # shell
    subparsers.add_parser("shell", help="Enter the interactive encrypted-sqlite REPL shell")

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
        "verify": cmd_verify,
        "get": cmd_get,
        "find": cmd_find,
        "count": cmd_count,
        "cloud-backup": cmd_cloud_backup,
        "cloud-list": cmd_cloud_list,
        "cloud-restore": cmd_cloud_restore,
        "shell": cmd_shell,
    }

    cmd_fn = dispatch.get(args.command)
    if cmd_fn:
        cmd_fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
