"""
migrate.py — Scan a directory of JSON files and migrate all data into Encrypted SQLite.
"""

import sys
import json
from pathlib import Path
from src.database import kv_set, init_db, _get_cipher
from cryptography.fernet import InvalidToken


def migrate_folder(target_dir: Path):
    init_db()
    cipher = _get_cipher()
    
    if not target_dir.exists():
        print(f"Target directory {target_dir} not found.")
        return

    json_files = list(target_dir.glob("*.json"))
    if not json_files:
        print(f"No .json files found in {target_dir}")
        return

    print(f"Found {len(json_files)} JSON files. Starting migration into SQLite...\n")
    success = 0

    for file in json_files:
        try:
            raw = file.read_bytes()
            if not raw:
                continue

            # Try decryption first
            try:
                plaintext = cipher.decrypt(raw)
                data = json.loads(plaintext)
            except (InvalidToken, Exception):
                # Fallback to plain JSON
                data = json.loads(raw.decode("utf-8"))

            kv_set(file.name, data)
            success += 1
            print(f"  ✅ Migrated: {file.name}")
        except Exception as e:
            print(f"  ❌ Failed {file.name}: {e}")

    print(f"\nMigration complete! {success}/{len(json_files)} files transferred into SQLite.")


if __name__ == "__main__":
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "data"
    migrate_folder(folder)
