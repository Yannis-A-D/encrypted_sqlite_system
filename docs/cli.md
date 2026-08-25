# 🖥️ Command Line Interface (CLI)

The package includes a built-in `encrypted-sqlite` CLI command to manage and inspect your database.

---

## Commands

### 1. Generate Encryption Key
```bash
encrypted-sqlite keygen
```

### 2. View Database & Cache Stats
```bash
encrypted-sqlite stats
```
**Sample Output**:
```text
============================================================
 DATABASE & CACHE TELEMETRY
============================================================
 Database Path : data/app_database.db
 Database Size : 2.84 MB
 Stored Keys   : 147 documents

 Tier 1 (L1 RAM Cache):
 - Cached Items : 42 / 1000
 - Cache Hits   : 1420
 - Cache Misses : 31
 - Hit Ratio    : 97.8%
============================================================
```

---

### 3. Export Decrypted JSON Files
Export all encrypted database documents into a folder of plain-text `.json` files:
```bash
encrypted-sqlite export --out ./backup_json/
```

---

### 4. Import JSON Files into Database
Scan a folder of `.json` files and import them into the encrypted database:
```bash
encrypted-sqlite import ./my_data/
```

---

### 5. Inspect a Specific Document
```bash
encrypted-sqlite get user_101.json
```

---

### 6. Run Database Maintenance
```bash
encrypted-sqlite vacuum
```
