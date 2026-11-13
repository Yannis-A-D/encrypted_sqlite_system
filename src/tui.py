"""
tui.py — Terminal User Interface (TUI) Dashboard for Encrypted SQLite System.

Powered by Rich:
- Live Database & Engine Telemetry Header (Encryption, KDF, Compression, WAL, DPAPI)
- KPI Metrics Panels (Record Count, Cache Hit Rate, Memory Usage, Expired Records)
- Interactive Document Browser with Syntax-Highlighted JSON Viewer
- One-Click Maintenance Actions (Vacuum, Purge Expired, Key Rotation, Integrity Check)
"""

import sys
import os
import json
import time
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.syntax import Syntax
from rich.text import Text
from rich.prompt import Prompt, Confirm

# Ensure project root is available
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from src.database import (
    DB_PATH,
    DATA_DIR,
    get_db_connection,
    get_active_algorithm,
    get_active_compression,
    get_active_kdf_algorithm,
    kv_get,
    kv_set,
    kv_delete,
    kv_search,
    kv_count,
    purge_expired_records,
    db_maintenance,
    rotate_encryption_key,
    SALT_FILE,
)
from src.cache import cache
from src.keyring_manager import KeyManager
from src.integrity import verify_database_integrity

console = Console()


def render_header() -> Panel:
    """Renders the top system telemetry status panel."""
    wal_path = Path(str(DB_PATH) + "-wal")
    db_size = f"{DB_PATH.stat().st_size / 1024:.1f} KB" if DB_PATH.exists() else "0 KB"
    wal_size = f"{wal_path.stat().st_size / 1024:.1f} KB" if wal_path.exists() else "0 KB"

    salt_status = "[green]Active (16-byte)[/green]" if SALT_FILE.exists() else "[yellow]Default/None[/yellow]"
    backend = KeyManager.get_backend_name()

    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="right", ratio=1)

    col1 = Text()
    col1.append("🗄️ Database: ", style="bold cyan")
    col1.append(f"{DB_PATH.name} ({db_size})\n", style="white")
    col1.append("🌊 WAL Journal: ", style="bold cyan")
    col1.append(f"{wal_size}\n", style="white")
    col1.append("🔑 Key Storage: ", style="bold cyan")
    col1.append(f"{backend}\n", style="green")

    col2 = Text()
    col2.append("🔒 Cipher: ", style="bold magenta")
    col2.append(f"{get_active_algorithm()}\n", style="bold white")
    col2.append("🛡️ KDF: ", style="bold magenta")
    col2.append(f"{get_active_kdf_algorithm()}\n", style="bold white")
    col2.append("🗜️ Codec: ", style="bold magenta")
    col2.append(f"{get_active_compression()} | Salt: ", style="white")
    col2.append("Salt OK\n" if SALT_FILE.exists() else "Init\n", style="green" if SALT_FILE.exists() else "yellow")

    grid.add_row(col1, col2)

    return Panel(
        grid,
        title="[bold green]🔐 Encrypted SQLite System v2.0 Dashboard[/bold green]",
        subtitle="[dim]Zero-Knowledge Encrypted Document Engine[/dim]",
        border_style="green",
    )


def render_kpis() -> Table:
    """Renders KPI metrics cards."""
    total_docs = kv_count()
    l1_items = cache._adapter.size() if hasattr(cache, "_adapter") else 0
    hits = cache._hits
    misses = cache._misses
    total_reqs = hits + misses
    hit_rate = (hits / total_reqs * 100) if total_reqs > 0 else 0.0

    # Count expired records pending purge
    expired_pending = 0
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        now_ts = int(time.time())
        cur.execute("SELECT COUNT(*) FROM kv_store WHERE expires_at > 0 AND expires_at <= ?", (now_ts,))
        row = cur.fetchone()
        if row:
            expired_pending = row[0]
    except Exception:
        pass

    table = Table(expand=True, show_header=True, header_style="bold blue")
    table.add_column("📊 Total Documents", justify="center")
    table.add_column("⚡ L1 Cache Items", justify="center")
    table.add_column("🎯 L1 Hit Rate", justify="center")
    table.add_column("⏱️ Expired Pending", justify="center")

    hit_style = "bold green" if hit_rate >= 80 else ("bold yellow" if hit_rate >= 50 else "bold red")
    expired_style = "bold yellow" if expired_pending > 0 else "dim green"

    table.add_row(
        f"[bold white]{total_docs:,}[/bold white]",
        f"[bold cyan]{l1_items:,}[/bold cyan]",
        f"[{hit_style}]{hit_rate:.1f}% ({hits}/{total_reqs})[/{hit_style}]",
        f"[{expired_style}]{expired_pending:,}[/{expired_style}]",
    )
    return table


def view_document(key: str):
    """Fetches and displays syntax-highlighted JSON for a key."""
    console.print(f"\n[cyan]Fetching key:[/cyan] [bold]{key}[/bold]...")
    data = kv_get(key)
    if data is None:
        console.print(f"[bold red]❌ Key '{key}' not found or already expired.[/bold red]")
        return

    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"📄 [bold]{key}[/bold]", border_style="cyan"))


def list_keys(pattern: str = "*", limit: int = 25):
    """Lists matching keys in a structured table."""
    keys = kv_search(pattern=pattern)
    table = Table(title=f"Keys matching '{pattern}' (Found: {len(keys)})", expand=True)
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Key Name", justify="left", style="bold white")

    for idx, k in enumerate(keys[:limit], 1):
        table.add_row(str(idx), k)

    if len(keys) > limit:
        table.add_row("...", f"[dim]and {len(keys) - limit} more keys...[/dim]")

    console.print(table)


def run_tui():
    """Main interactive TUI loop."""
    while True:
        console.clear()
        console.print(render_header())
        console.print(render_kpis())
        console.print()

        menu = Table.grid(expand=True)
        menu.add_column(justify="left")
        menu.add_column(justify="left")

        col1 = """[bold cyan][1][/bold cyan] 📄 View / Inspect Document
[bold cyan][2][/bold cyan] 🔍 Search Keys (Glob)
[bold cyan][3][/bold cyan] ✏️  Set / Update Document
[bold cyan][4][/bold cyan] 🗑️  Delete Document
[bold cyan][5][/bold cyan] ⏱️  Purge Expired TTLs"""

        col2 = """[bold cyan][6][/bold cyan] 🧹 Vacuum & Checkpoint WAL
[bold cyan][7][/bold cyan] 🛡️  Cryptographic Integrity Audit
[bold cyan][8][/bold cyan] 🔄 Rotate Encryption Key
[bold cyan][9][/bold cyan] 🔑 Key Storage Info / Set DPAPI
[bold cyan][0][/bold cyan] 🚪 Exit Dashboard"""

        menu.add_row(Panel(col1, title="[bold]Document Operations[/bold]"), Panel(col2, title="[bold]Engine & Security[/bold]"))
        console.print(menu)

        choice = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "q", "exit"], default="1")

        if choice in ("0", "q", "exit"):
            console.print("[dim]Exiting dashboard. Goodbye![/dim]\n")
            break

        elif choice == "1":
            key = Prompt.ask("Enter document key (or pattern to search)")
            if "*" in key or "?" in key:
                list_keys(key)
                sub_key = Prompt.ask("Select key to view (or leave empty to go back)", default="")
                if sub_key:
                    view_document(sub_key)
            else:
                view_document(key)
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "2":
            pattern = Prompt.ask("Enter glob search pattern", default="*")
            list_keys(pattern)
            sub_key = Prompt.ask("Select key to view (or leave empty to go back)", default="")
            if sub_key:
                view_document(sub_key)
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "3":
            key = Prompt.ask("Enter document key name")
            json_str = Prompt.ask("Enter JSON payload (e.g. {\"name\": \"Alice\", \"role\": \"admin\"})")
            ttl_str = Prompt.ask("Optional TTL in seconds (leave empty for permanent)", default="")
            try:
                payload = json.loads(json_str)
                ttl_val = float(ttl_str) if ttl_str.strip() else None
                kv_set(key, payload, ttl=ttl_val)
                console.print(f"[bold green]✅ Stored '{key}' successfully" + (f" (TTL: {ttl_val}s)" if ttl_val else "") + ".[/bold green]")
            except Exception as e:
                console.print(f"[bold red]❌ Failed to store: {e}[/bold red]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "4":
            key = Prompt.ask("Enter document key to delete")
            if Confirm.ask(f"Are you sure you want to permanently delete '{key}'?"):
                success = kv_delete(key)
                if success:
                    console.print(f"[bold green]✅ Key '{key}' deleted.[/bold green]")
                else:
                    console.print(f"[bold yellow]⚠️ Key '{key}' not found.[/bold yellow]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "5":
            purged = purge_expired_records()
            console.print(f"[bold green]✅ Purge complete: Removed {purged} expired record(s).[/bold green]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "6":
            console.print("[cyan]Running WAL checkpoint and VACUUM...[/cyan]")
            db_maintenance()
            console.print("[bold green]✅ Database vacuumed and optimized.[/bold green]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "7":
            console.print("[cyan]Auditing AEAD integrity tags and data checksums...[/cyan]")
            result = verify_database_integrity()
            status_style = "bold green" if result.get("corrupted_records", 0) == 0 else "bold red"
            console.print(f"[{status_style}]Audit result: {result.get('status')} | Verified: {result.get('verified_records')}/{result.get('total_records')} records.[/{status_style}]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "8":
            console.print("[yellow]⚠️ Key rotation will re-encrypt all stored records.[/yellow]")
            if Confirm.ask("Do you want to proceed with atomic key rotation?"):
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                import base64
                new_key = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode("utf-8")
                res = rotate_encryption_key(old_key=None, new_key=new_key)
                console.print(f"[bold green]✅ Successfully re-encrypted {res.get('re_encrypted_count')} records.[/bold green]")
                console.print(f"[bold cyan]New Key:[/bold cyan] {new_key}")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")

        elif choice == "9":
            backend = KeyManager.get_backend_name()
            console.print(f"[bold cyan]Active Backend:[/bold cyan] {backend}")
            saved_key = KeyManager.get_master_key()
            if saved_key:
                console.print("[green]Secure master key is present in OS keyring / DPAPI storage.[/green]")
            else:
                console.print("[yellow]No master key currently stored in OS keyring / DPAPI.[/yellow]")
                if Confirm.ask("Would you like to store the current active key in OS Keyring / DPAPI?"):
                    from src.database import _get_raw_key_material
                    import base64
                    raw_b = _get_raw_key_material()
                    b64_k = base64.urlsafe_b64encode(raw_b).decode("utf-8")
                    used = KeyManager.save_master_key(b64_k)
                    console.print(f"[bold green]✅ Master key saved securely via {used}![/bold green]")
            Prompt.ask("\nPress [bold]Enter[/bold] to return to menu")


if __name__ == "__main__":
    run_tui()
