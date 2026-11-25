"""
generate_visuals.py — Generates visual architecture diagrams for the Encrypted SQLite System
using the Rust-accelerated Feather 2D Graphics Engine.
"""

from pathlib import Path
from feather import Canvas, ui, Font


def _draw_grid_and_backdrop(canvas: Canvas, width: int, height: int):
    canvas.draw_circle(240.0, 170.0, 360.0, fill="rgba(56, 189, 248, 0.045)")
    canvas.draw_circle(width * 0.5, height * 0.5, 420.0, fill="rgba(168, 85, 247, 0.035)")
    canvas.draw_circle(width - 220.0, height - 180.0, 380.0, fill="rgba(34, 197, 94, 0.035)")
    for x in range(0, width, 40):
        canvas.draw_line(float(x), 0.0, float(x), float(height), stroke="rgba(255, 255, 255, 0.015)", stroke_width=1.0)
    for y in range(0, height, 40):
        canvas.draw_line(0.0, float(y), float(width), float(y), stroke="rgba(255, 255, 255, 0.015)", stroke_width=1.0)


def render_system_visual_v3():
    print("[Feather Engine] Rendering Encrypted SQLite v3.0 Architecture Infographic...")

    root_dir = Path(__file__).parent
    docs_dir = root_dir / "docs" / "images"
    assets_dir = root_dir / "assets"
    docs_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)

    width, height = 1440, 980
    canvas = Canvas(width, height, background="#0c1017")
    font = Font.default_font()
    _draw_grid_and_backdrop(canvas, width, height)

    # Header Title Block
    canvas.draw_rounded_rect(40.0, 28.0, 1360.0, 86.0, rx=14.0, fill="#131926", stroke="#26334d", stroke_width=1.5)
    canvas.draw_text("ENCRYPTED SQLITE SYSTEM v3.0", 65.0, 46.0, size=24.0, color="#ffffff", font=font)
    canvas.draw_text(
        "INSTANTIABLE TWO-TIER CACHING ENGINE, KEK/DEK ENVELOPE CRYPTO & TYPED COLLECTIONS",
        65.0,
        80.0,
        size=11.5,
        color="#7dd3fc",
        font=font,
    )

    # Top-right security badges
    badges = [
        (820.0, 128.0, "AES-256-GCM", "#38bdf8", "rgba(56, 189, 248, 0.14)"),
        (960.0, 136.0, "CHACHA20-POLY", "#c084fc", "rgba(168, 85, 247, 0.14)"),
        (1108.0, 146.0, "KEK/DEK ENVELOPE", "#4ade80", "rgba(34, 197, 94, 0.14)"),
        (1266.0, 114.0, "SIV KEYS", "#fbbf24", "rgba(245, 158, 11, 0.14)"),
    ]
    for bx, bw, label, fg, bg in badges:
        canvas.draw_rounded_rect(bx, 49.0, bw, 32.0, rx=8.0, fill=bg, stroke=fg, stroke_width=1.0)
        canvas.draw_text(label, bx + 12.0, 59.0, size=10.5, color=fg, font=font)

    # KPI Telemetry Bar (4 metrics fit comfortably inside 1360px)
    telemetry_card = ui.Card(
        width=1360.0,
        padding=18.0,
        corner_radius=12.0,
        background="rgba(255, 255, 255, 0.025)",
        border_color="rgba(255, 255, 255, 0.08)",
    )
    kpi_row = ui.Row(gap=12.0)
    kpi_row.add(ui.Metric("< 0.007 ms", label="L1 Memory Read", trend="Copy-Isolated LRU"))
    kpi_row.add(ui.Metric("322,580", label="Write-Behind Ops/sec", trend="Re-Queue Safe"))
    kpi_row.add(ui.Metric("< 0.0001 ms", label="BLAKE2b Bloom", trend="Auto-Scaling Slices"))
    kpi_row.add(ui.Metric("< 1 ms O(1)", label="KEK Rotation", trend="Multi-Slot Recovery"))
    telemetry_card.add(kpi_row)
    telemetry_card.render(canvas, 40.0, 132.0)

    # COLUMN 1: Tier 1 - Isolated L1 & Scalable Bloom
    c1 = ui.Card(
        width=430.0,
        padding=22.0,
        corner_radius=16.0,
        background="#111722",
        border_color="rgba(56, 189, 248, 0.35)",
        shadow_blur=20.0,
        shadow_color="rgba(0, 0, 0, 0.4)",
    )
    c1.add(ui.Text("## [Tier 1] Isolated L1 & Bloom", size=17.0, color="#38bdf8"))
    c1.add(ui.Text("Zero-leak RAM caching & FIPS-safe negative lookups", size=11.0, color="#94a3b8"))
    c1.add(ui.Divider(thickness=1.0, color="rgba(255, 255, 255, 0.08)", margin=6.0))
    c1.add(
        ui.Text(
            "• **MemoryL1Adapter**: Copy-isolated LRU preventing rollback leaks\n"
            "• **CompressedMemoryL1**: Zstd/Zlib RAM (75% memory reduction)\n"
            "• **Encrypted RedisL1**: AEAD `ENC1:` envelopes + non-blocking `SCAN`\n"
            "• **BLAKE2b BloomFilter**: 128-bit double-hash with auto-scaling slices\n"
            "• **TTL Synchronization**: Unified reaper & automatic L1 eviction",
            size=11.5,
            color="#cbd5e1",
            line_spacing=6.0,
        )
    )
    c1.add(ui.Spacer(height=10.0))
    b1_row = ui.Row(gap=10.0)
    b1_row.add(ui.Button("Copy-Isolated LRU", background="#1e293b", size=10.5))
    b1_row.add(ui.Button("ENC1 Redis", background="rgba(56, 189, 248, 0.2)", size=10.5))
    c1.add(b1_row)
    c1.render(canvas, 40.0, 238.0)

    # COLUMN 2: Security - Envelope & HKDF Core
    c2 = ui.Card(
        width=430.0,
        padding=22.0,
        corner_radius=16.0,
        background="#111722",
        border_color="rgba(168, 85, 247, 0.35)",
        shadow_blur=20.0,
        shadow_color="rgba(0, 0, 0, 0.4)",
    )
    c2.add(ui.Text("## [Security] Envelope & HKDF Core", size=17.0, color="#c084fc"))
    c2.add(ui.Text("Multi-slot KEK/DEK wrapping & domain-separated subkeys", size=11.0, color="#94a3b8"))
    c2.add(ui.Divider(thickness=1.0, color="rgba(255, 255, 255, 0.08)", margin=6.0))
    c2.add(
        ui.Text(
            "• **KEK/DEK Vault Slots**: O(1) instant rotation + passphrase recovery\n"
            "• **HKDF v2 Subkeys**: Isolated keys for GCM, ChaCha20 & Fernet\n"
            "• **SIV Key Encryption**: Deterministic `ENCK1:` hides primary key names\n"
            "• **OS KeyManager**: Windows DPAPI, macOS Keychain & Secret Service\n"
            "• **HMAC GDPR Masking**: Keyed pseudonymization + traversal guards",
            size=11.5,
            color="#cbd5e1",
            line_spacing=6.0,
        )
    )
    c2.add(ui.Spacer(height=10.0))
    b2_row = ui.Row(gap=10.0)
    b2_row.add(ui.Button("DEKW1 Slots", background="#1e293b", size=10.5))
    b2_row.add(ui.Button("HKDF RFC 5869", background="rgba(168, 85, 247, 0.2)", size=10.5))
    c2.add(b2_row)
    c2.render(canvas, 505.0, 238.0)

    # COLUMN 3: Tier 2 - SQLite WAL & Typed Collections
    c3 = ui.Card(
        width=430.0,
        padding=22.0,
        corner_radius=16.0,
        background="#111722",
        border_color="rgba(34, 197, 94, 0.35)",
        shadow_blur=20.0,
        shadow_color="rgba(0, 0, 0, 0.4)",
    )
    c3.add(ui.Text("## [Tier 2] SQLite WAL & Collections", size=17.0, color="#4ade80"))
    c3.add(ui.Text("Multi-database isolation, typed schemas & ACID transactions", size=11.0, color="#94a3b8"))
    c3.add(ui.Divider(thickness=1.0, color="rgba(255, 255, 255, 0.08)", margin=6.0))
    c3.add(
        ui.Text(
            "• **EncryptedSQLite Engine**: Isolated instances (`encrypted_sqlite`)\n"
            "• **Typed Collection[T]**: Dataclass/Pydantic hydration & scoped queries\n"
            "• **Dot-Path Blind Indexes**: Indexes nested dicts & list arrays in O(1)\n"
            "• **BEGIN IMMEDIATE OCC**: Serializable multi-key transactions (no TOCTOU)\n"
            "• **Typed Reports**: `IntegrityReport`, `RotationReport` & `EngineStats`",
            size=11.5,
            color="#cbd5e1",
            line_spacing=6.0,
        )
    )
    c3.add(ui.Spacer(height=10.0))
    b3_row = ui.Row(gap=10.0)
    b3_row.add(ui.Button("Collection[T]", background="#1e293b", size=10.5))
    b3_row.add(ui.Button("BEGIN IMMEDIATE", background="rgba(34, 197, 94, 0.2)", size=10.5))
    c3.add(b3_row)
    c3.render(canvas, 970.0, 238.0)

    # Bottom Left: Durable Write-Behind & Async Engine
    b_left = ui.Card(
        width=660.0,
        padding=20.0,
        corner_radius=14.0,
        background="#10151f",
        border_color="rgba(245, 158, 11, 0.30)",
        shadow_blur=16.0,
        shadow_color="rgba(0, 0, 0, 0.3)",
    )
    b_left.add(ui.Text("### [Throughput] Durable Write-Behind & Async Engine", size=15.0, color="#fbbf24"))
    b_left.add(
        ui.Text(
            "• **Transient Failure Re-Queue**: Restores failed batches automatically on SQLite lock\n"
            "• **Chunked kv_mget + Pool**: 900-var SQL batches with persistent ThreadPool decryption\n"
            "• **Format-Tagged Codecs**: `MP1:` MessagePack + `orjson` with 256 MiB bomb caps\n"
            "• **Opt-In Disk Mirroring**: `mirror_to_disk=False` halves `save_json` write latency",
            size=11.5,
            color="#cbd5e1",
            line_spacing=5.5,
        )
    )
    b_left.render(canvas, 40.0, 610.0)

    # Bottom Right: Chunked AEAD Cloud Disaster Recovery
    b_right = ui.Card(
        width=660.0,
        padding=20.0,
        corner_radius=14.0,
        background="#10151f",
        border_color="rgba(236, 72, 153, 0.30)",
        shadow_blur=16.0,
        shadow_color="rgba(0, 0, 0, 0.3)",
    )
    b_right.add(ui.Text("### [Disaster Recovery] Streaming Chunked AEAD Cloud Sync", size=15.0, color="#f472b6"))
    b_right.add(
        ui.Text(
            "• **Framed AEAD Streaming**: Constant-RAM 4 MiB AES-GCM chunks (`ENCSNAP1:CHK1:`)\n"
            "• **Anti-Truncation & Reorder**: Sequence index + EOF finality bit bound in AAD\n"
            "• **S3 / R2 Multipart Sync**: Automatic multipart upload above 16 MiB + retention pruning\n"
            "• **Atomic Live Restore**: Closes SQLite pools, swaps DB, reloads DEK & clears L1",
            size=11.5,
            color="#cbd5e1",
            line_spacing=5.5,
        )
    )
    b_right.render(canvas, 740.0, 610.0)

    # Connectors (flush against card borders)
    canvas.draw_line(470.0, 380.0, 505.0, 380.0, stroke="#38bdf8", stroke_width=2.0)
    canvas.draw_circle(470.0, 380.0, 4.0, fill="#38bdf8")
    canvas.draw_circle(505.0, 380.0, 4.0, fill="#c084fc")

    canvas.draw_line(935.0, 380.0, 970.0, 380.0, stroke="#a855f7", stroke_width=2.0)
    canvas.draw_circle(935.0, 380.0, 4.0, fill="#c084fc")
    canvas.draw_circle(970.0, 380.0, 4.0, fill="#4ade80")

    canvas.draw_line(255.0, 540.0, 255.0, 610.0, stroke="#38bdf8", stroke_width=2.0)
    canvas.draw_circle(255.0, 540.0, 4.0, fill="#38bdf8")
    canvas.draw_circle(255.0, 610.0, 4.0, fill="#fbbf24")

    canvas.draw_line(1185.0, 540.0, 1185.0, 610.0, stroke="#4ade80", stroke_width=2.0)
    canvas.draw_circle(1185.0, 540.0, 4.0, fill="#4ade80")
    canvas.draw_circle(1185.0, 610.0, 4.0, fill="#f472b6")

    # Footer
    canvas.draw_text(
        "RENDERED WITH FEATHER ENGINE (RUST VECTOR RASTERIZER • SIMD AVX2 • SUBPIXEL AA)",
        40.0,
        948.0,
        size=11.0,
        color="#64748b",
        font=font,
    )
    canvas.draw_text(
        "MIT LICENSE • Yannis-A-D/encrypted_sqlite_system v3.0",
        1020.0,
        948.0,
        size=11.0,
        color="#64748b",
        font=font,
    )

    for target in (docs_dir / "architecture_v3.png", assets_dir / "architecture_v3.png"):
        canvas.save(str(target))
        print(f"[Feather Engine] Generated: {target}")


def render_envelope_visual():
    print("[Feather Engine] Rendering KEK/DEK Envelope & HKDF Key Hierarchy Infographic...")

    root_dir = Path(__file__).parent
    docs_dir = root_dir / "docs" / "images"
    assets_dir = root_dir / "assets"
    docs_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)

    width, height = 1440, 680
    canvas = Canvas(width, height, background="#0c1017")
    font = Font.default_font()
    _draw_grid_and_backdrop(canvas, width, height)

    # Header
    canvas.draw_rounded_rect(40.0, 26.0, 1360.0, 76.0, rx=14.0, fill="#131926", stroke="#26334d", stroke_width=1.5)
    canvas.draw_text("TWO-LAYER KEK / DEK ENVELOPE & HKDF KEY HIERARCHY", 65.0, 42.0, size=22.0, color="#ffffff", font=font)
    canvas.draw_text(
        "O(1) INSTANT KEY ROTATION (< 1 MS) • MULTI-SLOT RECOVERY PASSPHRASES • DOMAIN-SEPARATED SUBKEYS",
        65.0,
        74.0,
        size=11.0,
        color="#4ade80",
        font=font,
    )

    # Left Column: Unlock Slots (KEKs)
    slot1 = ui.Card(
        width=360.0,
        padding=18.0,
        corner_radius=14.0,
        background="#111722",
        border_color="rgba(56, 189, 248, 0.40)",
    )
    slot1.add(ui.Text("### Slot 1: Primary Service KEK", size=14.5, color="#38bdf8"))
    slot1.add(
        ui.Text(
            "• Source: **DPAPI / OS Keyring / Env Key**\n"
            "• Wraps DEK with AES-256-GCM (`DEKW1:`)\n"
            "• AAD bound to `vault-dek-wrap-v3:primary`",
            size=11.0,
            color="#cbd5e1",
            line_spacing=5.0,
        )
    )
    slot1.render(canvas, 40.0, 145.0)

    slot2 = ui.Card(
        width=360.0,
        padding=18.0,
        corner_radius=14.0,
        background="#111722",
        border_color="rgba(245, 158, 11, 0.40)",
    )
    slot2.add(ui.Text("### Slot 2: Offline Recovery KEK", size=14.5, color="#fbbf24"))
    slot2.add(
        ui.Text(
            "• Source: **Argon2id / PBKDF2 Passphrase**\n"
            "• Per-slot 16-byte CSPRNG salt in SQLite\n"
            "• Unlocks vault if primary key is lost",
            size=11.0,
            color="#cbd5e1",
            line_spacing=5.0,
        )
    )
    slot2.render(canvas, 40.0, 340.0)

    # Center Column: Vault Key Slots & Master DEK
    dek_card = ui.Card(
        width=400.0,
        padding=22.0,
        corner_radius=16.0,
        background="#131926",
        border_color="rgba(34, 197, 94, 0.45)",
        shadow_blur=24.0,
        shadow_color="rgba(34, 197, 94, 0.12)",
    )
    dek_card.add(ui.Text("## Master 256-Bit DEK", size=18.0, color="#4ade80"))
    dek_card.add(ui.Text("Stored wrapped inside `vault_key_slots`", size=11.0, color="#94a3b8"))
    dek_card.add(ui.Divider(thickness=1.0, color="rgba(255, 255, 255, 0.08)", margin=6.0))
    dek_card.add(
        ui.Text(
            "• **Routine rotate_kek(new_key)**:\n"
            "  Re-wraps 32-byte DEK in **< 1 ms (O(1))**.\n"
            "  Zero row decryption needed.\n\n"
            "• **Emergency deep_rekey=True**:\n"
            "  Generates brand-new DEK and re-encrypts\n"
            "  all SQLite rows atomically (**O(N)**).",
            size=11.5,
            color="#cbd5e1",
            line_spacing=5.5,
        )
    )
    dek_card.render(canvas, 500.0, 175.0)

    # Right Column: HKDF-SHA256 Subkey Fan-out
    hkdf_card = ui.Card(
        width=410.0,
        padding=20.0,
        corner_radius=16.0,
        background="#111722",
        border_color="rgba(168, 85, 247, 0.45)",
    )
    hkdf_card.add(ui.Text("## HKDF-SHA256 Subkey Fan-Out", size=17.0, color="#c084fc"))
    hkdf_card.add(ui.Text("Strict cryptographic domain separation (RFC 5869)", size=11.0, color="#94a3b8"))
    hkdf_card.add(ui.Divider(thickness=1.0, color="rgba(255, 255, 255, 0.08)", margin=6.0))
    hkdf_card.add(
        ui.Text(
            "1. `aes-256-gcm-v2` -> Row & Redis AEAD payloads\n"
            "2. `chacha20-poly1305-v2` -> Alternate AEAD cipher\n"
            "3. `sqlite-key-siv` -> Deterministic `ENCK1:` keys\n"
            "4. `sqlite-blind-indexing` -> Dot-path HMAC indexes\n"
            "5. `sqlite-gdpr-pseudonym` -> Keyed PII hashes",
            size=11.5,
            color="#cbd5e1",
            line_spacing=7.5,
        )
    )
    hkdf_card.render(canvas, 990.0, 165.0)

    # Bottom Summary Strip
    strip = ui.Card(
        width=1360.0,
        padding=14.0,
        corner_radius=12.0,
        background="rgba(255, 255, 255, 0.025)",
        border_color="rgba(255, 255, 255, 0.08)",
    )
    row = ui.Row(gap=28.0)
    row.add(ui.Metric("O(1) < 1 ms", label="Routine KEK Swap", trend="Unchanged Rows"))
    row.add(ui.Metric("DEKW1:", label="AES-256-GCM Wrap", trend="Slot AAD Bound"))
    row.add(ui.Metric("5 Subkeys", label="HKDF Isolation", trend="Zero Key Reuse"))
    row.add(ui.Metric("Multi-Slot", label="Lockout Protection", trend="Primary + Recovery"))
    strip.add(row)
    strip.render(canvas, 40.0, 530.0)

    # Flow lines
    canvas.draw_line(400.0, 220.0, 500.0, 280.0, stroke="#38bdf8", stroke_width=2.0)
    canvas.draw_circle(400.0, 220.0, 4.0, fill="#38bdf8")
    canvas.draw_circle(500.0, 280.0, 4.0, fill="#4ade80")

    canvas.draw_line(400.0, 415.0, 500.0, 340.0, stroke="#fbbf24", stroke_width=2.0)
    canvas.draw_circle(400.0, 415.0, 4.0, fill="#fbbf24")
    canvas.draw_circle(500.0, 340.0, 4.0, fill="#4ade80")

    canvas.draw_line(900.0, 315.0, 990.0, 315.0, stroke="#4ade80", stroke_width=2.0)
    canvas.draw_circle(900.0, 315.0, 4.0, fill="#4ade80")
    canvas.draw_circle(990.0, 315.0, 4.0, fill="#c084fc")

    # Footer
    canvas.draw_text(
        "ENVELOPE KEY ARCHITECTURE • Yannis-A-D/encrypted_sqlite_system v3.0",
        40.0,
        650.0,
        size=11.0,
        color="#64748b",
        font=font,
    )

    for target in (docs_dir / "envelope_kek_dek.png", assets_dir / "envelope_kek_dek.png"):
        canvas.save(str(target))
        print(f"[Feather Engine] Generated: {target}")


if __name__ == "__main__":
    render_system_visual_v3()
    render_envelope_visual()
