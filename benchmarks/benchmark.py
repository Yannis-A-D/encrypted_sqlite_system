"""
benchmark.py — High-Precision Performance Benchmark Suite.

Compares:
1. Standard Python json.load() (Direct physical disk I/O)
2. Direct Encrypted SQLite (L2 Persistent Storage)
3. Two-Tier L1 Cache (RAM <0.01ms)

Measures: Latency (avg, min, p95), Operations per Second (Throughput), and Speedup Multipliers.
"""

import sys
import time
import json
import statistics
from pathlib import Path

# Ensure package is in sys.path
pkg_root = Path(__file__).parent.parent
sys.path.insert(0, str(pkg_root))

from src.secure_json import load_json, save_json
from src.cache import cache
from src.database import kv_set, kv_get, init_db


def generate_bar_chart(label: str, value: float, max_val: float, width: int = 35) -> str:
    """Generate an ASCII visual bar chart."""
    filled_len = int(width * (value / max_val)) if max_val > 0 else 0
    bar = "#" * filled_len + "-" * (width - filled_len)
    return f"{label:<26} |{bar}| {value:,.0f} ops/sec"


def run_benchmark(iterations: int = 1000):
    init_db()
    bench_dir = pkg_root / "benchmarks" / "data"
    bench_dir.mkdir(parents=True, exist_ok=True)
    raw_json_file = bench_dir / "bench_raw.json"

    sample_doc = {
        "user_id": "818106391411163217",
        "username": "BenchmarkUser",
        "level": 75,
        "xp": 450900,
        "inventory": ["netherite_sword", "elytra", "golden_apple", "shulker_box"],
        "history": [f"Action log event #{i} recorded at timestamp" for i in range(25)],
        "settings": {"notifications": True, "theme": "dark", "two_factor": True}
    }

    print("\n" + "=" * 75)
    print(f" TWO-TIER L1/L2 CACHE BENCHMARK SUITE ({iterations:,} Iterations)")
    print("=" * 75)

    # 1. Benchmark Standard JSON Disk Read
    raw_json_file.write_text(json.dumps(sample_doc, indent=2), encoding="utf-8")
    raw_latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = json.loads(raw_json_file.read_text(encoding="utf-8"))
        raw_latencies.append((time.perf_counter() - t0) * 1000)

    # 2. Benchmark Direct L2 SQLite Read (Decryption from disk)
    kv_set("bench_l2.json", sample_doc)
    cache.clear_l1()
    l2_latencies = []
    for _ in range(iterations):
        cache.clear_l1()  # Force L1 miss to test raw SQLite + AES decryption speed
        t0 = time.perf_counter()
        _ = kv_get("bench_l2.json")
        l2_latencies.append((time.perf_counter() - t0) * 1000)

    # 3. Benchmark Two-Tier L1 RAM Cache Read
    save_json("bench_l1.json", sample_doc)
    _ = load_json("bench_l1.json")  # Warmup
    l1_latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = load_json("bench_l1.json")
        l1_latencies.append((time.perf_counter() - t0) * 1000)

    # Calculate Metrics
    raw_avg = statistics.mean(raw_latencies)
    raw_p95 = statistics.quantiles(raw_latencies, n=20)[18]
    raw_ops = 1000 / raw_avg if raw_avg > 0 else 0

    l2_avg = statistics.mean(l2_latencies)
    l2_p95 = statistics.quantiles(l2_latencies, n=20)[18]
    l2_ops = 1000 / l2_avg if l2_avg > 0 else 0

    l1_avg = statistics.mean(l1_latencies)
    l1_p95 = statistics.quantiles(l1_latencies, n=20)[18]
    l1_ops = 1000 / l1_avg if l1_avg > 0 else 0

    speedup = raw_avg / l1_avg if l1_avg > 0 else 1.0

    # Print Formatted Results
    print("\n1. READ LATENCY & THROUGHPUT COMPARISON:")
    print("-" * 75)
    print(f" {'Storage Strategy':<28} | {'Avg Latency':<12} | {'P95 Latency':<12} | {'Throughput':<15}")
    print("-" * 75)
    print(f" {'1. Standard JSON (Disk/SSD)':<28} | {raw_avg:.4f} ms    | {raw_p95:.4f} ms    | {raw_ops:,.0f} ops/sec")
    print(f" {'2. L2 Encrypted SQLite (WAL)':<28} | {l2_avg:.4f} ms    | {l2_p95:.4f} ms    | {l2_ops:,.0f} ops/sec")
    print(f" {'3. Two-Tier L1 Cache (RAM)':<28} | {l1_avg:.4f} ms    | {l1_p95:.4f} ms    | {l1_ops:,.0f} ops/sec")
    print("-" * 75)

    print("\n2. VISUAL THROUGHPUT GRAPH (Higher is Better):")
    print("-" * 75)
    max_ops = max(raw_ops, l2_ops, l1_ops)
    print(" " + generate_bar_chart("Standard JSON (Disk)", raw_ops, max_ops))
    print(" " + generate_bar_chart("L2 Encrypted SQLite", l2_ops, max_ops))
    print(" " + generate_bar_chart("Two-Tier L1 RAM Cache", l1_ops, max_ops))
    print("-" * 75)

    print(f"\n[PERFORMANCE] Two-Tier L1 Cache is {speedup:.1f}x FASTER than physical disk reads!")
    print("=" * 75 + "\n")

    # Cleanup benchmark files
    try:
        import shutil
        if bench_dir.exists():
            shutil.rmtree(bench_dir)
    except Exception:
        pass


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_benchmark(count)
