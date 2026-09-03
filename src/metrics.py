"""
metrics.py — Real-Time Telemetry, Prometheus & OpenTelemetry Exporter.

Tracks real-time database operations, cache hit/miss ratios, and p50/p95/p99
encryption and I/O latency percentiles without external dependencies.
"""

import time
import threading
from collections import deque
from contextlib import contextmanager
from typing import Any
from http.server import HTTPServer, BaseHTTPRequestHandler


class MetricsCollector:
    """Thread-safe collector for operations, latencies, and storage metrics."""

    def __init__(self, sample_window: int = 1000):
        self._lock = threading.Lock()
        self.sample_window = sample_window

        # Counters
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.operations: dict[str, int] = {
            "read": 0,
            "write": 0,
            "delete": 0,
            "rotate": 0,
            "purge": 0,
        }

        # Bounded latency samples
        self._latencies: dict[str, deque[float]] = {
            "encrypt": deque(maxlen=sample_window),
            "decrypt": deque(maxlen=sample_window),
            "read": deque(maxlen=sample_window),
            "write": deque(maxlen=sample_window),
        }

    def record_cache_hit(self):
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self):
        with self._lock:
            self.cache_misses += 1

    def record_operation(self, op: str, count: int = 1):
        with self._lock:
            self.operations[op] = self.operations.get(op, 0) + count

    def record_latency(self, op: str, duration_seconds: float):
        with self._lock:
            if op not in self._latencies:
                self._latencies[op] = deque(maxlen=self.sample_window)
            self._latencies[op].append(duration_seconds)

    @contextmanager
    def measure(self, op: str):
        """Context manager to measure and record execution latency."""
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - t0
            self.record_latency(op, elapsed)

    def get_quantiles(self, op: str) -> dict[str, float]:
        """Compute p50, p95, and p99 percentiles for a given operation."""
        with self._lock:
            samples = list(self._latencies.get(op, []))

        if not samples:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "count": 0}

        samples.sort()
        n = len(samples)

        def _percentile(p: float) -> float:
            idx = int(p * n)
            return samples[min(idx, n - 1)]

        return {
            "p50": _percentile(0.50),
            "p95": _percentile(0.95),
            "p99": _percentile(0.99),
            "avg": sum(samples) / n,
            "count": n,
        }

    def reset(self):
        """Reset all tracked metrics to zero."""
        with self._lock:
            self.cache_hits = 0
            self.cache_misses = 0
            for k in self.operations:
                self.operations[k] = 0
            for k in self._latencies:
                self._latencies[k].clear()

    def export_prometheus(self) -> str:
        """Render metrics in Prometheus text exposition format (version 0.0.4)."""
        lines = []

        with self._lock:
            hits = self.cache_hits
            misses = self.cache_misses
            ops = dict(self.operations)

        total_cache = hits + misses
        hit_ratio = (hits / total_cache) if total_cache > 0 else 1.0

        # Dynamic database telemetry
        db_size = 0
        records_count = 0
        l1_count = 0
        try:
            from .database import DB_PATH, kv_count
            if DB_PATH.exists():
                db_size = DB_PATH.stat().st_size
            records_count = kv_count()
        except Exception:
            pass

        try:
            from .cache import cache
            l1_count = cache._adapter.size()
        except Exception:
            pass

        # Cache Counters
        lines.append("# HELP encrypted_sqlite_cache_hits_total Total number of L1 cache hits")
        lines.append("# TYPE encrypted_sqlite_cache_hits_total counter")
        lines.append(f"encrypted_sqlite_cache_hits_total {hits}")

        lines.append("# HELP encrypted_sqlite_cache_misses_total Total number of L1 cache misses")
        lines.append("# TYPE encrypted_sqlite_cache_misses_total counter")
        lines.append(f"encrypted_sqlite_cache_misses_total {misses}")

        lines.append("# HELP encrypted_sqlite_cache_hit_ratio Current L1 cache hit ratio")
        lines.append("# TYPE encrypted_sqlite_cache_hit_ratio gauge")
        lines.append(f"encrypted_sqlite_cache_hit_ratio {hit_ratio:.4f}")

        # Operations
        lines.append("# HELP encrypted_sqlite_operations_total Total database operations by type")
        lines.append("# TYPE encrypted_sqlite_operations_total counter")
        for op, count in ops.items():
            lines.append(f'encrypted_sqlite_operations_total{{operation="{op}"}} {count}')

        # Latency Summaries (Quantiles)
        lines.append("# HELP encrypted_sqlite_latency_seconds Latency percentiles in seconds")
        lines.append("# TYPE encrypted_sqlite_latency_seconds summary")
        for op in ["encrypt", "decrypt", "read", "write"]:
            q = self.get_quantiles(op)
            lines.append(f'encrypted_sqlite_latency_seconds{{operation="{op}",quantile="0.5"}} {q["p50"]:.6f}')
            lines.append(f'encrypted_sqlite_latency_seconds{{operation="{op}",quantile="0.95"}} {q["p95"]:.6f}')
            lines.append(f'encrypted_sqlite_latency_seconds{{operation="{op}",quantile="0.99"}} {q["p99"]:.6f}')
            lines.append(f'encrypted_sqlite_latency_seconds_count{{operation="{op}"}} {q["count"]}')

        # Gauges
        lines.append("# HELP encrypted_sqlite_database_size_bytes Database file size on disk in bytes")
        lines.append("# TYPE encrypted_sqlite_database_size_bytes gauge")
        lines.append(f"encrypted_sqlite_database_size_bytes {db_size}")

        lines.append("# HELP encrypted_sqlite_records_total Total number of active non-expired records")
        lines.append("# TYPE encrypted_sqlite_records_total gauge")
        lines.append(f"encrypted_sqlite_records_total {records_count}")

        lines.append("# HELP encrypted_sqlite_l1_items_cached Number of items cached in L1 RAM")
        lines.append("# TYPE encrypted_sqlite_l1_items_cached gauge")
        lines.append(f"encrypted_sqlite_l1_items_cached {l1_count}")

        return "\n".join(lines) + "\n"

    def export_opentelemetry(self) -> dict[str, Any]:
        """Export metrics structured as OpenTelemetry OTLP ResourceMetrics JSON dictionary."""
        with self._lock:
            hits = self.cache_hits
            misses = self.cache_misses
            ops = dict(self.operations)

        now_nano = int(time.time() * 1e9)

        metrics_list = [
            {
                "name": "encrypted_sqlite.cache.hits",
                "unit": "1",
                "sum": {"dataPoints": [{"timeUnixNano": now_nano, "asInt": hits}]},
            },
            {
                "name": "encrypted_sqlite.cache.misses",
                "unit": "1",
                "sum": {"dataPoints": [{"timeUnixNano": now_nano, "asInt": misses}]},
            },
        ]

        for op, count in ops.items():
            metrics_list.append({
                "name": "encrypted_sqlite.operations",
                "unit": "1",
                "sum": {
                    "dataPoints": [
                        {"timeUnixNano": now_nano, "asInt": count, "attributes": [{"key": "operation", "value": {"stringValue": op}}]}
                    ]
                },
            })

        for op in ["encrypt", "decrypt", "read", "write"]:
            q = self.get_quantiles(op)
            metrics_list.append({
                "name": f"encrypted_sqlite.latency.{op}",
                "unit": "s",
                "gauge": {
                    "dataPoints": [
                        {"timeUnixNano": now_nano, "asDouble": q["p50"], "attributes": [{"key": "quantile", "value": {"stringValue": "p50"}}]},
                        {"timeUnixNano": now_nano, "asDouble": q["p95"], "attributes": [{"key": "quantile", "value": {"stringValue": "p95"}}]},
                        {"timeUnixNano": now_nano, "asDouble": q["p99"], "attributes": [{"key": "quantile", "value": {"stringValue": "p99"}}]},
                    ]
                },
            })

        return {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "encrypted-sqlite-system"}}
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "encrypted-sqlite-metrics"},
                            "metrics": metrics_list,
                        }
                    ],
                }
            ]
        }


# Global Metrics Collector Singleton
metrics = MetricsCollector()


class _PrometheusRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler serving Prometheus metrics."""

    def do_GET(self):
        if self.path in ("/metrics", "/"):
            payload = metrics.export_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}\n')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress standard HTTP request logging to avoid console noise
        pass


def start_metrics_server(port: int = 9108, host: str = "0.0.0.0") -> HTTPServer:
    """
    Start a lightweight, zero-dependency embedded Prometheus metrics server in a daemon thread.
    Returns the running HTTPServer instance.
    """
    server = HTTPServer((host, port), _PrometheusRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="PrometheusMetricsServer")
    thread.start()
    return server
