import time
import base64
import unittest
import urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src import (
    kv_set, kv_get, kv_delete, cache,
    metrics, MetricsCollector, start_metrics_server,
    get_db_connection
)
from src.database import ROOT_DIR, set_cipher_key


class TestMetricsExporter(unittest.TestCase):
    def setUp(self):
        # Clean test key setup
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

        cache.clear_l1()
        metrics.reset()
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

    def tearDown(self):
        cache.clear_l1()
        metrics.reset()
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

    def test_metrics_counters(self):
        """Verify counter recording and cache hit/miss tracking."""
        collector = MetricsCollector()
        collector.record_cache_hit()
        collector.record_cache_hit()
        collector.record_cache_miss()
        collector.record_operation("write", 5)

        self.assertEqual(collector.cache_hits, 2)
        self.assertEqual(collector.cache_misses, 1)
        self.assertEqual(collector.operations["write"], 5)

    def test_latency_quantiles(self):
        """Verify p50, p95, p99 percentiles computation."""
        collector = MetricsCollector(sample_window=100)
        # Add sample durations: 1ms to 100ms
        for i in range(1, 101):
            collector.record_latency("encrypt", i * 0.001)

        q = collector.get_quantiles("encrypt")
        self.assertEqual(q["count"], 100)
        self.assertAlmostEqual(q["p50"], 0.051, places=3)
        self.assertAlmostEqual(q["p95"], 0.096, places=3)
        self.assertAlmostEqual(q["p99"], 0.100, places=3)

    def test_measure_context_manager(self):
        """Verify measure() context manager records execution duration."""
        collector = MetricsCollector()
        with collector.measure("test_task"):
            time.sleep(0.02)

        q = collector.get_quantiles("test_task")
        self.assertEqual(q["count"], 1)
        self.assertGreater(q["p50"], 0.015)

    def test_prometheus_export_format(self):
        """Verify standard Prometheus 0.0.4 text exposition output."""
        collector = MetricsCollector()
        collector.record_cache_hit()
        collector.record_operation("read", 10)
        collector.record_latency("encrypt", 0.00025)

        prom_text = collector.export_prometheus()
        self.assertIn("# HELP encrypted_sqlite_cache_hits_total", prom_text)
        self.assertIn("# TYPE encrypted_sqlite_cache_hits_total counter", prom_text)
        self.assertIn("encrypted_sqlite_cache_hits_total 1", prom_text)
        self.assertIn('encrypted_sqlite_operations_total{operation="read"} 10', prom_text)
        self.assertIn('encrypted_sqlite_latency_seconds{operation="encrypt",quantile="0.5"}', prom_text)
        self.assertIn("encrypted_sqlite_database_size_bytes", prom_text)

    def test_opentelemetry_export_format(self):
        """Verify OpenTelemetry OTLP JSON dictionary structure."""
        collector = MetricsCollector()
        collector.record_cache_hit()
        collector.record_operation("write", 3)
        collector.record_latency("decrypt", 0.00015)

        otel = collector.export_opentelemetry()
        self.assertIn("resourceMetrics", otel)
        resource = otel["resourceMetrics"][0]
        self.assertEqual(
            resource["resource"]["attributes"][0]["value"]["stringValue"],
            "encrypted-sqlite-system"
        )
        metrics_list = resource["scopeMetrics"][0]["metrics"]
        metric_names = [m["name"] for m in metrics_list]
        self.assertIn("encrypted_sqlite.cache.hits", metric_names)
        self.assertIn("encrypted_sqlite.operations", metric_names)
        self.assertIn("encrypted_sqlite.latency.decrypt", metric_names)

    def test_end_to_end_instrumentation(self):
        """Verify that live database and cache actions increment metrics automatically."""
        # Initial state
        initial_writes = metrics.operations.get("write", 0)
        initial_reads = metrics.operations.get("read", 0)

        # Write through TwoTierCache
        cache.set("telemetry_test.json", {"key": "value"})
        self.assertGreater(metrics.operations.get("write", 0), initial_writes)

        # Cache hit
        cache.get("telemetry_test.json")
        self.assertGreaterEqual(metrics.cache_hits, 1)

        # Cache miss & direct DB read
        cache.clear_l1()
        cache.get("telemetry_test.json")
        self.assertGreater(metrics.operations.get("read", 0), initial_reads)
        self.assertGreaterEqual(metrics.cache_misses, 1)

        # Delete
        kv_delete("telemetry_test.json")
        self.assertGreaterEqual(metrics.operations.get("delete", 0), 1)

        # Verify encryption and decryption latencies were tracked
        enc_quantiles = metrics.get_quantiles("encrypt")
        dec_quantiles = metrics.get_quantiles("decrypt")
        self.assertGreater(enc_quantiles["count"], 0)
        self.assertGreater(dec_quantiles["count"], 0)

    def test_embedded_http_metrics_server(self):
        """Verify the background HTTP metrics server responds with Prometheus text."""
        test_port = 19108
        server = start_metrics_server(port=test_port, host="127.0.0.1")
        try:
            # Test /metrics endpoint
            url = f"http://127.0.0.1:{test_port}/metrics"
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
                self.assertIn("encrypted_sqlite_cache_hits_total", body)

            # Test /health endpoint
            url_health = f"http://127.0.0.1:{test_port}/health"
            with urllib.request.urlopen(url_health, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
                self.assertIn("ok", body)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
