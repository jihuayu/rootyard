#!/usr/bin/env python3
"""Offline unit, static contract, and deterministic reference tests for Track 3
(F48 Multi-Node 1/2/4-Node Concurrency & P95/P99 Latency Benchmark Suite +
F49 Pinned-Root Reachability & Resource Telemetry Verification).
"""
import argparse
import ast
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_tiers  # noqa: E402
import sharding  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class BenchmarkTiersTrack3ContractTest(unittest.TestCase):
    def test_benchmark_rs_static_contract_and_anti_monolith_bounds(self):
        sharding_rs = ROOT / "src/sharding.rs"
        benchmark_rs = ROOT / "src/sharding/benchmark.rs"
        bench_py = ROOT / "tests/benchmark_tiers.py"

        self.assertTrue(sharding_rs.is_file())
        self.assertTrue(benchmark_rs.is_file())
        self.assertTrue(bench_py.is_file())

        sharding_lines = sharding_rs.read_text(encoding="utf-8").splitlines()
        self.assertLess(len(sharding_lines), 90, f"src/sharding.rs must be < 90 lines, got {len(sharding_lines)}")

        bench_src = benchmark_rs.read_text(encoding="utf-8")
        bench_lines = bench_src.splitlines()
        self.assertGreaterEqual(
            len(bench_lines),
            300,
            f"src/sharding/benchmark.rs must be >= 300 lines, got {len(bench_lines)}",
        )
        self.assertLess(
            len(bench_lines),
            480,
            f"src/sharding/benchmark.rs must be < 480 lines, got {len(bench_lines)}",
        )
        self.assertGreaterEqual(bench_src.count("#[serde(deny_unknown_fields)]"), 7)
        self.assertGreaterEqual(bench_src.count("#[derive(Clone, Debug, Serialize, Deserialize)]"), 7)

        for required_token in (
            "CLUSTER_BENCHMARK_LOG_FILE",
            "REPO_BENCHMARK_RECEIPT_FILE",
            "pub struct BenchmarkRunRequest",
            "pub struct LatencyPercentiles",
            "pub struct ResourceTelemetry",
            "pub struct PinnedRootVerification",
            "pub struct NodeTierBenchmarkResult",
            "pub struct BenchmarkSuiteReceipt",
            "pub fn compute_latency_percentiles(",
            "pub fn collect_process_telemetry(",
            "pub fn render_benchmark_markdown(",
            "pub async fn list_cluster_benchmarks(",
            "pub async fn run_cluster_benchmark(",
            "pub async fn list_repo_benchmarks(",
            "pub async fn run_repo_benchmark(",
            "/proc/self/stat",
            "/proc/self/status",
            "/proc/self/io",
            "#[cfg(test)]",
        ):
            self.assertIn(required_token, bench_src, f"Missing {required_token} in src/sharding/benchmark.rs")

        py_src = bench_py.read_text(encoding="utf-8")
        py_lines = py_src.splitlines()
        self.assertLess(len(py_lines), 850, f"tests/benchmark_tiers.py must be < 850 lines, got {len(py_lines)}")
        ast.parse(py_src)

    def test_real_git_pinned_root_reachability_survives_prune(self):
        with tempfile.TemporaryDirectory(prefix="ry-git-pinned-") as tmp:
            repo_dir = Path(tmp) / "repo.git"
            fixture = benchmark_tiers.create_pinned_git_fixture(
                repo_dir,
                ["refs/rootyard-ci/jobs/job-a", "refs/rootyard-ci/jobs/job-b"],
            )
            self.assertEqual(len(fixture["pinned_refs"]), 2)
            self.assertGreaterEqual(len(fixture["expected_oids"]), 3)

            # Prune unreferenced loose objects
            benchmark_tiers._git(repo_dir, "prune", "--expire=now")
            check = benchmark_tiers.verify_git_pinned_roots(
                repo_dir,
                fixture["pinned_refs"],
                fixture["expected_oids"],
                active_snapshots=4,
                split_brain_rejected=2,
            )
            self.assertTrue(check["all_reachable"])
            self.assertEqual(check["missing_objects"], 0)
            self.assertEqual(check["pinned_refs_checked"], 2)

            # Simulating a missing expected object OID triggers missing_objects > 0 and all_reachable == False
            bad_check = benchmark_tiers.verify_git_pinned_roots(
                repo_dir,
                fixture["pinned_refs"],
                fixture["expected_oids"] + ["0" * 40],
            )
            self.assertFalse(bad_check["all_reachable"])
            self.assertGreaterEqual(bad_check["missing_objects"], 1)

    def test_1_2_4_node_benchmark_suite_and_symlink_rejection(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        repo = eng.create_repo(alice, "tier-repo")

        st, receipt = eng.run_repo_benchmark(
            alice,
            "alice",
            "tier-repo",
            node_counts=[1, 2, 4],
            concurrency=8,
            operations_per_tier=32,
            pinned_roots=["refs/rootyard-ci/jobs/bench-1", "refs/rootyard-ci/jobs/bench-2"],
        )
        self.assertEqual(st, 200)
        self.assertEqual([t["node_count"] for t in receipt["node_tiers"]], [1, 2, 4])
        self.assertTrue(receipt["pinned_roots_verified"])
        self.assertIn("| 1-node | 1024 |", receipt["markdown_report"])
        self.assertIn("| 2-node | 1024 |", receipt["markdown_report"])
        self.assertIn("| 4-node | 1024 |", receipt["markdown_report"])

        # Symlinked receipt file is rejected with 409 Conflict
        r_path = eng.repo_benchmark_receipt_path(repo["id"])
        r_path.unlink()
        r_path.symlink_to("/dev/null")
        self.assertEqual(eng.list_repo_benchmarks(alice, "alice", "tier-repo")[0], 409)

    def test_cli_runner_report_and_markdown_generation(self):
        with tempfile.TemporaryDirectory(prefix="ry-bench-cli-") as tmp:
            json_out = Path(tmp) / "bench.json"
            md_out = Path(tmp) / "bench.md"
            ns = argparse.Namespace(
                binary="target/debug/rootyard",
                report=json_out,
                markdown_report=md_out,
                node_counts="1,2,4",
                concurrency=8,
                keep=False,
                case="all",
                reference_only=True,
            )
            runner = benchmark_tiers.ShardingBenchmarkReferenceRunner(ns)
            try:
                runner.run_all()
            finally:
                runner.cleanup()
            self.assertIsNotNone(runner.suite_receipt)
            md_text = runner.suite_receipt["markdown_report"]
            self.assertIn("# Rootyard Multi-Node Sharding Benchmark Report", md_text)


if __name__ == "__main__":
    unittest.main()
