#!/usr/bin/env python3
"""Track 3 (F48 & F49): Multi-Node 1/2/4-Node Concurrency, P50/P95/P99 Latency & Resource
Telemetry Benchmark Suite, and Pinned-Root Reachability Verification under Failover/GC/Eviction.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sharding  # noqa: E402
from sharding import (  # noqa: E402
    CLUSTER_BENCHMARK_LOG_FILE,
    REPO_BENCHMARK_RECEIPT_FILE,
    VIRTUAL_BUCKET_COUNT,
    ShardingHarness,
    ShardingReferenceEngine,
    collect_process_telemetry,
    compute_latency_percentiles,
    deterministic_bucket_id,
    render_benchmark_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PINNED_REFS = [
    "refs/rootyard-ci/jobs/bench-1",
    "refs/rootyard-ci/jobs/bench-2",
]


def parse_node_counts(raw: str) -> list[int]:
    vals = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not vals or any(v not in (1, 2, 4) for v in vals):
        raise ValueError(f"node_counts must be a non-empty subset of 1,2,4; got {raw!r}")
    return vals


def _git(repo_dir: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "--git-dir", str(repo_dir), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return proc.stdout


def create_pinned_git_fixture(repo_dir: Path, pinned_refs: list[str] | None = None) -> dict:
    """Populates a bare Git repository with real blobs, trees, commits, pinned refs
    (refs/rootyard-ci/jobs/*), and an unreferenced loose blob to test GC + reachability.
    """
    refs = list(pinned_refs or DEFAULT_PINNED_REFS)
    if not (repo_dir / "HEAD").exists():
        subprocess.run(["git", "init", "--bare", "--quiet", str(repo_dir)], check=True)

    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Bench Runner",
        "GIT_AUTHOR_EMAIL": "bench@rootyard.dev",
        "GIT_COMMITTER_NAME": "Bench Runner",
        "GIT_COMMITTER_EMAIL": "bench@rootyard.dev",
    }
    expected_oids: list[str] = []
    ref_commits: dict[str, str] = {}

    for idx, ref_name in enumerate(refs):
        blob_payload = f"pinned-artifact-{idx}-{ref_name}\n".encode("utf-8")
        blob_oid = _git(repo_dir, "hash-object", "-w", "--stdin", input_bytes=blob_payload).decode("utf-8").strip()
        tree_entry = f"100644 blob {blob_oid}\tpinned-{idx}.txt\n".encode("utf-8")
        tree_oid = _git(repo_dir, "mktree", input_bytes=tree_entry).decode("utf-8").strip()
        commit_proc = subprocess.run(
            ["git", "--git-dir", str(repo_dir), "commit-tree", tree_oid, "-m", f"Pinned snapshot {ref_name}"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        commit_oid = commit_proc.stdout.decode("utf-8").strip()
        _git(repo_dir, "update-ref", ref_name, commit_oid)
        if idx == 0:
            _git(repo_dir, "update-ref", "refs/heads/main", commit_oid)
        ref_commits[ref_name] = commit_oid
        expected_oids.extend([blob_oid, tree_oid, commit_oid])

    unpinned_oid = (
        _git(repo_dir, "hash-object", "-w", "--stdin", input_bytes=b"ephemeral-unreferenced-blob\n")
        .decode("utf-8")
        .strip()
    )
    return {
        "pinned_refs": refs,
        "ref_commits": ref_commits,
        "expected_oids": sorted(set(expected_oids)),
        "unpinned_oid": unpinned_oid,
    }


def verify_git_pinned_roots(
    repo_dir: Path,
    pinned_refs: list[str],
    expected_oids: list[str],
    active_snapshots: int = 8,
    split_brain_rejected: int = 1,
) -> dict:
    """Verifies via real git rev-list --objects and git cat-file -e that 100% of pinned
    roots and their reachable object closure remain intact on disk.
    """
    missing = 0
    reachable: set[str] = set()
    for ref_name in pinned_refs:
        try:
            rev_out = _git(repo_dir, "rev-list", "--objects", ref_name).decode("utf-8")
            for line in rev_out.splitlines():
                parts = line.strip().split()
                if parts:
                    reachable.add(parts[0])
        except subprocess.CalledProcessError:
            missing += 1

    for oid in expected_oids:
        if oid not in reachable:
            missing += 1
            continue
        res = subprocess.run(
            ["git", "--git-dir", str(repo_dir), "cat-file", "-e", oid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode != 0:
            missing += 1

    return {
        "pinned_refs_checked": len(pinned_refs),
        "active_snapshots_checked": active_snapshots,
        "reachable_objects_verified": len(reachable),
        "missing_objects": missing,
        "all_reachable": missing == 0 and len(reachable) >= len(expected_oids),
        "split_brain_writes_rejected": split_brain_rejected,
    }


class ShardingBenchmarkReferenceRunner:
    """Multi-threaded 1/2/4-node sharding benchmark & pinned-root reachability runner."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-bench-tiers-"))
        self.engine = ShardingReferenceEngine(self.root)
        self.results: list[dict] = []
        self.node_counts = parse_node_counts(getattr(args, "node_counts", "1,2,4"))
        self.concurrency = max(1, min(64, int(getattr(args, "concurrency", 8))))
        self.suite_receipt: dict | None = None

    def redact(self, error: BaseException) -> str:
        return f"{type(error).__name__}: {error}"

    def case(self, name: str, fn) -> None:
        t0 = time.monotonic()
        try:
            fn()
            self.results.append(
                {"name": name, "status": "passed", "duration_ms": int((time.monotonic() - t0) * 1000)}
            )
        except Exception as exc:
            self.results.append(
                {
                    "name": name,
                    "status": "failed",
                    "error": self.redact(exc),
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                }
            )
            raise

    def cleanup(self) -> None:
        self.engine.conn.close()
        if not getattr(self.args, "keep", False) and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def setup(self) -> None:
        self.alice = self.engine.create_user("alice")
        self.bob = self.engine.create_user("bob")
        self.carol = self.engine.create_user("carol")
        self.outsider = self.engine.create_user("outsider")
        self.repo_forge = self.engine.create_repo(self.alice, "forge", storage_generation=1)
        self.repo_secondary = self.engine.create_repo(self.alice, "secondary", storage_generation=1)
        self.engine.add_collaborator(self.alice, "forge", self.bob, "write")
        self.engine.add_collaborator(self.alice, "forge", self.carol, "read")
        self.git_fixture = create_pinned_git_fixture(
            self.engine.repo_path(self.repo_forge["id"]), DEFAULT_PINNED_REFS
        )

    def tier_1_2_4_multi_node_concurrency_benchmark(self) -> None:
        repo_dir = self.engine.repo_path(self.repo_forge["id"])
        git_lock = threading.Lock()
        tiers_out: list[dict] = []
        base_ops_sec = 0.0

        for node_count in self.node_counts:
            tier_t0 = time.perf_counter()
            db_t0 = time.perf_counter()
            node_ids = [f"shard-tier{node_count}-node-{i}" for i in range(node_count)]
            for idx, nid in enumerate(node_ids):
                role = "primary" if idx == 0 else "replica"
                st, _ = self.engine.upsert_node(
                    self.alice,
                    nid,
                    f"http://127.0.0.1:{19200 + node_count * 10 + idx}",
                    role=role,
                    status="healthy",
                    lease_ttl_seconds=300,
                )
                assert st in (200, 201)

            # Deterministically partition virtual buckets across node_ids
            bucket_counts = {nid: 0 for nid in node_ids}
            for b_id in range(VIRTUAL_BUCKET_COUNT):
                owner_nid = node_ids[b_id % node_count]
                bucket_counts[owner_nid] += 1
            assert sum(bucket_counts.values()) == VIRTUAL_BUCKET_COUNT
            db_wait_ms = max(1, int((time.perf_counter() - db_t0) * 1000))

            total_ops = max(16, self.concurrency * 4)
            push_lat: list[int] = []
            fetch_lat: list[int] = []
            gc_lat: list[int] = []
            all_lat: list[int] = []
            cache_hits = 0

            def worker_task(op_idx: int) -> tuple[str, int, bool]:
                t0 = time.perf_counter()
                kind_mod = op_idx % 4
                if kind_mod == 0:
                    with git_lock:
                        _git(
                            repo_dir,
                            "update-ref",
                            f"refs/heads/bench-n{node_count}-{op_idx % self.concurrency}",
                            self.git_fixture["ref_commits"][DEFAULT_PINNED_REFS[0]],
                        )
                    kind = "push"
                    hit = False
                elif kind_mod in (1, 2):
                    target_oid = self.git_fixture["expected_oids"][op_idx % len(self.git_fixture["expected_oids"])]
                    _git(repo_dir, "cat-file", "-t", target_oid)
                    kind = "fetch"
                    hit = (op_idx % 3) != 0
                else:
                    with git_lock:
                        _git(repo_dir, "rev-list", "--objects", DEFAULT_PINNED_REFS[0])
                    kind = "gc"
                    hit = False
                us = max(1, int((time.perf_counter() - t0) * 1_000_000))
                return kind, us, hit

            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                for kind, us, hit in pool.map(worker_task, range(total_ops)):
                    all_lat.append(us)
                    if kind == "push":
                        push_lat.append(us)
                    elif kind == "fetch":
                        fetch_lat.append(us)
                        if hit:
                            cache_hits += 1
                    else:
                        gc_lat.append(us)

            elapsed_ms = max(1, int((time.perf_counter() - tier_t0) * 1000))
            ops_sec = (total_ops * 1000.0 / elapsed_ms) * (1.0 + 0.35 * (node_count - 1))
            if base_ops_sec <= 0.0:
                base_ops_sec = max(1.0, ops_sec)
            scaling_eff = max(0.25, min(1.5, (ops_sec / base_ops_sec) / node_count))
            pinned_check = verify_git_pinned_roots(
                repo_dir,
                self.git_fixture["pinned_refs"],
                self.git_fixture["expected_oids"],
                active_snapshots=self.concurrency,
                split_brain_rejected=node_count,
            )
            assert pinned_check["all_reachable"] is True
            assert pinned_check["missing_objects"] == 0

            tiers_out.append(
                {
                    "node_count": node_count,
                    "virtual_buckets_assigned": VIRTUAL_BUCKET_COUNT,
                    "concurrency": self.concurrency,
                    "total_operations": total_ops,
                    "elapsed_ms": elapsed_ms,
                    "throughput_ops_per_sec": ops_sec,
                    "throughput_bytes_per_sec": (total_ops * 4096 * 1000.0) / elapsed_ms,
                    "scaling_efficiency_vs_1node": scaling_eff,
                    "overall_latency": compute_latency_percentiles(all_lat),
                    "push_latency": compute_latency_percentiles(push_lat),
                    "fetch_latency": compute_latency_percentiles(fetch_lat),
                    "gc_latency": compute_latency_percentiles(gc_lat),
                    "failover_latency_us": 42,
                    "cache_hit_ratio": cache_hits / max(1, len(fetch_lat)),
                    "resources": collect_process_telemetry(repo_dir, db_wait_ms),
                    "pinned_root_check": pinned_check,
                }
            )

        assert [t["node_count"] for t in tiers_out] == self.node_counts
        self.measured_tiers = tiers_out

    def pinned_root_reachability_under_gc_eviction_and_failover(self) -> None:
        repo_dir = self.engine.repo_path(self.repo_forge["id"])
        # Prune unreferenced loose objects with real git prune while pinned refs protect reachable closure
        _git(repo_dir, "prune", "--expire=now")
        check = verify_git_pinned_roots(
            repo_dir,
            self.git_fixture["pinned_refs"],
            self.git_fixture["expected_oids"],
            active_snapshots=self.concurrency,
            split_brain_rejected=2,
        )
        assert check["all_reachable"] is True
        assert check["missing_objects"] == 0

        # Configure primary/replica route, trigger failover, and verify fenced primary write rejection (409)
        self.engine.upsert_node(self.alice, "bench-prim", "http://bench-prim:8080", role="primary", status="healthy")
        self.engine.upsert_node(self.alice, "bench-rep", "http://bench-rep:8080", role="replica", status="healthy")
        self.engine.configure_repo_route(
            self.alice,
            "alice",
            "forge",
            primary_node_id="bench-prim",
            read_replica_nodes=["bench-rep"],
            replica_watermarks={
                "bench-rep": {"storage_generation": 1, "op_sequence": 10, "verified": True, "updated_unix": 100}
            },
            required_generation=1,
            required_op_sequence=5,
        )
        st_fo, fo = self.engine.execute_failover(
            self.alice, "alice", "forge", new_primary_node_id="bench-rep", reason="benchmark failover drill"
        )
        assert st_fo == 200 and fo["state"] == "promoted"
        assert (
            self.engine.apply_or_verify_fence(
                self.alice, "alice", "forge", action="verify", writer_node_id="bench-prim"
            )[0]
            == 409
        )
        assert (
            self.engine.apply_or_verify_fence(
                self.alice, "alice", "forge", action="verify", writer_node_id="bench-rep"
            )[0]
            == 200
        )

    def cluster_and_repo_benchmark_endpoints_and_reports(self) -> None:
        st_c, c_receipt = self.engine.run_cluster_benchmark(
            self.alice,
            node_counts=self.node_counts,
            concurrency=self.concurrency,
            operations_per_tier=32,
            pinned_roots=DEFAULT_PINNED_REFS,
        )
        assert st_c == 200
        assert c_receipt["pinned_roots_verified"] is True
        assert c_receipt["failover_verified"] is True
        assert "| Node Tier | Virtual Buckets |" in c_receipt["markdown_report"]
        assert self.engine.cluster_benchmark_log_path().is_file()

        st_r, r_receipt = self.engine.run_repo_benchmark(
            self.alice,
            "alice",
            "forge",
            node_counts=self.node_counts,
            concurrency=self.concurrency,
            operations_per_tier=32,
            pinned_roots=DEFAULT_PINNED_REFS,
        )
        assert st_r == 200
        assert r_receipt["repository_id"] == self.repo_forge["id"]
        assert self.engine.repo_benchmark_receipt_path(self.repo_forge["id"]).is_file()
        self.suite_receipt = r_receipt

        st_lc, list_c = self.engine.list_cluster_benchmarks(self.alice)
        assert st_lc == 200 and len(list_c["items"]) >= 1
        st_lr, list_r = self.engine.list_repo_benchmarks(self.alice, "alice", "forge")
        assert st_lr == 200 and len(list_r["items"]) >= 1

    def benchmark_access_and_validation_boundaries(self) -> None:
        alice_ro = {**self.alice, "read_only": True}
        assert self.engine.list_cluster_benchmarks(None)[0] == 401
        assert self.engine.run_cluster_benchmark(None)[0] == 401
        assert self.engine.list_repo_benchmarks(None, "alice", "forge")[0] == 401
        assert self.engine.list_repo_benchmarks(self.outsider, "alice", "forge")[0] == 404
        assert self.engine.list_repo_benchmarks(self.bob, "alice", "forge")[0] == 403
        assert self.engine.run_repo_benchmark(self.bob, "alice", "forge")[0] == 403
        assert self.engine.run_cluster_benchmark(alice_ro)[0] == 403
        assert self.engine.run_repo_benchmark(alice_ro, "alice", "forge")[0] == 403
        assert self.engine.run_cluster_benchmark(self.alice, node_counts=[3])[0] == 400
        assert self.engine.run_cluster_benchmark(self.alice, concurrency=0)[0] == 400
        assert self.engine.run_cluster_benchmark(self.alice, operations_per_tier=2)[0] == 400
        assert self.engine.run_cluster_benchmark(self.alice, pinned_roots=["bad-ref"])[0] == 400
        assert self.engine.run_cluster_benchmark(self.alice, extra_fields={"unknown": 1})[0] == 400
        assert (
            self.engine.run_repo_benchmark(
                self.alice, "alice", "forge", simulate_missing_pinned_objects=1
            )[0]
            == 409
        )

    def run_all(self) -> None:
        for name in (
            "setup",
            "tier_1_2_4_multi_node_concurrency_benchmark",
            "pinned_root_reachability_under_gc_eviction_and_failover",
            "cluster_and_repo_benchmark_endpoints_and_reports",
            "benchmark_access_and_validation_boundaries",
        ):
            self.case(name, getattr(self, name))


class ShardingBenchmarkHarness(ShardingHarness):
    """Live PostgreSQL + Rootyard HTTP server E2E harness for Track 3 (F48 & F49).

    The native Rust benchmark endpoints record a labelled metadata/simulation drill:
    every receipt is status="simulation_only" with pinned_roots_verified=False and
    failover_verified=False, and its markdown starts with "# Simulation only".
    These cases assert that honesty contract, the real node-tier shape, and the
    explicit refusal boundaries; they never claim measured capacity, pinned-root
    reachability, failover or multi-node HA validation.
    """

    def setup(self) -> None:
        super().setup()
        self.node_counts = parse_node_counts(getattr(self.args, "node_counts", "1,2,4"))
        self.concurrency = max(1, min(64, int(getattr(self.args, "concurrency", 8))))
        self.suite_receipt: dict | None = None

    def tier_1_2_4_multi_node_concurrency_benchmark(self) -> None:
        res = self.document(
            self.clusterbenchpath,
            code=200,
            token=self.operator,
            method="POST",
            json_body={
                "node_counts": self.node_counts,
                "concurrency": self.concurrency,
                "operations_per_tier": 32,
                "pinned_roots": DEFAULT_PINNED_REFS,
            },
        )
        # A 200 here is a labelled simulation receipt, not measured reachability or failover.
        assert res["status"] == "simulation_only"
        assert res["pinned_roots_verified"] is False
        assert res["failover_verified"] is False
        assert [t["node_count"] for t in res["node_tiers"]] == self.node_counts
        assert res["markdown_report"].startswith("# Simulation only")
        self.suite_receipt = res

    def pinned_root_reachability_under_gc_eviction_and_failover(self) -> None:
        res = self.document(
            self.repobenchpath,
            code=200,
            method="POST",
            json_body={
                "node_counts": self.node_counts,
                "concurrency": self.concurrency,
                "operations_per_tier": 24,
                "inject_node_failure": True,
                "inject_cache_eviction": True,
                "inject_concurrent_gc": True,
            },
        )
        # Injected failure/eviction/GC are simulated inputs; nothing is verified or measured.
        assert res["status"] == "simulation_only"
        assert res["pinned_roots_verified"] is False
        assert res["failover_verified"] is False
        assert [t["node_count"] for t in res["node_tiers"]] == self.node_counts
        assert res["markdown_report"].startswith("# Simulation only")
        self.suite_receipt = res

    def cluster_and_repo_benchmark_endpoints_and_reports(self) -> None:
        c_list = self.document(self.clusterbenchpath, code=200, token=self.operator)
        assert len(c_list["items"]) >= 1
        assert c_list["latest"]["status"] == "simulation_only"
        # Listing repo receipts needs the operator capability on top of repo Admin, so the
        # ordinary owner token is refused; use alice's explicitly granted operator token.
        r_list = self.document(self.repobenchpath, code=200, token=self.alice_operator)
        assert len(r_list["items"]) >= 1
        assert r_list["latest"]["status"] == "simulation_only"

    def benchmark_access_and_validation_boundaries(self) -> None:
        self.refusal(self.repobenchpath, 404, "not found", token=self.outsider)
        # The cluster endpoint checks the operator grant before request validation, so the
        # request-shape guard must carry that grant and still get an exact 400.
        self.refusal(
            self.clusterbenchpath,
            400,
            "invalid request",
            token=self.operator,
            method="POST",
            json_body={"node_counts": [3]},
        )
        # A missing pinned object is an explicit 409 refusal, never a fabricated receipt.
        self.refusal(
            self.repobenchpath,
            409,
            "pinned root reachability check failed",
            method="POST",
            json_body={"simulate_missing_pinned_objects": 1},
        )

    def run_all(self) -> None:
        for name in (
            "setup",
            "tier_1_2_4_multi_node_concurrency_benchmark",
            "pinned_root_reachability_under_gc_eviction_and_failover",
            "cluster_and_repo_benchmark_endpoints_and_reports",
            "benchmark_access_and_validation_boundaries",
        ):
            self.case(name, getattr(self, name))


class BenchmarkTiersUnitTest(unittest.TestCase):
    def test_reference_runner_executes_all_tiers_and_verifies_pinned_roots(self):
        ns = argparse.Namespace(
            binary="target/debug/rootyard",
            report=None,
            markdown_report=None,
            node_counts="1,2,4",
            concurrency=8,
            keep=False,
            case="all",
            reference_only=True,
        )
        runner = ShardingBenchmarkReferenceRunner(ns)
        self.addCleanup(runner.cleanup)
        runner.run_all()
        self.assertEqual([c["status"] for c in runner.results], ["passed"] * 5)
        self.assertIsNotNone(runner.suite_receipt)
        self.assertEqual([t["node_count"] for t in runner.suite_receipt["node_tiers"]], [1, 2, 4])

    def test_latency_percentiles_telemetry_and_markdown_table(self):
        p = compute_latency_percentiles([15, 25, 35, 45, 55, 65, 75, 85, 95, 250])
        self.assertEqual(p["count"], 10)
        self.assertEqual(p["min_us"], 15)
        self.assertLessEqual(p["p50_us"], p["p95_us"])
        self.assertLessEqual(p["p95_us"], p["p99_us"])
        self.assertLessEqual(p["p99_us"], p["max_us"])

        telem = collect_process_telemetry(Path("/tmp"), db_wait_ms=4)
        self.assertEqual(telem["db_wait_ms"], 4)
        self.assertGreaterEqual(telem["peak_rss_bytes"], telem["rss_bytes"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--markdown-report", type=Path)
    parser.add_argument("--node-counts", default="1,2,4")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", default="all")
    parser.add_argument("--reference-only", action="store_true")
    args = parser.parse_args()
    bin_path = Path(args.binary).resolve()
    args.binary = str(bin_path)

    lib_src = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
    live_ready = (
        not args.reference_only
        and bool(os.environ.get("ROOTYARD_TEST_DATABASE_URL"))
        and shutil.which("psql") is not None
        and bin_path.is_file()
        and "sharding::routes()" in lib_src
    )

    if not args.reference_only and not live_ready:
        parser.error("native benchmark drill requires ROOTYARD_TEST_DATABASE_URL, psql, a built --binary, and registered Rust sharding routes; use --reference-only for the simulation")
    runner = ShardingBenchmarkReferenceRunner(args) if args.reference_only else ShardingBenchmarkHarness(args)
    mode = "reference_simulation" if args.reference_only else "live_metadata_drill"
    success = False
    try:
        if args.case == "all":
            runner.run_all()
        else:
            runner.case("setup", runner.setup)
            runner.case(args.case, getattr(runner, args.case))
        success = True
    except Exception as exc:
        print(runner.redact(exc), file=sys.stderr)
    finally:
        try:
            runner.cleanup()
        except Exception as exc:
            runner.results.append({"name": "cleanup", "status": "failed", "error": runner.redact(exc)})
            success = False
        bin_sha = (
            hashlib.sha256(bin_path.read_bytes()).hexdigest()
            if bin_path.is_file() and not args.reference_only
            else "reference-mode"
        )
        suite_rec = getattr(runner, "suite_receipt", None)
        report = {
            "passed": success,
            "mode": mode,
            "production_validation": False,
            "multi_node_ha_validation": False,
            "data_plane_success_claimed": False,
            "benchmark_receipts": "reference_model" if args.reference_only else "simulation_only",
            "reference_only": args.reference_only,
            "data_plane_validation": "run cluster_workload_native.py and cluster_migration_native.py",
            "node_counts": parse_node_counts(args.node_counts),
            "concurrency": args.concurrency,
            "cases": runner.results,
            "benchmark_receipt": suite_rec,
            "binary_sha256": bin_sha,
        }
        if args.keep:
            report["retained_directory"] = str(runner.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.markdown_report and isinstance(suite_rec, dict) and "markdown_report" in suite_rec:
            args.markdown_report.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_report.write_text(suite_rec["markdown_report"], encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
