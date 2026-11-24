"""Offline contract tests for the Rubicon mixed workload & scaling harness (Refs #164)."""

from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from rubicon_workload.corpus import DATASET_CLASSES, generate_repo_corpus, parse_push_porcelain  # noqa: E402
from rubicon_workload.report import (  # noqa: E402
    REFUSAL_RECEIPT_CLASSES,
    compute_overlap_metrics,
    find_secret_leaks,
    percentile_stats,
    render_summary_markdown,
    validate_report,
)
from rubicon_workload.runner import (  # noqa: E402
    PreflightError,
    WorkloadConfig,
    _preflight,
    _query_first_refusal_receipts,
)
from rubicon_workload.workloads import S3MeterProxy  # noqa: E402


def _valid_sample_report() -> dict:
    tier_base = {
        "compute_processes": 1,
        "wall_seconds": 8.5,
        "committed_ops_per_sec": 3.2941,
        "outcomes": {"total_ops": 35, "committed_success": 28, "typed_refusal": 6, "unknown_outcome": 1},
        "independent_ref_overlap": {
            "scope": "cross_repo_distinct_repositories",
            "total_ops": 6,
            "max_concurrent_overlap": 4,
            "overlapped_pairs": 7,
            "wall_span_ms": 420.0,
            "sum_op_durations_ms": 1320.0,
        },
        "same_repo_mixed_concurrency": {
            "scope": "same_repository_distinct_refs",
            "repo": "tiny-delta-t1",
            "total_ops": 3,
            "max_concurrent_overlap": 2,
            "overlapped_pairs": 1,
            "wall_span_ms": 210.0,
            "sum_op_durations_ms": 420.0,
            "committed_success": 3,
            "contention_retries": 0,
            "read_browse_ops": 4,
            "maintenance_pg_select_ops": 3,
        },
        "cas_race": {"participants": 4, "winner_count": 1, "loser_refused": 3, "false_ok": 0, "remote_ref_matches_winner": True},
        "atomic_vs_subset": {"atomic_rejected_unchanged": True, "subset_partial_exact": True, "atomic_positive_committed": True},
        "ci_read_amplification": {"burst_latencies": percentile_stats([45.0, 52.0, 61.0, 65.0]), "s3_wire": {"observed": True, "get_requests": 12, "get_bytes": 4096}},
        "cold_vs_warm": {
            "cold_clone": percentile_stats([120.0, 145.0]),
            "warm_clone": percentile_stats([72.0, 88.0]),
            "cold_browse": percentile_stats([18.0, 22.0]),
            "warm_browse": percentile_stats([11.0, 14.0]),
        },
        "fault_revocation_window": {"total_attempts": 3, "committed_success": 0, "typed_refusal": 2, "unknown_outcome": 1},
        "audit": {"acked_targets_total": 18, "verified_exact": 18, "fsck_failed": 0, "ref_mismatch": 0},
        "storage_accounting": {
            "pack_count": 20,
            "publication_count": 23,
            "serving_pack_bytes": 950000,
            "coexisting_pack_bytes": 1100000,
            "uncommitted_or_stale_registered_bytes": 150000,
            "gc_executed": False,
            "gc_reclaimed_physical_bytes": 0,
            "physical_savings_claimed": False,
        },
        "s3_wire": {"observed": True, "get_requests": 30, "get_bytes": 1500000, "put_requests": 46, "put_bytes": 1100000},
        "resource_peaks": {"cpu_seconds_total": 1.85, "max_total_rss_kib": 48120, "max_total_hwm_kib": 49000, "max_temp_disk_bytes": 655360, "max_pg_active": 3, "max_pg_lock_waiters": 0},
        "latency_by_op_class": {"concurrent_push": percentile_stats([90.0, 130.0]), "cold_clone": percentile_stats([120.0, 145.0])},
        "latency_by_dataset_class": {ds: percentile_stats([80.0, 110.0]) for ds in DATASET_CLASSES},
        "time_series": [
            {"t_ms": 0, "pack_count": 6, "coexisting_pack_bytes": 250000, "serving_pack_bytes": 250000, "active_serving_reads": 0, "pending_ops": 0},
            {"t_ms": 400, "pack_count": 20, "coexisting_pack_bytes": 1100000, "serving_pack_bytes": 950000, "active_serving_reads": 2, "pending_ops": 0},
        ],
    }
    tier2 = copy.deepcopy(tier_base)
    tier2["compute_processes"] = 2
    tier2["committed_ops_per_sec"] = 4.5
    return {
        "schema_version": "rootyard/rubicon-mixed-workload/v1",
        "issue": "#164",
        "measurement_kind": "native_execution",
        "simulated": False,
        "seed": 16420261116,
        "source": {"commit": "a" * 40, "dirty": False, "receipt_workspace_commit": "a" * 40, "source_inputs_sha256": "c" * 64},
        "binary": {
            "path": "/tmp/rootyard",
            "sha256": "b" * 64,
            "size_bytes": 123456,
            "receipt_verified": True,
            "receipt_schema": "v2",
            "receipt_sha256": "d" * 64,
            "workspace_commit": "a" * 40,
            "config_digest": "e" * 64,
            "source_inputs_sha256": "c" * 64,
        },
        "tools": {"git": "git version 2.56.1", "postgres": "PostgreSQL 17.0"},
        "hardware": {"logical_cpus": 4, "machine": "x86_64"},
        "topology": "1..2 serve-blob processes sharing one PG schema + one S3 provider",
        "tiers": [tier_base, tier2],
        "scaling_comparison": {"ratios": {"throughput_ratio_2_vs_1": 1.366}, "bottlenecks": ["single host contention"]},
        "limitations": ["Single host shared PG + S3"],
    }


class RubiconCorpusAndMetricsTests(unittest.TestCase):
    def test_deterministic_corpus_covers_all_dataset_classes_and_fits_quotas(self) -> None:
        for ds in DATASET_CLASSES:
            seed_a, delta_a = generate_repo_corpus(ds, seed=164, repo_index=0, variant_index=1)
            seed_b, delta_b = generate_repo_corpus(ds, seed=164, repo_index=0, variant_index=1)
            self.assertEqual(seed_a, seed_b)
            self.assertEqual(delta_a, delta_b)
            self.assertGreaterEqual(len(seed_a), 1)
            self.assertGreaterEqual(len(delta_a), 3)
            total_raw = sum(c.raw_bytes for c in seed_a + delta_a)
            self.assertLess(total_raw, 4 * 1024 * 1024, f"{ds} raw payload exceeds 4 MiB Browse bound")

    def test_overlap_and_porcelain_and_percentiles(self) -> None:
        overlap = compute_overlap_metrics([(100, 500), (150, 450), (600, 900)])
        self.assertEqual(overlap["max_concurrent_overlap"], 2)
        self.assertEqual(overlap["overlapped_pairs"], 1)

        parsed = parse_push_porcelain(
            "*\tHEAD:refs/heads/main\t[new branch]\n"
            "!\tHEAD:refs/heads/protected\t[rejected] (non-fast-forward)\n"
        )
        self.assertEqual([e["flag"] for e in parsed], ["*", "!"])
        self.assertEqual([e["target"] for e in parsed], ["refs/heads/main", "refs/heads/protected"])

        stats = percentile_stats([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual(stats["min_ms"], 10.0)
        self.assertEqual(stats["p50_ms"], 30.0)
        self.assertEqual(stats["p95_ms"], 50.0)
        self.assertEqual(stats["p99_ms"], 50.0)
        self.assertEqual(stats["max_ms"], 50.0)


class RubiconPreflightFailFastTests(unittest.TestCase):
    def test_cli_fails_fast_without_binary_or_fallback(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".rubicon-cli-test-") as tmp:
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "rubicon_mixed_workload.py"), "--binary", str(Path(tmp) / "missing-bin"), "--report", str(Path(tmp) / "out.json")],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse((Path(tmp) / "out.json").exists(), "report must not be created when preflight fails")

    def test_preflight_rejects_missing_dependencies_even_on_mocked_linux(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".rubicon-pre-test-") as tmp:
            fake_bin = Path(tmp) / "rootyard"
            fake_bin.write_bytes(b"stub")
            cfg = WorkloadConfig(binary=str(fake_bin), report=str(Path(tmp) / "r.json"), git=str(fake_bin), require_build_receipt=False)
            with (
                patch("rubicon_workload.runner.sys.platform", "linux"),
                patch("rubicon_workload.runner.Path.is_file", return_value=True),
                patch("rubicon_workload.runner.os.access", return_value=True),
                patch("rubicon_workload.runner.shutil.which", return_value="/usr/bin/psql"),
            ):
                with self.assertRaisesRegex(PreflightError, "ROOTYARD_TEST_DATABASE_URL"):
                    _preflight(cfg, {}, ROOT)
                with self.assertRaisesRegex(PreflightError, "ROOTYARD_BLOB_"):
                    _preflight(cfg, {"ROOTYARD_TEST_DATABASE_URL": "postgresql://u@127.0.0.1/db"}, ROOT)


class RubiconS3ProxyTests(unittest.TestCase):
    def test_s3_meter_proxy_preserves_host_header_and_counts_wire_traffic(self) -> None:
        observed_hosts: list[str] = []
        stored: dict[str, bytes] = {}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_PUT(self) -> None:
                observed_hosts.append(self.headers.get("Host", ""))
                length = int(self.headers.get("Content-Length", "0"))
                stored[self.path] = self.rfile.read(length)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                observed_hosts.append(self.headers.get("Host", ""))
                data = stored.get(self.path, b"")
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_HEAD(self) -> None:
                observed_hosts.append(self.headers.get("Host", ""))
                data = stored.get(self.path, b"")
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_thread.start()
        proxy = S3MeterProxy("127.0.0.1", srv.server_address[1])
        proxy.start()
        try:
            payload = b"rubicon-pack-bytes-0123456789" * 100
            req_put = urllib.request.Request(f"{proxy.endpoint}/bucket/pack.bin", data=payload, method="PUT")
            with urllib.request.urlopen(req_put, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
            req_head = urllib.request.Request(f"{proxy.endpoint}/bucket/pack.bin", method="HEAD")
            with urllib.request.urlopen(req_head, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
            req_get = urllib.request.Request(f"{proxy.endpoint}/bucket/pack.bin", method="GET")
            with urllib.request.urlopen(req_get, timeout=5) as resp:
                self.assertEqual(resp.read(), payload)

            # Separate 5s boundary budget; same numeric value as urlopen(timeout=5),
            # not a shared absolute timeout.
            snap = proxy.snapshot_after_quiescence(time.monotonic() + 5.0)
            self.assertEqual(snap["put_requests"], 1)
            self.assertEqual(snap["put_bytes"], len(payload))
            self.assertEqual(snap["head_requests"], 1)
            self.assertEqual(snap["get_requests"], 1)
            self.assertEqual(snap["get_bytes"], len(payload))
            self.assertTrue(all(h == f"127.0.0.1:{proxy.port}" for h in observed_hosts), observed_hosts)
        finally:
            proxy.stop()
            srv.shutdown()
            srv.server_close()


class RubiconReportValidationTests(unittest.TestCase):
    def test_valid_report_and_markdown_rendering(self) -> None:
        report = _valid_sample_report()
        validate_report(report, secrets=("supersecret",))
        md = render_summary_markdown(report)
        self.assertIn("Rubicon Mixed Workload", md)
        self.assertIn("`16420261116`", md)
        self.assertNotIn("Same-Repository First Attempts", md)

    def test_reports_first_attempts_separately_from_successes_after_retries(self) -> None:
        report = _valid_sample_report()
        same_repo = report["tiers"][0]["same_repo_mixed_concurrency"]
        same_repo["first_attempt_outcomes"] = {"committed_success": 1, "typed_refusal": 1, "unknown_outcome": 1}
        same_repo["contention_retries"] = 3

        validate_report(report)
        md = render_summary_markdown(report)
        self.assertIn("1 / 3 first-attempt successes, 1 refused and 1 unknown", md)
        self.assertIn("3 / 3 succeeded including retries.", md)

    def test_rejects_inconsistent_first_attempt_outcomes(self) -> None:
        for first, final, error in (
            (None, 3, "must contain"),
            ({"committed_success": 3, "typed_refusal": 0}, 3, "must contain"),
            ({"committed_success": True, "typed_refusal": 1, "unknown_outcome": 1}, 3, "non-negative int"),
            ({"committed_success": 1, "typed_refusal": 3, "unknown_outcome": -1}, 3, "non-negative int"),
            ({"committed_success": 1, "typed_refusal": 1, "unknown_outcome": 0}, 3, "must partition"),
            ({"committed_success": 2, "typed_refusal": 1, "unknown_outcome": 0}, 1, "must be between"),
            ({"committed_success": 1, "typed_refusal": 2, "unknown_outcome": 0}, 4, "must be between"),
        ):
            with self.subTest(first=first, final=final):
                report = _valid_sample_report()
                same_repo = report["tiers"][0]["same_repo_mixed_concurrency"]
                same_repo["first_attempt_outcomes"] = first
                same_repo["committed_success"] = final
                with self.assertRaisesRegex(ValueError, error):
                    validate_report(report)

    def test_first_refusal_receipt_validation_and_summary(self) -> None:
        report = _valid_sample_report()
        same_repo = report["tiers"][0]["same_repo_mixed_concurrency"]
        same_repo["first_attempt_outcomes"] = {"committed_success": 1, "typed_refusal": 2, "unknown_outcome": 0}
        receipts = {
            "admitted_base_superseded": 1,
            "per_ref_cas_rejected": 1,
            "other_durable_rejection": 0,
            "unresolved": 0,
        }
        same_repo["first_refusal_receipts"] = receipts
        validate_report(report)
        md = render_summary_markdown(report)
        for name, count in receipts.items():
            self.assertIn(f"{name}={count}", md)

        for mutate, error in (
            (lambda r: r.update(extra=0), "exactly the four receipt classes"),
            (lambda r: r.pop("unresolved"), "exactly the four receipt classes"),
            (lambda r: r.update(unresolved=True), "non-negative int"),
            (lambda r: r.update(other_durable_rejection=-1), "non-negative int"),
            (lambda r: r.update(other_durable_rejection=1), "must partition"),
        ):
            with self.subTest(error=error):
                broken = copy.deepcopy(report)
                mutate(broken["tiers"][0]["same_repo_mixed_concurrency"]["first_refusal_receipts"])
                with self.assertRaisesRegex(ValueError, error):
                    validate_report(broken)
        no_first = copy.deepcopy(report)
        del no_first["tiers"][0]["same_repo_mixed_concurrency"]["first_attempt_outcomes"]
        with self.assertRaisesRegex(ValueError, "requires first_attempt_outcomes"):
            validate_report(no_first)

    def test_first_refusal_receipt_query_is_bounded_and_finite(self) -> None:
        import uuid

        repo = "11111111-1111-4111-8111-111111111111"
        observations = [(i, str(uuid.uuid4())) for i in range(3)]
        calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            calls.append((cmd, kwargs))  # type: ignore[arg-type]
            return subprocess.CompletedProcess(
                cmd, 0,
                b'["admitted_base_superseded", "per_ref_cas_rejected", "unresolved"]',
                b"",
            )

        with patch("rubicon_workload.runner.subprocess.run", side_effect=fake_run):
            counts = _query_first_refusal_receipts("postgresql://u@127.0.0.1/db", {}, repo, observations)
        self.assertEqual(
            counts,
            {
                "admitted_base_superseded": 1,
                "per_ref_cas_rejected": 1,
                "other_durable_rejection": 0,
                "unresolved": 1,
            },
        )
        self.assertEqual(set(counts), set(REFUSAL_RECEIPT_CLASSES))
        cmd, kwargs = calls[0]
        sql = cmd[-1]
        self.assertEqual(kwargs["timeout"], 10)
        self.assertIn("SELECT json_agg(verdict ORDER BY ordinal)", sql)
        self.assertIn("refs/heads/same_branch_2", sql)
        for _, operation_id in observations:
            self.assertIn(operation_id, sql)

        with patch("rubicon_workload.runner.subprocess.run", side_effect=subprocess.TimeoutExpired("psql", 10)):
            failed = _query_first_refusal_receipts("postgresql://u@127.0.0.1/db", {}, repo, observations)
        self.assertEqual(failed["unresolved"], 3)

        unexpected = subprocess.CompletedProcess([], 0, b'["admitted_base_superseded", "bad", "unresolved"]')
        with patch("rubicon_workload.runner.subprocess.run", return_value=unexpected):
            malformed = _query_first_refusal_receipts("postgresql://u@127.0.0.1/db", {}, repo, observations)
        self.assertEqual(malformed["admitted_base_superseded"], 0)
        self.assertEqual(malformed["unresolved"], 3)
        bad = [(3, str(uuid.uuid4()))]
        with patch("rubicon_workload.runner.subprocess.run") as run:
            invalid = _query_first_refusal_receipts("postgresql://u@127.0.0.1/db", {}, repo, bad)
        run.assert_not_called()
        self.assertEqual(invalid["unresolved"], 1)

    def test_rejects_false_success_during_fault_window_and_unverified_audit(self) -> None:
        bad_fault = _valid_sample_report()
        bad_fault["tiers"][0]["fault_revocation_window"]["committed_success"] = 1
        with self.assertRaisesRegex(ValueError, "fault_revocation_window"):
            validate_report(bad_fault)

        bad_audit = _valid_sample_report()
        bad_audit["tiers"][0]["audit"]["verified_exact"] = 17
        with self.assertRaisesRegex(ValueError, "100% of ACKed"):
            validate_report(bad_audit)

    def test_rejects_unbacked_gc_savings_and_secret_leaks(self) -> None:
        bad_gc = _valid_sample_report()
        bad_gc["tiers"][0]["storage_accounting"]["physical_savings_claimed"] = True
        with self.assertRaisesRegex(ValueError, "physical storage savings"):
            validate_report(bad_gc)

        leaked = _valid_sample_report()
        leaked["topology"] = "leaked-s3-secret-token"
        self.assertEqual(find_secret_leaks(leaked, ["leaked-s3-secret-token"]), ["secret[0]"])
        with self.assertRaisesRegex(ValueError, "leaked sensitive"):
            validate_report(leaked, secrets=["leaked-s3-secret-token"])

    def test_workflow_and_docs_match_conventions(self) -> None:
        wf = (ROOT / ".github" / "workflows" / "rubicon-mixed-workload.yml").read_bytes()
        self.assertNotIn(b"\r", wf, "workflow must use pure LF line endings")
        wf_text = wf.decode("utf-8")
        for token in (
            "rubicon_mixed_workload.py",
            "owned_garage_fixture.sh",
            "persist-credentials: false",
            "test_rubicon_mixed_workload",
            "src/blob_store/**",
            "src/storage/**",
            "migrations/**",
        ):
            self.assertIn(token, wf_text)
        doc_text = (ROOT / "docs" / "rubicon-mixed-workload.md").read_text(encoding="utf-8")
        self.assertIn("#164", doc_text)
        self.assertIn("physical_savings_claimed", doc_text)
        self.assertIn("public.cluster_authority", doc_text)
        self.assertIn("same_repo_mixed_concurrency", doc_text)
        self.assertIn("verify_source_files=True", doc_text)


class RubiconProvisioningAndAuthorityTests(unittest.TestCase):
    def test_create_repo_and_wait_retries_409_and_provisioning_then_succeeds(self) -> None:
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from scripts.rubicon_workload.runner import _create_repo_and_wait

        state = {"gets": 0}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                body = json.dumps({"owner": "alice", "name": "r1", "state": "provisioning"}).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                state["gets"] += 1
                if state["gets"] == 1:
                    code, payload = 409, {"error": "repository is not ready"}
                elif state["gets"] == 2:
                    code, payload = 200, {"owner": "alice", "name": "r1", "state": "provisioning"}
                else:
                    code, payload = 200, {"owner": "alice", "name": "r1", "state": "ready"}
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            data = _create_repo_and_wait(f"http://127.0.0.1:{port}", "r1", {"token": "ryt_" + "a" * 64})
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(data["state"], "ready")
        self.assertEqual(state["gets"], 3)

    def test_create_repo_and_wait_fails_fast_on_500_and_redacts_token(self) -> None:
        import json
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from scripts.rubicon_workload.runner import _create_repo_and_wait

        secret_tok = "ryt_" + "b" * 64

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                body = json.dumps({"owner": "alice", "name": "r2", "state": "ready"}).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                body = json.dumps({"error": f"relation public.cluster_authority missing {secret_tok}"}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        t0 = time.monotonic()
        try:
            port = server.server_address[1]
            with self.assertRaises(RuntimeError) as ctx:
                _create_repo_and_wait(f"http://127.0.0.1:{port}", "r2", {"token": secret_tok})
        finally:
            server.shutdown()
            server.server_close()
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 3.0)
        msg = str(ctx.exception)
        self.assertIn("status=500", msg)
        self.assertIn("cluster_authority", msg)
        self.assertNotIn(secret_tok, msg)

    def test_verify_public_cluster_authority_checks_pg_result_without_leaking_dsn(self) -> None:
        import subprocess
        from unittest import mock
        from scripts.rubicon_workload.runner import _verify_public_cluster_authority

        with mock.patch("subprocess.check_output", return_value="t\n"):
            _verify_public_cluster_authority("postgresql://u:pw@127.0.0.1/db", {})

        with mock.patch("subprocess.check_output", return_value="f\n"):
            with self.assertRaisesRegex(RuntimeError, "public.cluster_authority"):
                _verify_public_cluster_authority("postgresql://u:pw@127.0.0.1/db", {})

        err = subprocess.CalledProcessError(2, ["psql", "--dbname", "postgresql://u:supersecretpw@127.0.0.1/db"])
        with mock.patch("subprocess.check_output", side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                _verify_public_cluster_authority("postgresql://u:supersecretpw@127.0.0.1/db", {})
        self.assertIn("exit=2", str(ctx.exception))
        self.assertNotIn("supersecretpw", str(ctx.exception))

    def test_collect_barrier_futures_prefers_root_cause_over_broken_barrier(self) -> None:
        import threading
        from concurrent.futures import Future
        from scripts.rubicon_workload.runner import _collect_barrier_futures

        f_barrier: Future[object] = Future()
        f_barrier.set_exception(threading.BrokenBarrierError())
        f_root: Future[object] = Future()
        f_root.set_exception(RuntimeError("indep clone failed (rc=128)"))

        with self.assertRaisesRegex(RuntimeError, "indep clone failed"):
            _collect_barrier_futures([f_barrier, f_root])

        f_only_barrier: Future[object] = Future()
        f_only_barrier.set_exception(threading.BrokenBarrierError())
        with self.assertRaises(threading.BrokenBarrierError):
            _collect_barrier_futures([f_only_barrier])

    def test_cli_and_runner_preserve_type_on_empty_exception_with_redaction(self) -> None:
        import contextlib
        import io
        import os
        import pathlib
        import tempfile
        import threading
        from unittest import mock
        import scripts.rubicon_mixed_workload as cli_mod
        from scripts.rubicon_workload.runner import WorkloadConfig, run_rubicon_workload

        with tempfile.TemporaryDirectory() as td:
            rep = pathlib.Path(td) / "out" / "report.json"
            fake_pre = {
                "binary": "/bin/true",
                "binary_sha256": "0" * 64,
                "binary_size_bytes": 1,
                "receipt_verified": False,
                "git": "/usr/bin/git",
                "git_version": "git version 2.43.0",
                "psql_version": "psql 17",
                "pg_base": "postgresql://u:topsecret@127.0.0.1/db",
                "s3_loopback_http": False,
                "s3_host": "127.0.0.1",
                "s3_port": 9000,
                "logical_cpus": 2,
                "tiers": [1],
                "tier_notes": [],
            }
            fake_env = {
                "ROOTYARD_TEST_DATABASE_URL": "postgresql://u:topsecret@127.0.0.1/db",
                "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "s3secretval",
                "ROOTYARD_BLOB_ACCESS_KEY_ID": "s3keyid",
                "ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:9000",
            }
            cfg = WorkloadConfig(binary="/bin/true", report=str(rep), git="/usr/bin/git", require_build_receipt=False)
            with mock.patch("scripts.rubicon_workload.runner._preflight", return_value=fake_pre), \
                 mock.patch.dict(os.environ, fake_env, clear=False), \
                 mock.patch("scripts.rubicon_workload.runner._verify_public_cluster_authority", side_effect=threading.BrokenBarrierError()):
                with self.assertRaises(RuntimeError) as ctx:
                    run_rubicon_workload(cfg)
            msg = str(ctx.exception)
            self.assertIn("BrokenBarrierError", msg)
            self.assertNotIn("topsecret", msg)
            self.assertTrue((rep.parent / "failure-diagnostics.log").is_file())

            stderr_buf = io.StringIO()
            with mock.patch("scripts.rubicon_mixed_workload.run_rubicon_workload", side_effect=TimeoutError()), \
                 contextlib.redirect_stderr(stderr_buf):
                rc = cli_mod.main(["--binary", "/bin/true", "--report", str(rep)])
            self.assertEqual(rc, 1)
            self.assertIn("rubicon-mixed-workload failed (TimeoutError): TimeoutError", stderr_buf.getvalue())

    def test_start_fleet_sets_concurrent_and_byte_budget_defaults(self) -> None:
        import inspect
        from scripts.rubicon_workload.runner import _start_fleet

        src = inspect.getsource(_start_fleet)
        self.assertIn("ROOTYARD_MAX_CONCURRENT_GIT", src)
        self.assertIn("ROOTYARD_MAX_REQUEST_BYTES", src)
        self.assertIn("ROOTYARD_MAX_INFLIGHT_BYTES", src)

    def test_run_rubicon_workload_switches_cli_to_external_schema_mode_after_migrate(self) -> None:
        import os
        import pathlib
        import tempfile
        from unittest import mock
        from scripts.rubicon_workload.runner import WorkloadConfig, run_rubicon_workload

        seen_cli_modes: list[tuple[str, str | None]] = []
        tier_modes: list[str | None] = []

        def fake_cli(_binary: str, env: dict[str, str], *args: str) -> str:
            seen_cli_modes.append((args[0], env.get("ROOTYARD_SCHEMA_MODE")))
            return "{}"

        def fake_tier(_n: int, _cfg: object, _pre: object, _benv: object, cli_env: dict[str, str], *_rest: object) -> dict[str, object]:
            tier_modes.append(cli_env.get("ROOTYARD_SCHEMA_MODE"))
            raise RuntimeError("stop-after-check")

        with tempfile.TemporaryDirectory() as td:
            rep = pathlib.Path(td) / "report.json"
            fake_pre = {
                "binary": "/bin/true",
                "binary_sha256": "0" * 64,
                "binary_size_bytes": 1,
                "receipt_verified": False,
                "git": "/usr/bin/git",
                "git_version": "git version 2.43.0",
                "psql_version": "psql 17",
                "pg_base": "postgresql://u:pw@127.0.0.1/db",
                "s3_loopback_http": False,
                "s3_host": "127.0.0.1",
                "s3_port": 9000,
                "logical_cpus": 2,
                "tiers": [1],
                "tier_notes": [],
            }
            fake_env = {
                "ROOTYARD_TEST_DATABASE_URL": "postgresql://u:pw@127.0.0.1/db",
                "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "s3secretval",
                "ROOTYARD_BLOB_ACCESS_KEY_ID": "s3keyid",
                "ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:9000",
                "ROOTYARD_SCHEMA_MODE": "external",
            }
            cfg = WorkloadConfig(binary="/bin/true", report=str(rep), git="/usr/bin/git", require_build_receipt=False)
            with mock.patch("scripts.rubicon_workload.runner._preflight", return_value=fake_pre), \
                 mock.patch.dict(os.environ, fake_env, clear=False), \
                 mock.patch("scripts.rubicon_workload.runner._verify_public_cluster_authority"), \
                 mock.patch("subprocess.run"), \
                 mock.patch("subprocess.check_output", return_value="17.0"), \
                 mock.patch("scripts.rubicon_workload.runner._cli", side_effect=fake_cli), \
                 mock.patch("scripts.rubicon_workload.runner._run_tier", side_effect=fake_tier):
                with self.assertRaisesRegex(RuntimeError, "stop-after-check"):
                    run_rubicon_workload(cfg)
        self.assertEqual(seen_cli_modes, [("migrate", "auto")])
        self.assertEqual(tier_modes, ["external"])

    def test_fault_phase_only_invokes_revoke_token_while_fleet_is_running(self) -> None:
        import inspect
        import pathlib
        import tempfile
        from unittest import mock
        from scripts.rubicon_workload.runner import _phase_fault_and_audit, _run_tier

        run_tier_src = inspect.getsource(_run_tier)
        self.assertLess(run_tier_src.index('"create-token"'), run_tier_src.index("_start_fleet"))

        seen_cli: list[tuple[str, ...]] = []

        def fake_cli(_binary: str, _env: dict[str, str], *args: str) -> str:
            seen_cli.append(args)
            return ""

        with tempfile.TemporaryDirectory() as td:
            wdir = pathlib.Path(td) / "work"
            wdir.mkdir()
            repos = {
                "fault_repo": {
                    "info": {"clone_path": "/git/u2/fault.git", "owner": "u2", "name": "fault"},
                    "work": wdir,
                    "rw": {"username": "u2", "token": "ryt_" + "c" * 64},
                    "ro": {"username": "u2", "token": "ryt_" + "d" * 64},
                }
            }
            records: list[dict[str, object]] = []
            with mock.patch("scripts.rubicon_workload.runner._cli", side_effect=fake_cli), \
                 mock.patch("scripts.rubicon_workload.runner.http_json", side_effect=[(200, b"{}", {}, 1.0), (401, b"{}", {}, 1.0)]), \
                 mock.patch("scripts.rubicon_workload.runner.materialize_commit_spec", return_value="a" * 40), \
                 mock.patch("scripts.rubicon_workload.runner.run_git", return_value=(mock.Mock(returncode=1, stdout=b"", stderr=b"denied"), 1.0)), \
                 mock.patch("scripts.rubicon_workload.runner.git_remote_refs", return_value=({}, 1.0)):
                fault_counts, audit = _phase_fault_and_audit(
                    {"binary": "/bin/true", "git": "/usr/bin/git"},
                    {},
                    {},
                    ["http://127.0.0.1:9999"],
                    pathlib.Path(td),
                    pathlib.Path(td) / "askpass.sh",
                    repos,
                    records,
                    [],
                    {"username": "u2", "token_id": "tok-123", "token": "ryt_" + "e" * 64},
                )
        self.assertEqual(seen_cli, [("revoke-token", "tok-123")])
        self.assertEqual(fault_counts["committed_success"], 0)
        self.assertEqual(audit["acked_targets_total"], 0)

    def test_upsert_acked_inserts_after_initial_miss_and_updates_without_duplicates(self) -> None:
        from scripts.rubicon_workload.runner import _upsert_acked

        acked: list[dict[str, object]] = []
        entry = {"info": {"owner": "u0", "name": "repo0", "clone_path": "/git/u0/repo0.git"}, "rw": {"username": "u0", "token": "tok"}}
        # Initial wave missed refs/heads/indep_0; timed wave retry succeeded -> must insert!
        _upsert_acked(acked, "text_history", entry, "refs/heads/indep_0", "1" * 40)
        self.assertEqual(len(acked), 1)
        self.assertEqual(acked[0]["expected_oid"], "1" * 40)

        # Subsequent wave updates existing entry without adding a duplicate.
        _upsert_acked(acked, "text_history", entry, "refs/heads/indep_0", "2" * 40)
        self.assertEqual(len(acked), 1)
        self.assertEqual(acked[0]["expected_oid"], "2" * 40)

    def test_load_receipt_binds_source_commit_and_verifies_source_files(self) -> None:
        import pathlib
        import sys
        import tempfile
        from unittest import mock
        from scripts.rubicon_workload.runner import _load_receipt_or_fail

        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "scripts").mkdir()
            bin_path = root / "rootyard"
            bin_path.write_bytes(b"ELF")
            receipt_path = root / "rootyard.build.json"
            receipt_path.write_text("{}", encoding="utf-8")

            fake_validated = mock.Mock(
                schema="v2",
                workspace_commit="a" * 40,
                receipt_sha256="b" * 64,
                config_digest="c" * 64,
                source_inputs_sha256="d" * 64,
            )
            fake_mod = mock.Mock()
            fake_mod.load_receipt.return_value = fake_validated
            with mock.patch.dict(sys.modules, {"native_build_receipt": fake_mod}):
                info = _load_receipt_or_fail(bin_path, root, True, "a" * 40)
            fake_mod.load_receipt.assert_called_once_with(
                receipt_path,
                source_root=root,
                binary_path=bin_path,
                expected_commit="a" * 40,
                verify_source_files=True,
            )
            self.assertEqual(info["workspace_commit"], "a" * 40)
            self.assertEqual(info["config_digest"], "c" * 64)
            self.assertEqual(info["source_inputs_sha256"], "d" * 64)

            fake_mod.load_receipt.side_effect = ValueError("build receipt: workspace_commit mismatch")
            with mock.patch.dict(sys.modules, {"native_build_receipt": fake_mod}):
                with self.assertRaisesRegex(ValueError, "workspace_commit"):
                    _load_receipt_or_fail(bin_path, root, True, "e" * 40)

    def test_validate_report_enforces_receipt_commit_and_config_digest(self) -> None:
        bad_commit = _valid_sample_report()
        bad_commit["binary"]["workspace_commit"] = "9" * 40
        with self.assertRaisesRegex(ValueError, "workspace_commit"):
            validate_report(bad_commit)

        missing_cfg = _valid_sample_report()
        missing_cfg["binary"]["config_digest"] = ""
        with self.assertRaisesRegex(ValueError, "config_digest"):
            validate_report(missing_cfg)

    def test_format_topology_handles_loopback_vs_external_https(self) -> None:
        from scripts.rubicon_workload.runner import _format_topology

        metered = _format_topology([1, 2], "http", True, True)
        self.assertIn("loopback HTTP S3 provider (metered via loopback proxy)", metered)
        ext = _format_topology([1, 2, 4], "https", False, False)
        self.assertIn("external HTTPS S3 provider (unmetered)", ext)
        self.assertNotIn("loopback HTTP", ext)

    def test_read_proc_metrics_counts_scratch_and_worktrees_without_double_counting(self) -> None:
        import pathlib
        import tempfile
        from scripts.rubicon_workload.workloads import read_proc_metrics

        with tempfile.TemporaryDirectory() as td:
            tier_dir = pathlib.Path(td)
            scratch0 = tier_dir / "scratches" / "scratch-0"
            work0 = tier_dir / "work-text"
            scratch0.mkdir(parents=True)
            work0.mkdir(parents=True)
            (scratch0 / "pack.bin").write_bytes(b"x" * 100)
            (work0 / "blob.bin").write_bytes(b"y" * 250)

            metrics = read_proc_metrics([], [scratch0], worktree_dirs=[tier_dir])
            self.assertEqual(metrics["server_scratch_bytes"], 100)
            self.assertEqual(metrics["client_worktree_bytes"], 250)
            self.assertEqual(metrics["temp_disk_bytes"], 350)

    def test_allocate_distinct_ports_and_start_fleet_log_diagnostics(self) -> None:
        import pathlib
        import tempfile
        from unittest import mock
        from scripts.rubicon_workload.runner import _allocate_distinct_ports, _start_fleet

        ports = _allocate_distinct_ports(4)
        self.assertEqual(len(ports), 4)
        self.assertEqual(len(set(ports)), 4)

        secret_tok = "ryt_" + "f" * 64
        with tempfile.TemporaryDirectory() as td:
            scratch = pathlib.Path(td)
            attempt_calls = {"n": 0}

            def fake_popen(_cmd: list[str], **_kwargs: object) -> mock.Mock:
                attempt_calls["n"] += 1
                stdout = _kwargs["stdout"]
                if attempt_calls["n"] == 1:
                    stdout.write(b"could not bind Blob service listener\n")
                else:
                    stdout.write(f"fatal startup failure {secret_tok}\n".encode("utf-8"))
                stdout.flush()
                proc = mock.Mock(pid=12345 + attempt_calls["n"], returncode=1)
                proc.poll.return_value = 1
                return proc

            def fake_stop(fleet: list[tuple[object, str, pathlib.Path, object]]) -> None:
                for _, _, _, fh in fleet:
                    fh.close()

            with mock.patch("subprocess.Popen", side_effect=fake_popen), \
                 mock.patch("scripts.rubicon_workload.runner._stop_fleet", side_effect=fake_stop):
                with self.assertRaises(RuntimeError) as ctx:
                    _start_fleet(1, "/bin/rootyard", {}, "/usr/bin/git", "postgresql://u@127.0.0.1/db", "http://127.0.0.1:9000", scratch)
            msg = str(ctx.exception)
            self.assertIn("fatal startup failure", msg)
            self.assertNotIn(secret_tok, msg)
            self.assertEqual(attempt_calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
