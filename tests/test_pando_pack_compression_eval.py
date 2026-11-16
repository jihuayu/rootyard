#!/usr/bin/env python3
"""Unit, stock-Git parity/safety, metering proxy, and CI workflow tests for Issue #178."""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval.corpus import (  # noqa: E402
    DATASET_ARCHETYPES,
    build_archetype_commits,
    isolated_git_env,
    resolve_trusted_git,
    seed_multi_push_bare_repo,
)
from pack_compression_eval.correctness import run_correctness_suite  # noqa: E402
from pack_compression_eval.live_server import resolve_live_env  # noqa: E402
from pack_compression_eval.pack_matrix import CANDIDATE_CONFIGS, evaluate_repo_pack_matrix  # noqa: E402
from pack_compression_eval.report import redact_text, validate_report  # noqa: E402
from pack_compression_eval.s3_meter import S3MeterProxy  # noqa: E402
from pack_compression_eval.telemetry import percentile_stats  # noqa: E402


class PackCompressionEvalTests(unittest.TestCase):
    def test_corpus_determinism_and_six_archetypes(self) -> None:
        self.assertEqual(
            DATASET_ARCHETYPES,
            ("compressed_media", "large_binary", "text_history", "small_deltas", "similar_files", "multi_repo"),
        )
        for arch in DATASET_ARCHETYPES:
            s1, w1, b1 = build_archetype_commits(arch, seed=42, scale="quick")
            s2, w2, b2 = build_archetype_commits(arch, seed=42, scale="quick")
            s3, w3, _ = build_archetype_commits(arch, seed=99, scale="quick")
            self.assertEqual(s1, s2)
            self.assertEqual(w1, w2)
            self.assertEqual(b1, b2)
            self.assertGreaterEqual(len(w1), 2)
            self.assertNotEqual((s1, w1), (s3, w3))
            for commit in [*s1, *(c for batch in w1 for c in batch)]:
                self.assertTrue(commit.files)
                for content in commit.files.values():
                    self.assertIsInstance(content, bytes)

    def test_real_git_pack_matrix_recompute_and_sha1_sha256_correctness(self) -> None:
        git_bin = resolve_trusted_git(None)
        env = isolated_git_env(os.environ)
        selected = tuple(s for s in CANDIDATE_CONFIGS if s.name in ("rootyard_default", "zlib_store_c0", "wide_window_c6_w50_t2"))
        with tempfile.TemporaryDirectory(prefix="pack-eval-unit-") as tmp:
            troot = Path(tmp)
            seeded = seed_multi_push_bare_repo(
                git_bin, "similar_files", seed=178, scale="quick", root_dir=troot / "sim", env=env, object_format="sha1"
            )
            res = evaluate_repo_pack_matrix(git_bin, seeded, selected, troot / "matrix", env, clone_runs=1)
            by_name = {c["config"]["name"]: c for c in res["candidates"]}
            self.assertLess(
                by_name["wide_window_c6_w50_t2"]["compacted_pack_idx_bytes"],
                by_name["zlib_store_c0"]["compacted_pack_idx_bytes"],
                "recomputed compressed/wide pack must beat c=0 uncompressed store on compressible similar files",
            )
            for c in res["candidates"]:
                self.assertTrue(c["objects_exact_match"])
                self.assertEqual(
                    c["coexisting_non_gc_bytes"],
                    res["pre_compaction"]["pack_idx_total_bytes"] + c["compacted_pack_idx_bytes"],
                )
            corr = run_correctness_suite(git_bin, seed=178, scale="quick", work_root=troot / "corr", env=env, configs=selected)
            self.assertTrue(corr["passed"])
            for fmt in ("sha1", "sha256"):
                self.assertTrue(corr["formats"][fmt]["passed"])
                safe = corr["formats"][fmt]["safety_and_failure_checks"]
                self.assertTrue(safe["cancel_mid_repack_preserves_serving_pack"])
                self.assertTrue(safe["truncated_pack_refused"])
                self.assertTrue(safe["missing_idx_refused"])
                self.assertTrue(safe["invalid_depth_refused"])

    def test_s3_meter_proxy_preserves_host_and_counts_bytes(self) -> None:
        observed_hosts: list[str] = []

        class StubS3(http.server.BaseHTTPRequestHandler):
            def do_PUT(self) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(n)
                observed_hosts.append(self.headers.get("Host", ""))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                observed_hosts.append(self.headers.get("Host", ""))
                payload = b"packed-object-bytes"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt: str, *args: object) -> None:
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StubS3)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        proxy = S3MeterProxy("127.0.0.1", srv.server_address[1])
        proxy.start()
        try:
            body = b"hello-s3-pack-payload"
            req_put = urllib.request.Request(proxy.endpoint + "/bucket/pack-1", data=body, method="PUT")
            with urllib.request.urlopen(req_put, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
            with urllib.request.urlopen(proxy.endpoint + "/bucket/pack-1", timeout=5) as resp:
                self.assertEqual(resp.read(), b"packed-object-bytes")
            snap = proxy.snapshot()
            self.assertEqual(snap["put_requests"], 1)
            self.assertEqual(snap["put_bytes"], len(body))
            self.assertEqual(snap["get_requests"], 1)
            self.assertEqual(snap["get_bytes"], len(b"packed-object-bytes"))
            self.assertEqual(observed_hosts[0], f"127.0.0.1:{proxy.port}")
        finally:
            proxy.stop()
            srv.shutdown()
            srv.server_close()

    def test_percentiles_redaction_and_fail_closed_guards(self) -> None:
        stats = percentile_stats([10.0, 20.0, 30.0, 40.0, 100.0])
        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["p50_ms"], 30.0)
        self.assertEqual(stats["p95_ms"], 100.0)

        scrubbed = redact_text("Bearer ryt_0123456789abcdef0123 postgresql://u:pw@127.0.0.1:5432/db", ["pw"])
        self.assertNotIn("ryt_012345", scrubbed)
        self.assertNotIn(":pw@", scrubbed)

        with self.assertRaises(RuntimeError):
            resolve_live_env({})

        fake_cand = {
            "config": CANDIDATE_CONFIGS[0].to_dict(),
            "compacted_pack_idx_bytes": 100,
            "coexisting_non_gc_bytes": 200,
            "objects_exact_match": True,
        }
        fake_report = {
            "schema_version": "rootyard/pando-pack-compression-eval/v1",
            "issue": "#178",
            "simulated": False,
            "mode": "full",
            "seed": 1,
            "environment": {"git_version": "git 2.45"},
            "pack_matrix": [
                {"archetype": a, "pre_compaction": {"pack_count": 2}, "candidates": [fake_cand]} for a in DATASET_ARCHETYPES
            ],
            "correctness": {"passed": True, "formats": {"sha1": {"passed": True}, "sha256": {"passed": True}}},
            "e2e_serve_blob": None,
        }
        with self.assertRaises(ValueError):
            validate_report(fake_report)
        fake_report["e2e_serve_blob"] = {
            "executed": True,
            "physical_savings_claimed": True,
            "concurrent_push_and_browse": {"acked_verified": 1, "acked_total": 1},
        }
        with self.assertRaises(ValueError):
            validate_report(fake_report)

    def test_module_sizes_pure_lf_and_workflow_contracts(self) -> None:
        files = [
            ROOT / "scripts" / "pando_pack_compression_eval.py",
            *(ROOT / "scripts" / "pack_compression_eval").glob("*.py"),
            ROOT / "tests" / "test_pando_pack_compression_eval.py",
            ROOT / "docs" / "pando-pack-compression-eval.md",
            ROOT / ".github" / "workflows" / "pando-pack-compression-eval.yml",
        ]
        for path in files:
            self.assertTrue(path.is_file(), f"Missing {path}")
            raw = path.read_bytes()
            self.assertNotIn(b"\r", raw, f"CR byte found in {path}")
            line_count = len(raw.decode("utf-8").splitlines())
            self.assertLess(line_count, 500, f"{path} exceeds 500 lines ({line_count})")

        wf_text = (ROOT / ".github" / "workflows" / "pando-pack-compression-eval.yml").read_text(encoding="utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        self.assertNotIn("\n  push:", wf_text)
        for required in (
            "pull_request:",
            "workflow_dispatch:",
            "postgres:17",
            "scripts/owned_garage_fixture.sh start",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "1.101.0",
            "1.99.1",
            "scripts/build_native.py",
            "scripts/pando_pack_compression_eval.py",
            "--mode full",
            "scripts/check_design_docs.py",
        ):
            self.assertIn(required, wf_text, f"workflow missing {required}")


if __name__ == "__main__":
    unittest.main()
