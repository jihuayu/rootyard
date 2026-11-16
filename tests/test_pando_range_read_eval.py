#!/usr/bin/env python3
"""Unit and structural contract tests for Issue #179 OID range-read evaluation."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.pando_range_eval import (
    FailClosedError,
    MultiPackIndex,
    PackIndex,
    RangeObjectServer,
    apply_git_delta,
    build_real_git_fixtures,
)
from scripts.pando_range_eval.benchmarks import run_adversarial_suite, run_evaluation
from scripts.pando_range_eval.clients import RangeReadClient
from scripts.pando_range_read_eval import render_markdown

ROOT = Path(__file__).resolve().parents[1]
OWNED_FILES = (
    ROOT / "scripts" / "pando_range_read_eval.py",
    ROOT / "scripts" / "pando_range_eval" / "__init__.py",
    ROOT / "scripts" / "pando_range_eval" / "benchmarks.py",
    ROOT / "scripts" / "pando_range_eval" / "clients.py",
    ROOT / "scripts" / "pando_range_eval" / "fixture_builder.py",
    ROOT / "scripts" / "pando_range_eval" / "git_pack_codec.py",
    ROOT / "scripts" / "pando_range_eval" / "range_server.py",
    ROOT / "tests" / "test_pando_range_read_eval.py",
    ROOT / "docs" / "pando-oid-range-read-research.md",
    ROOT / ".github" / "workflows" / "pando-range-read-eval.yml",
)


class TestPandoRangeReadEval(unittest.TestCase):
    def test_idx_and_midx_binary_parsing_and_corruption_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for algo in ("sha1", "sha256"):
                art = build_real_git_fixtures(root, algo, scale="quick")
                main_pack = next(n for n in sorted(art.pack_bytes) if not n.startswith("pack-thin-"))
                idx = PackIndex.parse(main_pack, art.idx_bytes[main_pack], len(art.pack_bytes[main_pack]), algo)
                self.assertGreater(len(idx.entries), 10)
                self.assertIsNotNone(art.midx_parsed)
                assert art.midx_parsed is not None
                for oid_hex in art.sparse_blob_oids:
                    self.assertIn(oid_hex, art.midx_parsed.mapping)

                # Corrupt .idx checksum -> fail closed
                bad_idx = bytearray(art.idx_bytes[main_pack])
                bad_idx[-1] ^= 0x55
                with self.assertRaises(FailClosedError) as ctx:
                    PackIndex.parse(main_pack, bytes(bad_idx), len(art.pack_bytes[main_pack]), algo)
                self.assertEqual(ctx.exception.code, "corrupt_checksum")

                # Corrupt MIDX checksum -> fail closed
                assert art.midx_bytes is not None
                bad_midx = bytearray(art.midx_bytes)
                bad_midx[-1] ^= 0xAA
                with self.assertRaises(FailClosedError) as mctx:
                    MultiPackIndex.parse(bytes(bad_midx), algo)
                self.assertEqual(mctx.exception.code, "corrupt_checksum")

    def test_delta_decoder_and_cross_pack_range_parity_with_stock_git(self) -> None:
        # Delta decoder exact reconstruction + tamper rejection
        base = b"hello world prefix bytes"
        # src_len=24, tgt_len=30, copy(0, 12), insert(6, 'delta '), copy(12, 12)
        delta = bytes([24, 30, 0x80 | 0x10, 12, 6]) + b"delta " + bytes([0x80 | 0x01 | 0x10, 12, 12])
        self.assertEqual(apply_git_delta(base, delta), b"hello world delta prefix bytes")
        with self.assertRaises(FailClosedError):
            apply_git_delta(base[:-1], delta)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for algo in ("sha1", "sha256"):
                art = build_real_git_fixtures(root, algo, scale="quick")
                self.assertGreater(len(art.cross_pack_delta_oids), 0)
                srv = RangeObjectServer(art).start()
                srv.add_grant("tok-alpha", art.tenant_id, art.repo_id)
                try:
                    cli = RangeReadClient(srv.base_url, art, "tok-alpha", root / f"cli_{algo}")
                    cli.load_indices(srv.pack_etags)
                    repo_dir = root / f"repo_{algo}"
                    for oid in art.cross_pack_delta_oids + [art.commit_oids[-1], art.tree_root_oid]:
                        otype, raw = cli.fetch_object(oid, verify_closure=(oid == art.commit_oids[-1]))
                        git_raw = subprocess.run(
                            ["git", "-C", str(repo_dir), "cat-file", otype, oid],
                            check=True,
                            capture_output=True,
                        ).stdout
                        self.assertEqual(raw, git_raw)
                        digest = hashlib.sha1(f"{otype} {len(raw)}\0".encode() + raw).hexdigest() if algo == "sha1" else hashlib.sha256(f"{otype} {len(raw)}\0".encode() + raw).hexdigest()
                        self.assertEqual(digest, oid)
                finally:
                    srv.stop()

    def test_adversarial_fail_closed_matrix_sha1_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for algo in ("sha1", "sha256"):
                art = build_real_git_fixtures(root, algo, scale="quick")
                cases = run_adversarial_suite(root, art)
                self.assertEqual(len(cases), 12)
                self.assertTrue(all(c["status"] == "fail_closed_ok" for c in cases))
                codes = {c["observed_code"] for c in cases}
                self.assertTrue(
                    {"truncated_range", "corrupt_checksum", "object_identity_mismatch", "unauthorized", "history_drift", "membership_drift", "pin_evicted"}.issubset(codes)
                )

    def test_quick_evaluation_report_and_markdown_rendering(self) -> None:
        report = run_evaluation(scale="quick", simulated_rtt_ms=0.0)
        self.assertEqual(report["issue"], 179)
        self.assertIn("sha1", report["fixtures"])
        self.assertIn("sha256", report["fixtures"])
        self.assertGreaterEqual(len(report["benchmarks"]), 16)
        for row in report["benchmarks"]:
            self.assertLessEqual(row["p50_ms"], row["p95_ms"])
            self.assertLessEqual(row["p95_ms"], row["p99_ms"])
            self.assertGreater(row["total_gets"], 0)
            self.assertGreater(row["bytes_downloaded"], 0)
            self.assertGreaterEqual(row["scratch_disk_bytes"], 0)
        md = render_markdown(report)
        self.assertIn("Workload Comparison", md)
        self.assertIn("Adversarial Fail-Closed Experiments", md)

    def test_file_line_caps_lf_and_research_doc_contracts(self) -> None:
        for path in OWNED_FILES:
            raw = path.read_bytes()
            self.assertNotIn(b"\r\n", raw, f"{path} must use pure LF")
            lines = raw.decode("utf-8").splitlines()
            self.assertLess(len(lines), 500, f"{path} exceeded 500L ({len(lines)}L)")

        wf = (ROOT / ".github" / "workflows" / "pando-range-read-eval.yml").read_text(encoding="utf-8")
        self.assertTrue(wf.startswith("name: "))
        self.assertNotIn("\t", wf)
        self.assertNotIn("\n  push:\n", wf)
        self.assertIn("workflow_dispatch:", wf)
        self.assertIn("owned_garage_fixture.sh start", wf)

        doc = (ROOT / "docs" / "pando-oid-range-read-research.md").read_text(encoding="utf-8")
        for required in ("#163", "#164", "#162", "#122", "#151", "#153", "SHA-1", "SHA-256", "MIDX"):
            self.assertIn(required, doc, f"research doc missing {required}")


if __name__ == "__main__":
    unittest.main()
