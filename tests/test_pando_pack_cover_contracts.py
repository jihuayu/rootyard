#!/usr/bin/env python3
"""Contract and benchmark smoke tests for Issue #184 (Pando pack-cover planner)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACK_COVER_DIR = ROOT / "src" / "ref_store" / "core" / "ref_version" / "pack_cover"

OWNED_RUST_FILES = [
    ROOT / "src" / "ref_store" / "core" / "ref_version" / "pack_cover.rs",
    PACK_COVER_DIR / "auth.rs",
    PACK_COVER_DIR / "blob_verify.rs",
    PACK_COVER_DIR / "model.rs",
    PACK_COVER_DIR / "model_codec.rs",
    PACK_COVER_DIR / "planner.rs",
    PACK_COVER_DIR / "planner_select.rs",
    PACK_COVER_DIR / "retention_class.rs",
    PACK_COVER_DIR / "tests.rs",
    PACK_COVER_DIR / "tests_diamond.rs",
    PACK_COVER_DIR / "tests_git_blob.rs",
    PACK_COVER_DIR / "tests_matrix.rs",
    PACK_COVER_DIR / "tests_safety.rs",
    PACK_COVER_DIR / "verifier.rs",
    ROOT / "tests" / "pando_pack_cover.rs",
]

OWNED_TEXT_FILES = [
    *OWNED_RUST_FILES,
    ROOT / "scripts" / "eval_pando_pack_cover.py",
    ROOT / "docs" / "pando-pack-cover.md",
    ROOT / ".github" / "workflows" / "pando-pack-cover.yml",
    ROOT / "tests" / "test_pando_pack_cover_contracts.py",
]

EXPECTED_TOPOLOGIES = (
    "empty_clone",
    "small_incremental",
    "deep_lag",
    "criss_cross_merge",
    "multi_ref",
    "historical_pin",
    "non_fast_forward",
)


class PandoPackCoverContractTests(unittest.TestCase):
    def test_owned_files_line_limits_lf_and_hygiene(self) -> None:
        self.assertFalse((PACK_COVER_DIR / "mod.rs").exists(), "mod.rs inside pack_cover/ is forbidden")
        for path in OWNED_TEXT_FILES:
            self.assertTrue(path.is_file(), f"missing owned file: {path}")
            raw = path.read_bytes()
            self.assertNotIn(b"\r", raw, f"CR byte found in {path}")
            lines = raw.decode("utf-8").splitlines()
            self.assertLess(len(lines), 500, f"{path} exceeds 500 lines ({len(lines)})")
        for rs in OWNED_RUST_FILES:
            txt = rs.read_text(encoding="utf-8")
            self.assertNotIn("#[allow(", txt, f"#[allow( forbidden in {rs}")

    def test_ref_version_mod_export_and_unforgeable_proof(self) -> None:
        mod_rs = (ROOT / "src" / "ref_store" / "core" / "ref_version" / "mod.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod pack_cover;", mod_rs)

        verifier_rs = (PACK_COVER_DIR / "verifier.rs").read_text(encoding="utf-8")
        m = re.search(r"#\[derive\(([^)]*)\)\]\s*pub struct VerifiedFetchPlanProof", verifier_rs)
        self.assertIsNotNone(m, "missing VerifiedFetchPlanProof derive attribute")
        derives = m.group(1) if m else ""
        self.assertNotIn("Clone", derives)
        self.assertNotIn("Deserialize", derives)

    def test_workflow_structure_and_pinning(self) -> None:
        wf = ROOT / ".github" / "workflows" / "pando-pack-cover.yml"
        raw = wf.read_text(encoding="utf-8")
        self.assertTrue(raw.startswith("name: "), "workflow must start with name:")
        self.assertNotIn("\t", raw, "workflow must not contain tab characters")
        for token in (
            "workflow_dispatch:",
            "pull_request:",
            "paths:",
            "1.99.1",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            'RUSTFLAGS="-D warnings"',
            "actions/upload-artifact@v4",
            "tests/test_pando_pack_cover_contracts.py",
        ):
            self.assertIn(token, raw, f"missing workflow token: {token}")

    def test_design_doc_contracts_and_non_claims(self) -> None:
        doc = (ROOT / "docs" / "pando-pack-cover.md").read_text(encoding="utf-8")
        for token in (
            "PhysicallyPresent",
            "PlannableForFetch",
            "GcEligible",
            "TtlExpired",
            "CacheEvicted",
            "AsyncProjectionLag",
            "StrongSnapshot",
            "#122/#151/#153",
            "ry-pack-cover-record-v1",
        ):
            self.assertIn(token, doc, f"missing design doc token: {token}")

    def test_eval_script_sha1_sha256_all_topologies_and_parity(self) -> None:
        script = ROOT / "scripts" / "eval_pando_pack_cover.py"
        with tempfile.TemporaryDirectory() as td:
            out_json = Path(td) / "eval.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--profiles",
                    "small",
                    "--formats",
                    "sha1,sha256",
                    "--trials",
                    "5",
                    "--out-json",
                    str(out_json),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"eval failed:\n{proc.stderr}\n{proc.stdout}")
            report = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(report["issue"], 184)
            runs_by_fmt = {r["object_format"]: r for r in report["runs"]}
            self.assertEqual(set(runs_by_fmt.keys()), {"sha1", "sha256"})

            for fmt, run in runs_by_fmt.items():
                self.assertGreater(run["write_amplification"], 0.0, fmt)
                phys = run["old_new_pack_physical_bytes"]
                self.assertTrue(phys["physical_savings_require_gc"], fmt)
                self.assertGreaterEqual(phys["total_physical_bytes"], phys["serving_pack_bytes"], fmt)
                self.assertGreater(phys["retained_old_pack_bytes"], 0, fmt)
                topos = run["topologies"]
                self.assertEqual(set(topos.keys()), set(EXPECTED_TOPOLOGIES), fmt)
                for name in EXPECTED_TOPOLOGIES:
                    item = topos[name]
                    plan = item["causal_tiered_cover"]
                    base = item["baseline_full_materialization"]
                    self.assertEqual(plan["git_fsck_parity"], "pass", f"{fmt}/{name}")
                    self.assertGreater(plan["selected_packs"], 0, f"{fmt}/{name}")
                    self.assertGreater(base["selected_packs"], 0, f"{fmt}/{name}")
                    self.assertGreater(plan["transferred_bytes"], 0, f"{fmt}/{name}")
                    self.assertGreater(plan["metadata_reads"], 0, f"{fmt}/{name}")
                    cpu = plan["plan_cpu_p50_p95_p99"]
                    self.assertLessEqual(cpu["p50_ms"], cpu["p95_ms"], f"{fmt}/{name}")
                    self.assertLessEqual(cpu["p95_ms"], cpu["p99_ms"], f"{fmt}/{name}")


if __name__ == "__main__":
    unittest.main()
