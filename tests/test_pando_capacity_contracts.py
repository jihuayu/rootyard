#!/usr/bin/env python3
"""Offline structural, policy, benchmark, and CI workflow contracts for Issue #177."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
CAP_DIR = ROOT / "src" / "blob_store" / "capacity_contract"
RUST_FILES = [
    ROOT / "src" / "blob_store" / "capacity_contract.rs",
    *sorted(CAP_DIR.glob("*.rs")),
    ROOT / "tests" / "pando_capacity_contract.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "pando-capacity-contract.yml"
DOC = ROOT / "docs" / "pando-capacity-contract.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_pando_capacity.py"


class PandoCapacityContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        facade = ROOT / "src" / "blob_store.rs"
        facade_text = facade.read_text(encoding="utf-8")
        self.assertIn("pub mod capacity_contract;", facade_text)
        self.assertLess(len(facade_text.splitlines()), 100)
        self.assertFalse(list((ROOT / "src" / "blob_store").rglob("mod.rs")))

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (must stay < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")
                for match in re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)",
                    text,
                ):
                    self.assertIn("deny_unknown_fields", match.group(0), f"{match.group(1)} missing deny_unknown_fields")

    def test_contract_separates_layers_and_protects_retained_ledger(self) -> None:
        limits_src = (CAP_DIR / "limits.rs").read_text(encoding="utf-8")
        for token in (
            "LEDGER_REPO_MAX_LOGICAL_BYTES: i64 = 8 * MIB as i64",
            "LEDGER_REPO_MAX_ACTIVE_MEMBERSHIPS: usize = 16",
            "VERIFIER_WINDOW_MAX_TOTAL_BYTES: u64 = 64 * MIB",
            "VERIFIER_WINDOW_MAX_OBJECTS: u64 = 16_384",
            "VERIFIER_VIEW_MAX_LOGICAL_BYTES: u64 = 160 * MIB",
            "delete_during_compaction_enabled: false",
        ):
            self.assertIn(token, limits_src)

        ledger_src = (CAP_DIR / "ledger_retention.rs").read_text(encoding="utf-8")
        self.assertIn("CompactionDoesNotAuthorizeDelete", ledger_src)
        self.assertIn("ProtectedByHold", ledger_src)
        self.assertIn("ReleasedEligibleForArchive", ledger_src)

    def test_workflow_contract_and_doc_links(self) -> None:
        raw_wf = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", raw_wf)
        wf_text = raw_wf.decode("utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        if yaml is not None:
            doc = yaml.safe_load(wf_text)
            on_cfg = doc.get("on") if "on" in doc else doc.get(True)
            self.assertIsInstance(on_cfg, dict)
            self.assertIn("pull_request", on_cfg)
            self.assertIn("workflow_dispatch", on_cfg)
            self.assertNotIn("push", on_cfg)
            paths = on_cfg["pull_request"]["paths"]
            for required in (
                "src/blob_store/capacity_contract.rs",
                "src/blob_store/capacity_contract/**",
                "tests/pando_capacity_contract.rs",
                "scripts/eval_pando_capacity.py",
                "docs/pando-capacity-contract.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib blob_store::capacity_contract",
            "cargo test --locked --no-default-features --test pando_capacity_contract",
            "scripts/eval_pando_capacity.py",
        ):
            self.assertIn(token, wf_text)

        raw_doc = DOC.read_bytes()
        self.assertNotIn(b"\r\n", raw_doc)
        doc_text = raw_doc.decode("utf-8")
        self.assertLess(len(doc_text.splitlines()), 500)
        for token in ("#177", "#162", "#164", "CurrentCodeFact", "EnforcedBoundedEngine", "MeasuredBenchmarkBaseline"):
            self.assertIn(token, doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution_beyond_16_packs(self) -> None:
        eval_raw = EVAL_SCRIPT.read_bytes()
        self.assertNotIn(b"\r\n", eval_raw)
        eval_text = eval_raw.decode("utf-8")
        self.assertLess(len(eval_text.splitlines()), 500)
        self.assertIn("validate_receipt", eval_text)
        self.assertNotIn("verify_receipt", eval_text)

        spec = importlib.util.spec_from_file_location("eval_pando_capacity", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark([18], ["sha1"], compact_trigger=10, max_workers=2, max_queue=8)
        self.assertEqual(report["issue"], 177)
        self.assertEqual(report["target_calibration_issue"], 164)
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertTrue(row["closure_verified"])
        self.assertGreater(row["target_packs"], 16)
        self.assertGreaterEqual(row["compactions_completed"], 1)
        self.assertLessEqual(row["active_frontier_final"], 16)
        self.assertGreater(row["no_new_pack_updates"], 0)
        self.assertGreater(row["blob_bytes"]["retained_old_pack_bytes"], 0)
        self.assertGreater(row["peak_scratch_disk_bytes"], 0)
        self.assertGreater(row["peak_rss_kib"], 0)


if __name__ == "__main__":
    unittest.main()
