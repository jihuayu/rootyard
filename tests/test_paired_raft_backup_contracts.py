#!/usr/bin/env python3
"""Offline structural, protocol, evaluator, and CI workflow contracts for Issue #153."""
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
MOD_DIR = ROOT / "src" / "maintenance" / "paired_raft_backup"
RUST_FILES = [
    ROOT / "src" / "maintenance" / "paired_raft_backup.rs",
    *sorted(MOD_DIR.glob("*.rs")),
    ROOT / "tests" / "paired_raft_backup_restore.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "paired-raft-backup.yml"
DOC = ROOT / "docs" / "paired-raft-backup-restore.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_paired_raft_backup.py"


class PairedRaftBackupContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        facade = ROOT / "src" / "maintenance.rs"
        facade_raw = facade.read_bytes()
        self.assertNotIn(b"\r\n", facade_raw)
        facade_text = facade_raw.decode("utf-8")
        self.assertLess(len(facade_text.splitlines()), 500)
        self.assertIn("pub mod paired_raft_backup;", facade_text)
        self.assertNotIn('#[path = "maintenance/paired_raft_backup.rs"]', facade_text)
        self.assertFalse(list((ROOT / "src" / "maintenance").rglob("mod.rs")))

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

    def test_paired_protocol_enforces_freeze_close_incarnation_and_s3_connection_close(self) -> None:
        types_src = (MOD_DIR / "types.rs").read_text(encoding="utf-8")
        for token in (
            "IncompleteCut",
            "FreezeNotHeld",
            "ScopeNotClosed",
            "UnknownInFlightOperations",
            "DeleterNotFenced",
            "CutpointSkew",
            "TenantOrRepoMismatch",
            "BlobClosureIncomplete",
            "CorruptBlobOrDigest",
            "BackendIdentityMismatch",
            "StaleIncarnation",
            "StaleGrantRefused",
            "StaleDecisionRefused",
            "StaleDeleterRefused",
        ):
            self.assertIn(token, types_src)

        freeze_src = (MOD_DIR / "freeze_drain.rs").read_text(encoding="utf-8")
        for token in (
            "CloseAuthScope",
            "CreateSnapshotPin",
            "AcquireHoldBatch",
            "RegisterRoot",
            "unfreeze_after_backup",
        ):
            self.assertIn(token, freeze_src)

        backup_src = (MOD_DIR / "backup.rs").read_text(encoding="utf-8")
        self.assertIn("IsolationLevel::RepeatableRead", backup_src)

        pg_src = (MOD_DIR / "pg_cutpoint.rs").read_text(encoding="utf-8")
        for token in (
            "capture_pg_cutpoint_in_tx",
            "pando_storage_authorities",
            "pando_retention_roots",
            "ref_cas_projection_cursors",
            "ref_store_serving_repositories",
        ):
            self.assertIn(token, pg_src)

        it_src = (ROOT / "tests" / "paired_raft_backup_restore.rs").read_text(encoding="utf-8")
        self.assertIn("RETRY_MAX_TIMES=3", it_src)
        self.assertIn("header::CONNECTION", it_src)
        self.assertIn('"close"', it_src)

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
                "src/maintenance.rs",
                "src/maintenance/paired_raft_backup.rs",
                "src/maintenance/paired_raft_backup/**",
                "tests/paired_raft_backup_restore.rs",
                "scripts/eval_paired_raft_backup.py",
                "docs/paired-raft-backup-restore.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "postgres:17",
            "cargo test --locked --no-default-features --lib maintenance::paired_raft_backup",
            "cargo test --locked --no-default-features --test paired_raft_backup_restore",
            "--ignored",
            "scripts/eval_paired_raft_backup.py",
        ):
            self.assertIn(token, wf_text)

        raw_doc = DOC.read_bytes()
        self.assertNotIn(b"\r\n", raw_doc)
        doc_text = raw_doc.decode("utf-8")
        self.assertLess(len(doc_text.splitlines()), 500)
        for token in ("#153", "CurrentCodeFact", "EnforcedRestoreProtocol", "MeasuredEvalBaseline"):
            self.assertIn(token, doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution(self) -> None:
        eval_raw = EVAL_SCRIPT.read_bytes()
        self.assertNotIn(b"\r\n", eval_raw)
        eval_text = eval_raw.decode("utf-8")
        self.assertLess(len(eval_text.splitlines()), 500)
        self.assertIn("validate_receipt", eval_text)
        self.assertNotIn("verify_receipt", eval_text)

        spec = importlib.util.spec_from_file_location("eval_paired_raft_backup", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_evaluation([4], ["sha1"])
        self.assertEqual(report["issue"], 153)
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertEqual(row["pack_count"], 4)
        self.assertEqual(row["closure_artifacts"], 8)
        self.assertEqual(row["negative_faults_rejected"], 1)
        self.assertEqual(row["git_verified_refs"], 1)
        self.assertTrue(row["new_incarnation_minted"])


if __name__ == "__main__":
    unittest.main()
