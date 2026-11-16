#!/usr/bin/env python3
"""Offline structural contracts for the Issue #151 PG <-> Ref-CAS retention bridge."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_HOLD_DIR = ROOT / "src" / "ref_store" / "core" / "artifact_hold"
BRIDGE_MODULES = (
    "bridge_contract.rs",
    "retention_bridge.rs",
    "retirement_reconcile.rs",
    "bridge_tests.rs",
)
WORKFLOW = ROOT / ".github" / "workflows" / "retention-bridge.yml"
DOC = ROOT / "docs" / "refcas-retention-bridge.md"
PG_TEST = ROOT / "tests" / "ref_store_retention_bridge.rs"


class TestRetentionBridgeContracts(unittest.TestCase):
    def test_module_size_caps_and_zero_allow_attributes(self) -> None:
        mod_lines = (ARTIFACT_HOLD_DIR / "mod.rs").read_text(encoding="utf-8").splitlines()
        self.assertLess(len(mod_lines), 100, f"mod.rs exceeded 100L cap ({len(mod_lines)}L)")

        for name in BRIDGE_MODULES:
            path = ARTIFACT_HOLD_DIR / name
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            self.assertLess(len(lines), 500, f"{name} exceeded 500L cap ({len(lines)}L)")
            self.assertNotIn("#[allow(", text, f"{name} must not suppress clippy/rustc warnings")

        pg_test_text = PG_TEST.read_text(encoding="utf-8")
        self.assertNotIn("#[allow(", pg_test_text, "PG integration test must not use #[allow(")

    def test_strict_serde_deny_unknown_fields_on_bridge_dtos(self) -> None:
        struct_re = re.compile(
            r"(#\[derive\([^\]]*Deserialize[^\]]*\)\]\s*)(#\[serde\([^\]]*\)\]\s*)?pub struct\s+([A-Za-z0-9_]+)"
        )
        for name in ("bridge_contract.rs", "retention_bridge.rs", "retirement_reconcile.rs"):
            text = (ARTIFACT_HOLD_DIR / name).read_text(encoding="utf-8")
            for match in struct_re.finditer(text):
                serde_attr = match.group(2) or ""
                struct_name = match.group(3)
                self.assertIn(
                    "deny_unknown_fields",
                    serde_attr,
                    f"{name}:{struct_name} missing #[serde(deny_unknown_fields)]",
                )

    def test_pure_determinism_and_no_ledger_mutation(self) -> None:
        contract_text = (ARTIFACT_HOLD_DIR / "bridge_contract.rs").read_text(encoding="utf-8")
        for forbidden in ("tokio_postgres", "deadpool_postgres", "BlobStore", "reqwest"):
            self.assertNotIn(forbidden, contract_text)

        sm_dir = ROOT / "src" / "ref_store" / "core" / "state_machine"
        for rs_file in sm_dir.glob("*.rs"):
            sm_text = rs_file.read_text(encoding="utf-8")
            for forbidden in ("tokio_postgres", "deadpool_postgres", "BlobStore", "opendal"):
                self.assertNotIn(forbidden, sm_text, f"{rs_file.name} must keep zero PG/Blob I/O")

        for name in ("retention_bridge.rs", "retirement_reconcile.rs"):
            text = (ARTIFACT_HOLD_DIR / name).read_text(encoding="utf-8").upper()
            for table in ("ARTIFACT_HOLDS", "ARTIFACT_HOLD_REQUESTS", "ARTIFACT_HOLD_CONSUME_RECEIPTS"):
                self.assertNotIn(f"UPDATE {table}", text)
                self.assertNotIn(f"DELETE FROM {table}", text)

    def test_workflow_and_documentation_contracts(self) -> None:
        raw = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", raw, "retention-bridge.yml must use pure LF")
        self.assertNotIn(b"\t", raw, "retention-bridge.yml must not contain tabs")
        yml = raw.decode("utf-8")
        for expected in (
            "postgres:17",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "1.101.0",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo fmt --all -- --check",
            "cargo clippy --locked --all-targets -- -D warnings",
            "cargo test --locked --lib ref_store::core::artifact_hold",
            "cargo test --locked --test ref_store_retention_bridge -- --ignored --test-threads=1",
        ):
            self.assertIn(expected, yml)

        doc_raw = DOC.read_bytes()
        self.assertNotIn(b"\r\n", doc_raw, "docs/refcas-retention-bridge.md must use pure LF")
        doc = doc_raw.decode("utf-8")
        for needle in (
            "bridge_contract.rs",
            "retention_bridge.rs",
            "retirement_reconcile.rs",
            "ref_cas_projection_cursors",
            "artifact_holds",
        ):
            self.assertIn(needle, doc)


if __name__ == "__main__":
    unittest.main()
