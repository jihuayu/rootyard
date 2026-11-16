#!/usr/bin/env python3
"""Offline structural, modularity, workflow, and documentation contracts for Issue #152."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECTOR_ENTRY = ROOT / "src/ref_store/projector.rs"
PROJECTOR_DIR = ROOT / "src/ref_store/projector"
SM_ENTRY = ROOT / "src/ref_store/core/state_machine.rs"
SM_DIR = ROOT / "src/ref_store/core/state_machine"
NEW_PROJECTOR_SUBS = ("remote_authz_bridge.rs", "remote_authz_grant.rs", "remote_authz_pg.rs")
TOUCHED_SM_SUBS = ("apply_scopes.rs", "commands.rs", "state.rs", "snapshot.rs", "response.rs", "machine.rs", "apply_decisions.rs")
TEST_SUPPORT_ENTRY = ROOT / "tests/remote_authz_support.rs"
TEST_SUPPORT_SUBS = ("cluster.rs", "e2e.rs", "fixtures.rs", "pg.rs")
TEST_RS = ROOT / "tests/ref_store_remote_authz_bridge.rs"
WORKFLOW = ROOT / ".github/workflows/refcas-remote-authz.yml"
DOC = ROOT / "docs/refcas-remote-authz-bridge.md"


class RemoteAuthzBridgeContractTest(unittest.TestCase):
    def test_module_boundaries_and_line_limits(self) -> None:
        self.assertFalse((PROJECTOR_DIR / "mod.rs").exists(), "Forbidden projector/mod.rs")
        self.assertFalse((SM_DIR / "mod.rs").exists(), "Forbidden state_machine/mod.rs")
        self.assertFalse((ROOT / "tests/remote_authz_support/mod.rs").exists(), "Forbidden remote_authz_support/mod.rs")

        for entry in (PROJECTOR_ENTRY, SM_ENTRY, TEST_SUPPORT_ENTRY):
            self.assertTrue(entry.is_file(), f"Missing {entry}")
            txt = entry.read_text(encoding="utf-8")
            self.assertLess(len(txt.splitlines()), 100, f"Entry exceeds 100 lines: {entry}")
            self.assertNotIn("#[allow(", txt)
            self.assertNotIn("Command::new", txt)
            self.assertNotRegex(txt, r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b")

        all_subs = (
            [PROJECTOR_DIR / s for s in NEW_PROJECTOR_SUBS]
            + [SM_DIR / s for s in TOUCHED_SM_SUBS]
            + [ROOT / "tests/remote_authz_support" / s for s in TEST_SUPPORT_SUBS]
            + [TEST_RS]
        )
        for path in all_subs:
            self.assertTrue(path.is_file(), f"Missing {path}")
            txt = path.read_text(encoding="utf-8")
            self.assertLess(len(txt.splitlines()), 500, f"File exceeds 500 lines: {path}")

        strict_new = (
            [PROJECTOR_DIR / s for s in NEW_PROJECTOR_SUBS]
            + [SM_DIR / "apply_scopes.rs"]
            + [ROOT / "tests/remote_authz_support" / s for s in TEST_SUPPORT_SUBS]
            + [TEST_RS]
        )
        for path in strict_new:
            txt = path.read_text(encoding="utf-8")
            self.assertNotIn("#[allow(", txt, f"Forbidden #[allow( in {path}")

        for src_path in [PROJECTOR_DIR / s for s in NEW_PROJECTOR_SUBS] + [SM_DIR / s for s in TOUCHED_SM_SUBS]:
            txt = src_path.read_text(encoding="utf-8")
            self.assertNotIn("Command::new", txt, f"Forbidden Command::new in {src_path}")

    def test_deserialize_structs_deny_unknown_fields(self) -> None:
        checked = [
            PROJECTOR_DIR / "remote_authz_bridge.rs",
            PROJECTOR_DIR / "remote_authz_grant.rs",
            SM_DIR / "apply_scopes.rs",
            SM_DIR / "snapshot.rs",
            TEST_RS,
        ]
        for path in checked:
            txt = path.read_text(encoding="utf-8")
            matches = list(
                re.finditer(
                    r"#\[derive\([^\)]*Deserialize[^\)]*\)\]\s*\n(?:#\[[^\n]+\]\s*\n)*(?:pub )?struct\b",
                    txt,
                )
            )
            for m in matches:
                block = m.group(0)
                self.assertIn("deny_unknown_fields", block, f"Missing deny_unknown_fields in {path.name}: {block}")

    def test_grant_and_bridge_invariants(self) -> None:
        grant_txt = (PROJECTOR_DIR / "remote_authz_grant.rs").read_text(encoding="utf-8")
        self.assertIn("GRANT_TRANSCRIPT_DOMAIN", grant_txt)
        self.assertIn("RetiredSigningKey", grant_txt)
        self.assertIn("ServiceIdentityMismatch", grant_txt)
        self.assertIn("Zeroizing", grant_txt)

        pg_txt = (PROJECTOR_DIR / "remote_authz_pg.rs").read_text(encoding="utf-8")
        self.assertIn("ref_store_publication_decisions", pg_txt)
        self.assertIn("ref_store_decision_cancellations", pg_txt)
        self.assertIn("ref_store_decision_dependencies", pg_txt)
        self.assertIn("ref_store_decision_scopes", pg_txt)

        bridge_txt = (PROJECTOR_DIR / "remote_authz_bridge.rs").read_text(encoding="utf-8")
        self.assertIn("assert_authoritative_source", bridge_txt)
        self.assertIn("UnknownQuorumLoss", bridge_txt)
        self.assertIn("DrainedAndConfirmed", bridge_txt)
        self.assertIn("evaluate_revocation_drain_barrier", bridge_txt)

    def test_workflow_and_docs_match_issue152_contract(self) -> None:
        wf_bytes = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_bytes, "Workflow must use pure LF")
        wf_txt = wf_bytes.decode("utf-8")
        for token in (
            "postgres:17",
            "scripts/install_ci_cargo_fork.sh verify",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "crates/refcas-log/Cargo.toml",
            "ref_store_remote_authz_bridge",
            "--ignored --test-threads=1",
        ):
            self.assertIn(token, wf_txt)

        doc_bytes = DOC.read_bytes()
        self.assertNotIn(b"\r\n", doc_bytes, "Doc must use pure LF")
        doc_txt = doc_bytes.decode("utf-8")
        for phrase in ("Refs #152", "OPEN -> CLOSING", "ReadIndex", "DecisionGrantKeyring", "UnknownQuorumLoss"):
            self.assertIn(phrase, doc_txt)


if __name__ == "__main__":
    unittest.main()
