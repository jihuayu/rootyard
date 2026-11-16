#!/usr/bin/env python3
"""Offline structural, modularity, workflow, and documentation contracts for Issue #175."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECTOR_ENTRY = ROOT / "src/ref_store/projector.rs"
PROJECTOR_DIR = ROOT / "src/ref_store/projector"
NEW_SUBMODULES = ("session_fence.rs", "dependency.rs", "session_tests.rs")
WORKFLOW = ROOT / ".github/workflows/raft-session-consistency.yml"
DOC = ROOT / "docs/raft-session-consistency.md"
TEST_RS = ROOT / "tests/ref_store_raft_session_consistency.rs"


class RaftSessionConsistencyContractTest(unittest.TestCase):
    def test_projector_entry_and_submodules_keep_strict_boundaries(self) -> None:
        self.assertTrue(PROJECTOR_ENTRY.is_file())
        self.assertFalse((PROJECTOR_DIR / "mod.rs").exists(), "Forbidden projector/mod.rs")
        entry_txt = PROJECTOR_ENTRY.read_text(encoding="utf-8")
        self.assertLess(len(entry_txt.splitlines()), 100)
        self.assertNotIn("Command::new", entry_txt)
        self.assertNotRegex(entry_txt, r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b")
        for sub in NEW_SUBMODULES:
            path = PROJECTOR_DIR / sub
            self.assertTrue(path.is_file(), f"Missing {path}")
            txt = path.read_text(encoding="utf-8")
            with self.subTest(submodule=sub):
                self.assertLess(len(txt.splitlines()), 500)
                self.assertNotIn("#[allow(", txt)
                self.assertNotIn("Command::new", txt)

    def test_deserialize_structs_deny_unknown_fields(self) -> None:
        for path in (
            PROJECTOR_DIR / "session_fence.rs",
            PROJECTOR_DIR / "dependency.rs",
            TEST_RS,
        ):
            txt = path.read_text(encoding="utf-8")
            matches = list(re.finditer(r"#\[derive\([^\)]*Deserialize[^\)]*\)\]\s*\n(?:#\[[^\n]+\]\s*\n)*pub struct\b|(?:#\[derive\([^\)]*Deserialize[^\)]*\)\]\s*\n)(?:#\[[^\n]+\]\s*\n)*struct\b", txt))
            self.assertGreater(len(matches), 0, f"Expected Deserialize structs in {path.name}")
            for m in matches:
                block = m.group(0)
                self.assertIn("deny_unknown_fields", block, f"Missing deny_unknown_fields in {path.name}: {block}")

    def test_no_cross_group_bare_index_or_pg_fallback_in_session_fence(self) -> None:
        fence_txt = (PROJECTOR_DIR / "session_fence.rs").read_text(encoding="utf-8")
        self.assertIn("PgRefsProjection", fence_txt)
        self.assertIn("RedisCache", fence_txt)
        self.assertIn("UnverifiedLocalReplica", fence_txt)
        self.assertIn("RaftReadIndexQuorum", fence_txt)
        self.assertIn("assert_authoritative_source", fence_txt)
        self.assertIn("RealmMismatch", fence_txt)
        self.assertIn("rrs1.", fence_txt)

    def test_dependency_module_enforces_contiguous_cursor_and_no_gap_skip(self) -> None:
        dep_txt = (PROJECTOR_DIR / "dependency.rs").read_text(encoding="utf-8")
        dep_code = "\n".join(l for l in dep_txt.splitlines() if not l.lstrip().startswith("//"))
        self.assertIn("ref_cas_projected_operations", dep_code)
        self.assertIn("SequenceGapOrResync", dep_code)
        self.assertIn("can_authorize_write", dep_code)
        self.assertIn("apply_projection_stream_stop_on_gap", dep_code)
        self.assertIn("await_projected_event", dep_code)
        self.assertNotIn("MAX(id)", dep_code)
        self.assertNotIn("MAX(event_seq)", dep_code)

    def test_workflow_and_docs_match_issue175_contract(self) -> None:
        wf_bytes = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_bytes, "Workflow must use pure LF")
        wf_txt = wf_bytes.decode("utf-8")
        for token in (
            "postgres:17",
            "scripts/install_ci_cargo_fork.sh verify",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "crates/refcas-log/Cargo.toml",
            "ref_store_raft_session_consistency",
            "--ignored --test-threads=1",
        ):
            self.assertIn(token, wf_txt)

        doc_txt = DOC.read_text(encoding="utf-8")
        for phrase in (
            "group_id",
            "history_incarnation",
            "authority_id",
            "raft_log_index",
            "repo_ref_version",
            "ReadIndex",
            "ref_cas_projection_cursors",
            "#157",
        ):
            self.assertIn(phrase, doc_txt)


if __name__ == "__main__":
    unittest.main()
