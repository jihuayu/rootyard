"""Offline structural & policy contract tests for Issue #156 (`Refs #156`).

Strictly inspects owned Rust, workflow, script, and doc files without spawning
native compilers or build scripts.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD_DIR = ROOT / "src" / "pulls" / "remote_merge_finalizer"
PULLS_RS = ROOT / "src" / "pulls.rs"
FACADE_RS = ROOT / "src" / "pulls" / "remote_merge_finalizer.rs"
INT_TEST_RS = ROOT / "tests" / "pulls_remote_merge_finalizer.rs"
SUPPORT_DIR = ROOT / "tests" / "pulls_remote_merge_support"
WORKFLOW_YML = ROOT / ".github" / "workflows" / "pulls-remote-merge.yml"
EVAL_PY = ROOT / "scripts" / "eval_pulls_remote_merge.py"
DOC_MD = ROOT / "docs" / "pulls-remote-merge-finalizer.md"

RUST_SUBMODULES = (
    "types.rs",
    "validation.rs",
    "git_pack.rs",
    "coordinator.rs",
    "projector.rs",
    "pg_store.rs",
    "unit_tests.rs",
    "unit_recovery_tests.rs",
)
SUPPORT_FILES = ("mod.rs", "ctx.rs", "raft.rs")
PINNED_CARGO_FORK_SHA = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"


class PullsRemoteMergeContractsTest(unittest.TestCase):
    def test_owned_files_exist_pure_lf_and_line_caps(self) -> None:
        owned = [
            (PULLS_RS, 60),
            (FACADE_RS, 100),
            (INT_TEST_RS, 500),
            (EVAL_PY, 500),
            (DOC_MD, 500),
            (WORKFLOW_YML, 500),
            *((MOD_DIR / name, 500) for name in RUST_SUBMODULES),
            *((SUPPORT_DIR / name, 500) for name in SUPPORT_FILES),
        ]
        for path, cap in owned:
            self.assertTrue(path.is_file(), f"Missing owned file: {path}")
            raw = path.read_bytes()
            self.assertNotIn(b"\r", raw, f"CR byte forbidden in {path}")
            lines = raw.decode("utf-8").splitlines()
            self.assertLess(len(lines), cap, f"{path} exceeded {cap}L cap ({len(lines)}L)")

    def test_module_layout_and_zero_allow_attributes(self) -> None:
        self.assertFalse((MOD_DIR / "mod.rs").exists(), "Forbidden src/pulls/remote_merge_finalizer/mod.rs")
        pulls_src = PULLS_RS.read_text(encoding="utf-8")
        self.assertIn("pub mod remote_merge_finalizer;", pulls_src)
        self.assertNotIn("Command::new", pulls_src)
        self.assertNotIn("CREATE TABLE", pulls_src)

        for path in [PULLS_RS, FACADE_RS, *(MOD_DIR / n for n in RUST_SUBMODULES), INT_TEST_RS]:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("#[allow(", text, f"#[allow(...)] forbidden in {path}")

    def test_deserialize_types_deny_unknown_fields(self) -> None:
        derive_re = re.compile(r"#\[derive\([^]]*\bDeserialize\b[^]]*\)\](?:\s*#\[[^\]]+\])*\s*pub\s+(?:struct|enum)\s+(\w+)")
        for path in [FACADE_RS, *(MOD_DIR / n for n in RUST_SUBMODULES if "unit" not in n)]:
            text = path.read_text(encoding="utf-8")
            for match in derive_re.finditer(text):
                snippet = match.group(0)
                self.assertIn(
                    "deny_unknown_fields",
                    snippet,
                    f"Missing #[serde(deny_unknown_fields)] on {match.group(1)} in {path}",
                )

    def test_required_domain_invariants_and_sql_guards(self) -> None:
        src_blob = "\n".join((MOD_DIR / n).read_text(encoding="utf-8") for n in RUST_SUBMODULES if "unit" not in n)
        for token in (
            "StaleRequiredChecks",
            "StaleHeadOid",
            "TargetRefMoved",
            "RevokedAuthorization",
            "RemoteAuthzDenied",
            "PendingMerge",
            "CommittedMerge",
            "RejectedMerge",
            "AbortedBeforeCas",
            "PullRemoteMergeProducer",
            "PullMergeReceiptProjector",
            "RecoverablePullMergeFinalizer",
            "PgMergeStore",
            "SET LOCAL synchronous_commit = 'on'",
            "pull_remote_merge_attempts",
            "pull_remote_merge_monotonic_trig",
            "UPDATE forge_pulls",
            "prepare_merge_candidate",
            "compute_merge_binding_digest",
            "RefCommitResult::Applied",
            "pack_sha256",
            "facts_digest",
        ):
            self.assertIn(token, src_blob, f"Missing required symbol/SQL guard: {token}")

    def test_workflow_gates_and_pins(self) -> None:
        raw = WORKFLOW_YML.read_bytes()
        text = raw.decode("utf-8")
        self.assertTrue(text.startswith("name: "), "Workflow must start with 'name: '")
        self.assertNotIn("\t", text, "Tabs forbidden in workflow YAML")
        for token in (
            "workflow_dispatch:",
            "pull_request:",
            "postgres:17",
            "1.99.1",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            PINNED_CARGO_FORK_SHA,
            "RUSTFLAGS",
            "crates/refcas-log/Cargo.toml",
            "pulls_remote_merge_finalizer",
            "--ignored --test-threads=1",
            "scripts/eval_pulls_remote_merge.py",
        ):
            self.assertIn(token, text, f"Missing CI gate token in workflow: {token}")

    def test_doc_and_eval_scope_honesty(self) -> None:
        doc = DOC_MD.read_text(encoding="utf-8")
        self.assertIn("Refs #156", doc)
        self.assertNotIn("Closes #156", doc)
        self.assertNotIn("Fixes #156", doc)
        for phrase in ("PendingMerge", "CommittedMerge", "Ref-CAS", "OPEN", "Non-Goals"):
            self.assertIn(phrase, doc, f"Missing required section/phrase in doc: {phrase}")

        eval_src = EVAL_PY.read_text(encoding="utf-8")
        for marker in (
            "python_reference_model_with_stock_git",
            '"covers_rust_pg17_raft_acceptance": False',
            "--ignored --test-threads=1",
        ):
            self.assertIn(marker, eval_src, f"Missing scope honesty marker in evaluator: {marker}")


if __name__ == "__main__":
    unittest.main()
