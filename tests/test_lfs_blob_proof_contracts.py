#!/usr/bin/env python3
"""Offline structural, hygiene, and workflow contracts for Issue #145 (`Refs #145`)."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FACADE = ROOT / "src" / "lfs" / "blob_proof_publication.rs"
MOD_DIR = ROOT / "src" / "lfs" / "blob_proof_publication"
WORKFLOW = ROOT / ".github" / "workflows" / "lfs-blob-proof.yml"
DOC = ROOT / "docs" / "lfs-blob-proof-publication.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_lfs_blob_proof.py"
TEST_MAIN = ROOT / "tests" / "lfs_blob_proof_publication.rs"
TEST_SUPPORT = ROOT / "tests" / "lfs_blob_proof_support"


class LfsBlobProofContractTests(unittest.TestCase):
    def _owned_files(self) -> list[Path]:
        return sorted(
            [
                ROOT / "src" / "lfs.rs",
                FACADE,
                *MOD_DIR.glob("*.rs"),
                TEST_MAIN,
                *TEST_SUPPORT.glob("*.rs"),
                EVAL_SCRIPT,
                ROOT / "tests" / "test_lfs_blob_proof_contracts.py",
                DOC,
                WORKFLOW,
            ]
        )

    def test_line_budgets_pure_lf_zero_mod_rs_and_zero_allow(self) -> None:
        owned = self._owned_files()
        self.assertGreaterEqual(len(owned), 16)
        for path in owned:
            self.assertTrue(path.is_file(), f"missing owned file: {path}")
            raw = path.read_bytes()
            self.assertNotIn(b"\r", raw, f"CR byte found in {path}")
            lines = raw.decode("utf-8").splitlines()
            self.assertLess(len(lines), 500, f"{path} exceeded 500-line cap ({len(lines)})")
            if path.suffix == ".rs":
                self.assertNotIn("#[allow(", raw.decode("utf-8"), f"#[allow( forbidden in {path}")

        self.assertLess(len((ROOT / "src" / "lfs.rs").read_text(encoding="utf-8").splitlines()), 60)
        self.assertLess(len(FACADE.read_text(encoding="utf-8").splitlines()), 100)
        self.assertEqual([], list((ROOT / "src" / "lfs").rglob("mod.rs")))

    def test_serde_deny_unknown_fields_on_all_deserialize_types(self) -> None:
        pattern = re.compile(r"#\[derive\([^\]]*Deserialize[^\]]*\)\]")
        deny_attr = re.compile(r"#\[serde\([^\]]*\bdeny_unknown_fields\b[^\]]*\)\]")
        for path in sorted(MOD_DIR.glob("*.rs")):
            lines = path.read_text(encoding="utf-8").splitlines()
            for idx, line in enumerate(lines):
                if pattern.search(line):
                    window = "\n".join(lines[idx : idx + 4])
                    self.assertRegex(
                        window,
                        deny_attr,
                        f"{path.name}:{idx + 1} Deserialize missing deny_unknown_fields",
                    )

    def test_domain_symbols_and_durability_contracts(self) -> None:
        combined = "\n".join(p.read_text(encoding="utf-8") for p in [FACADE, *sorted(MOD_DIR.glob("*.rs"))])
        required = (
            "LfsBlobRuntimeGate",
            "LfsProofRejectCode",
            "RemoteBlobUnconfigured",
            "RemoteBlobUnreachable",
            "MalformedLfsPointer",
            "MissingRemoteBlob",
            "SizeOrDigestMismatch",
            "ForeignBackendMismatch",
            "UnauthorizedCollaborator",
            "UnauthorizedSharedHold",
            "LockedPathConflict",
            "AttestationEquivocation",
            "DeleteDisabledByPolicy",
            "LfsPointerAttestation",
            "SharedLfsHoldGrant",
            "ProtectedUploader",
            "PgArtifactHoldStore",
            "lfs_blob_objects_immutable_trig",
            "SET LOCAL synchronous_commit = 'on'",
            "hydrate_clean_compute_view",
            "reconcile_in_flight_uploads",
        )
        for token in required:
            with self.subTest(token=token):
                self.assertIn(token, combined)

    def test_workflow_and_doc_contracts(self) -> None:
        wf = WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(wf.startswith("name: "))
        self.assertNotIn("\t", wf)
        for token in (
            "postgres:17",
            "scripts/install_git_lfs.sh",
            "3.6.1",
            "1.99.1",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "1.101.0",
            "scripts/build_native_test.py",
            "--ignored --test-threads=1",
            "scripts/eval_lfs_blob_proof.py",
            "lfs-blob-proof-evidence",
        ):
            self.assertIn(token, wf)

        harness = (TEST_SUPPORT / "mod.rs").read_text(encoding="utf-8")
        self.assertIn('("RETRY_MAX_TIMES", "3")', harness)
        self.assertIn("header::CONNECTION", harness)
        self.assertIn('"close"', harness)

        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("Refs #145", doc)
        self.assertIn("OPEN", doc)
        for forbidden in ("Closes #145", "Fixes #145", "Resolves #145"):
            self.assertNotIn(forbidden, doc)

        ev = EVAL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("validate_receipt", ev)
        self.assertNotIn("verify_receipt(", ev)
        self.assertIn('"covers_rust_pg17_git_lfs_acceptance": False', ev)


if __name__ == "__main__":
    unittest.main()
