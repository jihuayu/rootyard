#!/usr/bin/env python3
"""Unit and contract tests for Milestone M6 Phase 1 Closure (F20 & F21).

Verifies:
- F20: .github/workflows/ci.yml wires all Tier-1 E2E harnesses (pulls, backup_pulls,
  browse, lfs, ci_mirror, workspace, workspaces, pando_lab with non-root PG 17 &
  pando-lab feature build), e2e_tiers.py, unittest discovery, check_design_docs.py,
  and schema_contract.py aligned with Schema 030.
- F21: docs/design/implementation-status.md and docs/README.md register Schema 030
  and all four Tier-1 tracks (PR/Review/Check/Merge, Browse/Ref-Transactions,
  Git LFS, CI Mirror watermark eviction/limiter/metrics, Pando/Workspace labs)
  while preserving scripts/check_design_docs.py archive digests and relative links.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_baseline  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github/workflows/ci.yml"
IMPL_STATUS_MD = ROOT / "docs/design/implementation-status.md"
DOCS_README_MD = ROOT / "docs/README.md"
SOURCE_MANIFEST_JSON = ROOT / "docs/design/source-manifest.json"


class TestPhase1CiWorkflowWiring(unittest.TestCase):
    """F20: Verify .github/workflows/ci.yml wires all Tier-1 suites and Schema 030 contracts."""

    def test_ci_workflow_installs_pg17_server_and_builds_all_binaries(self) -> None:
        self.assertTrue(CI_YML.is_file(), f"Missing {CI_YML}")
        ci_text = CI_YML.read_text(encoding="utf-8")

        # Must install postgresql-17 server package (for initdb/pg_ctl in pando_lab.py) and client tools
        self.assertIn("postgresql-client-17", ci_text)
        self.assertIn("postgresql-17", ci_text)
        self.assertIn("initdb --version", ci_text)
        self.assertIn("pg_ctl --version", ci_text)

        # Must build standard binaries and pando-lab feature binary
        self.assertIn("cargo build --locked", ci_text)
        self.assertRegex(
            ci_text,
            r"python3\s+scripts/build_native\.py\s+--features\s+pando-lab\s+--bins\b",
            "ci.yml must invoke the attested native build for all pando-lab binaries",
        )
        build_script = (ROOT / "scripts/build_native.py").read_text(encoding="utf-8")
        for required in (
            "command = ['cargo', 'build', '--locked']",
            "['--bins'] if args.bins",
            "command += ['--features', args.features]",
            "subprocess.run(command, cwd=ROOT, check=True)",
            "before = source_digest()",
            "after = source_digest()",
            "if before != after:",
            "'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()",
            "'source_inputs_sha256': before",
            "temporary.replace(destination)",
        ):
            self.assertIn(required, build_script, f"native build wrapper lost {required}")
        self.assertRegex(
            ci_text,
            r"cargo\s+clippy\s+--locked\s+--all-targets\s+--features\s+pando-lab\b",
            "ci.yml must run clippy with --features pando-lab",
        )
        self.assertRegex(
            ci_text,
            r"cargo\s+test\s+--locked\s+--all-targets\s+--features\s+pando-lab\b",
            "ci.yml must run cargo test with --features pando-lab",
        )

    def test_ci_workflow_wires_schema_030_and_all_tier1_e2e_harnesses(self) -> None:
        ci_text = CI_YML.read_text(encoding="utf-8")

        # Schema 030 alignment
        self.assertIn("python3 tests/schema_contract.py --binary target/debug/rootyard", ci_text)
        self.assertNotIn("Verify schema-008 catalog", ci_text)
        self.assertIn("schema-030", ci_text)

        # Required Tier-1 E2E and backup harnesses with --binary and --report
        expected_commands = (
            "python3 tests/pulls.py --binary target/debug/rootyard --report test-results/pulls.json",
            "python3 tests/backup_pulls.py --binary target/debug/rootyard --report test-results/backup-pulls.json",
            "python3 tests/browse.py --binary target/debug/rootyard --report test-results/browse.json",
            "python3 tests/lfs.py --binary target/debug/rootyard --report test-results/lfs.json",
            "python3 tests/ci_mirror.py --binary target/debug/rootyard --report test-results/ci-mirror.json",
            "python3 tests/workspaces.py --binary target/debug/rootyard-workspace-lab --report test-results/workspaces.json",
            "python3 tests/workspace.py --binary target/debug/rootyard-workspace-lab --report test-results/workspace.json",
        )
        for cmd in expected_commands:
            self.assertIn(cmd, ci_text, f"Missing CI step command in .github/workflows/ci.yml: {cmd}")

        # initdb requires non-root. Container jobs switch user; the qualified
        # plain-host profile executes as runner and verifies its uid at runtime.
        self.assertIn("tests/pando_lab.py", ci_text)
        self.assertIn("rootyard-pando-lab", ci_text)
        verify = ci_text.split("\n  container:\n", 1)[0]
        switches_user = any(command in verify for command in (
            "runuser -u postgres", "su -s /bin/bash postgres", "su postgres"))
        host_runner = ("runs-on: ubuntu-22.04" in verify and "container:" not in verify
                       and 'test "$(id -u)" -ne 0\n          python3 tests/pando_lab.py' in verify)
        self.assertTrue(switches_user or host_runner,
                        "Pando initdb must execute with a verified non-root user")
        self.assertIn("/usr/lib/postgresql/17/bin", ci_text)

    def test_ci_workflow_wires_design_docs_gate_unit_discovery_and_e2e_tiers(self) -> None:
        ci_text = CI_YML.read_text(encoding="utf-8")

        self.assertIn("python3 scripts/check_design_docs.py", ci_text)
        self.assertIn("python3 tests/e2e_tiers.py", ci_text)
        self.assertRegex(
            ci_text,
            r"python3\s+-m\s+unittest\s+discover\s+-s\s+tests\s+-p\s+['\"]test_\*\.py['\"]",
            "ci.yml must run full unittest discovery over tests/test_*.py",
        )

    def test_all_python_scripts_referenced_in_ci_yml_exist_and_parse_cleanly(self) -> None:
        ci_text = CI_YML.read_text(encoding="utf-8")
        referenced = set(re.findall(r"\b(?:tests|scripts)/[a-zA-Z0-9_]+\.py\b", ci_text))
        self.assertGreaterEqual(len(referenced), 24)
        for rel_path in sorted(referenced):
            abs_path = ROOT / rel_path
            self.assertTrue(abs_path.is_file(), f"Script referenced in ci.yml does not exist: {rel_path}")
            source = abs_path.read_text(encoding="utf-8")
            ast.parse(source, filename=str(abs_path))


class TestPhase1ImplementationStatusAndDocsSync(unittest.TestCase):
    """F21: Verify docs/design/implementation-status.md and docs/README.md synchronization."""

    def test_check_design_docs_passes_with_intact_archive_sha256(self) -> None:
        manifest = json.loads(SOURCE_MANIFEST_JSON.read_text(encoding="utf-8"))
        expected_sha256 = manifest["source_body_sha256"]
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/check_design_docs.py")],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"check_design_docs.py failed:\n{proc.stderr}")
        self.assertIn(
            "PASS: 823 source blocks, 11 chapters, 7 synchronized diagrams",
            proc.stdout,
        )
        self.assertIn(expected_sha256, proc.stdout)

    def test_implementation_status_md_registers_schema_030_and_tier1_tracks(self) -> None:
        self.assertTrue(IMPL_STATUS_MD.is_file(), f"Missing {IMPL_STATUS_MD}")
        status_text = IMPL_STATUS_MD.read_text(encoding="utf-8")

        # Schema 030 baseline
        self.assertIn("030", status_text)
        self.assertIn("23", status_text)
        self.assertIn("030_catalog.sql", status_text)

        # Track 1: PR / Review / Check Run / Branch Rules / Merge
        for token in (
            "pulls.rs",
            "009_forge_pulls.sql",
            "Pull Request",
            "Review",
            "Check Run",
            "branch-rules",
            "merge",
        ):
            self.assertIn(token, status_text, f"implementation-status.md missing Track 1 token: {token}")

        # Track 2A & 2B: Browse / Ref-Transactions & Git LFS
        for token in (
            "browse.rs",
            "git_read.rs",
            "transactions.rs",
            "ref-transactions",
            "lfs.rs",
            "020_lfs_objects.sql",
            "LFS",
        ):
            self.assertIn(token, status_text, f"implementation-status.md missing Track 2 token: {token}")

        # Track 3: CI Mirror watermark/LRU eviction, lease-coordinated pin release, rate limiting & metrics
        for token in (
            "mirror.rs",
            "eviction.rs",
            "limiter.rs",
            "observability.rs",
            "030_ci_mirror.sql",
            "ci_pins.rs",
            "ci_checkouts.rs",
            "ci_mirror_evictions",
            "mirror-evict",
            "mirror-status",
        ):
            self.assertIn(token, status_text, f"implementation-status.md missing Track 3 token: {token}")

        # Track 4: Pando Lab & Workspace Lab Tier-1 capabilities
        for token in (
            "verify-delta",
            "walk-graph",
            "diff-export",
            "sync-dirty",
            "verify-readonly-view",
            ".rootyardignore",
        ):
            self.assertIn(token, status_text, f"implementation-status.md missing Track 4 token: {token}")

    def test_docs_readme_links_and_parallel_development_index(self) -> None:
        self.assertTrue(DOCS_README_MD.is_file(), f"Missing {DOCS_README_MD}")
        readme_text = DOCS_README_MD.read_text(encoding="utf-8")

        for expected_link in (
            "design/README.md",
            "design/implementation-status.md",
            "design/08-roadmap.md",
            "parallel-development.md",
            "backup-restore.md",
            "ci-mirror.md",
            "workspace-foundation.md",
            "../experimental/pando/README.md",
            "../src/pulls.rs",
            "../src/browse.rs",
            "../src/lfs.rs",
            "../schema/030_catalog.sql",
            "../tests/pulls.py",
            "../tests/backup_pulls.py",
            "../tests/browse.py",
            "../tests/lfs.py",
            "../tests/ci_mirror.py",
            "../tests/pando_lab.py",
            "../tests/workspace.py",
            "../tests/e2e_tiers.py",
            "../tests/test_tier5_adversarial.py",
        ):
            self.assertIn(expected_link, readme_text, f"docs/README.md missing link to {expected_link}")

    def test_schema_030_and_tier1_suite_inventory_complete(self) -> None:
        self.assertEqual(schema_baseline.SCHEMA_VERSIONS[:9], [1, 2, 3, 6, 7, 8, 9, 20, 30])
        self.assertGreaterEqual(schema_baseline.LATEST_VERSION, 30)
        self.assertEqual(schema_baseline.LATEST_PREFIX, f"{schema_baseline.LATEST_VERSION:03d}")
        self.assertGreaterEqual(schema_baseline.TABLE_COUNT, 23)

        required_test_files = (
            "tests/pulls.py",
            "tests/backup_pulls.py",
            "tests/browse.py",
            "tests/lfs.py",
            "tests/ci_mirror.py",
            "tests/pando_lab.py",
            "tests/workspace.py",
            "tests/workspaces.py",
            "tests/e2e_tiers.py",
            "tests/test_pulls.py",
            "tests/test_browse_lfs.py",
            "tests/test_ci_mirror.py",
            "tests/test_track4_labs.py",
            "tests/test_tier5_adversarial.py",
            "tests/test_parallel_boundaries.py",
            "tests/test_e2e_sync.py",
            "tests/test_download_ci_kafka.py",
            "tests/test_phase1_closure.py",
        )
        for rel in required_test_files:
            self.assertTrue((ROOT / rel).is_file(), f"Missing required test file: {rel}")


if __name__ == "__main__":
    unittest.main()
