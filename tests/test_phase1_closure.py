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
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_baseline  # noqa: E402
from e2e_tiers import Phase1ClosureAndDocsFixture  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_build_receipt as receipt_contract  # noqa: E402

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
        self.assertEqual(
            Phase1ClosureAndDocsFixture.ci_build_native_batch_tokens(
                Phase1ClosureAndDocsFixture.live_ci_run_commands(ci_text)
            ),
            [
                "python3",
                "scripts/build_native_batch.py",
                "--all-bins",
                "--features",
                "pando-lab",
                "--strip-debuginfo",
                "--test",
                "ref_store_snapshot_backup_fixture",
                "--output",
                "test-results/refstore-snapshot-fixture",
                "--test",
                "ref_store_holds_backup_fixture",
                "--output",
                "test-results/refstore-holds-fixture",
                "--manifest-out",
                "test-results/native-build-batch.json",
                "--artifact-store",
                "$HOME/.cache/rootyard/native-artifacts",
            ],
            "ci.yml must invoke the attested native batch build for all pando-lab binaries",
        )
        # The standalone producer is the shared v2 contract: it copies Cargo's
        # reported freshness truthfully (either boolean), never forces a clean
        # or rebuilt claim, and records source/config/toolchain/content
        # provenance across the transaction.
        build_script = (ROOT / "scripts/build_native.py").read_text(encoding="utf-8")
        for required in (
            "command = ['cargo', 'build', '--locked']",
            "fresh = event.get('fresh')",
            "if fresh is not True and fresh is not False:",
            "receipt.make_receipt_v2(",
            "bound_before = capture_bound_inputs(environment)",
            "bound_after = capture_bound_inputs(environment)",
            "if bound_before != bound_after:",
            "toolchain_before = probe_toolchain(environment)",
            "toolchain_after = probe_toolchain(environment)",
            "if toolchain_before != toolchain_after:",
            "git_before = git_state()",
            "git_after = git_state()",
            "if git_before != git_after:",
            "bound_inputs=bound_after",
            "toolchain=toolchain_after",
            "workspace_commit=git_after['commit']",
            "lock_file=lock_path",
            "git_head=git_after['head']",
            "working_tree={'tree': git_after['tree'], 'status': git_after['status']}",
        ):
            self.assertIn(required, build_script, f"native build wrapper lost {required}")
        for obsolete in (
            "['cargo', 'clean'",
            "'package_rebuilt':",
            "'fresh_false_artifacts':",
        ):
            self.assertNotIn(
                obsolete, build_script,
                f"v2 native build wrapper must not force {obsolete}",
            )
        for banned in ("package_rebuilt", "clean_command", "fresh_false_artifacts", "fresh"):
            self.assertIn(banned, receipt_contract.V2_BANNED_FIELDS)
        parameters = inspect.signature(receipt_contract.make_receipt_v2).parameters
        for field in (
            "binary_path", "command", "artifacts", "toolchain", "bound_inputs",
            "workspace_commit", "target_dir", "features", "lock_file",
        ):
            self.assertIn(field, parameters)

        # The workflow exports the batch's immutable paths once and every later
        # consumer, including the final report step, binds those exact bytes
        # instead of a mutable target/debug artifact.
        export_command = "python3 scripts/export_native_artifacts.py"
        export_start = ci_text.index(export_command)
        manifest_start = ci_text.rindex(
            "python3 scripts/native_report_manifest.py --mode job",
            0,
            ci_text.index("--manifest-out test-results/native-pr-gate.json"),
        )
        self.assertLess(export_start, manifest_start)
        export_step = ci_text[export_start:manifest_start]
        for binding in (
            "--bin rootyard=ROOTYARD_BIN",
            "--bin-receipt rootyard=ROOTYARD_BUILD_RECEIPT",
            "--test ref_store_snapshot_backup_fixture=ROOTYARD_SNAPSHOT_FIXTURE",
            "--test ref_store_holds_backup_fixture=ROOTYARD_HOLDS_FIXTURE",
        ):
            self.assertIn(binding, export_step)
        later = ci_text[export_start:]
        for mutable in (
            "target/debug/rootyard",
            "target/debug/rootyard-workspace-lab",
            "target/debug/rootyard-view-lab",
            "target/debug/rootyard-pando-lab",
        ):
            self.assertNotIn(mutable, later)
        manifest_step = ci_text[manifest_start:].split("\n      - name:", 1)[0]
        self.assertIn('--binary "$ROOTYARD_BIN"', manifest_step)
        self.assertIn('--build-receipt "$ROOTYARD_BUILD_RECEIPT"', manifest_step)
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

    def test_vault_manifest_builder_input_preserves_native_batch_guard(self) -> None:
        ci_text = CI_YML.read_text(encoding="utf-8")
        fixture = Phase1ClosureAndDocsFixture
        commands = fixture.live_ci_run_commands(ci_text)
        vault_start = next(
            index for index, tokens in enumerate(commands)
            if tokens[:2] == ["python3", "tests/pando_vault_rotation.py"]
        )
        vault, report, manifest = commands[vault_start:vault_start + 3]
        self.assertIn("--receipt", vault)
        self.assertEqual(report[:2], ["python3", "tests/pando_vault_rotation_ci_report.py"])
        self.assertEqual(manifest[:2], ["python3", "scripts/native_report_manifest.py"])
        builder = "scripts/build_native_batch.py"
        binding = manifest.index(builder)
        self.assertEqual(manifest[binding - 1], "--harness")
        self.assertEqual(fixture.ci_build_native_batch_tokens(commands)[:2], ["python3", builder])

        step_start = ci_text.index("      - name: Qualify pinned real Vault rotation")
        step_end = ci_text.index("      - name:", step_start + 1)
        bad_commands = (
            f"python3 {builder} --all-bins",
            f"python {builder} --all-bins",
            "python3 -m build_native_batch",
            "python3 -m scripts.build_native_batch",
            "python3 -mbuild_native_batch",
            f"python3 scripts/native_report_manifest.py --harness {builder} && python3 {builder}",
            f"python3 scripts/native_report_manifest.py --binary {builder}",
        )
        for bad_command in bad_commands:
            with self.subTest(command=bad_command):
                mutated = ci_text[:step_end] + f"          {bad_command}\n" + ci_text[step_end:]
                with self.assertRaisesRegex(AssertionError, "build_native_batch"):
                    fixture.ci_build_native_batch_tokens(fixture.live_ci_run_commands(mutated))

    def test_ci_workflow_wires_schema_030_and_all_tier1_e2e_harnesses(self) -> None:
        ci_text = CI_YML.read_text(encoding="utf-8")

        # Schema 030 alignment
        self.assertIn('python3 tests/schema_contract.py --binary "$ROOTYARD_BIN"', ci_text)
        self.assertNotIn("Verify schema-008 catalog", ci_text)
        self.assertIn("schema-030", ci_text)

        # Required Tier-1 E2E and backup harnesses with --binary and --report
        expected_commands = (
            'python3 tests/pulls.py --binary "$ROOTYARD_BIN" --report test-results/pulls.json',
            'python3 tests/backup_pulls.py --binary "$ROOTYARD_BIN" --report test-results/backup-pulls.json',
            'python3 tests/browse.py --mixed-refs --git "$(command -v git)" '
            '--binary "$ROOTYARD_BIN" --report test-results/browse.json',
            'python3 tests/lfs.py --binary "$ROOTYARD_BIN" --report test-results/lfs.json',
            'python3 tests/ci_mirror.py --binary "$ROOTYARD_BIN" --report test-results/ci-mirror.json',
            'python3 tests/workspaces.py --binary "$ROOTYARD_WORKSPACE_LAB_BIN" --report test-results/workspaces.json',
            'python3 tests/workspace.py --binary "$ROOTYARD_WORKSPACE_LAB_BIN" --report test-results/workspace.json',
            'python3 tests/webhooks.py --binary "$ROOTYARD_BIN" --report test-results/webhooks.json',
        )
        for cmd in expected_commands:
            self.assertIn(cmd, ci_text, f"Missing CI step command in .github/workflows/ci.yml: {cmd}")

        # Real-service pagination harnesses and their evidence bindings
        pagination_commands = (
            'python3 tests/repository_pagination.py --binary "$ROOTYARD_BIN" --report test-results/repository-pagination.json',
            'python3 tests/organization_pagination.py --binary "$ROOTYARD_BIN" --report test-results/organization-pagination.json',
            'python3 tests/web_detail_pagination.py --binary "$ROOTYARD_BIN" --report test-results/web-detail-pagination.json',
        )
        pagination_reports = (
            "--report repository_pagination=test-results/repository-pagination.json",
            "--report organization_pagination=test-results/organization-pagination.json",
            "--report web_detail_pagination=test-results/web-detail-pagination.json",
        )
        pagination_harnesses = (
            "--harness tests/repository_pagination.py",
            "--harness tests/organization_pagination.py",
            "--harness tests/web_detail_pagination.py",
        )
        for binding in pagination_commands + pagination_reports + pagination_harnesses:
            self.assertIn(binding, ci_text, f"Missing pagination wiring in .github/workflows/ci.yml: {binding}")
        # Webhook and Browse reports and their exact source inputs are part of
        # the native gate.
        # The PostgreSQL start-gate job manifest is separate and earlier;
        # target the CLI job manifest by its unique output path.
        manifest_marker = "--manifest-out test-results/native-pr-gate.json"
        manifest_start = ci_text.rindex(
            "python3 scripts/native_report_manifest.py --mode job",
            0,
            ci_text.index(manifest_marker),
        )
        manifest_step = ci_text[manifest_start:].split("\n      - name:", 1)[0]
        for argument in (
            "--report webhooks=test-results/webhooks.json",
            "--harness tests/webhooks.py",
            "--harness tests/webhook_tenant_matrix.py",
            # Browse report, its runtime harness and the imported scale helper
            # are part of the native gate, with its key cases required to pass.
            "--report browse=test-results/browse.json",
            "--harness tests/browse.py",
            "--harness tests/browse_ref_scale.py",
            "--harness tests/mixed_ref_cases.py",
            "--harness tests/mixed_ref_support.py",
            "--harness tests/refusal_audit_sql.py",
            "--require-case browse=protected_writes_and_ref_ack_failure",
            "--require-case browse=ref_transaction_settlement_recovery",
            "--require-case browse=ref_transaction_crash_recovery",
            "--require-case browse=ref_scale_complete_traversal",
            "--require-case browse=mixed_protected_unprotected_atomic_push",
            "--require-case browse=mixed_protected_unprotected_ref_transaction",
        ):
            self.assertIn(argument, manifest_step)
        # One Browse report and harness entry; the scale helper is the only
        # other Browse-named source binding.
        self.assertEqual(manifest_step.count("--report browse="), 1)
        self.assertEqual(sum(1 for line in manifest_step.splitlines()
                             if line.strip() == "--harness tests/browse.py \\"), 1)

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
        self.assertIn(
            "python3 scripts/run_python_ci_tests.py",
            ci_text,
            "ci.yml must run full tests/test_*.py discovery via the diagnostics runner",
        )

    def test_ci_workspace_autocapture_acceptance_wiring(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")

        def step_block(name: str) -> str:
            marker = f"      - name: {name}"
            start = text.find(marker)
            self.assertNotEqual(start, -1, f"missing CI step {name!r}")
            nxt = text.find("\n      - name:", start + len(marker))
            if nxt == -1:
                return text[start:]
            return text[start:nxt]

        acceptance = step_block("Exercise native workspace autocapture acceptance")
        self.assertIn(
            'python3 tests/workspace_capture_acceptance.py --binary "$ROOTYARD_BIN" '
            "--report test-results/workspace-capture.json",
            acceptance,
        )
        self.assertIn("timeout-minutes: 20", acceptance)
        self.assertIn(
            "ROOTYARD_TEST_EVIDENCE_DIR: ${{ github.workspace }}/test-results/evidence",
            acceptance,
        )
        self.assertIn("ROOTYARD_WORKSPACE_MOUNT_MODE: direct", acceptance)

        manifest = step_block("Bind native regressions to the built binary and source inputs")
        self.assertIn(
            "--report workspace_capture=test-results/workspace-capture.json", manifest
        )
        self.assertIn("tests/workspace_capture_acceptance.py", manifest)
        self.assertIn("tests/fixtures/capture_read_gate.c", manifest)
        self.assertIn("--fixture workspace_mount_mode=direct", manifest)
        for case in (
            "__main__.WorkspaceCaptureAcceptance.test_capture_reaches_ids_beyond_fixed_prefix",
            "__main__.WorkspaceCaptureAcceptance.test_api_write_baseline_does_not_emit_spurious_capture",
            "__main__.WorkspaceCaptureAcceptance.test_large_inventory_keeps_single_tokio_worker_responsive",
            "__main__.WorkspaceCaptureAcceptance.test_sse_reconnect_and_retention_gap_uses_live_revision",
            "__main__.WorkspaceCaptureAcceptance.test_scan_does_not_hold_row_lock_and_rejects_stale_revision",
            "__main__.WorkspaceCaptureAcceptance.test_scan_revalidates_lease_epoch_before_committing",
        ):
            self.assertEqual(
                manifest.count(f"--require-case workspace_capture={case}"),
                1,
                case,
            )

        upload = step_block("Upload end-to-end report")
        self.assertIn("test-results/*.json", upload)
        self.assertIn("test-results/evidence/*.jsonl", upload)

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
            f"PASS: 823 source blocks, 11 chapters, {len(list((ROOT / 'docs/design/diagrams').glob('*.mmd')))} synchronized diagrams",
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
