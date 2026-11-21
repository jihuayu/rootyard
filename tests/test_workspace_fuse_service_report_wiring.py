"""Pure contract tests for the workspace FUSE service report wiring.

These tests read the existing workflow and import the acceptance projection.
They do not start the service, FUSE, PostgreSQL, Git, a child process, a thread,
or the network.  The real C5 case is still executed by the generic unfiltered
Python discovery and by the root native helper step.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest

import workspace_fuse_service_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github/workflows/ci.yml"
GENERIC_RUNNER = ROOT / "scripts/run_python_ci_tests.py"

# Current main's verify/lifecycle budget: 95 existing + 12 cold tenant LFS gate
# on owned Garage + 28 full Redis qualification (including restore/FLUSHALL,
# partition, failover, and cleanup/manifest binding) + 40 Pando package gates:
# 175. The merged job keeps it and adds only this branch's independent FUSE
# phases plus PR #321's independent #29 remote-CAS witness.
MAIN_VERIFY_BUDGET = 175
REMOTE_CAS_BUDGET = 22

C5 = "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_api_sigkill_with_pending_kernel_writer"
EXISTING_REQUIRED = (
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_live_editor_capture_checkpoint_and_remount",
    "tests.test_workspace_handoff.WorkspaceHandoffTest.test_expired_host_reattach_from_remote_checkpoint",
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_normal_sigterm_helper_unmount_precedes_parked_git_join",
)
REMOTE_REQUIRED = (
    "invalid_optin_rejected_at_startup",
    "default_retains_failed_remote_cleanup",
    "exit77_with_pending_fuse_request",
)
LEGACY_REQUIRED = (
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_normal_legacy_sigterm_join_evidence_and_exact_unmount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_partial_reconcile_failure_cleans_earlier_owned_mount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_post_reconcile_api_bind_failure_cleans_owned_mount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_sigterm_during_blocked_startup_joins_mounted_owner",
)
HARNESSES = (
    "tests/test_workspace_fuse_service.py",
    "tests/test_workspace_handoff.py",
    "tests/workspace_fuse_service_acceptance.py",
    "tests/workspace_remote_delete_policy.py",
    "tests/runtime_binary.py",
    "tests/source_bound_binary.py",
    "tests/native_evidence.py",
    "tests/e2e.py",
    "tests/owned_fuse_cleanup.py",
    "tests/ops_provenance.py",
    "tests/fuse_helper_native_support.py",
    "tests/workspace_normal_shutdown_support.py",
    "tests/workspace_capture_acceptance.py",
    "tests/lfs_hydration_concurrency.py",
    "tests/lfs.py",
    "tests/lfs_remote_contract.py",
    "tests/schema_baseline.py",
    "tests/fixtures/capture_read_gate.c",
    "scripts/native_report_manifest.py",
    "scripts/native_build_receipt.py",
    ".github/workflows/ci.yml",
)


def _step(text, name):
    start = text.index(f"- name: {name}")
    end = text.find("\n      - name:", start)
    return text[start:] if end == -1 else text[start:end]


def _manifest_step(text):
    marker = "--manifest-out test-results/native-workspace-fuse-gate.json"
    command = "python3 scripts/native_report_manifest.py --mode job"
    start = text.rindex(command, 0, text.index(marker))
    end = text.find("\n      - name:", start)
    return text[start:] if end == -1 else text[start:end]


class WorkspaceFuseServiceReportWiringTest(unittest.TestCase):
    def setUp(self):
        self.ci = CI_YML.read_text(encoding="utf-8")
        self.manifest = _manifest_step(self.ci)

    def test_required_inventory_has_exactly_the_existing_four(self):
        self.assertEqual(acceptance.REQUIRED_CASES, EXISTING_REQUIRED + (C5,))

    def test_manifest_requires_the_exact_four_helper_cases_once(self):
        required = EXISTING_REQUIRED + (C5,)
        for case in required:
            binding = f"--require-case workspace_fuse_service={case}"
            self.assertEqual(self.manifest.count(binding), 1, binding)

    def test_remote_three_and_legacy_four_requirements_are_preserved(self):
        for case in REMOTE_REQUIRED:
            binding = f"--require-case workspace_remote_delete={case}"
            self.assertEqual(self.manifest.count(binding), 1, binding)
        for case in LEGACY_REQUIRED:
            binding = f"--require-case workspace_legacy_service={case}"
            self.assertIn(binding, self.ci)

    def test_manifest_binds_the_complete_source_harness_closure_once(self):
        for harness in HARNESSES:
            binding = f"--harness {harness}"
            self.assertEqual(self.manifest.count(binding), 1, binding)

    def test_helper_report_command_is_unchanged_except_for_the_added_case(self):
        step = _step(self.ci, "Exercise original FUSE helper and remote-delete acceptance")
        normalized = " ".join(step.split())
        self.assertIn(
            "ROOTYARD_TEST_FUSE_BACKEND=fuse-helper "
            "python3 tests/workspace_fuse_service_acceptance.py "
            "--report test-results/workspace-fuse-service.json",
            normalized,
        )
        self.assertIn("timeout-minutes: 30", step)

    def test_job_keeps_main_budget_and_adds_only_independent_fuse_phases(self):
        verify = self.ci.split("  container:", 1)[0]
        fixture = _step(
            self.ci, "Start the job-owned workspace FUSE/remote S3 fixture")
        helper = _step(
            self.ci, "Exercise original FUSE helper and remote-delete acceptance")
        legacy = _step(
            self.ci, "Exercise four legacy in-process FUSE service-shutdown cases")
        redis = _step(
            self.ci, "Verify browse cache incarnation across restore with owned Redis")

        def _cap(step):
            match = re.search(r"^        timeout-minutes: (\d+)$", step, re.MULTILINE)
            return int(match.group(1)) if match else None

        phases = (_cap(fixture), _cap(helper), _cap(legacy))
        self.assertEqual(phases, (12, 30, 10), "independent FUSE phases keep their caps")
        # C5 is required from the very report the 30-minute helper step produces,
        # so it runs inside that step and shares its cap instead of reserving
        # extra job minutes.
        self.assertIn("--report test-results/workspace-fuse-service.json", " ".join(helper.split()))
        self.assertIn(f"--require-case workspace_fuse_service={C5}", self.manifest)
        self.assertEqual(_cap(helper), 30)
        # The merged verify job keeps main's 175-minute budget, adds only
        # those three FUSE phases, then adds PR #321's independent #29
        # remote-CAS witness. Keeping 175 or 227 alone would under-budget the
        # merged job.
        main_cap = MAIN_VERIFY_BUDGET + sum(phases)
        self.assertEqual(main_cap, 227)
        merged_cap = main_cap + REMOTE_CAS_BUDGET
        self.assertEqual(merged_cap, 249)
        self.assertIn(f"    timeout-minutes: {merged_cap}", verify)
        self.assertNotIn(f"    timeout-minutes: {MAIN_VERIFY_BUDGET}", verify)
        self.assertNotIn(f"    timeout-minutes: {main_cap}", verify)
        # No pre-existing main step cap is inflated by this branch; the Redis
        # step already holds main's 28-minute promotion allowance.
        self.assertEqual(_cap(redis), 28)

    def test_existing_upload_path_keeps_reports_on_always(self):
        step = _step(self.ci, "Upload workspace FUSE/remote acceptance reports")
        self.assertIn("if: always()", step)
        for report in (
                "test-results/workspace-fuse-service.json",
                "test-results/workspace-remote-delete-policy.json",
                "test-results/workspace-legacy-service.json",
                "test-results/native-workspace-fuse-gate.json"):
            self.assertIn(report, step)

    def test_generic_python_discovery_remains_unfiltered(self):
        self.assertIn("python3 scripts/run_python_ci_tests.py", self.ci)
        runner = GENERIC_RUNNER.read_text(encoding="utf-8")
        self.assertIn('TEST_PATTERN = "test_*.py"', runner)
        self.assertNotIn("test_workspace_fuse_service", runner)
        self.assertNotIn("workspace_fuse_service", runner)

    def test_main_selects_the_backend_before_importing_real_case_modules(self):
        tree = ast.parse(Path(acceptance.__file__).read_text(encoding="utf-8"))
        main = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main")
        real_modules = {"tests.test_workspace_fuse_service", "tests.test_workspace_handoff"}

        def _backend_line(node):
            for item in ast.walk(node):
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Attribute)
                            and target.value.attr == "environ"):
                        return item.lineno
            return None

        env_line = _backend_line(main)
        import_lines = [
            item.lineno for item in ast.walk(main)
            if isinstance(item, ast.ImportFrom) and item.module in real_modules
        ]
        self.assertIsNotNone(env_line)
        self.assertTrue(import_lines)
        self.assertLess(env_line, min(import_lines))


if __name__ == "__main__":
    unittest.main()
