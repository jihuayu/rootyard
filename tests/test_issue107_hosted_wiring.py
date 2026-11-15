#!/usr/bin/env python3
"""Pure static tests for the fixed #107 hosted inventory wiring."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import http_report_contract as http_contract  # noqa: E402
import issue107_native11_inventory as native_inventory  # noqa: E402

WORKFLOW = ROOT / ".github/workflows/refstore-protocol-acceptance.yml"
STEP_NAME = "Build and run the fixed issue107 HTTP13 and native11 acceptance inventory"


def workflow():
    with WORKFLOW.open() as stream:
        return yaml.safe_load(stream)


def inventory_step():
    text = WORKFLOW.read_text()
    marker = f'      - name: "{STEP_NAME}"\n'
    assert marker in text
    return text.split(marker, 1)[1].split('\n      - name: "', 1)[0]


class HostedWiringTests(unittest.TestCase):
    def test_trigger_closure_covers_new_http_helpers_and_core_support(self):
        document = workflow()
        paths = set(document[True]["pull_request"]["paths"])
        required = {
            ".github/workflows/refstore-protocol-acceptance.yml",
            "tests/refstore_roots_http.py",
            "tests/refstore_snapshot_http.py",
            "tests/refstore_root_browse_http.py",
            "tests/refstore_cancel_scope_race.py",
            "tests/test_root_blob_fault_gate.py",
            "tests/test_root_browse_race_cleanup.py",
            "tests/test_issue107_http_report_validator.py",
            "tests/test_issue107_native11_runner.py",
            "tests/test_issue107_hosted_wiring.py",
            "tests/ref_store_core_support/**",
            "tests/verifier_budgets_support/**",
            "tests/blob_gateway_support/**",
            "scripts/**",
        }
        self.assertEqual(required - paths, set())

    def test_http_inventory_is_full_13_and_uses_strict_validator(self):
        step = inventory_step()
        for script, report in (
            ("tests/refstore_roots_http.py", "roots.json"),
            ("tests/refstore_snapshot_http.py", "snapshot.json"),
            ("tests/refstore_root_browse_http.py", "root-browse.json"),
            ("tests/refstore_cancel_scope_race.py", "cancel-scope-race.json"),
        ):
            self.assertIn(f"python3 {script} ", step)
            self.assertIn(f"--report \"$http_dir/{report}\"", step)
        self.assertNotIn("--case", step)
        self.assertEqual(sum(len(suite["cases"]) for suite in http_contract.EXPECTED_SUITES), 13)
        self.assertIn("scripts/issue107_http_report_validator.py", step)
        self.assertIn('--source-head "$GITHUB_SHA" --source-root "$GITHUB_WORKSPACE"', step)
        for suite in http_contract.EXPECTED_SUITES:
            for case in suite["cases"]:
                self.assertIn(case, step)
        self.assertIn("roots_http_registered_pack_get_refusal_no_fallback", step)
        self.assertNotIn("root_browse_authority_loss_denies_without_fallback", step)

    def test_http_job_manifest_binds_only_the_four_cli_reports(self):
        step = inventory_step()
        manifest = step.split("scripts/native_report_manifest.py --mode job", 1)[1].split(
            "target_args=()", 1)[0]
        self.assertIn("issue107-http-job.json", manifest)
        self.assertIn('--build-receipt "$cli_receipt"', manifest)
        self.assertIn('--binary "$binary"', manifest)
        for helper in (
            "tests/refstore_roots_http.py", "tests/refstore_snapshot_http.py",
            "tests/refstore_root_browse_http.py", "tests/refstore_cancel_scope_race.py",
            "tests/blob_gateway_support/root_blob_fault_gate.py",
            "tests/e2e.py", "tests/owned_fuse_cleanup.py",
            "scripts/http_report_contract.py", "scripts/native_report_manifest.py",
        ):
            self.assertIn(helper, manifest)
        for name in ("roots", "snapshot", "root-browse", "cancel-scope-race"):
            self.assertIn(f'--report "{name}=', manifest)
        self.assertNotIn("issue107-native11", manifest)
        self.assertNotIn("--target", manifest)

    def test_native_preparation_loops_exact_11_single_target_builds(self):
        step = inventory_step()
        for target in native_inventory.TARGET_ORDER:
            self.assertIn(target, step)
        self.assertIn("scripts/build_native_test.py", step)
        self.assertIn('--test "$target" --features pando-lab', step)
        self.assertIn('--artifact-store "$artifact_store" --output "$output"', step)
        self.assertEqual(len(native_inventory.TARGET_ORDER), 11)
        self.assertEqual(sum(len(native_inventory.TARGETS[t]["cases"]) for t in native_inventory.TARGET_ORDER), 167)
        self.assertNotIn("build_native_batch.py", step)

    def test_native_acceptance_is_prebuilt_only_and_all_11_bound(self):
        step = inventory_step()
        acceptance = step.split("python3 scripts/issue107_native11_runner.py", 1)[1]
        self.assertIn('--target "$target=$native11_dir/$target"', step)
        self.assertIn('--receipt "$target=$native11_dir/$target.build.json"', step)
        self.assertIn('--source-head "$GITHUB_SHA" --source-root "$GITHUB_WORKSPACE"', step)
        self.assertNotIn("cargo", acceptance.lower())
        self.assertNotIn("build_native", acceptance)
        self.assertNotIn("rustc", acceptance)
        for target in native_inventory.TARGET_ORDER:
            self.assertIn(target, step)
        self.assertIn("runner.validate_report(report, sys.argv[1])", acceptance)
        self.assertIn("test-results/refstore/issue107-native11.json", acceptance)

    def test_existing_unfiltered_sequence_still_has_all_legacy_reports(self):
        text = WORKFLOW.read_text()
        for marker in (
            "standalone-http.json",
            "standalone-commit-unknown.json",
            "standalone-browse.json",
            "standalone-history.json",
            "standalone-provisioning.json",
            "standalone-paired-backup.json",
        ):
            self.assertIn(marker, text)
        for marker in (
            "tests/blob_only_service.py",
            "tests/blob_commit_unknown_service.py",
            "tests/blob_gateway_browse.py",
            "tests/blob_gateway_history.py",
            "tests/blob_provisioning_service.py",
            "tests/backup_blob_serving147.py",
        ):
            self.assertIn(marker, text)

    def test_closure_has_workflow_collector_and_native_test_count(self):
        self.assertIn(".github/workflows/refstore-protocol-acceptance.yml", http_contract.INPUT_PATHS)
        self.assertIn("scripts/native_report_manifest.py", http_contract.INPUT_PATHS)
        self.assertEqual(len(http_contract.INPUT_PATHS), 19)
        self.assertEqual(len(native_inventory.TARGET_ORDER), 11)
        closure = native_inventory.closure(ROOT)
        self.assertIn("tests/test_issue107_native11_runner.py", closure)
        self.assertIn("tests/ref_store_verifier_budgets.rs", closure)
        self.assertGreaterEqual(len(closure), 52)


if __name__ == "__main__":
    unittest.main()
