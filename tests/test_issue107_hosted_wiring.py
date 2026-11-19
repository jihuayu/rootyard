#!/usr/bin/env python3
"""Pure static tests for the fixed #107 hosted inventory wiring."""
from __future__ import annotations

import re
import sys
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import http_report_contract as http_contract  # noqa: E402
import issue107_native11_inventory as native_inventory  # noqa: E402

WORKFLOW = ROOT / ".github/workflows/refstore-protocol-acceptance.yml"
STEP_NAME = "Build and run the fixed issue107 HTTP13 and native11 acceptance inventory"
NATIVE_STEP_NAME = "Exercise roots, decisions, accepted subset and pack-read regressions"
A4_CASE = (
    "decision_subset_support::cases_f::"
    "a4_capture_fences_restore_and_only_matched_capture_wakes_target_audit")


def workflow():
    with WORKFLOW.open() as stream:
        return yaml.safe_load(stream)


def inventory_step():
    text = WORKFLOW.read_text()
    marker = f'      - name: "{STEP_NAME}"\n'
    assert marker in text
    return text.split(marker, 1)[1].split('\n      - name: "', 1)[0]


def native_step():
    text = WORKFLOW.read_text()
    marker = f'      - name: {NATIVE_STEP_NAME}\n'
    assert marker in text
    return text.split(marker, 1)[1].split('\n      - name: ', 1)[0]


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
        self.assertIn("2>/dev/null", step)
        self.assertNotIn("stderr_file", step)
        self.assertNotIn(".stderr", step)
        self.assertNotIn("$RUNNER_TEMP/issue107-native11-", step.split("2>/dev/null", 1)[0])
        self.assertIn('echo "issue107 native11 preparation failed: $target" >&2', step)
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
        self.assertEqual(acceptance.count("--allow-known-a4-extra"), 1)

    def test_step11_requires_exact_a4_ok_row_and_bound_separate_report(self):
        step = native_step()
        self.assertIn(f"a4_name = '{A4_CASE}'", step)
        self.assertIn("a4_prefix = f'test {a4_name} ...'", step)
        self.assertIn("a4_ok = f'{a4_prefix} ok'", step)
        self.assertIn(
            "a4_rows = [line for line in log.splitlines() if a4_prefix in line]",
            step)
        self.assertIn("assert len(a4_rows) == 1", step)
        self.assertIn("assert a4_rows[0] == a4_ok", step)
        self.assertNotIn("log.count(a4_row", step)
        self.assertNotIn("log.count(a4_prefix", step)
        self.assertIn("issue107-a4-native.json", step)
        self.assertIn("'case': a4_name", step)
        self.assertIn("'status': 'passed'", step)
        self.assertIn("'passed': True", step)
        self.assertIn("'row': a4_ok", step)
        self.assertIn("'source_head': source_head", step)
        self.assertIn("'checkout_head': checkout_head", step)
        self.assertIn("'checkout_tree': checkout_tree", step)
        self.assertIn("'native_log_sha256': hashlib.sha256(raw_log).hexdigest()", step)
        self.assertIn("native.json", step)
        self.assertIn("'suite_counts': [int(row[1]) for row in rows]", step)
        self.assertIn("suite_counts = sorted(int(passed) for _, passed, _, _ in rows)", step)
        self.assertIn("assert suite_counts == [8, 12, 23, 24]", step)
        self.assertIn("source_head = os.environ.get('GITHUB_SHA', '')", step)
        self.assertIn("assert re.fullmatch(r'[0-9a-f]{40}', source_head)", step)
        self.assertIn("checkout_head = subprocess.check_output(", step)
        self.assertIn("['git', 'rev-parse', 'HEAD']", step)
        self.assertIn("assert checkout_head == source_head", step)
        self.assertIn("checkout_tree = subprocess.check_output(", step)
        self.assertIn("['git', 'rev-parse', 'HEAD^{tree}']", step)
        self.assertIn("assert re.fullmatch(r'[0-9a-f]{40}', checkout_tree)", step)

    def test_step11_a4_row_and_source_checks_reject_false_positive_and_wrong_source(self):
        step = native_step()

        def snippet(start_marker, end_marker):
            start = step.index(start_marker)
            start = step.rfind("\n", 0, start) + 1
            end = step.index(end_marker, start)
            end = step.index("\n", end)
            return textwrap.dedent(step[start:end])

        row_source = snippet("a4_name = ", "assert a4_rows[0] == a4_ok")
        expected = f"test {A4_CASE} ... ok"
        namespace = {"log": "harness noise\n" + expected + "\n"}
        exec(row_source, namespace)
        self.assertEqual(namespace["a4_rows"], [expected])

        false_positives = (
            expected + " trailing",
            "prefix " + expected,
            f"test {A4_CASE} ... ignored",
            f"test {A4_CASE} ...",
            expected + "\n" + expected + "\n",
        )
        for log in false_positives:
            with self.assertRaises(AssertionError):
                exec(row_source, {"log": log})

        source_source = snippet(
            "source_head = os.environ.get",
            "assert re.fullmatch(r'[0-9a-f]{40}', checkout_tree)")
        head = "a" * 40
        tree = "b" * 40

        def check_output(argv, **kwargs):
            self.assertEqual(kwargs.get("cwd"), "/workspace")
            self.assertEqual(kwargs.get("text"), True)
            if argv == ["git", "rev-parse", "HEAD"]:
                return head + "\n"
            if argv == ["git", "rev-parse", "HEAD^{tree}"]:
                return tree + "\n"
            raise AssertionError(argv)

        source_namespace = {
            "os": SimpleNamespace(environ={
                "GITHUB_SHA": head, "GITHUB_WORKSPACE": "/workspace"}),
            "re": re,
            "subprocess": SimpleNamespace(check_output=check_output),
        }
        exec(source_source, source_namespace)
        self.assertEqual(source_namespace["source_head"], head)
        self.assertEqual(source_namespace["checkout_head"], head)
        self.assertEqual(source_namespace["checkout_tree"], tree)

        wrong_source = {
            **source_namespace,
            "os": SimpleNamespace(environ={
                "GITHUB_SHA": "c" * 40, "GITHUB_WORKSPACE": "/workspace"}),
        }
        with self.assertRaises(AssertionError):
            exec(source_source, wrong_source)

        bad_hex = {
            **source_namespace,
            "os": SimpleNamespace(environ={
                "GITHUB_SHA": "A" * 40, "GITHUB_WORKSPACE": "/workspace"}),
        }
        with self.assertRaises(AssertionError):
            exec(source_source, bad_hex)

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
