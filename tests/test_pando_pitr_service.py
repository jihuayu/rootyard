"""Unit-test wrapper and pure reporting-boundary tests for Pando PITR acceptance (#77)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_service  # noqa: E402
import runtime_binary  # noqa: E402
from test_native_build_receipt_v2 import ReceiptFixture  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


class PandoPitrEvidenceBoundaryTest(ReceiptFixture):
    """Prove the report accepts only exact, immutable, fully-passed evidence."""

    def setUp(self) -> None:
        super().setUp()
        self.commit = COMMIT
        self.receipt_path = self.binary.with_suffix(".build.json")
        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit), indent=2) + "\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.harness = self.root / "owned-harness.py"
        self.harness.write_text("HARNESS_VERSION = 1\n", encoding="utf-8")
        self.report_path = self.root / "pando-pitr-service.json"
        self.lib_source = (self.root / "src/lib.rs").read_text(encoding="utf-8")
        head_patch = mock.patch.object(
            pando_pitr_service,
            "_workspace_head",
            lambda source_root, phase="preflight": self.commit,
        )
        head_patch.start()
        self.addCleanup(head_patch.stop)

    def passing_results(self) -> dict:
        results = {name: True for name in pando_pitr_service.MANDATORY_CASES}
        results["passed"] = True
        return results

    def run_acceptance(self, suite=None, **overrides) -> dict:
        arguments = {
            "binary": str(self.binary),
            "build_receipt": str(self.receipt_path),
            "expect_commit": self.commit,
            "report_path": self.report_path,
            "source_root": self.root,
            "harness_files": [self.harness],
            "suite": suite or (lambda binary: self.passing_results()),
        }
        arguments.update(overrides)
        return pando_pitr_service.run_acceptance(**arguments)

    def assert_preflight_failure(self, report: dict, calls: list[str]) -> None:
        self.assertFalse(report["passed"])
        self.assertEqual([], calls)
        self.assertEqual(report["failure"]["phase"], "preflight")
        self.assertEqual(report["cases"], [
            {"name": name, "status": "missing"}
            for name in pando_pitr_service.MANDATORY_CASES
        ])

    def test_missing_binary_and_receipt_fail_before_the_suite(self) -> None:
        for missing in ("binary", "receipt"):
            with self.subTest(missing=missing):
                calls: list[str] = []

                def spy(binary: str) -> dict:
                    calls.append(binary)
                    return self.passing_results()

                overrides = (
                    {"binary": str(self.root / "missing-rootyard")}
                    if missing == "binary"
                    else {"build_receipt": str(self.root / "missing.build.json")}
                )
                report = self.run_acceptance(spy, **overrides)
                self.assert_preflight_failure(report, calls)

    def test_mismatched_binary_receipt_and_commit_fail_before_the_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        self.binary.write_bytes(b"tampered-binary")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        self.binary.write_bytes(b"native-binary")

        payload = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        payload["workspace_commit"] = "b" * 40
        self.receipt_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)

        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit)), encoding="utf-8"
        )
        report = self.run_acceptance(spy, expect_commit="b" * 40)
        self.assert_preflight_failure(report, calls)
        self.assertEqual(report["failure"]["code"], "source_head_mismatch")

    def test_source_file_closure_drift_fails_before_the_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        (self.root / "src/lib.rs").write_text("pub fn changed() {}\n", encoding="utf-8")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        (self.root / "src/lib.rs").write_text(self.lib_source, encoding="utf-8")

        (self.root / "src/main.rs").unlink()
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)

    def test_binary_mutation_during_suite_cannot_pass(self) -> None:
        def mutate(binary: str) -> dict:
            self.binary.write_bytes(b"mutated-during-suite")
            return self.passing_results()

        report = self.run_acceptance(mutate)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "postflight")
        self.assertFalse(report["provenance_unchanged"])
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))

    def test_harness_mutation_during_suite_cannot_pass(self) -> None:
        def mutate(binary: str) -> dict:
            self.harness.write_text("HARNESS_VERSION = 2\n", encoding="utf-8")
            return self.passing_results()

        report = self.run_acceptance(mutate)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "postflight")
        self.assertFalse(report["provenance_unchanged"])
        self.assertEqual(report["failure"]["code"], "provenance_changed")

    def test_false_or_missing_mandatory_case_cannot_pass(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                results = self.passing_results()
                if missing:
                    del results["pitr_epoch_rollback_fenced"]
                else:
                    results["clone_fail_closed_zero_deletes"] = False
                report = self.run_acceptance(lambda binary: results)
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["phase"], "suite")
                self.assertEqual(report["failure"]["code"], "mandatory_case_not_passed")
                self.assertTrue(report["provenance_unchanged"])
                status = "missing" if missing else "failed"
                self.assertIn(
                    {"name": "pitr_epoch_rollback_fenced" if missing
                     else "clone_fail_closed_zero_deletes", "status": status},
                    report["cases"],
                )

    def test_deadline_exceeded_cannot_pass(self) -> None:
        report = self.run_acceptance(timeout=0)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "suite")
        self.assertEqual(report["failure"]["code"], "deadline_exceeded")
        self.assertTrue(report["provenance_unchanged"])

    def test_passing_report_binds_cases_topology_and_provenance(self) -> None:
        report = self.run_acceptance()
        self.assertTrue(report["passed"])
        self.assertEqual(report["source_commit"], self.commit)
        self.assertEqual(report["source_head"], self.commit)
        self.assertEqual(report["binary_sha256"], pando_pitr_service.receipts.sha256_file(self.binary))
        self.assertEqual(
            report["build_receipt_sha256"],
            pando_pitr_service.receipts.sha256_file(self.receipt_path),
        )
        self.assertEqual(
            [case["name"] for case in report["cases"]],
            list(pando_pitr_service.MANDATORY_CASES),
        )
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        for name in pando_pitr_service.MANDATORY_CASES:
            self.assertIs(report[name], True)
        self.assertTrue(report["provenance_unchanged"])
        self.assertEqual(report["provenance"]["before"], report["provenance"]["after"])
        self.assertIn("harnesses", report["provenance"]["before"])
        topology = json.dumps(report["topology"]).lower()
        for marker in ("in-process", "not external", "logical pg_dump", "not physical"):
            self.assertIn(marker, topology)
        self.assertNotIn("cleanup_passed", report)
        self.assertNotIn("failure_traceback", report)
        self.assertEqual(json.loads(self.report_path.read_text(encoding="utf-8")), report)

    def test_ci_selects_the_evidence_binding_and_required_cases(self) -> None:
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        start = text.index("      - name: Exercise live Pando PITR fencing")
        end = text.index("\n      - name:", start + 1)
        step = text[start:end]
        for marker in (
            'python3 tests/pando_pitr_service.py',
            '--binary "$ROOTYARD_BIN"',
            '--build-receipt "$ROOTYARD_BUILD_RECEIPT"',
            '--expect-commit "$GITHUB_SHA"',
            "--report test-results/pando-pitr-service.json",
        ):
            self.assertIn(marker, step)

        manifest_start = text.index(
            "      - name: Bind native regressions to the built binary and source inputs"
        )
        manifest_end = text.index("\n      - name:", manifest_start + 1)
        manifest = text[manifest_start:manifest_end]
        self.assertIn(
            "--report pando_pitr=test-results/pando-pitr-service.json", manifest
        )
        for name in pando_pitr_service.MANDATORY_CASES:
            self.assertEqual(
                manifest.count(f"--require-case pando_pitr={name}"), 1, name
            )
        self.assertIn("--harness tests/pando_pitr_service.py", manifest)
        self.assertIn("--harness tests/test_pando_pitr_service.py", manifest)


class PandoPitrServiceTest(unittest.TestCase):
    def test_pando_pitr_pg_dump_clone_and_retention_roots(self) -> None:
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        if os.name == "nt" and not in_ci:
            self.skipTest("live rootyard service tests target Linux runtime")
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            if in_ci:
                self.fail("ROOTYARD_TEST_DATABASE_URL is required in GitHub Actions")
            self.skipTest("ROOTYARD_TEST_DATABASE_URL is unset")
        try:
            binary, _binding = runtime_binary.select_runtime_binary()
        except runtime_binary.RuntimeBinarySelectionError as exc:
            if in_ci:
                self.fail(f"prebuilt rootyard binary unavailable in CI: {exc}")
            self.skipTest(str(exc))

        report = pando_pitr_service.run_suite(str(binary))
        self.assertTrue(report["passed"])
        self.assertTrue(report["clone_fail_closed_zero_deletes"])
        self.assertTrue(report["operator_isolate_recovered"])
        self.assertTrue(report["post_isolate_empty_cache_http_browse"])
        self.assertTrue(report["post_isolate_stock_git_clone_fetch"])
        self.assertTrue(report["post_isolate_deleted_artifact_refused"])
        self.assertTrue(report["pitr_epoch_rollback_fenced"])


if __name__ == "__main__":
    unittest.main()
