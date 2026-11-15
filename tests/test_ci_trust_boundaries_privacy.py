#!/usr/bin/env python3
"""Offline privacy and provenance regression for the trusted-boundary harness.

``PullsHarness.case`` records and prints a redacted failure, but re-raises so a
caller can decide whether to continue. ``ci_trust_boundaries.main`` used to let
that original exception escape, which made Python print the unredacted
assertion payload a second time. These tests use a sentinel claimed checkout
token and prove that neither the boundary diagnostics nor the retained failed
result/report contain it. They also exercise the structured report: exactly the
eight named cases on success, a redacted completed prefix on failure, and
start/end refusal of head, binary, source, receipt and harness drift. No native
binary, PostgreSQL or network is required.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_trust_boundaries as module  # noqa: E402
from e2e import Harness  # noqa: E402
from pulls import PullsHarness  # noqa: E402


SENTINEL = "claim-checkout-token-5d41402abc4b2a76b9719d911017c592"
CASE_METHODS = set(module.CASE_METHODS)
RAW_DIAGNOSTICS = (
    "postgresql://fixture:fixture@127.0.0.1:1/rootyard_test",
    "Authorization: Bearer " + SENTINEL,
    "SELECT * FROM forge_webhooks",
    "Traceback (most recent call last)",
    "ROOTYARD_TEST_DATABASE_URL=",
)


class _BoundaryHarness:
    """Minimal harness state; only the real PullsHarness.case is exercised."""

    def __init__(self):
        self.secrets = [SENTINEL]
        self.results = []
        self.base_db = "postgresql://fixture:fixture@127.0.0.1:1/rootyard_test"
        self.db = self.base_db + "?options=-csearch_path%3Dfixture"
        self.cleaned = False
        self.cleanup_error = None

    def redact(self, value):
        return Harness.redact(self, value)

    def case(self, name, fn):
        return PullsHarness.case(self, name, fn)

    def setup(self):
        pass

    def cleanup(self):
        self.cleaned = True
        if self.cleanup_error is not None:
            raise RuntimeError(self.cleanup_error)

    def __getattr__(self, name):
        if name in CASE_METHODS:
            return lambda: None
        raise AttributeError(name)


def claimed_checkout_assertion():
    claimed = {"checkout": {"token": SENTINEL}}
    assert claimed == {"checkout": {"token": SENTINEL + "-stale"}}, claimed


def snapshot(**overrides):
    value = {
        "schema": "v1",
        "source_binding": "v1_current_source",
        "head": "a" * 40,
        "clean": True,
        "binary_sha256": "b" * 64,
        "source_inputs_sha256": "c" * 64,
        "receipt_sha256": "d" * 64,
        "receipt_workspace_commit": "a" * 40,
        "receipt_source_inputs_sha256": "c" * 64,
        "source_snapshot_matches_current": True,
        "inputs": {
            "tests/ci_trust_boundaries.py": "e" * 64,
            "scripts/build_native.py": "f" * 64,
        },
        "inputs_sha256": "1" * 64,
    }
    value.update(overrides)
    return value


def passing_run():
    harness = _BoundaryHarness()
    result = module.run_harness(harness, module.bound_cases(harness))
    return harness, result


class HarnessPrivacyTest(unittest.TestCase):
    def run_main(self, harness, extra_args=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = ["ci_trust_boundaries.py", "--binary", "rootyard"]
        argv.extend(extra_args or [])
        with mock.patch.object(
            module, "TrustBoundaryHarness", return_value=harness
        ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            code = module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_failed_claim_assertion_is_redacted_at_outer_boundary(self):
        harness = _BoundaryHarness()

        def failing_case():
            # The real positive matrix registers the claimed capability before
            # any assertion that embeds the response object.
            harness.secrets.append(SENTINEL)
            claimed_checkout_assertion()

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            success = module.run_cases(
                harness, [("claimed checkout assertion", failing_case)]
            )

        self.assertFalse(success)
        self.assertEqual(len(harness.results), 1)
        failed = harness.results[0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["name"], "claimed checkout assertion")
        diagnostics = stderr.getvalue()
        self.assertNotIn(SENTINEL, diagnostics)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", diagnostics)

    def test_main_keeps_failed_result_cleans_up_and_exits_nonzero(self):
        harness = _BoundaryHarness()
        harness.configure = claimed_checkout_assertion
        code, stdout, stderr = self.run_main(harness)

        self.assertEqual(code, 1)
        self.assertTrue(harness.cleaned)
        self.assertEqual(len(harness.results), 1)
        failed = harness.results[0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["name"], module.CASE_NAMES[0])
        self.assertNotIn(SENTINEL, stderr)
        self.assertNotIn(SENTINEL, stdout)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", stderr)

    def test_main_cleanup_failure_is_redacted_and_nonzero(self):
        harness = _BoundaryHarness()
        harness.cleanup_error = "fixture cleanup leaked " + SENTINEL
        code, stdout, stderr = self.run_main(harness)

        self.assertEqual(code, 1)
        self.assertTrue(harness.cleaned)
        cleanup = [row for row in harness.results if row["name"] == "cleanup"]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0]["status"], "failed")
        self.assertNotIn(SENTINEL, stderr)
        self.assertNotIn(SENTINEL, stdout)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", stderr)


class ReportPrivacyTest(unittest.TestCase):
    def test_success_report_has_exactly_eight_passed_cases_and_provenance(self):
        harness, result = passing_run()
        self.assertTrue(result["success"])
        start = snapshot()
        end = snapshot()
        report = module.build_report(start, end, result, harness)

        self.assertTrue(report["passed"])
        self.assertEqual([case["name"] for case in report["cases"]], list(module.CASE_NAMES))
        self.assertEqual(len(report["cases"]), 8)
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        self.assertTrue(report["cleanup_success"])
        self.assertEqual(report["binary_sha256"], "b" * 64)
        self.assertEqual(report["source_head"], "a" * 40)
        self.assertEqual(report["source_inputs_sha256"], "c" * 64)
        self.assertEqual(report["build_receipt_sha256"], "d" * 64)
        self.assertEqual(report["provenance"]["inputs"], start["inputs"])
        self.assertEqual(report["provenance"]["inputs_sha256"], "1" * 64)
        self.assertTrue(report["provenance"]["head_stable"])
        self.assertTrue(report["provenance"]["binary_stable"])
        self.assertTrue(report["provenance"]["source_stable"])
        self.assertTrue(report["provenance"]["receipt_stable"])
        self.assertTrue(report["provenance"]["inputs_stable"])
        self.assertIsNone(report["failure"])
        self.assertNotIn("detail", report["cases"][0])

    def test_failed_case_keeps_completed_prefix_without_raw_diagnostics(self):
        harness = _BoundaryHarness()
        harness.configure = claimed_checkout_assertion
        result = module.run_harness(harness, module.bound_cases(harness))
        report = module.build_report(snapshot(), snapshot(), result, harness)

        self.assertFalse(report["passed"])
        self.assertEqual([case["name"] for case in report["cases"]], [module.CASE_NAMES[0]])
        failed = report["cases"][0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error_type"], "AssertionError")
        self.assertNotIn("error", failed)
        self.assertNotIn("traceback", failed)
        self.assertNotIn("detail", failed)
        self.assertEqual(report["failure"]["stage"], "cases")
        self.assertEqual(report["failure"]["code"], "case_failed")
        serialized = json.dumps(report)
        self.assertNotIn(SENTINEL, serialized)
        self.assertNotIn("Traceback", serialized)

    def test_cleanup_failure_is_reported_and_redacted(self):
        harness = _BoundaryHarness()
        harness.cleanup_error = "fixture cleanup leaked " + SENTINEL
        result = module.run_harness(harness, module.bound_cases(harness))
        report = module.build_report(snapshot(), snapshot(), result, harness)

        self.assertFalse(report["passed"])
        self.assertFalse(report["cleanup_success"])
        self.assertEqual(report["failure"]["stage"], "cleanup")
        self.assertEqual(report["failure"]["code"], "cleanup_failed")
        self.assertEqual(report["cases"][-1]["name"], "cleanup")
        self.assertEqual(report["cases"][-1]["status"], "failed")
        self.assertNotIn(SENTINEL, json.dumps(report))

    def test_head_binary_source_receipt_and_harness_drift_are_refused(self):
        harness, result = passing_run()
        base = snapshot()
        drifts = (
            ({"head": "9" * 40}, "head_changed"),
            ({"binary_sha256": "9" * 64}, "binary_changed"),
            ({"source_inputs_sha256": "9" * 64}, "source_changed"),
            ({"receipt_sha256": "9" * 64}, "receipt_changed"),
            ({"inputs": {"tests/ci_trust_boundaries.py": "9" * 64}}, "harness_changed"),
        )
        for change, code in drifts:
            with self.subTest(code=code):
                report = module.build_report(base, snapshot(**change), result, harness)
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["stage"], "provenance")
                self.assertEqual(report["failure"]["code"], code)

    def test_success_requires_the_exact_unique_case_inventory(self):
        harness = _BoundaryHarness()
        result = module.run_harness(
            harness, [(module.CASE_NAMES[0], lambda: None)]
        )
        report = module.build_report(snapshot(), snapshot(), result, harness)

        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["code"], "case_set")
        self.assertEqual(len(report["cases"]), 1)

    def test_raw_http_sql_and_traceback_fields_are_not_persisted(self):
        harness = _BoundaryHarness()
        harness.results = [
            {
                "name": module.CASE_NAMES[0],
                "status": "failed",
                "seconds": 0.01,
                "error": " | ".join(RAW_DIAGNOSTICS),
                "traceback": " | ".join(RAW_DIAGNOSTICS),
                "detail": {"body": " | ".join(RAW_DIAGNOSTICS)},
            }
        ]
        report = module.build_report(
            None,
            None,
            {"success": False, "cleanup_ok": True, "failure": {"stage": "cases", "type": "AssertionError"}},
            harness,
            start_error="receipt_invalid",
        )
        serialized = json.dumps(report)
        self.assertFalse(report["passed"])
        for raw in RAW_DIAGNOSTICS:
            self.assertNotIn(raw, serialized)
        self.assertEqual(report["cases"][0]["diagnostic"], "case failed; see redacted runner diagnostics")

    def test_main_writes_a_success_report_without_case_details(self):
        harness = _BoundaryHarness()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            argv = [
                "ci_trust_boundaries.py",
                "--binary",
                "rootyard",
                "--report",
                str(path),
            ]
            with mock.patch.object(
                module, "TrustBoundaryHarness", return_value=harness
            ), mock.patch.object(
                module, "capture_provenance", side_effect=[snapshot(), snapshot()]
            ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
                stdout
            ), contextlib.redirect_stderr(stderr):
                code = module.main()
            self.assertEqual(code, 0)
            report = json.loads(path.read_text())
            self.assertTrue(report["passed"])
            self.assertEqual([case["name"] for case in report["cases"]], list(module.CASE_NAMES))
            self.assertNotIn("detail", report["cases"][0])
            self.assertNotIn(SENTINEL, path.read_text())
            self.assertNotIn(SENTINEL, stdout.getvalue())
            self.assertNotIn(SENTINEL, stderr.getvalue())

    def test_main_writes_a_passed_false_report_when_binding_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            argv = [
                "ci_trust_boundaries.py",
                "--binary",
                "rootyard",
                "--report",
                str(path),
            ]
            with mock.patch.object(
                module, "capture_provenance", side_effect=module.ReportError("stale_receipt")
            ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(io.StringIO()):
                code = module.main()
            self.assertEqual(code, 1)
            report = json.loads(path.read_text())
            self.assertFalse(report["passed"])
            self.assertEqual(report["failure"]["stage"], "binding")
            self.assertEqual(report["failure"]["code"], "stale_receipt")
            self.assertEqual(report["cases"][0]["name"], "report binding")
            self.assertEqual(report["cases"][0]["status"], "failed")
            self.assertNotIn(SENTINEL, path.read_text())


class ReportBindingMappingTest(unittest.TestCase):
    def test_reviewed_source_binding_refusals_map_to_fixed_codes(self):
        mappings = (
            (
                module.source_bound_binary.SourceBindingError(
                    "no matching adjacent receipt: no build receipt"
                ),
                "receipt_missing",
            ),
            (
                module.source_bound_binary.SourceBindingError(
                    "the executed binary does not match this checkout's production source inputs "
                    "(receipt aaa, current bbb)"
                ),
                "source_drift",
            ),
            (
                module.source_bound_binary.SourceBindingError(
                    "stale build receipt: workspace_commit differs from the expected source commit"
                ),
                "stale_receipt",
            ),
            (
                module.source_bound_binary.SourceBindingError(
                    "build receipt rejected: RuntimeError"
                ),
                "receipt_invalid",
            ),
            (
                module.source_bound_binary.SourceBindingError(
                    "build receipt is missing rustc"
                ),
                "receipt_invalid",
            ),
        )
        for error, code in mappings:
            with self.subTest(code=code):
                with mock.patch.object(
                    module.source_bound_binary, "bind", side_effect=error
                ):
                    with self.assertRaises(module.ReportError) as raised:
                        module.capture_provenance("rootyard")
                self.assertEqual(raised.exception.code, code)


    def test_capture_provenance_dispatches_v1_and_v2_identities_without_faking_current(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "rootyard"
            binary.write_bytes(b"binary")
            receipt = Path(directory) / "rootyard.build.json"
            receipt.write_bytes(b"receipt")
            v1_binding = {
                "schema": "v1",
                "binary_sha256": "b" * 64,
                "current_source_inputs_sha256": "c" * 64,
                "source_inputs_sha256": "c" * 64,
                "workspace_commit": "a" * 40,
            }
            v2_binding = {
                "schema": "v2",
                "binary_sha256": "b" * 64,
                "source_inputs_sha256": "c" * 64,
                "workspace_commit": "a" * 40,
            }

            def git_output(*args):
                return "a" * 40 if args[:2] == ("rev-parse", "HEAD") else ""

            with mock.patch.object(
                module.source_bound_binary, "bind", return_value=v1_binding
            ), mock.patch.object(
                module.source_bound_binary, "_git", side_effect=git_output
            ), mock.patch.object(
                module, "_digest_provenance_inputs", return_value={"x": "y"}
            ):
                v1 = module.capture_provenance(str(binary))
            self.assertEqual(v1["schema"], "v1")
            self.assertEqual(v1["source_binding"], "v1_current_source")
            self.assertEqual(v1["source_inputs_sha256"], "c" * 64)

            with mock.patch.object(
                module.source_bound_binary, "bind", return_value=v2_binding
            ), mock.patch.object(
                module.source_bound_binary, "_git", side_effect=git_output
            ), mock.patch.object(
                module.source_bound_binary,
                "production_source_digest",
                return_value="e" * 64,
            ), mock.patch.object(
                module, "_digest_provenance_inputs", return_value={"x": "y"}
            ):
                v2 = module.capture_provenance(str(binary))
                self.assertEqual(v2["schema"], "v2")
                self.assertEqual(v2["source_binding"], "v2_recorded_snapshot")
                self.assertEqual(v2["source_inputs_sha256"], "e" * 64)
                self.assertEqual(v2["receipt_source_inputs_sha256"], "c" * 64)
                self.assertFalse(v2["source_snapshot_matches_current"])
                with self.assertRaises(module.ReportError) as raised:
                    module.capture_provenance(str(binary), expected_commit="a" * 40)
                self.assertEqual(raised.exception.code, "source_drift")


if __name__ == "__main__":
    unittest.main()
