#!/usr/bin/env python3
"""Pure tests for final binding read failures and sanitized report projection.

No source subprocess, receipt validation, provider, network or product binary is
used.  Sensitive mock sentinels must never reach the report, stderr or a
traceback, and already-recorded cases/cleanup must survive a final binding
failure.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation as main  # noqa: E402
import pando_vault_rotation_support as support  # noqa: E402

A = "a" * 40
B = "b" * 40
C = "c" * 64
D = "d" * 64
E = "e" * 64
SENTINEL = "SENSITIVE-SENTINEL-TOKEN-DSN-PATH"


def before_binding():
    return {
        "source_commit": A,
        "source_tree": B,
        "source_clean": True,
        "binary_sha256": C,
        "receipt_sha256": D,
        "harness_sha256": E,
    }


def inputs(report):
    return {
        "report": report,
        "binary": Path("/never-read-binary"),
        "receipt": Path("/never-read-receipt"),
        "source_root": Path("/never-read-source"),
        "source_commit": A,
        "source_tree": B,
        "source_clean": True,
        "binary_sha256": C,
        "receipt_sha256": D,
        "harness_sha256": E,
    }


def passed_cases():
    return [
        {"id": case_id, "status": "passed", "facts": {}}
        for case_id in support.CASES[:4]
    ]


class BindingSnapshotReadFailureTest(unittest.TestCase):
    def test_binary_rehash_oserror_is_fixed_unavailable_without_raw_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            receipt = root / "receipt"
            binary.write_bytes(b"dummy binary")
            receipt.write_bytes(b"dummy receipt")
            value = inputs(root / "report.json")
            value.update({"binary": binary, "receipt": receipt,
                          "source_root": root})
            with mock.patch.object(main.receipts, "git_state", return_value={
                    "commit": A, "tree": B, "clean": True}), \
                 mock.patch.object(main, "sha256_file",
                                   side_effect=OSError(SENTINEL)):
                with self.assertRaises(support.QualificationError) as caught:
                    main.binding_snapshot(value)
            self.assertEqual(caught.exception.code, "binding_unavailable")
            self.assertNotIn(SENTINEL, str(caught.exception))
            self.assertNotIn(SENTINEL, repr(caught.exception))

    def test_harness_rehash_oserror_is_fixed_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            receipt = root / "receipt"
            binary.write_bytes(b"dummy binary")
            receipt.write_bytes(b"dummy receipt")
            value = inputs(root / "report.json")
            value.update({"binary": binary, "receipt": receipt,
                          "source_root": root})
            with mock.patch.object(main.receipts, "git_state", return_value={
                    "commit": A, "tree": B, "clean": True}), \
                 mock.patch.object(main, "sha256_file", side_effect=[C, D]), \
                 mock.patch.object(main, "_harness_sha256",
                                   side_effect=OSError(SENTINEL)):
                with self.assertRaises(support.QualificationError) as caught:
                    main.binding_snapshot(value)
            self.assertEqual(caught.exception.code, "binding_unavailable")


class FinalBindingFailureReportTest(unittest.TestCase):
    def _run_with_final_binding(self, failure):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        report_path = Path(temporary.name) / "report.json"
        args = main.parse_args(["--report", str(report_path)])
        context = SimpleNamespace(
            start_base=lambda: None,
            prepare_initial_packs=lambda: None,
        )
        cleanup = {
            "id": support.CASES[4],
            "status": "passed",
            "facts": {"cleanup_ok": True},
        }
        rows = passed_cases()
        with mock.patch.object(main, "validate_inputs",
                               return_value=inputs(report_path)), \
             mock.patch.object(main, "binding_snapshot",
                               side_effect=[before_binding(), failure]), \
             mock.patch.object(main, "Context", return_value=context), \
             mock.patch.object(
                 main.cases, "case_fixture_and_app_capability_boundary",
                 return_value=rows[0]), \
             mock.patch.object(
                 main.cases, "case_authentic_envelope_digest_and_cold_read",
                 return_value=rows[1]), \
             mock.patch.object(
                 main.cases,
                 "case_admin_rotated_target_interrupted_resume_and_new_write",
                 return_value=rows[2]), \
             mock.patch.object(
                 main.negative,
                 "case_wrong_key_ciphertext_envelope_and_provider_revocation",
                 return_value=rows[3]), \
             mock.patch.object(
                 main.negative, "case_owned_resource_cleanup",
                 return_value=cleanup):
            report = main.run_qualification(args, environ={})
        return report, report_path

    def test_final_oserror_is_sanitized_and_preserves_cleanup_and_cases(self):
        report, report_path = self._run_with_final_binding(OSError(SENTINEL))
        self.assertFalse(report["passed"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error_code"], "binding_unavailable")
        self.assertEqual(report["stage"], "binding")
        self.assertEqual(report["case_count"], 5)
        self.assertEqual(len(report["cases"]), 5)
        self.assertEqual(report["cases"][4]["status"], "passed")
        self.assertTrue(report["cleanup"]["cleanup_ok"])
        self.assertEqual(report["binding"], before_binding())
        text = json.dumps(report)
        self.assertNotIn(SENTINEL, text)
        self.assertTrue(report_path.is_file())
        self.assertNotIn(SENTINEL, report_path.read_text())

    def test_final_changed_hash_is_fixed_binding_changed(self):
        failure = support.QualificationError("binary_binding_changed", "binding")
        report, _ = self._run_with_final_binding(failure)
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "binding_changed")
        self.assertEqual(report["stage"], "binding")
        self.assertEqual(report["case_count"], 5)

    def test_final_unexpected_oserror_does_not_escape(self):
        report, _ = self._run_with_final_binding(RuntimeError(SENTINEL))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "binding_unavailable")
        self.assertNotIn(SENTINEL, json.dumps(report))


class InitialBindingFailureTest(unittest.TestCase):
    def _assert_no_start(self, report, context_calls):
        self.assertFalse(report["passed"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error_code"], "binding_unavailable")
        self.assertEqual(report["stage"], "binding")
        self.assertEqual(report["case_count"], 5)
        self.assertEqual(len(report["cases"]), 5)
        self.assertTrue(all(case["status"] == "failed"
                            for case in report["cases"]))
        self.assertFalse(report["cleanup"]["cleanup_ok"])
        self.assertEqual(context_calls, [])
        self.assertNotIn(SENTINEL, json.dumps(report))

    def test_initial_binding_oserror_never_constructs_context_or_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            args = main.parse_args(["--report", str(report_path)])
            context_calls = []

            def context_must_not_start(*args, **kwargs):
                context_calls.append((args, kwargs))
                raise AssertionError("Context must not be constructed")

            with mock.patch.object(main, "validate_inputs",
                                   return_value=inputs(report_path)), \
                 mock.patch.object(main, "binding_snapshot",
                                   side_effect=OSError(SENTINEL)), \
                 mock.patch.object(main, "Context",
                                   side_effect=context_must_not_start), \
                 mock.patch.object(
                     main.negative, "case_owned_resource_cleanup",
                     side_effect=AssertionError(
                         "cleanup must not run for unstarted resources")):
                report = main.run_qualification(args, environ={})
            self._assert_no_start(report, context_calls)
            self.assertTrue(report_path.is_file())
            self.assertNotIn(SENTINEL, report_path.read_text())

    def test_initial_binding_qualification_error_returns_fixed_before_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            args = main.parse_args(["--report", str(report_path)])
            context_calls = []
            with mock.patch.object(main, "validate_inputs",
                                   return_value=inputs(report_path)), \
                 mock.patch.object(
                     main, "binding_snapshot",
                     side_effect=support.QualificationError(
                         "source_binding_changed", "binding")), \
                 mock.patch.object(
                     main, "Context",
                     side_effect=lambda *a, **k: context_calls.append(1)):
                report = main.run_qualification(args, environ={})
            self.assertFalse(report["passed"])
            self.assertEqual(report["error_code"], "binding_changed")
            self.assertEqual(report["stage"], "binding")
            self.assertEqual(report["case_count"], 5)
            self.assertEqual(context_calls, [])
            self.assertFalse(report["cleanup"]["cleanup_ok"])

    def test_initial_binding_oserror_main_returns_nonzero_and_writes_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            with mock.patch.object(main, "validate_inputs",
                                   return_value=inputs(report_path)), \
                 mock.patch.object(main, "binding_snapshot",
                                   side_effect=OSError(SENTINEL)), \
                 mock.patch.object(
                     main, "Context",
                     side_effect=AssertionError("must not construct Context")):
                code = main.main(["--report", str(report_path)])
            self.assertEqual(code, 1)
            payload = json.loads(report_path.read_text())
            self.assertFalse(payload["passed"])
            self.assertEqual(payload["case_count"], 5)
            self.assertNotIn(SENTINEL, report_path.read_text())


class ReportWriteFailureTest(unittest.TestCase):
    def test_report_write_oserror_is_reported_without_raw_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            args = main.parse_args(["--report", str(report_path)])
            with mock.patch.object(
                    main, "validate_inputs",
                    side_effect=support.QualificationError(
                        "missing_binary", "input")), \
                 mock.patch.object(main, "_write_report",
                                   side_effect=OSError(SENTINEL)):
                report = main.run_qualification(args, environ={})
            self.assertFalse(report["passed"])
            self.assertEqual(report["error_code"], "report_write_failed")
            self.assertEqual(report["case_count"], 5)
            self.assertNotIn(SENTINEL, json.dumps(report))

    def test_main_never_prints_unexpected_final_oserror(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            with mock.patch.object(main, "run_qualification",
                                   side_effect=OSError(SENTINEL)):
                code = main.main(["--report", str(report_path)])
            self.assertEqual(code, 1)
            self.assertTrue(report_path.is_file())
            payload = json.loads(report_path.read_text())
            self.assertFalse(payload["passed"])
            self.assertNotIn(SENTINEL, report_path.read_text())


if __name__ == "__main__":
    unittest.main()
