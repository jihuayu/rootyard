#!/usr/bin/env python3
"""Pure finite failure-projection tests for the legacy shutdown report.

Every case here uses fake unittest cases, in-memory error tuples and compiled
synthetic tracebacks. Nothing starts the legacy acceptance class, a service,
Git, a subprocess, FUSE, PostgreSQL, the network or a thread.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import unittest
from unittest import mock

from tests import workspace_legacy_fuse_shutdown_acceptance as acceptance
from tests import workspace_legacy_fuse_shutdown_ownership as ownership
from tests import workspace_legacy_fuse_shutdown_report as report

ROOT = Path(__file__).resolve().parents[1]
REPORT_SOURCE = "tests/workspace_legacy_fuse_shutdown_report.py"


def _captured_error(filename, source, name, *args):
    namespace = {}
    exec(compile(source, filename, "exec"), namespace)
    try:
        namespace[name](*args)
    except BaseException as error:
        return (type(error), error, error.__traceback__)
    raise AssertionError("compiled source did not raise")


def _run_inventory(case_class):
    suite = unittest.TestLoader().loadTestsFromTestCase(case_class)
    stream = io.StringIO()
    return unittest.TextTestRunner(
        stream=stream, verbosity=0, resultclass=report.InventoryResult
    ).run(suite)


class _FakeTest:
    def __init__(self, name):
        self._name = name

    def id(self):
        return self._name


class _FakeResult:
    def __init__(self, names, diagnostics=None):
        self.started_ids = list(names)
        self.testsRun = len(names)
        self.failures = []
        self.errors = []
        self.skipped = []
        self.expectedFailures = []
        self.unexpectedSuccesses = []
        self.diagnostics = dict(diagnostics or {})
        self.unstarted_diagnostics = []


class FailureProjectionTest(unittest.TestCase):
    def test_source_whitelist_is_exactly_the_bound_ten_files(self):
        expected = tuple(acceptance.SOURCE_PATHS) + (
            "tests/e2e.py",
            "tests/runtime_binary.py",
            "tests/native_evidence.py",
            "tests/fuse_helper_native_support.py",
        )
        self.assertEqual(report.DIAGNOSTIC_SOURCE_PATHS, expected)
        self.assertEqual(len(set(expected)), 10)
        for relative in report.DIAGNOSTIC_SOURCE_PATHS:
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertNotIn(
            "tests/test_workspace_legacy_fuse_failure_projection.py",
            report.DIAGNOSTIC_SOURCE_PATHS,
        )

    def test_known_and_unknown_exception_classes_are_closed(self):
        for name in ("RuntimeError", "AssertionError", "ValueError", "FileNotFoundError"):
            error = _captured_error(
                "<external>",
                f"def boom():\n    raise {name}('secret-body')\n",
                "boom",
            )
            diagnostic = report._project_failure(
                error, case_id="tests.fake.Case.test_known", started=True
            )
            self.assertEqual(diagnostic["exception_class"], name)
            self.assertEqual(diagnostic["stage"], "unknown")
            self.assertEqual(diagnostic["frames"], [])
            self.assertEqual(diagnostic["locus"], "unknown")
            self.assertNotIn("secret-body", json.dumps(diagnostic, sort_keys=True))

        class MysteryError(Exception):
            pass

        try:
            raise MysteryError("secret-body")
        except MysteryError as error:
            captured = (type(error), error, error.__traceback__)
        diagnostic = report._project_failure(
            captured, case_id="tests.fake.Case.test_unknown", started=True
        )
        self.assertEqual(diagnostic["exception_class"], "unknown")
        self.assertNotIn("MysteryError", json.dumps(diagnostic, sort_keys=True))

    def test_verified_frame_is_repo_relative_and_statically_matched(self):
        facts = report._static_function_index()
        path, _line_count, functions = facts[REPORT_SOURCE]
        static_name, qualified, start, end = next(
            item for item in functions
            if item[0] == "_binding_value" and item[1] == "_binding_value"
        )
        self.assertLess(start, end)
        source = (
            "\n" * (start - 1)
            + "def _binding_value(binding, name):\n"
            + "    raise RuntimeError('payload-secret')\n"
        )
        error = _captured_error(str(path), source, static_name, None, None)
        diagnostic = report._project_failure(
            error, case_id="tests.fake.Case.test_verified", started=True
        )
        self.assertEqual(diagnostic["locus"], "verified_source")
        self.assertEqual(diagnostic["frames"], [{
            "path": REPORT_SOURCE,
            "line": start + 1,
            "function": qualified,
        }])
        self.assertNotIn("payload-secret", json.dumps(diagnostic, sort_keys=True))

    def test_external_malicious_and_malformed_frames_never_emit_raw_paths(self):
        for filename in ("/etc/passwd", "<external>", "tests/../outside.py"):
            error = _captured_error(
                filename, "def boom():\n    raise RuntimeError('secret')\n", "boom"
            )
            diagnostic = report._project_failure(
                error, case_id="tests.fake.Case.test_external", started=True
            )
            self.assertEqual(diagnostic["frames"], [])
            self.assertEqual(diagnostic["locus"], "unknown")
            self.assertNotIn("/etc/passwd", json.dumps(diagnostic, sort_keys=True))

        facts = report._static_function_index()
        path, line_count, functions = facts[REPORT_SOURCE]
        _name, _qualified, start, _end = next(
            item for item in functions
            if item[0] == "_binding_value" and item[1] == "_binding_value"
        )

        wrong_function = (
            "\n" * (start - 1)
            + "def definitely_not_a_source_function():\n"
            + "    raise RuntimeError('secret')\n"
        )
        error = _captured_error(
            str(path), wrong_function, "definitely_not_a_source_function"
        )
        self.assertEqual(
            report._project_failure(error, started=True)["frames"], []
        )

        wrong_line = (
            "\n" * (line_count + 20)
            + "def _binding_value(binding, name):\n"
            + "    raise RuntimeError('secret')\n"
        )
        error = _captured_error(str(path), wrong_line, "_binding_value", None, None)
        self.assertEqual(
            report._project_failure(error, started=True)["frames"], []
        )

        mismatched_real_function = (
            "\n" * (start - 1)
            + "def _git_field(argument):\n"
            + "    raise RuntimeError('secret')\n"
        )
        error = _captured_error(
            str(path), mismatched_real_function, "_git_field", "HEAD"
        )
        self.assertEqual(
            report._project_failure(error, started=True)["frames"], []
        )

        for malformed in ("not-a-tuple", (None, None), None):
            diagnostic = report._project_failure(malformed, started=True)
            self.assertEqual(diagnostic["exception_class"], "unknown")
            self.assertEqual(diagnostic["stage"], "unknown")
            self.assertEqual(diagnostic["frames"], [])
            self.assertEqual(diagnostic["locus"], "unknown")

    def test_verified_frames_are_capped(self):
        source = (
            "def recurse(n):\n"
            "    if n:\n"
            "        recurse(n - 1)\n"
            "    raise RuntimeError('deep-secret')\n"
        )
        error = _captured_error("<external>", source, "recurse", 12)
        record = {"path": "tests/e2e.py", "line": 1, "function": "verified"}
        with mock.patch.object(report, "_frame_record", return_value=record):
            diagnostic = report._project_failure(
                error, case_id="tests.fake.Case.test_deep", started=True
            )
        self.assertEqual(len(diagnostic["frames"]), report.DIAGNOSTIC_FRAME_CAP)
        self.assertTrue(diagnostic["frames_truncated"])
        self.assertEqual(diagnostic["locus"], "verified_source")

    def test_error_body_is_never_stringified_or_serialized(self):
        class HostileError(Exception):
            def __str__(self):
                raise AssertionError("str must not be called")

            def __repr__(self):
                raise AssertionError("repr must not be called")

        try:
            raise HostileError("SECRET-BODY")
        except HostileError as error:
            captured = (type(error), error, error.__traceback__)
        diagnostic = report._project_failure(
            captured, case_id="tests.fake.Case.test_hostile", started=True
        )
        encoded = json.dumps(diagnostic, sort_keys=True)
        self.assertEqual(diagnostic["exception_class"], "unknown")
        self.assertNotIn("SECRET-BODY", encoded)
        self.assertNotIn("HostileError", encoded)

    def test_setup_failure_before_case_details_is_projected_per_case(self):
        class SetupFailureCase(unittest.TestCase):
            def setUp(self):
                raise RuntimeError("setup-secret")

            def test_case(self):
                pass

        SetupFailureCase.__module__ = "tests.fake_setup_failure"
        SetupFailureCase.__qualname__ = "SetupFailureCase"
        result = _run_inventory(SetupFailureCase)
        case_id = result.errors[0][0].id()
        self.assertIn(case_id, result.started_ids)
        self.assertIn(case_id, result.diagnostics)
        diagnostic = result.diagnostics[case_id]
        self.assertEqual(diagnostic["stage"], "setup")
        self.assertTrue(diagnostic["started"])
        self.assertEqual(diagnostic["kind"], "error")
        self.assertNotIn(case_id, acceptance.CASE_DETAILS)

        with mock.patch.object(acceptance, "REQUIRED_CASES", (case_id,)), \
                mock.patch.object(acceptance, "CASE_DETAILS", {}):
            payload = report._report_payload(
                scheduled=(case_id,),
                result=result,
                imported=True,
                containment_owner=ownership.ContainmentOwner(),
            )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["cases"][0]["status"], "error")
        self.assertIsNone(payload["cases"][0]["detail"])
        self.assertEqual(payload["cases"][0]["diagnostic"], diagnostic)
        self.assertEqual(payload["tests_run"], 1)
        self.assertEqual(payload["counts"]["error"], 1)
        self.assertEqual(payload["counts"]["success"], 0)
        self.assertFalse(payload["cleanup"]["owned_mounts_remaining_known"])
        self.assertIsNone(payload["cleanup"]["owned_mounts_remaining"])

    def test_class_setup_failure_stays_unstarted_and_separate(self):
        class ClassSetupFailureCase(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise RuntimeError("class-setup-secret")

            def test_a(self):
                pass

            def test_b(self):
                pass

        ClassSetupFailureCase.__module__ = "tests.fake_class_setup_failure"
        ClassSetupFailureCase.__qualname__ = "ClassSetupFailureCase"
        result = _run_inventory(ClassSetupFailureCase)
        self.assertEqual(result.started_ids, [])
        self.assertEqual(result.testsRun, 0)
        self.assertEqual(result.diagnostics, {})
        self.assertEqual(len(result.unstarted_diagnostics), 1)
        diagnostic = result.unstarted_diagnostics[0]
        self.assertEqual(diagnostic["stage"], "class_setup")
        self.assertFalse(diagnostic["started"])
        self.assertIsNone(diagnostic["case_id"])
        self.assertEqual(diagnostic["exception_class"], "RuntimeError")

        names = (
            "tests.fake.ClassSetup.test_a",
            "tests.fake.ClassSetup.test_b",
        )
        with mock.patch.object(acceptance, "REQUIRED_CASES", names), \
                mock.patch.object(acceptance, "CASE_DETAILS", {}):
            payload = report._report_payload(
                scheduled=names,
                result=result,
                imported=True,
                containment_owner=ownership.ContainmentOwner(),
            )
        self.assertFalse(payload["passed"])
        self.assertEqual(len(payload["cases"]), 2)
        self.assertEqual(
            [case["status"] for case in payload["cases"]], ["not_run", "not_run"]
        )
        self.assertEqual(payload["tests_run"], 0)
        self.assertEqual(payload["counts"]["error"], 0)
        self.assertEqual(payload["counts"]["not_run"], 2)
        self.assertEqual(len(payload["failure_diagnostics"]["unstarted"]), 1)
        self.assertEqual(
            payload["failure_diagnostics"]["unstarted"][0]["stage"], "class_setup"
        )

    def test_additive_diagnostics_preserve_failed_counts_and_unknown_cleanup(self):
        names = tuple(f"tests.fake.AdditiveCase.test_{index}" for index in range(4))
        diagnostics = {}
        for name in names:
            error = _captured_error(
                "<external>", "def boom():\n    raise RuntimeError('body')\n", "boom"
            )
            diagnostics[name] = report._project_failure(
                error, case_id=name, started=True
            )
        result = _FakeResult(names, diagnostics)
        result.errors = [(_FakeTest(name), "formatted-in-memory") for name in names]

        with mock.patch.object(acceptance, "REQUIRED_CASES", names), \
                mock.patch.object(acceptance, "CASE_DETAILS", {}):
            payload = report._report_payload(
                scheduled=names,
                result=result,
                imported=True,
                containment_owner=ownership.ContainmentOwner(),
            )

        self.assertEqual(payload["status"], "failed")
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["counts"], {
            "success": 0,
            "failure": 0,
            "error": 4,
            "skipped": 0,
            "expected_failure": 0,
            "unexpected_success": 0,
            "not_run": 0,
        })
        self.assertEqual(payload["summary"]["success"], 0)
        self.assertEqual(payload["summary"]["error"], 4)
        self.assertFalse(payload["cleanup"]["owned_mounts_remaining_known"])
        self.assertIsNone(payload["cleanup"]["owned_mounts_remaining"])
        self.assertEqual(payload["cleanup"]["required"], 4)
        self.assertEqual(payload["cleanup"]["scheduled"], 4)
        self.assertEqual(payload["cleanup"]["tests_run"], 4)
        self.assertTrue(payload["cleanup"]["zero_skips"])
        self.assertIsNone(payload["failure_type"])
        self.assertEqual(
            payload["failure_diagnostics"]["frame_cap"], report.DIAGNOSTIC_FRAME_CAP
        )
        self.assertEqual(payload["failure_diagnostics"]["unstarted"], [])
        for index, name in enumerate(names):
            case = payload["cases"][index]
            self.assertEqual(case["status"], "error")
            self.assertEqual(case["diagnostic"], diagnostics[name])


if __name__ == "__main__":
    unittest.main()
