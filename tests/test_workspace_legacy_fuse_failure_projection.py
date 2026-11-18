#!/usr/bin/env python3
"""Pure finite failure-projection tests for the legacy shutdown report.

Every case here uses fake unittest cases, in-memory error tuples, compiled
synthetic tracebacks and temporary bounded evidence files. Nothing starts the
legacy acceptance class, a service, Git, a subprocess, FUSE, PostgreSQL, the
network or a thread.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests import workspace_legacy_fuse_shutdown_acceptance as acceptance
from tests import workspace_legacy_fuse_shutdown_ownership as ownership
from tests import workspace_legacy_fuse_shutdown_report as report
from tests import workspace_legacy_fuse_shutdown_support as support

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


_LEGACY_WORKSPACE_IDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
)
_LEGACY_FOREIGN_WORKSPACE_ID = "33333333-3333-4333-8333-333333333333"


def _legacy_join_payload(workspace_hashes, *, joined_mounts=None, total=None):
    """Copy the fixed v1 legacy-shutdown-evidence shape emitted by Rust."""
    return {
        "schema": support.EVIDENCE_SCHEMA,
        "mount_namespace": 4021,
        "joined_mounts": (
            len(workspace_hashes) if joined_mounts is None else joined_mounts
        ),
        "joined_workspaces": list(workspace_hashes),
        "joined_workspaces_total": (
            len(workspace_hashes) if total is None else total
        ),
        "joined_workspaces_truncated": False,
        "pending_admissions": 0,
        "retained_owners": 0,
        "cleanup_failures": 0,
    }


class JoinEvidenceParsingTest(unittest.TestCase):
    """The v1 evidence parser must accept the real list shape and stay exact."""

    def _read(self, payload, expected):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "service.log"
            log_path.write_bytes(
                (support.EVIDENCE_PREFIX + json.dumps(payload) + "\n").encode("utf-8")
            )
            return support.read_join_evidence(
                log_path, payload["mount_namespace"], expected
            )

    def _assert_rejected(self, payload, expected, message):
        with self.assertRaisesRegex(support.LegacyAcceptanceError, message):
            self._read(payload, expected)

    def test_exact_v1_joined_workspaces_list_is_accepted(self):
        hashes = [
            support.workspace_hash(workspace_id)
            for workspace_id in _LEGACY_WORKSPACE_IDS
        ]
        payload = _legacy_join_payload(hashes)
        self.assertIsInstance(payload["joined_workspaces"], list)
        self.assertEqual(
            self._read(payload, hashes),
            {
                "schema": support.EVIDENCE_SCHEMA,
                "mount_namespace": 4021,
                "joined_mounts": 2,
                "joined_workspaces": 2,
                "workspace_hashes": hashes,
                "expected_workspace_hashes": hashes,
                "pending_admissions": 0,
                "retained_owners": 0,
                "cleanup_failures": 0,
            },
        )

    def test_non_list_and_existing_workspace_proof_mismatches_still_fail(self):
        hashes = [
            support.workspace_hash(workspace_id)
            for workspace_id in _LEGACY_WORKSPACE_IDS
        ]
        foreign = support.workspace_hash(_LEGACY_FOREIGN_WORKSPACE_ID)

        non_list = _legacy_join_payload(hashes)
        non_list["joined_workspaces"] = ",".join(hashes)
        self._assert_rejected(
            non_list, hashes, "joined_workspaces has an invalid type"
        )

        count_mismatch = _legacy_join_payload(hashes, total=len(hashes) + 1)
        self._assert_rejected(
            count_mismatch, hashes, "workspace count mismatch"
        )

        set_mismatch = _legacy_join_payload([hashes[0], foreign])
        self._assert_rejected(
            set_mismatch, hashes, "workspace set is not the exact expected set"
        )

        missing_expected = _legacy_join_payload([hashes[0]], joined_mounts=len(hashes))
        self._assert_rejected(
            missing_expected, hashes, "workspace set is not the exact expected set"
        )

        for name in (
            "mount_namespace",
            "joined_mounts",
            "joined_workspaces_total",
            "pending_admissions",
            "retained_owners",
            "cleanup_failures",
        ):
            with self.subTest(field=name):
                bool_not_int = _legacy_join_payload(hashes)
                bool_not_int[name] = True
                self._assert_rejected(
                    bool_not_int, hashes, f"{name} has an invalid type"
                )


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

    def test_nested_finally_reports_the_raise_line_not_the_cleanup_line(self):
        path, _line_count, functions = report._static_function_index()[REPORT_SOURCE]
        ranges = {qualified: (start, end) for _name, qualified, start, end in functions}
        inner_start, inner_end = ranges["_frame_record"]
        outer_start, outer_end = ranges["_project_failure"]
        self.assertLess(inner_end, outer_start)
        # The synthetic module needs room for nested try/finally bodies inside
        # the static ranges it claims to belong to.
        self.assertGreaterEqual(inner_end - inner_start, 7)
        self.assertGreaterEqual(outer_end - outer_start, 4)

        raise_line = inner_start + 3
        inner_finally_line = inner_start + 5
        inner_cleanup_line = inner_start + 7
        outer_call_line = outer_start + 2
        outer_cleanup_line = outer_start + 4
        self.assertLessEqual(outer_cleanup_line, outer_end)
        self.assertLess(raise_line, inner_finally_line)
        self.assertLess(inner_finally_line, inner_cleanup_line)

        lines = [""] * outer_cleanup_line

        def put(number, text):
            lines[number - 1] = text

        put(inner_start, "def _frame_record(tb):")
        put(inner_start + 1, "    try:")
        put(inner_start + 2, "        try:")
        put(raise_line, "            raise RuntimeError('synthetic-secret-body')")
        put(inner_start + 4, "        finally:")
        put(inner_finally_line, "            parked = 'inner-finally'")
        put(inner_start + 6, "    finally:")
        put(inner_start + 7, "        parked = 'outer-finally'")
        put(outer_start, "def _project_failure(err, case_id=None):")
        put(outer_start + 1, "    try:")
        put(outer_call_line, "        return _frame_record(None)")
        put(outer_start + 3, "    finally:")
        put(outer_cleanup_line, "        parked = 'outer-finally'")

        error = _captured_error(
            str(path), "\n".join(lines) + "\n", "_project_failure", None
        )
        nodes = {}
        tb = error[2]
        while tb is not None:
            nodes.setdefault(tb.tb_frame.f_code.co_name, tb)
            tb = tb.tb_next
        raised = nodes["_frame_record"]
        self.assertEqual(raised.tb_lineno, raise_line)
        # Both raising frames ran their ``finally`` bodies after the failure, so
        # the live frame line has moved on while the traceback node has not.
        self.assertEqual(raised.tb_frame.f_lineno, inner_cleanup_line)
        self.assertNotEqual(raised.tb_lineno, raised.tb_frame.f_lineno)
        self.assertGreater(raised.tb_frame.f_lineno, raise_line)
        self.assertEqual(
            nodes["_project_failure"].tb_frame.f_lineno, outer_cleanup_line
        )

        diagnostic = report._project_failure(
            error, case_id="tests.fake.Case.test_finally", started=True
        )
        self.assertEqual(diagnostic["schema"], report.DIAGNOSTIC_SCHEMA)
        self.assertEqual(set(diagnostic), {
            "schema", "kind", "case_id", "started", "stage", "exception_class",
            "locus", "frames", "frames_truncated",
        })
        self.assertEqual(diagnostic["exception_class"], "RuntimeError")
        self.assertEqual(diagnostic["kind"], "error")
        self.assertEqual(diagnostic["locus"], "verified_source")
        self.assertFalse(diagnostic["frames_truncated"])
        self.assertEqual(diagnostic["frames"], [
            {
                "path": REPORT_SOURCE,
                "line": outer_call_line,
                "function": "_project_failure",
            },
            {
                "path": REPORT_SOURCE,
                "line": raise_line,
                "function": "_frame_record",
            },
        ])
        for frame in diagnostic["frames"]:
            self.assertEqual(set(frame), {"path", "line", "function"})

        encoded = json.dumps(diagnostic, sort_keys=True)
        for secret in (
            "synthetic-secret-body", "inner-finally", "outer-finally",
            "raise RuntimeError", str(path),
        ):
            self.assertNotIn(secret, encoded)

        case_id = "tests.fake.Case.test_finally"
        result = _FakeResult((case_id,), {case_id: diagnostic})
        result.errors = [(_FakeTest(case_id), "formatted-in-memory")]
        with mock.patch.object(acceptance, "REQUIRED_CASES", (case_id,)), \
                mock.patch.object(acceptance, "CASE_DETAILS", {}):
            payload = report._report_payload(
                scheduled=(case_id,),
                result=result,
                imported=True,
                containment_owner=ownership.ContainmentOwner(),
            )
        self.assertEqual(
            payload["failure_diagnostics"]["frame_cap"], report.DIAGNOSTIC_FRAME_CAP
        )
        self.assertEqual(payload["cases"][0]["diagnostic"], diagnostic)
        self.assertEqual(
            payload["cases"][0]["diagnostic"]["frames"][1]["line"], raise_line
        )
        report_encoded = json.dumps(payload, sort_keys=True)
        self.assertNotIn("synthetic-secret-body", report_encoded)
        self.assertNotIn(str(path), report_encoded)

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
        self.assertEqual(result.first_diagnostics, {})
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
        self.assertEqual(
            set(payload["cases"][0]),
            {"name", "status", "detail", "diagnostic"},
        )
        self.assertEqual(payload["tests_run"], 1)
        self.assertEqual(payload["counts"]["error"], 1)
        self.assertEqual(payload["counts"]["success"], 0)
        self.assertFalse(payload["cleanup"]["owned_mounts_remaining_known"])
        self.assertIsNone(payload["cleanup"]["owned_mounts_remaining"])

    def test_body_failure_then_teardown_error_keeps_first_and_last(self):
        class BodyRaisingDict(dict):
            def get(self, name, default=None):
                raise AssertionError("body-secret")

        class BodyFailureThenTeardownErrorCase(unittest.TestCase):
            def test_case(self):
                report._binding_value(BodyRaisingDict(), "value")

            def tearDown(self):
                next(report._flatten(1))

        BodyFailureThenTeardownErrorCase.__module__ = "tests.fake_repeated_event"
        BodyFailureThenTeardownErrorCase.__qualname__ = (
            "BodyFailureThenTeardownErrorCase"
        )
        result = _run_inventory(BodyFailureThenTeardownErrorCase)
        case_id = result.errors[0][0].id()
        self.assertEqual([test.id() for test, _ in result.failures], [case_id])
        self.assertEqual([test.id() for test, _ in result.errors], [case_id])
        first = result.first_diagnostics[case_id]
        last = result.diagnostics[case_id]

        source_lines = (ROOT / REPORT_SOURCE).read_text(encoding="utf-8").splitlines()
        binding_line = next(
            index for index, line in enumerate(source_lines, 1)
            if line.strip() == "value = binding.get(name)"
        )
        flatten_line = next(
            index for index, line in enumerate(source_lines, 1)
            if line.strip() == "for test in suite:"
        )

        diagnostic_keys = {
            "schema", "kind", "case_id", "started", "stage", "exception_class",
            "locus", "frames", "frames_truncated",
        }
        self.assertEqual(set(first), diagnostic_keys)
        self.assertEqual(set(last), diagnostic_keys)
        self.assertEqual(first["schema"], report.DIAGNOSTIC_SCHEMA)
        self.assertEqual(last["schema"], report.DIAGNOSTIC_SCHEMA)
        self.assertEqual(first["stage"], "test")
        self.assertEqual(last["stage"], "teardown")
        self.assertEqual(first["kind"], "failure")
        self.assertEqual(last["kind"], "error")
        self.assertEqual(first["exception_class"], "AssertionError")
        self.assertEqual(last["exception_class"], "TypeError")
        self.assertTrue(first["started"])
        self.assertTrue(last["started"])
        self.assertEqual(first["case_id"], case_id)
        self.assertEqual(last["case_id"], case_id)
        self.assertLessEqual(len(first["frames"]), report.DIAGNOSTIC_FRAME_CAP)
        self.assertLessEqual(len(last["frames"]), report.DIAGNOSTIC_FRAME_CAP)
        self.assertEqual(first["frames"], [{
            "path": REPORT_SOURCE,
            "line": binding_line,
            "function": "_binding_value",
        }])
        self.assertEqual(last["frames"], [{
            "path": REPORT_SOURCE,
            "line": flatten_line,
            "function": "_flatten",
        }])

        with mock.patch.object(acceptance, "REQUIRED_CASES", (case_id,)), \
                mock.patch.object(acceptance, "CASE_DETAILS", {}):
            payload = report._report_payload(
                scheduled=(case_id,),
                result=result,
                imported=True,
                containment_owner=ownership.ContainmentOwner(),
            )
        case = payload["cases"][0]
        self.assertEqual(set(case), {
            "name", "status", "detail", "diagnostic", "first_diagnostic",
        })
        self.assertEqual(case["status"], "error")
        self.assertEqual(case["diagnostic"], last)
        self.assertEqual(case["first_diagnostic"], first)
        self.assertEqual(payload["counts"], {
            "success": 0,
            "failure": 0,
            "error": 1,
            "skipped": 0,
            "expected_failure": 0,
            "unexpected_success": 0,
            "not_run": 0,
        })
        self.assertEqual(payload["tests_run"], 1)
        self.assertEqual(payload["summary"]["error"], 1)
        self.assertEqual(payload["summary"]["success"], 0)
        self.assertFalse(payload["cleanup"]["owned_mounts_remaining_known"])
        self.assertIsNone(payload["cleanup"]["owned_mounts_remaining"])
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["failure_diagnostics"]["unstarted"], [])
        encoded = json.dumps(payload, sort_keys=True)
        self.assertNotIn("body-secret", encoded)
        self.assertNotIn("not iterable", encoded)

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
