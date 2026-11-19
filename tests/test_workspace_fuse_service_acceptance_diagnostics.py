"""Pure contract tests for the workspace FUSE failure diagnostics projection.

These tests use only local fake exceptions and tracebacks. They do not start the
service, a FUSE mount, a child process, PostgreSQL, Git, or the network.
"""
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock
import urllib.error

from workspace_fuse_service_acceptance import (
    DIAGNOSTIC_FAILURE_TYPES,
    FAILURE_PHASES,
    MAX_DIAGNOSTIC_LINE,
    MAX_SHUTDOWN_RECORD_BYTES,
    MAX_SHUTDOWN_TAIL_BYTES,
    REQUIRED_CASES,
    ROOT,
    SHUTDOWN_OUTCOMES,
    SHUTDOWN_OUTCOME_MULTIPLE,
    SHUTDOWN_OUTCOME_UNKNOWN,
    SOURCE_PATHS,
    WorkspaceFuseDiagnosticResult,
    _bounded_int,
    _busy_target,
    _child_exit,
    _diagnostic_record,
    _errno,
    _exception_kind,
    _failure_phase,
    _http_status,
    _report_payload,
    _source_location,
    _unknown_diagnostic,
    _writer_close,
    project_shutdown_outcome,
    read_shutdown_outcome,
)

SECRET = "SECRET-must-never-appear"
C5 = "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_api_sigkill_with_pending_kernel_writer"


class _HiddenError(Exception):
    """Unknown exception whose text/repr expose a secret and count calls."""

    def __init__(self):
        self.text_calls = 0

    def __str__(self):
        self.text_calls += 1
        return SECRET

    def __repr__(self):
        self.text_calls += 1
        return SECRET


def _traceback_at(filename, source):
    try:
        exec(compile(source, filename, "exec"), {})
    except BaseException as error:
        return error.__traceback__
    raise AssertionError("synthetic source did not raise")


def _case(test_id):
    return types.SimpleNamespace(id=lambda: test_id)


def _terminal(payload, prefix="Error: normal shutdown incomplete: "):
    return (prefix + payload + "\n").encode()


class _ResultShape:
    def __init__(self, failures=(), errors=(), skipped=(), tests_run=4):
        self.failures = list(failures)
        self.errors = list(errors)
        self.skipped = list(skipped)
        self.expectedFailures = []
        self.unexpectedSuccesses = []
        self.testsRun = tests_run


class WorkspaceFuseDiagnosticsContractTest(unittest.TestCase):
    def test_secret_message_is_never_rendered(self):
        error = _HiddenError()
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        record = _diagnostic_record(test, error, tb)

        self.assertEqual(error.text_calls, 0)
        self.assertNotIn(SECRET, json.dumps(record))
        self.assertEqual(record["exception"], "unknown")
        self.assertEqual(record["phase"], "signal")
        self.assertEqual(record["source"], {"path": "tests/test_workspace_fuse_service.py", "line": 1})

    def test_unknown_exception_and_phase_remain_unknown(self):
        self.assertEqual(_exception_kind(_HiddenError()), "unknown")
        self.assertEqual(_exception_kind(AssertionError("synthetic")), "AssertionError")
        self.assertIn("CalledProcessError", DIAGNOSTIC_FAILURE_TYPES)
        for phase in FAILURE_PHASES:
            self.assertEqual(_failure_phase(types.SimpleNamespace(
                _rootyard_diagnostic_primary_phase=phase)), phase)
        self.assertIsNone(_failure_phase(types.SimpleNamespace(
            _rootyard_diagnostic_primary_phase="not-a-phase")))

    def test_non_numeric_bool_and_overflow_scalars_are_rejected(self):
        self.assertEqual(_bounded_int(503, 100, 599), 503)
        for value in (True, False, "503", 99, 600, 10 ** 9, 503.0):
            self.assertIsNone(_bounded_int(value, 100, 599))

        status_error = urllib.error.HTTPError("http://invalid", 503, "", None, None)
        try:
            self.assertEqual(_http_status(status_error), 503)
        finally:
            status_error.close()
        bool_error = urllib.error.HTTPError("http://invalid", True, "", None, None)
        try:
            self.assertIsNone(_http_status(bool_error))
        finally:
            bool_error.close()

        self.assertEqual(_errno(OSError(5, SECRET)), 5)
        class _BoolErrno(OSError):
            errno = True
        self.assertIsNone(_errno(_BoolErrno()))
        class _BigErrno(OSError):
            errno = 10 ** 9
        self.assertIsNone(_errno(_BigErrno()))

        self.assertEqual(_child_exit(
            subprocess.CalledProcessError(3, ["secret-argv"], output=b"secret")), 3)
        self.assertIsNone(_child_exit(
            subprocess.CalledProcessError(True, ["secret-argv"])))
        self.assertIsNone(_child_exit(
            subprocess.CalledProcessError(10 ** 6, ["secret-argv"])))

    def test_child_exit_is_only_a_real_child_process_code(self):
        test = _case(REQUIRED_CASES[2])
        for value in (0, 1, -11, 255, -256, 10 ** 6, True, False,
                      "1", 1.0, None):
            with self.subTest(api_exit=value):
                test._rootyard_diagnostic_api_exit = value
                record = _diagnostic_record(
                    test, AssertionError("synthetic"), None)
                self.assertIsNone(
                    record["child_exit"],
                    "a service exit must never be relabelled as a child exit")

        no_attribute = _case(REQUIRED_CASES[2])
        self.assertIsNone(_diagnostic_record(
            no_attribute, AssertionError("synthetic"), None)["child_exit"])

        # Only a real CalledProcessError code belongs in child_exit.
        test._rootyard_diagnostic_api_exit = 7
        original = subprocess.CalledProcessError(
            3, ["secret-argv"], output=b"secret")
        self.assertEqual(_diagnostic_record(
            test, original, None)["child_exit"], 3)

        invalid = subprocess.CalledProcessError(True, ["secret-argv"])
        self.assertIsNone(_diagnostic_record(
            test, invalid, None)["child_exit"])
        self.assertIsNone(_diagnostic_record(
            test, AssertionError("synthetic"), None)["child_exit"])

    def test_api_exit_poison_value_or_payload_is_never_serialized(self):
        class _Poison:
            def __init__(self):
                self.calls = 0

            def __str__(self):
                self.calls += 1
                return SECRET

            def __repr__(self):
                self.calls += 1
                return SECRET

            def __int__(self):
                self.calls += 1
                return 5

            def __index__(self):
                self.calls += 1
                return 5

        poison = _Poison()
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "joins"
        test._rootyard_diagnostic_api_exit = poison
        record = _diagnostic_record(test, _HiddenError(), None)

        self.assertEqual(poison.calls, 0)
        self.assertIsNone(record["child_exit"])
        self.assertNotIn(SECRET, json.dumps(record))

        test._rootyard_diagnostic_api_exit = {"payload": poison}
        payload_record = _diagnostic_record(test, _HiddenError(), None)
        self.assertEqual(poison.calls, 0)
        self.assertIsNone(payload_record["child_exit"])
        self.assertNotIn(SECRET, json.dumps(payload_record))

    def test_child_exit_fallback_removed_keeps_other_fields_and_pass_state(self):
        error = AssertionError("synthetic")
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "joins"
        test._rootyard_diagnostic_api_exit = 1
        record = _diagnostic_record(test, error, tb)

        self.assertEqual(record, {
            "phase": "joins",
            "exception": "AssertionError",
            "source": {"path": "tests/test_workspace_fuse_service.py", "line": 1},
            "http_status": None,
            "errno": None,
            "child_exit": None,
            "shutdown_outcome": "unknown",
            "busy_target": "unknown",
            "writer_close": "unknown",
        })
        self.assertEqual(set(record), set(_unknown_diagnostic()))

        report = _report_payload(
            scheduled=REQUIRED_CASES,
            result=_ResultShape(
                errors=[(test, "raw error detail " + SECRET)]),
            imported=True,
            diagnostics={REQUIRED_CASES[2]: record})
        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"]["error"], 1)
        self.assertEqual(report["counts"]["success"], 3)
        self.assertNotIn(SECRET, json.dumps(report))

    def test_shutdown_outcome_is_a_closed_complete_clause_projection(self):
        capture = (
            "workspace capture/helper shutdown did not complete cleanly: ")
        helper = "workspace FUSE helper shutdown failed: "
        cases = (
            (capture + helper + "HTTP 503: service temporarily unavailable",
             "helper_internal_503"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited unsuccessfully"),
             "helper_child_exit"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 101"),
             "helper_child_exit_101"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 102"),
             "helper_child_exit_102"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 103"),
             "helper_child_exit_103"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 104"),
             "helper_child_exit_104"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 105"),
             "helper_child_exit_105"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exited with code 1"),
             "helper_child_exit_1"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child was killed by SIGKILL"),
             "helper_child_sigkill"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child was terminated by SIGTERM"),
             "helper_child_sigterm"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child exit was not observed"),
             "helper_child_absent"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child reap deadline expired"),
             "helper_child_reap_deadline"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper child wait failed"),
             "helper_child_reap_error"),
            (capture + helper + (
                "HTTP 503: workspace FUSE helper teardown timed out"),
             "helper_timeout"),
            (capture + helper + (
                "HTTP 504: workspace FUSE helper shutdown exceeded the shared "
                "normal-shutdown deadline"), "helper_deadline"),
            (capture + (
                "workspace capture worker did not stop before the "
                "abort-confirmation window"), "capture_scan"),
            ("owned workspace Git jobs/process cleanup did not complete cleanly",
             "git_drain"),
            ("HTTP server did not join within the shutdown deadline", "http_join"),
            ("background worker did not stop cleanly", "background_join"),
            ("native Git process cleanup did not prove quiescence",
             "native_quiescence"),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                outcome = project_shutdown_outcome(_terminal(payload))
                self.assertEqual(outcome, expected)
                self.assertIn(outcome, SHUTDOWN_OUTCOMES)
        mixed = (
            capture + helper + "HTTP 503: service temporarily unavailable"
            + "; owned workspace Git jobs/process cleanup did not complete cleanly")
        self.assertEqual(
            project_shutdown_outcome(
                _terminal(mixed, "Error: service cleanup incomplete: ")),
            SHUTDOWN_OUTCOME_MULTIPLE)
        unknown_child_status = (
            capture + helper
            + "HTTP 503: workspace FUSE helper child exited with code 2")
        self.assertEqual(
            project_shutdown_outcome(_terminal(unknown_child_status)),
            SHUTDOWN_OUTCOME_UNKNOWN)
        mixed_child_exit = (
            capture + helper
            + "HTTP 503: workspace FUSE helper child exited unsuccessfully"
            + "; owned workspace Git jobs/process cleanup did not complete cleanly")
        self.assertEqual(
            project_shutdown_outcome(
                _terminal(mixed_child_exit, "Error: service cleanup incomplete: ")),
            SHUTDOWN_OUTCOME_MULTIPLE)

    def test_shutdown_outcome_rejects_incomplete_ambiguous_or_unrecognized(self):
        known = _terminal("native Git process cleanup did not prove quiescence")
        other = b"Error: a different primary failure\n"
        bodies = (
            b"", b"rootyard listening\n", other, _terminal(""),
            _terminal(
                "workspace capture/helper shutdown did not complete cleanly: "),
            _terminal("HTTP 503: service temporarily unavailable"),
            _terminal(
                "HTTP 503: workspace FUSE helper child exited unsuccessfully"),
            _terminal(
                "workspace capture/helper shutdown did not complete cleanly: "
                "workspace FUSE helper shutdown failed: "
                "HTTP 503: workspace FUSE helper child reaping failed"),
            known[:-1], known[:-1] + b"; not-a-source-clause\n",
            known.replace(b"native Git", b"not-native Git"),
            known + other, other + known, known + b"trailing non-Error output\n",
            b"\xff\xfe\x00",
            known.rstrip(b"\n") + b"x" * MAX_SHUTDOWN_RECORD_BYTES + b"\n",
            known + b"x" * MAX_SHUTDOWN_TAIL_BYTES,
        )
        for body in bodies:
            with self.subTest(body_length=len(body)):
                self.assertEqual(project_shutdown_outcome(body),
                                 SHUTDOWN_OUTCOME_UNKNOWN)
        self.assertEqual(project_shutdown_outcome(known), "native_quiescence")
        self.assertEqual(project_shutdown_outcome(known + b"\n"),
                         "native_quiescence")
        self.assertEqual(project_shutdown_outcome(None),
                         SHUTDOWN_OUTCOME_UNKNOWN)
        self.assertEqual(project_shutdown_outcome("not bytes"),
                         SHUTDOWN_OUTCOME_UNKNOWN)

    def test_read_shutdown_outcome_reads_only_a_bound_bounded_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "server.log"
            path.write_bytes(b"rootyard: unrelated line\n" * (
                MAX_SHUTDOWN_TAIL_BYTES // 22 + 2) + _terminal(
                    "background worker did not stop cleanly"))
            with path.open("ab") as source:
                self.assertEqual(read_shutdown_outcome(source),
                                 "background_join")
                self.assertEqual(
                    read_shutdown_outcome(source, proc_fd_root=root / "absent"),
                    "background_join")
            self.assertEqual(read_shutdown_outcome(str(path)), "background_join")
            self.assertEqual(read_shutdown_outcome(root / "missing.log"),
                             SHUTDOWN_OUTCOME_UNKNOWN)
            self.assertEqual(read_shutdown_outcome(None),
                             SHUTDOWN_OUTCOME_UNKNOWN)

    def test_read_shutdown_outcome_rejects_a_replacement_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "server.log"
            replacement = root / "replacement.log"
            proc = root / "proc"
            proc.mkdir()
            path.write_bytes(_terminal("background worker did not stop cleanly"))
            replacement.write_bytes(_terminal(
                "native Git process cleanup did not prove quiescence"))
            with path.open("ab") as source:
                (proc / str(source.fileno())).symlink_to(replacement)
                self.assertEqual(
                    read_shutdown_outcome(source, proc_fd_root=proc),
                    SHUTDOWN_OUTCOME_UNKNOWN)
            with path.open("ab") as source:
                path.unlink()
                path.write_bytes(_terminal(
                    "native Git process cleanup did not prove quiescence"))
                self.assertEqual(
                    read_shutdown_outcome(source, proc_fd_root=root / "absent"),
                    SHUTDOWN_OUTCOME_UNKNOWN)

    def test_read_shutdown_outcome_rejects_denied_proc_inspect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_bytes(_terminal("background worker did not stop cleanly"))
            with path.open("ab") as source, mock.patch(
                    "workspace_fuse_service_acceptance._open_bound_snapshot",
                    side_effect=PermissionError("denied")):
                self.assertEqual(read_shutdown_outcome(source),
                                 SHUTDOWN_OUTCOME_UNKNOWN)

    def test_shutdown_outcome_field_is_closed_and_never_formats_test_data(self):
        class _Poison:
            def __str__(self):
                raise AssertionError(SECRET)

            def __repr__(self):
                raise AssertionError(SECRET)

        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "joins"
        test._rootyard_diagnostic_api_exit = 1
        test._rootyard_diagnostic_shutdown_outcome = "helper_internal_503"
        record = _diagnostic_record(test, AssertionError("synthetic"), None)
        self.assertEqual(record["shutdown_outcome"], "helper_internal_503")
        self.assertEqual(set(record), set(_unknown_diagnostic()))

        for value in (None, "", "clean", _Poison(), {"value": SECRET},
                      "helper_internal_503 "):
            test._rootyard_diagnostic_shutdown_outcome = value
            poisoned = _diagnostic_record(
                test, AssertionError("synthetic"), None)
            self.assertEqual(poisoned["shutdown_outcome"],
                             SHUTDOWN_OUTCOME_UNKNOWN)
            self.assertNotIn(SECRET, json.dumps(poisoned))

    def test_source_location_allows_only_known_paths_and_valid_lines(self):
        allowed = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n"))
        self.assertEqual(allowed, {"path": "tests/test_workspace_fuse_service.py", "line": 1})
        self.assertIn(allowed["path"], SOURCE_PATHS)

        foreign = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service_acceptance_diagnostics.py"),
            "raise ValueError('synthetic')\n"))
        self.assertIsNone(foreign)

        overflowing = _source_location(_traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "\n" * (MAX_DIAGNOSTIC_LINE - 1) + "raise ValueError('synthetic')\n"))
        self.assertIsNone(overflowing)

    def test_primary_phase_wins_over_cleanup_and_missing_record_is_null(self):
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        test._rootyard_diagnostic_phase = "cleanup"
        self.assertEqual(_failure_phase(test), "signal")

        self.assertEqual(_failure_phase(types.SimpleNamespace(
            _rootyard_diagnostic_phase="cleanup")), "cleanup")
        self.assertIsNone(_failure_phase(types.SimpleNamespace()))

        unknown = _unknown_diagnostic()
        self.assertEqual(unknown["exception"], "unknown")
        self.assertIsNone(unknown["phase"])
        self.assertIsNone(unknown["source"])
        self.assertIsNone(unknown["http_status"])
        self.assertIsNone(unknown["errno"])
        self.assertIsNone(unknown["child_exit"])
        self.assertEqual(unknown["shutdown_outcome"], SHUTDOWN_OUTCOME_UNKNOWN)
        self.assertEqual(unknown["busy_target"], "unknown")
        self.assertEqual(unknown["writer_close"], "unknown")

    def test_busy_witness_fields_accept_only_closed_values(self):
        test = _case(REQUIRED_CASES[2])
        self.assertEqual(_busy_target(test), "unknown")
        self.assertEqual(_writer_close(test), "unknown")
        test._rootyard_diagnostic_busy_target = "writer"
        test._rootyard_diagnostic_writer_close = "completed_before_unmount_entry"
        self.assertEqual(_busy_target(test), "writer")
        self.assertEqual(_writer_close(test), "completed_before_unmount_entry")
        for value in (SECRET, "writer ", "OTHER", 1, True, None, ["writer"]):
            test._rootyard_diagnostic_busy_target = value
            test._rootyard_diagnostic_writer_close = value
            self.assertEqual(_busy_target(test), "unknown")
            self.assertEqual(_writer_close(test), "unknown")
        record = _diagnostic_record(test, AssertionError("synthetic"), None)
        self.assertNotIn(SECRET, json.dumps(record))
        self.assertEqual(record["busy_target"], "unknown")
        self.assertEqual(record["writer_close"], "unknown")

    def test_result_captures_before_unittest_formats_the_exception(self):
        result = WorkspaceFuseDiagnosticResult(io.StringIO(), False, 0)
        seen = {}
        error = _HiddenError()
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )

        def _formatted(err, test):
            seen["captured"] = test.id() in result.diagnostics
            return SECRET

        result._exc_info_to_string = _formatted
        test = _case(REQUIRED_CASES[2])
        test._rootyard_diagnostic_primary_phase = "signal"
        result.addError(test, (_HiddenError, error, tb))

        self.assertTrue(seen["captured"])
        self.assertEqual(result.diagnostics[REQUIRED_CASES[2]]["phase"], "signal")
        self.assertEqual(result.diagnostics[REQUIRED_CASES[2]]["exception"], "unknown")
        self.assertNotIn(SECRET, json.dumps(result.diagnostics))

    def test_passed_skipped_error_counts_are_unchanged(self):
        error_id = REQUIRED_CASES[2]
        skipped_id = REQUIRED_CASES[1]
        result = _ResultShape(
            errors=[(_case(error_id), "raw error detail " + SECRET)],
            skipped=[(_case(skipped_id), "raw skip reason " + SECRET)],
        )
        diagnostics = {error_id: {
            "phase": "signal", "exception": "AssertionError", "source": None,
            "http_status": None, "errno": None, "child_exit": None,
        }}
        report = _report_payload(
            scheduled=REQUIRED_CASES, result=result, imported=True,
            diagnostics=diagnostics)

        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"], {
            "success": 2, "failure": 0, "error": 1, "skipped": 1,
            "expected_failure": 0, "unexpected_success": 0,
        })
        by_name = {case["name"]: case for case in report["cases"]}
        self.assertEqual(by_name[error_id]["status"], "error")
        self.assertEqual(by_name[error_id]["diagnostic"]["phase"], "signal")
        self.assertEqual(by_name[skipped_id]["status"], "skipped")
        self.assertNotIn("diagnostic", by_name[skipped_id])
        self.assertNotIn(SECRET, json.dumps(report))

    def test_missing_or_invalid_diagnostics_never_create_a_pass(self):
        error_id = REQUIRED_CASES[2]
        result = _ResultShape(errors=[(_case(error_id), "raw error detail " + SECRET)])
        report = _report_payload(
            scheduled=REQUIRED_CASES, result=result, imported=True,
            diagnostics={"not-the-case": {"phase": "signal"}})

        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"]["error"], 1)
        case = next(case for case in report["cases"] if case["name"] == error_id)
        self.assertEqual(case["diagnostic"], _unknown_diagnostic())
        self.assertNotIn(SECRET, json.dumps(report))

        passing = _report_payload(
            scheduled=REQUIRED_CASES, result=_ResultShape(), imported=True,
            diagnostics={"junk": {"phase": "signal"}})
        self.assertTrue(passing["passed"])
        self.assertTrue(all("diagnostic" not in case for case in passing["cases"]))

    def test_c5_failure_projection_stays_bounded_and_secret_free(self):
        error = _HiddenError()
        tb = _traceback_at(
            str(ROOT / "tests/test_workspace_fuse_service.py"),
            "raise ValueError('synthetic')\n",
        )
        record = _diagnostic_record(_case(C5), error, tb)

        self.assertEqual(error.text_calls, 0)
        self.assertEqual(record["exception"], "unknown")
        self.assertIsNone(record["phase"])
        self.assertEqual(
            record["source"],
            {"path": "tests/test_workspace_fuse_service.py", "line": 1})
        self.assertNotIn(SECRET, json.dumps(record))

    def test_required_inventory_is_the_exact_existing_four(self):
        self.assertEqual(REQUIRED_CASES, (
            "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_live_editor_capture_checkpoint_and_remount",
            "tests.test_workspace_handoff.WorkspaceHandoffTest.test_expired_host_reattach_from_remote_checkpoint",
            "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_normal_sigterm_helper_unmount_precedes_parked_git_join",
            C5,
        ))

    def test_full_four_only_passes_when_every_required_case_is_scheduled(self):
        report = _report_payload(
            scheduled=REQUIRED_CASES, result=_ResultShape(), imported=True)

        self.assertTrue(report["passed"])
        self.assertEqual([case["name"] for case in report["cases"]],
                         list(REQUIRED_CASES))
        self.assertEqual(report["counts"]["success"], 4)
        self.assertEqual(report["summary"]["required"], 4)
        self.assertEqual(report["summary"]["scheduled"], 4)
        self.assertEqual(report["summary"]["tests_run"], 4)

    def test_c5_failed_error_or_skipped_is_rejected(self):
        for field, status in (
                ("failures", "failed"),
                ("errors", "error"),
                ("skipped", "skipped")):
            with self.subTest(field=field):
                report = _report_payload(
                    scheduled=REQUIRED_CASES,
                    result=_ResultShape(**{field: [(_case(C5), "raw detail")]}),
                    imported=True)

                self.assertFalse(report["passed"])
                self.assertEqual(report["counts"]["success"], 3)
                case = next(case for case in report["cases"] if case["name"] == C5)
                self.assertEqual(case["status"], status)
                if status == "skipped":
                    self.assertNotIn("diagnostic", case)
                else:
                    self.assertEqual(case["diagnostic"], _unknown_diagnostic())

    def test_c5_missing_replacement_duplicate_or_extra_is_rejected(self):
        replacement = "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_not_in_the_required_inventory"

        missing = _report_payload(
            scheduled=REQUIRED_CASES[:-1], result=_ResultShape(tests_run=3),
            imported=True)
        self.assertFalse(missing["passed"])
        self.assertNotIn(C5, [case["name"] for case in missing["cases"]])

        replaced = _report_payload(
            scheduled=REQUIRED_CASES[:-1] + (replacement,),
            result=_ResultShape(tests_run=4), imported=True)
        self.assertFalse(replaced["passed"])
        self.assertNotIn(C5, [case["name"] for case in replaced["cases"]])
        self.assertIn(replacement, [case["name"] for case in replaced["cases"]])

        duplicated = _report_payload(
            scheduled=REQUIRED_CASES + (C5,), result=_ResultShape(tests_run=5),
            imported=True)
        self.assertFalse(duplicated["passed"])
        self.assertEqual(duplicated["counts"]["success"], 5)
        self.assertEqual([case["name"] for case in duplicated["cases"]].count(C5), 2)

        extra = _report_payload(
            scheduled=REQUIRED_CASES + (replacement,),
            result=_ResultShape(tests_run=5), imported=True)
        self.assertFalse(extra["passed"])
        self.assertEqual(extra["counts"]["success"], 5)
        self.assertIn(replacement, [case["name"] for case in extra["cases"]])

    def test_allowed_type_set_is_closed(self):
        self.assertLessEqual({"AssertionError", "OSError", "NormalShutdownError"},
                             DIAGNOSTIC_FAILURE_TYPES)
        self.assertNotIn("_HiddenError", DIAGNOSTIC_FAILURE_TYPES)


if __name__ == "__main__":
    unittest.main()
