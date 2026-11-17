#!/usr/bin/env python3
"""Pure parser, privacy and fake-process tests for native11 failure projection."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import issue107_native11_inventory as inventory  # noqa: E402
import issue107_native11_runner as runner  # noqa: E402

HEAD = "a" * 40
TARGET = "ref_store_operations"
FAIL_TARGET = "ref_store_pack_snapshots"
SECRET = "SECRET_DO_NOT_SERIALIZE_7f91"
SQL = "SELECT * FROM private_credentials WHERE token='leaked'"
DSN = "postgres://rootyard:supersecret@db.internal:5432/private"


class FakeStdout:
    def __init__(self, payload):
        self.payload = payload

    def read(self, size):
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk

    def close(self):
        pass


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, timeout=False):
        self.stdout = FakeStdout(stdout)
        self.stderr = FakeStdout(stderr)
        self.returncode = returncode
        self.pid = 4242
        self._timeout = timeout
        self._timed_out = False

    def wait(self, timeout=None):
        if self._timeout and not self._timed_out:
            self._timed_out = True
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def poll(self):
        if self._timeout and not self._timed_out:
            return None
        return self.returncode

    def kill(self):
        pass


class FakeReader:
    def __init__(self, target, args):
        self.target = target
        self.args = args
        self.alive = True

    def run(self):
        self.target(*self.args)
        self.alive = False

    def join(self, timeout=None):
        self.alive = False

    def is_alive(self):
        return self.alive


def synchronous_start(readers, target, *args):
    reader = FakeReader(target, args)
    readers.append(reader)
    reader.run()
    return reader


def case_line(name, status="ok"):
    return f"test {name} ... {status}"


def summary(status="ok", passed=1, failed=0, ignored=0):
    return (f"test result: {status}. {passed} passed; {failed} failed; "
            f"{ignored} ignored; 0 measured; 0 filtered out; finished in 0.01s")


def project(output, returncode=101, stderr=b"", **changes):
    options = {
        "timed_out": False,
        "phase": "run",
        "selected_case": inventory.TARGETS[TARGET]["cases"][0],
    }
    options.update(changes)
    return runner.project_target_failure(
        TARGET, output, returncode, stderr=stderr, **options)


class ProjectionParserTests(unittest.TestCase):
    def test_known_inventory_pass_fail_and_ignored_are_exact(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "ok"),
            case_line(cases[1], "FAILED"),
            case_line(cases[2], "ignored"),
            summary("FAILED", 1, 1, 1),
        ]).encode()
        diag = project(output)
        self.assertEqual(diag["kind"], runner.FAILURE_KIND)
        self.assertEqual(diag["prefix"], runner.FAILURE_PREFIX)
        self.assertEqual(diag["source_prefix"], runner.SOURCE_PREFIX)
        self.assertEqual(diag["target"], TARGET)
        self.assertEqual(diag["phase"], "run")
        self.assertEqual(diag["selected_case"], cases[0])
        self.assertTrue(diag["selected_case_known"])
        self.assertEqual(diag["source_allowlist"], list(runner.SOURCE_ALLOWLIST))
        self.assertEqual(diag["error_class"], "native_process_failed")
        self.assertEqual(diag["exit"]["returncode"], 101)
        self.assertEqual([row["name"] for row in diag["cases"]],
                         [cases[0], cases[1], cases[2]])
        self.assertEqual([row["status"] for row in diag["cases"]],
                         ["passed", "failed", "ignored"])
        self.assertEqual(diag["case_counts"],
                         {"passed": 1, "failed": 1, "ignored": 1, "unknown": 0})
        self.assertEqual(diag["inventory"]["expected"], len(cases))
        self.assertEqual(diag["inventory"]["observed"], 3)
        self.assertEqual(diag["inventory"]["missing"], len(cases) - 3)
        self.assertEqual(diag["unknown"]["missing_inventory_cases"], len(cases) - 3)
        self.assertEqual(diag["libtest_summary"],
                         {"status": "FAILED", "passed": 1, "failed": 1,
                          "ignored": 1, "measured": 0, "filtered_out": 0})

    def test_explicit_list_phase_has_null_source_inventory_case(self):
        diag = project(b"", phase="list", selected_case=None)
        self.assertEqual(diag["phase"], "list")
        self.assertEqual(diag["scope"], "list")
        self.assertIsNone(diag["selected_case"])
        self.assertFalse(diag["selected_case_known"])
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["inventory"]["missing"],
                         len(inventory.TARGETS[TARGET]["cases"]))

    def test_unknown_selected_case_is_dropped_not_serialized(self):
        diag = project(b"", selected_case=SECRET)
        self.assertEqual(diag["phase"], "run")
        self.assertIsNone(diag["selected_case"])
        self.assertFalse(diag["selected_case_known"])
        self.assertNotIn(SECRET, json.dumps(diag, sort_keys=True))

    def test_missing_case_or_summary_is_never_success(self):
        diag = project(b"test result: ok. 1 passed; 0 failed; 0 ignored;\n")
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"]["passed"], 0)
        self.assertEqual(diag["inventory"]["observed"], 0)
        self.assertEqual(diag["inventory"]["missing"],
                         len(inventory.TARGETS[TARGET]["cases"]))
        self.assertEqual(diag["libtest_summary"]["passed"], 1)
        # The bare summary is retained as a count only, never as a case pass.
        self.assertNotIn("passed", [row["status"] for row in diag["cases"]])

    def test_unlisted_malformed_and_duplicate_names_are_dropped(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line("arbitrary_" + SECRET, "ok"),
            case_line(cases[0], "ok"),
            case_line(cases[0], "FAILED"),
            "test " + cases[1] + " ... nonsense",
            summary("FAILED", 1, 1, 0),
        ]).encode()
        diag = project(output)
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"]["passed"], 0)
        self.assertEqual(diag["inventory"]["unlisted"], 1)
        self.assertEqual(diag["inventory"]["duplicate"], 1)
        self.assertEqual(diag["inventory"]["malformed"], 1)
        serialized = json.dumps(diag)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn(cases[0] + " ... FAILED", serialized)

    def test_duplicate_inventory_name_cannot_become_a_pass(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "ok"),
            case_line(cases[0], "ok"),
            summary("ok", 1, 0, 0),
        ]).encode()
        diag = project(output)
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"]["passed"], 0)
        self.assertEqual(diag["inventory"]["duplicate"], 1)

    def test_source_path_and_line_only_from_fixed_allowlist(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "FAILED"),
            summary("FAILED", 0, 1, 0),
        ]).encode()
        stderr = "\n".join([
            "thread 'x' panicked at tests/ref_store_pack_snapshots.rs:123:45:",
            "thread 'x' panicked at /tmp/outside.rs:9:1:",
            "thread 'x' panicked at tests/not_an_inventory_file.rs:4:2:",
            "thread 'x' panicked at tests/ref_store_operations.rs:0:1:",
        ]).encode()
        diag = project(output, stderr=stderr)
        self.assertEqual(diag["source_locations"],
                         [{"file": "tests/ref_store_pack_snapshots.rs", "line": 123}])
        self.assertLessEqual(len(diag["source_locations"]),
                             runner.MAX_SOURCE_LOCATIONS)
        self.assertEqual(diag["parse_caps"]["source_locations"],
                         runner.MAX_SOURCE_LOCATIONS)
        serialized = json.dumps(diag)
        self.assertNotIn("/tmp/outside.rs", serialized)
        self.assertNotIn("tests/not_an_inventory_file.rs", serialized)

    def test_source_location_count_is_bounded(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = (case_line(cases[0], "FAILED") + "\n" + summary("FAILED", 0, 1, 0)).encode()
        stderr = "\n".join(
            "thread 'x' panicked at tests/ref_store_operations.rs:%d:1:"
            % (index + 1) for index in range(20)).encode()
        diag = project(output, stderr=stderr)
        self.assertEqual(len(diag["source_locations"]),
                         runner.MAX_SOURCE_LOCATIONS)
        self.assertEqual(diag["source_locations"][0],
                         {"file": "tests/ref_store_operations.rs", "line": 1})

    def test_negative_returncode_has_numeric_signal_and_timeout_is_distinct(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "FAILED"),
            summary("FAILED", 0, 1, 0),
        ]).encode()
        stderr = b"thread 'x' panicked at tests/ref_store_operations.rs:7:3:\n"
        failed = project(output, stderr=stderr, returncode=-9, timed_out=False)
        self.assertEqual(failed["error_class"], "native_process_failed")
        self.assertEqual(failed["exit"]["returncode"], -9)
        self.assertEqual(failed["exit"]["signal"], 9)
        self.assertEqual(failed["exit"]["signal_name"], "SIGKILL")
        self.assertFalse(failed["timed_out"])
        timed = project(output, stderr=stderr, returncode=-9, timed_out=True)
        self.assertEqual(timed["error_class"], "native_timeout")
        self.assertTrue(timed["timed_out"])
        self.assertEqual(timed["exit"]["signal_name"], "SIGKILL")

    def test_zero_parsed_cases_still_has_error_exit_and_unknown(self):
        diag = project(b"", returncode=101)
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"],
                         {"passed": 0, "failed": 0, "ignored": 0, "unknown": 0})
        self.assertEqual(diag["error_class"], "native_process_failed")
        self.assertEqual(diag["exit"]["returncode"], 101)
        self.assertEqual(diag["inventory"]["missing"],
                         len(inventory.TARGETS[TARGET]["cases"]))
        self.assertIn("unknown", diag)
        self.assertIn("missing_inventory_cases", diag["unknown"])

    def test_secret_stdout_and_sql_stderr_are_not_serialized(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "FAILED"),
            summary("FAILED", 0, 1, 0),
        ]).encode()
        stderr = "\n".join([
            SECRET,
            SQL,
            DSN,
            "thread 'x' panicked at tests/ref_store_operations.rs:11:2:",
            "panic statement: " + SECRET,
        ]).encode()
        diag = project(output, stderr=stderr, returncode=101)
        serialized = json.dumps(diag, sort_keys=True)
        for forbidden in (SECRET, SQL, DSN, "panic statement", "supersecret"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(diag["source_locations"],
                         [{"file": "tests/ref_store_operations.rs", "line": 11}])


class BoundedFailureProjectionTests(unittest.TestCase):
    def setUp(self):
        self.reader_patch = mock.patch.object(
            runner, "_start_reader", side_effect=synchronous_start)
        self.reader_patch.start()
        self.addCleanup(self.reader_patch.stop)

    def test_nonzero_attaches_safe_diagnostic_and_outer_code(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        output = "\n".join([
            case_line(cases[0], "FAILED"),
            summary("FAILED", 0, 1, 0),
        ]).encode()
        stderr = "\n".join([
            "thread 'x' panicked at tests/ref_store_operations.rs:19:4:",
            SECRET,
        ]).encode()
        process = FakeProcess(output, stderr=stderr, returncode=101)
        projector = lambda output, stderr, code, timed_out: runner.project_target_failure(
            TARGET, output, code, timed_out=timed_out, phase="run",
            selected_case=cases[0], stderr=stderr)
        with mock.patch.object(runner.subprocess, "Popen", return_value=process):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1, failure_projector=projector)
        error = raised.exception
        self.assertEqual(error.code, "native_process_failed")
        self.assertIsInstance(error.diagnostic, dict)
        self.assertEqual(error.diagnostic["source_locations"],
                         [{"file": "tests/ref_store_operations.rs", "line": 19}])
        self.assertFalse(hasattr(error, "output"))
        self.assertFalse(hasattr(error, "stdout"))
        self.assertNotIn(SECRET, json.dumps(error.diagnostic))

    def test_timeout_keeps_native_timeout_code_and_diagnostic(self):
        process = FakeProcess(b"test secret ... failed\n", returncode=-9, timeout=True)
        projector = lambda output, stderr, code, timed_out: runner.project_target_failure(
            TARGET, output, code, timed_out=timed_out, phase="list",
            stderr=stderr)
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner.os, "getpgid", return_value=4242), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=0.01, failure_projector=projector)
        error = raised.exception
        self.assertEqual(error.code, "native_timeout")
        self.assertEqual(error.diagnostic["error_class"], "native_timeout")
        self.assertTrue(error.diagnostic["timed_out"])
        self.assertEqual(error.diagnostic["exit"]["signal"], 9)
        self.assertEqual(error.diagnostic["exit"]["signal_name"], "SIGKILL")
        self.assertNotIn("secret", json.dumps(error.diagnostic))

    def test_projection_failure_does_not_swallow_outer_failure(self):
        process = FakeProcess(b"anything\n", returncode=101)
        projector = mock.Mock(side_effect=RuntimeError(SECRET))
        with mock.patch.object(runner.subprocess, "Popen", return_value=process):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1, failure_projector=projector)
        self.assertEqual(raised.exception.code, "native_process_failed")
        self.assertIsNone(raised.exception.diagnostic)
        self.assertNotIn(SECRET, str(raised.exception))


class ExplicitPhaseContextTests(unittest.TestCase):
    def setUp(self):
        self.reader_patch = mock.patch.object(
            runner, "_start_reader", side_effect=synchronous_start)
        self.reader_patch.start()
        self.addCleanup(self.reader_patch.stop)

    def test_list_and_run_failure_share_code_but_distinguish_phase(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        cfg = inventory.TARGETS[TARGET]

        with mock.patch.object(
                runner.subprocess, "Popen",
                return_value=FakeProcess(b"", returncode=101)):
            with self.assertRaises(runner.RunnerError) as listed:
                runner._list_target("fake", cfg, 5.0, TARGET)
        self.assertEqual(listed.exception.code, "native_process_failed")
        list_diag = listed.exception.diagnostic
        self.assertEqual(list_diag["phase"], "list")
        self.assertEqual(list_diag["scope"], "list")
        self.assertIsNone(list_diag["selected_case"])
        self.assertFalse(list_diag["selected_case_known"])
        self.assertEqual(list_diag["error_class"], "native_process_failed")
        self.assertEqual(list_diag["returncode"], 101)
        self.assertEqual(list_diag["cases"], [])
        self.assertEqual(list_diag["source_allowlist"],
                         list(runner.SOURCE_ALLOWLIST))

        with mock.patch.object(
                runner.subprocess, "Popen",
                return_value=FakeProcess(b"", returncode=101)):
            with self.assertRaises(runner.RunnerError) as ran:
                runner._run_one("fake", cases[0], 5.0, target=TARGET)
        self.assertEqual(ran.exception.code, "native_process_failed")
        run_diag = ran.exception.diagnostic
        self.assertEqual(run_diag["phase"], "run")
        self.assertEqual(run_diag["scope"], "case")
        self.assertEqual(run_diag["selected_case"], cases[0])
        self.assertTrue(run_diag["selected_case_known"])
        self.assertEqual(run_diag["error_class"], "native_process_failed")
        self.assertEqual(run_diag["returncode"], 101)
        self.assertEqual(run_diag["cases"], [])

    def test_unknown_selected_case_context_is_dropped(self):
        context = {"target": TARGET, "phase": "run", "selected_case": SECRET}
        with mock.patch.object(
                runner.subprocess, "Popen",
                return_value=FakeProcess(b"", returncode=101)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1,
                                   failure_context=context)
        diag = raised.exception.diagnostic
        self.assertEqual(diag["phase"], "run")
        self.assertIsNone(diag["selected_case"])
        self.assertFalse(diag["selected_case_known"])
        self.assertNotIn(SECRET, json.dumps(diag, sort_keys=True))

    def test_context_survives_parser_failure_and_empty_output(self):
        cases = inventory.TARGETS[TARGET]["cases"]
        context = {"target": TARGET, "phase": "run",
                   "selected_case": cases[0]}
        with mock.patch.object(
                runner.subprocess, "Popen",
                return_value=FakeProcess(b"", returncode=101)), \
             mock.patch.object(runner, "project_target_failure",
                               side_effect=RuntimeError(SECRET)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1,
                                   failure_context=context)
        self.assertEqual(raised.exception.code, "native_process_failed")
        diag = raised.exception.diagnostic
        self.assertEqual(diag["prefix"], runner.FAILURE_PREFIX)
        self.assertEqual(diag["phase"], "run")
        self.assertEqual(diag["selected_case"], cases[0])
        self.assertTrue(diag["selected_case_known"])
        self.assertEqual(diag["error_class"], "native_process_failed")
        self.assertEqual(diag["returncode"], 101)
        self.assertEqual(diag["exit"]["returncode"], 101)
        self.assertIsNone(diag["exit"]["signal"])
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["source_allowlist"],
                         list(runner.SOURCE_ALLOWLIST))
        self.assertEqual(diag["parse_caps"]["output_bytes"],
                         runner.MAX_CAPTURE_BYTES)
        self.assertNotIn(SECRET, json.dumps(diag, sort_keys=True))

    def test_invalid_phase_never_replaces_outer_failure(self):
        context = {"target": TARGET, "phase": "from-argv", "selected_case": None}
        with mock.patch.object(
                runner.subprocess, "Popen",
                return_value=FakeProcess(b"", returncode=101)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1,
                                   failure_context=context)
        self.assertEqual(raised.exception.code, "native_process_failed")
        self.assertIsNone(raised.exception.diagnostic)


def success_report():
    rows = []
    for target in inventory.TARGET_ORDER:
        cases = [{"name": name, "status": "passed"}
                 for name in inventory.TARGETS[target]["cases"]]
        rows.append({"target": target, "passed": True, "cases": cases,
                     "case_count": len(cases)})
    total = sum(len(inventory.TARGETS[target]["cases"])
                for target in inventory.TARGET_ORDER)
    return {
        "kind": runner.REPORT_KIND,
        "passed": True,
        "measurement_kind": "native_execution",
        "simulated_fields": False,
        "source_head": HEAD,
        "targets": rows,
        "case_count": total,
        "expected_count": total,
        "skips": 0,
        "pending_cases": [],
        "cleanup_unresolved": False,
        "error_codes": [],
        "input_closure_sha256": {"a": "f" * 64},
        "input_closure_after_sha256": {"a": "f" * 64},
    }


class AcceptanceFailureReportTests(unittest.TestCase):
    def setUp(self):
        self.reader_patch = mock.patch.object(
            runner, "_start_reader", side_effect=synchronous_start)
        self.reader_patch.start()
        self.addCleanup(self.reader_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.targets = {}
        self.receipts = {}
        for target in inventory.TARGET_ORDER:
            binary = self.root / target
            binary.write_bytes(b"fake binary")
            binary.chmod(0o755)
            receipt = self.root / (target + ".build.json")
            receipt.write_text("{}")
            self.targets[target] = str(binary)
            self.receipts[target] = str(receipt)
        self.fail_case_index = 0
        self.fail_listing = False
        self.identities = {
            target: {
                "target": target,
                "binary_sha256": "b" * 64,
                "receipt_sha256": "e" * 64,
                "source_inputs_sha256": "c" * 64,
                "config_digest": "d" * 64,
                "kind": "rust-integration-test",
                "profile": "test",
                "test_count": len(inventory.TARGETS[target]["cases"]),
                "required_env": [],
                "command_test_targets": [],
            }
            for target in inventory.TARGET_ORDER
        }

    def tearDown(self):
        self.temp.cleanup()

    def _popen(self, command):
        target = Path(command[0]).name
        if "--list" in command:
            if target == FAIL_TARGET and self.fail_listing:
                return FakeProcess(b"", returncode=101)
            payload = "\n".join(
                name + ": test" for name in inventory.TARGETS[target]["cases"]
            ).encode()
            return FakeProcess(payload, returncode=0)
        name = command[1]
        failing_name = inventory.TARGETS[target]["cases"][self.fail_case_index]
        if target == FAIL_TARGET and name == failing_name:
            output = "\n".join([
                case_line(name, "FAILED"),
                summary("FAILED", 0, 1, 0),
            ]).encode()
            stderr = "\n".join([
                "thread 'x' panicked at tests/ref_store_pack_snapshots.rs:42:9:",
                SECRET,
                SQL,
                DSN,
            ]).encode()
            return FakeProcess(output, stderr=stderr, returncode=101)
        payload = "\n".join([case_line(name, "ok"), summary("ok", 1, 0, 0)]).encode()
        return FakeProcess(payload, returncode=0)

    def _run(self, report_name):
        report_path = self.root / report_name
        with mock.patch.object(runner, "input_hashes",
                               return_value={"a": "f" * 64}), \
             mock.patch.object(runner, "_required_environment", return_value=None), \
             mock.patch.object(runner, "_receipt_identity",
                               side_effect=lambda target, *args: self.identities[target]), \
             mock.patch.object(runner.subprocess, "Popen",
                               side_effect=lambda command, **kwargs: self._popen(command)):
            return runner.run_acceptance(
                HEAD, self.source, self.targets, self.receipts,
                report_path=report_path), report_path

    def test_nonzero_target_failure_is_attached_before_propagation(self):
        report, report_path = self._run("failure.json")
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_codes"], ["native_process_failed"])
        self.assertEqual(report["expected_count"], 167)
        self.assertEqual(report["case_count"], 66)
        self.assertEqual(report["observed_case_count"], 67)
        self.assertEqual([row["target"] for row in report["targets"]],
                         list(inventory.TARGET_ORDER[:6]))
        failed = report["targets"][-1]
        self.assertEqual(failed["target"], FAIL_TARGET)
        self.assertFalse(failed["passed"])
        self.assertEqual(failed["diagnostic"]["target"], FAIL_TARGET)
        self.assertEqual(failed["diagnostic"]["exit"]["returncode"], 101)
        self.assertEqual(failed["diagnostic"]["error_class"],
                         "native_process_failed")
        self.assertEqual(failed["phase"], "run")
        self.assertEqual(failed["selected_case"],
                         inventory.TARGETS[FAIL_TARGET]["cases"][0])
        self.assertTrue(failed["selected_case_known"])
        self.assertEqual(failed["diagnostic"]["phase"], "run")
        self.assertEqual(failed["diagnostic"]["selected_case"],
                         inventory.TARGETS[FAIL_TARGET]["cases"][0])
        self.assertEqual(failed["diagnostic"]["source_allowlist"],
                         list(runner.SOURCE_ALLOWLIST))
        self.assertEqual(failed["diagnostic"]["case_counts"]["failed"], 1)
        self.assertEqual(failed["diagnostic"]["source_locations"],
                         [{"file": "tests/ref_store_pack_snapshots.rs", "line": 42}])
        self.assertEqual(report["failed_target"]["target"], FAIL_TARGET)
        self.assertEqual(failed["case_count"], 1)
        self.assertEqual(failed["cases"][0]["status"], "failed")

        persisted = json.loads(report_path.read_text())
        self.assertEqual(persisted["failed_target"]["target"], FAIL_TARGET)
        serialized = report_path.read_text()
        for forbidden in (SECRET, SQL, DSN, "supersecret", "panic statement"):
            self.assertNotIn(forbidden, serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_list_failure_report_records_list_phase_and_null_case(self):
        self.fail_listing = True
        report, report_path = self._run("list-failure.json")
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_codes"], ["native_process_failed"])
        self.assertEqual(report["case_count"], 66)
        failed = report["targets"][-1]
        self.assertEqual(failed["target"], FAIL_TARGET)
        self.assertEqual(failed["phase"], "list")
        self.assertIsNone(failed["selected_case"])
        self.assertFalse(failed["selected_case_known"])
        self.assertEqual(failed["diagnostic"]["phase"], "list")
        self.assertIsNone(failed["diagnostic"]["selected_case"])
        self.assertEqual(failed["diagnostic"]["error_class"],
                         "native_process_failed")
        self.assertEqual(failed["diagnostic"]["returncode"], 101)
        self.assertEqual(failed["cases"], [])
        self.assertNotIn(SECRET, report_path.read_text())

    def test_completed_cases_in_failing_target_are_recorded_honestly(self):
        self.fail_case_index = 2
        report, report_path = self._run("partial-failure.json")
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_codes"], ["native_process_failed"])
        self.assertEqual(report["case_count"], 68)
        self.assertEqual(report["observed_case_count"], 69)
        failed = report["targets"][-1]
        self.assertEqual(failed["target"], FAIL_TARGET)
        self.assertEqual(failed["phase"], "run")
        self.assertEqual(failed["selected_case"],
                         inventory.TARGETS[FAIL_TARGET]["cases"][2])
        self.assertEqual(failed["case_count"], 3)
        self.assertEqual([row["status"] for row in failed["cases"]],
                         ["passed", "passed", "failed"])
        self.assertEqual(
            [row["name"] for row in failed["cases"]],
            list(inventory.TARGETS[FAIL_TARGET]["cases"][:3]))
        self.assertEqual(failed["diagnostic"]["inventory"]["observed"], 3)
        self.assertEqual(failed["diagnostic"]["inventory"]["missing"],
                         len(inventory.TARGETS[FAIL_TARGET]["cases"]) - 3)
        self.assertNotIn(SECRET, report_path.read_text())

    def test_all_success_report_has_no_failure_only_fields(self):
        def no_failure(command):
            target = Path(command[0]).name
            if "--list" in command:
                payload = "\n".join(
                    name + ": test" for name in inventory.TARGETS[target]["cases"]
                ).encode()
                return FakeProcess(payload, returncode=0)
            payload = "\n".join([case_line(command[1], "ok"),
                                 summary("ok", 1, 0, 0)]).encode()
            return FakeProcess(payload, returncode=0)

        with mock.patch.object(runner, "input_hashes",
                               return_value={"a": "f" * 64}), \
             mock.patch.object(runner, "_required_environment", return_value=None), \
             mock.patch.object(runner, "_receipt_identity",
                               side_effect=lambda target, *args: self.identities[target]), \
             mock.patch.object(runner.subprocess, "Popen",
                               side_effect=lambda command, **kwargs: no_failure(command)):
            report = runner.run_acceptance(
                HEAD, self.source, self.targets, self.receipts,
                report_path=self.root / "success.json")
        self.assertTrue(report["passed"])
        self.assertEqual(report["case_count"], 167)
        self.assertNotIn("failed_target", report)
        self.assertNotIn("observed_case_count", report)
        self.assertEqual([row["target"] for row in report["targets"]],
                         list(inventory.TARGET_ORDER))
        self.assertTrue(all(row["passed"] for row in report["targets"]))
        self.assertTrue(all("diagnostic" not in row for row in report["targets"]))
        self.assertEqual(runner.validate_report(report, HEAD),
                         {"targets": 11, "cases": 167})

    def test_success_contract_accepts_optional_clear_empty_diagnostic(self):
        report = success_report()
        report["failed_target"] = None
        for row in report["targets"]:
            row["diagnostic"] = None
        self.assertEqual(runner.validate_report(report, HEAD),
                         {"targets": 11, "cases": 167})


class MetadataReplayTraceTests(unittest.TestCase):
    target = runner.METADATA_REPLAY_TARGET
    case = runner.METADATA_REPLAY_CASE

    def _frame(self, phase, site, event, ok="", status="", counts="", checks="", iteration="", error_kind=""):
        return "|".join([
            runner.METADATA_REPLAY_PREFIX,
            str(phase), str(site), str(event), ok, status, counts, checks,
            iteration, error_kind,
        ])

    def _git_frame(self, outcome, exit_code="", signal="", message="0"):
        return "|".join([
            runner.HISTORICAL_GIT_PREFIX,
            str(runner.HISTORICAL_GIT_PHASE),
            str(runner.HISTORICAL_GIT_SITE),
            str(outcome), exit_code, signal, str(message),
        ])

    def _historical_git_failure(self, child=None, packs=2, site9_kind="6"):
        lines = self._historical_failure_prefix(9, packs=packs)
        lines.append(self._frame(17, 9, 0))
        if child is not None:
            lines.append(child)
        lines.extend([
            self._frame(17, 9, 1, ok="0", error_kind=site9_kind),
            self._frame(17, 1, 1, ok="0"),
        ])
        lines.extend(self._finish(ok=True))
        return lines

    def _project(self, lines, stdout=b"", **changes):
        options = {"phase": "run", "selected_case": self.case}
        options.update(changes)
        payload = ("\n".join(lines) + ("\n" if lines else "")).encode()
        return runner.project_target_failure(
            self.target, stdout, 101, stderr=payload, **options)

    def _historical_parent_success(self, packs=2):
        lines = [
            self._frame(17, 1, 0),
            self._frame(17, 3, 0),
            self._frame(17, 3, 1, ok="1"),
            self._frame(17, 4, 0),
            self._frame(17, 4, 1, ok="1"),
        ]
        for _ in range(packs):
            for site in (5, 7, 6, 8):
                lines.extend([
                    self._frame(17, site, 0),
                    self._frame(17, site, 1, ok="1"),
                ])
        lines.extend([
            self._frame(17, 9, 0),
            self._frame(17, 9, 1, ok="1"),
            self._frame(17, 1, 1, ok="1"),
        ])
        return lines

    def _historical_assert(self, lines, ok=True, status=""):
        lines.append(self._frame(17, 2, 0))
        if ok:
            lines.append(self._frame(17, 2, 1, ok="1", status=status))
        else:
            lines.append(self._frame(17, 2, 2, ok="0", status=status))
        return lines

    def _finish(self, ok=True):
        return [
            self._frame(24, 1, 0),
            self._frame(24, 1, 1, ok="1" if ok else "0"),
        ]

    def _historical_failure_prefix(self, fail_site, packs=2):
        lines = [self._frame(17, 1, 0)]
        if fail_site == 3:
            return lines
        lines.extend([
            self._frame(17, 3, 0),
            self._frame(17, 3, 1, ok="1"),
        ])
        if fail_site == 4:
            return lines
        lines.extend([
            self._frame(17, 4, 0),
            self._frame(17, 4, 1, ok="1"),
        ])
        for _ in range(packs):
            for site in (5, 7, 6, 8):
                if site == fail_site:
                    return lines
                lines.extend([
                    self._frame(17, site, 0),
                    self._frame(17, site, 1, ok="1"),
                ])
        return lines

    def test_valid_frame_survives_projection_safe_rebuild_and_attach(self):
        lines = self._historical_assert(
            self._historical_parent_success(packs=2), ok=False)
        lines.extend(self._finish(ok=True))
        diag = self._project(lines)
        trace = diag["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["incomplete"])
        self.assertFalse(trace["invalid"])
        self.assertEqual(trace["frames"], len(lines))
        self.assertEqual(trace["first_failure"]["phase"], 17)
        self.assertEqual(trace["first_failure"]["site"], 2)
        self.assertIsNone(trace["first_failure"]["status"])
        self.assertIsNone(trace["first_failure"]["error_kind"])
        self.assertEqual(trace["primary"]["site_name"], "exact_first_advance_content_assert")
        self.assertIsNone(trace["status"])
        self.assertIsNone(trace["error_kind"])
        self.assertIsNone(trace["last_incomplete"])
        self.assertTrue(trace["cleanup_completed"])
        self.assertEqual(trace["last_completed"]["phase"], 24)
        self.assertEqual(trace["last_completed"]["ok"], True)

        safe = runner._safe_failure_diagnostic(diag, self.target)
        self.assertEqual(safe["case_trace"]["primary"], trace["primary"])
        self.assertEqual(safe["case_trace"]["cleanup_completed"], True)
        report = {"targets": []}
        runner._attach_failed_target(report, diag, {}, [])
        attached = report["targets"][0]["case_trace"]
        self.assertEqual(attached["primary"], trace["primary"])
        self.assertIsNone(attached["first_failure"]["status"])
        self.assertIsNone(attached["first_failure"]["error_kind"])
        serialized = json.dumps(report)
        for forbidden in (SECRET, SQL, DSN):
            self.assertNotIn(forbidden, serialized)

    def test_failed_operation_event_and_marker_alone_cannot_pass(self):
        lines = [
            self._frame(18, 2, 0),
            self._frame(18, 2, 1, ok="0", status="500"),
        ]
        diag = self._project(
            lines, stdout=(summary("ok", 1, 0, 0) + "\n").encode())
        trace = diag["case_trace"]
        self.assertTrue(trace["known"])
        self.assertEqual(trace["first_failure"]["event"], 1)
        self.assertFalse(trace["first_failure"]["ok"])
        self.assertEqual(trace["first_failure"]["status"], 500)
        self.assertEqual(trace["primary"]["site"], 2)
        self.assertEqual(diag["case_counts"]["passed"], 0)
        self.assertEqual(diag["cases"], [])

    def test_historical_subsites_and_closed_error_kind_survive_rebuild(self):
        lines = [
            self._frame(17, 1, 0),
            self._frame(17, 3, 0),
            self._frame(17, 3, 1, ok="1"),
            self._frame(17, 4, 0),
            self._frame(17, 4, 1, ok="1"),
            self._frame(17, 5, 0),
            self._frame(17, 5, 1, ok="0", error_kind="4"),
            self._frame(17, 1, 1, ok="0"),
        ]
        lines.extend(self._finish(ok=True))
        trace = self._project(lines)["case_trace"]
        self.assertTrue(trace["known"])
        self.assertEqual(trace["first_failure"]["phase_name"], "historical_content")
        self.assertEqual(trace["first_failure"]["site_name"], "exact_pack_bytes")
        self.assertEqual(trace["first_failure"]["error_kind"], 4)
        self.assertEqual(trace["primary"], trace["first_failure"])
        self.assertTrue(trace["cleanup_completed"])
        safe = runner._safe_failure_diagnostic(
            self._project(lines), self.target)["case_trace"]
        self.assertEqual(safe["primary"]["site_name"], "exact_pack_bytes")
        self.assertEqual(safe["primary"]["error_kind"], 4)

    def test_full_historical_producer_sequence_two_packs_survives_all_layers(self):
        lines = self._historical_assert(
            self._historical_parent_success(packs=2))
        lines.extend(self._finish(ok=True))
        trace = self._project(lines)["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["incomplete"])
        self.assertFalse(trace["invalid"])
        self.assertEqual(trace["frames"], len(lines))
        self.assertIsNone(trace["first_failure"])
        self.assertTrue(trace["cleanup_completed"])
        # Two complete pack groups in the actual 5 -> 7 -> 6 -> 8 order.
        self.assertEqual(sum(1 for line in lines
                             if line == self._frame(17, 5, 0)), 2)
        sites = [int(line.split("|")[2]) for line in lines
                 if line.startswith(runner.METADATA_REPLAY_PREFIX)]
        first = sites.index(5)
        self.assertEqual(sites[first:first + 8], [5, 5, 7, 7, 6, 6, 8, 8])
        parent_close = lines.index(self._frame(17, 1, 1, ok="1"))
        assert_close = lines.index(self._frame(17, 2, 0))
        self.assertLess(parent_close, assert_close)
        safe = runner._safe_failure_diagnostic(
            self._project(lines), self.target)["case_trace"]
        self.assertTrue(safe["known"])
        self.assertTrue(safe["cleanup_completed"])

    def test_failed_site2_rejects_business_phases_but_allows_cleanup(self):
        for phase in range(18, 24):
            lines = self._historical_assert(
                self._historical_parent_success(packs=2), ok=False)
            lines.extend([
                self._frame(phase, 1, 0),
                self._frame(phase, 1, 1, ok="1"),
            ])
            lines.extend(self._finish(ok=True))
            trace = self._project(lines)["case_trace"]
            self.assertFalse(trace["known"], phase)
            self.assertTrue(trace["invalid"], phase)
            self.assertIsNone(trace["primary"], phase)
        cleanup = self._historical_assert(
            self._historical_parent_success(packs=2), ok=False)
        cleanup.extend(self._finish(ok=True))
        trace = self._project(cleanup)["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["invalid"])
        self.assertEqual(trace["first_failure"]["site"], 2)
        self.assertEqual(trace["primary"]["site"], 2)
        self.assertTrue(trace["cleanup_completed"])

    def test_successful_site2_allows_business_phase_then_cleanup(self):
        lines = self._historical_assert(
            self._historical_parent_success(packs=2), ok=True)
        lines.extend([
            self._frame(18, 1, 0),
            self._frame(18, 1, 1, ok="1"),
        ])
        lines.extend(self._finish(ok=True))
        trace = self._project(lines)["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["invalid"])
        self.assertIsNone(trace["first_failure"])
        self.assertTrue(trace["cleanup_completed"])
        self.assertEqual(trace["last_completed"]["phase"], 24)

    def test_failure_at_each_historical_subcall_keeps_typed_primary(self):
        kinds = {3: 1, 4: 1, 5: 4, 7: 1, 6: 4, 8: 1, 9: 6}
        for site, kind in kinds.items():
            lines = self._historical_failure_prefix(site, packs=2)
            lines.extend([
                self._frame(17, site, 0),
                self._frame(17, site, 1, ok="0", error_kind=str(kind)),
                self._frame(17, 1, 1, ok="0"),
            ])
            lines.extend(self._finish(ok=True))
            diag = self._project(lines)
            trace = diag["case_trace"]
            self.assertTrue(trace["known"], site)
            self.assertFalse(trace["invalid"], site)
            self.assertEqual(trace["first_failure"]["site"], site)
            self.assertEqual(trace["first_failure"]["error_kind"], kind)
            self.assertEqual(trace["primary"], trace["first_failure"])
            self.assertTrue(trace["cleanup_completed"])
            safe = runner._safe_failure_diagnostic(
                diag, self.target)["case_trace"]
            self.assertEqual(safe["primary"]["site"], site)
            self.assertEqual(safe["primary"]["error_kind"], kind)
            report = {"targets": []}
            runner._attach_failed_target(report, diag, {}, [])
            attached = report["targets"][0]["case_trace"]
            self.assertEqual(attached["primary"]["site"], site)
            self.assertEqual(attached["primary"]["error_kind"], kind)

    def test_historical_git_child_frame_is_adopted_without_changing_primary(self):
        child = self._git_frame(1, exit_code="128", message="2")
        lines = self._historical_git_failure(child=child)
        self.assertLess(
            lines.index(child),
            lines.index(self._frame(17, 9, 1, ok="0", error_kind="6")))
        diag = self._project(lines)
        trace = diag["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["incomplete"])
        self.assertFalse(trace["invalid"])
        self.assertEqual(trace["frames"], sum(
            1 for line in lines
            if line.startswith(runner.METADATA_REPLAY_PREFIX)))
        self.assertEqual(trace["historical_git"], {
            "protocol": runner.HISTORICAL_GIT_PROTOCOL,
            "phase": runner.HISTORICAL_GIT_PHASE,
            "site": runner.HISTORICAL_GIT_SITE,
            "outcome": 1,
            "exit_code": 128,
            "signal": None,
            "message_class": 2,
        })
        self.assertEqual(trace["first_failure"]["phase"], 17)
        self.assertEqual(trace["first_failure"]["site"], 9)
        self.assertEqual(trace["first_failure"]["error_kind"], 6)
        self.assertEqual(trace["primary"], trace["first_failure"])
        safe = runner._safe_failure_diagnostic(diag, self.target)["case_trace"]
        self.assertEqual(safe["historical_git"], trace["historical_git"])
        self.assertEqual(safe["primary"], trace["primary"])
        report = {"targets": []}
        runner._attach_failed_target(report, diag, {}, [])
        attached = report["targets"][0]["case_trace"]
        self.assertEqual(attached["historical_git"], trace["historical_git"])
        self.assertEqual(attached["primary"], trace["primary"])
        serialized = json.dumps(report)
        for forbidden in (SECRET, SQL, DSN):
            self.assertNotIn(forbidden, serialized)

    def test_historical_git_child_accepts_every_closed_outcome_and_class(self):
        for message in range(5):
            for outcome, fields in ((1, {"exit_code": "1"}),
                                    (2, {"signal": "127"})):
                child = self._git_frame(
                    outcome, message=str(message), **fields)
                trace = self._project(
                    self._historical_git_failure(child=child))["case_trace"]
                self.assertTrue(trace["known"])
                self.assertEqual(
                    trace["historical_git"]["outcome"], outcome)
                self.assertEqual(
                    trace["historical_git"]["message_class"], message)
        for outcome in (3, 4, 5, 6):
            child = self._git_frame(outcome)
            trace = self._project(
                self._historical_git_failure(child=child))["case_trace"]
            self.assertTrue(trace["known"])
            self.assertEqual(trace["historical_git"], {
                "protocol": runner.HISTORICAL_GIT_PROTOCOL,
                "phase": runner.HISTORICAL_GIT_PHASE,
                "site": runner.HISTORICAL_GIT_SITE,
                "outcome": outcome,
                "exit_code": None,
                "signal": None,
                "message_class": 0,
            })

    def test_historical_git_child_absent_is_unavailable_and_optional(self):
        lines = self._historical_git_failure(child=None)
        diag = self._project(lines)
        trace = diag["case_trace"]
        self.assertTrue(trace["known"])
        self.assertFalse(trace["invalid"])
        self.assertIsNone(trace["historical_git"])
        self.assertEqual(trace["first_failure"]["site"], 9)
        self.assertEqual(trace["primary"], trace["first_failure"])
        safe = runner._safe_failure_diagnostic(diag, self.target)["case_trace"]
        self.assertIsNone(safe["historical_git"])
        self.assertEqual(safe["primary"], trace["primary"])

        other = self._historical_failure_prefix(5, packs=2)
        other.extend([
            self._frame(17, 5, 0),
            self._frame(17, 5, 1, ok="0", error_kind="4"),
            self._frame(17, 1, 1, ok="0"),
        ])
        other.extend(self._finish(ok=True))
        other_trace = self._project(other)["case_trace"]
        self.assertTrue(other_trace["known"])
        self.assertFalse(other_trace["invalid"])
        self.assertIsNone(other_trace["historical_git"])
        self.assertEqual(other_trace["primary"]["site"], 5)

        success = self._historical_assert(
            self._historical_parent_success(packs=1))
        success.extend(self._finish(ok=True))
        success_trace = self._project(success)["case_trace"]
        self.assertTrue(success_trace["known"])
        self.assertIsNone(success_trace["historical_git"])

    def test_historical_git_child_rejects_duplicates_misplacement_and_success(self):
        child = self._git_frame(1, exit_code="1", message="0")
        duplicate = self._historical_git_failure(child=child) + [child]
        conflicting = self._historical_git_failure(child=child) + [
            self._git_frame(2, signal="9")]

        early = self._historical_failure_prefix(9, packs=2)
        early.append(child)
        early.extend([
            self._frame(17, 9, 0),
            self._frame(17, 9, 1, ok="0", error_kind="6"),
            self._frame(17, 1, 1, ok="0"),
        ])
        early.extend(self._finish(ok=True))

        late = self._historical_failure_prefix(9, packs=2)
        late.extend([
            self._frame(17, 9, 0),
            self._frame(17, 9, 1, ok="0", error_kind="6"),
        ])
        late.append(child)
        late.extend([
            self._frame(17, 1, 1, ok="0"),
        ])
        late.extend(self._finish(ok=True))

        success = self._historical_parent_success(packs=1)
        success.insert(success.index(self._frame(17, 9, 0)) + 1, child)
        success.extend(self._finish(ok=True))

        wrong_parent = self._historical_git_failure(
            child=child, site9_kind="5")
        for lines in (duplicate, conflicting, early, late, success,
                      wrong_parent):
            trace = self._project(lines)["case_trace"]
            self.assertFalse(trace["known"])
            self.assertTrue(trace["invalid"])
            self.assertIsNone(trace["historical_git"])
            self.assertIsNone(trace["primary"])

    def test_historical_git_child_rejects_malformed_or_unbounded_forms(self):
        prefix = runner.HISTORICAL_GIT_PREFIX
        malformed = [
            "|".join([prefix, "17", "9", "1", "1", "", "0", "0"]),
            "|".join([prefix, "17", "9", "1", "1", ""]),
            "|".join([prefix, "17", "9", "0", "", "", "0"]),
            "|".join([prefix, "17", "9", "7", "1", "", "0"]),
            "|".join([prefix, "17", "9", "1", "", "", "0"]),
            "|".join([prefix, "17", "9", "2", "", "", "0"]),
            "|".join([prefix, "17", "9", "1", "1", "9", "0"]),
            "|".join([prefix, "17", "9", "3", "1", "", "0"]),
            "|".join([prefix, "17", "9", "3", "", "", "1"]),
            "|".join([prefix, "17", "9", "6", "", "", "1"]),
            "|".join([prefix, "18", "9", "1", "1", "", "0"]),
            "|".join([prefix, "17", "8", "1", "1", "", "0"]),
            "|".join([prefix, "17", "9", "1", "01", "", "0"]),
            "|".join([prefix, "17", "9", "1", "1", "", "5"]),
            "|".join([prefix, "17", "9", "1", "1", "", "-1"]),
            "|".join([prefix, "17", "9", "1", "1", "", "0"]) + "x" * 513,
            "|".join([prefix, "17", "9", "1", "1", "", "\u0660"]),
        ]
        for child in malformed:
            lines = self._historical_git_failure(child=child)
            trace = self._project(lines)["case_trace"]
            self.assertFalse(trace["known"], child)
            self.assertTrue(trace["invalid"], child)
            self.assertIsNone(trace["historical_git"], child)
            self.assertIsNone(trace["primary"], child)
            serialized = json.dumps(trace)
            for forbidden in (SECRET, SQL, DSN):
                self.assertNotIn(forbidden, serialized)

    def test_historical_git_safe_rebuild_rejects_unvalidated_forms(self):
        diag = self._project(self._historical_git_failure(
            child=self._git_frame(1, exit_code="128", message="2")))
        trace = runner._safe_failure_diagnostic(diag, self.target)["case_trace"]
        self.assertTrue(trace["known"])
        valid_child = trace["historical_git"]
        valid_failure = trace["first_failure"]
        self.assertIsNotNone(valid_child)
        self.assertIsNotNone(valid_failure)

        missing = dict(valid_child)
        missing.pop("message_class")
        invalid_children = [
            {},
            dict(valid_child, extra="x"),
            missing,
            dict(valid_child, protocol="historical_git_v2"),
            dict(valid_child, protocol=1),
            dict(valid_child, phase=18),
            dict(valid_child, phase=17.0),
            dict(valid_child, phase=True),
            dict(valid_child, site=8),
            dict(valid_child, site=9.0),
            dict(valid_child, site=False),
            dict(valid_child, outcome=True),
            dict(valid_child, outcome="1"),
            dict(valid_child, outcome=0),
            dict(valid_child, outcome=7),
            dict(valid_child, exit_code=True),
            dict(valid_child, exit_code="128"),
            dict(valid_child, exit_code=-1),
            dict(valid_child, exit_code=2_147_483_648),
            dict(valid_child, signal=True),
            dict(valid_child, signal=0),
            dict(valid_child, signal=128),
            dict(valid_child, signal="9"),
            dict(valid_child, message_class=True),
            dict(valid_child, message_class=5),
            dict(valid_child, message_class="2"),
            dict(valid_child, exit_code=None),
            dict(valid_child, signal=9),
            dict(valid_child, outcome=2, exit_code=None, signal=None),
            dict(valid_child, outcome=2, exit_code=1, signal=9),
            dict(valid_child, outcome=3, exit_code=1, signal=None),
            dict(valid_child, outcome=3, exit_code=None, signal=9),
            dict(valid_child, outcome=3, exit_code=None, signal=None,
                 message_class=1),
            dict(valid_child, outcome=6, exit_code=None, signal=None,
                 message_class=1),
        ]
        for child in invalid_children:
            raw = dict(trace)
            raw["historical_git"] = child
            safe = runner._safe_metadata_replay_trace(raw)
            self.assertFalse(safe["known"], child)
            self.assertTrue(safe["invalid"], child)
            self.assertIsNone(safe["historical_git"], child)
            self.assertIsNone(safe["primary"], child)

        invalid_parents = [
            dict(valid_failure, phase=16),
            dict(valid_failure, site=8),
            dict(valid_failure, event=0, ok=None),
            dict(valid_failure, ok=True),
            dict(valid_failure, error_kind=5),
            dict(valid_failure, status=500),
            dict(valid_failure, counts=[0, 0, 0, 0, 0]),
            dict(valid_failure, checks=[True]),
            dict(valid_failure, iteration=0),
        ]
        for parent in invalid_parents:
            raw = dict(trace)
            raw["first_failure"] = parent
            safe = runner._safe_metadata_replay_trace(raw)
            self.assertFalse(safe["known"], parent)
            self.assertTrue(safe["invalid"], parent)
            self.assertIsNone(safe["historical_git"], parent)
            self.assertIsNone(safe["primary"], parent)

        for key, value in (("known", False), ("invalid", True),
                           ("incomplete", True), ("frames", 0)):
            raw = dict(trace)
            raw[key] = value
            safe = runner._safe_metadata_replay_trace(raw)
            self.assertFalse(safe["known"], key)
            self.assertTrue(safe["invalid"], key)
            self.assertIsNone(safe["historical_git"], key)
            self.assertIsNone(safe["primary"], key)

        raw = dict(trace)
        raw["historical_git"] = dict(valid_child, protocol=SECRET)
        safe = runner._safe_metadata_replay_trace(raw)
        self.assertNotIn(SECRET, json.dumps(safe, sort_keys=True))

        safe = runner._safe_metadata_replay_trace(dict(trace))
        self.assertTrue(safe["known"])
        self.assertFalse(safe["invalid"])
        self.assertEqual(safe["historical_git"], valid_child)
        self.assertEqual(safe["primary"], valid_failure)

    def test_historical_grammar_rejects_skip_backtrack_duplicate_crossphase(self):
        p = self._frame
        invalid = [
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="1"),
             p(17, 5, 0)],
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="1"),
             p(17, 4, 0), p(17, 4, 1, ok="1"),
             p(17, 5, 0), p(17, 5, 1, ok="1"), p(17, 6, 0)],
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="1"),
             p(17, 4, 0), p(17, 4, 1, ok="1"),
             p(17, 5, 0), p(17, 5, 1, ok="1"),
             p(17, 7, 0), p(17, 7, 1, ok="1"), p(17, 7, 0)],
            [p(17, 1, 0), p(17, 3, 0), p(18, 1, 0)],
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="0"),
             p(17, 1, 1, ok="0"), p(18, 1, 0)],
            [p(17, 1, 0), p(17, 3, 0, iteration="0")],
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="1"),
             p(17, 4, 0), p(17, 4, 1, ok="1"),
             p(17, 5, 0), p(17, 5, 1, ok="1"),
             p(17, 7, 0), p(17, 7, 1, ok="1"),
             p(17, 6, 0), p(17, 6, 1, ok="1"),
             p(17, 8, 0), p(17, 8, 1, ok="1"),
             p(17, 1, 1, ok="1")],
            [p(17, 1, 0), p(17, 3, 0), p(17, 3, 1, ok="1"),
             p(17, 4, 0), p(17, 4, 1, ok="1"),
             p(17, 5, 0), p(17, 5, 1, ok="1"),
             p(17, 7, 0), p(17, 7, 1, ok="1"),
             p(17, 6, 0), p(17, 6, 1, ok="1"),
             p(17, 8, 0), p(17, 8, 1, ok="1"),
             p(17, 9, 0), p(17, 9, 1, ok="1"),
             p(17, 2, 0)],
            self._historical_parent_success(packs=1),
        ]
        for lines in invalid:
            trace = self._project(lines)["case_trace"]
            self.assertFalse(trace["known"])
            self.assertTrue(trace["invalid"])
            self.assertIsNone(trace["primary"])

    def test_historical_duplicate_site2_and_secret_payload_fail_closed(self):
        lines = self._historical_assert(
            self._historical_parent_success(packs=1))
        duplicated = lines + [self._frame(17, 2, 0)]
        trace = self._project(duplicated)["case_trace"]
        self.assertFalse(trace["known"])
        self.assertTrue(trace["invalid"])
        secret = self._frame(17, 5, 1, ok="0", status=SECRET)
        trace = self._project([
            self._frame(17, 1, 0),
            self._frame(17, 3, 0), self._frame(17, 3, 1, ok="1"),
            self._frame(17, 4, 0), self._frame(17, 4, 1, ok="1"),
            self._frame(17, 5, 0), secret,
        ])["case_trace"]
        self.assertFalse(trace["known"])
        self.assertTrue(trace["invalid"])
        self.assertNotIn(SECRET, json.dumps(trace, sort_keys=True))

    def test_closed_error_kind_map_covers_only_source_classes(self):
        expected = {
            3: "git_repo_new",
            4: "pack_dir_create",
            5: "exact_pack_bytes",
            6: "exact_idx_bytes",
            7: "write_pack",
            8: "write_idx",
            9: "cat_file",
        }
        for site, name in expected.items():
            self.assertEqual(
                runner._metadata_replay_location(17, site),
                {"phase": 17, "site": site,
                 "phase_name": "historical_content", "site_name": name},
            )
        self.assertEqual(set(runner.METADATA_REPLAY_ERROR_KINDS),
                         set(range(1, runner.METADATA_REPLAY_MAX_ERROR_KIND + 1)))

    def test_phase17_field_schema_rejects_impossible_ancillary_fields(self):
        p = self._frame
        parent = self._historical_parent_success(packs=1)
        child_prefix = self._historical_failure_prefix(5, packs=2)
        invalid = [
            [p(17, 1, 0, status="200")],
            [p(17, 1, 0, iteration="0")],
            [p(17, 1, 0), p(17, 1, 1, ok="1", error_kind="4")],
            parent + [p(17, 2, 2, ok="0", status="404")],
            parent + [p(17, 2, 2, ok="0", error_kind="4")],
            parent + [p(17, 2, 0), p(17, 2, 2, ok="0", checks="1")],
            parent + [p(17, 2, 0), p(17, 2, 1, ok="0")],
            parent + [p(17, 2, 0, counts="1,2,3,4,5")],
            child_prefix + [p(17, 5, 0, status="200")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="1", status="200")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="1", error_kind="4")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="1", counts="0,0,0,0,0")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="1", iteration="0")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="0")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="0", status="200", error_kind="4")],
            child_prefix + [p(17, 5, 0), p(17, 5, 1, ok="0", error_kind="8")],
            child_prefix + [p(17, 5, 0), p(17, 5, 2, ok="0")],
        ]
        for lines in invalid:
            trace = self._project(lines)["case_trace"]
            self.assertFalse(trace["known"])
            self.assertTrue(trace["invalid"])
            self.assertIsNone(trace["primary"])

    def test_unknown_or_bool_error_kind_is_rejected_without_text(self):
        prefix = [
            self._frame(17, 1, 0),
            self._frame(17, 3, 0),
            self._frame(17, 3, 1, ok="1"),
            self._frame(17, 4, 0),
            self._frame(17, 4, 1, ok="1"),
            self._frame(17, 5, 0),
        ]
        bad = [
            self._frame(17, 5, 1, ok="0", error_kind="9"),
            self._frame(17, 5, 1, ok="0", error_kind=SECRET),
        ]
        for payload in bad:
            diag = self._project(prefix + [payload])
            trace = diag["case_trace"]
            self.assertFalse(trace["known"])
            self.assertTrue(trace["invalid"])
            self.assertNotIn(SECRET, json.dumps(diag, sort_keys=True))
        lines = self._historical_assert(
            self._historical_parent_success(packs=1))
        lines.extend(self._finish(ok=True))
        valid = self._project(lines)["case_trace"]
        for bad_kind in (True, 99, "4", SECRET):
            raw = dict(valid)
            raw["last_completed"] = dict(
                valid["last_completed"], error_kind=bad_kind)
            safe = runner._safe_metadata_replay_trace(raw)
            self.assertTrue(safe["invalid"])
            self.assertNotIn(SECRET, json.dumps(safe, sort_keys=True))

    def test_checks_and_counts_are_fixed_bounded_fields(self):
        lines = [
            self._frame(16, 3, 0),
            self._frame(16, 3, 1, ok="1", checks="1,0,1"),
        ]
        diag = self._project(lines)
        trace = diag["case_trace"]
        self.assertEqual(trace["last_completed"]["checks"], [True, False, True])
        self.assertEqual(trace["checks"], [True, False, True])
        counts_lines = [
            self._frame(18, 1, 0),
            self._frame(18, 1, 1, ok="1", counts="0,1,2,3,4"),
        ]
        counts_trace = self._project(counts_lines)["case_trace"]
        self.assertEqual(counts_trace["counts"], [0, 1, 2, 3, 4])

    def test_invalid_frames_are_unknown_and_never_retain_text(self):
        malformed = [
            self._frame(17, 1, 0) + "|extra",
            self._frame(17, 1, 1, ok="1", status=SECRET),
            self._frame(17, 1, 1, ok="2"),
            self._frame(17, 1, 1, ok="1", checks="2"),
            self._frame(17, 99, 0),
            self._frame(17, 1, 3),
            self._frame(17, 1, 0) + "\n" + self._frame(17, 2, 0),
        ]
        for bad in malformed:
            diag = self._project([bad])
            trace = diag["case_trace"]
            self.assertFalse(trace["known"])
            self.assertTrue(trace["incomplete"])
            self.assertTrue(trace["invalid"])
            self.assertIsNone(trace["last_event"])
            serialized = json.dumps(diag)
            for forbidden in (SECRET, SQL, DSN):
                self.assertNotIn(forbidden, serialized)

    def test_truncated_frame_is_incomplete_not_a_completion(self):
        diag = runner.project_target_failure(
            self.target,
            b"",
            101,
            stderr=self._frame(17, 1, 0).encode(),
            phase="run",
            selected_case=self.case,
        )
        trace = diag["case_trace"]
        self.assertFalse(trace["known"])
        self.assertTrue(trace["incomplete"])
        self.assertFalse(trace["invalid"])
        self.assertIsNone(trace["last_event"])
        self.assertIsNone(trace["primary"])
        safe = runner._safe_failure_diagnostic(diag, self.target)["case_trace"]
        self.assertFalse(safe["known"])
        self.assertTrue(safe["incomplete"])
        self.assertFalse(safe["invalid"])
        self.assertIsNone(safe["primary"])

    def test_cleanup_failure_does_not_replace_earlier_incomplete_primary(self):
        lines = [
            self._frame(17, 1, 0),
            self._frame(17, 3, 0),
            self._frame(17, 3, 1, ok="1"),
            self._frame(17, 4, 0),
            self._frame(17, 4, 1, ok="1"),
            self._frame(17, 5, 0),
            self._frame(17, 5, 1, ok="0", error_kind="4"),
            self._frame(17, 1, 1, ok="0"),
        ]
        lines.extend(self._finish(ok=False))
        trace = self._project(lines)["case_trace"]
        self.assertEqual(trace["first_failure"]["phase"], 17)
        self.assertEqual(trace["first_failure"]["site"], 5)
        self.assertEqual(trace["primary"]["phase"], 17)
        self.assertEqual(trace["primary"]["site"], 5)
        self.assertEqual(trace["last_completed"]["phase"], 24)
        self.assertFalse(trace["cleanup_completed"])

    def test_frame_parser_is_gated_to_exact_target_phase_and_case(self):
        lines = self._historical_assert(
            self._historical_parent_success(packs=1))
        self.assertIsNone(self._project(lines, phase="list", selected_case=None)["case_trace"])
        self.assertIsNone(self._project(lines, selected_case=inventory.TARGETS[self.target]["cases"][1])["case_trace"])
        other = inventory.TARGETS[TARGET]["cases"][0]
        diag = runner.project_target_failure(
            TARGET, b"", 101,
            stderr=("\n".join(lines) + "\n").encode(),
            phase="run", selected_case=other)
        self.assertIsNone(diag["case_trace"])


if __name__ == "__main__":
    unittest.main()
