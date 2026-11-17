#!/usr/bin/env python3
"""Pure contract tests for the 17-case producer PG execution and report.

No real Cargo, subprocess, Git, PostgreSQL, Vault, HTTP, network, Docker or
compiler is used.  The selected executable, source captures, fixture cleanup,
case runner and report writer are deterministic fakes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.cases as cases  # noqa: E402
import pando_producer_pg.report as report  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
from pando_producer_pg.process import Completed  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402

BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"
BINARY = "/tmp/owned/target/debug/deps/rootyard_pando_lab-abc"


def ok_output(name):
    return (
        "running 1 test\n"
        "test %s ... ok\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.01s\n" % name
    ).encode()


def failed_output(name):
    return (
        "running 1 test\n"
        "test %s ... FAILED\n\n"
        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.01s\n" % name
    ).encode()


class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class CaseSetTest(unittest.TestCase):
    def test_exact_seventeen_names_and_family_counts(self):
        self.assertEqual(len(cases.CASES), 17)
        self.assertEqual(len(set(cases.CASE_NAMES)), 17)
        counts = cases.family_counts(cases.not_run_records())
        self.assertEqual(counts["migration"]["total"], 7)
        self.assertEqual(counts["repack"]["total"], 5)
        self.assertEqual(counts["snapshot"]["total"], 5)

    def test_passing_summary_is_accepted(self):
        name = cases.CASE_NAMES[0]
        self.assertEqual(
            cases.parse_libtest(ok_output(name), name),
            {"passed": 1, "failed": 0, "ignored": 0, "filtered": 0},
        )

    def assert_code(self, output, name, code):
        with self.assertRaises(RunnerError) as caught:
            cases.parse_libtest(output, name)
        self.assertEqual(caught.exception.code, code)

    def test_zero_tests_exit_zero_is_failure(self):
        output = (
            b"running 0 tests\n\n"
            b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
            b"0 filtered out; finished in 0.00s\n"
        )
        self.assert_code(output, cases.CASE_NAMES[0], "zero_tests")

    def test_ignored_wrong_missing_duplicate_and_unexpected_cases_fail(self):
        name = cases.CASE_NAMES[0]
        other = cases.CASE_NAMES[1]
        self.assert_code(
            ("running 1 test\ntest %s ... ignored\n\n"
             "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; "
             "0 filtered out; finished in 0.01s\n" % name).encode(),
            name,
            "case_ignored",
        )
        self.assert_code(ok_output(other), name, "case_mismatch")
        self.assert_code(
            b"running 1 test\n\ntest result: ok. 1 passed; 0 failed; "
            b"0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
            name,
            "case_missing",
        )
        duplicate = ok_output(name).replace(b"\n\n", b"\ntest %s ... ok\n\n" % name.encode(), 1)
        self.assert_code(duplicate, name, "duplicate_case")
        unexpected = (
            "running 1 test\ntest %s ... ok\ntest %s ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.01s\n" % (other, cases.CASE_NAMES[2])
        ).encode()
        self.assert_code(unexpected, name, "unexpected_case")

    def test_failed_filtered_inconsistent_and_missing_summary_fail(self):
        name = cases.CASE_NAMES[0]
        self.assert_code(failed_output(name), name, "case_failed")
        self.assert_code(
            ok_output(name).replace(b"0 filtered out", b"1 filtered out"),
            name,
            "summary_mismatch",
        )
        self.assert_code(
            ok_output(name).replace(b"1 passed", b"2 passed"),
            name,
            "summary_mismatch",
        )
        self.assert_code(b"running 1 test\n", name, "summary_missing")
        self.assert_code(
            b"running 2 tests\n" + ok_output(name).split(b"\n", 1)[1],
            name,
            "output_invalid",
        )


class ExecuteCasesTest(unittest.TestCase):
    def test_executes_all_cases_serially_with_exact_arguments(self):
        responses = [Completed([], 0, ok_output(name), b"") for name in cases.CASE_NAMES]
        fake = FakeRunner(responses)
        records = cases.execute_cases(
            BINARY, {"TMPDIR": "/tmp/owned"}, fake,
            work_deadline=1000, case_timeout=30, clock=lambda: 0,
            cwd="/tmp/source",
        )
        self.assertEqual(len(records), 17)
        self.assertTrue(all(row["status"] == "passed" for row in records))
        self.assertEqual(len(fake.calls), 17)
        for (argv, kwargs), name in zip(fake.calls, cases.CASE_NAMES):
            self.assertEqual(
                argv, [BINARY, name, "--exact", "--ignored", "--test-threads=1"]
            )
            self.assertNotIn("--", argv)
            self.assertEqual(kwargs["env"], {"TMPDIR": "/tmp/owned"})
            self.assertEqual(kwargs["cwd"], "/tmp/source")

    def test_stops_at_first_failure_and_reports_not_run(self):
        responses = [
            Completed([], 0, ok_output(cases.CASE_NAMES[0]), b""),
            Completed([], 0, ok_output(cases.CASE_NAMES[1]), b""),
            Completed([], 7, b"", b""),
        ]
        fake = FakeRunner(responses)
        records = cases.execute_cases(
            BINARY, {}, fake, work_deadline=1000, case_timeout=30, clock=lambda: 0
        )
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(records[2]["status"], "failed")
        self.assertEqual(records[2]["code"], "nonzero_exit")
        self.assertTrue(all(row["status"] == "not_run" for row in records[3:]))

    def test_timeout_and_deadline_are_finite(self):
        fake = FakeRunner([RunnerError("execute", "case_timeout")])
        records = cases.execute_cases(
            BINARY, {}, fake, work_deadline=1000, case_timeout=30, clock=lambda: 0
        )
        self.assertEqual(records[0]["code"], "case_timeout")
        self.assertTrue(all(row["status"] == "not_run" for row in records[1:]))
        fake = FakeRunner([])
        records = cases.execute_cases(
            BINARY, {}, fake, work_deadline=100, case_timeout=30,
            clock=lambda: 100,
        )
        self.assertEqual(fake.calls, [])
        self.assertEqual(records[0]["code"], "not_run_deadline")
        self.assertTrue(all(row["status"] == "not_run" for row in records))


def passing_records():
    rows = cases.not_run_records()
    for row in rows:
        row.update(
            status="passed", executed=True, exit_code=0, passed=1, code="passed"
        )
    return rows


class ReportTest(unittest.TestCase):
    def selection(self):
        return {
            "target": "rootyard-pando-lab",
            "kind": ["bin"],
            "profile": {"test": True},
            "features": ["pando-lab"],
            "command": ["cargo", "test", "--locked"],
            "fresh": True,
            "source": "src/bin/rootyard-pando-lab.rs",
            "executable_path": "/tmp/owned/target/debug/deps/rootyard_pando_lab-abc",
            "executable_sha256": "a" * 64,
            "executable": {
                "executable_name": "rootyard_pando_lab-abc",
                "sha256": "a" * 64,
                "size": 123,
                "st_dev": 1,
                "st_ino": 2,
                "mtime_ns": 3,
            },
        }

    def binding(self):
        return {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
            "source_clean": True,
            "source_inputs_sha256": "d" * 64,
            "bound_inputs_sha256": "e" * 64,
            "cargo_lock_sha256": "f" * 64,
            "schema_sha256": "1" * 64,
            "input_hashes": [{"path": "src/pando_lab/mod.rs", "sha256": "2" * 64}],
            "runner_source_hashes": [],
        }

    def cleanup(self):
        return {"cleanup_ok": True, "postgres_dropped": True,
                "root_removed": True}

    def test_success_report_has_seventeen_records_and_no_runtime_path(self):
        payload = report.build_report(
            passed=True,
            records=passing_records(),
            binding=self.binding(),
            selection=self.selection(),
            product_receipt={
                "provided": True,
                "same_source": True,
                "used_as_test_binary_receipt": False,
                "attached_to_native_gate": False,
            },
            cleanup=self.cleanup(),
            actual_fresh={"selected_test_binary": True,
                          "cargo_selection_reused_cache": True},
        )
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["case_count"], 17)
        self.assertEqual(payload["families"]["migration"]["passed"], 7)
        self.assertEqual(payload["test_binary_sha256"], "a" * 64)
        self.assertTrue(payload["actual_fresh"]["selected_test_binary"])
        self.assertNotIn("executable_path", json.dumps(payload))
        self.assertNotIn(BOOTSTRAP, json.dumps(payload))
        self.assertFalse(payload["product_receipt"]["used_as_test_binary_receipt"])

    def test_partial_failure_keeps_finite_not_run_records(self):
        rows = cases.not_run_records()
        rows[0].update(status="passed", executed=True, exit_code=0, passed=1,
                       code="passed")
        rows[1].update(status="failed", executed=True, exit_code=1,
                       code="nonzero_exit")
        payload = report.build_report(
            passed=False, records=rows, binding={}, selection=None,
            product_receipt=None, cleanup={"cleanup_ok": False},
            actual_fresh={}, error_code="nonzero_exit", stage="execute",
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["families"]["migration"]["not_run"], 5)
        self.assertEqual(payload["cases"][0]["status"], "passed")
        self.assertEqual(payload["cases"][1]["status"], "failed")

    def test_sanitizer_rejects_dsn_and_projection_falls_back(self):
        with self.assertRaises(RunnerError) as caught:
            report.sanitize({"dsn": BOOTSTRAP})
        self.assertEqual(caught.exception.code, "report_projection_rejected")
        payload = report.build_report(
            passed=True, records=passing_records(),
            binding={"value": BOOTSTRAP}, selection=None, product_receipt=None,
            cleanup={"cleanup_ok": True}, actual_fresh={},
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "report_projection_rejected")

    def test_report_writer_is_private_and_refuses_owned_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "test-results/report.json"
            report.write_report(target, {"schema": "x", "passed": True})
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(RunnerError) as caught:
                report.write_report(base / "owned/report.json", {"passed": True},
                                    forbidden_root=base / "owned")
            self.assertEqual(caught.exception.code, "report_write_failed")


class FakeFixture:
    def __init__(self, cleanup_result=None):
        self.root = type("Root", (), {"path": Path("/tmp/owned-root")})()
        self.child_environment = {"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP}
        self.started = False
        self.cleaned = None
        self.cleanup_result = cleanup_result or {
            "cleanup_ok": True, "postgres_dropped": True, "root_removed": True,
            "cleanup_within_deadline": True,
        }

    def start(self, deadline):
        self.started = True

    def cleanup(self, deadline):
        self.cleaned = deadline
        return dict(self.cleanup_result)


class RunOrchestrationTest(unittest.TestCase):
    def config(self, prepare_only=False):
        return runner.Config(
            source_root=Path("/tmp/source"),
            expected_commit="b" * 40,
            expected_tree="c" * 40,
            report=Path("/tmp/report.json"),
            product_receipt=Path("/tmp/pando-product.json"),
            total_seconds=100.0,
            cleanup_reserve_seconds=20.0,
            selection_timeout_seconds=10.0,
            setup_timeout_seconds=10.0,
            case_timeout_seconds=5.0,
            prepare_only=prepare_only,
        )

    def binding(self, source_inputs="d" * 64):
        return {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
            "source_clean": True,
            "source_inputs_sha256": source_inputs,
            "bound_inputs_sha256": "e" * 64,
            "cargo_lock_sha256": "f" * 64,
            "schema_sha256": "1" * 64,
            "input_hashes": [],
            "runner_source_hashes": [],
        }

    def selection(self):
        return {
            "target": "rootyard-pando-lab", "kind": ["bin"],
            "profile": {"test": True}, "features": ["pando-lab"],
            "command": ["cargo", "test"], "fresh": True,
            "source": "src/bin/rootyard-pando-lab.rs",
            "executable_path": BINARY, "executable_sha256": "a" * 64,
            "executable": {"executable_name": "fake", "sha256": "a" * 64,
                           "size": 1, "st_dev": 1, "st_ino": 1,
                           "mtime_ns": 1},
        }

    def invoke(self, config, captures=None, cleanup=None, records=None,
               product=None, write=None):
        captures = captures or [self.binding(), self.binding()]
        cleanup = cleanup or {"cleanup_ok": True, "postgres_dropped": True,
                              "root_removed": True,
                              "cleanup_within_deadline": True}
        records = records or passing_records()
        product = product or {
            "provided": True, "same_source": True,
            "used_as_test_binary_receipt": False,
            "attached_to_native_gate": False,
        }
        writes = []
        fixture = FakeFixture(cleanup)
        index = {"value": 0}

        def capture(*args, **kwargs):
            value = captures[min(index["value"], len(captures) - 1)]
            index["value"] += 1
            return dict(value)

        with mock.patch.object(runner.artifacts, "verify_selected_binary",
                               return_value={}):
            payload = runner.run(
                config,
                runner=object(),
                clock=lambda: 0.0,
                capture_source=capture,
                select_binary=lambda *args, **kwargs: self.selection(),
                fixture_factory=lambda *args, **kwargs: fixture,
                execute_cases_fn=lambda *args, **kwargs: records,
                write_report_fn=write or (
                    lambda path, payload, **kwargs: writes.append((path, payload))
                ),
                validate_product=lambda *args, **kwargs: product,
                environ={"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP},
            )
        return payload, writes, fixture

    def test_success_keeps_product_receipt_separate_from_test_binary(self):
        payload, writes, fixture = self.invoke(self.config())
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["case_count"], 17)
        self.assertEqual(payload["test_binary_sha256"], "a" * 64)
        self.assertEqual(len(writes), 1)
        self.assertTrue(fixture.started)
        self.assertNotIn(BOOTSTRAP, json.dumps(payload))
        self.assertFalse(payload["product_receipt"]["used_as_test_binary_receipt"])

    def test_source_drift_fails_and_retains_the_initial_binding(self):
        payload, _, _ = self.invoke(
            self.config(), captures=[self.binding("d" * 64), self.binding("9" * 64)]
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "source_drift")
        self.assertEqual(payload["source_bindings"]["source_inputs_sha256"], "d" * 64)
        self.assertFalse(payload["source_bindings"]["source_unchanged"])
        self.assertEqual(payload["cases"][0]["status"], "passed")

    def test_cleanup_failure_and_case_failure_make_the_run_fail(self):
        payload, _, _ = self.invoke(
            self.config(), cleanup={"cleanup_ok": False,
                                     "error_code": "postgres_drop_unverified",
                                     "cleanup_within_deadline": True}
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "postgres_drop_unverified")
        rows = cases.not_run_records()
        rows[0].update(status="passed", executed=True, exit_code=0, passed=1,
                       code="passed")
        rows[1].update(status="failed", executed=True, exit_code=1,
                       code="nonzero_exit")
        payload, _, _ = self.invoke(self.config(), records=rows)
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "nonzero_exit")
        self.assertEqual(payload["families"]["migration"]["not_run"], 5)
        self.assertEqual(payload["families"]["repack"]["not_run"], 5)
        self.assertEqual(payload["families"]["snapshot"]["not_run"], 5)

    def test_cleanup_after_deadline_is_never_a_clean_success(self):
        payload, _, _ = self.invoke(
            self.config(),
            cleanup={"cleanup_ok": True, "postgres_dropped": True,
                     "root_removed": True, "cleanup_within_deadline": False},
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "cleanup_deadline_exceeded")

    def test_missing_product_receipt_fails_closed_in_execution_mode(self):
        config = self.config()
        object.__setattr__(config, "product_receipt", None)
        with self.assertRaises(RunnerError) as caught:
            self.invoke(config)
        self.assertEqual(caught.exception.code, "product_receipt_missing")

    def test_prepare_only_writes_no_report_and_runs_no_cases(self):
        payload, writes, _ = self.invoke(
            self.config(prepare_only=True),
            records=cases.not_run_records(),
        )
        self.assertTrue(payload["passed"])
        self.assertEqual(writes, [])
        self.assertTrue(all(row["status"] == "not_run" for row in payload["cases"]))


if __name__ == "__main__":
    unittest.main()
