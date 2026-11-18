"""Pure contracts for the native hosted slot-zero evidence driver.

These tests do not start PostgreSQL, Cargo, Git or the network.  They pin the
strict libtest parser, the allowlist projector and the static workflow shape
that keeps the scratch job isolated from the production path.
"""
from pathlib import Path
from types import SimpleNamespace
import inspect
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import issue42_native_hosted_slot0 as driver  # noqa: E402


COMMIT = "a" * 40
TREE = "b" * 40
SHA = "c" * 64


def libtest(name, *, ignored=False, passed=1, failed=0, skipped=0, filtered=13, status="ok"):
    shown = "ignored" if skipped else ("FAILED" if status == "FAILED" else "ok")
    return (
        "running 1 test\n"
        f"test {name} ... {shown}\n\n"
        f"test result: {status}. {passed} passed; {failed} failed; {skipped} ignored; "
        f"0 measured; {filtered} filtered out; finished in 0.01s\n"
    ).encode()


def provenance():
    return {
        "repository": "jihuayu/rootyard",
        "ref": driver.QUALIFICATION_REF,
        "run_id": 42,
        "run_attempt": 2,
        "workflow_path": driver.WORKFLOW_PATH,
        "workflow_commit": COMMIT,
        "workflow_tree": TREE,
        "workflow_sha256": SHA,
        "event_head": COMMIT,
        "event_tree": TREE,
        "product_commit": "d" * 40,
        "product_tree": "e" * 40,
        "product_clean": True,
        "product_reachable": True,
        "cargo_lock_sha256": SHA,
    }


def binary(kind):
    return {
        "kind": kind,
        "binary_sha256": SHA,
        "receipt_sha256": SHA,
        "source_inputs_sha256": SHA,
        "config_digest": SHA,
        "bound_inputs_sha256": SHA,
        "cargo_lock_sha256": SHA,
        "test_closure_sha256": SHA,
        "command_sha256": SHA,
        "summary_sha256": SHA,
    }


def passed_cases():
    statuses = {key: "passed" for key in ((target, name) for target, name, _ in driver.ALL_CASES)}
    observed = {
        (target, name): {"passed": 1, "failed": 0, "ignored": 0, "filtered_out": 3}
        for target, name, _ in driver.ALL_CASES
    }
    return driver.expected_rows(statuses, observed)


class LibtestParserTest(unittest.TestCase):
    def test_exact_passed_ignored_case(self):
        name = driver.ALL_CASES[1][1]
        parsed = driver.parse_case_output(libtest(name, filtered=27), name)
        self.assertEqual(parsed["passed"], 1)
        self.assertEqual(parsed["failed"], 0)
        self.assertEqual(parsed["ignored"], 0)
        self.assertEqual(parsed["filtered_out"], 27)

    def test_exact_pure_case(self):
        name = driver.ALL_CASES[5][1]
        parsed = driver.parse_case_output(libtest(name, filtered=2), name)
        self.assertEqual(parsed["status"], "passed")

    def test_zero_tests_is_red(self):
        raw = b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n"
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(raw, driver.ALL_CASES[0][1])

    def test_wrong_name_is_red(self):
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(libtest("some_other_test"), driver.ALL_CASES[0][1])

    def test_ignored_case_did_not_run_is_red(self):
        name = driver.ALL_CASES[0][1]
        raw = libtest(name, passed=0, skipped=1, status="ok")
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(raw, name)

    def test_failed_case_is_red(self):
        name = driver.ALL_CASES[0][1]
        raw = libtest(name, passed=0, failed=1, status="FAILED")
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(raw, name)

    def test_two_executed_cases_is_red(self):
        name = driver.ALL_CASES[0][1]
        raw = (
            "running 2 tests\n"
            f"test {name} ... ok\n"
            f"test {name}x ... ok\n\n"
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        ).encode()
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(raw, name)

    def test_oversized_or_ansi_output_is_red(self):
        name = driver.ALL_CASES[0][1]
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(b"x" * (driver.OUTPUT_LIMIT + 1), name)
        with self.assertRaises(driver.EvidenceError):
            driver.parse_case_output(libtest(name).replace(b"running", b"\x1b[31mrunning"), name)


class ReceiptProjectionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "tests").mkdir()
        (self.root / "Cargo.lock").write_bytes(b"lock")
        (self.root / "tests" / "ref_store_operations.rs").write_bytes(b"test source")
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"binary")
        self.receipt = self.root / "binary.build.json"
        self.receipt.write_text("{}")

    def tearDown(self):
        self.directory.cleanup()

    def payload(self, kind):
        payload = {
            "kind": "rust-integration-test" if kind == "integration" else "rust-library-test",
            "git_head": COMMIT,
            "working_tree": {"tree": TREE, "status": ""},
            "features": {"enabled": ["pando-lab"], "no_default_features": True},
            "profile": "test",
            "target_triple": driver.TARGET,
            "relocated_artifact": True,
            "toolchain": {
                "cargo": {"release": driver.CARGO_RELEASE, "commit_hash": driver.CARGO_FORK},
                "rustc": {"release": driver.RUSTC_RELEASE},
            },
            "original_artifact_sha256": driver.sha256_file(self.binary),
            "cargo_lock_sha256": driver.sha256_file(self.root / "Cargo.lock"),
            "bound_inputs": {"digest": SHA},
        }
        if kind == "integration":
            payload["integration_test_source"] = "tests/ref_store_operations.rs"
            payload["integration_test_source_sha256"] = driver.sha256_file(
                self.root / "tests" / "ref_store_operations.rs")
        else:
            payload["lib_test_support_inputs_sha256"] = SHA
        return payload

    def loader(self, kind, payload=None):
        captured = {}

        def load(path, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                schema="v2",
                payload=self.payload(kind) if payload is None else payload,
                binary_sha256=driver.sha256_file(self.binary),
                receipt_sha256=SHA,
                source_inputs_sha256=SHA,
                config_digest=SHA,
            )

        return load, captured

    def test_integration_summary_uses_exact_anchors_and_no_paths(self):
        load, captured = self.loader("integration")
        summary = driver.receipt_summary(
            load, receipt_path=self.receipt, binary_path=self.binary, source_root=self.root,
            product_commit=COMMIT, product_tree=TREE, kind="integration")
        self.assertEqual(captured["expected_commit"], COMMIT)
        self.assertEqual(captured["expected_command"], driver.expected_command("integration"))
        self.assertEqual(captured["expected_toolchain"], driver.TOOLCHAIN_EXPECTATION)
        self.assertTrue(captured["verify_source_files"])
        self.assertEqual(summary["binary_sha256"], driver.sha256_file(self.binary))
        self.assertNotIn("command", summary)
        self.assertNotIn("path", summary)
        self.assertNotIn(str(self.root), json.dumps(summary))

    def test_lib_summary_binds_support_digest(self):
        load, _ = self.loader("lib")
        summary = driver.receipt_summary(
            load, receipt_path=self.receipt, binary_path=self.binary, source_root=self.root,
            product_commit=COMMIT, product_tree=TREE, kind="lib")
        self.assertEqual(summary["kind"], "rust-library-test")

    def test_wrong_feature_set_is_red(self):
        payload = self.payload("integration")
        payload["features"]["no_default_features"] = False
        load, _ = self.loader("integration", payload)
        with self.assertRaises(driver.EvidenceError):
            driver.receipt_summary(
                load, receipt_path=self.receipt, binary_path=self.binary, source_root=self.root,
                product_commit=COMMIT, product_tree=TREE, kind="integration")

    def test_dirty_tree_or_wrong_kind_is_red(self):
        payload = self.payload("integration")
        payload["working_tree"] = {"tree": TREE, "status": "?? dirty"}
        load, _ = self.loader("integration", payload)
        with self.assertRaises(driver.EvidenceError):
            driver.receipt_summary(
                load, receipt_path=self.receipt, binary_path=self.binary, source_root=self.root,
                product_commit=COMMIT, product_tree=TREE, kind="integration")
        payload = self.payload("integration")
        payload["kind"] = "native-binary"
        load, _ = self.loader("integration", payload)
        with self.assertRaises(driver.EvidenceError):
            driver.receipt_summary(
                load, receipt_path=self.receipt, binary_path=self.binary, source_root=self.root,
                product_commit=COMMIT, product_tree=TREE, kind="integration")


class ReportProjectionTest(unittest.TestCase):
    def report(self, **overrides):
        values = {
            "provenance": provenance(),
            "validator_sha256": SHA,
            "binaries": {driver.INTEGRATION: binary("rust-integration-test"),
                         driver.LIB: binary("rust-library-test")},
            "postgres": {"server_version_num": 170005, "major": 17, "client_major": 17,
                         "baseline_database_count": 3, "owned_database_created": True},
            "cases": passed_cases(),
            "source_recheck": True,
            "cleanup": {"database_removed": True, "roster_restored": True,
                        "work_removed": True, "evidence_clean": True},
            "stage": "complete",
            "failure_class": None,
        }
        values.update(overrides)
        return driver.make_report(**values)

    def test_success_is_bounded_allowlist_with_exact_counts(self):
        report = self.report()
        self.assertTrue(report["passed"])
        self.assertFalse(report["product_acceptance_complete"])
        self.assertEqual(report["scope"], "library-layer-only")
        self.assertFalse(report["qualification"]["production_path_switched"])
        self.assertFalse(report["qualification"]["issue42_original_acceptance"])
        self.assertEqual(report["bounds"]["job_timeout_minutes"], driver.JOB_TIMEOUT_MINUTES)
        self.assertEqual(report["workflow"]["head"], report["workflow"]["commit"])
        self.assertEqual(report["event_head"], report["workflow"]["commit"])
        self.assertEqual(report["counts"], {"expected": 7, "executed": 7, "passed": 7,
                                            "failed": 0, "not_run": 0, "ignored": 0})
        self.assertEqual(report["run"], {"id": 42, "attempt": 2})
        encoded = json.dumps(report)
        for forbidden in ('"command":', '"stdout":', '"stderr":', "postgresql://", "/tmp/", "password="):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("path", report["binaries"][driver.INTEGRATION])

    def test_failed_case_is_never_green(self):
        rows = passed_cases()
        rows[2]["status"] = "failed"
        rows[2]["observed"] = None
        report = self.report(cases=rows, failure_class="case")
        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"]["passed"], 6)
        self.assertEqual(report["counts"]["failed"], 1)

    def test_missing_binary_or_cleanup_is_never_green(self):
        self.assertFalse(self.report(binaries={})["passed"])
        self.assertFalse(self.report(cleanup={"database_removed": True, "roster_restored": True,
                                              "work_removed": False, "evidence_clean": True})["passed"])

    def test_evidence_rejects_paths_and_non_allowlisted_keys(self):
        with self.assertRaises(driver.EvidenceError):
            driver.assert_allowlisted({"command": "cargo test"})
        with self.assertRaises(driver.EvidenceError):
            driver.assert_allowlisted({"note": "/home/runner/work"})
        with self.assertRaises(driver.EvidenceError):
            driver.assert_allowlisted({"note": "postgresql://rootyard@127.0.0.1/db"})


class HostedFlowMockTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.work = self.root / "work"
        self.evidence = self.root / "evidence"
        self.product = self.root / "product"
        self.work.mkdir()
        self.evidence.mkdir()
        self.product.mkdir()
        self.binding = {"provenance": provenance(),
                        "binaries": {driver.INTEGRATION: binary("rust-integration-test"),
                                     driver.LIB: binary("rust-library-test")},
                        "validator_sha256": SHA}
        for name, path in ((driver.INTEGRATION, self.work / "ref-store-operations"),
                           (driver.LIB, self.work / "slot-zero-lib")):
            path.write_bytes(name.encode())
            receipt = Path(str(path) + ".build.json")
            receipt.write_bytes((name + "-receipt").encode())
            self.binding["binaries"][name]["binary_sha256"] = driver.sha256_file(path)
            self.binding["binaries"][name]["receipt_sha256"] = driver.sha256_file(receipt)
        (self.work / "binding.json").write_text(json.dumps(self.binding))
        (self.work / "pg-baseline.json").write_text(json.dumps({
            "server_version_num": 170005,
            "databases": ["postgres", "template0", "template1"],
            "client_major": 17,
        }))
        (self.evidence / "stage").write_text("test")
        self.owned_present = False

    def tearDown(self):
        self.directory.cleanup()

    def patches(self):
        def create():
            self.owned_present = True
            return "slot0_native_" + "1" * 32

        def roster():
            values = ["postgres", "template0", "template1"]
            return values + (["slot0_native_" + "1" * 32] if self.owned_present else [])

        def cleanup(owned, baseline):
            self.owned_present = False
            return True, True

        def execute(binary, name, ignored, *, database, timeout, cwd):
            self.assertIn(binary, (str(self.work / "ref-store-operations"),
                                   str(self.work / "slot-zero-lib")))
            return libtest(name, filtered=4)

        return [
            mock.patch.object(driver, "verify_sources", return_value=provenance()),
            mock.patch.object(driver, "check_postgres", return_value={
                "server_version_num": 170005, "major": 17, "client_major": 17,
                "baseline_database_count": 3, "owned_database_created": False}),
            mock.patch.object(driver, "create_database", side_effect=create),
            mock.patch.object(driver, "roster", side_effect=roster),
            mock.patch.object(driver, "cleanup_databases", side_effect=cleanup),
            mock.patch.object(driver, "drop_database"),
            mock.patch.object(driver, "execute_case", side_effect=execute),
        ]

    def test_success_flow_keeps_only_allowlist_evidence(self):
        patches = self.patches()
        for patcher in patches:
            patcher.start()
        try:
            run = driver.cmd_run(SimpleNamespace(
                work=str(self.work), product=str(self.product),
                workflow_source=str(self.root), integration=str(self.work / "ref-store-operations"),
                lib=str(self.work / "slot-zero-lib")))
            self.assertEqual(run, 0)
            candidate = json.loads((self.work / "candidate.json").read_text())
            self.assertTrue(candidate["passed"])
            self.assertTrue(all(row["observed"] == {"passed": 1, "failed": 0, "ignored": 0,
                                                    "filtered_out": 4}
                                for row in candidate["cases"]))
            finalize = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
            self.assertEqual(finalize, 0)
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        report = json.loads((self.evidence / "qualification.json").read_text())
        self.assertTrue(report["passed"])
        self.assertEqual(report["counts"]["passed"], 7)
        self.assertTrue(report["cleanup"]["work_removed"])
        self.assertEqual([entry.name for entry in self.evidence.iterdir()], ["qualification.json"])
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_failed_case_is_red_but_still_reports_cleanup(self):
        patches = self.patches()
        for patcher in patches:
            patcher.start()
        original = driver.execute_case.side_effect

        def fail_on_third(binary, name, ignored, *, database, timeout, cwd):
            if name.endswith("slot_zero_rejects_equal_ids_private_conflict_and_wire_rebinding"):
                raise driver.EvidenceError("case")
            return original(binary, name, ignored, database=database, timeout=timeout, cwd=cwd)

        driver.execute_case.side_effect = fail_on_third
        try:
            run = driver.cmd_run(SimpleNamespace(
                work=str(self.work), product=str(self.product),
                workflow_source=str(self.root), integration=str(self.work / "ref-store-operations"),
                lib=str(self.work / "slot-zero-lib")))
            self.assertEqual(run, 1)
            finalize = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
            self.assertEqual(finalize, 1)
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        report = json.loads((self.evidence / "qualification.json").read_text())
        self.assertFalse(report["passed"])
        self.assertEqual(report["counts"]["passed"], 2)
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertEqual(report["counts"]["not_run"], 4)
        self.assertEqual(report["failure_class"], "case")


class BoundedExecutionTest(unittest.TestCase):
    """Controllable local children for the bounded stdout/stderr collector."""

    CHILD = r"""import os
import sys
import time

arguments = sys.argv[1:]
name = arguments[arguments.index("--exact") + 1]
mode = os.environ.get("CHILD_MODE")
parent_pid_file = os.environ.get("CHILD_PID_FILE")
descendant_pid_file = os.environ.get("DESCENDANT_PID_FILE")


def write_pid(path):
    if path:
        with open(path, "w") as stream:
            stream.write(str(os.getpid()))


if mode == "normal":
    sys.stdout.write("running 1 test\n")
    sys.stdout.write("test %s ... ok\n\n" % name)
    sys.stdout.write(
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        "4 filtered out; finished in 0.01s\n")
    sys.stderr.write("local child noise\n")
    sys.stdout.flush()
    sys.stderr.flush()
elif mode == "stdout-overflow":
    sys.stdout.write("x" * 70000)
    sys.stdout.flush()
elif mode == "stderr-overflow":
    sys.stderr.write("x" * 9000)
    sys.stderr.flush()
elif mode == "timeout":
    write_pid(parent_pid_file)
    time.sleep(5)
elif mode == "hold-stdout":
    write_pid(parent_pid_file)
    child = os.fork()
    if child == 0:
        write_pid(descendant_pid_file)
        time.sleep(5)
        os._exit(0)
    time.sleep(0.05)
    os._exit(0)
else:
    sys.exit(3)
"""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.script = self.root / "local-child"
        self.script.write_text("#!" + sys.executable + "\n" + self.CHILD)
        self.script.chmod(0o755)
        self.environment = mock.patch.dict(os.environ, {
            "PGUSER": "local", "PGHOST": "127.0.0.1", "PGPORT": "1"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def run_child(self, mode, *, timeout, pid_file=None, descendant_file=None):
        environment = {"CHILD_MODE": mode}
        if pid_file is not None:
            environment["CHILD_PID_FILE"] = str(pid_file)
        if descendant_file is not None:
            environment["DESCENDANT_PID_FILE"] = str(descendant_file)
        with mock.patch.dict(os.environ, environment):
            return driver.execute_case(
                self.script, "local_case", False, database="local", timeout=timeout,
                cwd=self.root)

    def assert_pid_gone(self, pid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail("child process was not reaped")

    def test_normal_child_keeps_one_bounded_pass(self):
        raw = self.run_child("normal", timeout=2)
        parsed = driver.parse_case_output(raw, "local_case")
        self.assertEqual(parsed["passed"], 1)
        self.assertLessEqual(len(raw), driver.OUTPUT_LIMIT)

    def test_stdout_overflow_is_a_fixed_failure(self):
        started = time.monotonic()
        with self.assertRaises(driver.EvidenceError) as caught:
            self.run_child("stdout-overflow", timeout=2)
        self.assertEqual(caught.exception.kind, driver.EXEC_OUTPUT_OVERFLOW)
        self.assertEqual(str(caught.exception), "qualification check failed")
        self.assertLess(time.monotonic() - started, 3)

    def test_stderr_overflow_is_a_fixed_failure(self):
        started = time.monotonic()
        with self.assertRaises(driver.EvidenceError) as caught:
            self.run_child("stderr-overflow", timeout=2)
        self.assertEqual(caught.exception.kind, driver.EXEC_OUTPUT_OVERFLOW)
        self.assertLess(time.monotonic() - started, 3)

    def test_deadline_kills_and_reaps_the_direct_child(self):
        pid_file = self.root / "timeout.pid"
        started = time.monotonic()
        with self.assertRaises(driver.EvidenceError) as caught:
            self.run_child("timeout", timeout=1.0, pid_file=pid_file)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 3)
        self.assert_pid_gone(int(pid_file.read_text()))

    def test_descendant_holding_stdout_cannot_hold_the_parent(self):
        pid_file = self.root / "parent.pid"
        descendant_file = self.root / "descendant.pid"
        started = time.monotonic()
        with self.assertRaises(driver.EvidenceError) as caught:
            self.run_child("hold-stdout", timeout=1.0, pid_file=pid_file,
                           descendant_file=descendant_file)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 3)
        self.assert_pid_gone(int(pid_file.read_text()))
        self.assertTrue(descendant_file.is_file())
        self.assert_pid_gone(int(descendant_file.read_text()))

    def test_cleanup_failure_cannot_produce_a_pass(self):
        fake = mock.Mock(pid=os.getpid())
        with mock.patch.object(driver.subprocess, "Popen", return_value=fake), \
                mock.patch.object(driver, "_collect_bounded", return_value=(b"x", b"", 0)), \
                mock.patch.object(driver, "_close_process_pipes", return_value=False), \
                mock.patch.object(driver, "_terminate_process",
                                  side_effect=driver.EvidenceError(driver.EXEC_REAP)):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.execute_case(self.script, "local_case", False, database="local",
                                    timeout=1, cwd=self.root)
        self.assertEqual(caught.exception.kind, driver.EXEC_REAP)

    def test_timeout_cleanup_failure_is_never_a_pass(self):
        fake = mock.Mock(pid=os.getpid())
        with mock.patch.object(driver.subprocess, "Popen", return_value=fake), \
                mock.patch.object(driver, "_collect_bounded",
                                  side_effect=driver.EvidenceError("timeout")), \
                mock.patch.object(driver, "_terminate_process",
                                  side_effect=driver.EvidenceError(driver.EXEC_REAP)):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.execute_case(self.script, "local_case", False, database="local",
                                    timeout=1, cwd=self.root)
        self.assertEqual(caught.exception.kind, driver.EXEC_REAP)

    def test_process_group_kill_refuses_the_caller_group(self):
        with mock.patch.object(driver.os, "killpg") as killpg:
            driver._kill_process_group(os.getpgrp())
        killpg.assert_not_called()

    def test_no_unbounded_communicate_remains(self):
        source = inspect.getsource(driver.execute_case) + inspect.getsource(driver._collect_bounded)
        self.assertNotIn("communicate", source)


class WorkflowStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / driver.WORKFLOW_PATH
        cls.text = cls.path.read_text()

    def test_trigger_is_only_the_owned_scratch_branch_and_this_workflow(self):
        self.assertIn("  push:\n    branches: [codex/goal-issue42-original-ac-source-audit-20261117]", self.text)
        self.assertIn("    paths: [.github/workflows/issue42-native-hosted-slot0-postgres.yml]", self.text)
        for forbidden in ("pull_request:", "workflow_dispatch:", "schedule:", "workflow_run:", "  main:"):
            self.assertNotIn(forbidden, self.text)

    def test_read_only_checkouts_and_no_secrets(self):
        self.assertIn("permissions:\n  contents: read", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertEqual(self.text.count("persist-credentials: false"), 2)
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("${{ secrets", self.text)

    def test_pinned_actions_and_product_pair(self):
        for action in (
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ):
            self.assertIn(action, self.text)
        pin = self.text.split("PRODUCT_SHA:", 1)[1].splitlines()[0].strip()
        tree = self.text.split("PRODUCT_TREE:", 1)[1].splitlines()[0].strip()
        self.assertRegex(pin, r"^[0-9a-f]{40}$")
        self.assertRegex(tree, r"^[0-9a-f]{40}$")

    def test_owned_postgres_and_fixed_artifact(self):
        self.assertEqual(driver.WORKFLOW_PATH, self.path.relative_to(ROOT).as_posix())
        self.assertIn(f"timeout-minutes: {driver.JOB_TIMEOUT_MINUTES}", self.text)
        self.assertIn("image: postgres:17", self.text)
        self.assertIn("127.0.0.1:55432:5432", self.text)
        self.assertIn("if-no-files-found: error", self.text)
        self.assertIn("qualification.json", self.text)
        self.assertIn("issue42_native_hosted_slot0.py", self.text)
        self.assertNotIn("garage", self.text.lower())
        self.assertNotIn("redis", self.text.lower())


if __name__ == "__main__":
    unittest.main()
