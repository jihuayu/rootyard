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
import subprocess
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
    def test_inventory_is_exact_serial_and_ordered(self):
        expected = (
            (driver.INTEGRATION, "fresh_lane_creation_waits_for_an_uncommitted_creator", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_admission_commits_then_exact_retry_replays", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_rejects_equal_ids_private_conflict_and_wire_rebinding", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_replay_rejects_missing_or_wrong_producer_binding", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_rollback_leaves_no_sequence_or_half_binding_and_rejects_overflow", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_typed_plan_error_rolls_back_only_the_savepoint", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_cancelled_owned_tx_cannot_be_committed", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_restore_rotation_waits_for_admission_commit", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_waits_for_legacy_lane_before_scope_and_gate", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_fixture_setup_error_drops_only_its_owned_database", True),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_request_rejects_equal_ids_and_noncanonical_backend", False),
            (driver.LIB, "ref_store::pg::slot_zero::tests::slot_zero_proof_binds_sequence_plan_and_wire", False),
        )
        self.assertEqual(driver.ALL_CASES, expected)
        self.assertEqual(len({(target, name) for target, name, _ in expected}), len(expected))
        self.assertEqual(sum(ignored for _, _, ignored in expected), 10)
        self.assertEqual(sum(not ignored for _, _, ignored in expected), 2)
        self.assertFalse(driver.ALL_CASES[-1][2])
        self.assertFalse(driver.ALL_CASES[-2][2])

    def test_run_cases_executes_inventory_serially(self):
        calls = []
        binaries = {driver.INTEGRATION: "integration-binary",
                    driver.LIB: "lib-binary"}

        def execute(binary, name, ignored, *, database, timeout, cwd):
            calls.append((binary, name, ignored, database, timeout, cwd))
            return libtest(name, filtered=4)

        with mock.patch.object(driver, "execute_case", side_effect=execute):
            statuses, failure = driver.run_cases(
                binaries=binaries, database="owned", deadline=time.monotonic() + 900,
                cwd=Path("/product"))
        self.assertIsNone(failure)
        self.assertEqual(len(calls), len(driver.ALL_CASES))
        self.assertEqual(len({(call[1], call[2]) for call in calls}), len(calls))
        self.assertEqual(
            [(call[0], call[1], call[2]) for call in calls],
            [(binaries[target], name, ignored) for target, name, ignored in driver.ALL_CASES])
        self.assertTrue(all(call[3] == "owned" and call[5] == Path("/product") for call in calls))
        self.assertTrue(all(0 < call[4] <= driver.CASE_TIMEOUT_SECONDS for call in calls))
        self.assertTrue(all(row["status"] == "passed" for row in statuses))

    def test_exact_passed_ignored_case(self):
        name = driver.ALL_CASES[1][1]
        parsed = driver.parse_case_output(libtest(name, filtered=27), name)
        self.assertEqual(parsed["passed"], 1)
        self.assertEqual(parsed["failed"], 0)
        self.assertEqual(parsed["ignored"], 0)
        self.assertEqual(parsed["filtered_out"], 27)

    def test_exact_pure_case(self):
        name = next(name for _, name, ignored in driver.ALL_CASES if not ignored)
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
        expected = len(driver.ALL_CASES)
        self.assertEqual(report["counts"], {"expected": expected, "executed": expected,
                                            "passed": expected, "failed": 0,
                                            "not_run": 0, "ignored": 0})
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
        self.assertEqual(report["counts"]["passed"], len(driver.ALL_CASES) - 1)
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
        self.environment = mock.patch.dict(os.environ, {"PGUSER": "local"})
        self.environment.start()
        self.nonce = "1" * 32
        self.owned_name = driver.database_candidate_name(42, 2, self.nonce)
        self.owned_present = False

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def patches(self):
        def create(work, baseline, provenance):
            marker = driver.ownership_marker(provenance, baseline, self.nonce, state="created")
            driver.write_ownership_marker(Path(work), marker)
            self.owned_present = True
            return marker["database"]

        def roster():
            values = ["postgres", "template0", "template1"]
            return values + ([self.owned_name] if self.owned_present else [])

        def cleanup(baseline, marker):
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
        self.assertEqual(report["counts"]["passed"], len(driver.ALL_CASES))
        self.assertTrue(report["cleanup"]["work_removed"])
        self.assertEqual([entry.name for entry in self.evidence.iterdir()], ["qualification.json"])
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_partial_create_owner_failure_uses_marker_for_cleanup(self):
        patches = self.patches()
        for patcher in patches:
            patcher.start()

        def create_partial(work, baseline, provenance):
            marker = driver.ownership_marker(provenance, baseline, self.nonce, state="candidate")
            driver.write_ownership_marker(Path(work), marker)
            self.owned_present = True
            raise driver.EvidenceError("postgres")

        def cleanup_marker(baseline, marker):
            self.assertEqual(marker["database"], self.owned_name)
            self.owned_present = False
            return True, True

        driver.create_database.side_effect = create_partial
        driver.cleanup_databases.side_effect = cleanup_marker
        try:
            run = driver.cmd_run(SimpleNamespace(
                work=str(self.work), product=str(self.product),
                workflow_source=str(self.root), integration=str(self.work / "ref-store-operations"),
                lib=str(self.work / "slot-zero-lib")))
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(run, 1)
        candidate = json.loads((self.work / "candidate.json").read_text())
        self.assertEqual(candidate["failure_class"], "postgres")
        self.assertTrue(candidate["cleanup"]["database_removed"])
        self.assertTrue(candidate["cleanup"]["roster_restored"])
        marker = driver.load_ownership_marker(self.work, {
            "server_version_num": 170005,
            "databases": ["postgres", "template0", "template1"],
            "client_major": 17,
        }, provenance())
        self.assertEqual(marker["state"], "candidate")

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
        self.assertEqual(report["counts"]["not_run"], len(driver.ALL_CASES) - 3)
        self.assertEqual(report["failure_class"], "case")


class OwnershipMarkerTest(unittest.TestCase):
    """Pure marker contracts: exact ownership, fail-closed cleanup, retryable finalize."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.work = self.root / "work"
        self.evidence = self.root / "evidence"
        self.product = self.root / "product"
        self.work.mkdir()
        self.evidence.mkdir()
        self.product.mkdir()
        self.environment = mock.patch.dict(os.environ, {"PGUSER": "local"})
        self.environment.start()
        self.provenance = provenance()
        self.baseline = {
            "server_version_num": 170005,
            "databases": ["postgres", "template0", "template1"],
            "client_major": 17,
        }
        self.nonce = "2" * 32
        self.name = driver.database_candidate_name(42, 2, self.nonce)

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def marker(self, *, state="candidate", nonce=None, provenance_value=None, baseline=None):
        return driver.ownership_marker(
            provenance_value or self.provenance,
            baseline or self.baseline,
            nonce or self.nonce,
            state=state)

    def write_marker(self, marker=None):
        marker = marker or self.marker()
        driver.write_ownership_marker(self.work, marker)
        return marker

    def test_candidate_name_binds_run_attempt_and_nonce(self):
        self.assertRegex(self.name, driver.DATABASE_FULL)
        self.assertLessEqual(len(self.name), 63)
        self.assertEqual(self.name, driver.database_candidate_name(42, 2, self.nonce))
        self.assertNotEqual(self.name, driver.database_candidate_name(42, 3, self.nonce))
        self.assertNotEqual(self.name, driver.database_candidate_name(42, 2, "3" * 32))

    def test_marker_publication_is_exclusive_and_bounded(self):
        first = self.write_marker()
        path = self.work / driver.OWNERSHIP_MARKER
        before = path.read_bytes()
        self.assertLessEqual(len(before), driver.OWNERSHIP_LIMIT)
        with self.assertRaises(driver.EvidenceError) as caught:
            driver.write_ownership_marker(self.work, self.marker(state="preexisting"))
        self.assertEqual(caught.exception.kind, "ownership")
        self.assertEqual(path.read_bytes(), before)

    def test_marker_delivery_failure_never_creates_database(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome") as psql, \
                mock.patch.object(driver, "write_ownership_marker",
                                  side_effect=driver.EvidenceError("ownership")):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "ownership")
        psql.assert_not_called()
        self.assertFalse((self.work / driver.OWNERSHIP_MARKER).exists())

    def test_marker_already_present_stops_before_create(self):
        inherited = self.write_marker()
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome") as psql:
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "ownership")
        psql.assert_not_called()
        self.assertEqual(driver.load_ownership_marker(
            self.work, self.baseline, self.provenance), inherited)

    def test_old_run_or_changed_baseline_is_not_inherited(self):
        self.write_marker()
        old = dict(self.provenance)
        old["run_id"] = 99
        with self.assertRaises(driver.EvidenceError) as caught:
            driver.load_ownership_marker(self.work, self.baseline, old)
        self.assertEqual(caught.exception.kind, "ownership")
        changed = dict(self.baseline)
        changed["databases"] = list(self.baseline["databases"]) + ["slot_zero_" + "4" * 32]
        with self.assertRaises(driver.EvidenceError) as caught:
            driver.load_ownership_marker(self.work, changed, self.provenance)
        self.assertEqual(caught.exception.kind, "ownership")

    def test_preexisting_name_is_rejected_before_marker(self):
        with mock.patch.object(driver, "database_exists", return_value=True), \
                mock.patch.object(driver, "psql_outcome") as psql:
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "database-exists")
        psql.assert_not_called()
        self.assertFalse((self.work / driver.OWNERSHIP_MARKER).exists())

    def test_generated_name_already_in_baseline_is_rejected(self):
        baseline = dict(self.baseline)
        baseline["databases"] = list(self.baseline["databases"]) + [self.name]
        with mock.patch.object(driver.secrets, "token_hex", return_value=self.nonce), \
                mock.patch.object(driver, "database_exists") as exists, \
                mock.patch.object(driver, "psql_outcome") as psql:
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "database-exists")
        exists.assert_not_called()
        psql.assert_not_called()
        self.assertFalse((self.work / driver.OWNERSHIP_MARKER).exists())

    def test_uncreated_candidate_marker_is_clean(self):
        marker = self.write_marker()
        with mock.patch.object(driver, "roster", return_value=self.baseline["databases"]), \
                mock.patch.object(driver, "drop_database") as drop:
            removed, restored = driver.cleanup_databases(self.baseline["databases"], marker)
        self.assertTrue(removed)
        self.assertTrue(restored)
        drop.assert_not_called()

    def test_unknown_create_response_with_owner_evidence_cleans_exactly(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome",
                                  side_effect=driver.EvidenceError("postgres")):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "postgres")
        marker = driver.load_ownership_marker(self.work, self.baseline, self.provenance)
        self.assertEqual(marker["state"], "candidate")
        present = {marker["database"]: True}

        def roster():
            return self.baseline["databases"] + ([marker["database"]] if present[marker["database"]] else [])

        def drop(name):
            present[name] = False

        with mock.patch.object(driver, "roster", side_effect=roster), \
                mock.patch.object(driver, "database_owner", return_value="local"), \
                mock.patch.object(driver, "drop_database", side_effect=drop) as drop_mock:
            removed, restored = driver.cleanup_databases(self.baseline["databases"], marker)
        self.assertTrue(removed)
        self.assertTrue(restored)
        drop_mock.assert_called_once_with(marker["database"])

    def test_successful_create_writes_created_marker(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome", return_value=(0, b"", b"")), \
                mock.patch.object(driver, "database_owner", return_value="local"):
            name = driver.create_database(self.work, self.baseline, self.provenance)
        marker = driver.load_ownership_marker(self.work, self.baseline, self.provenance)
        self.assertEqual(name, marker["database"])
        self.assertEqual(marker["state"], "created")
        self.assertEqual(marker["run_id"], 42)
        self.assertEqual(marker["run_attempt"], 2)
        self.assertEqual(marker["owner"], "local")
        self.assertNotIn(str(self.root), json.dumps(marker))

    def test_owner_check_unavailable_after_create_is_cleaned(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome", return_value=(0, b"", b"")), \
                mock.patch.object(driver, "database_owner",
                                  side_effect=driver.EvidenceError("postgres")):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "postgres")
        marker = driver.load_ownership_marker(self.work, self.baseline, self.provenance)
        self.assertEqual(marker["state"], "candidate")
        present = {marker["database"]: True}

        def roster():
            return self.baseline["databases"] + ([marker["database"]] if present[marker["database"]] else [])

        def drop(name):
            present[name] = False

        with mock.patch.object(driver, "roster", side_effect=roster), \
                mock.patch.object(driver, "database_owner", return_value="local"), \
                mock.patch.object(driver, "drop_database", side_effect=drop) as drop_mock:
            removed, restored = driver.cleanup_databases(self.baseline["databases"], marker)
        self.assertTrue(removed)
        self.assertTrue(restored)
        drop_mock.assert_called_once_with(marker["database"])

    def test_owner_mismatch_keeps_marker_and_never_drops(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome", return_value=(0, b"", b"")), \
                mock.patch.object(driver, "database_owner", return_value="other"):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "ownership")
        marker = driver.load_ownership_marker(self.work, self.baseline, self.provenance)
        self.assertEqual(marker["state"], "owner-mismatch")
        with mock.patch.object(driver, "roster",
                               return_value=self.baseline["databases"] + [marker["database"]]), \
                mock.patch.object(driver, "database_owner", return_value="other"), \
                mock.patch.object(driver, "drop_database") as drop:
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.cleanup_databases(self.baseline["databases"], marker)
        self.assertEqual(caught.exception.kind, "ownership")
        drop.assert_not_called()

    def test_duplicate_create_is_preexisting_and_never_dropped(self):
        with mock.patch.object(driver, "database_exists", return_value=False), \
                mock.patch.object(driver, "psql_outcome", return_value=(
                    1, b"", b'ERROR:  database "x" already exists\n')):
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.create_database(self.work, self.baseline, self.provenance)
        self.assertEqual(caught.exception.kind, "ownership")
        marker = driver.load_ownership_marker(self.work, self.baseline, self.provenance)
        self.assertEqual(marker["state"], "preexisting")
        with mock.patch.object(driver, "roster",
                               return_value=self.baseline["databases"] + [marker["database"]]), \
                mock.patch.object(driver, "database_owner", return_value="local"), \
                mock.patch.object(driver, "drop_database") as drop:
            with self.assertRaises(driver.EvidenceError) as caught:
                driver.cleanup_databases(self.baseline["databases"], marker)
        self.assertEqual(caught.exception.kind, "ownership")
        drop.assert_not_called()

    def test_unknown_sibling_is_never_scanned_or_dropped(self):
        sibling = "slot0_native_999_9_" + "f" * 32
        with mock.patch.object(driver, "roster",
                               return_value=self.baseline["databases"] + [sibling]), \
                mock.patch.object(driver, "drop_database") as drop:
            removed, restored = driver.cleanup_databases(self.baseline["databases"], None)
        self.assertFalse(removed)
        self.assertFalse(restored)
        drop.assert_not_called()

    def test_invalid_marker_fails_closed_without_drop(self):
        old = dict(self.provenance)
        old["run_id"] = 99
        marker = driver.ownership_marker(old, self.baseline, self.nonce, state="created")
        driver.write_ownership_marker(self.work, marker)
        (self.work / "pg-baseline.json").write_text(json.dumps(self.baseline))
        (self.evidence / "stage").write_text("test")
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance), \
                mock.patch.object(driver, "roster",
                                  return_value=self.baseline["databases"] + [marker["database"]]), \
                mock.patch.object(driver, "drop_database") as drop:
            result = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(result, 1)
        report = json.loads((self.evidence / "qualification.json").read_text())
        self.assertEqual(report["failure_class"], "ownership")
        self.assertFalse(report["cleanup"]["work_removed"])
        self.assertTrue(self.work.exists())
        drop.assert_not_called()

    def test_finalize_owner_mismatch_retains_marker(self):
        marker = self.write_marker(self.marker(state="owner-mismatch"))
        (self.work / "pg-baseline.json").write_text(json.dumps(self.baseline))
        (self.evidence / "stage").write_text("test")
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance), \
                mock.patch.object(driver, "roster",
                                  return_value=self.baseline["databases"] + [marker["database"]]), \
                mock.patch.object(driver, "drop_database") as drop:
            result = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(result, 1)
        report = json.loads((self.evidence / "qualification.json").read_text())
        self.assertEqual(report["failure_class"], "ownership")
        self.assertFalse(report["cleanup"]["work_removed"])
        self.assertTrue(self.work.exists())
        self.assertEqual(driver.load_ownership_marker(
            self.work, self.baseline, self.provenance), marker)
        drop.assert_not_called()

    def test_pg_unavailable_keeps_work_and_marker(self):
        marker = self.write_marker(self.marker(state="created"))
        (self.work / "pg-baseline.json").write_text(json.dumps(self.baseline))
        (self.evidence / "stage").write_text("test")
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance), \
                mock.patch.object(driver, "roster",
                                  side_effect=driver.EvidenceError("postgres")), \
                mock.patch.object(driver, "drop_database") as drop:
            result = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(result, 1)
        report = json.loads((self.evidence / "qualification.json").read_text())
        self.assertEqual(report["failure_class"], "postgres")
        self.assertFalse(report["cleanup"]["work_removed"])
        self.assertTrue(self.work.exists())
        self.assertEqual(driver.load_ownership_marker(
            self.work, self.baseline, self.provenance), marker)
        drop.assert_not_called()

    def test_finalize_retries_after_cleanup_failure(self):
        self.write_marker(self.marker(state="created"))
        (self.work / "pg-baseline.json").write_text(json.dumps(self.baseline))
        (self.evidence / "stage").write_text("test")
        calls = [driver.EvidenceError("postgres"), (True, True)]
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance), \
                mock.patch.object(driver, "cleanup_databases", side_effect=calls):
            first = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
            self.assertEqual(first, 1)
            self.assertTrue(self.work.exists())
            second = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(second, 1)
        self.assertFalse(self.work.exists())

    def test_repeated_finalize_preserves_existing_report(self):
        self.work.rmdir()
        report_path = self.evidence / "qualification.json"
        report_path.write_text(json.dumps({
            "schema": driver.SCHEMA,
            "run": {"id": 42, "attempt": 2},
            "product": {"commit": self.provenance["product_commit"],
                        "tree": self.provenance["product_tree"]},
            "workflow": {"sha256": self.provenance["workflow_sha256"]},
            "validator_sha256": driver.sha256_file(Path(driver.__file__).resolve()),
            "passed": True,
            "failure_class": None,
            "cleanup": {"database_removed": True, "roster_restored": True,
                        "work_removed": True, "evidence_clean": True},
        }))
        before = report_path.read_bytes()
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance):
            result = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(result, 0)
        self.assertEqual(report_path.read_bytes(), before)

    def test_old_report_with_different_run_is_not_inherited(self):
        self.work.rmdir()
        report_path = self.evidence / "qualification.json"
        report_path.write_text(json.dumps({
            "schema": driver.SCHEMA,
            "run": {"id": 99, "attempt": 2},
            "passed": True,
            "failure_class": None,
            "cleanup": {"database_removed": True, "roster_restored": True,
                        "work_removed": True, "evidence_clean": True},
        }))
        with mock.patch.object(driver, "verify_sources", return_value=self.provenance):
            result = driver.cmd_finalize(SimpleNamespace(
                work=str(self.work), evidence=str(self.evidence),
                product=str(self.product), workflow_source=str(self.root)))
        self.assertEqual(result, 1)
        report = json.loads(report_path.read_text())
        self.assertFalse(report["passed"])


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


    def prepare_block(self):
        return self.text.split(
            "      - name: Prepare job-owned scratch directories\n", 1)[1].split(
            "\n      - name: Check out", 1)[0]

    def prepare_script(self):
        lines = self.prepare_block().splitlines()
        start = lines.index("        run: |") + 1
        body = []
        for line in lines[start:]:
            if not line.startswith("          "):
                break
            body.append(line[10:])
        return "\n".join(body) + "\n"

    def run_prepare(self, root, env):
        script = root / "prepare.sh"
        script.write_text(self.prepare_script())
        subprocess.run(["bash", "-n", str(script)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return subprocess.run(["bash", str(script)], env=env, cwd=root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def prepare_env(self, runner, work, evidence, github_env):
        return {
            "PATH": os.environ.get("PATH", ""),
            "RUNNER_TEMP": str(runner),
            "WORK": str(work),
            "EVIDENCE": str(evidence),
            "GITHUB_ENV": str(github_env),
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "7",
        }

    def test_runner_context_is_limited_to_prepare_steps_env(self):
        top = self.text.split("\njobs:\n", 1)[0]
        job_prefix = self.text.split("  library-layer:\n", 1)[1].split("    steps:\n", 1)[0]
        for section in (top, job_prefix):
            self.assertNotIn("${{ runner.", section)
            self.assertNotIn("\n  WORK:", section)
            self.assertNotIn("\n  EVIDENCE:", section)
        prepare = self.prepare_block()
        self.assertEqual(self.text.count("${{ runner."), 2)
        self.assertIn("        env:\n", prepare)
        self.assertIn("WORK: ${{ runner.temp }}/issue42-native-slot0-${{ github.run_id }}-${{ github.run_attempt }}", prepare)
        self.assertIn("EVIDENCE: ${{ runner.temp }}/issue42-native-slot0-evidence-${{ github.run_id }}-${{ github.run_attempt }}", prepare)
        self.assertLess(prepare.index("mkdir -m 700 \"$WORK\""),
                        prepare.index("printf 'WORK=%s\\n'"))
        self.assertLess(prepare.index("mkdir -m 700 \"$EVIDENCE\""),
                        prepare.index("printf 'EVIDENCE=%s\\n'"))
        self.assertLess(prepare.index("printf 'EVIDENCE=%s\\n'"),
                        prepare.index("printf 'SLOT0_PATHS_READY=1\\n'"))
        guard = "if: ${{ always() && env.SLOT0_PATHS_READY == '1' && env.WORK != '' && env.EVIDENCE != '' }}"
        self.assertEqual(self.text.count(guard), 2)
        upload = self.text.split("      - name: Upload only the fixed allowlist qualification JSON\n", 1)[1]
        self.assertIn("          path: ${{ env.EVIDENCE }}/qualification.json", upload)
        self.assertNotIn("runner.temp", upload)

    def test_prepare_step_exports_only_after_owned_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner"
            runner.mkdir()
            work = runner / "issue42-native-slot0-42-7"
            evidence = runner / "issue42-native-slot0-evidence-42-7"
            github_env = root / "github_env"
            github_env.write_text("")
            result = self.run_prepare(root, self.prepare_env(runner, work, evidence, github_env))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stage=workspace status=ok", result.stdout)
            self.assertTrue(work.is_dir())
            self.assertTrue(evidence.is_dir())
            self.assertEqual(work.stat().st_mode & 0o777, 0o700)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            self.assertEqual(github_env.read_text(),
                             f"WORK={work}\nEVIDENCE={evidence}\nSLOT0_PATHS_READY=1\n")

    def test_prepare_step_failure_does_not_export_or_reuse_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner"
            runner.mkdir()
            work = runner / "issue42-native-slot0-42-7"
            evidence = runner / "issue42-native-slot0-evidence-42-7"
            evidence.mkdir(mode=0o700)
            github_env = root / "github_env"
            github_env.write_text("KEEP=1\n")
            result = self.run_prepare(root, self.prepare_env(runner, work, evidence, github_env))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(work.exists())
            self.assertEqual(github_env.read_text(), "KEEP=1\n")

    def test_prepare_step_rejects_empty_or_unbound_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner"
            runner.mkdir()
            github_env = root / "github_env"
            github_env.write_text("KEEP=1\n")
            candidates = (
                ("", ""),
                (runner / "issue42-native-slot0-99-7",
                 runner / "issue42-native-slot0-evidence-42-7"),
            )
            for work, evidence in candidates:
                result = self.run_prepare(
                    root, self.prepare_env(runner, work, evidence, github_env))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(github_env.read_text(), "KEEP=1\n")
                if str(work):
                    self.assertFalse(work.exists())
                if str(evidence):
                    self.assertFalse(evidence.exists())

    def test_all_run_blocks_parse_with_bash(self):
        lines = self.text.splitlines()
        blocks = []
        index = 0
        while index < len(lines):
            if lines[index].strip() != "run: |":
                index += 1
                continue
            indent = len(lines[index]) - len(lines[index].lstrip())
            body = []
            index += 1
            while index < len(lines):
                line = lines[index]
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                body.append(line[indent + 2:] if line.strip() else "")
                index += 1
            blocks.append("\n".join(body) + "\n")
        self.assertGreaterEqual(len(blocks), 7)
        for block in blocks:
            subprocess.run(["bash", "-n"], input=block, text=True, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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
        self.assertEqual(pin, "d148e5e75e441facf122b686dbd4647ff79fb266")
        self.assertEqual(tree, "7570397d3765bfa92dff4226b7876799f0071f5a")
        self.assertIn("Run exactly the twelve bounded native cases", self.text)

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
