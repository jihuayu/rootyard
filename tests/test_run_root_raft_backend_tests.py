#!/usr/bin/env python3
"""Pure regression for the dedicated Root Raft backend report runner.

These tests never compile Rust, execute Cargo, start a database, open a
network socket or run the real integration binary.  They exercise the parser,
privacy allowlist, finite timeout, direct one-shot invocation with an injected
in-memory process result, and the real shared v2 receipt validator against a
synthetic source tree and receipt fixture.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
from unittest import mock
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_build_receipt as receipts  # noqa: E402
import run_root_raft_backend_tests as runner  # noqa: E402

CASE_REAL = "real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart"
CASE_PRUNED = "pruned_receipts_export_restore_and_sqlite_reopen"
CASE_DRAIN = (
    "scope_drain_support::privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete"
)
SECRET = "fixture-secret-8f3c"
NOISE = (
    f"thread 'main' panicked at /tmp/private/{SECRET}/state.sqlite: boom\n"
    f"ROOTYARD_FIXTURE_SECRET={SECRET}\n"
)
GOOD_OUTPUT = NOISE + f"""running 3 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
REORDERED_OUTPUT = f"""running 3 tests
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... ok
test {CASE_REAL} ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
MISSING_OUTPUT = f"""running 1 test
test {CASE_REAL} ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
DUPLICATE_OUTPUT = f"""running 2 tests
test {CASE_REAL} ... ok
test {CASE_REAL} ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
EXTRA_OUTPUT = f"""running 4 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... ok
test secret_case ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
IGNORED_OUTPUT = f"""running 2 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... ignored

test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
FAILED_OUTPUT = f"""running 2 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... FAILED

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
NONZERO_FAILED_OUTPUT = f"""running 3 tests
test {CASE_REAL} ... FAILED
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... ok

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
ZERO_OUTPUT = """running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
COUNT_MISMATCH_OUTPUT = f"""running 4 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
SUMMARY = (
    "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; "
    "0 filtered out; finished in 0.01s"
)
REPORT_KEYS = {
    "passed",
    "source_head",
    "binary_sha256",
    "receipt_sha256",
    "cases",
    "counts",
    "finite_phase",
    "error_class",
}
DIAGNOSTIC_KEYS = {
    "exit_code",
    "signal",
    "evidence_complete",
    "suite_counts",
    "case_failures",
    "failure_phase",
    "failure_class",
    "unknown_case",
    "diagnostics_valid",
    "evidence_unchanged",
}


class FakeProcess:
    def __init__(self, stdout="", stderr="", returncode=0, timeout=False):
        self.stdout = io.BytesIO(stdout.encode("utf-8") if isinstance(stdout, str) else stdout)
        self.stderr = io.BytesIO(stderr.encode("utf-8") if isinstance(stderr, str) else stderr)
        self.returncode = None
        self._code = returncode
        self._timeout = timeout
        self.killed = False

    def wait(self, timeout=None):
        if self._timeout:
            self._timeout = False
            raise subprocess.TimeoutExpired("fake", timeout)
        self.returncode = self._code
        return self._code

    def kill(self):
        self.killed = True
        self.returncode = -9


class RootRaftRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        for relative, content in (
            ("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.0"\n'),
            ("Cargo.lock", "lock\n"),
            ("build.rs", "fn main() {}\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
            ("src/lib.rs", "pub fn fixture() {}\n"),
            ("experimental/pando/schema.sql", "create table fixture();\n"),
            (
                runner.TEST_SOURCE,
                "// synthetic Root Raft integration target\n",
            ),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.head = "a" * 40
        self.binary = self.root / "relocated" / runner.TEST_TARGET
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"#!/bin/sh\n")
        self.binary.chmod(0o755)
        self.receipt = self.binary.with_suffix(".build.json")
        self.write_receipt()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def toolchain(self) -> dict:
        return {
            "cargo": {
                "executable": str(self.root / "toolchain/cargo"),
                "executable_sha256": "1" * 64,
                "version": "cargo 1.101.0 (64a6ee6a4 2026-11-10)",
                "release": "1.101.0",
                "commit_hash": "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
                "host": "x86_64-unknown-linux-gnu",
            },
            "rustc": {
                "executable": str(self.root / "toolchain/rustc"),
                "executable_sha256": "2" * 64,
                "version": "rustc 1.99.1 (fixture)",
                "release": "1.99.1",
                "commit_hash": "b" * 40,
                "host": "x86_64-unknown-linux-gnu",
            },
            "target_triple": "x86_64-unknown-linux-gnu",
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def command(self) -> list[str]:
        return [
            "cargo",
            "--config",
            "profile.dev.package.rootyard.debug=0",
            "--config",
            "profile.test.package.rootyard.debug=0",
            "--config",
            'profile.dev.package.rootyard.strip="debuginfo"',
            "--config",
            'profile.test.package.rootyard.strip="debuginfo"',
            "rustc",
            "--locked",
            "--profile",
            "test",
            "--test",
            runner.TEST_TARGET,
            "--message-format=json-render-diagnostics",
        ]

    def write_receipt(self) -> dict:
        bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        event = {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": {
                "name": runner.TEST_TARGET,
                "kind": ["test"],
                "src_path": str(self.root / runner.TEST_SOURCE),
            },
            "profile": {
                "opt_level": "0",
                "debuginfo": 0,
                "debug_assertions": True,
                "overflow_checks": True,
                "test": True,
            },
            "fresh": False,
            "executable": str(self.binary),
        }
        artifact = receipts.cargo_artifact_record(event, self.root, kind="test")
        binary_digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        payload = receipts.make_receipt_v2(
            binary_path=self.binary,
            command=self.command(),
            profile="test",
            artifacts=[artifact],
            toolchain=self.toolchain(),
            bound_inputs=bound,
            workspace_commit=self.head,
            target_dir=self.root / "target",
            features=None,
            no_default_features=False,
            extra={
                "kind": "rust-integration-test",
                "relocated_artifact": True,
                "integration_test_source": runner.TEST_SOURCE,
                "integration_test_source_sha256": receipts.sha256_file(
                    self.root / runner.TEST_SOURCE
                ),
                "original_artifact_sha256": binary_digest,
            },
        )
        self.receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return payload

    def payload(self) -> dict:
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def rewrite(self, payload: dict) -> None:
        self.receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def assert_code(self, code: str, function, *args, **kwargs) -> runner.RunnerError:
        with self.assertRaises(runner.RunnerError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertIn(caught.exception.phase, runner.PHASES)
        self.assertNotIn(SECRET, str(caught.exception))
        return caught.exception

    # -- receipt binding ---------------------------------------------------
    def test_load_and_validate_accepts_fixed_v2_receipt(self) -> None:
        validated, receipt_sha, binary_sha = runner.load_and_validate(
            self.binary, self.receipt, self.head, root=self.root
        )
        self.assertEqual(validated.schema, "v2")
        self.assertEqual(validated.workspace_commit, self.head)
        self.assertEqual(
            receipt_sha, hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        )
        self.assertEqual(binary_sha, hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_receipt_tamper_counterexamples_are_refused(self) -> None:
        changes = (
            ("binary_sha256", "0" * 64, "binary_mismatch"),
            ("workspace_commit", "d" * 40, "stale_receipt"),
            ("kind", "rust-test", "receipt_kind"),
            ("relocated_artifact", False, "receipt_not_relocated"),
        )
        for field, value, code in changes:
            with self.subTest(field=field):
                payload = self.payload()
                payload[field] = value
                self.rewrite(payload)
                self.assert_code(
                    code,
                    runner.load_and_validate,
                    self.binary,
                    self.receipt,
                    self.head,
                    root=self.root,
                )
                self.write_receipt()

    def test_target_feature_and_source_tamper_are_refused(self) -> None:
        payload = self.payload()
        payload["cargo_artifacts"][0]["target"] = "other_target"
        self.rewrite(payload)
        self.assert_code(
            "receipt_target_mismatch",
            runner.load_and_validate,
            self.binary,
            self.receipt,
            self.head,
            root=self.root,
        )
        self.write_receipt()

        payload = self.payload()
        payload["features"]["no_default_features"] = True
        self.rewrite(payload)
        self.assert_code(
            "receipt_features",
            runner.load_and_validate,
            self.binary,
            self.receipt,
            self.head,
            root=self.root,
        )
        self.write_receipt()

        target = self.root / runner.TEST_SOURCE
        target.write_text(target.read_text(encoding="utf-8") + "// drift\n")
        self.assert_code(
            "receipt_invalid",
            runner.load_and_validate,
            self.binary,
            self.receipt,
            self.head,
            root=self.root,
        )

    def test_expected_commit_resolution_requires_external_anchor(self) -> None:
        self.assertEqual(
            runner.resolve_expected_commit(None, {"GITHUB_SHA": self.head}), self.head
        )
        self.assertEqual(runner.resolve_expected_commit(self.head, {}), self.head)
        self.assert_code(
            "missing_expected_commit", runner.resolve_expected_commit, None, {}
        )
        self.assert_code(
            "invalid_expected_commit",
            runner.resolve_expected_commit,
            "deadbeef",
            {},
        )
        self.assert_code(
            "expected_commit_conflict",
            runner.resolve_expected_commit,
            self.head,
            {"GITHUB_SHA": "d" * 40},
        )

    def test_timeout_is_finite_and_capped(self) -> None:
        self.assertEqual(runner._require_timeout(900), 900.0)
        for value in (901, 0, -1, float("nan"), float("inf"), True, "900"):
            with self.subTest(value=value):
                self.assert_code("timeout_invalid", runner._require_timeout, value)

    # -- parser ------------------------------------------------------------
    def test_parser_accepts_exact_three_case_fixture(self) -> None:
        cases, counts = runner.parse_test_output(GOOD_OUTPUT)
        self.assertEqual(
            cases, [{"name": name, "status": "passed"} for name in runner.REQUIRED_CASES]
        )
        self.assertEqual(runner.REQUIRED_CASES, (CASE_REAL, CASE_PRUNED, CASE_DRAIN))
        self.assertEqual(
            counts,
            {"passed": 3, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0},
        )
        self.assertNotIn(SECRET, json.dumps(cases))

    def test_parser_normalizes_required_case_order(self) -> None:
        cases, _counts = runner.parse_test_output(REORDERED_OUTPUT)
        self.assertEqual([case["name"] for case in cases], list(runner.REQUIRED_CASES))

    def test_parser_refuses_missing_duplicate_extra_and_ignored_cases(self) -> None:
        for output, code in (
            (MISSING_OUTPUT, "missing_case"),
            (DUPLICATE_OUTPUT, "duplicate_case"),
            (EXTRA_OUTPUT, "extra_case"),
            (IGNORED_OUTPUT, "ignored_case"),
        ):
            with self.subTest(code=code):
                self.assert_code(code, runner.parse_test_output, output)

    def test_parser_refuses_failed_zero_and_inconsistent_suites(self) -> None:
        for output, code in (
            (FAILED_OUTPUT, "test_failed"),
            (ZERO_OUTPUT, "zero_suite"),
            (COUNT_MISMATCH_OUTPUT, "count_mismatch"),
            (GOOD_OUTPUT + SUMMARY + "\n", "output_invalid"),
            ("noise " + SUMMARY + "\n", "output_invalid"),
        ):
            with self.subTest(code=code):
                self.assert_code(code, runner.parse_test_output, output)

    def test_unknown_case_names_are_never_serialized(self) -> None:
        self.assert_code("extra_case", runner.parse_test_output, EXTRA_OUTPUT)
        report = runner.build_report(
            False,
            self.head,
            "b" * 64,
            "c" * 64,
            [],
            runner._zero_counts(),
            "parse",
            "extra_case",
        )
        serialized = json.dumps(report)
        self.assertNotIn("secret_case", serialized)
        self.assertNotIn(SECRET, serialized)

    # -- execution and report ---------------------------------------------
    def test_execute_runs_the_exact_binary_once(self) -> None:
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return FakeProcess(GOOD_OUTPUT, SECRET, 0)

        result = runner.execute_case(self.binary, 900.0, run=fake_run)
        self.assertEqual(result.stdout, GOOD_OUTPUT)
        self.assertEqual(result.stderr, SECRET)
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.signal)
        self.assertEqual(result.termination, "exited")
        self.assertFalse(result.capture_truncated)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], [str(self.binary), "--test-threads=1"])
        self.assertEqual(calls[0][1]["stdout"], subprocess.PIPE)
        self.assertEqual(calls[0][1]["stderr"], subprocess.PIPE)
        self.assertNotIn("--", calls[0][0])
        self.assertNotIn("text", calls[0][1])
        self.assertNotIn("check", calls[0][1])

    def test_execute_retains_nonzero_signal_and_timeout_results(self) -> None:
        nonzero = runner.execute_case(
            self.binary, 900.0, run=lambda *_a, **_k: FakeProcess("", SECRET, 101)
        )
        self.assertEqual(nonzero.returncode, 101)
        self.assertIsNone(nonzero.signal)
        self.assertEqual(nonzero.termination, "exited")

        killed = runner.execute_case(
            self.binary, 900.0, run=lambda *_a, **_k: FakeProcess("", SECRET, -9)
        )
        self.assertIsNone(killed.returncode)
        self.assertEqual(killed.signal, 9)
        self.assertEqual(killed.termination, "signal")

        timed = runner.execute_case(
            self.binary,
            900.0,
            run=lambda *_a, **_k: FakeProcess("partial out", "partial err", timeout=True),
        )
        self.assertEqual(timed.stdout, "partial out")
        self.assertEqual(timed.stderr, "partial err")
        self.assertIsNone(timed.returncode)
        self.assertIsNone(timed.signal)
        self.assertEqual(timed.termination, "timeout")

        def spawn_failed(_command, **_kwargs):
            raise OSError("spawn refused")

        self.assert_code(
            "spawn_failed",
            runner.execute_case,
            self.binary,
            900.0,
            run=spawn_failed,
        )

    def test_execute_bounds_total_capture_across_streams(self) -> None:
        cap = runner.MAX_TOTAL_CAPTURE_BYTES
        result = runner.execute_case(
            self.binary,
            900.0,
            run=lambda *_a, **_k: FakeProcess(b"x" * (cap + 4096), b"y" * 4096, 0),
        )
        self.assertTrue(result.capture_truncated)
        self.assertLessEqual(
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")),
            cap,
        )
        evidence = runner.collect_failure_evidence(
            GOOD_OUTPUT, "", capture_truncated=True
        )
        self.assertFalse(evidence.complete)

    def test_failure_evidence_retains_complete_failed_suite(self) -> None:
        evidence = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT)
        self.assertTrue(evidence.complete)
        self.assertEqual(
            evidence.cases,
            [
                {"name": CASE_REAL, "status": "failed"},
                {"name": CASE_PRUNED, "status": "passed"},
                {"name": CASE_DRAIN, "status": "passed"},
            ],
        )
        self.assertEqual(
            evidence.counts,
            {"passed": 2, "failed": 1, "ignored": 0, "measured": 0, "filtered": 0},
        )
        self.assertEqual(evidence.suite_counts, evidence.counts)
        self.assertIsNone(evidence.failure_phase)
        self.assertIsNone(evidence.failure_class)
        self.assertTrue(evidence.diagnostics_valid)
        self.assertNotIn(SECRET, json.dumps(evidence.cases))

    def test_failure_evidence_requires_summary_status_and_counts_to_match_rows(self) -> None:
        all_ok_failed_summary = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... ok\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_DRAIN} ... ok\n"
            f"test result: FAILED. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        evidence = runner.collect_failure_evidence(all_ok_failed_summary)
        self.assertFalse(evidence.complete)
        self.assertEqual(
            evidence.counts,
            {"passed": 3, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0},
        )
        self.assertEqual([case["status"] for case in evidence.cases], ["passed"] * 3)
        self.assertEqual(evidence.suite_counts["passed"], 3)

        failed_row_ok_summary = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... FAILED\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_DRAIN} ... ok\n"
            f"test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        evidence = runner.collect_failure_evidence(failed_row_ok_summary)
        self.assertFalse(evidence.complete)
        self.assertEqual(
            evidence.counts,
            {"passed": 2, "failed": 1, "ignored": 0, "measured": 0, "filtered": 0},
        )
        self.assertEqual(evidence.cases[0], {"name": CASE_REAL, "status": "failed"})
        self.assertEqual(evidence.suite_counts, {"passed": 3, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0})

        consistent = runner.collect_failure_evidence(
            f"running 3 tests\n"
            f"test {CASE_REAL} ... FAILED\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_DRAIN} ... ok\n"
            f"test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        self.assertTrue(consistent.complete)
        self.assertEqual(consistent.counts["failed"], 1)

    def test_failure_evidence_is_partial_without_summary(self) -> None:
        partial = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... ok\n"
            f"test {CASE_PRUNED} ... ok\n"
        )
        evidence = runner.collect_failure_evidence(partial)
        self.assertFalse(evidence.complete)
        self.assertEqual(
            [case["name"] for case in evidence.cases], [CASE_REAL, CASE_PRUNED]
        )
        self.assertEqual(
            evidence.counts,
            {"passed": 2, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0},
        )
        self.assertIsNone(evidence.suite_counts)
        empty = runner.collect_failure_evidence("")
        self.assertFalse(empty.complete)
        self.assertEqual(empty.cases, [])
        self.assertEqual(
            empty.counts,
            {"passed": 0, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0},
        )
        oversized = runner.collect_failure_evidence(
            f"running 3 tests\n"
            f"test {CASE_REAL} ... ok\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_DRAIN} ... ok\n"
            f"test result: FAILED. 999 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        self.assertFalse(oversized.complete)
        self.assertIsNone(oversized.suite_counts)
        self.assertEqual(oversized.counts["passed"], 3)

    def test_failure_evidence_rejects_unknown_duplicate_and_bad_frames(self) -> None:
        duplicate = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... ok\n"
            f"test {CASE_REAL} ... FAILED\n"
            f"test secret_case ... ok\n"
            f"test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        evidence = runner.collect_failure_evidence(duplicate + SECRET)
        self.assertFalse(evidence.complete)
        self.assertTrue(evidence.unknown_case)
        self.assertNotIn("secret_case", json.dumps(evidence.cases))
        self.assertNotIn(SECRET, json.dumps(evidence.cases))

        frame = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=commit class=proposal_scope\n"
        )
        framed = runner.collect_failure_evidence("", frame)
        self.assertEqual(framed.failure_phase, "commit")
        self.assertEqual(framed.failure_class, "proposal_scope")
        self.assertTrue(framed.diagnostics_valid)

        bad = runner.collect_failure_evidence(
            "",
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=commit class=not_a_class\n" + SECRET,
        )
        self.assertIsNone(bad.failure_phase)
        self.assertFalse(bad.diagnostics_valid)
        self.assertNotIn(SECRET, json.dumps(bad.cases))

        conflicting = runner.collect_failure_evidence(
            "",
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=refusal class=storage\n",
        )
        self.assertIsNone(conflicting.failure_phase)
        self.assertFalse(conflicting.diagnostics_valid)

    def test_failure_evidence_keeps_stdout_rows_and_stderr_frames_separate(self) -> None:
        frame = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=commit class=proposal_scope\n"
        )
        evidence = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, frame)
        self.assertTrue(evidence.complete)
        self.assertEqual(evidence.failure_phase, "commit")
        self.assertEqual(evidence.failure_class, "proposal_scope")
        self.assertEqual(evidence.suite_counts, evidence.counts)

        frame_on_stdout = runner.collect_failure_evidence(frame, "")
        self.assertEqual(frame_on_stdout.cases, [])
        self.assertIsNone(frame_on_stdout.failure_phase)
        self.assertIsNone(frame_on_stdout.failure_class)

        collided = (
            f"running 3 tests\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_REAL} ... {frame.strip()}\n"
            "FAILED\n"
            f"test {CASE_DRAIN} ... FAILED\n"
            "test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        evidence = runner.collect_failure_evidence(collided, frame)
        self.assertFalse(evidence.complete)
        self.assertEqual([case["name"] for case in evidence.cases], [CASE_PRUNED, CASE_DRAIN])
        self.assertEqual(evidence.suite_counts, {"passed": 1, "failed": 2, "ignored": 0, "measured": 0, "filtered": 0})
        self.assertEqual(evidence.failure_phase, "commit")
        self.assertEqual(evidence.failure_class, "proposal_scope")

    def test_failure_frames_are_attributed_per_case(self) -> None:
        stdout = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... FAILED\n"
            f"test {CASE_PRUNED} ... ok\n"
            f"test {CASE_DRAIN} ... FAILED\n"
            "test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        stderr = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} phase=settled_evaluate class=scope_binding\n"
        )
        evidence = runner.collect_failure_evidence(stdout, stderr)
        self.assertTrue(evidence.diagnostics_valid)
        self.assertEqual(
            evidence.case_failures,
            [
                {"case": CASE_REAL, "phase": "commit", "class": "proposal_scope"},
                {"case": CASE_DRAIN, "phase": "settled_evaluate", "class": "scope_binding"},
            ],
        )
        self.assertIsNone(evidence.failure_phase)
        self.assertIsNone(evidence.failure_class)
        self.assertTrue(evidence.complete)
        self.assertEqual(evidence.suite_counts, evidence.counts)

        conflict = runner.collect_failure_evidence(
            stdout,
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=refusal class=storage\n",
        )
        self.assertFalse(conflict.diagnostics_valid)
        self.assertEqual(conflict.case_failures, [])
        self.assertIsNone(conflict.failure_phase)

        partial_conflict = runner.collect_failure_evidence(
            stdout,
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=refusal class=storage\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} phase=settled_evaluate class=scope_binding\n",
        )
        self.assertFalse(partial_conflict.diagnostics_valid)
        self.assertEqual(
            partial_conflict.case_failures,
            [{"case": CASE_DRAIN, "phase": "settled_evaluate", "class": "scope_binding"}],
        )
        self.assertIsNone(partial_conflict.failure_phase)
        self.assertIsNone(partial_conflict.failure_class)

        duplicate = runner.collect_failure_evidence(
            stdout,
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n",
        )
        self.assertTrue(duplicate.diagnostics_valid)
        self.assertEqual(len(duplicate.case_failures), 1)

        unknown = runner.collect_failure_evidence(
            stdout,
            "ROOTYARD_FAILURE_FRAME v1 case=secret_case phase=commit class=proposal_scope\n",
        )
        self.assertTrue(unknown.unknown_case)
        self.assertEqual(unknown.case_failures, [])

    def test_main_retains_partial_evidence_on_nonzero_without_passing(self) -> None:
        path = self.root / "out" / "nonzero-report.json"
        output = NONZERO_FAILED_OUTPUT
        stderr = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=commit class=proposal_scope\n"
        )

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(output, stderr, 101, None, "exited")

        with mock.patch.object(runner, "require_source_state", return_value=self.head), \
             mock.patch.object(runner, "_safe_head", return_value=self.head), \
             mock.patch.object(
                 runner,
                 "load_and_validate",
                 return_value=(None, "c" * 64, "b" * 64),
             ), \
             mock.patch.object(runner, "execute_case", side_effect=fake_execute), \
             mock.patch.object(runner, "_verify_evidence_unchanged", return_value=None):
            code = runner.main(
                [
                    "--test-binary",
                    str(self.binary),
                    "--build-receipt",
                    str(self.receipt),
                    "--report",
                    str(path),
                    "--expected-commit",
                    self.head,
                ]
            )
        self.assertEqual(code, 1)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_class"], "nonzero_exit")
        self.assertEqual(report["finite_phase"], "execute")
        self.assertEqual(len(report["cases"]), 3)
        self.assertEqual(report["diagnostics"], {
            "exit_code": 101,
            "signal": None,
            "evidence_complete": True,
            "suite_counts": {"passed": 2, "failed": 1, "ignored": 0, "measured": 0, "filtered": 0},
            "case_failures": [{"case": CASE_REAL, "phase": "commit", "class": "proposal_scope"}],
            "failure_phase": "commit",
            "failure_class": "proposal_scope",
            "unknown_case": False,
            "diagnostics_valid": True,
            "evidence_unchanged": True,
        })
        serialized = json.dumps(report)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_main_nonzero_with_passing_suite_still_fails(self) -> None:
        path = self.root / "out" / "nonzero-passing-report.json"

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(GOOD_OUTPUT, "", 101, None, "exited")

        with mock.patch.object(runner, "require_source_state", return_value=self.head), \
             mock.patch.object(runner, "_safe_head", return_value=self.head), \
             mock.patch.object(
                 runner,
                 "load_and_validate",
                 return_value=(None, "c" * 64, "b" * 64),
             ), \
             mock.patch.object(runner, "execute_case", side_effect=fake_execute), \
             mock.patch.object(runner, "_verify_evidence_unchanged", return_value=None):
            code = runner.main(
                [
                    "--test-binary",
                    str(self.binary),
                    "--build-receipt",
                    str(self.receipt),
                    "--report",
                    str(path),
                    "--expected-commit",
                    self.head,
                ]
            )
        self.assertEqual(code, 1)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_class"], "nonzero_exit")
        self.assertEqual([case["status"] for case in report["cases"]], ["passed"] * 3)
        self.assertEqual(report["counts"]["passed"], 3)
        self.assertTrue(report["diagnostics"]["evidence_complete"])

    def test_main_preserves_original_failure_when_postrun_evidence_is_unavailable(self) -> None:
        path = self.root / "out" / "evidence-changed-report.json"

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(NONZERO_FAILED_OUTPUT, "", 101, None, "exited")

        def changed(*_args, **_kwargs):
            raise runner.RunnerError("execute", "evidence_changed")

        with mock.patch.object(runner, "require_source_state", return_value=self.head), \
             mock.patch.object(runner, "_safe_head", return_value=self.head), \
             mock.patch.object(
                 runner,
                 "load_and_validate",
                 return_value=(None, "c" * 64, "b" * 64),
             ), \
             mock.patch.object(runner, "execute_case", side_effect=fake_execute), \
             mock.patch.object(runner, "_verify_evidence_unchanged", side_effect=changed):
            code = runner.main(
                [
                    "--test-binary",
                    str(self.binary),
                    "--build-receipt",
                    str(self.receipt),
                    "--report",
                    str(path),
                    "--expected-commit",
                    self.head,
                ]
            )
        self.assertEqual(code, 1)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_class"], "nonzero_exit")
        self.assertEqual(len(report["cases"]), 3)
        self.assertFalse(report["diagnostics"]["evidence_unchanged"])
        self.assertEqual(
            report["diagnostics"]["suite_counts"],
            {"passed": 2, "failed": 1, "ignored": 0, "measured": 0, "filtered": 0},
        )

    def test_main_timeout_and_signal_keep_partial_evidence(self) -> None:
        partial = (
            f"running 3 tests\n"
            f"test {CASE_REAL} ... ok\n"
            f"test {CASE_PRUNED} ... ok\n"
        )
        for termination, signal, expected_class in (
            ("timeout", None, "timeout"),
            ("signal", 9, "signal_killed"),
        ):
            with self.subTest(termination=termination):
                path = self.root / "out" / f"{termination}-report.json"

                def fake_execute(*_args, **_kwargs):
                    return runner.ExecutionResult(partial, SECRET, None, signal, termination)

                with mock.patch.object(runner, "require_source_state", return_value=self.head), \
                     mock.patch.object(runner, "_safe_head", return_value=self.head), \
                     mock.patch.object(
                         runner,
                         "load_and_validate",
                         return_value=(None, "c" * 64, "b" * 64),
                     ), \
                     mock.patch.object(runner, "execute_case", side_effect=fake_execute), \
                     mock.patch.object(runner, "_verify_evidence_unchanged", return_value=None):
                    code = runner.main(
                        [
                            "--test-binary",
                            str(self.binary),
                            "--build-receipt",
                            str(self.receipt),
                            "--report",
                            str(path),
                            "--expected-commit",
                            self.head,
                        ]
                    )
                self.assertEqual(code, 1)
                report = json.loads(path.read_text(encoding="utf-8"))
                self.assertFalse(report["passed"])
                self.assertEqual(report["error_class"], expected_class)
                self.assertEqual(len(report["cases"]), 2)
                self.assertEqual(report["counts"]["passed"], 2)
                self.assertEqual(report["diagnostics"]["exit_code"], None)
                self.assertEqual(report["diagnostics"]["signal"], signal)
                self.assertFalse(report["diagnostics"]["evidence_complete"])
                self.assertIsNone(report["diagnostics"]["suite_counts"])
                self.assertIsNone(report["diagnostics"]["failure_phase"])
                self.assertIsNone(report["diagnostics"]["failure_class"])
                self.assertTrue(report["diagnostics"]["diagnostics_valid"])
                self.assertNotIn(SECRET, json.dumps(report))

    def test_main_evidence_drift_after_success_fails_without_losing_cases(self) -> None:
        path = self.root / "out" / "evidence-changed-success-report.json"

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(GOOD_OUTPUT, "", 0, None, "exited")

        def changed(*_args, **_kwargs):
            raise runner.RunnerError("execute", "evidence_changed")

        with mock.patch.object(runner, "require_source_state", return_value=self.head), \
             mock.patch.object(runner, "_safe_head", return_value=self.head), \
             mock.patch.object(
                 runner,
                 "load_and_validate",
                 return_value=(None, "c" * 64, "b" * 64),
             ), \
             mock.patch.object(runner, "execute_case", side_effect=fake_execute), \
             mock.patch.object(runner, "_verify_evidence_unchanged", side_effect=changed):
            code = runner.main(
                [
                    "--test-binary",
                    str(self.binary),
                    "--build-receipt",
                    str(self.receipt),
                    "--report",
                    str(path),
                    "--expected-commit",
                    self.head,
                ]
            )
        self.assertEqual(code, 1)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_class"], "evidence_changed")
        self.assertEqual(len(report["cases"]), 3)
        self.assertFalse(report["diagnostics"]["evidence_unchanged"])

    def test_report_allowlist_and_privacy(self) -> None:
        cases = [
            {"name": name, "status": "passed"} for name in runner.REQUIRED_CASES
        ]
        counts = {
            "passed": 3,
            "failed": 0,
            "ignored": 0,
            "measured": 0,
            "filtered": 0,
        }
        report = runner.build_report(
            True, self.head, "b" * 64, "c" * 64, cases, counts, "complete", None
        )
        self.assertEqual(set(report), REPORT_KEYS)
        self.assertEqual(report["cases"], cases)
        self.assertEqual(report["counts"], counts)
        self.assertIsNone(report["error_class"])
        serialized = json.dumps(report)
        for forbidden in (SECRET, str(self.root), "/tmp/private", "--test-threads"):
            self.assertNotIn(forbidden, serialized)
        failure = runner.build_report(
            False,
            None,
            None,
            None,
            [],
            runner._zero_counts(),
            "parse",
            "missing_case",
        )
        self.assertEqual(set(failure), REPORT_KEYS)
        self.assertEqual(failure["error_class"], "missing_case")
        self.assertEqual(failure["finite_phase"], "parse")
        diagnostics = {
            "exit_code": 101,
            "signal": None,
            "evidence_complete": True,
            "suite_counts": {"passed": 2, "failed": 1, "ignored": 0, "measured": 0, "filtered": 0},
            "case_failures": [{"case": CASE_REAL, "phase": "commit", "class": "proposal_scope"}],
            "failure_phase": "commit",
            "failure_class": "proposal_scope",
            "unknown_case": False,
            "diagnostics_valid": True,
            "evidence_unchanged": True,
        }
        failed_with_diagnostics = runner.build_report(
            False,
            self.head,
            "b" * 64,
            "c" * 64,
            [],
            runner._zero_counts(),
            "execute",
            "nonzero_exit",
            diagnostics,
        )
        self.assertEqual(set(failed_with_diagnostics), REPORT_KEYS | {"diagnostics"})
        self.assertEqual(set(failed_with_diagnostics["diagnostics"]), DIAGNOSTIC_KEYS)

    def test_write_report_is_atomic_json(self) -> None:
        path = self.root / "out" / "root-raft-report.json"
        payload = runner.build_report(
            True,
            self.head,
            "b" * 64,
            "c" * 64,
            [{"name": CASE_REAL, "status": "passed"}],
            {"passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0},
            "complete",
            None,
        )
        runner.write_report(path, payload)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)
        self.assertFalse(path.with_name(path.name + ".tmp").exists())

    def test_runner_source_uses_only_the_shared_receipt_reader(self) -> None:
        source = Path(runner.__file__).read_text(encoding="utf-8")
        self.assertIn("import native_build_receipt", source)
        self.assertIn("validate_receipt", source)
        self.assertNotIn("verify_receipt", source)
        self.assertNotIn("import build_native", source)
        self.assertNotIn("from build_native", source)


if __name__ == "__main__":
    unittest.main()
