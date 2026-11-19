#!/usr/bin/env python3
"""Pure regression for the dedicated Root Raft backend report runner.

These tests never compile Rust, execute Cargo, start a database, open a
network socket or run the real integration binary.  They exercise the parser,
privacy allowlist, finite timeout, direct one-shot invocation with an injected
in-memory process result, and the real shared v2 receipt validator against a
synthetic source tree and receipt fixture.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
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
SCOPE_FAILED_OUTPUT = f"""running 3 tests
test {CASE_REAL} ... ok
test {CASE_PRUNED} ... ok
test {CASE_DRAIN} ... FAILED

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
    "quorum_diagnostics",
    "append_witness",
}


def _diagnostic_node(slot):
    return {
        "slot": slot,
        "running_state": "ok",
        "server_state": "leader" if slot == 1 else "follower",
        "leader_slot": "slot1",
        "term": 7,
        "last_log_index": 42,
        "last_applied_index": 41,
        "voter_count": 3,
        "millis_since_quorum_ack": 5 if slot == 1 else None,
        "numeric_overflow": False,
    }


def _matching_entry(slot, matched_index=None, matched_term=None, matched_leader_slot=None):
    return {
        "slot": slot,
        "matched_index": matched_index,
        "matched_term": matched_term,
        "matched_leader_slot": matched_leader_slot,
    }


def _diagnostic_v2_node(slot, replication_matching):
    node = _diagnostic_node(slot)
    node["replication_matching"] = replication_matching
    return node


def _diagnostic_payload():
    return {
        "schema": "rootyard.quorum_diagnostics.v1",
        "case": CASE_REAL,
        "phase": "semantic_input_write",
        "operation": "client_write",
        "cause": "write_forward",
        "elapsed_ms": 12,
        "elapsed_overflow": False,
        "snapshots": [
            {"at": "before", "nodes": [_diagnostic_node(1), _diagnostic_node(2), _diagnostic_node(3)]},
            {"at": "after", "nodes": [_diagnostic_node(1), _diagnostic_node(2), _diagnostic_node(3)]},
        ],
    }


def _diagnostic_v2_matching():
    return [
        _matching_entry(1, 42, 7, "slot1"),
        _matching_entry(2, 42, 7, "slot1"),
        _matching_entry(3),
    ]


def _diagnostic_v2_payload():
    payload = _diagnostic_payload()
    payload["schema"] = "rootyard.quorum_diagnostics.v2"
    payload["snapshots"] = [
        {
            "at": at,
            "nodes": [
                _diagnostic_v2_node(1, _diagnostic_v2_matching()),
                _diagnostic_v2_node(2, None),
                _diagnostic_v2_node(3, None),
            ],
        }
        for at in ("before", "after")
    ]
    return payload


def _diagnostic_frame(payload=None):
    return (
        "ROOTYARD_QUORUM_DIAGNOSTICS v1 "
        + json.dumps(_diagnostic_payload() if payload is None else payload, separators=(",", ":"))
        + "\n"
    )


def _diagnostic_v2_frame(payload=None):
    return (
        "ROOTYARD_QUORUM_DIAGNOSTICS v2 "
        + json.dumps(
            _diagnostic_v2_payload() if payload is None else payload, separators=(",", ":")
        )
        + "\n"
    )


def _append_observation(
    target_slot=2,
    sender_slot=1,
    decoded=3,
    handled=3,
    handler="success",
    write_ok=3,
    write_error=0,
    term=7,
    prev_index=19,
    first_index=20,
    last_index=20,
    entry_count=1,
    overflow=False,
):
    return {
        "target_slot": target_slot,
        "sender_slot": sender_slot,
        "decoded": decoded,
        "handled": handled,
        "handler": handler,
        "write_ok": write_ok,
        "write_error": write_error,
        "term": term,
        "prev_index": prev_index,
        "first_index": first_index,
        "last_index": last_index,
        "entry_count": entry_count,
        "overflow": overflow,
    }


def _append_witness_payload(observations=None, case=CASE_REAL):
    return {
        "schema": "rootyard.append_witness.v1",
        "case": case,
        "observations": [_append_observation()] if observations is None else observations,
    }


def _append_witness_frame(payload=None):
    return (
        "ROOTYARD_APPEND_WITNESS v1 "
        + json.dumps(
            _append_witness_payload() if payload is None else payload,
            separators=(",", ":"),
        )
        + "\n"
    )


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

    def _cli_anchor_environment(self):
        """Neutralize only an ambient CI SHA for cases using --expected-commit.

        The production resolver keeps its deliberate conflict check; these
        mocked CLI cases supply their own anchor and must not be preempted by
        an unrelated full GITHUB_SHA from the invoking host. Other environment
        variables stay visible because the patch does not clear the mapping.
        """
        return mock.patch.dict(os.environ, {"GITHUB_SHA": ""}, clear=False)

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
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=semantic_healthy_write class=storage\n",
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
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=semantic_healthy_write class=storage\n",
        )
        self.assertFalse(conflict.diagnostics_valid)
        self.assertEqual(conflict.case_failures, [])
        self.assertIsNone(conflict.failure_phase)

        partial_conflict = runner.collect_failure_evidence(
            stdout,
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=proposal_scope\n"
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=semantic_healthy_write class=storage\n"
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

    def test_fixed_transition_subphases_are_closed_and_case_scoped(self) -> None:
        self.assertEqual(runner.EXPECTED_CASE_COUNT, 3)
        self.assertEqual(runner.REQUIRED_CASES, (CASE_REAL, CASE_PRUNED, CASE_DRAIN))
        phases = (
            "semantic_input_write",
            "semantic_input_view",
            "semantic_identity_write",
            "semantic_identity_view",
            "semantic_healthy_write",
            "semantic_healthy_view",
            "closing_write",
            "closing_view",
            "refused_write",
            "refused_view",
            "refusal_lookup",
            "refusal_replay",
            "healthy_write",
            "healthy_view",
            "standalone_probe",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                frame = (
                    f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
                    f"phase={phase} class=quorum_unavailable\n"
                )
                evidence = runner.collect_failure_evidence("", frame)
                self.assertTrue(evidence.diagnostics_valid)
                self.assertEqual(
                    evidence.case_failures,
                    [{"case": CASE_REAL, "phase": phase, "class": "quorum_unavailable"}],
                )
                self.assertEqual(evidence.failure_phase, phase)

        wrong_case = runner.collect_failure_evidence(
            "",
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} phase=closing_write class=quorum_unavailable\n",
        )
        self.assertFalse(wrong_case.diagnostics_valid)
        self.assertEqual(wrong_case.case_failures, [])

        for removed in ("transition", "refusal"):
            with self.subTest(removed=removed):
                removed_phase = runner.collect_failure_evidence(
                    "",
                    f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase={removed} class=quorum_unavailable\n",
                )
                self.assertFalse(removed_phase.diagnostics_valid)
                self.assertEqual(removed_phase.case_failures, [])

        secret_phase = runner.collect_failure_evidence(
            "",
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=secret_phase class=quorum_unavailable\n"
            + SECRET,
        )
        self.assertFalse(secret_phase.diagnostics_valid)
        self.assertNotIn(SECRET, json.dumps(secret_phase.case_failures))

    def test_final_reopen_failure_classes_are_closed(self) -> None:
        classes = (
            "final_reopen_shutdown",
            "final_reopen_directory",
            "final_reopen_exhausted",
            "final_reopen_snapshot_read",
            "final_reopen_snapshot_missing",
        )
        for class_code in classes:
            with self.subTest(class_code=class_code):
                frame = (
                    f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
                    f"phase=final_reopen class={class_code}\n"
                )
                evidence = runner.collect_failure_evidence("", frame)
                self.assertTrue(evidence.diagnostics_valid)
                self.assertEqual(
                    evidence.case_failures,
                    [{"case": CASE_REAL, "phase": "final_reopen", "class": class_code}],
                )
                self.assertEqual(evidence.failure_phase, "final_reopen")
                self.assertEqual(evidence.failure_class, class_code)
                self.assertNotIn(SECRET, json.dumps(evidence.case_failures))

        unknown = runner.collect_failure_evidence(
            "",
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=final_reopen class=final_reopen_attempt\n" + SECRET,
        )
        self.assertFalse(unknown.diagnostics_valid)
        self.assertEqual(unknown.case_failures, [])
        self.assertNotIn(SECRET, json.dumps(unknown.case_failures))

    def test_quorum_diagnostic_is_validated_and_safely_rebuilt(self) -> None:
        for operation, cause, phase in (
            ("client_write", "write_forward", "semantic_input_write"),
            ("client_write", "write_fatal_storage", "semantic_healthy_write"),
            ("read_view", "read_quorum_shortfall", "closing_view"),
            ("read_view", "read_outer_deadline", "closing_view"),
            ("receipt", "read_fatal_panicked", "refusal_lookup"),
            ("prepare", "unclassified", "commit"),
        ):
            with self.subTest(operation=operation, cause=cause):
                payload = _diagnostic_payload()
                payload.update(operation=operation, cause=cause, phase=phase)
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, _diagnostic_frame(payload)
                )
                self.assertTrue(evidence.diagnostics_valid)
                self.assertEqual(len(evidence.quorum_diagnostics), 1)
                safe = evidence.quorum_diagnostics[0]
                self.assertEqual(set(safe), runner._DIAGNOSTIC_TOP_KEYS)
                self.assertEqual(safe["schema"], "rootyard.quorum_diagnostics.v1")
                self.assertEqual(safe["case"], CASE_REAL)
                self.assertEqual(safe["phase"], phase)
                self.assertEqual(safe["operation"], operation)
                self.assertEqual(safe["cause"], cause)
                self.assertEqual(safe["elapsed_ms"], 12)
                self.assertFalse(safe["elapsed_overflow"])
                self.assertEqual([item["at"] for item in safe["snapshots"]], ["before", "after"])
                self.assertEqual(
                    [node["slot"] for node in safe["snapshots"][0]["nodes"]], [1, 2, 3]
                )
                self.assertEqual(
                    set(safe["snapshots"][0]), runner._DIAGNOSTIC_SNAPSHOT_KEYS
                )
                self.assertEqual(
                    set(safe["snapshots"][0]["nodes"][0]), runner._DIAGNOSTIC_NODE_KEYS_V1
                )
                self.assertNotIn(SECRET, json.dumps(safe))

    def test_quorum_diagnostic_rejects_duplicate_unknown_extra_and_oversized_frames(self) -> None:
        valid = _diagnostic_frame()
        duplicate = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, valid + valid)
        self.assertFalse(duplicate.diagnostics_valid)
        self.assertEqual(duplicate.quorum_diagnostics, [])

        extra_payload = _diagnostic_payload()
        extra_payload["secret"] = SECRET
        extra = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(extra_payload)
        )
        self.assertFalse(extra.diagnostics_valid)
        self.assertEqual(extra.quorum_diagnostics, [])
        self.assertNotIn(SECRET, json.dumps(extra.quorum_diagnostics))

        unknown_payload = _diagnostic_payload()
        unknown_payload["case"] = "secret_case"
        unknown = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(unknown_payload)
        )
        self.assertTrue(unknown.unknown_case)
        self.assertFalse(unknown.diagnostics_valid)
        self.assertEqual(unknown.quorum_diagnostics, [])
        self.assertNotIn("secret_case", json.dumps(unknown.quorum_diagnostics))

        wrong_known = _diagnostic_payload()
        wrong_known["case"] = CASE_DRAIN
        other_case = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(wrong_known)
        )
        self.assertFalse(other_case.diagnostics_valid)
        self.assertEqual(other_case.quorum_diagnostics, [])

        passed = runner.collect_failure_evidence(GOOD_OUTPUT, valid)
        self.assertFalse(passed.diagnostics_valid)
        self.assertEqual(passed.quorum_diagnostics, [])

        duplicate_key = _diagnostic_frame().replace(
            '"elapsed_ms":12', '"elapsed_ms":12,"elapsed_ms":13'
        )
        duplicated_field = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, duplicate_key
        )
        self.assertFalse(duplicated_field.diagnostics_valid)
        self.assertEqual(duplicated_field.quorum_diagnostics, [])

        oversized_payload = json.dumps(_diagnostic_payload(), separators=(",", ":"))
        oversized = (
            "ROOTYARD_QUORUM_DIAGNOSTICS v1 "
            + oversized_payload.replace(",", " " * 300 + ",")
            + "\n"
        )
        too_large = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, oversized)
        self.assertFalse(too_large.diagnostics_valid)
        self.assertEqual(too_large.quorum_diagnostics, [])

    def test_quorum_diagnostic_rejects_bad_types_ranges_cardinality_and_binding(self) -> None:
        cases = []
        payload = _diagnostic_payload()
        payload["elapsed_ms"] = True
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["elapsed_ms"] = 900_001
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["elapsed_overflow"] = 1
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["elapsed_overflow"] = True
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["snapshots"][0]["nodes"] = payload["snapshots"][0]["nodes"][:2]
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["snapshots"][1]["nodes"][2]["slot"] = 2
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["snapshots"][0]["nodes"][0]["term"] = 1_000_000_001
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["snapshots"][0]["nodes"][0]["numeric_overflow"] = True
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["phase"] = "refusal"
        cases.append(payload)
        payload = _diagnostic_payload()
        payload.update(operation="client_write", cause="read_quorum_shortfall")
        cases.append(payload)
        payload = _diagnostic_payload()
        payload["snapshots"][0]["at"] = "after"
        cases.append(payload)
        for payload in cases:
            with self.subTest(payload=payload):
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, _diagnostic_frame(payload)
                )
                self.assertFalse(evidence.diagnostics_valid)
                self.assertEqual(evidence.quorum_diagnostics, [])

        coarse = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=commit class=quorum_unavailable\n"
        )
        mismatched = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, coarse + _diagnostic_frame()
        )
        self.assertFalse(mismatched.diagnostics_valid)
        self.assertEqual(mismatched.quorum_diagnostics, [])

    def test_quorum_diagnostic_accepts_exact_scope_and_heal_phases(self) -> None:
        cases = (
            (CASE_REAL, NONZERO_FAILED_OUTPUT, "heal", "read_view", "read_quorum_shortfall"),
            (CASE_DRAIN, SCOPE_FAILED_OUTPUT, "heal", "read_view", "read_outer_deadline"),
            (
                CASE_DRAIN,
                SCOPE_FAILED_OUTPUT,
                "recovery_rejections",
                "prepare",
                "read_quorum_shortfall",
            ),
        )
        for case, stdout, phase, operation, cause in cases:
            with self.subTest(case=case, phase=phase):
                payload = _diagnostic_payload()
                payload.update(
                    case=case,
                    phase=phase,
                    operation=operation,
                    cause=cause,
                )
                scalar = (
                    f"ROOTYARD_FAILURE_FRAME v1 case={case} "
                    f"phase={phase} class=quorum_unavailable\n"
                )
                evidence = runner.collect_failure_evidence(
                    stdout, scalar + _diagnostic_frame(payload)
                )
                self.assertTrue(evidence.diagnostics_valid)
                self.assertEqual(len(evidence.quorum_diagnostics), 1)
                self.assertEqual(evidence.quorum_diagnostics[0]["case"], case)
                self.assertEqual(evidence.quorum_diagnostics[0]["phase"], phase)
                self.assertEqual(evidence.quorum_diagnostics[0]["operation"], operation)
                self.assertEqual(evidence.quorum_diagnostics[0]["cause"], cause)
                self.assertEqual(
                    [node["slot"] for node in evidence.quorum_diagnostics[0]["snapshots"][0]["nodes"]],
                    [1, 2, 3],
                )

    def test_append_witness_is_bound_to_failed_real_case_receipt(self) -> None:
        scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=heal class=quorum_unavailable\n"
        )
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, scalar + _append_witness_frame()
        )
        self.assertTrue(evidence.diagnostics_valid)
        self.assertEqual(len(evidence.append_witness), 1)
        safe = evidence.append_witness[0]
        self.assertEqual(set(safe), runner._APPEND_WITNESS_TOP_KEYS)
        self.assertEqual(safe["schema"], runner._APPEND_WITNESS_SCHEMA)
        self.assertEqual(safe["case"], CASE_REAL)
        observation = safe["observations"][0]
        self.assertEqual(set(observation), runner._APPEND_WITNESS_OBSERVATION_KEYS)
        self.assertEqual(observation["target_slot"], 2)
        self.assertEqual(observation["sender_slot"], 1)
        self.assertEqual(observation["decoded"], 3)
        self.assertEqual(observation["handled"], 3)
        self.assertEqual(observation["handler"], "success")
        self.assertEqual(observation["write_ok"], 3)
        self.assertEqual(observation["write_error"], 0)
        self.assertEqual(observation["term"], 7)
        self.assertEqual(observation["prev_index"], 19)
        self.assertEqual(observation["first_index"], 20)
        self.assertEqual(observation["last_index"], 20)
        self.assertEqual(observation["entry_count"], 1)
        self.assertFalse(observation["overflow"])
        self.assertNotIn(SECRET, json.dumps(evidence.append_witness))

    def test_append_witness_rejects_bad_shapes_and_bindings(self) -> None:
        scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=heal class=quorum_unavailable\n"
        )
        valid = _append_witness_frame()

        no_receipt = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, valid)
        self.assertFalse(no_receipt.diagnostics_valid)
        self.assertEqual(no_receipt.append_witness, [])

        passed = runner.collect_failure_evidence(GOOD_OUTPUT, valid)
        self.assertFalse(passed.diagnostics_valid)
        self.assertEqual(passed.append_witness, [])

        duplicate = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, scalar + valid + valid
        )
        self.assertFalse(duplicate.diagnostics_valid)
        self.assertEqual(duplicate.append_witness, [])

        duplicate_key = valid.replace('"decoded":3', '"decoded":3,"decoded":4')
        duplicated_field = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, scalar + duplicate_key
        )
        self.assertFalse(duplicated_field.diagnostics_valid)
        self.assertEqual(duplicated_field.append_witness, [])

        oversized = (
            "ROOTYARD_APPEND_WITNESS v1 "
            + " " * runner._MAX_APPEND_FRAME_BYTES
            + json.dumps(_append_witness_payload(), separators=(",", ":"))
            + "\n"
        )
        too_large = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, scalar + oversized)
        self.assertFalse(too_large.diagnostics_valid)
        self.assertEqual(too_large.append_witness, [])

        cases = []
        payload = _append_witness_payload()
        payload["schema"] = "rootyard.append_witness.v2"
        cases.append(payload)
        payload = _append_witness_payload(case=CASE_DRAIN)
        cases.append(payload)
        payload = _append_witness_payload(observations=[])
        payload["case"] = CASE_PRUNED
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["target_slot"] = 4
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["decoded"] = 0
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["handled"] = 4
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["handler"] = "secret_handler"
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["first_index"] = 21
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["entry_count"] = 0
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["overflow"] = 1
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["term"] = runner._MAX_DIAGNOSTIC_TERM + 1
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["decoded"] = runner._MAX_APPEND_COUNT + 1
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["prev_index"] = -1
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"][0]["secret"] = SECRET
        cases.append(payload)
        payload = _append_witness_payload()
        payload["observations"].append(copy.deepcopy(payload["observations"][0]))
        cases.append(payload)
        for payload in cases:
            with self.subTest(payload=payload):
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, scalar + _append_witness_frame(payload)
                )
                self.assertFalse(evidence.diagnostics_valid)
                self.assertEqual(evidence.append_witness, [])
                self.assertNotIn(SECRET, json.dumps(evidence.append_witness))

    def test_append_witness_accepts_null_previous_index_and_bounded_overflow(self) -> None:
        scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=heal class=quorum_unavailable\n"
        )
        payload = _append_witness_payload()
        payload["observations"][0].update(
            prev_index=None,
            term=runner._MAX_DIAGNOSTIC_TERM,
            first_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
            last_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
            decoded=runner._MAX_APPEND_COUNT,
            handled=runner._MAX_APPEND_COUNT,
            write_ok=runner._MAX_APPEND_COUNT,
            overflow=True,
        )
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, scalar + _append_witness_frame(payload)
        )
        self.assertTrue(evidence.diagnostics_valid)
        self.assertEqual(len(evidence.append_witness), 1)
        observation = evidence.append_witness[0]["observations"][0]
        self.assertIsNone(observation["prev_index"])
        self.assertTrue(observation["overflow"])
        self.assertEqual(observation["decoded"], runner._MAX_APPEND_COUNT)

    def test_append_witness_sticky_overflow_survives_later_in_range_event(self) -> None:
        scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} phase=heal class=quorum_unavailable\n"
        )
        before = _append_witness_payload(
            [
                _append_observation(
                    decoded=1,
                    handled=1,
                    write_ok=1,
                    term=6,
                    prev_index=18,
                    first_index=19,
                    last_index=19,
                    entry_count=1,
                )
            ]
        )
        capped = _append_witness_payload(
            [
                _append_observation(
                    decoded=runner._MAX_APPEND_COUNT,
                    handled=runner._MAX_APPEND_COUNT,
                    write_ok=runner._MAX_APPEND_COUNT,
                    term=runner._MAX_DIAGNOSTIC_TERM,
                    prev_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
                    first_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
                    last_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
                    entry_count=runner._MAX_APPEND_ENTRIES,
                    overflow=True,
                )
            ]
        )
        after = _append_witness_payload(
            [
                _append_observation(
                    decoded=2,
                    handled=2,
                    write_ok=2,
                    term=7,
                    prev_index=19,
                    first_index=20,
                    last_index=20,
                    entry_count=1,
                    overflow=True,
                )
            ]
        )
        for label, payload in (("before", before), ("capped", capped), ("after", after)):
            with self.subTest(label=label):
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, scalar + _append_witness_frame(payload)
                )
                self.assertTrue(evidence.diagnostics_valid)
                self.assertEqual(len(evidence.append_witness), 1)
                self.assertEqual(
                    evidence.append_witness[0]["observations"],
                    payload["observations"],
                )
                self.assertNotIn(SECRET, json.dumps(evidence.append_witness))

    def test_quorum_diagnostic_accepts_bounded_overflow(self) -> None:
        payload = _diagnostic_payload()
        payload.update(
            case=CASE_DRAIN,
            phase="heal",
            operation="read_view",
            cause="read_outer_deadline",
        )
        payload["elapsed_ms"] = runner._MAX_DIAGNOSTIC_ELAPSED_MS
        payload["elapsed_overflow"] = True
        payload["snapshots"][0]["nodes"][0].update(
            term=runner._MAX_DIAGNOSTIC_TERM,
            millis_since_quorum_ack=runner._MAX_DIAGNOSTIC_MILLIS,
            numeric_overflow=True,
        )
        scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} "
            "phase=heal class=quorum_unavailable\n"
        )
        evidence = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT, scalar + _diagnostic_frame(payload)
        )
        self.assertTrue(evidence.diagnostics_valid)
        self.assertEqual(len(evidence.quorum_diagnostics), 1)
        safe = evidence.quorum_diagnostics[0]
        self.assertTrue(safe["elapsed_overflow"])
        self.assertTrue(safe["snapshots"][0]["nodes"][0]["numeric_overflow"])

    def test_quorum_diagnostic_v2_keeps_null_map_and_none_matching_distinct(self) -> None:
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame()
        )
        self.assertTrue(evidence.diagnostics_valid)
        self.assertEqual(len(evidence.quorum_diagnostics), 1)
        safe = evidence.quorum_diagnostics[0]
        self.assertEqual(safe["schema"], runner._DIAGNOSTIC_SCHEMA_V2)
        self.assertEqual(set(safe), runner._DIAGNOSTIC_TOP_KEYS)
        nodes = safe["snapshots"][0]["nodes"]
        self.assertEqual([node["slot"] for node in nodes], [1, 2, 3])
        for node in nodes:
            self.assertEqual(set(node), runner._DIAGNOSTIC_NODE_KEYS_V2)
        leader_matching = nodes[0]["replication_matching"]
        self.assertEqual([entry["slot"] for entry in leader_matching], [1, 2, 3])
        self.assertEqual(
            leader_matching[0],
            {
                "slot": 1,
                "matched_index": 42,
                "matched_term": 7,
                "matched_leader_slot": "slot1",
            },
        )
        self.assertEqual(
            leader_matching[2],
            {
                "slot": 3,
                "matched_index": None,
                "matched_term": None,
                "matched_leader_slot": None,
            },
        )
        self.assertTrue(
            all(set(entry) == runner._DIAGNOSTIC_MATCHING_KEYS for entry in leader_matching)
        )
        self.assertIsNone(nodes[1]["replication_matching"])
        self.assertIsNone(nodes[2]["replication_matching"])
        self.assertNotIn("7-42", json.dumps(safe))

    def test_quorum_diagnostic_v1_and_v2_are_separated(self) -> None:
        legacy = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame()
        )
        self.assertTrue(legacy.diagnostics_valid)
        legacy_safe = legacy.quorum_diagnostics[0]
        self.assertEqual(legacy_safe["schema"], runner._DIAGNOSTIC_SCHEMA_V1)
        for node in legacy_safe["snapshots"][0]["nodes"]:
            self.assertEqual(set(node), runner._DIAGNOSTIC_NODE_KEYS_V1)
            self.assertNotIn("replication_matching", node)

        injected_v1 = _diagnostic_payload()
        for node in injected_v1["snapshots"][0]["nodes"]:
            node["replication_matching"] = None
        injected = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(injected_v1)
        )
        self.assertFalse(injected.diagnostics_valid)
        self.assertEqual(injected.quorum_diagnostics, [])

        current = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame()
        )
        self.assertTrue(current.diagnostics_valid)
        self.assertEqual(current.quorum_diagnostics[0]["schema"], runner._DIAGNOSTIC_SCHEMA_V2)

        v2_with_v1_schema = _diagnostic_v2_payload()
        v2_with_v1_schema["schema"] = runner._DIAGNOSTIC_SCHEMA_V1
        mismatch = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame(v2_with_v1_schema)
        )
        self.assertFalse(mismatch.diagnostics_valid)
        self.assertEqual(mismatch.quorum_diagnostics, [])

        v1_with_v2_schema = _diagnostic_payload()
        v1_with_v2_schema["schema"] = runner._DIAGNOSTIC_SCHEMA_V2
        mismatch = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(v1_with_v2_schema)
        )
        self.assertFalse(mismatch.diagnostics_valid)
        self.assertEqual(mismatch.quorum_diagnostics, [])

        v2_prefix_with_v1_body = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame(_diagnostic_payload())
        )
        self.assertFalse(v2_prefix_with_v1_body.diagnostics_valid)
        self.assertEqual(v2_prefix_with_v1_body.quorum_diagnostics, [])

        v1_prefix_with_v2_body = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(_diagnostic_v2_payload())
        )
        self.assertFalse(v1_prefix_with_v2_body.diagnostics_valid)
        self.assertEqual(v1_prefix_with_v2_body.quorum_diagnostics, [])

    def test_quorum_diagnostic_v2_preserves_historical_matching_proposer(self) -> None:
        payload = _diagnostic_v2_payload()
        leader_node = payload["snapshots"][0]["nodes"][0]
        leader_node["replication_matching"][1].update(
            matched_index=41,
            matched_term=6,
            matched_leader_slot="slot2",
        )
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame(payload)
        )
        self.assertTrue(evidence.diagnostics_valid)
        safe_node = evidence.quorum_diagnostics[0]["snapshots"][0]["nodes"][0]
        self.assertEqual(safe_node["leader_slot"], "slot1")
        self.assertEqual(safe_node["term"], 7)
        self.assertEqual(
            safe_node["replication_matching"][1],
            {
                "slot": 2,
                "matched_index": 41,
                "matched_term": 6,
                "matched_leader_slot": "slot2",
            },
        )

    def test_quorum_diagnostic_v2_rejects_malformed_matching_shapes(self) -> None:
        cases = []

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"] = (
            payload["snapshots"][0]["nodes"][0]["replication_matching"][:2]
        )
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        matching = payload["snapshots"][0]["nodes"][0]["replication_matching"]
        payload["snapshots"][0]["nodes"][0]["replication_matching"] = matching + [matching[2]]
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        matching = payload["snapshots"][0]["nodes"][0]["replication_matching"]
        payload["snapshots"][0]["nodes"][0]["replication_matching"] = [
            matching[0],
            copy.deepcopy(matching[0]),
            matching[2],
        ]
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][2]["slot"] = 4
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        matching = payload["snapshots"][0]["nodes"][0]["replication_matching"]
        payload["snapshots"][0]["nodes"][0]["replication_matching"] = [
            matching[1],
            matching[0],
            matching[2],
        ]
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["log_id"] = "7-42"
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        del payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_term"]
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_index"] = True
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_term"] = True
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_index"] = -1
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_index"] = (
            runner._MAX_DIAGNOSTIC_LOG_INDEX + 1
        )
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_term"] = (
            runner._MAX_DIAGNOSTIC_TERM + 1
        )
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_index"] = None
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_term"] = None
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_leader_slot"] = None
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_leader_slot"] = "slot4"
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        del payload["snapshots"][0]["nodes"][0]["replication_matching"]
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["replication_matching"] = {}
        cases.append(payload)

        payload = _diagnostic_v2_payload()
        payload["snapshots"][0]["nodes"][0]["numeric_overflow"] = True
        cases.append(payload)

        for payload in cases:
            with self.subTest(payload=payload):
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame(payload)
                )
                self.assertFalse(evidence.diagnostics_valid)
                self.assertEqual(evidence.quorum_diagnostics, [])
                self.assertNotIn("7-42", json.dumps(evidence.quorum_diagnostics))
                self.assertNotIn(SECRET, json.dumps(evidence.quorum_diagnostics))

        oversized = _diagnostic_v2_frame().replace(",", "," + " " * 300)
        too_large = runner.collect_failure_evidence(NONZERO_FAILED_OUTPUT, oversized)
        self.assertFalse(too_large.diagnostics_valid)
        self.assertEqual(too_large.quorum_diagnostics, [])

        duplicate_field = _diagnostic_v2_frame().replace(
            '"matched_term":7', '"matched_term":7,"matched_term":7', 1
        )
        duplicated = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, duplicate_field
        )
        self.assertFalse(duplicated.diagnostics_valid)
        self.assertEqual(duplicated.quorum_diagnostics, [])

    def test_quorum_diagnostic_v2_accepts_bounded_matching_overflow(self) -> None:
        payload = _diagnostic_v2_payload()
        node = payload["snapshots"][0]["nodes"][0]
        node["numeric_overflow"] = True
        node["replication_matching"][0].update(
            matched_index=runner._MAX_DIAGNOSTIC_LOG_INDEX,
            matched_term=runner._MAX_DIAGNOSTIC_TERM,
        )
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_v2_frame(payload)
        )
        self.assertTrue(evidence.diagnostics_valid)
        safe = evidence.quorum_diagnostics[0]
        self.assertTrue(safe["snapshots"][0]["nodes"][0]["numeric_overflow"])
        self.assertEqual(
            safe["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_index"],
            runner._MAX_DIAGNOSTIC_LOG_INDEX,
        )
        self.assertEqual(
            safe["snapshots"][0]["nodes"][0]["replication_matching"][0]["matched_term"],
            runner._MAX_DIAGNOSTIC_TERM,
        )

    def test_quorum_diagnostic_rejects_cross_case_phases_and_scope_conflicts(self) -> None:
        scope_payload = _diagnostic_payload()
        scope_payload.update(case=CASE_DRAIN, phase="recovery_rejections", operation="prepare", cause="read_quorum_shortfall")
        scope_frame = _diagnostic_frame(scope_payload)
        scope_scalar = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} "
            "phase=recovery_rejections class=quorum_unavailable\n"
        )

        wrong_scope_phase = _diagnostic_payload()
        wrong_scope_phase.update(
            case=CASE_DRAIN,
            phase="closing_write",
            operation="client_write",
            cause="write_forward",
        )
        evidence = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT, _diagnostic_frame(wrong_scope_phase)
        )
        self.assertFalse(evidence.diagnostics_valid)
        self.assertEqual(evidence.quorum_diagnostics, [])

        wrong_real_phase = _diagnostic_payload()
        wrong_real_phase.update(
            case=CASE_REAL,
            phase="recovery_rejections",
            operation="prepare",
            cause="read_quorum_shortfall",
        )
        evidence = runner.collect_failure_evidence(
            NONZERO_FAILED_OUTPUT, _diagnostic_frame(wrong_real_phase)
        )
        self.assertFalse(evidence.diagnostics_valid)
        self.assertEqual(evidence.quorum_diagnostics, [])

        pruned_payload = _diagnostic_payload()
        pruned_payload.update(case=CASE_PRUNED)
        pruned = runner.collect_failure_evidence(
            FAILED_OUTPUT, _diagnostic_frame(pruned_payload)
        )
        self.assertFalse(pruned.diagnostics_valid)
        self.assertEqual(pruned.quorum_diagnostics, [])

        duplicate = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT, scope_scalar + scope_frame + scope_frame
        )
        self.assertFalse(duplicate.diagnostics_valid)
        self.assertEqual(duplicate.quorum_diagnostics, [])

        conflict_payload = _diagnostic_payload()
        conflict_payload.update(
            case=CASE_DRAIN, phase="heal", operation="read_view", cause="read_outer_deadline"
        )
        conflict = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT,
            scope_scalar + scope_frame + _diagnostic_frame(conflict_payload),
        )
        self.assertFalse(conflict.diagnostics_valid)
        self.assertEqual(conflict.quorum_diagnostics, [])

        mismatched_terminal = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_DRAIN} "
            "phase=heal class=quorum_unavailable\n"
        )
        mismatched = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT, mismatched_terminal + scope_frame
        )
        self.assertFalse(mismatched.diagnostics_valid)
        self.assertEqual(mismatched.quorum_diagnostics, [])

    def test_quorum_diagnostic_rejects_nonfinite_and_scope_unknown_fields(self) -> None:
        for nonfinite in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(nonfinite=nonfinite):
                payload = _diagnostic_payload()
                payload["elapsed_ms"] = nonfinite
                evidence = runner.collect_failure_evidence(
                    NONZERO_FAILED_OUTPUT, _diagnostic_frame(payload)
                )
                self.assertFalse(evidence.diagnostics_valid)
                self.assertEqual(evidence.quorum_diagnostics, [])

        payload = _diagnostic_payload()
        payload.update(case=CASE_DRAIN, phase="recovery_rejections")
        payload["secret"] = SECRET
        evidence = runner.collect_failure_evidence(
            SCOPE_FAILED_OUTPUT, _diagnostic_frame(payload)
        )
        self.assertFalse(evidence.diagnostics_valid)
        self.assertEqual(evidence.quorum_diagnostics, [])
        self.assertNotIn(SECRET, json.dumps(evidence.quorum_diagnostics))

    def test_main_retains_partial_evidence_on_nonzero_without_passing(self) -> None:
        path = self.root / "out" / "nonzero-report.json"
        output = NONZERO_FAILED_OUTPUT
        stderr = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=commit class=proposal_scope\n"
        )

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(output, stderr, 101, None, "exited")

        with self._cli_anchor_environment(), \
             mock.patch.object(runner, "require_source_state", return_value=self.head), \
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
            "quorum_diagnostics": [],
            "append_witness": [],
        })
        serialized = json.dumps(report)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_main_failed_report_includes_safe_quorum_diagnostic(self) -> None:
        path = self.root / "out" / "quorum-diagnostic-report.json"
        output = NONZERO_FAILED_OUTPUT
        stderr = (
            f"ROOTYARD_FAILURE_FRAME v1 case={CASE_REAL} "
            "phase=semantic_input_write class=quorum_unavailable\n"
            + _diagnostic_frame()
        )

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(output, stderr, 101, None, "exited")

        with self._cli_anchor_environment(), \
             mock.patch.object(runner, "require_source_state", return_value=self.head), \
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
        self.assertTrue(report["diagnostics"]["diagnostics_valid"])
        self.assertEqual(
            report["diagnostics"]["case_failures"],
            [{"case": CASE_REAL, "phase": "semantic_input_write", "class": "quorum_unavailable"}],
        )
        quorum = report["diagnostics"]["quorum_diagnostics"]
        self.assertEqual(len(quorum), 1)
        self.assertEqual(quorum[0]["case"], CASE_REAL)
        self.assertEqual(quorum[0]["phase"], "semantic_input_write")
        self.assertEqual(quorum[0]["operation"], "client_write")
        self.assertEqual(quorum[0]["cause"], "write_forward")
        self.assertEqual(len(quorum[0]["snapshots"]), 2)
        self.assertEqual(
            [node["slot"] for node in quorum[0]["snapshots"][0]["nodes"]], [1, 2, 3]
        )
        serialized = json.dumps(report)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_main_nonzero_with_passing_suite_still_fails(self) -> None:
        path = self.root / "out" / "nonzero-passing-report.json"

        def fake_execute(*_args, **_kwargs):
            return runner.ExecutionResult(GOOD_OUTPUT, "", 101, None, "exited")

        with self._cli_anchor_environment(), \
             mock.patch.object(runner, "require_source_state", return_value=self.head), \
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

        with self._cli_anchor_environment(), \
             mock.patch.object(runner, "require_source_state", return_value=self.head), \
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

                with self._cli_anchor_environment(), \
                     mock.patch.object(runner, "require_source_state", return_value=self.head), \
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

        with self._cli_anchor_environment(), \
             mock.patch.object(runner, "require_source_state", return_value=self.head), \
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
            "quorum_diagnostics": [],
            "append_witness": [],
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
