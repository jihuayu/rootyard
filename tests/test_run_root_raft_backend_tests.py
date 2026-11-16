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
import json
from pathlib import Path
import subprocess
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
            return subprocess.CompletedProcess(command, 0, GOOD_OUTPUT, SECRET)

        self.assertEqual(runner.execute_case(self.binary, 900.0, run=fake_run), GOOD_OUTPUT)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], [str(self.binary), "--test-threads=1"])
        self.assertEqual(calls[0][1]["timeout"], 900.0)
        self.assertIs(calls[0][1]["text"], True)
        self.assertNotIn("--", calls[0][0])

    def test_execute_refuses_nonzero_signal_timeout_and_spawn_failure(self) -> None:
        def result(code):
            def run(command, **_kwargs):
                return subprocess.CompletedProcess(command, code, "", SECRET)
            return run

        for code, expected in ((101, "nonzero_exit"), (-9, "signal_killed")):
            with self.subTest(code=code):
                self.assert_code(
                    expected, runner.execute_case, self.binary, 900.0, run=result(code)
                )

        def timed_out(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=SECRET)

        def spawn_failed(_command, **_kwargs):
            raise OSError("spawn refused")

        self.assert_code(
            "timeout", runner.execute_case, self.binary, 900.0, run=timed_out
        )
        self.assert_code(
            "spawn_failed",
            runner.execute_case,
            self.binary,
            900.0,
            run=spawn_failed,
        )

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
