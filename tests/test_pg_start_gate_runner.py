#!/usr/bin/env python3
"""Offline regression for the dedicated PostgreSQL start-gate runner.

The real case needs Linux, PostgreSQL and a native Rust test binary, so these
tests use a relocated shell stub with libtest-shaped output and a synthetic
``rust-library-test`` receipt.  They exercise the real receipt validator, the
direct (no Cargo separator) invocation, zero-test/ignored/case-identity
refusals, missing DB URL, tamper/stale/source drift, immutable before/after
checks, and failure-output privacy.  The final test feeds a successful report
into the existing ``native_report_manifest.py --mode job`` gate to prove the
separate test-binary manifest shape.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_build_receipt as receipts  # noqa: E402
import run_pg_start_gate as gate  # noqa: E402

CASE = gate.CASE
OK_OUTPUT = """running 1 test
test sandbox::runner::tests::start_gate_serializes_context_removal_under_policy_fence ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
ZERO_OUTPUT = """running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
IGNORED_OUTPUT = """running 1 test
test sandbox::runner::tests::start_gate_serializes_context_removal_under_policy_fence ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
WRONG_CASE_OUTPUT = """running 1 test
test sandbox::runner::tests::some_other_case ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
FAIL_OUTPUT = """running 1 test
test sandbox::runner::tests::start_gate_serializes_context_removal_under_policy_fence ... FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
SECRET = "postgresql://fixture-user:fixture-password@127.0.0.1:55432/rootyard_test"


class GateRunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        for relative, content in (
            ("Cargo.toml", '[package]\nname = "rootyard"\n'),
            ("Cargo.lock", "lock\n"),
            ("build.rs", "fn main() {}\n"),
            ("src/lib.rs", "pub fn gate() {}\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
            ("experimental/pando/schema.sql", "create table pando_gate();\n"),
            ("tests/fixtures/gate.txt", "support\n"),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.lock_digest = hashlib.sha256(b"lock\n").hexdigest()
        self.v2_bound = None
        self.head = "a" * 40
        self.source = "b" * 64
        self.support = "c" * 64
        self.database_url = SECRET
        self.binary = self.root / "relocated" / "rootyard-lib-tests"
        self.binary.parent.mkdir()
        self.receipt = self.binary.with_suffix(".build.json")
        self.report = self.root / "pg-start-gate.json"
        self.argv_log = self.root / "argv.log"
        self.write_binary()
        self.write_receipt()

    def tearDown(self):
        self.tmp.cleanup()

    def binary_digest(self):
        return hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def write_binary(self, output=OK_OUTPUT, exit_code=0, stderr="", mutate_receipt=False):
        script = "#!/bin/sh\n"
        script += "printf '%s\\n' \"$@\" > \"$ARGV_LOG\"\n"
        if mutate_receipt:
            script += "printf '\\n' >> \"$RECEIPT_PATH\"\n"
        script += "cat <<'OUT'\n" + output + "OUT\n"
        if stderr:
            script += "printf '%s\\n' " + shlex.quote(stderr) + " >&2\n"
        script += f"exit {exit_code}\n"
        self.binary.write_text(script)
        self.binary.chmod(0o755)
        if self.receipt.exists():
            # Keep a synthetic receipt valid when a test replaces the stub.
            self.write_receipt()

    def write_receipt(self, **overrides):
        data = {
            "kind": "rust-library-test",
            "relocated_artifact": True,
            "package_rebuilt": True,
            "fresh": False,
            "source_inputs_sha256": self.source,
            "lib_test_support_inputs_sha256": self.support,
            "cargo_lock_sha256": self.lock_digest,
            "binary_sha256": self.binary_digest(),
            "original_artifact_sha256": self.binary_digest(),
            "workspace_commit": self.head,
            "command": [
                "cargo",
                "--config",
                "profile.dev.package.rootyard.debug=0",
                "--config",
                "profile.test.package.rootyard.debug=0",
                "--config",
                'profile.dev.package.rootyard.strip="debuginfo"',
                "--config",
                'profile.test.package.rootyard.strip="debuginfo"',
                "test",
                "--locked",
                "--features",
                "pando-lab",
                "--lib",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ],
            "rustc": "rustc 1.99.1 (test)",
            "fresh_false_artifacts": [
                {
                    "target": "rootyard",
                    "kind": "lib-test",
                    "fresh": False,
                    "executable": "/tmp/original-rootyard-lib-tests",
                }
            ],
        }
        data.update(overrides)
        self.receipt.write_text(json.dumps(data, indent=2) + "\n")

    def write_v2_toolchain(self):
        toolchain_dir = self.root / "toolchain"
        toolchain_dir.mkdir(exist_ok=True)
        for name in ("cargo", "rustc", "rustup"):
            (toolchain_dir / name).write_bytes(("fake-" + name).encode())

        def identity(name, release, commit_hash):
            executable = toolchain_dir / name
            return {
                "executable": str(executable),
                "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "version": f"{name} {release} (fixture 2026-01-01)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": "aarch64-unknown-linux-gnu",
            }

        return {
            "cargo": identity("cargo", "1.101.0", gate.CARGO_FORK_COMMIT),
            "rustc": dict(
                identity("rustc", "1.99.1", "d" * 40),
                path_entry=str(toolchain_dir / "rustc"),
                proxy=False,
            ),
            "rustup": {
                "executable": str(toolchain_dir / "rustup"),
                "executable_sha256": hashlib.sha256(
                    (toolchain_dir / "rustup").read_bytes()
                ).hexdigest(),
                "resolved_rustc": str(toolchain_dir / "rustc"),
                "resolved_rustc_sha256": hashlib.sha256(
                    (toolchain_dir / "rustc").read_bytes()
                ).hexdigest(),
            },
            "target_triple": "aarch64-unknown-linux-gnu",
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def write_v2_receipt(self, fresh=False, lib_fresh=None):
        self.write_v2_toolchain()
        bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        self.v2_bound = bound

        def artifact(kind, source, executable, artifact_fresh):
            event = {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {
                    "name": "rootyard",
                    "kind": ["lib"],
                    "src_path": str(source),
                },
                "profile": {
                    "opt_level": "0",
                    "debuginfo": 2,
                    "debug_assertions": True,
                    "overflow_checks": True,
                    "test": kind == "lib-test",
                },
                "fresh": artifact_fresh,
            }
            if executable is not None:
                event["executable"] = str(executable)
            return receipts.cargo_artifact_record(event, self.root, kind=kind)

        artifacts = [
            artifact("lib-test", self.root / "src/lib.rs", self.binary, fresh)
        ]
        if lib_fresh is not None:
            artifacts.insert(
                0,
                artifact("lib", self.root / "src/lib.rs", None, lib_fresh),
            )
        support = hashlib.sha256()
        for entry in sorted(
            (item for item in bound["bound_input_inventory"]
             if item["role"] == "test_support" and item["present"]),
            key=lambda item: item["path"],
        ):
            support.update(entry["path"].encode() + b"\0")
            support.update(bytes.fromhex(entry["sha256"]))
        payload = receipts.make_receipt_v2(
            binary_path=self.binary,
            command=[
                "cargo",
                "test",
                "--locked",
                "--features",
                "pando-lab",
                "--lib",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ],
            profile="test",
            artifacts=artifacts,
            toolchain=self.write_v2_toolchain(),
            bound_inputs=bound,
            workspace_commit=self.head,
            target_dir=self.root / "target",
            features="pando-lab",
            extra={
                "kind": "rust-library-test",
                "relocated_artifact": True,
                "original_artifact_sha256": self.binary_digest(),
                "lib_test_support_inputs_sha256": support.hexdigest(),
            },
        )
        self.receipt.write_text(json.dumps(payload, indent=2) + "\n")
        return payload

    def run_gate(self, extra=None, env=None, source=None, support=None):
        argv = [
            "--test-binary",
            str(self.binary),
            "--build-receipt",
            str(self.receipt),
            "--report",
            str(self.report),
            "--expected-commit",
            self.head,
            "--timeout",
            "5",
        ]
        argv.extend(extra or [])
        stdout = io.StringIO()
        stderr = io.StringIO()
        environment = {
            "ROOTYARD_TEST_DATABASE_URL": self.database_url,
            "ARGV_LOG": str(self.argv_log),
            "RECEIPT_PATH": str(self.receipt),
        }
        if env is not None:
            environment.update(env)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "ROOT", self.root))
            stack.enter_context(
                mock.patch.object(
                gate, "git_state", return_value={"head": self.head, "status": "", "clean": True}
            )
            )
            stack.enter_context(
                mock.patch.object(
                    gate, "source_digest",
                    return_value=self.source if source is None else source,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate, "lib_test_support_digest",
                    return_value=self.support if support is None else support,
                )
            )
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=False))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = gate.main(argv)
        report = (
            json.loads(self.report.read_text()) if self.report.exists() else None
        )
        return code, stdout.getvalue(), stderr.getvalue(), report

    def argv_lines(self):
        if not self.argv_log.exists():
            return None
        return [line for line in self.argv_log.read_text().splitlines() if line]

    def assert_report_has_no_secret(self, report, stdout="", stderr=""):
        serialized = json.dumps(report)
        self.assertNotIn(self.database_url, serialized)
        self.assertNotIn(self.database_url, stdout)
        self.assertNotIn(self.database_url, stderr)

    def test_valid_receipt_executes_direct_exact_ignored_case(self):
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["cases"], [{"name": CASE, "status": "passed"}])
        self.assertEqual(report["failure"], None)
        self.assertEqual(report["test"]["passed"], 1)
        self.assertEqual(report["test"]["failed"], 0)
        self.assertEqual(report["test"]["ignored"], 0)
        self.assertEqual(
            report["test"]["argv"],
            [str(self.binary.resolve()), "--exact", CASE, "--ignored", "--test-threads=1"],
        )
        self.assertNotIn("--", report["test"]["argv"])
        self.assertEqual(
            self.argv_lines(), ["--exact", CASE, "--ignored", "--test-threads=1"]
        )
        self.assertEqual(report["binary_sha256"], self.binary_digest())
        self.assertEqual(report["source_head"], self.head)
        self.assertEqual(report["receipt_workspace_commit"], self.head)
        self.assertEqual(report["receipt"]["kind"], "rust-library-test")
        self.assertEqual(
            report["receipt"]["fresh_false_artifacts"],
            [{"target": "rootyard", "kind": "lib-test", "fresh": False}],
        )
        self.assertTrue(all(report["immutable"].values()))
        self.assertEqual(report["start"], report["end"])
        self.assert_report_has_no_secret(report, stdout, stderr)

    def test_runner_reads_only_the_shared_receipt_contract(self):
        source = Path(gate.__file__).read_text(encoding="utf-8")
        self.assertIn("import native_build_receipt", source)
        self.assertNotIn("import build_native\n", source)
        self.assertNotIn("from build_native", source)
        self.assertNotIn("from build_native_test", source)
        self.assertNotIn("import build_native_test", source)

    def test_missing_database_url_is_refused_before_the_binary_runs(self):
        code, stdout, stderr, report = self.run_gate(
            env={"ROOTYARD_TEST_DATABASE_URL": ""}
        )

        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(
            report["failure"],
            {"stage": "environment", "code": "missing_database_url"},
        )
        self.assertEqual(report["cases"][0]["status"], "failed")
        self.assertEqual(report["receipt_workspace_commit"], self.head)
        self.assertEqual(report["binary_sha256"], self.binary_digest())
        self.assertIsNotNone(report["start"])
        self.assertIsNone(self.argv_lines())
        self.assert_report_has_no_secret(report, stdout, stderr)

    def test_tampered_binary_digest_is_refused(self):
        self.write_receipt(binary_sha256="0" * 64)
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 1)
        self.assertEqual(
            report["failure"], {"stage": "receipt", "code": "binary_mismatch"}
        )
        self.assertIsNone(self.argv_lines())
        self.assert_report_has_no_secret(report, stdout, stderr)

    def test_stale_receipt_commit_is_refused(self):
        self.write_receipt(workspace_commit="d" * 40)
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 1)
        self.assertEqual(
            report["failure"], {"stage": "receipt", "code": "stale_receipt"}
        )
        self.assertIsNone(self.argv_lines())

    def test_source_support_and_lock_drift_are_refused(self):
        changes = (
            ({"source_inputs_sha256": "d" * 64}, "source_drift"),
            ({"lib_test_support_inputs_sha256": "d" * 64}, "support_drift"),
            ({"cargo_lock_sha256": "d" * 64}, "cargo_lock_drift"),
        )
        for change, code in changes:
            with self.subTest(code=code):
                self.write_receipt(**change)
                code_value, stdout, stderr, report = self.run_gate()
                self.assertEqual(code_value, 1)
                self.assertEqual(
                    report["failure"], {"stage": "source", "code": code}
                )
                self.assertIsNone(self.argv_lines())

    def test_receipt_shape_refusals_are_typed_and_safe(self):
        changes = (
            ({"kind": "rust-integration-test"}, "receipt_kind"),
            ({"relocated_artifact": False}, "receipt_not_relocated"),
            ({"package_rebuilt": False}, "receipt_not_rebuilt"),
            ({"fresh_false_artifacts": []}, "receipt_fresh_artifact"),
            (
                {
                    "fresh_false_artifacts": [
                        {"target": "other", "kind": "lib-test", "fresh": False}
                    ]
                },
                "receipt_fresh_artifact",
            ),
            ({"command": ["cargo", "test", "--no-run"]}, "receipt_command"),
            ({"rustc": ""}, "receipt_invalid"),
        )
        for change, code in changes:
            with self.subTest(code=code):
                self.write_receipt(**change)
                code_value, stdout, stderr, report = self.run_gate()
                self.assertEqual(code_value, 1)
                self.assertEqual(
                    report["failure"], {"stage": "receipt", "code": code}
                )
                self.assertIsNone(self.argv_lines())
                self.assert_report_has_no_secret(report, stdout, stderr)

    def test_exit_zero_with_zero_tests_is_refused(self):
        self.write_binary(output=ZERO_OUTPUT)
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 1)
        self.assertEqual(report["failure"], {"stage": "parse", "code": "zero_tests"})
        self.assertEqual(self.argv_lines(), ["--exact", CASE, "--ignored", "--test-threads=1"])
        self.assertNotIn("running 0", json.dumps(report))

    def test_ignored_and_wrong_case_outputs_are_refused(self):
        cases = (
            (IGNORED_OUTPUT, "ignored_tests"),
            (WRONG_CASE_OUTPUT, "case_identity"),
        )
        for output, code in cases:
            with self.subTest(code=code):
                self.write_binary(output=output)
                code_value, stdout, stderr, report = self.run_gate()
                self.assertEqual(code_value, 1)
                self.assertEqual(
                    report["failure"], {"stage": "parse", "code": code}
                )

    def test_failing_case_output_is_never_published(self):
        self.write_binary(output=FAIL_OUTPUT, exit_code=101, stderr=SECRET)
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 1)
        self.assertEqual(
            report["failure"], {"stage": "execute", "code": "test_failed"}
        )
        serialized = json.dumps(report)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn(SECRET, stdout)
        self.assertNotIn(SECRET, stderr)
        self.assertNotIn("test result", serialized)
        self.assertNotIn("FAILED", serialized)

    def test_immutable_receipt_change_after_execution_is_refused(self):
        self.write_binary(mutate_receipt=True)
        code, stdout, stderr, report = self.run_gate()

        self.assertEqual(code, 1)
        self.assertEqual(
            report["failure"], {"stage": "immutable", "code": "immutable_drift"}
        )
        self.assertEqual(report["test"]["passed"], 1)
        self.assert_report_has_no_secret(report, stdout, stderr)

    def test_report_is_accepted_by_an_independent_job_manifest(self):
        code, stdout, stderr, report = self.run_gate()
        self.assertEqual(code, 0)

        manifest = self.root / "native-pg-start-gate.json"
        command = [
            sys.executable,
            str(ROOT / "scripts/native_report_manifest.py"),
            "--mode",
            "job",
            "--manifest-out",
            str(manifest),
            "--build-receipt",
            str(self.receipt),
            "--binary",
            str(self.binary),
            "--expect-commit",
            self.head,
            "--report",
            f"pg_start_gate={self.report}",
            "--require-case",
            f"pg_start_gate={CASE}",
            "--harness",
            str(ROOT / "scripts/run_pg_start_gate.py"),
            "--harness",
            str(ROOT / "src/sandbox/runner.rs"),
        ]
        process = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(manifest.read_text())
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["binary_sha256"], report["binary_sha256"])
        self.assertEqual(data["source_commit"], self.head)
        self.assertEqual(data["reports"]["pg_start_gate"]["case_names"], [CASE])



    def test_v2_receipt_executes_and_records_actual_true_false_and_mixed(self):
        bound = self.write_v2_receipt(fresh=False)
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"],
            support=report_support(bound),
        )
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["receipt_schema"], "v2")
        self.assertEqual(report["source_inputs_sha256"], bound["source_inputs_sha256"])
        self.assertEqual(
            report["receipt_source_inputs_sha256"], bound["source_inputs_sha256"]
        )
        self.assertFalse(report["receipt"]["fresh"])
        self.assertEqual(report["receipt"]["cargo_artifacts"][0]["fresh"], False)
        self.assertEqual(
            report["receipt"]["toolchain"]["cargo"]["commit_hash"],
            gate.CARGO_FORK_COMMIT,
        )

        bound = self.write_v2_receipt(fresh=True)
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"],
            support=report_support(bound),
        )
        self.assertEqual(code, 0)
        self.assertTrue(report["receipt"]["fresh"])
        self.assertEqual(report["receipt"]["cargo_artifacts"][0]["fresh"], True)

        bound = self.write_v2_receipt(fresh=True, lib_fresh=False)
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"],
            support=report_support(bound),
        )
        self.assertEqual(code, 0)
        self.assertEqual(report["receipt"]["fresh"], "mixed")
        self.assertEqual(
            [row["fresh"] for row in report["receipt"]["cargo_artifacts"]],
            [False, True],
        )
        self.assert_report_has_no_secret(report, stdout, stderr)

    def test_v2_identity_refusals_are_typed_and_safe(self):
        cases = (
            ("kind", lambda payload: payload.__setitem__("kind", "rust-integration-test"), "receipt_kind"),
            (
                "target",
                lambda payload: payload["cargo_artifacts"][0].__setitem__("target", "other"),
                "receipt_invalid",
            ),
            (
                "source",
                lambda payload: payload["cargo_artifacts"][0].__setitem__(
                    "source", "src/main.rs"
                ),
                "receipt_invalid",
            ),
            (
                "toolchain",
                lambda payload: payload["toolchain"]["cargo"].__setitem__(
                    "commit_hash", "e" * 40
                ),
                "receipt_invalid",
            ),
            (
                "features",
                lambda payload: payload["features"].__setitem__("enabled", []),
                "receipt_invalid",
            ),
            (
                "profile",
                lambda payload: payload.__setitem__("profile", "dev"),
                "receipt_invalid",
            ),
            (
                "freshness",
                lambda payload: payload["cargo_artifacts"][0].__setitem__(
                    "fresh", "true"
                ),
                "receipt_invalid",
            ),
        )
        for name, mutate, code_name in cases:
            with self.subTest(name=name):
                payload = self.write_v2_receipt(fresh=False)
                mutate(payload)
                self.receipt.write_text(json.dumps(payload, indent=2) + "\n")
                code, stdout, stderr, report = self.run_gate(
                    source=payload["source_inputs_sha256"],
                    support=report_support(self.v2_bound),
                )
                self.assertEqual(code, 1)
                self.assertEqual(
                    report["failure"], {"stage": "receipt", "code": code_name}
                )
                self.assertIsNone(self.argv_lines())
                self.assert_report_has_no_secret(report, stdout, stderr)

    def test_v2_source_support_lock_and_config_drift_are_refused(self):
        bound = self.write_v2_receipt(fresh=False)
        code, stdout, stderr, report = self.run_gate(
            source="d" * 64, support=report_support(bound)
        )
        self.assertEqual(report["failure"], {"stage": "source", "code": "source_drift"})
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"], support="d" * 64
        )
        self.assertEqual(report["failure"], {"stage": "source", "code": "support_drift"})

        original = gate.sha256_file

        def fake_digest(path):
            if Path(path).name == "Cargo.lock":
                return "d" * 64
            return original(path)

        with mock.patch.object(gate, "sha256_file", side_effect=fake_digest):
            code, stdout, stderr, report = self.run_gate(
                source=bound["source_inputs_sha256"], support=report_support(bound)
            )
        self.assertEqual(
            report["failure"], {"stage": "source", "code": "cargo_lock_drift"}
        )

        (self.root / "src/lib.rs").write_text("pub fn changed() {}\n")
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"], support=report_support(bound)
        )
        self.assertEqual(report["failure"], {"stage": "source", "code": "source_drift"})

    def test_v2_report_is_accepted_by_an_independent_job_manifest(self):
        bound = self.write_v2_receipt(fresh=False)
        code, stdout, stderr, report = self.run_gate(
            source=bound["source_inputs_sha256"], support=report_support(bound)
        )
        self.assertEqual(code, 0)

        manifest = self.root / "native-pg-start-gate-v2.json"
        command = [
            sys.executable,
            str(ROOT / "scripts/native_report_manifest.py"),
            "--mode",
            "job",
            "--manifest-out",
            str(manifest),
            "--build-receipt",
            str(self.receipt),
            "--binary",
            str(self.binary),
            "--expect-commit",
            self.head,
            "--report",
            f"pg_start_gate={self.report}",
            "--require-case",
            f"pg_start_gate={CASE}",
            "--harness",
            str(ROOT / "scripts/run_pg_start_gate.py"),
            "--harness",
            str(ROOT / "scripts/native_build_receipt.py"),
        ]
        process = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(manifest.read_text())
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["build_receipt"]["receipt_schema"], "v2")


def report_support(bound):
    digest = hashlib.sha256()
    for entry in sorted(
        (
            item
            for item in bound["bound_input_inventory"]
            if item["role"] == "test_support" and item["present"]
        ),
        key=lambda item: item["path"],
    ):
        digest.update(entry["path"].encode() + b"\0")
        digest.update(bytes.fromhex(entry["sha256"]))
    return digest.hexdigest()


if __name__ == "__main__":
    unittest.main()
