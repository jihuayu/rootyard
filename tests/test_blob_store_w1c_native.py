#!/usr/bin/env python3
"""Focused contract tests for ``tests/blob_store_w1c_native.py`` and W1-C CI wiring."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TESTS = ROOT / "tests"
for entry in (str(SCRIPTS), str(TESTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import blob_store_w1c_native as w1c  # noqa: E402
import native_build_receipt as receipt_contract  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"
COMMIT = "a" * 40
LIST_OK = "\n".join(f"{name}: test" for name in w1c.EXPECTED_CASES) + "\n2 tests, 0 benchmarks\n"
RUN_OK = (
    "\nrunning 2 tests\n"
    f"test {w1c.EXPECTED_CASES[0]} ... ok\n"
    f"test {w1c.EXPECTED_CASES[1]} ... ok\n\n"
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s\n"
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _restore_writable_tree(root: Path) -> None:
    if not root.exists():
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        with contextlib.suppress(OSError):
            os.chmod(current, 0o700)
        for name in filenames:
            with contextlib.suppress(OSError):
                os.chmod(current / name, 0o700)


def _make_fake_process_runner(list_proc=None, run_proc=None, on_execute=None):
    """Build a deterministic stub for ``subprocess.run`` that never invokes binaries."""

    def fake_run(cmd, **kwargs):
        args = list(cmd[1:])
        if args == ["--ignored", "--list"]:
            if isinstance(list_proc, BaseException):
                raise list_proc
            return list_proc or subprocess.CompletedProcess(cmd, 0, LIST_OK, "")
        if args == ["--ignored", "--test-threads=1"]:
            if on_execute is not None:
                on_execute()
            if isinstance(run_proc, BaseException):
                raise run_proc
            return run_proc or subprocess.CompletedProcess(cmd, 0, RUN_OK, "")
        raise AssertionError(f"unexpected subprocess invocation: {cmd!r}")

    return fake_run


class W1CNativeFixture:
    """Self-contained synthetic repository, CAS snapshot, and v1/v2 receipts."""

    def __init__(self, tmp: Path):
        self.base = tmp
        self.root = tmp / "repo"
        self.store_root = tmp / "native-artifacts"
        self.out_dir = tmp / "out"
        self.report_dir = tmp / "report"
        self.root.mkdir(parents=True)
        self.store_root.mkdir(parents=True)
        self.out_dir.mkdir(parents=True)
        self.report_dir.mkdir(parents=True)

        for rel, body in (
            ("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.0"\n'),
            ("Cargo.lock", "# synthetic lock\nversion = 3\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
            ("experimental/pando/schema.sql", "-- synthetic schema\nCREATE SCHEMA IF NOT EXISTS pando_lab;\n"),
            ("src/lib.rs", "pub fn marker() -> u8 { 1 }\n"),
            ("tests/blob_store_w1c_contract.rs", "#[test]\nfn contract() {}\n"),
            ("tests/blob_store_w1c_native.py", "# harness\n"),
        ):
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")

        self.binary_bytes = b"#!/bin/sh\necho synthetic-w1c-binary\n"
        self.binary_sha = _sha256_bytes(self.binary_bytes)
        self.alias_bin = self.out_dir / w1c.TARGET_NAME
        self.alias_bin.write_bytes(self.binary_bytes)
        os.chmod(self.alias_bin, 0o555)
        self.alias_receipt = self.alias_bin.with_suffix(".build.json")
        self.build_report = self.out_dir / "build-report.json"

        self.target_dir = self.root / "target"
        self.target_dir.mkdir(parents=True)
        self.original_bin = (
            self.target_dir / "debug" / "deps" / f"{w1c.TARGET_NAME}-0123456789abcdef"
        )
        self.original_bin.parent.mkdir(parents=True)
        self.original_bin.write_bytes(self.binary_bytes)

        self.toolchain = self._make_toolchain()
        self.command = [
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
            w1c.TARGET_NAME,
            "--features",
            "pando-lab",
            "--no-default-features",
            "--message-format=json-render-diagnostics",
            "--jobs",
            "2",
        ]
        self.worktree_dirty = False
        self.env = {
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://rootyard@127.0.0.1:55432/rootyard_run_w1c_1_1",
            "DATABASE_URL": "postgresql://rootyard@127.0.0.1:55432/rootyard_run_w1c_1_1",
            "ROOTYARD_BLOB_DRIVER": "opendal",
            "ROOTYARD_BLOB_SERVICE": "s3",
            "ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:3900",
            "ROOTYARD_BLOB_BUCKET": "rootyard-test-bucket",
            "ROOTYARD_BLOB_REGION": "garage",
            "ROOTYARD_BLOB_ACCESS_KEY_ID": "GK_SYNTHETIC_KEY_1234",
            "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "SECRET_SYNTHETIC_VALUE_56789",
            "ROOTYARD_BLOB_ROOT": "w1c-pg-1-1",
        }

    def _make_toolchain(self) -> dict[str, object]:
        tdir = self.base / "toolchain"
        tdir.mkdir(parents=True, exist_ok=True)
        for tool in ("cargo", "rustc", "rustup"):
            (tdir / tool).write_bytes(f"fake-{tool}".encode())

        def identity(name: str, release: str, commit_hash: str) -> dict[str, object]:
            exe = tdir / name
            return {
                "executable": str(exe),
                "executable_sha256": receipt_contract.sha256_file(exe),
                "version": f"{name} {release} (synthetic 2026-11-15)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-11-15",
                "host": "x86_64-unknown-linux-gnu",
            }

        return {
            "cargo": identity("cargo", w1c.CARGO_FORK_RELEASE, w1c.CARGO_FORK_COMMIT),
            "rustc": dict(
                identity("rustc", w1c.RUSTC_RELEASE, "d" * 40),
                path_entry=str(tdir / "rustc"),
                proxy=False,
            ),
            "rustup": {
                "executable": str(tdir / "rustup"),
                "executable_sha256": receipt_contract.sha256_file(tdir / "rustup"),
                "resolved_rustc": str(tdir / "rustc"),
                "resolved_rustc_sha256": receipt_contract.sha256_file(tdir / "rustc"),
            },
            "target_triple": "x86_64-unknown-linux-gnu",
            "pinned_channel": w1c.RUSTC_RELEASE,
            "pin_source": "rust-toolchain.toml",
        }

    def write_v2_cas_receipt(
        self,
        mutate=None,
        *,
        cas_snap_name: str = f"{w1c.TARGET_NAME}-0123456789abcdef",
        cas_receipt_name: str | None = None,
        cas_obj_name: str | None = None,
    ) -> Path:
        bound = receipt_contract.capture_bound_inputs(self.root, environ={"PATH": ""})
        artifact = receipt_contract.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {
                    "name": w1c.TARGET_NAME,
                    "kind": ["test"],
                    "src_path": str(self.root / w1c.TEST_SOURCE),
                },
                "profile": {
                    "opt_level": "0",
                    "debuginfo": 0,
                    "debug_assertions": True,
                    "overflow_checks": True,
                    "test": True,
                },
                "fresh": False,
                "executable": str(self.original_bin),
            },
            source_root=self.root,
            kind="test",
        )
        config_key = "c" * 64
        build_id = "b1"
        obj_path = self.store_root / "objects/sha256" / (cas_obj_name or self.binary_sha)
        obj_path.parent.mkdir(parents=True, exist_ok=True)
        obj_path.write_bytes(self.binary_bytes)
        os.chmod(obj_path, 0o555)

        snap_dir = self.store_root / "snapshots" / COMMIT / config_key / build_id
        snap_dir.mkdir(parents=True, exist_ok=True)
        self.canonical_bin = snap_dir / cas_snap_name
        self.canonical_bin.write_bytes(self.binary_bytes)
        os.chmod(self.canonical_bin, 0o555)

        canonical_receipt = snap_dir / (cas_receipt_name or f"{cas_snap_name}.receipt.json")
        canonical_build_receipt = snap_dir / f"{cas_snap_name}.build.json"
        cas_record = {
            "schema": w1c.STORE_SCHEMA,
            "root": str(self.store_root),
            "object": str(obj_path),
            "binary": str(self.canonical_bin),
            "receipt": str(canonical_receipt),
            "build_receipt": str(canonical_build_receipt),
            "binary_sha256": self.binary_sha,
            "config_key": config_key,
            "build_id": build_id,
            "method": "copy",
            "reused": False,
            "copied_bytes": len(self.binary_bytes),
            "output_alias": {
                "path": str(self.alias_bin),
                "receipt": str(self.alias_receipt),
                "method": "copy",
                "same_inode_as_cas_object": False,
                "overwrote_existing": False,
            },
        }
        test_src_sha = receipt_contract.sha256_file(self.root / w1c.TEST_SOURCE)
        payload = receipt_contract.make_receipt_v2(
            binary_path=self.canonical_bin,
            command=self.command,
            profile="test",
            artifacts=[artifact],
            toolchain=self.toolchain,
            bound_inputs=bound,
            workspace_commit=COMMIT,
            target_dir=self.target_dir,
            features="pando-lab",
            no_default_features=True,
            lock_file=self.root / "Cargo.lock",
            git_head=COMMIT,
            working_tree={"tree": "t" * 40, "status": ""},
            extra={
                "kind": "rust-integration-test",
                "relocated_artifact": True,
                "original_artifact_sha256": self.binary_sha,
                "integration_test_source": w1c.TEST_SOURCE,
                "integration_test_source_sha256": test_src_sha,
                "artifact_store": cas_record,
            },
        )
        if mutate is not None:
            mutate(payload, self)
        raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        for target in (canonical_receipt, canonical_build_receipt, self.alias_receipt):
            if target.exists():
                os.chmod(target, 0o600)
            target.write_bytes(raw)
            os.chmod(target, 0o444)
        self.build_report.write_bytes(raw)
        return self.alias_receipt

    def write_v1_receipt(self, mutate=None) -> Path:
        bound = receipt_contract.capture_bound_inputs(self.root, environ={"PATH": ""})
        payload = {
            "version": 1,
            "kind": "rust-integration-test",
            "relocated_artifact": True,
            "original_artifact_sha256": self.binary_sha,
            "binary_sha256": self.binary_sha,
            "source_inputs_sha256": bound["source_inputs_sha256"],
            "cargo_lock_sha256": bound["cargo_lock_sha256"],
            "config_digest": bound["config_digest"],
            "workspace_commit": COMMIT,
            "rustc": f"rustc {w1c.RUSTC_RELEASE} (synthetic 2026-11-15)",
            "command": self.command,
            "fresh": False,
            "package_rebuilt": True,
            "fresh_false_artifacts": [
                {"kind": "test", "target": w1c.TARGET_NAME, "fresh": False}
            ],
            "bound_inputs": bound["bound_inputs"],
            "bound_input_inventory": bound["bound_input_inventory"],
        }
        if mutate is not None:
            mutate(payload, self)
        raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if self.alias_receipt.exists():
            os.chmod(self.alias_receipt, 0o600)
        self.alias_receipt.write_bytes(raw)
        return self.alias_receipt

    def cli_args(self, *, cas: bool = True, with_build_report: bool = True) -> list[str]:
        argv = [
            "--build-receipt",
            str(self.alias_receipt),
            "--binary",
            str(self.alias_bin),
            "--receipt-copy",
            str(self.report_dir / f"{w1c.TARGET_NAME}.build.json"),
            "--canonical-path-out",
            str(self.out_dir / "w1c-exec.path"),
            "--report",
            str(self.report_dir / "acceptance.json"),
            "--summary-log",
            str(self.report_dir / "w1c-summary.log"),
            "--expected-commit",
            COMMIT,
        ]
        if with_build_report:
            argv += ["--build-report", str(self.build_report)]
        if cas:
            argv += [
                "--expected-store-root",
                str(self.store_root),
                "--require-cas",
                "--require-ci-pins",
                "--require-package-debug-zero",
                "--require-strip-debuginfo",
            ]
        return argv


class BlobStoreW1CNativeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = Path(tempfile.mkdtemp(prefix="w1c-native-test-"))
        self.addCleanup(lambda: (_restore_writable_tree(self.tempdir), shutil.rmtree(self.tempdir, ignore_errors=True)))
        self.fixture = W1CNativeFixture(self.tempdir)

    def _run_cli(self, argv, *, list_proc=None, run_proc=None, on_execute=None, env=None):
        orig_root = w1c.ROOT
        orig_git = w1c.git_state
        orig_sub = w1c.run_subprocess
        orig_env = os.environ.copy()

        def fake_git(root):
            self.assertEqual(Path(root).resolve(), self.fixture.root.resolve())
            return {
                "head": COMMIT,
                "commit": COMMIT,
                "tree": "t" * 40,
                "status": " M src/lib.rs\n" if self.fixture.worktree_dirty else "",
            }

        w1c.ROOT = self.fixture.root
        w1c.git_state = fake_git
        w1c.run_subprocess = _make_fake_process_runner(
            list_proc=list_proc, run_proc=run_proc, on_execute=on_execute
        )
        active_env = self.fixture.env if env is None else env
        for key in list(os.environ):
            if key in self.fixture.env:
                os.environ.pop(key, None)
        os.environ.update(active_env)
        stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                rc = w1c.main(argv)
        finally:
            w1c.ROOT = orig_root
            w1c.git_state = orig_git
            w1c.run_subprocess = orig_sub
            for key in list(os.environ):
                if key in self.fixture.env or key in active_env:
                    os.environ.pop(key, None)
            os.environ.update(orig_env)

        report_path = self.fixture.report_dir / "acceptance.json"
        summary_path = self.fixture.report_dir / "w1c-summary.log"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        summary = summary_path.read_text(encoding="utf-8")
        return rc, report, summary, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_v2_cas_acceptance_and_job_manifest_binding_pass(self) -> None:
        self.fixture.write_v2_cas_receipt()
        rc, report, summary, out, err = self._run_cli(self.fixture.cli_args(cas=True))
        self.assertEqual(rc, 0, f"summary={summary} err={err}")
        self.assertEqual(err, "")
        self.assertTrue(report["passed"])
        self.assertEqual(report["receipt_schema"], "v2")
        self.assertEqual(report["binary_sha256"], self.fixture.binary_sha)
        self.assertEqual(report["source_head"], COMMIT)
        self.assertEqual([c["name"] for c in report["cases"]], list(w1c.EXPECTED_CASES))
        self.assertTrue(all(c["status"] == "passed" for c in report["cases"]))
        self.assertEqual(report["test"]["passed"], 2)
        self.assertEqual(report["test"]["failed"], 0)
        self.assertEqual(report["test"]["ignored"], 0)
        self.assertIn(w1c.SUMMARY_PASS_MARKER, summary)
        self.assertIn(w1c.SUMMARY_PASS_MARKER, out)

        # Ensure zero raw Rust logs exist on disk and copied receipt matches canonical bytes.
        files = {p.name for p in self.fixture.report_dir.iterdir()}
        self.assertEqual(
            files,
            {
                "acceptance.json",
                "w1c-summary.log",
                f"{w1c.TARGET_NAME}.build.json",
            },
        )
        copied_receipt = self.fixture.report_dir / f"{w1c.TARGET_NAME}.build.json"
        self.assertEqual(copied_receipt.read_bytes(), self.fixture.alias_receipt.read_bytes())
        self.assertEqual(stat.S_IMODE(copied_receipt.stat().st_mode) & 0o222, 0)

        canonical_exec = (self.fixture.out_dir / "w1c-exec.path").read_text(encoding="utf-8").strip()
        self.assertEqual(Path(canonical_exec).resolve(), self.fixture.canonical_bin.resolve())

        manifest_out = self.fixture.out_dir / "w1c-native-job.json"
        cmd = [
            sys.executable,
            str(ROOT / "scripts/native_report_manifest.py"),
            "--mode",
            "job",
            "--build-receipt",
            str(copied_receipt),
            "--binary",
            canonical_exec,
            "--expect-commit",
            COMMIT,
            "--report",
            f"w1c={self.fixture.report_dir / 'acceptance.json'}",
            "--require-case",
            f"w1c={w1c.EXPECTED_CASES[0]}",
            "--require-case",
            f"w1c={w1c.EXPECTED_CASES[1]}",
            "--log",
            f"w1c-summary={self.fixture.report_dir / 'w1c-summary.log'}",
            "--log-marker",
            f"w1c-summary={w1c.SUMMARY_PASS_MARKER}",
            "--harness",
            str(self.fixture.root / "tests/blob_store_w1c_native.py"),
            "--harness",
            str(self.fixture.root / w1c.TEST_SOURCE),
            "--fixture-rust-from-receipt",
            "--fixture",
            "postgres=postgres:17",
            "--fixture",
            "garage=Garage v2.1.0 sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78e93ee8da7cf6a",
            "--manifest-out",
            str(manifest_out),
        ]
        manifest_proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(manifest_proc.returncode, 0, manifest_proc.stderr)
        manifest = json.loads(manifest_out.read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(manifest["binary_sha256"], self.fixture.binary_sha)
        self.assertEqual(manifest["source_commit"], COMMIT)
        self.assertEqual(manifest["reports"]["w1c"]["case_names"], list(w1c.EXPECTED_CASES))

    def test_v1_receipt_accepted_without_require_cas_and_rejected_with_require_cas(self) -> None:
        self.fixture.write_v1_receipt()
        rc, report, _summary, _out, _err = self._run_cli(
            self.fixture.cli_args(cas=False, with_build_report=False)
        )
        self.assertEqual(rc, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["receipt_schema"], "v1")

        rc_strict, report_strict, _summary2, _out2, _err2 = self._run_cli(
            self.fixture.cli_args(cas=True, with_build_report=False)
        )
        self.assertEqual(rc_strict, 1)
        self.assertFalse(report_strict["passed"])
        self.assertEqual(report_strict["failure"]["stage"], "receipt")
        self.assertEqual(report_strict["failure"]["code"], "receipt_artifact_store")

    def test_tampered_binary_receipt_source_and_flags_fail_closed(self) -> None:
        cases = [
            ("alias_binary_drift", "receipt", "binary_mismatch"),
            ("build_report_drift", "receipt", "build_report_mismatch"),
            ("source_file_drift", "source", "source_drift"),
            ("lock_drift", "source", "source_drift"),
            ("dirty_worktree", "source", "worktree_dirty"),
            ("implicit_build", "receipt", "receipt_invalid"),
            ("all_features", "receipt", "receipt_features"),
            ("release_profile", "receipt", "receipt_profile"),
            ("missing_strip", "receipt", "receipt_profile"),
            ("wrong_target_artifact", "receipt", "receipt_artifacts"),
            ("wrong_cas_target_name", "receipt", "receipt_artifact_store"),
            ("wrong_cas_nonhex_suffix", "receipt", "receipt_artifact_store"),
            ("mismatched_cas_receipt_name", "receipt", "receipt_artifact_store"),
            ("mismatched_cas_executable_name", "receipt", "receipt_artifact_store"),
            ("bad_cas_object_name", "receipt", "receipt_artifact_store"),
        ]
        for mode, exp_stage, exp_code in cases:
            with self.subTest(mode=mode):
                local = Path(tempfile.mkdtemp(prefix=f"w1c-{mode}-"))
                self.addCleanup(lambda p=local: (_restore_writable_tree(p), shutil.rmtree(p, ignore_errors=True)))
                self.fixture = W1CNativeFixture(local)

                def mutator(payload, fx):
                    if mode == "implicit_build":
                        payload["implicit_build"] = True
                    elif mode == "all_features":
                        payload["command"] = [*payload["command"], "--all-features"]
                    elif mode == "release_profile":
                        payload["command"] = [
                            "--release" if tok == "--profile" else tok
                            for tok in payload["command"]
                            if tok != "test"
                        ]
                    elif mode == "missing_strip":
                        payload["command"] = [
                            tok
                            for tok in payload["command"]
                            if 'strip="debuginfo"' not in tok
                        ]
                    elif mode == "wrong_target_artifact":
                        payload["cargo_artifacts"][0]["target"] = "other_test"

                snap_name = f"{w1c.TARGET_NAME}-0123456789abcdef"
                receipt_name = None
                obj_name = None
                if mode == "wrong_cas_target_name":
                    snap_name = "other_target-0123456789abcdef"
                elif mode == "wrong_cas_nonhex_suffix":
                    snap_name = f"{w1c.TARGET_NAME}-nothex"
                elif mode == "mismatched_cas_receipt_name":
                    receipt_name = f"{w1c.TARGET_NAME}.receipt.json"
                elif mode == "mismatched_cas_executable_name":
                    snap_name = f"{w1c.TARGET_NAME}-fedcba9876543210"
                elif mode == "bad_cas_object_name":
                    obj_name = "bad_object_name"

                self.fixture.write_v2_cas_receipt(
                    mutate=mutator,
                    cas_snap_name=snap_name,
                    cas_receipt_name=receipt_name,
                    cas_obj_name=obj_name,
                )
                if mode == "alias_binary_drift":
                    os.chmod(self.fixture.alias_bin, 0o600)
                    self.fixture.alias_bin.write_bytes(b"tampered")
                    os.chmod(self.fixture.alias_bin, 0o555)
                elif mode == "build_report_drift":
                    self.fixture.build_report.write_text('{"tampered": true}\n', encoding="utf-8")
                elif mode == "source_file_drift":
                    (self.fixture.root / "src/lib.rs").write_text("pub fn marker() -> u8 { 9 }\n", encoding="utf-8")
                elif mode == "lock_drift":
                    (self.fixture.root / "Cargo.lock").write_text("tampered\n", encoding="utf-8")
                elif mode == "dirty_worktree":
                    self.fixture.worktree_dirty = True

                rc, report, summary, _out, _err = self._run_cli(self.fixture.cli_args(cas=True))
                self.assertEqual(rc, 1, f"{mode}: unexpected pass")
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["stage"], exp_stage, mode)
                self.assertEqual(report["failure"]["code"], exp_code, mode)
                self.assertIn(f"failed ({exp_stage}/{exp_code})", summary)

    def test_post_execution_immutable_drift_rejected(self) -> None:
        self.fixture.write_v2_cas_receipt()
        target = self.fixture.root / "src/lib.rs"
        rc, report, summary, _out, _err = self._run_cli(
            self.fixture.cli_args(cas=True),
            on_execute=lambda: target.write_text("pub fn marker() -> u8 { 42 }\n", encoding="utf-8"),
        )
        self.assertEqual(rc, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["stage"], "immutable")
        self.assertEqual(report["failure"]["code"], "immutable_drift")
        self.assertIn("failed (immutable/immutable_drift)", summary)

    def test_memory_only_execution_never_leaks_secrets_urls_or_raw_rust_lines(self) -> None:
        self.fixture.write_v2_cas_receipt()
        secret = "SECRET_CANARY_KEY_999888"
        dsn = f"postgresql://rootyard:{secret}@127.0.0.1:55432/rootyard_secret_db"
        noisy_stdout = (
            "running 2 tests\n"
            f"test {w1c.EXPECTED_CASES[0]} ... ok\n"
            f"connection={dsn}\n"
            f"ROOTYARD_BLOB_SECRET_ACCESS_KEY={secret}\n"
            f"test {w1c.EXPECTED_CASES[1]} ... FAILED\n\n"
            "failures:\n\n"
            "---- failure stdout ----\n"
            "canceling statement due to lock timeout on relation\n\n"
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
        )
        noisy_stderr = f"stderr debug url={dsn} key={secret}\n"

        rc, report, summary, out, err = self._run_cli(
            self.fixture.cli_args(cas=True),
            run_proc=subprocess.CompletedProcess(["bin"], 101, noisy_stdout, noisy_stderr),
        )
        self.assertEqual(rc, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"], {"stage": "execute", "code": "lock_timeout", "exit_code": 101})
        self.assertEqual(report["test"]["passed"], 1)
        self.assertEqual(report["test"]["failed"], 1)
        self.assertEqual(
            {c["name"]: c["status"] for c in report["cases"]},
            {
                w1c.EXPECTED_CASES[0]: "passed",
                w1c.EXPECTED_CASES[1]: "failed",
            },
        )
        serialized = json.dumps(report) + "\n" + summary + "\n" + out + "\n" + err
        for canary in (secret, "postgresql://", "rootyard_secret_db", "canceling statement due to"):
            self.assertNotIn(canary, serialized)
        self.assertFalse((self.fixture.report_dir / "ignored-inventory.txt").exists())
        self.assertFalse((self.fixture.report_dir / "native.raw.log").exists())
        self.assertFalse((self.fixture.report_dir / "native.log").exists())

    def test_timeout_and_inventory_and_missing_env_fail_closed_without_leaks(self) -> None:
        self.fixture.write_v2_cas_receipt()
        secret_bytes = b"TIMEOUT_SECRET_CANARY_12345"
        exc = subprocess.TimeoutExpired(["bin", "--ignored", "--test-threads=1"], 300.0, output=secret_bytes, stderr=secret_bytes)
        rc, report, summary, out, err = self._run_cli(self.fixture.cli_args(cas=True), run_proc=exc)
        self.assertEqual(rc, 1)
        self.assertEqual(report["failure"], {"stage": "execute", "code": "timeout", "exit_code": None})
        self.assertNotIn("TIMEOUT_SECRET_CANARY_12345", json.dumps(report) + summary + out + err)

        bad_inv = subprocess.CompletedProcess(["bin"], 0, f"{w1c.EXPECTED_CASES[0]}: test\nunexpected: test\n", "")
        rc2, report2, _s2, _o2, _e2 = self._run_cli(self.fixture.cli_args(cas=True), list_proc=bad_inv)
        self.assertEqual(rc2, 1)
        self.assertEqual(report2["failure"]["stage"], "inventory")
        self.assertEqual(report2["failure"]["code"], "inventory_mismatch")

        zero_run = subprocess.CompletedProcess(
            ["bin"],
            0,
            "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            "",
        )
        rc3, report3, _s3, _o3, _e3 = self._run_cli(self.fixture.cli_args(cas=True), run_proc=zero_run)
        self.assertEqual(rc3, 1)
        self.assertEqual(report3["failure"]["stage"], "parse")
        self.assertEqual(report3["failure"]["code"], "zero_tests")

        bad_env = dict(self.fixture.env)
        bad_env.pop("ROOTYARD_BLOB_SECRET_ACCESS_KEY")
        rc4, report4, _s4, _o4, _e4 = self._run_cli(self.fixture.cli_args(cas=True), env=bad_env)
        self.assertEqual(rc4, 1)
        self.assertEqual(report4["failure"], {"stage": "environment", "code": "missing_blob_env", "exit_code": None})

    def test_workflow_wires_shared_runner_and_job_manifest_without_raw_logs(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("- 'tests/blob_store_w1c_native.py'", text)

        step_marker = '- name: "Build and exercise #109 blob_store_w1c_contract against PostgreSQL and Garage S3"'
        start = text.index(step_marker)
        end = text.index('- name: "Drop only the job-owned #109 w1c database"', start)
        step = text[start:end]
        self.assertNotIn("ignored-inventory.txt", step)
        self.assertNotIn("native.raw.log", step)
        self.assertNotIn("native.log", step)
        self.assertIn("python3 tests/blob_store_w1c_native.py", step)
        self.assertIn("python3 scripts/native_report_manifest.py --mode job", step)
        self.assertIn('--harness "tests/blob_store_w1c_native.py"', step)
        self.assertIn('--harness "tests/blob_store_w1c_contract.rs"', step)
        self.assertIn("--fixture-rust-from-receipt", step)
        self.assertIn("--manifest-out test-results/refstore/w1c-native-job.json", step)


if __name__ == "__main__":
    unittest.main()
