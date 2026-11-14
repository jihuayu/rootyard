#!/usr/bin/env python3
"""Offline contract tests for the v2 explicit test producer.

No Cargo, rustc or rustup invocation: synthetic compiler-artifact streams and
mocked metadata probes exercise the exact argv, no-clean cache-compatible
freshness, v2 receipt bindings, support closure, relocation immutability and
every refusal path.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_native_test as bnt  # noqa: E402
import native_build_receipt as receipt  # noqa: E402
from build_native import BuildError  # noqa: E402

TRIPLE = "x86_64-unknown-linux-gnu"
CARGO_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
PROFILE = {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
           "overflow_checks": True, "test": True}


def artifact(*, name="rootyard", kind=("lib",), fresh=False,
             executable=None, source=None, profile=None, test_flag=True,
             package_id="rootyard 0.1.0"):
    return {
        "reason": "compiler-artifact",
        "package_id": package_id,
        "target": {"name": name, "kind": list(kind), "test": test_flag,
                   "src_path": str(source or (ROOT / "src/lib.rs"))},
        "profile": dict(PROFILE, **(profile or {})),
        "fresh": fresh,
        **({"executable": str(executable)} if executable is not None else {}),
    }


def build_finished(success=True):
    return {"reason": "build-finished", "success": success}


@contextlib.contextmanager
def no_lock(_target):
    yield


class FakeProcess:
    def __init__(self, events):
        self.stdout = iter(json.dumps(event) + "\n" for event in events)
        self.returncode = 0
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "tests" / "fixtures").mkdir(parents=True)
        (self.root / "tests" / "serving_support").mkdir()
        (self.root / "toolchain").mkdir()
        (self.root / "Cargo.toml").write_text('[package]\nname = "rootyard"\n')
        (self.root / "Cargo.lock").write_text("version = 3\n")
        (self.root / "src" / "lib.rs").write_text("pub fn hello() {}\n")
        (self.root / "src" / "main.rs").write_text("fn main() {}\n")
        (self.root / "tests" / "example.rs").write_text("#[test]\nfn one() {}\n")
        (self.root / "tests" / "other.rs").write_text("#[test]\nfn other() {}\n")
        (self.root / "tests" / "helper.rs").write_text("pub fn helper() {}\n")
        (self.root / "experimental" / "pando").mkdir(parents=True)
        shutil.copyfile(ROOT / "experimental" / "pando" / "schema.sql",
                        self.root / "experimental" / "pando" / "schema.sql")
        (self.root / "tests" / "fixtures" / "data.txt").write_text("fixture\n")
        (self.root / "tests" / "serving_support" / "support.rs").write_text("pub fn s() {}\n")
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.99.1"\n')
        for name in ("cargo", "rustc", "rustup"):
            (self.root / "toolchain" / name).write_bytes(("fake-" + name).encode())
        self.target = self.root / "target"
        self.output = self.root / "relocated" / "libtest"
        self.lib_artifact = self.target / "debug" / "deps" / "rootyard-lib-test"
        self.test_artifact = self.target / "debug" / "deps" / "example-0123456789abcdef"
        self.lib_artifact.parent.mkdir(parents=True)
        self.lib_artifact.write_bytes(b"binary-rootyard")
        self.test_artifact.write_bytes(b"binary-example")
        self.popen_calls = []
        self.probe_sequences = None
        self.git_sequences = None
        self.mutate = None
        self.environment = mock.patch.dict(
            os.environ,
            {"CARGO_TARGET_DIR": "target", "HOME": str(self.root / "home"),
             "CARGO_HOME": str(self.root / "cargo-home")},
            clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        (self.root / "home").mkdir()
        (self.root / "cargo-home").mkdir()
        patches = [
            mock.patch.object(bnt, "ROOT", self.root),
            mock.patch.object(bnt, "build_lock", no_lock),
            mock.patch.object(bnt, "canonical_target", return_value=self.target),
            mock.patch.object(bnt, "probe_toolchain", self.fake_toolchain),
            mock.patch.object(bnt, "git_state", self.fake_git),
            mock.patch.object(bnt.subprocess, "run", self.fail_run),
            mock.patch.object(bnt.subprocess, "check_output", self.fail_check_output),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def fail_run(self, command, **kwargs):
        raise AssertionError(f"unexpected subprocess.run: {command}")

    def fail_check_output(self, command, **kwargs):
        raise AssertionError(f"unexpected subprocess.check_output: {command}")

    def fake_toolchain(self, environment):
        if self.probe_sequences is not None:
            value = self.probe_sequences.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        def identity(name, release, commit_hash, proxy=None):
            path = self.root / "toolchain" / name
            result = {
                "executable": str(path),
                "executable_sha256": receipt.sha256_file(path),
                "version": f"{name} {release} (fake 2026-01-01)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": TRIPLE,
            }
            if proxy is not None:
                result["path_entry"] = str(path)
                result["proxy"] = proxy
            return result
        return {
            "cargo": identity("cargo", "1.101.0", CARGO_COMMIT),
            "rustc": identity("rustc", "1.99.1", "d" * 40, proxy=False),
            "rustup": {
                "executable": str(self.root / "toolchain/rustup"),
                "executable_sha256": receipt.sha256_file(self.root / "toolchain/rustup"),
                "resolved_rustc": str(self.root / "toolchain/rustc"),
                "resolved_rustc_sha256": receipt.sha256_file(self.root / "toolchain/rustc"),
            },
            "target_triple": TRIPLE,
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def fake_git(self):
        if self.git_sequences is not None:
            return self.git_sequences.pop(0)
        return {"head": "a" * 40, "commit": "a" * 40,
                "tree": "b" * 40, "status": " M src/lib.rs\n"}

    def args(self, **overrides):
        values = dict(lib=True, test=None, features=None, no_default_features=False,
                      package_debug=None, strip_debuginfo=False,
                      output=str(self.output))
        values.update(overrides)
        return argparse.Namespace(**values)

    def events(self, *, kind="lib", fresh=False, executable=None, source=None,
               name="rootyard"):
        if kind == "lib":
            executable = executable or self.lib_artifact
            source = source or self.root / "src" / "lib.rs"
            target_kind = ("lib",)
        else:
            executable = executable or self.test_artifact
            source = source or self.root / "tests" / (name + ".rs")
            target_kind = ("test",)
        return [artifact(name=name, kind=target_kind, fresh=fresh,
                         executable=executable, source=source),
                build_finished()]

    def fake_popen(self, events):
        def popen(command, **kwargs):
            self.popen_calls.append((list(command), kwargs))
            for event in events:
                executable = event.get("executable")
                if executable:
                    path = Path(executable)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(("binary-" + event["target"]["name"]).encode())
            if self.mutate is not None:
                self.mutate()
            return FakeProcess(events)
        return popen

    def run_with(self, events=None, args=None, **kwargs):
        events = self.events() if events is None else events
        args = self.args() if args is None else args
        with mock.patch.object(bnt.subprocess, "Popen", self.fake_popen(events)):
            return bnt.run_build(args, **kwargs)

    def receipt_path(self, output=None):
        return Path(output or self.output).with_suffix(".build.json")

    def assert_no_output(self, output=None):
        output = Path(output or self.output)
        self.assertFalse(output.exists())
        self.assertFalse(output.with_suffix(".build.json").exists())
        self.assertFalse(output.with_name("." + output.name + ".tmp").exists())


class LibReceiptTests(Fixture):
    def test_lib_receipt_shape_exact_argv_and_cache_compatible_freshness(self):
        for fresh in (False, True):
            with self.subTest(fresh=fresh):
                self.popen_calls = []
                report = self.run_with(self.events(fresh=fresh))
                expected = [
                    "cargo", "test", "--locked", "--lib", "--no-run",
                    "--message-format=json-render-diagnostics",
                ]
                self.assertEqual(report["command"], expected)
                self.assertEqual(self.popen_calls[0][0], expected)
                self.assertEqual(self.popen_calls[0][1]["cwd"], self.root)
                self.assertEqual(report["receipt_schema"], receipt.RECEIPT_SCHEMA_V2)
                for banned in receipt.V2_BANNED_FIELDS:
                    self.assertNotIn(banned, report)
                self.assertEqual(report["kind"], "rust-library-test")
                self.assertIs(report["relocated_artifact"], True)
                self.assertEqual(report["cargo_artifacts"][0]["kind"], "lib-test")
                self.assertEqual(report["cargo_artifacts"][0]["target"], "rootyard")
                self.assertEqual(report["cargo_artifacts"][0]["fresh"], fresh)
                self.assertEqual(report["cargo_artifacts"][0]["source"], "src/lib.rs")
                self.assertEqual(report["original_artifact_sha256"],
                                 receipt.sha256_file(self.lib_artifact))
                self.assertEqual(report["binary_sha256"], receipt.sha256_file(self.output))
                self.assertEqual(report["binary_sha256"], report["original_artifact_sha256"])
                self.assertEqual(report["profile"], "test")
                self.assertEqual(report["target_triple"], TRIPLE)
                self.assertEqual(report["workspace_commit"], "a" * 40)
                self.assertEqual(report["git_head"], "a" * 40)
                self.assertEqual(report["working_tree"],
                                 {"tree": "b" * 40, "status": " M src/lib.rs\n"})
                self.assertEqual(report["toolchain"]["cargo"]["commit_hash"], CARGO_COMMIT)
                self.assertEqual(report["toolchain"]["rustc"]["proxy"], False)
                self.assertEqual(report["lib_test_support_inputs_sha256"],
                                 bnt.support_digest_from_bound(report))
                self.assertEqual(report["build_options"], {"jobs": None})
                self.assertEqual(json.loads(self.receipt_path().read_text()), report)
                self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
                self.assertNotEqual(os.stat(self.output).st_ino,
                                    os.stat(self.lib_artifact).st_ino)
                self.assertTrue(self.lib_artifact.is_file())
                self.assertFalse(list(self.output.parent.rglob("*.tmp")))

    def test_integration_target_binds_exact_source_and_relocated_digest(self):
        output = self.root / "relocated" / "example"
        report = self.run_with(
            self.events(kind="test", name="example", fresh=True),
            args=self.args(lib=False, test="example", output=str(output)))
        self.assertEqual(report["kind"], "rust-integration-test")
        self.assertEqual(report["cargo_artifacts"][0]["kind"], "test")
        self.assertEqual(report["cargo_artifacts"][0]["source"], "tests/example.rs")
        self.assertEqual(report["cargo_artifacts"][0]["fresh"], True)
        self.assertEqual(report["integration_test_source"], "tests/example.rs")
        self.assertEqual(report["integration_test_source_sha256"],
                         receipt.sha256_file(self.root / "tests" / "example.rs"))
        self.assertEqual(report["original_artifact_sha256"],
                         receipt.sha256_file(self.test_artifact))
        self.assertEqual(report["binary_sha256"], receipt.sha256_file(output))
        self.assertEqual(Path(output).read_bytes(), self.test_artifact.read_bytes())
        self.assertTrue(self.test_artifact.is_file())
        self.assertEqual(report["features"], {"enabled": [], "no_default_features": False})

    def test_profile_flags_and_jobs_are_recorded_verbatim(self):
        os.environ["CARGO_BUILD_JOBS"] = "2"
        try:
            report = self.run_with(
                self.events(),
                args=self.args(no_default_features=True, package_debug="0",
                               strip_debuginfo=True, features="pando-lab"))
        finally:
            os.environ.pop("CARGO_BUILD_JOBS", None)
        command = self.popen_calls[0][0]
        self.assertEqual(command, [
            "cargo",
            "--config", "profile.dev.package.rootyard.debug=0",
            "--config", "profile.test.package.rootyard.debug=0",
            "--config", 'profile.dev.package.rootyard.strip="debuginfo"',
            "--config", 'profile.test.package.rootyard.strip="debuginfo"',
            "test", "--locked", "--no-default-features",
            "--features", "pando-lab", "--lib", "--no-run",
            "--message-format=json-render-diagnostics", "--jobs", "2",
        ])
        self.assertNotIn("CARGO_BUILD_JOBS", self.popen_calls[0][1]["env"])
        self.assertEqual(report["command"], command)
        self.assertEqual(report["features"], {"enabled": ["pando-lab"], "no_default_features": True})
        self.assertEqual(report["build_options"], {"jobs": 2})


class SelectionRefusalTests(Fixture):
    def test_missing_lib_test_artifact_is_refused(self):
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact([])

    def test_duplicate_lib_test_artifacts_are_refused(self):
        events = self.events() + self.events()[:-1]
        with self.assertRaisesRegex(BuildError, "2 rootyard lib test artifacts"):
            bnt.selected_library_artifact(events)

    def test_ordinary_lib_without_test_profile_is_skipped(self):
        events = self.events()
        events[0]["profile"]["test"] = False
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact(events)

    def test_lib_target_marked_non_test_is_skipped(self):
        events = self.events()
        events[0]["target"]["test"] = False
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact(events)

    def test_absent_or_non_boolean_freshness_is_refused(self):
        for value in (None, 0, 1, "true", [], {}):
            with self.subTest(value=value):
                events = self.events()
                events[0]["fresh"] = value
                with self.assertRaisesRegex(BuildError, "non-boolean freshness"):
                    bnt.selected_library_artifact(events)
        events = self.events()
        del events[0]["fresh"]
        with self.assertRaisesRegex(BuildError, "non-boolean freshness"):
            bnt.selected_library_artifact(events)

    def test_wrong_kind_and_source_are_refused(self):
        event = self.events()[0]
        event["target"]["kind"] = ["bin"]
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact([event])
        wrong_source = self.events(kind="test", name="example",
                                   source=self.root / "tests" / "other.rs")
        with self.assertRaisesRegex(BuildError, "not tests/example.rs"):
            bnt.selected_artifact(wrong_source, "example")
        lib_wrong_source = self.events(source=self.root / "tests" / "helper.rs")
        with self.assertRaisesRegex(BuildError, "outside src/"):
            bnt.selected_library_artifact(lib_wrong_source)

    def test_missing_non_test_profile_and_duplicate_integration_artifacts_are_refused(self):
        with self.assertRaisesRegex(BuildError, "0 example test artifacts"):
            bnt.selected_artifact([], "example")
        wrong_profile = self.events(kind="test", name="example")
        wrong_profile[0]["profile"]["test"] = False
        with self.assertRaisesRegex(BuildError, "test artifact profile.test must be exactly true"):
            bnt.selected_artifact(wrong_profile, "example")
        with self.assertRaisesRegex(BuildError, "2 example test artifacts"):
            bnt.selected_artifact(self.events(kind="test", name="example") * 2, "example")


class RunRefusalTests(Fixture):
    def assert_failure(self, events=None, message="", args=None):
        self.receipt_path().parent.mkdir(parents=True, exist_ok=True)
        self.receipt_path().write_text('{"stale": true}\n')
        with self.assertRaises(BuildError) as caught:
            self.run_with(events, args=args)
        self.assertIn(message, str(caught.exception))
        self.assert_no_output((args or self.args()).output)

    def test_lib_and_test_are_mutually_exclusive(self):
        with self.assertRaisesRegex(BuildError, "mutually exclusive"):
            bnt.run_build(self.args(lib=True, test="example"))

    def test_one_of_lib_or_test_is_required(self):
        with self.assertRaisesRegex(BuildError, "one of --test or --lib is required"):
            bnt.run_build(self.args(lib=False, test=None))

    def test_missing_or_unsafe_test_name_is_refused(self):
        with self.assertRaisesRegex(BuildError, "plain Rust target identifier"):
            bnt.run_build(self.args(lib=False, test="../evil"))
        with self.assertRaisesRegex(BuildError, "integration-test source is missing"):
            bnt.run_build(self.args(lib=False, test="missing"))

    def test_output_inside_target_is_refused(self):
        with self.assertRaisesRegex(BuildError, "outside CARGO_TARGET_DIR"):
            bnt.run_build(self.args(output=str(self.target / "debug" / "test")))

    def test_output_symlink_is_refused(self):
        self.output.parent.mkdir(parents=True)
        self.output.symlink_to(self.root / "historical")
        with self.assertRaisesRegex(BuildError, "symlink"):
            bnt.run_build(self.args())

    def test_source_change_during_build_is_refused_for_integration(self):
        def mutate():
            (self.root / "tests" / "example.rs").write_text("#[test]\nfn changed() {}\n")
        events = self.events(kind="test", name="example")
        self.mutate = mutate
        self.assert_failure(events, "Source inputs changed during build",
                            args=self.args(lib=False, test="example",
                                           output=str(self.root / "relocated" / "example")))

    def test_lib_support_change_during_build_is_refused(self):
        def mutate():
            (self.root / "tests" / "fixtures" / "data.txt").write_text("changed\n")
        self.mutate = mutate
        self.assert_failure(self.events(), "lib test-support inputs changed")

    def test_toolchain_and_head_changes_are_refused(self):
        before = self.fake_toolchain({})
        after = json.loads(json.dumps(before))
        after["rustc"]["executable_sha256"] = "0" * 64
        self.probe_sequences = [before, after]
        self.assert_failure(self.events(), "Toolchain identity changed")
        self.probe_sequences = None
        good = {"head": "a" * 40, "commit": "a" * 40, "tree": "b" * 40, "status": ""}
        self.git_sequences = [good, dict(good, head="c" * 40)]
        self.assert_failure(self.events(), "HEAD or working-tree state changed")

    def test_cargo_failure_missing_build_finished_and_non_json_are_refused(self):
        self.assert_failure(self.events()[:-1], "build-finished")
        failed = self.events()
        failed[-1] = build_finished(False)
        self.assert_failure(failed, "build-finished")

        class RawProcess:
            def __init__(self):
                self.stdout = iter(["not json\n"])
                self.returncode = 0

            def wait(self):
                return 0

            def kill(self):
                pass

        def non_json(command, **kwargs):
            for event in self.events():
                executable = event.get("executable")
                if executable:
                    path = Path(executable)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"binary")
            return RawProcess()
        with mock.patch.object(bnt.subprocess, "Popen", non_json):
            with self.assertRaisesRegex(BuildError, "non-JSON"):
                bnt.run_build(self.args())
        self.assert_no_output()

    def test_copy_tamper_is_refused_and_publishes_nothing(self):
        real_copyfile = shutil.copyfile

        def tampered(source, destination, *args, **kwargs):
            real_copyfile(source, destination, *args, **kwargs)
            with open(destination, "ab") as handle:
                handle.write(b"tampered")

        with mock.patch.object(bnt.shutil, "copyfile", tampered):
            with self.assertRaisesRegex(BuildError, "does not match the selected artifact"):
                self.run_with(self.events())
        self.assert_no_output()

    def test_failure_withdraws_previous_receipt_and_output(self):
        self.output.parent.mkdir(parents=True)
        self.output.write_bytes(b"old-output")
        self.receipt_path().write_text('{"stale": true}\n')
        with self.assertRaises(BuildError):
            self.run_with(self.events()[:-1])
        self.assert_no_output()


if __name__ == "__main__":
    unittest.main()
