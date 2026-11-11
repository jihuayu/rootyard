#!/usr/bin/env python3
"""Unit tests for scripts/build_native_test.py --lib mode and receipts.

No cargo invocation: synthetic compiler-artifact streams and mocked subprocess
boundaries exercise the refusal paths, the exact argv, and the receipt shape.
"""
from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_native_test as bnt  # noqa: E402
from build_native import BuildError  # noqa: E402


def artifact(*, name="rootyard", kind=("lib",), fresh=False, profile_test=True,
             executable="/tmp/rootyard-lib-test", test_flag=True):
    return {
        "reason": "compiler-artifact",
        "target": {"name": name, "kind": list(kind), "test": test_flag},
        "profile": {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
                    "overflow_checks": True, "test": profile_test},
        "fresh": fresh,
        "executable": executable,
    }


def build_finished():
    return {"reason": "build-finished", "success": True}


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


class SelectedLibraryArtifactTests(unittest.TestCase):
    def test_valid_single_fresh_false_lib_test_is_selected(self):
        selected = bnt.selected_library_artifact([artifact(fresh=False)])
        self.assertEqual(selected["target"], "rootyard")
        self.assertEqual(selected["kind"], "lib-test")
        self.assertFalse(selected["fresh"])
        self.assertEqual(selected["profile"]["test"], True)
        self.assertTrue(selected["executable"].endswith("rootyard-lib-test"))

    def test_missing_lib_test_artifact_is_refused(self):
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact([{"reason": "compiler-artifact", "target": {"name": "other"}}])

    def test_duplicate_lib_test_artifacts_are_refused(self):
        with self.assertRaisesRegex(BuildError, "2 rootyard lib test artifacts"):
            bnt.selected_library_artifact([artifact(), artifact()])

    def test_fresh_lib_test_artifact_is_refused(self):
        with self.assertRaisesRegex(BuildError, "Fresh"):
            bnt.selected_library_artifact([artifact(fresh=True)])

    def test_ordinary_lib_without_test_profile_is_skipped(self):
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact([artifact(profile_test=False)])

    def test_lib_target_marked_non_test_is_skipped(self):
        with self.assertRaisesRegex(BuildError, "0 rootyard lib test artifacts"):
            bnt.selected_library_artifact([artifact(test_flag=False)])


class RunBuildRefusalTests(unittest.TestCase):
    def namespace(self, **overrides):
        values = dict(lib=True, test=None, features=None, no_default_features=False,
                      package_debug=None, strip_debuginfo=False, output="out/libtest")
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_lib_and_test_are_mutually_exclusive(self):
        with self.assertRaisesRegex(BuildError, "mutually exclusive"):
            bnt.run_build(self.namespace(lib=True, test="blob_git_gateway"))

    def test_one_of_lib_or_test_is_required(self):
        with self.assertRaisesRegex(BuildError, "one of --test or --lib is required"):
            bnt.run_build(self.namespace(lib=False, test=None))


class RunBuildReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "target"
        self.output = self.root / "relocated" / "libtest"
        self.artifact = self.root / "target-artifact"
        self.artifact.write_bytes(b"fake-libtest-binary")
        self.artifact.chmod(0o755)
        self.events = [artifact(executable=str(self.artifact)), build_finished()]

    def tearDown(self):
        self.tmp.cleanup()

    def args(self):
        return argparse.Namespace(
            lib=True, test=None, features=None, no_default_features=True,
            package_debug="0", strip_debuginfo=True, output=str(self.output))

    def run_with(self, events=None, support=None):
        events = events if events is not None else self.events
        support = support if support is not None else ["c" * 64, "c" * 64]
        patches = [
            mock.patch.object(bnt, "build_lock", no_lock),
            mock.patch.object(bnt, "canonical_target", return_value=self.target),
            mock.patch.object(bnt, "source_digest", return_value="a" * 64),
            mock.patch.object(bnt, "git_state", return_value=("b" * 40, "")),
            mock.patch.object(bnt, "lib_test_support_digest", side_effect=support),
            mock.patch.object(bnt.subprocess, "run", return_value=mock.Mock(returncode=0)),
            mock.patch.object(bnt.subprocess, "Popen", side_effect=lambda *a, **k: FakeProcess(events)),
            mock.patch.object(bnt.subprocess, "check_output", return_value="rustc 1.88.0 (test)\n"),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return bnt.run_build(self.args())

    def test_lib_receipt_shape_and_exact_argv(self):
        report = self.run_with()
        expected = [
            "cargo",
            "--config", "profile.dev.package.rootyard.debug=0",
            "--config", "profile.test.package.rootyard.debug=0",
            "--config", 'profile.dev.package.rootyard.strip="debuginfo"',
            "--config", 'profile.test.package.rootyard.strip="debuginfo"',
            "test", "--locked", "--no-default-features", "--lib", "--no-run",
            "--message-format=json-render-diagnostics",
        ]
        self.assertEqual(report["kind"], "rust-library-test")
        self.assertEqual(report["command"], expected)
        self.assertEqual(report["lib_test_support_inputs_sha256"], "c" * 64)
        self.assertNotIn("test", report)
        self.assertNotIn("test_inputs_sha256", report)
        self.assertEqual(report["fresh_false_artifacts"][0]["kind"], "lib-test")
        self.assertEqual(report["fresh_false_artifacts"][0]["target"], "rootyard")
        self.assertFalse(report["fresh_false_artifacts"][0]["fresh"])
        self.assertEqual(report["source_inputs_sha256"], "a" * 64)
        receipt = json.loads(self.output.with_suffix(".build.json").read_text())
        self.assertEqual(receipt, report)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.output.read_bytes(), self.artifact.read_bytes())

    def test_mid_build_support_digest_change_is_refused(self):
        with self.assertRaisesRegex(BuildError, "test-support inputs changed"):
            self.run_with(support=["c" * 64, "d" * 64])
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_suffix(".build.json").exists())


if __name__ == "__main__":
    unittest.main()
