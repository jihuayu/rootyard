#!/usr/bin/env python3
"""Pure contract tests for the source-bound producer PG preparation.

No Cargo, Git, PostgreSQL, Vault, Docker, HTTP, network or real child process is
used.  Cargo JSON, Popen/time, Git state and owned-resource probes are replaced
with deterministic fakes; filesystem trees are temporary fixtures only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import native_build_receipt as receipts  # noqa: E402
import pando_producer_pg.artifacts as artifacts  # noqa: E402
import pando_producer_pg.process as process  # noqa: E402
import pando_producer_pg.source as source  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeThread,
    GroupKiller,
    StreamingPopen,
)

COMMIT = "a" * 40
TREE = "b" * 40


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


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


def state(commit=COMMIT, tree=TREE, clean=True):
    return {
        "head": commit,
        "commit": commit,
        "tree": tree,
        "status": "" if clean else " M src/x",
        "tracked_status": "" if clean else " M src/x",
        "status_with_untracked": "" if clean else " M src/x",
        "untracked": [],
        "untracked_count": 0,
        "tracked_dirty": not clean,
        "dirty": not clean,
        "clean": clean,
    }


def write_tree(root):
    (root / "Cargo.toml").write_text('[package]\nname = "rootyard"\n')
    (root / "Cargo.lock").write_text("lock\n")
    for relative in source.EXPLICIT_INPUTS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture %s\n" % relative)
    support = root / "scripts/pando_producer_pg/support.py"
    support.parent.mkdir(parents=True, exist_ok=True)
    support.write_text("SUPPORT = 1\n")


class ArtifactSelectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / "src/bin/rootyard-pando-lab.rs"
        self.src.parent.mkdir(parents=True)
        self.src.write_text("fn main() {}\n")
        self.deps = self.root / "target/debug/deps"
        self.deps.mkdir(parents=True)
        self.exe = self.deps / "rootyard_pando_lab-abc"
        self.exe.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.exe.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def event(self, fresh=False, executable=None, kind=None, test=True):
        return {
            "reason": "compiler-artifact",
            "target": {
                "name": "rootyard-pando-lab",
                "kind": list(kind or ["bin"]),
                "src_path": str(self.src),
            },
            "profile": {"test": test},
            "fresh": fresh,
            "executable": str(self.exe if executable is None else executable),
        }

    def run_selection(self, events):
        payload = b"\n".join(json.dumps(item).encode() for item in events) + b"\n"
        runner = FakeRunner([Result(0, payload, b"")])
        return artifacts.select_test_binary(self.root, runner, 5), runner

    def assert_code(self, events, code):
        with self.assertRaises(process.RunnerError) as caught:
            self.run_selection(events)
        self.assertEqual(caught.exception.code, code)

    def test_selects_one_fresh_bin_test_executable(self):
        selection, runner = self.run_selection(
            [self.event(fresh=True), {"reason": "build-finished", "success": True}]
        )
        self.assertEqual(selection["fresh"], True)
        self.assertEqual(selection["target"], "rootyard-pando-lab")
        self.assertEqual(selection["profile"], {"test": True})
        self.assertEqual(
            selection["executable_sha256"], hashlib.sha256(self.exe.read_bytes()).hexdigest()
        )
        self.assertNotIn("--", runner.calls[0][0])
        self.assertEqual(selection["executable_path"], str(self.exe))
        self.assertEqual(
            runner.calls[0][1]["cwd"], str(self.root.resolve())
        )

    def test_selects_pinned_fork_new_build_dir_out_layout(self):
        out = (
            self.root
            / "target/cargo-fork-cache/targets/rootyard-abc/debug/build"
            / "rootyard-pando-lab/abc123/out"
        )
        out.mkdir(parents=True)
        executable = out / "rootyard_pando_lab-abc123"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        selection, _ = self.run_selection(
            [
                self.event(executable=executable),
                {"reason": "build-finished", "success": True},
            ]
        )
        self.assertNotEqual(executable.parent.name, "deps")
        self.assertEqual(selection["executable_path"], str(executable))
        self.assertEqual(
            selection["executable_sha256"],
            hashlib.sha256(executable.read_bytes()).hexdigest(),
        )

    def test_profile_test_false_is_not_a_bin_test_artifact(self):
        self.assert_code(
            [self.event(test=False), {"reason": "build-finished", "success": True}],
            "artifact_profile",
        )

    def test_lib_artifact_is_not_accepted(self):
        self.assert_code(
            [self.event(kind=["lib"]), {"reason": "build-finished", "success": True}],
            "artifact_kind",
        )

    def test_multiple_candidates_fail(self):
        self.assert_code(
            [self.event(), self.event(), {"reason": "build-finished", "success": True}],
            "artifact_ambiguous",
        )

    def test_missing_candidate_fails(self):
        self.assert_code(
            [{"reason": "build-finished", "success": True}], "artifact_missing"
        )

    def test_missing_or_unsuccessful_build_finished_fails(self):
        self.assert_code([self.event()], "build_not_finished")
        self.assert_code(
            [self.event(), {"reason": "build-finished", "success": False}],
            "build_failed",
        )

    def test_wrong_target_source_is_not_accepted(self):
        other = self.root / "src/bin/other.rs"
        other.write_text("fn main() {}\n")
        event = self.event()
        event["target"]["src_path"] = str(other)
        self.assert_code([event, {"reason": "build-finished", "success": True}],
                         "artifact_source_missing")

    def test_missing_executable_fails(self):
        event = self.event()
        event["executable"] = None
        self.assert_code([event, {"reason": "build-finished", "success": True}],
                         "artifact_executable")

    def test_normal_cli_path_is_not_accepted(self):
        normal = self.root / "target/debug/rootyard-pando-lab"
        normal.write_bytes(b"#!/bin/sh\n")
        normal.chmod(0o755)
        self.assert_code(
            [self.event(executable=normal), {"reason": "build-finished", "success": True}],
            "artifact_executable",
        )

    def test_symlinked_executable_is_rejected(self):
        link = self.deps / "rootyard_pando_lab-link"
        link.symlink_to(self.exe)
        self.assert_code(
            [self.event(executable=link), {"reason": "build-finished", "success": True}],
            "artifact_executable",
        )

    def test_non_executable_test_binary_is_rejected(self):
        self.exe.chmod(0o644)
        self.assert_code(
            [self.event(), {"reason": "build-finished", "success": True}],
            "artifact_executable",
        )

    def test_non_boolean_fresh_is_rejected(self):
        event = self.event()
        event["fresh"] = "yes"
        self.assert_code([event, {"reason": "build-finished", "success": True}],
                         "artifact_fresh_invalid")

    def test_invalid_json_and_nonzero_cargo_fail_closed(self):
        runner = FakeRunner([Result(0, b"not-json\n", b"")])
        with self.assertRaises(process.RunnerError) as caught:
            artifacts.select_test_binary(self.root, runner, 5)
        self.assertEqual(caught.exception.code, "cargo_output_invalid")
        runner = FakeRunner([Result(1, b"", b"")])
        with self.assertRaises(process.RunnerError) as caught:
            artifacts.select_test_binary(self.root, runner, 5)
        self.assertEqual(caught.exception.code, "cargo_failed")

    def test_executable_digest_drift_is_detected(self):
        selection, _ = self.run_selection(
            [self.event(), {"reason": "build-finished", "success": True}]
        )
        self.exe.write_bytes(b"#!/bin/sh\nexit 1\n")
        with self.assertRaises(process.RunnerError) as caught:
            artifacts.verify_selected_binary(selection)
        self.assertEqual(caught.exception.code, "binary_changed")


class SourceBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write_tree(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def capture(self, fake_state=None, environ=None):
        with mock.patch.object(source, "git_state", return_value=fake_state or state()):
            return source.capture(self.root, COMMIT, environ={} if environ is None else environ)

    def test_capture_binds_inventory_lock_schema_and_runner_sources(self):
        binding = self.capture()
        self.assertEqual(binding["source_commit"], COMMIT)
        self.assertEqual(binding["source_tree"], TREE)
        self.assertRegex(binding["source_inputs_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            binding["cargo_lock_sha256"],
            hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest(),
        )
        self.assertEqual(
            binding["schema_sha256"],
            hashlib.sha256((self.root / source.SCHEMA_REL).read_bytes()).hexdigest(),
        )
        paths = {row["path"] for row in binding["input_hashes"]}
        self.assertIn("src/pando_lab/migration/pg_tests.rs", paths)
        self.assertIn(source.SOURCE_CAPTURE_CHILD_REL, paths)
        self.assertIn(source.SOURCE_CAPTURE_ADAPTER_REL, paths)
        runner_paths = {row["path"] for row in binding["runner_source_hashes"]}
        self.assertIn("scripts/run_pando_producer_pg.py", runner_paths)
        self.assertIn(source.SOURCE_CAPTURE_CHILD_REL, runner_paths)
        self.assertTrue(any(row.startswith("tests/test_pando_producer_pg") for row in runner_paths))

    def test_commit_tree_clean_mismatches_fail(self):
        with self.assertRaises(process.RunnerError) as caught:
            self.capture(state(commit="c" * 40))
        self.assertEqual(caught.exception.code, "commit_mismatch")
        with self.assertRaises(process.RunnerError) as caught:
            self.capture(state(clean=False))
        self.assertEqual(caught.exception.code, "source_not_clean")
        with mock.patch.object(source, "git_state", return_value=state()):
            with self.assertRaises(process.RunnerError) as caught:
                source.capture(self.root, COMMIT, expected_tree="c" * 40, environ={})
        self.assertEqual(caught.exception.code, "tree_mismatch")

    def test_source_drift_is_detected_and_truth_is_retained(self):
        before = self.capture()
        (self.root / "src/pando_lab/mod.rs").write_text("changed\n")
        after = self.capture()
        self.assertFalse(source.same(before, after))
        with self.assertRaises(process.RunnerError) as caught:
            source.verify_unchanged(before, after)
        self.assertEqual(caught.exception.code, "source_drift")
        self.assertNotEqual(
            before["source_inputs_sha256"], after["source_inputs_sha256"]
        )

    def test_capture_failure_does_not_echo_receipt_message(self):
        secret = "postgresql://user:password@127.0.0.1/db"
        with mock.patch.object(
            source, "capture_bound_inputs", side_effect=receipts.ReceiptError(secret)
        ):
            with self.assertRaises(process.RunnerError) as caught:
                self.capture()
        self.assertEqual(caught.exception.code, "source_capture_failed")
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("password", str(caught.exception))

    def test_product_receipt_is_same_source_only(self):
        receipt = self.root / "pando.build.json"
        receipt.write_text("{}\n")
        validated = SimpleNamespace(
            workspace_commit=COMMIT,
            source_inputs_sha256="d" * 64,
            receipt_sha256="e" * 64,
            artifacts=({"target": "rootyard-pando-lab", "kind": "bin"},),
        )
        with mock.patch.object(source, "load_receipt", return_value=validated):
            result = source.validate_product_receipt(
                receipt, self.root, COMMIT, "d" * 64
            )
        self.assertTrue(result["same_source"])
        self.assertFalse(result["used_as_test_binary_receipt"])
        self.assertFalse(result["attached_to_native_gate"])
        with mock.patch.object(source, "load_receipt", return_value=validated):
            with self.assertRaises(process.RunnerError) as caught:
                source.validate_product_receipt(receipt, self.root, COMMIT, "f" * 64)
        self.assertEqual(caught.exception.code, "product_receipt_source_mismatch")
        absent = source.validate_product_receipt(None, self.root, COMMIT, "d" * 64)
        self.assertFalse(absent["provided"])


class UnreapPopen(StreamingPopen):
    def kill(self):
        pass


class ProcessOwnershipTest(unittest.TestCase):
    def runner_for(self, fake, group=None):
        return process.ProcessRunner(
            popen=lambda *args, **kwargs: fake,
            thread_factory=FakeThread,
            killpg=group or GroupKiller(),
        )

    def test_timeout_kills_and_reaps_before_failure(self):
        fake = StreamingPopen(block=True)
        group = GroupKiller()
        runner = self.runner_for(fake, group)
        with self.assertRaises(process.RunnerError) as caught:
            runner.run(["cargo"], timeout=0.05, stage="selection",
                       timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())
        self.assertEqual(group.calls[0][0], fake.pid)

    def test_spawn_failure_is_fixed(self):
        def fail(*args, **kwargs):
            raise OSError("secret path /tmp/dsn")

        runner = process.ProcessRunner(popen=fail)
        with self.assertRaises(process.RunnerError) as caught:
            runner.run(["cargo"], timeout=1)
        self.assertEqual(caught.exception.code, "process_spawn_failed")
        self.assertNotIn("secret", str(caught.exception))

    def test_unreaped_process_is_not_reported_as_clean(self):
        fake = UnreapPopen(block=True)
        runner = self.runner_for(fake)
        with self.assertRaises(process.RunnerError) as caught:
            runner.run(["cargo"], timeout=0.05, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "process_unreaped")
        self.assertEqual(caught.exception.primary_code, "cargo_timeout")


if __name__ == "__main__":
    unittest.main()
