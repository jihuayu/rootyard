#!/usr/bin/env python3
"""Pure source-root cwd regressions for Cargo selection and the 17 harness runs.

No Cargo, compiler, Git, PostgreSQL, Vault, Docker, network or real child process
is used.  The Popen layer and all runner stages are deterministic fakes; the only
filesystem trees are temporary fixtures.
"""
from __future__ import annotations

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

import pando_producer_pg.artifacts as artifacts  # noqa: E402
import pando_producer_pg.cases as cases  # noqa: E402
import pando_producer_pg.process as process  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
from pando_producer_pg.process import Completed  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeThread,
    GroupKiller,
    StreamingPopen,
)

BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"


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


def write_source_tree(root):
    source = root / "src/bin/rootyard-pando-lab.rs"
    source.parent.mkdir(parents=True)
    source.write_text("fn main() {}\n")
    deps = root / "target/debug/deps"
    deps.mkdir(parents=True)
    executable = deps / "rootyard_pando_lab-abc"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    return source, executable


def cargo_payload(executable, source_path):
    event = {
        "reason": "compiler-artifact",
        "target": {
            "name": "rootyard-pando-lab",
            "kind": ["bin"],
            "src_path": str(source_path),
        },
        "profile": {"test": True},
        "fresh": True,
        "executable": str(executable),
    }
    finished = {"reason": "build-finished", "success": True}
    return (json.dumps(event) + "\n" + json.dumps(finished) + "\n").encode()


class CargoSourceCwdTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "source"
        self.source, self.exe = write_source_tree(self.root)
        self.foreign = self.base / "foreign"
        self.foreign.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_relative_src_path_uses_the_actual_popen_source_cwd(self):
        payload = cargo_payload(
            self.exe, "src/bin/rootyard-pando-lab.rs"
        )
        recorded = {}

        def popen(argv, **kwargs):
            recorded["argv"] = list(argv)
            recorded["kwargs"] = dict(kwargs)
            return StreamingPopen(stdout=payload)

        selection = artifacts.select_test_binary(
            self.root,
            process.ProcessRunner(
                popen=popen,
                thread_factory=FakeThread,
                killpg=GroupKiller(),
            ),
            5,
            deadline=100,
            clock=lambda: 0,
        )
        self.assertEqual(recorded["kwargs"]["cwd"], str(self.root.resolve()))
        self.assertEqual(selection["source"], artifacts.EXPECTED_SOURCE)
        self.assertEqual(selection["executable_path"], str(self.exe))

    def test_differing_parent_cwd_cannot_attribute_the_foreign_workspace(self):
        foreign_source = self.foreign / artifacts.EXPECTED_SOURCE
        foreign_source.parent.mkdir(parents=True)
        foreign_source.write_text("fn foreign() {}\n")
        payload = cargo_payload(self.exe, "src/bin/rootyard-pando-lab.rs")
        fake = FakeRunner([Result(0, payload, b"")])
        previous = Path.cwd()
        try:
            os.chdir(self.foreign)
            selection = artifacts.select_test_binary(
                self.root, fake, 5, deadline=100, clock=lambda: 0
            )
        finally:
            os.chdir(previous)
        self.assertEqual(
            fake.calls[0][1]["cwd"], str(self.root.resolve())
        )
        self.assertEqual(selection["source"], artifacts.EXPECTED_SOURCE)
        self.assertEqual(selection["executable_path"], str(self.exe))

    def test_foreign_or_out_of_root_src_path_is_rejected(self):
        payload = cargo_payload(
            self.exe, str(self.foreign / artifacts.EXPECTED_SOURCE)
        )
        fake = FakeRunner([Result(0, payload, b"")])
        with self.assertRaises(RunnerError) as caught:
            artifacts.select_test_binary(
                self.root, fake, 5, deadline=100, clock=lambda: 0
            )
        self.assertEqual(caught.exception.code, "artifact_source_outside")
        payload = cargo_payload(
            self.exe, "../foreign/src/bin/rootyard-pando-lab.rs"
        )
        fake = FakeRunner([Result(0, payload, b"")])
        with self.assertRaises(RunnerError) as caught:
            artifacts.select_test_binary(
                self.root, fake, 5, deadline=100, clock=lambda: 0
            )
        self.assertEqual(caught.exception.code, "artifact_source_outside")


class HarnessSourceCwdTest(unittest.TestCase):
    def test_all_seventeen_cases_receive_the_source_cwd(self):
        source_cwd = "/tmp/source-root"
        responses = [
            Completed([], 0, (
                "running 1 test\n"
                "test %s ... ok\n\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.01s\n" % name
            ).encode(), b"")
            for name in cases.CASE_NAMES
        ]
        fake = FakeRunner(responses)
        records = cases.execute_cases(
            "/tmp/owned/deps/rootyard_pando_lab-abc",
            {},
            fake,
            work_deadline=1000,
            case_timeout=30,
            clock=lambda: 0,
            cwd=source_cwd,
        )
        self.assertEqual(len(records), 17)
        self.assertTrue(all(row["status"] == "passed" for row in records))
        for _, kwargs in fake.calls:
            self.assertEqual(kwargs["cwd"], source_cwd)

    def test_runner_passes_resolved_source_root_to_the_harness(self):
        source = Path("/tmp/relative-parent/source")
        config = runner.Config(
            source_root=source,
            expected_commit="b" * 40,
            expected_tree="c" * 40,
            report=Path("/tmp/report.json"),
            product_receipt=Path("/tmp/pando-product.json"),
            total_seconds=100.0,
            cleanup_reserve_seconds=20.0,
            selection_timeout_seconds=10.0,
            setup_timeout_seconds=10.0,
            case_timeout_seconds=5.0,
            prepare_only=False,
        )
        binding = {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
            "source_clean": True,
            "source_inputs_sha256": "d" * 64,
            "bound_inputs_sha256": "e" * 64,
            "cargo_lock_sha256": "f" * 64,
            "schema_sha256": "1" * 64,
            "input_hashes": [],
            "runner_source_hashes": [],
        }
        selection = {
            "target": "rootyard-pando-lab", "kind": ["bin"],
            "profile": {"test": True}, "features": ["panda-lab"],
            "command": ["cargo", "test"], "fresh": True,
            "source": "src/bin/rootyard-pando-lab.rs",
            "executable_path": "/tmp/owned/deps/rootyard_pando_lab-abc",
            "executable_sha256": "a" * 64,
            "executable": {"executable_name": "fake", "sha256": "a" * 64,
                           "size": 1, "st_dev": 1, "st_ino": 1,
                           "mtime_ns": 1},
        }
        records = cases.not_run_records()
        for row in records:
            row.update(
                status="passed", executed=True, exit_code=0, passed=1,
                code="passed",
            )
        captured = {}

        def execute(*args, **kwargs):
            captured.update(kwargs)
            return records

        fixture = SimpleNamespace(
            root=SimpleNamespace(path=Path("/tmp/owned-root")),
            child_environment={},
            start=lambda deadline: None,
            cleanup=lambda deadline: {
                "cleanup_ok": True,
                "postgres_dropped": True,
                "database_absent": True,
                "root_removed": True,
                "root_absent": True,
                "cleanup_within_deadline": True,
            },
        )
        with mock.patch.object(
            runner.artifacts, "verify_selected_binary", return_value={}
        ):
            payload = runner.run(
                config,
                runner=object(),
                clock=lambda: 0.0,
                capture_source=lambda *args, **kwargs: dict(binding),
                select_binary=lambda *args, **kwargs: dict(selection),
                fixture_factory=lambda *args, **kwargs: fixture,
                execute_cases_fn=execute,
                write_report_fn=lambda *args, **kwargs: None,
                validate_product=lambda *args, **kwargs: {
                    "provided": True,
                    "same_source": True,
                    "used_as_test_binary_receipt": False,
                    "attached_to_native_gate": False,
                },
                environ={"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP},
            )
        self.assertEqual(captured["cwd"], str(source.resolve()))
        self.assertTrue(payload["source_bindings"]["source_cwd_bound"])

    def test_process_runner_forwards_cwd_to_popen(self):
        recorded = {}

        def popen(argv, **kwargs):
            recorded.update(kwargs)
            return StreamingPopen(stdout=b"")

        process.ProcessRunner(
            popen=popen,
            thread_factory=FakeThread,
            killpg=GroupKiller(),
        ).run(["fixture"], cwd="/tmp/source-root", timeout=5)
        self.assertEqual(recorded["cwd"], "/tmp/source-root")


if __name__ == "__main__":
    unittest.main()
