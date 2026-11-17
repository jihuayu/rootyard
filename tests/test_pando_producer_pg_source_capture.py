#!/usr/bin/env python3
"""Pure bounded source-capture adapter and reserved-cleanup regressions.

No Cargo, compiler, Git, PostgreSQL, Vault, Docker, network or real child process
is used.  The adapter is exercised with fake Popen/ProcessRunner objects and the
canonical binding shape is represented by a deterministic in-memory payload.
"""
from __future__ import annotations

import contextlib
import io
import json
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

import pando_producer_pg.cases as cases  # noqa: E402
import pando_producer_pg.process as process  # noqa: E402
import pando_producer_pg.source as source  # noqa: E402
import pando_producer_pg.source_capture as source_capture  # noqa: E402
import pando_producer_pg.source_capture_child as child  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
from pando_producer_pg.process import Completed  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeThread,
    GroupKiller,
    StreamingPopen,
)

BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"
BINARY = "/tmp/owned/target/debug/deps/rootyard_pando_lab-abc"
COMMIT = "a" * 40
TREE = "b" * 40


class FakeClock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class StepClock:
    def __init__(self, step=10.0):
        self.now = 0.0
        self.step = float(step)

    def __call__(self):
        self.now += self.step
        return self.now


def binding(commit=COMMIT, tree=TREE):
    rows = [
        {"path": source.SOURCE_CAPTURE_CHILD_REL, "sha256": "c" * 64},
        {"path": "scripts/run_pando_producer_pg.py", "sha256": "d" * 64},
        {"path": "tests/test_pando_producer_pg_runner.py", "sha256": "e" * 64},
    ]
    return {
        "source_commit": commit,
        "source_tree": tree,
        "source_clean": True,
        "expected_commit": commit,
        "expected_tree": tree,
        "source_inputs_sha256": "1" * 64,
        "bound_inputs_sha256": "2" * 64,
        "bound_inputs_present_count": 3,
        "bound_inputs_absent_count": 0,
        "cargo_lock_sha256": "3" * 64,
        "config_digest": "4" * 64,
        "schema_sha256": "5" * 64,
        "input_hashes": rows,
        "runner_source_hashes": rows,
    }


def success_payload(commit=COMMIT, tree=TREE):
    return json.dumps(
        {"ok": True, "binding": binding(commit, tree)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode() + b"\n"


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


class BoundedCaptureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = FakeClock(0)

    def tearDown(self):
        self.tmp.cleanup()

    def test_child_gets_explicit_cwd_and_reserved_timeout(self):
        fake = FakeRunner([Completed([], 0, success_payload(), b"")])
        result = source_capture.capture_bounded(
            self.root,
            COMMIT,
            expected_tree=TREE,
            environ={"KEEP": "1"},
            deadline=100,
            clock=self.clock,
            process_runner=fake,
        )
        argv, kwargs = fake.calls[0]
        self.assertEqual(kwargs["cwd"], str(self.root.resolve()))
        self.assertEqual(kwargs["timeout"], 98)
        self.assertEqual(kwargs["env"]["KEEP"], "1")
        self.assertEqual(kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(argv[1], str(source_capture.CHILD_SCRIPT))
        self.assertEqual(argv[2], str(self.root.resolve()))
        self.assertEqual(kwargs["max_stdout"], source_capture.MAX_BINDING_BYTES)
        self.assertEqual(kwargs["max_total"], source_capture.MAX_BINDING_BYTES)
        self.assertTrue(kwargs["fail_on_output_exceeded"])
        self.assertEqual(kwargs["output_code"], "source_capture_failed")
        self.assertEqual(result["source_commit"], COMMIT)
        self.assertEqual(
            result["input_hashes"][0]["path"],
            source.SOURCE_CAPTURE_CHILD_REL,
        )

    def test_capture_refuses_to_invade_the_reserved_window(self):
        fake = FakeRunner([])
        self.clock.now = 98
        with self.assertRaises(RunnerError) as caught:
            source_capture.capture_bounded(
                self.root,
                COMMIT,
                deadline=100,
                clock=self.clock,
                process_runner=fake,
            )
        self.assertEqual(
            caught.exception.code, "source_capture_deadline_exceeded"
        )
        self.assertEqual(fake.calls, [])

    def test_stalled_child_is_killed_reaped_and_fails_fixed(self):
        stall = StreamingPopen(block=True)
        process_runner = process.ProcessRunner(
            clock=StepClock(),
            popen=lambda *args, **kwargs: stall,
            thread_factory=FakeThread,
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            source_capture.capture_bounded(
                self.root,
                COMMIT,
                deadline=100,
                clock=self.clock,
                process_runner=process_runner,
            )
        self.assertEqual(
            caught.exception.code, "source_capture_deadline_exceeded"
        )
        self.assertTrue(stall.killed)
        self.assertIsNotNone(stall.poll())

    def test_invalid_oversized_or_unregistered_child_output_fails_fixed(self):
        for response in (
            Completed([], 0, b"not-json", b""),
            Completed([], 0, b"x" * (source_capture.MAX_BINDING_BYTES + 1), b""),
            Completed([], 1, success_payload(), b""),
            Completed([], 0, success_payload(), b"", output_exceeded=True),
            Completed([], 0, b'{"ok":false,"stage":"source","code":"raw text"}', b""),
        ):
            fake = FakeRunner([response])
            with self.assertRaises(RunnerError) as caught:
                source_capture.capture_bounded(
                    self.root,
                    COMMIT,
                    deadline=100,
                    clock=self.clock,
                    process_runner=fake,
                )
            self.assertEqual(caught.exception.code, "source_capture_failed")
            self.assertNotIn("raw text", str(caught.exception))

    def test_registered_child_failure_is_preserved(self):
        payload = b'{"ok":false,"stage":"source","code":"commit_mismatch"}\n'
        fake = FakeRunner([Completed([], 0, payload, b"")])
        with self.assertRaises(RunnerError) as caught:
            source_capture.capture_bounded(
                self.root,
                COMMIT,
                deadline=100,
                clock=self.clock,
                process_runner=fake,
            )
        self.assertEqual(caught.exception.code, "commit_mismatch")

    def test_group_unverified_child_status_is_preserved(self):
        fake = FakeRunner([
            RunnerError(
                "source",
                "process_group_unverified",
                primary_code="source_capture_deadline_exceeded",
            )
        ])
        with self.assertRaises(RunnerError) as caught:
            source_capture.capture_bounded(
                self.root,
                COMMIT,
                deadline=100,
                clock=self.clock,
                process_runner=fake,
            )
        self.assertEqual(caught.exception.code, "process_group_unverified")
        self.assertEqual(
            caught.exception.primary_code, "source_capture_deadline_exceeded"
        )

    def test_binding_shape_requires_helper_relative_rows_and_exact_anchor(self):
        missing_helper = binding()
        missing_helper["input_hashes"] = missing_helper["input_hashes"][1:]
        absolute = binding()
        absolute["input_hashes"][0]["path"] = "/tmp/foreign.py"
        wrong_commit = binding(commit="f" * 40)
        for item in (missing_helper, absolute, wrong_commit):
            payload = json.dumps({"ok": True, "binding": item}).encode()
            fake = FakeRunner([Completed([], 0, payload, b"")])
            with self.assertRaises(RunnerError) as caught:
                source_capture.capture_bounded(
                    self.root,
                    COMMIT,
                    deadline=100,
                    clock=self.clock,
                    process_runner=fake,
                )
            self.assertEqual(caught.exception.code, "source_capture_failed")

    def test_child_emits_only_fixed_failure_fields(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = child.run(
                ["child", str(self.root), COMMIT, ""],
                capture_fn=lambda *args, **kwargs: binding(),
            )
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["ok"])

        output = io.StringIO()
        def fail(*args, **kwargs):
            raise RunnerError("source", "commit_mismatch")

        with contextlib.redirect_stdout(output):
            child.run(["child", str(self.root), COMMIT, ""], capture_fn=fail)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"ok": False, "stage": "source", "code": "commit_mismatch"},
        )

        output = io.StringIO()
        def leak(*args, **kwargs):
            raise ValueError("secret /tmp/path")

        with contextlib.redirect_stdout(output):
            child.run(["child", str(self.root), COMMIT, ""], capture_fn=leak)
        text = output.getvalue()
        self.assertNotIn("secret", text)
        self.assertEqual(
            json.loads(text),
            {"ok": False, "stage": "source", "code": "source_capture_failed"},
        )


class TimeoutChild:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        self.clock.advance(kwargs["timeout"])
        raise RunnerError("source", "source_capture_deadline_exceeded")


def passing_records():
    rows = cases.not_run_records()
    for row in rows:
        row.update(
            status="passed", executed=True, exit_code=0, passed=1, code="passed"
        )
    return rows


class ReservedCleanupTest(unittest.TestCase):
    def test_final_capture_stall_enters_teardown_with_reserved_time(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        source_root = Path(tmp.name)
        clock = FakeClock(0)
        initial = binding()
        child_runner = TimeoutChild(clock)
        state = {"calls": 0}

        def capture(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] == 1:
                return dict(initial)
            kwargs.pop("process_runner", None)
            return source_capture.capture_bounded(
                *args, process_runner=child_runner, **kwargs
            )

        fixture = SimpleNamespace(
            root=SimpleNamespace(path=Path("/tmp/owned-root")),
            child_environment={},
            start=lambda deadline: None,
            cleanup=None,
        )
        cleaned = {}

        def cleanup(deadline):
            cleaned["deadline"] = deadline
            return {
                "cleanup_ok": True,
                "postgres_dropped": True,
                "database_absent": True,
                "root_removed": True,
                "root_absent": True,
                "cleanup_within_deadline": True,
            }

        fixture.cleanup = cleanup
        config = runner.Config(
            source_root=source_root,
            expected_commit=COMMIT,
            expected_tree=TREE,
            report=Path("/tmp/report.json"),
            product_receipt=Path("/tmp/pando-product.json"),
            total_seconds=100.0,
            cleanup_reserve_seconds=20.0,
            selection_timeout_seconds=10.0,
            setup_timeout_seconds=10.0,
            case_timeout_seconds=5.0,
            prepare_only=False,
        )
        writes = []
        with mock.patch.object(
            runner.artifacts, "verify_selected_binary", return_value={}
        ):
            payload = runner.run(
                config,
                runner=object(),
                clock=clock,
                capture_source=capture,
                select_binary=lambda *args, **kwargs: {
                    "target": "rootyard-pando-lab", "kind": ["bin"],
                    "profile": {"test": True}, "features": ["pando-lab"],
                    "command": ["cargo", "test"], "fresh": True,
                    "source": "src/bin/rootyard-pando-lab.rs",
                    "executable_path": BINARY, "executable_sha256": "a" * 64,
                    "executable": {"executable_name": "fake",
                                   "sha256": "a" * 64, "size": 1,
                                   "st_dev": 1, "st_ino": 1,
                                   "mtime_ns": 1},
                },
                fixture_factory=lambda *args, **kwargs: fixture,
                execute_cases_fn=lambda *args, **kwargs: passing_records(),
                write_report_fn=lambda path, payload, **kwargs: writes.append(
                    (path, payload)
                ),
                validate_product=lambda *args, **kwargs: {
                    "provided": True,
                    "same_source": True,
                    "used_as_test_binary_receipt": False,
                    "attached_to_native_gate": False,
                },
                environ={"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP},
            )
        self.assertFalse(payload["passed"])
        self.assertEqual(
            payload["error_code"], "source_recheck_deadline_exceeded"
        )
        self.assertFalse(payload["source_bindings"]["source_rechecked"])
        self.assertFalse(payload["fresh_verification"])
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(child_runner.calls), 1)
        self.assertEqual(child_runner.calls[0][1]["timeout"], 78)
        self.assertEqual(cleaned["deadline"], 100)
        self.assertEqual(clock.now, 78)


if __name__ == "__main__":
    unittest.main()
