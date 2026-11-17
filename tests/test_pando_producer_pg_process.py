#!/usr/bin/env python3
"""Pure streaming-output and process-group ownership regressions.

No real process, thread, pipe, Git command, compiler, database or network is
used.  The Popen/thread/group-kill seams are deterministic fakes with in-memory
byte streams.
"""
from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import pando_producer_pg.process as process  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402


class FakeThread:
    """Synchronous fake reader/writer thread; never creates an OS thread."""

    def __init__(self, target=None, name=None, daemon=None, **kwargs):
        self.target = target
        self.name = name
        self.daemon = daemon
        self.started = False
        self.joined = False
        self.alive = False
        self.run_target = True

    def start(self):
        if not self.run_target:
            self.alive = True
            return
        self.started = True
        self.alive = True
        try:
            self.target()
        finally:
            self.alive = False

    def join(self, timeout=None):
        self.joined = True

    def is_alive(self):
        return self.alive


class NoRunThread(FakeThread):
    """Reader appears alive forever because a descendant keeps the pipe open."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.run_target = False


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class SlowStartThread(FakeThread):
    def __init__(self, clock, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock

    def start(self):
        self.started = True
        self.alive = True
        self.clock.advance(6)

    def join(self, timeout=None):
        self.joined = True
        self.alive = False


class RecordingThread(FakeThread):
    def __init__(self, records, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = records

    def start(self):
        self.started = True
        self.alive = True

    def join(self, timeout=None):
        self.records.append(timeout)
        self.joined = True

    def is_alive(self):
        return True


class DeferredThread(FakeThread):
    """Reader does not run until join, reproducing late drain interleavings."""

    def start(self):
        self.started = True
        self.alive = True

    def join(self, timeout=None):
        if not self.joined:
            self.joined = True
            try:
                self.target()
            finally:
                self.alive = False


class LateErrorStream:
    def __init__(self):
        self.closed = False

    def read(self, size):
        raise OSError("late reader failure")

    def close(self):
        self.closed = True


class StartFailThread(FakeThread):
    def start(self):
        raise RuntimeError("reader start failed")


class RecordingStdin:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)

    def flush(self):
        pass

    def close(self):
        self.closed = True

    def getvalue(self):
        return bytes(self.data)


class StreamingPopen:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, pid=4242, block=False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.stdin = RecordingStdin()
        self.returncode = returncode
        self.pid = pid
        self.block = block
        self.killed = False
        self.closed = False
        self._poll = None if block else returncode

    def wait(self, timeout=None):
        if self.block and not self.killed:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def poll(self):
        return self._poll

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._poll = -9


class ExitAtDeadlinePopen(StreamingPopen):
    def __init__(self, clock, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock

    def wait(self, timeout=None):
        self.returncode = 0
        self._poll = 0
        self.clock.advance(5)
        return 0


class GroupKiller:
    def __init__(self, fail=False, remains=False):
        self.fail = fail
        self.remains = remains
        self.calls = []

    def __call__(self, pgid, sig):
        self.calls.append((pgid, sig))
        if sig == 0:
            if self.remains:
                return None
            raise ProcessLookupError()
        if self.fail:
            raise PermissionError("denied")
        return None


def stream_runner(fake, thread_factory=FakeThread, group=None):
    return process.ProcessRunner(
        popen=lambda *args, **kwargs: fake,
        thread_factory=thread_factory,
        killpg=group or GroupKiller(),
    )


class StreamingBudgetTest(unittest.TestCase):
    def test_fast_oversized_dual_stream_is_bounded_total(self):
        fake = StreamingPopen(stdout=b"a" * 4000, stderr=b"b" * 4000)
        result = stream_runner(fake).run(
            ["fixture"],
            timeout=5,
            max_stdout=2048,
            max_stderr=2048,
            max_total=2048,
        )
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 2048)
        self.assertTrue(result.output_exceeded)
        self.assertTrue(result.stdout_truncated or result.stderr_truncated)
        self.assertEqual(result.returncode, 0)

    def test_total_cap_boundary_and_fail_mode(self):
        exact = StreamingPopen(stdout=b"a" * 1024)
        result = stream_runner(exact).run(
            ["fixture"], timeout=5, max_stdout=1024, max_stderr=1024,
            max_total=1024,
        )
        self.assertEqual(result.stdout, b"a" * 1024)
        self.assertFalse(result.output_exceeded)

        over = StreamingPopen(stdout=b"a" * 1025)
        with self.assertRaises(RunnerError) as caught:
            stream_runner(over).run(
                ["fixture"], timeout=5, max_stdout=1024, max_stderr=1024,
                max_total=1024, fail_on_output_exceeded=True,
                output_code="source_capture_failed",
            )
        self.assertEqual(caught.exception.code, "source_capture_failed")

    def test_reader_startup_interruption_is_fixed_and_reaped(self):
        fake = StreamingPopen(stdout=b"x")
        runner = stream_runner(fake, thread_factory=StartFailThread)
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_failed")
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())

    def test_blocked_pipe_reader_failure_is_fixed(self):
        class BlockingStream:
            def read(self, size):
                raise BlockingIOError("would block")

        fake = StreamingPopen()
        fake.stdout = BlockingStream()
        with self.assertRaises(RunnerError) as caught:
            stream_runner(fake).run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_failed")

    def test_nonzero_and_input_are_preserved(self):
        fake = StreamingPopen(stdout=b"out", returncode=7)
        result = stream_runner(fake).run(
            ["fixture"], timeout=5, input=b"schema"
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"out")
        self.assertEqual(fake.stdin.getvalue(), b"schema")


class DeferredDrainTest(unittest.TestCase):
    def test_deferred_overflow_during_join_cannot_be_accepted(self):
        fake = StreamingPopen(
            stdout=b'{"ok":true}\n', stderr=b"x" * 2048
        )
        group = GroupKiller()
        runner = process.ProcessRunner(
            popen=lambda *args, **kwargs: fake,
            thread_factory=DeferredThread,
            killpg=group,
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(
                ["fixture"],
                timeout=5,
                max_stdout=1024,
                max_stderr=1024,
                max_total=1024,
                fail_on_output_exceeded=True,
                output_code="source_capture_failed",
            )
        self.assertEqual(caught.exception.code, "source_capture_failed")
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())

    def test_deferred_reader_error_during_join_cannot_be_accepted(self):
        fake = StreamingPopen(stdout=b'{"ok":true}\n')
        fake.stderr = LateErrorStream()
        runner = process.ProcessRunner(
            popen=lambda *args, **kwargs: fake,
            thread_factory=DeferredThread,
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_failed")
        self.assertTrue(fake.killed)

    def test_deferred_overflow_ordinary_mode_keeps_truncation(self):
        fake = StreamingPopen(
            stdout=b'{"ok":true}\n', stderr=b"x" * 2048
        )
        result = process.ProcessRunner(
            popen=lambda *args, **kwargs: fake,
            thread_factory=DeferredThread,
            killpg=GroupKiller(),
        ).run(
            ["fixture"],
            timeout=5,
            max_stdout=1024,
            max_stderr=1024,
            max_total=1024,
        )
        self.assertTrue(result.output_exceeded)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)
        self.assertFalse(fake.killed)


class AbsoluteBudgetTest(unittest.TestCase):
    def test_late_popen_fails_and_reaps_before_reader_start(self):
        clock = FakeClock()
        fake = StreamingPopen()
        started = {"threads": 0}

        def popen(*args, **kwargs):
            clock.advance(6)
            return fake

        def factory(*args, **kwargs):
            started["threads"] += 1
            return FakeThread(*args, **kwargs)

        runner = process.ProcessRunner(
            clock=clock,
            popen=popen,
            thread_factory=factory,
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertEqual(started["threads"], 0)
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())

    def test_late_thread_start_fails_before_wait(self):
        clock = FakeClock()
        fake = StreamingPopen()
        runner = process.ProcessRunner(
            clock=clock,
            popen=lambda *args, **kwargs: fake,
            thread_factory=lambda *args, **kwargs: SlowStartThread(
                clock, *args, **kwargs
            ),
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertTrue(fake.killed)

    def test_deadline_passed_at_direct_exit_is_not_success(self):
        clock = FakeClock()
        fake = ExitAtDeadlinePopen(clock)
        runner = process.ProcessRunner(
            clock=clock,
            popen=lambda *args, **kwargs: fake,
            thread_factory=FakeThread,
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertTrue(fake.killed)

    def test_drain_and_cleanup_share_one_operation_deadline(self):
        clock = FakeClock()
        fake = StreamingPopen(returncode=0)
        records = []
        runner = process.ProcessRunner(
            clock=clock,
            popen=lambda *args, **kwargs: fake,
            thread_factory=lambda *args, **kwargs: RecordingThread(
                records, *args, **kwargs
            ),
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_unreaped")
        self.assertEqual(records, [5.0, 7.0])
        self.assertTrue(fake.killed)


class GroupOwnershipTest(unittest.TestCase):
    def test_timeout_group_absence_is_verified(self):
        fake = StreamingPopen(block=True)
        group = GroupKiller()
        runner = stream_runner(fake, group=group)
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=0.05, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())

    def test_group_kill_failure_is_unverified_with_primary_context(self):
        fake = StreamingPopen(block=True)
        group = GroupKiller(fail=True)
        runner = stream_runner(fake, group=group)
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=0.05, timeout_code="cargo_timeout")
        self.assertEqual(caught.exception.code, "process_group_unverified")
        self.assertEqual(caught.exception.primary_code, "cargo_timeout")
        self.assertTrue(fake.killed)

    def test_leader_exit_with_descendant_and_group_failure_is_unverified(self):
        fake = StreamingPopen(returncode=0)
        group = GroupKiller(fail=True)
        runner = stream_runner(fake, thread_factory=NoRunThread, group=group)
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_group_unverified")
        self.assertEqual(caught.exception.primary_code, "process_unreaped")
        self.assertTrue(fake.killed)
        self.assertEqual(len(group.calls), 1)

    def test_leader_exit_with_descendant_is_not_false_success(self):
        fake = StreamingPopen(returncode=0)
        group = GroupKiller()
        runner = stream_runner(fake, thread_factory=NoRunThread, group=group)
        with self.assertRaises(RunnerError) as caught:
            runner.run(["fixture"], timeout=5)
        self.assertEqual(caught.exception.code, "process_unreaped")
        self.assertTrue(fake.killed)


if __name__ == "__main__":
    unittest.main()
