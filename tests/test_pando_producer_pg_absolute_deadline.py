#!/usr/bin/env python3
"""Pure absolute-deadline regressions for the private producer-PG runner.

No real process, thread, pipe, Git command, compiler, database or network is
used.  The Popen/thread/group-kill seams are deterministic in-memory fakes.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.process as process  # noqa: E402
from pando_producer_pg.errors import CODES, RunnerError  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeClock,
    FakeThread,
    GroupKiller,
    StreamingPopen,
)


class AdvancingPopen(StreamingPopen):
    """Consume each requested wait slice, then report timeout until killed."""

    def __init__(self, clock, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock
        self.wait_timeouts = []

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if timeout is not None:
            self.clock.advance(timeout)
        if self.killed:
            self.returncode = -9
            self._poll = -9
            return -9
        raise subprocess.TimeoutExpired("fake", timeout)


class RecordingFactory:
    def __init__(self, fake=None):
        self.fake = fake
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fake is None:
            raise AssertionError("unexpected Popen")
        return self.fake


def clock_at(value):
    clock = FakeClock()
    clock.now = float(value)
    return clock


def make_runner(clock, factory, threads=None):
    def thread_factory(*args, **kwargs):
        thread = FakeThread(*args, **kwargs)
        if threads is not None:
            threads.append(thread)
        return thread

    return process.ProcessRunner(
        clock=clock,
        popen=factory,
        thread_factory=thread_factory,
        killpg=GroupKiller(),
    )


def run_runner(runner, argv=("fixture",), **kwargs):
    with mock.patch.object(process, "POLL_SECONDS", 100.0):
        return runner.run(list(argv), **kwargs)


class AbsoluteDeadlineMathTest(unittest.TestCase):
    def test_absolute_operation_and_cleanup_clamp_the_relative_cap(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        factory = RecordingFactory(fake)
        threads = []
        runner = make_runner(clock, factory, threads)
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=100,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=7,
                timeout_code="cargo_timeout",
            )
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertEqual(fake.wait_timeouts[0], 5.0)
        self.assertLessEqual(fake.wait_timeouts[-1], 2.0)
        self.assertLessEqual(clock(), 7.0)
        self.assertEqual(len(factory.calls), 1)
        self.assertTrue(all(thread.started for thread in threads))

    def test_smaller_relative_cap_is_preserved(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        runner = make_runner(clock, RecordingFactory(fake))
        with self.assertRaises(RunnerError):
            run_runner(
                runner,
                timeout=2,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=7,
            )
        self.assertEqual(fake.wait_timeouts[0], 2.0)
        self.assertLessEqual(clock(), 4.0)

    def test_cleanup_absolute_deadline_clamps_the_two_second_reserve(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        runner = make_runner(clock, RecordingFactory(fake))
        with self.assertRaises(RunnerError):
            run_runner(
                runner,
                timeout=100,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=6,
            )
        self.assertEqual(fake.wait_timeouts[0], 5.0)
        self.assertEqual(fake.wait_timeouts[-1], 1.0)
        self.assertLessEqual(clock(), 6.0)

    def test_defaults_none_keep_relative_timeout_and_two_second_reserve(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        runner = make_runner(clock, RecordingFactory(fake))
        with self.assertRaises(RunnerError):
            run_runner(runner, timeout=5)
        self.assertEqual(fake.wait_timeouts[0], 5.0)
        self.assertEqual(fake.wait_timeouts[-1], 2.0)
        self.assertLessEqual(clock(), 7.0)

    def test_cleanup_before_operation_deadline_is_rejected(self):
        for operation, cleanup in ((5, 4), (10, 9), (0.5, 0.25)):
            with self.subTest(operation=operation, cleanup=cleanup):
                clock = FakeClock()
                factory = RecordingFactory(None)
                runner = make_runner(clock, factory)
                with self.assertRaises(RunnerError) as caught:
                    run_runner(
                        runner,
                        timeout=5,
                        absolute_operation_deadline=operation,
                        absolute_cleanup_deadline=cleanup,
                    )
                self.assertEqual(caught.exception.code, "timeout_invalid")
                self.assertEqual(factory.calls, [])

    def test_cleanup_only_before_resolved_operation_deadline_is_rejected(self):
        clock = FakeClock()
        factory = RecordingFactory(None)
        runner = make_runner(clock, factory)
        with self.assertRaises(RunnerError) as caught:
            run_runner(runner, timeout=10, absolute_cleanup_deadline=5)
        self.assertEqual(caught.exception.code, "timeout_invalid")
        self.assertEqual(factory.calls, [])

    def test_invalid_absolute_deadlines_fail_before_any_popen(self):
        for name, value in (
            ("absolute_operation_deadline", True),
            ("absolute_operation_deadline", "5"),
            ("absolute_operation_deadline", float("nan")),
            ("absolute_operation_deadline", float("inf")),
            ("absolute_operation_deadline", 10 ** 1000),
            ("absolute_cleanup_deadline", False),
            ("absolute_cleanup_deadline", "5"),
            ("absolute_cleanup_deadline", float("nan")),
            ("absolute_cleanup_deadline", float("inf")),
            ("absolute_cleanup_deadline", 10 ** 1000),
        ):
            with self.subTest(name=name, value=value):
                clock = FakeClock()
                factory = RecordingFactory(None)
                runner = make_runner(clock, factory)
                with self.assertRaises(RunnerError) as caught:
                    run_runner(runner, timeout=5, **{name: value})
                self.assertEqual(caught.exception.code, "invalid_arguments")
                self.assertIn(caught.exception.code, CODES)
                self.assertEqual(factory.calls, [])

    def test_negative_absolute_deadline_is_valid_but_expired(self):
        clock = clock_at(0)
        factory = RecordingFactory(None)
        runner = make_runner(clock, factory)
        with self.assertRaises(RunnerError) as caught:
            run_runner(runner, timeout=5, absolute_operation_deadline=-1)
        self.assertEqual(caught.exception.code, "process_timeout")
        self.assertEqual(factory.calls, [])


class PrePopenDeadlineTest(unittest.TestCase):
    def test_late_entry_refuses_before_popen_and_thread_start(self):
        clock = clock_at(100)
        factory = RecordingFactory(None)
        threads = []
        runner = make_runner(clock, factory, threads)
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=100,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=7,
                timeout_code="cargo_timeout",
            )
        self.assertEqual(caught.exception.code, "cargo_timeout")
        self.assertEqual(factory.calls, [])
        self.assertEqual(threads, [])

    def test_entry_at_exact_absolute_operation_deadline_refuses(self):
        clock = clock_at(5)
        factory = RecordingFactory(None)
        runner = make_runner(clock, factory)
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=100,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=7,
            )
        self.assertEqual(caught.exception.code, "process_timeout")
        self.assertEqual(factory.calls, [])

    def test_failures_do_not_echo_argv_env_or_raw_text(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        runner = make_runner(clock, RecordingFactory(fake))
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                argv=["secret-argv"],
                env={"SECRET": "secret-env"},
                timeout=100,
                absolute_operation_deadline=1,
                absolute_cleanup_deadline=2,
            )
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("secret", repr(caught.exception))


class AbsoluteCleanupRegressionTest(unittest.TestCase):
    def test_group_unverified_primary_is_preserved_with_absolute_cleanup(self):
        clock = FakeClock()
        fake = AdvancingPopen(clock)
        runner = process.ProcessRunner(
            clock=clock,
            popen=RecordingFactory(fake),
            thread_factory=FakeThread,
            killpg=GroupKiller(fail=True),
        )
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=100,
                absolute_operation_deadline=1,
                absolute_cleanup_deadline=2,
                timeout_code="cargo_timeout",
            )
        self.assertEqual(caught.exception.code, "process_group_unverified")
        self.assertEqual(caught.exception.primary_code, "cargo_timeout")
        self.assertTrue(fake.killed)

    def test_output_overflow_primary_is_preserved_with_absolute_deadlines(self):
        clock = FakeClock()
        fake = StreamingPopen(stdout=b"a" * 2048)
        runner = make_runner(clock, RecordingFactory(fake))
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=100,
                max_stdout=1024,
                max_stderr=1024,
                max_total=1024,
                fail_on_output_exceeded=True,
                output_code="source_capture_failed",
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=7,
            )
        self.assertEqual(caught.exception.code, "source_capture_failed")
        self.assertTrue(fake.killed)

    def test_late_join_with_absolute_cleanup_fails_closed(self):
        class NeverDoneThread(FakeThread):
            def start(self):
                self.started = True
                self.alive = True

            def is_alive(self):
                return True

        clock = FakeClock()
        fake = AdvancingPopen(clock, returncode=0)
        runner = process.ProcessRunner(
            clock=clock,
            popen=RecordingFactory(fake),
            thread_factory=NeverDoneThread,
            killpg=GroupKiller(),
        )
        with self.assertRaises(RunnerError) as caught:
            run_runner(
                runner,
                timeout=5,
                absolute_operation_deadline=5,
                absolute_cleanup_deadline=6,
            )
        self.assertEqual(caught.exception.code, "process_unreaped")
        self.assertTrue(fake.killed)
        self.assertLessEqual(clock(), 6.0)


if __name__ == "__main__":
    unittest.main()
