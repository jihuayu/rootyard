#!/usr/bin/env python3
"""Pure counterexamples for the shared absolute deadline and command bounds.

Only fake monotonic clocks, fake Popen/thread/group seams and injected fake
process runners are used.  No process, thread, network, container, database or
filesystem child is started.
"""
from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from pando_producer_pg.errors import RunnerError  # noqa: E402
import pando_producer_pg.process as process_module  # noqa: E402
import pando_vault_rotation_budget as budget_mod  # noqa: E402
from pando_vault_rotation_budget import Budget, DeadlineError  # noqa: E402
from pando_vault_rotation_command import (  # noqa: E402
    CLEANUP_RESERVE_SECONDS,
    BoundedCommandRunner,
    CommandError,
)


class FakeClock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)
        return self.now


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.argv = ("fake",)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeProcessRunner:
    """No process is created; one scripted clock/result per call."""

    def __init__(self, clock, script):
        self.clock = clock
        self.script = list(script)
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        if not self.script:
            raise AssertionError("unexpected process call")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        if callable(action):
            return action(self.clock)
        return action


class BudgetDeadlineTest(unittest.TestCase):
    def test_defaults_leave_a_work_window_under_the_external_step(self):
        clock = FakeClock()
        budget = Budget(
            budget_mod.DEFAULT_TOTAL_SECONDS,
            budget_mod.DEFAULT_CLEANUP_RESERVE_SECONDS,
            clock=clock,
        )
        self.assertEqual(budget.overall_deadline, 1080.0)
        self.assertEqual(budget.work_deadline, 990.0)
        self.assertLess(budget.overall_deadline, 1200.0)

    def test_invalid_finite_bounds_fail_before_any_io(self):
        clock = FakeClock()
        for total, reserve in (
            (0, 90), (-1, 90), (float("inf"), 90), (float("nan"), 90),
            (1201, 90), (100, 100), (100, 80), (100, -1),
        ):
            with self.subTest(total=total, reserve=reserve):
                with self.assertRaises(DeadlineError) as caught:
                    Budget(total, reserve, clock=clock)
                self.assertEqual(caught.exception.code, "timeout_invalid")
                self.assertEqual(clock.now, 0.0)

    def test_same_deadline_is_reused_and_cleanup_does_not_reset_it(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock)
        work = budget.work_deadline
        overall = budget.overall_deadline
        self.assertEqual(budget.clamp(90, "case"), 80.0)
        clock.advance(30)
        self.assertEqual(budget.clamp(90, "case"), 50.0)
        budget.begin_cleanup()
        self.assertEqual(budget.work_deadline, work)
        self.assertEqual(budget.overall_deadline, overall)
        self.assertEqual(budget.clamp(90, "cleanup"), 70.0)
        clock.advance(60)
        self.assertEqual(budget.clamp(90, "cleanup", reserve=2.0), 8.0)
        self.assertEqual(budget.remaining_overall(), 10.0)
        clock.advance(10)
        self.assertEqual(budget.remaining_overall(), 0.0)

    def test_expired_work_fails_closed_before_a_start(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock)
        started = []
        clock.advance(80)
        with self.assertRaises(DeadlineError) as caught:
            budget.clamp(90, "case")
            started.append(True)
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(started, [])

    def test_work_expiry_still_leaves_the_cleanup_reserve(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock)
        clock.advance(80)
        with self.assertRaises(DeadlineError) as caught:
            budget.clamp(90, "case")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        budget.begin_cleanup()
        self.assertEqual(budget.clamp(30, "cleanup", reserve=2.0), 18.0)

    def test_late_boundary_recheck_prevents_success(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock)
        clock.advance(80)
        with self.assertRaises(DeadlineError) as caught:
            budget.late("case")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        clock.advance(20)
        with self.assertRaises(DeadlineError) as caught:
            budget.late_overall("report")
        self.assertEqual(caught.exception.code, "overall_deadline_exceeded")

    def test_error_factory_is_used_for_every_fixed_refusal(self):
        class FixedError(Exception):
            def __init__(self, code, stage=None):
                self.code = code
                self.stage = stage

        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=FixedError)
        clock.advance(80)
        with self.assertRaises(FixedError) as caught:
            budget.require("case")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(caught.exception.stage, "case")


class DeadlineModelRunner:
    """Fake approved runner that records the absolute deadlines it receives."""

    def __init__(self, clock, handoff=0.0, finish="operation"):
        self.clock = clock
        self.handoff = float(handoff)
        self.finish = finish
        self.calls = []
        self.operation_deadline = None
        self.cleanup_deadline = None

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        self.clock.advance(self.handoff)
        timeout = kwargs["timeout"]
        operation_deadline = kwargs.get("absolute_operation_deadline")
        if operation_deadline is None:
            operation_deadline = self.clock() + timeout
        cleanup_deadline = kwargs.get("absolute_cleanup_deadline")
        if cleanup_deadline is None:
            cleanup_deadline = operation_deadline + CLEANUP_RESERVE_SECONDS
        self.operation_deadline = operation_deadline
        self.cleanup_deadline = cleanup_deadline
        target = (
            cleanup_deadline if self.finish == "cleanup"
            else operation_deadline
        )
        if target > self.clock():
            self.clock.advance(target - self.clock())
        return Result()


class ImmediateThread:
    """Synchronous fake thread; never creates an OS thread."""

    def __init__(self, target=None, name=None, daemon=None, **kwargs):
        self.target = target
        self.started = False
        self.joined = False
        self.alive = False

    def start(self):
        self.started = True
        self.alive = True
        try:
            if self.target is not None:
                self.target()
        finally:
            self.alive = False

    def join(self, timeout=None):
        self.joined = True

    def is_alive(self):
        return self.alive


class AdvancingPopen:
    """In-memory child whose wait slices consume the fake clock."""

    def __init__(self, clock):
        self.clock = clock
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self.stdin = None
        self.pid = 4242
        self.returncode = 0
        self._poll = 0
        self.killed = False
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

    def poll(self):
        return self._poll

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._poll = -9


class GroupKiller:
    def __call__(self, pgid, sig):
        if sig == 0:
            raise ProcessLookupError()
        return None


class PopenFactory:
    def __init__(self, fake):
        self.fake = fake
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.fake


class HandoffRunner:
    """Advance the caller clock before entering the real approved runner."""

    def __init__(self, clock, delay, inner):
        self.clock = clock
        self.delay = delay
        self.inner = inner
        self.entered = False

    def run(self, argv, **kwargs):
        self.entered = True
        self.clock.advance(self.delay)
        return self.inner.run(argv, **kwargs)


class BoundedCommandTest(unittest.TestCase):
    def _runner(self, clock, script, budget):
        process = FakeProcessRunner(clock, script)
        return BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=process), process

    def test_operation_budget_is_clamped_by_an_absolute_deadline(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, process = self._runner(clock, [Result()], budget)
        clock.advance(30)
        command.run(["psql"], timeout=90, stage="database")
        _argv, kwargs = process.calls[0]
        self.assertEqual(kwargs["timeout"], 90)
        self.assertEqual(kwargs["absolute_operation_deadline"], 78.0)
        self.assertEqual(kwargs["absolute_cleanup_deadline"], 80.0)
        self.assertEqual(kwargs["stage"], "execute")
        self.assertTrue(kwargs["fail_on_output_exceeded"])

    def test_cleanup_keeps_the_reap_reserve_inside_the_overall_deadline(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, process = self._runner(clock, [Result()], budget)
        clock.advance(80)
        budget.begin_cleanup()
        command.run(["docker", "rm"], timeout=30, stage="cleanup")
        _argv, kwargs = process.calls[0]
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["absolute_operation_deadline"], 98.0)
        self.assertEqual(kwargs["absolute_cleanup_deadline"], 100.0)

    def test_smaller_per_operation_cap_is_preserved(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        model = DeadlineModelRunner(clock)
        command = BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=model)
        command.run(["git", "push"], timeout=5, stage="git")
        _argv, kwargs = model.calls[0]
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["absolute_operation_deadline"], 5.0)
        self.assertEqual(kwargs["absolute_cleanup_deadline"], 7.0)

    def test_late_return_after_blocking_call_is_not_success(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)

        def late_success(now):
            now.advance(80)
            return Result()

        command, _process = self._runner(clock, [late_success], budget)
        with self.assertRaises(CommandError) as caught:
            command.run(["docker", "inspect"], timeout=90, stage="docker")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(caught.exception.stage, "docker")

    def test_output_overflow_and_unreaped_are_fixed_failures(self):
        for internal, expected in (
            ("process_output_exceeded", "subprocess_output_exceeded"),
            ("process_unreaped", "subprocess_unreaped"),
            ("process_group_unverified", "subprocess_group_unverified"),
        ):
            with self.subTest(internal=internal):
                clock = FakeClock()
                budget = Budget(100, 20, clock=clock, error_factory=CommandError)
                command, _process = self._runner(
                    clock, [RunnerError("execute", internal)], budget)
                with self.assertRaises(CommandError) as caught:
                    command.run(["git", "fsck"], timeout=90, stage="git")
                self.assertEqual(caught.exception.code, expected)

    def test_original_command_failure_survives_a_late_clock(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)

        def timeout_after_deadline(now):
            now.advance(90)
            raise RunnerError("execute", "process_timeout")

        command, _process = self._runner(
            clock, [timeout_after_deadline], budget)
        with self.assertRaises(CommandError) as caught:
            command.run(["git", "push"], timeout=90, stage="git")
        self.assertEqual(caught.exception.code, "subprocess_timeout")
        self.assertEqual(caught.exception.stage, "git")

    def test_expired_budget_never_starts_the_approved_runner(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, process = self._runner(clock, [], budget)
        clock.advance(80)
        with self.assertRaises(CommandError) as caught:
            command.run(["docker", "pull"], timeout=300, stage="docker")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(process.calls, [])

    def test_no_operation_window_before_the_reap_reserve_fails_closed(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, process = self._runner(clock, [], budget)
        clock.advance(78.5)  # work deadline is 80; reserve needs 2 seconds
        with self.assertRaises(CommandError) as caught:
            command.run(["git", "push"], timeout=30, stage="git")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(process.calls, [])

    def test_unresolved_child_flag_is_set_only_for_unreaped_groups(self):
        for internal, expected_flag in (
            ("process_unreaped", True),
            ("process_group_unverified", True),
            ("process_timeout", False),
            ("process_output_exceeded", False),
        ):
            with self.subTest(internal=internal):
                clock = FakeClock()
                budget = Budget(
                    100, 20, clock=clock, error_factory=CommandError)
                command, _process = self._runner(
                    clock, [RunnerError("execute", internal)], budget)
                with self.assertRaises(CommandError):
                    command.run(["git", "push"], timeout=90, stage="git")
                self.assertEqual(
                    command.unresolved_children, expected_flag)

    def test_successful_reaped_command_leaves_no_unresolved_child(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, _process = self._runner(clock, [Result()], budget)
        command.run(["git", "fsck"], timeout=90, stage="git")
        self.assertFalse(command.unresolved_children)

    def test_work_absolute_deadline_keeps_the_full_cleanup_window(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(980)
        model = DeadlineModelRunner(clock, handoff=0.02)
        command = BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=model)
        command.run(["git", "push"], timeout=30, stage="git")
        _argv, kwargs = model.calls[0]
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["absolute_operation_deadline"], 988.0)
        self.assertEqual(kwargs["absolute_cleanup_deadline"], 990.0)
        self.assertLessEqual(model.cleanup_deadline, budget.work_deadline)
        self.assertGreaterEqual(
            budget.overall_deadline - model.cleanup_deadline, 90.0)

    def test_work_edge_uses_exactly_the_90_second_reserve(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(980)
        model = DeadlineModelRunner(clock, handoff=0.05, finish="cleanup")
        command = BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=model)
        with self.assertRaises(CommandError) as caught:
            command.run(["git", "push"], timeout=30, stage="git")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(model.cleanup_deadline, budget.work_deadline)
        self.assertEqual(budget.remaining_overall(), 90.0)

    def test_cleanup_absolute_deadline_ends_within_overall(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(1000)
        budget.begin_cleanup()
        model = DeadlineModelRunner(clock, handoff=0.02)
        command = BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=model)
        command.run(["docker", "rm"], timeout=100, stage="cleanup")
        _argv, kwargs = model.calls[0]
        self.assertEqual(kwargs["timeout"], 100)
        self.assertEqual(kwargs["absolute_operation_deadline"], 1078.0)
        self.assertEqual(kwargs["absolute_cleanup_deadline"], 1080.0)
        self.assertLessEqual(
            model.cleanup_deadline, budget.overall_deadline)
        self.assertGreaterEqual(budget.remaining_overall(), 0.0)


class ActualHandoffTest(unittest.TestCase):
    def _command(self, clock, budget, delay):
        fake = AdvancingPopen(clock)
        factory = PopenFactory(fake)
        inner = process_module.ProcessRunner(
            clock=clock,
            popen=factory,
            thread_factory=ImmediateThread,
            killpg=GroupKiller(),
        )
        handoff = HandoffRunner(clock, delay, inner)
        command = BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=handoff)
        return command, handoff, fake, factory

    def test_50ms_and_60ms_handoffs_end_at_work_deadline(self):
        for delay in (0.05, 0.06):
            with self.subTest(delay=delay):
                clock = FakeClock()
                budget = Budget(
                    1080, 90, clock=clock, error_factory=CommandError)
                clock.advance(980)
                command, handoff, fake, factory = self._command(
                    clock, budget, delay)
                with mock.patch.object(
                    process_module, "POLL_SECONDS", 100.0
                ):
                    with self.assertRaises(CommandError) as caught:
                        command.run(["git", "push"], timeout=30, stage="git")
                self.assertTrue(handoff.entered)
                self.assertEqual(caught.exception.code, "subprocess_timeout")
                self.assertEqual(caught.exception.stage, "git")
                self.assertEqual(len(factory.calls), 1)
                self.assertEqual(
                    fake.wait_timeouts[0], 988.0 - (980.0 + delay))
                self.assertEqual(fake.wait_timeouts[-1], 2.0)
                self.assertLessEqual(clock.now, 990.0)
                self.assertEqual(budget.remaining_overall(), 90.0)
                self.assertFalse(command.unresolved_children)

    def test_100s_handoff_refuses_before_popen(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(980)
        command, handoff, _fake, factory = self._command(
            clock, budget, 100.0)
        with self.assertRaises(CommandError) as caught:
            command.run(["git", "push"], timeout=30, stage="git")
        self.assertTrue(handoff.entered)
        self.assertEqual(caught.exception.code, "subprocess_timeout")
        self.assertEqual(factory.calls, [])
        self.assertEqual(clock.now, 1080.0)
        self.assertEqual(budget.remaining_overall(), 0.0)
        self.assertFalse(command.unresolved_children)

    def test_handoff_at_exact_operation_deadline_refuses_before_popen(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(980)
        command, _handoff, _fake, factory = self._command(
            clock, budget, 8.0)
        with self.assertRaises(CommandError) as caught:
            command.run(["git", "push"], timeout=30, stage="git")
        self.assertEqual(caught.exception.code, "subprocess_timeout")
        self.assertEqual(factory.calls, [])

    def test_cleanup_phase_handoff_ends_at_overall_deadline(self):
        clock = FakeClock()
        budget = Budget(1080, 90, clock=clock, error_factory=CommandError)
        clock.advance(1000)
        budget.begin_cleanup()
        command, _handoff, fake, factory = self._command(
            clock, budget, 0.02)
        with mock.patch.object(process_module, "POLL_SECONDS", 100.0):
            with self.assertRaises(CommandError) as caught:
                command.run(["docker", "rm"], timeout=100, stage="cleanup")
        self.assertEqual(caught.exception.code, "subprocess_timeout")
        self.assertEqual(len(factory.calls), 1)
        self.assertEqual(fake.wait_timeouts[0], 1078.0 - 1000.02)
        self.assertEqual(fake.wait_timeouts[-1], 2.0)
        self.assertLessEqual(clock.now, 1080.0)
        self.assertEqual(budget.remaining_overall(), 0.0)


if __name__ == "__main__":
    unittest.main()
