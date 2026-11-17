#!/usr/bin/env python3
"""Pure counterexamples for the shared absolute deadline and command bounds.

Only a fake monotonic clock and an injected fake process runner are used.  No
process, thread, network, container, database or filesystem child is started.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from pando_producer_pg.errors import RunnerError  # noqa: E402
import pando_vault_rotation_budget as budget_mod  # noqa: E402
from pando_vault_rotation_budget import Budget, DeadlineError  # noqa: E402
from pando_vault_rotation_command import (  # noqa: E402
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


class BoundedCommandTest(unittest.TestCase):
    def _runner(self, clock, script, budget):
        process = FakeProcessRunner(clock, script)
        return BoundedCommandRunner(
            budget=budget, clock=clock, process_runner=process), process

    def test_operation_timeout_is_clamped_to_the_shared_budget(self):
        clock = FakeClock()
        budget = Budget(100, 20, clock=clock, error_factory=CommandError)
        command, process = self._runner(clock, [Result()], budget)
        clock.advance(30)
        command.run(["psql"], timeout=90, stage="database")
        _argv, kwargs = process.calls[0]
        self.assertEqual(kwargs["timeout"], 50.0)
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
        self.assertEqual(kwargs["timeout"], 18.0)

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


if __name__ == "__main__":
    unittest.main()
