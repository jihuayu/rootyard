#!/usr/bin/env python3
"""Owned, bounded subprocess execution for the Vault rotation harness.

This is a thin harness interface over the already source-approved private
producer-PG ``ProcessRunner``.  That runner creates one immediate ``Popen``,
retains the parent handles, owns a new process group, drains both pipes with one
aggregate in-memory ceiling, kills only the exact owned group, reaps and joins
before closing, and never replaces a primary failure with a cleanup outcome.

This module adds only the shared absolute deadline: each call is clamped to the
current remaining work/cleanup budget, the approved runner anchors its own
operation deadline before ``Popen``, and this interface rechecks the clock after
the call so a late return cannot be recorded as success.  The wrapper snapshots
the caller clock once, derives an absolute operation deadline and an absolute
cleanup deadline from the same phase deadline, and passes both to the approved
runner together with the unchanged per-operation cap.  The runner takes the
final ``min()`` before ``Popen``, so even a late hand-off cannot start a child
after the operation deadline and the bounded 2-second reap always ends at or
before workD/overallD.  There is no fixed hand-off margin and no fresh reader,
kill or reap window.  Existing per-operation caps and polls are preserved; the
absolute bounds only lower a call, never raise it, add a retry or borrow from
the dedicated 90-second cleanup window.
"""
from __future__ import annotations

from pathlib import Path
import math
import sys
import time

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pando_producer_pg.errors import RunnerError  # noqa: E402
from pando_producer_pg.process import (  # noqa: E402
    CLEANUP_RESERVE_SECONDS,
    ProcessRunner as _ApprovedProcessRunner,
)

# Harness stage names are not registered producer-PG stages.  The approved
# runner receives one of its own fixed stages; the harness keeps its stage in
# the translated code below.
_INTERNAL_STAGE = "execute"

_CODE_MAP = {
    "process_timeout": "subprocess_timeout",
    "process_unreaped": "subprocess_unreaped",
    "process_output_exceeded": "subprocess_output_exceeded",
    "process_group_unverified": "subprocess_group_unverified",
    "process_spawn_failed": "subprocess_failed",
    "process_failed": "subprocess_failed",
    "invalid_arguments": "subprocess_invalid_arguments",
}


class CommandError(RuntimeError):
    """A fixed, report-safe command failure code and harness stage."""

    def __init__(self, code, stage=None):
        self.code = code
        self.stage = stage
        super().__init__(code)


def _mapped_code(code):
    return _CODE_MAP.get(code, "subprocess_failed")


def _requested_timeout(timeout, stage, budget):
    """Validate the existing per-operation cap without taking a clock sample."""
    value = timeout
    valid = (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value > 0
    )
    if valid:
        try:
            valid = math.isfinite(value)
        except (OverflowError, TypeError):
            valid = False
    if not valid:
        raise budget.error_factory("timeout_invalid", stage)
    return float(value)


def _phase_deadline(budget, now, stage):
    """Mirror Budget's phase refusal using one caller-clock snapshot."""
    if now >= budget.overall_deadline:
        raise budget.error_factory("overall_deadline_exceeded", stage)
    if not budget.in_cleanup and now >= budget.work_deadline:
        raise budget.error_factory("work_deadline_exceeded", stage)
    deadline = (
        budget.overall_deadline if budget.in_cleanup else budget.work_deadline
    )
    if deadline - now <= CLEANUP_RESERVE_SECONDS:
        code = (
            "cleanup_deadline_exceeded"
            if budget.in_cleanup
            else "work_deadline_exceeded"
        )
        raise budget.error_factory(code, stage)
    return deadline


class BoundedCommandRunner:
    """One approved Popen per call under one shared absolute deadline."""

    def __init__(self, budget=None, clock=None, process_runner=None):
        self.budget = budget
        self.clock = clock or (
            getattr(budget, "clock", None) if budget is not None else None
        ) or time.monotonic
        self._runner = process_runner or _ApprovedProcessRunner(clock=self.clock)
        self.unresolved_children = False

    def run(
        self,
        argv,
        env=None,
        input=None,
        timeout=90,
        stage="subprocess",
        cwd=None,
    ):
        operation_deadline = None
        cleanup_deadline = None
        if self.budget is not None:
            # One caller-clock snapshot feeds the phase validation and both
            # absolute deadlines.  The original per-operation cap is passed
            # through; the approved runner takes the final min() and refuses
            # before Popen if an arbitrarily late hand-off already crossed the
            # absolute operation deadline.
            now = self.clock()
            requested = _requested_timeout(timeout, stage, self.budget)
            phase_deadline = _phase_deadline(self.budget, now, stage)
            operation_deadline = min(
                now + requested,
                phase_deadline - CLEANUP_RESERVE_SECONDS,
            )
            cleanup_deadline = min(
                operation_deadline + CLEANUP_RESERVE_SECONDS,
                phase_deadline,
            )
        try:
            completed = self._runner.run(
                [str(item) for item in argv],
                env=env,
                input=input,
                timeout=timeout,
                cwd=None if cwd is None else str(cwd),
                stage=_INTERNAL_STAGE,
                timeout_code="process_timeout",
                spawn_code="process_spawn_failed",
                fail_on_output_exceeded=True,
                absolute_operation_deadline=operation_deadline,
                absolute_cleanup_deadline=cleanup_deadline,
            )
        except RunnerError as error:
            code = _mapped_code(error.code)
            if code in ("subprocess_unreaped", "subprocess_group_unverified"):
                # A retained live writer/group means the private root cannot be
                # declared removed by cleanup.
                self.unresolved_children = True
            raise CommandError(code, stage) from None
        if self.budget is not None:
            # Popen, pipe readers and the final join are non-preemptible
            # boundaries.  The entire call is charged and a late return fails.
            self.budget.late(stage)
        return completed
