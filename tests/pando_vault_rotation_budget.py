#!/usr/bin/env python3
"""One absolute monotonic deadline shared by the whole Vault rotation harness.

The harness has one overall deadline ``D`` established before any input is
validated.  A fixed cleanup reserve is subtracted exactly once to obtain the
work deadline; cleanup is allowed to use the whole ``D``.  Nothing in this
module resets either deadline per case, phase or operation.

Every blocking boundary receives ``min(existing operation cap, remaining)``.
An expired budget fails closed before a child/Popen/HTTP/server start, and a
late return after a non-preemptible OS, filesystem or Popen boundary is checked
again before success is recorded.  Those boundaries are explicitly not claimed
as wall-clock guarantees: only the deadline check around them is.

Only clocks, fixed codes and numeric values are handled here; no argv,
environment value, SQL, provider body, path or raw child text is retained.
"""
from __future__ import annotations

import math
import time

DEFAULT_TOTAL_SECONDS = 1080.0
DEFAULT_CLEANUP_RESERVE_SECONDS = 90.0
MAX_TOTAL_SECONDS = 1200.0
MIN_WORK_SECONDS = 30.0
MIN_REAP_SECONDS = 2.0

WORK_DEADLINE_EXCEEDED = "work_deadline_exceeded"
CLEANUP_DEADLINE_EXCEEDED = "cleanup_deadline_exceeded"
OVERALL_DEADLINE_EXCEEDED = "overall_deadline_exceeded"
DEADLINE_CODES = (
    WORK_DEADLINE_EXCEEDED,
    CLEANUP_DEADLINE_EXCEEDED,
    OVERALL_DEADLINE_EXCEEDED,
)
DEADLINE_STAGES = ("input", "binding", "setup", "case", "cleanup", "report")


class DeadlineError(RuntimeError):
    """A fixed deadline failure without any caller-supplied text."""

    def __init__(self, code, stage=None):
        self.code = code
        self.stage = stage
        super().__init__(code)


def _finite(value, code="timeout_invalid"):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
    ):
        raise DeadlineError(code, "input")
    return float(value)


class Budget:
    """One immutable pair of deadlines plus a work/cleanup phase marker.

    ``clock`` is injected so tests can advance time without sleeping.  The
    phase may move from ``work`` to ``cleanup`` exactly once; neither deadline
    nor the recorded start changes, so there is no fresh per-case budget.
    """

    def __init__(
        self,
        total_seconds,
        cleanup_reserve_seconds,
        *,
        clock=time.monotonic,
        error_factory=None,
    ):
        total = _finite(total_seconds)
        reserve = _finite(cleanup_reserve_seconds)
        if total <= 0 or total > MAX_TOTAL_SECONDS:
            raise DeadlineError("timeout_invalid", "input")
        if reserve < 0 or reserve >= total:
            raise DeadlineError("timeout_invalid", "input")
        if total - reserve < MIN_WORK_SECONDS:
            raise DeadlineError("timeout_invalid", "input")
        if clock is None:
            raise DeadlineError("timeout_invalid", "input")
        self.error_factory = error_factory or DeadlineError
        self.clock = clock
        self.total_seconds = total
        self.cleanup_reserve_seconds = reserve
        self.started = clock()
        self.overall_deadline = self.started + total
        self.work_deadline = self.overall_deadline - reserve
        self.phase = "work"

    def begin_cleanup(self):
        """Enter the reserve phase; the absolute deadlines are not changed."""
        self.phase = "cleanup"
        return self

    @property
    def in_cleanup(self):
        return self.phase == "cleanup"

    def _fail(self, code, stage):
        raise self.error_factory(code, stage or "input")

    def _deadline_code(self):
        if self.clock() >= self.overall_deadline:
            return OVERALL_DEADLINE_EXCEEDED
        if self.phase == "cleanup":
            return CLEANUP_DEADLINE_EXCEEDED
        return WORK_DEADLINE_EXCEEDED

    @property
    def deadline(self):
        return self.overall_deadline if self.in_cleanup else self.work_deadline

    def remaining(self):
        """Seconds left in the current phase, never negative."""
        return max(0.0, self.deadline - self.clock())

    def remaining_work(self):
        return max(0.0, self.work_deadline - self.clock())

    def remaining_overall(self):
        return max(0.0, self.overall_deadline - self.clock())

    def expired(self):
        return self.clock() >= self.deadline

    def expired_overall(self):
        return self.clock() >= self.overall_deadline

    def require(self, stage=None):
        """Fail closed before a start, or return the remaining phase budget."""
        if self.clock() >= self.overall_deadline:
            self._fail(OVERALL_DEADLINE_EXCEEDED, stage)
        if self.phase == "work" and self.clock() >= self.work_deadline:
            self._fail(WORK_DEADLINE_EXCEEDED, stage)
        return self.remaining()

    def clamp(self, requested, stage=None, reserve=0.0):
        """Return ``min(requested, remaining - reserve)`` or fail closed.

        ``requested`` is the existing smaller per-operation cap.  This method
        never increases it; it only lowers it to the shared absolute budget.
        """
        cap = _finite(requested)
        if cap <= 0:
            self._fail("timeout_invalid", stage)
        remaining = self.require(stage)
        slack = _finite(reserve)
        if slack < 0 or slack >= remaining:
            self._fail(self._deadline_code(), stage)
        return min(cap, remaining - slack)

    def late(self, stage=None):
        """Recheck a phase boundary after a non-preemptible call."""
        self.require(stage)
        return True

    def late_overall(self, stage=None):
        if self.clock() >= self.overall_deadline:
            self._fail(OVERALL_DEADLINE_EXCEEDED, stage)
        return True
