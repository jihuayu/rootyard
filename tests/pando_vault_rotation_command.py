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
the call so a late return cannot be recorded as success.  The approved runner's
bounded post-operation reap (2 seconds) plus a small fixed call/hand-off margin
is reserved inside the current phase deadline, so the child's reap ends at or
before workD/cleanupD and the dedicated 90-second cleanup window is not
silently borrowed.  Existing per-operation caps and polls are preserved; this
reservation only lowers a call's timeout, never raises it or adds a retry.
"""
from __future__ import annotations

from pathlib import Path
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
HANDOFF_RESERVE_SECONDS = 0.05
_PHASE_RESERVE_SECONDS = CLEANUP_RESERVE_SECONDS + HANDOFF_RESERVE_SECONDS

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
        effective = timeout
        if self.budget is not None:
            # The approved runner adds its own 2-second reap window after the
            # operation deadline.  Reserve that window and a small call/handoff
            # margin inside the current phase so work reap ends no later than
            # workD and cleanup reap ends no later than overallD.  The fixed
            # margin is a fail-closed allowance, not a wall-clock claim for an
            # arbitrarily delayed handoff.
            effective = self.budget.clamp(
                timeout, stage, reserve=_PHASE_RESERVE_SECONDS)
        try:
            completed = self._runner.run(
                [str(item) for item in argv],
                env=env,
                input=input,
                timeout=effective,
                cwd=None if cwd is None else str(cwd),
                stage=_INTERNAL_STAGE,
                timeout_code="process_timeout",
                spawn_code="process_spawn_failed",
                fail_on_output_exceeded=True,
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
