#!/usr/bin/env python3
"""Pure regression: a drain that finishes after the operation deadline fails."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.process as process  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeClock,
    FakeThread,
    GroupKiller,
    StreamingPopen,
)


class JoinAtThread(FakeThread):
    """Report stopped only after the join advances the shared clock."""

    def __init__(self, clock, at, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock
        self.at = at
        self.did_join = False

    def start(self):
        self.started = True
        self.alive = True

    def join(self, timeout=None):
        if not self.did_join:
            self.did_join = True
            self.clock.now = self.at
            self.target()
        self.alive = False
        self.joined = True


def runner_at(clock, at):
    return process.ProcessRunner(
        clock=clock,
        popen=lambda *args, **kwargs: StreamingPopen(returncode=0),
        thread_factory=lambda *args, **kwargs: JoinAtThread(
            clock, at, *args, **kwargs
        ),
        killpg=GroupKiller(),
    )


class PostJoinDeadlineTest(unittest.TestCase):
    def test_drain_finishing_after_deadline_is_timeout(self):
        clock = FakeClock()
        with self.assertRaises(RunnerError) as caught:
            runner_at(clock, 6).run(
                ["fixture"], timeout=5, timeout_code="cargo_timeout"
            )
        self.assertEqual(caught.exception.code, "cargo_timeout")

    def test_drain_at_exact_deadline_is_timeout(self):
        clock = FakeClock()
        with self.assertRaises(RunnerError) as caught:
            runner_at(clock, 5).run(
                ["fixture"], timeout=5, timeout_code="cargo_timeout"
            )
        self.assertEqual(caught.exception.code, "cargo_timeout")

    def test_drain_just_before_deadline_is_completed(self):
        clock = FakeClock()
        result = runner_at(clock, 4.9).run(
            ["fixture"], timeout=5, timeout_code="cargo_timeout"
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
