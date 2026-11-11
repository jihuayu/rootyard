#!/usr/bin/env python3
"""Focused unit tests for the Browse deadline case's `/proc` group check.

No native binary, PostgreSQL, Cargo or live Git is required.  These tests
drive the same parser and `/proc` scan that `tests/browse.py` uses to prove a
delayed Git process group is quiescent, matching the service's rule that a
group is quiescent only when no member is in a state other than Z/X.
"""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browse import BrowseHarness  # noqa: E402

HARNESS = object.__new__(BrowseHarness)


def proc_stat(pid, comm, state, pgrp, ppid=1):
    """Kernel-style `/proc/<pid>/stat`: `comm` is verbatim between parentheses."""
    rest = [
        state, ppid, pgrp,
        0, 0, 0, 0, 0, 0, 0, 0, 0,  # pgrp..cmin_flt
        0, 0,     # maj_flt, cmaj_flt
        0, 0, 0, 0, 0, 0,  # utime..processor
        0, 0, 0,  # rt_priority, policy, delayacct_blkio_ticks
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # guest_time..exit_code
    ]
    return f"{pid} ({comm}) " + " ".join(str(value) for value in rest) + "\n"


class ProcStatParseTest(unittest.TestCase):
    def test_comm_with_spaces_and_closing_parentheses(self):
        text = proc_stat(4242, 'git (deadline) x) )', "R", 4240)
        self.assertEqual(HARNESS._parse_proc_stat(text), ("R", 4240))

    def test_states_and_process_group_after_comm(self):
        for state in ("R", "S", "D", "T", "Z", "X", "I"):
            self.assertEqual(
                HARNESS._parse_proc_stat(proc_stat(7, "sleep", state, 9)), (state, 9)
            )

    def test_malformed_stat_is_not_a_member(self):
        for text in ("", "7 git R 1 7", "7 (truncated) R", "7 (comm) R x"):
            self.assertIsNone(HARNESS._parse_proc_stat(text), text)


class LiveGroupMembersTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proc = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, pid, state, pgrp, comm="git"):
        directory = self.proc / str(pid)
        directory.mkdir()
        (directory / "stat").write_text(proc_stat(pid, comm, state, pgrp))

    def members(self, pgid):
        return HARNESS._live_group_members(pgid, proc_root=str(self.proc))

    def test_zombies_and_dead_are_quiescent_running_is_not(self):
        self.write(10, "S", 10, comm="sh (wrapper)")
        self.write(11, "Z", 10, comm="sleep 0.7")
        self.write(12, "X", 10)
        self.write(13, "R", 99)
        self.write(14, "S", 10, comm="git rev-parse")
        self.assertEqual(self.members(10), [10, 14])
        self.assertEqual(self.members(11), [])

    def test_only_zombies_prove_quiescence(self):
        self.write(20, "S", 20)
        self.write(21, "Z", 20, comm="sleep")
        self.assertEqual(self.members(20), [20])
        (self.proc / "20" / "stat").unlink()
        self.assertEqual(self.members(20), [])

    def test_disappearing_stat_is_gone_not_live(self):
        self.write(30, "R", 30)
        self.assertEqual(self.members(30), [30])
        (self.proc / "30" / "stat").unlink()
        self.assertEqual(self.members(30), [])

    def test_unreadable_stat_is_an_error_not_quiescence(self):
        self.write(40, "R", 40)
        (self.proc / "40" / "stat").chmod(0)
        try:
            if os.access(self.proc / "40" / "stat", os.R_OK):
                self.skipTest("running as a user that bypasses file permissions")
            with self.assertRaisesRegex(AssertionError, "PermissionError"):
                self.members(40)
        finally:
            (self.proc / "40" / "stat").chmod(0o600)


if __name__ == "__main__":
    unittest.main()
