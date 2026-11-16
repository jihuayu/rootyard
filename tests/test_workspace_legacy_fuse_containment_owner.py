#!/usr/bin/env python3
"""Pure owner-liveness tests for legacy failure-containment children.

These tests use fake clocks, fake Popen handles, fake mountinfo and fake mount
disappearance observations. They never start a process, send a signal, enter a
namespace, read real /proc, use FUSE, service, PG, network or Docker.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from tests import workspace_legacy_fuse_shutdown_acceptance as acceptance
from tests import workspace_legacy_fuse_shutdown_ownership as ownership
from tests import workspace_legacy_fuse_shutdown_report as report
from tests import workspace_legacy_fuse_shutdown_support as support

MOUNTPOINT = "/fake/owned/workspace"
MOUNT_ID = 4242


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


class FakeChild:
    def __init__(
        self,
        pid=7001,
        returncode=None,
        exits_on_kill=False,
        exit_on_late_wait=False,
        wait_error=None,
        kill_error=None,
        poll_error=None,
    ):
        self.pid = pid
        self.returncode = returncode
        self.exits_on_kill = exits_on_kill
        self.exit_on_late_wait = exit_on_late_wait
        self.wait_error = wait_error
        self.kill_error = kill_error
        self.poll_error = poll_error
        self.waits = []
        self.kills = 0

    def poll(self):
        if self.poll_error is not None:
            raise self.poll_error
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.wait_error is not None:
            raise self.wait_error
        if self.returncode is not None:
            return self.returncode
        if timeout is None and self.exit_on_late_wait:
            self.returncode = 0
            return 0
        if timeout is None:
            return self.returncode
        raise subprocess.TimeoutExpired("owned-child", timeout)

    def kill(self):
        self.kills += 1
        if self.kill_error is not None:
            raise self.kill_error
        if self.exits_on_kill:
            self.returncode = 0


class FakeMounts:
    def __init__(self, clock=None, expire_after_read=False):
        self.clock = clock
        self.expire_after_read = expire_after_read
        self.reads = 0

    def __call__(self, _holder_pid):
        self.reads += 1
        if self.clock is not None and self.expire_after_read:
            self.clock.now = max(self.clock.now, 5.0)
        return [{
            "mountpoint": MOUNTPOINT,
            "mount_id": MOUNT_ID,
            "source": support.FUSE_SOURCE,
            "fstype": "fuse.rootyard",
        }]


class FakeSpawn:
    def __init__(self, child, clock=None, expire_to=5.0):
        self.child = child
        self.clock = clock
        self.expire_to = expire_to
        self.calls = []

    def __call__(self, _holder_pid, argv):
        self.calls.append(tuple(argv))
        if self.clock is not None:
            self.clock.now = max(self.clock.now, self.expire_to)
        return self.child


class FakeResult:
    def __init__(self):
        self.started_ids = list(acceptance.REQUIRED_CASES)
        self.failures = []
        self.errors = []
        self.skipped = []
        self.expectedFailures = []
        self.unexpectedSuccesses = []
        self.testsRun = len(self.started_ids)


def _contain(clock, child, spawn=None, mounts=None, wait_gone=None, owner=None):
    owner = owner or ownership.ContainmentOwner()
    if spawn is None:
        spawn = FakeSpawn(child)
    if mounts is None:
        mounts = FakeMounts()
    if wait_gone is None:
        def wait_gone(_holder_pid, _mountpoint, _mount_id, _deadline):
            return None
    return support.contain_proven_owned_mounts(
        holder_pid=9001,
        records=[(MOUNTPOINT, MOUNT_ID)],
        deadline=5.0,
        owner=owner,
        clock=clock,
        spawn=spawn,
        read_mountinfo=mounts,
        wait_mount_gone=wait_gone,
        read_identity=lambda _pid: None,
    ), owner


class ContainmentOwnerTest(unittest.TestCase):
    def test_expired_deadline_admits_no_child_and_fails_finite(self):
        clock = FakeClock(5.0)
        spawn = FakeSpawn(FakeChild())
        result, owner = _contain(clock, FakeChild(), spawn=spawn)
        self.assertEqual(spawn.calls, [])
        self.assertEqual(result["started"], 0)
        self.assertEqual(result["outcome"], "deadline_exhausted")
        self.assertTrue(result["failed"])
        self.assertEqual(owner.snapshot()["pending"], 0)

    def test_deadline_expiry_during_mount_validation_admits_no_child(self):
        clock = FakeClock(4.0)
        spawn = FakeSpawn(FakeChild())
        mounts = FakeMounts(clock=clock, expire_after_read=True)
        result, _owner = _contain(clock, FakeChild(), spawn=spawn, mounts=mounts)
        self.assertEqual(spawn.calls, [])
        self.assertEqual(result["outcome"], "deadline_exhausted")
        self.assertTrue(result["failed"])

    def test_child_crossing_deadline_is_registered_killed_and_reaped(self):
        clock = FakeClock(4.0)
        child = FakeChild(exits_on_kill=True)
        spawn = FakeSpawn(child, clock=clock, expire_to=5.0)
        result, owner = _contain(clock, child, spawn=spawn)
        self.assertEqual(len(spawn.calls), 1)
        self.assertEqual(child.kills, 1)
        self.assertEqual(result["started"], 1)
        self.assertEqual(result["reaped"], 1)
        self.assertEqual(owner.snapshot()["pending"], 0)
        self.assertGreaterEqual(owner.snapshot()["deadline_exhausted"], 1)
        self.assertTrue(result["failed"])

    def test_signal_negative_child_is_failed_without_foreign_signal(self):
        clock = FakeClock(1.0)
        child = FakeChild(returncode=-9)
        result, owner = _contain(clock, child)
        self.assertEqual(result["reaped"], 1)
        self.assertEqual(child.kills, 0)
        self.assertIn("nonzero_exit", owner.snapshot()["error_classes"])
        self.assertTrue(result["failed"])

    def test_wait_error_uses_exact_owned_kill_and_reap(self):
        clock = FakeClock(1.0)
        child = FakeChild(wait_error=RuntimeError("boom"), exits_on_kill=True)
        result, owner = _contain(clock, child)
        self.assertEqual(child.kills, 1)
        self.assertEqual(result["reaped"], 1)
        self.assertEqual(owner.snapshot()["pending"], 0)
        self.assertIn("RuntimeError", owner.snapshot()["error_classes"])
        self.assertTrue(result["failed"])

    def test_kill_error_retains_pending_without_foreign_pid_fallback(self):
        clock = FakeClock(1.0)
        child = FakeChild(
            wait_error=subprocess.TimeoutExpired("owned-child", 1.0),
            kill_error=ProcessLookupError("gone"),
        )
        with mock.patch("os.kill", side_effect=AssertionError("foreign kill")), \
                mock.patch("os.killpg", side_effect=AssertionError("group kill")), \
                mock.patch("os.getpgid", side_effect=AssertionError("pgid probe")):
            result, owner = _contain(clock, child)
        snapshot = owner.snapshot()
        self.assertEqual(child.kills, 1)
        self.assertEqual(snapshot["pending"], 1)
        self.assertEqual(snapshot["pending_children"][0]["state"], "pending")
        self.assertEqual(snapshot["pending_children"][0]["signal_error"], "ProcessLookupError")
        self.assertTrue(result["failed"])

    def test_already_exited_child_is_reaped_after_deadline(self):
        child = FakeChild(returncode=0)
        code = support._wait_exit(child, 0.0, clock=FakeClock(5.0), sleep=lambda _s: None)
        self.assertEqual(code, 0)
        owner = ownership.ContainmentOwner()
        record = owner.register(child, MOUNT_ID)
        self.assertEqual(owner.reap_owned_child(record, 0.0, clock=FakeClock(5.0)), 0)
        self.assertEqual(owner.snapshot()["pending"], 0)
        self.assertEqual(child.kills, 0)

    def test_reset_refuses_to_clear_pending_owner(self):
        owner = ownership.ContainmentOwner()
        owner.register(FakeChild(pid=7200), MOUNT_ID)
        with self.assertRaises(ownership.LegacyAcceptanceError):
            owner.reset()
        self.assertEqual(owner.snapshot()["pending"], 1)

    def test_pending_child_is_retained_and_late_drained(self):
        clock = FakeClock(4.0)
        child = FakeChild(exits_on_kill=False, exit_on_late_wait=True)
        spawn = FakeSpawn(child, clock=clock, expire_to=5.0)
        result, owner = _contain(clock, child, spawn=spawn)
        self.assertEqual(result["pending"], 1)
        self.assertEqual(owner.snapshot()["late_cleanup"]["state"], "pending")
        self.assertEqual(owner.late_physical_drain(), 1)
        snapshot = owner.snapshot()
        self.assertEqual(snapshot["pending"], 0)
        self.assertEqual(snapshot["late_cleanup"]["state"], "reaped_late")
        self.assertEqual(snapshot["late_cleanup"]["reaped_late"], 1)
        self.assertEqual(child.waits[-1], None)

    def test_multiple_records_admit_no_second_child_after_deadline(self):
        clock = FakeClock(4.0)
        child = FakeChild(exits_on_kill=True)
        spawn = FakeSpawn(child, clock=clock, expire_to=5.0)
        owner = ownership.ContainmentOwner()
        result = support.contain_proven_owned_mounts(
            holder_pid=9001,
            records=[(MOUNTPOINT, MOUNT_ID), ("/fake/second", MOUNT_ID + 1)],
            deadline=5.0,
            owner=owner,
            clock=clock,
            spawn=spawn,
            read_mountinfo=FakeMounts(),
            wait_mount_gone=lambda *_args: None,
            read_identity=lambda _pid: None,
        )
        self.assertEqual(len(spawn.calls), 1)
        self.assertEqual(result["started"], 1)
        self.assertTrue(result["failed"])

    def test_child_finishes_before_deadline_and_mount_gone_is_contained(self):
        clock = FakeClock(1.0)
        child = FakeChild(returncode=0)
        calls = []

        def wait_gone(*args):
            calls.append(args)

        result, owner = _contain(clock, child, wait_gone=wait_gone)
        self.assertEqual(result["contained"], 1)
        self.assertEqual(result["outcome"], "contained")
        self.assertTrue(result["failed"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(owner.snapshot()["contained"], 1)

    def test_pending_owner_cannot_pass_report_and_late_reap_cannot_revive(self):
        owner = ownership.ContainmentOwner()
        child = FakeChild(pid=7100, exits_on_kill=False, exit_on_late_wait=True)
        owner.register(child, MOUNT_ID, starttime=33)
        saved = dict(acceptance.CASE_DETAILS)
        try:
            acceptance.CASE_DETAILS.clear()
            for name in acceptance.REQUIRED_CASES:
                acceptance.CASE_DETAILS[name] = {"owned_mounts_remaining": 0}
            result = FakeResult()
            pending_report = report._report_payload(
                scheduled=acceptance.REQUIRED_CASES,
                result=result,
                imported=True,
                containment_owner=owner,
            )
            self.assertFalse(pending_report["passed"])
            self.assertEqual(pending_report["status"], "failed")
            self.assertEqual(pending_report["cleanup"]["containment_pending"], 1)
            self.assertEqual(pending_report["containment"]["pending_children"][0]["pid"], 7100)
            owner.late_physical_drain()
            late_report = report._report_payload(
                scheduled=acceptance.REQUIRED_CASES,
                result=result,
                imported=True,
                containment_owner=owner,
            )
            self.assertFalse(late_report["passed"])
            self.assertEqual(late_report["containment"]["late_cleanup"]["state"], "reaped_late")
            self.assertEqual(late_report["containment"]["pending"], 0)
            clean_owner = ownership.ContainmentOwner()
            clean_report = report._report_payload(
                scheduled=acceptance.REQUIRED_CASES,
                result=result,
                imported=True,
                containment_owner=clean_owner,
            )
            self.assertTrue(clean_report["passed"])
        finally:
            acceptance.CASE_DETAILS.clear()
            acceptance.CASE_DETAILS.update(saved)


if __name__ == "__main__":
    unittest.main()
