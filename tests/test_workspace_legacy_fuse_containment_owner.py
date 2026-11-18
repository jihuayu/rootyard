#!/usr/bin/env python3
"""Pure owner-liveness and namespace-attach readiness tests.

These tests use fake clocks, fake Popen handles, fake namespace identity, fake
mountinfo and fake mount disappearance observations. They never start a
process, send a signal, enter a namespace, read real /proc, use FUSE, service,
PG, network or Docker.
"""
from __future__ import annotations

import subprocess
import threading
import unittest
from unittest import mock

from tests import fuse_helper_native_support as native_support
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
        late_sequence=None,
        late_release=None,
    ):
        self.pid = pid
        self.returncode = returncode
        self.exits_on_kill = exits_on_kill
        self.exit_on_late_wait = exit_on_late_wait
        self.wait_error = wait_error
        self.kill_error = kill_error
        self.poll_error = poll_error
        self.late_sequence = list(late_sequence or [])
        self.late_release = late_release
        self.waits = []
        self.kills = 0

    def poll(self):
        if self.poll_error is not None:
            raise self.poll_error
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if timeout is None:
            if self.late_release is not None:
                if self.late_release.is_set():
                    self.returncode = 0
                    return 0
                return None
            if self.late_sequence:
                item = self.late_sequence.pop(0)
                if isinstance(item, BaseException):
                    raise item
                if item is None:
                    return None
                self.returncode = item
                return item
            if self.exit_on_late_wait:
                self.returncode = 0
                return 0
            return self.returncode
        if self.wait_error is not None:
            raise self.wait_error
        if self.returncode is not None:
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


class FakeAttachClock:
    def __init__(self, now=0.0):
        self.now = now
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += max(seconds, 1e-9)


class FakeAttachIdentity:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def __call__(self, pid):
        self.calls.append(pid)
        value = self.rows[pid]
        if isinstance(value, list):
            if len(value) > 1:
                return value.pop(0)
            return value[0]
        if callable(value):
            return value()
        return value


class FakeAttachNamespaces:
    def __init__(self, rows, enclosing):
        self.rows = rows
        self.enclosing = dict(enclosing)
        self.calls = []

    def __call__(self, pid):
        self.calls.append(pid)
        value = self.rows.get(pid, self.enclosing)
        if isinstance(value, list):
            if len(value) > 1:
                return value.pop(0)
            return value[0]
        if callable(value):
            return value()
        return dict(value)


class FakeAttachSpawn:
    def __init__(self, children, events=None):
        self.children = list(children)
        self.calls = []
        self.events = events

    def __call__(self, api_pid):
        child = self.children.pop(0)
        self.calls.append(api_pid)
        if self.events is not None:
            self.events.append(("spawn", child.pid))
        return child


def _attach_identity(service_pid, holder_pid, service_starttime=1000, holder_starttime=2000):
    return FakeAttachIdentity({
        service_pid: {"pid": service_pid, "state": "S", "starttime": service_starttime},
        holder_pid: {"pid": holder_pid, "state": "S", "starttime": holder_starttime},
    })


def _attach_service(pid):
    return FakeChild(pid=pid)


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

    def test_late_drain_retries_wait_exception_until_real_exit(self):
        owner = ownership.ContainmentOwner()
        child = FakeChild(late_sequence=[RuntimeError("transient"), 0])
        owner.register(child, MOUNT_ID)
        self.assertEqual(
            owner.late_physical_drain(sleep=lambda _seconds: None, poll_interval=0), 1
        )
        snapshot = owner.snapshot()
        self.assertEqual(snapshot["pending"], 0)
        self.assertEqual(snapshot["late_cleanup"]["state"], "reaped_late")
        self.assertEqual(snapshot["late_cleanup"]["reaped_late"], 1)
        self.assertEqual(snapshot["late_cleanup"]["wait_error_count"], 1)
        self.assertIn("RuntimeError", snapshot["late_cleanup"]["wait_error_classes"])
        self.assertEqual(snapshot["records"][0]["returncode"], 0)

    def test_late_drain_retries_none_until_real_exit(self):
        owner = ownership.ContainmentOwner()
        child = FakeChild(late_sequence=[None, None, 0])
        owner.register(child, MOUNT_ID)
        self.assertEqual(
            owner.late_physical_drain(sleep=lambda _seconds: None, poll_interval=0), 1
        )
        snapshot = owner.snapshot()
        self.assertEqual(snapshot["pending"], 0)
        self.assertEqual(snapshot["late_cleanup"]["wait_error_count"], 2)
        self.assertIn("wait_none", snapshot["late_cleanup"]["wait_error_classes"])
        self.assertEqual(snapshot["records"][0]["returncode"], 0)

    def test_late_drain_diagnostics_are_bounded(self):
        owner = ownership.ContainmentOwner()
        child = FakeChild(late_sequence=[RuntimeError("spam")] * 8 + [0])
        owner.register(child, MOUNT_ID)
        self.assertEqual(
            owner.late_physical_drain(sleep=lambda _seconds: None, poll_interval=0), 1
        )
        snapshot = owner.snapshot()
        self.assertEqual(snapshot["pending"], 0)
        self.assertEqual(snapshot["errors"], 0)
        self.assertEqual(snapshot["late_cleanup"]["wait_error_count"], ownership.LATE_DIAG_LIMIT)
        self.assertTrue(snapshot["late_cleanup"]["wait_diagnostics_capped"])
        self.assertEqual(snapshot["late_cleanup"]["wait_error_classes"], ["RuntimeError"])

    def test_late_drain_does_not_return_before_release(self):
        release = threading.Event()
        child = FakeChild(late_release=release)
        owner = ownership.ContainmentOwner()
        owner.register(child, MOUNT_ID)
        started = threading.Event()
        wake = threading.Event()

        def sleeper(_seconds):
            started.set()
            wake.wait(2)

        thread = threading.Thread(
            target=owner.late_physical_drain,
            kwargs={"sleep": sleeper, "poll_interval": 0},
        )
        thread.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertTrue(thread.is_alive())
            self.assertEqual(owner.snapshot()["pending"], 1)
            self.assertEqual(owner.snapshot()["late_cleanup"]["state"], "draining")
        finally:
            release.set()
            wake.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        snapshot = owner.snapshot()
        self.assertEqual(snapshot["pending"], 0)
        self.assertEqual(snapshot["late_cleanup"]["state"], "reaped_late")
        self.assertEqual(snapshot["late_cleanup"]["reaped_late"], 1)

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


class NamespaceAttachReadinessTest(unittest.TestCase):
    """Pure readiness proof for the owned service/holder attach race."""

    SERVICE_PID = 4100
    HOLDER_PID = 4200
    OLD = {"user": 101, "mount": 201}
    NEW = {"user": 102, "mount": 202}

    def test_service_stays_in_parent_namespace_until_wrapper_unshares(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = _attach_service(self.HOLDER_PID)
        namespaces = FakeAttachNamespaces(
            {self.SERVICE_PID: [self.OLD, self.NEW], self.HOLDER_PID: [self.NEW]},
            enclosing=self.OLD,
        )
        events = []

        def read_namespaces(pid):
            value = namespaces(pid)
            events.append(("ns", pid, value["mount"]))
            return value

        spawn = FakeAttachSpawn([holder], events=events)
        result = support.attach_namespace_holder(
            service,
            1.0,
            clock=clock,
            sleep=clock.sleep,
            read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
            read_namespaces=read_namespaces,
            spawn=spawn,
        )
        self.assertIs(result, holder)
        self.assertEqual(spawn.calls, [self.SERVICE_PID])
        spawn_at = events.index(("spawn", self.HOLDER_PID))
        service_mounts = [
            value for kind, pid, value in events[:spawn_at]
            if kind == "ns" and pid == self.SERVICE_PID
        ]
        self.assertEqual(service_mounts[0], self.OLD["mount"])
        self.assertIn(self.NEW["mount"], service_mounts)

    def test_pre_setns_holder_is_not_accepted_until_same_namespaces(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = _attach_service(self.HOLDER_PID)
        holder_reads = []
        namespaces = FakeAttachNamespaces(
            {self.SERVICE_PID: [self.NEW], self.HOLDER_PID: [self.OLD, self.NEW]},
            enclosing=self.OLD,
        )

        def read_namespaces(pid):
            value = namespaces(pid)
            if pid == self.HOLDER_PID:
                holder_reads.append(value["mount"])
            return value

        result = support.attach_namespace_holder(
            service,
            1.0,
            clock=clock,
            sleep=clock.sleep,
            read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
            read_namespaces=read_namespaces,
            spawn=FakeAttachSpawn([holder]),
        )
        self.assertIs(result, holder)
        self.assertGreaterEqual(len(holder_reads), 2)
        self.assertEqual(holder_reads[0], self.OLD["mount"])
        self.assertEqual(holder_reads[-1], self.NEW["mount"])
        self.assertEqual(holder.kills, 0)

    def test_early_exit_holder_is_reaped_and_attach_fails_bounded(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        children = [
            FakeChild(pid=self.HOLDER_PID + index, returncode=7)
            for index in range(support.MAX_HOLDER_ATTACH_ATTEMPTS)
        ]
        spawn = FakeAttachSpawn(children)
        with self.assertRaises(support.LegacyAcceptanceError) as caught:
            support.attach_namespace_holder(
                service,
                1.0,
                clock=clock,
                sleep=clock.sleep,
                read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
                read_namespaces=FakeAttachNamespaces(
                    {self.SERVICE_PID: [self.NEW]}, enclosing=self.OLD
                ),
                spawn=spawn,
            )
        self.assertEqual(
            spawn.calls, [self.SERVICE_PID] * support.MAX_HOLDER_ATTACH_ATTEMPTS
        )
        self.assertTrue(all(child.kills == 0 for child in children))
        self.assertIsNone(getattr(caught.exception, "holder", None))

    def test_service_identity_change_stops_the_exact_holder(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = FakeChild(pid=self.HOLDER_PID, exits_on_kill=True)
        state = {"service_starttime": 1000}
        identities = FakeAttachIdentity({
            self.SERVICE_PID: lambda: {
                "pid": self.SERVICE_PID,
                "state": "S",
                "starttime": state["service_starttime"],
            },
            self.HOLDER_PID: {
                "pid": self.HOLDER_PID,
                "state": "S",
                "starttime": 2000,
            },
        })

        def read_namespaces(pid):
            if pid == self.HOLDER_PID:
                state["service_starttime"] = 1001
                return dict(self.OLD)
            if pid == self.SERVICE_PID:
                return dict(self.NEW)
            return dict(self.OLD)

        with self.assertRaises(support.LegacyAcceptanceError) as caught:
            support.attach_namespace_holder(
                service,
                1.0,
                clock=clock,
                sleep=clock.sleep,
                read_identity=identities,
                read_namespaces=read_namespaces,
                spawn=FakeAttachSpawn([holder]),
            )
        self.assertEqual(holder.kills, 1)
        self.assertIsNone(getattr(caught.exception, "holder", None))

    def test_deadline_cleans_pre_setns_holder_and_fails(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = FakeChild(pid=self.HOLDER_PID, exits_on_kill=True)
        with self.assertRaises(support.LegacyAcceptanceError) as caught:
            support.attach_namespace_holder(
                service,
                0.05,
                clock=clock,
                sleep=clock.sleep,
                read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
                read_namespaces=FakeAttachNamespaces(
                    {self.SERVICE_PID: [self.NEW], self.HOLDER_PID: [self.OLD]},
                    enclosing=self.OLD,
                ),
                spawn=FakeAttachSpawn([holder]),
            )
        self.assertEqual(holder.kills, 1)
        self.assertIsNone(getattr(caught.exception, "holder", None))

    def test_unreapable_holder_is_handed_back_with_failure(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = FakeChild(pid=self.HOLDER_PID, exits_on_kill=False)
        with self.assertRaises(support.LegacyAcceptanceError) as caught:
            support.attach_namespace_holder(
                service,
                0.05,
                clock=clock,
                sleep=clock.sleep,
                read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
                read_namespaces=FakeAttachNamespaces(
                    {self.SERVICE_PID: [self.NEW], self.HOLDER_PID: [self.OLD]},
                    enclosing=self.OLD,
                ),
                spawn=FakeAttachSpawn([holder]),
            )
        self.assertEqual(holder.kills, 1)
        self.assertIs(getattr(caught.exception, "holder", None), holder)

    def test_attach_never_uses_real_process_or_namespace_probes(self):
        clock = FakeAttachClock()
        service = _attach_service(self.SERVICE_PID)
        holder = _attach_service(self.HOLDER_PID)
        spawn = FakeAttachSpawn([holder])
        with mock.patch.object(
            native_support, "process_identity",
            side_effect=AssertionError("real identity"),
        ), mock.patch.object(
            support, "probe_namespace_inodes",
            side_effect=AssertionError("real namespace"),
        ), mock.patch.object(
            native_support, "spawn_api_namespace_holder",
            side_effect=AssertionError("real spawn"),
        ):
            result = support.attach_namespace_holder(
                service,
                1.0,
                clock=clock,
                sleep=clock.sleep,
                read_identity=_attach_identity(self.SERVICE_PID, self.HOLDER_PID),
                read_namespaces=FakeAttachNamespaces(
                    {self.SERVICE_PID: [self.NEW], self.HOLDER_PID: [self.NEW]},
                    enclosing=self.OLD,
                ),
                spawn=spawn,
            )
        self.assertIs(result, holder)

    def test_capture_rejects_user_namespace_mismatch(self):
        holder = FakeChild(pid=self.HOLDER_PID)
        service = FakeChild(pid=self.SERVICE_PID)

        def read_identity(pid):
            starttime = 2000 if pid == self.HOLDER_PID else 1000
            return {"pid": pid, "state": "S", "starttime": starttime}

        with mock.patch.object(
            ownership.support, "process_identity", side_effect=read_identity
        ), mock.patch.object(
            ownership,
            "namespace_inodes",
            side_effect=[
                {"user": 101, "mount": 201},
                {"user": 999, "mount": 201},
            ],
        ), mock.patch.object(ownership.os, "getpgid", return_value=self.SERVICE_PID):
            with self.assertRaises(ownership.LegacyAcceptanceError):
                ownership.capture_holder_identity(holder, service)

    def test_capture_rejects_service_that_exited_before_capture(self):
        holder = FakeChild(pid=self.HOLDER_PID)
        service = FakeChild(pid=self.SERVICE_PID, returncode=1)
        with self.assertRaises(ownership.LegacyAcceptanceError):
            ownership.capture_holder_identity(holder, service)


if __name__ == "__main__":
    unittest.main()
