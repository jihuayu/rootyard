#!/usr/bin/env python3
"""Unit tests for the owned-FUSE crash-cleanup helper.

These tests use mocked syscall boundaries only.  They prove the parser and the
bounded command shape; they are not evidence that a real native FUSE fixture
recovers.  Only the coordinator's run of tests/test_workspace_fuse_service.py
and tests/test_workspace_handoff.py against the v8 binary can show that.
"""
import errno
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import owned_fuse_cleanup
from tests.e2e import Harness

FIXTURE_ROOT = "/tmp/rootyard-e2e-owned"
DATA_ROOT = FIXTURE_ROOT + "/data"
MOUNT_ROOT = DATA_ROOT + "/workspace-service/mounts"


def owned_id():
    return str(uuid.uuid4())


def mount_line(mountpoint, fstype="fuse", source="rootyard-workspace", mount_id=36):
    return "%d 25 0:%d / %s rw,nosuid,nodev,relatime - %s %s rw,user_id=0,group_id=0" % (
        mount_id, mount_id, mountpoint, fstype, source)


class FakeProc:
    def __init__(self, pid=4001):
        self.pid = pid
        self.returncode = None
        self.wait_calls = []


class HarnessStub:
    def __init__(self, proc, root=FIXTURE_ROOT, env=None):
        self.root = Path(root)
        self.env = {"ROOTYARD_DATA_DIR": str(self.root / "data")} if env is None else env
        self.proc = proc


def scan(harness, mountinfo, tids=("4001", "4002"), listdir_path=None):
    paths = {"/proc/%d/task/%s/mountinfo" % (harness.proc.pid, tid): text
             for tid, text in zip(tids, mountinfo)}

    def fake_open(path, *args, **kwargs):
        if path in paths:
            return io.StringIO(paths[path])
        raise FileNotFoundError(errno.ENOENT, "missing", path)

    def fake_listdir(path):
        if listdir_path is not None:
            listdir_path.append(path)
        return list(tids)

    with mock.patch.object(owned_fuse_cleanup, "open", fake_open, create=True), \
            mock.patch.object(owned_fuse_cleanup.os, "listdir", side_effect=fake_listdir), \
            mock.patch.object(owned_fuse_cleanup.os, "getpgid", return_value=harness.proc.pid):
        return owned_fuse_cleanup.owned_mounts(harness)


class ParseTest(unittest.TestCase):
    def test_selects_only_owned_rootyard_uuid_fuse_mounts(self):
        mine = owned_id()
        selected = mount_line(MOUNT_ROOT + "/" + mine)
        other_source = mount_line(MOUNT_ROOT + "/" + owned_id(), source="other-workspace")
        other_type = mount_line(MOUNT_ROOT + "/" + owned_id(), fstype="ext4")
        no_type = mount_line(MOUNT_ROOT + "/" + owned_id(), fstype="fuseblk")
        host_path = mount_line("/var/lib/rootyard/workspace-service/mounts/" + owned_id())
        tmp_path = mount_line("/tmp/unrelated/workspace-service/mounts/" + owned_id())
        deeper = mount_line(MOUNT_ROOT + "/" + owned_id() + "/sub")
        not_uuid = mount_line(MOUNT_ROOT + "/definitely-not-a-uuid")
        upper_uuid = mount_line(MOUNT_ROOT + "/" + owned_id().upper())
        dotted = mount_line(MOUNT_ROOT + "/../" + owned_id())
        escape = mount_line(MOUNT_ROOT + "/" + owned_id() + "/../../../../etc")
        trailing = mount_line(MOUNT_ROOT + "/" + owned_id() + "/")
        root = HarnessStub(FakeProc())
        mounts = scan(root, ["\n".join([other_source, other_type, no_type, host_path,
                                        tmp_path, deeper, not_uuid, upper_uuid, dotted,
                                        escape, trailing, selected])])
        self.assertEqual([m.mountpoint for m in mounts], [MOUNT_ROOT + "/" + mine])
        self.assertEqual(mounts[0].source, "rootyard-workspace")
        self.assertEqual(mounts[0].fstype, "fuse")
        self.assertEqual(mounts[0].tid, 4001)

    def test_deduplicates_across_tids_and_keeps_first_owner(self):
        one = owned_id()
        text = mount_line(MOUNT_ROOT + "/" + one)
        root = HarnessStub(FakeProc())
        mounts = scan(root, [text, text])
        self.assertEqual([(m.mountpoint, m.tid) for m in mounts], [(MOUNT_ROOT + "/" + one, 4001)])

    def test_second_volume_root_is_allowed_only_inside_fixture(self):
        second = owned_id()
        root = HarnessStub(FakeProc(), env={"ROOTYARD_DATA_DIR": FIXTURE_ROOT + "/second-volume"})
        text = mount_line(FIXTURE_ROOT + "/second-volume/workspace-service/mounts/" + second)
        self.assertEqual([m.mountpoint for m in scan(root, [text])],
                         [FIXTURE_ROOT + "/second-volume/workspace-service/mounts/" + second])
        outside = HarnessStub(FakeProc(), env={"ROOTYARD_DATA_DIR": "/srv/elsewhere"})
        sneaky = mount_line("/srv/elsewhere/workspace-service/mounts/" + second)
        self.assertEqual(scan(outside, [sneaky]), [])

    def test_octal_escapes_are_decoded_before_matching(self):
        self.assertEqual(owned_fuse_cleanup._decode_field("/a\\040b"), "/a b")
        self.assertEqual(owned_fuse_cleanup._decode_field("/tab\\011new\\012line"), "/tab\tnew\nline")
        self.assertEqual(owned_fuse_cleanup._decode_field("/back\\134slash"), "/back\\slash")
        self.assertEqual(owned_fuse_cleanup._decode_field("/plain"), "/plain")
        root = HarnessStub(FakeProc())
        space = mount_line("/var/lib/rootyard\\040copy/workspace-service/mounts/" + owned_id())
        self.assertEqual(scan(root, [space]), [])

    def test_malformed_lines_are_ignored(self):
        root = HarnessStub(FakeProc())
        mounts = scan(root, ["", "garbage", "36 25 0:36 / /x rw - fuse"])
        self.assertEqual(mounts, [])

    def test_symlinks_and_escapes_are_not_resolved(self):
        proc = FakeProc()
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-unit-") as directory:
            root_path = Path(directory)
            outside = root_path / "outside"
            outside.mkdir()
            mountpoint = root_path / "data/workspace-service/mounts" / owned_id()
            mountpoint.parent.mkdir(parents=True)
            mountpoint.symlink_to(outside, target_is_directory=True)
            root = HarnessStub(proc, root=str(root_path))
            with mock.patch.object(owned_fuse_cleanup.os.path, "realpath",
                                   side_effect=AssertionError("must not resolve")), \
                    mock.patch.object(owned_fuse_cleanup.os, "stat",
                                      side_effect=AssertionError("must not stat")):
                mounts = scan(root, [mount_line(str(mountpoint))])
            self.assertEqual([m.mountpoint for m in mounts], [str(mountpoint)])

    def test_refuses_unbounded_thread_or_mount_counts(self):
        root = HarnessStub(FakeProc())
        with self.assertRaises(RuntimeError):
            scan(root, [""] * (owned_fuse_cleanup.MAX_TIDS + 1),
                 tids=[str(4001 + index) for index in range(owned_fuse_cleanup.MAX_TIDS + 1)])
        many = "\n".join(mount_line(MOUNT_ROOT + "/" + owned_id())
                         for _ in range(owned_fuse_cleanup.MAX_MOUNTS + 1))
        with self.assertRaises(RuntimeError):
            scan(root, [many], tids=["4001"])

    def test_ownership_guards_skip_foreign_or_reaped_processes(self):
        foreign = FakeProc()
        foreign.returncode = 0
        self.assertEqual(scan(HarnessStub(foreign), [mount_line(MOUNT_ROOT + "/" + owned_id())]), [])
        proc = FakeProc()
        harness = HarnessStub(proc)
        paths = {"/proc/4001/task/4001/mountinfo":
                 mount_line(MOUNT_ROOT + "/" + owned_id())}

        def fake_open(path, *args, **kwargs):
            return io.StringIO(paths[path])

        with mock.patch.object(owned_fuse_cleanup, "open", fake_open, create=True), \
                mock.patch.object(owned_fuse_cleanup.os, "listdir", return_value=["4001"]), \
                mock.patch.object(owned_fuse_cleanup.os, "getpgid", return_value=1):
            self.assertEqual(owned_fuse_cleanup.owned_mounts(harness), [])
        with mock.patch.object(owned_fuse_cleanup.os, "getpgid", side_effect=ProcessLookupError):
            self.assertEqual(owned_fuse_cleanup.owned_mounts(harness), [])
        with mock.patch.object(owned_fuse_cleanup.os, "listdir", side_effect=FileNotFoundError):
            self.assertEqual(owned_fuse_cleanup.owned_mounts(harness), [])


class CommandTest(unittest.TestCase):
    def test_force_lazy_unmount_runs_in_owner_namespaces(self):
        argv = owned_fuse_cleanup.umount_command(4242, MOUNT_ROOT + "/" + owned_id())
        self.assertEqual(argv[:6], ["nsenter", "--preserve-credentials",
                                    "--user=/proc/4242/ns/user", "--mount=/proc/4242/ns/mnt",
                                    "--", "umount"])
        self.assertEqual(argv[-4:], ["-f", "-l", "--", argv[-1]])
        self.assertTrue(argv[-1].startswith(MOUNT_ROOT + "/"))

    def test_release_uses_bounded_force_umount_and_returns_released_paths(self):
        run = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts",
                               return_value=[owned_fuse_cleanup.Mount(
                                   MOUNT_ROOT + "/" + owned_id(), "fuse",
                                   "rootyard-workspace", 4001)]):
            released = owned_fuse_cleanup.release_owned_fuse_mounts(HarnessStub(FakeProc()), run=run)
        self.assertEqual(released, [run.call_args.args[0][-1]])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], owned_fuse_cleanup.UMOUNT_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["timeout"], 5)
        self.assertFalse(kwargs["check"])
        self.assertEqual(run.call_args.args[0][-4:], ["-f", "-l", "--", run.call_args.args[0][-1]])
        self.assertEqual(run.call_args.args[0][5], "umount")
        self.assertTrue(released[0].startswith(MOUNT_ROOT))

    def test_unmount_failures_raise_instead_of_reporting_success(self):
        owned = [owned_fuse_cleanup.Mount(MOUNT_ROOT + "/" + owned_id(), "fuse",
                                          "rootyard-workspace", 4001)]
        failing = mock.Mock(return_value=types.SimpleNamespace(returncode=32, stdout=b"",
                                                               stderr=b"umount: target is busy"))
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=owned):
            with self.assertRaises(RuntimeError) as caught:
                owned_fuse_cleanup.release_owned_fuse_mounts(HarnessStub(FakeProc()), run=failing)
        self.assertIn("target is busy", str(caught.exception))
        self.assertIn(owned[0].mountpoint, str(caught.exception))
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=owned):
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.release_owned_fuse_mounts(
                    HarnessStub(FakeProc()),
                    run=mock.Mock(side_effect=subprocess.TimeoutExpired("umount", 5)))
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.release_owned_fuse_mounts(
                    HarnessStub(FakeProc()), run=mock.Mock(side_effect=OSError("no nsenter")))
        # No owned mounts simply returns, leaving the caller's second wait to
        # decide success or raise.
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=[]):
            self.assertEqual(owned_fuse_cleanup.release_owned_fuse_mounts(
                HarnessStub(FakeProc()), run=mock.Mock()), [])


class StopFallbackTest(unittest.TestCase):
    def harness(self, proc):
        harness = object.__new__(Harness)
        harness.proc = proc
        harness.log = None
        return harness

    def stopped(self, proc, hard, waits, release=None):
        events = []

        def fake_wait(timeout=None):
            proc.wait_calls.append(timeout)
            outcome = waits.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        def fake_release(harness):
            events.append(("release", harness.proc.pid))
            if isinstance(release, Exception):
                raise release
            return ["/owned/mount"]

        proc.wait = fake_wait
        proc.poll = lambda: None
        harness = self.harness(proc)
        with mock.patch.object(os, "killpg",
                               side_effect=lambda pid, sig: events.append(("kill", pid, sig))), \
                mock.patch.object(owned_fuse_cleanup, "release_owned_fuse_mounts",
                                  side_effect=fake_release):
            try:
                harness.stop(hard=hard)
                error = None
            except RuntimeError as caught:
                error = caught
        return harness, events, error

    def test_sigterm_timeout_kills_then_force_releases_then_waits(self):
        proc = FakeProc()
        harness, events, error = self.stopped(
            proc, False, [subprocess.TimeoutExpired("svc", 5), 0])
        self.assertIsNone(error)
        self.assertEqual([event[0] for event in events], ["kill", "kill", "release"])
        self.assertEqual([event[2] for event in events[:2]], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(events[0][1], proc.pid)
        self.assertEqual(events[2][1], proc.pid)
        self.assertEqual(proc.wait_calls, [5, 5])
        self.assertIsNone(harness.proc)

    def test_hard_stop_skips_graceful_term_and_only_releases_after_timeout(self):
        proc = FakeProc()
        harness, events, error = self.stopped(
            proc, True, [subprocess.TimeoutExpired("svc", 5), 0])
        self.assertIsNone(error)
        self.assertEqual([event[0] for event in events], ["kill", "release"])
        self.assertEqual(len(proc.wait_calls), 2)
        self.assertIsNone(harness.proc)

    def test_no_release_when_first_wait_succeeds(self):
        proc = FakeProc()
        harness, events, error = self.stopped(proc, False, [0])
        self.assertIsNone(error)
        self.assertEqual([event[0] for event in events], ["kill"])
        self.assertEqual(proc.wait_calls, [5])

    def test_hard_stop_without_timeout_never_unmounts(self):
        proc = FakeProc()
        _, events, error = self.stopped(proc, True, [0])
        self.assertIsNone(error)
        self.assertEqual([event[0] for event in events], ["kill"])

    def test_second_wait_timeout_raises_and_preserves_fixture(self):
        proc = FakeProc()
        harness, events, error = self.stopped(
            proc, False, [subprocess.TimeoutExpired("svc", 5),
                          subprocess.TimeoutExpired("svc", 5)])
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("Preserve the fixture", str(error))
        self.assertEqual([event[0] for event in events], ["kill", "kill", "release"])
        self.assertIs(harness.proc, proc)

    def test_release_failure_propagates_and_preserves_fixture(self):
        proc = FakeProc()
        harness, events, error = self.stopped(
            proc, True, [subprocess.TimeoutExpired("svc", 5)],
            release=RuntimeError("Owned FUSE mount reclaim failed"))
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("reclaim failed", str(error))
        self.assertIs(harness.proc, proc)


if __name__ == "__main__":
    unittest.main()
