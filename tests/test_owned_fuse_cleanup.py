#!/usr/bin/env python3
"""Unit tests for the owned-FUSE crash-cleanup helper.

These tests use mocked syscall boundaries and real temporary directories only.
They prove the parser, the FD-bound inner unmount path and the bounded command
shape; they are not evidence that a real native FUSE fixture recovers.  Only
the coordinator's run of tests/test_workspace_fuse_service.py and
tests/test_workspace_handoff.py against the v8 binary can show that.
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
MINIMAL_ENV = {"PATH": os.defpath, "LC_ALL": "C"}
SECRET_ENV = {"DATABASE_URL": "postgres://user:secret@db/rootyard-SENTINEL",
              "GARAGE_ACCESS_KEY": "garage-access-key-SENTINEL",
              "ROOTYARD_API_KEY": "api-key-SENTINEL"}
SECRET_VALUES = tuple(SECRET_ENV.values())


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
        self.assertEqual(mounts[0].mount_id, 36)
        self.assertEqual(mounts[0].source, "rootyard-workspace")
        self.assertEqual(mounts[0].fstype, "fuse")
        self.assertEqual(mounts[0].tid, 4001)

    def test_deduplicates_across_tids_and_keeps_first_owner(self):
        one = owned_id()
        text = mount_line(MOUNT_ROOT + "/" + one, mount_id=77)
        root = HarnessStub(FakeProc())
        mounts = scan(root, [text, text])
        self.assertEqual([(m.mountpoint, m.mount_id, m.tid) for m in mounts],
                         [(MOUNT_ROOT + "/" + one, 77, 4001)])

    def test_conflicting_mount_id_across_tids_is_refused(self):
        one = owned_id()
        root = HarnessStub(FakeProc())
        with self.assertRaises(RuntimeError) as caught:
            scan(root, [mount_line(MOUNT_ROOT + "/" + one, mount_id=36),
                        mount_line(MOUNT_ROOT + "/" + one, mount_id=37)])
        self.assertIn("changed mount ID", str(caught.exception))

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
        mounts = scan(root, ["", "garbage", "notanid 25 0:36 / /x rw - fuse src rw",
                             "36 25 0:36 / /x rw - fuse"])
        self.assertEqual(mounts, [])

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


class InnerUnmountTest(unittest.TestCase):
    """Exercise the inner helper against real temporary-directory layouts."""

    def layout(self, directory, leaf_symlink=False, parent_symlink=False):
        root = Path(os.path.realpath(directory))
        outside = root / "outside"
        (outside / "workspace-service/mounts").mkdir(parents=True)
        name = owned_id()
        mounts = root / "workspace-service/mounts"
        if parent_symlink:
            (root / "workspace-service").symlink_to(outside / "workspace-service",
                                                    target_is_directory=True)
        else:
            mounts.mkdir(parents=True)
        mountpoint = root / "workspace-service/mounts" / name
        if leaf_symlink:
            mountpoint.symlink_to(outside, target_is_directory=True)
        elif not parent_symlink:
            mountpoint.mkdir()
        return root, mountpoint, name, outside

    def args(self, mountpoint, root, mount_id=36):
        return ["--unmount", str(mountpoint), "--mount-id", str(mount_id),
                "--source", "rootyard-workspace", "--fstype", "fuse",
                "--allowed-root", str(root)]

    def inner(self, argv):
        return owned_fuse_cleanup._unmount_main(argv)

    def test_parent_symlink_is_rejected_before_any_command(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-parent-") as directory:
            root, mountpoint, name, outside = self.layout(directory, parent_symlink=True)
            # Silently ignore a real command if this ever gets through.
            run = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
            with mock.patch.object(owned_fuse_cleanup.subprocess, "run", run):
                self.assertEqual(self.inner(self.args(mountpoint, root)), 1)
            run.assert_not_called()
            self.assertFalse((outside / "workspace-service/mounts" / name).exists())

    def test_leaf_symlink_is_rejected_before_any_command(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-leaf-") as directory:
            root, mountpoint, _, _ = self.layout(directory, leaf_symlink=True)
            self.assertTrue(mountpoint.is_symlink())
            run = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
            with mock.patch.object(owned_fuse_cleanup.subprocess, "run", run):
                self.assertEqual(self.inner(self.args(mountpoint, root)), 1)
            run.assert_not_called()

    def test_mount_id_mismatch_is_rejected_before_any_command(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-id-") as directory:
            root, mountpoint, _, _ = self.layout(directory)
            probe = owned_fuse_cleanup.open_mountpoint_fd(str(mountpoint), [str(root)])
            try:
                actual = owned_fuse_cleanup.read_mnt_id(probe)
            finally:
                os.close(probe)
            run = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
            with mock.patch.object(owned_fuse_cleanup.subprocess, "run", run):
                self.assertEqual(self.inner(self.args(mountpoint, root, actual + 1)), 1)
            run.assert_not_called()

    def test_namespace_mount_identity_must_match(self):
        mine = owned_id()
        mountpoint = MOUNT_ROOT + "/" + mine
        text = "\n".join([mount_line("/srv/other", mount_id=90),
                          mount_line(mountpoint, mount_id=91)])
        with mock.patch.object(owned_fuse_cleanup, "open",
                               side_effect=lambda *args, **kwargs: io.StringIO(text),
                               create=True):
            owned_fuse_cleanup.verify_namespace_mount(
                91, mountpoint, "rootyard-workspace", "fuse")
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.verify_namespace_mount(
                    91, mountpoint, "other-workspace", "fuse")
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.verify_namespace_mount(
                    91, MOUNT_ROOT + "/" + owned_id(), "rootyard-workspace", "fuse")
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.verify_namespace_mount(
                    99, mountpoint, "rootyard-workspace", "fuse")

    def test_unmount_uses_bound_fd_no_canonicalize_minimal_env_and_no_secrets(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-fd-") as directory:
            root, mountpoint, _, _ = self.layout(directory)
            probe = owned_fuse_cleanup.open_mountpoint_fd(str(mountpoint), [str(root)])
            try:
                actual = owned_fuse_cleanup.read_mnt_id(probe)
            finally:
                os.close(probe)
            seen = {}

            def fake_run(argv, **kwargs):
                fd = kwargs["pass_fds"][0]
                os.fstat(fd)  # must still be a live descriptor in the child call
                seen["argv"] = argv
                seen["kwargs"] = kwargs
                return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            secret_env = dict(SECRET_ENV)
            with mock.patch.dict(os.environ, secret_env), \
                    mock.patch.object(owned_fuse_cleanup, "verify_namespace_mount"), \
                    mock.patch.object(owned_fuse_cleanup.subprocess, "run",
                                      side_effect=fake_run):
                self.assertEqual(self.inner(self.args(mountpoint, root, actual)), 0)
            fd = seen["kwargs"]["pass_fds"][0]
            self.assertEqual(seen["argv"], ["umount", "--no-canonicalize", "-f", "-l",
                                            "--", "/proc/self/fd/%d" % fd])
            self.assertEqual(seen["kwargs"]["pass_fds"], (fd,))
            self.assertEqual(seen["kwargs"]["env"], MINIMAL_ENV)
            self.assertEqual(seen["kwargs"]["timeout"], 5)
            self.assertFalse(seen["kwargs"]["check"])
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, repr(seen["argv"]))
                self.assertNotIn(secret, repr(seen["kwargs"]["env"]))

    def test_inner_rejects_path_outside_allowed_root_or_bad_uuid(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-cleanup-out-") as directory:
            root, mountpoint, _, _ = self.layout(directory)
            run = mock.Mock()
            with mock.patch.object(owned_fuse_cleanup.subprocess, "run", run):
                self.assertEqual(self.inner(self.args(mountpoint, "/srv/elsewhere")), 1)
                self.assertEqual(self.inner(self.args(root / "workspace-service/mounts/nope", root)), 1)
            run.assert_not_called()


class CommandTest(unittest.TestCase):
    def test_helper_runs_inner_unmount_in_owner_namespaces(self):
        mount = owned_fuse_cleanup.Mount(4242, MOUNT_ROOT + "/" + owned_id(),
                                         "fuse", "rootyard-workspace", 4001)
        argv = owned_fuse_cleanup.helper_command(mount, [FIXTURE_ROOT + "/data"])
        self.assertEqual(argv[:6], ["nsenter", "--preserve-credentials",
                                    "--user=/proc/4001/ns/user", "--mount=/proc/4001/ns/mnt",
                                    "--", sys.executable])
        self.assertEqual(argv[6], os.path.abspath(owned_fuse_cleanup.__file__))
        self.assertEqual(argv[7:], ["--unmount", mount.mountpoint,
                                    "--mount-id", "4242",
                                    "--source", "rootyard-workspace",
                                    "--fstype", "fuse",
                                    "--allowed-root", FIXTURE_ROOT + "/data"])

    def test_umount_fd_command_is_no_canonicalize_bound_fd(self):
        self.assertEqual(owned_fuse_cleanup.umount_fd_command(17),
                         ["umount", "--no-canonicalize", "-f", "-l", "--", "/proc/self/fd/17"])

    def test_release_uses_bounded_helper_and_minimal_env(self):
        mount = owned_fuse_cleanup.Mount(36, MOUNT_ROOT + "/" + owned_id(),
                                         "fuse", "rootyard-workspace", 4001)
        run = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
        secret_env = dict(SECRET_ENV)
        with mock.patch.dict(os.environ, secret_env), \
                mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=[mount]):
            released = owned_fuse_cleanup.release_owned_fuse_mounts(
                HarnessStub(FakeProc()), run=run)
        self.assertEqual(released, [mount.mountpoint])
        argv = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertEqual(argv[:6], ["nsenter", "--preserve-credentials",
                                    "--user=/proc/4001/ns/user", "--mount=/proc/4001/ns/mnt",
                                    "--", sys.executable])
        self.assertIn("--unmount", argv)
        self.assertIn(mount.mountpoint, argv)
        self.assertEqual(kwargs["timeout"], owned_fuse_cleanup.HELPER_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["timeout"], 5)
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["env"], MINIMAL_ENV)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, repr(argv))
            self.assertNotIn(secret, repr(kwargs["env"]))

    def test_helper_failures_raise_instead_of_reporting_success(self):
        owned = [owned_fuse_cleanup.Mount(36, MOUNT_ROOT + "/" + owned_id(), "fuse",
                                          "rootyard-workspace", 4001)]
        failing = mock.Mock(return_value=types.SimpleNamespace(returncode=32, stdout=b"",
                                                               stderr=b"inner helper failed"))
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=owned):
            with self.assertRaises(RuntimeError) as caught:
                owned_fuse_cleanup.release_owned_fuse_mounts(HarnessStub(FakeProc()), run=failing)
        self.assertIn("inner helper failed", str(caught.exception))
        self.assertIn(owned[0].mountpoint, str(caught.exception))
        with mock.patch.object(owned_fuse_cleanup, "owned_mounts", return_value=owned):
            with self.assertRaises(RuntimeError):
                owned_fuse_cleanup.release_owned_fuse_mounts(
                    HarnessStub(FakeProc()),
                    run=mock.Mock(side_effect=subprocess.TimeoutExpired("nsenter", 5)))
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
