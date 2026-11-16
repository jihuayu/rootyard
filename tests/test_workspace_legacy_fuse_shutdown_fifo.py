#!/usr/bin/env python3
"""Hermetic tests for the owned startup-FIFO fixture controller.

These tests use temporary-directory FIFOs, fake clocks, fake process identity,
fake thread wait rows and fake file-descriptor operations. They never start or
signal a process, read real ``/proc``, enter a namespace, mount FUSE, or touch a
service, database, network or container.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock
import uuid

from tests import workspace_legacy_fuse_shutdown_fifo as fifo
from tests import workspace_legacy_fuse_shutdown_ownership as ownership
from tests import workspace_legacy_fuse_shutdown_support as support


class FakeClock:
    def __init__(self, now=0.0, step=1.0):
        self.now = now
        self.step = step

    def __call__(self):
        return self.now

    def sleep(self, _seconds):
        self.now += self.step


class FakeIdentity:
    def __init__(self, starttime=42, state="S", pid=None):
        self.starttime = starttime
        self.state = state
        self.pid = pid

    def __call__(self, pid):
        return {
            "pid": int(pid) if self.pid is None else int(self.pid),
            "starttime": self.starttime,
            "state": self.state,
        }


class FakeProbe:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = 0

    def __call__(self, _pid):
        self.calls += 1
        if len(self.rows) == 1:
            return list(self.rows[0])
        return list(self.rows.pop(0))


class FakeProc:
    def __init__(self, alive=True):
        self.alive = alive

    def poll(self):
        return None if self.alive else 0


class FakeHarness:
    def __init__(self, status=200, raise_error=False, alive=True):
        self.status = status
        self.raise_error = raise_error
        self.proc = FakeProc(alive=alive)
        self.calls = 0

    def http(self, _path):
        self.calls += 1
        if self.raise_error:
            raise RuntimeError("connection refused")
        return self.status, b"", {}


def _make_controller(root: Path, *, clock=None, identity=None, probe=None, **kwargs):
    lazy = root / "lazy"
    lazy.mkdir(parents=True, exist_ok=True)
    clock = clock or FakeClock()
    return fifo.FifoController(
        lazy,
        str(uuid.uuid4()),
        clock=clock,
        sleep=clock.sleep,
        process_identity=identity or FakeIdentity(),
        thread_probe=probe or FakeProbe([[]]),
        **kwargs,
    )


def _forbidden_open(*_args, **_kwargs):
    raise AssertionError("the reader proof must never open the FIFO")


class InstallTest(unittest.TestCase):
    def test_install_replaces_only_owned_manifest_and_close_unlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lazy = root / "lazy"
            lazy.mkdir()
            controller = fifo.FifoController(
                lazy, str(uuid.uuid4()), process_identity=FakeIdentity(),
                open_fn=_forbidden_open,
            )
            controller.path.write_text("old regular manifest\n", encoding="utf-8")
            other = lazy / "other.json"
            other.write_text("keep me\n", encoding="utf-8")

            record = controller.install()

            self.assertTrue(stat.S_ISFIFO(os.lstat(controller.path).st_mode))
            self.assertEqual(record["fifo_inode"], os.lstat(controller.path).st_ino)
            self.assertTrue(stat.S_ISREG(os.lstat(other).st_mode))
            controller.close()
            self.assertFalse(os.path.lexists(controller.path))
            self.assertEqual(other.read_text(encoding="utf-8"), "keep me\n")
            controller.close()

    def test_install_refuses_symlink_without_following_or_unlinking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lazy = root / "lazy"
            lazy.mkdir()
            controller = fifo.FifoController(lazy, str(uuid.uuid4()))
            target = root / "target.json"
            target.write_text("target\n", encoding="utf-8")
            os.symlink(target, controller.path)

            with self.assertRaises(support.LegacyAcceptanceError):
                controller.install()

            self.assertTrue(os.path.islink(controller.path))
            self.assertEqual(target.read_text(encoding="utf-8"), "target\n")

    def test_install_refuses_a_second_owned_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lazy = root / "lazy"
            lazy.mkdir()
            os.mkfifo(lazy / "foreign.fifo", 0o600)
            controller = fifo.FifoController(lazy, str(uuid.uuid4()))

            with self.assertRaises(support.LegacyAcceptanceError):
                controller.install()

            self.assertTrue(stat.S_ISFIFO(os.lstat(controller.path).st_mode))
            controller.close()
            self.assertFalse(os.path.lexists(controller.path))


class ReaderProofTest(unittest.TestCase):
    def test_prove_never_opens_the_fifo_and_requires_a_fifo_open_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=1.0)
            probe = FakeProbe([[
                {"tid": 11, "state": "S", "wchan": "do_sys_openat2", "stack": ""},
            ]])
            controller = _make_controller(
                Path(directory), clock=clock, probe=probe, open_fn=_forbidden_open
            )
            controller.install()
            with self.assertRaises(support.LegacyAcceptanceError):
                controller.prove_reader_blocked(100, 42, deadline=3.0)
            self.assertGreaterEqual(probe.calls, 2)
            controller.close()

    def test_prove_accepts_fifo_open_wait_on_exact_service_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            probe = FakeProbe([[
                {"tid": 12, "state": "S", "wchan": "wait_for_partner", "stack": ""},
            ]])
            controller = _make_controller(
                Path(directory), clock=clock, probe=probe, open_fn=_forbidden_open
            )
            controller.install()
            proof = controller.prove_reader_blocked(100, 42, deadline=5.0)
            self.assertEqual(proof["service_pid"], 100)
            self.assertEqual(proof["service_starttime"], 42)
            self.assertEqual(proof["tid"], 12)
            self.assertEqual(proof["matched_marker"], "wait_for_partner")
            self.assertFalse(proof["via_kernel_stack"])
            self.assertEqual(proof["fifo_inode"], os.lstat(controller.path).st_ino)
            controller.close()

    def test_prove_accepts_kernel_stack_fallback_without_wchan(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            probe = FakeProbe([[
                {"tid": 13, "state": "D", "wchan": "0",
                 "stack": "[<0>] wait_for_partner+0x1/0x80"},
            ]])
            controller = _make_controller(Path(directory), clock=clock, probe=probe)
            controller.install()
            proof = controller.prove_reader_blocked(101, 42, deadline=5.0)
            self.assertTrue(proof["via_kernel_stack"])
            self.assertEqual(proof["matched_marker"], "wait_for_partner")
            controller.close()

    def test_prove_rejects_service_identity_change(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            probe = FakeProbe([[
                {"tid": 14, "state": "S", "wchan": "wait_for_partner", "stack": ""},
            ]])
            controller = _make_controller(
                Path(directory), clock=clock, probe=probe,
                identity=FakeIdentity(starttime=99),
            )
            controller.install()
            with self.assertRaises(support.LegacyAcceptanceError):
                controller.prove_reader_blocked(102, 42, deadline=5.0)
            controller.close()

    def test_prove_and_release_create_no_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            probe = FakeProbe([[
                {"tid": 15, "state": "S", "wchan": "wait_for_partner", "stack": ""},
            ]])
            opened = []
            controller = _make_controller(
                Path(directory), clock=clock, probe=probe,
                open_fn=lambda path, flags: opened.append((path, flags)) or 55,
                write_fn=lambda _fd, data: len(data),
                close_fn=lambda _fd: None,
            )
            controller.install()
            before = threading.active_count()
            controller.prove_reader_blocked(103, 42, deadline=5.0)
            controller.release_invalid_manifest(deadline=5.0)
            controller.close()
            self.assertEqual(threading.active_count(), before)
            self.assertEqual(len(opened), 1)


class ReleaseTest(unittest.TestCase):
    def test_release_writes_invalid_manifest_nonblocking_and_retains_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            opened = []
            written = []
            closed = []

            def open_writer(path, flags):
                opened.append((str(path), flags))
                return 77

            controller = _make_controller(
                Path(directory), clock=clock, open_fn=open_writer,
                write_fn=lambda fd, data: written.append((fd, data)) or len(data),
                close_fn=lambda fd: closed.append(fd),
            )
            controller.install()
            released = controller.release_invalid_manifest(deadline=5.0)
            self.assertEqual(released["bytes_written"], len(fifo.INVALID_MANIFEST))
            self.assertTrue(released["writer_retained"])
            self.assertEqual(len(opened), 1)
            self.assertTrue(opened[0][1] & os.O_WRONLY)
            self.assertTrue(opened[0][1] & os.O_NONBLOCK)
            self.assertEqual(written, [(77, fifo.INVALID_MANIFEST)])
            self.assertEqual(closed, [])
            controller.close_writer()
            self.assertEqual(closed, [77])
            controller.close_writer()
            self.assertEqual(closed, [77])
            controller.close()

    def test_release_retries_enxio_within_the_same_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=1.0)
            calls = []

            def open_writer(_path, _flags):
                calls.append(1)
                if len(calls) == 1:
                    raise OSError(errno.ENXIO, "no reader")
                return 78

            closed = []
            controller = _make_controller(
                Path(directory), clock=clock, open_fn=open_writer,
                write_fn=lambda _fd, data: len(data),
                close_fn=lambda fd: closed.append(fd),
            )
            controller.install()
            released = controller.release_invalid_manifest(deadline=5.0)
            self.assertEqual(released["attempts"], 2)
            self.assertEqual(released["bytes_written"], len(fifo.INVALID_MANIFEST))
            controller.close_writer()
            self.assertEqual(closed, [78])
            controller.close()

    def test_release_exhausts_bound_without_leaking_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=1.0)
            calls = []

            def open_writer(_path, _flags):
                calls.append(1)
                raise OSError(errno.ENXIO, "no reader")

            controller = _make_controller(
                Path(directory), clock=clock, open_fn=open_writer,
            )
            controller.install()
            with self.assertRaises(support.LegacyAcceptanceError):
                controller.release_invalid_manifest(deadline=2.0)
            self.assertGreaterEqual(len(calls), 2)
            self.assertIsNone(controller._writer_fd)
            controller.close()

    def test_release_closes_writer_on_unexpected_write_error(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            closed = []

            def failing_write(_fd, _data):
                raise OSError(errno.EIO, "write failed")

            controller = _make_controller(
                Path(directory), clock=clock,
                open_fn=lambda _path, _flags: 79,
                write_fn=failing_write,
                close_fn=lambda fd: closed.append(fd),
            )
            controller.install()
            with self.assertRaises(support.LegacyAcceptanceError):
                controller.release_invalid_manifest(deadline=5.0)
            self.assertEqual(closed, [79])
            self.assertIsNone(controller._writer_fd)
            controller.close()

    def test_release_tolerates_a_closed_reader_but_retains_no_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock(now=0.0, step=0.1)
            closed = []

            def closed_pipe(_fd, _data):
                raise OSError(errno.EPIPE, "reader closed")

            controller = _make_controller(
                Path(directory), clock=clock,
                open_fn=lambda _path, _flags: 80,
                write_fn=closed_pipe,
                close_fn=lambda fd: closed.append(fd),
            )
            controller.install()
            released = controller.release_invalid_manifest(deadline=5.0)
            self.assertEqual(released["bytes_written"], 0)
            self.assertTrue(released["writer_retained"])
            controller.close_writer()
            self.assertEqual(closed, [80])
            controller.close()


class StartupEvidenceTest(unittest.TestCase):
    def test_clean_log_reports_startup_owner_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "service.log"
            log.write_bytes(
                b"rootyard: legacy-shutdown-evidence {}\n"
                b"Error: workspace lazy manifest read failed\n"
            )
            evidence = fifo.startup_owner_join_evidence(log)
            self.assertTrue(evidence["startup_owner_joined"])

    def test_pending_startup_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "service.log"
            log.write_bytes(
                b"Error: workspace startup reconcile failed: "
                b"startup reconcile owner remained pending at the shutdown deadline\n"
            )
            with self.assertRaises(support.LegacyAcceptanceError):
                fifo.startup_owner_join_evidence(log)

    def test_join_failure_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "service.log"
            log.write_bytes(b"Error: startup reconcile join failed: startup producer panicked\n")
            with self.assertRaises(support.LegacyAcceptanceError):
                fifo.startup_owner_join_evidence(log)

    def test_cleanup_incomplete_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "service.log"
            log.write_bytes(
                b"Error: workspace lazy manifest read failed\n\n"
                b"Caused by: service cleanup incomplete: worker did not stop cleanly\n"
            )
            with self.assertRaises(support.LegacyAcceptanceError):
                fifo.startup_owner_join_evidence(log)

    def test_unreadable_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(support.LegacyAcceptanceError):
                fifo.startup_owner_join_evidence(Path(directory) / "missing.log")


class ServiceIdentityTest(unittest.TestCase):
    class Proc:
        pid = 500

    def test_capture_and_recheck_require_the_same_pid_and_starttime(self):
        proc = self.Proc()
        with mock.patch.object(ownership.os, "getpgid", return_value=500), \
                mock.patch.object(
                    ownership.support, "process_identity",
                    side_effect=[
                        {"pid": 500, "starttime": 42, "state": "S"},
                        {"pid": 500, "starttime": 42, "state": "S"},
                    ],
                ):
            captured = ownership.capture_service_identity(proc)
            rechecked = ownership.recheck_service_identity(proc, captured)
        self.assertEqual(captured, {"service_pid": 500, "service_starttime": 42})
        self.assertEqual(rechecked, captured)

    def test_starttime_change_is_rejected(self):
        proc = self.Proc()
        with mock.patch.object(ownership.os, "getpgid", return_value=500), \
                mock.patch.object(
                    ownership.support, "process_identity",
                    side_effect=[
                        {"pid": 500, "starttime": 42, "state": "S"},
                        {"pid": 500, "starttime": 43, "state": "S"},
                    ],
                ):
            captured = ownership.capture_service_identity(proc)
            with self.assertRaises(support.LegacyAcceptanceError):
                ownership.recheck_service_identity(proc, captured)


class ReadinessTest(unittest.TestCase):
    def test_connection_refused_and_200_are_distinguished(self):
        refused = FakeHarness(raise_error=True)
        evidence = fifo.assert_startup_not_ready(refused, seconds=0.05)
        self.assertFalse(evidence["ready"])
        self.assertGreaterEqual(refused.calls, 1)

        ready = FakeHarness(status=200)
        with self.assertRaises(support.LegacyAcceptanceError):
            fifo.assert_startup_not_ready(ready, seconds=0.05)

    def test_dead_service_is_rejected(self):
        harness = FakeHarness(raise_error=True, alive=False)
        with self.assertRaises(support.LegacyAcceptanceError):
            fifo.assert_startup_not_ready(harness, seconds=0.0)


if __name__ == "__main__":
    unittest.main()
