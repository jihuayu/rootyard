#!/usr/bin/env python3
"""Pure filesystem/mock tests for owned source witnesses."""
from dataclasses import replace
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

import transfer_revocation_backpressure as revocation_backpressure  # noqa: E402
import transfer_revocation_git_source as git_source  # noqa: E402
import transfer_revocation_observer as observer  # noqa: E402
import transfer_revocation_source as source  # noqa: E402


def _stat_text(pid, comm, *, state="S", ppid=1, pgid=None, starttime=1):
    pgid = pid if pgid is None else pgid
    fields = [state, str(ppid), str(pgid), str(pgid)] + ["0"] * 15 + [str(starttime)]
    return f"{pid} ({comm}) " + " ".join(fields)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fdinfo(path, *, pos, flags, ino, mnt_id=77):
    _write(path, f"pos:\t{pos}\nflags:\t{flags:o}\nino:\t{ino}\nmnt_id:\t{mnt_id}\n")


def _window_sample(now_ns, qualified, *, inode=17):
    return {
        "observed_ns": now_ns,
        "sample_start_ns": now_ns,
        "sample_duration_ns": 0,
        "net_table_available": True,
        "same_netns": True,
        "probe0_pending": True,
        "source_qualified": qualified,
        "server_tx_queue": 4096,
        "client_rx_queue": 4096,
        "server_socket_inode": inode,
        "server_fd_owned": True,
        "client_inode_owned": True,
    }


class TestSourceParsers(unittest.TestCase):
    def test_fdinfo_parses_decimal_position_octal_flags_and_mount(self):
        info = source.parse_fdinfo("pos:\t41\nflags:\t0100000\nino:\t99\nmnt_id:\t7\n")
        self.assertEqual(info.pos, 41)
        self.assertEqual(info.flags, int("100000", 8))
        self.assertEqual(info.ino, 99)
        self.assertEqual(info.mnt_id, 7)
        with self.assertRaises(source.SourceParseError):
            source.parse_fdinfo("pos:\t1\nflags:\t00\nino:\t2\n")

    def test_syscall_parser_supports_only_x86_64_write_and_writev(self):
        write = source.parse_syscall("1 0x1 0x2 0x10 0x0 0x0 0x0")
        self.assertEqual(write.kind, "write")
        self.assertEqual(write.fd, 1)
        self.assertEqual(write.count, 16)
        writev = source.parse_syscall("20 0x1 0x2 0x3 0x0 0x0 0x0")
        self.assertEqual(writev.kind, "writev")
        self.assertEqual(writev.count, 3)
        for text in ("running", "-1 0x0", "61 0x1 0x2 0x3", "1 0x1", "1 0x1 0x2 0x0"):
            with self.assertRaises(source.SourceParseError):
                source.parse_syscall(text)

    def test_wchan_requires_exact_pipe_write_symbol(self):
        self.assertEqual(source.parse_wchan("pipe_write\n"), "pipe_write")
        self.assertEqual(source.parse_wchan("pipe_write+0x12\n"), "pipe_write")
        for text in ("anon_pipe_write\n", "pipe\n", ""):
            with self.assertRaises(source.SourceParseError):
                source.parse_wchan(text)


class TestOwnedStdoutPipeFullObservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proc = Path(self.temp.name) / "proc"
        self.path = self.proc / "100" / "fd" / "5"
        self.path.parent.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def _observe(self, *, unread=4096, capacity=4096, info=None,
                 supported=True, open_error=None, stat_error=None,
                 fcntl_error=None, close_error=None,
                 expected_dev=42, expected_ino=700):
        info = info or mock.Mock(
            st_mode=stat.S_IFIFO | 0o600, st_dev=42, st_ino=700)

        def ioctl(fd, request, buffer, mutate):
            buffer[0] = unread
            return buffer

        def number(fd, request):
            if fcntl_error is not None:
                raise fcntl_error
            return capacity

        patches = [
            mock.patch.object(source, "pipe_full_observation_supported",
                              return_value=supported),
            mock.patch.object(source.fcntl, "F_GETPIPE_SZ", 1032, create=True),
            mock.patch.object(source.os, "open",
                              side_effect=open_error, return_value=7),
            mock.patch.object(source.os, "fstat",
                              side_effect=stat_error, return_value=info),
            mock.patch.object(source.fcntl, "fcntl", side_effect=number),
            mock.patch.object(source.fcntl, "ioctl", side_effect=ioctl),
        ]
        with patches[0], patches[1], patches[2] as opened, patches[3], \
                patches[4], patches[5], \
                mock.patch.object(
                    source.os, "close", side_effect=close_error) as closed:
            result = source.observe_owned_stdout_pipe_full(
                self.proc, 100, 5,
                expected_dev=expected_dev, expected_ino=expected_ino)
        return result, opened, closed

    def test_full_observation_opens_nonblocking_cloexec_and_closes(self):
        result, opened, closed = self._observe()
        self.assertEqual(result, source.PIPE_FULL_PROVEN)
        opened.assert_called_once_with(
            self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        closed.assert_called_once_with(7)

    def test_drain_one_byte_is_not_full_and_still_closes(self):
        for unread in (0, 1, 4095):
            with self.subTest(unread=unread):
                result, _, closed = self._observe(unread=unread)
                self.assertEqual(result, source.PIPE_FULL_NOT_FULL)
                closed.assert_called_once_with(7)

    def test_capacity_and_unread_must_be_positive_and_equal(self):
        for unread, capacity in ((0, 4096), (4096, 0), (4096, -1)):
            with self.subTest(unread=unread, capacity=capacity):
                result, _, closed = self._observe(
                    unread=unread, capacity=capacity)
                self.assertIn(result, (source.PIPE_FULL_NOT_FULL,
                                       source.PIPE_FULL_UNAVAILABLE))
                closed.assert_called_once_with(7)

    def test_endpoint_mismatch_and_non_fifo_are_not_proof(self):
        for info in (
            mock.Mock(st_mode=stat.S_IFIFO | 0o600, st_dev=42, st_ino=701),
            mock.Mock(st_mode=stat.S_IFIFO | 0o600, st_dev=43, st_ino=700),
            mock.Mock(st_mode=stat.S_IFREG | 0o600, st_dev=42, st_ino=700),
        ):
            with self.subTest(info=info):
                result, _, closed = self._observe(info=info)
                self.assertEqual(result, source.PIPE_FULL_MISMATCH)
                closed.assert_called_once_with(7)

    def test_unavailable_observations_never_retain_a_reader(self):
        for kwargs, open_attempted in (
            ({"expected_dev": None}, False),
            ({"expected_ino": 0}, False),
            ({"supported": False}, False),
            ({"open_error": OSError(13, "denied")}, True),
        ):
            with self.subTest(kwargs=kwargs):
                result, opened, closed = self._observe(**kwargs)
                self.assertEqual(result, source.PIPE_FULL_UNAVAILABLE)
                if open_attempted:
                    opened.assert_called_once()
                else:
                    opened.assert_not_called()
                closed.assert_not_called()

    def test_close_failure_never_reports_full_pipe(self):
        result, _, closed = self._observe(
            close_error=OSError(9, "descriptor already gone"))
        self.assertEqual(result, source.PIPE_FULL_UNAVAILABLE)
        closed.assert_called_once_with(7)

    def test_zero_pipe_device_is_still_a_bound_identity(self):
        info = mock.Mock(st_mode=stat.S_IFIFO | 0o600, st_dev=0, st_ino=700)
        result, opened, closed = self._observe(info=info, expected_dev=0)
        self.assertEqual(result, source.PIPE_FULL_PROVEN)
        opened.assert_called_once()
        closed.assert_called_once_with(7)

    def test_errors_after_open_close_the_observation_fd(self):
        for kwargs in (
            {"stat_error": OSError(5, "io")},
            {"fcntl_error": OSError(22, "bad ioctl")},
        ):
            with self.subTest(kwargs=kwargs):
                result, _, closed = self._observe(**kwargs)
                self.assertEqual(result, source.PIPE_FULL_UNAVAILABLE)
                closed.assert_called_once_with(7)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and source.pipe_full_observation_supported(),
        "observed full-pipe proof is Linux-only; mocks cover non-Linux hosts")
    def test_linux_controlled_pipe_observation_does_not_consume_bytes(self):
        import termios
        from array import array

        read_fd, write_fd = os.pipe()
        try:
            capacity = fcntl.fcntl(read_fd, fcntl.F_GETPIPE_SZ)
            self.assertGreater(capacity, 0)
            os.set_blocking(write_fd, False)
            written = 0
            while written < capacity:
                try:
                    chunk = os.write(write_fd, b"x" * (capacity - written))
                except BlockingIOError:
                    break
                self.assertGreater(chunk, 0)
                written += chunk
            self.assertEqual(written, capacity)
            unread_before = array("i", [0])
            fcntl.ioctl(read_fd, termios.FIONREAD, unread_before, True)
            self.assertEqual(unread_before[0], capacity)
            info = os.fstat(read_fd)
            pid_dir = self.proc / str(os.getpid()) / "fd"
            pid_dir.mkdir(parents=True)
            (pid_dir / "9").symlink_to(f"/proc/self/fd/{read_fd}")
            result = source.observe_owned_stdout_pipe_full(
                self.proc, os.getpid(), 9,
                expected_dev=info.st_dev, expected_ino=info.st_ino)
            self.assertEqual(result, source.PIPE_FULL_PROVEN)
            unread_after = array("i", [0])
            fcntl.ioctl(read_fd, termios.FIONREAD, unread_after, True)
            self.assertEqual(unread_after[0], unread_before[0])
            drained = 0
            while drained < capacity:
                chunk = os.read(read_fd, capacity - drained)
                self.assertGreater(len(chunk), 0)
                drained += len(chunk)
            self.assertEqual(drained, capacity)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and source.pipe_full_observation_supported(),
        "observed full-pipe proof is Linux-only; mocks cover non-Linux hosts")
    def test_linux_draining_one_byte_rejects_the_second_proof(self):
        import termios
        from array import array

        read_fd, write_fd = os.pipe()
        try:
            capacity = fcntl.fcntl(read_fd, fcntl.F_GETPIPE_SZ)
            os.set_blocking(write_fd, False)
            written = 0
            while written < capacity:
                try:
                    chunk = os.write(write_fd, b"x" * (capacity - written))
                except BlockingIOError:
                    break
                self.assertGreater(chunk, 0)
                written += chunk
            self.assertEqual(written, capacity)
            self.assertEqual(os.read(read_fd, 1), b"x")
            info = os.fstat(read_fd)
            pid_dir = self.proc / str(os.getpid()) / "fd"
            pid_dir.mkdir(parents=True)
            (pid_dir / "9").symlink_to(f"/proc/self/fd/{read_fd}")
            result = source.observe_owned_stdout_pipe_full(
                self.proc, os.getpid(), 9,
                expected_dev=info.st_dev, expected_ino=info.st_ino)
            self.assertEqual(result, source.PIPE_FULL_NOT_FULL)
            unread = array("i", [0])
            fcntl.ioctl(read_fd, termios.FIONREAD, unread, True)
            self.assertEqual(unread[0], capacity - 1)
            drained = 0
            while drained < capacity - 1:
                chunk = os.read(read_fd, capacity - 1 - drained)
                self.assertGreater(len(chunk), 0)
                drained += len(chunk)
            self.assertEqual(drained, capacity - 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)


class TestLfsSourceWitness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.pid = 100
        self.object_path = self.root / "data" / "lfs" / "repo" / "oid"
        self.object_path.parent.mkdir(parents=True)
        self.object_path.write_bytes(b"x" * 100)
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=50))
        (self.proc / str(self.pid) / "fd").mkdir(parents=True, exist_ok=True)
        self.ino = self.object_path.stat().st_ino
        self.witness = source.LfsSourceWitness(
            self.pid, self.object_path, 100, proc_root=self.proc
        )
        self.assertTrue(self.witness.prepare_no_match())

    def tearDown(self):
        self.temp.cleanup()

    def _remove_fds(self):
        fd_dir = self.proc / str(self.pid) / "fd"
        fdinfo_dir = self.proc / str(self.pid) / "fdinfo"
        for directory in (fd_dir, fdinfo_dir):
            if directory.exists():
                for entry in directory.iterdir():
                    entry.unlink()

    def _add_fd(self, fd=9, pos=40, inode=None, flags=0, mnt_id=77):
        fd_dir = self.proc / str(self.pid) / "fd"
        fd_dir.mkdir(parents=True, exist_ok=True)
        link = fd_dir / str(fd)
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(self.object_path)
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / str(fd),
                pos=pos, flags=flags, ino=self.ino if inode is None else inode,
                mnt_id=mnt_id)

    def test_unique_readable_descriptor_below_size_qualifies(self):
        self.assertTrue(self.witness.prepare_no_match())
        self._add_fd()
        self.assertTrue(self.witness.bind())
        report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertTrue(report["source_unfinished"])
        self.assertEqual(report["source_position"], 40)
        self.assertEqual(report["source_remaining"], 60)
        self.assertNotIn(str(self.object_path), json.dumps(report))
        self.assertNotIn("oid", json.dumps(report))

    def test_eof_wrong_inode_multiple_fds_and_missing_fdinfo_fail(self):
        self._remove_fds()
        eof = source.LfsSourceWitness(self.pid, self.object_path, 100, proc_root=self.proc)
        self.assertTrue(eof.prepare_no_match())
        self._add_fd(pos=100)
        self.assertFalse(eof.bind())
        self.assertEqual(eof.fatal_failure_code, source.SOURCE_FAILURE_POSITION_EOF)

        self._remove_fds()
        wrong = source.LfsSourceWitness(self.pid, self.object_path, 100, proc_root=self.proc)
        self.assertTrue(wrong.prepare_no_match())
        self._add_fd(pos=40, inode=self.ino + 1)
        self.assertFalse(wrong.bind())
        self.assertEqual(wrong.fatal_failure_code, source.SOURCE_FAILURE_NOT_READABLE)

        self._remove_fds()
        multiple = source.LfsSourceWitness(self.pid, self.object_path, 100, proc_root=self.proc)
        self.assertTrue(multiple.prepare_no_match())
        self._add_fd(fd=9, pos=40)
        self._add_fd(fd=10, pos=40)
        self.assertFalse(multiple.bind())
        self.assertEqual(multiple.fatal_failure_code, source.SOURCE_FAILURE_MULTIPLE_MATCH)

        self._remove_fds()
        missing = source.LfsSourceWitness(self.pid, self.object_path, 100, proc_root=self.proc)
        self.assertTrue(missing.prepare_no_match())
        self._add_fd(fd=9, pos=40)
        (self.proc / str(self.pid) / "fdinfo" / "9").unlink()
        self.assertFalse(missing.bind())
        self.assertEqual(missing.fatal_failure_code, source.SOURCE_FAILURE_FDINFO)

    def test_pre_request_owner_change_before_fd_is_fatal_and_sticky(self):
        self.assertFalse(self.witness.bind())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=51))
        self.assertFalse(self.witness.bind())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_IDENTITY)
        self._add_fd(pos=40)
        self.assertFalse(self.witness.sample()["qualified"])
        self.assertFalse(self.witness.bind())
        self.assertFalse(self.witness.prepare_no_match())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_IDENTITY)

    def test_repeated_prepare_cannot_reanchor_changed_owner(self):
        witness = source.LfsSourceWitness(self.pid, self.object_path, 100,
                                          proc_root=self.proc)
        self.assertTrue(witness.prepare_no_match())
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=51))
        self.assertFalse(witness.prepare_no_match())
        self.assertEqual(witness.fatal_failure_code, source.SOURCE_FAILURE_IDENTITY)
        self._add_fd(pos=40)
        self.assertFalse(witness.bind())

    def test_unprepared_caller_cannot_bind_post_request_identity(self):
        self._remove_fds()
        witness = source.LfsSourceWitness(self.pid, self.object_path, 100,
                                          proc_root=self.proc)
        self._add_fd(pos=40)
        self.assertFalse(witness.bind())
        self.assertEqual(witness.fatal_failure_code, source.SOURCE_FAILURE_PRE_ANCHOR)
        self.assertFalse(witness.sample()["qualified"])

    def test_no_fd_progress_then_stable_position_qualifies_after_progress(self):
        self.assertTrue(self.witness.prepare_no_match())
        self.assertFalse(self.witness.bind())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        self._add_fd(pos=40)
        self.assertTrue(self.witness.bind())
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=41, flags=0, ino=self.ino)
        progress = self.witness.sample()
        self.assertFalse(progress["qualified"])
        self.assertEqual(progress["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(progress["failure_code"], source.SOURCE_FAILURE_POSITION_PROGRESS)
        self.assertTrue(self.witness.sample()["qualified"])

        # The last progress sample starts a fresh continuous source window.
        window = revocation_backpressure.SustainedStallWindow(
            500_000_000, max_gap_ns=100_000_000
        )
        for now in range(0, 561_000_000, 20_000_000):
            qualified = now >= 60_000_000
            window.observe(_window_sample(now, qualified), now)
            if now < 560_000_000:
                self.assertFalse(window.qualified)
        self.assertTrue(window.qualified)

    def test_backwards_and_eof_positions_cannot_recover(self):
        self._add_fd(pos=40)
        self.assertTrue(self.witness.bind())
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=41, flags=0, ino=self.ino)
        self.assertFalse(self.witness.sample()["qualified"])
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=40, flags=0, ino=self.ino)
        self.assertFalse(self.witness.sample()["qualified"])
        self.assertEqual(self.witness.fatal_failure_code,
                         source.SOURCE_FAILURE_POSITION_RESET)
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=41, flags=0, ino=self.ino)
        self.assertFalse(self.witness.sample()["qualified"],
                         "a fatal backwards position must not be recovered by retry")

        self._remove_fds()
        eof = source.LfsSourceWitness(self.pid, self.object_path, 100, proc_root=self.proc)
        self.assertTrue(eof.prepare_no_match())
        self._add_fd(pos=40)
        self.assertTrue(eof.bind())
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=100, flags=0, ino=self.ino)
        self.assertFalse(eof.sample()["qualified"])
        self.assertEqual(eof.fatal_failure_code, source.SOURCE_FAILURE_POSITION_EOF)
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=40, flags=0, ino=self.ino)
        self.assertFalse(eof.sample()["qualified"],
                         "EOF then rewind must not requalify")

    def test_fd_replacement_and_pid_reuse_cannot_recover(self):
        self._add_fd(pos=40)
        self.assertTrue(self.witness.bind())
        replacement = self.root / "data" / "lfs" / "repo" / "replacement"
        replacement.write_bytes(b"z" * 100)
        link = self.proc / str(self.pid) / "fd" / "9"
        link.unlink()
        link.symlink_to(replacement)
        self.assertFalse(self.witness.sample()["qualified"])
        self.assertNotEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        link.unlink()
        link.symlink_to(self.object_path)
        self.assertFalse(self.witness.sample()["qualified"],
                         "an already-bound FD replacement must not be adopted back")

        self._remove_fds()
        identity = source.LfsSourceWitness(self.pid, self.object_path, 100,
                                           proc_root=self.proc)
        self.assertTrue(identity.prepare_no_match())
        self._add_fd(pos=40)
        self.assertTrue(identity.bind())
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=51))
        self.assertFalse(identity.sample()["qualified"])
        self.assertEqual(identity.fatal_failure_code, source.SOURCE_FAILURE_IDENTITY)
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=50))
        self.assertFalse(identity.sample()["qualified"],
                         "owner PID starttime reuse must not recover")

    def test_permission_denial_and_missing_identity_fail_closed(self):
        self._add_fd()
        self.assertTrue(self.witness.bind())
        with mock.patch("transfer_revocation_source.read_fdinfo",
                        side_effect=source.SourceParseError):
            self.assertFalse(self.witness.sample()["qualified"])
        (self.proc / str(self.pid) / "stat").unlink()
        self.assertFalse(self.witness.sample()["qualified"])


class TestGitSourceWitness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.service_pid = 100
        self.tgid = 200
        self.tid = 201
        self.pipe_inode = 700
        _write(self.proc / "100" / "stat", _stat_text(100, "rootyard", starttime=50))
        _write(self.proc / "200" / "stat", _stat_text(200, "git", ppid=100, pgid=200,
                                                       starttime=60))
        _write(self.proc / "200" / "task" / "201" / "stat",
               _stat_text(201, "git", ppid=200, pgid=200, starttime=61))
        self._service_pipe()
        self._task_files()
        self.identity = observer.GroupIdentity(200, 200, 60)
        self.witness = git_source.GitSourceWitness(
            100, [self.identity], proc_root=self.proc, uid=None, arch="x86_64"
        )

    def tearDown(self):
        self.temp.cleanup()

    def _service_pipe(self):
        fd_dir = self.proc / "100" / "fd"
        fd_dir.mkdir(parents=True, exist_ok=True)
        (fd_dir / "5").symlink_to(f"pipe:[{self.pipe_inode}]")
        _fdinfo(self.proc / "100" / "fdinfo" / "5", pos=0, flags=0,
                ino=self.pipe_inode)

    def _task_files(self, *, fd=1, syscall="1 0x1 0x2 0x10 0x0 0x0 0x0",
                    wchan="pipe_write\n", pipe_inode=None, pgid=200,
                    starttime=61):
        pipe_inode = self.pipe_inode if pipe_inode is None else pipe_inode
        task = self.proc / "200" / "task" / "201"
        _write(task / "stat", _stat_text(201, "git", ppid=200, pgid=pgid,
                                         starttime=starttime))
        _write(task / "syscall", syscall)
        _write(task / "wchan", wchan)
        fd_dir = self.proc / "200" / "fd"
        fd_dir.mkdir(parents=True, exist_ok=True)
        link = fd_dir / "1"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(f"pipe:[{pipe_inode}]")
        _fdinfo(self.proc / "200" / "fdinfo" / "1", pos=0,
                flags=1 if fd == 1 else 2, ino=pipe_inode)
        task_fd_dir = task / "fd"
        task_fd_dir.mkdir(parents=True, exist_ok=True)
        task_link = task_fd_dir / "1"
        if task_link.exists() or task_link.is_symlink():
            task_link.unlink()
        task_link.symlink_to(f"pipe:[{pipe_inode}]")
        _fdinfo(task / "fdinfo" / "1", pos=0,
                flags=1 if fd == 1 else 2, ino=pipe_inode)

    def _sample_running_recheck(self, witness, wchan, *, change=None):
        self._task_files(wchan=wchan)
        task_path = self.proc / "200" / "task" / "201" / "stat"
        read_text = witness._task_text

        def read_then_run(tgid, tid, name):
            text = read_text(tgid, tid, name)
            if name == "wchan":
                _write(task_path, _stat_text(201, "git", state="R", pgid=200, starttime=61))
                if change is not None:
                    change()
            return text

        with mock.patch.object(witness, "_task_text", side_effect=read_then_run):
            return witness.sample()

    def test_sleeping_write_to_owned_stdout_pipe_qualifies(self):
        self.assertTrue(self.witness.bind())
        report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertTrue(report["source_pipe_paired"])
        self.assertTrue(report["source_writer_blocked"])
        self.assertEqual(report["source_syscall_kind_code"], 1)
        serialized = json.dumps(report)
        self.assertNotIn(str(self.proc), serialized)
        self.assertNotIn("0x", serialized)
        self.assertNotIn("pipe_write", serialized)
        self.assertNotIn("wchan_shape", report)
        self.assertNotIn("wchan_writer_recheck", report)

    def test_missing_wchan_diagnoses_once_and_stays_fatal(self):
        for wchan, state, starttime, expected in (
            (" \n", "D", 61, "same_writer_sleeping_in_stdout_write"),
            ("0\n", "S", 61, "same_writer_sleeping_in_stdout_write"),
            ("0\n", "T", 61, "same_writer_other"),
            ("0\n", "R", 62, "identity_changed"),
            ("0\n", None, 61, "unavailable"),
        ):
            with self.subTest(expected=expected):
                self._task_files()
                witness = git_source.GitSourceWitness(
                    self.service_pid, [self.identity], proc_root=self.proc)
                self.assertTrue(witness.bind())
                task = witness._task_stat(self.tgid, self.tid)
                recheck = None if state is None else replace(
                    task, state=state, starttime=starttime)
                self._task_files(wchan=wchan)
                with mock.patch.object(witness, "_task_stat", side_effect=[task, recheck]) as read:
                    report = witness.sample()
                    self._task_files()
                    self.assertEqual(witness.sample(), report)
                self.assertEqual(read.call_args_list, [mock.call(self.tgid, self.tid)] * 2)
                self.assertFalse(report["qualified"])
                self.assertEqual(report["failure_code"], source.SOURCE_FAILURE_WCHAN)
                self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_WCHAN)
                self.assertEqual(report["wchan_shape"], "zero" if wchan.strip() else "empty")
                self.assertEqual(report["wchan_writer_recheck"], expected)

    def test_running_recheck_rejects_sample_and_requires_a_fresh_pressure_window(self):
        self.assertTrue(self.witness.bind())
        writer = self.witness.writer
        window = revocation_backpressure.SustainedStallWindow(500_000_000)
        for now_ms in range(20, 521, 20):
            now = now_ms * 1_000_000
            window.observe(_window_sample(now, self.witness.sample()["qualified"]), now)
        self.assertTrue(window.qualified)

        for now, wchan in ((540_000_000, "0\n"), (560_000_000, " \n")):
            report = self._sample_running_recheck(self.witness, wchan)
            self.assertFalse(report["qualified"])
            self.assertFalse(report["source_writer_blocked"])
            self.assertEqual(report["failure_code"], source.SOURCE_FAILURE_WRITER_RUNNING)
            self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
            self.assertNotIn("wchan_writer_recheck", report)
            self.assertIs(self.witness.writer, writer)
            self.assertFalse(window.observe(_window_sample(now, report["qualified"]), now))
            self.assertEqual(window.last_reset_reason, "source_unqualified")
            self.assertEqual(window.samples, [])

        self._task_files()
        for now_ms in range(580, 1081, 20):
            now = now_ms * 1_000_000
            report = self.witness.sample()
            self.assertTrue(report["qualified"])
            self.assertEqual(
                window.observe(_window_sample(now, report["qualified"]), now), now_ms == 1080,
            )
        self.assertIs(self.witness.writer, writer)

    def test_running_recheck_with_changed_stat_or_fd_stays_fatal(self):
        task_stat = self.proc / "200" / "task" / "201" / "stat"
        for path, changed, expected in (
            (task_stat, "malformed stat", "unavailable"),
            (task_stat, _stat_text(202, "git", state="R", pgid=200, starttime=61), "unavailable"),
            (task_stat, _stat_text(201, "git", state="R", pgid=201, starttime=61), "identity_changed"),
            (self.proc / "100" / "stat", _stat_text(100, "rootyard", starttime=51), "identity_changed"),
            (self.proc / "200" / "stat", _stat_text(200, "git", pgid=201, starttime=60), "identity_changed"),
            (self.proc / "100" / "fdinfo" / "5",
             "pos: 0\nflags: 01\nino: 700\nmnt_id: 77\n", "identity_changed"),
            (self.proc / "200" / "fdinfo" / "1",
             "pos: 0\nflags: 01\nino: 701\nmnt_id: 77\n", "identity_changed"),
            (self.proc / "200" / "fdinfo" / "1", "malformed fdinfo", "unavailable"),
        ):
            with self.subTest(path=path.relative_to(self.proc), changed=changed):
                self._task_files()
                original = path.read_text(encoding="utf-8")
                witness = git_source.GitSourceWitness(
                    self.service_pid, [self.identity], proc_root=self.proc)
                self.assertTrue(witness.bind())
                report = self._sample_running_recheck(
                    witness, "0\n", change=lambda: _write(path, changed))
                _write(path, original)
                self._task_files()
                self.assertFalse(report["qualified"])
                self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_WCHAN)
                self.assertEqual(report["wchan_writer_recheck"], expected)
                self.assertEqual(witness.sample(), report)

    def test_running_recheck_with_replaced_pipe_stays_fatal(self):
        self.assertTrue(self.witness.bind())
        writer_fd = self.proc / "200" / "fd" / "1"

        def replace_pipe():
            writer_fd.unlink()
            writer_fd.symlink_to("pipe:[701]")

        report = self._sample_running_recheck(self.witness, "0\n", change=replace_pipe)
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_WCHAN)
        self.assertEqual(report["wchan_writer_recheck"], "identity_changed")
        self._task_files()
        self.assertEqual(self.witness.sample(), report)

    def test_missing_or_undecodable_wchan_file_stays_fatal(self):
        path = self.proc / "200" / "task" / "201" / "wchan"
        for contents in (None, b"\xff"):
            with self.subTest(contents=contents):
                self._task_files()
                witness = git_source.GitSourceWitness(
                    self.service_pid, [self.identity], proc_root=self.proc)
                self.assertTrue(witness.bind())
                if contents is None:
                    path.unlink()
                else:
                    path.write_bytes(contents)
                report = witness.sample()
                self.assertFalse(report["qualified"])
                self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_UNOBSERVABLE)
                self.assertNotIn("wchan_writer_recheck", report)
                self._task_files()
                self.assertEqual(witness.sample(), report)

    def test_writev_on_owned_stdout_pipe_qualifies(self):
        self._task_files(syscall="20 0x1 0x2 0x3 0x0 0x0 0x0")
        self.assertTrue(self.witness.bind())
        report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertEqual(report["source_syscall_kind_code"], 2)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_PIPE_WRITE_SLEEP)
        self.assertFalse(report["source_pipe_full"])

    def test_pipe_write_proof_does_not_open_a_second_reader(self):
        self.assertTrue(self.witness.bind())
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full") as observed:
            report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_PIPE_WRITE_SLEEP)
        observed.assert_not_called()

    def _second_writer(self, *, tid=202, starttime=63, wchan="0\n",
                       syscall="1 0x1 0x2 0x10 0x0 0x0 0x0"):
        task = self.proc / "200" / "task" / str(tid)
        _write(task / "stat", _stat_text(tid, "git", ppid=200, pgid=200,
                                         starttime=starttime))
        _write(task / "syscall", syscall)
        _write(task / "wchan", wchan)

    def test_initial_bind_requires_pipe_write_not_zero_wchan(self):
        self._task_files(wchan="0\n")
        witness = git_source.GitSourceWitness(
            self.service_pid, [self.identity], proc_root=self.proc)
        self.assertFalse(witness.bind())
        self.assertEqual(witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        self.assertEqual(witness.failure_code, source.SOURCE_FAILURE_NO_CANDIDATE)
        self._task_files(wchan="pipe_write\n")
        self.assertTrue(witness.bind())

    def test_zero_wchan_full_owned_stdout_pipe_is_positive_proof(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        self.witness.writer.service_dev = 42
        with mock.patch.object(
                git_source, "_read_pipe_stat",
                return_value=git_source._PipeInfo(dev=42, ino=self.pipe_inode)), \
                mock.patch.object(
                    git_source, "observe_owned_stdout_pipe_full",
                    return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_OWNED_STDOUT_PIPE_FULL)
        self.assertTrue(report["source_pipe_full"])
        self.assertEqual(report["failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertNotIn("wchan_shape", report)
        self.assertNotIn("wchan_writer_recheck", report)
        observed.assert_called_once_with(
            self.proc, self.service_pid, 5,
            expected_dev=42, expected_ino=self.pipe_inode)
        serialized = json.dumps(report)
        for raw in (str(self.proc), "pipe:[", "[700]", "0x", "wchan"):
            self.assertNotIn(raw, serialized)

    def test_writev_zero_wchan_never_uses_full_pipe_fallback(self):
        self.assertTrue(self.witness.bind())
        self._task_files(
            wchan="0\n", syscall="20 0x1 0x2 0x3 0x0 0x0 0x0")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(report["failure_code"], source.SOURCE_FAILURE_SYSCALL)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_NONE)
        observed.assert_not_called()

    def test_write_to_writev_swap_after_probe_is_not_a_sample(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        self.witness.writer.service_dev = 42

        def swap_then_prove(*args, **kwargs):
            self._task_files(
                wchan="0\n", syscall="20 0x1 0x2 0x3 0x0 0x0 0x0")
            return source.PIPE_FULL_PROVEN

        with mock.patch.object(
                git_source, "_read_pipe_stat",
                return_value=git_source._PipeInfo(dev=42, ino=self.pipe_inode)), \
                mock.patch.object(
                    git_source, "observe_owned_stdout_pipe_full",
                    side_effect=swap_then_prove) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(report["failure_code"], source.SOURCE_FAILURE_SYSCALL)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_NONE)
        observed.assert_called_once()

    def test_task_specific_stdout_fd_replacement_blocks_fallback(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        link = self.proc / "200" / "task" / "201" / "fd" / "1"
        link.unlink()
        link.symlink_to("pipe:[701]")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        observed.assert_not_called()

    def test_bound_service_dev_change_blocks_fallback(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        self.witness.writer.service_dev = 42
        with mock.patch.object(
                git_source, "_read_pipe_stat",
                return_value=git_source._PipeInfo(dev=43, ino=self.pipe_inode)), \
                mock.patch.object(
                    git_source, "observe_owned_stdout_pipe_full",
                    return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        observed.assert_not_called()

    def test_bound_service_dev_change_after_probe_blocks_proof(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        self.witness.writer.service_dev = 42
        changed = [False]

        def service_pipe(*args, **kwargs):
            return git_source._PipeInfo(
                dev=43 if changed[0] else 42, ino=self.pipe_inode)

        def change_then_prove(*args, **kwargs):
            changed[0] = True
            return source.PIPE_FULL_PROVEN

        with mock.patch.object(
                git_source, "_read_pipe_stat", side_effect=service_pipe), \
                mock.patch.object(
                    git_source, "observe_owned_stdout_pipe_full",
                    side_effect=change_then_prove):
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_NONE)

    def _task_dir_error(self, error):
        real_iterdir = Path.iterdir

        def fail(path):
            if path == self.proc / "200" / "task":
                raise error
            return real_iterdir(path)

        return mock.patch.object(
            Path, "iterdir", autospec=True, side_effect=fail)

    def test_unreadable_task_directory_blocks_initial_bind(self):
        witness = git_source.GitSourceWitness(
            self.service_pid, [self.identity], proc_root=self.proc)
        with self._task_dir_error(PermissionError(13, "denied")):
            self.assertFalse(witness.bind())
        self.assertEqual(witness.fatal_failure_code,
                         source.SOURCE_FAILURE_UNOBSERVABLE)

    def test_unreadable_task_directory_blocks_full_pipe_sample(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        with self._task_dir_error(PermissionError(13, "denied")), \
                mock.patch.object(
                    git_source, "observe_owned_stdout_pipe_full",
                    return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"],
                         source.SOURCE_FAILURE_UNOBSERVABLE)
        observed.assert_not_called()

    def test_vanished_task_directory_is_a_legal_empty_census(self):
        witness = git_source.GitSourceWitness(
            self.service_pid, [self.identity], proc_root=self.proc)
        with self._task_dir_error(FileNotFoundError(2, "gone")):
            self.assertFalse(witness.bind())
        self.assertEqual(witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        self.assertEqual(witness.failure_code, source.SOURCE_FAILURE_NO_CANDIDATE)
        self.assertTrue(witness.bind())

    def test_unreadable_census_fd_link_fails_closed(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        path = self.proc / "200" / "fd" / "1"
        path.unlink()
        path.mkdir()
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"],
                         source.SOURCE_FAILURE_UNOBSERVABLE)
        observed.assert_not_called()

    def test_unreadable_census_fdinfo_fails_closed(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        path = self.proc / "200" / "fdinfo" / "1"
        path.unlink()
        path.mkdir()
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"],
                         source.SOURCE_FAILURE_UNOBSERVABLE)
        observed.assert_not_called()

    def test_second_zero_wchan_writer_makes_census_ambiguous_and_sticky(self):
        self.assertTrue(self.witness.bind())
        self._second_writer(wchan="0\n")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_TASK)
        observed.assert_not_called()
        shutil.rmtree(self.proc / "200" / "task" / "202")
        self.assertFalse(self.witness.sample()["qualified"],
                         "an ambiguous writer census must remain fatal")

    def test_second_zero_wchan_writer_blocks_initial_bind(self):
        self._second_writer(wchan="0\n")
        witness = git_source.GitSourceWitness(
            self.service_pid, [self.identity], proc_root=self.proc)
        self.assertFalse(witness.bind())
        self.assertEqual(witness.fatal_failure_code, source.SOURCE_FAILURE_TASK)

    def test_full_pipe_not_full_is_transient_and_recovers_from_new_window(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_NOT_FULL):
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(report["failure_code"],
                         source.SOURCE_FAILURE_PIPE_NOT_FULL)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_NONE)
        self.assertFalse(report["source_pipe_full"])
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN):
            report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_OWNED_STDOUT_PIPE_FULL)

    def test_full_pipe_unavailable_keeps_fatal_wchan_diagnostics(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_UNAVAILABLE):
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"],
                         source.SOURCE_FAILURE_WCHAN)
        self.assertEqual(report["wchan_shape"], "zero")
        self.assertEqual(report["wchan_writer_recheck"],
                         "same_writer_sleeping_in_stdout_write")

    def test_full_pipe_probe_detects_stdout_endpoint_replacement(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")

        def replace_then_prove(*args, **kwargs):
            self._task_files(pipe_inode=701, wchan="0\n")
            return source.PIPE_FULL_PROVEN

        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                side_effect=replace_then_prove):
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        self._task_files(wchan="pipe_write\n")
        self.assertFalse(self.witness.sample()["qualified"],
                         "a replaced stdout endpoint must not be adopted back")

    def test_service_read_endpoint_replacement_blocks_the_probe(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        link = self.proc / "100" / "fd" / "5"
        link.unlink()
        link.symlink_to("pipe:[701]")
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        observed.assert_not_called()

    def test_two_owned_service_read_endpoints_block_the_probe(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")
        fd_dir = self.proc / "100" / "fd"
        (fd_dir / "6").symlink_to(f"pipe:[{self.pipe_inode}]")
        _fdinfo(self.proc / "100" / "fdinfo" / "6", pos=0, flags=0, ino=0)
        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                return_value=source.PIPE_FULL_PROVEN) as observed:
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_PIPE)
        observed.assert_not_called()

    def test_full_pipe_probe_after_wake_is_not_positive_proof(self):
        self.assertTrue(self.witness.bind())
        self._task_files(wchan="0\n")

        def wake_then_prove(*args, **kwargs):
            self._task_files(wchan="0\n", syscall="running")
            return source.PIPE_FULL_PROVEN

        with mock.patch.object(
                git_source, "observe_owned_stdout_pipe_full",
                side_effect=wake_then_prove):
            report = self.witness.sample()
        self.assertFalse(report["qualified"])
        self.assertEqual(report["fatal_failure_code"], source.SOURCE_FAILURE_NONE)
        self.assertEqual(report["failure_code"],
                         source.SOURCE_FAILURE_NO_BLOCKED_WRITER)
        self.assertEqual(report["source_proof_kind_code"],
                         source.SOURCE_PROOF_KIND_NONE)

    def test_single_full_pipe_sample_does_not_relax_sustained_window(self):
        window = revocation_backpressure.SustainedStallWindow(
            500_000_000, max_gap_ns=100_000_000
        )
        for now in range(0, 300_000_000, 20_000_000):
            window.observe(_window_sample(now, True), now)
        self.assertFalse(window.qualified)
        window.observe(_window_sample(300_000_000, False), 300_000_000)
        self.assertFalse(window.qualified)
        for offset in range(0, 501_000_000, 20_000_000):
            now = 320_000_000 + offset
            window.observe(_window_sample(now, True), now)
            if offset < 500_000_000:
                self.assertFalse(window.qualified)
        self.assertTrue(window.qualified)

    def test_no_candidate_then_blocked_writer_recovers_and_window_qualifies(self):
        self._task_files(syscall="running")
        self.assertFalse(self.witness.bind())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        self._task_files(syscall="1 0x1 0x2 0x10 0x0 0x0 0x0")
        self.assertTrue(self.witness.sample()["qualified"])
        window = revocation_backpressure.SustainedStallWindow(
            500_000_000, max_gap_ns=100_000_000
        )
        for now in range(0, 561_000_000, 20_000_000):
            qualified = now >= 60_000_000
            window.observe(_window_sample(now, qualified, inode=700), now)
            if now < 560_000_000:
                self.assertFalse(window.qualified)
        self.assertTrue(window.qualified)

    def test_running_writer_then_blocked_same_identity_recovers(self):
        self._task_files(syscall="running")
        self.assertFalse(self.witness.bind())
        self.assertFalse(self.witness.sample()["qualified"])
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_NONE)
        self._task_files(syscall="1 0x1 0x2 0x10 0x0 0x0 0x0")
        self.assertTrue(self.witness.sample()["qualified"])

    def test_task_identity_and_pipe_change_cannot_recover(self):
        self.assertTrue(self.witness.bind())
        self._task_files(starttime=62)
        self.assertFalse(self.witness.sample()["qualified"])
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_TASK)
        self._task_files(starttime=61)
        self.assertFalse(self.witness.sample()["qualified"],
                         "task starttime reuse must not be cleared by retry")

        pipe = git_source.GitSourceWitness(
            100, [self.identity], proc_root=self.proc, uid=None, arch="x86_64"
        )
        self.assertTrue(pipe.bind())
        self._task_files(pipe_inode=701)
        self.assertFalse(pipe.sample()["qualified"])
        self.assertEqual(pipe.fatal_failure_code, source.SOURCE_FAILURE_PIPE)
        self._task_files(pipe_inode=700)
        self.assertFalse(pipe.sample()["qualified"],
                         "paired pipe replacement must not be adopted back")

    def test_two_blocked_writers_are_ambiguous_and_cannot_recover(self):
        _write(self.proc / "200" / "task" / "202" / "stat",
               _stat_text(202, "git", ppid=200, pgid=200, starttime=63))
        _write(self.proc / "200" / "task" / "202" / "syscall",
               "1 0x1 0x2 0x10 0x0 0x0 0x0")
        _write(self.proc / "200" / "task" / "202" / "wchan", "pipe_write\n")
        self.assertFalse(self.witness.bind())
        self.assertEqual(self.witness.fatal_failure_code, source.SOURCE_FAILURE_TASK)
        (self.proc / "200" / "task" / "202" / "syscall").unlink()
        self.assertFalse(self.witness.sample()["qualified"])

    def test_running_unknown_syscall_and_wait4_fail(self):
        for syscall in ("running", "999 0x1 0x2 0x3", "61 0x1 0x2 0x3"):
            self._task_files(syscall=syscall)
            self.assertFalse(self.witness.bind())

    def test_stderr_unowned_pipe_wrong_pgid_and_unknown_wchan_fail(self):
        self._task_files(syscall="1 0x2 0x2 0x10 0x0 0x0 0x0")
        self.assertFalse(self.witness.bind())
        self._task_files(pipe_inode=701)
        self.assertFalse(self.witness.bind())
        self._task_files(pgid=201)
        self.assertFalse(self.witness.bind())
        self._task_files(wchan="anon_pipe_write\n")
        self.assertFalse(self.witness.bind())

    def test_multiple_writers_and_writer_identity_reuse_fail(self):
        self.assertTrue(self.witness.bind())
        self._task_files(starttime=62)
        self.assertFalse(self.witness.sample()["qualified"])
        _write(self.proc / "200" / "task" / "202" / "stat",
               _stat_text(202, "git", ppid=200, pgid=200, starttime=63))
        _write(self.proc / "200" / "task" / "202" / "syscall",
               "1 0x1 0x2 0x10 0x0 0x0 0x0")
        _write(self.proc / "200" / "task" / "202" / "wchan", "pipe_write\n")
        self.assertFalse(self.witness.bind())

    def test_permission_denial_fails_closed(self):
        syscall_path = self.proc / "200" / "task" / "201" / "syscall"
        syscall_path.chmod(0)
        try:
            self.assertFalse(self.witness.bind())
            self.assertEqual(self.witness.fatal_failure_code,
                             source.SOURCE_FAILURE_UNOBSERVABLE)
        finally:
            syscall_path.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
