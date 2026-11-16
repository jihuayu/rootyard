#!/usr/bin/env python3
"""Pure filesystem/mock tests for owned source witnesses."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

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

    def tearDown(self):
        self.temp.cleanup()

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
        self._add_fd(pos=100)
        self.assertFalse(self.witness.bind())
        self._add_fd(pos=40, inode=self.ino + 1)
        self.assertFalse(self.witness.bind())
        self._add_fd(fd=9, pos=40)
        self._add_fd(fd=10, pos=40)
        self.assertFalse(self.witness.bind())
        (self.proc / str(self.pid) / "fdinfo" / "9").unlink()
        self.assertFalse(self.witness.bind())

    def test_progress_file_replacement_and_pid_reuse_fail(self):
        self._add_fd()
        self.assertTrue(self.witness.bind())
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=41, flags=0, ino=self.ino)
        self.assertFalse(self.witness.sample()["qualified"])
        _fdinfo(self.proc / str(self.pid) / "fdinfo" / "9",
                pos=40, flags=0, ino=self.ino)
        self.object_path.unlink()
        self.object_path.write_bytes(b"y" * 100)
        self.assertFalse(self.witness.sample()["qualified"])
        replacement = source.LfsSourceWitness(
            self.pid, self.object_path, 100, proc_root=self.proc
        )
        _write(self.proc / str(self.pid) / "stat",
               _stat_text(self.pid, "rootyard", starttime=51))
        self.assertFalse(replacement.bind())

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
        _fdinfo(self.proc / "100" / "fdinfo" / "5", pos=0, flags=0, ino=0)

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
                flags=1 if fd == 1 else 2, ino=0)

    def test_sleeping_write_to_owned_stdout_pipe_qualifies(self):
        self.assertTrue(self.witness.bind())
        report = self.witness.sample()
        self.assertTrue(report["qualified"])
        self.assertTrue(report["source_pipe_paired"])
        self.assertTrue(report["source_writer_blocked"])
        self.assertEqual(report["source_syscall_kind_code"], 1)
        self.assertNotIn(str(self.proc), json.dumps(report))

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
        finally:
            syscall_path.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
