#!/usr/bin/env python3
"""Task-level owned Git stdout-pipe writer witness for Issue #37."""
from dataclasses import dataclass
import os
from pathlib import Path

from transfer_revocation_observer import (
    ObserverUnavailable,
    parse_proc_stat,
    read_proc_table,
)
from transfer_revocation_source import (
    SOURCE_FAILURE_IDENTITY,
    SOURCE_FAILURE_NONE,
    SOURCE_FAILURE_NOT_SLEEPING,
    SOURCE_FAILURE_PIPE,
    SOURCE_FAILURE_SYSCALL,
    SOURCE_FAILURE_TASK,
    SOURCE_FAILURE_UNOBSERVABLE,
    SOURCE_FAILURE_UNSUPPORTED_ARCH,
    SOURCE_FAILURE_WCHAN,
    SourceParseError,
    read_fdinfo,
    read_pipe_inode,
    read_service_identity,
    verify_service_identity,
    parse_syscall,
    parse_wchan,
    _fd_numbers,
)


@dataclass
class _Writer:
    tgid: int
    tid: int
    starttime: int
    pipe_inode: int
    service_fd: int
    syscall_kind: str


class GitSourceWitness:
    """Find one sleeping owned writer on the service-owned stdout pipe."""

    witness_kind_code = 2

    def __init__(self, service_pid, group_identities, *, proc_root=Path("/proc"),
                 uid=None, arch="x86_64"):
        self.service_pid = int(service_pid)
        self.group_identities = tuple(group_identities)
        self.proc_root = Path(proc_root)
        self.uid = os.geteuid() if uid is None else uid
        self.arch = arch
        self.service_identity = None
        self.writer = None
        self.qualified = False
        self.failure_code = SOURCE_FAILURE_NONE

    def _base_report(self, qualified, failure_code):
        return {
            "witness_version": 1,
            "witness_kind_code": self.witness_kind_code,
            "witness_available": bool(self.service_identity is not None),
            "qualified": bool(qualified),
            "failure_code": int(failure_code),
            "source_identity_unique": bool(qualified),
            "source_pipe_paired": bool(qualified),
            "source_writer_blocked": bool(qualified),
            "source_writer_starttime": (
                int(self.writer.starttime) if self.writer is not None else 0
            ),
            "source_syscall_kind_code": (
                1 if self.writer is not None and self.writer.syscall_kind == "write"
                else 2 if self.writer is not None else 0
            ),
        }

    def _fail(self, code):
        self.qualified = False
        self.failure_code = code
        return self._base_report(False, code)

    def _read_pipes(self):
        pipes = []
        for fd in _fd_numbers(self.proc_root, self.service_pid):
            try:
                inode = read_pipe_inode(self.proc_root, self.service_pid, fd)
                info = read_fdinfo(self.proc_root, self.service_pid, fd)
            except SourceParseError:
                continue
            if (info.flags & os.O_ACCMODE) == os.O_RDONLY:
                pipes.append((fd, inode))
        return pipes

    def _tasks_for_group(self, table, group):
        members = [
            process.pid for process in table.values()
            if process.pgid == group.pgid and process.live
        ]
        for tgid in sorted(members):
            task_dir = self.proc_root / str(tgid) / "task"
            try:
                entries = list(task_dir.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.name.isdigit():
                    yield tgid, int(entry.name)

    def bind(self):
        if self.arch != "x86_64":
            return self._fail(SOURCE_FAILURE_UNSUPPORTED_ARCH)["qualified"]
        if len(self.group_identities) != 1:
            return self._fail(SOURCE_FAILURE_TASK)["qualified"]
        group = self.group_identities[0]
        try:
            self.service_identity = read_service_identity(
                self.service_pid, proc_root=self.proc_root
            )
            table = read_proc_table(self.proc_root, uid=self.uid)
        except (OSError, SourceParseError, ObserverUnavailable):
            return self._fail(SOURCE_FAILURE_UNOBSERVABLE)["qualified"]
        leader = table.get(group.leader_pid)
        if leader is None or leader.starttime != group.leader_starttime:
            return self._fail(SOURCE_FAILURE_IDENTITY)["qualified"]
        try:
            read_pipes = self._read_pipes()
        except (OSError, SourceParseError):
            return self._fail(SOURCE_FAILURE_UNOBSERVABLE)["qualified"]
        candidates = []
        for tgid, tid in self._tasks_for_group(table, group):
            task_stat_path = self.proc_root / str(tgid) / "task" / str(tid) / "stat"
            try:
                task = parse_proc_stat(task_stat_path.read_text(encoding="utf-8"), pid=tid)
            except (OSError, ValueError):
                continue
            if task.pgid != group.pgid or task.state not in ("S", "D"):
                continue
            try:
                pipe_inode = read_pipe_inode(self.proc_root, tgid, 1)
                fd_info = read_fdinfo(self.proc_root, tgid, 1)
            except SourceParseError:
                continue
            if (fd_info.flags & os.O_ACCMODE) != os.O_WRONLY:
                continue
            matches = [fd for fd, inode in read_pipes if inode == pipe_inode]
            if len(matches) != 1:
                continue
            try:
                syscall = parse_syscall(
                    (self.proc_root / str(tgid) / "task" / str(tid) / "syscall")
                    .read_text(encoding="utf-8")
                )
                parse_wchan(
                    (self.proc_root / str(tgid) / "task" / str(tid) / "wchan")
                    .read_text(encoding="utf-8")
                )
            except (OSError, SourceParseError):
                continue
            if syscall.fd != 1 or syscall.count <= 0:
                continue
            candidates.append(_Writer(
                tgid=tgid, tid=tid, starttime=task.starttime,
                pipe_inode=pipe_inode, service_fd=matches[0],
                syscall_kind=syscall.kind,
            ))
        if not candidates:
            return self._fail(SOURCE_FAILURE_PIPE)["qualified"]
        if len(candidates) > 1:
            return self._fail(SOURCE_FAILURE_TASK)["qualified"]
        self.writer = candidates[0]
        self.qualified = True
        self.failure_code = SOURCE_FAILURE_NONE
        return True

    def sample(self):
        if not self.qualified or self.writer is None or self.service_identity is None:
            return self._fail(self.failure_code or SOURCE_FAILURE_TASK)
        if not verify_service_identity(self.service_identity, proc_root=self.proc_root):
            return self._fail(SOURCE_FAILURE_IDENTITY)
        group = self.group_identities[0]
        try:
            table = read_proc_table(self.proc_root, uid=self.uid)
        except (OSError, ObserverUnavailable):
            return self._fail(SOURCE_FAILURE_UNOBSERVABLE)
        leader = table.get(group.leader_pid)
        if leader is None or leader.starttime != group.leader_starttime:
            return self._fail(SOURCE_FAILURE_IDENTITY)
        task_stat_path = (self.proc_root / str(self.writer.tgid) / "task"
                          / str(self.writer.tid) / "stat")
        try:
            task = parse_proc_stat(task_stat_path.read_text(encoding="utf-8"),
                                   pid=self.writer.tid)
            pipe_inode = read_pipe_inode(self.proc_root, self.writer.tgid, 1)
            fd_info = read_fdinfo(self.proc_root, self.writer.tgid, 1)
            syscall = parse_syscall(
                (self.proc_root / str(self.writer.tgid) / "task" / str(self.writer.tid)
                 / "syscall").read_text(encoding="utf-8")
            )
            parse_wchan(
                (self.proc_root / str(self.writer.tgid) / "task" / str(self.writer.tid)
                 / "wchan").read_text(encoding="utf-8")
            )
            service_info = read_fdinfo(self.proc_root, self.service_pid, self.writer.service_fd)
            service_inode = read_pipe_inode(
                self.proc_root, self.service_pid, self.writer.service_fd
            )
        except (OSError, SourceParseError):
            return self._fail(SOURCE_FAILURE_UNOBSERVABLE)
        if (task.starttime != self.writer.starttime or task.pgid != group.pgid):
            return self._fail(SOURCE_FAILURE_IDENTITY)
        if task.state not in ("S", "D"):
            return self._fail(SOURCE_FAILURE_NOT_SLEEPING)
        if (pipe_inode != self.writer.pipe_inode
                or service_inode != self.writer.pipe_inode
                or (fd_info.flags & os.O_ACCMODE) != os.O_WRONLY
                or (service_info.flags & os.O_ACCMODE) != os.O_RDONLY):
            return self._fail(SOURCE_FAILURE_PIPE)
        if (syscall.kind != self.writer.syscall_kind
                or syscall.fd != 1 or syscall.count <= 0):
            return self._fail(SOURCE_FAILURE_SYSCALL)
        return self._base_report(True, SOURCE_FAILURE_NONE)

    def report(self):
        return self.sample()
