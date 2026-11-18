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
    SOURCE_FAILURE_NO_CANDIDATE,
    SOURCE_FAILURE_WRITER_RUNNING,
    SOURCE_FAILURE_NO_BLOCKED_WRITER,
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
    """Keep the owned request anchor while a writer is transiently running."""

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
        self.fatal_failure_code = SOURCE_FAILURE_NONE
        self._wchan_diagnostic = {}

    def _base_report(self, *, qualified=False, failure_code=SOURCE_FAILURE_NONE):
        report = {
            "witness_version": 1,
            "witness_kind_code": self.witness_kind_code,
            "witness_available": bool(self.service_identity is not None),
            "witness_bound": bool(self.writer is not None),
            "qualified": bool(qualified),
            "failure_code": int(failure_code),
            "fatal_failure_code": int(self.fatal_failure_code),
            "source_identity_unique": bool(self.writer is not None
                                            and not self.fatal_failure_code),
            "source_pipe_paired": bool(self.writer is not None
                                       and not self.fatal_failure_code),
            "source_writer_blocked": bool(qualified),
            "source_writer_starttime": (
                int(self.writer.starttime) if self.writer is not None else 0
            ),
            "source_syscall_kind_code": (
                1 if self.writer is not None and self.writer.syscall_kind == "write"
                else 2 if self.writer is not None else 0
            ),
            **self._wchan_diagnostic,
        }
        return report

    def _transient(self, code):
        self.qualified = False
        self.failure_code = code
        return self._base_report(qualified=False, failure_code=code)

    def _fatal(self, code):
        self.qualified = False
        self.fatal_failure_code = code
        self.failure_code = code
        return self._base_report(qualified=False, failure_code=code)

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

    def _read_stat(self, path, expected_pid):
        try:
            task = parse_proc_stat(path.read_text(encoding="utf-8"))
            if task.pid != expected_pid:
                raise ValueError("proc stat PID mismatch")
            return task
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise SourceParseError("task metadata unavailable") from error

    def _task_stat(self, tgid, tid):
        path = self.proc_root / str(tgid) / "task" / str(tid) / "stat"
        return self._read_stat(path, tid)

    def _task_text(self, tgid, tid, name):
        path = self.proc_root / str(tgid) / "task" / str(tid) / name
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise SourceParseError(f"task {name} unavailable") from error

    def _syscall_state(self, text):
        fields = text.split()
        if not fields:
            raise SourceParseError("empty syscall")
        if fields[0] == "running" or fields[0].startswith("-"):
            return "running"
        try:
            number = int(fields[0], 10)
        except ValueError as error:
            raise SourceParseError("invalid syscall number") from error
        if number not in (1, 20):
            return "other"
        try:
            return parse_syscall(text)
        except SourceParseError as error:
            raise SourceParseError("invalid write syscall") from error

    def _candidate(self, tgid, tid, group, read_pipes):
        task = self._task_stat(tgid, tid)
        if task is None:
            return None
        if task.pgid != group.pgid:
            return None
        try:
            pipe_inode = read_pipe_inode(self.proc_root, tgid, 1)
            fd_info = read_fdinfo(self.proc_root, tgid, 1)
        except SourceParseError:
            return None
        if (fd_info.flags & os.O_ACCMODE) != os.O_WRONLY:
            return None
        matches = [fd for fd, inode in read_pipes if inode == pipe_inode]
        if len(matches) != 1:
            return None
        if task.state not in ("S", "D"):
            return None
        state = self._syscall_state(self._task_text(tgid, tid, "syscall"))
        if state in ("running", "other"):
            return None
        if state.fd != 1 or state.count <= 0:
            return None
        wchan_text = self._task_text(tgid, tid, "wchan").strip()
        if not wchan_text or wchan_text == "0":
            return None
        try:
            parse_wchan(wchan_text)
        except SourceParseError:
            return None
        return _Writer(
            tgid=tgid, tid=tid, starttime=task.starttime,
            pipe_inode=pipe_inode, service_fd=matches[0],
            syscall_kind=state.kind,
        )

    def _discover_writer(self, table, group, read_pipes):
        candidates = []
        for tgid, tid in self._tasks_for_group(table, group):
            try:
                candidate = self._candidate(tgid, tid, group, read_pipes)
            except (OSError, SourceParseError):
                return self._fatal(SOURCE_FAILURE_UNOBSERVABLE)["qualified"]
            if candidate is not None:
                candidates.append(candidate)
        if not candidates:
            return self._transient(SOURCE_FAILURE_NO_CANDIDATE)["qualified"]
        if len(candidates) > 1:
            return self._fatal(SOURCE_FAILURE_TASK)["qualified"]
        self.writer = candidates[0]
        self.failure_code = SOURCE_FAILURE_NONE
        return True

    def bind(self):
        if self.fatal_failure_code:
            return False
        if self.arch != "x86_64":
            return self._fatal(SOURCE_FAILURE_UNSUPPORTED_ARCH)["qualified"]
        if len(self.group_identities) != 1:
            return self._fatal(SOURCE_FAILURE_TASK)["qualified"]
        group = self.group_identities[0]
        try:
            self.service_identity = read_service_identity(
                self.service_pid, proc_root=self.proc_root
            )
            table = read_proc_table(self.proc_root, uid=self.uid)
            read_pipes = self._read_pipes()
        except (OSError, SourceParseError, ObserverUnavailable):
            return self._fatal(SOURCE_FAILURE_UNOBSERVABLE)["qualified"]
        leader = table.get(group.leader_pid)
        if leader is None or leader.starttime != group.leader_starttime:
            return self._fatal(SOURCE_FAILURE_IDENTITY)["qualified"]
        if self.writer is None:
            qualified = self._discover_writer(table, group, read_pipes)
        else:
            qualified = self._sample_writer(group)
        self.qualified = bool(qualified)
        return self.qualified

    def _recheck_wchan_writer(self, writer, group):
        try:
            task = self._task_stat(writer.tgid, writer.tid)
            if task is None:
                return "unavailable"
            if task.starttime != writer.starttime or task.pgid != group.pgid:
                return "identity_changed"
            if task.state == "R":
                service = self._read_stat(
                    self.proc_root / str(self.service_pid) / "stat", self.service_pid
                )
                leader = self._read_stat(
                    self.proc_root / str(group.leader_pid) / "stat", group.leader_pid
                )
                if service is None or leader is None:
                    return "unavailable"
                if (service.starttime != self.service_identity.starttime or not service.live
                        or leader.starttime != group.leader_starttime
                        or leader.pgid != group.pgid or not leader.live):
                    return "identity_changed"
                pipe_failure = self._pipe_failure(writer, verify_fdinfo_inode=True)
                if pipe_failure == SOURCE_FAILURE_PIPE:
                    return "identity_changed"
                if pipe_failure:
                    return "unavailable"
                return "same_writer_running"
            if task.state in ("S", "D"):
                state = self._syscall_state(self._task_text(writer.tgid, writer.tid, "syscall"))
                if state not in ("running", "other") and state.fd == 1 and state.count > 0:
                    return "same_writer_sleeping_in_stdout_write"
        except (SourceParseError, UnicodeDecodeError):
            return "unavailable"
        return "same_writer_other"

    def _pipe_failure(self, writer, *, verify_fdinfo_inode=False):
        try:
            pipe_inode = read_pipe_inode(self.proc_root, writer.tgid, 1)
            fd_info = read_fdinfo(self.proc_root, writer.tgid, 1)
            service_info = read_fdinfo(
                self.proc_root, self.service_pid, writer.service_fd
            )
            service_inode = read_pipe_inode(
                self.proc_root, self.service_pid, writer.service_fd
            )
        except (OSError, SourceParseError):
            return SOURCE_FAILURE_UNOBSERVABLE
        if (pipe_inode != writer.pipe_inode
                or service_inode != writer.pipe_inode
                or (fd_info.flags & os.O_ACCMODE) != os.O_WRONLY
                or (service_info.flags & os.O_ACCMODE) != os.O_RDONLY):
            return SOURCE_FAILURE_PIPE
        if verify_fdinfo_inode and (fd_info.ino != pipe_inode or service_info.ino != service_inode):
            return SOURCE_FAILURE_PIPE
        return SOURCE_FAILURE_NONE

    def _sample_writer(self, group):
        writer = self.writer
        if writer is None:
            return False
        task = self._task_stat(writer.tgid, writer.tid)
        if task is None or task.starttime != writer.starttime or task.pgid != group.pgid:
            self._fatal(SOURCE_FAILURE_TASK)
            return False
        pipe_failure = self._pipe_failure(writer)
        if pipe_failure:
            self._fatal(pipe_failure)
            return False
        if task.state not in ("S", "D"):
            self._transient(SOURCE_FAILURE_WRITER_RUNNING)
            return False
        try:
            state = self._syscall_state(self._task_text(writer.tgid, writer.tid, "syscall"))
            if state in ("running", "other"):
                self._transient(SOURCE_FAILURE_NO_BLOCKED_WRITER)
                return False
            if state.fd != 1 or state.count <= 0:
                self._transient(SOURCE_FAILURE_NO_BLOCKED_WRITER)
                return False
            wchan_text = self._task_text(writer.tgid, writer.tid, "wchan").strip()
            if not wchan_text or wchan_text == "0":
                recheck = self._recheck_wchan_writer(writer, group)
                if recheck == "same_writer_running":
                    # The separate proc reads straddled a state change. Drop
                    # this sample; only later positive samples can qualify.
                    self._transient(SOURCE_FAILURE_WRITER_RUNNING)
                    return False
                self._fatal(SOURCE_FAILURE_WCHAN)
                self._wchan_diagnostic = {
                    "wchan_shape": "zero" if wchan_text else "empty",
                    "wchan_writer_recheck": recheck,
                }
                return False
            try:
                parse_wchan(wchan_text)
            except SourceParseError:
                self._transient(SOURCE_FAILURE_NO_BLOCKED_WRITER)
                return False
        except SourceParseError:
            self._fatal(SOURCE_FAILURE_UNOBSERVABLE)
            return False
        self.qualified = True
        self.failure_code = SOURCE_FAILURE_NONE
        return True

    def sample(self):
        if self.fatal_failure_code:
            return self._fatal(self.fatal_failure_code)
        if not verify_service_identity(self.service_identity, proc_root=self.proc_root):
            return self._fatal(SOURCE_FAILURE_IDENTITY)
        if len(self.group_identities) != 1:
            return self._fatal(SOURCE_FAILURE_TASK)
        group = self.group_identities[0]
        try:
            table = read_proc_table(self.proc_root, uid=self.uid)
            read_pipes = self._read_pipes()
        except (OSError, SourceParseError, ObserverUnavailable):
            return self._fatal(SOURCE_FAILURE_UNOBSERVABLE)
        leader = table.get(group.leader_pid)
        if leader is None or leader.starttime != group.leader_starttime:
            return self._fatal(SOURCE_FAILURE_IDENTITY)
        if self.writer is None:
            qualified = self._discover_writer(table, group, read_pipes)
            if not qualified:
                return self._base_report(
                    qualified=False,
                    failure_code=self.failure_code,
                )
        qualified = self._sample_writer(group)
        self.qualified = bool(qualified)
        return self._base_report(
            qualified=self.qualified,
            failure_code=self.failure_code,
        )

    def report(self):
        return self.sample()
