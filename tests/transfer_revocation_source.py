#!/usr/bin/env python3
"""Actual owned LFS source-descriptor witness for Issue #37."""
from dataclasses import dataclass
import os
from pathlib import Path
import stat as stat_module

from transfer_revocation_observer import parse_proc_stat


SOURCE_FAILURE_NONE = 0
SOURCE_FAILURE_IDENTITY = 1
SOURCE_FAILURE_OBJECT = 2
SOURCE_FAILURE_NO_MATCH = 3
SOURCE_FAILURE_MULTIPLE_MATCH = 4
SOURCE_FAILURE_FDINFO = 5
SOURCE_FAILURE_NOT_READABLE = 6
SOURCE_FAILURE_POSITION_EDGE = 7
SOURCE_FAILURE_POSITION_MOVED = 8
SOURCE_FAILURE_OBJECT_CHANGED = 9
SOURCE_FAILURE_UNOBSERVABLE = 10
SOURCE_FAILURE_UNSUPPORTED_ARCH = 11
SOURCE_FAILURE_TASK = 12
SOURCE_FAILURE_PIPE = 13
SOURCE_FAILURE_SYSCALL = 14
SOURCE_FAILURE_WCHAN = 15
SOURCE_FAILURE_NOT_SLEEPING = 16
SOURCE_FAILURE_FD_MISSING = 17
SOURCE_FAILURE_FD_REPLACED = 18
SOURCE_FAILURE_POSITION_RESET = 19
SOURCE_FAILURE_POSITION_PROGRESS = 20
SOURCE_FAILURE_POSITION_EOF = 21
SOURCE_FAILURE_NO_CANDIDATE = 22
SOURCE_FAILURE_WRITER_RUNNING = 23
SOURCE_FAILURE_NO_BLOCKED_WRITER = 24


class SourceParseError(ValueError):
    """Malformed or unsupported proc source metadata."""


@dataclass(frozen=True)
class ServiceIdentity:
    pid: int
    starttime: int


@dataclass(frozen=True)
class FdInfo:
    pos: int
    flags: int
    ino: int
    mnt_id: int


@dataclass(frozen=True)
class SyscallInfo:
    kind: str
    fd: int
    count: int


def parse_fdinfo(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if not value:
            continue
        values[key] = value
    try:
        pos = int(values["pos"], 10)
        flags = int(values["flags"], 8)
        ino = int(values["ino"], 10)
        mnt_id = int(values["mnt_id"], 10)
    except (KeyError, ValueError) as error:
        raise SourceParseError("invalid fdinfo") from error
    if pos < 0 or flags < 0 or ino < 0 or mnt_id < 0:
        raise SourceParseError("invalid fdinfo")
    return FdInfo(pos=pos, flags=flags, ino=ino, mnt_id=mnt_id)


def parse_syscall(text):
    fields = text.split()
    if not fields:
        raise SourceParseError("empty syscall")
    if fields[0] == "running" or fields[0].startswith("-"):
        raise SourceParseError("unsupported syscall form")
    try:
        number = int(fields[0], 10)
    except ValueError as error:
        raise SourceParseError("invalid syscall number") from error
    if number == 1:
        kind = "write"
    elif number == 20:
        kind = "writev"
    else:
        raise SourceParseError("unsupported syscall")
    if len(fields) < 4:
        raise SourceParseError("short syscall form")
    try:
        fd = int(fields[1], 16)
        count = int(fields[3], 16)
    except ValueError as error:
        raise SourceParseError("invalid syscall arguments") from error
    if fd < 0 or count <= 0:
        raise SourceParseError("invalid syscall arguments")
    return SyscallInfo(kind=kind, fd=fd, count=count)


def parse_wchan(text):
    symbol = text.strip().split("+", 1)[0].strip()
    if symbol != "pipe_write":
        raise SourceParseError("unsupported wait channel")
    return symbol


def read_service_identity(service_pid, proc_root=Path("/proc")):
    try:
        text = (Path(proc_root) / str(service_pid) / "stat").read_text(encoding="utf-8")
        parsed = parse_proc_stat(text, pid=service_pid)
    except (OSError, ValueError) as error:
        raise SourceParseError("service identity unavailable") from error
    return ServiceIdentity(pid=parsed.pid, starttime=parsed.starttime)


def verify_service_identity(identity, proc_root=Path("/proc")):
    try:
        current = read_service_identity(identity.pid, proc_root=proc_root)
    except SourceParseError:
        return False
    return current.starttime == identity.starttime


def read_fdinfo(proc_root, pid, fd):
    try:
        text = (Path(proc_root) / str(pid) / "fdinfo" / str(fd)).read_text(encoding="utf-8")
        return parse_fdinfo(text)
    except (OSError, SourceParseError) as error:
        raise SourceParseError("fdinfo unavailable") from error


def read_pipe_inode(proc_root, pid, fd):
    try:
        target = os.readlink(Path(proc_root) / str(pid) / "fd" / str(fd))
    except OSError as error:
        raise SourceParseError("fd link unavailable") from error
    if not target.startswith("pipe:[") or not target.endswith("]"):
        raise SourceParseError("fd is not a pipe")
    try:
        return int(target[6:-1], 10)
    except ValueError as error:
        raise SourceParseError("invalid pipe inode") from error


def _fd_numbers(proc_root, pid):
    fd_dir = Path(proc_root) / str(pid) / "fd"
    try:
        entries = list(fd_dir.iterdir())
    except OSError as error:
        raise SourceParseError("fd table unavailable") from error
    return sorted(int(entry.name) for entry in entries if entry.name.isdigit())


class LfsSourceWitness:
    """Separate immutable LFS source identity from transient qualification."""

    witness_kind_code = 1

    def __init__(self, service_pid, object_path, expected_size,
                 proc_root=Path("/proc")):
        self.service_pid = int(service_pid)
        self.object_path = Path(object_path)
        self.expected_size = int(expected_size)
        self.proc_root = Path(proc_root)
        self.identity = None
        self.bound = False
        self.fd = 0
        self.st_dev = 0
        self.st_ino = 0
        self.mnt_id = 0
        self.flags = 0
        self.position = 0
        self.size = 0
        self.qualified = False
        self.failure_code = SOURCE_FAILURE_NONE
        self.fatal_failure_code = SOURCE_FAILURE_NONE

    def _base_report(self, *, qualified=False, failure_code=SOURCE_FAILURE_NONE):
        return {
            "witness_version": 1,
            "witness_kind_code": self.witness_kind_code,
            "witness_available": bool(self.identity is not None),
            "witness_bound": bool(self.bound),
            "qualified": bool(qualified),
            "failure_code": int(failure_code),
            "fatal_failure_code": int(self.fatal_failure_code),
            "source_identity_unique": bool(self.bound and not self.fatal_failure_code),
            "source_position_unchanged": bool(qualified),
            "source_unfinished": bool(qualified),
            "source_position": int(self.position if self.bound else 0),
            "source_size": int(self.size if self.bound else 0),
            "source_remaining": (
                max(0, int(self.size) - int(self.position)) if self.bound else 0
            ),
        }

    def _transient(self, code):
        self.qualified = False
        self.failure_code = code
        return self._base_report(qualified=False, failure_code=code)

    def _fatal(self, code):
        self.qualified = False
        self.fatal_failure_code = code
        self.failure_code = code
        return self._base_report(qualified=False, failure_code=code)

    def _bind_candidate(self):
        if self.bound or self.fatal_failure_code:
            return
        try:
            self.identity = read_service_identity(self.service_pid, proc_root=self.proc_root)
        except SourceParseError:
            self._fatal(SOURCE_FAILURE_IDENTITY)
            return
        try:
            object_stat = os.stat(self.object_path)
        except FileNotFoundError:
            self._transient(SOURCE_FAILURE_NO_MATCH)
            return
        except OSError:
            self._fatal(SOURCE_FAILURE_OBJECT)
            return
        if (not stat_module.S_ISREG(object_stat.st_mode)
                or object_stat.st_size != self.expected_size):
            self._fatal(SOURCE_FAILURE_OBJECT)
            return
        try:
            fd_numbers = _fd_numbers(self.proc_root, self.service_pid)
        except (OSError, SourceParseError):
            self._fatal(SOURCE_FAILURE_UNOBSERVABLE)
            return
        candidates = []
        for fd in fd_numbers:
            fd_path = self.proc_root / str(self.service_pid) / "fd" / str(fd)
            try:
                descriptor_stat = os.stat(fd_path)
            except FileNotFoundError:
                continue
            except OSError:
                self._fatal(SOURCE_FAILURE_UNOBSERVABLE)
                return
            if (descriptor_stat.st_dev != object_stat.st_dev
                    or descriptor_stat.st_ino != object_stat.st_ino
                    or descriptor_stat.st_size != self.expected_size):
                continue
            try:
                info = read_fdinfo(self.proc_root, self.service_pid, fd)
            except SourceParseError:
                self._fatal(SOURCE_FAILURE_FDINFO)
                return
            if (info.flags & os.O_ACCMODE) != os.O_RDONLY or info.ino != object_stat.st_ino:
                self._fatal(SOURCE_FAILURE_NOT_READABLE)
                return
            if info.pos >= self.expected_size:
                self._fatal(SOURCE_FAILURE_POSITION_EOF)
                return
            candidates.append((fd, info, descriptor_stat))
        if not candidates:
            self._transient(SOURCE_FAILURE_NO_CANDIDATE)
            return
        if len(candidates) > 1:
            self._fatal(SOURCE_FAILURE_MULTIPLE_MATCH)
            return
        if candidates[0][1].pos <= 0:
            self._transient(SOURCE_FAILURE_NO_CANDIDATE)
            return
        self.fd, info, descriptor_stat = candidates[0]
        self.st_dev = descriptor_stat.st_dev
        self.st_ino = descriptor_stat.st_ino
        self.mnt_id = info.mnt_id
        self.flags = info.flags
        self.position = info.pos
        self.size = object_stat.st_size
        self.bound = True
        self.failure_code = SOURCE_FAILURE_NONE
        self.qualified = True

    def prepare_no_match(self):
        try:
            self.identity = read_service_identity(self.service_pid, proc_root=self.proc_root)
            object_stat = os.stat(self.object_path)
        except FileNotFoundError:
            return True
        except (OSError, SourceParseError):
            return False
        if not stat_module.S_ISREG(object_stat.st_mode):
            return False
        try:
            for fd in _fd_numbers(self.proc_root, self.service_pid):
                try:
                    descriptor_stat = os.stat(
                        self.proc_root / str(self.service_pid) / "fd" / str(fd)
                    )
                except FileNotFoundError:
                    continue
                if (descriptor_stat.st_dev == object_stat.st_dev
                        and descriptor_stat.st_ino == object_stat.st_ino):
                    return False
        except (OSError, SourceParseError):
            return False
        return True

    def bind(self):
        if self.fatal_failure_code:
            return False
        if not self.bound:
            self._bind_candidate()
        if not self.bound:
            return False
        return bool(self.qualified)

    def sample(self):
        if self.fatal_failure_code:
            return self._fatal(self.fatal_failure_code)
        if not self.bound:
            self._bind_candidate()
            if not self.bound:
                return self._base_report(qualified=False, failure_code=self.failure_code)
            return self._base_report(qualified=True)
        if not verify_service_identity(self.identity, proc_root=self.proc_root):
            return self._fatal(SOURCE_FAILURE_IDENTITY)
        try:
            object_stat = os.stat(self.object_path)
            descriptor_stat = os.stat(
                self.proc_root / str(self.service_pid) / "fd" / str(self.fd)
            )
            info = read_fdinfo(self.proc_root, self.service_pid, self.fd)
        except FileNotFoundError:
            return self._fatal(SOURCE_FAILURE_FD_MISSING)
        except (OSError, SourceParseError):
            return self._fatal(SOURCE_FAILURE_UNOBSERVABLE)
        if (not stat_module.S_ISREG(object_stat.st_mode)
                or object_stat.st_dev != self.st_dev
                or object_stat.st_ino != self.st_ino
                or object_stat.st_size != self.size):
            return self._fatal(SOURCE_FAILURE_OBJECT_CHANGED)
        if (descriptor_stat.st_dev != self.st_dev
                or descriptor_stat.st_ino != self.st_ino
                or descriptor_stat.st_size != self.size):
            return self._fatal(SOURCE_FAILURE_FD_REPLACED)
        if (info.flags & os.O_ACCMODE) != os.O_RDONLY or info.ino != self.st_ino:
            return self._fatal(SOURCE_FAILURE_NOT_READABLE)
        if info.mnt_id != self.mnt_id:
            return self._fatal(SOURCE_FAILURE_OBJECT_CHANGED)
        if info.pos >= self.size:
            return self._fatal(SOURCE_FAILURE_POSITION_EOF)
        if info.pos <= 0 or info.pos < self.position:
            return self._fatal(SOURCE_FAILURE_POSITION_RESET)
        if info.pos > self.position:
            self.position = info.pos
            return self._transient(SOURCE_FAILURE_POSITION_PROGRESS)
        return self._base_report(qualified=True, failure_code=SOURCE_FAILURE_NONE)

    def report(self):
        return self.sample()
