#!/usr/bin/env python3
"""Owned FIFO fixture control for the legacy startup SIGTERM case.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It places a FIFO at the exact private lazy-manifest path of one ready workspace
so the existing ``lazy::read_manifest`` blocking open keeps startup incomplete.
It is fixture filesystem state only: there is no product fault switch, no
environment backdoor, no mock service and no mount.

The controller never blocks the acceptance process and never starts a thread.
The reader proof reads the exact owned service PID/starttime and looks for a
blocked FIFO-open kernel wait (wchan, or the root-only kernel stack fallback).
The release opens the FIFO write side with ``O_NONBLOCK``, writes an invalid
manifest and *retains* that writer descriptor until the caller closes it, so
the service's blocking reader can never lose the writer-pairing race. Both the
probe and the retained writer are closed in ``finally`` on every path.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import time
import uuid

from tests import fuse_helper_native_support as support
from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError

INVALID_MANIFEST = b'{"schema":1,"tenant_id":"not-a-uuid","entries":[]}\n'
FIFO_OPEN_WAIT_MARKERS = ("wait_for_partner", "fifo_open")
STARTUP_JOIN_FAILURE_MARKERS = (
    "startup reconcile owner remained pending at the shutdown deadline",
    "startup reconcile join failed:",
    "startup producer panicked",
    "startup producer was cancelled",
    "startup producer was already joined",
)
SERVICE_CLEANUP_INCOMPLETE_MARKERS = (
    "service cleanup incomplete:",
    "normal shutdown incomplete:",
)
_BLOCKED_STATES = frozenset(("S", "D"))
_OPEN_RETRY_ERRNOS = frozenset((errno.ENXIO, errno.EAGAIN, errno.EINTR))
_WRITE_CLOSED_ERRNOS = frozenset((errno.EPIPE,))
_POLL_SECONDS = 0.02
_STACK_LIMIT = 4096
_MAX_LOG_BYTES = 4 * 1024 * 1024


def startup_owner_join_evidence(log_path) -> dict:
    """Require the service's own bounded log to lack a pending/join failure.

    The service appends one of these fixed ``ServiceCompletion``
    classifications only when the startup producer did not join cleanly. The
    caller separately checks the positive primary exit and the legacy mount
    evidence; this function never stores or returns raw log text.
    """
    try:
        raw = Path(log_path).read_bytes()
    except OSError:
        raise LegacyAcceptanceError("service startup evidence log is unavailable") from None
    if len(raw) > _MAX_LOG_BYTES:
        raise LegacyAcceptanceError("service startup evidence log exceeded the bounded fixture limit")
    text = raw.decode("utf-8", "replace")
    for marker in STARTUP_JOIN_FAILURE_MARKERS:
        if marker in text:
            raise LegacyAcceptanceError(
                "startup owner was not joined cleanly under the shared deadline"
            )
    for marker in SERVICE_CLEANUP_INCOMPLETE_MARKERS:
        if marker in text:
            raise LegacyAcceptanceError(
                "service completion reported incomplete cleanup for the blocked startup"
            )
    return {"startup_owner_joined": True, "log_bytes": len(raw)}


def assert_startup_not_ready(harness, seconds: float = 0.25) -> dict:
    """Require the owned service never reports readiness while startup is held."""
    deadline = time.monotonic() + max(0.0, float(seconds))
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            status, _body, _headers = harness.http("/health/ready")
        except Exception:
            status = None
        if status == 200:
            raise LegacyAcceptanceError(
                "owned service reported readiness while legacy startup was blocked"
            )
        time.sleep(_POLL_SECONDS)
    proc = getattr(harness, "proc", None)
    if proc is None or proc.poll() is not None:
        raise LegacyAcceptanceError("owned service exited while legacy startup was blocked")
    return {"ready": False, "attempts": attempts}


def _positive_int(value, label: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise LegacyAcceptanceError(f"{label} is not a numeric identity") from None
    if number < 1:
        raise LegacyAcceptanceError(f"{label} is not a positive identity")
    return number


def _thread_rows(pid: int, proc_root: Path):
    """Return safe per-thread wait facts for the exact owned service PID."""
    task_root = Path(proc_root) / str(int(pid)) / "task"
    try:
        names = os.listdir(task_root)
    except OSError:
        return []
    rows = []
    for name in names:
        if not name.isdigit():
            continue
        directory = task_root / name
        try:
            raw = (directory / "stat").read_text(encoding="utf-8", errors="replace")
            state = raw.rsplit(")", 1)[-1].split()[0]
        except (OSError, IndexError):
            continue
        try:
            wchan = (directory / "wchan").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            wchan = ""
        stack = ""
        if not any(marker in wchan.lower() for marker in FIFO_OPEN_WAIT_MARKERS):
            try:
                stack = (directory / "stack").read_text(
                    encoding="utf-8", errors="replace"
                )[: _STACK_LIMIT]
            except OSError:
                stack = ""
        rows.append({"tid": int(name), "state": state, "wchan": wchan, "stack": stack})
    return rows


class FifoController:
    """One owned FIFO at the private lazy-manifest path of one workspace."""

    def __init__(
        self,
        lazy_dir,
        workspace_id,
        *,
        clock=time.monotonic,
        sleep=time.sleep,
        proc_root=Path("/proc"),
        process_identity=support.process_identity,
        thread_probe=None,
        open_fn=os.open,
        close_fn=os.close,
        write_fn=os.write,
        lstat_fn=os.lstat,
        mkfifo_fn=os.mkfifo,
        unlink_fn=os.unlink,
    ):
        self._lazy_dir = Path(lazy_dir)
        self._workspace_id = str(uuid.UUID(str(workspace_id)))
        self.path = self._lazy_dir / f"{self._workspace_id}.json"
        self._clock = clock
        self._sleep = sleep
        self._process_identity = process_identity
        self._thread_probe = thread_probe or (lambda pid: _thread_rows(pid, proc_root))
        self._open = open_fn
        self._close = close_fn
        self._write = write_fn
        self._lstat = lstat_fn
        self._mkfifo = mkfifo_fn
        self._unlink = unlink_fn
        self._writer_fd = None
        self._installed = False
        self._inode = None
        self._device = None
        self._released = None

    # ------------------------------------------------------------------ setup
    def install(self) -> dict:
        """Replace only the owned manifest path with a mode-0600 FIFO."""
        if self._installed:
            raise LegacyAcceptanceError("owned FIFO fixture was installed twice")
        try:
            self._lazy_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise LegacyAcceptanceError("owned lazy-manifest directory is unavailable") from None
        try:
            existing = self._lstat(self.path)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise LegacyAcceptanceError("owned lazy-manifest path is unreadable") from None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise LegacyAcceptanceError("owned lazy-manifest path is a symlink")
            if not (stat.S_ISREG(existing.st_mode) or stat.S_ISFIFO(existing.st_mode)):
                raise LegacyAcceptanceError("owned lazy-manifest path is not a regular file or FIFO")
            try:
                self._unlink(self.path)
            except OSError:
                raise LegacyAcceptanceError("owned lazy-manifest path could not be replaced") from None
        try:
            self._mkfifo(self.path, 0o600)
            created = self._lstat(self.path)
        except OSError:
            raise LegacyAcceptanceError("owned lazy-manifest FIFO could not be created") from None
        if not stat.S_ISFIFO(created.st_mode):
            raise LegacyAcceptanceError("owned lazy-manifest fixture is not a FIFO")
        self._inode = int(created.st_ino)
        self._device = int(created.st_dev)
        self._installed = True
        self._assert_only_owned_fifo()
        return {"fifo_inode": self._inode, "fifo_device": self._device}

    def _assert_only_owned_fifo(self) -> None:
        """Require the private lazy directory to contain only this FIFO."""
        if not self._installed:
            raise LegacyAcceptanceError("owned FIFO fixture is not installed")
        try:
            entries = list(self._lazy_dir.iterdir())
        except OSError:
            raise LegacyAcceptanceError("owned lazy-manifest directory is unreadable") from None
        fifos = []
        for entry in entries:
            try:
                mode = self._lstat(entry).st_mode
            except OSError:
                continue
            if stat.S_ISFIFO(mode):
                fifos.append(entry)
        if len(fifos) != 1:
            raise LegacyAcceptanceError("owned lazy directory does not contain exactly one FIFO")
        try:
            owned = self._lstat(self.path)
        except OSError:
            raise LegacyAcceptanceError("owned FIFO disappeared") from None
        if int(owned.st_ino) != self._inode or int(owned.st_dev) != self._device:
            raise LegacyAcceptanceError("owned FIFO identity changed")

    # ------------------------------------------------------------- reader proof
    def _recheck_service(self, pid: int, starttime: int) -> None:
        identity = self._process_identity(int(pid))
        if not isinstance(identity, dict):
            raise LegacyAcceptanceError("owned service identity is unavailable")
        if int(identity.get("pid", -1)) != int(pid):
            raise LegacyAcceptanceError("owned service PID changed during FIFO proof")
        if identity.get("state") == "Z":
            raise LegacyAcceptanceError("owned service exited during FIFO proof")
        observed = _positive_int(identity.get("starttime"), "owned service starttime")
        if observed != int(starttime):
            raise LegacyAcceptanceError("owned service starttime changed during FIFO proof")

    def prove_reader_blocked(self, service_pid: int, service_starttime: int, deadline: float) -> dict:
        """Prove the owned service has a real thread blocked opening this FIFO.

        No writer is opened here: opening one would pair with the service's
        blocking read open and release it before SIGTERM. The proof is the
        exact service PID/starttime plus a FIFO-open kernel wait on one of that
        process's own threads.
        """
        pid = _positive_int(service_pid, "owned service pid")
        starttime = _positive_int(service_starttime, "owned service starttime")
        if not self._installed:
            raise LegacyAcceptanceError("owned FIFO fixture is not installed")
        attempts = 0
        last_wchan = None
        last_state = None
        while self._clock() < deadline:
            attempts += 1
            self._recheck_service(pid, starttime)
            for thread in self._thread_probe(pid):
                state = str(thread.get("state", ""))
                wchan = str(thread.get("wchan") or "")
                stack = str(thread.get("stack") or "")
                last_wchan, last_state = wchan, state
                if state not in _BLOCKED_STATES:
                    continue
                match = None
                via_stack = False
                for marker in FIFO_OPEN_WAIT_MARKERS:
                    if marker in wchan.lower():
                        match = marker
                        break
                if match is None:
                    for marker in FIFO_OPEN_WAIT_MARKERS:
                        if marker in stack.lower():
                            match = marker
                            via_stack = True
                            break
                if match is None:
                    continue
                self._recheck_service(pid, starttime)
                self._assert_only_owned_fifo()
                return {
                    "service_pid": pid,
                    "service_starttime": starttime,
                    "tid": _positive_int(thread.get("tid"), "blocked service tid"),
                    "thread_state": state,
                    "wchan": wchan,
                    "matched_marker": match,
                    "via_kernel_stack": via_stack,
                    "attempts": attempts,
                    "fifo_inode": self._inode,
                }
            self._sleep(min(_POLL_SECONDS, max(0.0, deadline - self._clock())))
        raise LegacyAcceptanceError(
            "FIFO read side did not expose a blocked FIFO-open kernel wait before the "
            f"startup observation deadline (last state={last_state!r}, wchan={last_wchan!r})"
        )

    # ---------------------------------------------------------------- release
    def release_invalid_manifest(self, deadline: float) -> dict:
        """Open a nonblocking writer, write an invalid manifest and retain it."""
        if not self._installed:
            raise LegacyAcceptanceError("owned FIFO fixture is not installed")
        if self._released is not None:
            return self._released
        if self._writer_fd is not None:
            raise LegacyAcceptanceError("owned FIFO writer is already retained")
        self._assert_only_owned_fifo()
        attempts = 0
        while self._clock() < deadline:
            attempts += 1
            try:
                fd = self._open(self.path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno in _OPEN_RETRY_ERRNOS:
                    self._sleep(min(_POLL_SECONDS, max(0.0, deadline - self._clock())))
                    continue
                raise LegacyAcceptanceError(
                    f"owned FIFO release open failed with errno {error.errno}"
                ) from None
            self._writer_fd = fd
            written = 0
            try:
                written = int(self._write(fd, INVALID_MANIFEST))
            except OSError as error:
                if error.errno not in _WRITE_CLOSED_ERRNOS:
                    self._close_writer()
                    raise LegacyAcceptanceError(
                        f"owned FIFO release write failed with errno {error.errno}"
                    ) from None
            self._released = {
                "attempts": attempts,
                "bytes_written": written,
                "writer_retained": self._writer_fd is not None,
            }
            return self._released
        raise LegacyAcceptanceError("owned FIFO release did not pair within the shared deadline")

    # ----------------------------------------------------------------- cleanup
    def _close_writer(self) -> None:
        fd = self._writer_fd
        self._writer_fd = None
        if fd is not None:
            try:
                self._close(fd)
            except OSError:
                pass

    def close_writer(self) -> None:
        """Close the retained release writer; safe and idempotent on all paths."""
        self._close_writer()

    def close(self) -> None:
        """Close the writer and unlink only the exact FIFO this fixture created."""
        self.close_writer()
        if self._installed:
            try:
                current = self._lstat(self.path)
            except OSError:
                current = None
            if (
                current is not None
                and stat.S_ISFIFO(current.st_mode)
                and int(current.st_ino) == self._inode
                and int(current.st_dev) == self._device
            ):
                try:
                    self._unlink(self.path)
                except OSError:
                    pass
            self._installed = False
