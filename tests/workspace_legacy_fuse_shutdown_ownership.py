#!/usr/bin/env python3
"""Owned holder and containment-child ownership for legacy shutdown cases.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It pins the independent namespace holder to the exact ``Popen`` process the case
started, proves that holder's mount namespace equals the service's mount
namespace, rechecks the same PID/starttime after the service exits, and retains
failure-containment children as exact owned ``Popen`` objects until their real
reap is observed. It never selects a process by name, path, or environment and
never signals a foreign process or an inherited process group.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
import time

from tests import fuse_helper_native_support as support
from tests.workspace_legacy_fuse_shutdown_support import (
    LegacyAcceptanceError,
    namespace_inodes,
)

SAFE_CONTAINMENT_ERRORS = frozenset((
    "TimeoutExpired", "ProcessLookupError", "OSError", "LegacyAcceptanceError",
    "HarnessError", "RuntimeError", "ValueError", "TypeError", "AttributeError",
))
LATE_POLL_SECONDS = 0.01
LATE_DIAG_LIMIT = 3


def safe_error_name(error) -> str:
    """Return a finite class name, never raw exception text."""
    name = type(error).__name__
    return name if name in SAFE_CONTAINMENT_ERRORS else "unknown"


def _positive_int(value, label: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise LegacyAcceptanceError(f"{label} is not a numeric identity") from None
    if number < 1:
        raise LegacyAcceptanceError(f"{label} is not a positive identity")
    return number


def owned_service_group(service_proc):
    """Require the exact owned Popen to lead its own process group."""
    if service_proc is None:
        raise LegacyAcceptanceError("owned service process is unavailable")
    pid = _positive_int(service_proc.pid, "owned service pid")
    try:
        pgid = os.getpgid(pid)
    except OSError:
        raise LegacyAcceptanceError("owned service process group is unavailable") from None
    if pgid != pid:
        raise LegacyAcceptanceError("owned service is not its process-group leader")
    return pid, pgid


def capture_service_identity(service_proc):
    """Capture the exact owned service PID/starttime before startup trigger."""
    pid, _pgid = owned_service_group(service_proc)
    identity = support.process_identity(pid)
    if not isinstance(identity, dict):
        raise LegacyAcceptanceError("owned service identity is unavailable")
    if int(identity.get("pid", -1)) != pid:
        raise LegacyAcceptanceError("owned service identity PID changed before startup trigger")
    if identity.get("state") == "Z":
        raise LegacyAcceptanceError("owned service exited before startup trigger")
    return {
        "service_pid": pid,
        "service_starttime": _positive_int(identity.get("starttime"), "owned service starttime"),
    }


def recheck_service_identity(service_proc, captured):
    """Require the same owned service PID/starttime just before the trigger."""
    pid, _pgid = owned_service_group(service_proc)
    captured_pid = _positive_int(captured.get("service_pid"), "captured owned service pid")
    if pid != captured_pid:
        raise LegacyAcceptanceError("owned service PID changed before startup trigger")
    identity = support.process_identity(pid)
    if not isinstance(identity, dict):
        raise LegacyAcceptanceError("owned service identity is unavailable before startup trigger")
    if int(identity.get("pid", -1)) != captured_pid:
        raise LegacyAcceptanceError("owned service identity PID changed before startup trigger")
    if identity.get("state") == "Z":
        raise LegacyAcceptanceError("owned service exited before startup trigger")
    starttime = _positive_int(identity.get("starttime"), "owned service starttime")
    if starttime != _positive_int(
        captured.get("service_starttime"), "captured owned service starttime"
    ):
        raise LegacyAcceptanceError("owned service starttime changed before startup trigger")
    return {"service_pid": captured_pid, "service_starttime": starttime}


def capture_holder_identity(holder, service_proc):
    """Capture the exact owned holder and prove it shares the service namespace."""
    if holder is None:
        raise LegacyAcceptanceError("namespace holder process is unavailable")
    pid = _positive_int(holder.pid, "namespace holder pid")
    if holder.poll() is not None:
        raise LegacyAcceptanceError("namespace holder exited before ownership capture")
    identity = support.process_identity(pid)
    if identity is None:
        raise LegacyAcceptanceError("namespace holder identity is unavailable")
    if int(identity.get("pid", -1)) != pid:
        raise LegacyAcceptanceError("namespace holder identity does not match its owned Popen PID")
    if identity.get("state") == "Z":
        raise LegacyAcceptanceError("namespace holder is not a live observer")
    starttime = _positive_int(identity.get("starttime"), "namespace holder starttime")
    if service_proc is None or service_proc.poll() is not None:
        raise LegacyAcceptanceError("owned service exited before namespace holder capture")
    service_pid, service_pgid = owned_service_group(service_proc)
    service_identity = support.process_identity(service_pid)
    if not isinstance(service_identity, dict):
        raise LegacyAcceptanceError("owned service identity is unavailable at holder capture")
    if int(service_identity.get("pid", -1)) != service_pid:
        raise LegacyAcceptanceError("owned service identity PID changed at holder capture")
    if service_identity.get("state") == "Z":
        raise LegacyAcceptanceError("owned service exited before namespace holder capture")
    service_starttime = _positive_int(
        service_identity.get("starttime"), "service starttime"
    )
    service_namespaces = namespace_inodes(service_pid)
    holder_namespaces = namespace_inodes(pid)
    if holder_namespaces["mount"] != service_namespaces["mount"]:
        raise LegacyAcceptanceError("namespace holder mount namespace does not match the service")
    if holder_namespaces["user"] != service_namespaces["user"]:
        raise LegacyAcceptanceError("namespace holder user namespace does not match the service")
    return {
        "service_pid": service_pid,
        "service_pgid": service_pgid,
        "service_starttime": service_starttime,
        "holder_pid": pid,
        "holder_starttime": starttime,
        "holder_mount_namespace": holder_namespaces["mount"],
        "holder_user_namespace": holder_namespaces["user"],
        "service_namespace": service_namespaces["mount"],
        "service_user_namespace": service_namespaces["user"],
    }


def recheck_holder_identity(holder, captured):
    """Require the same owned holder PID/starttime after the service exits."""
    if holder is None:
        raise LegacyAcceptanceError("namespace holder process is unavailable")
    captured_pid = _positive_int(captured.get("holder_pid"), "captured namespace holder pid")
    if _positive_int(holder.pid, "namespace holder pid") != captured_pid:
        raise LegacyAcceptanceError("namespace holder Popen PID changed before release")
    identity = support.process_identity(captured_pid)
    if identity is None:
        raise LegacyAcceptanceError("namespace holder exited before the post-exit recheck")
    if int(identity.get("pid", -1)) != captured_pid:
        raise LegacyAcceptanceError("namespace holder identity PID changed before release")
    if identity.get("state") == "Z":
        raise LegacyAcceptanceError("namespace holder is no longer the live observer before release")
    starttime = _positive_int(identity.get("starttime"), "namespace holder starttime")
    captured_starttime = _positive_int(
        captured.get("holder_starttime"), "captured namespace holder starttime"
    )
    if starttime != captured_starttime:
        raise LegacyAcceptanceError("namespace holder starttime changed before release")
    return {"pid": captured_pid, "starttime": starttime}


def observed_mount_ids(records):
    """Return the exact observed numeric mount IDs without paths."""
    ids = [
        _positive_int(mount_id, "observed owned mount id")
        for _mountpoint, mount_id in records
    ]
    if len(ids) != len(set(ids)):
        raise LegacyAcceptanceError("observed owned mount identities are not unique")
    return sorted(ids)


def record_ownership_detail(detail, captured, mount_ids) -> None:
    """Persist only safe numeric identities and exact mount IDs."""
    namespace = _positive_int(captured.get("service_namespace"), "service mount namespace")
    detail.update({
        "service_pid": _positive_int(captured.get("service_pid"), "owned service pid"),
        "service_pgid": _positive_int(captured.get("service_pgid"), "owned service process group"),
        "holder_pid": _positive_int(captured.get("holder_pid"), "namespace holder pid"),
        "holder_starttime": _positive_int(
            captured.get("holder_starttime"), "namespace holder starttime"
        ),
        "holder_mount_namespace": _positive_int(
            captured.get("holder_mount_namespace"), "holder mount namespace"
        ),
        "mount_namespace": namespace,
        "owned_mount_ids": sorted(
            _positive_int(value, "observed owned mount id") for value in mount_ids
        ),
    })


@dataclass
class ContainmentRecord:
    """One exact direct child held by the failed-run containment owner."""

    proc: object
    pid: int
    mount_id: int
    starttime: int | None = None
    state: str = "started"
    returncode: int | None = None
    kill_requested: bool = False
    deadline_crossed: bool = False
    signal_error: str | None = None
    reap_error: str | None = None

    def safe(self) -> dict:
        return {
            "pid": self.pid,
            "starttime": self.starttime,
            "mount_id": self.mount_id,
            "state": self.state,
            "returncode": self.returncode,
            "kill_requested": bool(self.kill_requested),
            "deadline_crossed": bool(self.deadline_crossed),
            "signal_error": self.signal_error,
            "reap_error": self.reap_error,
        }


class ContainmentOwner:
    """Strong owner for containment Popen children and retained fixtures.

    The record holds the live ``Popen`` object, not a reconstructed PID. A
    record leaves the pending state only after ``poll``/``wait`` returns a real
    code. ``late_physical_drain`` is reserved for the already-failed report
    runner and deliberately has no positive acceptance grace.
    """

    def __init__(self):
        self._records: list[ContainmentRecord] = []
        self._contained = 0
        self._deadline_exhausted = 0
        self._errors = 0
        self._error_classes: set[str] = set()
        self._late_state = "not_needed"
        self._late_reaped = 0
        self._late_wait_errors = 0
        self._late_wait_error_classes: set[str] = set()
        self._retained: list[object] = []

    def reset(self) -> None:
        if self.pending_records():
            raise LegacyAcceptanceError("cannot reset containment owner with pending children")
        self._records.clear()
        self._contained = 0
        self._deadline_exhausted = 0
        self._errors = 0
        self._error_classes.clear()
        self._late_state = "not_needed"
        self._late_reaped = 0
        self._late_wait_errors = 0
        self._late_wait_error_classes.clear()
        self._retained.clear()

    def register(self, proc, mount_id, starttime=None) -> ContainmentRecord:
        """Register the exact child immediately after Popen returns."""
        pid = _positive_int(proc.pid, "containment child pid")
        record = ContainmentRecord(
            proc=proc,
            pid=pid,
            mount_id=_positive_int(mount_id, "containment mount id"),
            starttime=starttime,
        )
        self._records.append(record)
        return record

    def note_contained(self) -> None:
        self._contained += 1

    def note_deadline_exhausted(self) -> None:
        self._deadline_exhausted += 1

    def note_error(self, error=None, error_class=None) -> None:
        self._errors += 1
        if error_class is not None:
            self._error_classes.add(str(error_class))
        elif error is not None:
            self._error_classes.add(safe_error_name(error))

    def pending_records(self):
        return [record for record in self._records if record.state != "reaped"]

    def _poll(self, record):
        try:
            return record.proc.poll()
        except Exception as error:
            record.reap_error = safe_error_name(error)
            self.note_error(error)
            return None

    def _note_late_wait_issue(self, record, error_class: str) -> None:
        """Record bounded late-drain diagnostics, never an unbounded list."""
        if error_class not in self._late_wait_error_classes:
            self._late_wait_error_classes.add(error_class)
        if self._late_wait_errors < LATE_DIAG_LIMIT:
            self._late_wait_errors += 1
        record.reap_error = error_class

    def _poll_late(self, record):
        try:
            return record.proc.poll()
        except Exception as error:
            self._note_late_wait_issue(record, safe_error_name(error))
            return None

    def mark_reaped(self, record, code) -> None:
        record.state = "reaped"
        record.returncode = int(code)

    def reap_owned_child(self, record, deadline, *, clock=time.monotonic):
        """Reap the exact child, polling even after D, then kill/poll if needed."""
        code = self._poll(record)
        if code is not None:
            self.mark_reaped(record, code)
            return record.returncode

        now = clock()
        if now < deadline:
            remaining = max(0.0, deadline - now)
            try:
                code = record.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                record.deadline_crossed = True
                self.note_deadline_exhausted()
            except Exception as error:
                record.reap_error = safe_error_name(error)
                self.note_error(error)
            else:
                if code is not None:
                    self.mark_reaped(record, code)
                    return record.returncode
        else:
            record.deadline_crossed = True
            self.note_deadline_exhausted()

        code = self._poll(record)
        if code is not None:
            self.mark_reaped(record, code)
            return record.returncode
        record.kill_requested = True
        record.state = "kill_requested"
        try:
            record.proc.kill()
        except Exception as error:
            record.signal_error = safe_error_name(error)
            self.note_error(error)
        code = self._poll(record)
        if code is not None:
            self.mark_reaped(record, code)
            return record.returncode
        record.state = "pending"
        return None

    def late_physical_drain(self, *, sleep=time.sleep, poll_interval=LATE_POLL_SECONDS) -> int:
        """Explicit failed-run drain that never returns while a child is pending.

        This is not an acceptance grace and cannot revive the oracle. A wait
        exception or a ``None`` result is retried on the same exact owned
        ``Popen`` at a quiet poll cadence. There is no timeout and no success
        state until ``poll`` or ``wait`` yields a real return code. If the
        child is permanently unobservable, this call keeps the runner, owner,
        holders and failed pending report alive until an external resolution
        or the outer job terminates the process.
        """
        if not self.pending_records():
            self._late_state = "reaped_late" if self._late_reaped > 0 else "not_needed"
            return 0
        self._late_state = "draining"
        while self.pending_records():
            for record in list(self.pending_records()):
                code = self._poll_late(record)
                if code is not None:
                    self.mark_reaped(record, code)
                    self._late_reaped += 1
                    continue
                try:
                    code = record.proc.wait()
                except Exception as error:
                    self._note_late_wait_issue(record, safe_error_name(error))
                    code = self._poll_late(record)
                else:
                    if code is None:
                        self._note_late_wait_issue(record, "wait_none")
                        code = self._poll_late(record)
                if code is not None:
                    self.mark_reaped(record, code)
                    self._late_reaped += 1
            if self.pending_records():
                sleep(poll_interval)
        self._late_state = "reaped_late"
        return self._late_reaped

    def snapshot(self) -> dict:
        records = [record.safe() for record in self._records]
        pending = [row for row in records if row["state"] != "reaped"]
        late_state = self._late_state
        if late_state == "not_needed" and pending:
            late_state = "pending"
        return {
            "started": len(records),
            "contained": self._contained,
            "kill_requested": sum(1 for row in records if row["kill_requested"]),
            "reaped": sum(1 for row in records if row["state"] == "reaped"),
            "pending": len(pending),
            "deadline_exhausted": self._deadline_exhausted,
            "errors": self._errors,
            "error_classes": sorted(self._error_classes),
            "records": records,
            "pending_children": pending,
            "late_cleanup": {
                "state": late_state,
                "reaped_late": self._late_reaped,
                "pending": len(pending),
                "wait_error_count": self._late_wait_errors,
                "wait_error_classes": sorted(self._late_wait_error_classes),
                "wait_diagnostics_capped": self._late_wait_errors >= LATE_DIAG_LIMIT,
            },
            "retained_fixtures": len(self._retained),
        }

    def retain_fixture(self, fixture) -> None:
        """Keep an unresolved fixture/namespace object strongly reachable."""
        self._retained.append(fixture)


def attach_containment_detail(detail, result, owner) -> None:
    """Attach safe per-case containment accounting and defer marker."""
    snapshot = owner.snapshot()
    detail["containment"] = dict(result)
    detail["containment_outcome"] = str(result.get("outcome", "unknown"))
    detail["containment_pending"] = int(result.get("pending", 0))
    detail["containment_deadline_exhausted"] = int(result.get("deadline_exhausted", 0))
    detail["containment_errors"] = int(result.get("errors", 0))
    if snapshot["pending"] > 0:
        detail["fixture_cleanup_deferred"] = True


def retain_unresolved_fixtures(owner, holders, harness) -> None:
    """Retain exact holders/harness when a pending child blocks safe cleanup."""
    for holder in holders:
        owner.retain_fixture(holder)
    if harness is not None:
        owner.retain_fixture(harness)
