#!/usr/bin/env python3
"""Private helpers for the legacy in-process FUSE shutdown acceptance cases.

This module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It only observes and contains resources that the acceptance case itself proved
it owns:

* the service process group it started;
* the exact FUSE mount IDs it read from that service's ``/proc`` mountinfo;
* the independent namespace holder it started from the service's mount/user
  namespaces before the service exited.

There is no mock service, fake mount, SQL-ready/ACK substitute, lazy unmount in
a pass path, or foreign-path cleanup. Failure containment runs only for exact
recorded ``rootyard-vfs`` mount IDs in the holder's own namespace and never
turns a failed case into a pass.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

from tests import fuse_helper_native_support as support

EVIDENCE_PREFIX = "rootyard: legacy-shutdown-evidence "
EVIDENCE_SCHEMA = "rootyard/issues91-95/legacy-shutdown-evidence/v1"
EVIDENCE_MAX_WORKSPACES = 64
ORACLE_SECONDS = 5.0
STARTUP_OBSERVATION_SECONDS = 15.0
PREP_SHUTDOWN_SECONDS = 180.0
FUSE_SOURCE = "rootyard-vfs"
ATTACH_POLL_SECONDS = 0.02
MAX_HOLDER_ATTACH_ATTEMPTS = 3
_MAX_SAFE_LOG_BYTES = 4 * 1024 * 1024


class LegacyAcceptanceError(RuntimeError):
    """A bounded fixture precondition or oracle failure, never a skip."""


def workspace_hash(workspace_id) -> str:
    """Stable hash of the canonical lowercase UUID form used by the service."""
    return hashlib.sha256(str(uuid.UUID(str(workspace_id))).encode()).hexdigest()


def probe_namespace_inodes(pid: int):
    """Return exact user/mount namespace inodes, or None when unreadable."""
    try:
        user = int(os.stat(f"/proc/{int(pid)}/ns/user").st_ino)
        mount = int(os.stat(f"/proc/{int(pid)}/ns/mnt").st_ino)
    except (OSError, TypeError, ValueError):
        return None
    if user < 1 or mount < 1:
        return None
    return {"user": user, "mount": mount}


def namespace_inodes(pid: int) -> dict:
    """Return exact user/mount namespace inodes for an owned process."""
    pair = probe_namespace_inodes(pid)
    if pair is None:
        raise LegacyAcceptanceError("process namespace identity is unavailable")
    return pair


def start_service(harness, log_path=None):
    """Start one owned service process; never use a readiness timeout here."""
    log = open(log_path or (harness.root / "server.log"), "ab")
    proc = subprocess.Popen(
        [harness.args.binary, "serve"],
        env=harness.env,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    harness.log = log
    harness.proc = proc
    return proc


def wait_ready(harness, deadline: float) -> None:
    """Wait for the service health endpoint before a fixture case starts."""
    while time.monotonic() < deadline:
        if harness.proc is not None and harness.proc.poll() is not None:
            raise LegacyAcceptanceError("owned service exited before readiness")
        try:
            if harness.http("/health/ready")[0] == 200:
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise LegacyAcceptanceError("owned service did not become ready within the startup bound")


def _wait_exit(proc, deadline: float, *, clock=time.monotonic, sleep=time.sleep):
    """Poll first, then wait only to the same absolute deadline.

    An already-exited owned child is reaped even when the deadline has just
    expired; expiry never starts a fresh positive wait budget.
    """
    code = proc.poll()
    if code is not None:
        return code
    while True:
        now = clock()
        if now >= deadline:
            code = proc.poll()
            if code is not None:
                return code
            raise LegacyAcceptanceError("owned process did not exit within the shared deadline")
        code = proc.poll()
        if code is not None:
            return code
        sleep(min(0.01, max(0.0, deadline - now)))


def stop_service_gracefully(harness, timeout: float = ORACLE_SECONDS):
    """SIGTERM the exact owned process group and return its real exit code."""
    proc = harness.proc
    if proc is None:
        return None
    if proc.poll() is None:
        if os.getpgid(proc.pid) != proc.pid:
            raise LegacyAcceptanceError("owned service is not its process-group leader")
        os.killpg(proc.pid, signal.SIGTERM)
    code = _wait_exit(proc, time.monotonic() + timeout)
    harness.proc = None
    if harness.log is not None:
        harness.log.close()
        harness.log = None
    return code


def force_stop_owned_service(harness) -> None:
    """Failure containment: SIGKILL only the exact owned process group.

    The caller runs exact-owner mount containment before waiting for the
    process, so a FUSE-blocked task can be released by unmounting its proven
    mount instead of leaving the harness in an unbounded wait.
    """
    proc = harness.proc
    if proc is None or proc.poll() is not None:
        return
    if os.getpgid(proc.pid) != proc.pid:
        raise LegacyAcceptanceError("owned service is not its process-group leader")
    os.killpg(proc.pid, signal.SIGKILL)


def _attach_error(message: str, holder=None):
    """Build the existing bounded error, optionally handing back one child."""
    error = LegacyAcceptanceError(message)
    error.holder = holder
    return error


def _safe_namespaces(reader, pid):
    try:
        value = reader(pid)
    except OSError:
        return None
    if not isinstance(value, dict):
        return None
    try:
        user = int(value["user"])
        mount = int(value["mount"])
    except (KeyError, TypeError, ValueError):
        return None
    if user < 1 or mount < 1:
        return None
    return {"user": user, "mount": mount}


def _poll_pause(deadline: float, clock, sleep):
    now = clock()
    if now >= deadline:
        return
    sleep(min(ATTACH_POLL_SECONDS, max(0.0, deadline - now)))


def _live_starttime(proc, read_identity, expected_starttime=None):
    """Return the exact live Popen starttime, or None when it is gone."""
    if proc is None or proc.poll() is not None:
        return None
    try:
        identity = read_identity(proc.pid)
    except OSError:
        return None
    if not isinstance(identity, dict):
        return None
    try:
        pid = int(identity.get("pid", -1))
    except (TypeError, ValueError):
        raise LegacyAcceptanceError("owned process identity PID is not numeric") from None
    if pid != int(proc.pid):
        raise LegacyAcceptanceError("owned process identity PID changed before namespace readiness")
    if identity.get("state") == "Z":
        return None
    try:
        starttime = int(identity.get("starttime"))
    except (TypeError, ValueError):
        raise LegacyAcceptanceError("owned process starttime is not numeric") from None
    if starttime < 1:
        raise LegacyAcceptanceError("owned process starttime is not positive")
    if expected_starttime is not None and starttime != int(expected_starttime):
        raise LegacyAcceptanceError("owned process starttime changed before namespace readiness")
    return starttime


def _prove_service_namespaces(
    service_proc,
    deadline: float,
    *,
    clock,
    sleep,
    read_identity,
    read_namespaces,
):
    """Prove the exact owned service is live and already in private namespaces.

    The wrapper execs ``unshare -Urm`` in the same PID, so the service must be
    observed outside both the enclosing fixture's user and mount namespaces
    before any observer is spawned. This is namespace identity, never a PID,
    command-line or timing guess.
    """
    if service_proc is None:
        raise LegacyAcceptanceError("owned service process is unavailable")
    enclosing = _safe_namespaces(read_namespaces, os.getpid())
    if enclosing is None:
        raise LegacyAcceptanceError("enclosing fixture namespace identity is unavailable")
    while True:
        if clock() >= deadline:
            raise _attach_error(
                "owned service did not enter private namespaces within the attach bound"
            )
        if service_proc.poll() is not None:
            raise _attach_error("owned service exited before namespace readiness")
        starttime = _live_starttime(service_proc, read_identity)
        if starttime is None:
            _poll_pause(deadline, clock, sleep)
            continue
        namespaces = _safe_namespaces(read_namespaces, service_proc.pid)
        if (
            namespaces is not None
            and namespaces["user"] != enclosing["user"]
            and namespaces["mount"] != enclosing["mount"]
        ):
            stable_starttime = _live_starttime(service_proc, read_identity, starttime)
            stable_namespaces = _safe_namespaces(read_namespaces, service_proc.pid)
            if stable_starttime == starttime and stable_namespaces == namespaces:
                return {
                    "service_pid": int(service_proc.pid),
                    "service_starttime": starttime,
                    "namespaces": namespaces,
                }
        _poll_pause(deadline, clock, sleep)


def _require_service_stable(service_proc, service, *, read_identity, read_namespaces):
    """Terminally fail unless the exact owned service still owns its namespaces."""
    if service_proc is None or service_proc.poll() is not None:
        raise _attach_error("owned service exited before the holder attached")
    starttime = _live_starttime(
        service_proc, read_identity, service["service_starttime"]
    )
    if starttime is None:
        raise _attach_error("owned service exited before the holder attached")
    namespaces = _safe_namespaces(read_namespaces, service_proc.pid)
    if namespaces != service["namespaces"]:
        raise _attach_error("owned service namespaces changed before the holder attached")


def _holder_still_matches(holder, starttime, namespaces, *, read_identity, read_namespaces):
    if holder.poll() is not None:
        return False
    if _live_starttime(holder, read_identity, starttime) != starttime:
        return False
    return _safe_namespaces(read_namespaces, holder.pid) == namespaces


def _wait_holder_ready(
    holder,
    service,
    service_proc,
    deadline: float,
    *,
    clock,
    sleep,
    read_identity,
    read_namespaces,
):
    """Poll one exact owned holder until setns completed in the same namespaces."""
    holder_starttime = None
    while clock() < deadline:
        if holder.poll() is not None:
            return False
        _require_service_stable(
            service_proc,
            service,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        )
        starttime = _live_starttime(holder, read_identity, holder_starttime)
        if starttime is None:
            _poll_pause(deadline, clock, sleep)
            continue
        holder_starttime = starttime
        namespaces = _safe_namespaces(read_namespaces, holder.pid)
        if namespaces != service["namespaces"]:
            _poll_pause(deadline, clock, sleep)
            continue
        # Recheck holder and service in a fixed order so no stale pre-setns
        # namespace or changed service identity can satisfy readiness.
        if not _holder_still_matches(
            holder,
            starttime,
            namespaces,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        ):
            if holder.poll() is not None:
                return False
            _poll_pause(deadline, clock, sleep)
            continue
        _require_service_stable(
            service_proc,
            service,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        )
        if not _holder_still_matches(
            holder,
            starttime,
            namespaces,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        ):
            if holder.poll() is not None:
                return False
            _poll_pause(deadline, clock, sleep)
            continue
        _require_service_stable(
            service_proc,
            service,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        )
        return True
    return False


def _stop_owned_holder(holder, deadline: float, *, clock, sleep):
    """Kill and reap only this exact Popen; return it when still pending at D."""
    if holder is None:
        return None
    if holder.poll() is None:
        try:
            holder.kill()
        except OSError:
            pass
    while True:
        if holder.poll() is not None:
            return None
        now = clock()
        if now >= deadline:
            return holder
        sleep(min(ATTACH_POLL_SECONDS, max(0.0, deadline - now)))


def attach_namespace_holder(
    service_proc,
    deadline: float,
    *,
    clock=time.monotonic,
    sleep=time.sleep,
    read_identity=support.process_identity,
    read_namespaces=probe_namespace_inodes,
    spawn=support.spawn_api_namespace_holder,
):
    """Enter the service's own user/mount namespaces before it exits.

    One absolute deadline bounds service namespace readiness, every holder
    spawn, setns completion, identity/namespace rechecks, and exact-child
    cleanup. A holder is returned only after the exact owned service PID and
    starttime are live in the captured private namespaces and the exact owned
    holder PID and starttime are live in those same namespaces. A still-running
    pre-setns holder is never accepted; an exited or reparented/identity-changed
    child is reaped before a bounded retry or an unequivocal failure.
    """
    service = _prove_service_namespaces(
        service_proc,
        deadline,
        clock=clock,
        sleep=sleep,
        read_identity=read_identity,
        read_namespaces=read_namespaces,
    )
    for _attempt in range(MAX_HOLDER_ATTACH_ATTEMPTS):
        if clock() >= deadline:
            break
        _require_service_stable(
            service_proc,
            service,
            read_identity=read_identity,
            read_namespaces=read_namespaces,
        )
        holder = spawn(int(service_proc.pid))
        try:
            if _wait_holder_ready(
                holder,
                service,
                service_proc,
                deadline,
                clock=clock,
                sleep=sleep,
                read_identity=read_identity,
                read_namespaces=read_namespaces,
            ):
                return holder
        except BaseException:
            pending = _stop_owned_holder(
                holder, deadline, clock=clock, sleep=sleep
            )
            if pending is not None:
                raise _attach_error(
                    "independent namespace holder could not be reaped within the attach bound",
                    pending,
                ) from None
            raise
        pending = _stop_owned_holder(holder, deadline, clock=clock, sleep=sleep)
        if pending is not None:
            raise _attach_error(
                "independent namespace holder could not be reaped within the attach bound",
                pending,
            )
    raise _attach_error("independent namespace holder could not attach before service exit")


def _owned_rows(pid: int, mountpoint: Path):
    expected = str(mountpoint)
    rows = support.read_process_mountinfo(pid)
    return [
        row for row in rows
        if row["mountpoint"] == expected
        and row["source"] == FUSE_SOURCE
        and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
    ]


def wait_owned_mount(pid: int, mountpoint: Path, deadline: float) -> dict:
    """Wait for exactly one owned FUSE mount at the exact API-created path."""
    while time.monotonic() < deadline:
        rows = _owned_rows(pid, mountpoint)
        if len(rows) == 1:
            return rows[0]
        if len(rows) > 1:
            raise LegacyAcceptanceError("multiple owned FUSE mounts appeared at one workspace path")
        time.sleep(0.02)
    raise LegacyAcceptanceError("owned FUSE mount was not observed within the startup observation bound")


def wait_exact_mount_gone(holder_pid: int, mountpoint: Path, mount_id: int, deadline: float) -> None:
    """Require the exact old mount ID absent and no replacement at that path."""
    expected = str(mountpoint)
    while time.monotonic() < deadline:
        rows = support.read_process_mountinfo(holder_pid)
        at_path = [row for row in rows if row["mountpoint"] == expected]
        if not at_path:
            return
        if not any(
            row["mount_id"] == int(mount_id)
            and row["source"] == FUSE_SOURCE
            and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
            for row in at_path
        ):
            raise LegacyAcceptanceError("owned workspace path carried a replacement mount after cleanup")
        time.sleep(0.02)
    raise LegacyAcceptanceError("exact owned mount did not disappear within the shared deadline")


def owned_leftovers(holder_pid: int, mountpoints) -> int:
    """Count exact owned-source mounts at this run's workspace paths."""
    expected = {str(path) for path in mountpoints}
    rows = support.read_process_mountinfo(holder_pid)
    return sum(
        1 for row in rows
        if row["mountpoint"] in expected
        and row["source"] == FUSE_SOURCE
        and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
    )


def _containment_result(owner, before, any_failure: bool) -> dict:
    after = owner.snapshot()
    started = after["started"] - before["started"]
    contained = after["contained"] - before["contained"]
    deadline_exhausted = after["deadline_exhausted"] - before["deadline_exhausted"]
    errors = after["errors"] - before["errors"]
    pending = after["pending"]
    if pending > 0:
        outcome = "pending"
    elif deadline_exhausted > 0:
        outcome = "deadline_exhausted"
    elif any_failure or errors > 0:
        outcome = "failed"
    elif started > 0:
        outcome = "contained"
    else:
        outcome = "clean"
    result = {
        "outcome": outcome,
        "started": started,
        "contained": contained,
        "kill_requested": after["kill_requested"] - before["kill_requested"],
        "reaped": after["reaped"] - before["reaped"],
        "pending": pending,
        "deadline_exhausted": deadline_exhausted,
        "errors": errors,
        "error_classes": after["error_classes"],
        "pending_children": after["pending_children"],
    }
    result["failed"] = bool(
        outcome != "clean"
        or started > 0
        or pending > 0
        or deadline_exhausted > 0
        or errors > 0
    )
    return result


def contain_proven_owned_mounts(
    holder_pid: int,
    records,
    deadline: float,
    owner,
    *,
    clock=time.monotonic,
    spawn=None,
    read_mountinfo=None,
    wait_mount_gone=None,
    read_identity=None,
):
    """Failure containment for exact recorded owned identities only.

    ``records`` contains ``(mountpoint, mount_id)`` observed before the failure.
    ``owner`` is the runner-level strong owner that receives the exact Popen
    immediately after it returns. D is checked at entry, per record, and again
    immediately before spawn. Once D is observed expired, no new child is
    admitted; an already-created child is polled/killed/polled and retained as
    pending until a real reap is observed. No lazy unmount, path guess, process
    group signal, or foreign mount is touched.
    """
    if spawn is None:
        spawn = support.spawn_api_namespace
    if read_mountinfo is None:
        read_mountinfo = support.read_process_mountinfo
    if wait_mount_gone is None:
        wait_mount_gone = wait_exact_mount_gone
    if read_identity is None:
        read_identity = support.process_identity
    before = owner.snapshot()
    any_failure = False
    if deadline is None or clock() >= deadline:
        owner.note_deadline_exhausted()
        return _containment_result(owner, before, True)

    for mountpoint, mount_id in records:
        if clock() >= deadline:
            owner.note_deadline_exhausted()
            any_failure = True
            break
        try:
            rows = read_mountinfo(holder_pid)
        except Exception as error:
            owner.note_error(error)
            any_failure = True
            break
        exact = [
            row for row in rows
            if row["mountpoint"] == str(mountpoint)
            and row["mount_id"] == int(mount_id)
            and row["source"] == FUSE_SOURCE
            and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
        ]
        if not exact:
            continue
        if clock() >= deadline:
            owner.note_deadline_exhausted()
            any_failure = True
            break
        try:
            child = spawn(
                holder_pid, ["umount", "--no-canonicalize", str(mountpoint)]
            )
        except Exception as error:
            owner.note_error(error)
            any_failure = True
            break
        try:
            record = owner.register(child, int(mount_id))
        except BaseException:
            # Registration should not fail for a real Popen/mount ID, but never
            # abandon the just-returned exact child if it does.
            try:
                child.kill()
            except Exception:
                pass
            try:
                child.poll()
            except Exception:
                pass
            raise
        try:
            identity = read_identity(record.pid)
        except Exception:
            identity = None
        if isinstance(identity, dict):
            try:
                starttime = int(identity.get("starttime"))
            except (TypeError, ValueError):
                starttime = None
            if starttime is not None and starttime >= 1:
                record.starttime = starttime

        if clock() >= deadline:
            owner.note_deadline_exhausted()
            owner.reap_owned_child(record, deadline, clock=clock)
            any_failure = True
            break
        try:
            code = owner.reap_owned_child(record, deadline, clock=clock)
        except Exception as error:
            owner.note_error(error)
            any_failure = True
            break
        if code is None:
            any_failure = True
            break
        if code != 0:
            owner.note_error(error_class="nonzero_exit")
            any_failure = True
            break
        try:
            wait_mount_gone(holder_pid, mountpoint, int(mount_id), deadline)
        except Exception as error:
            if clock() >= deadline:
                owner.note_deadline_exhausted()
            owner.note_error(error)
            any_failure = True
            break
        owner.note_contained()
    return _containment_result(owner, before, any_failure)


def close_holder(holder) -> None:
    if holder is None:
        return
    support.terminate_process(holder)


def _safe_field(value, kind):
    if kind is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is str:
        return isinstance(value, str)
    if kind is bool:
        return isinstance(value, bool)
    return False


def read_join_evidence(
    log_path: Path,
    expected_namespace: int,
    expected_workspace_hashes,
    forbidden_workspace_hashes=(),
):
    """Parse exactly one fixed-schema evidence line from our own service log.

    The evidence must name exactly the expected workspace identities, with no
    duplicates or omissions, and the joined-mount count must equal that exact
    set size. Forbidden identities (for example the deliberately corrupted
    later fixture) must be absent. Only matching lines are parsed; unrelated
    service diagnostics are ignored and never returned. The caller receives
    safe counts/hashes only.
    """
    expected = tuple(str(value) for value in expected_workspace_hashes)
    if not expected:
        raise LegacyAcceptanceError("legacy join evidence has no expected workspace")
    if len(set(expected)) != len(expected):
        raise LegacyAcceptanceError("expected legacy workspace identities are not unique")
    forbidden = {str(value) for value in forbidden_workspace_hashes}
    path = Path(log_path)
    try:
        raw = path.read_bytes()
    except OSError:
        raise LegacyAcceptanceError("service evidence log is unavailable") from None
    if len(raw) > _MAX_SAFE_LOG_BYTES:
        raise LegacyAcceptanceError("service evidence log exceeded the bounded fixture limit")
    lines = raw.decode("utf-8", "replace").splitlines()
    matches = [line for line in lines if line.startswith(EVIDENCE_PREFIX)]
    if len(matches) != 1:
        raise LegacyAcceptanceError("service emitted no unique legacy join evidence line")
    try:
        payload = json.loads(matches[0][len(EVIDENCE_PREFIX):])
    except ValueError:
        raise LegacyAcceptanceError("legacy join evidence was not valid JSON") from None
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_SCHEMA:
        raise LegacyAcceptanceError("legacy join evidence schema mismatch")

    fields = (
        ("mount_namespace", int),
        ("joined_mounts", int),
        ("joined_workspaces", list),
        ("joined_workspaces_total", int),
        ("joined_workspaces_truncated", bool),
        ("pending_admissions", int),
        ("retained_owners", int),
        ("cleanup_failures", int),
    )
    for name, kind in fields:
        if name not in payload or not _safe_field(payload[name], kind):
            raise LegacyAcceptanceError(f"legacy join evidence field {name} has an invalid type")

    namespace = payload["mount_namespace"]
    joined = payload["joined_mounts"]
    workspaces = payload["joined_workspaces"]
    if namespace <= 0 or namespace != int(expected_namespace):
        raise LegacyAcceptanceError("legacy join evidence mount namespace does not match the service")
    if joined < 1:
        raise LegacyAcceptanceError("empty legacy ticket was reported as one mounted proof")
    if payload["joined_workspaces_truncated"]:
        raise LegacyAcceptanceError("legacy join evidence unexpectedly truncated")
    if payload["joined_workspaces_total"] != len(workspaces):
        raise LegacyAcceptanceError("legacy join evidence workspace count mismatch")
    if not (1 <= len(workspaces) <= EVIDENCE_MAX_WORKSPACES):
        raise LegacyAcceptanceError("legacy join evidence workspace list is not bounded")
    if any(not isinstance(value, str) or len(value) != 64 for value in workspaces):
        raise LegacyAcceptanceError("legacy join evidence workspace identity is not a SHA-256")
    if len(set(workspaces)) != len(workspaces):
        raise LegacyAcceptanceError("legacy join evidence workspace identities are not unique")
    if payload["pending_admissions"] != 0:
        raise LegacyAcceptanceError("legacy join evidence retained a pending admission")
    if payload["retained_owners"] != 0:
        raise LegacyAcceptanceError("legacy join evidence retained an owned mount")
    if payload["cleanup_failures"] != 0:
        raise LegacyAcceptanceError("legacy join evidence reported a cleanup failure")
    if forbidden.intersection(workspaces):
        raise LegacyAcceptanceError("legacy join evidence named a forbidden workspace")
    if joined != len(expected):
        raise LegacyAcceptanceError("legacy join evidence mount count does not match the exact workspace set")
    if set(workspaces) != set(expected):
        raise LegacyAcceptanceError("legacy join evidence workspace set is not the exact expected set")
    return {
        "schema": EVIDENCE_SCHEMA,
        "mount_namespace": namespace,
        "joined_mounts": joined,
        "joined_workspaces": len(workspaces),
        "workspace_hashes": list(workspaces),
        "expected_workspace_hashes": list(expected),
        "pending_admissions": 0,
        "retained_owners": 0,
        "cleanup_failures": 0,
    }
