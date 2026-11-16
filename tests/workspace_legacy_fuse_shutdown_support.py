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

import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
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
_MAX_SAFE_LOG_BYTES = 4 * 1024 * 1024


class LegacyAcceptanceError(RuntimeError):
    """A bounded fixture precondition or oracle failure, never a skip."""


def workspace_hash(workspace_id) -> str:
    """Stable hash of the canonical lowercase UUID form used by the service."""
    return hashlib.sha256(str(uuid.UUID(str(workspace_id))).encode()).hexdigest()


def mount_namespace_inode(pid: int) -> int:
    try:
        return int(os.stat(f"/proc/{int(pid)}/ns/mnt").st_ino)
    except OSError:
        raise LegacyAcceptanceError("mount namespace identity is unavailable") from None


def create_workspace(harness, agent_id: str, idempotency_key: str) -> dict:
    status, body, _ = harness.http(
        "/api/workspaces",
        token=harness.alice,
        method="POST",
        body={
            "owner": "alice",
            "repository": "demo",
            "agent_id": agent_id,
            "base_oid": harness.second,
        },
        extra_headers={"Idempotency-Key": idempotency_key},
    )
    if status != 201:
        raise LegacyAcceptanceError(f"workspace creation returned {status}, not 201")
    try:
        value = json.loads(body)
    except ValueError:
        raise LegacyAcceptanceError("workspace creation returned invalid JSON") from None
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise LegacyAcceptanceError("workspace creation returned no stable id")
    return value


def workspace_state(harness, workspace_id: str) -> dict:
    return json.loads(harness.expect(f"/api/workspaces/{workspace_id}", 200, token=harness.alice))


def workspace_paths(harness, workspace_id: str) -> dict:
    root = harness.root / "data/workspace-service"
    return {
        "lower": root / "workspaces" / workspace_id,
        "upper": root / "uppers" / workspace_id,
        "mountpoint": root / "mounts" / workspace_id,
    }


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


def _wait_exit(proc, deadline: float):
    while time.monotonic() < deadline:
        code = proc.poll()
        if code is not None:
            return code
        time.sleep(0.01)
    raise LegacyAcceptanceError("owned service did not exit within the shared deadline")


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


def attach_namespace_holder(api_pid: int, deadline: float):
    """Enter the service's own user/mount namespaces before it exits."""
    while time.monotonic() < deadline:
        if not Path(f"/proc/{int(api_pid)}").exists():
            break
        try:
            holder = support.spawn_api_namespace_holder(api_pid)
        except support.HarnessError:
            raise
        if holder.poll() is not None:
            support.terminate_process(holder)
            time.sleep(0.02)
            continue
        return holder
    raise LegacyAcceptanceError("independent namespace holder could not attach before service exit")


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


def contain_proven_owned_mounts(holder_pid: int, records, deadline: float) -> int:
    """Failure containment for exact recorded owned identities only.

    ``records`` contains ``(mountpoint, mount_id)`` observed before the failure.
    A record whose exact ID no longer occupies that path is skipped. No lazy
    unmount, path guess or foreign mount is touched.
    """
    contained = 0
    for mountpoint, mount_id in records:
        rows = support.read_process_mountinfo(holder_pid)
        exact = [
            row for row in rows
            if row["mountpoint"] == str(mountpoint)
            and row["mount_id"] == int(mount_id)
            and row["source"] == FUSE_SOURCE
            and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
        ]
        if not exact:
            continue
        child = support.spawn_api_namespace(
            holder_pid, ["umount", "--no-canonicalize", str(mountpoint)]
        )
        code = _wait_exit(child, deadline)
        if code != 0:
            raise LegacyAcceptanceError("exact owned failure containment did not confirm unmount")
        wait_exact_mount_gone(holder_pid, mountpoint, int(mount_id), deadline)
        contained += 1
    return contained


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


def read_join_evidence(log_path: Path, expected_namespace: int, expected_workspace_hash: str):
    """Parse exactly one fixed-schema evidence line from our own service log.

    Only matching lines are parsed; unrelated service diagnostics are ignored
    and never returned. The caller receives safe counts/hashes only.
    """
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
    if payload["pending_admissions"] != 0:
        raise LegacyAcceptanceError("legacy join evidence retained a pending admission")
    if payload["retained_owners"] != 0:
        raise LegacyAcceptanceError("legacy join evidence retained an owned mount")
    if payload["cleanup_failures"] != 0:
        raise LegacyAcceptanceError("legacy join evidence reported a cleanup failure")
    if expected_workspace_hash not in workspaces:
        raise LegacyAcceptanceError("legacy join evidence did not name the HTTP-created workspace")
    return {
        "schema": EVIDENCE_SCHEMA,
        "mount_namespace": namespace,
        "joined_mounts": joined,
        "joined_workspaces": len(workspaces),
        "workspace_hashes": list(workspaces),
        "pending_admissions": 0,
        "retained_owners": 0,
        "cleanup_failures": 0,
    }


def read_workspace_file(harness, workspace_id: str, path: str) -> bytes:
    value = json.loads(
        harness.expect(f"/api/workspaces/{workspace_id}/files?path={path}", 200, token=harness.alice)
    )
    try:
        return base64.b64decode(value["content_base64"], validate=True)
    except (KeyError, ValueError):
        raise LegacyAcceptanceError("workspace file response did not carry valid base64") from None


def write_workspace_file(harness, workspace_id: str, path: str, data: bytes, idempotency_key: str) -> None:
    state = workspace_state(harness, workspace_id)
    body = {
        "content_base64": base64.b64encode(data).decode(),
        "expected_entry_version": 0,
        "expected_workspace_revision": state["revision"],
        "lease_epoch": state["lease_epoch"],
    }
    status, _, _ = harness.http(
        f"/api/workspaces/{workspace_id}/files?path={path}",
        token=harness.alice,
        method="PUT",
        body=body,
        extra_headers={"Idempotency-Key": idempotency_key},
    )
    if status != 200:
        raise LegacyAcceptanceError(f"workspace write returned {status}, not 200")


def bind_owned_conflict(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", int(port)))
    sock.listen(1)
    return sock


def close_conflict(sock) -> None:
    if sock is not None:
        try:
            sock.close()
        finally:
            pass
