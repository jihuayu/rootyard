#!/usr/bin/env python3
"""Owned holder and exact mount ownership proof for legacy shutdown cases.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It pins the independent namespace holder to the exact ``Popen`` process the case
started, proves that holder's mount namespace equals the service's mount
namespace, rechecks the same PID/starttime after the service exits, and records
only safe numeric identities plus exact observed mount IDs. It never selects a
process by name, path, or environment and never signals a foreign process.
"""
from __future__ import annotations

import os

from tests import fuse_helper_native_support as support
from tests.workspace_legacy_fuse_shutdown_support import (
    LegacyAcceptanceError,
    mount_namespace_inode,
)


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
    service_pid, service_pgid = owned_service_group(service_proc)
    service_namespace = _positive_int(
        mount_namespace_inode(service_pid), "service mount namespace"
    )
    holder_namespace = _positive_int(
        mount_namespace_inode(pid), "holder mount namespace"
    )
    if holder_namespace != service_namespace:
        raise LegacyAcceptanceError("namespace holder mount namespace does not match the service")
    return {
        "service_pid": service_pid,
        "service_pgid": service_pgid,
        "holder_pid": pid,
        "holder_starttime": starttime,
        "holder_mount_namespace": holder_namespace,
        "service_namespace": service_namespace,
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
