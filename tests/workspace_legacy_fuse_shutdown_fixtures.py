#!/usr/bin/env python3
"""HTTP/API fixture helpers for the legacy FUSE shutdown acceptance cases.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It creates and reads workspaces through the real HTTP API and owns only the
conflict listener it binds. It contains no SQL-ready fixture, mock Git, fake
mount, public fault endpoint, or environment backdoor.
"""
from __future__ import annotations

import base64
import json
import socket

from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError


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


def read_workspace_file(harness, workspace_id: str, path: str) -> bytes:
    value = json.loads(
        harness.expect(f"/api/workspaces/{workspace_id}/files?path={path}", 200, token=harness.alice)
    )
    try:
        return base64.b64decode(value["content_base64"], validate=True)
    except (KeyError, ValueError):
        raise LegacyAcceptanceError("workspace file response did not carry valid base64") from None


def write_workspace_file(
    harness, workspace_id: str, path: str, data: bytes, idempotency_key: str
) -> None:
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
