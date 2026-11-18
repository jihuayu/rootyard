#!/usr/bin/env python3
"""HTTP/API fixture helpers for the legacy FUSE shutdown acceptance cases.

This private module is owned by ``tests/workspace_legacy_fuse_shutdown_acceptance.py``.
It creates and reads workspaces through the real HTTP API and owns only the
conflict listener it binds. The optional bind gate is compiled from
``tests/fixtures/api_bind_gate.c`` and preloaded only into the fixture-owned
service child; the optional metadata gate is compiled from
``tests/fixtures/legacy_stat_gate.c`` and preloaded only into its failure-run
service child. Both are inert without that child's private environment. This
module contains no SQL-ready fixture, mock Git, fake mount, public fault
endpoint, or production environment backdoor.
"""
from __future__ import annotations

import base64
import errno
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import time

from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError

API_BIND_GATE_SCHEMA = "rootyard/issues91-95/api-bind-gate/v1"
API_BIND_GATE_VERSION = 1
API_BIND_GATE_ENV_NAMES = (
    "LD_PRELOAD",
    "ROOTYARD_TEST_BIND_GATE",
    "ROOTYARD_TEST_BIND_GATE_ADDR",
)
API_BIND_GATE_HOLD_SECONDS = 30.0
API_BIND_GATE_OUTCOME_SECONDS = 10.0
_API_BIND_GATE_OUTCOME_FIELDS = frozenset((
    "schema", "version", "events", "held", "timed_out", "duplicate",
    "abi_verified", "bind_result", "bind_errno",
))
_API_BIND_GATE_FAILURES = ("duplicate", "abi", "timeout")

STAT_GATE_SCHEMA = "rootyard/issues91-95/legacy-stat-gate/v1"
STAT_GATE_VERSION = 1
STAT_GATE_ENV_NAMES = (
    "LD_PRELOAD",
    "ROOTYARD_TEST_STAT_GATE",
    "ROOTYARD_TEST_STAT_GATE_TARGET",
    "ROOTYARD_TEST_STAT_GATE_EXE",
)
STAT_GATE_HOLD_SECONDS = 30.0
STAT_GATE_OUTCOME_SECONDS = 10.0
_STAT_GATE_OUTCOME_FIELDS = frozenset((
    "schema", "version", "events", "held", "timed_out", "duplicate",
    "abi_verified", "scope_verified", "lookup", "struct_size", "result",
    "errno", "mode", "is_regular", "is_directory",
))
_STAT_GATE_FAILURES = ("duplicate", "abi", "scope", "timeout")
_STAT_GATE_LOOKUPS = frozenset((
    "statx", "stat", "lstat", "fstatat", "stat64", "lstat64", "fstatat64",
))
_TESTS_DIR = Path(__file__).resolve().parent


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


def _gate_marker(gate, suffix: str) -> Path:
    return Path(f"{gate}.{suffix}")


def parse_api_bind_gate_address(value) -> str:
    """Require exactly one IPv4 loopback host:port listener address."""
    if not isinstance(value, str) or not value or ":" not in value:
        raise LegacyAcceptanceError("API bind gate address is not host:port")
    host, port_text = value.rsplit(":", 1)
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text, 10)
    except ValueError:
        raise LegacyAcceptanceError("API bind gate address is not a numeric IPv4 listener") from None
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
        raise LegacyAcceptanceError("API bind gate address is not IPv4 loopback")
    if port < 1 or port > 65535:
        raise LegacyAcceptanceError("API bind gate port is outside 1..65535")
    return f"{address}:{port}"


def _build_preload_gate(harness, source_name: str, build_name: str, library_name: str,
                        label: str, compiler=None) -> Path:
    """Compile one fixture-owned preload library into this harness's temp root."""
    if not sys.platform.startswith("linux") or not Path("/proc/self").is_dir():
        raise LegacyAcceptanceError(f"{label} requires Linux process and procfs support")
    compiler = compiler or shutil.which("gcc")
    if compiler is None:
        raise LegacyAcceptanceError(f"{label} requires gcc on PATH")
    source = _TESTS_DIR / "fixtures" / source_name
    if not source.is_file():
        raise LegacyAcceptanceError(f"{label} fixture is missing: {source}")
    build = harness.root / build_name
    build.mkdir(parents=True, exist_ok=True)
    library = build / library_name
    build_env = dict(harness.env)
    for name in set(API_BIND_GATE_ENV_NAMES) | set(STAT_GATE_ENV_NAMES):
        build_env.pop(name, None)
    harness.run(
        [compiler, "-shared", "-fPIC", "-O2", "-pthread", "-o", str(library), str(source), "-ldl"],
        env=build_env,
    )
    if not library.is_file():
        raise LegacyAcceptanceError(f"{label} did not produce {library}")
    return library


def _snapshot_gate_env(harness, names) -> dict:
    return {name: harness.env.get(name) for name in names}


def _restore_gate_env(harness, prior, names) -> None:
    for name in names:
        value = prior.get(name)
        if value is None:
            harness.env.pop(name, None)
        else:
            harness.env[name] = value


def install_api_bind_gate(harness, compiler=None):
    """Compile the single-use bind gate and configure only this child.

    The library is inert unless both private gate variables are set. It is
    built in this harness's owned temp root before the service starts. Callers
    must snapshot and restore the three environment names after ``Popen`` has
    copied them, so no later fixture child inherits the preload.
    """
    address = parse_api_bind_gate_address(harness.env.get("ROOTYARD_BIND"))
    library = _build_preload_gate(
        harness, "api_bind_gate.c", "legacy-api-bind-gate", "api_bind_gate.so",
        "API bind gate", compiler,
    )
    build = library.parent
    prefix = build / "gate"
    harness.env.update(
        LD_PRELOAD=str(library),
        ROOTYARD_TEST_BIND_GATE=str(prefix),
        ROOTYARD_TEST_BIND_GATE_ADDR=address,
    )
    return prefix


def snapshot_api_bind_gate_env(harness) -> dict:
    """Remember only the three private names so they can be removed after Popen."""
    return _snapshot_gate_env(harness, API_BIND_GATE_ENV_NAMES)


def restore_api_bind_gate_env(harness, prior) -> None:
    """Restore the exact pre-gate environment after the owned child was spawned."""
    _restore_gate_env(harness, prior, API_BIND_GATE_ENV_NAMES)


def install_stat_gate(harness, target, executable, compiler=None):
    """Compile the one-use metadata gate for the exact service child.

    ``target`` becomes the canonical regular-file path the real lower ``.git``
    lookup must match. ``executable`` is the canonical service binary; the
    child verifies it through ``/proc/self/exe`` and its own process-group
    scope before it can hold a matching lookup.
    """
    target = Path(target).resolve(strict=True)
    executable = Path(executable).resolve(strict=True)
    if not target.is_file() or target.is_symlink():
        raise LegacyAcceptanceError("metadata gate target is not a regular file")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise LegacyAcceptanceError("metadata gate executable is not executable")
    library = _build_preload_gate(
        harness, "legacy_stat_gate.c", "legacy-stat-gate", "legacy_stat_gate.so",
        "legacy metadata gate", compiler,
    )
    prefix = library.parent / "gate"
    harness.env.update(
        LD_PRELOAD=str(library),
        ROOTYARD_TEST_STAT_GATE=str(prefix),
        ROOTYARD_TEST_STAT_GATE_TARGET=str(target),
        ROOTYARD_TEST_STAT_GATE_EXE=str(executable),
    )
    return prefix


def snapshot_stat_gate_env(harness) -> dict:
    """Remember only the four private names so they can be removed after Popen."""
    return _snapshot_gate_env(harness, STAT_GATE_ENV_NAMES)


def restore_stat_gate_env(harness, prior) -> None:
    """Restore the exact pre-gate environment after the owned child was spawned."""
    _restore_gate_env(harness, prior, STAT_GATE_ENV_NAMES)


def _assert_no_gate_failure(gate) -> None:
    for suffix in _API_BIND_GATE_FAILURES:
        marker = _gate_marker(gate, suffix)
        if marker.exists():
            raise LegacyAcceptanceError(f"API bind gate reported {suffix}")


def wait_api_bind_gate(gate, timeout: float = API_BIND_GATE_HOLD_SECONDS) -> Path:
    """Wait for the one matching bind to be held, failing on any bad event."""
    gate = Path(gate)
    hit = _gate_marker(gate, "hit")
    deadline = time.monotonic() + float(timeout)
    while time.monotonic() < deadline:
        _assert_no_gate_failure(gate)
        if hit.exists():
            _assert_no_gate_failure(gate)
            return hit
        time.sleep(0.05)
    _assert_no_gate_failure(gate)
    raise LegacyAcceptanceError("API bind gate was not reached within the bounded setup")


def release_api_bind_gate(gate) -> Path:
    """Release the single held bind exactly once."""
    release = _gate_marker(gate, "release")
    try:
        with open(release, "xb") as stream:
            stream.write(b"release\n")
    except FileExistsError:
        raise LegacyAcceptanceError("API bind gate release already existed") from None
    except OSError as error:
        raise LegacyAcceptanceError("API bind gate release could not be written") from error
    return release


def validate_api_bind_gate_outcome(payload, expected_errno: int = errno.EADDRINUSE) -> dict:
    """Accept only the real single bind failure with its original errno."""
    if not isinstance(payload, dict):
        raise LegacyAcceptanceError("API bind gate outcome is not an object")
    if set(payload) != _API_BIND_GATE_OUTCOME_FIELDS:
        raise LegacyAcceptanceError("API bind gate outcome has an unexpected field set")
    exact = {
        "schema": API_BIND_GATE_SCHEMA,
        "version": API_BIND_GATE_VERSION,
        "events": 1,
        "held": 1,
        "timed_out": 0,
        "duplicate": 0,
        "abi_verified": 1,
    }
    for name, expected in exact.items():
        if type(payload.get(name)) is not type(expected) or payload.get(name) != expected:
            raise LegacyAcceptanceError(f"API bind gate outcome {name} is not exact")
    if type(payload["bind_result"]) is not int or payload["bind_result"] != -1:
        raise LegacyAcceptanceError("API bind gate did not observe a real bind failure")
    if type(payload["bind_errno"]) is not int or payload["bind_errno"] != int(expected_errno):
        raise LegacyAcceptanceError("API bind gate did not observe the expected real errno")
    return payload


def read_api_bind_gate_outcome(
    gate, timeout: float = API_BIND_GATE_OUTCOME_SECONDS, expected_errno: int = errno.EADDRINUSE
) -> dict:
    """Read the bounded outcome written after the real bind call returned."""
    gate = Path(gate)
    outcome = _gate_marker(gate, "outcome")
    deadline = time.monotonic() + float(timeout)
    last_error = None
    while time.monotonic() < deadline:
        if outcome.is_file():
            try:
                if outcome.stat().st_size > 4096:
                    raise LegacyAcceptanceError("API bind gate outcome exceeds the bounded size")
                payload = json.loads(outcome.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as error:
                # The gate creates the file before writing its short body; a
                # bounded retry distinguishes that transient state from a
                # permanently missing outcome.
                last_error = error
            else:
                validated = validate_api_bind_gate_outcome(payload, expected_errno)
                _assert_no_gate_failure(gate)
                return validated
        _assert_no_gate_failure(gate)
        time.sleep(0.05)
    _assert_no_gate_failure(gate)
    if last_error is not None:
        raise LegacyAcceptanceError("API bind gate outcome is unreadable") from last_error
    raise LegacyAcceptanceError("API bind gate outcome was not observed within the bound")


def _assert_no_stat_gate_failure(gate) -> None:
    for suffix in _STAT_GATE_FAILURES:
        marker = _gate_marker(gate, suffix)
        if marker.exists():
            raise LegacyAcceptanceError(f"legacy metadata gate reported {suffix}")


def wait_stat_gate(gate, timeout: float = STAT_GATE_HOLD_SECONDS) -> Path:
    """Wait for the one exact metadata lookup to be held before its result."""
    gate = Path(gate)
    hit = _gate_marker(gate, "hit")
    deadline = time.monotonic() + float(timeout)
    while time.monotonic() < deadline:
        _assert_no_stat_gate_failure(gate)
        if hit.exists():
            _assert_no_stat_gate_failure(gate)
            return hit
        time.sleep(0.05)
    _assert_no_stat_gate_failure(gate)
    raise LegacyAcceptanceError("legacy metadata gate was not reached within the bounded setup")


def release_stat_gate(gate) -> Path:
    """Release the single held metadata lookup exactly once."""
    release = _gate_marker(gate, "release")
    try:
        with open(release, "xb") as stream:
            stream.write(b"release\n")
    except FileExistsError:
        raise LegacyAcceptanceError("legacy metadata gate release already existed") from None
    except OSError as error:
        raise LegacyAcceptanceError("legacy metadata gate release could not be written") from error
    return release


def validate_stat_gate_outcome(payload) -> dict:
    """Accept only the real, successful, non-directory regular-file lookup."""
    if not isinstance(payload, dict):
        raise LegacyAcceptanceError("legacy metadata gate outcome is not an object")
    if set(payload) != _STAT_GATE_OUTCOME_FIELDS:
        raise LegacyAcceptanceError("legacy metadata gate outcome has an unexpected field set")
    exact = {
        "schema": STAT_GATE_SCHEMA,
        "version": STAT_GATE_VERSION,
        "events": 1,
        "held": 1,
        "timed_out": 0,
        "duplicate": 0,
        "abi_verified": 1,
        "scope_verified": 1,
        "is_regular": 1,
        "is_directory": 0,
    }
    for name, expected in exact.items():
        if type(payload.get(name)) is not type(expected) or payload.get(name) != expected:
            raise LegacyAcceptanceError(f"legacy metadata gate outcome {name} is not exact")
    lookup = payload.get("lookup")
    if not isinstance(lookup, str) or lookup not in _STAT_GATE_LOOKUPS:
        raise LegacyAcceptanceError("legacy metadata gate lookup ABI is not verified")
    for name in ("struct_size", "result", "errno", "mode"):
        if type(payload.get(name)) is not int:
            raise LegacyAcceptanceError(f"legacy metadata gate outcome {name} is not an integer")
    if payload["struct_size"] < 1:
        raise LegacyAcceptanceError("legacy metadata gate struct size is not positive")
    if payload["result"] != 0:
        raise LegacyAcceptanceError("legacy metadata gate did not retain a successful real result")
    if payload["errno"] < 0:
        raise LegacyAcceptanceError("legacy metadata gate errno is not a real errno")
    mode = payload["mode"]
    if mode < 0 or not stat.S_ISREG(mode) or stat.S_ISDIR(mode):
        raise LegacyAcceptanceError("legacy metadata gate did not observe regular-file metadata")
    return payload


def read_stat_gate_outcome(
    gate, timeout: float = STAT_GATE_OUTCOME_SECONDS
) -> dict:
    """Read the bounded outcome written only after the real metadata returned."""
    gate = Path(gate)
    outcome = _gate_marker(gate, "outcome")
    deadline = time.monotonic() + float(timeout)
    last_error = None
    while time.monotonic() < deadline:
        if outcome.is_file():
            try:
                if outcome.stat().st_size > 4096:
                    raise LegacyAcceptanceError("legacy metadata gate outcome exceeds the bounded size")
                payload = json.loads(outcome.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as error:
                last_error = error
            else:
                validated = validate_stat_gate_outcome(payload)
                _assert_no_stat_gate_failure(gate)
                return validated
        _assert_no_stat_gate_failure(gate)
        time.sleep(0.05)
    _assert_no_stat_gate_failure(gate)
    if last_error is not None:
        raise LegacyAcceptanceError("legacy metadata gate outcome is unreadable") from last_error
    raise LegacyAcceptanceError("legacy metadata gate outcome was not observed within the bound")
