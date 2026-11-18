#!/usr/bin/env python3
"""Task-owned pinned HashiCorp Vault Transit fixture for issue #21 rotation.

One fixture owns exactly one nonce-labelled Vault dev container with the pinned
image digest.  The root token and the restricted application token live only in
this Python process's memory and in child process environments / HTTP headers.
The Docker argv uses ``-e NAME`` (never ``-e NAME=value``), and no token, Vault
request body, response body, credential file, container log or raw subprocess
output is written to a report or stdout.

The admin side creates a derived ``aes256-gcm96`` Transit key, keeps the
decryption floor at version 1 and is the only caller of master-key rotate.
The application policy can read the named key and wrap/unwrap/rewrap with that
key; it cannot rotate, delete, change config, administer policies or create
tokens.  New writes are pinned through the product's rotation checkpoint, not
by this fixture.

This module starts nothing unless a caller explicitly invokes it.  The pure
contract tests use injected runners only; no Docker daemon, Vault, HTTP server
or credential is needed at import time.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request

VAULT_IMAGE = (
    "hashicorp/vault@sha256:"
    "dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6"
)
VAULT_VERSION = "2.2.2"
VAULT_KIND = "owned-pando-vault-rotation"
VAULT_GOAL = "issue21"
OWNERSHIP_SCHEMA = "rootyard/issue21-pando-vault-rotation-ownership/v1"
PROVIDER_SCHEMA = "rootyard/issue21-pando-vault-rotation-provider/v1"
CONTAINER_PREFIX = "rootyard-pando-vault-rotation-"
NONCE_RE = re.compile(r"^[0-9a-f]{12}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 256 * 1024
PULL_TIMEOUT = 300
HEALTH_TIMEOUT = 45
APP_ACTIONS = ("encrypt", "decrypt", "rewrap")


class FixtureError(RuntimeError):
    """A fixed, report-safe fixture failure code."""

    def __init__(self, code, stage=None):
        self.code = code
        self.stage = stage
        super().__init__(code)


def _require(condition, code, stage=None):
    if not condition:
        raise FixtureError(code, stage)


def expected_container_name(nonce):
    return CONTAINER_PREFIX + nonce


def service_policy(key_name):
    """Least privilege for the application: no rotate/delete/config/admin."""
    _require(bool(key_name) and "\n" not in key_name and '"' not in key_name,
             "vault_key_name_invalid")
    lines = ['path "transit/keys/%s" { capabilities = ["read"] }' % key_name]
    for action in APP_ACTIONS:
        lines.append(
            'path "transit/%s/%s" { capabilities = ["update"] }' % (action, key_name)
        )
    return "\n".join(lines) + "\n"


def _validate_state(state):
    if not isinstance(state, dict):
        raise FixtureError("vault_state_invalid")
    if state.get("schema") != OWNERSHIP_SCHEMA:
        raise FixtureError("vault_state_schema_invalid")
    if state.get("kind") != VAULT_KIND or state.get("goal") != VAULT_GOAL:
        raise FixtureError("vault_state_kind_mismatch")
    nonce = state.get("nonce")
    if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
        raise FixtureError("vault_state_nonce_invalid")
    if state.get("uid") != os.getuid():
        raise FixtureError("vault_state_uid_mismatch")
    if state.get("container_name") != expected_container_name(nonce):
        raise FixtureError("vault_state_name_mismatch")
    if state.get("image") != VAULT_IMAGE:
        raise FixtureError("vault_state_image_mismatch")
    phase = state.get("phase")
    container_id = state.get("container_id")
    if phase not in ("intent", "created"):
        raise FixtureError("vault_state_phase_invalid")
    if phase == "intent" and container_id is not None:
        raise FixtureError("vault_state_container_invalid")
    if phase == "created" and (
        not isinstance(container_id, str)
        or CONTAINER_ID_RE.fullmatch(container_id) is None
    ):
        raise FixtureError("vault_state_container_invalid")
    return dict(state)


def _inspect_owned(runner, state, container_id, prefix):
    id_result = runner.run([
        "docker", "inspect", "--type", "container", "--format", "{{.Id}}",
        container_id,
    ])
    if id_result.returncode != 0:
        raise FixtureError(prefix + "_unverified")
    if id_result.stdout.decode(errors="replace").strip() != container_id:
        raise FixtureError(prefix + "_id_mismatch")
    image = runner.run([
        "docker", "inspect", "--type", "container",
        "--format", "{{.Config.Image}}", container_id,
    ])
    if image.returncode != 0:
        raise FixtureError(prefix + "_unverified")
    if image.stdout.decode(errors="replace").strip() != state["image"]:
        raise FixtureError(prefix + "_image_mismatch")
    labels = runner.run([
        "docker", "inspect", "--type", "container",
        "--format", "{{json .Config.Labels}}", container_id,
    ])
    if labels.returncode != 0:
        raise FixtureError(prefix + "_labels_unreadable")
    try:
        values = json.loads(labels.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FixtureError(prefix + "_labels_invalid") from None
    expected = {
        "rootyard.fixture.kind": state["kind"],
        "rootyard.fixture.nonce": state["nonce"],
        "rootyard.fixture.goal": state["goal"],
        "rootyard.fixture.uid": str(state["uid"]),
    }
    if not isinstance(values, dict) or any(
        values.get(key) != value for key, value in expected.items()
    ):
        raise FixtureError(prefix + "_label_mismatch")
    return container_id


def _find_owned_by_name(runner, state, prefix):
    state = _validate_state(state)
    name = state["container_name"]
    result = runner.run([
        "docker", "ps", "-a", "--no-trunc",
        "--filter", "name=^/" + name + "$",
        "--format", "{{.ID}}\t{{.Names}}",
    ])
    if result.returncode != 0:
        raise FixtureError(prefix + "_name_query_failed")
    rows = []
    for line in result.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" not in line:
            raise FixtureError(prefix + "_name_query_invalid")
        container_id, actual_name = line.split("\t", 1)
        if actual_name != name or CONTAINER_ID_RE.fullmatch(container_id) is None:
            raise FixtureError(prefix + "_name_ambiguous")
        rows.append(container_id)
    if not rows:
        return None
    if len(rows) != 1:
        raise FixtureError(prefix + "_name_ambiguous")
    return _inspect_owned(runner, state, rows[0], prefix)


def _resolve_owned(runner, state, prefix):
    state = _validate_state(state)
    recorded = state.get("container_id")
    if recorded:
        try:
            return _inspect_owned(runner, state, recorded, prefix)
        except FixtureError as error:
            if error.code != prefix + "_unverified":
                raise
    found = _find_owned_by_name(runner, state, prefix)
    if found is None:
        return None
    if recorded and found != recorded:
        raise FixtureError(prefix + "_id_mismatch")
    return found


def published_loopback_url(lines):
    """Accept only the exact requested IPv4 loopback publication."""
    if not lines:
        raise FixtureError("vault_port_invalid")
    published = lines[0].strip()
    if ":" not in published:
        raise FixtureError("vault_port_invalid")
    host, port = published.rsplit(":", 1)
    if host.strip() != "127.0.0.1":
        raise FixtureError("vault_port_not_loopback")
    if not port.isdigit() or not 1 <= int(port, 10) <= 65535:
        raise FixtureError("vault_port_invalid")
    return "http://127.0.0.1:" + str(int(port, 10))


class ProcessRunner:
    """Bounded process wrapper.  Output stays in RAM and is never persisted."""

    def __init__(self, timeout=60):
        self.timeout = timeout

    def run(self, argv, env=None, input=None, timeout=None):
        try:
            return subprocess.run(
                argv,
                env=env,
                input=input,
                stdin=subprocess.DEVNULL if input is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout if timeout is None else timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise FixtureError("process_failed") from None


DockerRunner = ProcessRunner


def remove_owned_container(runner, state):
    state = _validate_state(state)
    container_id = _resolve_owned(runner, state, "vault_cleanup")
    if container_id is None:
        return "absent"
    remove = runner.run(["docker", "rm", "-f", "--", container_id])
    if remove.returncode != 0:
        raise FixtureError("vault_cleanup_failed")
    return "stopped"


def cleanup_owned_state(state_path, runner=None):
    path = Path(state_path)
    if not path.exists():
        return 0
    try:
        state = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise FixtureError("vault_state_invalid") from None
    remove_owned_container(runner or DockerRunner(), state)
    path.unlink()
    return 0
