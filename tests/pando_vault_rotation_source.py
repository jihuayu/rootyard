#!/usr/bin/env python3
"""Bounded source/receipt binding reads for the Vault rotation harness.

Both the initial input validation and the before/after binding snapshots run
the unchanged ``native_build_receipt`` Git/receipt semantics in one promptly
owned child.  No unbounded global Git call is made in the harness process while
owned Docker/PG/root/server resources exist.  The child inherits the shared
absolute deadline; a timeout, late return, oversized output or malformed payload
fails with one fixed code and never forwards raw child text.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

from pando_vault_rotation_budget import DEADLINE_CODES
from pando_vault_rotation_support import QualificationError, require

CHILD_SCRIPT = Path(__file__).with_name("pando_vault_rotation_source_child.py")
MAX_BINDING_BYTES = 64 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
FIELDS = (
    "source_commit",
    "source_tree",
    "source_clean",
    "binary_sha256",
    "receipt_sha256",
)


def _unavailable():
    return QualificationError("binding_unavailable", "binding")


def _invoke(runner, budget, mode, argv, stage):
    timeout = budget.remaining()
    if timeout <= 0:
        budget.require(stage)
    try:
        result = runner.run(
            [sys.executable, str(CHILD_SCRIPT), mode, *argv],
            timeout=timeout,
            stage=stage,
        )
    except QualificationError as error:
        if error.code in DEADLINE_CODES:
            raise
        raise _unavailable() from None
    except Exception:
        raise _unavailable() from None
    if result.returncode != 0:
        raise _unavailable()
    raw = result.stdout[:MAX_BINDING_BYTES + 1]
    if len(raw) > MAX_BINDING_BYTES:
        raise _unavailable()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise _unavailable() from None
    if not isinstance(payload, dict):
        raise _unavailable()
    if payload.get("ok") is not True:
        code = payload.get("code")
        if not isinstance(code, str) or CODE_RE.fullmatch(code) is None:
            raise _unavailable()
        raise QualificationError(code, "binding")
    if set(payload) != {"ok", "code", "stage", *FIELDS}:
        raise _unavailable()
    if payload.get("code") is not None or payload.get("stage") != "binding":
        raise _unavailable()
    source_commit = payload.get("source_commit")
    source_tree = payload.get("source_tree")
    if (not isinstance(source_commit, str)
            or SHA_RE.fullmatch(source_commit) is None
            or not isinstance(source_tree, str)
            or SHA_RE.fullmatch(source_tree) is None
            or payload.get("source_clean") is not True):
        raise _unavailable()
    for name in ("binary_sha256", "receipt_sha256"):
        value = payload.get(name)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise _unavailable()
    return {name: payload[name] for name in FIELDS}


def validate(runner, budget, *, source_root, expected_commit, binary, receipt,
             expected_binary_sha256=None):
    """Validate clean source, receipt and the exact Pando v2 bin artifact."""
    payload = _invoke(
        runner,
        budget,
        "validate",
        [
            str(source_root),
            str(expected_commit),
            str(binary),
            str(receipt),
            expected_binary_sha256 or "-",
        ],
        "binding",
    )
    require(payload["source_commit"] == expected_commit,
            "expected_commit_mismatch", "binding")
    return payload


def snapshot(runner, budget, inputs):
    """Re-read every bound identity in one bounded child."""
    payload = _invoke(
        runner,
        budget,
        "snapshot",
        [
            str(inputs["source_root"]),
            str(inputs["source_commit"]),
            str(inputs["source_tree"]),
            str(inputs["binary"]),
            str(inputs["binary_sha256"]),
            str(inputs["receipt"]),
            str(inputs["receipt_sha256"]),
        ],
        "binding",
    )
    require(payload["source_commit"] == inputs["source_commit"]
            and payload["source_tree"] == inputs["source_tree"],
            "source_binding_changed", "binding")
    require(payload["binary_sha256"] == inputs["binary_sha256"],
            "binary_binding_changed", "binding")
    require(payload["receipt_sha256"] == inputs["receipt_sha256"],
            "receipt_binding_changed", "binding")
    return payload
