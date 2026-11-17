"""Bounded child adapter for the complete canonical source capture.

The canonical in-process semantics remain in :mod:`pando_producer_pg.source`.
This adapter runs that unchanged capture inside one promptly owned, output-capped
and actually reaped child with an explicit source-root cwd.  It refuses to enter
the final 2-second reap window, validates the fixed binding shape, preserves
registered fixed failures and never forwards raw child text.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import sys
import time

from .errors import CODES, STAGES, RunnerError, require
from .process import ProcessRunner
from .source import SHA_RE, SHA256_RE, SOURCE_CAPTURE_CHILD_REL

CHILD_SCRIPT = Path(__file__).with_name("source_capture_child.py")
MAX_BINDING_BYTES = 1024 * 1024
CAPTURE_REAP_RESERVE_SECONDS = 2.0
BINDING_KEYS = (
    "source_commit",
    "source_tree",
    "source_clean",
    "expected_commit",
    "expected_tree",
    "source_inputs_sha256",
    "bound_inputs_sha256",
    "bound_inputs_present_count",
    "bound_inputs_absent_count",
    "cargo_lock_sha256",
    "config_digest",
    "schema_sha256",
    "input_hashes",
    "runner_source_hashes",
)


def _binding_rows(raw_rows, allowed_paths, require_helper):
    require(isinstance(raw_rows, list) and bool(raw_rows), "source", "source_capture_failed")
    rows = []
    seen = {}
    for row in raw_rows:
        require(isinstance(row, dict), "source", "source_capture_failed")
        path = row.get("path")
        digest = row.get("sha256")
        require(
            isinstance(path, str)
            and bool(path)
            and not Path(path).is_absolute()
            and "\\" not in path,
            "source",
            "source_capture_failed",
        )
        parts = path.split("/")
        require(
            all(part not in ("", ".", "..") for part in parts),
            "source",
            "source_capture_failed",
        )
        require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            "source",
            "source_capture_failed",
        )
        require(path not in seen, "source", "source_capture_failed")
        seen[path] = digest
        rows.append({"path": path, "sha256": digest})
    if allowed_paths is not None:
        require(set(seen) <= allowed_paths, "source", "source_capture_failed")
    if require_helper:
        require(
            SOURCE_CAPTURE_CHILD_REL in seen,
            "source",
            "source_capture_failed",
        )
    return rows, seen


def _validated_binding(binding, expected_commit, expected_tree):
    require(isinstance(binding, dict), "source", "source_capture_failed")
    for key in BINDING_KEYS:
        require(key in binding, "source", "source_capture_failed")
    require(
        binding["source_commit"] == expected_commit
        and SHA_RE.fullmatch(str(binding["source_commit"])) is not None,
        "source",
        "source_capture_failed",
    )
    require(
        SHA_RE.fullmatch(str(binding["source_tree"])) is not None,
        "source",
        "source_capture_failed",
    )
    require(binding["source_clean"] is True, "source", "source_capture_failed")
    if expected_tree is not None:
        require(
            binding["source_tree"] == expected_tree,
            "source",
            "source_capture_failed",
        )
    require(
        binding["expected_commit"] == expected_commit,
        "source",
        "source_capture_failed",
    )
    require(
        binding["expected_tree"]
        == (expected_tree or binding["source_tree"]),
        "source",
        "source_capture_failed",
    )
    for key in (
        "source_inputs_sha256",
        "bound_inputs_sha256",
        "cargo_lock_sha256",
        "config_digest",
        "schema_sha256",
    ):
        require(
            isinstance(binding[key], str)
            and SHA256_RE.fullmatch(binding[key]) is not None,
            "source",
            "source_capture_failed",
        )
    for key in ("bound_inputs_present_count", "bound_inputs_absent_count"):
        require(
            type(binding[key]) is int and binding[key] >= 0,
            "source",
            "source_capture_failed",
        )
    rows, seen = _binding_rows(
        binding["input_hashes"], allowed_paths=None, require_helper=True
    )
    runner_rows, _ = _binding_rows(
        binding["runner_source_hashes"],
        allowed_paths=set(seen),
        require_helper=False,
    )
    clean = {key: binding[key] for key in BINDING_KEYS}
    clean["input_hashes"] = rows
    clean["runner_source_hashes"] = runner_rows
    return clean


def capture_bounded(
    source_root,
    expected_commit,
    *,
    expected_tree=None,
    environ=None,
    deadline=None,
    clock=time.monotonic,
    process_runner=None,
):
    """Run the complete canonical capture in one bounded, reaped child."""
    root = Path(source_root).resolve()
    require(root.is_dir(), "source", "source_root_missing")
    require(
        isinstance(expected_commit, str)
        and SHA_RE.fullmatch(expected_commit) is not None,
        "input",
        "missing_expected_commit",
    )
    if expected_tree is not None:
        require(
            isinstance(expected_tree, str)
            and SHA_RE.fullmatch(expected_tree) is not None,
            "input",
            "invalid_arguments",
        )
    require(
        isinstance(deadline, (int, float))
        and not isinstance(deadline, bool)
        and math.isfinite(deadline),
        "input",
        "invalid_arguments",
    )
    remaining = float(deadline) - clock()
    if remaining <= CAPTURE_REAP_RESERVE_SECONDS:
        raise RunnerError("source", "source_capture_deadline_exceeded")
    environment = dict(os.environ if environ is None else environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    runner = process_runner or ProcessRunner(clock=clock)
    try:
        completed = runner.run(
            [
                sys.executable,
                str(CHILD_SCRIPT),
                str(root),
                expected_commit,
                expected_tree or "-",
            ],
            cwd=str(root),
            env=environment,
            timeout=remaining - CAPTURE_REAP_RESERVE_SECONDS,
            stage="source",
            timeout_code="source_capture_deadline_exceeded",
            spawn_code="source_capture_failed",
            max_stdout=MAX_BINDING_BYTES,
            max_stderr=MAX_BINDING_BYTES,
            max_total=MAX_BINDING_BYTES,
            fail_on_output_exceeded=True,
            output_code="source_capture_failed",
        )
    except RunnerError:
        raise
    except Exception:
        raise RunnerError("source", "source_capture_failed") from None
    raw = getattr(completed, "stdout", b"") or b""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_BINDING_BYTES:
        raise RunnerError("source", "source_capture_failed")
    if getattr(completed, "returncode", None) != 0:
        raise RunnerError("source", "source_capture_failed")
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        raise RunnerError("source", "source_capture_failed") from None
    if not isinstance(payload, dict) or type(payload.get("ok")) is not bool:
        raise RunnerError("source", "source_capture_failed")
    if payload["ok"] is not True:
        stage = payload.get("stage")
        code = payload.get("code")
        if stage in STAGES and code in CODES:
            raise RunnerError(stage, code)
        raise RunnerError("source", "source_capture_failed")
    return _validated_binding(
        payload.get("binding"), expected_commit, expected_tree
    )
