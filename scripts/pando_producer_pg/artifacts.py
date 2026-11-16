"""Select one real target/test-profile bin executable from Cargo JSON.

The selection command is the existing all-targets cache path.  It compiles no
new Rust target and does not consult newest-file globs, the normal CLI path or
a library/integration artifact.  Exactly one ``compiler-artifact`` named
``rootyard-pando-lab`` with a ``bin`` kind, ``profile.test=true`` and an
executable, plus exactly one successful ``build-finished`` event, is accepted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from .errors import RunnerError, require

TARGET = "rootyard-pando-lab"
FEATURES = ("pando-lab",)
CARGO_COMMAND = (
    "cargo",
    "test",
    "--locked",
    "--features",
    "pando-lab",
    "--bin",
    TARGET,
    "--no-run",
    "--message-format=json",
)
EXPECTED_SOURCE = "src/bin/rootyard-pando-lab.rs"


def _sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _events(raw):
    text = raw.decode("utf-8", errors="replace")
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            raise RunnerError("selection", "cargo_output_invalid") from None
        require(isinstance(event, dict), "selection", "cargo_output_invalid")
        events.append(event)
    return events


def _snapshot(path, stage, code):
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            raise RunnerError(stage, code)
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(candidate, os.X_OK):
            raise RunnerError(stage, code)
        digest = _sha256_file(candidate)
    except RunnerError:
        raise
    except (OSError, ValueError):
        raise RunnerError(stage, code) from None
    return {
        "executable_name": candidate.name,
        "sha256": digest,
        "size": info.st_size,
        "st_dev": info.st_dev,
        "st_ino": info.st_ino,
        "mtime_ns": info.st_mtime_ns,
    }


def select_test_binary(source_root, runner, timeout):
    """Run the single bounded Cargo selection and return safe metadata."""
    root = Path(source_root).resolve()
    result = runner.run(
        list(CARGO_COMMAND),
        timeout=timeout,
        stage="selection",
        timeout_code="cargo_timeout",
        spawn_code="cargo_failed",
    )
    require(result.returncode == 0, "selection", "cargo_failed")
    events = _events(result.stdout)
    finished = [
        event for event in events if event.get("reason") == "build-finished"
    ]
    require(len(finished) == 1, "selection", "build_not_finished")
    require(finished[0].get("success") is True, "selection", "build_failed")
    candidates = [
        event
        for event in events
        if event.get("reason") == "compiler-artifact"
        and isinstance(event.get("target"), dict)
        and event["target"].get("name") == TARGET
    ]
    require(bool(candidates), "selection", "artifact_missing")
    require(len(candidates) == 1, "selection", "artifact_ambiguous")
    event = candidates[0]
    target = event["target"]
    kinds = target.get("kind")
    require(isinstance(kinds, list) and "bin" in kinds, "selection", "artifact_kind")
    profile = event.get("profile")
    require(
        isinstance(profile, dict) and profile.get("test") is True,
        "selection",
        "artifact_profile",
    )
    fresh = event.get("fresh")
    require(type(fresh) is bool, "selection", "artifact_fresh_invalid")
    executable = event.get("executable")
    require(
        isinstance(executable, str) and bool(executable),
        "selection",
        "artifact_executable",
    )
    path = Path(executable)
    require(path.is_absolute(), "selection", "artifact_executable")
    require(path.parent.name == "deps", "selection", "artifact_executable")
    require(path.name != TARGET, "selection", "artifact_executable")
    snapshot = _snapshot(path, "selection", "artifact_executable")
    source = None
    source_path = target.get("src_path")
    if isinstance(source_path, str) and source_path:
        candidate = Path(source_path)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            raise RunnerError("selection", "artifact_source_missing") from None
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            raise RunnerError("selection", "artifact_source_outside") from None
        require(resolved.is_file(), "selection", "artifact_source_missing")
        source = relative
    require(source == EXPECTED_SOURCE, "selection", "artifact_source_missing")
    return {
        "target": TARGET,
        "kind": list(kinds),
        "profile": {"test": True},
        "features": list(FEATURES),
        "command": list(CARGO_COMMAND),
        "fresh": fresh,
        "source": source,
        "executable_path": str(path),
        "executable_sha256": snapshot["sha256"],
        "executable": snapshot,
    }


def verify_selected_binary(selection, path=None):
    """Re-hash and re-stat the selected executable, retaining the first hash."""
    executable = path or selection.get("executable_path")
    require(bool(executable), "binding", "binary_unreadable")
    current = _snapshot(executable, "binding", "binary_unreadable")
    trusted = selection.get("executable")
    require(isinstance(trusted, dict), "binding", "binary_unreadable")
    for key in ("sha256", "size", "st_dev", "st_ino", "mtime_ns"):
        require(current[key] == trusted.get(key), "binding", "binary_changed")
    return current
