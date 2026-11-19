#!/usr/bin/env python3
"""Failure-only external observer for the S4 Git View reverse-import path.

The observer runs the exact integration-test executable under non-interactive
GDB with one breakpoint at the unsuccessful-child-exit return in
``run_git_bounded``. It never reads target arguments, locals, memory strings,
stdout/stderr or a raw stack. A GDB Python extension walks a bounded DWARF frame
prefix, keeps only physical repo-relative source locators, and writes them to a
private result file. This module maps those locators through a statically
verified table into a closed operation enum.

A real run needs Linux GDB with Python support and an unstripped test executable.
The local test suite exercises syntax, the pure mapper, strict result parsing and
the process plumbing with a fake GDB; it does not need GDB, PostgreSQL, S3 or a
network listener.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
GDB_SCRIPT = Path(__file__).with_name("s4_git_exit_gdb.py")
GDB_PREFLIGHT = Path(__file__).with_name("s4_git_exit_preflight.gdb")

BREAK_FILE = "src/namespace_service/s4_git_proc.rs"
BREAK_LINE = 359
BREAK_NEEDLE = "return Err(fail_error)"

TEST_FILE = "tests/s4_ci_pins_git_view.rs"
HARNESS_FILE = "tests/s4_ci_pins_git_view_support/harness.rs"
RUNNER_FILE = "src/namespace_service/s4_git_proc.rs"
REVERSE_FILE = "src/namespace_service/s4_git_view_reverse.rs"

TARGET_CASE = "s4_git_view_bundle_is_projected_only_and_reverse_merges_the_subtree"
TARGET_OBJECT_FORMAT = "sha1"
TARGET_CASE_MARKER = 'create_repository("view-repo", "sha1")'
REVERSE_PHASE_FILES = (
    "src/namespace_service/s4_git_view_reverse.rs",
    "src/namespace_service/s4_git_proc_reverse.rs",
)

RESULT_SCHEMA = "s4-git-exit-diagnostic-v1"
RESULT_HEADER = "s4git-result 1"
MAX_FRAMES = 12
MAX_RESULT_BYTES = 8192
MAX_RESULT_LINES = 48
MAX_REPORT_BYTES = 16384
STOP_GRACE_SECONDS = 2

NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
GIT_VERSION_PATTERN = re.compile(r"^git version (\d+)\.(\d+)\.(\d+)", re.MULTILINE)
CASE_PATTERN = re.compile(
    r"#\[tokio::test\]\s*\n#\[ignore[^\]]*\]\s*\nasync fn ([a-z0-9_]+)\(",
    re.MULTILINE,
)

class Operation(str, Enum):
    """Closed enum for the observed reverse-import Git caller."""

    PROPOSAL_FETCH = "proposal_fetch"
    PROPOSAL_BUNDLE_VERIFY = "proposal_bundle_verify"
    PROPOSAL_MERGE_BASE = "proposal_merge_base"
    PROPOSAL_FSCK = "proposal_fsck"
    SOURCE_PROJECTION = "source_projection"
    SOURCE_FETCH = "source_fetch"
    SOURCE_TREE_LISTING = "source_tree_listing"
    ROOT_MKTREE = "root_mktree"
    COMMIT_SYNTHESIS = "commit_synthesis"
    PACK_INDEX = "pack_index"


class Status(str, Enum):
    CLASSIFIED_FAILURE = "classified_failure"
    OBSERVER_MISMATCH = "observer_mismatch"
    UNRESOLVED_FAILURE = "unresolved_failure"
    NO_FAILURE_OBSERVED = "no_failure_observed"
    UNSUPPORTED = "unsupported"


class Reason(str, Enum):
    CLASSIFIED = "classified"
    NO_KNOWN_CALLER_FRAME = "no_known_caller_frame"
    NO_FAILURE_MARKER = "no_failure_marker"
    BREAKPOINT_UNRESOLVED = "breakpoint_unresolved"
    GDB_UNAVAILABLE = "gdb_unavailable"
    WORKDIR_UNAVAILABLE = "workdir_unavailable"
    RESULT_MISSING = "result_missing"
    RESULT_INVALID = "result_invalid"
    RUN_TIMED_OUT = "run_timed_out"
    RUN_INTERRUPTED = "run_interrupted"
    GIT_VERSION_UNAVAILABLE = "git_version_unavailable"
    BINARY_UNAVAILABLE = "binary_unavailable"
    BINARY_CHANGED = "binary_changed"
    SOURCE_PREFLIGHT_FAILED = "source_preflight_failed"
    NONE = "none"


class RunPhase(str, Enum):
    PREFLIGHT_NOT_RUN = "preflight_not_run"
    RUN_STARTED_TARGET_NOT_RUN = "run_started_target_not_run"
    RUN_STARTED_NO_RESULT = "run_started_no_result"
    RUN_STARTED_TIMED_OUT = "run_started_timed_out"
    RUN_STARTED_INTERRUPTED = "run_started_interrupted"
    RUN_STARTED_INVALID_RESULT = "run_started_invalid_result"
    COMPLETED = "completed"


class PreflightError(RuntimeError):
    """The local source, binary or toolchain cannot support the probe."""


class MappingError(RuntimeError):
    """The closed caller table is ambiguous or stale."""


class ResultError(RuntimeError):
    """The GDB result file is missing, oversized or malformed."""


@dataclass(frozen=True)
class Site:
    file: str
    line: int
    operation: Operation
    needle: str


@dataclass(frozen=True)
class Frame:
    file: str
    line: int


@dataclass(frozen=True)
class GdbResult:
    nonce: str
    breakpoint_state: str
    breakpoint_file: str
    breakpoint_line: int
    failure: bool
    frames: tuple[Frame, ...]
    exit_code: int | None
    exit_signal: int | None
    error: str | None


# Every entry is a physical repo-relative source line whose text is checked
# before GDB is allowed to run. The innermost mapped frame wins, so nested
# helpers such as mktree classify as the root mktree operation even when an
# outer replace_tree frame is also present.
SITES: tuple[Site, ...] = (
    Site("src/namespace_service/s4_git_view_reverse.rs", 153, Operation.SOURCE_PROJECTION, "git_clone("),
    Site("src/namespace_service/s4_git_view_reverse.rs", 162, Operation.SOURCE_PROJECTION, "s4_git_view::project"),
    Site("src/namespace_service/s4_git_view_reverse.rs", 169, Operation.PROPOSAL_BUNDLE_VERIFY, '"bundle", "verify"'),
    Site("src/namespace_service/s4_git_view_reverse.rs", 170, Operation.PROPOSAL_FETCH, '"fetch", "--no-tags"'),
    Site("src/namespace_service/s4_git_view_reverse.rs", 171, Operation.PROPOSAL_FETCH, "FETCH_HEAD^{commit}"),
    Site("src/namespace_service/s4_git_view_reverse.rs", 173, Operation.PROPOSAL_MERGE_BASE, "merge_base"),
    Site("src/namespace_service/s4_git_view_reverse.rs", 175, Operation.PROPOSAL_FSCK, '"fsck", "--strict"'),
    Site("src/namespace_service/s4_git_view_reverse.rs", 189, Operation.SOURCE_FETCH, "run_git("),
    Site("src/namespace_service/s4_git_view_reverse.rs", 192, Operation.SOURCE_FETCH, '"fetch", "--no-tags"'),
    Site("src/namespace_service/s4_git_view_reverse.rs", 197, Operation.SOURCE_TREE_LISTING, "source_tree_arg"),
    Site("src/namespace_service/s4_git_view_reverse.rs", 202, Operation.SOURCE_TREE_LISTING, "replace_tree("),
    Site("src/namespace_service/s4_git_view_reverse.rs", 206, Operation.COMMIT_SYNTHESIS, "git_input("),
    Site("src/namespace_service/s4_git_view_reverse.rs", 220, Operation.PACK_INDEX, "new_pack("),
    Site("src/namespace_service/s4_git_view.rs", 152, Operation.SOURCE_PROJECTION, '"checkout", "-B"'),
    Site("src/namespace_service/s4_git_view.rs", 153, Operation.SOURCE_PROJECTION, '"for-each-ref"'),
    Site("src/namespace_service/s4_git_view.rs", 155, Operation.SOURCE_PROJECTION, '"update-ref", "-d"'),
    Site("src/namespace_service/s4_git_view.rs", 159, Operation.SOURCE_PROJECTION, '"cat-file", "-t"'),
    Site("src/namespace_service/s4_git_view.rs", 163, Operation.SOURCE_PROJECTION, "run_git("),
    Site("src/namespace_service/s4_git_view.rs", 170, Operation.SOURCE_PROJECTION, '"update-ref", "-d"'),
    Site("src/namespace_service/s4_git_view.rs", 172, Operation.SOURCE_PROJECTION, '"rev-parse", "refs/heads/projected"'),
    Site("src/namespace_service/s4_git_view.rs", 173, Operation.SOURCE_PROJECTION, '"symbolic-ref"'),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 58, Operation.PACK_INDEX, "git_bytes("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 66, Operation.PACK_INDEX, "git_input("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 86, Operation.PACK_INDEX, "git_bytes("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 110, Operation.PACK_INDEX, "run_git_bounded("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 132, Operation.PACK_INDEX, "git_input("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 190, Operation.ROOT_MKTREE, "git_input("),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 210, Operation.SOURCE_TREE_LISTING, '"ls-tree"'),
    Site("src/namespace_service/s4_git_proc_reverse.rs", 227, Operation.SOURCE_TREE_LISTING, '"ls-tree"'),
)


def _inside_worktree(root: Path, raw: str | Path, label: str) -> Path:
    root = root.resolve()
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise PreflightError(label + " must not be a symlink")
    path = path.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise PreflightError(label + " must live inside the worktree") from error
    if ".git" in relative.parts:
        raise PreflightError(label + " must not live in .git")
    return path


def safe_repo_path(root: Path, relative: str) -> Path:
    """Resolve one physical repo-relative file and reject escapes/symlinks."""
    if not _valid_relative(relative):
        raise PreflightError("repo-relative source path required")
    path = _inside_worktree(root, relative, "source path")
    if not path.is_file():
        raise PreflightError("source path is not a regular file")
    return path


def read_source(root: Path, relative: str) -> str:
    path = safe_repo_path(root, relative)
    try:
        body = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PreflightError("source path is unreadable") from error
    if "\r" in body:
        raise PreflightError("source path is not pure LF")
    return body


def target_case(root: Path) -> str:
    """Resolve exactly one stable SHA-1 reverse case; reject ambiguity."""
    body = read_source(root, TEST_FILE)
    names = CASE_PATTERN.findall(body)
    if names.count(TARGET_CASE) != 1:
        raise PreflightError("target case is missing or ambiguous")
    signature = "async fn " + TARGET_CASE + "("
    if body.count(signature) != 1:
        raise PreflightError("target case is missing or ambiguous")
    lines = body.splitlines()
    start = next(index for index, line in enumerate(lines) if signature in line)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if "#[tokio::test]" in lines[index]:
            end = index
            break
    block = "\n".join(lines[start:end])
    if TARGET_CASE_MARKER not in block or "cluster.reverse" not in block:
        raise PreflightError("target case is not the SHA-1 reverse case")
    return TARGET_CASE


def verify_sites(root: Path, sites: Sequence[Site] = SITES) -> None:
    """Verify every closed-table file/line/needle against the physical source."""
    seen: dict[tuple[str, int], Operation] = {}
    for site in sites:
        key = (site.file, site.line)
        if key in seen:
            raise MappingError("duplicate caller location")
        seen[key] = site.operation
        body = read_source(root, site.file)
        lines = body.splitlines()
        if site.line < 1 or site.line > len(lines):
            raise MappingError("caller location is outside the source file")
        if site.needle not in lines[site.line - 1]:
            raise MappingError("caller location text does not match the closed table")
    runner = read_source(root, RUNNER_FILE).splitlines()
    if BREAK_LINE < 1 or BREAK_LINE > len(runner) or BREAK_NEEDLE not in runner[BREAK_LINE - 1]:
        raise PreflightError("the exact child-exit return line moved")
    for relative in (HARNESS_FILE, REVERSE_FILE):
        read_source(root, relative)


def _valid_relative(relative: str) -> bool:
    if not relative or relative.startswith("/") or "\\" in relative:
        return False
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return ".git" not in parts


def classify_frames(frames: Iterable[Frame], sites: Sequence[Site] = SITES) -> tuple[Operation | None, Frame | None]:
    """Map the innermost verified caller locator to the closed enum."""
    table: dict[tuple[str, int], Operation] = {}
    for site in sites:
        key = (site.file, site.line)
        if key in table and table[key] != site.operation:
            raise MappingError("ambiguous caller location")
        table[key] = site.operation
    for frame in frames:
        if not _valid_relative(frame.file) or frame.line < 1:
            continue
        operation = table.get((frame.file, frame.line))
        if operation is not None:
            return operation, frame
    return None, None


def observation_nonce() -> str:
    return secrets.token_hex(16)


def _bounded_int(value: str, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise ResultError("integer field is not decimal") from error
    if parsed < minimum or parsed > maximum:
        raise ResultError("integer field is outside its bound")
    return parsed


def parse_result(text: str, nonce: str) -> GdbResult:
    """Parse the fixed, bounded GDB result grammar; reject anything else."""
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ResultError("result file exceeds its bound")
    lines = text.splitlines()
    if not lines or len(lines) > MAX_RESULT_LINES:
        raise ResultError("result file has an invalid line count")
    if any("\r" in line for line in lines):
        raise ResultError("result file is not pure LF")
    header = lines[0].split(" ")
    if header != [RESULT_HEADER.split(" ")[0], "1", nonce]:
        raise ResultError("result header or nonce mismatch")
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ResultError("nonce is not fixed-width lowercase hex")
    seen = {"breakpoint": 0, "failure": 0, "exit": 0, "signal": 0, "error": 0}
    breakpoint_state = ""
    breakpoint_file = ""
    breakpoint_line = 0
    failure = False
    frames: list[Frame] = []
    exit_code: int | None = None
    exit_signal: int | None = None
    error: str | None = None
    for line in lines[1:]:
        fields = line.split(" ")
        key = fields[0]
        if key in seen:
            seen[key] += 1
        if key == "breakpoint":
            if len(fields) != 4 or fields[1] not in ("resolved", "unresolved"):
                raise ResultError("malformed breakpoint record")
            if not _valid_relative(fields[2]):
                raise ResultError("breakpoint path is not repo-relative")
            breakpoint_state = fields[1]
            breakpoint_file = fields[2]
            breakpoint_line = _bounded_int(fields[3], minimum=1, maximum=10_000_000)
        elif key == "failure":
            if len(fields) != 2 or fields[1] not in ("0", "1"):
                raise ResultError("malformed failure record")
            failure = fields[1] == "1"
        elif key == "frame":
            if len(fields) != 3:
                raise ResultError("malformed frame record")
            if not _valid_relative(fields[1]):
                raise ResultError("frame path is not repo-relative")
            if len(frames) >= MAX_FRAMES:
                raise ResultError("frame count exceeds its bound")
            frames.append(Frame(fields[1], _bounded_int(fields[2], minimum=1, maximum=10_000_000)))
        elif key == "exit":
            if len(fields) != 2:
                raise ResultError("malformed exit record")
            exit_code = _bounded_int(fields[1], minimum=-1, maximum=255)
        elif key == "signal":
            if len(fields) != 2:
                raise ResultError("malformed signal record")
            exit_signal = _bounded_int(fields[1], minimum=0, maximum=255)
        elif key == "error":
            if len(fields) != 2 or fields[1] not in (
                "breakpoint_unresolved",
                "setup_error",
                "write_error",
            ):
                raise ResultError("malformed error record")
            error = fields[1]
        else:
            raise ResultError("unknown result record")
    if any(count > 1 for count in seen.values()):
        raise ResultError("duplicate result record")
    if seen["error"] == 1:
        if error == "breakpoint_unresolved":
            if (
                seen["breakpoint"] != 1
                or breakpoint_state != "unresolved"
                or breakpoint_file != BREAK_FILE
                or breakpoint_line != BREAK_LINE
                or seen["failure"]
                or seen["exit"]
                or seen["signal"]
                or frames
            ):
                raise ResultError("unresolved breakpoint result is inconsistent")
            return GdbResult(
                nonce,
                breakpoint_state,
                breakpoint_file,
                breakpoint_line,
                False,
                (),
                None,
                None,
                error,
            )
        if seen["breakpoint"] or seen["failure"] or seen["exit"] or seen["signal"] or frames:
            raise ResultError("error result carries target data")
        return GdbResult(nonce, "", "", 0, False, (), None, None, error)
    if seen["breakpoint"] != 1 or seen["failure"] != 1:
        raise ResultError("required result record is missing")
    if breakpoint_file != BREAK_FILE or breakpoint_line != BREAK_LINE:
        raise ResultError("breakpoint location is not the bound failure site")
    if breakpoint_state == "unresolved":
        if failure or frames or seen["exit"] or seen["signal"]:
            raise ResultError("unresolved breakpoint carries target data")
        return GdbResult(
            nonce,
            breakpoint_state,
            breakpoint_file,
            breakpoint_line,
            False,
            (),
            None,
            None,
            None,
        )
    if seen["exit"] != 1 or seen["signal"] != 1:
        raise ResultError("resolved run has no exit record")
    if not failure and frames:
        raise ResultError("successful child path carries frames")
    return GdbResult(
        nonce,
        breakpoint_state,
        breakpoint_file,
        breakpoint_line,
        failure,
        tuple(frames),
        exit_code,
        exit_signal,
        None,
    )


def parse_git_version(text: str) -> tuple[int, int, int]:
    match = GIT_VERSION_PATTERN.search(text)
    if match is None:
        raise PreflightError("selected Git did not report a numeric version")
    return tuple(int(part) for part in match.groups())


def probe_git_version(git_binary: str) -> tuple[int, int, int]:
    try:
        completed = subprocess.run(
            [git_binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("selected Git is unavailable") from error
    if completed.returncode != 0:
        raise PreflightError("selected Git version probe failed")
    return parse_git_version(completed.stdout)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_binary(root: Path, raw: str) -> Path:
    path = _inside_worktree(root, raw, "test executable")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PreflightError("test executable is missing or not executable")
    return path


def safe_work_path(root: Path, raw: str | Path, label: str) -> Path:
    return _inside_worktree(root, raw, label)


def target_argv(binary: Path) -> list[str]:
    """The one named SHA-1 case, with the normal serial ignored selection."""
    return [
        str(binary),
        "--ignored",
        "--exact",
        TARGET_CASE,
        "--test-threads=1",
    ]


def build_gdb_argv(source_root: Path, gdb: str, binary: Path) -> list[str]:
    """Fixed batch argv: no attach, no user -ex, no arbitrary target call."""
    return [
        gdb,
        "--batch",
        "--nx",
        "--quiet",
        "-iex",
        "set pagination off",
        "-iex",
        "set confirm off",
        "-iex",
        "set history save off",
        "-iex",
        "set width 0",
        "-iex",
        "set height 0",
        "-iex",
        "set print frame-arguments none",
        "-iex",
        "directory " + str(source_root),
        "-x",
        str(GDB_SCRIPT),
        "--args",
        *target_argv(binary),
    ]


def build_preflight_argv(source_root: Path, gdb: str, binary: Path) -> list[str]:
    return [
        gdb,
        "--batch",
        "--nx",
        "--quiet",
        "-iex",
        "set pagination off",
        "-iex",
        "set confirm off",
        "-iex",
        "set history save off",
        "-iex",
        "directory " + str(source_root),
        "--se",
        str(binary),
        "-x",
        str(GDB_PREFLIGHT),
    ]


def _preflight_resolved(output: str) -> bool:
    return (
        "Line " + str(BREAK_LINE) + " of" in output
        and BREAK_FILE in output
        and "s4-gdb-python-ok" in output
        and "0x" in output
    )


def preflight_gdb(source_root: Path, gdb: str, binary: Path) -> tuple[bool, Reason]:
    try:
        completed = subprocess.run(
            build_preflight_argv(source_root, gdb, binary),
            cwd=source_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return False, Reason.GDB_UNAVAILABLE
    except (OSError, subprocess.SubprocessError):
        return False, Reason.GDB_UNAVAILABLE
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or not _preflight_resolved(output):
        return False, Reason.BREAKPOINT_UNRESOLVED
    return True, Reason.NONE


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _stop_process_group(process: subprocess.Popen) -> None:
    """Bounded terminate, kill and reap for the owned GDB session."""
    if process.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except OSError:
            try:
                process.send_signal(sig)
            except OSError:
                pass
        try:
            process.wait(timeout=STOP_GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue
        except KeyboardInterrupt:
            continue


def run_observer(
    source_root: Path,
    gdb: str,
    binary: Path,
    work_dir: Path,
    nonce: str,
    timeout_seconds: int,
) -> tuple[GdbResult | None, Reason, RunPhase]:
    try:
        work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        work_dir.chmod(0o700)
    except OSError:
        return None, Reason.WORKDIR_UNAVAILABLE, RunPhase.PREFLIGHT_NOT_RUN
    result_path = work_dir / "result.txt"
    _remove(result_path)
    environment = dict(os.environ)
    environment.update(
        {
            "S4_GIT_REPO_ROOT": str(source_root),
            "S4_GIT_RESULT_PATH": str(result_path),
            "S4_GIT_NONCE": nonce,
            "S4_GIT_BREAK_FILE": BREAK_FILE,
            "S4_GIT_BREAK_LINE": str(BREAK_LINE),
            "S4_GIT_MAX_FRAMES": str(MAX_FRAMES),
        }
    )
    argv = build_gdb_argv(source_root, gdb, binary)
    process: subprocess.Popen | None = None
    timed_out = False
    interrupted = False
    try:
        process = subprocess.Popen(
            argv,
            cwd=source_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _stop_process_group(process)
        except KeyboardInterrupt:
            interrupted = True
            _stop_process_group(process)
        if timed_out:
            _remove(result_path)
            return None, Reason.RUN_TIMED_OUT, RunPhase.RUN_STARTED_TIMED_OUT
        if interrupted:
            parsed = _interrupted_result(result_path, nonce)
            _remove(result_path)
            return parsed, Reason.RUN_INTERRUPTED, RunPhase.RUN_STARTED_INTERRUPTED
        if result_path.is_symlink() or not result_path.is_file():
            raise ResultError("result file is not a regular file")
        size = result_path.stat().st_size
        if size > MAX_RESULT_BYTES:
            raise ResultError("result file exceeds its bound")
        text = result_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, Reason.GDB_UNAVAILABLE, RunPhase.PREFLIGHT_NOT_RUN
    except (OSError, subprocess.SubprocessError):
        return None, Reason.GDB_UNAVAILABLE, RunPhase.PREFLIGHT_NOT_RUN
    except ResultError:
        existed = result_path.exists() or result_path.is_symlink()
        _remove(result_path)
        if existed:
            return None, Reason.RESULT_INVALID, RunPhase.RUN_STARTED_INVALID_RESULT
        return None, Reason.RESULT_MISSING, RunPhase.RUN_STARTED_NO_RESULT
    except KeyboardInterrupt:
        if process is None:
            return None, Reason.RUN_INTERRUPTED, RunPhase.PREFLIGHT_NOT_RUN
        _stop_process_group(process)
        _remove(result_path)
        return None, Reason.RUN_INTERRUPTED, RunPhase.RUN_STARTED_INTERRUPTED
    try:
        parsed = parse_result(text, nonce)
    except ResultError:
        _remove(result_path)
        return None, Reason.RESULT_INVALID, RunPhase.RUN_STARTED_INVALID_RESULT
    except KeyboardInterrupt:
        _remove(result_path)
        return None, Reason.RUN_INTERRUPTED, RunPhase.RUN_STARTED_INTERRUPTED
    _remove(result_path)
    return parsed, Reason.NONE, RunPhase.COMPLETED


def _interrupted_result(path: Path, nonce: str) -> GdbResult | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_RESULT_BYTES:
            return None
        return parse_result(path.read_text(encoding="utf-8"), nonce)
    except (OSError, UnicodeError, ResultError):
        return None


def observed_exit(result: GdbResult) -> int | None:
    if result.exit_signal is not None and result.exit_signal > 0:
        return 128 + result.exit_signal
    if result.exit_code is not None and result.exit_code >= 0:
        return result.exit_code
    return None


def source_hashes(root: Path) -> dict[str, str]:
    return {
        "runner_sha256": hash_file(safe_repo_path(root, RUNNER_FILE)),
        "reverse_sha256": hash_file(safe_repo_path(root, REVERSE_FILE)),
        "test_sha256": hash_file(safe_repo_path(root, TEST_FILE)),
        "harness_sha256": hash_file(safe_repo_path(root, HARNESS_FILE)),
    }


def _base_value(value: str | None, label: str, pattern: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    if not pattern.fullmatch(value):
        raise PreflightError(label + " is not a full lowercase object id")
    return value


def make_report(
    *,
    status: Status,
    reason: Reason,
    run_phase: RunPhase,
    test_exit: int | None,
    failure_observed: bool,
    operation: Operation | None,
    caller: Frame | None,
    debug_resolution: str,
    git_version: tuple[int, int, int] | None,
    binary_sha256: str | None,
    source: dict[str, str | None | list[str]],
    base_commit: str | None,
    base_tree: str | None,
    base_parents: list[str],
) -> dict[str, object]:
    if test_exit is None:
        test_suite = (
            "not_run"
            if run_phase in (RunPhase.PREFLIGHT_NOT_RUN, RunPhase.RUN_STARTED_TARGET_NOT_RUN)
            else "started_unknown"
        )
    else:
        test_suite = "failed" if test_exit != 0 else "passed"
    return {
        "schema": RESULT_SCHEMA,
        "status": status.value,
        "reason": reason.value,
        "run_phase": run_phase.value,
        "test_suite": test_suite,
        "test_exit": test_exit,
        "failure_observed": failure_observed,
        "operation": operation.value if operation is not None else None,
        "failure_kind": "unknown",
        "failure_kind_reason": "exit_status_is_local_and_not_read",
        "caller": (
            {"file": caller.file, "line": caller.line} if caller is not None else None
        ),
        "debug_resolution": debug_resolution,
        "breakpoint": {"file": BREAK_FILE, "line": BREAK_LINE},
        "git_version": list(git_version) if git_version is not None else None,
        "case": TARGET_CASE,
        "case_object_format": TARGET_OBJECT_FORMAT,
        "scope": "single_case",
        "authoritative_suite": "six_case_s4_acceptance",
        "single_case_result_does_not_refute_six_case_failure": True,
        "selection": {"ignored": True, "exact": True, "test_threads": 1, "filtered_by_name": True},
        "binary_sha256": binary_sha256,
        "source": source,
        "base_commit": base_commit,
        "base_tree": base_tree,
        "base_parents": list(base_parents),
        "rebuilt_executable_may_differ_by_build_path": True,
        "limitations": [
            "child_exit_status_is_not_read_from_target_memory",
            "first_reverse_phase_child_exit_wins",
            "classification_requires_the_exact_unstripped_source_line",
            "single_case_probe_does_not_refute_the_six_case_failure",
            "rebuilt_executable_can_differ_from_a_prior_hosted_binary",
        ],
    }


def validate_report(report: dict[str, object]) -> None:
    """Strict shape check used by tests and by the workflow-side reader."""
    required = {
        "schema", "status", "reason", "run_phase", "test_suite", "test_exit",
        "failure_observed", "operation", "failure_kind", "failure_kind_reason",
        "caller", "debug_resolution", "breakpoint", "git_version", "case",
        "case_object_format", "scope", "authoritative_suite",
        "single_case_result_does_not_refute_six_case_failure", "selection",
        "binary_sha256", "source", "base_commit", "base_tree", "base_parents",
        "rebuilt_executable_may_differ_by_build_path", "limitations",
    }

    def require(condition: object, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(set(report) == required, "report keys changed")
    require(report["schema"] == RESULT_SCHEMA, "report schema changed")
    require(report["status"] in {status.value for status in Status}, "report status is not closed")
    require(report["reason"] in {reason.value for reason in Reason}, "report reason is not closed")
    require(report["run_phase"] in {phase.value for phase in RunPhase}, "report run phase is not closed")
    require(report["test_suite"] in ("passed", "failed", "not_run", "started_unknown"),
            "report test suite is not closed")
    require(report["debug_resolution"] in ("resolved", "unresolved", "not_run"),
            "report debug resolution is not closed")
    require(report["case"] == TARGET_CASE and report["case_object_format"] == TARGET_OBJECT_FORMAT,
            "report case identity changed")
    require(report["scope"] == "single_case", "report scope changed")
    require(report["authoritative_suite"] == "six_case_s4_acceptance", "report authoritative suite changed")
    require(report["single_case_result_does_not_refute_six_case_failure"] is True,
            "report single-case caveat changed")
    require(report["breakpoint"] == {"file": BREAK_FILE, "line": BREAK_LINE}, "report breakpoint changed")
    require(report["selection"] == {"ignored": True, "exact": True, "test_threads": 1, "filtered_by_name": True},
            "report selection changed")
    require(report["rebuilt_executable_may_differ_by_build_path"] is True, "report rebuild caveat changed")
    require(report["failure_kind"] == "unknown", "report failure kind changed")
    require(report["failure_kind_reason"] == "exit_status_is_local_and_not_read",
            "report failure-kind reason changed")
    require(report["operation"] is None or report["operation"] in {op.value for op in Operation},
            "report operation is not closed")
    caller = report["caller"]
    if caller is not None:
        require(isinstance(caller, dict) and set(caller) == {"file", "line"}
                and isinstance(caller["file"], str) and _valid_relative(caller["file"])
                and isinstance(caller["line"], int) and caller["line"] >= 1,
                "report caller shape changed")
    status, phase, test_exit = report["status"], report["run_phase"], report["test_exit"]
    completed = phase == RunPhase.COMPLETED.value
    if completed:
        require(isinstance(test_exit, int) and not isinstance(test_exit, bool) and 0 <= test_exit <= 255,
                "report test exit is not a bounded integer")
        require(isinstance(report["binary_sha256"], str)
                and SHA256_PATTERN.fullmatch(report["binary_sha256"]), "report binary digest is missing")
        require(report["test_suite"] == ("failed" if test_exit != 0 else "passed"),
                "report test suite does not match the runner exit")
    elif phase == RunPhase.RUN_STARTED_INTERRUPTED.value:
        if test_exit is None:
            require(report["test_suite"] == "started_unknown",
                    "interrupted run without an exit claims a suite outcome")
        else:
            require(isinstance(test_exit, int) and not isinstance(test_exit, bool)
                    and 0 <= test_exit <= 255,
                    "interrupted runner exit is not a bounded integer")
            require(report["test_suite"] == ("failed" if test_exit != 0 else "passed"),
                    "interrupted runner exit does not match the suite state")
    else:
        require(test_exit is None, "incomplete run carries a runner exit")
        expected = "not_run" if phase in (RunPhase.PREFLIGHT_NOT_RUN.value,
                                          RunPhase.RUN_STARTED_TARGET_NOT_RUN.value) else "started_unknown"
        require(report["test_suite"] == expected, "report suite state does not match the run phase")

    if status == Status.CLASSIFIED_FAILURE.value:
        require(completed and test_exit != 0 and report["failure_observed"] is True,
                "classified failure needs a completed nonzero runner")
        require(report["operation"] is not None and isinstance(caller, dict),
                "classified failure has no caller")
        site = next((site for site in SITES if site.file == caller["file"] and site.line == caller["line"]), None)
        require(site is not None and site.operation.value == report["operation"],
                "classified caller is not a verified site")
    elif status == Status.OBSERVER_MISMATCH.value:
        require(completed and test_exit == 0 and report["failure_observed"] is True,
                "observer mismatch needs a completed zero runner")
        if report["operation"] is None:
            require(caller is None, "observer mismatch caller has no operation")
        else:
            require(isinstance(caller, dict), "observer mismatch operation has no caller")
            site = next((site for site in SITES if site.file == caller["file"] and site.line == caller["line"]), None)
            require(site is not None and site.operation.value == report["operation"],
                    "observer mismatch caller is not a verified site")
    elif status == Status.UNRESOLVED_FAILURE.value:
        require(completed and test_exit != 0 and report["operation"] is None and caller is None,
                "unresolved failure carries an inconsistent caller")
    elif status == Status.NO_FAILURE_OBSERVED.value:
        require(completed and test_exit == 0 and report["failure_observed"] is False
                and report["operation"] is None and caller is None,
                "no-failure status is inconsistent")
    else:
        require(report["operation"] is None and caller is None and not completed,
                "unsupported status is inconsistent")

    payload = json.dumps(report, sort_keys=True)
    require(len(payload.encode("utf-8")) <= MAX_REPORT_BYTES, "report exceeds its bound")

    def reject_absolute(value: object) -> None:
        if isinstance(value, str):
            require(not value.startswith("/") and str(ROOT) not in value
                    and not value.startswith(("/Users/", "/tmp/", "/home/", "/private/"))
                    and ".." not in value.split("/"), "report leaked an absolute path")
        elif isinstance(value, dict):
            for item in value.values():
                reject_absolute(item)
        elif isinstance(value, list):
            for item in value:
                reject_absolute(item)

    reject_absolute(report)


def write_report(path: Path, report: dict[str, object]) -> None:
    validate_report(report)
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
        raise PreflightError("report exceeds its bound")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + ".tmp")
    if temporary.is_symlink():
        raise PreflightError("report temporary path is a symlink")
    _remove(temporary)
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Failure-only GDB observer for one exact S4 reverse-import test case."
    )
    parser.add_argument("--binary", required=True, help="unstripped integration-test executable")
    parser.add_argument("--report", required=True, help="fixed bounded JSON report path")
    parser.add_argument(
        "--work-dir",
        default="target/s4-git-exit-debugger/run",
        help="private ephemeral GDB result directory inside the worktree",
    )
    parser.add_argument("--source-root", default=str(ROOT), help="exact source worktree")
    parser.add_argument("--gdb", default="gdb", help="Linux GDB with Python support")
    parser.add_argument(
        "--git",
        default=os.environ.get("ROOTYARD_TEST_GIT", "/usr/bin/git"),
        help="exact selected Git binary",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--base-commit")
    parser.add_argument("--base-tree")
    parser.add_argument("--base-parent", action="append", default=[])
    args = parser.parse_args(argv)

    if args.timeout_seconds < 1 or args.timeout_seconds > 3300:
        print("s4-git-exit-debugger: timeout outside 1..3300 seconds", file=sys.stderr)
        return 2
    try:
        root = Path(args.source_root).resolve()
        if not root.is_dir():
            raise PreflightError("source root is not a directory")
        report_path = safe_work_path(root, args.report, "report path")
        work_dir = safe_work_path(root, args.work_dir, "work directory")
        base_commit = _base_value(args.base_commit, "base commit", COMMIT_PATTERN)
        base_tree = _base_value(args.base_tree, "base tree", COMMIT_PATTERN)
        base_parents = [
            _base_value(parent, "base parent", COMMIT_PATTERN) for parent in args.base_parent
        ]
        if (base_commit is None) != (base_tree is None):
            raise PreflightError("base commit and base tree must be supplied together")
        if any(parent is None for parent in base_parents):
            raise PreflightError("base parent is invalid")
    except PreflightError as error:
        print("s4-git-exit-debugger: " + str(error), file=sys.stderr)
        return 2

    source: dict[str, str | None | list[str]] = {}
    binary_sha256: str | None = None
    binary: Path | None = None
    git_version: tuple[int, int, int] | None = None

    def emit(
        status: Status,
        reason: Reason,
        *,
        run_phase: RunPhase = RunPhase.PREFLIGHT_NOT_RUN,
        test_exit: int | None = None,
        failure_observed: bool = False,
        operation: Operation | None = None,
        caller: Frame | None = None,
        debug_resolution: str = "not_run",
    ) -> dict[str, object] | None:
        report = make_report(
            status=status,
            reason=reason,
            run_phase=run_phase,
            test_exit=test_exit,
            failure_observed=failure_observed,
            operation=operation,
            caller=caller,
            debug_resolution=debug_resolution,
            git_version=git_version,
            binary_sha256=binary_sha256,
            source=source,
            base_commit=base_commit,
            base_tree=base_tree,
            base_parents=[parent for parent in base_parents if parent is not None],
        )
        try:
            write_report(report_path, report)
        except (OSError, PreflightError, ValueError):
            return None
        return report

    def unsupported(
        reason: Reason,
        *,
        run_phase: RunPhase = RunPhase.PREFLIGHT_NOT_RUN,
        test_exit: int | None = None,
        failure_observed: bool = False,
        debug_resolution: str = "unresolved",
    ) -> int:
        emit(
            Status.UNSUPPORTED,
            reason,
            run_phase=run_phase,
            test_exit=test_exit,
            failure_observed=failure_observed,
            debug_resolution=debug_resolution,
        )
        return 2

    try:
        verify_sites(root)
        target_case(root)
        source = source_hashes(root)
    except (PreflightError, MappingError):
        print("s4-git-exit-debugger: source preflight failed", file=sys.stderr)
        return unsupported(Reason.SOURCE_PREFLIGHT_FAILED)
    try:
        binary = verify_binary(root, args.binary)
        binary_sha256 = hash_file(binary)
    except PreflightError:
        print("s4-git-exit-debugger: test executable preflight failed", file=sys.stderr)
        return unsupported(Reason.BINARY_UNAVAILABLE)
    try:
        git_version = probe_git_version(args.git)
    except PreflightError:
        print("s4-git-exit-debugger: selected Git version preflight failed", file=sys.stderr)
        return unsupported(Reason.GIT_VERSION_UNAVAILABLE)

    ok, preflight_reason = preflight_gdb(root, args.gdb, binary)
    if not ok:
        return unsupported(preflight_reason)
    if hash_file(binary) != binary_sha256:
        return unsupported(Reason.BINARY_CHANGED)

    assert binary is not None
    nonce = observation_nonce()
    result, run_reason, run_phase = run_observer(
        root,
        args.gdb,
        binary,
        work_dir,
        nonce,
        args.timeout_seconds,
    )
    if run_phase == RunPhase.RUN_STARTED_INTERRUPTED:
        test_exit = observed_exit(result) if result is not None else None
        return unsupported(
            Reason.RUN_INTERRUPTED,
            run_phase=run_phase,
            test_exit=test_exit,
            failure_observed=result.failure if result is not None else False,
            debug_resolution=(
                "resolved"
                if result is not None and result.breakpoint_state == "resolved"
                else "unresolved"
            ),
        )
    if result is None:
        return unsupported(run_reason, run_phase=run_phase)
    if result.error is not None:
        reason = Reason.GDB_UNAVAILABLE if result.error == "setup_error" else Reason.BREAKPOINT_UNRESOLVED
        return unsupported(reason, run_phase=RunPhase.RUN_STARTED_TARGET_NOT_RUN)
    if result.breakpoint_state != "resolved":
        return unsupported(Reason.BREAKPOINT_UNRESOLVED, run_phase=RunPhase.RUN_STARTED_TARGET_NOT_RUN)

    test_exit = observed_exit(result)
    if test_exit is None:
        return unsupported(
            Reason.RESULT_INVALID,
            run_phase=RunPhase.RUN_STARTED_INVALID_RESULT,
            failure_observed=result.failure,
            debug_resolution="resolved",
        )
    if result.failure:
        operation, caller = classify_frames(result.frames)
        if test_exit == 0:
            status = Status.OBSERVER_MISMATCH
            reason = Reason.CLASSIFIED if operation is not None else Reason.NO_KNOWN_CALLER_FRAME
        elif operation is None:
            status = Status.UNRESOLVED_FAILURE
            reason = Reason.NO_KNOWN_CALLER_FRAME
        else:
            status = Status.CLASSIFIED_FAILURE
            reason = Reason.CLASSIFIED
    elif test_exit != 0:
        status = Status.UNRESOLVED_FAILURE
        reason = Reason.NO_FAILURE_MARKER
        operation = None
        caller = None
    else:
        status = Status.NO_FAILURE_OBSERVED
        reason = Reason.NONE
        operation = None
        caller = None

    report = emit(
        status,
        reason,
        run_phase=RunPhase.COMPLETED,
        test_exit=test_exit,
        failure_observed=result.failure,
        operation=operation,
        caller=caller,
        debug_resolution="resolved",
    )
    if report is None:
        print("s4-git-exit-debugger: report could not be written", file=sys.stderr)
        return 2
    return test_exit


if __name__ == "__main__":
    raise SystemExit(main())
