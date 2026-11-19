#!/usr/bin/env python3
"""Run the CI Python unittest discovery with bounded log diagnostics.

The hosted verify job previously used the default non-verbose
``python3 -m unittest discover`` invocation, so a long-running case could not
be identified from the log. This runner keeps the existing selection and
result semantics:

* discover the existing ``tests/test_*.py`` set, in unittest order;
* restore the repository-root import context used by ``python -m unittest``;
* install the stdlib fatal-signal handler before discovery, so a fatal signal
  still writes an all-thread Python stack;
* leave an already-installed process-global handler untouched, and remove only
  the handler this run installed on exit;
* run verbosely, keeping normal test-count, skip and failure/error handling;
* print every test id as it starts, to stderr;
* write one bounded START and one DONE marker per test to stderr, carrying
  only a fixed state, the numeric unittest ordinal and a SHA-256 of the test
  id;
* run one Python daemon thread that writes a bounded, sanitized all-thread
  Python stack snapshot every 120 seconds.

The periodic snapshot reads ``sys._current_frames`` and never calls
``faulthandler.dump_traceback_later``: the fatal-signal handler stays a
separate, fatal-only path. The snapshot never reads frame locals, source line
contents, call arguments or full paths. A file basename, line number or
function name is emitted only when it matches a small ASCII allowlist;
otherwise it is replaced with ``<omitted>``. Thread count, frame depth and
total bytes are bounded, and the daemon thread is stopped and joined with a
bounded timeout on every exit.

faulthandler reports thread stacks only on a fatal signal; it does not dump
locals, arguments, the environment, or a core file. The per-test markers are
written immediately with ``os.write`` and never contain a raw test id,
description, failure text or other unbounded value. An opt-in JSON report uses
only projected unittest outcomes and a verified checkout identity.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
import faulthandler
import hashlib
from itertools import chain, islice
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from typing import TextIO
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
TESTS_DIR = ROOT / "tests"
TEST_PATTERN = "test_*.py"
TRACEBACK_INTERVAL_SECONDS = 120
DIAGNOSTIC_MAX_THREADS = 32
DIAGNOSTIC_MAX_FRAMES = 32
DIAGNOSTIC_MAX_BYTES = 16 * 1024
DIAGNOSTIC_MAX_BASENAME_LENGTH = 96
DIAGNOSTIC_MAX_FUNCTION_LENGTH = 80
DIAGNOSTIC_MIN_INTERVAL_SECONDS = 0.01
DIAGNOSTIC_STOP_TIMEOUT_SECONDS = 5.0
DIAGNOSTIC_OMITTED = "<omitted>"
DIAGNOSTIC_TRUNCATED = b"... diagnostics truncated\n"
DIAGNOSTIC_BASENAME = re.compile(
    rf"[A-Za-z0-9_.-]{{1,{DIAGNOSTIC_MAX_BASENAME_LENGTH}}}"
)
DIAGNOSTIC_FUNCTION = re.compile(
    rf"(?:[A-Za-z_][A-Za-z0-9_.]{{0,{DIAGNOSTIC_MAX_FUNCTION_LENGTH - 1}}}"
    r"|<(?:module|lambda|listcomp|dictcomp|setcomp|genexpr|string|stdin)>)"
)
REPORT_MAX_CASES = 32
REPORT_MAX_COUNT = 99_999_999
REPORT_MAX_ELAPSED_MS = 24 * 60 * 60 * 1000
REPORT_MAX_BYTES = 8192

MARKER_PREFIX = b"DSH-RUNNER-DIAG v=1 state="
MARKER_STATE_START = b"START"
MARKER_STATE_DONE = b"DONE"
MARKER_ORDINAL_FIELD = b" ordinal="
MARKER_ORDINAL_WIDTH = 8
MARKER_HASH_FIELD = b" test_sha256="
MARKER_HASH_HEX_LENGTH = 64
MARKER_TERMINATOR = b"\n"
MARKER_MAX_BYTES = (
    len(MARKER_PREFIX)
    + max(len(MARKER_STATE_START), len(MARKER_STATE_DONE))
    + len(MARKER_ORDINAL_FIELD)
    + MARKER_ORDINAL_WIDTH
    + len(MARKER_HASH_FIELD)
    + MARKER_HASH_HEX_LENGTH
    + len(MARKER_TERMINATOR)
)


def _write_marker_to_stderr(payload: bytes) -> int:
    """Write one complete marker to fd 2 without Python-level buffering."""
    return os.write(2, payload)


def _bounded_ordinal(ordinal: int) -> bytes:
    """Render the unittest ordinal in a fixed-width, bounded field."""
    if ordinal < 0:
        ordinal = 0
    ordinal = min(ordinal, 10**MARKER_ORDINAL_WIDTH - 1)
    return f"{ordinal:0{MARKER_ORDINAL_WIDTH}d}".encode("ascii")


def _test_id_sha256(test: unittest.TestCase) -> str:
    """Hash the test id in RAM; the raw id never enters the marker."""
    test_id = test.id()
    if not isinstance(test_id, str):
        raise TypeError("test id must be a string")
    return hashlib.sha256(test_id.encode("utf-8", "surrogatepass")).hexdigest()


class _MarkerEmitter:
    """Write a closed, bounded marker without disturbing unittest semantics."""

    def __init__(self, write: Callable[[bytes], int]) -> None:
        self._write = write
        self.failed = False

    def emit(self, state: bytes, ordinal: int, test: unittest.TestCase) -> None:
        if self.failed:
            return
        try:
            payload = b"".join(
                (
                    MARKER_PREFIX,
                    state,
                    MARKER_ORDINAL_FIELD,
                    _bounded_ordinal(ordinal),
                    MARKER_HASH_FIELD,
                    _test_id_sha256(test).encode("ascii"),
                    MARKER_TERMINATOR,
                )
            )
            if len(payload) > MARKER_MAX_BYTES:
                raise ValueError("marker exceeds its fixed bound")
            if self._write(payload) != len(payload):
                raise OSError("short marker write")
        except Exception:
            # Keep the primary unittest result and cleanup intact. ``run``
            # turns this sticky flag into a conservative non-zero exit only
            # when the real result would otherwise exit zero.
            self.failed = True


def _diagnostic_result_class(
    emitter: _MarkerEmitter,
    observe_result: Callable[[unittest.TextTestResult], None] | None = None,
) -> type[unittest.TextTestResult]:
    """Return the TextTestResult that emits one START/DONE pair per test."""

    class _DiagnosticTextTestResult(unittest.TextTestResult):
        def startTestRun(self) -> None:
            super().startTestRun()
            if observe_result is not None:
                observe_result(self)

        def startTest(self, test: unittest.TestCase) -> None:
            super().startTest(test)
            emitter.emit(MARKER_STATE_START, self.testsRun, test)

        def stopTest(self, test: unittest.TestCase) -> None:
            try:
                emitter.emit(MARKER_STATE_DONE, self.testsRun, test)
            finally:
                super().stopTest(test)

    return _DiagnosticTextTestResult


def _safe_basename(value: object) -> str:
    """Return a path-free, allowlisted file basename or ``<omitted>``."""
    if not isinstance(value, str):
        return DIAGNOSTIC_OMITTED
    try:
        basename = os.path.basename(value)
    except (OSError, ValueError):
        return DIAGNOSTIC_OMITTED
    if basename in {".", ".."} or not DIAGNOSTIC_BASENAME.fullmatch(basename):
        return DIAGNOSTIC_OMITTED
    return basename


def _safe_function(value: object) -> str:
    """Return an allowlisted code name or ``<omitted>``."""
    if not isinstance(value, str) or not DIAGNOSTIC_FUNCTION.fullmatch(value):
        return DIAGNOSTIC_OMITTED
    return value


def _safe_lineno(value: object) -> int:
    """Return a bounded line number; never a raw or negative value."""
    try:
        lineno = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return min(max(lineno, 0), 2**31 - 1)


def _frame_records(
    frame: object, limit: int
) -> tuple[list[tuple[str, int, str]], bool]:
    """Extract bounded, sanitized records from one Python frame chain."""
    records: list[tuple[str, int, str]] = []
    seen: set[int] = set()
    while frame is not None and len(records) < limit:
        if id(frame) in seen:
            break
        seen.add(id(frame))
        try:
            code = frame.f_code
            filename = getattr(code, "co_filename", None)
            function = getattr(code, "co_name", None)
            lineno = getattr(frame, "f_lineno", 0)
            back = getattr(frame, "f_back", None)
        except Exception:
            break
        records.append(
            (
                _safe_basename(filename),
                _safe_lineno(lineno),
                _safe_function(function),
            )
        )
        frame = back
    return records, frame is not None


class _PeriodicDiagnostics:
    """One daemon thread writing bounded, sanitized Python stack snapshots.

    The only thread state inspected is ``sys._current_frames()``, a plain
    Python dict of the topmost frame per thread. No native stack is walked and
    faulthandler's process-global periodic timer is never used, so this path
    is separate from the fatal-signal handler. The snapshot and all frame
    attribute reads happen in Python under the GIL; the completed payload is
    then written as one bounded logical write. With no injected stream the
    writer uses fd 2 directly and never the buffered ``sys.stderr`` wrapper.
    """

    def __init__(
        self,
        interval: float,
        stream: TextIO | None = None,
        *,
        frames_snapshot: Callable[[], dict[int, object]] = sys._current_frames,
        thread_factory: Callable[..., threading.Thread] = threading.Thread,
    ) -> None:
        try:
            interval_seconds = float(interval)
        except (TypeError, ValueError):
            interval_seconds = float(TRACEBACK_INTERVAL_SECONDS)
        self.interval = max(interval_seconds, DIAGNOSTIC_MIN_INTERVAL_SECONDS)
        self._stream = stream
        self._frames_snapshot = frames_snapshot
        self._thread_factory = thread_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.failed = False

    def start(self) -> None:
        """Start the single daemon diagnostics thread."""
        if self._thread is not None:
            raise RuntimeError("periodic diagnostics already started")
        thread = self._thread_factory(
            target=self._run,
            name="dsh-python-ci-diagnostics",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.dump_once()

    def dump_once(self) -> None:
        """Write one snapshot; a diagnostic failure must never fail the run."""
        try:
            self._write(self.render(exclude_ident=threading.get_ident()))
        except Exception:
            # Stop after the first failure instead of spamming a broken sink.
            self.failed = True

    def render(
        self,
        *,
        exclude_ident: int | None = None,
        frames: dict[int, object] | None = None,
    ) -> bytes:
        """Render one bounded snapshot without touching locals or source."""
        try:
            snapshot = self._frames_snapshot() if frames is None else frames
        except Exception:
            snapshot = {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        try:
            items = [
                (ident, frame)
                for ident, frame in snapshot.items()
                if isinstance(ident, int) and ident != exclude_ident
            ]
        except Exception:
            items = []
        main_ident = getattr(threading.main_thread(), "ident", None)
        items.sort(key=lambda item: (item[0] != main_ident, item[0]))

        total = len(items)
        shown = min(total, DIAGNOSTIC_MAX_THREADS)
        interval_ms = min(max(int(round(self.interval * 1000)), 0), 2**31 - 1)
        lines = [
            "DSH-RUNNER-DIAG v=1 state=PERIODIC "
            f"interval_ms={interval_ms} threads={total} shown={shown}\n",
            "most recent call first\n",
        ]
        for ident, frame in items[:shown]:
            lines.append(
                f"thread id={ident} main={1 if ident == main_ident else 0}\n"
            )
            records, truncated = _frame_records(frame, DIAGNOSTIC_MAX_FRAMES)
            for basename, lineno, function in records:
                lines.append(
                    f'  file="{basename}" line={lineno} function={function}\n'
                )
            if truncated:
                lines.append("  frames_truncated=1\n")
        if total > shown:
            lines.append(f"threads_truncated={total - shown}\n")

        payload = "".join(lines).encode("ascii", "replace")
        if len(payload) > DIAGNOSTIC_MAX_BYTES:
            budget = max(
                DIAGNOSTIC_MAX_BYTES - len(DIAGNOSTIC_TRUNCATED), 0
            )
            payload = payload[:budget]
            newline = payload.rfind(b"\n")
            payload = payload[: newline + 1] if newline >= 0 else b""
            payload += DIAGNOSTIC_TRUNCATED
        return payload

    def _write(self, payload: bytes) -> None:
        if len(payload) > DIAGNOSTIC_MAX_BYTES:
            raise ValueError("periodic diagnostics payload exceeds its bound")
        stream = self._stream
        if stream is None:
            # A single unbuffered fd-2 path avoids TextIOWrapper locks that a
            # forked child could inherit in a locked state.
            view = memoryview(payload)
            while view:
                written = os.write(2, view)
                if written <= 0:
                    raise OSError("short periodic diagnostics write")
                view = view[written:]
            return
        stream.write(payload.decode("ascii"))
        flush = getattr(stream, "flush", None)
        if flush is not None:
            flush()

    def stop(self) -> None:
        """Stop and join with a bounded timeout; never block shutdown forever."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=DIAGNOSTIC_STOP_TIMEOUT_SECONDS)


def _install_fatal_handler(
    *,
    is_enabled: Callable[[], bool],
    enable: Callable[..., None],
) -> bool:
    """Install the fatal handler only when no process-global owner exists.

    Return ``True`` when this call installed the handler and therefore owns
    its removal. An existing handler belongs to the process, possibly to an
    outer full-suite runner, and must keep its original destination and
    lifetime.
    """
    if is_enabled():
        return False
    enable(all_threads=True)
    return True


def _restore_repo_root_import_context() -> None:
    """Match the import context of ``python -m unittest`` from the repo root.

    Running a file puts its directory (``scripts/``) at sys.path[0], whereas
    the module entrypoint puts the repository root there. This only runs for
    the CLI entrypoint, so importing this module from a test does not reorder
    the active discovery path.
    """
    if sys.path and sys.path[0] == str(SCRIPT_DIR):
        sys.path.pop(0)
    if str(ROOT) in sys.path:
        sys.path.remove(str(ROOT))
    sys.path.insert(0, str(ROOT))


def discover(tests_dir: Path = TESTS_DIR) -> unittest.TestSuite:
    """Discover the existing ``tests/test_*.py`` selection."""
    return unittest.TestLoader().discover(
        start_dir=str(tests_dir), pattern=TEST_PATTERN
    )


def _checkout_binding(expected_commit: str | None) -> tuple[str, str] | None:
    if expected_commit is None or not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        return None
    try:
        git = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{commit}", "HEAD^{tree}"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if not re.fullmatch(rb"[0-9a-f]{40}\n[0-9a-f]{40}\n", git.stdout):
        return None
    commit, tree = git.stdout.decode("ascii").splitlines()
    return (commit, tree) if commit == expected_commit else None


def _unittest_evidence(result: unittest.TextTestResult | None) -> dict:
    # Read the existing result's recorded outcomes. Hash the owning test for
    # subtests so their parameters do not affect the lookup key.
    failures = result.failures if result is not None else ()
    errors = result.errors if result is not None else ()
    unexpected = result.unexpectedSuccesses if result is not None else ()
    counts = {
        "tests_run": result.testsRun if result is not None else 0,
        "failures": len(failures),
        "errors": len(errors),
        "skipped": len(result.skipped) if result is not None else 0,
        "expected_failures": len(result.expectedFailures) if result is not None else 0,
        "unexpected_successes": len(unexpected),
    }
    tests = chain(
        (("failure", test) for test, _ in failures),
        (("error", test) for test, _ in errors),
        (("unexpected_success", test) for test in unexpected),
    )
    cases = []
    for outcome, test in islice(tests, REPORT_MAX_CASES):
        try:
            if isinstance(test, unittest.case._SubTest):
                test = test.test_case
            digest = _test_id_sha256(test)
        except Exception:
            continue
        cases.append({"test_sha256": digest, "outcome": outcome})
    return {
        "counts": {name: min(max(value, 0), REPORT_MAX_COUNT) for name, value in counts.items()},
        "cases": cases,
        "cases_truncated": len(failures) + len(errors) + len(unexpected) > len(cases),
    }


def _write_report(path: Path, report: dict) -> None:
    payload = (json.dumps(report, separators=(",", ":")) + "\n").encode("ascii")
    if len(payload) > REPORT_MAX_BYTES:
        raise OSError("Python CI report exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(payload)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run(
    tests_dir: Path = TESTS_DIR,
    *,
    stream: TextIO | None = None,
    watchdog_stream: TextIO | None = None,
    traceback_interval: float = TRACEBACK_INTERVAL_SECONDS,
    diagnostics_factory: Callable[..., _PeriodicDiagnostics] = _PeriodicDiagnostics,
    enable_fatal_handler: Callable[..., None] = faulthandler.enable,
    disable_fatal_handler: Callable[[], None] = faulthandler.disable,
    is_fatal_handler_enabled: Callable[[], bool] = faulthandler.is_enabled,
    marker_write: Callable[[bytes], int] = _write_marker_to_stderr,
    report_out: Path | None = None,
    expected_commit: str | None = None,
) -> int:
    """Run discovery and return unittest's success/failure exit status.

    The periodic-diagnostics factory, fatal-handler and marker-writer seams
    are injectable so focused tests can avoid touching process-global
    faulthandler state, stderr, or a live diagnostics thread.
    """
    output = sys.stderr if stream is None else stream
    # ``None`` means the unbuffered process stderr fd, not the TextIOWrapper:
    # the diagnostics thread must not participate in a buffered-I/O lock that
    # a forked child could inherit in a locked state.
    diagnostics = watchdog_stream
    emitter = _MarkerEmitter(marker_write)
    result = None

    def capture_result(active_result: unittest.TextTestResult) -> None:
        # Keep the outcomes recorded before a suite-level interruption.
        nonlocal result
        result = active_result

    result_class = _diagnostic_result_class(emitter, capture_result if report_out is not None else None)
    report_start = time.monotonic_ns() if report_out is not None else 0
    binding = _checkout_binding(expected_commit) if report_out is not None else None
    code = None
    stage = "setup"
    fatal_handler_owned = False
    watchdog = None
    watchdog_started = False
    try:
        try:
            fatal_handler_owned = _install_fatal_handler(
                is_enabled=is_fatal_handler_enabled,
                enable=enable_fatal_handler,
            )
            watchdog = diagnostics_factory(traceback_interval, diagnostics)
            watchdog.start()
            watchdog_started = True
            stage = "discovery"
            suite = discover(tests_dir)
            stage = "suite"
            result = unittest.TextTestRunner(
                stream=output, verbosity=2, resultclass=result_class
            ).run(suite)
            stage = "cleanup"
        finally:
            try:
                if watchdog_started:
                    watchdog.stop()
            finally:
                if fatal_handler_owned:
                    disable_fatal_handler()

        stage = "suite"
        # Match unittest.main.TestProgram.runTests: an empty selection with no
        # recorded skips exits 5, never 0, so an empty gate cannot go green.
        if result.testsRun == 0 and len(result.skipped) == 0:
            code = 5
        elif not result.wasSuccessful():
            code = 1
        elif emitter.failed:
            stage = "markers"
            code = 1
        else:
            code = 0
    finally:
        if report_out is not None:
            try:
                if binding is None or binding != _checkout_binding(expected_commit):
                    raise OSError("checkout binding unavailable")
                elapsed_ms = (time.monotonic_ns() - report_start) // 1_000_000
                _write_report(report_out, {
                    "version": 1,
                    "source_commit": binding[0],
                    "source_tree": binding[1],
                    "stage": stage,
                    "outcome": {None: "incomplete", 0: "passed", 1: "failed", 5: "empty"}[code],
                    "exit_code": code,
                    "elapsed_ms": min(max(elapsed_ms, 0), REPORT_MAX_ELAPSED_MS),
                    **_unittest_evidence(result),
                })
            except OSError:
                print("Python CI report unavailable", file=sys.stderr)
                if code == 0:
                    code = 1
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report-out", type=Path)
    parser.add_argument("--expected-commit")
    args = parser.parse_args(argv)
    if (args.report_out is None) != (args.expected_commit is None):
        parser.error("--report-out and --expected-commit must be supplied together")
    _restore_repo_root_import_context()
    return run(report_out=args.report_out, expected_commit=args.expected_commit)


if __name__ == "__main__":
    raise SystemExit(main())
