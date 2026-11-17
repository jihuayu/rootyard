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
* ask stdlib faulthandler for all-thread stack dumps every 120 seconds.

faulthandler reports thread stacks only; it does not dump locals, arguments,
the environment, or a core file. The per-test markers are written immediately
with ``os.write`` and never contain a raw test id, description, failure text or
other unbounded value. The periodic timer is cancelled on every exit.
"""
from __future__ import annotations

from collections.abc import Callable
import faulthandler
import hashlib
import os
import sys
import unittest
from pathlib import Path
from typing import TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
TESTS_DIR = ROOT / "tests"
TEST_PATTERN = "test_*.py"
TRACEBACK_INTERVAL_SECONDS = 120

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
) -> type[unittest.TextTestResult]:
    """Return a TextTestResult that emits one START/DONE pair per test."""

    class _DiagnosticTextTestResult(unittest.TextTestResult):
        def startTest(self, test: unittest.TestCase) -> None:
            super().startTest(test)
            emitter.emit(MARKER_STATE_START, self.testsRun, test)

        def stopTest(self, test: unittest.TestCase) -> None:
            try:
                emitter.emit(MARKER_STATE_DONE, self.testsRun, test)
            finally:
                super().stopTest(test)

    return _DiagnosticTextTestResult


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


def run(
    tests_dir: Path = TESTS_DIR,
    *,
    stream: TextIO | None = None,
    watchdog_stream: TextIO | None = None,
    traceback_interval: float = TRACEBACK_INTERVAL_SECONDS,
    start_timer: Callable[..., None] = faulthandler.dump_traceback_later,
    stop_timer: Callable[[], None] = faulthandler.cancel_dump_traceback_later,
    enable_fatal_handler: Callable[..., None] = faulthandler.enable,
    disable_fatal_handler: Callable[[], None] = faulthandler.disable,
    is_fatal_handler_enabled: Callable[[], bool] = faulthandler.is_enabled,
    marker_write: Callable[[bytes], int] = _write_marker_to_stderr,
) -> int:
    """Run discovery and return unittest's success/failure exit status.

    Timer, fatal-handler and marker-writer seams are injectable so focused
    tests can avoid touching the process-global faulthandler state and stderr
    owned by an outer full-suite runner.
    """
    output = sys.stderr if stream is None else stream
    diagnostics = sys.stderr if watchdog_stream is None else watchdog_stream
    emitter = _MarkerEmitter(marker_write)
    result_class = _diagnostic_result_class(emitter)
    fatal_handler_owned = False
    timer_started = False
    try:
        fatal_handler_owned = _install_fatal_handler(
            is_enabled=is_fatal_handler_enabled,
            enable=enable_fatal_handler,
        )
        start_timer(traceback_interval, repeat=True, file=diagnostics)
        timer_started = True
        suite = discover(tests_dir)
        result = unittest.TextTestRunner(
            stream=output, verbosity=2, resultclass=result_class
        ).run(suite)
        # Match unittest.main.TestProgram.runTests: an empty selection with no
        # recorded skips exits 5, never 0, so an empty gate cannot go green.
        if result.testsRun == 0 and len(result.skipped) == 0:
            return 5
        code = 0 if result.wasSuccessful() else 1
        # Marker failures must never hide a real failure or an empty selection,
        # but they must not leave an otherwise green run green either.
        return 1 if emitter.failed else code
    finally:
        try:
            if timer_started:
                stop_timer()
        finally:
            if fatal_handler_owned:
                disable_fatal_handler()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("usage: run_python_ci_tests.py", file=sys.stderr)
        return 2
    _restore_repo_root_import_context()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
