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
* ask stdlib faulthandler for all-thread stack dumps every 120 seconds.

faulthandler reports thread stacks only; it does not dump locals, arguments,
the environment, or a core file. The periodic timer is cancelled on every exit.
"""
from __future__ import annotations

from collections.abc import Callable
import faulthandler
import sys
import unittest
from pathlib import Path
from typing import TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
TESTS_DIR = ROOT / "tests"
TEST_PATTERN = "test_*.py"
TRACEBACK_INTERVAL_SECONDS = 120


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
) -> int:
    """Run discovery and return unittest's success/failure exit status.

    Timer and fatal-handler seams are injectable so focused tests can avoid
    touching the process-global faulthandler state owned by an outer
    full-suite runner.
    """
    output = sys.stderr if stream is None else stream
    diagnostics = sys.stderr if watchdog_stream is None else watchdog_stream
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
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        # Match unittest.main.TestProgram.runTests: an empty selection with no
        # recorded skips exits 5, never 0, so an empty gate cannot go green.
        if result.testsRun == 0 and len(result.skipped) == 0:
            return 5
        return 0 if result.wasSuccessful() else 1
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
