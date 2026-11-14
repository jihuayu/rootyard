#!/usr/bin/env python3
"""Run the CI Python unittest discovery with bounded log diagnostics.

The hosted verify job previously used the default non-verbose
``python3 -m unittest discover`` invocation, so a long-running case could not
be identified from the log. This runner keeps the existing selection and
result semantics:

* discover the existing ``tests/test_*.py`` set, in unittest order;
* run verbosely, keeping normal test-count, skip and failure/error handling;
* print every test id as it starts, to stderr;
* ask stdlib faulthandler for all-thread stack dumps every 120 seconds.

faulthandler reports thread stacks only; it does not dump locals, arguments or
the environment. The periodic timer is cancelled on every exit.
"""
from __future__ import annotations

import faulthandler
import sys
import unittest
from pathlib import Path
from typing import TextIO

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
TEST_PATTERN = "test_*.py"
TRACEBACK_INTERVAL_SECONDS = 120


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
) -> int:
    """Run discovery and return unittest's success/failure exit status."""
    output = sys.stderr if stream is None else stream
    diagnostics = sys.stderr if watchdog_stream is None else watchdog_stream
    faulthandler.dump_traceback_later(
        traceback_interval, repeat=True, file=diagnostics
    )
    try:
        suite = discover(tests_dir)
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        faulthandler.cancel_dump_traceback_later()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("usage: run_python_ci_tests.py", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
