#!/usr/bin/env python3
"""Run exactly one named unittest and emit a sanitized acceptance receipt.

The #29 hosted witness is one existing ``unittest`` method.  Discovery would
silently turn a skipped or missing case into an acceptable run, so this helper
loads one exact dotted test id, rejects any other selection, requires exactly
one executed case, and treats a skip, expected failure, unexpected success or
ordinary failure as a hard failure.

The JSON receipt contains only fixed outcome strings, the exact test id, the
actual source commit/tree, and SHA-256 anchors for the supplied binary and build
receipt.  unittest's stream, tracebacks, environment, credentials, URLs and
filesystem paths are never copied into it.  The native report manifest binds the
receipt to the same immutable build receipt and binary as the rest of CI.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for _entry in (str(ROOT), str(TESTS)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

SCHEMA = "rootyard/named-unittest-report/v1"
TEST_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,255}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
LIMITATIONS = (
    "One exact named unittest invocation on one hosted Linux job; no discovery, retry or extra case is accepted.",
    "The workspace witness runs against a second data directory on the same host; it is not a distinct-machine or concurrent-GC proof.",
)


class RunFailure(Exception):
    """A fixed, non-disclosing failure classification."""

    def __init__(self, outcome: str):
        super().__init__(outcome)
        self.outcome = outcome


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def source_anchor() -> tuple[str, str]:
    try:
        process = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{commit}", "HEAD^{tree}"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RunFailure("source_anchor_unavailable") from None
    lines = process.stdout.splitlines()
    if process.returncode != 0 or len(lines) != 2 or not all(COMMIT.fullmatch(line) for line in lines):
        raise RunFailure("source_anchor_unavailable")
    return lines[0], lines[1]


def flatten(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        elif isinstance(item, unittest.TestCase):
            yield item
        else:
            raise RunFailure("selection_invalid")


def exact_suite(loader: unittest.TestLoader, name: str) -> unittest.TestSuite:
    if not TEST_ID.fullmatch(name) or ".." in name:
        raise RunFailure("selection_invalid")
    try:
        loaded = loader.loadTestsFromName(name)
        tests = list(flatten(loaded))
    except RunFailure:
        raise
    except Exception:
        raise RunFailure("selection_unavailable") from None
    ids = [test.id() for test in tests]
    if ids != [name]:
        raise RunFailure("selection_not_exact")
    return unittest.TestSuite(tests)


def classify(result: unittest.TextTestResult | None) -> tuple[str, dict]:
    if result is None:
        return "incomplete", {
            "scheduled": 1,
            "tests_run": 0,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
    counts = {
        "scheduled": 1,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    if result.testsRun != 1:
        return "incomplete", counts
    if result.skipped:
        return "skipped", counts
    if result.errors:
        return "error", counts
    if result.failures:
        return "failure", counts
    if result.expectedFailures:
        return "expected_failure", counts
    if result.unexpectedSuccesses:
        return "unexpected_success", counts
    if not result.wasSuccessful():
        return "failure", counts
    return "passed", counts


def write_report(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, prefix=path.name + ".", encoding="utf-8", delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--test", required=True, help="exact dotted unittest id")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--build-receipt", required=True, type=Path)
    parser.add_argument("--expect-commit")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)

    case_name = args.test if TEST_ID.fullmatch(args.test) else "<invalid-test-selection>"
    outcome = "runner_error"
    counts = {
        "scheduled": 1,
        "tests_run": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    source_head = source_tree = None
    binary_sha256 = build_receipt_sha256 = None

    try:
        binary = args.binary.expanduser().resolve()
        receipt = args.build_receipt.expanduser().resolve()
        if not (binary.is_file() and os.access(binary, os.X_OK)):
            raise RunFailure("binary_unavailable")
        if not receipt.is_file():
            raise RunFailure("build_receipt_unavailable")
        binary_sha256 = sha256_file(binary)
        build_receipt_sha256 = sha256_file(receipt)
        if not DIGEST.fullmatch(binary_sha256) or not DIGEST.fullmatch(build_receipt_sha256):
            raise RunFailure("digest_invalid")
        source_head, source_tree = source_anchor()
        if args.expect_commit is not None and source_head != args.expect_commit:
            raise RunFailure("source_mismatch")

        # The test's own runtime_binary selection must resolve this exact file.
        for variable in ("ROOTYARD_BIN", "ROOTYARD_TEST_BINARY", "ROOTYARD_BINARY"):
            os.environ[variable] = str(binary)
        os.environ["GITHUB_SHA"] = source_head
        os.environ["ROOTYARD_EXPECTED_SOURCE_COMMIT"] = source_head

        # Keep any loader/test print or unittest rendering out of the job log.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            suite = exact_suite(unittest.TestLoader(), args.test)
            result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        outcome, counts = classify(result)
    except RunFailure as error:
        outcome = error.outcome
    except Exception:
        outcome = "runner_error"

    passed = outcome == "passed"
    payload = {
        "schema": SCHEMA,
        "passed": passed,
        "outcome": outcome,
        "test_id": case_name,
        "cases": [{"name": case_name, "status": outcome}],
        "counts": counts,
        "source_head": source_head,
        "source_tree": source_tree,
        "binary_sha256": binary_sha256,
        "build_receipt_sha256": build_receipt_sha256,
        "limitations": list(LIMITATIONS),
    }
    try:
        write_report(args.report, payload)
    except OSError:
        print("named unittest: failed: report_unavailable", file=sys.stderr)
        return 1
    print("named unittest: " + outcome)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
