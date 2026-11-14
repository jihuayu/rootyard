#!/usr/bin/env python3
"""Run the exact ignored PostgreSQL sandbox start-gate lock-order regression.

The test binary is a relocated ``rust-library-test`` produced by
``scripts/build_native_test.py --lib``.  This runner deliberately does not go
through Cargo: it executes that binary directly with the full libtest path,
``--exact``, ``--ignored`` and ``--test-threads=1``.  A ``--`` separator would
turn those flags into test-name filters, so none is emitted.

Acceptance is fail-closed:

* ``ROOTYARD_TEST_DATABASE_URL`` must be non-empty, because the Rust case
  otherwise returns success without exercising PostgreSQL;
* the adjacent original receipt must be a genuine Fresh=false
  ``rust-library-test`` with a relocated artifact, a rebuilt package, exactly
  one ``lib-test`` Fresh=false artifact for ``rootyard``, the library-test
  command shape, and digests matching the current binary, production source,
  lib-test support inputs, ``Cargo.lock`` and clean HEAD;
* the direct process is bounded, and the parsed output must contain exactly one
  passed case with the exact libtest name, zero failed and zero ignored.  An
  exit status of zero with zero executed tests is refused;
* binary, receipt, HEAD, source, support and lock bytes are sampled before and
  after execution and must be unchanged.

Raw Rust stdout/stderr is never printed, persisted or uploaded; failures carry
only an allowlisted stage and code.  On success the report is a credential-free
one-case JSON binding the relocated test binary SHA-256 to the receipt's source
commit.  Because this digest differs from the CLI server binary, callers bind it
with a separate ``scripts/native_report_manifest.py --mode job`` manifest.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

from build_native import ROOT, source_digest
from build_native_test import git_state, lib_test_support_digest, sha256_file

CASE = "sandbox::runner::tests::start_gate_serializes_context_removal_under_policy_fence"
REPORT_KIND = "rootyard/pg-start-gate-report"
STAGES = frozenset(
    ("environment", "receipt", "source", "execute", "parse", "immutable", "report", "internal")
)
CODES = frozenset(
    (
        "missing_database_url",
        "timeout_invalid",
        "binary_missing",
        "receipt_missing",
        "receipt_invalid",
        "receipt_kind",
        "receipt_not_relocated",
        "receipt_not_rebuilt",
        "receipt_fresh_artifact",
        "receipt_command",
        "stale_receipt",
        "binary_mismatch",
        "source_drift",
        "support_drift",
        "cargo_lock_drift",
        "worktree_dirty",
        "git_unavailable",
        "source_unavailable",
        "immutable_drift",
        "spawn_failed",
        "timeout",
        "test_failed",
        "zero_tests",
        "ignored_tests",
        "case_identity",
        "output_invalid",
        "report_write_failed",
        "internal_error",
    )
)
_TEST_ARGS = ("--exact", CASE, "--ignored", "--test-threads=1")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RUNNING = re.compile(r"^running (\d+) tests?$", re.MULTILINE)
_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    re.MULTILINE,
)
_ANY_CASE = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)$", re.MULTILINE)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


class GateError(RuntimeError):
    """A fail-closed refusal with only an allowlisted stage and code."""

    def __init__(self, stage, code):
        if stage not in STAGES or code not in CODES:
            raise ValueError("unregistered PG start-gate failure")
        super().__init__(code)
        self.stage = stage
        self.code = code


def _need(condition, stage, code):
    if not condition:
        raise GateError(stage, code)


def _require_database_url():
    value = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
    if not isinstance(value, str) or not value.strip():
        raise GateError("environment", "missing_database_url")


def _require_timeout(value):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
        or value > 3600
    ):
        raise GateError("environment", "timeout_invalid")
    return float(value)


def _validate_command(command):
    _need(
        isinstance(command, list)
        and command
        and all(isinstance(part, str) and part for part in command),
        "receipt",
        "receipt_command",
    )
    _need(command[0] == "cargo", "receipt", "receipt_command")
    for required in ("test", "--locked", "--lib", "--no-run"):
        _need(required in command, "receipt", "receipt_command")
    _need(
        "--test" not in command and "--bin" not in command,
        "receipt",
        "receipt_command",
    )
    _need(
        "--message-format=json-render-diagnostics" in command,
        "receipt",
        "receipt_command",
    )


def load_receipt(receipt_path, binary, expected_commit=None):
    """Read and validate the original rust-library-test receipt without rewriting it."""
    receipt_path = Path(receipt_path)
    binary = Path(binary)
    _need(
        receipt_path.is_file() and not receipt_path.is_symlink(),
        "receipt",
        "receipt_missing",
    )
    _need(
        binary.is_file() and os.access(binary, os.X_OK) and not binary.is_symlink(),
        "receipt",
        "binary_missing",
    )
    try:
        data = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise GateError("receipt", "receipt_invalid") from None
    _need(isinstance(data, dict), "receipt", "receipt_invalid")
    _need(data.get("kind") == "rust-library-test", "receipt", "receipt_kind")
    _need(data.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    _need(data.get("package_rebuilt") is True, "receipt", "receipt_not_rebuilt")
    _need(data.get("fresh") is False, "receipt", "receipt_fresh_artifact")
    artifacts = data.get("fresh_false_artifacts")
    _need(
        isinstance(artifacts, list) and len(artifacts) == 1,
        "receipt",
        "receipt_fresh_artifact",
    )
    artifact = artifacts[0]
    _need(isinstance(artifact, dict), "receipt", "receipt_fresh_artifact")
    _need(
        artifact.get("target") == "rootyard"
        and artifact.get("kind") == "lib-test"
        and artifact.get("fresh") is False,
        "receipt",
        "receipt_fresh_artifact",
    )
    _validate_command(data.get("command"))
    _need(
        isinstance(data.get("rustc"), str) and data["rustc"].strip(),
        "receipt",
        "receipt_invalid",
    )
    _need(
        isinstance(data.get("workspace_commit"), str)
        and _COMMIT.fullmatch(data["workspace_commit"]) is not None,
        "receipt",
        "receipt_invalid",
    )
    if expected_commit:
        _need(
            data["workspace_commit"] == expected_commit,
            "receipt",
            "stale_receipt",
        )
    for field in (
        "source_inputs_sha256",
        "lib_test_support_inputs_sha256",
        "cargo_lock_sha256",
        "binary_sha256",
        "original_artifact_sha256",
    ):
        _need(
            isinstance(data.get(field), str)
            and _SHA256.fullmatch(data[field]) is not None,
            "receipt",
            "receipt_invalid",
        )
    actual_binary = sha256_file(binary)
    _need(
        data["binary_sha256"] == actual_binary
        and data["original_artifact_sha256"] == actual_binary,
        "receipt",
        "binary_mismatch",
    )
    return {
        "kind": data["kind"],
        "binary_sha256": actual_binary,
        "original_artifact_sha256": data["original_artifact_sha256"],
        "workspace_commit": data["workspace_commit"],
        "source_inputs_sha256": data["source_inputs_sha256"],
        "lib_test_support_inputs_sha256": data["lib_test_support_inputs_sha256"],
        "cargo_lock_sha256": data["cargo_lock_sha256"],
        "command": list(data["command"]),
        "rustc": data["rustc"],
        "fresh_false_artifacts": [
            {"target": "rootyard", "kind": "lib-test", "fresh": False}
        ],
    }


def current_state(receipt, receipt_path, binary, expected_commit=None):
    """Revalidate the receipt against the current checkout and return safe hashes."""
    try:
        head, status = git_state()
    except Exception:
        raise GateError("source", "git_unavailable") from None
    _need(isinstance(head, str) and bool(head) and status is not None, "source", "git_unavailable")
    _need(not status.strip(), "source", "worktree_dirty")
    if expected_commit:
        _need(head == expected_commit, "source", "stale_receipt")
    _need(head == receipt["workspace_commit"], "source", "stale_receipt")
    try:
        source = source_digest()
        support = lib_test_support_digest()
        cargo_lock = sha256_file(Path(ROOT) / "Cargo.lock")
        binary_digest = sha256_file(binary)
        receipt_digest = sha256_file(receipt_path)
    except Exception:
        raise GateError("source", "source_unavailable") from None
    _need(source == receipt["source_inputs_sha256"], "source", "source_drift")
    _need(support == receipt["lib_test_support_inputs_sha256"], "source", "support_drift")
    _need(cargo_lock == receipt["cargo_lock_sha256"], "source", "cargo_lock_drift")
    _need(binary_digest == receipt["binary_sha256"], "source", "binary_mismatch")
    return {
        "head": head,
        "binary_sha256": binary_digest,
        "source_inputs_sha256": source,
        "lib_test_support_inputs_sha256": support,
        "cargo_lock_sha256": cargo_lock,
        "receipt_sha256": receipt_digest,
    }


def parse_test_output(text):
    """Parse the libtest summary; raise a fixed code rather than retain output."""
    text = _ANSI.sub("", text)
    running = _RUNNING.findall(text)
    results = _RESULT.findall(text)
    cases = _ANY_CASE.findall(text)
    _need(len(running) == 1, "parse", "output_invalid")
    _need(int(running[0]) == 1, "parse", "zero_tests")
    _need(len(results) == 1, "parse", "output_invalid")
    status, passed, failed, ignored = results[0]
    passed, failed, ignored = int(passed), int(failed), int(ignored)
    _need(not (passed == 0 and failed == 0 and ignored == 0), "parse", "zero_tests")
    _need(ignored == 0, "parse", "ignored_tests")
    _need(failed == 0 and status == "ok", "parse", "test_failed")
    _need(passed == 1, "parse", "zero_tests")
    _need(len(cases) == 1, "parse", "case_identity")
    name, outcome = cases[0]
    _need(name == CASE, "parse", "case_identity")
    _need(outcome == "ok", "parse", "test_failed")
    return {"passed": passed, "failed": failed, "ignored": ignored}


def execute_case(binary, timeout):
    command = [str(binary), *_TEST_ARGS]
    try:
        process = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GateError("execute", "timeout") from None
    except OSError:
        raise GateError("execute", "spawn_failed") from None
    if process.returncode != 0:
        # The captured output is deliberately discarded; it may contain SQL,
        # connection diagnostics or fixture credentials.
        raise GateError("execute", "test_failed")
    return parse_test_output(process.stdout or "")


def compare_immutable(start, end):
    checks = {
        "binary": start["binary_sha256"] == end["binary_sha256"],
        "source": start["source_inputs_sha256"] == end["source_inputs_sha256"],
        "support": start["lib_test_support_inputs_sha256"]
        == end["lib_test_support_inputs_sha256"],
        "cargo_lock": start["cargo_lock_sha256"] == end["cargo_lock_sha256"],
        "receipt": start["receipt_sha256"] == end["receipt_sha256"],
        "head": start["head"] == end["head"],
    }
    if not all(checks.values()):
        raise GateError("immutable", "immutable_drift")
    return checks


def _public_snapshot(snapshot):
    if snapshot is None:
        return None
    return {
        key: snapshot[key]
        for key in (
            "head",
            "binary_sha256",
            "source_inputs_sha256",
            "lib_test_support_inputs_sha256",
            "cargo_lock_sha256",
            "receipt_sha256",
        )
    }


def _receipt_summary(receipt):
    if receipt is None:
        return None
    return {
        "kind": receipt["kind"],
        "fresh": False,
        "relocated_artifact": True,
        "package_rebuilt": True,
        "fresh_false_artifacts": list(receipt["fresh_false_artifacts"]),
        "command": list(receipt["command"]),
        "rustc": receipt["rustc"],
    }


def _test_record(command, timeout, result):
    return {
        "case": CASE,
        "argv": list(command) if command else None,
        "timeout_seconds": timeout,
        "passed": result["passed"] if result else 0,
        "failed": result["failed"] if result else 0,
        "ignored": result["ignored"] if result else 0,
    }


def build_report(
    *,
    passed,
    receipt,
    start,
    end,
    test_result,
    command,
    timeout,
    failure=None,
    immutable=None,
):
    snapshot = start or end
    return {
        "kind": REPORT_KIND,
        "passed": bool(passed),
        "cases": [
            {
                "name": CASE,
                "status": "passed" if passed else "failed",
                **({} if passed else {"error_code": failure["code"]}),
            }
        ],
        "failure": failure,
        "test": _test_record(command, timeout, test_result),
        "binary_sha256": (
            snapshot["binary_sha256"]
            if snapshot is not None
            else _safe_binary_digest(command[0] if command else None)
        ),
        "source_head": (
            snapshot["head"] if snapshot is not None else _safe_head()
        ),
        "source_inputs_sha256": (
            snapshot["source_inputs_sha256"] if snapshot is not None else None
        ),
        "lib_test_support_inputs_sha256": (
            snapshot["lib_test_support_inputs_sha256"] if snapshot is not None else None
        ),
        "cargo_lock_sha256": (
            snapshot["cargo_lock_sha256"] if snapshot is not None else None
        ),
        "build_receipt_sha256": (
            snapshot["receipt_sha256"] if snapshot is not None else None
        ),
        "receipt_workspace_commit": (
            receipt["workspace_commit"] if receipt is not None else None
        ),
        "receipt": _receipt_summary(receipt),
        "start": _public_snapshot(start),
        "end": _public_snapshot(end),
        "immutable": immutable,
    }


def _safe_binary_digest(binary):
    try:
        path = Path(binary)
        if path.is_file():
            return sha256_file(path)
    except Exception:
        pass
    return None


def _safe_head():
    try:
        head, _ = git_state()
        return head if isinstance(head, str) and head else None
    except Exception:
        return None


def write_report(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _resolve_binary(raw):
    try:
        return Path(raw).expanduser().resolve()
    except (OSError, ValueError):
        return None


def _resolve_receipt(raw, binary):
    if raw:
        try:
            return Path(raw).expanduser().resolve()
        except (OSError, ValueError):
            return None
    if binary is None:
        return None
    return binary.with_suffix(".build.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, help="relocated rust-library-test executable")
    parser.add_argument("--build-receipt", help="receipt adjacent to the test binary by default")
    parser.add_argument("--report", type=Path, required=True, help="credential-free JSON report")
    parser.add_argument("--expected-commit", help="require the receipt and HEAD to equal this commit")
    parser.add_argument("--timeout", type=float, default=120.0, help="bounded direct-test timeout in seconds")
    args = parser.parse_args(argv)
    binary = _resolve_binary(args.test_binary)
    receipt_path = _resolve_receipt(args.build_receipt, binary)
    command = [str(binary), *_TEST_ARGS] if binary is not None else None
    receipt = None
    start = None
    end = None
    test_result = None
    immutable = None
    timeout = args.timeout
    try:
        timeout = _require_timeout(args.timeout)
        _need(binary is not None, "receipt", "binary_missing")
        _need(receipt_path is not None, "receipt", "receipt_missing")
        receipt = load_receipt(receipt_path, binary, args.expected_commit)
        start = current_state(receipt, receipt_path, binary, args.expected_commit)
        _require_database_url()
        test_result = execute_case(binary, timeout)
        try:
            end = current_state(receipt, receipt_path, binary, args.expected_commit)
        except GateError:
            raise GateError("immutable", "immutable_drift") from None
        immutable = compare_immutable(start, end)
        report = build_report(
            passed=True,
            receipt=receipt,
            start=start,
            end=end,
            test_result=test_result,
            command=command,
            timeout=timeout,
            immutable=immutable,
        )
        status = 0
    except GateError as error:
        report = build_report(
            passed=False,
            receipt=receipt,
            start=start,
            end=end,
            test_result=test_result,
            command=command,
            timeout=timeout,
            failure={"stage": error.stage, "code": error.code},
            immutable=immutable,
        )
        status = 1
    except Exception:
        report = build_report(
            passed=False,
            receipt=receipt,
            start=start,
            end=end,
            test_result=test_result,
            command=command,
            timeout=timeout,
            failure={"stage": "internal", "code": "internal_error"},
            immutable=immutable,
        )
        status = 1
    try:
        write_report(args.report, report)
    except OSError:
        print("pg start gate: report write failed", file=sys.stderr, flush=True)
        return 1
    if status == 0:
        print("pg start gate: passed (1 case)", flush=True)
    else:
        failure = report["failure"]
        print(
            f"pg start gate: failed ({failure['stage']}/{failure['code']})",
            flush=True,
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
