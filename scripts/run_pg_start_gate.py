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
* the adjacent original receipt is read only through the shared
  ``native_build_receipt`` v1/v2 reader.  Historical v1 receipts keep their
  exact legacy semantics: a rebuilt package, one Fresh=false ``rootyard``
  ``lib-test`` artifact, the library-test command shape and matching digests.
  v2 receipts instead require the selected ``lib-test`` artifact to be
  ``rootyard`` from ``src/lib.rs`` with the CI ``test`` profile and
  ``pando-lab`` features, the pinned full Cargo/Rust toolchain, and a clean
  current HEAD whose source, lib-test support, ``Cargo.lock`` and complete
  bound inventory all match the receipt.  Actual v2 ``fresh`` booleans are
  reported literally (true, false or mixed), never forced to false;
* the receipt's recorded v2 source snapshot is reported separately from the
  digest recomputed from this checkout, so it is never forged into "current";
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
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

import native_build_receipt as receipt_contract

# Shared-reader entry points are module attributes so focused tests can replace
# the environment probes with deterministic fixtures without a builder import.
git_state = receipt_contract.git_state
source_digest = receipt_contract.source_digest
sha256_file = receipt_contract.sha256_file

ROOT = Path(__file__).resolve().parents[1]
CARGO_FORK_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
CARGO_FORK_RELEASE = "1.101.0"
RUSTC_RELEASE = "1.99.1"

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


def _sha256(value):
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_legacy_v1_library(payload):
    """Keep the exact issue-#35 v1 library-test semantics.

    v1 receipts are historical evidence: they must still say the package was
    rebuilt from a non-fresh Cargo artifact and carry the original relocated
    executable digest.  No v2 rule is ever applied to them.
    """
    _need(payload.get("kind") == "rust-library-test", "receipt", "receipt_kind")
    _need(payload.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    _need(payload.get("package_rebuilt") is True, "receipt", "receipt_not_rebuilt")
    _need(payload.get("fresh") is False, "receipt", "receipt_fresh_artifact")
    artifacts = payload.get("fresh_false_artifacts")
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
    _validate_command(payload.get("command"))
    _need(
        isinstance(payload.get("rustc"), str) and payload["rustc"].strip(),
        "receipt",
        "receipt_invalid",
    )
    _need(
        isinstance(payload.get("workspace_commit"), str)
        and _COMMIT.fullmatch(payload["workspace_commit"]) is not None,
        "receipt",
        "receipt_invalid",
    )
    for field in (
        "source_inputs_sha256",
        "lib_test_support_inputs_sha256",
        "cargo_lock_sha256",
        "binary_sha256",
        "original_artifact_sha256",
    ):
        _need(_sha256(payload.get(field)), "receipt", "receipt_invalid")


def _validate_v2_library(validated):
    """Bind the shared v2 reader to the exact selected lib-test artifact."""
    payload = validated.payload
    _need(payload.get("kind") == "rust-library-test", "receipt", "receipt_kind")
    _need(payload.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    _validate_command(payload.get("command"))
    features = payload.get("features")
    _need(
        isinstance(features, dict)
        and features.get("enabled") == ["pando-lab"]
        and features.get("no_default_features") is False,
        "receipt",
        "receipt_invalid",
    )
    _need(payload.get("profile") == "test", "receipt", "receipt_invalid")
    executable_rows = [
        row
        for row in validated.artifacts
        if row.get("kind") in receipt_contract.EXECUTABLE_KINDS
    ]
    _need(len(executable_rows) == 1, "receipt", "receipt_invalid")
    artifact = executable_rows[0]
    _need(
        artifact.get("kind") == "lib-test"
        and artifact.get("target") == "rootyard"
        and artifact.get("source") == "src/lib.rs"
        and artifact.get("profile", {}).get("test") is True,
        "receipt",
        "receipt_invalid",
    )
    _need(
        all(row.get("kind") == "lib" for row in validated.artifacts if row is not artifact),
        "receipt",
        "receipt_invalid",
    )
    _need(_sha256(payload.get("lib_test_support_inputs_sha256")), "receipt", "receipt_invalid")
    _need(_sha256(payload.get("cargo_lock_sha256")), "receipt", "receipt_invalid")
    toolchain = validated.toolchain
    _need(toolchain is not None, "receipt", "receipt_invalid")
    cargo = toolchain.get("cargo")
    rustc = toolchain.get("rustc")
    _need(
        isinstance(cargo, dict)
        and cargo.get("commit_hash") == CARGO_FORK_COMMIT
        and cargo.get("release") == CARGO_FORK_RELEASE
        and isinstance(rustc, dict)
        and rustc.get("release") == RUSTC_RELEASE,
        "receipt",
        "receipt_invalid",
    )


def load_receipt(receipt_path, binary, expected_commit=None):
    """Read the receipt through the shared v1/v2 reader without rewriting it."""
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
        raw = receipt_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        raise GateError("receipt", "receipt_invalid") from None
    _need(isinstance(payload, dict), "receipt", "receipt_invalid")
    schema_v2 = "receipt_schema" in payload
    actual_binary = sha256_file(binary)
    if not schema_v2:
        _validate_legacy_v1_library(payload)
        if expected_commit:
            _need(payload["workspace_commit"] == expected_commit, "receipt", "stale_receipt")
        _need(
            payload["binary_sha256"] == actual_binary
            and payload["original_artifact_sha256"] == actual_binary,
            "receipt",
            "binary_mismatch",
        )
    else:
        _need(_sha256(payload.get("binary_sha256")), "receipt", "receipt_invalid")
        _need(payload["binary_sha256"] == actual_binary, "receipt", "binary_mismatch")
        if expected_commit:
            _need(payload.get("workspace_commit") == expected_commit, "receipt", "stale_receipt")
    try:
        validated = receipt_contract.validate_receipt(
            payload,
            source_root=None,
            receipt_path=receipt_path,
            receipt_sha256=receipt_contract.sha256_bytes(raw),
            binary_path=binary,
            expected_commit=expected_commit,
            verify_source_files=False,
        )
    except receipt_contract.ReceiptError:
        raise GateError("receipt", "receipt_invalid") from None
    if schema_v2:
        _validate_v2_library(validated)
    else:
        _need(validated.schema == "v1", "receipt", "receipt_invalid")
    return validated


def _support_digest():
    """The exact test-support digest over the shared v2 bound inventory."""
    entries, _blobs = receipt_contract.bound_input_inventory(ROOT)
    digest = hashlib.sha256()
    for entry in sorted(
        (item for item in entries if item["role"] == "test_support" and item["present"]),
        key=lambda item: item["path"],
    ):
        digest.update(entry["path"].encode() + b"\0")
        digest.update(bytes.fromhex(entry["sha256"]))
    return digest.hexdigest()


def lib_test_support_digest():
    return _support_digest()


def current_state(receipt, receipt_path, binary, expected_commit=None):
    """Revalidate the receipt against the current checkout and return safe hashes.

    For v2 the report keeps the receipt's recorded source snapshot separate from
    the digest recomputed from this checkout.  The two are compared as a strict
    freshness guard, but the recorded value is never relabelled as "current".
    """
    try:
        state = git_state(ROOT)
    except Exception:
        raise GateError("source", "git_unavailable") from None
    head = state.get("head") if isinstance(state, dict) else None
    status = state.get("status") if isinstance(state, dict) else None
    _need(isinstance(head, str) and bool(head) and status is not None, "source", "git_unavailable")
    _need(not status.strip(), "source", "worktree_dirty")
    if expected_commit:
        _need(head == expected_commit, "source", "stale_receipt")
    _need(head == receipt.workspace_commit, "source", "stale_receipt")
    payload = receipt.payload
    try:
        source = source_digest(ROOT)
        support = lib_test_support_digest()
        cargo_lock = sha256_file(Path(ROOT) / "Cargo.lock")
        binary_digest = sha256_file(binary)
        receipt_digest = sha256_file(receipt_path)
    except Exception:
        raise GateError("source", "source_unavailable") from None
    _need(source == receipt.source_inputs_sha256, "source", "source_drift")
    _need(support == payload["lib_test_support_inputs_sha256"], "source", "support_drift")
    _need(cargo_lock == payload["cargo_lock_sha256"], "source", "cargo_lock_drift")
    _need(binary_digest == receipt.binary_sha256, "source", "binary_mismatch")
    bound_inputs_digest = None
    if receipt.schema == "v2":
        try:
            entries, blobs = receipt_contract.bound_input_inventory(ROOT)
            summary = receipt_contract.bound_inputs_summary(entries, blobs)
            current_config = receipt_contract.config_digest(entries, blobs)
        except Exception:
            raise GateError("source", "source_unavailable") from None
        _need(summary == payload.get("bound_inputs"), "source", "source_drift")
        _need(current_config == receipt.config_digest, "source", "source_drift")
        bound_inputs_digest = summary["digest"]
    return {
        "schema": receipt.schema,
        "head": head,
        "binary_sha256": binary_digest,
        "source_inputs_sha256": source,
        "receipt_source_inputs_sha256": receipt.source_inputs_sha256,
        "lib_test_support_inputs_sha256": support,
        "cargo_lock_sha256": cargo_lock,
        "bound_inputs_digest": bound_inputs_digest,
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
        "schema": start["schema"] == end["schema"],
        "receipt_source": start["receipt_source_inputs_sha256"]
        == end["receipt_source_inputs_sha256"],
        "bound_inputs": start.get("bound_inputs_digest") == end.get("bound_inputs_digest"),
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
            "schema",
            "head",
            "binary_sha256",
            "source_inputs_sha256",
            "receipt_source_inputs_sha256",
            "lib_test_support_inputs_sha256",
            "cargo_lock_sha256",
            "bound_inputs_digest",
            "receipt_sha256",
        )
    }


def _fresh_rollup(rows):
    if not rows:
        return None
    values = {row["fresh"] for row in rows}
    if values == {True}:
        return True
    if values == {False}:
        return False
    return "mixed"


def _receipt_summary(receipt):
    if receipt is None:
        return None
    payload = receipt.payload
    summary = {
        "schema": receipt.schema,
        "kind": payload.get("kind"),
        "relocated_artifact": payload.get("relocated_artifact"),
        "command": list(payload["command"]),
    }
    if receipt.schema == "v1":
        summary.update(
            {
                "fresh": False,
                "package_rebuilt": True,
                "fresh_false_artifacts": [
                    {
                        "target": row["target"],
                        "kind": row["kind"],
                        "fresh": row["fresh"],
                    }
                    for row in payload["fresh_false_artifacts"]
                ],
                "rustc": payload["rustc"],
            }
        )
    else:
        artifacts = [
            {
                "target": row["target"],
                "kind": row["kind"],
                "fresh": row["fresh"],
                "source": row["source"],
            }
            for row in receipt.artifacts
        ]
        toolchain = receipt.toolchain or {}
        summary.update(
            {
                "fresh": _fresh_rollup(artifacts),
                "cargo_artifacts": artifacts,
                "features": dict(payload.get("features") or {}),
                "profile": payload.get("profile"),
                "target_triple": payload.get("target_triple"),
                "toolchain": {
                    "cargo": {
                        key: toolchain.get("cargo", {}).get(key)
                        for key in ("release", "commit_hash")
                    },
                    "rustc": {
                        key: toolchain.get("rustc", {}).get(key)
                        for key in ("release", "commit_hash")
                    },
                },
            }
        )
    return summary


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
        "receipt_schema": (
            snapshot["schema"] if snapshot is not None else None
        ),
        "receipt_source_inputs_sha256": (
            snapshot["receipt_source_inputs_sha256"] if snapshot is not None else None
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
            receipt.workspace_commit if receipt is not None else None
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
        state = git_state(ROOT)
        head = state.get("head") if isinstance(state, dict) else None
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
