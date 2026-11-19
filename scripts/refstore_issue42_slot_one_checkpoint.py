#!/usr/bin/env python3
"""Bounded CI checkpoint for the exact #42 slot-one native replay case.

The workflow already builds one immutable, preflight-bound #174 libtest
artifact and owns a disposable PostgreSQL 17 database and Garage scope.  This
module only re-anchors that artifact to the current HEAD/source tree, proves
the fixed case is present exactly once, runs the single selected ignored case
with ``--exact --test-threads=1``, and writes a closed, raw-output-free report.

The selector/listing and result/report parsers are importable without touching
a database, the network, Cargo, rustc, native services or the local runtime.
They are covered by focused pure regressions in
``tests/test_refstore_issue42_slot_one_checkpoint.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

CASE = (
    "ref_store::pg::slot_one::tests::native::"
    "slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5"
)
REPORT_SCHEMA = "rootyard/refstore-issue42-slot-one-checkpoint/v1"

# Fixed failure-stage observations for the two reviewed Slot-One handoff
# cases. The native fixture emits these only on failure; the runner keeps the
# last strictly increasing value and never persists any other console text.
FAILURE_STAGE_PREFIX = "ROOTYARD_SLOT_ONE_STAGE="
FAILURE_STAGES = (
    "fixture_guard",
    "db_setup",
    "postgres17",
    "blob_git",
    "retire_p0",
    "retire_serving",
    "retire_admit",
    "retire_stage",
    "retire_p1",
    "retire_reject",
    "retire_mirror",
    "retire_evidence",
    "gateway_state",
    "live_serving",
    "baseline",
    "rotation",
    "fresh_assertions",
    "a3_a4_stage",
    "authorized_commit",
    "a5_snapshot",
    "terminal",
    "wrapper",
    "public_status",
    "revoke",
    "restore",
    "fresh_positive",
    "later_gate",
    "replay",
    "revoked_replay",
    "restored_replay",
    "cleanup",
)
FAILURE_STAGE_UNAVAILABLE = "stage_unavailable"
FAILURE_STAGE_LINE = re.compile(r"^ROOTYARD_SLOT_ONE_STAGE=([a-z0-9_]+)$")
CAPTURE_HEADER = re.compile(r"^---- (.+) (stdout|stderr) ----$")

DEFAULT_TIMEOUT_SECONDS = 600.0
DEFAULT_STDOUT_LIMIT = 16 * 1024
LISTING_STDOUT_LIMIT = 1 << 20
KILL_GRACE_SECONDS = 5.0

SUMMARY = re.compile(
    r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$",
    re.M,
)
CASE_LINE = re.compile(r"^test (.+) \.\.\. (ok|FAILED|failed|ignored|bench)$")
EXPECTED_SUMMARY = ("ok", "1", "0", "0", "0")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TREE = re.compile(r"^[0-9a-f]{40,64}$")

PROCESS_OUTCOMES = frozenset({
    "exited", "timed_out", "output_limit", "spawn_failed", "runner_error",
    "cleanup_failed",
})
ERROR_CLASSES = frozenset({
    "timeout", "output_limit", "spawn", "runner", "cleanup", "output_malformed",
    "case_missing", "case_multiple", "case_wrong", "case_skipped", "case_failed",
    "summary_missing", "summary_multiple", "summary_not_exact", "exit",
})
REPORT_FIELDS = (
    "schema", "case", "expected_commit", "head", "tree",
    "source_inputs_sha256", "lib_test_support_inputs_sha256",
    "receipt_sha256", "binary_sha256", "lib_alias", "preflight_sha256",
    "selection", "exit_code", "process_outcome", "ran", "passed", "failed",
    "ignored", "complete", "result", "error_class",
)
ATTESTATION_FIELDS = REPORT_FIELDS[:12]


class CheckpointError(RuntimeError):
    """A safe, already-projected checkpoint failure."""


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_command(lib, name=CASE):
    """The single fixed selector used for the new checkpoint."""
    return [str(lib), "--ignored", "--exact", name, "--test-threads=1"]


def listing_command(lib):
    return [str(lib), "--list", "--ignored", "--format", "terse"]


def parse_listing(raw):
    """Parse a terse libtest listing without accepting surprise lines."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CheckpointError("listing_malformed") from error
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.endswith(": test"):
            raise CheckpointError("listing_malformed")
        name = line[: -len(": test")]
        if not name or name != name.strip():
            raise CheckpointError("listing_malformed")
        names.append(name)
    return names


def require_membership(names, expected=CASE):
    """Require exactly one compiled occurrence of the selected case."""
    count = names.count(expected)
    if count == 0:
        raise CheckpointError("selection_missing")
    if count != 1:
        raise CheckpointError("selection_duplicate")
    return "unique"


def _failed(error_class, *, ran=0, ignored=0):
    return {
        "ran": int(bool(ran)),
        "complete": False,
        "passed": 0,
        "failed": 1,
        "ignored": int(bool(ignored)),
        "error_class": error_class,
    }


def classify_result(raw, exit_code, *, outcome="exited", error_class=None,
                    expected=CASE):
    """Project one bounded stdout view into the closed pass/fail fields.

    Missing, duplicated, wrong, skipped, failed, summary-less, summary-double,
    non-exact-summary, non-zero-exit and bounded-process failures all fail.
    No child output is returned or persisted.
    """
    if outcome != "exited":
        return _failed(error_class if error_class in ERROR_CLASSES else "runner")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return _failed("runner")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _failed("output_malformed")
    lines = text.splitlines()
    if any(
        line.startswith("test ")
        and not line.startswith("test result: ")
        and CASE_LINE.fullmatch(line) is None
        for line in lines
    ):
        return _failed("output_malformed")
    rows = []
    for line in lines:
        match = CASE_LINE.fullmatch(line)
        if match is not None:
            rows.append((match.group(1), match.group(2)))
    if not rows:
        return _failed("case_missing")
    if len(rows) != 1:
        return _failed("case_multiple")
    name, status = rows[0]
    if name != expected:
        return _failed("case_wrong")
    if status == "ignored":
        return _failed("case_skipped", ignored=1)
    if status != "ok":
        return _failed("case_failed", ran=True)
    summaries = SUMMARY.findall(text)
    if not summaries:
        return _failed("summary_missing", ran=True)
    if len(summaries) != 1:
        return _failed("summary_multiple", ran=True)
    if tuple(summaries[0][:5]) != EXPECTED_SUMMARY:
        return _failed("summary_not_exact", ran=True)
    if exit_code != 0:
        return _failed("exit", ran=True)
    return {
        "ran": 1,
        "complete": True,
        "passed": 1,
        "failed": 0,
        "ignored": 0,
        "error_class": None,
    }


def classify_failure_stage(raw, *, expected=CASE, sequence=FAILURE_STAGES):
    """Return one stage only from the exact FAILED row and its stdout block.

    The pinned libtest pretty formatter places the combined captured stream,
    including stderr markers, under one ``---- <case> stdout ----`` header.
    The caller must already have projected ``case_failed``; this function
    independently requires one exact FAILED row, one exact failure summary, and
    exactly that one stdout capture block for the same case. Any additional,
    stderr, duplicate or foreign capture header is closed as
    ``stage_unavailable``, as are malformed or out-of-order markers. No raw
    output is returned or persisted.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return FAILURE_STAGE_UNAVAILABLE
    summaries = SUMMARY.findall(text)
    if len(summaries) != 1 or tuple(summaries[0][:5]) != ("FAILED", "0", "1", "0", "0"):
        return FAILURE_STAGE_UNAVAILABLE
    lines = text.splitlines()
    rows = []
    for line in lines:
        match = CASE_LINE.fullmatch(line.strip())
        if match is not None:
            rows.append((match.group(1), match.group(2)))
    if len(rows) != 1:
        return FAILURE_STAGE_UNAVAILABLE
    name, status = rows[0]
    if name != expected or status not in ("FAILED", "failed"):
        return FAILURE_STAGE_UNAVAILABLE
    headers = []
    for index, line in enumerate(lines):
        match = CAPTURE_HEADER.fullmatch(line.strip())
        if match is not None:
            headers.append((index, match.group(1), match.group(2)))
    if any(header_name != expected for _index, header_name, _stream in headers):
        return FAILURE_STAGE_UNAVAILABLE
    if len(headers) != 1 or headers[0][2] != "stdout":
        return FAILURE_STAGE_UNAVAILABLE
    start = headers[0][0] + 1
    end = None
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if CAPTURE_HEADER.fullmatch(stripped) is not None:
            end = index
            break
        if stripped.startswith("failures:") or stripped.startswith("test result:"):
            end = index
            break
    if end is None:
        return FAILURE_STAGE_UNAVAILABLE
    stages = []
    for line in lines[start:end]:
        stripped = line.strip()
        if not stripped.startswith(FAILURE_STAGE_PREFIX):
            continue
        match = FAILURE_STAGE_LINE.fullmatch(stripped)
        if match is None:
            return FAILURE_STAGE_UNAVAILABLE
        stage = match.group(1)
        if stage not in sequence:
            return FAILURE_STAGE_UNAVAILABLE
        stages.append(stage)
    if not stages:
        return FAILURE_STAGE_UNAVAILABLE
    if stages[-1] == "cleanup":
        if tuple(stages[:-1]) != tuple(sequence[:-1]):
            return FAILURE_STAGE_UNAVAILABLE
    elif tuple(stages) != tuple(sequence[:len(stages)]):
        return FAILURE_STAGE_UNAVAILABLE
    return stages[-1]


def make_report(attestation, projection, exit_code, process_outcome,
                *, schema=REPORT_SCHEMA, case=CASE):
    """Merge source attestations and one projection into the closed report."""
    report = dict(attestation)
    report.update({
        "exit_code": exit_code,
        "process_outcome": process_outcome,
        "ran": int(projection["ran"]),
        "passed": int(projection["passed"]),
        "failed": int(projection["failed"]),
        "ignored": int(projection["ignored"]),
        "complete": bool(projection["complete"]),
        "result": "passed" if projection["complete"] else "failed",
        "error_class": projection["error_class"],
    })
    validate_report(report, schema=schema, case=case)
    return report


def validate_report(report, *, schema=REPORT_SCHEMA, case=CASE):
    """Reject anything that is not the one closed, self-consistent report."""
    if not isinstance(report, dict) or set(report) != set(REPORT_FIELDS):
        raise CheckpointError("report_shape")
    if report.get("schema") != schema:
        raise CheckpointError("report_schema")
    if report.get("case") != case:
        raise CheckpointError("report_case")
    for key in ("expected_commit", "head"):
        if not isinstance(report.get(key), str) or COMMIT.fullmatch(report[key]) is None:
            raise CheckpointError("report_" + key)
    if report["expected_commit"] != report["head"]:
        raise CheckpointError("report_head")
    if not isinstance(report.get("tree"), str) or TREE.fullmatch(report["tree"]) is None:
        raise CheckpointError("report_tree")
    for key in ("source_inputs_sha256", "lib_test_support_inputs_sha256",
                "receipt_sha256", "binary_sha256", "preflight_sha256"):
        if not isinstance(report.get(key), str) or HEX64.fullmatch(report[key]) is None:
            raise CheckpointError("report_" + key)
    if not isinstance(report.get("lib_alias"), str) or not report["lib_alias"]:
        raise CheckpointError("report_lib_alias")
    if report.get("selection") != "unique":
        raise CheckpointError("report_selection")
    if report.get("process_outcome") not in PROCESS_OUTCOMES:
        raise CheckpointError("report_process_outcome")
    exit_code = report.get("exit_code")
    if exit_code is not None and (not isinstance(exit_code, int)
                                  or isinstance(exit_code, bool)):
        raise CheckpointError("report_exit_code")
    for key in ("ran", "passed", "failed", "ignored"):
        value = report.get(key)
        if (not isinstance(value, int) or isinstance(value, bool)
                or value not in (0, 1)):
            raise CheckpointError("report_" + key)
    if not isinstance(report.get("complete"), bool):
        raise CheckpointError("report_complete")
    if report.get("result") not in ("passed", "failed"):
        raise CheckpointError("report_result")
    error = report.get("error_class")
    if error is not None and (not isinstance(error, str) or error not in ERROR_CLASSES):
        raise CheckpointError("report_error_class")
    if report["complete"]:
        if (report["result"] != "passed" or report["ran"] != 1
                or report["passed"] != 1 or report["failed"] != 0
                or report["ignored"] != 0 or report["exit_code"] != 0
                or report["process_outcome"] != "exited" or error is not None):
            raise CheckpointError("report_complete_inconsistent")
    else:
        if (report["result"] != "failed" or report["passed"] != 0
                or report["failed"] != 1 or not error):
            raise CheckpointError("report_failure_inconsistent")
    return report


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(payload)
    os.replace(temporary, path)


def recheck_report(path, *, schema=REPORT_SCHEMA, case=CASE):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise CheckpointError("report_recheck") from error
    return validate_report(payload, schema=schema, case=case)


def _readonly_file(path, label):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise CheckpointError(label + "_path")
    if path.is_symlink() or not path.is_file():
        raise CheckpointError(label + "_file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise CheckpointError(label + "_file")
    if info.st_uid != os.geteuid():
        raise CheckpointError(label + "_owner")
    if info.st_mode & 0o222:
        raise CheckpointError(label + "_writable")
    return path


def _git(workspace, *arguments):
    try:
        process = subprocess.run(
            ["git", *arguments], cwd=workspace, text=True, capture_output=True,
            check=False)
    except OSError as error:
        raise CheckpointError("source_tree") from error
    if process.returncode != 0:
        raise CheckpointError("source_tree")
    return process.stdout.strip()


def load_preflight(path):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise CheckpointError("preflight_unreadable") from error
    if not isinstance(payload, dict) or payload.get("passed") is not True:
        raise CheckpointError("preflight_not_passed")
    return payload


def build_attestation(lib, receipt, preflight_path, workspace, expected_commit,
                      *, schema=REPORT_SCHEMA, case=CASE):
    """Re-anchor the exact preflighted #174 libtest to HEAD and its sources."""
    workspace = Path(workspace).resolve()
    lib = _readonly_file(lib, "lib_alias")
    receipt = _readonly_file(receipt, "lib_receipt")
    preflight_path = Path(preflight_path)
    preflight = load_preflight(preflight_path)
    if not isinstance(expected_commit, str) or COMMIT.fullmatch(expected_commit) is None:
        raise CheckpointError("expected_commit")
    head = _git(workspace, "rev-parse", "HEAD")
    tree = _git(workspace, "rev-parse", "HEAD^{tree}")
    if head != expected_commit or preflight.get("head") != head:
        raise CheckpointError("build_sha")
    if str(lib.resolve()) != preflight.get("lib_alias"):
        raise CheckpointError("preflight_lib_alias")
    if sha256_file(lib) != preflight.get("lib_binary_sha256"):
        raise CheckpointError("preflight_binary_sha256")
    record = preflight.get("lib_receipt")
    if not isinstance(record, dict):
        raise CheckpointError("preflight_lib_receipt")
    if sha256_file(receipt) != record.get("sha256"):
        raise CheckpointError("preflight_receipt_sha256")
    if Path(record.get("path") or "").resolve() != receipt.resolve():
        raise CheckpointError("preflight_receipt_path")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import native_build_receipt as receipts
    try:
        validated = receipts.load_receipt(
            receipt, binary_path=lib, expected_commit=head,
            source_root=workspace, verify_source_files=True)
    except (receipts.ReceiptError, OSError) as error:
        raise CheckpointError("receipt_invalid") from error
    if validated.schema != preflight.get("receipt_schema"):
        raise CheckpointError("receipt_schema")
    if validated.workspace_commit != head:
        raise CheckpointError("receipt_commit")
    if validated.receipt_sha256 != record.get("sha256"):
        raise CheckpointError("receipt_sha256")
    if validated.binary_sha256 != preflight.get("lib_binary_sha256"):
        raise CheckpointError("receipt_binary_sha256")
    if validated.source_inputs_sha256 != preflight.get("source_inputs_sha256"):
        raise CheckpointError("receipt_source_digest")
    payload = validated.payload
    if payload.get("kind") != "rust-library-test":
        raise CheckpointError("receipt_kind")
    if payload.get("relocated_artifact") is not True:
        raise CheckpointError("receipt_relocated")
    support = payload.get("lib_test_support_inputs_sha256")
    if (not isinstance(support, str) or HEX64.fullmatch(support) is None
            or support != preflight.get("lib_test_support_inputs_sha256")):
        raise CheckpointError("receipt_support_digest")
    artifacts = list(validated.artifacts)
    if len(artifacts) != 1:
        raise CheckpointError("receipt_artifact")
    artifact = artifacts[0]
    if artifact.get("kind") != "lib-test" or artifact.get("target") != "rootyard":
        raise CheckpointError("receipt_artifact")
    if validated.schema == "v2" and artifact.get("executable_sha256") != validated.binary_sha256:
        raise CheckpointError("receipt_artifact_sha256")
    return {
        "schema": schema,
        "case": case,
        "expected_commit": expected_commit,
        "head": head,
        "tree": tree,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "lib_test_support_inputs_sha256": support,
        "receipt_sha256": validated.receipt_sha256,
        "binary_sha256": validated.binary_sha256,
        "lib_alias": str(lib.resolve()),
        "preflight_sha256": sha256_file(preflight_path),
        "selection": "unique",
    }


def apply_lib_alias_label(attestation, label):
    """Replace the verified resolved path with a fixed public report label.

    Internal attestation and receipt checks have already validated the exact
    resolved libtest path before this projection. ``None`` keeps the legacy
    slot-one report shape/value unchanged; an explicit label must be a simple
    anonymous token, never a path or credential-bearing value.
    """
    if label is None:
        return attestation
    if not isinstance(label, str) or re.fullmatch(
            r"[A-Za-z0-9._#-]{1,64}", label) is None:
        raise CheckpointError("lib_alias_label")
    attestation["lib_alias"] = label
    return attestation


def _signal_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _terminate(process):
    _signal_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
        return True
    except subprocess.TimeoutExpired:
        _signal_group(process, signal.SIGKILL)
    except OSError:
        return False
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False


def run_bounded(command, *, timeout, stdout_limit, environment=None):
    """Capture at most ``stdout_limit`` bytes; stderr is never retained."""
    deadline = time.monotonic() + max(float(timeout), 1.0)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
    except OSError:
        return {"outcome": "spawn_failed", "exit_code": None,
                "stdout": b"", "error_class": "spawn"}
    raw = []
    total = 0
    outcome = "exited"
    error_class = None
    selector = None
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "timed_out"
                error_class = "timeout"
                break
            if not selector.select(min(remaining, 0.5)):
                continue
            try:
                chunk = os.read(process.stdout.fileno(), 8192)
            except BlockingIOError:
                continue
            if not chunk:
                break
            if total + len(chunk) > stdout_limit:
                outcome = "output_limit"
                error_class = "output_limit"
                break
            total += len(chunk)
            raw.append(chunk)
        if outcome == "exited":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "timed_out"
                error_class = "timeout"
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    outcome = "timed_out"
                    error_class = "timeout"
    except OSError:
        outcome = "runner_error"
        error_class = "runner"
    finally:
        if selector is not None:
            selector.close()
        if outcome != "exited" or process.returncode is None:
            if not _terminate(process):
                outcome = "cleanup_failed"
                error_class = "cleanup"
        try:
            process.stdout.close()
        except OSError:
            pass
    return {"outcome": outcome, "exit_code": process.returncode,
            "stdout": b"".join(raw), "error_class": error_class}


def _run_checkpoint(args, *, observe_stage):
    attestation = build_attestation(
        args.lib, args.receipt, args.preflight, args.workspace,
        args.expected_commit, schema=args.report_schema, case=args.case)
    apply_lib_alias_label(attestation, args.lib_alias_label)
    listing = run_bounded(
        listing_command(args.lib), timeout=min(60.0, args.timeout),
        stdout_limit=LISTING_STDOUT_LIMIT)
    if listing["outcome"] != "exited" or listing["exit_code"] != 0:
        raise CheckpointError("listing_failed")
    attestation["selection"] = require_membership(
        parse_listing(listing["stdout"]), args.case)
    run = run_bounded(
        exact_command(args.lib, args.case), timeout=args.timeout,
        stdout_limit=args.stdout_limit, environment=os.environ.copy())
    projection = classify_result(
        run["stdout"], run["exit_code"], outcome=run["outcome"],
        error_class=run["error_class"], expected=args.case)
    failure_stage = None
    if observe_stage and not projection["complete"]:
        if run["outcome"] == "exited" and projection["error_class"] == "case_failed":
            sequence = getattr(args, "stage_sequence", FAILURE_STAGES)
            failure_stage = classify_failure_stage(
                run["stdout"], expected=args.case, sequence=sequence)
        else:
            failure_stage = FAILURE_STAGE_UNAVAILABLE
    report = make_report(
        attestation, projection, run["exit_code"], run["outcome"],
        schema=args.report_schema, case=args.case)
    write_report(args.report, report)
    recheck_report(args.report, schema=args.report_schema, case=args.case)
    return report, failure_stage


def run_checkpoint(args):
    report, _failure_stage = _run_checkpoint(args, observe_stage=False)
    return report


def run_checkpoint_observed(args):
    return _run_checkpoint(args, observe_stage=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--preflight", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--case", default=CASE)
    parser.add_argument("--report-schema", default=REPORT_SCHEMA)
    parser.add_argument("--lib-alias-label", default=None)
    parser.add_argument("--report", required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--stdout-limit", type=int, default=DEFAULT_STDOUT_LIMIT)
    args = parser.parse_args(argv)
    try:
        report = run_checkpoint(args)
    except CheckpointError as error:
        print("slot-one checkpoint failed: " + str(error), file=sys.stderr)
        return 1
    except Exception as error:  # never echo child output or environment values
        print("slot-one checkpoint failed: internal " + type(error).__name__,
              file=sys.stderr)
        return 1
    print("slot-one checkpoint: " + report["result"] + " " + report["case"])
    print("  head=" + report["head"] + " tree=" + report["tree"])
    print("  source_inputs_sha256=" + report["source_inputs_sha256"])
    print("  lib_test_support_inputs_sha256="
          + report["lib_test_support_inputs_sha256"])
    print("  binary_sha256=" + report["binary_sha256"])
    print("  report=" + str(Path(args.report)))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
