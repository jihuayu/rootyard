#!/usr/bin/env python3
"""Authored (not executed here) real Vault/PG rotation qualification harness.

Run this only in an environment that intentionally owns Docker, PostgreSQL 17,
Vault and the lab binary.  It accepts an existing ``rootyard-pando-lab`` binary
and its native-build receipt, proves the source/receipt/binary identity, then
runs exactly five mandatory cases.  Missing tools, fixtures, unsupported
operations or unverifiable identities fail; there is no skip path.

The report is a fixed allowlist of case names, statuses, counts, hashes and
booleans.  It never contains tokens, DSNs, provider bodies, SQL rows, wrapped
DEKs, pack/plaintext bytes, marker text, environment dumps, raw child output,
container logs or traceback text.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SCRIPTS = ROOT / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import native_build_receipt as receipts  # noqa: E402
from pando_vault_rotation_budget import (  # noqa: E402
    DEFAULT_CLEANUP_RESERVE_SECONDS,
    DEFAULT_TOTAL_SECONDS,
    OVERALL_DEADLINE_EXCEEDED,
    Budget,
    DeadlineError,
)
from pando_vault_rotation_fixture import FixtureError  # noqa: E402
import pando_vault_rotation_cases as cases  # noqa: E402
import pando_vault_rotation_negative as negative  # noqa: E402
import pando_vault_rotation_source as source  # noqa: E402
from pando_vault_rotation_context import Context  # noqa: E402
from pando_vault_rotation_support import (  # noqa: E402
    ALLOWED_LIMITATIONS,
    CASES,
    COMMIT_RE,
    QualificationError,
    Runner,
    atomic_write_json,
    inside,
    require,
    sanitize_report,
    sha256_bytes,
    sha256_file,
    sha256_file_bounded,
)

REPORT_SCHEMA = "rootyard/issue21-derived-vault-rotation/v1"
REPORT_WRITE_RESERVE_SECONDS = 2.0


def required_cases():
    return CASES


def parse_args(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--binary", default=None,
                        help="rootyard-pando-lab binary (default ROOTYARD_PANDO_LAB_BIN)")
    parser.add_argument("--receipt", default=None,
                        help="native-build receipt (default ROOTYARD_PANDO_BUILD_RECEIPT)")
    parser.add_argument("--source-root", default=str(ROOT))
    parser.add_argument("--expected-commit", default=None)
    parser.add_argument("--expected-binary-sha256", default=None)
    parser.add_argument("--report", default=None)
    parser.add_argument("--timeout-seconds", type=float,
                        default=DEFAULT_TOTAL_SECONDS,
                        help="one absolute overall deadline in seconds")
    parser.add_argument("--cleanup-reserve-seconds", type=float,
                        default=DEFAULT_CLEANUP_RESERVE_SECONDS,
                        help="cleanup reserve carved out of the overall deadline")
    return parser.parse_args(argv)


# The private command interface deliberately reuses the source-approved
# producer-PG owned Popen runner.  These files are part of the harness binding
# closure so the reused semantics cannot drift without changing the harness
# hash and the CI manifest harness list.
BOUND_SUPPORT_FILES = (
    "scripts/pando_producer_pg/__init__.py",
    "scripts/pando_producer_pg/errors.py",
    "scripts/pando_producer_pg/process.py",
)


def _harness_files():
    paths = sorted(TESTS.glob("pando_vault_rotation*.py"))
    paths += sorted(TESTS.glob("test_pando_vault_rotation*.py"))
    paths += [ROOT / relative for relative in BOUND_SUPPORT_FILES]
    return [path for path in paths if path.is_file()]


def _harness_sha256(budget=None):
    rows = []
    for path in _harness_files():
        if budget is not None:
            budget.require("binding")
            digest = sha256_file_bounded(path, budget, "binding")
        else:
            digest = sha256_file(path)
        rows.append(path.relative_to(ROOT).as_posix() + "\0" + digest)
    require(bool(rows), "harness_files_missing", "binding")
    if budget is not None:
        budget.late("binding")
    return sha256_bytes("\n".join(rows).encode())


def _source_state(root):
    try:
        return receipts.require_clean_git_state(root)
    except receipts.ReceiptError:
        raise QualificationError("source_not_clean", "binding") from None
    except (OSError, ValueError):
        raise QualificationError("source_unreadable", "binding") from None


def _pando_artifact(receipt, binary_sha256):
    """Require the modern v2 per-bin Pando artifact, not a v1 secondary row.

    Legacy v1 receipts only bind the supplied binary to their primary artifact;
    a secondary ``rootyard-pando-lab`` row may omit executable path and hash.
    This gate therefore rejects v1 outright and requires the v2 artifact row's
    executable digest to equal the actual selected binary.
    """
    require(getattr(receipt, "schema", None) == "v2",
            "receipt_pando_receipt_not_v2", "binding")
    payload = getattr(receipt, "payload", None)
    require(isinstance(payload, dict)
            and payload.get("receipt_schema") == receipts.RECEIPT_SCHEMA_V2,
            "receipt_pando_schema_mismatch", "binding")
    rows = [
        row for row in receipt.artifacts
        if isinstance(row, dict) and row.get("kind") == "bin"
        and row.get("target") == "rootyard-pando-lab"
    ]
    require(bool(rows), "receipt_pando_artifact_missing", "binding")
    require(len(rows) == 1, "receipt_pando_artifact_ambiguous", "binding")
    row = rows[0]
    require(isinstance(row.get("executable_sha256"), str)
            and row["executable_sha256"] == binary_sha256,
            "receipt_pando_artifact_mismatch", "binding")
    return True


def validate_inputs(args, environ, budget=None, runner=None):
    if budget is not None:
        budget.require("input")
    binary = args.binary or environ.get("ROOTYARD_PANDO_LAB_BIN")
    receipt = args.receipt or environ.get("ROOTYARD_PANDO_BUILD_RECEIPT")
    expected_commit = args.expected_commit or environ.get("ROOTYARD_EXPECTED_COMMIT")
    expected_sha = args.expected_binary_sha256 or environ.get(
        "ROOTYARD_PANDO_LAB_SHA256")
    report = args.report
    require(bool(binary), "missing_binary", "input")
    require(bool(receipt), "missing_receipt", "input")
    require(bool(expected_commit), "missing_expected_commit", "input")
    require(bool(report), "missing_report", "input")
    require(COMMIT_RE.fullmatch(expected_commit) is not None,
            "expected_commit_invalid", "input")
    if expected_sha is not None:
        require(re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None,
                "expected_binary_sha256_invalid", "input")
    binary = Path(binary).resolve()
    receipt = Path(receipt).resolve()
    source_root = Path(args.source_root).resolve()
    report = Path(report).resolve()
    require(binary.is_file() and os.access(binary, os.X_OK),
            "binary_missing_or_not_executable", "input")
    require(receipt.is_file(), "receipt_missing", "input")
    require(source_root.is_dir(), "source_root_missing", "input")
    require(not any(part.startswith("rootyard-pando-vault-rotation-")
                    for part in report.parts),
            "report_path_inside_owned_root", "input")
    for tool in ("docker", "psql", "git"):
        require(shutil.which(tool) is not None, tool + "_missing", "input")
    bootstrap = environ.get("ROOTYARD_TEST_DATABASE_URL")
    require(bool(bootstrap), "missing_pg_bootstrap", "input")
    if budget is not None:
        budget.late("input")
    if budget is not None and runner is not None:
        bound = source.validate(
            runner, budget,
            source_root=source_root,
            expected_commit=expected_commit,
            binary=binary,
            receipt=receipt,
            expected_binary_sha256=expected_sha,
        )
        state = {
            "commit": bound["source_commit"],
            "tree": bound["source_tree"],
            "clean": True,
        }
        binary_sha256 = bound["binary_sha256"]
        receipt_sha256 = bound["receipt_sha256"]
    else:
        state = _source_state(source_root)
        require(state["commit"] == expected_commit, "expected_commit_mismatch",
                "binding")
        binary_sha256 = sha256_file(binary)
        try:
            validated = receipts.load_receipt(
                receipt,
                source_root=source_root,
                binary_path=binary,
                expected_commit=expected_commit,
                expected_binary_sha256=expected_sha,
                forbid_implicit_build=True,
            )
        except receipts.ReceiptError:
            raise QualificationError("receipt_rejected", "binding") from None
        require(validated.binary_sha256 == binary_sha256,
                "receipt_binary_digest_mismatch", "binding")
        require(validated.workspace_commit == expected_commit,
                "receipt_commit_mismatch", "binding")
        require(_pando_artifact(validated, binary_sha256),
                "receipt_pando_artifact_missing", "binding")
        receipt_sha256 = validated.receipt_sha256
    return {
        "binary": binary,
        "receipt": receipt,
        "source_root": source_root,
        "expected_commit": expected_commit,
        "expected_binary_sha256": expected_sha,
        "report": report,
        "bootstrap_dsn": bootstrap,
        "source_commit": state["commit"],
        "source_tree": state["tree"],
        "source_clean": bool(state["clean"]),
        "binary_sha256": binary_sha256,
        "receipt_sha256": receipt_sha256,
        "harness_sha256": _harness_sha256(budget),
    }


def _binding_read_error():
    return QualificationError("binding_unavailable", "binding")


def binding_snapshot(inputs, budget=None, runner=None):
    """Re-read every bound identity without letting OS errors escape.

    A mismatch is a fixed ``*_binding_changed`` code.  Any unreadable source,
    binary, receipt or harness source is ``binding_unavailable``; no fresh hash
    is fabricated for the report.  When a budget and runner are supplied every
    Git/receipt read runs in one bounded owned child; the unbudgeted in-process
    path is retained only for the existing pure unit contract.
    """
    if budget is not None and runner is not None:
        bound = source.snapshot(runner, budget, inputs)
        try:
            harness_sha256 = _harness_sha256(budget)
        except QualificationError:
            raise
        except (OSError, ValueError, TypeError):
            raise _binding_read_error() from None
        require(harness_sha256 == inputs["harness_sha256"],
                "harness_binding_changed", "binding")
        return {
            "source_commit": bound["source_commit"],
            "source_tree": bound["source_tree"],
            "source_clean": True,
            "binary_sha256": inputs["binary_sha256"],
            "receipt_sha256": inputs["receipt_sha256"],
            "harness_sha256": inputs["harness_sha256"],
        }
    try:
        state = receipts.git_state(inputs["source_root"])
    except QualificationError:
        raise
    except Exception:
        raise _binding_read_error() from None
    require(state["commit"] == inputs["source_commit"]
            and state["tree"] == inputs["source_tree"],
            "source_binding_changed", "binding")
    require(bool(state["clean"]), "source_became_dirty", "binding")
    try:
        binary_sha256 = sha256_file(inputs["binary"])
    except (OSError, ValueError, TypeError):
        raise _binding_read_error() from None
    require(binary_sha256 == inputs["binary_sha256"],
            "binary_binding_changed", "binding")
    try:
        receipt_sha256 = sha256_file(inputs["receipt"])
    except (OSError, ValueError, TypeError):
        raise _binding_read_error() from None
    require(receipt_sha256 == inputs["receipt_sha256"],
            "receipt_binding_changed", "binding")
    try:
        harness_sha256 = _harness_sha256()
    except (OSError, ValueError, TypeError, QualificationError):
        raise _binding_read_error() from None
    require(harness_sha256 == inputs["harness_sha256"],
            "harness_binding_changed", "binding")
    return {
        "source_commit": state["commit"],
        "source_tree": state["tree"],
        "source_clean": bool(state["clean"]),
        "binary_sha256": inputs["binary_sha256"],
        "receipt_sha256": inputs["receipt_sha256"],
        "harness_sha256": inputs["harness_sha256"],
    }


def _final_binding_code(error):
    code = getattr(error, "code", "")
    if code in ("binding_unavailable", "binding_unreadable",
                "harness_files_missing"):
        return "binding_unavailable"
    return "binding_changed"


def _failed_case(case_id, code, stage):
    return {
        "id": case_id,
        "status": "failed",
        "code": code or "mandatory_case_failed",
        "stage": stage or "case",
        "facts": {},
    }


def _failed_cleanup(code, stage):
    return {
        "id": CASES[4],
        "status": "failed",
        "code": code or "owned_resource_cleanup_unresolved",
        "stage": stage or "cleanup",
        "facts": {
            "cleanup_ok": False,
            "vault_stopped": False,
            "postgres_dropped": False,
            "root_removed": False,
            "no_global_cleanup": True,
        },
    }


def fill_cases(results, code, stage, cleanup):
    mapping = {row["id"]: row for row in results if row.get("id") in CASES}
    for case_id in CASES:
        if case_id == CASES[4]:
            mapping[case_id] = cleanup
        elif case_id not in mapping:
            mapping[case_id] = _failed_case(case_id, code, stage)
    return [mapping[case_id] for case_id in CASES]


def build_report(inputs, rows, cleanup, passed, error_code=None, stage=None):
    binding = {}
    if inputs is not None:
        binding = {
            "source_commit": inputs.get("source_commit"),
            "source_tree": inputs.get("source_tree"),
            "source_clean": inputs.get("source_clean"),
            "binary_sha256": inputs.get("binary_sha256"),
            "receipt_sha256": inputs.get("receipt_sha256"),
            "harness_sha256": inputs.get("harness_sha256"),
        }
    payload = {
        "schema": REPORT_SCHEMA,
        "passed": bool(passed),
        "status": "passed" if passed else "failed",
        "case_count": len(rows),
        "cases": rows,
        "binding": binding,
        "cleanup": cleanup.get("facts", {}),
        "limitations": list(ALLOWED_LIMITATIONS),
    }
    if error_code is not None:
        payload["error_code"] = error_code
    if stage is not None:
        payload["stage"] = stage
    return sanitize_report(payload)


def _report_path_allowed(path):
    return not any(part.startswith("rootyard-pando-vault-rotation-")
                   for part in Path(path).parts)


def _mark_failed(payload, code):
    payload["passed"] = False
    payload["status"] = "failed"
    payload["error_code"] = code
    payload.setdefault("stage", "report")


def _write_report(path, payload, budget=None):
    """Write the last artifact under the same absolute deadline.

    The write is not preemptible, so this is a late-recheck boundary rather
    than a wall-clock guarantee.  If the overall deadline is already spent the
    payload is switched to a truthful failure before the first write; an
    in-flight write that returns late is rewritten as failed so a stale green
    report cannot be left behind.  An existing primary failure code is never
    overwritten by a secondary deadline code.
    """
    if not _report_path_allowed(path):
        return False
    was_passed = payload.get("passed") is True
    if budget is not None:
        if budget.remaining_overall() <= REPORT_WRITE_RESERVE_SECONDS:
            if was_passed:
                _mark_failed(payload, OVERALL_DEADLINE_EXCEEDED)
        else:
            budget.late_overall("report")
    target = Path(path)
    atomic_write_json(target, payload)
    if budget is not None and budget.expired_overall() and payload.get("passed") is True:
        _mark_failed(payload, OVERALL_DEADLINE_EXCEEDED)
        try:
            atomic_write_json(target, payload)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        budget.late_overall("report")
    return True


def _finish_report(path, payload, budget):
    try:
        written = _write_report(path, payload, budget)
    except QualificationError as error:
        _mark_failed(payload, error.code)
        # Last fixed-size failed artifact; a late write is reported as failed
        # even if this best-effort attempt succeeds.
        try:
            atomic_write_json(Path(path), payload)
        except Exception:
            pass
        return False
    except Exception:
        _mark_failed(payload, "report_write_failed")
        return False
    if not written:
        _mark_failed(payload, "report_path_rejected")
        return False
    return True


def _minimal_failed_report():
    return {
        "schema": REPORT_SCHEMA,
        "passed": False,
        "status": "failed",
        "case_count": len(CASES),
        "cases": [
            {"id": case_id, "status": "failed",
             "code": "report_projection_rejected", "stage": "report", "facts": {}}
            for case_id in CASES
        ],
        "binding": {},
        "cleanup": {"cleanup_ok": False},
        "limitations": list(ALLOWED_LIMITATIONS),
        "error_code": "report_projection_rejected",
        "stage": "report",
    }


def _safe_build(inputs, rows, cleanup, passed, error_code=None, stage=None):
    try:
        return build_report(inputs, rows, cleanup, passed, error_code, stage)
    except QualificationError:
        fallback_cleanup = _failed_cleanup(
            "report_projection_rejected", "report")
        fallback_rows = fill_cases(
            [], "report_projection_rejected", "report", fallback_cleanup)
        try:
            return build_report(
                inputs, fallback_rows, fallback_cleanup, False,
                "report_projection_rejected", "report")
        except QualificationError:
            return _minimal_failed_report()


def _binding_failure_code(error):
    code = getattr(error, "code", "")
    if code in (
        "work_deadline_exceeded",
        "cleanup_deadline_exceeded",
        "overall_deadline_exceeded",
    ):
        return code
    return _final_binding_code(error)


def run_qualification(args, environ=None, clock=time.monotonic):
    environ = dict(os.environ if environ is None else environ)
    report_path = getattr(args, "report", None)
    try:
        budget = Budget(
            getattr(args, "timeout_seconds", DEFAULT_TOTAL_SECONDS),
            getattr(args, "cleanup_reserve_seconds",
                    DEFAULT_CLEANUP_RESERVE_SECONDS),
            clock=clock,
            error_factory=QualificationError,
        )
    except (DeadlineError, TypeError, ValueError):
        cleanup = _failed_cleanup("qualification_not_started", "cleanup")
        rows = fill_cases([], "timeout_invalid", "input", cleanup)
        report = _safe_build(None, rows, cleanup, False,
                             "timeout_invalid", "input")
        if report_path:
            _finish_report(report_path, report, None)
        return report
    runner = Runner(budget=budget, clock=clock)
    inputs = None
    context = None
    rows = []
    cleanup = None
    fatal_code = None
    fatal_stage = None
    before = None
    try:
        inputs = validate_inputs(args, environ, budget=budget, runner=runner)
    except QualificationError as error:
        fatal_code, fatal_stage = error.code, error.stage
    except Exception:
        fatal_code, fatal_stage = "unexpected_error", "input"
    if inputs is not None:
        try:
            before = binding_snapshot(inputs, budget=budget, runner=runner)
        except QualificationError as error:
            fatal_code, fatal_stage = _binding_failure_code(error), "binding"
        except Exception:
            fatal_code, fatal_stage = "binding_unavailable", "binding"
    if inputs is None or before is None:
        cleanup = _failed_cleanup("qualification_not_started", "cleanup")
        rows = fill_cases([], fatal_code or "input_validation_failed",
                          fatal_stage or "input", cleanup)
        report = _safe_build(inputs, rows, cleanup, False,
                             fatal_code or "input_validation_failed",
                             fatal_stage or "input")
        if report_path:
            _finish_report(report_path, report, budget)
        return report
    try:
        context = Context(inputs, environ, runner, budget=budget)
        try:
            budget.require("cases")
            context.start_base()
            budget.late("cases")
            result = cases.case_fixture_and_app_capability_boundary(context)
            budget.late("cases")
            rows.append(result)
            budget.require("cases")
            context.prepare_initial_packs()
            budget.late("cases")
            result = cases.case_authentic_envelope_digest_and_cold_read(context)
            budget.late("cases")
            rows.append(result)
            budget.require("cases")
            result = cases.case_admin_rotated_target_interrupted_resume_and_new_write(context)
            budget.late("cases")
            rows.append(result)
            budget.require("cases")
            result = negative.case_wrong_key_ciphertext_envelope_and_provider_revocation(context)
            budget.late("cases")
            rows.append(result)
        except (QualificationError, FixtureError) as error:
            if fatal_code is None:
                fatal_code, fatal_stage = error.code, error.stage
        except Exception:
            if fatal_code is None:
                fatal_code, fatal_stage = "unexpected_error", "case"
    finally:
        # Latch the primary failure before cleanup.  Cleanup outcomes are
        # recorded separately and never replace an earlier primary code.
        budget.begin_cleanup()
        if context is not None:
            try:
                cleanup = negative.case_owned_resource_cleanup(context)
            except Exception:
                cleanup = _failed_cleanup("cleanup_unexpected_error", "cleanup")
        else:
            cleanup = _failed_cleanup("qualification_not_started", "cleanup")
        if not isinstance(cleanup, dict):
            cleanup = _failed_cleanup("cleanup_unexpected_error", "cleanup")
        if cleanup.get("status") != "passed" and fatal_code is None:
            fatal_code = cleanup.get("code") or "owned_resource_cleanup_unresolved"
            fatal_stage = "cleanup"
        if budget.expired_overall():
            if fatal_code is None:
                fatal_code, fatal_stage = OVERALL_DEADLINE_EXCEEDED, "cleanup"
            if cleanup.get("status") == "passed":
                cleanup = dict(cleanup)
                cleanup["status"] = "failed"
                cleanup["code"] = OVERALL_DEADLINE_EXCEEDED
                cleanup["stage"] = "cleanup"
        rows = fill_cases(rows, fatal_code or "mandatory_case_failed",
                          fatal_stage or "case", cleanup)
    binding_ok = True
    if before is not None:
        try:
            after = binding_snapshot(inputs, budget=budget, runner=runner)
        except QualificationError as error:
            binding_ok = False
            if fatal_code is None:
                fatal_code, fatal_stage = _binding_failure_code(error), "binding"
        except Exception:
            binding_ok = False
            if fatal_code is None:
                fatal_code, fatal_stage = "binding_unavailable", "binding"
        else:
            if after != before:
                binding_ok = False
                if fatal_code is None:
                    fatal_code, fatal_stage = "binding_changed", "binding"
    all_green = bool(rows) and all(
        isinstance(row, dict) and row.get("status") == "passed" for row in rows)
    passed = bool(binding_ok and fatal_code is None and all_green
                  and cleanup is not None
                  and cleanup.get("status") == "passed"
                  and not budget.expired_overall())
    report = _safe_build(inputs, rows, cleanup, passed, fatal_code, fatal_stage)
    _finish_report(inputs["report"], report, budget)
    return report


def main(argv=None):
    args = parse_args(argv)
    try:
        report = run_qualification(args)
    except Exception:
        report = _minimal_failed_report()
        try:
            if args.report:
                _write_report(args.report, report)
        except Exception:
            pass
        return 1
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
