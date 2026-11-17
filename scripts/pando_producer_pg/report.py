"""Fixed-allowlist report projection for the producer PG runner.

Only booleans, bounded integers, fixed identifiers, source-relative paths,
digests and command selectors are accepted.  DSNs (``://``), credentials,
whitespace, SQL, argv with runtime paths and arbitrary exception text are
rejected rather than persisted.  A projection failure still writes a finite
17-record NOTRUN report.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from . import cases
from .errors import RunnerError, require

REPORT_SCHEMA = "rootyard/issue21-pando-producer-pg/v1"
LIMITATIONS = (
    "local_provider_pg_only",
    "not_real_vault",
    "not_a_native_product_receipt",
    "not_attached_to_rootyard_native_gate",
)
SAFE_RE = re.compile(r"^[A-Za-z0-9_.:/=+-][A-Za-z0-9_./:=+-]{0,255}$")
MAX_INT = 10**12


def _sanitize(value):
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        require(-10**6 <= value <= MAX_INT, "report", "report_projection_rejected")
        return value
    if isinstance(value, str):
        require(
            SAFE_RE.fullmatch(value) is not None and "://" not in value,
            "report",
            "report_projection_rejected",
        )
        return value
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            require(
                isinstance(key, str) and SAFE_RE.fullmatch(key) is not None,
                "report",
                "report_projection_rejected",
            )
            result[key] = _sanitize(item)
        return result
    raise RunnerError("report", "report_projection_rejected")


def sanitize(value):
    return _sanitize(value)


def _test_binary(selection):
    if not isinstance(selection, dict):
        return {}
    executable = selection.get("executable")
    executable = executable if isinstance(executable, dict) else {}
    profile = selection.get("profile")
    profile = profile if isinstance(profile, dict) else {}
    return {
        "target": selection.get("target"),
        "kind": list(selection.get("kind") or []),
        "profile_test": bool(profile.get("test")),
        "fresh": bool(selection.get("fresh")),
        "source": selection.get("source"),
        "executable_name": executable.get("executable_name"),
        "executable_size": executable.get("size"),
    }


def _minimal_report():
    rows = cases.not_run_records(code="report_projection_rejected")
    return {
        "schema": REPORT_SCHEMA,
        "passed": False,
        "status": "failed",
        "mode": "execute",
        "case_count": len(rows),
        "cases": rows,
        "families": cases.family_counts(rows),
        "source_bindings": {},
        "test_binary_sha256": None,
        "test_binary": {},
        "actual_fresh": {},
        "fresh_verification": False,
        "product_receipt": {
            "provided": False,
            "same_source": False,
            "used_as_test_binary_receipt": False,
            "attached_to_native_gate": False,
        },
        "cleanup": {"cleanup_ok": False},
        "limitations": list(LIMITATIONS),
        "error_code": "report_projection_rejected",
        "stage": "report",
    }


def build_report(
    *,
    passed,
    records,
    binding,
    selection,
    product_receipt,
    cleanup,
    actual_fresh,
    error_code=None,
    stage=None,
    fresh_verification=False,
):
    if not isinstance(records, list) or len(records) != len(cases.CASES):
        return _minimal_report()
    payload = {
        "schema": REPORT_SCHEMA,
        "passed": bool(passed),
        "status": "passed" if passed else "failed",
        "mode": "execute",
        "case_count": len(records),
        "cases": records,
        "families": cases.family_counts(records),
        "source_bindings": binding if isinstance(binding, dict) else {},
        "test_binary_sha256": (
            selection.get("executable_sha256")
            if isinstance(selection, dict)
            else None
        ),
        "test_binary": _test_binary(selection),
        "actual_fresh": actual_fresh if isinstance(actual_fresh, dict) else {},
        "fresh_verification": bool(fresh_verification),
        "product_receipt": (
            product_receipt
            if isinstance(product_receipt, dict)
            else {
                "provided": False,
                "same_source": False,
                "used_as_test_binary_receipt": False,
                "attached_to_native_gate": False,
            }
        ),
        "cleanup": cleanup if isinstance(cleanup, dict) else {"cleanup_ok": False},
        "limitations": list(LIMITATIONS),
    }
    if error_code is not None:
        payload["error_code"] = error_code
    if stage is not None:
        payload["stage"] = stage
    try:
        return _sanitize(payload)
    except RunnerError:
        return _minimal_report()


def _inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def write_report(path, payload, *, forbidden_root=None):
    target = Path(path)
    if forbidden_root is not None and _inside(target, forbidden_root):
        raise RunnerError("report", "report_write_failed")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except (OSError, ValueError, TypeError):
        raise RunnerError("report", "report_write_failed") from None
    return target
