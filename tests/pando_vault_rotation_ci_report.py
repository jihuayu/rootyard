#!/usr/bin/env python3
"""Strict native-gate projection for the authored issue #21 Vault evidence.

The canonical five-case report is produced by ``pando_vault_rotation.py``.  Its
nested ``binding`` object and ``cases[].id`` fields are intentionally not the
shape accepted by ``scripts/native_report_manifest.py``.  This module does not
run Vault, PostgreSQL, Docker, Git, the product binary or the fixture.  It
re-reads an already produced canonical report, re-validates the Pando
source/binary/receipt identity through the existing harness validators, and
then emits a small, deterministic projection for a future Pando-specific
native job manifest.

Only fixed case/status names, counts and digests are copied.  Failure text,
paths, DSNs, tokens, environment values and arbitrary raw fields are never
printed or projected.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation as rotation  # noqa: E402

REPORT_SCHEMA = rotation.REPORT_SCHEMA
CASE_IDS = tuple(rotation.required_cases())
CLEANUP_CASE_ID = CASE_IDS[-1]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_RAW_BYTES = 8 * 1024 * 1024

RAW_REQUIRED = frozenset({
    "schema", "passed", "status", "case_count", "cases", "binding",
    "cleanup", "limitations",
})
RAW_ALLOWED = RAW_REQUIRED | {"error_code", "stage"}
CASE_KEYS = frozenset({"id", "status", "facts", "code", "stage"})
BINDING_KEYS = frozenset({
    "source_commit", "source_tree", "source_clean", "binary_sha256",
    "receipt_sha256", "harness_sha256",
})
CLEANUP_KEYS = frozenset({
    "vault_owned", "vault_stopped", "container_absent", "postgres_owned",
    "postgres_created", "postgres_dropped", "database_absent", "root_owned",
    "root_removed", "root_absent", "server_stopped", "cleanup_ok",
    "credential_released", "pg_major", "image_digest_sha256",
    "vault_version", "no_global_cleanup", "raw_logs_persisted",
})
CLEANUP_TRUE = (
    "vault_owned", "vault_stopped", "container_absent", "postgres_owned",
    "postgres_created", "postgres_dropped", "database_absent", "root_owned",
    "root_removed", "root_absent", "server_stopped", "cleanup_ok",
    "credential_released", "no_global_cleanup",
)
SECRET_ENV_NAMES = (
    "ROOTYARD_KMS_VAULT_TOKEN",
    "PANDO_KMS_VAULT_TOKEN",
    "VAULT_TOKEN",
    "VAULT_APP_TOKEN",
    "ROOTYARD_TEST_DATABASE_URL",
    "DATABASE_URL",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
)
UNSAFE_VALUE_MARKERS = (
    "://", "@", "secret", "token", "password", "passwd", "bearer", "dsn",
)


class ProjectionError(RuntimeError):
    """A fixed, report-safe projection failure code."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _DuplicateKey(ValueError):
    """Internal marker; never carries the offending key or value."""


def _reject_duplicate_keys(pairs):
    """Reject duplicate JSON object keys at every nesting level."""
    seen = set()
    result = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKey()
        seen.add(key)
        result[key] = value
    return result


def require(condition, code):
    if not condition:
        raise ProjectionError(code)


def _sanitize(payload):
    """Reuse the fixture's allowlist instead of inventing a loose validator."""
    try:
        return rotation.sanitize_report(payload)
    except rotation.QualificationError as error:
        if getattr(error, "code", "") == "report_field_rejected":
            raise ProjectionError("raw_report_field_rejected") from None
        raise ProjectionError("raw_report_value_rejected") from None


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _reject_secrets(payload, secrets):
    text = json.dumps(payload, sort_keys=True)
    for secret in secrets or ():
        if secret and secret in text:
            raise ProjectionError("raw_report_secret_present")
    for value in _strings(payload):
        lowered = value.lower()
        if any(marker in lowered for marker in UNSAFE_VALUE_MARKERS):
            raise ProjectionError("raw_report_unsafe_value")


def _validate_cleanup(cleanup):
    require(isinstance(cleanup, dict), "raw_report_cleanup_invalid")
    require(set(cleanup) <= CLEANUP_KEYS, "raw_report_cleanup_field_rejected")
    require(CLEANUP_KEYS <= set(cleanup), "raw_report_cleanup_missing")
    for key in CLEANUP_TRUE:
        require(cleanup.get(key) is True, "raw_report_cleanup_not_truthful")
    require(cleanup.get("raw_logs_persisted") is False,
            "raw_report_cleanup_not_truthful")


def _validate_cases(cases, case_count):
    require(type(case_count) is int and case_count == len(CASE_IDS),
            "raw_report_case_count_mismatch")
    require(isinstance(cases, list) and len(cases) == len(CASE_IDS),
            "raw_report_case_count_mismatch")
    seen = set()
    for index, case in enumerate(cases):
        require(isinstance(case, dict), "raw_report_case_shape_invalid")
        require(set(case) <= CASE_KEYS, "raw_report_case_field_rejected")
        case_id = case.get("id")
        require(isinstance(case_id, str), "raw_report_case_id_invalid")
        require(case_id == CASE_IDS[index], "raw_report_case_order_mismatch")
        require(case_id not in seen, "raw_report_case_duplicate")
        seen.add(case_id)
        require(case.get("status") == "passed", "raw_report_case_not_passed")
        require(case.get("code") in (None,), "raw_report_case_failure_code")
        require("stage" not in case, "raw_report_case_failure_stage")
        require(isinstance(case.get("facts"), dict),
                "raw_report_case_facts_invalid")
    require(seen == set(CASE_IDS), "raw_report_case_order_mismatch")
    _validate_cleanup(cases[-1]["facts"])


def _validate_binding(binding, expected_commit, validated):
    require(isinstance(binding, dict), "raw_report_binding_invalid")
    require(isinstance(validated, dict), "validated_source_invalid")
    require(set(binding) == BINDING_KEYS, "raw_report_binding_fields_invalid")
    for key in ("source_commit", "source_tree"):
        value = binding.get(key)
        require(isinstance(value, str)
                and rotation.COMMIT_RE.fullmatch(value) is not None,
                "raw_report_binding_identity_invalid")
    for key in ("binary_sha256", "receipt_sha256", "harness_sha256"):
        value = binding.get(key)
        require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
                "raw_report_binding_digest_invalid")
    require(binding.get("source_clean") is True,
            "raw_report_binding_source_not_clean")

    require(validated.get("source_clean") is True,
            "validated_source_not_clean")
    require(isinstance(validated.get("source_tree"), str)
            and rotation.COMMIT_RE.fullmatch(validated["source_tree"]) is not None,
            "validated_source_invalid")
    for key in ("binary_sha256", "receipt_sha256", "harness_sha256"):
        value = validated.get(key)
        require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
                "validated_source_invalid")
    require(validated.get("source_commit") == expected_commit,
            "validated_source_commit_mismatch")

    require(binding["source_commit"] == expected_commit,
            "binding_source_commit_mismatch")
    require(binding["source_commit"] == validated["source_commit"],
            "binding_source_commit_mismatch")
    require(binding["source_tree"] == validated["source_tree"],
            "binding_source_tree_mismatch")
    require(binding["binary_sha256"] == validated["binary_sha256"],
            "binding_binary_sha256_mismatch")
    require(binding["receipt_sha256"] == validated["receipt_sha256"],
            "binding_receipt_sha256_mismatch")
    require(binding["harness_sha256"] == validated["harness_sha256"],
            "binding_harness_sha256_mismatch")


def project(payload, raw_report_sha256, expected_commit, validated,
            secrets=()):
    """Return only the fixed native-gate fields, or raise a fixed code."""
    require(isinstance(raw_report_sha256, str)
            and SHA256_RE.fullmatch(raw_report_sha256) is not None,
            "raw_report_digest_invalid")
    require(isinstance(expected_commit, str)
            and rotation.COMMIT_RE.fullmatch(expected_commit) is not None,
            "expected_commit_invalid")
    require(isinstance(payload, dict), "raw_report_not_object")
    payload = _sanitize(payload)
    _reject_secrets(payload, secrets)

    require(set(payload) <= RAW_ALLOWED, "raw_report_field_rejected")
    require(RAW_REQUIRED <= set(payload), "raw_report_field_missing")
    require(payload.get("schema") == REPORT_SCHEMA,
            "raw_report_schema_mismatch")
    require(payload.get("passed") is True, "raw_report_not_passed")
    require(payload.get("status") == "passed", "raw_report_not_passed")
    require("error_code" not in payload and "stage" not in payload,
            "raw_report_failure_fields_present")
    require(payload.get("limitations") == list(rotation.ALLOWED_LIMITATIONS),
            "raw_report_limitations_invalid")
    _validate_cases(payload.get("cases"), payload.get("case_count"))
    _validate_cleanup(payload.get("cleanup"))
    _validate_binding(payload.get("binding"), expected_commit, validated)

    return {
        "passed": True,
        "binary_sha256": validated["binary_sha256"],
        "source_head": validated["source_commit"],
        "cases": [
            {"name": case["id"], "status": case["status"]}
            for case in payload["cases"]
        ],
        "case_count": len(CASE_IDS),
        "raw_report_sha256": raw_report_sha256,
    }


def _load_raw(path):
    raw = Path(path)
    require(raw.is_file(), "raw_report_unreadable")
    try:
        data = raw.read_bytes()
    except (OSError, ValueError, TypeError):
        raise ProjectionError("raw_report_unreadable") from None
    require(len(data) <= MAX_RAW_BYTES, "raw_report_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProjectionError("raw_report_invalid_json") from None
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise ProjectionError("raw_report_duplicate_key") from None
    except (json.JSONDecodeError, RecursionError):
        raise ProjectionError("raw_report_invalid_json") from None
    require(isinstance(payload, dict), "raw_report_not_object")
    return payload, rotation.sha256_bytes(data)


def _validated_source(args, environ):
    namespace = argparse.Namespace(
        binary=args.binary,
        receipt=args.receipt,
        source_root=args.source_root,
        expected_commit=args.expected_commit,
        expected_binary_sha256=None,
        report=args.raw_report,
    )
    try:
        validated = rotation.validate_inputs(namespace, dict(environ))
    except rotation.QualificationError as error:
        code = getattr(error, "code", "")
        if not isinstance(code, str) or CODE_RE.fullmatch(code) is None:
            code = "input_validation_failed"
        raise ProjectionError(code) from None
    except Exception:
        raise ProjectionError("input_validation_failed") from None
    required = (
        "source_commit", "source_tree", "source_clean", "binary_sha256",
        "receipt_sha256", "harness_sha256",
    )
    require(isinstance(validated, dict)
            and all(key in validated for key in required),
            "input_validation_failed")
    return validated


def _secret_values(environ):
    values = []
    for name in SECRET_ENV_NAMES:
        value = environ.get(name)
        if isinstance(value, str) and len(value) >= 8:
            values.append(value)
    return tuple(values)


def _prepare_paths(raw_value, output_value):
    raw_path = Path(raw_value)
    try:
        raw_real = os.path.realpath(raw_path)
        output_abs = os.path.abspath(output_value)
        output_real = os.path.realpath(output_abs)
    except (OSError, ValueError, TypeError):
        raise ProjectionError("output_path_invalid") from None
    require(raw_real != output_real, "output_aliases_raw_report")
    require(not any(part.startswith("rootyard-pando-vault-rotation-")
                    for part in Path(output_abs).parts),
            "output_path_inside_owned_root")
    output = Path(output_abs)
    if output.is_symlink() or output.exists():
        require(not output.is_dir(), "output_is_directory")
        try:
            output.unlink()
        except OSError:
            raise ProjectionError("output_unwritable") from None
    return raw_path, output


def collect(args, environ=None):
    """Validate the canonical report and Pando identity, then write output."""
    environ = dict(os.environ if environ is None else environ)
    require(isinstance(args.expected_commit, str)
            and rotation.COMMIT_RE.fullmatch(args.expected_commit) is not None,
            "expected_commit_invalid")
    raw_path, output = _prepare_paths(args.raw_report, args.output)
    payload, raw_sha256 = _load_raw(raw_path)
    validated = _validated_source(args, environ)
    projection = project(
        payload, raw_sha256, args.expected_commit, validated,
        secrets=_secret_values(environ),
    )
    try:
        rotation.atomic_write_json(output, projection)
    except (OSError, ValueError, TypeError):
        raise ProjectionError("output_write_failed") from None
    return projection


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Project the canonical issue #21 Vault report into the "
                    "native job-gate contract.")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--raw-report", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        projection = collect(args)
    except ProjectionError as error:
        code = error.code
        if not isinstance(code, str) or CODE_RE.fullmatch(code) is None:
            code = "unexpected_error"
        print("pando_vault_rotation_ci_report: " + code, file=sys.stderr)
        return 1
    except Exception:
        print("pando_vault_rotation_ci_report: unexpected_error",
              file=sys.stderr)
        return 1
    print(json.dumps({"passed": True, "case_count": projection["case_count"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
