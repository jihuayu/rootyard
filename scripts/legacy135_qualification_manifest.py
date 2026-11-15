#!/usr/bin/env python3
"""Safe focused manifest for the #82 legacy135 hosted qualification.

This is not a generic native-report extension.  It consumes only the safe
qualification/provider JSON produced by ``tests/legacy135_qualification.py``,
the two role-separated build receipts and the workflow/wrapper/collector hashes.
It requires the exact seven green cases, the canonical current target, the
frozen source commit and distinct candidate/producer receipt roles, then emits a
small manifest containing no raw logs, provider locator, archive bytes or
credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
TESTS = ROOT / "tests"
for entry in (str(SCRIPTS), str(TESTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import native_build_receipt as receipts  # noqa: E402
from legacy135_qualification import VAULT_IMAGE, VAULT_VERSION  # noqa: E402
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION  # noqa: E402

FROZEN_SOURCE_COMMIT = "560e96f41f1d4670bfb5d2459af7af459eca4823"
MANIFEST_SCHEMA = "rootyard/issue82-legacy135-hosted-qualification/v1"
CASE_NAMES = (
    "create_real_schema135_pando_source",
    "legacy_binary_writes_format11_schema135_archive",
    "candidate_cli_usage_and_mixed_legacy_flags",
    "candidate_rejects_without_schema135_opt_in",
    "candidate_restores_schema%s_one_new_authority" % CURRENT_SCHEMA_VERSION,
    "restored_service_git_and_session_boundaries",
    "source_authority_and_remote_objects_remain_available",
)
FORBIDDEN_KEYS = {
    "token", "secret", "password", "credential", "dsn", "endpoint", "url",
    "raw_log", "raw_output", "request_body", "server_log", "environment",
}
SECRET_ENV_NAMES = (
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
    "ROOTYARD_KMS_VAULT_TOKEN",
)
SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
COMMIT = __import__("re").compile(r"^[0-9a-f]{40}$")


class CollectorError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise CollectorError(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path, label):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise CollectorError(label + "_invalid") from None
    require(isinstance(value, dict), label + "_invalid")
    return value


def walk_keys(value, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child, prefix + str(key) + ".")
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child, prefix)


def reject_unsafe_payload(payload, text):
    lowered = {key for key in walk_keys(payload)}
    require(not (lowered & FORBIDDEN_KEYS), "unsafe_field_present")
    for name in SECRET_ENV_NAMES:
        value = os.environ.get(name)
        if value:
            require(value not in text, "secret_value_present")


def receipt_identity(path, role):
    receipt = load_json(path, role + "_receipt")
    binary_sha = receipt.get("binary_sha256")
    commit = receipt.get("workspace_commit")
    require(isinstance(binary_sha, str) and SHA256.fullmatch(binary_sha) is not None,
            role + "_receipt_binary_invalid")
    require(isinstance(commit, str) and COMMIT.fullmatch(commit) is not None,
            role + "_receipt_commit_invalid")
    schema = "v2" if "receipt_schema" in receipt else "v1"
    if "receipt_schema" in receipt:
        require(receipt.get("receipt_schema") == receipts.RECEIPT_SCHEMA_V2,
                role + "_receipt_schema_invalid")
    return {
        "role": role,
        "path": str(Path(path).resolve()),
        "sha256": sha256_file(path),
        "binary_sha256": binary_sha,
        "workspace_commit": commit,
        "receipt_schema": schema,
    }


def validate_cases(qualification):
    cases = qualification.get("cases")
    require(isinstance(cases, list), "cases_missing")
    require(len(cases) == len(CASE_NAMES), "case_count_invalid")
    projected = []
    names = []
    for case in cases:
        require(isinstance(case, dict), "case_shape_invalid")
        name, status = case.get("name"), case.get("status")
        require(isinstance(name, str), "case_name_invalid")
        require(status == "passed", "case_not_green")
        names.append(name)
        projected.append({"name": name, "status": status})
    require(tuple(names) == CASE_NAMES, "case_names_mismatch")
    return projected


def collect(args):
    qualification = load_json(args.qualification, "qualification")
    provider = load_json(args.provider_report, "provider_report")
    text = json.dumps({"qualification": qualification, "provider": provider},
                      sort_keys=True)
    reject_unsafe_payload({"qualification": qualification, "provider": provider}, text)

    require(qualification.get("passed") is True, "qualification_not_passed")
    require(qualification.get("issue") == 82, "issue_invalid")
    require(qualification.get("schema") ==
            "rootyard/issue82-legacy135-qualification/v1",
            "qualification_schema_invalid")
    require(qualification.get("kind") ==
            "rootyard/issue82-legacy135-qualification",
            "qualification_kind_invalid")
    require(qualification.get("case_count") == len(CASE_NAMES),
            "case_count_invalid")
    cases = validate_cases(qualification)
    target = qualification.get("target") or {}
    require(target.get("schema") == CURRENT_SCHEMA_VERSION,
            "target_schema_invalid")
    require(target.get("format") == CURRENT_BACKUP_FORMAT,
            "target_format_invalid")
    candidate = qualification.get("candidate") or {}
    producer = qualification.get("producer") or {}
    require(candidate.get("source", {}).get("commit") ==
            args.expected_candidate_commit, "candidate_commit_invalid")
    require(producer.get("source", {}).get("commit") ==
            FROZEN_SOURCE_COMMIT == args.expected_producer_commit,
            "producer_commit_invalid")
    require(producer.get("source_format") == 11 and
            producer.get("source_schema") == 135, "producer_catalog_invalid")
    require(provider.get("schema") ==
            "rootyard/issue82-legacy135-provider/v1", "provider_schema_invalid")
    require(provider.get("image_digest") == VAULT_IMAGE,
            "provider_image_invalid")
    require(provider.get("vault_version") == VAULT_VERSION,
            "provider_version_invalid")
    require(provider.get("owned_container") is True,
            "provider_not_owned")
    require(provider.get("transit_round_trip") is True and
            provider.get("service_policy_scoped") is True,
            "provider_preflight_invalid")
    require(provider.get("raw_logs_persisted") is False and
            provider.get("credential_file_written") is False,
            "provider_privacy_invalid")
    require(provider.get("cleanup") == "stopped", "provider_cleanup_not_stopped")
    bound_provider = qualification.get("provider") or {}
    require(bound_provider.get("image_digest") == provider.get("image_digest") and
            bound_provider.get("cleanup") == provider.get("cleanup"),
            "provider_binding_mismatch")

    candidate_receipt = receipt_identity(args.candidate_receipt, "candidate")
    producer_receipt = receipt_identity(args.producer_receipt, "producer")
    require(candidate_receipt["sha256"] != producer_receipt["sha256"],
            "receipt_roles_reused")
    require(candidate_receipt["path"] != producer_receipt["path"],
            "receipt_paths_reused")
    require(candidate_receipt["workspace_commit"] ==
            args.expected_candidate_commit, "candidate_receipt_commit_mismatch")
    require(producer_receipt["workspace_commit"] == FROZEN_SOURCE_COMMIT,
            "producer_receipt_commit_mismatch")
    require(candidate_receipt["binary_sha256"] ==
            candidate.get("binary_sha256"), "candidate_binary_binding_mismatch")
    require(producer_receipt["binary_sha256"] ==
            producer.get("binary_sha256"), "producer_binary_binding_mismatch")
    require(candidate_receipt["receipt_schema"] == "v2",
            "candidate_receipt_not_v2")

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "kind": "rootyard/issue82-legacy135-hosted-qualification",
        "issue": 82,
        "passed": True,
        "target": {"schema": CURRENT_SCHEMA_VERSION,
                   "format": CURRENT_BACKUP_FORMAT},
        "cases": cases,
        "case_count": len(cases),
        "candidate": {
            "source_commit": args.expected_candidate_commit,
            "binary_sha256": candidate_receipt["binary_sha256"],
            "receipt_sha256": candidate_receipt["sha256"],
            "receipt_schema": candidate_receipt["receipt_schema"],
        },
        "producer": {
            "source_commit": FROZEN_SOURCE_COMMIT,
            "source_format": 11,
            "source_schema": 135,
            "binary_sha256": producer_receipt["binary_sha256"],
            "receipt_sha256": producer_receipt["sha256"],
            "receipt_schema": producer_receipt["receipt_schema"],
            "historical_binary_sha256_asserted": False,
        },
        "provider": {
            "image_digest": provider.get("image_digest"),
            "vault_version": provider.get("vault_version"),
            "transit_round_trip": True,
            "service_policy_scoped": True,
            "cleanup": "stopped",
            "raw_logs_persisted": False,
            "credential_file_written": False,
        },
        "bindings": {
            "qualification_sha256": sha256_file(args.qualification),
            "provider_report_sha256": sha256_file(args.provider_report),
            "workflow_sha256": sha256_file(args.workflow),
            "wrapper_sha256": sha256_file(args.wrapper),
            "collector_sha256": sha256_file(Path(__file__).resolve()),
        },
        "receipts_role_separated": True,
        "raw_logs_uploaded": False,
        "archive_bytes_uploaded": False,
        "limitations": [
            "Focused loopback metadata/functional restore drill only.",
            "No production RPO/RTO, power-loss, deployment or broad fault claim.",
            "The frozen producer is rebuilt from the exact 560 source; its historical binary hash is not asserted.",
        ],
    }
    return manifest


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", required=True)
    parser.add_argument("--provider-report", required=True)
    parser.add_argument("--candidate-receipt", required=True)
    parser.add_argument("--producer-receipt", required=True)
    parser.add_argument("--expected-candidate-commit", required=True)
    parser.add_argument("--expected-producer-commit", default=FROZEN_SOURCE_COMMIT)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        manifest = collect(args)
        receipts.atomic_write_json(args.output, manifest)
        print(json.dumps({"passed": True, "case_count": manifest["case_count"],
                          "schema": manifest["target"]["schema"],
                          "format": manifest["target"]["format"]}, sort_keys=True))
        return 0
    except CollectorError as error:
        print("legacy135_qualification_manifest: " + error.code, file=sys.stderr)
        return 1
    except Exception:
        print("legacy135_qualification_manifest: unexpected_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
