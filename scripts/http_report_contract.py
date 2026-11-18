#!/usr/bin/env python3
"""Static issue107 retained-HTTP report inventory and Python input closure."""
from __future__ import annotations

import hashlib
from pathlib import Path

EXPECTED_SUITES = (
    {
        "report": "roots",
        "source": "tests/refstore_roots_http.py",
        "kind": "rootyard/refstore-roots-http",
        "cases": ("roots_http_metadata_create_release_and_intent",),
    },
    {
        "report": "snapshot",
        "source": "tests/refstore_snapshot_http.py",
        "kind": "rootyard/refstore-snapshot-http",
        "cases": (
            "snapshot_http_create_read_replay_after_ref_advance",
            "snapshot_http_renew_release_expiry_and_exact_replay",
            "snapshot_http_authz_malformed_and_cross_repo_refusals",
            "snapshot_http_historical_tree_blob_and_current_reachability",
            "snapshot_http_historical_tree_blob_auth_and_state_refusals",
            "snapshot_http_historical_blob_common_read_bound",
        ),
    },
    {
        "report": "root-browse",
        "source": "tests/refstore_root_browse_http.py",
        "kind": "rootyard/refstore-root-browse-http",
        "cases": (
            "roots_http_browse_selected_closures",
            "roots_http_browse_sha256",
            "roots_http_post_json_scope_revocation_fence",
            "roots_http_registered_pack_get_refusal_no_fallback",
        ),
    },
    {
        "report": "cancel-scope-race",
        "source": "tests/refstore_cancel_scope_race.py",
        "kind": "rootyard/refstore-cancel-scope-race",
        "cases": (
            "narrow_first_scope_denial_leaves_cancel_state_unchanged",
            "cancel_first_late_scope_holds_until_terminal_commit",
        ),
    },
)
EXPECTED_CASE_COUNT = 13

INPUT_PATHS = (
    "tests/refstore_roots_http.py",
    "tests/refstore_snapshot_http.py",
    "tests/refstore_root_browse_http.py",
    "tests/refstore_cancel_scope_race.py",
    "tests/blob_commit_unknown_service.py",
    "tests/blob_only_service.py",
    "tests/e2e.py",
    "tests/native_evidence.py",
    "tests/ops_provenance.py",
    "tests/owned_fuse_cleanup.py",
    "tests/blob_gateway_support/root_blob_fault_gate.py",
    "tests/test_root_blob_fault_gate.py",
    "tests/test_root_browse_race_cleanup.py",
    "tests/test_issue107_http_report_validator.py",
    "scripts/http_report_contract.py",
    "scripts/issue107_http_report_validator.py",
    "scripts/native_build_receipt.py",
    "scripts/native_report_manifest.py",
    ".github/workflows/refstore-protocol-acceptance.yml",
)


class ContractError(ValueError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_inputs(root):
    base = Path(root).resolve()
    result = {}
    for relative in INPUT_PATHS:
        path = base / relative
        if not path.is_file() or path.is_symlink():
            raise ContractError("required HTTP input is unavailable")
        result[relative] = sha256_file(path)
    return result


def suite_by_name(name):
    for suite in EXPECTED_SUITES:
        if suite["report"] == name:
            return suite
    return None
