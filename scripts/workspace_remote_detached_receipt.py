#!/usr/bin/env python3
"""Write one sanitized receipt for the #88 remote checkpoint witness.

This focused helper reuses the existing FUSE receipt parser and digest helpers.
It never runs the witness, starts a service, contacts a network or rewrites
provenance. The raw unittest stream is read only to count the exact selected
case and its summary; its bytes, exception text, database URL, object-store
endpoint and credentials are never copied into the receipt or printed.

The witness bytes are pinned here as well as in the workflow. A changed
implementation, a different test case, a backend switch or a Garage image
mismatch is a failed receipt, never a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace_fuse_compat_receipt import HEX40, bounded, digest, parse_unittest  # noqa: E402

SCHEMA = "rootyard/workspace-remote-detached-receipt/v1"
TEST_FILE = "tests/workspace_remote_detached_witness.py"
TEST_CASE = "test_detached_inert_lfs_remote_publish_and_fresh_root_restore"
GATE = "ROOTYARD_TEST_ISSUE88_REMOTE_DETACHED_WITNESS=1"
BACKEND = "ROOTYARD_TEST_FUSE_BACKEND=fuse"
WORKFLOW = ".github/workflows/native-kernel-acceptance.yml"
EXPECTED_TEST_SHA256 = "bfbfc195e3457a18463ffa7eb13d98f5bc95430c027fbe68508584a068b1edc1"
EXPECTED_TEST_BLOB_SHA1 = "c8075efe514ecec8fb695852abcbc18ea53ce582"
EXPECTED_GARAGE_VERSION = "2.1.0"
EXPECTED_GARAGE_IMAGE_DIGEST = (
    "sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a"
)
SOURCE_ROOT_POLICY = (
    "owned temporary source root, quarantined by exact rename after clean source exit"
)
DESTINATION_ROOT_POLICY = "separate fresh empty owned root"
SCOPE = (
    "single-host source FUSE workspace, authenticated remote checkpoint publish "
    "and a fresh destination data root restore; no physical multi-host, remote "
    "LFS hydration, FUSE-on-destination, arbitrary filter execution or tenant "
    "authorization claim"
)


def git_blob_sha1(path):
    """Return the exact Git SHA-1 blob id for the file bytes, or None."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--raw-log", default="")
    parser.add_argument("--exit-code", type=int, default=1)
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--source-tree", default="")
    parser.add_argument("--binary", default="")
    parser.add_argument("--build-receipt", default="")
    parser.add_argument("--harness", default=TEST_FILE)
    parser.add_argument("--workflow", default=WORKFLOW)
    parser.add_argument("--test-case", default=TEST_CASE)
    parser.add_argument("--database-name", default="")
    parser.add_argument("--pg-version", default="")
    parser.add_argument("--dev-fuse", default="")
    parser.add_argument("--unshare-status", default="")
    parser.add_argument("--bwrap-status", default="")
    parser.add_argument("--fusermount-version", default="")
    parser.add_argument("--garage-version", default="")
    parser.add_argument("--garage-image-digest", default="")
    parser.add_argument("--blocked", action="store_true")
    parser.add_argument("--classification", default="")
    args = parser.parse_args()

    source_commit_ok = bool(HEX40.match(args.source_commit or ""))
    source_tree_ok = bool(HEX40.match(args.source_tree or ""))
    binary_sha256 = digest(args.binary)
    build_receipt_sha256 = digest(args.build_receipt)
    harness_sha256 = digest(args.harness)
    harness_blob_sha1 = git_blob_sha1(args.harness)
    workflow_sha256 = digest(args.workflow)
    harness_pinned = (
        harness_sha256 == EXPECTED_TEST_SHA256
        and harness_blob_sha1 == EXPECTED_TEST_BLOB_SHA1
        and Path(args.harness).as_posix() == TEST_FILE
        and args.test_case == TEST_CASE
    )
    workflow_path_ok = Path(args.workflow).as_posix() == WORKFLOW
    garage_pinned = (
        args.garage_version == EXPECTED_GARAGE_VERSION
        and args.garage_image_digest == EXPECTED_GARAGE_IMAGE_DIGEST
    )
    postgres_ok = bool(args.database_name) and str(args.pg_version).startswith("17.")
    preflight_ok = all(
        value
        for value in (
            args.dev_fuse,
            args.unshare_status,
            args.bwrap_status,
            args.fusermount_version,
        )
    )
    inputs_ok = all(
        value
        for value in (
            args.source_commit,
            args.source_tree,
            args.binary,
            args.build_receipt,
            binary_sha256,
            build_receipt_sha256,
            harness_sha256,
            workflow_sha256,
        )
    ) and source_commit_ok and source_tree_ok and workflow_path_ok

    parsed = {
        "tests_run": 0,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
        "expected_case_selected": False,
        "case_outcome": "not_run",
        "summary": "not_run",
        "passed": False,
        "classification": "blocked",
    }
    if not args.blocked:
        if not inputs_ok:
            parsed["classification"] = "input_unavailable"
        elif not args.raw_log:
            parsed["classification"] = "unittest_output_missing"
        else:
            parsed.update(parse_unittest(args.raw_log, args.exit_code, args.test_case))
            if parsed["passed"] and not harness_pinned:
                parsed["passed"] = False
                parsed["classification"] = "witness_bytes_or_case_mismatch"
            elif parsed["passed"] and not preflight_ok:
                parsed["passed"] = False
                parsed["classification"] = "fuse_preflight_unavailable"
            elif parsed["passed"] and not postgres_ok:
                parsed["passed"] = False
                parsed["classification"] = "postgres17_unavailable"
            elif parsed["passed"] and not garage_pinned:
                parsed["passed"] = False
                parsed["classification"] = "garage_fixture_mismatch"

    if args.blocked:
        status = "blocked"
        classification = args.classification or "blocked"
    else:
        status = "passed" if parsed["passed"] else "failed"
        classification = args.classification or parsed["classification"]

    receipt = {
        "schema": SCHEMA,
        "status": status,
        "classification": classification,
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "binary_sha256": binary_sha256,
        "build_receipt_sha256": build_receipt_sha256,
        "harness_sha256": harness_sha256,
        "harness_blob_sha1": harness_blob_sha1,
        "harness_pinned": harness_pinned,
        "workflow_sha256": workflow_sha256,
        "test_file": TEST_FILE,
        "test_case": args.test_case,
        "expected_case_selected": parsed["expected_case_selected"],
        "case_outcome": parsed["case_outcome"],
        "tests_run": parsed["tests_run"],
        "skipped": parsed["skipped"],
        "failures": parsed["failures"],
        "errors": parsed["errors"],
        "summary": parsed["summary"],
        "unittest_exit_code": args.exit_code,
        "selection": {"gate": GATE, "backend": BACKEND},
        "database": {
            "name": args.database_name,
            "server_version": bounded(args.pg_version, 40),
        },
        "garage": {
            "fixture": "job-owned pinned Garage 2.1",
            "version": bounded(args.garage_version, 40),
            "image_digest": bounded(args.garage_image_digest, 100),
        },
        "data_roots": {
            "source": SOURCE_ROOT_POLICY,
            "destination": DESTINATION_ROOT_POLICY,
            "independent": True,
            "physical_multi_host": False,
            "source_mount_mode": "fuse",
            "destination_mount_mode": "direct",
        },
        "preflight": {
            "dev_fuse": bounded(args.dev_fuse),
            "unshare": bounded(args.unshare_status),
            "bwrap": bounded(args.bwrap_status),
            "fusermount3": bounded(args.fusermount_version),
        },
        "runner": {
            "os": bounded(platform.platform()),
            "kernel": bounded(os.uname().release),
            "python": platform.python_version(),
        },
        "raw_unittest_output_retained": False,
        "database_url_retained": False,
        "object_store_endpoint_retained": False,
        "credentials_retained": False,
        "scope": SCOPE,
    }

    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, output)
    except OSError as error:
        print(
            "#88 remote receipt could not be written: " + type(error).__name__,
            file=sys.stderr,
        )
        return 2

    print(
        "#88 remote receipt: "
        f"{status} ({classification}); tests_run={parsed['tests_run']} "
        f"skipped={parsed['skipped']} failures={parsed['failures']} "
        f"errors={parsed['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
