#!/usr/bin/env python3
"""Schema-aware build-receipt binding for the RefStore backup fixture pair.

The populated RefStore backup drills consume two prebuilt executables from one
explicit native batch: a Rust integration-test helper and the candidate
``rootyard`` application binary.  Historical receipts are v1.  The current
producer writes shared v2 receipts (``rootyard/native-build-receipt/v2``) under
``cargo_artifacts`` with Cargo's literal per-artifact ``fresh`` boolean.

This module keeps the legacy v1 decision inside the two drills and dispatches a
v2 pair to the pure shared reader.  Loading and validating a receipt only reads
and hashes files: it never invokes Cargo, rustc, rustup, a builder or a
subprocess, and it never rewrites the receipt.  Unknown schema discriminators
and mixed v1/v2 pairs fail closed.

The v2 binding selects the exact ``(kind, target)`` rows instead of trusting an
array position:

* helper: ``kind == "rust-integration-test"``, one ``test`` row for the
  requested fixture target, the exact ``tests/ref_store_*_backup_fixture.rs``
  source path and digest, the relocated executable digest, a test profile, the
  real ``pando-lab`` feature/no-default selection and a v2 batch link;
* application: one ``lib`` and one ``bin`` row for target ``rootyard`` at
  ``src/lib.rs`` / ``src/main.rs``, an executable digest that matches the
  receipt's primary/relocated digest, the producer's actual ``dev`` (CLI) or
  ``test`` (batch) profile, the recorded lock file, the target triple and the
  shared source/config/toolchain/batch closure.

The two receipts must agree on ``source_inputs_sha256``,
``cargo_lock_sha256``, ``config_digest``, the full bound-input digest, the
workspace commit and the toolchain identity.  A batch application receipt must
also point at the helper receipt's batch manifest.  A legitimately qualified
CLI ``native-binary`` receipt is accepted without a batch link because its
source/config/toolchain closure is still enforced.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import native_build_receipt as native_receipts  # noqa: E402

RECEIPT_SCHEMA_V2 = native_receipts.RECEIPT_SCHEMA_V2
BATCH_KIND = "rootyard/native-build-batch"
APP_BATCH_KIND = "native-build-batch-bin"
APP_CLI_KIND = "native-binary"
APP_TARGET = "rootyard"
APP_LIB_SOURCE = "src/lib.rs"
APP_BIN_SOURCE = "src/main.rs"
EXPECTED_FEATURES = ["pando-lab"]


def sha256_file(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def candidate_receipt(path):
    """Locate the ``.build.json`` receipt that belongs to one built executable."""
    path = Path(path)
    for option in (Path(str(path) + ".build.json"), path.with_suffix(".build.json")):
        if option.is_file():
            return option
    raise AssertionError("no build receipt next to " + str(path) + " (expected " + str(path) + ".build.json)")


def read_receipt(path, label):
    """Read one receipt object without interpreting its schema."""
    path = Path(path)
    assert path.is_file(), label + " is missing: " + str(path)
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(label + " is not readable JSON: " + str(error)) from error
    assert isinstance(value, dict), label + " is not a JSON object"
    return value


def receipt_schema(receipt, label):
    """Return ``v1`` or ``v2``; reject every unknown discriminator."""
    if "receipt_schema" not in receipt:
        return "v1"
    schema = receipt.get("receipt_schema")
    if schema == RECEIPT_SCHEMA_V2:
        return "v2"
    raise AssertionError(label + " has an unknown receipt_schema " + repr(schema))


def receipt_pair_schema(helper_receipt, app_receipt, label):
    """Dispatch one helper/application receipt pair and reject mixed schemas."""
    helper = read_receipt(helper_receipt, label + " helper build receipt")
    application = read_receipt(app_receipt, label + " candidate application build receipt")
    helper_schema = receipt_schema(helper, label + " helper build receipt")
    app_schema = receipt_schema(application, label + " candidate application build receipt")
    if helper_schema != app_schema:
        raise AssertionError(
            label + " helper receipt is " + helper_schema +
            " but the candidate application receipt is " + app_schema +
            "; both executables must come from the same receipt schema and build")
    return helper_schema


def _load_v2(path, binary, label):
    try:
        return native_receipts.load_receipt(
            path, binary_path=binary, forbid_implicit_build=True)
    except native_receipts.ReceiptError as error:
        raise AssertionError(label + " v2 build receipt is invalid: " + str(error)) from error


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _check_features(payload, label):
    features = payload.get("features")
    _require(isinstance(features, dict), label + " receipt has no features object")
    _require(features.get("enabled") == EXPECTED_FEATURES,
             label + " receipt features.enabled is " + repr(features.get("enabled")) +
             ", expected " + repr(EXPECTED_FEATURES))
    _require(features.get("no_default_features") is False,
             label + " receipt must record no_default_features=false")


def _check_selection(payload, label):
    selection = payload.get("selection")
    _require(isinstance(selection, dict), label + " v2 batch receipt has no selection record")
    _require(selection.get("features") == ",".join(EXPECTED_FEATURES),
             label + " selection.features is " + repr(selection.get("features")))
    _require(selection.get("no_default_features") is False,
             label + " selection.no_default_features must be false")
    _require(selection.get("profile") == payload.get("profile"),
             label + " selection.profile does not match the receipt profile")
    _require(selection.get("strip_debuginfo") is True,
             label + " selection.strip_debuginfo must be true")


def _same_toolchain(helper, application, label):
    helper = helper or {}
    application = application or {}
    _require(helper.get("target_triple") == application.get("target_triple"),
             label + " helper and application target triples differ")
    for name in ("cargo", "rustc"):
        left = helper.get(name)
        right = application.get(name)
        _require(isinstance(left, dict) and isinstance(right, dict),
                 label + " helper and application toolchain." + name + " records are missing")
        for field in ("executable_sha256", "commit_hash", "release", "host"):
            _require(left.get(field) == right.get(field),
                     label + " helper and application toolchain." + name + "." + field + " differ")
    for field in ("pinned_channel", "pin_source"):
        _require(helper.get(field) == application.get(field),
                 label + " helper and application toolchain." + field + " differ")


def validate_v2_pair(*, helper, app_binary, helper_target, helper_source,
                     helper_source_relative, helper_receipt, app_receipt, label):
    """Validate one v2 helper/application pair through the shared pure reader."""
    helper = Path(helper)
    app_binary = Path(app_binary)
    helper_source = Path(helper_source)
    helper_receipt = Path(helper_receipt)
    app_receipt = Path(app_receipt)
    _require(helper.is_file(), label + " binary is missing: " + str(helper))
    _require(app_binary.is_file(), "candidate application binary is missing: " + str(app_binary))
    _require(helper_source.is_file(), "helper source is missing: " + str(helper_source))

    helper_valid = _load_v2(helper_receipt, helper, label)
    app_valid = _load_v2(app_receipt, app_binary, "candidate application")
    helper_payload = helper_valid.payload
    app_payload = app_valid.payload
    _require(helper_valid.schema == "v2", label + " helper receipt is not v2")
    _require(app_valid.schema == "v2", "candidate application receipt is not v2")

    # --- the selected helper integration-test artifact -------------------
    _require(helper_payload.get("kind") == "rust-integration-test",
             label + " receipt kind is " + repr(helper_payload.get("kind")))
    _require(helper_payload.get("relocated_artifact") is True,
             label + " receipt must record the relocated integration-test artifact")
    _require(helper_payload.get("profile") == "test",
             label + " receipt profile is " + repr(helper_payload.get("profile")) +
             ", expected the test profile")
    _require(helper_payload.get("integration_test_source") == helper_source_relative,
             label + " receipt integration_test_source is " +
             repr(helper_payload.get("integration_test_source")) +
             ", expected " + helper_source_relative)
    helper_source_sha = sha256_file(helper_source)
    _require(helper_payload.get("integration_test_source_sha256") == helper_source_sha,
             label + " receipt was produced from different integration-test source")
    _require(len(helper_valid.artifacts) == 1,
             label + " receipt must record exactly one selected test artifact")
    helper_row = helper_valid.artifacts[0]
    _require(helper_row["kind"] == "test", label + " selected artifact kind is not test")
    _require(helper_row["target"] == helper_target,
             label + " selected artifact target is " + repr(helper_row["target"]) +
             ", expected " + helper_target)
    _require(helper_row["source"] == helper_source_relative,
             label + " selected artifact source is " + repr(helper_row["source"]))
    _require(helper_row["source_sha256"] == helper_source_sha,
             label + " selected artifact source digest differs from the source file")
    _require(helper_row["profile"].get("test") is True,
             label + " selected artifact was not built with a test profile")
    helper_actual = sha256_file(helper)
    _require(helper_valid.binary_sha256 == helper_actual,
             label + " binary does not match its build receipt")
    _require(helper_row["executable_sha256"] == helper_actual,
             label + " selected artifact executable digest differs from the helper binary")
    _require(helper_payload.get("original_artifact_sha256") == helper_actual,
             label + " relocated original digest differs from the helper binary")
    helper_batch = helper_valid.batch
    _require(helper_batch is not None, label + " v2 receipt has no batch link")
    _require(helper_batch["kind"] == BATCH_KIND, label + " batch.kind is invalid")
    _require(helper_batch["receipt_version"] == 2,
             label + " batch.receipt_version is not 2")
    _require(helper_target in helper_batch["targets"],
             label + " batch.targets does not name " + helper_target)
    _check_features(helper_payload, label)
    _check_selection(helper_payload, label)

    # --- the candidate application receipt -------------------------------
    app_kind = app_payload.get("kind")
    _require(app_kind in (APP_BATCH_KIND, APP_CLI_KIND),
             "candidate application receipt kind is " + repr(app_kind))
    app_profile = app_payload.get("profile")
    if app_kind == APP_BATCH_KIND:
        _require(app_profile == "test",
                 "candidate application batch profile is " + repr(app_profile) +
                 ", expected test")
        app_batch = app_valid.batch
        _require(app_batch is not None,
                 "candidate application batch receipt has no batch link")
        _require(app_batch["kind"] == BATCH_KIND, "candidate application batch.kind is invalid")
        _require(app_batch["receipt_version"] == 2,
                 "candidate application batch.receipt_version is not 2")
        _require(Path(app_batch["manifest"]).resolve() == Path(helper_batch["manifest"]).resolve(),
                 "helper and candidate application receipts do not name the same batch manifest")
        _require(helper_batch["bound_inputs_sha256"] == app_batch["bound_inputs_sha256"],
                 "helper and candidate application batch bound-input digests differ")
        _require(APP_TARGET in app_batch["targets"],
                 "candidate application batch.targets does not name " + APP_TARGET)
    else:
        _require(app_profile == "dev",
                 "candidate application CLI profile is " + repr(app_profile) +
                 ", expected the actual dev producer profile")

    _check_features(app_payload, "candidate application")
    if app_payload.get("selection") is not None:
        _check_selection(app_payload, "candidate application")

    libs = [row for row in app_valid.artifacts
            if row["kind"] == "lib" and row["target"] == APP_TARGET]
    bins = [row for row in app_valid.artifacts
            if row["kind"] == "bin" and row["target"] == APP_TARGET]
    _require(len(libs) == 1,
             "candidate application receipt must record exactly one rootyard lib artifact")
    _require(len(bins) == 1,
             "candidate application receipt must record exactly one rootyard bin artifact")
    lib_row = libs[0]
    bin_row = bins[0]
    _require(lib_row["source"] == APP_LIB_SOURCE,
             "candidate application lib source is " + repr(lib_row["source"]))
    _require(bin_row["source"] == APP_BIN_SOURCE,
             "candidate application bin source is " + repr(bin_row["source"]))
    _require(lib_row["profile"].get("test") is False,
             "candidate application lib artifact has a test profile")
    _require(bin_row["profile"].get("test") is False,
             "candidate application bin artifact has a test profile")
    app_actual = sha256_file(app_binary)
    _require(app_valid.binary_sha256 == app_actual,
             "candidate application binary does not match its own build receipt")
    if app_payload.get("relocated_artifact") is True:
        relocated = app_payload.get("original_artifact_sha256")
        _require(relocated == app_valid.binary_sha256,
                 "candidate application relocated digest differs from binary_sha256")
        expected_bin_digest = relocated
    else:
        expected_bin_digest = app_valid.binary_sha256
    _require(bin_row["executable_sha256"] == expected_bin_digest,
             "candidate application rootyard bin digest does not match its receipt")
    _require(isinstance(app_payload.get("lock_file"), str) and
             Path(app_payload["lock_file"]).is_absolute(),
             "candidate application receipt has no absolute lock_file")

    # --- one build closure across both receipts --------------------------
    _require(helper_valid.source_inputs_sha256 == app_valid.source_inputs_sha256,
             "helper and candidate application source_inputs_sha256 differ")
    _require(helper_payload.get("cargo_lock_sha256") == app_payload.get("cargo_lock_sha256"),
             "helper and candidate application Cargo.lock digests differ")
    _require(helper_valid.config_digest == app_valid.config_digest,
             "helper and candidate application config digests differ")
    _require(helper_payload.get("bound_inputs", {}).get("digest") ==
             app_payload.get("bound_inputs", {}).get("digest"),
             "helper and candidate application bound-input digests differ")
    _require(helper_valid.workspace_commit == app_valid.workspace_commit,
             "helper and candidate application workspace commits differ")
    _same_toolchain(helper_valid.toolchain, app_valid.toolchain, label)
    _require(helper_valid.toolchain.get("target_triple") ==
             app_valid.toolchain.get("target_triple"),
             label + " helper and candidate application target triples differ")

    return {
        "binary": str(helper),
        "binary_sha256": helper_actual,
        "build_receipt": str(helper_receipt),
        "build_receipt_sha256": helper_valid.receipt_sha256,
        "build_kind": "rust-integration-test",
        "receipt_schema": RECEIPT_SCHEMA_V2,
        "cargo_artifacts": [dict(helper_row)],
        "fresh": helper_row["fresh"],
        "test_profile": True,
        "relocated_artifact": True,
        "original_artifact_sha256": helper_payload["original_artifact_sha256"],
        "integration_test_source": helper_payload["integration_test_source"],
        "integration_test_source_sha256": helper_source_sha,
        "integration_test_source_matches_source_file": True,
        "source_inputs_sha256": helper_valid.source_inputs_sha256,
        "workspace_commit": helper_valid.workspace_commit,
        "bound_inputs_sha256": helper_payload["bound_inputs"]["digest"],
        "cargo_lock_sha256": helper_payload["cargo_lock_sha256"],
        "config_digest": helper_valid.config_digest,
        "target_triple": helper_valid.toolchain["target_triple"],
        "batch_manifest": helper_batch["manifest"],
        "batch_receipt_version": helper_batch["receipt_version"],
        "candidate_application_receipt": str(app_receipt),
        "candidate_application_receipt_sha256": app_valid.receipt_sha256,
        "candidate_application_sha256": app_actual,
        "candidate_application_kind": app_kind,
        "candidate_application_profile": app_profile,
        "candidate_application_cargo_artifacts": [dict(lib_row), dict(bin_row)],
        "candidate_application_fresh": {"lib": lib_row["fresh"], "bin": bin_row["fresh"]},
        "candidate_application_features": dict(app_payload["features"]),
        "candidate_application_lock_file": app_payload["lock_file"],
        "candidate_application_target_triple": app_valid.toolchain["target_triple"],
        "candidate_application_source_inputs_sha256": app_valid.source_inputs_sha256,
        "source_inputs_match_candidate_application": True,
        "same_batch_manifest": app_valid.batch is not None,
        "shared_config_and_toolchain_closure": True,
    }
