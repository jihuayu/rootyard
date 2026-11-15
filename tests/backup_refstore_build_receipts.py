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
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import export_native_artifacts as cas_exporter  # noqa: E402
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


def expected_source_commit(environ=None):
    """Return the v2 expected source commit and its honest source label.

    Mirrors the collaborator transport contract: an explicit nonempty
    ``ROOTYARD_EXPECTED_SOURCE_COMMIT`` wins, otherwise a present ``GITHUB_SHA``
    is the fallback.  An empty explicit value is treated as absent; a malformed
    nonempty value is passed to the reader so it fails closed.
    """
    environ = os.environ if environ is None else environ
    explicit = environ.get("ROOTYARD_EXPECTED_SOURCE_COMMIT")
    fallback = environ.get("GITHUB_SHA")
    if explicit:
        return explicit, "ROOTYARD_EXPECTED_SOURCE_COMMIT"
    if fallback:
        return fallback, "GITHUB_SHA"
    return None, None


def _load_v2(path, binary, label, expected_commit=None):
    try:
        return native_receipts.load_receipt(
            path, binary_path=binary, expected_commit=expected_commit,
            forbid_implicit_build=True)
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


STORE_SCHEMA = "rootyard/native-artifact-store/v1"
MANIFEST_VERSION = 2


def _absolute_manifest_path(value, label, what):
    _require(isinstance(value, str) and bool(value),
             label + " " + what + " must be a nonempty path string")
    path = Path(value)
    _require(path.is_absolute(), label + " " + what + " must be absolute")
    _require(".." not in path.parts, label + " " + what + " must not traverse")
    return path


def _regular_manifest_file(path, label, what):
    path = Path(path)
    _require(path.exists(), label + " " + what + " is missing: " + str(path))
    _require(path.is_file(), label + " " + what + " must be a regular file")
    _require(not path.is_symlink(), label + " " + what + " must not be a symlink")
    return path


def _resolved_equal(left, right):
    try:
        return Path(left).resolve() == Path(right).resolve()
    except (OSError, ValueError):
        return False


def _inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False
    return True


def _manifest_artifact_rows(manifest, label):
    build = manifest.get("build")
    _require(isinstance(build, dict), label + " manifest build must be an object")
    rows = None
    for key in ("cargo_artifacts", "artifacts"):
        if isinstance(build.get(key), list):
            rows = build[key]
            break
    if rows is None:
        for key in ("cargo_artifacts", "artifacts"):
            if isinstance(manifest.get(key), list):
                rows = manifest[key]
                break
    _require(isinstance(rows, list) and bool(rows),
             label + " manifest must record a nonempty cargo_artifacts list")
    _require(all(isinstance(row, dict) for row in rows),
             label + " manifest cargo_artifacts entries must be objects")
    seen = set()
    for row in rows:
        _require(row.get("kind") in native_receipts.ARTIFACT_KINDS,
                 label + " manifest artifact kind is invalid")
        _require(isinstance(row.get("target"), str) and bool(row.get("target")),
                 label + " manifest artifact target must be a nonempty string")
        _require(isinstance(row.get("fresh"), bool),
                 label + " manifest artifact fresh must be a JSON boolean")
        key = (row.get("kind"), row.get("target"))
        _require(key not in seen, label + " manifest has a duplicate artifact row")
        seen.add(key)
    return rows, [(row["kind"], row["target"]) for row in rows]


def _manifest_build_row(rows, kind, target, label):
    matches = [row for row in rows
               if row.get("kind") == kind and row.get("target") == target]
    _require(len(matches) == 1,
             label + " manifest must record exactly one (" + kind + ", " + target +
             ") build artifact")
    return matches[0]


def _manifest_entry(manifest, kind, target, label):
    artifacts = manifest.get("artifacts")
    _require(isinstance(artifacts, list) and bool(artifacts),
             label + " manifest artifacts must be a nonempty list")
    _require(all(isinstance(row, dict) for row in artifacts),
             label + " manifest artifacts entries must be objects")
    matches = [row for row in artifacts
               if row.get("kind") == kind and row.get("target") == target]
    _require(len(matches) == 1,
             label + " manifest must record exactly one published (" + kind + ", " +
             target + ") artifact")
    return matches[0]


def _compare_build_row(manifest_row, receipt_row, label):
    for field in ("package_id", "profile", "source", "source_sha256",
                  "executable", "executable_sha256"):
        if field in manifest_row:
            _require(manifest_row[field] == receipt_row[field],
                     label + " manifest artifact " + field +
                     " does not match the receipt row")
    _require(manifest_row["fresh"] is receipt_row["fresh"],
             label + " manifest artifact freshness does not match the receipt")
    _require(manifest_row["source"] == receipt_row["source"],
             label + " manifest artifact source does not match the receipt")
    _require(manifest_row["source_sha256"] == receipt_row["source_sha256"],
             label + " manifest artifact source digest does not match the receipt")


def _check_manifest_header(manifest, validated, batch, label):
    payload = validated.payload
    batch_version = batch.get("receipt_version")
    _require(batch_version == MANIFEST_VERSION,
             label + " batch receipt version must be 2")
    _require(manifest.get("manifest_version") == MANIFEST_VERSION,
             label + " manifest version must be 2")
    _require(manifest.get("manifest_version") == batch_version,
             label + " manifest version does not match the batch receipt")
    _require(manifest.get("source_commit") == validated.workspace_commit,
             label + " manifest source_commit does not match the receipt")
    _require(manifest.get("source_inputs_sha256") == validated.source_inputs_sha256,
             label + " manifest source_inputs_sha256 does not match the receipt")
    _require(manifest.get("cargo_lock_sha256") == payload.get("cargo_lock_sha256"),
             label + " manifest Cargo.lock digest does not match the receipt")
    _require(manifest.get("config_digest") == validated.config_digest,
             label + " manifest config digest does not match the receipt")
    _require(manifest.get("profile") == payload.get("profile"),
             label + " manifest profile does not match the receipt")
    _require(manifest.get("features") == payload.get("features"),
             label + " manifest features do not match the receipt")
    _require(manifest.get("target_triple") == payload.get("target_triple"),
             label + " manifest target triple does not match the receipt")
    if payload.get("selection") is not None:
        _require(manifest.get("selection") == payload.get("selection"),
                 label + " manifest selection does not match the receipt")
    if payload.get("build_options") is not None:
        _require(manifest.get("build_options") == payload.get("build_options"),
                 label + " manifest build options do not match the receipt")
    if payload.get("git_head") is not None:
        _require(manifest.get("git_head") == payload.get("git_head"),
                 label + " manifest git_head does not match the receipt")
    if payload.get("working_tree") is not None:
        _require(manifest.get("working_tree") == payload.get("working_tree"),
                 label + " manifest working tree does not match the receipt")
    receipt_bound = payload.get("bound_inputs")
    manifest_bound = manifest.get("bound_inputs")
    _require(isinstance(receipt_bound, dict) and isinstance(manifest_bound, dict),
             label + " manifest and receipt bound_inputs must be objects")
    _require(manifest_bound == receipt_bound,
             label + " manifest bound_inputs do not match the receipt")
    _require(manifest_bound.get("digest") == batch.get("bound_inputs_sha256"),
             label + " manifest bound-input digest does not match the batch link")
    _require(manifest.get("bound_input_inventory") == payload.get("bound_input_inventory"),
             label + " manifest bound-input inventory does not match the receipt")
    _same_toolchain(manifest.get("toolchain"), validated.toolchain, label + " manifest")
    architecture = manifest.get("architecture")
    if isinstance(architecture, dict):
        _require(architecture.get("target_triple") == payload.get("target_triple"),
                 label + " manifest architecture target does not match the receipt")
        if "host" in architecture:
            _require(architecture.get("host") == validated.toolchain["rustc"]["host"],
                     label + " manifest architecture host does not match the toolchain")
    else:
        _require(architecture == payload.get("target_triple"),
                 label + " manifest architecture does not match the receipt")
    _require(_resolved_equal(manifest.get("target_directory"), payload.get("target_dir")),
             label + " manifest target directory does not match the receipt")
    if payload.get("lock_file") is not None:
        _require(_resolved_equal(manifest.get("lock_file"), payload.get("lock_file")),
                 label + " manifest lock file does not match the receipt")
    build = manifest.get("build")
    _require(isinstance(build, dict), label + " manifest build must be an object")
    _require(build.get("command") == payload.get("command"),
             label + " manifest build command does not match the receipt")
    _require(build.get("commands") == 1,
             label + " manifest build must record exactly one command")


def _check_manifest_entry(manifest, entry, kind, target, validated, receipt_row,
                          consumed_binary, consumed_receipt, label):
    _require(entry.get("kind") == kind,
             label + " manifest artifact kind does not match")
    _require(entry.get("target") == target,
             label + " manifest artifact target does not match")
    if kind == "bin":
        _require(entry.get("implicit") is False,
                 label + " manifest bin artifact must not be implicit")
    else:
        _require(entry.get("implicit") is not True,
                 label + " manifest test artifact must not be implicit")
    _require(entry.get("fresh") is receipt_row["fresh"],
             label + " manifest artifact freshness does not match the receipt")
    _require(entry.get("sha256") == validated.binary_sha256,
             label + " manifest artifact digest does not match the receipt")
    _require(entry.get("source") == receipt_row["source"],
             label + " manifest artifact source does not match the receipt")
    if "source_sha256" in entry:
        _require(entry["source_sha256"] == receipt_row["source_sha256"],
                 label + " manifest artifact source digest does not match the receipt")
    _require(entry.get("profile") == receipt_row["profile"],
             label + " manifest artifact profile does not match the receipt")
    if "package_id" in entry:
        _require(entry["package_id"] == receipt_row["package_id"],
                 label + " manifest artifact package id does not match the receipt")
    if "original_artifact_sha256" in entry:
        _require(entry["original_artifact_sha256"] == receipt_row["executable_sha256"],
                 label + " manifest original artifact digest does not match the receipt")
    _require(_resolved_equal(entry.get("artifact"), consumed_binary),
             label + " manifest artifact path does not match the consumed binary")
    _require(_resolved_equal(entry.get("receipt"), consumed_receipt),
             label + " manifest receipt path does not match the consumed receipt")

    store = manifest.get("artifact_store")
    if store is None:
        _require(validated.payload.get("artifact_store") is None,
                 label + " non-CAS manifest receipt may not carry artifact_store")
        if kind == "bin":
            _require(validated.payload.get("relocated_artifact") is not True,
                     label + " non-CAS bin receipt may not be relocated")
        _require(sha256_file(consumed_receipt) == validated.receipt_sha256,
                 label + " consumed receipt bytes do not match the parsed receipt SHA")
        return
    _require(isinstance(store, dict), label + " manifest artifact_store must be an object")
    _require(store.get("schema") == STORE_SCHEMA,
             label + " manifest artifact_store schema is invalid")
    root = _absolute_manifest_path(store.get("root"), label, "artifact_store.root")
    sealed = store.get("sealed")
    _require(isinstance(sealed, list) and bool(sealed),
             label + " manifest artifact_store.sealed must be a nonempty list")
    objects = store.get("objects")
    _require(isinstance(objects, list) and bool(objects),
             label + " manifest artifact_store.objects must be a nonempty list")
    _require(all(isinstance(item, str) and bool(item) for item in objects),
             label + " manifest artifact_store.objects entries must be nonempty strings")
    record = entry.get("artifact_store")
    _require(isinstance(record, dict),
             label + " CAS manifest artifact must carry artifact_store")
    _require(objects.count(record.get("object")) == 1,
             label + " selected CAS object is not exactly one manifest "
                     "artifact_store.objects entry")
    try:
        if kind == "bin":
            cas_exporter.validate_bin(manifest, target, root, sealed, label)
        else:
            cas_exporter.validate_test(manifest, target, root, sealed, label)
    except cas_exporter.ExportError as error:
        raise AssertionError(label + " CAS artifact is invalid: " + str(error)) from error
    object_path = Path(record["object"])
    alias_stat = consumed_binary.stat()
    object_stat = object_path.stat()
    actual_same_inode = (
        (alias_stat.st_dev, alias_stat.st_ino) ==
        (object_stat.st_dev, object_stat.st_ino))
    if kind == "test":
        _require(Path(record["binary"]).name == Path(consumed_binary).name,
                 label + " sealed test snapshot basename is not the output basename")
        output_alias = record["output_alias"]
        _require(output_alias.get("same_inode_as_cas_object") is actual_same_inode,
                 label + " output alias same_inode claim does not match the actual "
                         "alias/object relation")
        canonical_stat = Path(record["binary"]).stat()
        actual_alias_canonical = (
            (alias_stat.st_dev, alias_stat.st_ino) ==
            (canonical_stat.st_dev, canonical_stat.st_ino))
        method = output_alias.get("method")
        if method == "hardlink":
            _require(actual_alias_canonical is True,
                     label + " hardlink output alias is not the canonical snapshot inode")
        else:
            _require(actual_alias_canonical is False,
                     label + " copy output alias shares the canonical snapshot inode")
    else:
        _require(record.get("output_alias") is None,
                 label + " sealed bin record may not carry an output alias")
    _require(sha256_file(consumed_receipt) == validated.receipt_sha256,
             label + " consumed receipt bytes do not match the parsed receipt SHA")
    _require(sha256_file(Path(record["receipt"])) == validated.receipt_sha256,
             label + " canonical receipt bytes do not match the parsed receipt SHA")
    _require(sha256_file(Path(record["build_receipt"])) == validated.receipt_sha256,
             label + " build receipt bytes do not match the parsed receipt SHA")


def _check_exporter_anchors(environ, manifest_path, raw_sha256, label):
    environ = os.environ if environ is None else environ
    expected_path = environ.get("ROOTYARD_BATCH_MANIFEST")
    expected_sha = environ.get("ROOTYARD_BATCH_MANIFEST_SHA256")
    if expected_path:
        anchor = _absolute_manifest_path(
            expected_path, label, "ROOTYARD_BATCH_MANIFEST")
        _require(not anchor.is_symlink(),
                 label + " ROOTYARD_BATCH_MANIFEST must not be a symlink")
        _require(_resolved_equal(anchor, manifest_path),
                 label + " consumed batch manifest does not match ROOTYARD_BATCH_MANIFEST")
    if expected_sha:
        _require(isinstance(expected_sha, str) and len(expected_sha) == 64
                 and expected_sha == expected_sha.lower()
                 and all(char in "0123456789abcdef" for char in expected_sha),
                 label + " ROOTYARD_BATCH_MANIFEST_SHA256 must be 64 lowercase hex")
        _require(expected_sha == raw_sha256,
                 label + " consumed batch manifest SHA-256 does not match the exporter anchor")
    return (expected_path or None), (expected_sha or None)


def _load_batch_manifest(path, label):
    manifest_path = _absolute_manifest_path(path, label, "batch manifest")
    _regular_manifest_file(manifest_path, label, "batch manifest")
    try:
        raw = manifest_path.read_bytes()
    except OSError as error:
        raise AssertionError(label + " batch manifest cannot be read: " + str(error)) from error
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise AssertionError(label + " batch manifest is not valid JSON") from error
    _require(isinstance(manifest, dict), label + " batch manifest must be a JSON object")
    _require(manifest.get("kind") == BATCH_KIND, label + " batch manifest kind is invalid")
    _require(manifest.get("status") == "passed",
             label + " batch manifest must have passed status")
    _require(manifest.get("manifest_version") == MANIFEST_VERSION,
             label + " batch manifest version must be 2")
    return manifest_path, raw_sha256, manifest


def validate_v2_pair(*, helper, app_binary, helper_target, helper_source,
                     helper_source_relative, helper_receipt, app_receipt, label,
                     environ=None):
    """Validate one v2 helper/application pair through the shared pure reader."""
    helper = Path(helper)
    app_binary = Path(app_binary)
    helper_source = Path(helper_source)
    helper_receipt = Path(helper_receipt)
    app_receipt = Path(app_receipt)
    _require(helper.is_file(), label + " binary is missing: " + str(helper))
    _require(app_binary.is_file(), "candidate application binary is missing: " + str(app_binary))
    _require(helper_source.is_file(), "helper source is missing: " + str(helper_source))

    expected_commit, expected_source = expected_source_commit(environ)
    helper_valid = _load_v2(
        helper_receipt, helper, label, expected_commit=expected_commit)
    app_valid = _load_v2(
        app_receipt, app_binary, "candidate application",
        expected_commit=expected_commit)
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
    app_batch = app_valid.batch
    if app_kind == APP_BATCH_KIND:
        _require(app_profile == "test",
                 "candidate application batch profile is " + repr(app_profile) +
                 ", expected test")
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

    # --- the actual published batch manifest (never a receipt self-claim) --
    manifest_path, manifest_sha256, manifest = _load_batch_manifest(
        helper_batch["manifest"], label)
    expected_batch_manifest, expected_batch_manifest_sha256 = _check_exporter_anchors(
        environ, manifest_path, manifest_sha256, label)
    if app_batch is not None:
        _require(_resolved_equal(app_batch["manifest"], manifest_path),
                 "helper and candidate application receipts do not name the same "
                 "consumed batch manifest")
    build_rows, typed_targets = _manifest_artifact_rows(manifest, label)
    _check_manifest_header(manifest, helper_valid, helper_batch, label)
    helper_build_row = _manifest_build_row(build_rows, "test", helper_target, label)
    _compare_build_row(helper_build_row, helper_row, label)
    helper_entry = _manifest_entry(manifest, "test", helper_target, label)
    _check_manifest_entry(
        manifest, helper_entry, "test", helper_target, helper_valid, helper_row,
        helper, helper_receipt, label)
    _require(helper_batch["targets"] == [target for kind, target in typed_targets],
             label + " helper batch targets do not match the manifest build rows")
    if app_batch is not None:
        _check_manifest_header(manifest, app_valid, app_batch, "candidate application")
        for row in app_valid.artifacts:
            manifest_row = _manifest_build_row(
                build_rows, row["kind"], row["target"], label)
            _compare_build_row(manifest_row, row, "candidate application")
        _require(app_batch["targets"] == [row["target"] for row in app_valid.artifacts],
                 "candidate application batch targets do not match its artifact rows")
        app_entry = _manifest_entry(manifest, "bin", APP_TARGET, label)
        _check_manifest_entry(
            manifest, app_entry, "bin", APP_TARGET, app_valid, bin_row,
            app_binary, app_receipt, "candidate application")

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
        "expected_source_commit": expected_commit,
        "expected_source_commit_source": expected_source,
        "bound_inputs_sha256": helper_payload["bound_inputs"]["digest"],
        "cargo_lock_sha256": helper_payload["cargo_lock_sha256"],
        "config_digest": helper_valid.config_digest,
        "target_triple": helper_valid.toolchain["target_triple"],
        "batch_manifest": str(manifest_path),
        "batch_manifest_sha256": manifest_sha256,
        "batch_manifest_version": manifest.get("manifest_version"),
        "batch_manifest_status": manifest.get("status"),
        "expected_batch_manifest": expected_batch_manifest,
        "expected_batch_manifest_sha256": expected_batch_manifest_sha256,
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
