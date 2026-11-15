#!/usr/bin/env python3
"""Bind native acceptance evidence to the exact binary, source inputs and fixtures.

Ordinary push/pull-request CI runs the cheap native security, tenancy and
concurrency regressions; the candidate release workflow runs the expensive
browser and object-store suites. Both need the same guarantee: a report is only
accepted when it was produced by the binary that was built once from the
dispatched source commit, every declared case passed, and the report itself
carries that binary digest.

Two modes:

* ``--mode job`` validates one ``scripts/build_native.py`` receipt plus the
  reports and logs produced by that job, and writes a job manifest containing
  the commit, the compiled source-input digest, the binary digest, the harness
  digests and the safe (credential-free) fixture versions.  An optional
  exporter-provided expected batch-manifest SHA-256 (and path) anchors the exact
  raw bytes consumed and recorded as provenance.  The optional
  ``--fixture-rust-from-receipt`` records the already-validated receipt's full
  Rust version as the ``rust`` fixture without probing a compiler.
* ``--mode release`` consumes job manifests, re-verifies their harness digests
  against the current checkout, requires one shared commit and one shared
  source-input digest, checks the candidate-scoped reports and pinned fixture
  versions, and writes the candidate release gate manifest.

A missing report, empty log, failed case, digest mismatch, foreign commit, stale
harness, unrecorded fixture or a credential leaking into an artifact fails
closed with a non-zero exit status.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import native_build_receipt as receipts  # noqa: E402

REQUIRED_RECEIPT_FIELDS = ("binary_sha256", "source_inputs_sha256", "workspace_commit", "rustc", "command")
V2_MANIFEST_ARTIFACT_KEYS = ("cargo_artifacts", "artifacts")
JOB_KIND = "rootyard/native-acceptance-job-manifest"
RELEASE_KIND = "rootyard/candidate-release-gate"
FAILURE_KIND = "rootyard/native-acceptance-failure"
BATCH_KIND = "rootyard/native-build-batch"
STORE_SCHEMA = "rootyard/native-artifact-store/v1"
SECRET_ENVIRONMENT = (
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_FIXTURE_SECRET_KEY",
    "ROOTYARD_FIXTURE_ACCESS_KEY",
)


class ManifestError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ManifestError(message)


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def artifact_file(directory, record, label):
    """Resolve a downloaded artifact by its flattened name inside one job's dir.

    The job manifest records the path the file had inside the job workspace;
    upload/download-artifact flattens every job file under one artifact
    directory, so only the final name is bound. Missing files, symlinks, names
    that traverse and paths resolving outside the artifact directory fail
    closed, so the release gate can never re-hash a file of its own choosing.
    """
    require(isinstance(record, dict), f"{label}: malformed manifest record")
    recorded = record.get("file")
    expected = record.get("sha256")
    require(isinstance(recorded, str) and recorded, f"{label}: no recorded file name")
    require(isinstance(expected, str) and len(expected) == 64, f"{label}: no recorded sha256")
    require(".." not in Path(recorded).parts, f"{label}: recorded path {recorded!r} traverses out of its artifact")
    name = Path(recorded).name
    require(name not in ("", ".", ".."), f"{label}: recorded path {recorded!r} has no file name")
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink(), f"{label}: artifact directory {root} is missing or a symlink")
    candidate = root / name
    require(not candidate.is_symlink(), f"{label}: downloaded artifact {candidate} is a symlink")
    require(candidate.is_file(), f"{label}: downloaded artifact {candidate} is missing")
    resolved = candidate.resolve()
    require(
        resolved.parent == root.resolve(),
        f"{label}: downloaded artifact {candidate} resolves outside its artifact directory",
    )
    return resolved


def pairs(values, flag):
    result = {}
    for value in values or []:
        name, separator, item = value.partition("=")
        require(separator and name and item, f"{flag} expects name=value, got {value!r}")
        require(name not in result, f"{flag} repeats {name!r}")
        result[name] = item
    return result


def required_cases(values):
    result = {}
    for value in values or []:
        report, separator, case_name = value.partition("=")
        require(
            separator and report and case_name,
            f"--require-case expects REPORT=CASE_NAME, got {value!r}",
        )
        result.setdefault(report, []).append(case_name)
    return result


def secret_values():
    return [value for value in (os.environ.get(name) for name in SECRET_ENVIRONMENT) if value and len(value) >= 8]


def scan_secrets(label, text, secrets):
    for secret in secrets:
        if secret in text:
            raise ManifestError(f"{label} contains a live fixture credential")


def read_text(path, label):
    file = Path(path)
    require(file.is_file(), f"{label}: missing file {file}")
    return file.read_text(errors="replace")


def receipt_rustc(validated):
    """The toolchain string a job manifest records for either receipt schema."""
    if validated.schema == "v2":
        return validated.toolchain["rustc"]["version"]
    return validated.payload.get("rustc")


def _manifest_artifact_rows(manifest, manifest_build, schema, label):
    """Return the manifest's selected artifact rows, version-dispatched.

    Legacy v1 manifests keep the historical ``fresh_false_artifacts`` shape and
    strict false values.  V2 manifests carry the actual Cargo freshness values
    under ``cargo_artifacts`` (``artifacts`` is accepted only as the producer's
    documented alias); every row must still use a JSON boolean.
    """
    if schema == "v1":
        rows = manifest_build.get("fresh_false_artifacts")
        require(
            isinstance(rows, list) and rows,
            f"{label}: build.fresh_false_artifacts must be a nonempty list",
        )
        require(
            all(isinstance(item, dict) for item in rows),
            f"{label}: build.fresh_false_artifacts entries must be objects",
        )
        require(
            all(item.get("kind") in ("lib", "bin") for item in rows),
            f"{label}: build.fresh_false_artifacts kind must be 'lib' or 'bin'",
        )
        require(
            all(
                isinstance(item.get("target"), str) and item.get("target")
                for item in rows
            ),
            f"{label}: build.fresh_false_artifacts target must be a nonempty string",
        )
        require(
            all(item.get("fresh") is False for item in rows),
            f"{label}: build.fresh_false_artifacts fresh must be exactly false",
        )
    else:
        rows = None
        for key in V2_MANIFEST_ARTIFACT_KEYS:
            candidate = manifest_build.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        if rows is None:
            for key in V2_MANIFEST_ARTIFACT_KEYS:
                candidate = manifest.get(key)
                if isinstance(candidate, list):
                    rows = candidate
                    break
        require(
            isinstance(rows, list) and rows,
            f"{label}: v2 build must record a nonempty cargo_artifacts list",
        )
        require(
            all(isinstance(item, dict) for item in rows),
            f"{label}: v2 cargo_artifacts entries must be objects",
        )
        require(
            all(item.get("kind") in receipts.ARTIFACT_KINDS for item in rows),
            f"{label}: v2 cargo_artifacts kind is invalid",
        )
        require(
            all(
                isinstance(item.get("target"), str) and item.get("target")
                for item in rows
            ),
            f"{label}: v2 cargo_artifacts target must be a nonempty string",
        )
        require(
            all(isinstance(item.get("fresh"), bool) for item in rows),
            f"{label}: v2 cargo_artifacts fresh must be a JSON boolean",
        )
    typed = [(item.get("kind"), item.get("target")) for item in rows]
    require(
        len(typed) == len(set(typed)),
        f"{label}: duplicate (kind, target) pair in build artifacts",
    )
    return rows, typed


def _receipt_artifact_for(validated, target, kind):
    rows = [
        row for row in validated.artifacts
        if row.get("target") == target and row.get("kind") == kind
    ]
    if len(rows) == 1:
        return rows[0]
    return None


def _absolute_recorded(value, label, what):
    require(isinstance(value, str) and value, f"{label}: {what} must be a nonempty path")
    path = Path(value)
    require(path.is_absolute(), f"{label}: {what} must be absolute")
    require(".." not in path.parts, f"{label}: {what} must not traverse")
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


def _cas_sealed_record(manifest, entry, label):
    """Bind one published CAS row to exactly one sealed store record."""
    store = manifest.get("artifact_store")
    require(isinstance(store, dict), f"{label}: CAS manifest must carry artifact_store")
    require(
        store.get("schema") == STORE_SCHEMA,
        f"{label}: artifact_store schema is invalid",
    )
    root = _absolute_recorded(store.get("root"), label, "artifact_store.root")
    sealed = store.get("sealed")
    require(
        isinstance(sealed, list) and sealed,
        f"{label}: artifact_store.sealed must be a nonempty list",
    )
    require(
        all(isinstance(item, dict) for item in sealed),
        f"{label}: artifact_store.sealed entries must be objects",
    )
    record = entry.get("artifact_store")
    require(isinstance(record, dict), f"{label}: CAS artifacts entry must carry artifact_store")
    require(
        sum(1 for item in sealed if item == record) == 1,
        f"{label}: CAS artifacts entry is not exactly one sealed store record",
    )
    require(record.get("schema") == STORE_SCHEMA, f"{label}: sealed record schema is invalid")
    require(record.get("root") == str(root), f"{label}: sealed record root is foreign")
    require(
        record.get("kind") == entry.get("kind"),
        f"{label}: sealed record kind does not match the manifest row",
    )
    require(
        record.get("target") == entry.get("target"),
        f"{label}: sealed record target does not match the manifest row",
    )
    return root, record


def _cas_bin_paths(manifest, entry, label):
    """The exact canonical bin snapshot and adjacent receipt for one CAS row."""
    root, record = _cas_sealed_record(manifest, entry, label)
    require(record.get("kind") == "bin", f"{label}: sealed record is not a bin")
    binary = _absolute_recorded(record.get("binary"), label, "sealed binary")
    receipt = _absolute_recorded(record.get("receipt"), label, "sealed receipt")
    build_receipt = _absolute_recorded(record.get("build_receipt"), label, "sealed build receipt")
    for path, what in (
        (binary, "sealed binary"),
        (receipt, "sealed receipt"),
        (build_receipt, "sealed build receipt"),
    ):
        require(_inside(path, root), f"{label}: {what} is outside the sealed store")
    require(binary.name == entry.get("target"), f"{label}: sealed binary basename is not the target")
    require(
        receipt.name == binary.name + ".receipt.json",
        f"{label}: sealed receipt basename is invalid",
    )
    require(
        build_receipt.name == binary.name + ".build.json",
        f"{label}: sealed build receipt basename is invalid",
    )
    require(
        receipt.parent == binary.parent and build_receipt.parent == binary.parent,
        f"{label}: sealed receipts are not adjacent to the canonical binary",
    )
    require(
        _resolved_equal(entry.get("artifact"), binary),
        f"{label}: manifest artifact is not the sealed canonical snapshot",
    )
    require(
        _resolved_equal(entry.get("receipt"), build_receipt),
        f"{label}: manifest receipt is not the sealed .build.json alias",
    )
    require(
        entry.get("sha256") == record.get("binary_sha256"),
        f"{label}: manifest artifact sha256 does not match the sealed digest",
    )
    return binary, build_receipt, record


def _require_store_matches_receipt(record, validated, label):
    """The validated receipt must carry exactly the manifest's sealed record."""
    require(
        validated.schema == "v2",
        f"{label}: artifact_store is only valid on a v2 receipt",
    )
    receipt_store = validated.payload.get("artifact_store")
    require(
        isinstance(receipt_store, dict),
        f"{label}: receipt does not carry an artifact_store record",
    )
    require(
        receipt_store == record,
        f"{label}: receipt artifact_store does not match the sealed manifest record",
    )


def _cas_bin_entry(manifest, binary_name, label):
    artifacts = manifest.get("artifacts")
    require(
        isinstance(artifacts, list) and artifacts,
        f"{label}: artifacts must be a nonempty list",
    )
    require(
        all(isinstance(artifact, dict) for artifact in artifacts),
        f"{label}: artifacts entries must be objects",
    )
    matched = [
        artifact
        for artifact in artifacts
        if artifact.get("kind") == "bin" and artifact.get("target") == binary_name
    ]
    require(
        len(matched) == 1,
        f"{label}: expected exactly one CAS bin entry for {binary_name}, got {len(matched)}",
    )
    return matched[0]


def _require_v2_manifest_matches_receipt(rows, validated, label):
    """Cross-check manifest artifact fields against the validated receipt."""
    for row in rows:
        recorded = _receipt_artifact_for(validated, row["target"], row["kind"])
        require(
            recorded is not None,
            f"{label}: manifest artifact ({row['kind']}, {row['target']}) is not selected by the receipt",
        )
        require(
            row["fresh"] is recorded["fresh"],
            f"{label}: manifest artifact ({row['kind']}, {row['target']}) freshness "
            "does not match the receipt",
        )
        for field in ("package_id", "profile", "source", "source_sha256",
                      "executable", "executable_sha256"):
            if field in row:
                require(
                    row.get(field) == recorded.get(field),
                    f"{label}: manifest artifact ({row['kind']}, {row['target']}) "
                    f"{field} does not match the receipt",
                )


def _published_artifact_for(manifest, kind, target, label):
    artifacts = manifest.get("artifacts")
    require(
        isinstance(artifacts, list) and artifacts,
        f"{label}: artifacts must be a nonempty list",
    )
    require(
        all(isinstance(artifact, dict) for artifact in artifacts),
        f"{label}: artifacts entries must be objects",
    )
    matches = [
        artifact
        for artifact in artifacts
        if artifact.get("kind") == kind and artifact.get("target") == target
    ]
    require(
        len(matches) == 1,
        f"{label}: expected exactly one published ({kind}, {target}) artifact",
    )
    return matches[0]


def _require_published_artifact_matches_row(entry, row, label):
    identity = f"({row['kind']}, {row['target']})"
    require(
        entry.get("fresh") is row.get("fresh"),
        f"{label}: published artifact {identity} freshness does not match the build row",
    )
    for field in ("package_id", "profile", "source", "source_sha256"):
        if field in entry:
            require(
                entry.get(field) == row.get(field),
                f"{label}: published artifact {identity} {field} does not match the build row",
            )
    require(
        entry.get("sha256") == row.get("executable_sha256"),
        f"{label}: published artifact {identity} digest does not match the build row",
    )
    if "original_artifact" in entry:
        require(
            _resolved_equal(entry.get("original_artifact"), row.get("executable")),
            f"{label}: published artifact {identity} original path does not match the build row",
        )
        require(
            entry.get("original_artifact_sha256") == row.get("executable_sha256"),
            f"{label}: published artifact {identity} original digest does not match the build row",
        )
    else:
        require(
            _resolved_equal(entry.get("artifact"), row.get("executable")),
            f"{label}: published artifact {identity} path does not match the build row",
        )


def _require_v2_batch_scope(manifest, batch_targets, artifact_rows, typed_targets,
                            receipt, validated, label):
    """Match a v2 receipt's batch link to the producer cohort it actually built.

    A batch bin receipt names the lib and every selected/implicit bin.  The same
    one-command batch manifest also appends the selected integration tests, so
    those extra test rows must form a suffix and remain bound to the manifest's
    published test artifacts.  A test receipt names the full lib/bin/test
    cohort and binds its own test row to the validated receipt.
    """
    test_rows = [row for row in artifact_rows if row["kind"] == "test"]
    non_test_rows = [row for row in artifact_rows if row["kind"] != "test"]
    receipt_kind = receipt.get("kind")
    if receipt_kind == "rust-integration-test":
        require(
            all(row["kind"] == "test" for row in validated.artifacts),
            f"{label}: test receipt selected a non-test artifact",
        )
        require(
            batch_targets == [target for kind, target in typed_targets],
            f"{label}: test receipt batch targets {batch_targets!r} do not match "
            f"build artifact targets {[target for kind, target in typed_targets]!r}",
        )
    else:
        if receipt_kind == "native-build-batch-bin":
            require(
                all(row["kind"] in ("lib", "bin") for row in validated.artifacts),
                f"{label}: bin receipt selected a non-lib/bin artifact",
            )
        require(
            artifact_rows == non_test_rows + test_rows,
            f"{label}: test artifacts must follow the receipt's lib/bin cohort",
        )
        require(
            non_test_rows and non_test_rows[0]["kind"] == "lib",
            f"{label}: bin receipt cohort must begin with the lib artifact",
        )
        require(
            all(row["kind"] == "bin" for row in non_test_rows[1:]),
            f"{label}: bin receipt cohort may contain only lib/bin artifacts",
        )
        require(
            batch_targets == [row["target"] for row in non_test_rows],
            f"{label}: batch targets {batch_targets!r} do not match "
            f"receipt-kind lib/bin cohort {[row['target'] for row in non_test_rows]!r}",
        )

    receipt_targets = {(row["kind"], row["target"]) for row in validated.artifacts}
    own_rows = [
        row for row in artifact_rows
        if (row["kind"], row["target"]) in receipt_targets
    ]
    require(
        len(own_rows) == len(validated.artifacts),
        f"{label}: not every artifact selected by the receipt is present in the batch manifest",
    )
    require(
        [(row["kind"], row["target"]) for row in own_rows]
        == [(row["kind"], row["target"]) for row in validated.artifacts],
        f"{label}: receipt artifact order does not match the batch manifest cohort",
    )
    _require_v2_manifest_matches_receipt(own_rows, validated, label)

    published = [
        artifact
        for artifact in manifest.get("artifacts") or []
        if isinstance(artifact, dict)
    ]
    published_bins = [
        artifact for artifact in published if artifact.get("kind") == "bin"
    ]
    bin_rows = [row for row in artifact_rows if row["kind"] == "bin"]
    require(
        [(artifact.get("kind"), artifact.get("target")) for artifact in published_bins]
        == [(row["kind"], row["target"]) for row in bin_rows],
        f"{label}: published bin artifacts do not match the batch bin cohort",
    )
    for row, entry in zip(bin_rows, published_bins):
        _require_published_artifact_matches_row(entry, row, label)

    published_tests = [
        artifact for artifact in published if artifact.get("kind") == "test"
    ]
    require(
        [(artifact.get("kind"), artifact.get("target")) for artifact in published_tests]
        == [("test", row["target"]) for row in test_rows],
        f"{label}: published test artifacts do not match the batch test cohort",
    )
    for row, entry in zip(test_rows, published_tests):
        _require_published_artifact_matches_row(entry, row, label)

    extras = [
        row for row in artifact_rows
        if (row["kind"], row["target"]) not in receipt_targets
    ]
    for row in extras:
        if row["kind"] == "test":
            continue
        if row["kind"] == "lib":
            require(
                sum(1 for item in artifact_rows if item["kind"] == "lib") == 1,
                f"{label}: manifest must record exactly one lib artifact",
            )
            require(
                row.get("package_id") == manifest.get("cargo_package_id"),
                f"{label}: extra lib artifact package_id does not match the manifest",
            )
            continue
        entry = _published_artifact_for(manifest, row["kind"], row["target"], label)
        _require_published_artifact_matches_row(entry, row, label)


def load_receipt(path, binary_override):
    file = Path(path)
    require(file.is_file(), f"build receipt is missing: {file}")
    try:
        receipt = json.loads(file.read_text())
    except json.JSONDecodeError as error:
        raise ManifestError(f"build receipt is not JSON: {error}")
    binary = Path(binary_override) if binary_override else Path(str(file)[: -len(".build.json")])
    require(binary.is_file(), f"built binary is missing: {binary}")
    actual = digest(binary)
    try:
        validated = receipts.validate_receipt(
            receipt,
            receipt_path=file,
            binary_path=binary,
            verify_source_files=False,
        )
    except receipts.ReceiptError as error:
        raise ManifestError(str(error)) from None
    if validated.schema == "v1":
        for field in REQUIRED_RECEIPT_FIELDS:
            require(receipt.get(field), f"build receipt is missing {field}")
    require(
        actual == validated.binary_sha256,
        f"binary digest {actual} does not match the build receipt {validated.binary_sha256}",
    )
    return receipt, validated, file, binary


def verify_batch_receipt(receipt, validated, receipt_file, binary,
                         expected_manifest_sha=None, expected_manifest_path=None):
    """Validate the batch link and bind the exact manifest bytes consumed.

    ``expected_manifest_sha`` and ``expected_manifest_path`` are optional
    exporter-provided trust anchors.  When supplied, the SHA-256 is compared
    against the same raw byte buffer that is parsed and later recorded as the
    job manifest provenance, so a later re-read cannot hide a rewrite.
    """
    if expected_manifest_sha is not None:
        require(
            isinstance(expected_manifest_sha, str)
            and len(expected_manifest_sha) == 64
            and expected_manifest_sha == expected_manifest_sha.lower()
            and all(char in "0123456789abcdef" for char in expected_manifest_sha),
            "expected batch manifest SHA-256 must be 64 lowercase hexadecimal characters",
        )
    if expected_manifest_path is not None:
        expected_path = _absolute_recorded(
            expected_manifest_path, "expected batch manifest", "path"
        )
    else:
        expected_path = None
    if not isinstance(receipt, dict) or "batch" not in receipt:
        require(
            expected_manifest_sha is None and expected_path is None,
            "an explicit batch manifest anchor was supplied but the build receipt has no batch link",
        )
        return None
    batch = receipt["batch"]
    require(isinstance(batch, dict), "batch receipt must be an object")
    require(
        batch.get("kind") == BATCH_KIND,
        "batch receipt has an invalid kind",
    )
    batch_version = batch.get("receipt_version")
    require(
        isinstance(batch_version, int)
        and not isinstance(batch_version, bool)
        and batch_version > 0,
        "batch receipt has an invalid receipt_version",
    )
    require(batch.get("binary") == binary.name, "batch receipt has an invalid binary")
    require(
        not receipt.get("implicit_build"),
        "receipts produced by implicit builds cannot be accepted",
    )
    manifest_value = batch.get("manifest")
    require(
        isinstance(manifest_value, str) and manifest_value,
        "batch receipt manifest must be a nonempty path string",
    )
    manifest_path = Path(manifest_value)
    require(manifest_path.is_absolute(), "batch receipt manifest path must be absolute")
    require(
        manifest_path.exists() and manifest_path.is_file(),
        "batch receipt manifest must be a regular file",
    )
    require(
        manifest_path.is_symlink() is False,
        "batch receipt manifest must not be a symlink",
    )
    if expected_path is not None:
        require(
            _resolved_equal(manifest_path, expected_path),
            "batch receipt manifest path does not match the exporter-provided path",
        )
    targets = batch.get("targets")
    require(
        isinstance(targets, list) and targets,
        "batch receipt targets must be a nonempty list",
    )
    require(
        all(isinstance(target, str) and target for target in targets),
        "batch receipt targets must be nonempty strings",
    )

    try:
        raw = manifest_path.read_bytes()
    except OSError as error:
        raise ManifestError(f"batch receipt manifest cannot be read: {error}") from error
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_manifest_sha is not None:
        require(
            raw_sha256 == expected_manifest_sha,
            "batch receipt manifest SHA-256 does not match the exporter-validated SHA-256",
        )

    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise ManifestError("batch receipt manifest is not valid JSON") from error
    require(isinstance(manifest, dict), "batch receipt manifest must be an object")
    require(
        manifest.get("kind") == BATCH_KIND,
        "batch receipt manifest has an invalid kind",
    )
    require(
        manifest.get("status") == "passed",
        "batch receipt manifest must have passed status",
    )
    manifest_version = manifest.get("manifest_version")
    require(
        isinstance(manifest_version, int)
        and not isinstance(manifest_version, bool)
        and manifest_version == batch_version,
        "batch receipt manifest version does not match the batch receipt",
    )

    architecture = receipt.get("architecture")
    if validated.schema == "v2":
        architecture = {
            "target_triple": validated.toolchain["target_triple"],
            "host": validated.toolchain["rustc"]["host"],
        }
    for field, receipt_value in (
        ("source_commit", receipt.get("workspace_commit")),
        ("source_inputs_sha256", receipt.get("source_inputs_sha256")),
        ("toolchain", receipt.get("toolchain")),
        ("architecture", architecture),
        ("target_directory", receipt.get("target_dir")),
    ):
        require(
            manifest.get(field) == receipt_value,
            "batch receipt manifest does not match the receipt",
        )

    manifest_build = manifest.get("build")
    require(
        isinstance(manifest_build, dict),
        "batch receipt manifest build must be an object",
    )
    require(
        manifest_build.get("command") == receipt.get("command"),
        "batch receipt manifest does not match the receipt",
    )

    bound_inputs = manifest.get("bound_inputs")
    require(
        isinstance(bound_inputs, dict),
        "batch receipt manifest bound_inputs must be an object",
    )
    receipt_bound_inputs = receipt.get("bound_inputs")
    require(
        isinstance(receipt_bound_inputs, dict),
        "batch receipt bound_inputs must be an object",
    )
    bound_digest = bound_inputs.get("digest")
    require(
        isinstance(bound_digest, str) and bound_digest,
        "batch receipt manifest bound_inputs digest must be a nonempty string",
    )
    require(
        bound_digest == batch.get("bound_inputs_sha256"),
        "batch receipt manifest bound_inputs digest does not match the batch receipt",
    )
    require(
        bound_digest == receipt_bound_inputs.get("digest"),
        "batch receipt manifest bound_inputs digest does not match the receipt",
    )

    if validated.schema == "v1":
        clean = manifest.get("clean")
        require(
            isinstance(clean, dict),
            "batch receipt manifest clean must be an object",
        )
        require(
            isinstance(clean.get("commands"), int)
            and not isinstance(clean.get("commands"), bool)
            and clean.get("commands") == 1,
            "batch receipt manifest clean.commands must be exactly 1",
        )
        require(
            isinstance(manifest_build.get("commands"), int)
            and not isinstance(manifest_build.get("commands"), bool)
            and manifest_build.get("commands") == 1,
            "batch receipt manifest build.commands must be exactly 1",
        )

    artifact_rows, typed_targets = _manifest_artifact_rows(
        manifest, manifest_build, validated.schema, "batch receipt manifest"
    )
    if validated.schema == "v2":
        _require_v2_batch_scope(
            manifest, targets, artifact_rows, typed_targets,
            receipt, validated, "batch receipt manifest",
        )
    else:
        require(
            targets == [target for kind, target in typed_targets],
            "targets must match typed_targets order",
        )

    artifacts = manifest.get("artifacts")
    require(
        isinstance(artifacts, list) and artifacts,
        "batch receipt manifest artifacts must be a nonempty list",
    )
    require(
        all(isinstance(artifact, dict) for artifact in artifacts),
        "batch receipt manifest artifacts must be objects",
    )

    target_dir_value = receipt.get("target_dir")
    require(
        isinstance(target_dir_value, str)
        and bool(target_dir_value)
        and Path(target_dir_value).is_absolute(),
        "receipt.target_dir must be a nonempty absolute path",
    )
    target_dir = Path(target_dir_value)
    if manifest.get("artifact_store") is None:
        expected_binary = target_dir / "debug" / batch["binary"]
        expected_receipt = target_dir / "debug" / f'{batch["binary"]}.build.json'

        def resolves_to(entry_value, expected):
            if not isinstance(entry_value, str) or not entry_value:
                return False
            try:
                if not Path(entry_value).is_absolute():
                    return False
                return Path(entry_value).resolve() == expected.resolve()
            except (OSError, ValueError, RuntimeError):
                return False

        matched = [
            artifact
            for artifact in artifacts
            if resolves_to(artifact.get("artifact"), expected_binary)
            and resolves_to(artifact.get("receipt"), expected_receipt)
        ]
        require(
            len(matched) == 1,
            "batch receipt manifest must contain exactly one entry for the binary and receipt",
        )
        entry = matched[0]
    else:
        entry = _cas_bin_entry(manifest, batch["binary"], "batch receipt manifest")
        sealed_binary, sealed_receipt, record = _cas_bin_paths(
            manifest, entry, "batch receipt manifest"
        )
        store_root = Path(manifest["artifact_store"]["root"])
        require(
            not _inside(store_root, target_dir) and not _inside(target_dir, store_root),
            "batch receipt manifest artifact store must be disjoint from target_dir",
        )
        require(
            _resolved_equal(binary, sealed_binary),
            "batch receipt manifest consumed binary is not the sealed canonical snapshot",
        )
        require(
            _resolved_equal(receipt_file, sealed_receipt),
            "batch receipt manifest consumed receipt is not the sealed .build.json alias",
        )
        _require_store_matches_receipt(record, validated, "batch receipt manifest")
    require(entry.get("kind") == "bin", "batch receipt binary entry has an invalid kind")
    if validated.schema == "v1":
        require(
            entry.get("fresh") is False,
            "batch receipt binary entry must not be fresh",
        )
    else:
        require(
            isinstance(entry.get("fresh"), bool),
            "batch receipt binary entry fresh must be a JSON boolean",
        )
        selected = _receipt_artifact_for(
            validated, entry.get("target"), entry.get("kind")
        )
        require(
            selected is not None,
            "batch receipt binary entry is not selected by the receipt",
        )
        require(
            entry.get("fresh") is selected["fresh"],
            "batch receipt binary entry freshness does not match the receipt",
        )
    require(
        entry.get("implicit") is False,
        "batch receipt binary entry must not be implicit",
    )
    require(
        entry.get("target") in targets,
        "batch receipt binary entry target is not listed in the batch targets",
    )
    require(
        ("bin", entry.get("target")) in typed_targets,
        "bin entry target must be in typed_targets",
    )
    require(
        entry.get("sha256") == receipt.get("binary_sha256"),
        "batch receipt binary digest does not match the receipt",
    )

    return {
        "file": str(manifest_path.resolve()),
        "sha256": raw_sha256,
        "target": entry["target"],
    }


def job_manifest(args):
    receipt, validated, receipt_file, binary = load_receipt(args.build_receipt, args.binary)
    batch_manifest = verify_batch_receipt(
        receipt,
        validated,
        receipt_file,
        binary,
        expected_manifest_sha=args.expect_batch_manifest_sha,
        expected_manifest_path=args.expect_batch_manifest_path,
    )
    commit = args.expect_commit or receipt["workspace_commit"]
    require(
        commit == receipt["workspace_commit"],
        f"build receipt commit {receipt['workspace_commit']} != expected commit {commit}",
    )
    secrets = secret_values()
    scan_secrets("build command", json.dumps(receipt.get("command")), secrets)

    reports = pairs(args.report, "--report")
    require(reports, "at least one --report is required; a gate cannot pass without executed evidence")
    case_requirements = required_cases(args.require_case)
    missing_reports = [name for name in case_requirements if name not in reports]
    require(
        not missing_reports,
        f"--require-case names report(s) not supplied by --report: {', '.join(repr(name) for name in missing_reports)}",
    )
    report_records = {}
    for name, path in reports.items():
        text = read_text(path, f"report {name}")
        scan_secrets(f"report {name}", text, secrets)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ManifestError(f"report {name}: not JSON: {error}")
        require(isinstance(data, dict), f"report {name}: not a JSON object")
        require(data.get("passed") is True, f"report {name}: did not pass")
        require(
            data.get("binary_sha256") == receipt["binary_sha256"],
            f"report {name}: binary digest does not match the built binary",
        )
        cases = data.get("cases")
        require(isinstance(cases, list) and cases, f"report {name}: no executed cases")
        for case in cases:
            require(isinstance(case, dict), f"report {name}: malformed case record")
            require(case.get("status") == "passed", f"report {name}: case {case.get('name')!r} is not passed")
        executed_names = set()
        for case in cases:
            case_name = case.get("name")
            if isinstance(case_name, str):
                executed_names.add(case_name)
        for required_name in case_requirements.get(name, []):
            require(
                required_name in executed_names,
                f"report {name}: required case {required_name!r} is absent",
            )
        require(not data.get("failure_traceback"), f"report {name}: records a failure traceback")
        head = data.get("source_head")
        if name == "browse":
            require(
                head == commit,
                f"report {name}: source_head is required and must equal commit {commit}, got {head!r}",
            )
        else:
            require(head in (None, commit), f"report {name}: produced from commit {head}, expected {commit}")
        report_records[name] = {
            "file": str(path),
            "sha256": digest(path),
            "case_names": [case.get("name") for case in cases],
            "binary_sha256": data["binary_sha256"],
        }

    logs = pairs(args.log, "--log")
    markers = {}
    for value in args.log_marker or []:
        name, separator, marker = value.partition("=")
        require(separator and name and marker, f"--log-marker expects name=text, got {value!r}")
        markers.setdefault(name, []).append(marker)
    for name in markers:
        require(name in logs, f"--log-marker names the unrecorded log {name!r}")
    log_records = {}
    for name, path in logs.items():
        text = read_text(path, f"log {name}")
        require(text.strip(), f"log {name}: empty output; a skipped command is not a pass")
        scan_secrets(f"log {name}", text, secrets)
        for marker in markers.get(name, []):
            require(marker in text, f"log {name}: missing expected output {marker!r}")
        log_records[name] = {"file": str(path), "sha256": digest(path), "bytes": len(text.encode())}

    harnesses = {}
    for path in args.harness or []:
        file = Path(path)
        require(file.is_file(), f"harness is missing: {file}")
        harnesses[str(path)] = digest(path)
    require(harnesses, "at least one --harness is required to bind the executed test source")

    fixtures = pairs(args.fixture, "--fixture")
    if getattr(args, "fixture_rust_from_receipt", False):
        require(
            "rust" not in fixtures,
            "--fixture-rust-from-receipt conflicts with an explicit --fixture rust=...",
        )
        fixtures["rust"] = receipt_rustc(validated)
    for name, value in fixtures.items():
        require(value.strip(), f"fixture {name}: empty fixture version")
        require("\n" not in value and len(value) <= 300, f"fixture {name}: value is not a single safe line")
        scan_secrets(f"fixture {name}", value, secrets)

    return {
        "kind": JOB_KIND,
        "manifest_version": 1,
        "mode": "job",
        "status": "passed",
        "source_commit": commit,
        "source_inputs_sha256": receipt["source_inputs_sha256"],
        "binary_sha256": receipt["binary_sha256"],
        "binary": str(binary),
        "build_receipt": {
            "file": str(receipt_file),
            "sha256": digest(receipt_file),
            "rustc": receipt_rustc(validated),
            "receipt_schema": validated.schema,
            **({"batch_manifest": batch_manifest} if batch_manifest is not None else {}),
        },
        "build_command": receipt["command"],
        "harnesses": harnesses,
        "fixtures": fixtures,
        "reports": report_records,
        "logs": log_records,
        "generated_unix": int(time.time()),
    }


def release_manifest(args):
    require(args.expect_commit, "--expect-commit is required in release mode; the gate must name the dispatched commit")
    jobs = pairs(args.job_manifest, "--job-manifest")
    require(len(jobs) >= 2, "the candidate release gate requires at least two job manifests")
    required_reports = set(args.require_report or [])
    required_fixtures = pairs(args.require_fixture, "--require-fixture")
    exact_fixtures = pairs(args.require_fixture_exact, "--require-fixture-exact")
    artifact_dirs = pairs(args.artifact_dir, "--artifact-dir")

    job_records, all_reports, all_fixtures, all_harnesses = {}, {}, {}, {}
    source_digests, commits = set(), set()
    for name, path in jobs.items():
        text = read_text(path, f"job manifest {name}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ManifestError(f"job manifest {name}: not JSON: {error}")
        require(data.get("kind") == JOB_KIND, f"job manifest {name}: unexpected kind {data.get('kind')!r}")
        require(data.get("status") == "passed", f"job manifest {name}: status is {data.get('status')!r}")
        require(data.get("source_commit"), f"job manifest {name}: no source commit")
        commits.add(data["source_commit"])
        require(data.get("source_inputs_sha256"), f"job manifest {name}: no source input digest")
        source_digests.add(data["source_inputs_sha256"])
        require(data.get("binary_sha256"), f"job manifest {name}: no binary digest")
        artifact_dir = artifact_dirs.get(name)
        require(
            artifact_dir is not None,
            f"job manifest {name}: no --artifact-dir supplied for its downloaded artifacts",
        )

        reports = data.get("reports") or {}
        require(reports, f"job manifest {name}: no reports")
        verified = {}
        for kind, records in (("report", reports), ("log", data.get("logs") or {})):
            for record_name, record in records.items():
                label = f"job manifest {name}: {kind} {record_name}"
                downloaded = artifact_file(artifact_dir, record, label)
                actual = digest(downloaded)
                require(
                    actual == record["sha256"],
                    f"{label}: downloaded file does not match the manifest sha256",
                )
                verified[f"{kind}:{record_name}"] = {"file": downloaded.name, "sha256": actual}
        build_receipt = data.get("build_receipt")
        require(isinstance(build_receipt, dict), f"job manifest {name}: build_receipt must be an object")
        label = f"job manifest {name}: build receipt"
        downloaded_receipt = artifact_file(artifact_dir, build_receipt, label)
        receipt_sha256 = digest(downloaded_receipt)
        require(
            receipt_sha256 == build_receipt.get("sha256"),
            f"{label}: downloaded file does not match the manifest sha256",
        )
        try:
            receipt = json.loads(downloaded_receipt.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ManifestError(f"{label}: not valid JSON: {error}")
        require(isinstance(receipt, dict), f"{label}: not a JSON object")
        try:
            validated = receipts.validate_receipt(
                receipt,
                receipt_path=downloaded_receipt,
                verify_source_files=False,
            )
        except receipts.ReceiptError as error:
            raise ManifestError(f"{label}: {error}") from None
        require(
            receipt.get("workspace_commit") == data.get("source_commit"),
            f"{label}: workspace_commit does not match the job source commit",
        )
        require(
            receipt.get("source_inputs_sha256") == data.get("source_inputs_sha256"),
            f"{label}: source_inputs_sha256 does not match the job source input digest",
        )
        require(
            receipt.get("binary_sha256") == data.get("binary_sha256"),
            f"{label}: binary_sha256 does not match the job binary digest",
        )
        require(
            isinstance(build_receipt.get("rustc"), str) and build_receipt.get("rustc"),
            f"{label}: build receipt rustc must be a nonempty string",
        )
        require(
            receipt_rustc(validated) == build_receipt.get("rustc"),
            f"{label}: rustc does not match the job build receipt",
        )
        verified["build:receipt"] = {"file": downloaded_receipt.name, "sha256": receipt_sha256}

        batch = receipt.get("batch")
        if "batch" not in receipt:
            require(
                "batch_manifest" not in build_receipt,
                f"job manifest {name}: standalone build receipt must not carry a batch manifest",
            )
        else:
            require(isinstance(batch, dict), f"{label}: batch must be an object")
            require(
                batch.get("kind") == BATCH_KIND,
                f"{label}: batch has an invalid kind {batch.get('kind')!r}",
            )
            batch_version = batch.get("receipt_version")
            require(
                isinstance(batch_version, int)
                and not isinstance(batch_version, bool)
                and batch_version > 0,
                f"{label}: batch receipt_version must be a positive integer",
            )
            binary_name = batch.get("binary")
            require(
                isinstance(binary_name, str) and binary_name,
                f"{label}: batch binary must be a nonempty string",
            )
            require(
                isinstance(data.get("binary"), str) and data.get("binary"),
                f"job manifest {name}: binary must be a nonempty path",
            )
            require(
                Path(data["binary"]).name == binary_name,
                f"job manifest {name}: binary {data['binary']!r} does not name batch binary {binary_name!r}",
            )
            require(
                receipt.get("binary_sha256") == data.get("binary_sha256"),
                f"{label}: receipt binary_sha256 does not match the job binary digest",
            )
            batch_targets = batch.get("targets")
            require(
                isinstance(batch_targets, list) and batch_targets,
                f"{label}: batch targets must be a nonempty list",
            )
            require(
                all(isinstance(target, str) and target for target in batch_targets),
                f"{label}: batch targets must be nonempty strings",
            )
            receipt_bound = receipt.get("bound_inputs")
            require(
                isinstance(receipt_bound, dict),
                f"{label}: bound_inputs must be an object",
            )
            batch_bound = batch.get("bound_inputs_sha256")
            require(
                isinstance(batch_bound, str) and batch_bound,
                f"{label}: batch bound_inputs_sha256 must be a nonempty string",
            )
            require(
                isinstance(receipt_bound.get("digest"), str) and receipt_bound.get("digest"),
                f"{label}: bound_inputs digest must be a nonempty string",
            )
            require(
                receipt_bound.get("digest") == batch_bound,
                f"{label}: bound_inputs digest does not match batch bound_inputs_sha256",
            )

            batch_manifest = build_receipt.get("batch_manifest")
            require(
                isinstance(batch_manifest, dict),
                f"job manifest {name}: batch build receipt requires a build_receipt.batch_manifest object",
            )
            require(
                batch_manifest.get("target") == binary_name,
                f"job manifest {name}: build_receipt.batch_manifest target {batch_manifest.get('target')!r} "
                f"does not match batch binary {binary_name!r}",
            )
            recorded_manifest = batch_manifest.get("file")
            require(
                isinstance(recorded_manifest, str) and recorded_manifest,
                f"job manifest {name}: build_receipt.batch_manifest file must be a nonempty path",
            )
            require(
                Path(recorded_manifest).is_absolute(),
                f"job manifest {name}: build_receipt.batch_manifest file must be absolute",
            )
            receipt_manifest = batch.get("manifest")
            require(
                isinstance(receipt_manifest, str) and receipt_manifest and Path(receipt_manifest).is_absolute(),
                f"{label}: batch manifest must be a nonempty absolute path",
            )
            try:
                manifest_paths_match = Path(recorded_manifest).resolve() == Path(receipt_manifest).resolve()
            except (OSError, ValueError):
                manifest_paths_match = False
            require(
                manifest_paths_match,
                f"job manifest {name}: build_receipt.batch_manifest file does not match the receipt batch manifest",
            )
            require(
                isinstance(batch_manifest.get("sha256"), str) and batch_manifest.get("sha256"),
                f"job manifest {name}: build_receipt.batch_manifest sha256 is required",
            )
            manifest_label = f"job manifest {name}: batch manifest"
            downloaded_manifest = artifact_file(artifact_dir, batch_manifest, manifest_label)
            manifest_sha256 = digest(downloaded_manifest)
            require(
                manifest_sha256 == batch_manifest.get("sha256"),
                f"{manifest_label}: downloaded file does not match the manifest sha256",
            )
            try:
                manifest = json.loads(downloaded_manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise ManifestError(f"{manifest_label}: not valid JSON: {error}")
            require(isinstance(manifest, dict), f"{manifest_label}: not a JSON object")

            require(
                manifest.get("kind") == BATCH_KIND,
                f"{manifest_label}: invalid kind {manifest.get('kind')!r}",
            )
            require(
                manifest.get("status") == "passed",
                f"{manifest_label}: status must be 'passed'",
            )
            manifest_version = manifest.get("manifest_version")
            require(
                isinstance(manifest_version, int)
                and not isinstance(manifest_version, bool)
                and manifest_version == batch_version,
                f"{manifest_label}: manifest_version must equal batch receipt_version",
            )
            architecture = receipt.get("architecture")
            if validated.schema == "v2":
                architecture = {
                    "target_triple": validated.toolchain["target_triple"],
                    "host": validated.toolchain["rustc"]["host"],
                }
            for manifest_field, receipt_field, receipt_value in (
                ("source_commit", "workspace_commit", receipt.get("workspace_commit")),
                ("source_inputs_sha256", "source_inputs_sha256", receipt.get("source_inputs_sha256")),
                ("toolchain", "toolchain", receipt.get("toolchain")),
                ("architecture", "architecture", architecture),
                ("target_directory", "target_dir", receipt.get("target_dir")),
            ):
                require(
                    manifest.get(manifest_field) == receipt_value,
                    f"{manifest_label}: {manifest_field} does not match receipt {receipt_field}",
                )
            manifest_build = manifest.get("build")
            require(isinstance(manifest_build, dict), f"{manifest_label}: build must be an object")
            require(
                manifest_build.get("command") == receipt.get("command"),
                f"{manifest_label}: build.command does not match the receipt command",
            )
            manifest_bound = manifest.get("bound_inputs")
            require(isinstance(manifest_bound, dict), f"{manifest_label}: bound_inputs must be an object")
            manifest_bound_digest = manifest_bound.get("digest")
            require(
                isinstance(manifest_bound_digest, str) and manifest_bound_digest,
                f"{manifest_label}: bound_inputs digest must be a nonempty string",
            )
            require(
                manifest_bound_digest == receipt_bound.get("digest"),
                f"{manifest_label}: bound_inputs digest does not match the receipt",
            )
            if validated.schema == "v1":
                manifest_clean = manifest.get("clean")
                require(isinstance(manifest_clean, dict), f"{manifest_label}: clean must be an object")
                require(
                    isinstance(manifest_clean.get("commands"), int)
                    and not isinstance(manifest_clean.get("commands"), bool)
                    and manifest_clean.get("commands") == 1,
                    f"{manifest_label}: clean.commands must be exactly 1",
                )
                require(
                    isinstance(manifest_build.get("commands"), int)
                    and not isinstance(manifest_build.get("commands"), bool)
                    and manifest_build.get("commands") == 1,
                    f"{manifest_label}: build.commands must be exactly 1",
                )

            artifact_rows, typed_targets = _manifest_artifact_rows(
                manifest, manifest_build, validated.schema, manifest_label
            )
            if validated.schema == "v2":
                _require_v2_batch_scope(
                    manifest, batch_targets, artifact_rows, typed_targets,
                    receipt, validated, manifest_label,
                )
            else:
                require(
                    batch_targets == [target for kind, target in typed_targets],
                    f"{manifest_label}: batch targets {batch_targets!r} do not match "
                    f"build artifact targets {[target for kind, target in typed_targets]!r}",
                )
            require(
                ("bin", binary_name) in typed_targets,
                f"{manifest_label}: no (bin, {binary_name}) target recorded",
            )

            target_dir = receipt.get("target_dir")
            require(
                isinstance(target_dir, str) and target_dir and Path(target_dir).is_absolute(),
                f"{label}: target_dir must be a nonempty absolute path",
            )

            artifacts = manifest.get("artifacts")
            require(
                isinstance(artifacts, list) and artifacts,
                f"{manifest_label}: artifacts must be a nonempty list",
            )
            require(
                all(isinstance(artifact, dict) for artifact in artifacts),
                f"{manifest_label}: artifacts entries must be objects",
            )
            if manifest.get("artifact_store") is None:
                expect_binary = Path(target_dir) / "debug" / binary_name
                expect_receipt = Path(target_dir) / "debug" / f"{binary_name}.build.json"
                try:
                    expected_binary_path = expect_binary.resolve()
                    expected_receipt_path = expect_receipt.resolve()
                except (OSError, ValueError) as error:
                    raise ManifestError(f"{label}: cannot resolve the original batch artifact paths: {error}")

                def original_path_matches(value):
                    if not isinstance(value, str) or not value:
                        return False
                    path = Path(value)
                    if not path.is_absolute():
                        return False
                    try:
                        return Path(value).resolve()
                    except (OSError, ValueError):
                        return None

                matched = [
                    artifact
                    for artifact in artifacts
                    if original_path_matches(artifact.get("artifact")) == expected_binary_path
                    and original_path_matches(artifact.get("receipt")) == expected_receipt_path
                ]
                require(
                    len(matched) == 1,
                    f"{manifest_label}: expected exactly one artifacts entry for {expect_binary} and {expect_receipt}, "
                    f"got {len(matched)}",
                )
                entry = matched[0]
            else:
                entry = _cas_bin_entry(manifest, binary_name, manifest_label)
                sealed_binary, sealed_receipt, record = _cas_bin_paths(
                    manifest, entry, manifest_label
                )
                store_root = Path(manifest["artifact_store"]["root"])
                target_path = Path(target_dir)
                require(
                    not _inside(store_root, target_path)
                    and not _inside(target_path, store_root),
                    f"{manifest_label}: artifact store must be disjoint from target_dir",
                )
                recorded_binary = _absolute_recorded(
                    data.get("binary"), f"job manifest {name}", "binary"
                )
                recorded_receipt = _absolute_recorded(
                    build_receipt.get("file"), label, "receipt file"
                )
                require(
                    _resolved_equal(recorded_binary, sealed_binary),
                    f"{manifest_label}: recorded binary is not the sealed canonical snapshot",
                )
                require(
                    _resolved_equal(recorded_receipt, sealed_receipt),
                    f"{manifest_label}: recorded receipt is not the sealed .build.json alias",
                )
                _require_store_matches_receipt(record, validated, manifest_label)
            require(
                entry.get("kind") == "bin",
                f"{manifest_label}: binary artifacts entry kind must be 'bin'",
            )
            require(
                entry.get("target") == binary_name,
                f"{manifest_label}: binary artifacts entry target {entry.get('target')!r} "
                f"does not match binary {binary_name!r}",
            )
            if validated.schema == "v1":
                require(
                    entry.get("fresh") is False,
                    f"{manifest_label}: binary artifacts entry fresh must be exactly false",
                )
            else:
                require(
                    isinstance(entry.get("fresh"), bool),
                    f"{manifest_label}: binary artifacts entry fresh must be a JSON boolean",
                )
                selected = _receipt_artifact_for(
                    validated, entry.get("target"), entry.get("kind")
                )
                require(
                    selected is not None,
                    f"{manifest_label}: binary artifacts entry is not selected by the receipt",
                )
                require(
                    entry.get("fresh") is selected["fresh"],
                    f"{manifest_label}: binary artifacts entry freshness does not match the receipt",
                )
            require(
                entry.get("implicit") is False,
                f"{manifest_label}: binary artifacts entry implicit must be exactly false",
            )
            require(
                entry.get("sha256") == receipt.get("binary_sha256"),
                f"{manifest_label}: binary artifacts entry sha256 does not match the receipt binary_sha256",
            )

            verified["build:batch_manifest"] = {"file": downloaded_manifest.name, "sha256": manifest_sha256}
        for report_name, record in reports.items():
            require(report_name not in all_reports, f"report {report_name!r} is claimed by two jobs")
            all_reports[report_name] = {**record, "job": name, "downloaded_sha256": verified[f"report:{report_name}"]["sha256"]}

        fixtures = data.get("fixtures") or {}
        for fixture_name, value in fixtures.items():
            require(
                fixture_name not in all_fixtures or all_fixtures[fixture_name] == value,
                f"fixture {fixture_name!r} is recorded with conflicting values",
            )
            all_fixtures[fixture_name] = value

        harnesses = data.get("harnesses") or {}
        require(harnesses, f"job manifest {name}: no harness digests")
        for harness_path, recorded in harnesses.items():
            file = Path(harness_path)
            require(file.is_file(), f"job manifest {name}: harness {harness_path} is missing from this checkout")
            actual = digest(file)
            require(
                actual == recorded,
                f"job manifest {name}: harness {harness_path} changed after the job ran",
            )
            all_harnesses[harness_path] = actual

        job_records[name] = {
            "manifest": str(path),
            "sha256": digest(path),
            "source_commit": data["source_commit"],
            "source_inputs_sha256": data["source_inputs_sha256"],
            "binary_sha256": data["binary_sha256"],
            "reports": sorted(reports),
            "fixtures": fixtures,
            "artifacts": verified,
        }

    require(commits == {args.expect_commit}, "job manifests do not share the dispatched commit")
    require(len(source_digests) == 1, "job manifests disagree on the compiled source-input digest")
    missing = required_reports - set(all_reports)
    require(not missing, "required candidate reports are missing: " + ", ".join(sorted(missing)))
    for fixture_name, substring in required_fixtures.items():
        value = all_fixtures.get(fixture_name)
        require(value is not None, f"required fixture {fixture_name!r} was not recorded by any job")
        require(
            substring in value,
            f"fixture {fixture_name}={value!r} does not contain the required pin {substring!r}",
        )
    for fixture_name, expected in exact_fixtures.items():
        value = all_fixtures.get(fixture_name)
        require(value is not None, f"required fixture {fixture_name!r} was not recorded by any job")
        require(
            value == expected,
            f"fixture {fixture_name}={value!r} is not the exact required value {expected!r}",
        )

    return {
        "kind": RELEASE_KIND,
        "gate_version": 1,
        "mode": "release",
        "status": "passed",
        "source_commit": args.expect_commit,
        "source_inputs_sha256": source_digests.pop(),
        "jobs": job_records,
        "reports": sorted(all_reports),
        "fixtures": all_fixtures,
        "harnesses": all_harnesses,
        "generated_unix": int(time.time()),
    }


def emit(path, payload):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("job", "release"), default="job")
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--expect-commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--build-receipt")
    parser.add_argument("--binary")
    parser.add_argument("--expect-batch-manifest-sha")
    parser.add_argument("--expect-batch-manifest-path")
    parser.add_argument(
        "--fixture-rust-from-receipt",
        action="store_true",
        help="record fixtures.rust from the validated build receipt without probing rustc",
    )
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--require-case", action="append", default=[])
    parser.add_argument("--log", action="append", default=[])
    parser.add_argument("--log-marker", action="append", default=[])
    parser.add_argument("--harness", action="append", default=[])
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--job-manifest", action="append", default=[])
    parser.add_argument("--artifact-dir", action="append", default=[])
    parser.add_argument("--require-report", action="append", default=[])
    parser.add_argument("--require-fixture", action="append", default=[])
    parser.add_argument("--require-fixture-exact", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.mode == "job":
            require(args.build_receipt, "--build-receipt is required in job mode")
            payload = job_manifest(args)
            summary = {
                "status": payload["status"],
                "manifest": str(args.manifest_out),
                "source_commit": payload["source_commit"],
                "source_inputs_sha256": payload["source_inputs_sha256"],
                "binary_sha256": payload["binary_sha256"],
                "reports": sorted(payload["reports"]),
            }
        else:
            require(
                not args.fixture_rust_from_receipt,
                "--fixture-rust-from-receipt is only valid in job mode",
            )
            require(
                args.expect_batch_manifest_sha is None
                and args.expect_batch_manifest_path is None,
                "--expect-batch-manifest-sha/--expect-batch-manifest-path are only valid in job mode",
            )
            payload = release_manifest(args)
            summary = {
                "status": payload["status"],
                "manifest": str(args.manifest_out),
                "source_commit": payload["source_commit"],
                "source_inputs_sha256": payload["source_inputs_sha256"],
                "jobs": sorted(payload["jobs"]),
                "reports": payload["reports"],
            }
    except (ManifestError, OSError, json.JSONDecodeError) as error:
        emit(
            args.manifest_out,
            {
                "kind": FAILURE_KIND,
                "status": "failed",
                "mode": args.mode,
                "error": str(error),
                "generated_unix": int(time.time()),
            },
        )
        print(f"native acceptance manifest: FAILED: {error}", file=sys.stderr)
        return 1
    emit(args.manifest_out, payload)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
