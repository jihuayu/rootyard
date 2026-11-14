#!/usr/bin/env python3
"""Export validated immutable native artifact paths into ``$GITHUB_ENV``.

This is a small, standard-library-only consumer of the version-2 batch manifest
that ``scripts/build_native_batch.py --artifact-store`` writes.  It never runs
Cargo, a compiler, a shell or a builder, and it never evaluates manifest text.
Every exported value is an absolute path that is itself recorded by the
manifest and whose bytes were checked here against the sealed artifact-store
record:

* bin rows export the canonical readonly snapshot (``artifact``);
* test rows export the explicit readonly ``--output`` alias;
* receipts export the adjacent same-byte ``.build.json`` alias.

The store root, the manifest and the SHA-256 of the exact raw manifest bytes
that were parsed and validated are exported as well so a later step can bind
the exact files it consumed.  A missing row, a changed hash, a writable or
symlinked file, a foreign store root, a record that is not one of the
manifest's sealed entries, or a receipt that does not match the sealed
identity fails closed before anything is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

BATCH_KIND = "rootyard/native-build-batch"
STORE_SCHEMA = "rootyard/native-artifact-store/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
CHUNK = 1024 * 1024


class ExportError(ValueError):
    """A manifest, path or receipt failed validation."""


def require(condition, message):
    if not condition:
        raise ExportError(message)


def sha256_file(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _single_line(value, label):
    require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    require(
        "\x00" not in value and "\n" not in value and "\r" not in value,
        f"{label} must be a single safe line",
    )
    return value


def _absolute(value, label):
    text = _single_line(value, label)
    path = Path(text)
    require(path.is_absolute(), f"{label} must be absolute: {text}")
    require(".." not in path.parts, f"{label} must not traverse: {text}")
    return path


def _inside(path, root):
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _require_readonly_regular(path, label):
    require(not path.is_symlink(), f"{label} must not be a symlink: {path}")
    require(path.is_file(), f"{label} must be a regular file: {path}")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), f"{label} must be a regular file: {path}")
    require(info.st_uid == os.geteuid(), f"{label} must be owned by the current user: {path}")
    require(info.st_mode & 0o222 == 0, f"{label} must be readonly: {path}")
    return info


def _load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ExportError(f"{label} is not valid JSON: {error}") from None


def _load_store(manifest_path):
    try:
        raw = manifest_path.read_bytes()
    except OSError as error:
        raise ExportError(f"batch manifest cannot be read: {error}") from None
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ExportError(f"batch manifest is not valid JSON: {error}") from None
    require(isinstance(manifest, dict), "batch manifest must be a JSON object")
    require(manifest.get("kind") == BATCH_KIND, "batch manifest has an invalid kind")
    version = manifest.get("manifest_version")
    require(
        isinstance(version, int) and not isinstance(version, bool) and version == 2,
        "batch manifest_version must be the integer 2",
    )
    require(manifest.get("status") == "passed", "batch manifest status must be 'passed'")
    store = manifest.get("artifact_store")
    require(isinstance(store, dict), "batch manifest is not an artifact-store manifest")
    require(store.get("schema") == STORE_SCHEMA, "artifact_store schema is invalid")
    root = _absolute(store.get("root"), "artifact_store.root")
    root_resolved = root.resolve()
    workspace = Path.cwd().resolve()
    require(
        root_resolved != workspace and workspace not in root_resolved.parents,
        f"artifact_store.root must be outside the workspace: {root}",
    )
    target = manifest.get("target_directory")
    if target is not None:
        target_path = _absolute(target, "target_directory").resolve()
        require(
            root_resolved != target_path
            and target_path not in root_resolved.parents
            and root_resolved not in target_path.parents,
            "artifact_store.root must be disjoint from target_directory",
        )
    sealed = store.get("sealed")
    require(isinstance(sealed, list) and sealed, "artifact_store.sealed must be a nonempty list")
    require(
        all(isinstance(item, dict) for item in sealed),
        "artifact_store.sealed entries must be objects",
    )
    objects = store.get("objects")
    require(isinstance(objects, list) and objects, "artifact_store.objects must be a nonempty list")
    require(
        all(isinstance(item, str) and item for item in objects),
        "artifact_store.objects must be nonempty paths",
    )
    rows = manifest.get("artifacts")
    require(isinstance(rows, list) and rows, "batch manifest artifacts must be a nonempty list")
    require(
        all(isinstance(item, dict) for item in rows),
        "batch manifest artifacts entries must be objects",
    )
    return manifest, store, root, sealed, manifest_sha256


def _row(manifest, target, kind, label):
    matches = [
        row
        for row in manifest["artifacts"]
        if row.get("kind") == kind and row.get("target") == target
    ]
    require(len(matches) == 1, f"{label}: expected exactly one {kind} row for {target}, got {len(matches)}")
    return matches[0]


def _record(row, store_root, sealed, label):
    record = row.get("artifact_store")
    require(isinstance(record, dict), f"{label}: no artifact_store record")
    require(
        sum(1 for item in sealed if item == record) == 1,
        f"{label}: artifact_store record is not exactly one sealed entry",
    )
    require(record.get("schema") == STORE_SCHEMA, f"{label}: artifact_store record schema is invalid")
    require(record.get("root") == str(store_root), f"{label}: artifact_store record root is foreign")
    require(record.get("kind") == row.get("kind"), f"{label}: artifact_store record kind is foreign")
    require(record.get("target") == row.get("target"), f"{label}: artifact_store record target is foreign")
    binary_sha = record.get("binary_sha256")
    require(
        isinstance(binary_sha, str) and HEX64.fullmatch(binary_sha),
        f"{label}: artifact_store binary_sha256 is invalid",
    )
    config_key = record.get("config_key")
    require(
        isinstance(config_key, str) and HEX64.fullmatch(config_key),
        f"{label}: artifact_store config_key is invalid",
    )
    build_id = record.get("build_id")
    require(
        isinstance(build_id, str) and SAFE_COMPONENT.fullmatch(build_id),
        f"{label}: artifact_store build_id is unsafe",
    )
    require(
        record.get("method") in ("reflink", "copy", "reuse"),
        f"{label}: artifact_store method is invalid",
    )
    require(isinstance(record.get("reused"), bool), f"{label}: artifact_store reused must be a boolean")
    require(
        isinstance(record.get("copied_bytes"), int)
        and not isinstance(record.get("copied_bytes"), bool)
        and record.get("copied_bytes") >= 0,
        f"{label}: artifact_store copied_bytes is invalid",
    )
    require(
        row.get("sha256") == binary_sha,
        f"{label}: artifact row sha256 does not match the sealed binary digest",
    )
    return record


def _sealed_paths(record, store_root, label):
    object_path = _absolute(record.get("object"), f"{label}: sealed object")
    binary = _absolute(record.get("binary"), f"{label}: sealed binary")
    canonical_receipt = _absolute(record.get("receipt"), f"{label}: sealed receipt")
    build_receipt = _absolute(record.get("build_receipt"), f"{label}: sealed build receipt")
    for path, name in (
        (object_path, "object"),
        (binary, "binary"),
        (canonical_receipt, "receipt"),
        (build_receipt, "build receipt"),
    ):
        require(_inside(path, store_root), f"{label}: sealed {name} is outside the store: {path}")
    expected_object = store_root / "objects" / "sha256" / record["binary_sha256"]
    require(
        object_path == expected_object,
        f"{label}: sealed object is not the content-addressed path for its digest",
    )
    require(
        canonical_receipt.parent == binary.parent and build_receipt.parent == binary.parent,
        f"{label}: sealed receipts must be adjacent to the canonical binary",
    )
    require(
        canonical_receipt.name == binary.name + ".receipt.json",
        f"{label}: sealed receipt basename is invalid",
    )
    require(
        build_receipt.name == binary.name + ".build.json",
        f"{label}: sealed build receipt basename is invalid",
    )
    return object_path, binary, canonical_receipt, build_receipt


def _validate_bytes(row, record, paths, label):
    object_path, binary, canonical_receipt, build_receipt = paths
    for path, name in (
        (object_path, "object"),
        (binary, "canonical binary"),
        (canonical_receipt, "canonical receipt"),
        (build_receipt, "build receipt"),
    ):
        _require_readonly_regular(path, f"{label}: {name}")
    binary_sha = sha256_file(binary)
    require(
        binary_sha == record["binary_sha256"] == row.get("sha256"),
        f"{label}: binary bytes do not match the sealed digest",
    )
    require(
        sha256_file(object_path) == binary_sha,
        f"{label}: CAS object bytes do not match the sealed digest",
    )
    canonical_sha = sha256_file(canonical_receipt)
    require(
        sha256_file(build_receipt) == canonical_sha,
        f"{label}: .build.json alias is not a same-byte receipt alias",
    )
    payload = _load_json(canonical_receipt, f"{label}: canonical receipt")
    require(isinstance(payload, dict), f"{label}: canonical receipt must be a JSON object")
    require(
        payload.get("binary_sha256") == binary_sha,
        f"{label}: receipt binary_sha256 does not match the sealed bytes",
    )
    require(
        payload.get("artifact_store") == record,
        f"{label}: receipt artifact_store does not match the sealed record",
    )
    alias_payload = _load_json(build_receipt, f"{label}: .build.json alias")
    require(alias_payload == payload, f"{label}: .build.json alias is not the canonical receipt")
    return binary_sha


def validate_bin(manifest, target, store_root, sealed, label):
    row = _row(manifest, target, "bin", label)
    record = _record(row, store_root, sealed, label)
    paths = _sealed_paths(record, store_root, label)
    object_path, binary, canonical_receipt, build_receipt = paths
    require(row.get("implicit") is False, f"{label}: an implicit bin is not acceptance")
    require(row.get("artifact") == str(binary), f"{label}: artifact is not the canonical snapshot")
    require(row.get("receipt") == str(build_receipt), f"{label}: receipt is not the sealed .build.json alias")
    require(binary.name == target, f"{label}: canonical binary basename is not the target")
    _validate_bytes(row, record, paths, label)
    return binary, build_receipt


def validate_test(manifest, target, store_root, sealed, label):
    row = _row(manifest, target, "test", label)
    record = _record(row, store_root, sealed, label)
    paths = _sealed_paths(record, store_root, label)
    object_path, binary, canonical_receipt, build_receipt = paths
    alias = _absolute(row.get("artifact"), f"{label}: output alias")
    alias_receipt = _absolute(row.get("receipt"), f"{label}: output alias receipt")
    require(not _inside(alias, store_root), f"{label}: output alias must be outside the store")
    require(not _inside(alias_receipt, store_root), f"{label}: output alias receipt must be outside the store")
    output_alias = record.get("output_alias")
    require(isinstance(output_alias, dict), f"{label}: sealed record has no output_alias")
    require(output_alias.get("path") == str(alias), f"{label}: output_alias.path is foreign")
    require(output_alias.get("receipt") == str(alias_receipt), f"{label}: output_alias.receipt is foreign")
    require(output_alias.get("method") in ("hardlink", "copy"), f"{label}: output alias method is invalid")
    require(
        isinstance(output_alias.get("same_inode_as_cas_object"), bool),
        f"{label}: output alias inode claim must be a boolean",
    )
    require(
        output_alias.get("overwrote_existing") is False,
        f"{label}: output alias claims it overwrote an existing path",
    )
    _validate_bytes(row, record, paths, label)
    _require_readonly_regular(alias, f"{label}: output alias")
    _require_readonly_regular(alias_receipt, f"{label}: output alias receipt")
    require(
        sha256_file(alias) == record["binary_sha256"],
        f"{label}: output alias bytes do not match the sealed digest",
    )
    require(
        sha256_file(alias_receipt) == sha256_file(build_receipt),
        f"{label}: output alias receipt is not the sealed receipt bytes",
    )
    return alias, alias_receipt


def parse_assignments(values, flag):
    result = {}
    for value in values or []:
        target, separator, name = value.partition("=")
        require(separator and target and name, f"{flag} expects TARGET=ENV_NAME, got {value!r}")
        require(ENV_NAME.fullmatch(name), f"{flag} has an unsafe environment name: {name!r}")
        require(target not in result, f"{flag} repeats target {target!r}")
        result[target] = name
    return result


def build_exports(args):
    manifest_path = Path(args.manifest)
    require(manifest_path.is_file(), f"batch manifest is missing: {manifest_path}")
    manifest, store, root, sealed, manifest_sha256 = _load_store(manifest_path)
    exports = {}

    def add(name, value):
        _single_line(value, name)
        require(ENV_NAME.fullmatch(name), f"unsafe environment name: {name!r}")
        previous = exports.get(name)
        require(previous is None or previous == value, f"environment name {name!r} has conflicting values")
        exports[name] = value

    add(args.store_var, str(root))
    add(args.manifest_var, str(manifest_path.resolve()))
    add(args.manifest_sha256_var, manifest_sha256)
    for target, name in parse_assignments(args.bin, "--bin").items():
        binary, _ = validate_bin(manifest, target, root, sealed, f"bin {target}")
        add(name, str(binary))
    for target, name in parse_assignments(args.bin_receipt, "--bin-receipt").items():
        _, receipt = validate_bin(manifest, target, root, sealed, f"bin receipt {target}")
        add(name, str(receipt))
    for target, name in parse_assignments(args.test, "--test").items():
        alias, _ = validate_test(manifest, target, root, sealed, f"test {target}")
        add(name, str(alias))
    return exports


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Export validated immutable native artifact paths into GITHUB_ENV."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--github-env", required=True)
    parser.add_argument("--bin", action="append", default=[],
                        help="TARGET=ENV_NAME exporting the canonical readonly bin snapshot")
    parser.add_argument("--bin-receipt", action="append", default=[],
                        help="TARGET=ENV_NAME exporting the adjacent .build.json alias")
    parser.add_argument("--test", action="append", default=[],
                        help="TARGET=ENV_NAME exporting the readonly --output alias")
    parser.add_argument("--store-var", default="ROOTYARD_ARTIFACT_STORE")
    parser.add_argument("--manifest-var", default="ROOTYARD_BATCH_MANIFEST")
    parser.add_argument("--manifest-sha256-var", default="ROOTYARD_BATCH_MANIFEST_SHA256")
    args = parser.parse_args(argv)
    try:
        exports = build_exports(args)
        destination = Path(args.github_env)
        with destination.open("a", encoding="utf-8") as stream:
            for name in sorted(exports):
                stream.write(f"{name}={exports[name]}\n")
    except (ExportError, OSError) as error:
        print("export_native_artifacts: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
