#!/usr/bin/env python3
"""Focused offline tests for the immutable native artifact env exporter.

No Cargo, compiler, container, database or network is used. The fixture builds
the exact version-2 manifest/artifact-store layout documented for
``scripts/build_native_batch.py --artifact-store`` in a temporary directory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/export_native_artifacts.py"
COMMIT = "a" * 40
CONFIG_KEY = "b" * 64
TARGET = "x86_64-unknown-linux-gnu"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ArtifactFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(parents=True)
        self.target = self.workspace / "target"
        self.target.mkdir()
        self.store = self.root / "store"
        self.store.mkdir()
        self.manifest = self.workspace / "test-results/native-build-batch.json"
        self.manifest.parent.mkdir(parents=True)
        self.rows = []
        self.sealed = []

    def _write_readonly(self, path, data, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)

    def _seal(self, kind, target, name, *, implicit=False, output_alias=None,
              payload_override=None):
        data = (kind + ":" + target).encode()
        sha = hashlib.sha256(data).hexdigest()
        object_path = self.store / "objects/sha256" / sha
        self._write_readonly(object_path, data, 0o555)
        build_id = "build-" + target
        base = self.store / "snapshots" / COMMIT / CONFIG_KEY / build_id
        binary = base / name
        receipt = base / (name + ".receipt.json")
        build_receipt = base / (name + ".build.json")
        self._write_readonly(binary, data, 0o555)
        record = {
            "schema": "rootyard/native-artifact-store/v1",
            "root": str(self.store),
            "kind": kind,
            "target": target,
            "implicit": implicit,
            "object": str(object_path),
            "binary": str(binary),
            "receipt": str(receipt),
            "build_receipt": str(build_receipt),
            "binary_sha256": sha,
            "config_key": CONFIG_KEY,
            "build_id": build_id,
            "method": "copy",
            "reused": False,
            "copied_bytes": len(data),
            "output_alias": output_alias,
        }
        payload = {
            "receipt_schema": "rootyard/native-build-receipt/v2",
            "kind": "native-build-batch-bin" if kind == "bin" else "rust-integration-test",
            "binary_sha256": sha,
            "workspace_commit": COMMIT,
            "artifact_store": record,
        }
        payload.update(payload_override or {})
        receipt_bytes = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
        self._write_readonly(receipt, receipt_bytes, 0o444)
        self._write_readonly(build_receipt, receipt_bytes, 0o444)
        self.sealed.append(record)
        row = {
            "kind": kind,
            "target": target,
            "artifact": str(binary),
            "receipt": str(build_receipt),
            "fresh": True,
            "sha256": sha,
            "artifact_store": record,
        }
        if kind == "bin":
            row["implicit"] = implicit
        self.rows.append(row)
        return binary, build_receipt, record

    def create(self):
        snapshot_bin, snapshot_receipt, _ = self._seal("bin", "rootyard", "rootyard")
        view_bin, view_receipt, _ = self._seal("bin", "rootyard-view-lab", "rootyard-view-lab")
        test_name = "refstore-snapshot-fixture"
        test_sha = hashlib.sha256(b"test:ref_store_snapshot_backup_fixture").hexdigest()
        test_data = b"test:ref_store_snapshot_backup_fixture"
        test_object = self.store / "objects/sha256" / test_sha
        self._write_readonly(test_object, test_data, 0o555)
        test_base = self.store / "snapshots" / COMMIT / CONFIG_KEY / "build-test"
        test_binary = test_base / test_name
        test_receipt = test_base / (test_name + ".receipt.json")
        test_build_receipt = test_base / (test_name + ".build.json")
        self._write_readonly(test_binary, test_data, 0o555)
        alias = self.workspace / "test-results" / test_name
        alias_receipt = alias.with_suffix(".build.json")
        alias.parent.mkdir(parents=True, exist_ok=True)
        os.link(test_binary, alias)
        os.chmod(alias, 0o555)
        record = {
            "schema": "rootyard/native-artifact-store/v1",
            "root": str(self.store),
            "kind": "test",
            "target": "ref_store_snapshot_backup_fixture",
            "implicit": False,
            "object": str(test_object),
            "binary": str(test_binary),
            "receipt": str(test_receipt),
            "build_receipt": str(test_build_receipt),
            "binary_sha256": test_sha,
            "config_key": CONFIG_KEY,
            "build_id": "build-test",
            "method": "copy",
            "reused": False,
            "copied_bytes": len(test_data),
            "output_alias": {
                "path": str(alias),
                "receipt": str(alias_receipt),
                "method": "hardlink",
                "same_inode_as_cas_object": True,
                "overwrote_existing": False,
            },
        }
        payload = {
            "receipt_schema": "rootyard/native-build-receipt/v2",
            "kind": "rust-integration-test",
            "binary_sha256": test_sha,
            "workspace_commit": COMMIT,
            "artifact_store": record,
        }
        receipt_bytes = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
        self._write_readonly(test_receipt, receipt_bytes, 0o444)
        self._write_readonly(test_build_receipt, receipt_bytes, 0o444)
        os.link(test_build_receipt, alias_receipt)
        os.chmod(alias_receipt, 0o444)
        self.sealed.append(record)
        self.rows.append({
            "kind": "test",
            "target": "ref_store_snapshot_backup_fixture",
            "artifact": str(alias),
            "receipt": str(alias_receipt),
            "fresh": False,
            "sha256": test_sha,
            "artifact_store": record,
        })
        manifest = {
            "kind": "rootyard/native-build-batch",
            "manifest_version": 2,
            "status": "passed",
            "source_commit": COMMIT,
            "source_inputs_sha256": "c" * 64,
            "cargo_lock_sha256": "d" * 64,
            "config_digest": "e" * 64,
            "target_directory": str(self.target),
            "artifacts": self.rows,
            "artifact_store": {
                "schema": "rootyard/native-artifact-store/v1",
                "root": str(self.store),
                "objects": sorted({record["object"] for record in self.sealed}),
                "sealed": self.sealed,
            },
        }
        self.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.snapshot_bin = snapshot_bin
        self.snapshot_receipt = snapshot_receipt
        self.view_bin = view_bin
        self.view_receipt = view_receipt
        self.alias = alias
        self.alias_receipt = alias_receipt
        return manifest

    def run(self, *arguments, expect=0):
        env_file = self.root / "github-env"
        process = subprocess.run(
            [sys.executable, str(SCRIPT), "--manifest", str(self.manifest),
             "--github-env", str(env_file), *map(str, arguments)],
            cwd=self.workspace,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process.returncode != expect:
            raise AssertionError(
                f"expected exit {expect}, got {process.returncode}\n"
                f"stdout: {process.stdout}\nstderr: {process.stderr}"
            )
        return env_file, process

    def exports(self, *arguments):
        env_file, _ = self.run(*arguments)
        result = {}
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition("=")
            if separator:
                result[name] = value
        return result


class ExportNativeArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ArtifactFixture(self.temporary.name)
        self.fixture.create()

    def tearDown(self):
        self.temporary.cleanup()

    def test_exports_exact_canonical_bin_test_and_receipt_paths(self):
        exports = self.fixture.exports(
            "--bin", "rootyard=ROOTYARD_BIN",
            "--bin-receipt", "rootyard=ROOTYARD_BUILD_RECEIPT",
            "--test", "ref_store_snapshot_backup_fixture=ROOTYARD_SNAPSHOT_FIXTURE",
        )
        self.assertEqual(exports["ROOTYARD_BIN"], str(self.fixture.snapshot_bin))
        self.assertEqual(exports["ROOTYARD_BUILD_RECEIPT"], str(self.fixture.snapshot_receipt))
        self.assertEqual(exports["ROOTYARD_SNAPSHOT_FIXTURE"], str(self.fixture.alias))
        self.assertEqual(exports["ROOTYARD_ARTIFACT_STORE"], str(self.fixture.store))
        self.assertEqual(exports["ROOTYARD_BATCH_MANIFEST"], str(self.fixture.manifest.resolve()))
        self.assertEqual(exports["ROOTYARD_BATCH_MANIFEST_SHA256"], digest(self.fixture.manifest))

    def test_rejects_non_cas_manifest(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        del manifest["artifact_store"]
        self.fixture.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("artifact-store manifest", process.stderr)

    def test_rejects_record_not_present_in_sealed_list(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["artifact_store"]["target"] = "foreign"
        self.fixture.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("sealed entry", process.stderr)

    def test_rejects_implicit_bin(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["implicit"] = True
        self.fixture.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("implicit", process.stderr)

    def test_rejects_writable_sealed_binary(self):
        os.chmod(self.fixture.snapshot_bin, 0o755)
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("readonly", process.stderr)

    def test_rejects_changed_binary_bytes(self):
        os.chmod(self.fixture.snapshot_bin, 0o755)
        self.fixture.snapshot_bin.write_bytes(b"tampered")
        os.chmod(self.fixture.snapshot_bin, 0o555)
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("binary bytes", process.stderr)

    def test_rejects_receipt_that_does_not_bind_the_sealed_bytes(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        record = manifest["artifacts"][0]["artifact_store"]
        receipt = Path(record["receipt"])
        build_receipt = Path(record["build_receipt"])
        payload = json.loads(receipt.read_text(encoding="utf-8"))
        payload["binary_sha256"] = "0" * 64
        receipt_bytes = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
        for path in (receipt, build_receipt):
            os.chmod(path, 0o644)
            path.write_bytes(receipt_bytes)
            os.chmod(path, 0o444)
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("receipt binary_sha256", process.stderr)

    def test_rejects_output_alias_receipt_that_is_not_the_sealed_receipt(self):
        self.fixture.alias_receipt.unlink()
        self.fixture.alias_receipt.write_bytes(b"foreign receipt\n")
        os.chmod(self.fixture.alias_receipt, 0o444)
        _, process = self.fixture.run(
            "--test", "ref_store_snapshot_backup_fixture=ROOTYARD_SNAPSHOT_FIXTURE", expect=1
        )
        self.assertIn("output alias receipt", process.stderr)

    def test_rejects_store_inside_workspace(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        manifest["artifact_store"]["root"] = str(self.fixture.workspace / "store")
        self.fixture.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("outside the workspace", process.stderr)

    def test_rejects_missing_required_target(self):
        _, process = self.fixture.run("--bin", "rootyard-missing=ROOTYARD_BIN", expect=1)
        self.assertIn("exactly one bin row", process.stderr)

    def test_rejects_unsafe_environment_name(self):
        _, process = self.fixture.run("--bin", "rootyard=lower-case", expect=1)
        self.assertIn("unsafe environment name", process.stderr)

    def test_rejects_malformed_manifest(self):
        self.fixture.manifest.write_bytes(b'{"kind": ')
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("not valid JSON", process.stderr)

    def test_rejects_changed_selected_bin_artifact(self):
        manifest = json.loads(self.fixture.manifest.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["artifact"] = str(self.fixture.store / "foreign")
        self.fixture.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        _, process = self.fixture.run("--bin", "rootyard=ROOTYARD_BIN", expect=1)
        self.assertIn("artifact is not the canonical snapshot", process.stderr)

    def test_manifest_rewrite_after_read_keeps_validated_raw_sha(self):
        spec = importlib.util.spec_from_file_location(
            "export_native_artifacts_under_test", SCRIPT
        )
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)

        original_bytes = self.fixture.manifest.read_bytes()
        replacement = json.loads(original_bytes)
        replacement["status"] = "failed"
        replacement_bytes = (json.dumps(replacement, indent=2) + "\n").encode()
        self.assertNotEqual(replacement_bytes, original_bytes)
        rewritten = []
        original_read_bytes = Path.read_bytes
        original_read_text = Path.read_text

        def rewrite_once(path):
            if path == self.fixture.manifest and not rewritten:
                rewritten.append(path)
                path.write_bytes(replacement_bytes)

        def read_bytes_then_rewrite(path):
            data = original_read_bytes(path)
            rewrite_once(path)
            return data

        def read_text_then_rewrite(path, *args, **kwargs):
            data = original_read_text(path, *args, **kwargs)
            rewrite_once(path)
            return data

        arguments = argparse.Namespace(
            manifest=str(self.fixture.manifest),
            bin=["rootyard=ROOTYARD_BIN"],
            bin_receipt=[],
            test=[],
            store_var="ROOTYARD_ARTIFACT_STORE",
            manifest_var="ROOTYARD_BATCH_MANIFEST",
            manifest_sha256_var="ROOTYARD_BATCH_MANIFEST_SHA256",
        )
        previous = Path.cwd()
        try:
            os.chdir(self.fixture.workspace)
            with mock.patch.object(Path, "read_bytes", read_bytes_then_rewrite), \
                    mock.patch.object(Path, "read_text", read_text_then_rewrite):
                exports = exporter.build_exports(arguments)
        finally:
            os.chdir(previous)

        self.assertEqual(rewritten, [self.fixture.manifest])
        self.assertEqual(self.fixture.manifest.read_bytes(), replacement_bytes)
        self.assertEqual(
            exports["ROOTYARD_BATCH_MANIFEST_SHA256"],
            hashlib.sha256(original_bytes).hexdigest(),
        )
        self.assertNotEqual(
            exports["ROOTYARD_BATCH_MANIFEST_SHA256"],
            hashlib.sha256(replacement_bytes).hexdigest(),
        )
        self.assertEqual(exports["ROOTYARD_BIN"], str(self.fixture.snapshot_bin))


if __name__ == "__main__":
    unittest.main()
