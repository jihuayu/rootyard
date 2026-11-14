"""Focused schema-dispatch tests for the populated RefStore backup drills.

The fixtures below build real v2 receipts with the shared producer helpers from a
temporary source tree, then feed them to the actual reader through the consumer
validators.  They never invoke Cargo, rustc, rustup, a builder, a database or a
subprocess.  V1 receipts keep their historical flexible field names and strict
``package_rebuilt``/``fresh=False`` requirements.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SCRIPTS = ROOT / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import backup_refstore_build_receipts as binding  # noqa: E402
import backup_refstore_holds141 as holds141  # noqa: E402
import backup_refstore_snapshot140 as snapshot140  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

CARGO_FORK_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
RUSTC_COMMIT = "d" * 40
TARGET_TRIPLE = "aarch64-unknown-linux-gnu"
SNAPSHOT_TARGET = "ref_store_snapshot_backup_fixture"
SNAPSHOT_SOURCE = "tests/ref_store_snapshot_backup_fixture.rs"
HOLDS_TARGET = "ref_store_holds_backup_fixture"
HOLDS_SOURCE = "tests/ref_store_holds_backup_fixture.rs"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RefStoreReceiptFixture(unittest.TestCase):
    """A temporary source tree, executable fixtures and real v2 producer rows."""

    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix="rootyard-refstore-receipts-"))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.root = self.tempdir.resolve()
        self.write("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.0"\n')
        self.write("Cargo.lock", "version = 3\n")
        self.write("build.rs", "fn main() {}\n")
        self.write("src/lib.rs", "pub fn production() -> u8 { 1 }\n")
        self.write("src/main.rs", "fn main() {}\n")
        self.write("src/bin/rootyard-pando-lab.rs", "fn main() {}\n")
        # The consumer trusts the checked-in helper source file, so the fixture
        # tree must carry those exact bytes for the real digest binding to pass.
        self.write(SNAPSHOT_SOURCE, (ROOT / SNAPSHOT_SOURCE).read_bytes())
        self.write(HOLDS_SOURCE, (ROOT / HOLDS_SOURCE).read_bytes())
        self.write("tests/other_backup_fixture.rs", "#[test]\nfn other_backup_metadata_fixture() {}\n")
        self.write("tests/ref_store_other_fixture.rs", "#[test]\nfn other() {}\n")
        self.write("tests/fixtures/data.txt", "fixture-data\n")
        self.write("experimental/pando/schema.sql", "create table pando_session();\n")
        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n')
        self.write(".cargo/config.toml", "[build]\njobs = 4\n")
        self.app_binary = self.write("target/debug/rootyard", b"rootyard-application-binary")
        self.app_output = self.write("outputs/rootyard", b"rootyard-application-binary")
        self.other_bin = self.write("target/debug/rootyard-pando-lab",
                                    b"rootyard-pando-lab-binary")
        self.snapshot_original = self.write(
            "target/debug/deps/ref_store_snapshot_backup_fixture-deadbeef",
            b"snapshot-helper-binary")
        self.snapshot_output = self.write(
            "outputs/refstore-snapshot-fixture", b"snapshot-helper-binary")
        self.holds_original = self.write(
            "target/debug/deps/ref_store_holds_backup_fixture-feedface",
            b"holds-helper-binary")
        self.holds_output = self.write(
            "outputs/refstore-holds-fixture", b"holds-helper-binary")
        self.store_root = Path(tempfile.mkdtemp(prefix="rootyard-refstore-store-"))
        self.addCleanup(shutil.rmtree, self.store_root, ignore_errors=True)
        for name in ("cargo", "rustc", "rustup"):
            self.write("toolchain/" + name, ("fake-" + name).encode())
        self.environ = {"PATH": ""}
        self.profile = {
            "opt_level": "0",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": True,
            "test": False,
        }
        self.test_profile = dict(self.profile, test=True)
        self.bound = self.capture()
        self.commit = "a" * 40
        self.head = "b" * 40
        self.tree = "c" * 40
        self.manifest = self.root / "test-results/native-build-batch.json"
        self.command = [
            "cargo", "build", "--locked", "--profile", "test",
            "--features", "pando-lab", "--message-format=json-render-diagnostics",
        ]
        self.dev_command = [
            "cargo", "build", "--locked", "--bin", "rootyard",
            "--features", "pando-lab", "--message-format=json-render-diagnostics",
        ]

    # -- temporary tree ---------------------------------------------------
    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def capture(self):
        return receipts.capture_bound_inputs(self.root, environ=self.environ)

    def toolchain(self):
        def identity(name, release, commit_hash):
            executable = self.root / "toolchain" / name
            return {
                "executable": str(executable),
                "executable_sha256": receipts.sha256_file(executable),
                "version": f"{name} {release} (fake 2026-01-01)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": TARGET_TRIPLE,
            }

        return {
            "cargo": identity("cargo", "1.101.0", CARGO_FORK_COMMIT),
            "rustc": dict(
                identity("rustc", "1.99.1", RUSTC_COMMIT),
                path_entry=str(self.root / "toolchain/rustc"),
                proxy=False,
            ),
            "rustup": {
                "executable": str(self.root / "toolchain/rustup"),
                "executable_sha256": receipts.sha256_file(self.root / "toolchain/rustup"),
                "resolved_rustc": str(self.root / "toolchain/rustc"),
                "resolved_rustc_sha256": receipts.sha256_file(self.root / "toolchain/rustc"),
            },
            "target_triple": TARGET_TRIPLE,
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def selection(self, profile):
        return {
            "features": "pando-lab",
            "no_default_features": False,
            "profile": profile,
            "package_debug": None,
            "strip_debuginfo": True,
        }

    def batch_link(self, manifest, binary_name, targets, bound):
        return {
            "kind": binding.BATCH_KIND,
            "receipt_version": 2,
            "binary": Path(binary_name).name,
            "targets": list(targets),
            "bound_inputs_sha256": bound["bound_inputs"]["digest"],
            "manifest": str(Path(manifest).resolve()),
        }

    def event(self, *, target, kind, source, profile, executable, fresh, package_id="rootyard 0.1.0"):
        event = {
            "reason": "compiler-artifact",
            "package_id": package_id,
            "target": {"name": target, "kind": [kind], "src_path": str(self.root / source)},
            "profile": profile,
            "fresh": fresh,
        }
        if executable is not None:
            event["executable"] = str(executable)
        return event

    def write_receipt(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n")
        return path

    # -- v2 helper --------------------------------------------------------
    def helper_receipt(self, *, target=SNAPSHOT_TARGET, source=None,
                       fresh=True, output=None, original=None, manifest=None,
                       bound=None, toolchain=None, profile="test",
                       kind="rust-integration-test", relocated=True,
                       with_batch=True, with_selection=True,
                       batch_targets=None, artifact_store=None):
        if source is None:
            source = SNAPSHOT_SOURCE if target == SNAPSHOT_TARGET else HOLDS_SOURCE
        output = Path(output or (self.snapshot_output if target == SNAPSHOT_TARGET
                                 else self.holds_output))
        original = Path(original or (self.snapshot_original if target == SNAPSHOT_TARGET
                                     else self.holds_original))
        manifest = Path(manifest or self.manifest)
        bound = bound or self.bound
        toolchain = toolchain or self.toolchain()
        event = self.event(target=target, kind="test", source=source,
                           profile=self.test_profile, executable=original,
                           fresh=fresh)
        row = receipts.cargo_artifact_record(event, self.root)
        extra = {
            "kind": kind,
            "build_options": {"jobs": 2},
            "integration_test_source": row["source"],
            "integration_test_source_sha256": row["source_sha256"],
        }
        if relocated:
            extra["relocated_artifact"] = True
            extra["original_artifact_sha256"] = row["executable_sha256"]
        if artifact_store is not None:
            extra["artifact_store"] = artifact_store
        if with_batch:
            extra["batch"] = self.batch_link(
                manifest, output.name,
                batch_targets or ["rootyard", "rootyard", target], bound)
        if with_selection:
            extra["selection"] = self.selection(profile)
        return receipts.make_receipt_v2(
            binary_path=output,
            command=self.command,
            profile=profile,
            artifacts=[row],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=self.commit,
            target_dir=self.root / "target",
            target_triple=TARGET_TRIPLE,
            features="pando-lab",
            no_default_features=False,
            lock_file=self.root / "Cargo.lock",
            git_head=self.head,
            working_tree={"tree": self.tree, "status": ""},
            duration_seconds=1.0,
            extra=extra,
        )

    # -- v2 application ---------------------------------------------------
    def app_receipt(self, *, kind=binding.APP_BATCH_KIND, profile="test",
                    lib_fresh=True, bin_fresh=False, lib_source=binding.APP_LIB_SOURCE,
                    bin_source=binding.APP_BIN_SOURCE, bin_target=binding.APP_TARGET,
                    bin_executable=None, output=None, original_sha256=None,
                    manifest=None, bound=None, toolchain=None, relocated=False,
                    with_batch=True, with_selection=True, implicit=False,
                    extra_bins=(), artifact_store=None):
        bin_executable = Path(bin_executable or self.app_binary)
        if relocated:
            binary_path = Path(output or self.app_output)
        else:
            binary_path = Path(output or self.app_binary)
        manifest = Path(manifest or self.manifest)
        bound = bound or self.bound
        toolchain = toolchain or self.toolchain()
        lib_event = self.event(
            target=binding.APP_TARGET, kind="lib", source=lib_source,
            profile=self.profile, executable=None, fresh=lib_fresh)
        bin_event = self.event(
            target=bin_target, kind="bin", source=bin_source,
            profile=self.profile, executable=bin_executable, fresh=bin_fresh)
        lib_row = receipts.cargo_artifact_record(lib_event, self.root)
        bin_row = receipts.cargo_artifact_record(bin_event, self.root)
        rows = [lib_row, bin_row]
        targets = [binding.APP_TARGET, binding.APP_TARGET]
        for extra in extra_bins:
            extra_event = self.event(
                target=extra["target"], kind=extra.get("kind", "bin"),
                source=extra["source"], profile=self.profile,
                executable=extra.get("executable"), fresh=extra.get("fresh", True))
            rows.append(receipts.cargo_artifact_record(extra_event, self.root))
            targets.append(extra["target"])
        extra = {"kind": kind, "build_options": {"jobs": 2}}
        if implicit:
            extra["implicit_build"] = True
        if relocated:
            extra["relocated_artifact"] = True
            extra["original_artifact_sha256"] = original_sha256 or bin_row["executable_sha256"]
        if artifact_store is not None:
            extra["artifact_store"] = artifact_store
        if with_batch:
            extra["batch"] = self.batch_link(manifest, binary_path.name, targets, bound)
        if with_selection:
            extra["selection"] = self.selection(profile)
        return receipts.make_receipt_v2(
            binary_path=binary_path,
            command=self.command if profile == "test" else self.dev_command,
            profile=profile,
            artifacts=rows,
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=self.commit,
            target_dir=self.root / "target",
            target_triple=TARGET_TRIPLE,
            features="pando-lab",
            no_default_features=False,
            lock_file=self.root / "Cargo.lock",
            git_head=self.head,
            working_tree={"tree": self.tree, "status": ""},
            duration_seconds=1.0,
            extra=extra,
        )

    def app_cli_receipt(self, **overrides):
        overrides.setdefault("kind", binding.APP_CLI_KIND)
        overrides.setdefault("profile", "dev")
        overrides.setdefault("with_batch", False)
        overrides.setdefault("with_selection", False)
        return self.app_receipt(**overrides)

    # -- producer-shaped batch manifest -----------------------------------
    def manifest_artifact_row(self, row, artifact, receipt, implicit=None):
        entry = {
            "kind": row["kind"],
            "target": row["target"],
            "artifact": str(artifact),
            "original_artifact": row.get("executable", str(artifact)),
            "original_artifact_sha256": row.get("executable_sha256"),
            "receipt": str(receipt),
            "fresh": row["fresh"],
            "sha256": row.get("executable_sha256") or digest(artifact),
            "size": Path(artifact).stat().st_size if Path(artifact).is_file() else 0,
            "mtime_ns": 0,
            "duration_seconds": 1.0,
            "package_id": row["package_id"],
            "profile": row["profile"],
            "source": row["source"],
        }
        if row["kind"] == "test":
            entry["source_sha256"] = row["source_sha256"]
        if implicit is not None:
            entry["implicit"] = implicit
        return entry

    def producer_manifest(self, helper_payload, app_payload, helper_receipt,
                          app_receipt, app_binary, *, manifest_app_payload=None):
        helper_row = helper_payload["cargo_artifacts"][0]
        helper_binary = (self.snapshot_output
                         if helper_row["target"] == SNAPSHOT_TARGET
                         else self.holds_output)
        cas = (helper_payload.get("artifact_store") is not None
               or app_payload.get("artifact_store") is not None)
        if app_payload.get("batch") is None or "cargo_artifacts" not in app_payload:
            app_payload = manifest_app_payload
            if app_payload is None:
                app_payload = self.app_receipt(relocated=False)
            app_receipt = Path(str(self.app_binary) + ".build.json")
            app_binary = self.app_binary
        app_rows = list(app_payload["cargo_artifacts"])
        extra_row = receipts.cargo_artifact_record(self.event(
            target="rootyard-pando-lab", kind="bin",
            source="src/bin/rootyard-pando-lab.rs", profile=self.profile,
            executable=self.other_bin, fresh=True), self.root)
        build_rows = app_rows + [extra_row, helper_row]
        helper_payload["batch"]["targets"] = [row["target"] for row in build_rows]
        artifacts = []
        if not cas:
            artifacts.append(self.manifest_artifact_row(
                extra_row, self.other_bin,
                Path(str(self.other_bin) + ".build.json"), implicit=False))
        for row in app_rows:
            if row["kind"] != "bin":
                continue
            if row["target"] == binding.APP_TARGET:
                artifact_path = app_binary
                receipt_path = app_receipt
                record = app_payload.get("artifact_store")
            else:
                artifact_path = self.other_bin
                receipt_path = Path(str(self.other_bin) + ".build.json")
                record = None
            entry = self.manifest_artifact_row(
                row, artifact_path, receipt_path, implicit=False)
            if record is not None:
                entry["artifact_store"] = record
            artifacts.append(entry)
        helper_entry = self.manifest_artifact_row(
            helper_row, helper_binary, helper_receipt)
        if helper_payload.get("artifact_store") is not None:
            helper_entry["artifact_store"] = helper_payload["artifact_store"]
        artifacts.append(helper_entry)
        manifest = {
            "kind": binding.BATCH_KIND,
            "manifest_version": 2,
            "status": "passed",
            "source_commit": helper_payload["workspace_commit"],
            "git_head": helper_payload.get("git_head"),
            "working_tree": helper_payload.get("working_tree"),
            "source_inputs_sha256": helper_payload["source_inputs_sha256"],
            "cargo_lock_sha256": helper_payload["cargo_lock_sha256"],
            "config_digest": helper_payload["config_digest"],
            "bound_inputs": helper_payload["bound_inputs"],
            "bound_input_inventory": helper_payload["bound_input_inventory"],
            "toolchain": helper_payload["toolchain"],
            "features": helper_payload["features"],
            "profile": helper_payload["profile"],
            "target_triple": helper_payload["target_triple"],
            "selection": helper_payload.get("selection"),
            "architecture": {
                "target_triple": helper_payload["target_triple"],
                "host": helper_payload["toolchain"]["rustc"]["host"],
            },
            "target_directory": helper_payload["target_dir"],
            "lock_file": helper_payload.get("lock_file"),
            "cargo_metadata_target_directory": helper_payload["target_dir"],
            "cargo_package_id": "rootyard 0.1.0",
            "build_options": helper_payload.get("build_options"),
            "build": {
                "command": helper_payload["command"],
                "commands": 1,
                "duration_seconds": 1.0,
                "cargo_artifacts": build_rows,
            },
            "artifacts": artifacts,
            "duration_seconds": 2.0,
        }
        if cas:
            helper_record = helper_payload.get("artifact_store")
            app_record = app_payload.get("artifact_store")
            assert isinstance(helper_record, dict) and isinstance(app_record, dict)
            manifest["artifact_store"] = {
                "schema": binding.STORE_SCHEMA,
                "root": str(self.store_root),
                "objects": [helper_record["object"], app_record["object"]],
                "sealed": [helper_record, app_record],
            }
        return manifest

    def write_manifest(self, path, payload):
        return self.write_receipt(Path(path), payload)

    def cas_records(self, helper_target, helper_receipt):
        """Create canonical CAS binaries and return the helper/app store records."""
        helper_binary = (self.snapshot_output if helper_target == SNAPSHOT_TARGET
                         else self.holds_output)
        app_binary = self.app_output
        helper_sha = digest(helper_binary)
        app_sha = digest(app_binary)
        helper_dir = self.store_root / "snapshots" / self.commit / ("c" * 64) / "helper-build"
        app_dir = self.store_root / "snapshots" / self.commit / ("d" * 64) / "app-build"
        helper_dir.mkdir(parents=True, exist_ok=True)
        app_dir.mkdir(parents=True, exist_ok=True)
        helper_object = self.store_root / "objects/sha256" / helper_sha
        app_object = self.store_root / "objects/sha256" / app_sha
        helper_object.parent.mkdir(parents=True, exist_ok=True)
        app_object.parent.mkdir(parents=True, exist_ok=True)
        helper_object.write_bytes(helper_binary.read_bytes())
        app_object.write_bytes(app_binary.read_bytes())
        helper_canonical = helper_dir / helper_binary.name
        app_canonical = app_dir / "rootyard"
        helper_canonical.write_bytes(helper_binary.read_bytes())
        app_canonical.write_bytes(app_binary.read_bytes())
        helper_build = helper_dir / (helper_canonical.name + ".build.json")
        helper_canonical_receipt = helper_dir / (helper_canonical.name + ".receipt.json")
        app_build = app_dir / "rootyard.build.json"
        app_canonical_receipt = app_dir / "rootyard.receipt.json"
        helper_record = {
            "schema": binding.STORE_SCHEMA,
            "root": str(self.store_root),
            "kind": "test",
            "target": helper_target,
            "implicit": False,
            "object": str(helper_object),
            "binary": str(helper_canonical),
            "receipt": str(helper_canonical_receipt),
            "build_receipt": str(helper_build),
            "binary_sha256": helper_sha,
            "config_key": "c" * 64,
            "build_id": "helper-build",
            "method": "copy",
            "reused": False,
            "copied_bytes": helper_canonical.stat().st_size,
            "output_alias": {
                "path": str(helper_binary),
                "receipt": str(helper_receipt),
                "method": "copy",
                "same_inode_as_cas_object": False,
                "overwrote_existing": False,
            },
        }
        app_record = {
            "schema": binding.STORE_SCHEMA,
            "root": str(self.store_root),
            "kind": "bin",
            "target": binding.APP_TARGET,
            "implicit": False,
            "object": str(app_object),
            "binary": str(app_canonical),
            "receipt": str(app_canonical_receipt),
            "build_receipt": str(app_build),
            "binary_sha256": app_sha,
            "config_key": "d" * 64,
            "build_id": "app-build",
            "method": "copy",
            "reused": False,
            "copied_bytes": app_canonical.stat().st_size,
            "output_alias": None,
        }
        return helper_record, app_record

    def finalize_cas(self, helper_record, app_record, helper_receipt, app_receipt):
        helper_bytes = Path(helper_receipt).read_bytes()
        app_bytes = Path(app_receipt).read_bytes()
        Path(helper_record["build_receipt"]).write_bytes(helper_bytes)
        Path(helper_record["receipt"]).write_bytes(helper_bytes)
        Path(app_record["build_receipt"]).write_bytes(app_bytes)
        Path(app_record["receipt"]).write_bytes(app_bytes)

    def cas_pair(self, target):
        helper_output = (self.snapshot_output if target == SNAPSHOT_TARGET
                         else self.holds_output)
        helper_receipt = Path(str(helper_output) + ".build.json")
        helper_record, app_record = self.cas_records(target, helper_receipt)
        helper = self.helper_receipt(
            target=target, relocated=True, artifact_store=helper_record)
        app = self.app_receipt(
            relocated=True, output=app_record["binary"],
            artifact_store=app_record)
        return helper, app, helper_record, app_record

    # -- v1 receipts ------------------------------------------------------
    def v1_helper_receipt(self, *, target=SNAPSHOT_TARGET, fresh=False,
                          binary_field="binary_sha256", package_rebuilt=True):
        output = self.snapshot_output if target == SNAPSHOT_TARGET else self.holds_output
        original = self.snapshot_original if target == SNAPSHOT_TARGET else self.holds_original
        receipt = {
            "version": 1,
            "kind": "rust-integration-test",
            "source_inputs_sha256": self.bound["source_inputs_sha256"],
            "workspace_commit": self.commit,
            "rustc": "rustc 1.99.1 (fake 2025-01-01)",
            "command": ["cargo", "build", "--locked", "--profile", "test"],
            "package_rebuilt": package_rebuilt,
            "fresh": False,
            "relocated_artifact": True,
            "integration_test_source_sha256": digest(self.root / SNAPSHOT_SOURCE
                                                     if target == SNAPSHOT_TARGET else self.root / HOLDS_SOURCE),
            "fresh_false_artifacts": [{
                "target": target,
                "kind": "test",
                "fresh": fresh,
                "profile": self.test_profile,
                "executable": str(original),
            }],
        }
        receipt[binary_field] = digest(output)
        return receipt

    def v1_app_receipt(self, *, binary_field="binary_sha256", package_rebuilt=True,
                       fresh_rows=False):
        receipt = {
            "version": 1,
            "source_inputs_sha256": self.bound["source_inputs_sha256"],
            "workspace_commit": self.commit,
            "rustc": "rustc 1.99.1 (fake 2025-01-01)",
            "command": ["cargo", "build", "--locked", "--bin", "rootyard"],
            "package_rebuilt": package_rebuilt,
            "fresh": False,
            "fresh_false_artifacts": [
                {"target": "rootyard", "kind": "lib", "fresh": fresh_rows,
                 "package_id": "rootyard 0.1.0"},
                {"target": "rootyard", "kind": "bin", "fresh": fresh_rows,
                 "package_id": "rootyard 0.1.0", "executable": str(self.app_binary)},
            ],
        }
        receipt[binary_field] = digest(self.app_binary)
        return receipt

    def validate_snapshot(self, helper_payload, app_payload, *, default_paths=False,
                          environ=None, manifest=None, manifest_app_payload=None,
                          app_binary=None, finalize=None):
        app_binary = (app_binary or
                      (self.app_output if app_payload.get("relocated_artifact") is True
                       else self.app_binary))
        helper_receipt = Path(str(self.snapshot_output) + ".build.json")
        app_receipt = Path(str(app_binary) + ".build.json")
        selected_environ = {} if environ is None else environ
        if "receipt_schema" in helper_payload:
            manifest_payload = manifest
            if manifest_payload is None:
                manifest_payload = self.producer_manifest(
                    helper_payload, app_payload, helper_receipt, app_receipt,
                    app_binary, manifest_app_payload=manifest_app_payload)
            if manifest_payload is not False:
                self.write_manifest(
                    helper_payload["batch"]["manifest"], manifest_payload)
        self.write_receipt(helper_receipt, helper_payload)
        self.write_receipt(app_receipt, app_payload)
        if finalize is not None:
            finalize(helper_receipt, app_receipt)
        if default_paths:
            return snapshot140.validate_snapshot_fixture_binary(
                self.snapshot_output, app_binary, environ=selected_environ)
        return snapshot140.validate_snapshot_fixture_binary(
            self.snapshot_output, app_binary, helper_receipt, app_receipt,
            environ=selected_environ)

    def validate_holds(self, helper_payload, app_payload, *, default_paths=False,
                       environ=None, manifest=None, manifest_app_payload=None,
                       app_binary=None, finalize=None):
        app_binary = (app_binary or
                      (self.app_output if app_payload.get("relocated_artifact") is True
                       else self.app_binary))
        helper_receipt = Path(str(self.holds_output) + ".build.json")
        app_receipt = Path(str(app_binary) + ".build.json")
        selected_environ = {} if environ is None else environ
        if "receipt_schema" in helper_payload:
            manifest_payload = manifest
            if manifest_payload is None:
                manifest_payload = self.producer_manifest(
                    helper_payload, app_payload, helper_receipt, app_receipt,
                    app_binary, manifest_app_payload=manifest_app_payload)
            if manifest_payload is not False:
                self.write_manifest(
                    helper_payload["batch"]["manifest"], manifest_payload)
        self.write_receipt(helper_receipt, helper_payload)
        self.write_receipt(app_receipt, app_payload)
        if finalize is not None:
            finalize(helper_receipt, app_receipt)
        if default_paths:
            return holds141.validate_holds_fixture_binary(
                self.holds_output, app_binary, environ=selected_environ)
        return holds141.validate_holds_fixture_binary(
            self.holds_output, app_binary, helper_receipt, app_receipt,
            environ=selected_environ)


class ExpectedSourceCommitCases:
    """The v2 expected-source-commit contract, exercised by both drills."""

    def pair(self, *, v1=False):
        raise NotImplementedError

    def validate_pair(self, helper_payload, app_payload, environ):
        raise NotImplementedError

    def validate_manifest_pair(self, helper_payload, app_payload, manifest,
                               environ=None):
        raise NotImplementedError

    def validate_cas_pair(self, helper_payload, app_payload, helper_record,
                          app_record, manifest):
        raise NotImplementedError

    def default_manifest(self, helper_payload, app_payload, *, app_binary=None):
        helper_target = helper_payload["cargo_artifacts"][0]["target"]
        helper_output = (self.snapshot_output if helper_target == SNAPSHOT_TARGET
                         else self.holds_output)
        app_binary = (app_binary or
                      (self.app_output if app_payload.get("relocated_artifact") is True
                       else self.app_binary))
        return self.producer_manifest(
            helper_payload, app_payload,
            Path(str(helper_output) + ".build.json"),
            Path(str(app_binary) + ".build.json"),
            app_binary)

    def manifest_entry(self, manifest, kind, target):
        return next(row for row in manifest["artifacts"]
                    if row["kind"] == kind and row["target"] == target)

    def test_v2_manifest_positive_binds_path_raw_sha_and_not_first_row(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        report = self.validate_manifest_pair(helper, app, manifest, {})
        path = Path(helper["batch"]["manifest"])
        self.assertEqual(Path(report["batch_manifest"]).resolve(), path.resolve())
        self.assertEqual(report["batch_manifest_sha256"], digest(path))
        self.assertEqual(report["batch_manifest_version"], 2)
        self.assertEqual(report["batch_manifest_status"], "passed")
        self.assertIsNone(report["expected_batch_manifest"])
        self.assertIsNone(report["expected_batch_manifest_sha256"])
        self.assertEqual(manifest["artifacts"][0]["target"], "rootyard-pando-lab")

    def test_v2_cas_manifest_positive(self):
        target = self.pair()[0]["cargo_artifacts"][0]["target"]
        helper, app, helper_record, app_record = self.cas_pair(target)
        app_binary = Path(app_record["binary"])
        manifest = self.default_manifest(helper, app, app_binary=app_binary)
        report = self.validate_cas_pair(
            helper, app, helper_record, app_record, manifest)
        self.assertEqual(report["batch_manifest_sha256"],
                         digest(Path(helper["batch"]["manifest"])))
        self.assertEqual(report["batch_manifest_status"], "passed")
        self.assertEqual(report["candidate_application_sha256"],
                         digest(app_binary))

    def test_v2_non_cas_manifest_rejects_relocated_bin_receipt(self):
        helper, app = self.pair()
        self.assertFalse(app.get("relocated_artifact") is True)
        app["relocated_artifact"] = True
        app["original_artifact_sha256"] = app["binary_sha256"]
        manifest = self.default_manifest(helper, app)
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(helper, app, manifest, {})

    def test_v2_manifest_missing_or_nonpassed_fails(self):
        helper, app = self.pair()
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(helper, app, False, {})
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        manifest["status"] = "failed"
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(helper, app, manifest, {})

    def test_v2_manifest_wrong_missing_or_duplicate_helper_row_fails(self):
        helper, app = self.pair()
        target = helper["cargo_artifacts"][0]["target"]
        for mutation in ("wrong_hash", "wrong_receipt", "missing", "duplicate"):
            helper, app = self.pair()
            manifest = self.default_manifest(helper, app)
            entry = self.manifest_entry(manifest, "test", target)
            if mutation == "wrong_hash":
                entry["sha256"] = "0" * 64
            elif mutation == "wrong_receipt":
                entry["receipt"] = str(self.root / "foreign/helper.build.json")
            elif mutation == "missing":
                manifest["artifacts"].remove(entry)
            else:
                manifest["artifacts"].append(copy.deepcopy(entry))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.validate_manifest_pair(helper, app, manifest, {})

    def test_v2_manifest_wrong_missing_or_duplicate_app_row_fails(self):
        helper, app = self.pair()
        for mutation in ("wrong_hash", "wrong_receipt", "missing", "duplicate"):
            helper, app = self.pair()
            manifest = self.default_manifest(helper, app)
            entry = self.manifest_entry(manifest, "bin", binding.APP_TARGET)
            if mutation == "wrong_hash":
                entry["sha256"] = "0" * 64
            elif mutation == "wrong_receipt":
                entry["receipt"] = str(self.root / "foreign/rootyard.build.json")
            elif mutation == "missing":
                manifest["artifacts"].remove(entry)
            else:
                manifest["artifacts"].append(copy.deepcopy(entry))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.validate_manifest_pair(helper, app, manifest, {})

    def test_v2_manifest_mutation_with_expected_sha_fails(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        path = Path(helper["batch"]["manifest"])
        self.write_manifest(path, manifest)
        expected_sha = digest(path)
        # A harmless field the content validator does not bind: only the raw
        # exporter SHA can detect this mutation.
        manifest["duration_seconds"] = 999
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(
                helper, app, manifest,
                {"ROOTYARD_BATCH_MANIFEST_SHA256": expected_sha})

    def test_v2_manifest_expected_path_and_sha_positive(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        path = Path(helper["batch"]["manifest"])
        self.write_manifest(path, manifest)
        expected_sha = digest(path)
        report = self.validate_manifest_pair(
            helper, app, manifest,
            {"ROOTYARD_BATCH_MANIFEST": str(path),
             "ROOTYARD_BATCH_MANIFEST_SHA256": expected_sha})
        self.assertEqual(Path(report["expected_batch_manifest"]).resolve(),
                         path.resolve())
        self.assertEqual(report["expected_batch_manifest_sha256"], expected_sha)

    def test_v2_manifest_expected_path_mismatch_fails(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(
                helper, app, manifest,
                {"ROOTYARD_BATCH_MANIFEST": str(self.root / "foreign/manifest.json")})

    def test_v2_manifest_invalid_path_anchor_fails(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(
                helper, app, manifest,
                {"ROOTYARD_BATCH_MANIFEST": "relative/manifest.json"})
        path = Path(helper["batch"]["manifest"])
        self.write_manifest(path, manifest)
        link = self.root / "manifest-link.json"
        if not link.exists():
            os.symlink(path, link)
        with self.assertRaises(AssertionError):
            self.validate_manifest_pair(
                helper, app, manifest,
                {"ROOTYARD_BATCH_MANIFEST": str(link)})

    def test_v2_manifest_raw_sha_empty_is_ignored_and_invalid_fails(self):
        helper, app = self.pair()
        manifest = self.default_manifest(helper, app)
        report = self.validate_manifest_pair(
            helper, app, manifest, {"ROOTYARD_BATCH_MANIFEST_SHA256": ""})
        self.assertIsNone(report["expected_batch_manifest_sha256"])
        for value in ("not-a-sha", "A" * 64, "0" * 63):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                self.validate_manifest_pair(
                    helper, app, manifest,
                    {"ROOTYARD_BATCH_MANIFEST_SHA256": value})

    def test_v2_manifest_header_and_receipt_link_mismatches_fail(self):
        mutations = (
            lambda m: m.__setitem__("source_commit", "f" * 40),
            lambda m: m.__setitem__("config_digest", "f" * 64),
            lambda m: m["build"].__setitem__("command", ["false"]),
            lambda m: m["bound_inputs"].__setitem__("digest", "f" * 64),
        )
        helper, app = self.pair()
        for mutate in mutations:
            helper, app = self.pair()
            manifest = self.default_manifest(helper, app)
            mutate(manifest)
            with self.subTest(mutation=mutate), self.assertRaises(AssertionError):
                self.validate_manifest_pair(helper, app, manifest, {})

    def test_v2_explicit_expected_source_commit_matches(self):
        report = self.validate_pair(
            *self.pair(),
            {"ROOTYARD_EXPECTED_SOURCE_COMMIT": self.commit})
        self.assertEqual(report["expected_source_commit"], self.commit)
        self.assertEqual(report["expected_source_commit_source"],
                         "ROOTYARD_EXPECTED_SOURCE_COMMIT")
        self.assertEqual(report["workspace_commit"], self.commit)

    def test_v2_explicit_expected_source_commit_mismatch_fails(self):
        with self.assertRaises(AssertionError):
            self.validate_pair(
                *self.pair(),
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "0" * 40})

    def test_v2_diagnostic_zero_expected_commit_rejects_dd0_receipt(self):
        helper, app = self.pair()
        actual = "dd0b7788bf5ce7a590bb4c6ac953c2d95e3b06ce"
        helper["workspace_commit"] = actual
        app["workspace_commit"] = actual
        with self.assertRaises(AssertionError):
            self.validate_pair(
                helper, app,
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "0" * 40})

    def test_v2_github_sha_fallback_matches(self):
        report = self.validate_pair(*self.pair(), {"GITHUB_SHA": self.commit})
        self.assertEqual(report["expected_source_commit"], self.commit)
        self.assertEqual(report["expected_source_commit_source"], "GITHUB_SHA")

    def test_v2_github_sha_fallback_mismatch_fails(self):
        with self.assertRaises(AssertionError):
            self.validate_pair(*self.pair(), {"GITHUB_SHA": "0" * 40})

    def test_v2_explicit_wins_over_github_sha(self):
        report = self.validate_pair(
            *self.pair(),
            {"ROOTYARD_EXPECTED_SOURCE_COMMIT": self.commit,
             "GITHUB_SHA": "0" * 40})
        self.assertEqual(report["expected_source_commit"], self.commit)
        self.assertEqual(report["expected_source_commit_source"],
                         "ROOTYARD_EXPECTED_SOURCE_COMMIT")
        with self.assertRaises(AssertionError):
            self.validate_pair(
                *self.pair(),
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "0" * 40,
                 "GITHUB_SHA": self.commit})

    def test_v2_empty_explicit_falls_back_to_github_sha(self):
        report = self.validate_pair(
            *self.pair(),
            {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "", "GITHUB_SHA": self.commit})
        self.assertEqual(report["expected_source_commit"], self.commit)
        self.assertEqual(report["expected_source_commit_source"], "GITHUB_SHA")

    def test_v2_invalid_expected_source_commit_fails_closed(self):
        for environ in (
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "not-a-commit"},
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "0" * 39},
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": " "},
                {"GITHUB_SHA": "not-a-commit"}):
            with self.subTest(environ=environ), self.assertRaises(AssertionError):
                self.validate_pair(*self.pair(), environ)

    def test_v2_no_expected_source_commit_reports_none(self):
        report = self.validate_pair(*self.pair(), {})
        self.assertIsNone(report["expected_source_commit"])
        self.assertIsNone(report["expected_source_commit_source"])

    def test_v2_expected_commit_anchors_application_too(self):
        helper, app = self.pair()
        app["workspace_commit"] = "f" * 40
        with self.assertRaises(AssertionError):
            self.validate_pair(
                helper, app,
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": self.commit})

    def test_v1_ignores_expected_source_commit_environment(self):
        report = self.validate_pair(
            *self.pair(v1=True),
            {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "0" * 40,
             "GITHUB_SHA": "0" * 40})
        self.assertNotIn("expected_source_commit", report)
        self.assertNotIn("expected_source_commit_source", report)
        self.assertEqual(report["package_rebuilt"], True)


class Snapshot140ReceiptDispatchTest(ExpectedSourceCommitCases, RefStoreReceiptFixture):
    def pair(self, *, v1=False):
        if v1:
            return self.v1_helper_receipt(), self.v1_app_receipt()
        return self.helper_receipt(), self.app_receipt()

    def validate_pair(self, helper_payload, app_payload, environ):
        return self.validate_snapshot(helper_payload, app_payload, environ=environ)

    def validate_manifest_pair(self, helper_payload, app_payload, manifest,
                               environ=None):
        return self.validate_snapshot(
            helper_payload, app_payload, manifest=manifest, environ=environ)

    def validate_cas_pair(self, helper_payload, app_payload, helper_record,
                          app_record, manifest):
        return self.validate_snapshot(
            helper_payload, app_payload, manifest=manifest,
            app_binary=Path(app_record["binary"]),
            finalize=lambda helper_receipt, app_receipt: self.finalize_cas(
                helper_record, app_record, helper_receipt, app_receipt))

    def test_v1_pair_preserves_legacy_report_fields(self):
        report = self.validate_snapshot(
            self.v1_helper_receipt(), self.v1_app_receipt())
        self.assertEqual(report["package_rebuilt"], True)
        self.assertIs(report["fresh"], False)
        self.assertEqual(report["fresh_false_artifact"],
                         {"target": SNAPSHOT_TARGET, "kind": "test", "fresh": False})
        self.assertEqual(report["build_kind"], "rust-integration-test")
        self.assertNotIn("receipt_schema", report)
        self.assertNotIn("cargo_artifacts", report)
        self.assertEqual(report["source_inputs_sha256"],
                         self.bound["source_inputs_sha256"])

    def test_v1_flexible_binary_field_names_still_work(self):
        report = self.validate_snapshot(
            self.v1_helper_receipt(binary_field="artifact_sha256"),
            self.v1_app_receipt(binary_field="sha256"))
        self.assertEqual(report["binary_sha256"], digest(self.snapshot_output))
        self.assertEqual(report["candidate_application_sha256"], digest(self.app_binary))

    def test_v1_still_requires_package_rebuilt_and_false_freshness(self):
        with self.assertRaises(AssertionError):
            self.validate_snapshot(
                self.v1_helper_receipt(package_rebuilt=False),
                self.v1_app_receipt())
        with self.assertRaises(AssertionError):
            self.validate_snapshot(
                self.v1_helper_receipt(fresh=True),
                self.v1_app_receipt())
        with self.assertRaises(AssertionError):
            self.validate_snapshot(
                self.v1_helper_receipt(),
                self.v1_app_receipt(fresh_rows=True))

    def test_v2_pair_accepts_literal_true_false_and_mixed_freshness(self):
        cases = [
            (True, True, False),
            (False, False, True),
            (True, False, True),
            (False, True, False),
        ]
        for helper_fresh, lib_fresh, bin_fresh in cases:
            with self.subTest(helper_fresh=helper_fresh,
                              lib_fresh=lib_fresh, bin_fresh=bin_fresh):
                report = self.validate_snapshot(
                    self.helper_receipt(fresh=helper_fresh),
                    self.app_receipt(lib_fresh=lib_fresh, bin_fresh=bin_fresh))
                self.assertEqual(report["receipt_schema"], binding.RECEIPT_SCHEMA_V2)
                self.assertIs(report["fresh"], helper_fresh)
                self.assertEqual(report["cargo_artifacts"][0]["fresh"], helper_fresh)
                self.assertEqual(report["candidate_application_fresh"],
                                 {"lib": lib_fresh, "bin": bin_fresh})
                self.assertNotIn("package_rebuilt", report)
                self.assertNotIn("fresh_false_artifact", report)
                self.assertNotIn("candidate_application_package_rebuilt", report)
                self.assertEqual(report["source_inputs_sha256"],
                                 self.bound["source_inputs_sha256"])
                self.assertEqual(report["build_receipt_sha256"],
                                 digest(report["build_receipt"]))

    def test_v2_default_receipt_discovery_and_exact_selected_rows(self):
        report = self.validate_snapshot(
            self.helper_receipt(), self.app_receipt(), default_paths=True)
        self.assertEqual(report["cargo_artifacts"][0]["target"], SNAPSHOT_TARGET)
        self.assertEqual(report["cargo_artifacts"][0]["kind"], "test")
        self.assertEqual(report["candidate_application_cargo_artifacts"][0]["kind"], "lib")
        self.assertEqual(report["candidate_application_cargo_artifacts"][0]["source"],
                         binding.APP_LIB_SOURCE)
        self.assertEqual(report["candidate_application_cargo_artifacts"][1]["kind"], "bin")
        self.assertEqual(report["candidate_application_cargo_artifacts"][1]["source"],
                         binding.APP_BIN_SOURCE)
        self.assertTrue(report["same_batch_manifest"])

    def test_v2_legit_cli_dev_receipt_is_accepted(self):
        report = self.validate_snapshot(
            self.helper_receipt(),
            self.app_cli_receipt())
        self.assertEqual(report["candidate_application_kind"], binding.APP_CLI_KIND)
        self.assertEqual(report["candidate_application_profile"], "dev")
        self.assertFalse(report["same_batch_manifest"])
        self.assertTrue(report["shared_config_and_toolchain_closure"])

    def test_v2_non_relocated_batch_application_is_accepted(self):
        report = self.validate_snapshot(
            self.helper_receipt(),
            self.app_receipt(relocated=False))
        self.assertFalse(report["candidate_application_cargo_artifacts"][1]
                         .get("relocated_artifact", False))
        self.assertTrue(report["shared_config_and_toolchain_closure"])

    def assert_snapshot_rejects(self, helper_payload, app_payload):
        with self.assertRaises(AssertionError):
            self.validate_snapshot(helper_payload, app_payload)

    def test_v2_rejects_unknown_schema_and_mixed_schema_pairs(self):
        helper = self.helper_receipt()
        app = self.app_receipt()
        unknown = copy.deepcopy(app)
        unknown["receipt_schema"] = "rootyard/native-build-receipt/v3"
        self.assert_snapshot_rejects(helper, unknown)
        self.assert_snapshot_rejects(helper, self.v1_app_receipt())
        self.assert_snapshot_rejects(self.v1_helper_receipt(), app)

    def test_v2_rejects_wrong_helper_target_source_kind_and_tampered_fields(self):
        self.assert_snapshot_rejects(
            self.helper_receipt(target="ref_store_other_fixture",
                                source=SNAPSHOT_SOURCE,
                                output=self.snapshot_output,
                                original=self.snapshot_original),
            self.app_receipt())
        self.assert_snapshot_rejects(
            self.helper_receipt(source="tests/ref_store_other_fixture.rs"),
            self.app_receipt())
        self.assert_snapshot_rejects(
            self.helper_receipt(kind="native-build-batch-bin"),
            self.app_receipt())
        tampered_source = self.helper_receipt()
        tampered_source["integration_test_source_sha256"] = "0" * 64
        self.assert_snapshot_rejects(tampered_source, self.app_receipt())
        tampered_fresh = self.helper_receipt()
        tampered_fresh["cargo_artifacts"][0]["fresh"] = "false"
        self.assert_snapshot_rejects(tampered_fresh, self.app_receipt())

    def test_v2_rejects_wrong_application_target_source_and_digest(self):
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(bin_target="rootyard-pando-lab"))
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(bin_source="src/bin/rootyard-pando-lab.rs"))
        # Any executable row matching the relocated digest is not enough: the
        # exact rootyard bin row must carry the selected bytes.
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(
                bin_executable=self.other_bin,
                original_sha256=digest(self.app_binary),
                extra_bins=[{
                    "target": "rootyard-extra",
                    "source": "src/bin/rootyard-pando-lab.rs",
                    "executable": self.app_binary,
                }]))
        tampered_binary = self.app_receipt()
        tampered_binary["binary_sha256"] = "0" * 64
        self.assert_snapshot_rejects(self.helper_receipt(), tampered_binary)

    def test_v2_rejects_implicit_receipts_and_stale_batches(self):
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(implicit=True))
        self.assert_snapshot_rejects(
            self.helper_receipt(manifest=self.root / "stale-a/manifest.json"),
            self.app_receipt(manifest=self.root / "stale-b/manifest.json"))

    def test_v2_rejects_config_mismatch(self):
        self.write(".cargo/config.toml", "[build]\njobs = 8\n")
        different = self.capture()
        self.assertNotEqual(different["config_digest"], self.bound["config_digest"])
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(bound=different))

    def test_v2_rejects_toolchain_mismatch(self):
        toolchain = copy.deepcopy(self.toolchain())
        toolchain["rustc"]["commit_hash"] = "e" * 40
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(toolchain=toolchain))

    def test_v2_rejects_different_source_or_cargo_lock(self):
        self.write("src/lib.rs", "pub fn production() -> u8 { 2 }\n")
        changed_source = self.capture()
        self.assertNotEqual(changed_source["source_inputs_sha256"],
                            self.bound["source_inputs_sha256"])
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(bound=changed_source))

    def test_v2_rejects_different_cargo_lock(self):
        self.write("Cargo.lock", "version = 4\n")
        changed_lock = self.capture()
        self.assertNotEqual(changed_lock["cargo_lock_sha256"],
                            self.bound["cargo_lock_sha256"])
        self.assert_snapshot_rejects(
            self.helper_receipt(),
            self.app_receipt(bound=changed_lock))

    def test_v2_rejects_wrong_features_and_selection_flags(self):
        app = self.app_receipt()
        app["features"]["enabled"] = ["other"]
        self.assert_snapshot_rejects(self.helper_receipt(), app)
        app = self.app_receipt()
        app["selection"]["strip_debuginfo"] = False
        self.assert_snapshot_rejects(self.helper_receipt(), app)
        app = self.app_receipt()
        app["selection"]["features"] = "other"
        self.assert_snapshot_rejects(self.helper_receipt(), app)
        helper = self.helper_receipt()
        helper["features"]["enabled"] = ["other"]
        self.assert_snapshot_rejects(helper, self.app_receipt())

    def test_v2_validation_never_starts_a_subprocess(self):
        source = Path(binding.__file__).read_text()
        for forbidden in ("subprocess.", "probe_toolchain", "build_native",
                          "make_receipt_v2("):
            self.assertNotIn(forbidden, source)
        with mock.patch("subprocess.run", side_effect=AssertionError("subprocess")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                mock.patch("os.system", side_effect=AssertionError("subprocess")):
            report = self.validate_snapshot(
                self.helper_receipt(), self.app_receipt())
        self.assertEqual(report["receipt_schema"], binding.RECEIPT_SCHEMA_V2)


class Holds141ReceiptDispatchTest(ExpectedSourceCommitCases, RefStoreReceiptFixture):
    def pair(self, *, v1=False):
        if v1:
            return (self.v1_helper_receipt(target=HOLDS_TARGET),
                    self.v1_app_receipt())
        return self.helper_receipt(target=HOLDS_TARGET), self.app_receipt()

    def validate_pair(self, helper_payload, app_payload, environ):
        return self.validate_holds(helper_payload, app_payload, environ=environ)

    def validate_manifest_pair(self, helper_payload, app_payload, manifest,
                               environ=None):
        return self.validate_holds(
            helper_payload, app_payload, manifest=manifest, environ=environ)

    def validate_cas_pair(self, helper_payload, app_payload, helper_record,
                          app_record, manifest):
        return self.validate_holds(
            helper_payload, app_payload, manifest=manifest,
            app_binary=Path(app_record["binary"]),
            finalize=lambda helper_receipt, app_receipt: self.finalize_cas(
                helper_record, app_record, helper_receipt, app_receipt))

    def assert_holds_rejects(self, helper_payload, app_payload):
        with self.assertRaises(AssertionError):
            self.validate_holds(helper_payload, app_payload)

    def test_v1_pair_preserves_legacy_report_fields(self):
        report = self.validate_holds(
            self.v1_helper_receipt(target=HOLDS_TARGET), self.v1_app_receipt())
        self.assertEqual(report["package_rebuilt"], True)
        self.assertIs(report["fresh"], False)
        self.assertEqual(report["fresh_false_artifact"],
                         {"target": HOLDS_TARGET, "kind": "test", "fresh": False})
        self.assertEqual(report["build_kind"], "rust-integration-test")
        self.assertNotIn("receipt_schema", report)
        self.assertNotIn("cargo_artifacts", report)
        self.assertEqual(report["source_inputs_sha256"],
                         self.bound["source_inputs_sha256"])

    def test_v1_missing_package_rebuilt_or_false_freshness_still_fails(self):
        with self.assertRaises(AssertionError):
            self.validate_holds(
                self.v1_helper_receipt(target=HOLDS_TARGET, package_rebuilt=False),
                self.v1_app_receipt())
        with self.assertRaises(AssertionError):
            self.validate_holds(
                self.v1_helper_receipt(target=HOLDS_TARGET, fresh=True),
                self.v1_app_receipt())

    def test_v2_pair_accepts_literal_true_false_and_mixed_freshness(self):
        cases = [
            (True, True, False),
            (False, False, True),
            (True, False, True),
            (False, True, False),
        ]
        for helper_fresh, lib_fresh, bin_fresh in cases:
            with self.subTest(helper_fresh=helper_fresh,
                              lib_fresh=lib_fresh, bin_fresh=bin_fresh):
                report = self.validate_holds(
                    self.helper_receipt(target=HOLDS_TARGET, fresh=helper_fresh),
                    self.app_receipt(lib_fresh=lib_fresh, bin_fresh=bin_fresh))
                self.assertEqual(report["receipt_schema"], binding.RECEIPT_SCHEMA_V2)
                self.assertIs(report["fresh"], helper_fresh)
                self.assertEqual(report["cargo_artifacts"][0]["fresh"], helper_fresh)
                self.assertEqual(report["candidate_application_fresh"],
                                 {"lib": lib_fresh, "bin": bin_fresh})
                self.assertNotIn("package_rebuilt", report)
                self.assertNotIn("fresh_false_artifact", report)
                self.assertNotIn("candidate_application_package_rebuilt", report)

    def test_v2_default_receipt_discovery_and_exact_selected_rows(self):
        report = self.validate_holds(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(),
            default_paths=True)
        self.assertEqual(report["cargo_artifacts"][0]["target"], HOLDS_TARGET)
        self.assertEqual(report["cargo_artifacts"][0]["kind"], "test")
        self.assertEqual(report["candidate_application_cargo_artifacts"][0]["source"],
                         binding.APP_LIB_SOURCE)
        self.assertEqual(report["candidate_application_cargo_artifacts"][1]["source"],
                         binding.APP_BIN_SOURCE)
        self.assertTrue(report["same_batch_manifest"])

    def test_v2_legit_cli_dev_receipt_is_accepted(self):
        report = self.validate_holds(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_cli_receipt())
        self.assertEqual(report["candidate_application_kind"], binding.APP_CLI_KIND)
        self.assertEqual(report["candidate_application_profile"], "dev")
        self.assertFalse(report["same_batch_manifest"])

    def test_v2_rejects_wrong_helper_target_source_kind_and_tampered_fields(self):
        self.assert_holds_rejects(
            self.helper_receipt(target="ref_store_other_fixture",
                                source=HOLDS_SOURCE,
                                output=self.holds_output,
                                original=self.holds_original),
            self.app_receipt())
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET,
                                source="tests/ref_store_other_fixture.rs"),
            self.app_receipt())
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET,
                                kind="native-build-batch-bin"),
            self.app_receipt())
        tampered_source = self.helper_receipt(target=HOLDS_TARGET)
        tampered_source["integration_test_source_sha256"] = "0" * 64
        self.assert_holds_rejects(tampered_source, self.app_receipt())
        tampered_fresh = self.helper_receipt(target=HOLDS_TARGET)
        tampered_fresh["cargo_artifacts"][0]["fresh"] = "false"
        self.assert_holds_rejects(tampered_fresh, self.app_receipt())

    def test_v2_rejects_wrong_application_target_source_and_digest(self):
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(bin_target="rootyard-pando-lab"))
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(bin_source="src/bin/rootyard-pando-lab.rs"))
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(
                bin_executable=self.other_bin,
                original_sha256=digest(self.app_binary),
                extra_bins=[{
                    "target": "rootyard-extra",
                    "source": "src/bin/rootyard-pando-lab.rs",
                    "executable": self.app_binary,
                }]))
        tampered_binary = self.app_receipt()
        tampered_binary["binary_sha256"] = "0" * 64
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET), tampered_binary)

    def test_v2_rejects_unknown_mixed_implicit_and_stale_pairs(self):
        helper = self.helper_receipt(target=HOLDS_TARGET)
        app = self.app_receipt()
        unknown = copy.deepcopy(app)
        unknown["receipt_schema"] = "rootyard/native-build-receipt/v3"
        self.assert_holds_rejects(helper, unknown)
        self.assert_holds_rejects(helper, self.v1_app_receipt())
        self.assert_holds_rejects(
            self.v1_helper_receipt(target=HOLDS_TARGET), app)
        self.assert_holds_rejects(helper, self.app_receipt(implicit=True))
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET,
                                manifest=self.root / "stale-a/manifest.json"),
            self.app_receipt(manifest=self.root / "stale-b/manifest.json"))

    def test_v2_rejects_config_mismatch(self):
        self.write(".cargo/config.toml", "[build]\njobs = 8\n")
        different = self.capture()
        self.assertNotEqual(different["config_digest"], self.bound["config_digest"])
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(bound=different))

    def test_v2_rejects_toolchain_mismatch(self):
        toolchain = copy.deepcopy(self.toolchain())
        toolchain["rustc"]["commit_hash"] = "e" * 40
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET),
            self.app_receipt(toolchain=toolchain))

    def test_v2_rejects_wrong_features_and_selection_flags(self):
        app = self.app_receipt()
        app["features"]["enabled"] = ["other"]
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET), app)
        app = self.app_receipt()
        app["selection"]["strip_debuginfo"] = False
        self.assert_holds_rejects(
            self.helper_receipt(target=HOLDS_TARGET), app)
        helper = self.helper_receipt(target=HOLDS_TARGET)
        helper["selection"]["features"] = "other"
        self.assert_holds_rejects(helper, self.app_receipt())

    def test_v2_validation_never_starts_a_subprocess(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("subprocess")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                mock.patch("os.system", side_effect=AssertionError("subprocess")):
            report = self.validate_holds(
                self.helper_receipt(target=HOLDS_TARGET), self.app_receipt())
        self.assertEqual(report["receipt_schema"], binding.RECEIPT_SCHEMA_V2)

