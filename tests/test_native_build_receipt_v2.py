"""Offline contract tests for the shared native-build receipt API.

These tests never invoke Cargo, rustc, rustup or a builder.  They exercise the
version-dispatched reader, producer metadata helpers and strict freshness
handling against temporary workspaces and fake tool probes.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_native  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

CARGO_FORK_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
RUSTC_COMMIT = "d" * 40
TARGET_TRIPLE = "aarch64-unknown-linux-gnu"


class ReceiptFixture(unittest.TestCase):
    """A temporary source tree, executable fixtures and producer measurements."""

    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix="rootyard-native-receipt-v2-"))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.root = self.tempdir.resolve()
        self.write("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.0"\n')
        self.write("Cargo.lock", "version = 3\n")
        self.write("build.rs", "fn main() {}\n")
        self.write("src/lib.rs", "pub fn production() -> u8 { 1 }\n")
        self.write("src/main.rs", "fn main() {}\n")
        self.write("tests/example.rs", "#[test]\nfn example() {}\n")
        self.write("tests/fixtures/data.txt", "fixture-data\n")
        self.write("experimental/pando/schema.sql", "create table pando_session();\n")
        self.write(".cargo/config.toml", "[build]\njobs = 4\n")
        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n')
        self.binary = self.root / "target/debug/rootyard"
        self.write("target/debug/rootyard", b"native-binary")
        self.test_binary = self.root / "target/debug/deps/example-test"
        self.write("target/debug/deps/example-test", b"example-test-binary")
        self.lib_test_binary = self.root / "target/debug/deps/rootyard-lib-test"
        self.write("target/debug/deps/rootyard-lib-test", b"rootyard-lib-test-binary")
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

    def event(self, kind, fresh, *, source=None, executable=None, profile=None,
              package_id="rootyard 0.1.0"):
        if kind == "lib":
            target = {"name": "rootyard", "kind": ["lib"],
                      "src_path": str(source or self.root / "src/lib.rs")}
            profile = profile or self.profile
        elif kind == "lib-test":
            target = {"name": "rootyard", "kind": ["lib"],
                      "src_path": str(source or self.root / "src/lib.rs")}
            profile = profile or self.test_profile
            executable = executable or self.lib_test_binary
        elif kind == "bin":
            target = {"name": "rootyard", "kind": ["bin"],
                      "src_path": str(source or self.root / "src/main.rs")}
            profile = profile or self.profile
            executable = executable or self.binary
        elif kind == "test":
            target = {"name": "example", "kind": ["test"],
                      "src_path": str(source or self.root / "tests/example.rs")}
            profile = profile or self.test_profile
            executable = executable or self.test_binary
        else:
            raise AssertionError(kind)
        event = {
            "reason": "compiler-artifact",
            "package_id": package_id,
            "target": target,
            "profile": profile,
            "fresh": fresh,
        }
        if executable is not None:
            event["executable"] = str(executable)
        return event

    def artifacts(self, *, lib_fresh=False, bin_fresh=True):
        return [
            receipts.cargo_artifact_record(self.event("lib", lib_fresh), self.root),
            receipts.cargo_artifact_record(self.event("bin", bin_fresh), self.root),
        ]

    def make_v2(self, **overrides):
        arguments = {
            "binary_path": self.binary,
            "command": ["cargo", "build", "--locked", "--bin", "rootyard"],
            "profile": "dev",
            "artifacts": self.artifacts(),
            "toolchain": self.toolchain(),
            "bound_inputs": self.bound,
            "workspace_commit": "a" * 40,
            "target_dir": self.root / "target",
            "target_triple": TARGET_TRIPLE,
            "features": "pando-lab",
        }
        arguments.update(overrides)
        return receipts.make_receipt_v2(**arguments)

    def v1_receipt(self, *, fresh_lib=False, fresh_bin=False):
        return {
            "version": 1,
            "binary_sha256": receipts.sha256_file(self.binary),
            "source_inputs_sha256": self.bound["source_inputs_sha256"],
            "workspace_commit": "a" * 40,
            "rustc": "rustc 1.99.1 (fake 2025-01-01)",
            "command": ["cargo", "build", "--locked", "--bin", "rootyard"],
            "package_rebuilt": True,
            "clean_command": ["cargo", "clean", "--package", "rootyard"],
            "fresh": False,
            "target_dir": str(self.root / "target"),
            "fresh_false_artifacts": [
                {"target": "rootyard", "kind": "lib", "fresh": fresh_lib,
                 "package_id": "rootyard 0.1.0"},
                {"target": "rootyard", "kind": "bin", "fresh": fresh_bin,
                 "package_id": "rootyard 0.1.0", "executable": str(self.binary)},
            ],
        }

    def validate(self, payload, **overrides):
        arguments = {"source_root": self.root, "binary_path": self.binary}
        arguments.update(overrides)
        return receipts.validate_receipt(payload, **arguments)

    def assert_rejected(self, payload, message=None, **overrides):
        with self.assertRaises(receipts.ReceiptError) as caught:
            self.validate(payload, **overrides)
        if message is not None:
            self.assertIn(message, str(caught.exception))
        return caught.exception


class V1CompatibilityTest(ReceiptFixture):
    def test_historical_v1_receipt_is_readable_and_not_rewritten(self):
        receipt_path = self.binary.with_suffix(".build.json")
        payload = self.v1_receipt()
        receipt_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        before = receipt_path.read_bytes()

        validated = receipts.load_receipt(receipt_path, source_root=self.root)

        self.assertEqual(validated.schema, "v1")
        self.assertEqual(validated.binary_path, self.binary.resolve())
        self.assertEqual(validated.workspace_commit, "a" * 40)
        self.assertEqual(validated.receipt_sha256, hashlib.sha256(before).hexdigest())
        self.assertEqual(receipt_path.read_bytes(), before)
        self.assertEqual([row["fresh"] for row in validated.artifacts], [False, False])

    def test_minimal_v1_without_freshness_is_not_given_invented_freshness(self):
        payload = {
            "binary_sha256": receipts.sha256_file(self.binary),
            "source_inputs_sha256": self.bound["source_inputs_sha256"],
            "workspace_commit": "a" * 40,
            "rustc": "rustc 1.99.1",
            "command": ["cargo", "build", "--locked"],
        }
        validated = self.validate(payload)
        self.assertEqual(validated.schema, "v1")
        self.assertEqual(validated.artifacts, ())

    def test_invalid_historical_freshness_is_rejected(self):
        payload = self.v1_receipt()
        tampered = copy.deepcopy(payload)
        tampered["fresh_false_artifacts"][0]["fresh"] = True
        self.assert_rejected(tampered, "must be exactly false")

        missing = copy.deepcopy(payload)
        del missing["fresh_false_artifacts"][1]["fresh"]
        self.assert_rejected(missing, "must be exactly false")

        top_level = copy.deepcopy(payload)
        top_level["fresh"] = True
        self.assert_rejected(top_level, "legacy top-level fresh")

        rebuilt = copy.deepcopy(payload)
        rebuilt["package_rebuilt"] = False
        self.assert_rejected(rebuilt, "package_rebuilt")

        versioned = copy.deepcopy(payload)
        versioned["version"] = 2
        self.assert_rejected(versioned, "legacy version")

    def test_v1_source_commit_and_binary_bindings_are_checked(self):
        payload = self.v1_receipt()
        self.assert_rejected(payload, "expected_commit", expected_commit="b" * 40)
        self.assert_rejected(payload, "expected_source_digest", expected_source_digest="0" * 64)

        self.binary.write_bytes(b"different-binary")
        self.assert_rejected(payload, "binary digest")

    def test_v1_source_change_is_rejected(self):
        payload = self.v1_receipt()
        self.write("src/lib.rs", "pub fn production() -> u8 { 2 }\n")
        self.assert_rejected(payload, "source_inputs_sha256 differs")


class V2FreshnessTest(ReceiptFixture):
    def test_true_false_and_mixed_freshness_are_valid(self):
        for lib_fresh, bin_fresh in ((False, False), (True, True), (False, True), (True, False)):
            with self.subTest(lib=lib_fresh, bin=bin_fresh):
                payload = self.make_v2(artifacts=self.artifacts(lib_fresh=lib_fresh, bin_fresh=bin_fresh))
                validated = self.validate(payload)
                self.assertEqual(validated.schema, "v2")
                self.assertEqual(
                    [row["fresh"] for row in validated.artifacts],
                    [lib_fresh, bin_fresh],
                )
                for banned in receipts.V2_BANNED_FIELDS:
                    self.assertNotIn(banned, payload)
                self.assertNotIn("fresh_false_artifacts", json.dumps(payload))

    def test_missing_or_non_boolean_freshness_is_rejected(self):
        payload = self.make_v2()
        for value in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(value=value):
                tampered = copy.deepcopy(payload)
                tampered["cargo_artifacts"][1]["fresh"] = value
                self.assert_rejected(tampered, "fresh must be a JSON boolean")
        missing = copy.deepcopy(payload)
        del missing["cargo_artifacts"][1]["fresh"]
        self.assert_rejected(missing, "fresh must be a JSON boolean")

    def test_v2_legacy_aliases_are_rejected(self):
        payload = self.make_v2()
        for field, value in (
            ("package_rebuilt", True),
            ("clean_command", ["cargo", "clean"]),
            ("clean_commands", 1),
            ("clean", {"commands": 1}),
            ("fresh_false_artifacts", []),
            ("fresh", False),
        ):
            with self.subTest(field=field):
                tampered = copy.deepcopy(payload)
                tampered[field] = value
                self.assert_rejected(tampered, f"legacy field {field}")

    def test_v2_version_field_must_be_two(self):
        payload = self.make_v2()
        tampered = copy.deepcopy(payload)
        tampered["version"] = 1
        self.assert_rejected(tampered, "version must be 2")

    def test_unknown_schema_is_rejected(self):
        payload = self.make_v2()
        for value in (
            "rootyard/native-build-receipt/v3",
            "rootyard/native-build-receipt/v1",
            None,
            "",
        ):
            with self.subTest(value=value):
                tampered = copy.deepcopy(payload)
                tampered["receipt_schema"] = value
                self.assert_rejected(tampered, "unknown receipt_schema")


class V2BindingTest(ReceiptFixture):
    def test_wrong_selected_target_kind_or_count_is_rejected(self):
        payload = self.make_v2()
        expected = [
            {"target": "rootyard", "kind": "lib"},
            {"target": "rootyard", "kind": "bin"},
        ]
        self.validate(payload, expected_artifacts=expected)

        wrong_target = copy.deepcopy(expected)
        wrong_target[1]["target"] = "rootyard-view-lab"
        self.assert_rejected(payload, "was not selected", expected_artifacts=wrong_target)

        wrong_kind = copy.deepcopy(expected)
        wrong_kind[0]["kind"] = "test"
        self.assert_rejected(payload, "was not selected", expected_artifacts=wrong_kind)

        self.assert_rejected(payload, "selected artifacts",
                             expected_artifacts=expected[:1])

        tampered = copy.deepcopy(payload)
        tampered["cargo_artifacts"][1]["kind"] = "bench"
        self.assert_rejected(tampered, "kind is invalid")

        duplicate = copy.deepcopy(payload)
        duplicate["cargo_artifacts"][1]["target"] = "rootyard"
        duplicate["cargo_artifacts"][1]["kind"] = "lib"
        del duplicate["cargo_artifacts"][1]["executable"]
        del duplicate["cargo_artifacts"][1]["executable_sha256"]
        self.assert_rejected(duplicate, "duplicate")

    def test_binary_content_and_binary_anchor_are_checked(self):
        payload = self.make_v2()
        self.validate(payload, expected_binary_sha256=payload["binary_sha256"])
        self.assert_rejected(payload, "expected_binary_sha256",
                             expected_binary_sha256="0" * 64)
        self.binary.write_bytes(b"tampered-binary")
        self.assert_rejected(payload, "binary digest")

    def test_source_test_config_lock_and_manifest_changes_are_rejected(self):
        payload = self.make_v2()
        cases = (
            ("src/lib.rs", "pub fn production() -> u8 { 2 }\n"),
            ("src/main.rs", "fn main() { println!(\"changed\"); }\n"),
            ("tests/example.rs", "#[test]\nfn example() { assert!(true); }\n"),
            (".cargo/config.toml", "[build]\njobs = 8\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.98.0"\n'),
            ("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.1"\n'),
            ("Cargo.lock", "version = 4\n"),
            ("experimental/pando/schema.sql", "create table pando_session_v2();\n"),
        )
        for relative, replacement in cases:
            with self.subTest(relative=relative):
                original = (self.root / relative).read_bytes()
                try:
                    self.write(relative, replacement)
                    self.assert_rejected(payload)
                finally:
                    (self.root / relative).write_bytes(original)
        self.validate(payload)

    def test_expected_source_config_profile_commit_and_toolchain_anchors(self):
        payload = self.make_v2()
        self.assert_rejected(payload, "expected_source_digest",
                             expected_source_digest="0" * 64)
        self.assert_rejected(payload, "expected_config_digest",
                             expected_config_digest="0" * 64)
        self.assert_rejected(payload, "expected_commit", expected_commit="b" * 40)
        self.assert_rejected(payload, "expected_profile", expected_profile="test")
        self.assert_rejected(payload, "expected_command",
                             expected_command=["cargo", "build", "--bins"])
        self.assert_rejected(
            payload,
            "toolchain.cargo.commit_hash",
            expected_toolchain={"cargo": {"commit_hash": "e" * 40}},
        )

    def test_toolchain_shape_and_full_commit_binding(self):
        payload = self.make_v2()
        cases = (
            (("cargo", "commit_hash"), "64a6", "full 40- or 64-hex"),
            (("rustc", "commit_hash"), None, "full 40- or 64-hex"),
            (("cargo", "executable"), "relative/cargo", "absolute path"),
            (("cargo", "executable_sha256"), "A" * 64, "lowercase 64-hex"),
            (("cargo", "release"), "", "nonempty string"),
        )
        for (name, field), value, message in cases:
            with self.subTest(name=name, field=field):
                tampered = copy.deepcopy(payload)
                if value is None:
                    del tampered["toolchain"][name][field]
                else:
                    tampered["toolchain"][name][field] = value
                self.assert_rejected(tampered, message)

        triple = copy.deepcopy(payload)
        triple["target_triple"] = "x86_64-unknown-linux-gnu"
        self.assert_rejected(triple, "target_triple does not match")

        proxy = copy.deepcopy(payload)
        proxy["toolchain"]["rustc"]["proxy"] = "yes"
        self.assert_rejected(proxy, "toolchain.rustc.proxy")

        path_entry = copy.deepcopy(payload)
        path_entry["toolchain"]["rustc"]["path_entry"] = "relative/rustc"
        self.assert_rejected(path_entry, "absolute path")

        rustup = copy.deepcopy(payload)
        del rustup["toolchain"]["rustup"]["resolved_rustc_sha256"]
        self.assert_rejected(rustup, "resolved_rustc_sha256")

    def test_artifact_shape_source_profile_and_executable_bindings(self):
        payload = self.make_v2()
        cases = (
            (("package_id",), None, "package_id"),
            (("source",), "../outside.rs", "traverse"),
            (("source",), str(self.root / "src/lib.rs"), "repository-relative"),
            (("executable",), "target/debug/rootyard", "absolute path"),
            (("profile", "debug_assertions"), 1, "profile.debug_assertions"),
            (("profile", "opt_level"), None, "profile.opt_level"),
            (("source_sha256",), "0" * 64, "artifact source"),
        )
        for keys, value, message in cases:
            with self.subTest(keys=keys):
                tampered = copy.deepcopy(payload)
                row = tampered["cargo_artifacts"][1]
                target = row
                for key in keys[:-1]:
                    target = target[key]
                if value is None:
                    del target[keys[-1]]
                else:
                    target[keys[-1]] = value
                self.assert_rejected(tampered, message)

        lib_with_executable = copy.deepcopy(payload)
        lib_with_executable["cargo_artifacts"][0]["executable"] = str(self.test_binary)
        self.assert_rejected(lib_with_executable, "must not claim an executable")

        source_sha = copy.deepcopy(payload)
        source_sha["cargo_artifacts"][0]["source_sha256"] = "0" * 64
        self.assert_rejected(source_sha, "artifact source")

    def test_artifact_source_must_match_the_bound_inventory_without_a_source_root(self):
        payload = self.make_v2()

        unbound = copy.deepcopy(payload)
        unbound["cargo_artifacts"][1]["source"] = "not/bound.rs"
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.validate_receipt(unbound)
        self.assertIn("not present in bound_input_inventory", str(caught.exception))

        wrong_hash = copy.deepcopy(payload)
        wrong_hash["cargo_artifacts"][1]["source_sha256"] = "0" * 64
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.validate_receipt(wrong_hash)
        self.assertIn("hash does not match bound_input_inventory", str(caught.exception))

        self.validate(payload)

    def test_missing_required_compiled_asset_is_rejected_with_recomputed_summary(self):
        payload = self.make_v2()
        tampered = copy.deepcopy(payload)
        tampered["bound_input_inventory"] = [
            entry for entry in tampered["bound_input_inventory"]
            if entry["path"] != "experimental/pando/schema.sql"
        ]
        entries = tampered["bound_input_inventory"]
        present = [entry for entry in entries if entry["present"]]
        by_role = {role: 0 for role in receipts.BOUND_ROLES}
        for entry in present:
            by_role[entry["role"]] += 1
        tampered["bound_inputs"].update(
            {
                "digest": receipts.bound_inputs_digest_from_entries(entries),
                "present_count": len(present),
                "absent_count": len(entries) - len(present),
                "absent": [entry["path"] for entry in entries if not entry["present"]],
                "by_role": by_role,
            }
        )
        self.assert_rejected(tampered, "missing required compiled asset")

    def test_inventory_and_summary_tampering_is_rejected(self):
        payload = self.make_v2()
        digest = copy.deepcopy(payload)
        digest["bound_inputs"]["digest"] = "0" * 64
        self.assert_rejected(digest, "does not match bound_input_inventory")

        config = copy.deepcopy(payload)
        config["config_digest"] = "0" * 64
        self.assert_rejected(config, "config_digest does not match")

        absent = copy.deepcopy(payload)
        absent["bound_inputs"]["absent"] = []
        self.assert_rejected(absent, "absent does not match")

        role = copy.deepcopy(payload)
        role["bound_inputs"]["by_role"]["production_source"] += 1
        self.assert_rejected(role, "does not match inventory")

        missing_fixed = copy.deepcopy(payload)
        missing_fixed["bound_input_inventory"] = [
            entry for entry in missing_fixed["bound_input_inventory"] if entry["path"] != "build.rs"
        ]
        self.assert_rejected(missing_fixed, "missing fixed candidate build.rs")

        duplicate = copy.deepcopy(payload)
        duplicate["bound_input_inventory"].append(copy.deepcopy(duplicate["bound_input_inventory"][0]))
        self.assert_rejected(duplicate, "duplicate bound input")

        present_without_hash = copy.deepcopy(payload)
        present_entry = next(
            entry for entry in present_without_hash["bound_input_inventory"] if entry["present"]
        )
        present_entry["sha256"] = None
        self.assert_rejected(present_without_hash, "sha256")

        production_digest = copy.deepcopy(payload)
        production_entry = next(
            entry for entry in production_digest["bound_input_inventory"]
            if entry["path"] == "src/lib.rs"
        )
        production_entry["sha256"] = "0" * 64
        production_digest["bound_inputs"]["digest"] = receipts.bound_inputs_digest_from_entries(
            production_digest["bound_input_inventory"]
        )
        self.assert_rejected(production_digest, "production entries")

    def test_batch_link_is_validated_and_anchored(self):
        payload = self.make_v2()
        manifest = self.root / "test-results/native-build-batch.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("{}\n", encoding="utf-8")
        payload["batch"] = {
            "kind": receipts.BATCH_KIND,
            "receipt_version": 1,
            "binary": self.binary.name,
            "targets": ["rootyard", "rootyard"],
            "bound_inputs_sha256": payload["bound_inputs"]["digest"],
            "manifest": str(manifest.resolve()),
        }
        self.validate(payload, expected_batch_manifest=manifest)

        wrong_manifest = self.root / "test-results/other.json"
        self.assert_rejected(payload, "expected_batch_manifest",
                             expected_batch_manifest=wrong_manifest)

        wrong_digest = copy.deepcopy(payload)
        wrong_digest["batch"]["bound_inputs_sha256"] = "0" * 64
        self.assert_rejected(wrong_digest, "batch.bound_inputs_sha256")

        wrong_kind = copy.deepcopy(payload)
        wrong_kind["batch"]["kind"] = "rootyard/other-batch"
        self.assert_rejected(wrong_kind, "batch.kind")

        wrong_binary = copy.deepcopy(payload)
        wrong_binary["batch"]["binary"] = "other-binary"
        self.assert_rejected(wrong_binary, "batch.binary")

        relative_manifest = copy.deepcopy(payload)
        relative_manifest["batch"]["manifest"] = "relative.json"
        self.assert_rejected(relative_manifest, "batch.manifest")

        implicit = copy.deepcopy(payload)
        implicit["implicit_build"] = {"requested_by": "--test"}
        self.assert_rejected(implicit, "implicit-build",
                             forbid_implicit_build=True)

    def test_metadata_only_validation_needs_no_compiler_or_binary(self):
        payload = self.make_v2()
        self.binary.unlink()
        validated = receipts.validate_receipt(payload)
        self.assertEqual(validated.schema, "v2")
        self.assertIsNone(validated.binary_path)

    def test_validation_never_invokes_subprocesses(self):
        payload = self.make_v2()
        with mock.patch.object(receipts.subprocess, "run", side_effect=AssertionError("run")), \
                mock.patch.object(receipts.subprocess, "Popen", side_effect=AssertionError("Popen")), \
                mock.patch.object(receipts.subprocess, "check_output",
                                  side_effect=AssertionError("check_output")), \
                mock.patch.object(receipts.shutil, "which", side_effect=AssertionError("which")):
            self.validate(payload)
            self.validate(self.v1_receipt())


class BuildEnvironmentTest(ReceiptFixture):
    def test_jobs_are_extracted_to_explicit_argv_and_options(self):
        source = {
            "PATH": "",
            "CARGO_BUILD_JOBS": "2",
            "CARGO_TARGET_DIR": "/shared/target",
        }
        normalized = receipts.normalize_build_environment(source)

        self.assertEqual(normalized["jobs"], 2)
        self.assertEqual(normalized["cargo_args"], ["--jobs", "2"])
        self.assertEqual(normalized["build_options"], {"jobs": 2})
        self.assertEqual(
            normalized["environment"],
            {"PATH": "", "CARGO_TARGET_DIR": "/shared/target"},
        )
        self.assertNotIn("CARGO_BUILD_JOBS", normalized["environment"])
        self.assertEqual(source["CARGO_BUILD_JOBS"], "2")

        captured = receipts.capture_bound_inputs(
            self.root, environ=normalized["environment"]
        )
        self.assertEqual(captured["bound_inputs"], self.bound["bound_inputs"])
        self.assertEqual(captured["source_inputs_sha256"],
                         self.bound["source_inputs_sha256"])

    def test_absent_jobs_adds_no_explicit_arguments(self):
        normalized = receipts.normalize_build_environment({"PATH": ""})
        self.assertIsNone(normalized["jobs"])
        self.assertEqual(normalized["cargo_args"], [])
        self.assertEqual(normalized["build_options"], {"jobs": None})

    def test_invalid_jobs_fail_closed_without_echoing_the_value(self):
        sentinel = "SENTINEL-JOBS-BUDGET"
        for value in ("", "0", "-1", "+2", "2.0", "two", sentinel, "  ", True, 0, -2):
            with self.subTest(value=value):
                with self.assertRaises(receipts.ReceiptError) as caught:
                    receipts.normalize_build_environment({"CARGO_BUILD_JOBS": value})
                message = str(caught.exception)
                self.assertIn("CARGO_BUILD_JOBS", message)
                self.assertIn("positive decimal integer", message)
                if isinstance(value, str) and value:
                    self.assertNotIn(value, message)

    def test_normalization_keeps_compiler_and_profile_guards(self):
        sentinel = "SENTINEL-GUARD-VALUE"
        for name in (
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_BUILD_TARGET",
            "RUSTC_WRAPPER",
        ):
            with self.subTest(name=name):
                with self.assertRaises(receipts.ReceiptError) as caught:
                    receipts.normalize_build_environment(
                        {"CARGO_BUILD_JOBS": "2", name: sentinel}
                    )
                message = str(caught.exception)
                self.assertIn(name, message)
                self.assertNotIn(sentinel, message)

    def test_raw_jobs_environment_still_requires_normalization(self):
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.capture_bound_inputs(
                self.root,
                environ={"PATH": "", "CARGO_BUILD_JOBS": "2"},
            )
        self.assertIn("CARGO_BUILD_JOBS", str(caught.exception))


class ProducerHelperTest(ReceiptFixture):
    def test_source_digest_is_the_exact_existing_algorithm(self):
        with mock.patch.object(build_native, "ROOT", self.root):
            self.assertEqual(receipts.source_digest(self.root), build_native.source_digest())
        self.assertEqual(
            receipts.source_digest_from_entries(self.bound["bound_input_inventory"]),
            receipts.source_digest(self.root),
        )

    def test_inventory_has_roles_and_never_records_contents(self):
        entries, blobs = receipts.bound_input_inventory(self.root)
        self.assertEqual([entry["path"] for entry in entries], sorted(entry["path"] for entry in entries))
        by_path = {entry["path"]: entry for entry in entries}
        self.assertEqual(by_path["Cargo.toml"]["role"], "manifest")
        self.assertEqual(by_path["Cargo.lock"]["role"], "lockfile")
        self.assertEqual(by_path["build.rs"]["role"], "build_script")
        self.assertEqual(by_path["src/lib.rs"]["role"], "production_source")
        self.assertEqual(by_path["tests/example.rs"]["role"], "integration_test_source")
        self.assertEqual(by_path["tests/fixtures/data.txt"]["role"], "test_support")
        self.assertEqual(by_path["experimental/pando/schema.sql"]["role"], "compiled_asset")
        self.assertEqual(by_path[".cargo/config.toml"]["role"], "cargo_config")
        self.assertEqual(by_path["rust-toolchain.toml"]["role"], "toolchain")
        self.assertEqual(by_path["rust-toolchain"]["present"], False)
        self.assertEqual(by_path["rust-toolchain"]["sha256"], None)
        for entry in entries:
            if entry["present"]:
                self.assertEqual(entry["sha256"], hashlib.sha256(blobs[entry["path"]]).hexdigest())

        serialized = json.dumps(self.bound)
        for content in ("jobs = 4", "pub fn production", "fn main()", "#[test]",
                        "fixture-data", 'channel = "1.99.1"',
                        "create table pando_session"):
            self.assertNotIn(content, serialized)
        self.assertEqual(self.bound["config_digest"],
                         receipts.config_digest_from_entries(entries))

    def test_compile_time_pando_asset_changes_full_inventory_not_v1_digest(self):
        before = self.capture()
        by_path = {entry["path"]: entry for entry in before["bound_input_inventory"]}
        self.assertEqual(by_path["experimental/pando/schema.sql"]["role"], "compiled_asset")
        self.assertEqual(before["bound_inputs"]["by_role"]["compiled_asset"], 1)

        payload = self.make_v2()
        self.write("experimental/pando/schema.sql", "create table pando_session_v2();\n")
        after = self.capture()
        self.assertNotEqual(before["bound_inputs"]["digest"], after["bound_inputs"]["digest"])
        self.assertEqual(before["source_inputs_sha256"], after["source_inputs_sha256"])
        self.assert_rejected(payload, "inventory differs")

        (self.root / "experimental/pando/schema.sql").unlink()
        with self.assertRaises(receipts.ReceiptError) as caught:
            self.capture()
        self.assertIn("required compiled asset", str(caught.exception))
        self.assert_rejected(payload, "required compiled asset")

    def test_literal_compile_time_include_outside_covered_dirs_is_bound(self):
        self.write(
            "src/embedded.rs",
            'pub const EXTRA: &str = include_str!("../experimental/pando/extra.txt");\n',
        )
        self.write("experimental/pando/extra.txt", "extra-one\n")
        entries, _ = receipts.bound_input_inventory(self.root)
        by_path = {entry["path"]: entry for entry in entries}
        self.assertEqual(by_path["experimental/pando/extra.txt"]["role"], "compiled_asset")

        first = self.capture()
        self.write("experimental/pando/extra.txt", "extra-two\n")
        second = self.capture()
        self.assertNotEqual(first["bound_inputs"]["digest"], second["bound_inputs"]["digest"])

        (self.root / "experimental/pando/extra.txt").unlink()
        with self.assertRaises(receipts.ReceiptError) as caught:
            self.capture()
        self.assertIn("compile-time include target", str(caught.exception))

    def test_compile_time_include_outside_the_repository_is_rejected(self):
        self.write(
            "src/outside.rs",
            'pub const OUTSIDE: &str = include_str!("../../outside.txt");\n',
        )
        outside = self.tempdir.parent / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        with self.assertRaises(receipts.ReceiptError) as caught:
            self.capture()
        self.assertIn("resolves outside", str(caught.exception))

    def test_external_cargo_config_is_rejected_without_reading_contents(self):
        sentinel = "SENTINEL-CONFIG-VALUE"
        cargo_home = self.root / "cargo-home"
        config = cargo_home / "config.toml"
        config.parent.mkdir(parents=True)
        config.write_text('[build]\nrustc = "' + sentinel + '"\n', encoding="utf-8")
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.capture_bound_inputs(
                self.root, environ={"CARGO_HOME": str(cargo_home), "PATH": ""}
            )
        message = str(caught.exception)
        self.assertIn(os.path.abspath(str(config)), message)
        self.assertNotIn(sentinel, message)

    def test_in_repository_redirect_config_is_rejected_without_contents(self):
        sentinel = "SENTINEL-TARGET"
        self.write(".cargo/config.toml", f'[build]\ntarget = "{sentinel}"\n')
        with self.assertRaises(receipts.ReceiptError) as caught:
            self.capture()
        message = str(caught.exception)
        self.assertIn("build.target", message)
        self.assertNotIn(sentinel, message)

    def test_environment_guard_reports_names_only_and_allows_target_dir(self):
        self.assertFalse(receipts.is_rejected_environment_name("CARGO_TARGET_DIR"))
        self.assertTrue(receipts.is_rejected_environment_name("RUSTFLAGS"))
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.reject_passthrough_environment(
                {"RUSTFLAGS": "SENTINEL-RUSTFLAG", "CARGO_TARGET_DIR": "/shared/target"}
            )
        message = str(caught.exception)
        self.assertIn("RUSTFLAGS", message)
        self.assertNotIn("SENTINEL-RUSTFLAG", message)
        self.assertNotIn("CARGO_TARGET_DIR", message)

        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.capture_bound_inputs(
                self.root, environ={"RUSTFLAGS": "SENTINEL-RUSTFLAG", "PATH": ""}
            )
        self.assertNotIn("SENTINEL-RUSTFLAG", str(caught.exception))

    def test_artifact_record_copies_freshness_strictly(self):
        for fresh in (True, False):
            record = receipts.cargo_artifact_record(self.event("bin", fresh), self.root)
            self.assertIs(record["fresh"], fresh)
            self.assertEqual(record["kind"], "bin")
            self.assertEqual(record["target"], "rootyard")
            self.assertEqual(record["package_id"], "rootyard 0.1.0")
            self.assertEqual(record["source"], "src/main.rs")
            self.assertEqual(record["executable_sha256"], receipts.sha256_file(self.binary))

        for fresh in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(fresh=fresh):
                event = self.event("bin", fresh)
                with self.assertRaises(receipts.ReceiptError):
                    receipts.cargo_artifact_record(event, self.root)
        event = self.event("bin", True)
        del event["fresh"]
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(event, self.root)

    def test_artifact_record_rejects_inconsistent_targets_and_paths(self):
        no_executable = self.event("bin", True)
        del no_executable["executable"]
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(no_executable, self.root)

        lib_executable = self.event("lib", True, executable=self.binary)
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(lib_executable, self.root)

        outside = self.root.parent / "outside-source.rs"
        outside.write_text("fn main() {}\n", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(
                self.event("lib", True, source=outside), self.root
            )

        bad_kind = self.event("bin", True)
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(bad_kind, self.root, kind="test")

        missing_profile = self.event("bin", True)
        del missing_profile["profile"]["debug_assertions"]
        with self.assertRaises(receipts.ReceiptError):
            receipts.cargo_artifact_record(missing_profile, self.root)

    def test_make_v2_rejects_aliases_and_clean_commands(self):
        for field, value in (
            ("package_rebuilt", True),
            ("clean_command", ["cargo", "clean"]),
            ("fresh_false_artifacts", []),
        ):
            with self.subTest(field=field):
                with self.assertRaises(receipts.ReceiptError):
                    self.make_v2(extra={field: value})
        with self.assertRaises(receipts.ReceiptError):
            self.make_v2(extra={"binary_sha256": "0" * 64})
        with self.assertRaises(receipts.ReceiptError):
            self.make_v2(command=["cargo", "clean", "--package", "rootyard"])

    def test_probe_toolchain_uses_path_cargo_and_metadata_only(self):
        commands = []

        def fake_which(name, path=None):
            self.assertEqual(path, "/test/path")
            return str(self.root / "toolchain" / name) if name in ("cargo", "rustc", "rustup") else None

        def fake_run(command):
            commands.append(list(command))
            executable = Path(command[0]).name
            if executable == "cargo":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "cargo 1.101.0 (64a6ee6a 2026-01-01)\n"
                        "release: 1.101.0\n"
                        f"commit-hash: {CARGO_FORK_COMMIT}\n"
                        "commit-date: 2026-01-01\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            if executable == "rustc":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "rustc 1.99.1 (deadbeef 2025-01-01)\n"
                        "release: 1.99.1\n"
                        f"commit-hash: {RUSTC_COMMIT}\n"
                        "commit-date: 2025-01-01\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            if executable == "rustup":
                return SimpleNamespace(returncode=0, stdout=str(self.root / "toolchain/rustc") + "\n")
            raise AssertionError(command)

        toolchain = receipts.probe_toolchain(
            self.root, environ={"PATH": "/test/path"}, which=fake_which, run=fake_run
        )
        self.assertEqual(
            commands,
            [
                [str(self.root / "toolchain/cargo"), "-vV"],
                [str(self.root / "toolchain/rustc"), "-vV"],
                [str(self.root / "toolchain/rustup"), "which", "rustc"],
            ],
        )
        self.assertEqual(toolchain["cargo"]["commit_hash"], CARGO_FORK_COMMIT)
        self.assertEqual(toolchain["cargo"]["release"], "1.101.0")
        self.assertEqual(toolchain["rustc"]["commit_hash"], RUSTC_COMMIT)
        self.assertIs(toolchain["rustc"]["proxy"], False)
        self.assertEqual(toolchain["rustc"]["path_entry"],
                         str((self.root / "toolchain/rustc").absolute()))
        self.assertEqual(toolchain["target_triple"], TARGET_TRIPLE)
        self.assertEqual(toolchain["pinned_channel"], "1.99.1")
        self.assertEqual(
            toolchain["cargo"]["executable_sha256"],
            receipts.sha256_file(self.root / "toolchain/cargo"),
        )

    def test_probe_toolchain_requires_the_full_verbose_commit(self):
        def fake_which(name, path=None):
            return str(self.root / "toolchain" / name) if name in ("cargo", "rustc", "rustup") else None

        def short_commit(command):
            if Path(command[0]).name == "cargo":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "cargo 1.101.0 (64a6ee6a 2026-01-01)\n"
                        "release: 1.101.0\n"
                        "commit-hash: 64a6ee6a\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            if Path(command[0]).name == "rustc":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "rustc 1.99.1 (deadbeef 2025-01-01)\n"
                        "release: 1.99.1\n"
                        f"commit-hash: {RUSTC_COMMIT}\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            return SimpleNamespace(returncode=0, stdout=str(self.root / "toolchain/rustc") + "\n")

        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.probe_toolchain(
                self.root, environ={"PATH": "/test/path"}, which=fake_which, run=short_commit
            )
        self.assertIn("full 40- or 64-hex", str(caught.exception))

    def test_preferring_path_cargo_never_calls_rustup_which_cargo(self):
        commands = []

        def fake_which(name, path=None):
            return str(self.root / "toolchain" / name) if name in ("cargo", "rustc", "rustup") else None

        def fake_run(command):
            commands.append(list(command))
            if Path(command[0]).name == "cargo":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "cargo 1.101.0 (64a6ee6a 2026-01-01)\n"
                        "release: 1.101.0\n"
                        f"commit-hash: {CARGO_FORK_COMMIT}\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            if Path(command[0]).name == "rustc":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "rustc 1.99.1 (deadbeef 2025-01-01)\n"
                        "release: 1.99.1\n"
                        f"commit-hash: {RUSTC_COMMIT}\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            return SimpleNamespace(returncode=1, stdout="")

        receipts.probe_toolchain(
            self.root, environ={"PATH": "/test/path"}, which=fake_which, run=fake_run
        )
        self.assertFalse(
            [command for command in commands if command[1:3] == ["which", "cargo"]]
        )
        self.assertEqual(commands[-1], [str(self.root / "toolchain/rustup"), "which", "rustc"])

    def test_run_build_finished_requires_one_success(self):
        receipts.require_build_finished([{"reason": "build-finished", "success": True}])
        for events in (
            [],
            [{"reason": "build-finished", "success": False}],
            [
                {"reason": "build-finished", "success": True},
                {"reason": "build-finished", "success": True},
            ],
        ):
            with self.subTest(events=events):
                with self.assertRaises(receipts.ReceiptError):
                    receipts.require_build_finished(events)


class ToolchainProbeEnvironmentTest(ReceiptFixture):
    """Default probe subprocesses receive exactly the caller's environ."""

    def fake_which(self, name, path=None):
        self.assertEqual(path, "/test/path")
        if name in ("cargo", "rustc", "rustup"):
            return str(self.root / "toolchain" / name)
        return None

    def probe_result(self, command, *, release="1.99.1"):
        executable = Path(command[0]).name
        if executable == "cargo":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "cargo 1.101.0 (64a6ee6a 2026-01-01)\n"
                    "release: 1.101.0\n"
                    f"commit-hash: {CARGO_FORK_COMMIT}\n"
                    "commit-date: 2026-01-01\n"
                    f"host: {TARGET_TRIPLE}\n"
                ),
            )
        if executable == "rustc":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"rustc {release} (deadbeef 2025-01-01)\n"
                    f"release: {release}\n"
                    f"commit-hash: {RUSTC_COMMIT}\n"
                    "commit-date: 2025-01-01\n"
                    f"host: {TARGET_TRIPLE}\n"
                ),
            )
        if executable == "rustup":
            return SimpleNamespace(
                returncode=0, stdout=str(self.root / "toolchain/rustc") + "\n"
            )
        raise AssertionError(command)

    def test_default_runner_receives_the_exact_supplied_normalized_environment(self):
        supplied = {"PATH": "/test/path", "CARGO_TARGET_DIR": "/shared/target"}
        ambient = {
            "PATH": "/ambient/path",
            "RUSTUP_TOOLCHAIN": "SENTINEL-AMBIENT-TOOLCHAIN",
            "RUSTUP_HOME": "/ambient/rustup",
        }
        seen = []

        def fake_run(command, **kwargs):
            seen.append((list(command), kwargs))
            return self.probe_result(command)

        with mock.patch.object(receipts.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(receipts.os, "environ", ambient):
            toolchain = receipts.probe_toolchain(
                self.root, environ=supplied, which=self.fake_which
            )

        self.assertEqual(len(seen), 3)
        for command, kwargs in seen:
            self.assertEqual(kwargs["env"], supplied)
            self.assertIsNot(kwargs["env"], receipts.os.environ)
            self.assertNotIn("RUSTUP_TOOLCHAIN", kwargs["env"])
            self.assertNotIn("CARGO_BUILD_JOBS", kwargs["env"])
            self.assertEqual(kwargs["cwd"], self.root)
            self.assertIn(command, (
                [str(self.root / "toolchain/cargo"), "-vV"],
                [str(self.root / "toolchain/rustc"), "-vV"],
                [str(self.root / "toolchain/rustup"), "which", "rustc"],
            ))
        self.assertIs(toolchain["rustc"]["proxy"], False)

    def test_probe_refuses_a_raw_jobs_environment_without_running_a_tool(self):
        sentinel = {"PATH": "/test/path", "CARGO_BUILD_JOBS": "2"}
        with mock.patch.object(receipts.subprocess, "run", side_effect=AssertionError("run")), \
                mock.patch.object(receipts.shutil, "which", side_effect=AssertionError("which")):
            with self.assertRaises(receipts.ReceiptError) as caught:
                receipts.probe_toolchain(self.root, environ=sentinel)
        self.assertIn("CARGO_BUILD_JOBS", str(caught.exception))

    def test_direct_rustc_must_match_an_exact_pinned_channel(self):
        toolchain = receipts.probe_toolchain(
            self.root,
            environ={"PATH": "/test/path"},
            which=self.fake_which,
            run=self.probe_result,
        )
        self.assertIs(toolchain["rustc"]["proxy"], False)
        self.assertEqual(toolchain["rustc"]["release"], "1.99.1")

        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.98.0"\n')
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.probe_toolchain(
                self.root,
                environ={"PATH": "/test/path"},
                which=self.fake_which,
                run=self.probe_result,
            )
        self.assertIn("pinned channel", str(caught.exception))

        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "stable"\n')
        symbolic = receipts.probe_toolchain(
            self.root,
            environ={"PATH": "/test/path"},
            which=self.fake_which,
            run=self.probe_result,
        )
        self.assertEqual(symbolic["pinned_channel"], "stable")


class RustupProxyToolchainTest(ReceiptFixture):
    """Realistic Linux layout: PATH rustc is a symlink to the rustup binary."""

    def make_proxy(self, channel="1.99.1"):
        self.write("rust-toolchain.toml", f'[toolchain]\nchannel = "{channel}"\n')
        rustup = self.root / "toolchain/rustup"
        proxy = self.root / "toolchain/rustc"
        proxy.unlink()
        proxy.symlink_to(rustup)
        actual = self.root / "toolchain/actual/bin/rustc"
        self.write("toolchain/actual/bin/rustc", b"fake-actual-rustc")
        return proxy, rustup, actual

    def fake_which(self, name, path=None):
        self.assertEqual(path, "/test/path")
        if name in ("cargo", "rustc", "rustup"):
            return str(self.root / "toolchain" / name)
        return None

    def fake_run(self, actual, commands, *, release="1.99.1", rustup_returncode=0):
        cargo = self.root / "toolchain/cargo"
        rustup = self.root / "toolchain/rustup"

        def run(command):
            commands.append(list(command))
            if command[0] == str(cargo) and command[1:] == ["-vV"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "cargo 1.101.0 (64a6ee6a 2026-01-01)\n"
                        "release: 1.101.0\n"
                        f"commit-hash: {CARGO_FORK_COMMIT}\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            if command[0] == str(rustup) and command[1:] == ["which", "rustc"]:
                if rustup_returncode != 0:
                    return SimpleNamespace(returncode=rustup_returncode, stdout="")
                return SimpleNamespace(returncode=0, stdout=str(actual) + "\n")
            if Path(command[0]).resolve() == actual.resolve() and command[1:] == ["-vV"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        f"rustc {release} (58cf8f9c3 2025-01-01)\n"
                        f"release: {release}\n"
                        f"commit-hash: {RUSTC_COMMIT}\n"
                        f"host: {TARGET_TRIPLE}\n"
                    ),
                )
            raise AssertionError(f"unexpected toolchain probe: {command}")

        return run

    def test_proxy_rustc_is_resolved_and_probed_as_the_actual_compiler(self):
        proxy, rustup, actual = self.make_proxy()
        commands = []
        toolchain = receipts.probe_toolchain(
            self.root,
            environ={"PATH": "/test/path"},
            which=self.fake_which,
            run=self.fake_run(actual, commands),
        )

        self.assertEqual(toolchain["rustc"]["executable"], str(actual.resolve()))
        self.assertEqual(toolchain["rustc"]["executable_sha256"],
                         receipts.sha256_file(actual))
        self.assertIs(toolchain["rustc"]["proxy"], True)
        self.assertEqual(toolchain["rustc"]["path_entry"], str(proxy.absolute()))
        self.assertEqual(toolchain["rustc"]["version"].split()[0], "rustc")
        self.assertEqual(toolchain["rustc"]["release"], "1.99.1")
        self.assertEqual(toolchain["rustc"]["commit_hash"], RUSTC_COMMIT)
        self.assertEqual(toolchain["rustup"]["executable"], str(rustup.resolve()))
        self.assertEqual(toolchain["rustup"]["resolved_rustc"], str(actual.resolve()))
        self.assertEqual(toolchain["rustup"]["resolved_rustc_sha256"],
                         receipts.sha256_file(actual))
        self.assertEqual(toolchain["cargo"]["commit_hash"], CARGO_FORK_COMMIT)
        self.assertEqual(toolchain["target_triple"], TARGET_TRIPLE)
        self.assertEqual(toolchain["pinned_channel"], "1.99.1")

        self.assertIn([str(rustup.resolve()), "which", "rustc"], commands)
        self.assertIn([str(actual.resolve()), "-vV"], commands)
        self.assertNotIn([str(rustup.resolve()), "-vV"], commands)
        self.assertFalse(
            [command for command in commands if command[1:3] == ["which", "cargo"]]
        )

    def test_proxy_resolution_failure_never_probes_rustup_as_rustc(self):
        proxy, rustup, actual = self.make_proxy()
        commands = []
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.probe_toolchain(
                self.root,
                environ={"PATH": "/test/path"},
                which=self.fake_which,
                run=self.fake_run(actual, commands, rustup_returncode=1),
            )
        self.assertIn("rustup which rustc", str(caught.exception))
        self.assertNotIn([str(rustup.resolve()), "-vV"], commands)
        self.assertNotIn([str(actual.resolve()), "-vV"], commands)

    def test_proxy_compiler_release_must_match_an_exact_pinned_channel(self):
        proxy, rustup, actual = self.make_proxy(channel="1.98.0")
        commands = []
        with self.assertRaises(receipts.ReceiptError) as caught:
            receipts.probe_toolchain(
                self.root,
                environ={"PATH": "/test/path"},
                which=self.fake_which,
                run=self.fake_run(actual, commands),
            )
        self.assertIn("pinned channel", str(caught.exception))
        self.assertIn([str(actual.resolve()), "-vV"], commands)


if __name__ == "__main__":
    unittest.main()
