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
    def helper_receipt(self, *, target=SNAPSHOT_TARGET, source=SNAPSHOT_SOURCE,
                       fresh=True, output=None, original=None, manifest=None,
                       bound=None, toolchain=None, profile="test",
                       kind="rust-integration-test", relocated=True,
                       with_batch=True, with_selection=True):
        source_path = self.root / source
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
            "integration_test_source": row["source"],
            "integration_test_source_sha256": row["source_sha256"],
        }
        if relocated:
            extra["relocated_artifact"] = True
            extra["original_artifact_sha256"] = row["executable_sha256"]
        if with_batch:
            extra["batch"] = self.batch_link(
                manifest, output.name, ["rootyard", "rootyard", target], bound)
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
                    manifest=None, bound=None, toolchain=None, relocated=True,
                    with_batch=True, with_selection=True, implicit=False,
                    extra_bins=()):
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
        extra = {"kind": kind}
        if implicit:
            extra["implicit_build"] = True
        if relocated:
            extra["relocated_artifact"] = True
            extra["original_artifact_sha256"] = original_sha256 or bin_row["executable_sha256"]
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

    def validate_snapshot(self, helper_payload, app_payload, *, default_paths=False):
        helper_receipt = self.write_receipt(
            Path(str(self.snapshot_output) + ".build.json") if default_paths
            else self.root / "receipts/snapshot.build.json", helper_payload)
        app_receipt = self.write_receipt(
            Path(str(self.app_output) + ".build.json") if default_paths
            else self.root / "receipts/application.build.json", app_payload)
        if default_paths:
            return snapshot140.validate_snapshot_fixture_binary(
                self.snapshot_output, self.app_output)
        return snapshot140.validate_snapshot_fixture_binary(
            self.snapshot_output, self.app_output, helper_receipt, app_receipt)


class Snapshot140ReceiptDispatchTest(RefStoreReceiptFixture):
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
                    "target": "rootyard-pando-lab",
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

