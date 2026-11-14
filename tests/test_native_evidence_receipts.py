"""Offline v2 evidence-reader regressions.

These tests exercise the shared receipt reader through ``native_evidence``,
``source_bound_binary`` and ``blob_only_service``.  They prove that a copied
or content-addressed executable with the same bound SHA-256 remains valid when
the mutable original changes, that v1 keeps its historical current-source
check, and that no reader invokes Cargo, rustc, rustup or a builder.
"""
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
for path in (TESTS, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import blob_only_service  # noqa: E402
import native_build_receipt as receipts  # noqa: E402
import native_evidence  # noqa: E402
import source_bound_binary  # noqa: E402

PANDO_SCHEMA_SQL = (
    "-- Separate namespace, never applied by Rootyard's production migration runner.\n"
    "CREATE SCHEMA IF NOT EXISTS pando_lab;\n"
    "CREATE TABLE IF NOT EXISTS pando_lab.repositories (\n"
    " id uuid PRIMARY KEY, generation bigint NOT NULL DEFAULT 0);\n"
)

TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
COMMIT = "a" * 40
CARGO_FORK_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class V2EvidenceFixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        for relative, content in (
            ("Cargo.toml", '[package]\nname = "rootyard"\n'),
            ("Cargo.lock", "version = 3\n"),
            ("build.rs", "fn main() {}\n"),
            ("src/lib.rs", "pub fn production() -> u8 { 1 }\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
            ("experimental/pando/schema.sql", PANDO_SCHEMA_SQL),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.binary = self.root / "target/debug/rootyard"
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_bytes(b"native-binary")
        self.binary.chmod(0o700)
        self.toolchain_dir = self.root / "toolchain"
        self.toolchain_dir.mkdir()
        for name in ("cargo", "rustc", "rustup"):
            (self.toolchain_dir / name).write_bytes(("fake-" + name).encode())
        self.bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        self.profile = {
            "opt_level": "0",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": True,
            "test": False,
        }

    def toolchain(self):
        def identity(name, release, commit_hash):
            executable = self.toolchain_dir / name
            return {
                "executable": str(executable),
                "executable_sha256": digest(executable),
                "version": f"{name} {release} (fake 2026-01-01)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": TARGET_TRIPLE,
            }

        return {
            "cargo": identity("cargo", "1.101.0", CARGO_FORK_COMMIT),
            "rustc": dict(
                identity("rustc", "1.99.1", "d" * 40),
                path_entry=str(self.toolchain_dir / "rustc"),
                proxy=False,
            ),
            "rustup": {
                "executable": str(self.toolchain_dir / "rustup"),
                "executable_sha256": digest(self.toolchain_dir / "rustup"),
                "resolved_rustc": str(self.toolchain_dir / "rustc"),
                "resolved_rustc_sha256": digest(self.toolchain_dir / "rustc"),
            },
            "target_triple": TARGET_TRIPLE,
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def artifact(self, kind, source, executable=None, fresh=True):
        target = {"name": "rootyard", "kind": [kind], "src_path": str(source)}
        event = {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": target,
            "profile": self.profile,
            "fresh": fresh,
        }
        if executable is not None:
            event["executable"] = str(executable)
        return receipts.cargo_artifact_record(event, self.root)

    def make_v2(self, *, fresh=True):
        artifacts = [
            self.artifact("lib", self.root / "src/lib.rs", fresh=fresh),
            self.artifact("bin", self.root / "src/main.rs", executable=self.binary, fresh=fresh),
        ]
        payload = receipts.make_receipt_v2(
            binary_path=self.binary,
            command=["cargo", "build", "--locked", "--bin", "rootyard"],
            profile="dev",
            artifacts=artifacts,
            toolchain=self.toolchain(),
            bound_inputs=self.bound,
            workspace_commit=COMMIT,
            target_dir=self.binary.parent.parent,
            target_triple=TARGET_TRIPLE,
        )
        receipts.atomic_write_json(self.binary.with_suffix(".build.json"), payload)
        return payload

    def make_v1(self):
        payload = {
            "version": 1,
            "binary_sha256": digest(self.binary),
            "source_inputs_sha256": self.bound["source_inputs_sha256"],
            "workspace_commit": COMMIT,
            "rustc": "rustc 1.99.1",
            "command": ["cargo", "build", "--locked", "--bin", "rootyard"],
        }
        self.binary.with_suffix(".build.json").write_text(json.dumps(payload))
        return payload

    def copy_snapshot(self, name="snapshot"):
        directory = self.root / name
        directory.mkdir()
        binary = directory / "rootyard"
        shutil.copyfile(self.binary, binary)
        binary.chmod(0o700)
        receipt = directory / "rootyard.build.json"
        shutil.copyfile(self.binary.with_suffix(".build.json"), receipt)
        return binary, receipt


class NativeEvidenceV2Test(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = V2EvidenceFixture(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_build_record_uses_shared_v2_reader_and_keeps_raw_fields(self):
        payload = self.fixture.make_v2(fresh=True)
        record = native_evidence.build_record(self.fixture.binary)
        self.assertTrue(record["attested"])
        self.assertEqual(record["validated_schema"], "v2")
        self.assertEqual(record["binary_sha256"], payload["binary_sha256"])
        self.assertEqual(record["cargo_artifacts"], payload["cargo_artifacts"])

    def test_copied_snapshot_stays_valid_when_mutable_original_changes(self):
        self.fixture.make_v2(fresh=True)
        binary, receipt = self.fixture.copy_snapshot()
        original_receipt = receipt.read_bytes()
        self.fixture.binary.write_bytes(b"mutated-original")
        record = native_evidence.build_record(binary)
        self.assertTrue(record["attested"])
        self.assertEqual(record["validated_schema"], "v2")
        evidence = source_bound_binary.bind(binary, expected_commit=COMMIT, environ={})
        self.assertEqual(evidence["schema"], "v2")
        self.assertEqual(evidence["binary_sha256"], digest(binary))
        self.assertTrue(evidence["source_snapshot_bound"])
        self.assertEqual(evidence["receipt_sha256"], hashlib.sha256(original_receipt).hexdigest())
        self.assertEqual(receipt.read_bytes(), original_receipt)

    def test_v2_binding_does_not_require_current_tree_or_historical_compiler(self):
        self.fixture.make_v2(fresh=False)
        with mock.patch.object(source_bound_binary, "production_source_digest", return_value="f" * 64), \
                mock.patch.object(receipts, "probe_toolchain", side_effect=AssertionError("probe called")), \
                mock.patch.object(receipts, "capture_bound_inputs", side_effect=AssertionError("capture called")):
            evidence = source_bound_binary.bind(
                self.fixture.binary, expected_commit=COMMIT, environ={}
            )
        self.assertEqual(evidence["schema"], "v2")
        self.assertEqual(evidence["source_inputs_sha256"], self.fixture.bound["source_inputs_sha256"])
        self.assertEqual(evidence["config_digest"], self.fixture.bound["config_digest"])
        self.assertEqual(evidence["expected_commit"], COMMIT)
        self.assertEqual(evidence["receipt_toolchain"]["rustc"], "rustc 1.99.1 (fake 2026-01-01)")

    def test_v1_binding_keeps_its_current_production_source_check(self):
        self.fixture.make_v1()
        with mock.patch.object(source_bound_binary, "production_source_digest", return_value="f" * 64), \
                mock.patch.object(source_bound_binary, "_git", return_value=None):
            with self.assertRaises(source_bound_binary.SourceBindingError):
                source_bound_binary.bind(self.fixture.binary, expected_commit=COMMIT, environ={})

    def test_expected_commit_and_binary_sha_remain_exact(self):
        self.fixture.make_v2()
        with self.assertRaises(source_bound_binary.SourceBindingError):
            source_bound_binary.bind(self.fixture.binary, expected_commit="e" * 40, environ={})
        binary, _ = self.fixture.copy_snapshot()
        binary.write_bytes(b"different-copy")
        with self.assertRaises(Exception):
            source_bound_binary.bind(binary, expected_commit=COMMIT, environ={})

    def test_missing_or_non_boolean_freshness_is_rejected(self):
        for mutate in ("missing", "string"):
            payload = self.fixture.make_v2()
            target = dict(payload)
            rows = [dict(row) for row in target["cargo_artifacts"]]
            if mutate == "missing":
                rows[0].pop("fresh")
            else:
                rows[0]["fresh"] = "true"
            target["cargo_artifacts"] = rows
            self.fixture.binary.with_suffix(".build.json").write_text(json.dumps(target))
            with self.assertRaises(receipts.ReceiptError):
                native_evidence.build_record(self.fixture.binary)


class BlobProfileV2Test(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = V2EvidenceFixture(self.temporary.name)
        self.git = self.fixture.root / "git"
        self.git.write_bytes(b"fake-git")
        self.git.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_profile_accepts_v2_snapshot_without_current_source_or_probe(self):
        self.fixture.make_v2(fresh=True)
        binary, _ = self.fixture.copy_snapshot()
        self.fixture.binary.write_bytes(b"mutated-original")
        with mock.patch.object(blob_only_service.subprocess, "check_output", return_value=b""):
            profile = blob_only_service.NativeProfile(binary, str(self.git), {})
        self.assertEqual(profile.schema, "v2")
        self.assertEqual(profile.source_digest(), self.fixture.bound["source_inputs_sha256"])
        self.assertEqual(profile.config_digest, self.fixture.bound["config_digest"])
        self.assertEqual(profile.rustc, "rustc 1.99.1 (fake 2026-01-01)")

    def test_profile_rejects_v2_receipt_with_wrong_expected_commit(self):
        self.fixture.make_v2()
        with mock.patch.object(blob_only_service.subprocess, "check_output", return_value=b""):
            with self.assertRaises(blob_only_service.ProfileError):
                blob_only_service.NativeProfile(
                    self.fixture.binary,
                    str(self.git),
                    {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "e" * 40},
                )


if __name__ == "__main__":
    unittest.main()
