#!/usr/bin/env python3
"""Focused regression tests for the bounded feature-only implementation overlay."""
import copy
import hashlib
import sys
import tomllib
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import state_services_checks as checks  # noqa: E402


class ImplementationOverlayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dependencies = checks.load(checks.STATE / "dependencies.json")
        cls.parent = cls.dependencies["current_stack_parent"]
        cls.overlay = cls.dependencies["implementation_overlay"]
        cls.manifest_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        cls.file_hashes = {
            filename: checks.sha256_file(ROOT / filename)
            for filename in cls.parent["files"]
        }

    def check(self, manifest_text=None, file_hashes=None, overlay=None):
        text = self.manifest_text if manifest_text is None else manifest_text
        if file_hashes is None:
            file_hashes = dict(self.file_hashes)
            file_hashes["Cargo.toml"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        checks.check_feature_only_overlay(
            self.overlay if overlay is None else overlay,
            self.parent,
            text,
            file_hashes,
        )

    def overlay_for(self, manifest_text, **changes):
        overlay = copy.deepcopy(self.overlay)
        overlay["files"]["Cargo.toml"] = hashlib.sha256(
            manifest_text.encode("utf-8")
        ).hexdigest()
        overlay.update(changes)
        return overlay

    def mutated(self, old, new):
        text = self.manifest_text.replace(old, new, 1)
        self.assertNotEqual(text, self.manifest_text, f"fixture did not contain {old!r}")
        return text

    def test_legitimate_empty_feature_overlay_passes(self):
        manifest = tomllib.loads(self.manifest_text)
        self.assertEqual(manifest["features"]["state-baseline-metrics"], [])
        self.assertNotIn("state-baseline-metrics", manifest["features"].get("default", []))
        self.assertEqual(manifest["package"]["rust-version"], self.parent["declared_rust_version"])
        # The frozen parent manifest hash is not the child's current hash.
        self.assertNotEqual(self.overlay["parent_manifest_sha256"], self.file_hashes["Cargo.toml"])
        self.check()
        dependencies = checks.validate_dependencies()
        self.assertEqual(
            dependencies["implementation_overlay"]["schema"], checks.OVERLAY_SCHEMA
        )

    def test_parent_reference_is_the_frozen_archive_not_the_child_manifest(self):
        parent_bytes = (checks.STATE / "stack-parent.Cargo.toml").read_bytes()
        self.assertEqual(
            hashlib.sha256(parent_bytes).hexdigest(), self.parent["files"]["Cargo.toml"]
        )
        parent_manifest = tomllib.loads(parent_bytes.decode("utf-8"))
        self.assertEqual(
            checks.canonical_manifest_digest(parent_manifest),
            self.overlay["parent_manifest_semantic_sha256"],
        )
        self.assertNotEqual(
            self.parent["files"]["Cargo.toml"], self.file_hashes["Cargo.toml"]
        )
        self.assertEqual(
            self.file_hashes["Cargo.lock"], self.parent["files"]["Cargo.lock"]
        )

    def test_dependency_and_version_changes_fail(self):
        mutations = (
            ('anyhow = "1"', 'anyhow = "1"\nevil_crate = "1"'),
            ('axum = "0.8"', 'axum = "0.9"'),
        )
        for old, new in mutations:
            with self.subTest(change=new):
                text = self.mutated(old, new)
                with self.assertRaisesRegex(ValueError, "differs from the frozen parent"):
                    self.check(text, overlay=self.overlay_for(text))

    def test_extra_enabled_or_nonempty_features_fail(self):
        cases = (
            ("state-baseline-metrics = []", "state-baseline-metrics = []\nsurprise = []",
             "differs from the frozen parent"),
            ("[features]\npando-lab = []",
             '[features]\npando-lab = []\ndefault = ["state-baseline-metrics"]',
             "must not be enabled by default"),
            ('state-baseline-metrics = []', 'state-baseline-metrics = ["pando-lab"]',
             "must stay empty"),
        )
        for old, new, message in cases:
            with self.subTest(change=new):
                text = self.mutated(old, new)
                with self.assertRaisesRegex(ValueError, message):
                    self.check(text, overlay=self.overlay_for(text))

    def test_unknown_overlay_feature_name_fails(self):
        overlay = self.overlay_for(self.manifest_text)
        overlay["feature"] = dict(overlay["feature"], name="pando-lab")
        with self.assertRaisesRegex(ValueError, "may only declare"):
            self.check(overlay=overlay)

    def test_changed_or_relaxed_msrv_fails(self):
        for version in ("1.87", "1.89"):
            with self.subTest(rust_version=version):
                text = self.mutated('rust-version = "1.88"', f'rust-version = "{version}"')
                with self.assertRaisesRegex(ValueError, "MSRV"):
                    self.check(text, overlay=self.overlay_for(text))

    def test_lockfile_and_recorded_manifest_hashes_are_strict(self):
        changed_lock = dict(self.file_hashes, **{"Cargo.lock": "0" * 64})
        with self.assertRaisesRegex(ValueError, "lockfile must remain"):
            self.check(file_hashes=changed_lock)
        overlay = self.overlay_for(self.manifest_text)
        overlay["files"]["Cargo.toml"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "match the current manifest"):
            self.check(overlay=overlay)
        relabelled = self.overlay_for(self.manifest_text)
        relabelled["parent_manifest_sha256"] = self.file_hashes["Cargo.toml"]
        with self.assertRaisesRegex(ValueError, "never a relabelled child hash"):
            self.check(overlay=relabelled)

    def test_missing_overlay_keeps_the_original_strict_parent_hash_gate(self):
        without_overlay = copy.deepcopy(self.dependencies)
        del without_overlay["implementation_overlay"]
        with mock.patch.object(checks, "load", return_value=without_overlay):
            with self.assertRaisesRegex(ValueError, "current Cargo.toml hash drift"):
                checks.validate_dependencies()


if __name__ == "__main__":
    unittest.main()
