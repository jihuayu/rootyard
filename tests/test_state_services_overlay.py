#!/usr/bin/env python3
"""Focused regression tests for the bounded feature-only implementation overlay.

Two contracts are separated and must stay separated:

* the historical overlay is verified only against its archived parent
  (`stack-parent.Cargo.toml`/`stack-parent.Cargo.lock`), never today's Cargo;
* today's integrated manifest is verified by `check_integrated_manifest` with
  explicit negative cases for tampering.
"""
import copy
import hashlib
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import state_services_checks as checks  # noqa: E402


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ImplementationOverlayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dependencies = checks.load(checks.STATE / "dependencies.json")
        cls.parent = cls.dependencies["current_stack_parent"]
        cls.overlay = cls.dependencies["implementation_overlay"]
        cls.parent_text = (checks.STATE / "stack-parent.Cargo.toml").read_text(encoding="utf-8")
        cls.parent_manifest = tomllib.loads(cls.parent_text)
        cls.current_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")

    def overlay_for(self, parent_text, **changes):
        overlay = copy.deepcopy(self.overlay)
        overlay.update(changes)
        return overlay

    def child_text(self, old, new):
        text = self.parent_text.replace(old, new, 1)
        self.assertNotEqual(text, self.parent_text, f"fixture did not contain {old!r}")
        return text

    def child(self, old=None, new=None):
        """The archived parent, optionally mutated, plus the empty overlay feature."""
        text = self.parent_text if old is None else self.child_text(old, new)
        return checks.manifest_mutation(text, "pando-lab = []\n",
                                        f"pando-lab = []\n{checks.OVERLAY_FEATURE} = []\n")

    def test_legitimate_empty_feature_overlay_passes(self):
        self.assertEqual(self.parent_manifest["features"], {"pando-lab": []})
        self.assertEqual(self.overlay["feature"]["name"], checks.OVERLAY_FEATURE)
        self.assertEqual(self.overlay["feature"]["included"], [])
        self.assertFalse(self.overlay["feature"]["default_enabled"])
        checks.check_feature_only_overlay(self.overlay, self.parent, self.parent_manifest)
        dependencies = checks.validate_dependencies()
        self.assertEqual(
            dependencies["implementation_overlay"]["schema"], checks.OVERLAY_SCHEMA
        )

    def test_parent_reference_is_the_frozen_archive_not_the_child_manifest(self):
        parent_bytes = (checks.STATE / "stack-parent.Cargo.toml").read_bytes()
        self.assertEqual(
            hashlib.sha256(parent_bytes).hexdigest(), self.parent["files"]["Cargo.toml"]
        )
        self.assertEqual(
            checks.canonical_manifest_digest(tomllib.loads(parent_bytes.decode("utf-8"))),
            self.overlay["parent_manifest_semantic_sha256"],
        )
        self.assertEqual(self.overlay["parent_lock_sha256"], self.parent["files"]["Cargo.lock"])
        self.assertEqual(self.overlay["files"]["Cargo.lock"], self.parent["files"]["Cargo.lock"])
        self.assertNotIn("Cargo.toml", self.overlay["files"], "the child manifest bytes are not archived")
        # The child semantic digest is the parent plus exactly the empty feature.
        child = checks._manifest_without_feature(self.parent_manifest, checks.OVERLAY_FEATURE)
        child["features"][checks.OVERLAY_FEATURE] = []
        self.assertEqual(checks.canonical_manifest_digest(child),
                         self.overlay["child_manifest_semantic_sha256"])
        self.assertIsNone(self.overlay["child_manifest_sha256"])

    def test_historical_contract_never_reads_todays_cargo(self):
        # Today's Cargo differs (new features/dependencies) and that must not
        # reach the historical check: it neither raises nor can be relabelled.
        self.assertNotEqual(sha(self.current_text), self.parent["files"]["Cargo.toml"])
        self.assertNotEqual(checks.sha256_file(ROOT / "Cargo.lock"), self.parent["files"]["Cargo.lock"])
        checks.check_historical_fixtures(self.dependencies)
        relabelled = copy.deepcopy(self.overlay)
        relabelled["parent_manifest_sha256"] = checks.sha256_file(ROOT / "Cargo.toml")
        with self.assertRaisesRegex(ValueError, "never a relabelled child hash"):
            checks.check_feature_only_overlay(relabelled, self.parent, self.parent_manifest)
        wrong_lock = copy.deepcopy(self.overlay)
        wrong_lock["parent_lock_sha256"] = checks.sha256_file(ROOT / "Cargo.lock")
        with self.assertRaisesRegex(ValueError, "frozen parent lockfile hash"):
            checks.check_feature_only_overlay(wrong_lock, self.parent, self.parent_manifest)

    def test_dependency_and_version_changes_fail(self):
        mutations = (
            ('anyhow = "1"', 'anyhow = "1"\nevil_crate = "1"'),
            ('axum = "0.8"', 'axum = "0.9"'),
            ('reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json"] }',
             'reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json", "cookies"] }'),
        )
        for old, new in mutations:
            with self.subTest(change=new):
                text = self.child(old, new)
                with self.assertRaisesRegex(ValueError, "differs from the frozen parent"):
                    checks.check_overlay_child_manifest(self.overlay, text)

    def test_extra_enabled_or_nonempty_features_fail(self):
        cases = (
            ("[dependencies]\n", "[dependencies]\nsurprise-dependency = \"1\"\n"),
            ("[dependencies]\n", "[dependencies]\nsurprise-dependency = \"1\"\n\n[extra-table]\nvalue = true\n"),
        )
        # Extra features, default-enabled overlay and non-empty overlay are
        # checked on the explicitly built child manifest below.
        for old, new in cases:
            with self.subTest(change=new):
                text = self.child(old, new)
                with self.assertRaisesRegex(ValueError, "differs from the frozen parent"):
                    checks.check_overlay_child_manifest(self.overlay, text)

    def test_overlay_manifest_is_exactly_the_parent_plus_the_empty_feature(self):
        good = self.child()
        self.assertEqual(tomllib.loads(good)["features"]["state-baseline-metrics"], [])
        checks.check_overlay_child_manifest(self.overlay, good)
        non_empty = checks.manifest_mutation(
            good, f"{checks.OVERLAY_FEATURE} = []\n", f"{checks.OVERLAY_FEATURE} = [\"pando-lab\"]\n")
        with self.assertRaisesRegex(ValueError, "overlay feature must stay empty"):
            checks.check_overlay_child_manifest(self.overlay, non_empty)
        default_enabled = checks.manifest_mutation(
            good, f"{checks.OVERLAY_FEATURE} = []\n",
            f"{checks.OVERLAY_FEATURE} = []\ndefault = [\"{checks.OVERLAY_FEATURE}\"]\n")
        with self.assertRaisesRegex(ValueError, "must not be enabled by default"):
            checks.check_overlay_child_manifest(self.overlay, default_enabled)
        extra_feature = checks.manifest_mutation(
            good, f"{checks.OVERLAY_FEATURE} = []\n", f"{checks.OVERLAY_FEATURE} = []\nsurprise = []\n")
        with self.assertRaisesRegex(ValueError, "differs from the frozen parent"):
            checks.check_overlay_child_manifest(self.overlay, extra_feature)

    def test_unknown_overlay_feature_name_fails(self):
        overlay = self.overlay_for(self.parent_text)
        overlay["feature"] = dict(overlay["feature"], name="pando-lab")
        with self.assertRaisesRegex(ValueError, "may only declare"):
            checks.check_feature_only_overlay(overlay, self.parent, self.parent_manifest)

    def test_overlay_record_must_be_empty_and_default_off(self):
        for change in (
            {"included": ["pando-lab"]},
            {"default_enabled": True},
        ):
            overlay = self.overlay_for(self.parent_text, feature=dict(self.overlay["feature"], **change))
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "overlay feature must"):
                    checks.check_feature_only_overlay(overlay, self.parent, self.parent_manifest)

    def test_changed_or_relaxed_msrv_fails(self):
        for version in ("1.87", "1.89"):
            with self.subTest(rust_version=version):
                text = self.child_text('rust-version = "1.88"', f'rust-version = "{version}"')
                with self.assertRaisesRegex(ValueError, "MSRV"):
                    checks.check_overlay_child_manifest(self.overlay, text)

    def test_historical_archive_and_evidence_hashes_are_strict(self):
        # Every historical archive must keep its recorded bytes; a licence or
        # lockfile change, or a moved / re-hashed archive, fails closed.
        for name, path in checks.CARGO_ARCHIVES.items():
            self.assertEqual(checks.sha256_file(ROOT / path), self.dependencies["baseline"]["files"][name])
            self.assertEqual(self.dependencies["historical_manifest"][name],
                             self.dependencies["baseline"]["files"][name])
        self.assertEqual(self.parent["files"]["Cargo.lock"], self.dependencies["baseline"]["files"]["Cargo.lock"])
        self.assertEqual(self.parent["files"]["LICENSE"], self.dependencies["baseline"]["files"]["LICENSE"])
        for key, message in (
            (("baseline", "files", "Cargo.lock"), "historical Cargo.lock"),
            (("baseline", "files", "Cargo.toml"), "historical Cargo.toml"),
            (("historical_manifest", "Cargo.lock"), "historical Cargo.lock record"),
            (("current_stack_parent", "files", "Cargo.lock"), "frozen stack parent Cargo.lock"),
        ):
            broken = copy.deepcopy(self.dependencies)
            target = broken
            for part in key[:-1]:
                target = target[part]
            target[key[-1]] = "0" * 64
            with self.subTest(field=".".join(key)):
                with self.assertRaisesRegex(ValueError, message):
                    checks.check_historical_fixtures(broken)

    def test_missing_overlay_still_verifies_the_integrated_manifest(self):
        without_overlay = copy.deepcopy(self.dependencies)
        del without_overlay["implementation_overlay"]
        self.assertIsNone(without_overlay.get("implementation_overlay"))
        checks.check_historical_fixtures(without_overlay)
        # The integrated contract still sees today's Cargo only.
        with self.assertRaisesRegex(ValueError, "integrated manifest contract is missing"):
            checks.validate_integrated_dependencies(
                {**without_overlay, "integrated_manifest": None}, self.current_text,
                (ROOT / "Cargo.lock").read_text(encoding="utf-8"))


class IntegratedManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dependencies = checks.load(checks.STATE / "dependencies.json")
        cls.integrated = cls.dependencies["integrated_manifest"]
        cls.manifest_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        cls.lock_text = (ROOT / "Cargo.lock").read_text(encoding="utf-8")

    def check(self, manifest_text=None, lock_text=None, integrated=None):
        checks.check_integrated_manifest(
            self.integrated if integrated is None else integrated,
            self.manifest_text if manifest_text is None else manifest_text,
            self.lock_text if lock_text is None else lock_text,
        )

    def mutated(self, old, new):
        return checks.manifest_mutation(self.manifest_text, old, new)

    def test_current_integrated_manifest_matches_its_record(self):
        self.check()
        tomllib.loads(self.manifest_text)
        checks.validate_dependencies(self.manifest_text, self.lock_text)

    def test_dependency_tampering_fails(self):
        cases = (
            ('anyhow = "1"', 'anyhow = "1"\nevil_crate = "1"', "unreviewed integrated dependency"),
            ('axum = "0.8"', 'axum = "0.9"', "integrated dependency dependencies.axum changed"),
            ('rust-version = "1.88"', 'rust-version = "1.85"', "MSRV"),
        )
        for old, new, message in cases:
            with self.subTest(change=new):
                with self.assertRaisesRegex(ValueError, message):
                    self.check(self.mutated(old, new))
        extra_patch = self.mutated(
            'opendal-service-s3 = { path = "vendor/opendal-service-s3" }',
            'opendal-service-s3 = { path = "vendor/opendal-service-s3" }\nevil = { path = "vendor/evil" }')
        with self.assertRaisesRegex(ValueError, "unreviewed integrated dependency patch.crates-io.evil"):
            self.check(extra_patch)
        repointed = self.mutated(
            "opendal-service-s3 = { path = \"vendor/opendal-service-s3\" }",
            "opendal-service-s3 = { path = \"vendor/evil\" }")
        with self.assertRaisesRegex(ValueError, "vendored source path.opendal-service-s3 must stay at"):
            self.check(repointed)

    def test_default_enabled_or_nonempty_metrics_feature_fails(self):
        cases = (
            ('default = ["kafka-wake"]', 'default = ["kafka-wake", "state-baseline-metrics"]',
             "feature default must stay"),
            ("state-baseline-metrics = []", 'state-baseline-metrics = ["pando-lab"]',
             "feature state-baseline-metrics must stay"),
            ("state-baseline-metrics = []", 'state-baseline-metrics = []\nsurprise = []',
             "integrated features changed"),
        )
        for old, new, message in cases:
            with self.subTest(change=new):
                with self.assertRaisesRegex(ValueError, message):
                    self.check(self.mutated(old, new))

    def test_default_feature_list_is_pinned(self):
        integrated = copy.deepcopy(self.integrated)
        integrated["features"]["default"]["value"] = []
        with self.assertRaisesRegex(ValueError, "feature default must stay"):
            self.check(integrated=integrated)

    def test_lockfile_must_keep_frozen_packages_and_only_recorded_additions(self):
        extra = self.lock_text + (
            '\n[[package]]\nname = "evil-crate"\nversion = "9.9.9"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        with self.assertRaisesRegex(ValueError, "unreviewed additions"):
            self.check(lock_text=extra)
        dropped = self.lock_text.replace('name = "anyhow"\nversion = "1.0.104"',
                                         'name = "anyhow"\nversion = "1.0.99"', 1)
        self.assertNotEqual(dropped, self.lock_text)
        with self.assertRaisesRegex(ValueError, "lockfile lost frozen packages"):
            self.check(lock_text=dropped)
        added = checks.added_lock_packages(
            (ROOT / self.integrated["baseline_lock"]).read_text(encoding="utf-8"), self.lock_text)
        self.assertTrue(set(added) <= set(self.integrated["lock_additions"]))
        # Packages that already appear at another version stay listed so a new
        # second version is reviewed explicitly.
        self.assertNotIn("anyhow", added)
        self.assertIn("hashbrown", set(self.integrated["lock_additions"]) - set(added),
                      "overlapping names are recorded ahead of the lockfile they describe")
        self.assertEqual(len(set(self.integrated["lock_additions"])), len(self.integrated["lock_additions"]),
                         "recorded lock additions must be unique package names")


if __name__ == "__main__":
    unittest.main()
