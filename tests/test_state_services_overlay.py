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

    def assert_reviewed_inputs_reject(self, *, manifest_text=None, lock_text=None):
        """Mutated bytes must fail on the exact pins, then alone on semantics.

        The second call drops only the pin of the untouched input after
        re-hashing the mutated input *inside the recorded contract* to prove
        the semantic checks (not just the byte pin) still reject it.
        """
        text = self.manifest_text if manifest_text is None else manifest_text
        lock = self.lock_text if lock_text is None else lock_text
        with self.assertRaisesRegex(ValueError, "differs from the reviewed integrated (manifest|lockfile)"):
            self.check(text, lock)
        integrated = copy.deepcopy(self.integrated)
        if manifest_text is not None:
            integrated["manifest_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        else:
            integrated["lock_sha256"] = hashlib.sha256(lock.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, r"^(?!current Cargo)"):
            self.check(text, lock, integrated=integrated)

    def test_exact_reviewed_bytes_are_the_primary_pin(self):
        self.check()
        self.assertEqual(hashlib.sha256(self.manifest_text.encode("utf-8")).hexdigest(),
                         self.integrated["manifest_sha256"])
        self.assertEqual(hashlib.sha256(self.lock_text.encode("utf-8")).hexdigest(),
                         self.integrated["lock_sha256"])
        # A review record pointing at other bytes than the reviewed tree fails.
        for key, message in (("manifest_sha256", "reviewed integrated manifest"),
                             ("lock_sha256", "reviewed integrated lockfile")):
            integrated = copy.deepcopy(self.integrated)
            integrated[key] = "0" * 64
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, message):
                    self.check(integrated=integrated)
            integrated = copy.deepcopy(self.integrated)
            del integrated[key]
            with self.subTest(key=key, missing=True):
                with self.assertRaisesRegex(ValueError, "must record the reviewed Cargo.(toml|lock) SHA-256"):
                    self.check(integrated=integrated)

    def mutated(self, old, new):
        return checks.manifest_mutation(self.manifest_text, old, new)

    def rehashed(self, manifest_text):
        """The recorded contract with only the pin moved to the mutated bytes.

        Used to prove the semantic checks still reject; the default tests never
        do this, so mutated Cargo inputs are rejected by the exact pin alone.
        """
        integrated = copy.deepcopy(self.integrated)
        integrated["manifest_sha256"] = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()
        return integrated

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
                self.assert_reviewed_inputs_reject(manifest_text=self.mutated(old, new))
        extra_patch = self.mutated(
            'opendal-service-s3 = { path = "vendor/opendal-service-s3" }',
            'opendal-service-s3 = { path = "vendor/opendal-service-s3" }\nevil = { path = "vendor/evil" }')
        with self.assertRaisesRegex(ValueError, "unreviewed integrated dependency patch.crates-io.evil"):
            self.check(extra_patch, integrated=self.rehashed(extra_patch))
        repointed = self.mutated(
            "opendal-service-s3 = { path = \"vendor/opendal-service-s3\" }",
            "opendal-service-s3 = { path = \"vendor/evil\" }")
        with self.assertRaisesRegex(ValueError, "vendored source path.opendal-service-s3 must stay at"):
            self.check(repointed, integrated=self.rehashed(repointed))

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
                mutated = self.mutated(old, new)
                with self.assertRaisesRegex(ValueError, "differs from the reviewed integrated manifest"):
                    self.check(mutated)
                with self.assertRaisesRegex(ValueError, message):
                    self.check(mutated, integrated=self.rehashed(mutated))

    def test_default_feature_list_is_pinned(self):
        integrated = copy.deepcopy(self.integrated)
        integrated["features"]["default"]["value"] = []
        with self.assertRaisesRegex(ValueError, "feature default must stay"):
            self.check(integrated=integrated)

    def test_exact_feature_lists_allow_no_extra_providers_or_features(self):
        cases = (
            ('reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json"] }',
             'reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json", "cookies"] }',
             "integrated dependency dependencies.reqwest changed"),
            ('features = ["services-s3", "reqwest-rustls-no-provider-tls"',
             'features = ["services-s3", "reqwest-rustls-no-provider-tls", "services-fs"',
             "integrated dependency dependencies.opendal changed"),
            ('fuser = { version = "0.16", default-features = false, features = ["abi-7-31"] }',
             'fuser = { version = "0.16", default-features = true, features = ["abi-7-31"] }',
             "integrated dependency dependencies.fuser changed"),
        )
        for old, new, message in cases:
            with self.subTest(change=new):
                self.assert_reviewed_inputs_reject(manifest_text=self.mutated(old, new))
        # The reviewed request itself still passes unchanged.
        self.check()

    def test_dependency_line_changes_fail_the_exact_pin_and_the_record(self):
        for old, new in (('axum = "0.8"', 'axum = "0.7"'),
                         ('reqwest = { version = "0.12",', 'reqwest = { version = "0.11",')):
            with self.subTest(change=new):
                mutated = self.mutated(old, new)
                with self.assertRaisesRegex(ValueError, "differs from the reviewed integrated manifest"):
                    self.check(mutated)
                # Even a re-hashed review record cannot relocate a crate line.
                with self.assertRaisesRegex(ValueError, "integrated dependency dependencies.(axum|reqwest) changed"):
                    self.check(mutated, integrated=self.rehashed(mutated))

    def test_unreviewed_target_specific_dependency_tables_are_rejected(self):
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            extra = (
                "\n[target.'cfg(windows)'.%s]\nevil_crate = \"1\"\n" % table)
            with self.subTest(table=table):
                self.assert_reviewed_inputs_reject(manifest_text=self.manifest_text + extra)
        # Even a recorded target key cannot be smuggled into the contract.
        integrated = copy.deepcopy(self.integrated)
        integrated["dependencies"][
            "target.'cfg(windows)'.dependencies.evil_crate"] = {"version": "1", "features": [],
                                                                "default_features": True, "optional": False}
        target_text = self.manifest_text + "\n[target.'cfg(windows)'.dependencies]\nevil_crate = \"1\"\n"
        integrated["manifest_sha256"] = hashlib.sha256(target_text.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "unreviewed target-specific integrated dependency"):
            self.check(target_text, integrated=integrated)
        self.assertEqual(checks._dependency_entries(checks.parse_manifest(
            self.manifest_text + "\n[target.'cfg(windows)'.dependencies]\nevil_crate = \"1\"\n")),
            {**checks._dependency_entries(checks.parse_manifest(self.manifest_text)),
             "target.cfg(windows).dependencies.evil_crate": "1"})

    def test_lockfile_is_the_reviewed_file_and_checked_by_package_identity(self):
        self.assertEqual(hashlib.sha256(self.lock_text.encode("utf-8")).hexdigest(),
                         self.integrated["lock_sha256"])
        # A same-name package at a new version, a checksum tamper and a source
        # tamper all fail the exact pin, and still fail identity checks.
        renamed = self.lock_text.replace('name = "anyhow"\nversion = "1.0.104"',
                                         'name = "anyhow"\nversion = "99.0.0"', 1)
        self.assertNotEqual(renamed, self.lock_text)
        checksum = self.lock_text.replace(
            'checksum = "330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470"',
            'checksum = "%s"' % ("0" * 64), 1)
        self.assertNotEqual(checksum, self.lock_text)
        source = self.lock_text.replace('name = "axum"\nversion = "0.8.9"\n'
                                        'source = "registry+https://github.com/rust-lang/crates.io-index"',
                                        'name = "axum"\nversion = "0.8.9"\n'
                                        'source = "git+https://github.com/evil/axum"', 1)
        self.assertNotEqual(source, self.lock_text)
        for mutated, message in ((renamed, "lockfile lost frozen packages"),
                                 (checksum, "lockfile lost frozen packages"),
                                 (source, "lockfile lost frozen packages")):
            with self.subTest(case=message):
                with self.assertRaisesRegex(ValueError, "reviewed integrated lockfile"):
                    self.check(lock_text=mutated)
                integrated = copy.deepcopy(self.integrated)
                integrated["lock_sha256"] = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
                with self.assertRaisesRegex(ValueError, message):
                    self.check(lock_text=mutated, integrated=integrated)
        # Same name, new (non-frozen) version: rejected as an unreviewed pair.
        relocated = self.lock_text.replace('name = "wasm-streams"\nversion = "0.5.0"',
                                           'name = "wasm-streams"\nversion = "0.5.1"', 1)
        self.assertNotEqual(relocated, self.lock_text)
        integrated = copy.deepcopy(self.integrated)
        integrated["lock_sha256"] = hashlib.sha256(relocated.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "unreviewed additions"):
            self.check(lock_text=relocated, integrated=integrated)

    def test_recorded_lock_additions_are_explicit_name_version_pairs(self):
        frozen = checks.lock_package_identities(
            (ROOT / self.integrated["baseline_lock"]).read_text(encoding="utf-8"))
        present = checks.lock_package_identities(self.lock_text)
        added = sorted([name, version] for name, version, _, _ in present - frozen)
        self.assertTrue(all(isinstance(pair, list) and len(pair) == 2 for pair in self.integrated["lock_additions"]))
        self.assertEqual(added, self.integrated["lock_additions"])
        self.assertEqual(len({tuple(pair) for pair in added}), len(added), "additions must be unique")
        self.assertIn(["rand", "0.8.8"], added)
        self.assertNotIn(["anyhow", "1.0.104"], added, "frozen packages are not additions")
        extra = self.lock_text + (
            '\n[[package]]\nname = "evil-crate"\nversion = "9.9.9"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "' + "0" * 64 + '"\n')
        with self.assertRaisesRegex(ValueError, "reviewed integrated lockfile"):
            self.check(lock_text=extra)


if __name__ == "__main__":
    unittest.main()
