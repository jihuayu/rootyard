#!/usr/bin/env python3
"""Pure wiring and collector checks for the #82 legacy135 hosted gate.

No workflow, Docker, Cargo, PostgreSQL, Git client or provider runs here.  The
tests pin the dedicated-job boundary, exact frozen source, safe upload set,
full seven-case collector and fail-closed receipt/provider roles.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TESTS = ROOT / "tests"
for entry in (str(SCRIPTS), str(TESTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import legacy135_qualification as gate  # noqa: E402
import legacy135_qualification_manifest as collector  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "legacy-token-restore.yml"
CANDIDATE_COMMIT = "c" * 40
CANDIDATE_SHA = "a" * 64
PRODUCER_SHA = "b" * 64
FROZEN = collector.FROZEN_SOURCE_COMMIT


def qualification():
    return {
        "schema": "rootyard/issue82-legacy135-qualification/v1",
        "kind": "rootyard/issue82-legacy135-qualification",
        "issue": 82,
        "passed": True,
        "case_count": 7,
        "cases": [{"name": name, "status": "passed"}
                  for name in collector.CASE_NAMES],
        "target": {"schema": collector.CURRENT_SCHEMA_VERSION,
                   "format": collector.CURRENT_BACKUP_FORMAT},
        "candidate": {
            "binary_sha256": CANDIDATE_SHA,
            "source": {"commit": CANDIDATE_COMMIT, "tree": "d" * 40,
                       "clean": True},
        },
        "producer": {
            "binary_sha256": PRODUCER_SHA,
            "source": {"commit": FROZEN, "tree": "e" * 40, "clean": True},
            "source_format": 11,
            "source_schema": 135,
        },
        "provider": provider(),
        "bindings": {},
    }


def provider():
    return {
        "schema": "rootyard/issue82-legacy135-provider/v1",
        "kind": "owned-loopback-vault-transit",
        "image_digest": gate.VAULT_IMAGE,
        "vault_version": gate.VAULT_VERSION,
        "transit_round_trip": True,
        "service_policy_scoped": True,
        "owned_container": True,
        "raw_logs_persisted": False,
        "credential_file_written": False,
        "cleanup": "stopped",
    }


def candidate_receipt():
    return {"receipt_schema": receipts.RECEIPT_SCHEMA_V2,
            "binary_sha256": CANDIDATE_SHA,
            "workspace_commit": CANDIDATE_COMMIT}


def producer_receipt():
    return {"binary_sha256": PRODUCER_SHA,
            "workspace_commit": FROZEN}


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.qualification = self.root / "qualification.json"
        self.provider_report = self.root / "provider.json"
        self.candidate_receipt = self.root / "candidate.build.json"
        self.producer_receipt = self.root / "producer.build.json"
        self.write()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, qualification_value=None, provider_value=None,
              candidate_value=None, producer_value=None, candidate_path=None,
              producer_path=None):
        qualification_value = (qualification() if qualification_value is None
                               else qualification_value)
        provider_value = provider() if provider_value is None else provider_value
        candidate_path = candidate_path or self.candidate_receipt
        producer_path = producer_path or self.producer_receipt
        candidate_path.write_text(json.dumps(
            candidate_receipt() if candidate_value is None else candidate_value))
        producer_path.write_text(json.dumps(
            producer_receipt() if producer_value is None else producer_value))
        qualification_value["provider"] = provider_value
        qualification_value["candidate"]["receipt_sha256"] = (
            collector.sha256_file(candidate_path))
        qualification_value["producer"]["receipt_sha256"] = (
            collector.sha256_file(producer_path))
        self.qualification.write_text(json.dumps(qualification_value))
        self.provider_report.write_text(json.dumps(provider_value))

    def args(self, candidate_path=None, producer_path=None):
        return argparse.Namespace(
            qualification=str(self.qualification),
            provider_report=str(self.provider_report),
            candidate_receipt=str(candidate_path or self.candidate_receipt),
            producer_receipt=str(producer_path or self.producer_receipt),
            expected_candidate_commit=CANDIDATE_COMMIT,
            expected_producer_commit=FROZEN,
            workflow=str(WORKFLOW),
            wrapper=str(ROOT / "tests" / "legacy135_qualification.py"),
        )

    def reject(self, code, **kwargs):
        if kwargs:
            self.write(**kwargs)
        with self.assertRaises(collector.CollectorError) as caught:
            collector.collect(self.args(
                kwargs.get("candidate_path"), kwargs.get("producer_path")))
        self.assertEqual(caught.exception.code, code)

    def test_valid_manifest_binds_separate_receipt_roles_and_seven_cases(self):
        manifest = collector.collect(self.args())
        self.assertTrue(manifest["passed"])
        self.assertEqual(manifest["case_count"], 7)
        self.assertEqual([case["name"] for case in manifest["cases"]],
                         list(collector.CASE_NAMES))
        self.assertEqual(manifest["candidate"]["binary_sha256"], CANDIDATE_SHA)
        self.assertEqual(manifest["producer"]["binary_sha256"], PRODUCER_SHA)
        self.assertEqual(
            manifest["candidate"]["receipt_sha256"],
            collector.sha256_file(self.candidate_receipt))
        self.assertEqual(
            manifest["producer"]["receipt_sha256"],
            collector.sha256_file(self.producer_receipt))
        self.assertTrue(manifest["receipts_role_separated"])
        self.assertFalse(manifest["raw_logs_uploaded"])
        self.assertFalse(manifest["archive_bytes_uploaded"])

    def test_missing_extra_or_skipped_case_fails(self):
        missing = qualification()
        missing["cases"] = missing["cases"][:-1]
        self.reject("case_count_invalid", qualification_value=missing)
        skipped = qualification()
        skipped["cases"][3]["status"] = "skipped"
        self.reject("case_not_green", qualification_value=skipped)
        renamed = qualification()
        renamed["cases"][3]["name"] = "optional_case"
        self.reject("case_names_mismatch", qualification_value=renamed)
        extra = qualification()
        extra["cases"].append({"name": "extra", "status": "passed"})
        self.reject("case_count_invalid", qualification_value=extra)

    def test_wrong_target_or_not_passed_fails(self):
        target = qualification()
        target["target"]["schema"] = 148
        self.reject("target_schema_invalid", qualification_value=target)
        not_passed = qualification()
        not_passed["passed"] = False
        self.reject("qualification_not_passed", qualification_value=not_passed)
        fmt = qualification()
        fmt["target"]["format"] = 20
        self.reject("target_format_invalid", qualification_value=fmt)

    def test_mutated_candidate_receipt_bytes_are_rejected(self):
        self.write()
        changed = candidate_receipt()
        changed["note"] = "changed receipt bytes"
        self.candidate_receipt.write_text(json.dumps(changed))
        with self.assertRaises(collector.CollectorError) as caught:
            collector.collect(self.args())
        self.assertEqual(caught.exception.code,
                         "candidate_receipt_digest_mismatch")

    def test_mutated_producer_receipt_bytes_are_rejected(self):
        self.write()
        changed = producer_receipt()
        changed["note"] = "changed receipt bytes"
        self.producer_receipt.write_text(json.dumps(changed))
        with self.assertRaises(collector.CollectorError) as caught:
            collector.collect(self.args())
        self.assertEqual(caught.exception.code,
                         "producer_receipt_digest_mismatch")

    def test_qualification_receipt_digests_are_mandatory_sha256(self):
        for role, code in (
            ("candidate", "candidate_qualification_receipt_sha_invalid"),
            ("producer", "producer_qualification_receipt_sha_invalid"),
        ):
            for value in (None, "not-a-sha256"):
                with self.subTest(role=role, value=value):
                    self.write()
                    payload = json.loads(self.qualification.read_text())
                    if value is None:
                        payload[role].pop("receipt_sha256")
                    else:
                        payload[role]["receipt_sha256"] = value
                    self.qualification.write_text(json.dumps(payload))
                    with self.assertRaises(collector.CollectorError) as caught:
                        collector.collect(self.args())
                    self.assertEqual(caught.exception.code, code)

    def test_candidate_and_producer_receipts_must_stay_role_separated(self):
        wrong_candidate = candidate_receipt()
        wrong_candidate["workspace_commit"] = "d" * 40
        self.reject("candidate_receipt_commit_mismatch",
                    candidate_value=wrong_candidate)
        wrong_producer = producer_receipt()
        wrong_producer["workspace_commit"] = "d" * 40
        self.reject("producer_receipt_commit_mismatch",
                    producer_value=wrong_producer)
        v1_candidate = candidate_receipt()
        v1_candidate.pop("receipt_schema")
        self.reject("candidate_receipt_not_v2", candidate_value=v1_candidate)
        self.reject("receipt_roles_reused", candidate_path=self.producer_receipt,
                    producer_path=self.producer_receipt)

    def test_provider_must_be_exact_owned_preflight_and_cleanup(self):
        wrong_image = provider()
        wrong_image["image_digest"] = "hashicorp/vault:latest"
        self.reject("provider_image_invalid", provider_value=wrong_image)
        deferred = provider()
        deferred["cleanup"] = "deferred"
        self.reject("provider_cleanup_not_stopped", provider_value=deferred)
        not_owned = provider()
        not_owned["owned_container"] = False
        self.reject("provider_not_owned", provider_value=not_owned)

    def test_unsafe_fields_and_secret_values_are_rejected(self):
        unsafe = qualification()
        unsafe["token"] = "not-allowed"
        self.reject("unsafe_field_present", qualification_value=unsafe)
        secret = "collector-secret-value"
        leaked = qualification()
        leaked["note"] = secret
        with mock.patch.dict(os.environ,
                             {"ROOTYARD_OBJECT_STORE_SECRET_KEY": secret}):
            self.reject("secret_value_present", qualification_value=leaked)


class WorkflowContractTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_dedicated_job_is_not_appended_to_the_75_minute_verify_job(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertNotIn("legacy-token-restore", ci)
        self.assertNotIn("backup_legacy135_scopes.py", ci)
        self.assertIn("legacy-token-restore:", self.text)
        self.assertIn("runs-on: ubuntu-22.04", self.text)
        self.assertIn("timeout-minutes: 50", self.text)
        self.assertNotIn("continue-on-error", self.text)
        self.assertNotIn("if: false", self.text)

    def test_pinned_toolchain_providers_and_exact_source_are_present(self):
        for needle in (
            "postgres:17",
            "scripts/install_ci_native_tools.sh install",
            "rustup toolchain install 1.99.1",
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/owned_garage_fixture.sh start",
            "scripts/owned_garage_fixture.sh stop",
            "560e96f41f1d4670bfb5d2459af7af459eca4823",
            "LEGACY135_SOURCE_SHA",
        ):
            self.assertIn(needle, self.text)

    def test_candidate_and_producer_are_prepared_separately(self):
        self.assertIn("python3 scripts/build_native.py", self.text)
        self.assertIn("--artifact-store", self.text)
        self.assertIn("--output \"$candidate_dir/rootyard\"", self.text)
        self.assertIn("python3 scripts/prepare_legacy135_producer.py", self.text)
        self.assertIn("--source-dir \"$RUNNER_TEMP/legacy135-producer/source\"", self.text)
        self.assertIn("--candidate-source-root \"$GITHUB_WORKSPACE\"", self.text)
        self.assertIn("--expected-candidate-commit \"$GITHUB_SHA\"", self.text)
        self.assertIn("--expected-producer-commit \"$LEGACY135_SOURCE_SHA\"", self.text)
        self.assertIn("--producer-receipt \"$LEGACY135_PRODUCER_RECEIPT\"", self.text)
        self.assertIn("tests/legacy135_qualification.py", self.text)
        self.assertIn("legacy135_qualification_manifest.py", self.text)

    def test_cleanup_is_always_and_artifacts_are_safe_only(self):
        self.assertGreaterEqual(self.text.count("if: always()"), 2)
        self.assertIn("--cleanup-owned-state \"$RUNNER_TEMP/legacy135-vault-state.json\"",
                      self.text)
        upload = self.text[self.text.index("uses: actions/upload-artifact@v4"):]
        for safe in (
            "test-results/legacy135-qualification.json",
            "test-results/legacy135-provider.json",
            "test-results/legacy135-producer-prep.json",
            "test-results/legacy135-hosted-manifest.json",
            "test-results/legacy135/native-tools-phase.json",
        ):
            self.assertIn(safe, upload)
        for forbidden in (".env", "server.log", "archive", "target/",
                          "legacy135-producer/source", "data/", "*.log"):
            self.assertNotIn(forbidden, upload)

    def test_native_tool_steps_record_the_exact_phase_sidecar(self):
        record = "--phase-record test-results/legacy135/native-tools-phase.json"
        self.assertEqual(self.text.count(record), 2)
        install = self._step_block(self.text, "Install the reviewed native tool profile")
        verify = self._step_block(self.text, "Verify the native tool profile")
        for block in (install, verify):
            self.assertIn(record, block)
            self.assertIn(
                "--provenance test-results/legacy135/native-tools.json", block)
            self.assertNotIn("continue-on-error", block)
            self.assertNotIn("retry", block.lower())
        self.assertIn("timeout-minutes: 20", install)
        self.assertIn("timeout-minutes: 5", verify)
        upload = self._step_block(
            self.text, "Upload safe legacy135 qualification metadata")
        self.assertIn("if: always()", upload)
        paths = upload.split("path: |", 1)[1]
        self.assertEqual(
            paths.count("test-results/legacy135/native-tools-phase.json"), 1)
        self.assertNotIn("test-results/legacy135/native-tools-phase*", paths)

    @staticmethod
    def _step_block(text, name):
        marker = f"      - name: {name}"
        start = text.index(marker) + len(marker)
        rest = text[start:]
        end = rest.find("\n      - name: ")
        return rest if end == -1 else rest[:end]

    def test_trigger_paths_cover_source_auth_backup_schema_and_helpers(self):
        for path in (
            ".github/workflows/legacy-token-restore.yml",
            "src/**",
            "migrations/**",
            "schema/**",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "tests/backup.py",
            "tests/backup_legacy132_sessions.py",
            "tests/backup_legacy135_scopes.py",
            "tests/e2e.py",
            "tests/native_evidence.py",
            "tests/owned_fuse_cleanup.py",
            "tests/schema_baseline.py",
            "tests/legacy135_qualification.py",
            "scripts/prepare_legacy135_producer.py",
            "scripts/legacy135_qualification_manifest.py",
            "scripts/owned_garage_fixture.sh",
        ):
            self.assertIn(path, self.text)

    def test_workflow_is_valid_yaml_when_parser_is_available(self):
        try:
            import yaml
        except ImportError:
            return
        document = yaml.safe_load(self.text)
        self.assertIsInstance(document, dict)
        self.assertIn("legacy-token-restore", document["jobs"])
        events = document.get("on", document.get(True))
        self.assertIn("pull_request", events)
        self.assertIn("workflow_dispatch", events)


if __name__ == "__main__":
    unittest.main()
