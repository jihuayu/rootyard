#!/usr/bin/env python3
"""Pure static contracts for the issue #21 Vault qualification wiring.

The workflow is read as checked-in text; the Vault image pin, exact case list,
adapter CLI and native-manifest projection are checked against the actual
source.  No Docker, Vault, PostgreSQL, Cargo, compiler, Git fixture, network
child or real process is started; the adapter inputs below are finite fakes.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_vault_rotation as rotation  # noqa: E402
import pando_vault_rotation_ci_report as adapter  # noqa: E402
import pando_vault_rotation_fixture as vault_fixture  # noqa: E402
from test_ci_issue21_qualification import (  # noqa: E402
    PANDO_CLI_STEP,
    PANDO_PITR_STEP,
    UPLOAD_STEP,
    _flag_value,
    _flag_values,
    _step,
    _steps,
    _unsafe_upload_paths,
    _verify_lines,
)

VAULT_STEP = "Qualify pinned real Vault rotation and bind the Pando native gate"
PRIMARY_MANIFEST_STEP = "Bind native regressions to the built binary and source inputs"


def _vault_run():
    return _step(VAULT_STEP)["run"]


def _manifest_part():
    return _vault_run().split(
        "python3 scripts/native_report_manifest.py", 1
    )[1]


def _expected_harnesses():
    paths = sorted((ROOT / "tests").glob("pando_vault_rotation*.py"))
    paths += sorted((ROOT / "tests").glob("test_pando_vault_rotation*.py"))
    relative = [path.relative_to(ROOT).as_posix() for path in paths]
    relative.extend([
        "scripts/native_build_receipt.py",
        "scripts/native_report_manifest.py",
        "scripts/native_artifact_store.py",
        "scripts/build_native_batch.py",
        "scripts/export_native_artifacts.py",
        ".github/workflows/ci.yml",
    ])
    return relative


def _validated():
    return {
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "source_clean": True,
        "binary_sha256": "c" * 64,
        "receipt_sha256": "d" * 64,
        "harness_sha256": "e" * 64,
    }


def _cleanup():
    return {
        "vault_owned": True, "vault_stopped": True,
        "container_absent": True, "postgres_owned": True,
        "postgres_created": True, "postgres_dropped": True,
        "database_absent": True, "root_owned": True, "root_removed": True,
        "root_absent": True, "server_stopped": True, "cleanup_ok": True,
        "credential_released": True, "pg_major": 17,
        "image_digest_sha256": "f" * 64, "vault_version": "2.2.2",
        "no_global_cleanup": True, "raw_logs_persisted": False,
    }


def _raw():
    cleanup = _cleanup()
    cases = [
        {"id": case_id, "status": "passed", "facts": {}}
        for case_id in adapter.CASE_IDS[:-1]
    ]
    cases.append({
        "id": adapter.CASE_IDS[-1], "status": "passed",
        "code": None, "facts": cleanup,
    })
    return {
        "schema": adapter.REPORT_SCHEMA,
        "passed": True,
        "status": "passed",
        "case_count": 5,
        "cases": cases,
        "binding": {
            "source_commit": "a" * 40, "source_tree": "b" * 40,
            "source_clean": True, "binary_sha256": "c" * 64,
            "receipt_sha256": "d" * 64, "harness_sha256": "e" * 64,
        },
        "cleanup": cleanup,
        "limitations": list(rotation.ALLOWED_LIMITATIONS),
    }


class VaultWorkflowTest(unittest.TestCase):
    def test_vault_step_is_adjacent_mandatory_and_bounded(self):
        names = [step["name"] for step in _steps()]
        self.assertEqual(names.index(VAULT_STEP),
                         names.index(PANDO_CLI_STEP) + 1)
        self.assertLess(names.index(VAULT_STEP), names.index(PANDO_PITR_STEP))
        vault = _step(VAULT_STEP)
        self.assertEqual(vault["timeout-minutes"], "20")
        self.assertIsNone(vault.get("if"))
        self.assertNotIn("continue-on-error", vault)
        run = vault["run"]
        for expected in (
            'python3 tests/pando_vault_rotation.py \\',
            '--binary "$ROOTYARD_PANDO_LAB_BIN" \\',
            '--receipt "$ROOTYARD_PANDO_BUILD_RECEIPT" \\',
            '--source-root "$GITHUB_WORKSPACE" \\',
            '--expected-commit "$GITHUB_SHA" \\',
            "--timeout-seconds 1080 \\",
            "--cleanup-reserve-seconds 90 \\",
            "--report test-results/pando-vault-rotation.json",
            'python3 tests/pando_vault_rotation_ci_report.py \\',
            "--raw-report test-results/pando-vault-rotation.json \\",
            "--output test-results/pando-vault-native-report.json",
            "python3 scripts/native_report_manifest.py --mode job \\",
            "--manifest-out test-results/pando-vault-gate.json \\",
            '--build-receipt "$ROOTYARD_PANDO_BUILD_RECEIPT" \\',
            '--binary "$ROOTYARD_PANDO_LAB_BIN" \\',
            '--expect-commit "$GITHUB_SHA" \\',
            '--expect-batch-manifest-path "$ROOTYARD_BATCH_MANIFEST" \\',
            '--expect-batch-manifest-sha "$ROOTYARD_BATCH_MANIFEST_SHA256" \\',
            "--report pando_vault=test-results/pando-vault-native-report.json \\",
        ):
            self.assertIn(expected, run)
        for forbidden in (
            "--prepare-only", "--job-manifest", "|| true",
            "continue-on-error", "secrets.", "cargo build", "cargo test",
            "python3 scripts/build_native_batch.py",
            "python3 scripts/build_native.py",
        ):
            self.assertNotIn(forbidden, run)

    def test_vault_manifest_is_pando_specific_and_separate(self):
        manifest = _manifest_part()
        self.assertEqual(_flag_value(manifest, "--manifest-out"),
                         "test-results/pando-vault-gate.json")
        self.assertEqual(_flag_value(manifest, "--build-receipt"),
                         '"$ROOTYARD_PANDO_BUILD_RECEIPT"')
        self.assertEqual(_flag_value(manifest, "--binary"),
                         '"$ROOTYARD_PANDO_LAB_BIN"')
        self.assertEqual(_flag_value(manifest, "--expect-batch-manifest-path"),
                         '"$ROOTYARD_BATCH_MANIFEST"')
        self.assertEqual(_flag_value(manifest, "--expect-batch-manifest-sha"),
                         '"$ROOTYARD_BATCH_MANIFEST_SHA256"')
        self.assertEqual(
            _flag_values(manifest, "--report"),
            ["pando_vault=test-results/pando-vault-native-report.json"],
        )
        self.assertNotIn("--job-manifest", manifest)
        self.assertNotIn("ROOTYARD_BIN", manifest)
        self.assertNotIn("ROOTYARD_BUILD_RECEIPT", manifest)
        self.assertNotIn("native-pr-gate", manifest)
        self.assertNotIn("pando_vault=", _step(PRIMARY_MANIFEST_STEP)["run"])

        primary = _step(PRIMARY_MANIFEST_STEP)["run"]
        self.assertIn('--build-receipt "$ROOTYARD_BUILD_RECEIPT"', primary)
        self.assertIn('--binary "$ROOTYARD_BIN"', primary)
        self.assertIn("--manifest-out test-results/native-pr-gate.json", primary)

    def test_vault_requires_all_five_exact_cases(self):
        required = _flag_values(_manifest_part(), "--require-case")
        expected = [
            "pando_vault=" + case_id
            for case_id in rotation.required_cases()
        ]
        self.assertEqual(required, expected)
        self.assertEqual(len(required), 5)
        self.assertEqual(len(set(required)), 5)
        self.assertEqual(tuple(adapter.CASE_IDS), tuple(rotation.required_cases()))
        self.assertEqual(adapter.REPORT_SCHEMA, rotation.REPORT_SCHEMA)

    def test_vault_manifest_binds_complete_harness_set(self):
        harnesses = _flag_values(_manifest_part(), "--harness")
        self.assertEqual(harnesses, _expected_harnesses())
        self.assertEqual(len(harnesses), len(set(harnesses)))
        for relative in harnesses:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_vault_pin_matches_fixture_source(self):
        self.assertEqual(
            vault_fixture.VAULT_IMAGE,
            "hashicorp/vault@sha256:"
            "dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6",
        )
        self.assertEqual(vault_fixture.VAULT_VERSION, "2.2.2")
        run = _vault_run()
        self.assertIn(vault_fixture.VAULT_IMAGE, run)
        self.assertIn("--fixture vault_version=2.2.2", run)
        self.assertIn("--fixture postgres=postgres:17", run)
        self.assertNotIn("user-vault", run)

    def test_upload_includes_vault_reports_and_rejects_unsafe_paths(self):
        upload = _step(UPLOAD_STEP)
        self.assertEqual(upload.get("if"), "always()")
        paths = [line.strip() for line in upload["with"]["path"].splitlines()
                 if line.strip()]
        for expected in (
            "test-results/pando-vault-rotation.json",
            "test-results/pando-vault-native-report.json",
            "test-results/pando-vault-gate.json",
            "test-results/pando-producer-pg.json",
            "${{ env.ROOTYARD_PANDO_BUILD_RECEIPT }}",
            "${{ env.ROOTYARD_BATCH_MANIFEST }}",
        ):
            self.assertIn(expected, paths)
        self.assertEqual(_unsafe_upload_paths(paths), [])

    def test_existing_timeout_oracles_are_unchanged(self):
        expected = {
            "Verify PostgreSQL RefStore registry and metadata-core contracts": "5",
            "Build relocated rootyard library test harness for the PostgreSQL start gate": "10",
            "Verify managed PostgreSQL sandbox start-gate lock order": "10",
            "Build native bins and RefStore fixtures in one batch": "10",
            "Exercise native workspace autocapture acceptance": "20",
            PANDO_PITR_STEP: "10",
            "Exercise webhook fairness": "20",
        }
        for name, timeout in expected.items():
            self.assertEqual(_step(name)["timeout-minutes"], timeout, name)
        self.assertIsNone(_step(PRIMARY_MANIFEST_STEP)["timeout-minutes"])


class VaultAdapterContractTest(unittest.TestCase):
    def test_adapter_cli_and_exact_case_counterexamples(self):
        args = adapter.parse_args([
            "--source-root", str(ROOT),
            "--binary", "rootyard-pando-lab",
            "--receipt", "pando.build.json",
            "--expected-commit", "a" * 40,
            "--raw-report", "test-results/pando-vault-rotation.json",
            "--output", "test-results/pando-vault-native-report.json",
        ])
        self.assertEqual(args.expected_commit, "a" * 40)
        self.assertEqual(args.raw_report,
                         "test-results/pando-vault-rotation.json")

        projection = adapter.project(
            _raw(), "9" * 64, "a" * 40, _validated()
        )
        self.assertEqual(projection["case_count"], 5)
        self.assertEqual(
            [case["name"] for case in projection["cases"]],
            list(adapter.CASE_IDS),
        )

        missing = _raw()
        missing["cases"].pop()
        missing["case_count"] = 4
        with self.assertRaises(adapter.ProjectionError) as caught:
            adapter.project(missing, "9" * 64, "a" * 40, _validated())
        self.assertEqual(caught.exception.code, "raw_report_case_count_mismatch")

        wrong_schema = _raw()
        wrong_schema["schema"] = "rootyard/issue21-derived-vault-rotation/v2"
        with self.assertRaises(adapter.ProjectionError) as caught:
            adapter.project(wrong_schema, "9" * 64, "a" * 40, _validated())
        self.assertEqual(caught.exception.code, "raw_report_schema_mismatch")

        dirty = _raw()
        dirty["binding"]["source_clean"] = False
        with self.assertRaises(adapter.ProjectionError) as caught:
            adapter.project(dirty, "9" * 64, "a" * 40, _validated())
        self.assertEqual(caught.exception.code,
                         "raw_report_binding_source_not_clean")


if __name__ == "__main__":
    unittest.main()
