"""Pure boundary tests for the AC2 Pando archive/restore service harness (#77)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_backup_restore_service as ac2  # noqa: E402
import pando_pitr_physical_service as ac1  # noqa: E402
import pando_pitr_service as binding  # noqa: E402
from test_native_build_receipt_v2 import ReceiptFixture  # noqa: E402

COMMIT = "a" * 40


class Ac2SpecBoundaryTest(ReceiptFixture):
    def setUp(self) -> None:
        super().setUp()
        self.commit = COMMIT
        self.receipt_path = self.binary.with_suffix(".build.json")
        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit), indent=2) + "\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.harness = self.root / "ac2-service-harness.py"
        self.harness.write_text("AC2_HARNESS_VERSION = 1\n", encoding="utf-8")
        self.report_path = self.root / "ac2-service-report.json"
        patch = mock.patch.object(
            binding,
            "_workspace_head",
            lambda source_root, phase="preflight": self.commit,
        )
        patch.start()
        self.addCleanup(patch.stop)

    def results(self) -> dict:
        results = {name: True for name in ac2.AC2_MANDATORY_CASES}
        results["passed"] = True
        return results

    def _run_bound(self, results=None, extra=None):
        return binding.run_acceptance(
            binary=str(self.binary),
            build_receipt=str(self.receipt_path),
            expect_commit=self.commit,
            report_path=self.report_path,
            source_root=self.root,
            harness_files=[self.harness],
            suite=lambda binary: results or self.results(),
            spec=ac2.AC2_SPEC,
            extra_report=extra,
        )

    def test_ac2_case_inventory_is_exact(self) -> None:
        self.assertEqual(ac2.AC2_SPEC.mandatory_cases, ac2.AC2_MANDATORY_CASES)
        self.assertEqual(len(ac2.AC2_MANDATORY_CASES), 7)
        self.assertIn("rootyard/pando-backup-restore-service-acceptance", ac2.AC2_SPEC.kind)
        self.assertIn(f"format {ac2.schema_baseline.CURRENT_BACKUP_FORMAT}", json.dumps(ac2.AC2_SPEC.topology))

    def test_missing_or_false_ac2_case_cannot_pass(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                results = self.results()
                if missing:
                    del results["active_pin_reissued_under_new_authority_and_closure_remains_readable"]
                else:
                    results["archive_current_pando_only_and_backup_verify_passed"] = False
                report = self._run_bound(results, {"source_tree": "b" * 40})
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["code"], "mandatory_case_not_passed")
                self.assertEqual([case["name"] for case in report["cases"]],
                                 list(ac2.AC2_MANDATORY_CASES))
                status = "missing" if missing else "failed"
                self.assertIn(
                    {"name": "active_pin_reissued_under_new_authority_and_closure_remains_readable"
                     if missing else "archive_current_pando_only_and_backup_verify_passed",
                     "status": status},
                    report["cases"],
                )

    def test_all_ac2_cases_and_safe_extra_pass(self) -> None:
        extra = {
            "source_tree": "c" * 40,
            "archive": {"format": ac2.schema_baseline.CURRENT_BACKUP_FORMAT, "backup_verify_passed": True},
            "authority": {"authority_rotated": True, "generation_reset": 1},
            "permissions": {"source": {"owner_read": True}, "restored": {"owner_write": True}},
            "cleanup": {"services_stopped": True, "proxy_stopped": True},
        }
        report = self._run_bound(extra=extra)
        self.assertTrue(report["passed"])
        self.assertEqual(report["kind"], ac2.AC2_SPEC.kind)
        self.assertEqual(report["expected_cases"], list(ac2.AC2_MANDATORY_CASES))
        self.assertEqual([case["name"] for case in report["cases"]],
                         list(ac2.AC2_MANDATORY_CASES))
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        for name in ac2.AC2_MANDATORY_CASES:
            self.assertIs(report[name], True)
        self.assertEqual(report["source_tree"], "c" * 40)
        self.assertEqual(json.loads(self.report_path.read_text(encoding="utf-8")), report)

    def test_archive_contract_rejects_old_or_incomplete_metadata(self) -> None:
        current = ac2.schema_baseline.CURRENT_BACKUP_FORMAT
        schema = list(ac2.schema_baseline.SCHEMA_VERSIONS)
        self.assertTrue(ac2._archive_contract_matches(
            current, schema, complete=True, blob_artifacts=0, pando_only=True))
        self.assertFalse(ac2._archive_contract_matches(
            23, schema, complete=True, blob_artifacts=0, pando_only=True))
        self.assertFalse(ac2._archive_contract_matches(
            current, schema[:-1], complete=True, blob_artifacts=0, pando_only=True))
        self.assertFalse(ac2._archive_contract_matches(
            current, schema, complete=False, blob_artifacts=0, pando_only=True))
        self.assertFalse(ac2._archive_contract_matches(
            current, schema, complete=True, blob_artifacts=1, pando_only=False))

    def test_extra_report_cannot_override_core_fields(self) -> None:
        report = self._run_bound(extra={"passed": True, "cases": []})
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["code"], "extra_invalid")
        self.assertEqual([case["name"] for case in report["cases"]],
                         list(ac2.AC2_MANDATORY_CASES))

    def test_provider_endpoint_consistency_helpers_and_binding(self) -> None:
        endpoint = "http://127.0.0.1:3900"
        first = {"ROOTYARD_OBJECT_STORE_ENDPOINT": endpoint}
        second = {"ROOTYARD_OBJECT_STORE_ENDPOINT": endpoint}
        different = {"ROOTYARD_OBJECT_STORE_ENDPOINT": "http://127.0.0.1:3901"}
        self.assertTrue(ac2._same_provider_endpoint([first, second]))
        self.assertFalse(ac2._same_provider_endpoint([first, different]))
        self.assertFalse(ac2._same_provider_endpoint([{}]))
        self.assertRegex(ac2._endpoint_hash(endpoint), r"^[0-9a-f]{64}$")
        self.assertEqual(ac2._endpoint_hash(endpoint), ac2._endpoint_hash(endpoint))
        self.assertIn(ac1.GARAGE_FIXTURE, ac2.HARNESS_FILES)
        self.assertIn(ac2.ROOT / "tests/schema_baseline.py", ac2.HARNESS_FILES)
        self.assertEqual(len(ac2.AC2_MANDATORY_CASES), 7)

    def test_ac2_preflight_binds_exact_garage_pin(self) -> None:
        pin = ac1._owned_garage_pin()
        env = {
            "ROOTYARD_OBJECT_STORE_ENDPOINT": "http://127.0.0.1:3900",
            "ROOTYARD_OBJECT_STORE_BUCKET": "ac2-bound",
            "ROOTYARD_OBJECT_STORE_REGION": "garage",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY": "access",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY": "secret",
            "ROOTYARD_KMS_VAULT_URL": "http://127.0.0.1:8200",
            "ROOTYARD_KMS_VAULT_TOKEN": "token",
            "ROOTYARD_KMS_VAULT_KEY": "key",
            "ROOTYARD_GARAGE_IMAGE_DIGEST": pin,
            "ROOTYARD_VAULT_IMAGE_DIGEST": ac1.VAULT_IMAGE_PIN,
        }
        config, metadata = ac2.ac1.preflight_providers(env)
        self.assertEqual(config.garage_image, pin)
        self.assertEqual(metadata["garage_image_digest"], pin)
        with self.assertRaises(ac1.PhysicalFailure) as wrong:
            ac2.ac1.preflight_providers(dict(
                env, ROOTYARD_GARAGE_IMAGE_DIGEST="garage@sha256:" + "4" * 64))
        self.assertEqual((wrong.exception.stage, wrong.exception.code),
                         ("providers", "garage_image_pin_mismatch"))

    def test_no_provider_ac2_suite_does_not_launch_fixtures(self) -> None:
        with mock.patch.object(ac2, "PhysicalPitrFixture") as fixture:
            cases, extra = ac2.run_ac2_suite("/unused-rootyard", Path("/unused-pg"), {})
        fixture.assert_not_called()
        self.assertTrue(set(ac2.AC2_MANDATORY_CASES).issubset(cases))
        self.assertFalse(any(cases[name] for name in ac2.AC2_MANDATORY_CASES))
        self.assertIs(cases["passed"], False)
        self.assertEqual(extra["physical_failure"]["stage"], "providers")
        self.assertEqual(extra["physical_failure"]["code"], "missing_environment")
        self.assertFalse(cases["all_owned_resources_cleaned"])
        self.assertIsNone(extra["cleanup"]["source_fixture"])
        self.assertIsNone(extra["cleanup"]["target_fixture"])


if __name__ == "__main__":
    unittest.main()
