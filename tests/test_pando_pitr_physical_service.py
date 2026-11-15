"""Pure boundary tests for the AC1 physical Pando service harness (#77)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_physical_service as physical  # noqa: E402
import pando_pitr_service as binding  # noqa: E402
from test_native_build_receipt_v2 import ReceiptFixture  # noqa: E402

COMMIT = "a" * 40


class PhysicalSpecBoundaryTest(ReceiptFixture):
    def setUp(self) -> None:
        super().setUp()
        self.commit = COMMIT
        self.receipt_path = self.binary.with_suffix(".build.json")
        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit), indent=2) + "\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.harness = self.root / "physical-service-harness.py"
        self.harness.write_text("HARNESS_VERSION = 1\n", encoding="utf-8")
        self.report_path = self.root / "physical-service-report.json"
        patch = mock.patch.object(
            binding,
            "_workspace_head",
            lambda source_root, phase="preflight": self.commit,
        )
        patch.start()
        self.addCleanup(patch.stop)

    def results(self) -> dict:
        results = {name: True for name in physical.PHYSICAL_MANDATORY_CASES}
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
            spec=physical.PHYSICAL_SPEC,
            extra_report=extra,
        )

    def test_physical_spec_inventory_is_exact_and_nonempty(self) -> None:
        self.assertEqual(physical.PHYSICAL_SPEC.mandatory_cases,
                         physical.PHYSICAL_MANDATORY_CASES)
        self.assertTrue(physical.PHYSICAL_SPEC.mandatory_cases)
        self.assertIn("rootyard/pando-pitr-physical-service-acceptance",
                      physical.PHYSICAL_SPEC.kind)
        self.assertIn("real owned Garage", json.dumps(physical.PHYSICAL_SPEC.topology))

    def test_missing_or_false_physical_case_cannot_pass(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                results = self.results()
                if missing:
                    del results["real_service_stock_git_clone_fetch_fsck"]
                else:
                    results["stale_clone_fenced_before_remote_delete"] = False
                report = self._run_bound(results, {"source_tree": "b" * 40})
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["code"], "mandatory_case_not_passed")
                self.assertEqual(
                    [case["name"] for case in report["cases"]],
                    list(physical.PHYSICAL_MANDATORY_CASES),
                )
                status = "missing" if missing else "failed"
                self.assertIn(
                    {"name": "real_service_stock_git_clone_fetch_fsck" if missing
                     else "stale_clone_fenced_before_remote_delete", "status": status},
                    report["cases"],
                )
                self.assertEqual(report["source_tree"], "b" * 40)

    def test_all_physical_cases_and_safe_extra_fields_pass(self) -> None:
        extra = {
            "source_tree": "c" * 40,
            "providers": {"garage_image_digest": "sha256:" + "d" * 64,
                          "vault_image_digest": physical.VAULT_IMAGE_PIN},
            "artifact_baseline": [{"category": "live", "locator_sha256": "e" * 64}],
            "cleanup": {"all_service_children_stopped": True},
        }
        report = self._run_bound(extra=extra)
        self.assertTrue(report["passed"])
        self.assertEqual(report["kind"], physical.PHYSICAL_SPEC.kind)
        self.assertEqual(report["expected_cases"], list(physical.PHYSICAL_MANDATORY_CASES))
        self.assertEqual([case["name"] for case in report["cases"]],
                         list(physical.PHYSICAL_MANDATORY_CASES))
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        for name in physical.PHYSICAL_MANDATORY_CASES:
            self.assertIs(report[name], True)
        self.assertEqual(report["source_tree"], "c" * 40)
        self.assertEqual(report["providers"], extra["providers"])
        self.assertEqual(json.loads(self.report_path.read_text(encoding="utf-8")), report)

    def test_extra_report_cannot_override_core_physical_fields(self) -> None:
        report = self._run_bound(extra={"passed": True, "cases": []})
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["code"], "extra_invalid")
        self.assertEqual([case["name"] for case in report["cases"]],
                         list(physical.PHYSICAL_MANDATORY_CASES))

    def test_provider_preflight_missing_or_wrong_pin_fails_closed(self) -> None:
        with self.assertRaises(physical.PhysicalFailure) as missing:
            physical.preflight_providers({})
        self.assertEqual((missing.exception.stage, missing.exception.code),
                         ("providers", "missing_environment"))

        base = {
            "ROOTYARD_OBJECT_STORE_ENDPOINT": "http://127.0.0.1:3900",
            "ROOTYARD_OBJECT_STORE_BUCKET": "bucket",
            "ROOTYARD_OBJECT_STORE_REGION": "garage",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY": "ak",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY": "sk",
            "ROOTYARD_KMS_VAULT_URL": "http://127.0.0.1:8200",
            "ROOTYARD_KMS_VAULT_TOKEN": "token",
            "ROOTYARD_KMS_VAULT_KEY": "pando",
            "ROOTYARD_GARAGE_IMAGE_DIGEST": "garage@sha256:" + "1" * 64,
            "ROOTYARD_VAULT_IMAGE_DIGEST": "vault@sha256:" + "2" * 64,
        }
        with self.assertRaises(physical.PhysicalFailure) as wrong:
            physical.preflight_providers(base)
        self.assertEqual((wrong.exception.stage, wrong.exception.code),
                         ("providers", "vault_image_pin_mismatch"))

    def test_no_provider_physical_suite_does_not_launch(self) -> None:
        with mock.patch.object(physical, "PhysicalPitrFixture") as fixture:
            cases, extra = physical.run_physical_suite(
                "/unused-rootyard", Path("/unused-pg"), {}
            )
        fixture.assert_not_called()
        self.assertTrue(set(physical.PHYSICAL_MANDATORY_CASES).issubset(cases))
        self.assertFalse(any(cases[name] for name in physical.PHYSICAL_MANDATORY_CASES))
        self.assertIs(cases["passed"], False)
        self.assertEqual(extra["physical_failure"]["stage"], "providers")
        self.assertEqual(extra["physical_failure"]["code"], "missing_environment")


if __name__ == "__main__":
    unittest.main()
