#!/usr/bin/env python3
"""Pure regressions for the dual-case #42 slot-one handoff qualification.

No Cargo, rustc, database, Blob service, network, native binary or workflow
runner is touched.  The focused cases pin the two exact selectors, serial
one-probe-per-case execution, the closed manifest, the safe label/no-path
policy and the scoped workflow wiring.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import refstore_issue42_slot_one_checkpoint as checkpoint  # noqa: E402
import refstore_issue42_slot_one_handoff_qualification as qualification  # noqa: E402

HEAD = "1" * 40
TREE = "2" * 40
DIGEST = "a" * 64
HANDOFF_REF = (
    "refs/heads/codex/goal-issue42-slot-one-handoff-qualification-20261119"
)
LEGACY_REF = (
    "refs/heads/codex/goal-issue42-original-ac-source-audit-20261117"
)
PASSED = {
    "ran": 1, "complete": True, "passed": 1, "failed": 0, "ignored": 0,
    "error_class": None,
}
FAILED = {
    "ran": 1, "complete": False, "passed": 0, "failed": 1, "ignored": 0,
    "error_class": "case_failed",
}
SKIPPED = {
    "ran": 0, "complete": False, "passed": 0, "failed": 1, "ignored": 1,
    "error_class": "case_skipped",
}


def attestation(case, **overrides):
    values = {
        "schema": qualification.CASE_SCHEMA,
        "case": case,
        "expected_commit": HEAD,
        "head": HEAD,
        "tree": TREE,
        "source_inputs_sha256": DIGEST,
        "lib_test_support_inputs_sha256": DIGEST,
        "receipt_sha256": DIGEST,
        "binary_sha256": DIGEST,
        "lib_alias": "/tmp/verified-libtest",
        "preflight_sha256": DIGEST,
        "selection": "unique",
    }
    values.update(overrides)
    return values


def report(case, projection=PASSED, **overrides):
    source = attestation(case, **overrides)
    checkpoint.apply_lib_alias_label(source, qualification.LIB_LABEL)
    return checkpoint.make_report(
        source, projection, 0 if projection["complete"] else 1,
        "exited", schema=qualification.CASE_SCHEMA, case=case)


def runner_factory(projections=None, overrides=None):
    projections = projections or {}
    overrides = overrides or {}
    calls = []

    def runner(namespace):
        calls.append(namespace)
        if namespace.case in projections and projections[namespace.case] is None:
            raise checkpoint.CheckpointError("preflight_binary_sha256")
        projection = projections.get(namespace.case, PASSED)
        payload = report(namespace.case, projection,
                         **overrides.get(namespace.case, {}))
        checkpoint.write_report(namespace.report, payload)
        return payload

    return runner, calls


class InventoryTests(unittest.TestCase):
    def test_inventory_is_exactly_the_two_reviewed_gateway_cases(self):
        self.assertEqual(
            qualification.CASES,
            (
                "ref_store::pg::slot_one::tests::native::gateway::"
                "slot_one_handoff_commits_fresh_private_attempt_on_real_a3_a4_a5",
                "ref_store::pg::slot_one::tests::native::gateway::"
                "slot_one_handoff_revoked_fresh_rolls_back_and_replays_after_later_gate",
            ))
        self.assertEqual(qualification.PROBE_COUNT, 2)
        self.assertEqual(len(qualification.REPORTS), 2)

    def test_each_case_uses_a_separate_exact_ignored_invocation(self):
        for case in qualification.CASES:
            self.assertEqual(
                checkpoint.exact_command("/tmp/libtest", case),
                ["/tmp/libtest", "--ignored", "--exact", case,
                 "--test-threads=1"])

    def test_fixed_lib_label_replaces_the_verified_path_only_when_requested(self):
        source = attestation(qualification.CASES[0])
        self.assertIs(
            checkpoint.apply_lib_alias_label(source, qualification.LIB_LABEL),
            source)
        self.assertEqual(source["lib_alias"], qualification.LIB_LABEL)
        self.assertNotIn("/", source["lib_alias"])
        legacy = attestation(qualification.CASES[0])
        checkpoint.apply_lib_alias_label(legacy, None)
        self.assertEqual(legacy["lib_alias"], "/tmp/verified-libtest")
        for bad in ("/tmp/libtest", "C:\\libtest", "", "has space", "a" * 65):
            with self.subTest(label=bad):
                with self.assertRaises(checkpoint.CheckpointError) as raised:
                    checkpoint.apply_lib_alias_label(
                        attestation(qualification.CASES[0]), bad)
                self.assertEqual(str(raised.exception), "lib_alias_label")

    def test_case_and_report_names_are_safe_labels_not_paths(self):
        for case in qualification.CASES:
            self.assertNotIn("/", case)
            self.assertIn("::native::gateway::", case)
        for label in qualification.REPORTS:
            self.assertNotIn("/", label)
            self.assertTrue(label.endswith(".json"))
        self.assertRegex(qualification.LIB_LABEL, r"^[A-Za-z0-9._#-]{1,64}$")


class QualificationRunTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.args = SimpleNamespace(
            lib="/tmp/preflighted-libtest",
            receipt="/tmp/preflighted-receipt.json",
            preflight="/tmp/preflight.json",
            workspace="/tmp/workspace",
            expected_commit=HEAD,
            report_dir=self.temporary.name,
            timeout=600,
            stdout_limit=16384,
        )

    def run_qualification(self, runner):
        with patch.object(
                checkpoint, "build_attestation",
                lambda *args, **kwargs: attestation(qualification.CASES[0])):
            return qualification.run_qualification(
                self.args, run_checkpoint=runner)

    def test_two_passed_probes_are_serial_and_closed(self):
        runner, calls = runner_factory()
        manifest = self.run_qualification(runner)
        self.assertEqual([call.case for call in calls], list(qualification.CASES))
        self.assertEqual(manifest["result"], "passed")
        self.assertEqual(manifest["probe_count"], 2)
        self.assertEqual(manifest["error_class"], None)
        self.assertEqual(
            [item["result"] for item in manifest["cases"]],
            ["passed", "passed"])
        for item in manifest["cases"]:
            self.assertEqual(item["passed"], 1)
            self.assertEqual(item["failed"], 0)
            self.assertEqual(item["ignored"], 0)
            self.assertEqual(item["complete"], True)
        self.assertEqual(
            {item["report_label"] for item in manifest["cases"]},
            set(qualification.REPORTS))
        self.assertEqual(
            qualification.validate_manifest(manifest), manifest)
        names = {path.name for path in Path(self.temporary.name).iterdir()}
        self.assertEqual(
            names,
            set(qualification.REPORTS)
            | {"slot-one-handoff-qualification.json"})

    def test_report_contains_no_paths_credentials_or_raw_output(self):
        runner, _ = runner_factory()
        manifest = self.run_qualification(runner)
        encoded = json.dumps(manifest)
        self.assertEqual(manifest["lib_label"], qualification.LIB_LABEL)
        self.assertNotIn("lib_alias", encoded)
        for forbidden in ("stdout", "stderr", "test result:", "panicked",
                          "DATABASE_URL", "ACCESS_KEY", "SECRET", "/tmp",
                          "postgresql://", "preflighted-libtest"):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("libtest", json.dumps(manifest["cases"]))

    def test_failed_or_skipped_case_fails_the_gate_but_records_both(self):
        for projection, expected in ((FAILED, "case_failed"),
                                     (SKIPPED, "case_skipped")):
            with self.subTest(expected=expected):
                runner, calls = runner_factory(
                    {qualification.CASES[0]: projection})
                manifest = self.run_qualification(runner)
                self.assertEqual(len(calls), 2)
                self.assertEqual(manifest["result"], "failed")
                self.assertEqual(manifest["error_class"], expected)
                self.assertEqual(manifest["cases"][0]["result"], "failed")
                self.assertEqual(manifest["cases"][1]["result"], "passed")
                qualification.validate_manifest(manifest)

    def test_setup_failure_is_closed_and_the_other_case_still_runs(self):
        runner, calls = runner_factory({qualification.CASES[0]: None})
        manifest = self.run_qualification(runner)
        self.assertEqual(len(calls), 2)
        self.assertEqual(manifest["result"], "failed")
        self.assertEqual(manifest["error_class"], "setup")
        self.assertEqual(manifest["cases"][0]["error_class"], "setup")
        self.assertEqual(manifest["cases"][1]["result"], "passed")
        self.assertNotIn("preflight_binary_sha256", json.dumps(manifest))

    def test_non_matching_attestation_is_closed(self):
        runner, _ = runner_factory(
            overrides={qualification.CASES[1]: {"binary_sha256": "b" * 64}})
        manifest = self.run_qualification(runner)
        self.assertEqual(manifest["result"], "failed")
        self.assertEqual(manifest["error_class"], "attestation_mismatch")
        self.assertEqual(
            manifest["cases"][1]["error_class"], "attestation_mismatch")
        qualification.validate_manifest(manifest)

    def test_invalid_report_is_closed_without_echoing_it(self):
        def invalid_runner(namespace):
            payload = report(namespace.case)
            payload["case"] = "other::case"
            checkpoint.write_report(namespace.report, payload)
            return payload

        manifest = self.run_qualification(invalid_runner)
        self.assertEqual(manifest["result"], "failed")
        self.assertEqual(manifest["error_class"], "report_invalid")
        self.assertNotIn("other::case", json.dumps(manifest))


class ManifestValidationTests(unittest.TestCase):
    def valid_manifest(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        args = SimpleNamespace(
            lib="/tmp/lib", receipt="/tmp/receipt", preflight="/tmp/preflight",
            workspace="/tmp/workspace", expected_commit=HEAD,
            report_dir=temporary.name, timeout=600, stdout_limit=16384)
        runner, _ = runner_factory()
        with patch.object(
                checkpoint, "build_attestation",
                lambda *a, **k: attestation(qualification.CASES[0])):
            return qualification.run_qualification(args, run_checkpoint=runner)

    def test_manifest_rejects_extra_missing_and_tampered_fields(self):
        manifest = self.valid_manifest()
        extra = dict(manifest)
        extra["stdout"] = "raw"
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            qualification.validate_manifest(extra)
        self.assertEqual(str(raised.exception), "manifest_shape")
        missing = dict(manifest)
        missing.pop("tree")
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            qualification.validate_manifest(missing)
        self.assertEqual(str(raised.exception), "manifest_shape")
        for changes, expected in (
                ({"probe_count": 1}, "manifest_probe_count"),
                ({"schema": "other"}, "manifest_schema"),
                ({"lib_label": "/tmp/libtest"}, "manifest_lib_label"),
                ({"result": "failed", "error_class": None},
                 "manifest_failure_inconsistent"),
        ):
            with self.subTest(expected=expected):
                bad = dict(manifest)
                bad.update(changes)
                with self.assertRaises(checkpoint.CheckpointError) as raised:
                    qualification.validate_manifest(bad)
                self.assertEqual(str(raised.exception), expected)

    def test_manifest_rejects_case_order_and_inconsistent_probe(self):
        manifest = self.valid_manifest()
        reversed_cases = dict(manifest)
        reversed_cases["cases"] = list(reversed(manifest["cases"]))
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            qualification.validate_manifest(reversed_cases)
        self.assertEqual(str(raised.exception), "manifest_case_names")
        inconsistent = dict(manifest)
        inconsistent["cases"] = [dict(item) for item in manifest["cases"]]
        inconsistent["cases"][0]["failed"] = 1
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            qualification.validate_manifest(inconsistent)
        self.assertEqual(
            str(raised.exception), "manifest_case_complete_inconsistent")


if __name__ == "__main__":
    unittest.main()
