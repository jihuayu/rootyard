#!/usr/bin/env python3
"""Pure selector/report regression for the #42 slot-one CI checkpoint.

No database, network, Cargo, rustc, native binary or local service is touched.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import refstore_issue42_slot_one_checkpoint as checkpoint  # noqa: E402

HEAD = "1" * 40
TREE = "2" * 40
DIGEST = "a" * 64

CASE = (
    "ref_store::pg::slot_one::tests::native::"
    "slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5"
)


def selected_output(status="ok", name=CASE, summary=None):
    if summary is None:
        if status == "ignored":
            summary = ("test result: ok. 0 passed; 0 failed; 1 ignored; "
                       "0 measured; 0 filtered out; finished in 0.01s")
        elif status == "ok":
            summary = ("test result: ok. 1 passed; 0 failed; 0 ignored; "
                       "0 measured; 0 filtered out; finished in 0.01s")
        else:
            summary = ("test result: FAILED. 0 passed; 1 failed; 0 ignored; "
                       "0 measured; 0 filtered out; finished in 0.01s")
    return ("running 1 test\n"
            f"test {name} ... {status}\n\n{summary}\n").encode()


def projection(**overrides):
    values = {
        "ran": 1,
        "complete": True,
        "passed": 1,
        "failed": 0,
        "ignored": 0,
        "error_class": None,
    }
    values.update(overrides)
    return values


def attestation(**overrides):
    values = {
        "schema": checkpoint.REPORT_SCHEMA,
        "case": CASE,
        "expected_commit": HEAD,
        "head": HEAD,
        "tree": TREE,
        "source_inputs_sha256": DIGEST,
        "lib_test_support_inputs_sha256": DIGEST,
        "receipt_sha256": DIGEST,
        "binary_sha256": DIGEST,
        "lib_alias": "/tmp/preflighted-libtest",
        "preflight_sha256": DIGEST,
        "selection": "unique",
    }
    values.update(overrides)
    return values


class SelectorTests(unittest.TestCase):
    def test_fixed_case_and_exact_argv(self):
        self.assertEqual(checkpoint.CASE, CASE)
        self.assertEqual(
            checkpoint.exact_command("/tmp/libtest"),
            ["/tmp/libtest", "--ignored", "--exact", CASE, "--test-threads=1"])
        self.assertEqual(
            checkpoint.listing_command("/tmp/libtest"),
            ["/tmp/libtest", "--list", "--ignored", "--format", "terse"])

    def test_listing_membership_is_exactly_once(self):
        names = checkpoint.parse_listing(
            b"other::case: test\n" + CASE.encode() + b": test\n")
        self.assertEqual(names, ["other::case", CASE])
        self.assertEqual(checkpoint.require_membership(names), "unique")
        with self.assertRaises(checkpoint.CheckpointError) as missing:
            checkpoint.require_membership(["other::case"])
        self.assertEqual(str(missing.exception), "selection_missing")
        with self.assertRaises(checkpoint.CheckpointError) as duplicate:
            checkpoint.require_membership([CASE, CASE])
        self.assertEqual(str(duplicate.exception), "selection_duplicate")

    def test_listing_rejects_malformed_lines(self):
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            checkpoint.parse_listing(b"0 tests, 0 benchmarks\n")
        self.assertEqual(str(raised.exception), "listing_malformed")
        with self.assertRaises(checkpoint.CheckpointError) as decoded:
            checkpoint.parse_listing(b"\xff: test\n")
        self.assertEqual(str(decoded.exception), "listing_malformed")


class ResultProjectionTests(unittest.TestCase):
    def test_exact_pass_is_complete(self):
        self.assertEqual(
            checkpoint.classify_result(selected_output(), 0),
            {"ran": 1, "complete": True, "passed": 1, "failed": 0,
             "ignored": 0, "error_class": None})

    def test_missing_multiple_wrong_skipped_and_failed_are_rejected(self):
        summary = selected_output().decode().split("\n\n", 1)[1]
        cases = {
            "case_missing": (summary.encode(), 0),
            "case_multiple": (
                (f"test {CASE} ... ok\ntest {CASE} ... ok\n\n" + summary).encode(), 0),
            "case_wrong": (selected_output(name="other::case"), 0),
            "case_skipped": (selected_output(status="ignored"), 0),
            "case_failed": (selected_output(status="FAILED"), 1),
        }
        for expected, (raw, exit_code) in cases.items():
            with self.subTest(expected=expected):
                result = checkpoint.classify_result(raw, exit_code)
                self.assertFalse(result["complete"])
                self.assertEqual(result["failed"], 1)
                self.assertEqual(result["error_class"], expected)

    def test_missing_multiple_and_non_exact_summaries_are_rejected(self):
        summaryless = selected_output().split(b"\n\ntest result:", 1)[0] + b"\n"
        summary = selected_output().decode().split("\n\n", 1)[1]
        double = selected_output() + summary.encode()
        wrong = selected_output(summary=(
            "test result: ok. 2 passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 0.01s"))
        for expected, raw in (("summary_missing", summaryless),
                              ("summary_multiple", double),
                              ("summary_not_exact", wrong)):
            with self.subTest(expected=expected):
                result = checkpoint.classify_result(raw, 0)
                self.assertEqual(result["error_class"], expected)
                self.assertEqual(result["ran"], 1)

    def test_nonzero_exit_and_bounded_failures_are_rejected(self):
        self.assertEqual(
            checkpoint.classify_result(selected_output(), 1)["error_class"],
            "exit")
        for expected, outcome in (("timeout", "timed_out"),
                                  ("output_limit", "output_limit"),
                                  ("spawn", "spawn_failed"),
                                  ("runner", "runner_error"),
                                  ("cleanup", "cleanup_failed")):
            with self.subTest(expected=expected):
                result = checkpoint.classify_result(
                    b"", None, outcome=outcome, error_class=expected)
                self.assertFalse(result["complete"])
                self.assertEqual(result["error_class"], expected)

    def test_malformed_output_is_rejected(self):
        self.assertEqual(
            checkpoint.classify_result(b"\xff", 0)["error_class"],
            "output_malformed")
        self.assertEqual(
            checkpoint.classify_result(
                b"test broken line without status\n", 0)["error_class"],
            "output_malformed")


class ReportTests(unittest.TestCase):
    def test_attestation_shape_matches_the_closed_prefix(self):
        self.assertEqual(set(attestation()), set(checkpoint.ATTESTATION_FIELDS))

    def test_pass_report_is_closed_and_rechecks_from_disk(self):
        report = checkpoint.make_report(attestation(), projection(), 0, "exited")
        self.assertEqual(report["result"], "passed")
        self.assertEqual(
            checkpoint.validate_report(report), report)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "slot-one-rotation.json"
            checkpoint.write_report(path, report)
            self.assertEqual(checkpoint.recheck_report(path), report)
            self.assertEqual(json.loads(path.read_text()), report)

    def test_failed_report_is_closed_and_has_no_child_output(self):
        report = checkpoint.make_report(
            attestation(),
            projection(complete=False, passed=0, failed=1,
                       error_class="case_failed"),
            1, "exited")
        self.assertEqual(checkpoint.validate_report(report), report)
        self.assertEqual(report["result"], "failed")
        encoded = json.dumps(report)
        for forbidden in ("stdout", "stderr", "test result:", "panicked",
                          "DATABASE_URL", "ACCESS_KEY", "SECRET"):
            self.assertNotIn(forbidden, encoded)

    def test_report_rejects_extra_and_missing_fields(self):
        report = checkpoint.make_report(attestation(), projection(), 0, "exited")
        extra = dict(report)
        extra["stdout"] = "raw"
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            checkpoint.validate_report(extra)
        self.assertEqual(str(raised.exception), "report_shape")
        missing = dict(report)
        missing.pop("tree")
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            checkpoint.validate_report(missing)
        self.assertEqual(str(raised.exception), "report_shape")

    def test_report_rejects_tampered_attestation_and_inconsistency(self):
        report = checkpoint.make_report(attestation(), projection(), 0, "exited")
        mutations = (
            ("schema", "report_schema", {"schema": "other"}),
            ("case", "report_case", {"case": "other"}),
            ("commit", "report_head", {"expected_commit": "3" * 40}),
            ("tree", "report_tree", {"tree": "not-a-tree"}),
            ("source", "report_source_inputs_sha256",
             {"source_inputs_sha256": "not-a-digest"}),
            ("selection", "report_selection", {"selection": "many"}),
            ("outcome", "report_process_outcome",
             {"process_outcome": "unknown"}),
            ("exit", "report_exit_code", {"exit_code": True}),
            ("ran", "report_ran", {"ran": 2}),
            ("ran_float", "report_ran", {"ran": 1.0}),
            ("complete", "report_complete", {"complete": 1}),
            ("result", "report_result", {"result": "maybe"}),
            ("error", "report_error_class", {"error_class": "unknown"}),
        )
        for label, expected, changes in mutations:
            with self.subTest(label=label):
                bad = dict(report)
                bad.update(changes)
                with self.assertRaises(checkpoint.CheckpointError) as raised:
                    checkpoint.validate_report(bad)
                self.assertEqual(str(raised.exception), expected)

    def test_report_rejects_inconsistent_pass_and_fail_claims(self):
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            checkpoint.make_report(
                attestation(), projection(failed=1), 0, "exited")
        self.assertEqual(str(raised.exception), "report_complete_inconsistent")
        with self.assertRaises(checkpoint.CheckpointError) as raised:
            checkpoint.make_report(
                attestation(),
                projection(complete=False, passed=0, failed=1,
                           error_class=None),
                None, "spawn_failed")
        self.assertEqual(str(raised.exception), "report_failure_inconsistent")


class WorkflowWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            ROOT / ".github" / "workflows"
            / "refstore-protocol-acceptance.yml").read_text()

    def step(self, marker):
        start = self.text.index(marker)
        end = self.text.index("\n      - name:", start + len(marker))
        return self.text[start:end]

    def test_gate_is_once_on_the_owned_manual_ref(self):
        self.assertEqual(
            self.text.count(
                "refs/heads/codex/goal-issue42-original-ac-source-audit-20261117"),
            1)
        step = self.step('"Replay exactly one #42 slot-one rotation case')
        self.assertEqual(step.count("github.ref"), 1)
        self.assertIn("workflow_dispatch", step)
        self.assertIn("success()", step)

    def test_new_checkpoint_runs_after_old_cases_and_before_cleanup(self):
        old = self.text.index(
            '"Exercise the #174 HTTP foundation cases')
        new = self.text.index(
            '"Replay exactly one #42 slot-one rotation case')
        cleanup = self.text.index(
            '"Drop only the run-owned #174 foundation database"')
        self.assertLess(old, new)
        self.assertLess(new, cleanup)

    def test_default_174_inventory_and_case18_index_are_unchanged(self):
        step = self.step('"Exercise the #174 HTTP foundation cases')
        self.assertNotIn(CASE, step)
        self.assertIn("index == 18", step)
        self.assertIn(
            "pre_admission_revision_mismatch_rebases_to_old_oid_mismatch", step)

    def test_step_reuses_preflighted_binary_and_fresh_prefix(self):
        step = self.step('"Replay exactly one #42 slot-one rotation case')
        self.assertIn(
            "scripts/refstore_issue42_slot_one_checkpoint.py", step)
        for required in ('--lib "$lib"', '--receipt "$receipt"',
                         '--preflight "$evidence/preflight.json"',
                         '--expected-commit "$GITHUB_SHA"',
                         'session174-slot-one-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
                         'ROOTYARD_TEST_GIT="$(command -v git)"'):
            self.assertIn(required, step)
        self.assertNotIn("GITHUB_ENV", step)

    def test_report_is_collected_with_existing_174_evidence(self):
        step = self.step('"Collect #174 acceptance evidence"')
        self.assertIn("slot-one-rotation.json", step)


if __name__ == "__main__":
    unittest.main()
