#!/usr/bin/env python3
"""Offline wiring guard for the #107 commit-unknown native harness.

These checks never start the service, PostgreSQL or Blob. They pin the fixed
three-case inventory, the role-metadata fixture boundary, the transitive input
hash closure and the CI command order/report gate that runs after the existing
primary standalone harness.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "blob_commit_unknown_service.py"
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"
EXPECTED_CASES = (
    "receive_pack_commit_unknown_resolves_exact",
    "exact_receive_post_replays_before_native_without_second_effect",
    "registered_read_cycles_do_not_exhaust_retained_snapshot_quota",
)
INPUT_CLOSURE = (
    "blob_commit_unknown_service.py",
    "blob_only_service.py",
    "e2e.py",
    "native_evidence.py",
    "ops_provenance.py",
    "owned_fuse_cleanup.py",
)


def normalized_commands(text):
    return re.sub(r"\s+", " ", re.sub(r"\\\n", " ", text))


class BlobCommitUnknownCiWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = HARNESS.read_text(encoding="utf-8")
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.commands = normalized_commands(self.workflow)

    def test_case_inventory_is_the_original_three(self) -> None:
        constants = {}
        cases_node = None
        for node in ast.parse(self.harness).body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if target.id == "CASES":
                cases_node = node.value
            elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                constants[target.id] = node.value.value
        self.assertIsNotNone(cases_node, "CASES tuple is missing")
        cases = []
        for element in cases_node.elts:
            if isinstance(element, ast.Constant):
                cases.append(element.value)
            elif isinstance(element, ast.Name):
                self.assertIn(element.id, constants, "unresolved case constant")
                cases.append(constants[element.id])
            else:
                self.fail("CASES contains a non-literal entry")
        self.assertEqual(tuple(cases), EXPECTED_CASES)
        for name in EXPECTED_CASES:
            with self.subTest(case=name):
                self.assertEqual(self.workflow.count(name), 1, "case is missing or duplicated in CI")

    def test_role_fixture_is_narrow_metadata_only(self) -> None:
        self.assertNotIn("collaborators/bob", self.harness)
        self.assertNotIn('method="PUT"', self.harness)
        self.assertNotIn("grant_status", self.harness)
        match = re.search(
            r"    def add_write_collaborator\(self, repo, label\):(.*?)(?=\n    def )",
            self.harness,
            re.S,
        )
        self.assertIsNotNone(match, "missing add_write_collaborator fixture")
        block = match.group(1)
        self.assertIn("INSERT INTO repository_collaborators", block)
        self.assertIn("RETURNING role", block)
        self.assertIn("'write'", block)
        for forbidden in (
            "INSERT INTO repositories",
            "INSERT INTO ref_store_",
            "INSERT INTO users",
            "INSERT INTO tokens",
            "UPDATE repository",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, block, "role fixture writes non-role state")
        self.assertIn("role configuration only", self.harness)
        self.assertIn("product collaborator-management route", self.harness)

    def test_harness_binds_the_transitive_input_closure(self) -> None:
        match = re.search(r"def input_hashes\(\):(.*?)(?=\n\nclass |\n\ndef )", self.harness, re.S)
        self.assertIsNotNone(match, "input_hashes() closure is missing")
        block = match.group(1)
        self.assertIn("Path(__file__).name", block)
        for name in INPUT_CLOSURE:
            with self.subTest(input=name):
                if name == "blob_commit_unknown_service.py":
                    self.assertIn("Path(__file__).name", block)
                else:
                    self.assertIn('"%s"' % name, block)
        self.assertIn('report["harness_inputs_sha256"] = hashes_now', self.harness)
        self.assertIn('report["build_receipt_sha256"] = profile.receipt_sha256', self.harness)
        self.assertIn('errors.append("harness/helper source changed during native acceptance")', self.harness)
        self.assertIn('errors.append("executed binary changed during native acceptance")', self.harness)
        self.assertIn('errors.append("build receipt changed during native acceptance")', self.harness)

    def test_workflow_runs_full_inventory_after_the_primary_gate(self) -> None:
        primary = ('python3 tests/blob_only_service.py --binary "$binary" --git "$ROOTYARD_GIT" '
                   "--report test-results/refstore/standalone-http.json")
        commit_unknown = ('python3 tests/blob_commit_unknown_service.py --binary "$binary" '
                          '--git "$ROOTYARD_GIT" '
                          "--report test-results/refstore/standalone-commit-unknown.json")
        provisioning = ('python3 tests/blob_provisioning_service.py --binary "$binary" '
                        '--git "$ROOTYARD_GIT" '
                        "--report test-results/refstore/standalone-provisioning.json")
        self.assertEqual(self.commands.count(primary), 1, "the primary standalone gate changed")
        self.assertEqual(self.commands.count(commit_unknown), 1, "the new full-inventory command is missing")
        self.assertEqual(self.commands.count(provisioning), 1, "an existing neighbor command changed")
        self.assertLess(self.commands.index(primary), self.commands.index(commit_unknown),
                        "the new harness must run after the primary standalone gate")
        self.assertLess(self.commands.index(commit_unknown), self.commands.index(provisioning),
                        "the new harness must stay in the same post-build step")
        self.assertNotIn("--case", commit_unknown)
        self.assertEqual(self.workflow.count("      - 'tests/blob_commit_unknown_service.py'"), 1)
        for name in INPUT_CLOSURE[1:]:
            with self.subTest(trigger=name):
                self.assertEqual(self.workflow.count("      - 'tests/" + name + "'"), 1,
                                 "transitive input trigger is missing or duplicated")
        for report in ("standalone-http.json", "standalone-browse.json", "standalone-history.json",
                       "standalone-provisioning.json", "standalone-paired-backup.json"):
            with self.subTest(report=report):
                self.assertIn(report, self.workflow, "an existing standalone report was removed")

    def test_workflow_strictly_gates_three_unique_passes_and_input_hashes(self) -> None:
        path = "test-results/refstore/standalone-commit-unknown.json"
        self.assertEqual(self.workflow.count(path), 2, "report path must be produced and validated exactly once")
        for required in (
            "assert report.get('passed') is True",
            "assert isinstance(cases, list) and len(cases) == 3",
            "assert [case.get('name') for case in cases] == expected",
            "assert len({case.get('name') for case in cases}) == 3",
            "assert all(case.get('status') == 'passed'",
            "assert report.get('skips') == 0 and report.get('pending_cases') == []",
            "assert report.get('source_head') == os.environ['GITHUB_SHA']",
            "assert report.get('inputs_unchanged') is True",
            "assert profile.get('build_receipt_sha256') == report.get('build_receipt_sha256')",
            "hashes = report.get('harness_inputs_sha256')",
            "assert report.get('checkpoint_sha256') == hashes['blob_commit_unknown_service.py']",
            "assert report.get('harness_sha256') == hashes['blob_only_service.py']",
        ):
            with self.subTest(assertion=required):
                self.assertIn(required, self.workflow, "strict CI report binding is incomplete")


if __name__ == "__main__":
    unittest.main()
