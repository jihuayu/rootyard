#!/usr/bin/env python3
"""Static wiring contract for the issue-143 provisioning native harness.

These checks stay offline: they never start a service, connect to PostgreSQL or
Blob, or execute the native harness. They pin the reviewable inventory, the
source-closure binding and the separate CI command while keeping the existing
``tests/blob_only_service.py`` primary standalone gate in place.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "blob_provisioning_service.py"
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"

EXPECTED_CASES = (
    "concurrent_same_owner_name_creates_converge_one_authority",
    "concurrent_object_format_conflict_is_explicit_and_single_authority",
    "create_retry_and_service_restart_preserve_head_and_authority",
    "lost_create_ack_proxy_retry_resolves_one_authority",
    "deferred_commit_barrier_kill_rolls_back_and_retry_converges",
)
DEPENDENCIES = (
    "blob_only_service.py",
    "e2e.py",
    "native_evidence.py",
    "ops_provenance.py",
    "owned_fuse_cleanup.py",
)


class BlobProvisioningCiWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = HARNESS.read_text(encoding="utf-8")
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_case_inventory_and_checkpoint_split_are_exact(self) -> None:
        tree = ast.parse(self.harness)
        cases = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets
            ):
                cases = ast.literal_eval(node.value)
        self.assertEqual(cases, EXPECTED_CASES)
        self.assertIn("FIRST_CHECKPOINT = CASES[:4]", self.harness)
        self.assertIn("SECOND_CHECKPOINT = CASES[4:]", self.harness)
        self.assertIn('assert client_result in ("RemoteDisconnected", "ConnectionReset")', self.harness)

    def test_harness_binds_its_own_and_transitive_sources(self) -> None:
        match = re.search(r"def input_hashes\(\):(.*?)(?=\n\ndef |\n\nclass )", self.harness, re.S)
        self.assertIsNotNone(match, "input_hashes() source closure is missing")
        block = match.group(1)
        self.assertIn("Path(__file__).name", block)
        for name in DEPENDENCIES:
            with self.subTest(dependency=name):
                self.assertIn('"%s"' % name, block)
        self.assertIn('"harness_sha256": hashes[Path(__file__).name]', self.harness)
        self.assertIn('"harness_inputs_sha256": hashes', self.harness)
        self.assertIn('"source_inputs_sha256": profile.build["source_inputs_sha256"]', self.harness)

    def test_harness_never_inserts_a_ready_authority_or_ack(self) -> None:
        for table in ("repositories", "ref_store_serving_repositories",
                      "ref_store_core_gates", "ref_store_core_protocol_repos"):
            with self.subTest(table=table):
                self.assertNotIn("INSERT INTO " + table, self.harness)
                self.assertNotIn("INSERT INTO " + table + "(", self.harness)
        # The only fixture write is the temporary barrier in this run's schema.
        self.assertIn("rootyard_143_barrier", self.harness)
        self.assertIn("CREATE CONSTRAINT TRIGGER rootyard_143_deferred_commit", self.harness)
        self.assertIn("pg_advisory_xact_lock(143,", self.harness)
        self.assertIn("DEFERRABLE INITIALLY DEFERRED", self.harness)
        self.assertIn('"half_ready_listed"', self.harness)
        self.assertIn('"post_abort_authority_counts"', self.harness)

    def test_workflow_keeps_the_primary_gate_and_adds_the_new_harness(self) -> None:
        # Path trigger: both the primary harness and the new harness must rerun
        # this workflow when changed.
        self.assertEqual(self.workflow.count("      - 'tests/blob_only_service.py'"), 1)
        self.assertEqual(self.workflow.count("      - 'tests/blob_provisioning_service.py'"), 1)
        for transitive in ("e2e.py", "native_evidence.py", "ops_provenance.py", "owned_fuse_cleanup.py"):
            with self.subTest(transitive=transitive):
                self.assertEqual(self.workflow.count("      - 'tests/" + transitive + "'"), 1,
                                 "transitive harness input is missing from the CI path trigger")
        # Join shell line continuations and normalise runs of whitespace so the
        # command check is independent of wrapping and indentation.
        commands = re.sub(r"\s+", " ", re.sub(r"\\\n", " ", self.workflow))
        primary = ("python3 tests/blob_only_service.py --binary \"$binary\" --git \"$ROOTYARD_GIT\" "
                   "--report test-results/refstore/standalone-http.json")
        provisioning = ("python3 tests/blob_provisioning_service.py --binary \"$binary\" --git \"$ROOTYARD_GIT\" "
                        "--report test-results/refstore/standalone-provisioning.json")
        self.assertEqual(commands.count(primary), 1, "the existing primary standalone gate was removed or duplicated")
        self.assertEqual(commands.count(provisioning), 1, "the provisioning harness command is missing or duplicated")
        self.assertLess(commands.index(primary), commands.index(provisioning),
                        "the new harness must run after the existing primary gate in the same standalone step")
        # The new report lives under the existing uploaded artifact directory and
        # the command deliberately runs the whole checkpoint inventory.
        self.assertIn("--report test-results/refstore/standalone-provisioning.json", provisioning)
        self.assertNotIn("--case", provisioning)
        self.assertIn("path: test-results/refstore/", self.workflow)

    def test_first_checkpoint_stays_first(self) -> None:
        # A reordering that silently turns the independent kill checkpoint into
        # the first thing to run would invalidate the reviewable split.
        self.assertEqual(EXPECTED_CASES[:4], (
            "concurrent_same_owner_name_creates_converge_one_authority",
            "concurrent_object_format_conflict_is_explicit_and_single_authority",
            "create_retry_and_service_restart_preserve_head_and_authority",
            "lost_create_ack_proxy_retry_resolves_one_authority",
        ))
        self.assertEqual(EXPECTED_CASES[4], "deferred_commit_barrier_kill_rolls_back_and_retry_converges")


if __name__ == "__main__":
    unittest.main()
