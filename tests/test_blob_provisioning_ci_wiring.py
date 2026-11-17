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
    "backend_identity_conflict_is_explicit_and_preserves_authority",
    "unsupported_legacy_repository_format_is_explicitly_refused",
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
        self.assertIn("SECOND_CHECKPOINT = CASES[4:5]", self.harness)
        self.assertIn("REFUSAL_CHECKPOINT = CASES[5:]", self.harness)
        self.assertIn('"refusal": list(REFUSAL_CHECKPOINT)', self.harness)
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
        for table in ("ref_store_serving_repositories",
                      "ref_store_core_gates", "ref_store_core_protocol_repos"):
            with self.subTest(table=table):
                self.assertNotIn("INSERT INTO " + table, self.harness)
                self.assertNotIn("INSERT INTO " + table + "(", self.harness)
        # The one repository insert is the unserved legacy `gitfs` fixture. It
        # must never carry a ready state or the pg_refstore backend.
        self.assertEqual(self.harness.count("INSERT INTO repositories"), 1,
                         "only the negative legacy fixture may insert a repository row")
        start = self.harness.index("INSERT INTO repositories")
        statement = self.harness[start:start + 400]
        self.assertIn("'provisioning','gitfs','sha1'", statement)
        self.assertNotIn("'ready'", statement)
        self.assertNotIn("pg_refstore", statement)
        # The other fixture writes are the temporary barrier in this run's schema.
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

    def test_backend_identity_refusal_checks_the_real_boundary_and_source_mapping(self) -> None:
        tree = ast.parse(self.harness)
        functions = {
            node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        case_node = functions.get("backend_identity_conflict_is_explicit_and_preserves_authority")
        self.assertIsNotNone(case_node, "the backend-identity refusal case is missing")
        case = ast.get_source_segment(self.harness, case_node)
        # The case must issue the real create request once and assert the exact
        # closed status/body, not accept a retryable or internal outcome.
        self.assertIn("self.post_create(", case)
        self.assertIn("attempts=1", case)
        self.assertIn("assert refusal_status == 409", case)
        self.assertIn('"repository state changed; retry"', case)
        self.assertNotIn("time.sleep", case)
        # It must compare the full existing authority snapshot before/after the
        # refused request and restore the original backend before serving Git.
        self.assertIn("self.authority(repo, name)", case)
        self.assertIn("after_refusal == before", case)
        self.assertIn("after_restart == before", case)
        self.assertIn("self.get_repo_status", case)
        self.assertIn('"repository is not ready"', case)
        self.assertIn("self.push_and_clone(repo, name)", case)

        helper_node = functions.get("conflicting_blob_identity_overrides")
        self.assertIsNotNone(helper_node, "the conflicting backend fixture helper is missing")
        helper = ast.get_source_segment(self.harness, helper_node)
        self.assertIn("ROOTYARD_BLOB_ROOT", helper)
        self.assertIn("uuid.uuid4().hex", helper)

        # The injected boundary is the actual opened-store identity, and the
        # expected refusal literals are the production mappings. A future source
        # change that silently reinterprets this case fails here.
        serving_source = (ROOT / "src" / "ref_store" / "serving.rs").read_text(encoding="utf-8")
        self.assertIn("binding.backend_identity() != backend.as_hex()", serving_source)
        self.assertIn('"repository is bound to a different Blob backend"', serving_source)
        identity_source = (ROOT / "src" / "blob_store" / "backend_identity.rs").read_text(encoding="utf-8")
        self.assertIn('"root", profile.root()', identity_source)
        error_source = (ROOT / "src" / "blob_git_gateway" / "error.rs").read_text(encoding="utf-8")
        conflict = re.search(r'StatusCode::CONFLICT => Self::Conflict\("([^"]+)"\)', error_source)
        self.assertIsNotNone(conflict, "the gateway 409 mapping is missing")
        self.assertEqual(conflict.group(1), "repository state changed; retry")
        session_source = (ROOT / "src" / "blob_git_gateway" / "session.rs").read_text(encoding="utf-8")
        self.assertIn('StatusCode::CONFLICT => GatewayError::Conflict("repository is not ready")', session_source)

    def test_legacy_format_refusal_is_real_api_metadata_and_not_an_upgrade_path(self) -> None:
        tree = ast.parse(self.harness)
        functions = {
            node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        case_node = functions.get("unsupported_legacy_repository_format_is_explicitly_refused")
        self.assertIsNotNone(case_node, "the legacy-format refusal case is missing")
        case = ast.get_source_segment(self.harness, case_node)
        self.assertIn("insert_unserved_legacy_gitfs_repository", case)
        self.assertIn("legacy_repository_snapshot", case)
        self.assertIn("self.post_create(", case)
        self.assertIn("attempts=1", case)
        self.assertIn("assert refusal_status == 409", case)
        self.assertIn('"repository state changed; retry"', case)
        self.assertIn("legacy_after == legacy_before", case)
        self.assertIn("after_refusal == control_before", case)
        self.assertIn("self.get_repo_status", case)
        self.assertIn("assert lookup_status == 404", case)
        self.assertIn('"not found"', case)
        self.assertIn("legacy_listed", case)
        self.assertIn("self.push_and_clone(control, control_name)", case)
        # The refusal is a real API check, not an old binary, migration, import,
        # restore or format-upgrade path.
        for forbidden in ("migrate", "restore", "backup", "--allow-legacy", "upgrade"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, case)

        insert_node = functions.get("insert_unserved_legacy_gitfs_repository")
        self.assertIsNotNone(insert_node, "the legacy fixture insert helper is missing")
        insert = ast.get_source_segment(self.harness, insert_node)
        self.assertIn("'provisioning','gitfs','sha1'", insert)
        self.assertNotIn("'ready'", insert)
        self.assertNotIn("pg_refstore", insert)
        snapshot_node = functions.get("legacy_repository_snapshot")
        self.assertIsNotNone(snapshot_node, "the legacy fixture observer is missing")
        snapshot = ast.get_source_segment(self.harness, snapshot_node)
        self.assertIn("authority_count_for_name", snapshot)
        self.assertIn('counts == "1|0|0|0"', snapshot)
        self.assertIn('fields[3] == "provisioning"', snapshot)
        self.assertIn('fields[4] == "gitfs"', snapshot)
        self.assertIn('fields[5] == "sha1"', snapshot)

        serving_source = (ROOT / "src" / "ref_store" / "serving.rs").read_text(encoding="utf-8")
        self.assertIn("scope.storage_backend() != PG_REFSTORE_BACKEND", serving_source)
        self.assertIn(
            '"repository exists on another storage backend; the pg_refstore service cannot adopt it"',
            serving_source)
        scope_source = (ROOT / "src" / "ref_store" / "core" / "serving_scope.rs").read_text(encoding="utf-8")
        self.assertIn('LEGACY_GITFS_BACKEND: &str = "gitfs"', scope_source)
        self.assertIn("LegacyAuthority", scope_source)

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
        self.assertEqual(EXPECTED_CASES[5], "backend_identity_conflict_is_explicit_and_preserves_authority")
        self.assertEqual(EXPECTED_CASES[6], "unsupported_legacy_repository_format_is_explicitly_refused")


if __name__ == "__main__":
    unittest.main()
