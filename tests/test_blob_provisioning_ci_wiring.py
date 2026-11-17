#!/usr/bin/env python3
"""Static wiring contract for the issue-143 provisioning native harness.

These checks stay offline: they never start a service, connect to PostgreSQL or
Blob, or execute the native harness. They pin the reviewable inventory, the
source-closure binding and the separate CI command while keeping the existing
``tests/blob_only_service.py`` primary standalone gate in place.
"""
from __future__ import annotations

import ast
import json
import re
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "blob_provisioning_service.py"
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"

sys.path.insert(0, str(HARNESS.parent))
import blob_provisioning_service as provisioning

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

Phase = provisioning.BackendIdentityConflictPhase
BACKEND_CASE = "backend_identity_conflict_is_explicit_and_preserves_authority"
EXPECTED_PHASES = (
    "initial_create",
    "authority_before",
    "stop_original",
    "start_conflicting",
    "conflicting_create",
    "authority_after_refusal",
    "conflicting_lookup",
    "stop_conflicting",
    "start_restored",
    "authority_after_restore",
    "restored_read",
    "restored_git",
)
_REPOSITORY_ID = "11111111-1111-1111-1111-111111111111"
_AUTHORITY = {"counts": "1|1|1|1", "gate_revision": 1}
_BODY_PHASES = (
    Phase.start_conflicting,
    Phase.conflicting_create,
    Phase.authority_after_refusal,
    Phase.conflicting_lookup,
)


class _BackendIdentityCaseDouble(provisioning.ProvisioningHarness):
    """Pure case double: no Harness constructor, service, PG, Git or process.

    Every operation below is an existing dependency of the real case method.
    The inherited case, phase wrapper, phase error, Harness.case and
    Harness.redact are the real implementations under test.
    """

    def __init__(self, fail_phase=None, failure_factory=None):
        self.fail_phase = fail_phase
        self.failure_factory = failure_factory or (lambda: AssertionError("raw fixture detail"))
        self.results = []
        self.secrets = []
        self.base_db = "postgresql://base"
        self.db = "postgresql://db"
        self.env = {}
        self.alice = {"token": "fixture-token"}
        self.proc = types.SimpleNamespace(pid=1000)
        self.phase_calls = []
        self.stop_calls = []
        self.start_calls = []
        self.authority_calls = 0

    def _phase_failure(self, phase):
        self.phase_calls.append(phase)
        if self.fail_phase is phase:
            raise self.failure_factory()

    def create(self, name, owner):
        self._phase_failure(Phase.initial_create)
        return {"id": _REPOSITORY_ID}, 201

    def authority(self, repo, expected_name):
        self.authority_calls += 1
        phases = (Phase.authority_before,
                  Phase.authority_after_refusal,
                  Phase.authority_after_restore)
        self._phase_failure(phases[self.authority_calls - 1])
        return _AUTHORITY

    def stop(self, hard=False):
        self.stop_calls.append(hard)
        self._phase_failure(Phase.stop_conflicting if hard else Phase.stop_original)
        self.proc = None

    def start(self, overrides=None, label="server"):
        self.start_calls.append(label)
        if label == "conflicting-blob-identity":
            self._phase_failure(Phase.start_conflicting)
            self.proc = types.SimpleNamespace(pid=2000)
        else:
            self._phase_failure(Phase.start_restored)
            self.proc = types.SimpleNamespace(pid=3000)

    def post_create(self, payload, attempts=4):
        self._phase_failure(Phase.conflicting_create)
        return 409, json.dumps({"error": "repository state changed; retry"}).encode(), {}

    def get_repo_status(self, owner, name):
        self._phase_failure(Phase.conflicting_lookup)
        return 409, json.dumps({"error": "repository is not ready"}).encode(), {}

    def expect(self, path, code, **kwargs):
        self._phase_failure(Phase.restored_read)
        return json.dumps({"id": _REPOSITORY_ID, "state": "ready"}).encode()

    def push_and_clone(self, repo, name):
        self._phase_failure(Phase.restored_git)
        return "a" * 40


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
        self.assertIn("assert lookup_status == 409", case)
        self.assertIn('"repository is not ready"', case)
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
        auth_source = (ROOT / "src" / "auth.rs").read_text(encoding="utf-8")
        self.assertIn('if state != "ready"', auth_source)
        self.assertIn('"repository is not ready"', auth_source)

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

    def _run_failing_backend_case(self, harness):
        with self.assertRaises(provisioning.BackendIdentityConflictPhaseError) as caught:
            harness.case(BACKEND_CASE, getattr(harness, BACKEND_CASE))
        return caught.exception

    def test_backend_identity_phase_projection_is_closed_and_ordered(self) -> None:
        self.assertEqual(tuple(phase.value for phase in Phase), EXPECTED_PHASES)
        self.assertEqual(len(Phase), 12)

    def test_each_closed_phase_is_observed_and_cleanup_still_runs(self) -> None:
        all_phases = list(Phase)
        source_lines = self.harness.splitlines()
        for index, phase in enumerate(all_phases):
            with self.subTest(phase=phase.value):
                harness = _BackendIdentityCaseDouble(fail_phase=phase)
                error = self._run_failing_backend_case(harness)
                self.assertIs(error.phase, phase)
                self.assertEqual(error.exception_class, "AssertionError")
                self.assertIsInstance(error.source_line, int)
                self.assertIn("_backend_identity_conflict_phase(", source_lines[error.source_line - 1])
                diagnostic = error.diagnostic()
                self.assertEqual(str(error), "backend-identity-conflict phase="
                                 + phase.value + " class=AssertionError source_line="
                                 + str(diagnostic["source_line"]))
                self.assertEqual(diagnostic["phase"], phase.value)
                self.assertEqual(diagnostic["exception_class"], "AssertionError")
                self.assertEqual(diagnostic["source_line"], error.source_line)
                # Harness.case still records the same failed status and the safe
                # projection, never the raw AssertionError text.
                self.assertEqual(harness.results[-1]["name"], BACKEND_CASE)
                self.assertEqual(harness.results[-1]["status"], "failed")
                self.assertEqual(harness.results[-1]["error"], str(error))
                self.assertNotIn("raw fixture detail", harness.results[-1]["error"])
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)
                expected_calls = all_phases[:index + 1]
                if phase in _BODY_PHASES:
                    expected_calls = expected_calls + [Phase.stop_conflicting]
                self.assertEqual(harness.phase_calls, expected_calls,
                                 "the existing operations were reordered, duplicated or skipped")
                if phase in (Phase.initial_create, Phase.authority_before):
                    self.assertEqual(harness.stop_calls, [])
                elif phase is Phase.stop_original:
                    self.assertEqual(harness.stop_calls, [False])
                else:
                    self.assertEqual(harness.stop_calls, [False, True],
                                     "the case finally cleanup did not run after the phase failure")

    def test_unknown_class_and_poisonous_payload_never_serialize(self) -> None:
        secret = "POISONOUS-SECRET-PAYLOAD-143"
        class PoisonousFailure(Exception):
            def __str__(self):
                return secret

            def __repr__(self):
                return secret

        def factory():
            return PoisonousFailure(secret, {"secret": secret})

        harness = _BackendIdentityCaseDouble(Phase.conflicting_create, factory)
        error = self._run_failing_backend_case(harness)
        self.assertEqual(error.exception_class, "unknown")
        self.assertIs(error.phase, Phase.conflicting_create)
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error.args))
        self.assertNotIn(secret, json.dumps(error.diagnostic(), sort_keys=True))
        self.assertNotIn(secret, json.dumps(harness.results, sort_keys=True))
        self.assertEqual(harness.results[-1]["error"], str(error))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assertEqual(harness.stop_calls, [False, True])

    def test_harness_case_serializes_phase_class_and_validated_line_without_poison(self) -> None:
        secret = "POISONED-ORIGINAL-EXCEPTION-STRING"
        class PoisonedFailure(Exception):
            def __str__(self):
                return secret

            def __repr__(self):
                return secret

        harness = _BackendIdentityCaseDouble(
            Phase.conflicting_create,
            lambda: PoisonedFailure(secret, {"secret": secret}))
        error = self._run_failing_backend_case(harness)
        saved = harness.results[-1]
        diagnostic = error.diagnostic()
        self.assertIsInstance(diagnostic["source_line"], int)
        self.assertIn("_backend_identity_conflict_phase(",
                      self.harness.splitlines()[diagnostic["source_line"] - 1])
        self.assertEqual(
            saved["error"],
            "backend-identity-conflict phase=conflicting_create class=unknown source_line="
            + str(diagnostic["source_line"]))
        self.assertEqual(saved["error"], str(error))
        self.assertNotIn(secret, saved["error"])
        self.assertNotIn(secret, json.dumps(harness.results, sort_keys=True))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)

    def test_source_line_is_static_unknown_when_not_validated(self) -> None:
        missing = provisioning.BackendIdentityConflictPhaseError(
            Phase.initial_create, "AssertionError")
        self.assertEqual(
            str(missing),
            "backend-identity-conflict phase=initial_create class=AssertionError source_line=unknown")
        self.assertNotIn("source_line", missing.diagnostic())
        stale = provisioning.BackendIdentityConflictPhaseError(
            Phase.initial_create, "AssertionError", source_line=999999)
        self.assertEqual(
            str(stale),
            "backend-identity-conflict phase=initial_create class=AssertionError source_line=unknown")
        self.assertNotIn("source_line", stale.diagnostic())

    def test_phase_error_rejects_values_outside_the_closed_sets(self) -> None:
        with self.assertRaises(TypeError):
            provisioning.BackendIdentityConflictPhaseError("initial_create", "AssertionError")
        with self.assertRaises(ValueError):
            provisioning.BackendIdentityConflictPhaseError(Phase.initial_create, "Unbounded")
        with self.assertRaises(ValueError):
            provisioning.BackendIdentityConflictPhaseError(
                Phase.initial_create, "AssertionError", source_line=0)

    def test_closed_projection_leaves_inventory_and_failure_status_unchanged(self) -> None:
        self.assertEqual(provisioning.CASES, EXPECTED_CASES)
        self.assertEqual(provisioning.FIRST_CHECKPOINT, EXPECTED_CASES[:4])
        self.assertEqual(provisioning.SECOND_CHECKPOINT, EXPECTED_CASES[4:5])
        self.assertEqual(provisioning.REFUSAL_CHECKPOINT, EXPECTED_CASES[5:])
        harness = _BackendIdentityCaseDouble(fail_phase=Phase.initial_create)
        error = self._run_failing_backend_case(harness)
        self.assertEqual(len(harness.results), 1)
        self.assertEqual(set(harness.results[0]), {"name", "status", "seconds", "error"})
        self.assertEqual(harness.results[0]["name"], BACKEND_CASE)
        self.assertEqual(harness.results[0]["status"], "failed")
        self.assertEqual(harness.results[0]["error"], str(error))


if __name__ == "__main__":
    unittest.main()
