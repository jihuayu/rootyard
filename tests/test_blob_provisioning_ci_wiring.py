#!/usr/bin/env python3
"""Static wiring contract for the issue-143 provisioning native harness.

These checks stay offline: they never start a service, connect to PostgreSQL or
Blob, or execute the native harness. They pin the reviewable inventory, the
source-closure binding and the separate CI command while keeping the existing
``tests/blob_only_service.py`` primary standalone gate in place.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import json
import re
import sys
import types
import unittest
import uuid
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "blob_provisioning_service.py"
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"

sys.path.insert(0, str(HARNESS.parent))
import blob_only_service as serving
import blob_provisioning_service as provisioning

EXPECTED_CASES = (
    "concurrent_same_owner_name_creates_converge_one_authority",
    "concurrent_object_format_conflict_is_explicit_and_single_authority",
    "create_retry_and_service_restart_preserve_head_and_authority",
    "lost_create_ack_proxy_retry_resolves_one_authority",
    "deferred_commit_barrier_kill_rolls_back_and_retry_converges",
    "backend_identity_conflict_is_explicit_and_preserves_authority",
    "unsupported_legacy_repository_format_is_explicitly_refused",
    "missing_database_url_is_explicit_refusal_without_listener",
    "missing_blob_endpoint_is_explicit_refusal_without_legacy_fallback",
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

    def start(self, overrides=None, label="server", startup_projection=None):
        self.start_calls.append(label)
        if label == "conflicting-blob-identity":
            self._phase_failure(Phase.start_conflicting)
            self.proc = types.SimpleNamespace(pid=2000)
        else:
            self._phase_failure(Phase.start_restored)
            self.proc = types.SimpleNamespace(pid=3000)

    def post_create(self, payload, attempts=4):
        self._phase_failure(Phase.conflicting_create)
        return 409, json.dumps({"error": "repository state changed; retry"}).encode()

    def get_repo_status(self, owner, name):
        self._phase_failure(Phase.conflicting_lookup)
        return 409, json.dumps({"error": "repository is not ready"}).encode(), {}

    def expect(self, path, code, **kwargs):
        self._phase_failure(Phase.restored_read)
        return json.dumps({"id": _REPOSITORY_ID, "state": "ready"}).encode()

    def push_and_clone(self, repo, name):
        self._phase_failure(Phase.restored_git)
        return "a" * 40


class _FakeClock:
    """In-memory clock; no timer, thread or real sleep."""

    def __init__(self, timeout_after=None):
        self.now = 0.0
        self.timeout_after = timeout_after
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += self.timeout_after if self.timeout_after is not None else seconds


class _FakeProc:
    """Popen double with only the attributes the inherited start reads."""

    def __init__(self, pid=2000, returncode=None):
        self.pid = pid
        self.returncode = returncode
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return self.returncode


class _FakeLog:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _FakePath:
    def __init__(self, name):
        self.name = name


class _FakeRoot:
    def __truediv__(self, name):
        return _FakePath(name)


def _raise(error):
    raise error


class _StartHarness(provisioning.ProvisioningHarness):
    """No Harness constructor, service, process, thread, socket or real file.

    The inherited ``BlobOnlyHarness.start`` runs unmodified except that its
    Popen/open/clock/hash/native-evidence/http/stop dependencies are doubles.
    """

    def __init__(self, *, proc=None, http_impl=None, stop_impl=None, clock=None,
                 binary_digest="fake-digest", hash_error=None, native_error=None,
                 popen_error=None):
        self.proc = None
        self.env = {"ROOTYARD_BLOB_ROOT": "fixture/root"}
        self.server_count = 0
        self.root = _FakeRoot()
        self.log = None
        self.profile = types.SimpleNamespace(
            binary="fake-binary", build={"binary_sha256": binary_digest})
        self.clock = clock or _FakeClock()
        self.http_impl = http_impl or (lambda path: (200, b"", {}))
        self.stop_impl = stop_impl or (lambda hard=False: None)
        self.proc_factory = proc or (lambda: _FakeProc())
        self.binary_digest = binary_digest
        self.hash_error = hash_error
        self.native_error = native_error
        self.popen_error = popen_error
        self.popen_calls = 0
        self.http_calls = 0
        self.stop_calls = []
        self.hash_calls = 0
        self.native_calls = 0
        self.popen_proc = None
        self.http = self._http
        self.stop = self._stop

    def _popen(self, argv, **kwargs):
        self.popen_calls += 1
        self.popen_argv = argv
        self.popen_env = kwargs.get("env")
        if self.popen_error is not None:
            raise self.popen_error
        self.popen_proc = self.proc_factory()
        return self.popen_proc

    def _open(self, path, mode="ab", *args, **kwargs):
        self.log = _FakeLog()
        return self.log

    def _http(self, path, *args, **kwargs):
        self.http_calls += 1
        return self.http_impl(path)

    def _stop(self, hard=False):
        if self.proc:
            self.stop_calls.append(hard)
            self.stop_impl(hard=hard)
            self.proc = None
        if self.log:
            self.log.close()
            self.log = None

    def _hash(self, path):
        self.hash_calls += 1
        if self.hash_error is not None:
            raise self.hash_error
        return self.binary_digest

    def _native(self, harness):
        self.native_calls += 1
        if self.native_error is not None:
            raise self.native_error


@contextmanager
def _patched_serving(harness):
    """Replace only blob_only_service's runtime dependencies with doubles."""
    with mock.patch.object(serving, "subprocess", types.SimpleNamespace(Popen=harness._popen)), \
         mock.patch.object(serving, "open", harness._open, create=True), \
         mock.patch.object(serving, "time", harness.clock), \
         mock.patch.object(serving, "sha256_file", harness._hash), \
         mock.patch.object(serving, "native_evidence",
                           types.SimpleNamespace(started=harness._native)):
        yield


class _BackendIdentityStartupCaseDouble(_StartHarness):
    """Real inherited case/start/phase machinery; every other step is a double."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.proc = types.SimpleNamespace(pid=1000)
        self.results = []
        self.secrets = []
        self.base_db = "postgresql://base"
        self.db = "postgresql://db"
        self.alice = {"token": "fixture-token"}
        self.authority_calls = 0

    def create(self, name, owner):
        return {"id": _REPOSITORY_ID}, 201

    def authority(self, repo, expected_name):
        self.authority_calls += 1
        return _AUTHORITY

    def post_create(self, payload, attempts=4):
        return 409, json.dumps({"error": "repository state changed; retry"}).encode()

    def get_repo_status(self, owner, name):
        return 409, json.dumps({"error": "repository is not ready"}).encode(), {}

    def expect(self, path, code, **kwargs):
        return json.dumps({"id": _REPOSITORY_ID, "state": "ready"}).encode()

    def push_and_clone(self, repo, name):
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
        self.assertIn("REFUSAL_CHECKPOINT = CASES[5:7]", self.harness)
        self.assertIn("STARTUP_CHECKPOINT = CASES[7:]", self.harness)
        self.assertIn('"refusal": list(REFUSAL_CHECKPOINT)', self.harness)
        self.assertIn('"startup": list(STARTUP_CHECKPOINT)', self.harness)
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
        artifact_name = "          name: refstore-protocol-native-${{ github.run_id }}-${{ github.run_attempt }}"
        uploads = [step for step in re.split(r"(?m)(?=^      - )", self.workflow)
                   if artifact_name in step.splitlines()]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        upload_lines = upload.splitlines()
        self.assertTrue(upload.startswith("      - uses: actions/upload-artifact@v4\n"))
        self.assertIn("        if: always()", upload_lines)
        self.assertIn("          if-no-files-found: error", upload_lines)
        paths = re.search(r"(?ms)^ {10}path: \|\n(.*?)(?=^ {0,10}\S|\Z)", upload)
        self.assertIsNotNone(paths)
        self.assertEqual([line.strip() for line in paths[1].splitlines() if line.strip()], [
            "test-results/refstore/",
            "!test-results/refstore/blob_git_gateway/native.log",
        ])

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
        self.assertIn("uuid.uuid4()", helper)
        self.assertIn("identity.hex", helper)
        self.assertNotIn("identity-conflict-", helper)

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

    def test_post_create_returns_the_real_two_value_caller_shape(self) -> None:
        # The real HTTP helper returns (status, body, headers); post_create is
        # the two-value adapter every case call site unpacks. A fake HTTP triple
        # and the real method pin that boundary without a service or network.
        raw = json.dumps({"error": "repository state changed; retry"}).encode()
        headers = {"content-type": "application/json"}
        requests = []

        def fake_http(path, **kwargs):
            requests.append((path, kwargs))
            return 409, raw, headers

        harness = types.SimpleNamespace(http=fake_http, alice={"token": "fixture-token"})
        result = provisioning.ProvisioningHarness.post_create(
            harness,
            {"owner": "alice", "name": "conflict", "object_format": "sha1"},
            attempts=1)
        self.assertEqual(result, (409, raw))
        self.assertIs(result[1], raw)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][0], "/api/repos")
        self.assertEqual(requests[0][1], {
            "token": {"token": "fixture-token"},
            "method": "POST",
            "body": {"owner": "alice", "name": "conflict", "object_format": "sha1"},
        })

    def test_conflicting_blob_identity_fixture_stays_within_production_root_bounds(self) -> None:
        # Pure fixture check: no service, process, socket, database or Cargo run.
        fixed = uuid.UUID("0123456789abcdef0123456789abcdef")
        other = uuid.UUID("fedcba9876543210fedcba9876543210")
        self.assertEqual(len(fixed.hex), 32)
        self.assertEqual(len(other.hex), 32)
        parent = "owned-parent/run-289"
        env = {
            "ROOTYARD_BLOB_ROOT": parent,
            "ROOTYARD_BLOB_SERVICE": "s3",
            "ROOTYARD_BLOB_BUCKET": "fixture-bucket",
            "ROOTYARD_BLOB_ACCESS_KEY_ID": "fixture-access-key",
            "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "fixture-secret",
        }
        harness = types.SimpleNamespace(env=dict(env))
        overrides = [
            (provisioning.ProvisioningHarness.conflicting_blob_identity_overrides(harness, identity), identity)
            for identity in (fixed, other)
        ]
        generated = provisioning.ProvisioningHarness.conflicting_blob_identity_overrides(harness)
        # The override preserves the owned parent prefix, provider, bucket and
        # credentials. Only the fixture's root mapping changes.
        self.assertEqual(harness.env, env, "fixture mutated provider, bucket, credentials or parent prefix")
        self.assertEqual(set(generated), {"ROOTYARD_BLOB_ROOT"})
        self.assertEqual(generated["ROOTYARD_BLOB_ROOT"].rpartition("/")[0], parent)
        self.assertRegex(generated["ROOTYARD_BLOB_ROOT"].rpartition("/")[2],
                         r"\Aconflict-[0-9a-f]{32}\Z")
        # The production bound is read from the source the service validates
        # at startup, not duplicated as a local constant.
        types_source = (ROOT / "src" / "blob_store" / "types.rs").read_text(encoding="utf-8")
        namespace_match = re.search(r"(?m)^pub const MAX_NAMESPACE_BYTES: usize = (\d+);$", types_source)
        self.assertIsNotNone(namespace_match, "production MAX_NAMESPACE_BYTES is missing")
        namespace_bound = int(namespace_match.group(1))
        config_source = (ROOT / "src" / "blob_store" / "config.rs").read_text(encoding="utf-8")
        total_match = re.search(r"root\.len\(\) > (\d+)", config_source)
        self.assertIsNotNone(total_match, "production root total-length bound is missing")
        total_bound = int(total_match.group(1))
        roots = []
        for override, identity in overrides:
            self.assertEqual(set(override), {"ROOTYARD_BLOB_ROOT"})
            root = override["ROOTYARD_BLOB_ROOT"]
            roots.append(root)
            self.assertTrue(root.isascii(), "fixture root must be ASCII")
            self.assertFalse(root.startswith("/"))
            self.assertFalse(root.endswith("/"))
            self.assertLessEqual(len(root), total_bound)
            segments = root.split("/")
            self.assertEqual(segments[:-1], parent.split("/"),
                             "fixture replaced rather than appended to the owned parent prefix")
            for segment in segments:
                self.assertTrue(segment)
                self.assertNotIn(segment, (".", ".."))
                self.assertRegex(segment, r"\A[A-Za-z0-9._-]+\Z")
                self.assertLessEqual(len(segment), namespace_bound)
            child = segments[-1]
            self.assertEqual(child, "conflict-" + identity.hex)
            self.assertRegex(child, r"\Aconflict-[0-9a-f]{32}\Z")
            self.assertLess(len(child), namespace_bound,
                            "fixture child must keep a margin below the production namespace bound")
        self.assertNotEqual(roots[0], roots[1], "controlled identities must select distinct backend mappings")
        self.assertEqual(roots[0].rpartition("/")[0], roots[1].rpartition("/")[0],
                         "controlled identities must keep one stable parent prefix")

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

    def test_missing_dependency_cases_bind_real_cli_and_closed_reasons(self) -> None:
        tree = ast.parse(self.harness)
        functions = {
            node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        database = ast.get_source_segment(
            self.harness, functions["missing_database_url_is_explicit_refusal_without_listener"])
        self.assertIn('"missing-database-url", ("serve",), ("DATABASE_URL",)', database)
        self.assertIn('"DATABASE_URL is required"', database)
        blob = ast.get_source_segment(
            self.harness, functions["missing_blob_endpoint_is_explicit_refusal_without_legacy_fallback"])
        self.assertIn('"missing-blob-endpoint", ("serve-blob",), ("ROOTYARD_BLOB_ENDPOINT",)', blob)
        self.assertIn('"invalid Blob profile"', blob)
        helper = ast.get_source_segment(self.harness, functions["_startup_refusal"])
        self.assertIn("serving.StartupProjection()", helper)
        self.assertIn("closed_startup_reason(raw)", helper)
        self.assertIn("self._listener_absent(bind)", helper)
        self.assertIn("self.stop(hard=True)", helper)
        self.assertNotIn("raw.decode", helper)
        self.assertNotIn("print(", helper)
        listener = ast.get_source_segment(self.harness, functions["_listener_absent"])
        self.assertIn("probe.connect((host, int(port)))", listener)
        self.assertEqual(provisioning.STARTUP_REFUSAL_REASONS,
                         ("DATABASE_URL is required", "invalid Blob profile"))

        # The child must be the actual public CLI, not a fake handler. `serve`
        # reaches Config::from_env before the listener; `serve-blob` reaches the
        # standalone Blob profile after PostgreSQL is already valid.
        serving_source = (ROOT / "tests" / "blob_only_service.py").read_text(encoding="utf-8")
        self.assertIn('command=("serve-blob",), unset=()', serving_source)
        self.assertIn("for key in unset:", serving_source)
        self.assertIn("subprocess.Popen([str(self.profile.binary), *command]", serving_source)
        self.assertIn("self.log_path = self.root /", serving_source)
        main_source = (ROOT / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn('if args.len() == 1 && args[0] == "serve-blob"', main_source)
        self.assertIn("let config = Config::from_env()?;", main_source)
        self.assertIn('args.first().map(String::as_str).unwrap_or("serve")', main_source)
        config_source = (ROOT / "src" / "config.rs").read_text(encoding="utf-8")
        self.assertIn(
            'env::var("DATABASE_URL").context("DATABASE_URL is required")?', config_source)
        standalone_source = (ROOT / "src" / "standalone.rs").read_text(encoding="utf-8")
        self.assertIn(
            'BlobProfile::from_env().map_err(|_| anyhow!("invalid Blob profile"))',
            standalone_source)
        blob_config_source = (ROOT / "src" / "blob_store" / "config.rs").read_text(
            encoding="utf-8")
        self.assertIn('env_required("ROOTYARD_BLOB_SERVICE")?', blob_config_source)
        self.assertIn(
            '"standalone blob profile needs an explicit remote ROOTYARD_BLOB_ENDPOINT"',
            blob_config_source)
        # The standalone profile's production constructor never reads the
        # legacy object-store selector; a missing explicit endpoint is not
        # eligible for its local fallback.
        from_env = blob_config_source.split("pub fn from_env", 1)[1].split(
            "pub fn with_root", 1)[0]
        self.assertNotIn("ROOTYARD_OBJECT_STORE_ENDPOINT", from_env)

    def test_closed_startup_reason_projection_only_returns_fixed_literals(self) -> None:
        cases = (
            (b"Error: DATABASE_URL is required\n\nCaused by:\n    environment variable not found\n",
             "DATABASE_URL is required"),
            (b"Error: invalid Blob profile\n", "invalid Blob profile"),
        )
        for raw, expected in cases:
            with self.subTest(reason=expected):
                self.assertEqual(provisioning.closed_startup_reason(raw), expected)
        for raw in (b"", b"Error: something else\n",
                    b"Error: DATABASE_URL is required\nError: invalid Blob profile\n"):
            with self.subTest(raw=raw):
                with self.assertRaises(AssertionError) as caught:
                    provisioning.closed_startup_reason(raw)
                self.assertEqual(
                    str(caught.exception),
                    "startup refusal did not emit exactly one known fixed reason")
        secret = "POISONOUS-STARTUP-OUTPUT-143"
        with self.assertRaises(AssertionError) as caught:
            provisioning.closed_startup_reason(b"Error: " + secret.encode() + b"\n")
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception.args))
        with self.assertRaises(AssertionError):
            provisioning.closed_startup_reason("not bytes")
        with self.assertRaises(AssertionError):
            provisioning.closed_startup_reason(
                b"x" * (provisioning.MAX_STARTUP_LOG_BYTES + 1))

    def test_start_uses_the_fixed_public_command_and_removes_only_requested_env(self) -> None:
        harness = _StartHarness(proc=lambda: _FakeProc(returncode=1))
        harness.env = {"DATABASE_URL": "postgresql://owned", "ROOTYARD_GIT": "/owned/git",
                       "ROOTYARD_BIND": "127.0.0.1:1234"}
        with _patched_serving(harness):
            with self.assertRaises(RuntimeError) as caught:
                harness.start(label="missing-database-url", command=("serve",),
                              unset=("DATABASE_URL",),
                              overrides={"ROOTYARD_DATA_DIR": "/owned/data"})
        self.assertEqual(str(caught.exception), "serve exited during startup with status 1")
        self.assertEqual(harness.popen_argv, ["fake-binary", "serve"])
        self.assertNotIn("DATABASE_URL", harness.popen_env)
        self.assertEqual(harness.popen_env["ROOTYARD_GIT"], "/owned/git")
        self.assertEqual(harness.popen_env["ROOTYARD_DATA_DIR"], "/owned/data")
        for command, unset in ((["serve"], ()), ((), ()), (("serve",), ["DATABASE_URL"])):
            with self.subTest(command=command, unset=unset):
                with self.assertRaises(TypeError):
                    harness.start(command=command, unset=unset)

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
        self.assertEqual(EXPECTED_CASES[7:], (
            "missing_database_url_is_explicit_refusal_without_listener",
            "missing_blob_endpoint_is_explicit_refusal_without_legacy_fallback",
        ))

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

    def _start_error(self, harness):
        with _patched_serving(harness):
            with self.assertRaises(provisioning.BackendIdentityConflictPhaseError) as caught:
                with harness._backend_identity_conflict_phase(Phase.start_conflicting) as context:
                    harness.start(startup_projection=context.startup_projection)
        return caught.exception

    def test_actual_case_serializes_child_exit_projection(self) -> None:
        harness = _BackendIdentityStartupCaseDouble(proc=lambda: _FakeProc(returncode=1))
        with _patched_serving(harness):
            with self.assertRaises(provisioning.BackendIdentityConflictPhaseError) as caught:
                harness.case(BACKEND_CASE, getattr(harness, BACKEND_CASE))
        error = caught.exception
        self.assertIs(error.phase, Phase.start_conflicting)
        self.assertEqual(error.exception_class, "RuntimeError")
        self.assertEqual(error.startup_stage, "child_exit")
        self.assertEqual(error.exit_status, "exited_1")
        self.assertEqual(
            str(error),
            "backend-identity-conflict phase=start_conflicting class=RuntimeError source_line="
            + str(error.diagnostic()["source_line"])
            + " startup_stage=child_exit exit_status=exited_1")
        self.assertEqual(harness.results[-1]["error"], str(error))
        self.assertNotIn("serve-blob exited during startup", harness.results[-1]["error"])
        self.assertNotIn("fixture/root", harness.results[-1]["error"])
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        self.assertEqual(harness.http_calls, 0)
        self.assertEqual(harness.hash_calls, 0)
        self.assertEqual(harness.native_calls, 0)
        self.assertEqual(harness.stop_calls, [False, False])

    def test_startup_projection_readiness_timeout_has_no_added_probe(self) -> None:
        clock = _FakeClock(timeout_after=31.0)
        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=None),
            http_impl=lambda path: _raise(OSError("probe")),
            clock=clock)
        error = self._start_error(harness)
        self.assertEqual(error.startup_stage, "readiness_timeout")
        self.assertEqual(error.exit_status, "not_applicable")
        self.assertEqual(error.exception_class, "RuntimeError")
        self.assertIn("startup_stage=readiness_timeout", str(error))
        self.assertIn("exit_status=not_applicable", str(error))
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        self.assertEqual(harness.http_calls, 1)
        self.assertEqual(harness.stop_calls, [True])
        self.assertEqual(harness.hash_calls, 0)
        self.assertEqual(harness.native_calls, 0)
        self.assertEqual(clock.sleeps, [0.1])

    def test_startup_projection_probe_runtime_error_is_distinct(self) -> None:
        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=None),
            http_impl=lambda path: _raise(RuntimeError("probe failure")))
        error = self._start_error(harness)
        self.assertEqual(error.startup_stage, "readiness_probe")
        self.assertEqual(error.exit_status, "not_applicable")
        self.assertEqual(error.exception_class, "RuntimeError")
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        self.assertEqual(harness.http_calls, 1)
        self.assertEqual(harness.stop_calls, [])
        self.assertEqual(harness.hash_calls, 0)
        self.assertEqual(harness.native_calls, 0)

    def test_startup_projection_post_ready_hash_failure(self) -> None:
        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=None),
            http_impl=lambda path: (200, b"", {}),
            binary_digest="expected-digest",
            hash_error=AssertionError("hash mismatch"))
        error = self._start_error(harness)
        self.assertEqual(error.startup_stage, "post_ready")
        self.assertEqual(error.exit_status, "not_applicable")
        self.assertEqual(error.exception_class, "AssertionError")
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        self.assertEqual(harness.http_calls, 1)
        self.assertEqual(harness.hash_calls, 1)
        self.assertEqual(harness.native_calls, 0)
        self.assertEqual(harness.stop_calls, [])

    def test_startup_projection_post_ready_native_evidence_failure(self) -> None:
        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=None),
            http_impl=lambda path: (200, b"", {}),
            binary_digest="fake-digest",
            native_error=RuntimeError("receipt mismatch"))
        error = self._start_error(harness)
        self.assertEqual(error.startup_stage, "post_ready")
        self.assertEqual(error.exit_status, "not_applicable")
        self.assertEqual(error.exception_class, "RuntimeError")
        self.assertEqual(harness.http_calls, 1)
        self.assertEqual(harness.hash_calls, 1)
        self.assertEqual(harness.native_calls, 1)
        self.assertEqual(harness.stop_calls, [])

    def test_startup_projection_spawn_failure_is_bounded(self) -> None:
        harness = _StartHarness(
            proc=lambda: _FakeProc(),
            popen_error=OSError("spawn failure"))
        error = self._start_error(harness)
        self.assertEqual(error.startup_stage, "spawn")
        self.assertEqual(error.exit_status, "not_applicable")
        self.assertEqual(error.exception_class, "OSError")
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.http_calls, 0)
        self.assertEqual(harness.stop_calls, [])
        self.assertEqual(harness.hash_calls, 0)
        self.assertEqual(harness.native_calls, 0)

    def test_startup_projection_stop_failure_keeps_known_child_exit(self) -> None:
        raised = []

        def stop_impl(hard=False):
            if not hard:
                failure = RuntimeError("stop reclaim")
                raised.append(failure)
                raise failure

        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=101), stop_impl=stop_impl)
        projection = serving.StartupProjection()
        with _patched_serving(harness):
            with self.assertRaises(RuntimeError) as caught:
                harness.start(startup_projection=projection)
        self.assertIs(caught.exception, raised[0])
        self.assertEqual(projection.safe_fields(), ("child_exit", "exited_101"))
        self.assertEqual(harness.stop_calls, [False])
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        error = provisioning.BackendIdentityConflictPhaseError(
            Phase.start_conflicting, "RuntimeError", startup_projection=projection)
        self.assertEqual(error.startup_stage, "child_exit")
        self.assertEqual(error.exit_status, "exited_101")
        self.assertIn("startup_stage=child_exit", str(error))
        self.assertIn("exit_status=exited_101", str(error))

    def test_startup_projection_stop_failure_keeps_known_timeout(self) -> None:
        raised = []

        def stop_impl(hard=False):
            failure = RuntimeError("stop reclaim")
            raised.append(failure)
            raise failure

        clock = _FakeClock(timeout_after=31.0)
        harness = _StartHarness(
            proc=lambda: _FakeProc(returncode=None),
            http_impl=lambda path: _raise(OSError("probe")),
            clock=clock,
            stop_impl=stop_impl)
        projection = serving.StartupProjection()
        with _patched_serving(harness):
            with self.assertRaises(RuntimeError) as caught:
                harness.start(startup_projection=projection)
        self.assertIs(caught.exception, raised[0])
        self.assertEqual(projection.safe_fields(), ("readiness_timeout", "not_applicable"))
        self.assertEqual(harness.stop_calls, [True])
        error = provisioning.BackendIdentityConflictPhaseError(
            Phase.start_conflicting, "RuntimeError", startup_projection=projection)
        self.assertEqual(error.startup_stage, "readiness_timeout")
        self.assertEqual(error.exit_status, "not_applicable")

    def test_startup_projection_stop_reclaim_is_fallback_only(self) -> None:
        projection = serving.StartupProjection()
        projection.enter("readiness_probe")
        projection.enter_stop()
        projection.failed = True
        projection.mark_stop_reclaim()
        self.assertEqual(projection.safe_fields(), ("stop_reclaim", "not_applicable"))
        error = provisioning.BackendIdentityConflictPhaseError(
            Phase.start_conflicting, "RuntimeError", startup_projection=projection)
        self.assertEqual(error.diagnostic()["startup_stage"], "stop_reclaim")
        self.assertEqual(error.diagnostic()["exit_status"], "not_applicable")
        self.assertIn("startup_stage=stop_reclaim", str(error))
        self.assertIn("exit_status=not_applicable", str(error))

    def test_startup_projection_invalid_values_fall_back_without_poison(self) -> None:
        secret = "POISONOUS-STARTUP-SECRET-143"

        class Poison:
            def __str__(self):
                return secret

            def __repr__(self):
                return secret

        projection = serving.StartupProjection()
        projection._stage = Poison()
        projection._exit_status = Poison()
        projection.failed = True
        projection.touched = True
        error = provisioning.BackendIdentityConflictPhaseError(
            Phase.start_conflicting, "RuntimeError", startup_projection=projection)
        diagnostic = error.diagnostic()
        self.assertEqual(diagnostic["startup_stage"], "other")
        self.assertEqual(diagnostic["exit_status"], "not_applicable")
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, json.dumps(diagnostic, sort_keys=True))
        self.assertNotIn(secret, json.dumps(error.args, sort_keys=True))
        other = provisioning.BackendIdentityConflictPhaseError(
            Phase.start_conflicting, "RuntimeError", startup_projection=Poison())
        self.assertEqual(other.diagnostic()["startup_stage"], "other")
        self.assertEqual(other.diagnostic()["exit_status"], "not_applicable")
        self.assertNotIn(secret, str(other))
        self.assertEqual(
            provisioning._validated_startup_fields(True, 101), ("other", "not_applicable"))
        self.assertEqual(
            provisioning._validated_startup_fields("child_exit", 1),
            ("child_exit", "other_exit"))
        self.assertEqual(serving._exit_status_from_returncode(True), "other_exit")
        self.assertEqual(serving._exit_status_from_returncode(False), "other_exit")
        self.assertEqual(serving._exit_status_from_returncode("1"), "other_exit")
        self.assertEqual(serving._exit_status_from_returncode(-15), "signaled")
        self.assertEqual(serving._exit_status_from_returncode(0), "exited_0")
        self.assertEqual(serving._exit_status_from_returncode(1), "exited_1")
        self.assertEqual(serving._exit_status_from_returncode(101), "exited_101")
        self.assertEqual(serving._exit_status_from_returncode(2), "other_exit")

    def test_startup_observation_is_inert_without_the_phase_projection(self) -> None:
        harness = _StartHarness(proc=lambda: _FakeProc(returncode=1))
        with _patched_serving(harness):
            with self.assertRaises(RuntimeError) as caught:
                harness.start()
        self.assertEqual(
            str(caught.exception),
            "serve-blob exited during startup with status 1")
        self.assertEqual(harness.popen_calls, 1)
        self.assertEqual(harness.popen_proc.poll_calls, 1)
        self.assertEqual(harness.http_calls, 0)
        self.assertEqual(harness.stop_calls, [False])
        self.assertEqual(harness.hash_calls, 0)
        self.assertEqual(harness.native_calls, 0)
        harness = _StartHarness(proc=lambda: _FakeProc(returncode=1))
        with _patched_serving(harness):
            with self.assertRaises(RuntimeError):
                harness.start(startup_projection=object())
        self.assertEqual(harness.stop_calls, [False])

    def test_closed_projection_leaves_inventory_and_failure_status_unchanged(self) -> None:
        self.assertEqual(provisioning.CASES, EXPECTED_CASES)
        self.assertEqual(provisioning.FIRST_CHECKPOINT, EXPECTED_CASES[:4])
        self.assertEqual(provisioning.SECOND_CHECKPOINT, EXPECTED_CASES[4:5])
        self.assertEqual(provisioning.REFUSAL_CHECKPOINT, EXPECTED_CASES[5:7])
        self.assertEqual(provisioning.STARTUP_CHECKPOINT, EXPECTED_CASES[7:])
        harness = _BackendIdentityCaseDouble(fail_phase=Phase.initial_create)
        error = self._run_failing_backend_case(harness)
        self.assertEqual(len(harness.results), 1)
        self.assertEqual(set(harness.results[0]), {"name", "status", "seconds", "error"})
        self.assertEqual(harness.results[0]["name"], BACKEND_CASE)
        self.assertEqual(harness.results[0]["status"], "failed")
        self.assertEqual(harness.results[0]["error"], str(error))


if __name__ == "__main__":
    unittest.main()
