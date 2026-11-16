#!/usr/bin/env python3
"""Real-service receive-pack COMMIT ambiguity acceptance for #107.

Root supplies the same attested Blob standalone inputs as
`tests/blob_only_service.py`: --binary plus its adjacent .build.json, an
absolute --git/ROOTYARD_GIT, ROOTYARD_TEST_DATABASE_URL and the strict
ROOTYARD_BLOB_* OpenDAL S3 profile. This harness owns only a random schema and
its loopback server; it never seeds a ready repository or a successful ACK.

The commit case creates a repository through the real API, pushes a seed through
stock Git and then sends one raw v1 receive-pack POST. A fixture-owned deferred
constraint trigger on ref_store_core_events waits on a session advisory lock
held only by this harness. The service therefore issues the real final COMMIT
and waits past its own 30-second verifier deadline while the outer 60-second
request budget is still open. The wire response must be the typed unknown 503
with the operation id and no Git report. The unchanged/pending ledger is
asserted while the lock is still held. The fixture then terminates the
still-blocked COMMIT backend when present and releases its lock, so the original
final transaction is durably aborted and the registered operation remains
pending. This fixture resolves the pending operation only through the explicit
authorized POST .../cancel route; it never retries the same operation id
expecting an automatic recommit. A separate real committed operation proves the
commit-wins branch: Cancel must return that exact old terminal. The fixture
snapshots exact refs,
gate identity, events, terminal and pack rows rather than counting them, and
covers unknown/cross-repository/no-A3/non-admin/read-only/invalid-auth refusals
without creating a ready repository through SQL.

A separate real API-created and stock-Git-seeded proof repository carries the
one-row `repository_collaborators` write-role fixture used to prove Bob's actual
read and write path, a real committed operation/terminal, and identical 403
refusals for his known operation and an unknown UUID. That SQL row is role
metadata only; it never writes readiness, refs, operations, A3/A4 bindings,
ACKs, gate/events or a terminal. The original strict ledger stays separate from
this proof repository so its counts and final equality are unchanged.

By default the same native process also re-runs the existing exact receive
replay/digest-conflict and transient-read cleanup cases from
`tests/blob_only_service.py`.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as blob
import native_evidence

COMMIT_CASE = "receive_pack_commit_unknown_resolves_exact"
EXACT_REPLAY_CASE = "exact_receive_post_replays_before_native_without_second_effect"
TRANSIENT_READ_CASE = "registered_read_cycles_do_not_exhaust_retained_snapshot_quota"
CASES = (COMMIT_CASE, EXACT_REPLAY_CASE, TRANSIENT_READ_CASE)
LIMITATIONS = [item for item in blob.LIMITATIONS
               if not item.startswith("No SQL row creates a ready repository")] + [
    "The COMMIT ambiguity is fixture-owned PostgreSQL deferred-trigger/advisory-lock timing, not a kernel or power-loss claim.",
    "The harness waits for the service's own verifier deadline; it does not inject a product success or override the wire verdict.",
    "A settled pending operation is not resolved by an automatic same-ID recommit. It is resolved only by the explicit authorized Cancel route; a same-wire receive replay after that Cancel must return the stable cancellation report, and a fresh operation ID is required for a later publication.",
    "The cancel-wins path terminates only the fixture-blocked COMMIT backend when it is still present, then releases the deferred trigger and waits for every COMMIT statement to finish before calling Cancel. The original COMMIT is durably aborted; this is a serialized abort-then-cancel sequence, not an overlapping cancel/commit race and not power-loss evidence.",
    "The commit-wins path is exercised by a separate real committed operation; Cancel must return that exact committed terminal and must not relabel it cancelled.",
    "Cancel-COMMIT ambiguity is retained as a 503-unknown code path but is not forced by this fixture.",
    "The no-A3 refusal fixture inserts one migration-138 pending operation row without its migration-147 binding into a real API-created repository; it does not create a ready repository, decision, ref or ACK.",
    "The write-role fixture is one direct repository_collaborators role-metadata row in this run's random schema. The standalone serve-blob router does not mount the product collaborator-management route; this is not a product-route or service-level collaboration-management test.",
    "That role-metadata row never writes readiness, serving bindings, refs, operations, A3/A4 bindings, ACKs, gate/event state, cancellation tombstones or a terminal. Bob's actual GET, clone, commit, push and committed operation/terminal are produced separately by the real API and stock Git.",
]


def input_hashes():
    root = Path(__file__).resolve().parent
    names = (Path(__file__).name, "blob_only_service.py", "e2e.py", "native_evidence.py",
             "ops_provenance.py", "owned_fuse_cleanup.py")
    return {name: blob.sha256_file(root / name) for name in names}


class CheckpointProfile(blob.NativeProfile):
    def __init__(self, binary, git_flag, env):
        super().__init__(binary, git_flag, env)
        self.checkpoint_sha256 = blob.sha256_file(Path(__file__))


def rows(value):
    return json.loads(value)


def row_for(items, field, expected):
    matches = [item for item in items if item.get(field) == expected]
    if len(matches) != 1:
        raise AssertionError("expected one row for " + field + "=" + str(expected) + ", got " + repr(matches))
    return matches[0]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def pack_identity_summary(pack):
    publication_fields = ("registration_id", "pack_id", "plan_operation_id", "planned_pack_sha256",
                          "planned_idx_sha256", "planned_pack_length", "planned_idx_length",
                          "artifact_set_digest", "gate_revision", "gate_digest", "pack_mode", "backend_identity")
    artifact_fields = ("registration_id", "role", "pack_id", "namespace", "sha256", "content_length", "logical_bytes")
    return {
        "publications": [{field: item[field] for field in publication_fields}
                         for item in rows(pack["publications"])],
        "artifacts": [{field: item[field] for field in artifact_fields} for item in rows(pack["artifacts"])],
    }


# Fields that identify the gate realm and must not move when a cancellation
# leaves refs/events unchanged. Revision and digest are expected to move only
# with a real publication, so they are compared separately.
GATE_IDENTITY_FIELDS = ("repository_id", "tenant_id", "object_format", "history_incarnation",
                        "authority_epoch", "group_epoch", "head_ref")


def gate_identity(gate):
    items = rows(gate)
    assert len(items) == 1, items
    return {field: items[0][field] for field in GATE_IDENTITY_FIELDS}


class CheckpointHarness(blob.BlobOnlyHarness):
    def __init__(self, args, profile, blob_profile):
        super().__init__(args, profile, blob_profile)
        # The verifier stage clamps itself to 30s; keep the whole request open
        # well past that so the typed COMMIT-unknown wins over the HTTP timeout.
        self.env["ROOTYARD_GIT_TIMEOUT_SECONDS"] = "60"

    def _long_http(self, path, token, body, operation, timeout=75):
        headers = {
            "Authorization": "Bearer " + token["token"],
            "Content-Type": "application/x-git-receive-pack-request",
            "X-Rootyard-Operation": operation,
        }
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status, payload, response_headers = response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            status, payload, response_headers = error.code, error.read(), dict(error.headers)
        native_evidence.record(self, "http_response", method="POST",
                               path=path.split("?", 1)[0], status=status, response_bytes=len(payload))
        return status, payload, response_headers

    def _json_rows(self, repo_id, table, order, predicate=""):
        rid = str(uuid.UUID(repo_id))
        return self.sql(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY " + order + "), '[]'::jsonb)::text "
            "FROM " + table + " t WHERE t.repository_id='" + rid + "'" + predicate)

    def exact_ledger(self, repo_id):
        return {
            "refs": self._json_rows(repo_id, "ref_store_core_refs", "t.ref_name"),
            "gate": self._json_rows(repo_id, "ref_store_core_gates", "t.repository_id"),
            "events": self._json_rows(repo_id, "ref_store_core_events", "t.event_id"),
            "operations": self._json_rows(repo_id, "ref_store_operations", "t.operation_id"),
        }

    def pack_identity(self, repo_id, operation):
        rid = str(uuid.UUID(repo_id))
        operation = str(uuid.UUID(operation))
        return {
            "publications": self.sql(
                "SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.registration_id), '[]'::jsonb)::text "
                "FROM ref_store_core_pack_publications p "
                "WHERE p.repository_id='" + rid + "' AND p.plan_operation_id='" + operation + "'"),
            "artifacts": self.sql(
                "SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.registration_id,a.role), '[]'::jsonb)::text "
                "FROM ref_store_core_pack_artifacts a "
                "JOIN ref_store_core_pack_publications p ON p.registration_id=a.registration_id "
                "WHERE p.repository_id='" + rid + "' AND p.plan_operation_id='" + operation + "'"),
        }

    def operation_row(self, repo_id, operation):
        row = self.operation_row_optional(repo_id, operation)
        assert row is not None, "operation row is missing"
        return row

    def operation_row_optional(self, repo_id, operation):
        rid = str(uuid.UUID(repo_id))
        operation = str(uuid.UUID(operation))
        raw = self.sql(
            "SELECT to_jsonb(o)::text FROM ref_store_operations o "
            "WHERE o.repository_id='" + rid + "' AND o.operation_id='" + operation + "'")
        return json.loads(raw) if raw else None

    def cancellation_snapshot(self, repo_id, operation):
        """The two durable cancellation tombstones for one repository operation."""
        rid = str(uuid.UUID(repo_id))
        operation = str(uuid.UUID(operation))
        return {
            "legacy": rows(self.sql(
                "SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.sequence), '[]'::jsonb)::text "
                "FROM ref_store_cancellations c WHERE c.repository_id='" + rid
                + "' AND c.operation_id='" + operation + "'")),
            "decision": rows(self.sql(
                "SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.operation_id), '[]'::jsonb)::text "
                "FROM ref_store_decision_cancellations d WHERE d.repository_id='" + rid
                + "' AND d.operation_id='" + operation + "'")),
        }

    def insert_unbound_operation(self, repo_id, seed_operation, operation):
        """Insert one real migration-138 pending row without its A3 producer binding.

        This is not a ready-repository or ACK fixture: the repository was created
        and seeded through the real API/Git path. It exists only to prove the
        cancel route refuses a core row that lacks its exact migration-147
        binding instead of falling back to a weaker cancellation.
        """
        rid = str(uuid.UUID(repo_id))
        issuer = str(uuid.UUID(seed_operation["issuer_id"]))
        operation = str(uuid.UUID(operation))
        lane = seed_operation["lane"]
        # Migration 138's lane CHECK allows exactly this alphabet; asserting it
        # keeps the fixture's SQL interpolation exact.
        assert lane and all(c.isalnum() or c in "._:-" for c in lane), lane
        sequence = int(seed_operation["sequence"]) + 1000000
        request_digest = digest("unbound-operation:" + operation)
        self.sql(
            "INSERT INTO ref_store_operations"
            "(repository_id,issuer_id,lane,sequence,operation_id,request_digest,state) "
            "VALUES('" + rid + "','" + issuer + "','" + lane + "'," + str(sequence)
            + ",'" + operation + "','" + request_digest + "','pending')")
        return request_digest

    def add_write_collaborator(self, repo, label):
        """Insert exactly one repository_collaborators role-metadata row.

        The standalone serve-blob router deliberately does not mount the product
        collaborator-management API. This fixture therefore stores Bob's write
        role directly in this process's own random schema, only after the
        repository was created through POST /api/repos and seeded with stock
        Git. The SQL is role configuration only. It never creates a ready
        repository, serving binding, ref, operation, A3 producer binding, A4
        publication, gate/event/ACK, cancellation tombstone or terminal; those
        remain outcomes of the real API and stock Git calls.
        """
        schema = self.sql("SELECT current_schema()")
        assert schema == self.schema, ("phase=" + label + " collaborator fixture: not the owned schema", schema)
        rid = str(uuid.UUID(repo["id"]))
        bob_id = str(uuid.UUID(self.bob["user_id"]))
        actual = self.sql(
            "SELECT r.owner_id::text || '|' || u.id::text "
            "FROM repositories r JOIN users u ON u.id='" + bob_id + "' "
            "WHERE r.id='" + rid + "' AND u.username='bob'")
        assert actual, ("phase=" + label + " collaborator fixture: missing owned repository or Bob user",
                        rid, bob_id)
        owner_id, resolved_bob = actual.split("|", 1)
        assert resolved_bob == bob_id, ("phase=" + label + " collaborator fixture: Bob id mismatch", actual)
        assert owner_id != bob_id, ("phase=" + label + " collaborator fixture: Bob must not be the owner", actual)
        # Migration 050 binds collaborators (repository_id, tenant_id) to
        # repositories (id, owner_id), so the actual tenant is the owner id read
        # from this run's repository row, never a global/user-supplied value.
        inserted = self.sql(
            "WITH inserted AS ("
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role) "
            "VALUES('" + rid + "','" + owner_id + "','" + bob_id + "','write') "
            "RETURNING role || '|' || tenant_id::text || '|' || user_id::text AS row_text"
            ") SELECT row_text FROM inserted")
        assert inserted == "write|" + owner_id + "|" + bob_id, (
            "phase=" + label + " collaborator fixture: unexpected inserted role row", inserted)
        count = self.sql(
            "SELECT count(*) FROM repository_collaborators "
            "WHERE repository_id='" + rid + "' AND tenant_id='" + owner_id + "' AND user_id='" + bob_id + "'")
        assert count == "1", ("phase=" + label + " collaborator fixture: expected exactly one role row", count)

    def _create_commit_gate(self, key):
        self.sql(
            "CREATE FUNCTION rootyard_commit_unknown_gate() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN PERFORM pg_advisory_xact_lock(" + str(key) + "); RETURN NEW; END $$; "
            "CREATE CONSTRAINT TRIGGER rootyard_commit_unknown_gate "
            "AFTER INSERT ON ref_store_core_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "EXECUTE FUNCTION rootyard_commit_unknown_gate();")

    def _drop_commit_gate(self):
        self.sql(
            "SET lock_timeout='5s'; "
            "DROP TRIGGER IF EXISTS rootyard_commit_unknown_gate ON ref_store_core_events; "
            "DROP FUNCTION IF EXISTS rootyard_commit_unknown_gate();")

    @staticmethod
    def _validate_blocker_application_name(application_name):
        assert isinstance(application_name, str), "fixture blocker application_name must be text"
        try:
            raw = application_name.encode("ascii")
        except UnicodeEncodeError as error:
            raise AssertionError("fixture blocker application_name must be ASCII") from error
        assert 0 < len(raw) <= 63, "fixture blocker application_name exceeds 63 bytes"
        assert application_name.startswith(
            ("rootyard-commit-gate-", "rootyard-cancel-scope-")), \
            "fixture blocker application_name has an unexpected prefix"
        assert all(ch.isalnum() or ch in "-._" for ch in application_name), \
            "fixture blocker application_name has unsafe characters"

    def _owned_blocker_rows(self, application_name):
        self._validate_blocker_application_name(application_name)
        raw = self.sql(
            "SELECT coalesce(jsonb_agg(jsonb_build_object("
            "'pid',a.pid,'database',a.datname,'backend_start',a.backend_start::text) "
            "ORDER BY a.backend_start), '[]'::jsonb)::text "
            "FROM pg_stat_activity a "
            "WHERE a.application_name='" + application_name + "' "
            "AND a.datname=current_database()")
        return json.loads(raw)

    def _owned_advisory_lock_count(self, application_name):
        self._validate_blocker_application_name(application_name)
        return int(self.sql(
            "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid "
            "WHERE a.application_name='" + application_name + "' "
            "AND a.datname=current_database() AND l.locktype='advisory'"))

    @staticmethod
    def _blocker_row_matches(row, identity):
        return (
            isinstance(row, dict)
            and row.get("pid") == identity.get("pid")
            and row.get("database") == identity.get("database")
            and row.get("backend_start") == identity.get("backend_start")
        )

    def _register_owned_blocker(self, process, application_name):
        self._validate_blocker_application_name(application_name)
        rows = self._owned_blocker_rows(application_name)
        assert len(rows) == 1, "fixture blocker ownership is not a single backend"
        row = rows[0]
        pid = row.get("pid")
        database = row.get("database")
        backend_start = row.get("backend_start")
        assert type(pid) is int and pid > 0, "fixture blocker backend pid is invalid"
        assert database == self.sql("SELECT current_database()"), \
            "fixture blocker backend database is not owned"
        assert isinstance(backend_start, str) and backend_start, \
            "fixture blocker backend_start is missing"
        assert "'" not in backend_start, "fixture blocker backend_start is not SQL-safe"
        assert process.poll() is None, "fixture blocker child exited before ownership registration"
        identity = {
            "application_name": application_name,
            "database": database,
            "pid": pid,
            "backend_start": backend_start,
        }
        process._rootyard_blocker_identity = identity
        return identity

    def _register_owned_blocker_or_reap(self, process, application_name):
        try:
            return self._register_owned_blocker(process, application_name)
        except Exception:
            self._reap_blocker_child(process)
            raise

    def _reap_blocker_child(self, process):
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        except ValueError:
            pass
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def _start_blocker(self, key, application_name):
        self._validate_blocker_application_name(application_name)
        env = self.env.copy()
        env["PGDATABASE"] = self.db
        env["PGAPPNAME"] = application_name
        process = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
             "SET application_name='" + application_name + "'; "
             "SELECT pg_advisory_lock(" + str(key) + "); SELECT pg_sleep(300);"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, error = process.communicate()
                raise AssertionError("fixture advisory-lock session exited: "
                                     + self.redact(error[:500].decode(errors="replace")))
            held = int(self.sql(
                "SELECT count(*) FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid "
                "WHERE a.application_name='" + application_name + "' "
                "AND a.datname=current_database() AND l.locktype='advisory' AND l.granted"))
            if held == 1:
                self._register_owned_blocker_or_reap(process, application_name)
                return process
            time.sleep(0.05)
        self._reap_blocker_child(process)
        raise AssertionError("fixture advisory lock was not acquired")

    def _release_blocker(self, process):
        self._reap_blocker_child(process)
        identity = getattr(process, "_rootyard_blocker_identity", None)
        assert isinstance(identity, dict), "fixture blocker ownership identity is missing"
        application_name = identity.get("application_name")
        self._validate_blocker_application_name(application_name)
        rows = self._owned_blocker_rows(application_name)
        if not rows:
            assert self._owned_advisory_lock_count(application_name) == 0, \
                "fixture blocker advisory lock remained without an owned backend"
            return
        assert len(rows) == 1, "fixture blocker ownership is no longer a single backend"
        assert self._blocker_row_matches(rows[0], identity), \
            "fixture blocker ownership changed; refusing foreign termination"
        pid = identity["pid"]
        backend_start = identity["backend_start"]
        terminated = self.sql(
            "WITH owned AS MATERIALIZED ("
            "SELECT a.pid FROM pg_stat_activity a "
            "WHERE a.application_name='" + application_name + "' "
            "AND a.datname=current_database() AND a.pid=" + str(pid)
            + " AND a.backend_start::text='" + backend_start + "'"
            + " AND a.pid<>pg_backend_pid()) "
            "SELECT count(*) FROM owned WHERE pg_terminate_backend(owned.pid)")
        if terminated != "1":
            rows = self._owned_blocker_rows(application_name)
            if not rows and self._owned_advisory_lock_count(application_name) == 0:
                return
            raise AssertionError("fixture could not terminate exact owned blocker backend")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            rows = self._owned_blocker_rows(application_name)
            if not rows:
                assert self._owned_advisory_lock_count(application_name) == 0, \
                    "fixture blocker advisory lock remained after owned backend exit"
                return
            assert len(rows) == 1, "fixture blocker ownership changed while awaiting release"
            assert self._blocker_row_matches(rows[0], identity), \
                "fixture blocker ownership changed while awaiting release"
            time.sleep(0.05)
        raise AssertionError("fixture blocker backend did not disappear after exact terminate")

    @staticmethod
    def _advisory_key_parts(key):
        key = int(key)
        return (key >> 32) & 0xFFFFFFFF, key & 0xFFFFFFFF

    def _waiting_commit_pid(self, key):
        """The one service COMMIT waiting on this fixture's advisory-lock key."""
        classid, objid = self._advisory_key_parts(key)
        return self.sql(
            "SELECT a.pid FROM pg_stat_activity a "
            "JOIN pg_locks l ON l.pid=a.pid AND l.locktype='advisory' "
            "WHERE a.datname=current_database() AND a.state='active' "
            "AND regexp_replace(a.query, '\\s+', '', 'g') IN ('COMMIT','COMMIT;') "
            "AND a.wait_event_type='Lock' AND a.wait_event='advisory' "
            "AND l.granted=false AND l.classid::bigint=" + str(classid)
            + " AND l.objid::bigint=" + str(objid) + " AND l.objsubid=1 LIMIT 1")

    def _await_waiting_commit(self, key):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pid = self._waiting_commit_pid(key)
            if pid:
                return int(pid)
            time.sleep(0.1)
        raise AssertionError("HTTP receive-pack COMMIT never blocked on the fixture deferred trigger")

    def _await_commit_finished(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            active = int(self.sql(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname=current_database() AND state='active' "
                "AND regexp_replace(query, '\\s+', '', 'g') IN ('COMMIT','COMMIT;')"))
            if active == 0:
                return
            time.sleep(0.1)
        raise AssertionError("receive-pack COMMIT did not settle after the fixture release")

    def receive_pack_commit_unknown_resolves_exact(self):
        repo, _remote, work, old_oid = self.seed("commit-unknown", self.alice)
        before = self.exact_ledger(repo["id"])
        baseline_gate_identity = gate_identity(before["gate"])
        seed_operations = rows(before["operations"])
        assert len(seed_operations) == 1, seed_operations
        seed_operation = seed_operations[0]
        base_revision = rows(before["gate"])[0]["revision"]
        assert base_revision >= 2, base_revision
        new_revision = base_revision + 1

        new_oid = self.commit_files(work, "ambiguous commit", {"ambiguous.txt": "unknown must not be success or failure\n"})
        assert new_oid != old_oid
        pack = self.run([str(self.profile.git), "--no-pager", "pack-objects", "--stdout", "--all"],
                        cwd=work, data=b"").stdout
        assert pack.startswith(b"PACK") and len(pack) > 32, "trusted Git produced no pack stream"
        body = blob.receive_pack_request(old_oid, new_oid, "refs/heads/main", pack)
        operation = str(uuid.uuid4())
        path = repo["clone_path"] + "/git-receive-pack"
        key = uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF
        application_name = "rootyard-commit-gate-" + uuid.uuid4().hex
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        blocker = None
        try:
            self._create_commit_gate(key)
            blocker = self._start_blocker(key, application_name)
            future = executor.submit(self._long_http, path, self.alice, body, operation)
            commit_pid = self._await_waiting_commit(key)
            assert not future.done(), "receive-pack returned before the deferred COMMIT barrier"
            wire_status, response, response_headers = future.result(timeout=80)
            # The COMMIT barrier is still held. Assert the unknown boundary and
            # the unchanged/pending state now, before any release can let the
            # server-side COMMIT land.
            assert wire_status == 503, ("COMMIT ambiguity wire status=" + str(wire_status)
                                        + ": " + repr(response[:300]))
            assert blob.header_value(response_headers, "x-rootyard-operation") == operation, response_headers
            wire_error = json.loads(response)
            assert wire_error == {"error": "publication outcome is unknown; query the operation or inspect refs"}, wire_error
            for marker in (b"unpack ok", b"ok refs/heads/main", b"ng refs/heads/main"):
                assert marker not in response, "unknown COMMIT carried a Git report: " + repr(response[:300])
            inflight = self.exact_ledger(repo["id"])
            assert rows(inflight["refs"]) == rows(before["refs"]), "unknown COMMIT moved a ref before release"
            assert rows(inflight["gate"]) == rows(before["gate"]), "unknown COMMIT moved the gate before release"
            assert rows(inflight["events"]) == rows(before["events"]), "unknown COMMIT wrote an event before release"
            inflight_operations = rows(inflight["operations"])
            assert len(inflight_operations) == 2, inflight_operations
            assert row_for(inflight_operations, "operation_id", seed_operation["operation_id"]) == seed_operation
            inflight_operation = self.operation_row(repo["id"], operation)
            assert inflight_operation == row_for(inflight_operations, "operation_id", operation)
            assert inflight_operation["state"] == "pending", inflight_operation
            assert inflight_operation["terminal_result"] is None, inflight_operation
            inflight_pack = self.pack_identity(repo["id"], operation)
            inflight_publications = rows(inflight_pack["publications"])
            inflight_artifacts = rows(inflight_pack["artifacts"])
            assert len(inflight_publications) == 1, inflight_publications
            assert len(inflight_artifacts) == 2, inflight_artifacts
            assert sorted(item["role"] for item in inflight_artifacts) == ["idx", "pack"], inflight_artifacts
            assert inflight_publications[0]["plan_operation_id"] == operation, inflight_publications
            assert ({item["registration_id"] for item in inflight_artifacts}
                    == {inflight_publications[0]["registration_id"]}), inflight_artifacts
            # Force a deterministic durable-pending settlement: terminate only
            # the service's fixture-blocked COMMIT backend, then release the
            # fixture lock. The service already returned the typed unknown; its
            # server-side transaction is aborted, so the pending row remains and
            # explicit Cancel is the only resolution. This is a serialized
            # abort-then-cancel sequence, not an overlapping cancel/commit race.
            blocked_pid = self._waiting_commit_pid(key)
            if blocked_pid:
                assert int(blocked_pid) == commit_pid, "fixture found a different blocked COMMIT backend"
                terminated = self.sql("SELECT pg_terminate_backend(" + str(commit_pid) + ")")
                assert terminated == "t", "fixture could not terminate the blocked COMMIT backend"
            self._release_blocker(blocker)
            blocker = None
        finally:
            try:
                if blocker is not None:
                    self._release_blocker(blocker)
            finally:
                try:
                    executor.shutdown(wait=True, cancel_futures=False)
                    self._await_commit_finished()
                finally:
                    self._drop_commit_gate()

        def repo_operation_path(target_operation):
            return ("/api/repos/" + urllib.parse.quote(repo["owner"], safe="") + "/"
                    + urllib.parse.quote(repo["name"], safe="") + "/operations/" + target_operation)

        def cancel_path_for(target_operation):
            return repo_operation_path(target_operation) + "/cancel"

        def get_view(target_operation, label, expected=None):
            status, raw, headers = self.http(repo_operation_path(target_operation), token=self.alice)
            assert status == 200, "GET operation " + label + ": " + str(status) + ": " + repr(raw[:300])
            assert blob.header_value(headers, "cache-control") == "no-store", headers
            parsed = json.loads(raw)
            assert parsed["operation_id"] == target_operation, parsed
            if expected is not None:
                assert parsed["state"] == expected, parsed
            return status, parsed

        def post_cancel(target_operation, token=None):
            status, raw, headers = self.http(cancel_path_for(target_operation), token=token, method="POST")
            assert blob.header_value(headers, "cache-control") == "no-store", headers
            return status, raw, headers

        def assert_error(raw):
            body = json.loads(raw)
            assert set(body) == {"error"}, body
            return body["error"]

        view = get_view(operation, "after settlement")[1]
        # The fixture terminated the blocked COMMIT backend before releasing
        # its lock, so the original final transaction is durably aborted and the
        # operation is still pending. This is a no-effect state, never an
        # acceptance. Only the explicit authorized Cancel resolves it.
        assert view["state"] == "pending", view
        assert view["terminal"] is None, view
        resolved_by = "explicit_cancel"
        settled = self.exact_ledger(repo["id"])
        assert settled["refs"] == before["refs"], "settled pending COMMIT moved a ref"
        assert settled["gate"] == before["gate"], "settled pending COMMIT moved the gate"
        assert gate_identity(settled["gate"]) == baseline_gate_identity, settled["gate"]
        assert settled["events"] == before["events"], "settled pending COMMIT wrote an event"
        settled_operations = rows(settled["operations"])
        assert len(settled_operations) == 2, settled_operations
        assert row_for(settled_operations, "operation_id", seed_operation["operation_id"]) == seed_operation
        settled_operation = self.operation_row(repo["id"], operation)
        assert row_for(settled_operations, "operation_id", operation) == settled_operation
        assert settled_operation["state"] == "pending", settled_operation
        assert settled_operation["terminal_result"] is None, settled_operation
        assert self.pack_identity(repo["id"], operation) == inflight_pack, \
            "pending settlement changed the durable pack identity"

        cancel_status, cancel_raw, _ = post_cancel(operation, self.alice)
        assert cancel_status == 200, "pending cancel: " + str(cancel_status) + ": " + repr(cancel_raw[:300])
        cancel_view = json.loads(cancel_raw)
        assert set(cancel_view) == {"operation_id", "state", "terminal"}, cancel_view
        assert cancel_view["operation_id"] == operation, cancel_view
        assert cancel_view["state"] == "cancelled", cancel_view
        cancel_terminal = cancel_view["terminal"]
        assert cancel_terminal == {"state": "cancelled", "reason": "cancel_requested"}, cancel_terminal

        _, canonical = get_view(operation, "after explicit cancel", "cancelled")
        assert canonical == cancel_view

        cancelled = self.exact_ledger(repo["id"])
        assert cancelled["refs"] == before["refs"], "cancel moved a ref"
        assert cancelled["gate"] == before["gate"], "cancel moved the gate"
        assert gate_identity(cancelled["gate"]) == baseline_gate_identity, cancelled["gate"]
        assert cancelled["events"] == before["events"], "cancel wrote an event"
        cancelled_operation = self.operation_row(repo["id"], operation)
        assert cancelled_operation["state"] == "cancelled", cancelled_operation
        assert cancelled_operation["terminal_result"] == cancel_terminal, cancelled_operation
        assert row_for(rows(cancelled["operations"]), "operation_id",
                       seed_operation["operation_id"]) == seed_operation
        assert self.pack_identity(repo["id"], operation) == inflight_pack, \
            "cancel changed the durable pack identity"

        tombstones = self.cancellation_snapshot(repo["id"], operation)
        assert len(tombstones["legacy"]) == 1, tombstones
        legacy = tombstones["legacy"][0]
        assert legacy["operation_id"] == operation, legacy
        assert legacy["request_digest"] == settled_operation["request_digest"], legacy
        assert len(tombstones["decision"]) == 1, tombstones
        decision = tombstones["decision"][0]
        assert decision["reason"] == "http_cancel_requested", decision
        assert decision["actor_id"] == self.alice["user_id"], decision

        # The exact same wire bytes for the cancelled operation ID replay the
        # stable cancellation report without touching any durable effect.
        same_wire_status, same_wire_body, same_wire_headers = self._long_http(
            path, self.alice, body, operation)
        assert same_wire_status == 200, ("same-wire cancellation replay: "
                                         + str(same_wire_status) + " " + repr(same_wire_body[:300]))
        assert blob.header_value(same_wire_headers, "x-rootyard-operation") == operation, same_wire_headers
        unpack, statuses = blob.parse_receive_report(same_wire_body)
        assert unpack == "unpack ok", unpack
        assert statuses == ["ng refs/heads/main operation was cancelled"], statuses
        after_replay = self.exact_ledger(repo["id"])
        assert after_replay == cancelled, "same-wire cancellation replay changed durable state"
        assert self.pack_identity(repo["id"], operation) == inflight_pack
        assert self.cancellation_snapshot(repo["id"], operation) == tombstones, \
            "same-wire cancellation replay changed a tombstone"
        _, replay_view = get_view(operation, "after same-wire replay", "cancelled")
        assert replay_view == cancel_view

        # A different wire body under the same operation ID is a conflict,
        # never a second cancellation or an inherited unknown outcome.
        divergent_oid = self.commit_files(work, "divergent wire body",
                                          {"divergent.txt": "a different wire body\n"})
        divergent_pack = self.run([str(self.profile.git), "--no-pager",
                                   "pack-objects", "--stdout", "--all"],
                                  cwd=work, data=b"").stdout
        assert divergent_pack.startswith(b"PACK") and len(divergent_pack) > 32
        divergent_body = blob.receive_pack_request(old_oid, divergent_oid, "refs/heads/main", divergent_pack)
        divergent_status, divergent_raw, divergent_headers = self._long_http(
            path, self.alice, divergent_body, operation)
        assert divergent_status == 409, ("divergent-wire cancel replay: "
                                         + str(divergent_status) + " " + repr(divergent_raw[:300]))
        assert blob.header_value(divergent_headers, "x-rootyard-operation") == operation, divergent_headers
        assert blob.header_value(divergent_headers, "cache-control") == "no-store", divergent_headers
        divergent_error = assert_error(divergent_raw)
        assert "different request" in divergent_error, divergent_error
        for marker in (b"unpack ok", b"ok refs/heads/main", b"ng refs/heads/main"):
            assert marker not in divergent_raw, "divergent replay carried a Git report: " + repr(divergent_raw[:300])
        after_divergent = self.exact_ledger(repo["id"])
        assert after_divergent == cancelled, "divergent-wire conflict changed durable state"
        assert self.pack_identity(repo["id"], operation) == inflight_pack
        assert self.cancellation_snapshot(repo["id"], operation) == tombstones, \
            "divergent-wire conflict changed a tombstone"
        _, divergent_view = get_view(operation, "after divergent wire", "cancelled")
        assert divergent_view == cancel_view

        # After cancellation the client may use a NEW operation ID for the
        # same wire bytes; that fresh operation must be able to commit and
        # must not mutate the old cancelled operation or its pack snapshot.
        new_operation = str(uuid.uuid4())
        new_status, new_body, new_headers = self._long_http(path, self.alice, body, new_operation)
        assert new_status == 200, ("new operation after cancellation: "
                                   + str(new_status) + " " + repr(new_body[:300]))
        assert blob.header_value(new_headers, "x-rootyard-operation") == new_operation, new_headers
        blob.assert_receive_report_ok(new_body, "refs/heads/main")
        _, new_view = get_view(new_operation, "new operation", "committed")
        new_terminal = new_view["terminal"]
        assert new_terminal is not None and new_terminal["kind"] == "committed", new_view

        resolved = self.exact_ledger(repo["id"])
        resolved_operations = rows(resolved["operations"])
        assert len(resolved_operations) == 3, resolved_operations
        assert row_for(resolved_operations, "operation_id", seed_operation["operation_id"]) == seed_operation
        assert row_for(resolved_operations, "operation_id", operation) == cancelled_operation
        new_operation_row = self.operation_row(repo["id"], new_operation)
        assert row_for(resolved_operations, "operation_id", new_operation) == new_operation_row
        assert new_operation_row["state"] == "committed", new_operation_row
        assert new_operation_row["terminal_result"] == new_terminal, new_operation_row

        ref_rows = rows(resolved["refs"])
        assert len(ref_rows) == 1, ref_rows
        ref_row = row_for(ref_rows, "ref_name", "refs/heads/main")
        assert ref_row["oid"] == new_oid and ref_row["revision"] == new_revision, ref_row
        gate_rows = rows(resolved["gate"])
        assert len(gate_rows) == 1, gate_rows
        gate_row = gate_rows[0]
        assert gate_row["revision"] == new_revision and gate_row["head_ref"] == "refs/heads/main", gate_row
        assert gate_identity(resolved["gate"]) == baseline_gate_identity, resolved["gate"]
        event_rows = rows(resolved["events"])
        assert len(event_rows) == len(rows(before["events"])) + 1, event_rows
        for prior_event in rows(before["events"]):
            assert row_for(event_rows, "event_id", prior_event["event_id"]) == prior_event, \
                "an existing event changed during the new operation"
        event = row_for(event_rows, "operation_id", new_operation)
        assert event["outcome"] == "committed" and event["revision"] == new_revision, event
        assert event["payload"] == new_terminal, "new event payload differs from its terminal"

        assert self.pack_identity(repo["id"], operation) == inflight_pack, \
            "the new operation changed the cancelled pack snapshot"
        new_pack = self.pack_identity(repo["id"], new_operation)
        new_publications = rows(new_pack["publications"])
        new_artifacts = rows(new_pack["artifacts"])
        assert len(new_publications) == 1, new_publications
        assert len(new_artifacts) == 2, new_artifacts
        assert {(item["pack_id"], item["registration_id"], item["artifact_set_digest"])
                for item in new_publications} == {
                    (item["pack_id"], item["registration_id"], item["artifact_set_digest"])
                    for item in new_terminal["registrations"]}

        final_view = cancel_view
        final_operation = cancelled_operation
        final_pack = inflight_pack

        # A real committed operation is a serialized commit-wins outcome: the
        # commit was durable before Cancel. The route must return that exact old
        # terminal, never a fabricated cancellation, and must not move refs,
        # gate, events or the committed pack snapshot.
        seed_terminal = seed_operation["terminal_result"]
        assert isinstance(seed_terminal, dict), seed_operation
        seed_ledger_before = self.exact_ledger(repo["id"])
        seed_pack_before = self.pack_identity(repo["id"], seed_operation["operation_id"])
        seed_cancel_status, seed_cancel_raw, _ = post_cancel(seed_operation["operation_id"], self.alice)
        assert seed_cancel_status == 200, (seed_cancel_status, seed_cancel_raw[:300])
        seed_view = json.loads(seed_cancel_raw)
        assert set(seed_view) == {"operation_id", "state", "terminal"}, seed_view
        assert seed_view == {
            "operation_id": seed_operation["operation_id"],
            "state": "committed",
            "terminal": seed_terminal,
        }, seed_view
        seed_ledger_after = self.exact_ledger(repo["id"])
        assert seed_ledger_after == seed_ledger_before, "committed cancel changed durable state"
        assert self.pack_identity(repo["id"], seed_operation["operation_id"]) == seed_pack_before
        seed_tombstones = self.cancellation_snapshot(repo["id"], seed_operation["operation_id"])
        assert len(seed_tombstones["legacy"]) == 1, seed_tombstones
        # A committed operation returns AlreadyConsumed before bind_cancellation,
        # so it gets only the migration-138 tombstone; no decision-level
        # cancellation row is fabricated for a commit that already won.
        assert not seed_tombstones["decision"], seed_tombstones
        _, seed_get = get_view(seed_operation["operation_id"], "seed commit-wins", "committed")
        assert seed_get == seed_view

        # Refusals must not reveal operation existence or write a tombstone. The
        # repository remains a real API-created, Git-seeded repository; the only
        # SQL fixture below is one migration-138 pending row without an A3
        # binding, because that refusal cannot be produced by a successful push.
        unknown = str(uuid.uuid4())
        unknown_status, unknown_raw, _ = post_cancel(unknown, self.alice)
        assert unknown_status == 404, (unknown_status, unknown_raw[:300])
        assert assert_error(unknown_raw) == "not found"
        assert self.operation_row_optional(repo["id"], unknown) is None
        assert self.cancellation_snapshot(repo["id"], unknown) == {"legacy": [], "decision": []}

        other_repo, _ = self.create("commit-unknown-other", self.alice)
        other_path = ("/api/repos/" + urllib.parse.quote(other_repo["owner"], safe="") + "/"
                      + urllib.parse.quote(other_repo["name"], safe="") + "/operations/" + operation + "/cancel")
        crossrepo_status, crossrepo_raw, _ = self.http(other_path, token=self.alice, method="POST")
        assert crossrepo_status == 404, (crossrepo_status, crossrepo_raw[:300])
        assert assert_error(crossrepo_raw) == "not found"
        assert self.operation_row_optional(other_repo["id"], operation) is None
        assert self.cancellation_snapshot(other_repo["id"], operation) == {"legacy": [], "decision": []}
        assert self.operation_row(repo["id"], operation) == final_operation

        unbound = str(uuid.uuid4())
        unbound_before = self.exact_ledger(repo["id"])
        self.insert_unbound_operation(repo["id"], seed_operation, unbound)
        no_a3_status, no_a3_raw, _ = post_cancel(unbound, self.alice)
        assert no_a3_status == 409, (no_a3_status, no_a3_raw[:300])
        assert set(json.loads(no_a3_raw)) == {"error"}
        assert self.operation_row(repo["id"], unbound)["state"] == "pending"
        assert self.cancellation_snapshot(repo["id"], unbound) == {"legacy": [], "decision": []}
        unbound_after = self.exact_ledger(repo["id"])
        assert unbound_after["refs"] == unbound_before["refs"]
        assert unbound_after["gate"] == unbound_before["gate"]
        assert unbound_after["events"] == unbound_before["events"]

        # Bob is a real write collaborator but not an owner/admin. The standalone
        # serve-blob router does not mount the product collaborator-management
        # route, so add exactly one role-metadata row in this run's own schema
        # after a separate repository has been created by the real API and
        # seeded with stock Git. Keeping this proof on its own repository leaves
        # the original unknown/commit-wins ledger counts and hashes untouched.
        seed_before = self.cancellation_snapshot(repo["id"], seed_operation["operation_id"])
        original_strict_before_rbac = self.exact_ledger(repo["id"])

        rbac_repo, _ = self.create("commit-unknown-rbac", self.alice)
        rbac_remote = self.base + rbac_repo["clone_path"]
        rbac_seed_work = self.root / "commit-unknown-rbac-seed-work"
        self.clone(rbac_remote, rbac_seed_work, self.alice)
        self.configure(rbac_seed_work)
        rbac_base_oid = self.commit_files(
            rbac_seed_work, "seed rbac proof repo", {"rbac-base.txt": "rbac proof base\n"})
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=rbac_seed_work, token=self.alice)
        assert self.remote_refs(rbac_remote, self.alice).get("refs/heads/main") == rbac_base_oid, \
            "phase=rbac-seed: stock Git main ref is not the seed OID"
        rbac_seed_ledger = self.exact_ledger(rbac_repo["id"])
        rbac_seed_operations = rows(rbac_seed_ledger["operations"])
        assert len(rbac_seed_operations) == 1, ("phase=rbac-seed", rbac_seed_operations)
        rbac_seed_events = rows(rbac_seed_ledger["events"])
        rbac_gate_identity = gate_identity(rbac_seed_ledger["gate"])

        self.add_write_collaborator(rbac_repo, "bob-write-role")

        rbac_path = ("/api/repos/" + urllib.parse.quote(rbac_repo["owner"], safe="") + "/"
                     + urllib.parse.quote(rbac_repo["name"], safe=""))
        visible_status, visible_raw, _ = self.http(rbac_path, token=self.bob)
        assert visible_status == 200, ("phase=bob-repo-get", visible_status, visible_raw[:300])
        visible = json.loads(visible_raw)
        assert visible["id"] == rbac_repo["id"] and visible["owner"] == rbac_repo["owner"], \
            ("phase=bob-repo-get: repository identity", visible)
        assert visible["name"] == rbac_repo["name"] and visible["state"] == "ready", visible

        bob_work = self.root / "commit-unknown-rbac-bob-work"
        self.clone(rbac_remote, bob_work, self.bob)
        self.configure(bob_work)
        bob_oid = self.commit_files(
            bob_work, "bob write-role proof", {"bob-rbac.txt": "bob write role proof\n"})
        assert bob_oid != rbac_base_oid
        bob_operation = str(uuid.uuid4())
        bob_push = self.git(
            "-c", "http.extraHeader=X-Rootyard-Operation: " + bob_operation,
            "push", "--porcelain", "origin", "HEAD:refs/heads/bob-rbac-proof",
            cwd=bob_work, token=self.bob, check=False)
        assert bob_push.returncode == 0, (
            "phase=bob-write-push", json.dumps(blob.git_failure(bob_push)))
        assert blob.push_success(blob.parse_push(bob_push.stdout.decode()),
                                 "refs/heads/bob-rbac-proof"), \
            ("phase=bob-write-push", bob_push.stdout.decode(errors="replace")[-1000:])
        rbac_remote_refs = self.remote_refs(rbac_remote, self.bob)
        assert rbac_remote_refs.get("refs/heads/bob-rbac-proof") == bob_oid, (
            "phase=bob-write-push: durable advertised ref missing", rbac_remote_refs)
        assert rbac_remote_refs.get("refs/heads/main") == rbac_base_oid, rbac_remote_refs

        rbac_after_push = self.exact_ledger(rbac_repo["id"])
        rbac_ref_rows = rows(rbac_after_push["refs"])
        bob_ref = row_for(rbac_ref_rows, "ref_name", "refs/heads/bob-rbac-proof")
        assert bob_ref["oid"] == bob_oid, ("phase=bob-write-ledger: ref OID", bob_ref)
        assert row_for(rbac_ref_rows, "ref_name", "refs/heads/main")["oid"] == rbac_base_oid
        rbac_operation_rows = rows(rbac_after_push["operations"])
        assert len(rbac_operation_rows) == len(rbac_seed_operations) + 1, rbac_operation_rows
        bob_operation_row = self.operation_row(rbac_repo["id"], bob_operation)
        assert bob_operation_row["issuer_id"] == self.bob["user_id"], (
            "phase=bob-write-ledger: operation issuer is not Bob", bob_operation_row)
        assert bob_operation_row["state"] == "committed", bob_operation_row
        bob_terminal = bob_operation_row["terminal_result"]
        assert isinstance(bob_terminal, dict) and bob_terminal.get("kind") == "committed", bob_terminal
        rbac_event_rows = rows(rbac_after_push["events"])
        assert len(rbac_event_rows) == len(rbac_seed_events) + 1, rbac_event_rows
        bob_event = row_for(rbac_event_rows, "operation_id", bob_operation)
        assert bob_event["outcome"] == "committed" and bob_event["payload"] == bob_terminal, bob_event
        assert gate_identity(rbac_after_push["gate"]) == rbac_gate_identity, rbac_after_push["gate"]
        bob_pack = self.pack_identity(rbac_repo["id"], bob_operation)
        bob_publications = rows(bob_pack["publications"])
        bob_artifacts = rows(bob_pack["artifacts"])
        assert len(bob_publications) == 1 and len(bob_artifacts) == 2, bob_pack
        assert bob_publications[0]["plan_operation_id"] == bob_operation, bob_publications
        assert {(item["pack_id"], item["registration_id"], item["artifact_set_digest"])
                for item in bob_publications} == {
                    (item["pack_id"], item["registration_id"], item["artifact_set_digest"])
                    for item in bob_terminal["registrations"]}, (bob_publications, bob_terminal)

        # A second fresh stock-Git clone proves the acknowledged new branch is
        # actually served with the committed bytes.
        bob_proof_clone = self.root / "commit-unknown-rbac-bob-proof-clone"
        self.clone(rbac_remote, bob_proof_clone, self.bob)
        assert self.git("rev-parse", "refs/remotes/origin/bob-rbac-proof",
                        cwd=bob_proof_clone).stdout.decode().strip() == bob_oid
        assert self.git("show", "refs/remotes/origin/bob-rbac-proof:bob-rbac.txt",
                        cwd=bob_proof_clone).stdout == b"bob write role proof\n"

        # The route must refuse Bob before resolving any operation, and must not
        # let him distinguish his known operation from an unknown UUID. Both
        # refusals must leave refs, gate, events, operations, pack rows and both
        # cancellation tombstones exactly unchanged.
        def rbac_cancel_path(target_operation):
            return rbac_path + "/operations/" + target_operation + "/cancel"

        rbac_ledger_before_refusals = self.exact_ledger(rbac_repo["id"])
        rbac_pack_before_refusals = self.pack_identity(rbac_repo["id"], bob_operation)
        rbac_known_tombstones = self.cancellation_snapshot(rbac_repo["id"], bob_operation)
        rbac_unknown_tombstones = self.cancellation_snapshot(rbac_repo["id"], unknown)
        nonadmin_status, nonadmin_raw, nonadmin_headers = self.http(
            rbac_cancel_path(bob_operation), token=self.bob, method="POST")
        nonadmin_unknown_status, nonadmin_unknown_raw, nonadmin_unknown_headers = self.http(
            rbac_cancel_path(unknown), token=self.bob, method="POST")
        assert nonadmin_status == 403 and nonadmin_unknown_status == 403, (
            "phase=bob-cancel-nonadmin", nonadmin_status, nonadmin_raw[:300],
            nonadmin_unknown_status, nonadmin_unknown_raw[:300])
        assert nonadmin_raw == nonadmin_unknown_raw, (
            "phase=bob-cancel-nonadmin: known and unknown responses differ",
            nonadmin_raw[:300], nonadmin_unknown_raw[:300])
        assert assert_error(nonadmin_raw) == "operation is cancellable only by a repository owner or admin"
        assert blob.header_value(nonadmin_headers, "cache-control") == "no-store"
        assert blob.header_value(nonadmin_unknown_headers, "cache-control") == "no-store"
        assert self.operation_row(rbac_repo["id"], bob_operation) == bob_operation_row
        assert self.operation_row_optional(rbac_repo["id"], unknown) is None
        assert self.exact_ledger(rbac_repo["id"]) == rbac_ledger_before_refusals, \
            "phase=bob-cancel-nonadmin: refusals changed the RBAC proof ledger"
        assert self.pack_identity(rbac_repo["id"], bob_operation) == rbac_pack_before_refusals
        assert self.cancellation_snapshot(rbac_repo["id"], bob_operation) == rbac_known_tombstones
        assert self.cancellation_snapshot(rbac_repo["id"], unknown) == rbac_unknown_tombstones
        assert rbac_known_tombstones == {"legacy": [], "decision": []}, rbac_known_tombstones
        assert self.exact_ledger(repo["id"]) == original_strict_before_rbac, \
            "the separate RBAC proof repo changed the original strict ledger"

        read_only_status, read_only_raw, _ = post_cancel(seed_operation["operation_id"], self.reader)
        assert read_only_status == 403, (read_only_status, read_only_raw[:300])
        invalid_status, invalid_raw, _ = post_cancel(
            seed_operation["operation_id"], {"username": "alice", "token": "ryt_" + "0" * 64})
        assert invalid_status == 401, (invalid_status, invalid_raw[:300])
        assert set(json.loads(invalid_raw)) == {"error"}
        assert self.cancellation_snapshot(repo["id"], seed_operation["operation_id"]) == seed_before

        for raw_id in ("not-a-uuid", "00000000-0000-0000-0000-000000000000"):
            malformed_status, malformed_raw, _ = post_cancel(raw_id, self.alice)
            assert malformed_status == 400, (raw_id, malformed_status, malformed_raw[:300])
            assert assert_error(malformed_raw) == "invalid operation identifier"

        final_ledger = self.exact_ledger(repo["id"])
        assert final_ledger == original_strict_before_rbac, \
            "refusals after the RBAC proof changed the original strict ledger"
        _, fresh_final_view = get_view(operation, "final resolution")
        assert fresh_final_view == final_view, (fresh_final_view, final_view)
        assert fresh_final_view["state"] == "cancelled", fresh_final_view

        return {
            "operation": operation,
            "wire_status": wire_status,
            "wire_error": wire_error["error"],
            "resolved_state": final_view["state"],
            "resolved_by": resolved_by,
            "cancel_status": cancel_status,
            "cancel_state": final_view["state"],
            "cancel_terminal": cancel_terminal,
            "operation_get_status": 200,
            "commit_landed": False,
            "unknown_commit_landed": False,
            "cancel_won": True,
            "new_operation_committed": True,
            "seed_commit_wins_operation": seed_operation["operation_id"],
            "seed_commit_wins_state": seed_view["state"],
            "seed_commit_wins_terminal_sha256": digest(
                json.dumps(seed_view["terminal"], sort_keys=True, separators=(",", ":"))),
            "seed_commit_wins_refs_sha256": digest(seed_ledger_after["refs"]),
            "seed_commit_wins_gate_sha256": digest(seed_ledger_after["gate"]),
            "seed_commit_wins_events_sha256": digest(seed_ledger_after["events"]),
            "seed_commit_wins_checked": True,
            "new_operation": new_operation,
            "new_operation_state": new_view["state"] if new_view is not None else None,
            "new_operation_terminal": new_view["terminal"] if new_view is not None else None,
            "same_wire_status": same_wire_status,
            "divergent_wire_status": divergent_status,
            "unknown_cancel_status": unknown_status,
            "crossrepo_cancel_status": crossrepo_status,
            "no_a3_cancel_status": no_a3_status,
            "nonadmin_cancel_status": nonadmin_status,
            "nonadmin_unknown_cancel_status": nonadmin_unknown_status,
            "nonadmin_cancel_response_identical": nonadmin_raw == nonadmin_unknown_raw,
            "rbac_proof_repository": rbac_repo["id"],
            "rbac_proof_operation": bob_operation,
            "rbac_proof_operation_state": bob_operation_row["state"],
            "rbac_proof_issuer_id": bob_operation_row["issuer_id"],
            "rbac_proof_ref": "refs/heads/bob-rbac-proof",
            "rbac_proof_oid": bob_oid,
            "rbac_proof_clone_oid": bob_oid,
            "rbac_role_fixture": "repository_collaborators(write) metadata in the run-owned schema",
            "rbac_refusal_ledger_pack_tombstones_unchanged": True,
            "original_strict_ledger_unchanged_by_rbac_proof": True,
            "read_only_cancel_status": read_only_status,
            "invalid_auth_cancel_status": invalid_status,
            "one_effect_checked": True,
            "base_revision": base_revision,
            "new_revision": new_revision,
            "ack_oid": new_oid,
            "gate_identity": gate_identity(final_ledger["gate"]),
            "exact_refs": rows(final_ledger["refs"]),
            "exact_gate": rows(final_ledger["gate"]),
            "exact_events": rows(final_ledger["events"]),
            "exact_terminal": final_view["terminal"],
            "exact_operation": final_operation,
            "pack_identity": pack_identity_summary(final_pack),
            "new_pack_identity": pack_identity_summary(new_pack) if new_pack is not None else None,
            "refs_sha256": digest(final_ledger["refs"]),
            "gate_sha256": digest(final_ledger["gate"]),
            "events_sha256": digest(final_ledger["events"]),
            "terminal_sha256": digest(json.dumps(final_view["terminal"], sort_keys=True, separators=(",", ":"))),
            "pack_identity_sha256": digest(json.dumps(final_pack, sort_keys=True, separators=(",", ":"))),
            "pack_registration_ids": [item["registration_id"] for item in rows(final_pack["publications"])],
            "pack_identity_unchanged": True,
            "exact_ref_gate_event_terminal_checked": True,
            "cancel_commit_ambiguity_not_forced": True,
        }


def select_cases(names):
    if not names:
        return list(CASES)
    unknown = [name for name in names if name not in CASES]
    if unknown:
        raise blob.ProfileError("unknown case(s): " + ", ".join(unknown))
    selected = [name for name in CASES if name in set(names)]
    if not selected:
        raise blob.ProfileError("no cases selected; a zero-case run cannot be green")
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args(argv)
    env = os.environ.copy()
    hashes = None
    try:
        hashes = input_hashes()
        profile = CheckpointProfile(args.binary, args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(shutil.which("psql"), "psql is required")
        selected = select_cases(args.case)
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/blob-only-native-acceptance", "passed": False,
            "preflight_failed": True, "error": str(error), "cases": [],
            "expected_cases": [], "skips": 0, "limitations": LIMITATIONS,
            "checkpoint_sha256": blob.sha256_file(Path(__file__)),
            "harness_inputs_sha256": hashes or {},
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2

    args.binary = str(profile.binary)
    harness = CheckpointHarness(args, profile, blob_profile)
    success = False
    try:
        harness.prepare()
        for name in selected:
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report = blob.build_report(harness, profile, blob_profile, selected, success)
        hashes_now = input_hashes()
        checkpoint_name = Path(__file__).name
        report["checkpoint_sha256"] = hashes_now[checkpoint_name]
        report["build_receipt_sha256"] = profile.receipt_sha256
        report["harness_inputs_sha256"] = hashes_now
        report["harness_inputs"] = {
            "blob_only_service_sha256": hashes_now["blob_only_service.py"],
            "checkpoint_sha256": hashes_now[checkpoint_name],
            "e2e_sha256": hashes_now["e2e.py"],
            "native_evidence_sha256": hashes_now["native_evidence.py"],
            "ops_provenance_sha256": hashes_now["ops_provenance.py"],
            "owned_fuse_cleanup_sha256": hashes_now["owned_fuse_cleanup.py"],
            "input_hashes": hashes_now,
        }
        report["limitations"] = LIMITATIONS
        errors = []
        if hashes_now != hashes:
            errors.append("harness/helper source changed during native acceptance")
        if hashes_now[checkpoint_name] != profile.checkpoint_sha256:
            errors.append("checkpoint harness changed during native acceptance")
        if blob.sha256_file(profile.binary) != profile.build["binary_sha256"]:
            errors.append("executed binary changed during native acceptance")
        if blob.sha256_file(profile.binary.with_suffix(".build.json")) != profile.receipt_sha256:
            errors.append("build receipt changed during native acceptance")
        if errors:
            report["inputs_unchanged"] = False
            report["passed"] = False
            prior = report.get("binding_error")
            report["binding_error"] = "; ".join(errors + ([prior] if prior else []))
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
