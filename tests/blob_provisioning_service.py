#!/usr/bin/env python3
"""Isolated native acceptance for the bounded PG standalone #143 provisioning path.

This is deliberately *not* a Raft/multi-host/physical-durability test. It
exercises the existing ``serve-blob`` provisioning transaction through real
HTTP and stock Git against one owned PostgreSQL schema and one configured S3
provider. It reuses :class:`blob_only_service.BlobOnlyHarness`,
``NativeProfile`` and the strict remote S3 profile, so a run still requires an
attested source-bound binary and the trusted Git supplied by Root.

Cases (first checkpoint):

* concurrent HTTP creates for one owner/name all resolve to the same durable
  identity or an explicit conflict, with exactly one catalog row, serving
  binding/backend identity, core gate and history incarnation;
* a concurrent object-format disagreement is an explicit, terminal refusal and
  never mints a second authority;
* an idempotent create retry survives a service restart and preserves HEAD,
  the history/epoch realm, the backend binding and the gate;
* a genuine loopback HTTP proxy reads the backend's committed ``201`` and then
  drops the client reply; the retry resolves the same single authority and the
  repository can be pushed to and cloned.

Second, independent checkpoint (selected together by default, or alone):

* a fixture-owned deferred PostgreSQL constraint trigger blocks the service's
  ``COMMIT`` at a transaction-scoped advisory barrier; the harness observes the
  uncommitted state is never served, kills the service before the commit
  completes, forces the abandoned transaction to roll back, and proves the
  retry converges on one ready authority.

No SQL inserts a ready repository, binding, gate, protocol row, ref, object or
ACK. The only fixture SQL writes are a temporary barrier table, a deferred
constraint trigger and its function in the random schema this run owns; they are
dropped in a bounded ``finally`` block. Reports contain no DSN, token, S3
credential, raw server stderr or environment dump.
"""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import random
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as serving
import ops_provenance


CASES = (
    "concurrent_same_owner_name_creates_converge_one_authority",
    "concurrent_object_format_conflict_is_explicit_and_single_authority",
    "create_retry_and_service_restart_preserve_head_and_authority",
    "lost_create_ack_proxy_retry_resolves_one_authority",
    "deferred_commit_barrier_kill_rolls_back_and_retry_converges",
)

FIRST_CHECKPOINT = CASES[:4]
SECOND_CHECKPOINT = CASES[4:]

LIMITATIONS = [
    "Loopback HTTP, one PostgreSQL 17 server and one fixture-owned S3 provider; no Raft, multi-host, HA or physical durability claim.",
    "The retry/restart case kills only this harness's serve-blob process group; it does not claim kernel or power-loss behavior.",
    "The deferred-commit case uses a fixture-owned PostgreSQL deferred constraint trigger, a transaction-scoped advisory barrier and a process SIGKILL; the service's existing 5s statement timeout bounds that window, and the harness kills immediately after observing the barrier. It does not claim PostgreSQL crash recovery.",
    "The ACK-loss case is one real loopback proxy that reads a committed backend 201 and then closes the client connection; it is not exhaustive transport fault injection.",
    "No SQL creates a ready repository, binding, gate, protocol row, ref, object or acknowledgment. SQL reads authority state and writes only the temporary barrier in this run's random schema.",
    "The temporary barrier trigger/function/table are dropped in a bounded finally block; transaction-scoped advisory locks are released by PostgreSQL on commit/abort.",
    "Concurrency is a small bounded request group on one process, not a scalability benchmark.",
    "The harness sets the existing ROOTYARD_MAX_CONCURRENT_GIT knob to 8 so the half-ready read probe can run while one create is blocked; it is not a capacity claim.",
    "SHA-256 Git operations require the Root-supplied trusted Git to support that object format.",
]


def input_hashes():
    """Source closure this harness imports or otherwise depends on."""
    root = Path(__file__).resolve().parent
    names = (Path(__file__).name, "blob_only_service.py", "e2e.py", "native_evidence.py",
             "ops_provenance.py", "owned_fuse_cleanup.py")
    return {name: serving.sha256_file(root / name) for name in names}


def quote_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def sha256_hex(value):
    text = str(value)
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


class AckLossProxy:
    """One-shot loopback proxy that receives a backend response and drops it.

    The proxy forwards one ``POST /api/repos`` request to the real service,
    reads the complete backend status/headers/body, records it, and then closes
    the client connection without writing any response. This is a real HTTP
    acknowledgment loss at the client boundary; the backend has already sent
    its committed ``201``.
    """

    def __init__(self, backend_base):
        parsed = urllib.parse.urlsplit(backend_base)
        if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
            raise AssertionError("ACK-loss proxy needs one loopback HTTP backend origin")
        self.backend = (parsed.hostname, parsed.port)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.record = None
        self.error = None
        self.thread = threading.Thread(target=self._serve, name="rootyard-ack-loss-proxy", daemon=True)

    def start(self):
        self.thread.start()

    def join(self, timeout=20):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise AssertionError("ACK-loss proxy did not finish within its bound")
        if self.error is not None:
            raise AssertionError("ACK-loss proxy failed: " + repr(self.error))
        if self.record is None:
            raise AssertionError("ACK-loss proxy received no backend response")
        return self.record

    def _serve(self):
        try:
            connection, _ = self.listener.accept()
            with connection:
                method, path, headers, body = read_http_request(connection)
                self.record = forward_http(self.backend, method, path, headers, body)
            # Deliberately write no response. Closing the accepted socket after
            # the backend 201 is the lost acknowledgment under test.
        except Exception as error:  # noqa: BLE001 - reported through join()
            self.error = error
        finally:
            try:
                self.listener.close()
            except OSError:
                pass


def read_http_request(connection):
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(65536)
        if not chunk:
            raise AssertionError("client closed before sending request headers")
        raw += chunk
        if len(raw) > (1 << 20):
            raise AssertionError("proxy request headers exceeded their bound")
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    method, path, _version = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise AssertionError("malformed proxy request header")
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length < 0 or length > (16 << 20):
        raise AssertionError("proxy request body exceeded its bound")
    while len(body) < length:
        chunk = connection.recv(65536)
        if not chunk:
            raise AssertionError("client closed before sending the request body")
        body += chunk
    return method, path, headers, body[:length]


def forward_http(backend, method, path, headers, body):
    connection = http.client.HTTPConnection(backend[0], backend[1], timeout=20)
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name in ("authorization", "content-type", "accept", "user-agent", "content-encoding"):
            if name in headers:
                connection.putheader(name.title(), headers[name])
        connection.putheader("Host", backend[0] + ":" + str(backend[1]))
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        return {"status": response.status, "headers": dict(response.getheaders()), "body": response.read()}
    finally:
        connection.close()


class ProvisioningHarness(serving.BlobOnlyHarness):
    """BlobOnlyHarness plus provisioning barriers and authority observations."""

    def __init__(self, args, profile, blob_profile):
        super().__init__(args, profile, blob_profile)
        # One blocked create must not consume the whole request semaphore: the
        # deferred-commit case has to ask the same service for a read-only
        # catalog view while the uncommitted create is still at COMMIT. This is
        # the service's existing default, set explicitly for the fixture.
        self.env["ROOTYARD_MAX_CONCURRENT_GIT"] = "8"
        self.barrier_key = None
        self.barrier_schema = '"' + self.schema + '"'

    # -- native Git helpers -------------------------------------------------
    def push_and_clone(self, repo, label, object_format="sha1", files=None):
        files = files or {"provisioned.txt": "provisioned through the single authority\n"}
        remote = self.base + repo["clone_path"]
        work = self.root / (label + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        assert self.object_format(work) == object_format, "clone object format differs from the created repository"
        oid = self.commit_files(work, "provisioning acceptance " + label, files)
        pushed = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/main",
                          cwd=work, token=self.alice, check=False)
        assert pushed.returncode == 0, "provisioned repository push failed: " + json.dumps(serving.git_failure(pushed))
        assert serving.push_success(serving.parse_push(pushed.stdout.decode()), "refs/heads/main")
        self.assert_ref(remote, "refs/heads/main", oid)
        self.exact_clone(remote, self.root / (label + "-clone"), oid, object_format, files, self.reader)
        return oid

    def probe_sha256(self):
        probe = self.git("init", "--object-format=sha256", str(self.root / "provisioning-sha256-probe"), check=False)
        assert probe.returncode == 0, "trusted Git lacks SHA-256 support: " + json.dumps(serving.git_failure(probe))

    # -- HTTP helpers -------------------------------------------------------
    def post_create(self, payload, attempts=4):
        """POST one create, retrying only the explicitly retryable unknown outcomes."""
        last = None
        for attempt in range(attempts):
            code, raw, _ = self.http("/api/repos", token=self.alice, method="POST", body=payload)
            last = (code, raw)
            if code not in (503, 504):
                return code, raw
            time.sleep(0.1 * (attempt + 1))
        return last

    def post_through_ack_loss_proxy(self, proxy, payload):
        connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=20)
        body = json.dumps(payload).encode()
        try:
            connection.request("POST", "/api/repos", body=body, headers={
                "Authorization": "Bearer " + self.alice["token"],
                "Content-Type": "application/json",
            })
            try:
                connection.getresponse()
            except http.client.RemoteDisconnected:
                return "RemoteDisconnected"
            except (ConnectionResetError, BrokenPipeError):
                return "ConnectionReset"
            else:
                raise AssertionError("client received a response although the proxy was instructed to drop it")
        finally:
            connection.close()

    def get_repo_status(self, owner, name):
        return self.http("/api/repos/" + urllib.parse.quote(owner, safe="") + "/"
                         + urllib.parse.quote(name, safe=""), token=self.alice)

    def listed_repos(self):
        code, raw, _ = self.http("/api/repos", token=self.alice)
        assert code == 200, "repository list status=" + str(code)
        items = json.loads(raw)
        assert isinstance(items, list), "repository list is not an array"
        return items

    # -- authority observations (read-only catalog SQL) ---------------------
    def one(self, query, label):
        rows = [line for line in self.sql(query).splitlines() if line]
        assert len(rows) == 1, label + " expected exactly one row, got " + repr(rows)
        return rows[0]

    def bounded_sql(self, query):
        """Fixture SQL with explicit statement/lock bounds.

        A failed test may still have a service transaction at COMMIT while the
        finally block drops the temporary trigger. The session-local timeouts
        make that cleanup fail closed instead of waiting forever.
        """
        return self.sql("SET statement_timeout = '5s'; SET lock_timeout = '3s'; " + query)

    def authority(self, repo, expected_name):
        repo_id = str(uuid.UUID(str(repo["id"])))
        owner_id = str(uuid.UUID(str(self.alice["user_id"])))
        name = quote_literal(expected_name)
        owner = quote_literal(owner_id)
        repository = quote_literal(repo_id)
        counts = self.one(
            "SELECT (SELECT count(*) FROM repositories WHERE owner_id=" + owner + " AND name=" + name + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_serving_repositories WHERE owner_id=" + owner
            + " AND name=" + name + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_core_gates WHERE repository_id=" + repository + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_core_protocol_repos WHERE repository_id="
            + repository + ")::text",
            "authority row counts")
        assert counts == "1|1|1|1", "expected exactly one catalog/binding/gate/protocol row: " + counts
        catalog = self.one(
            "SELECT id::text || '|' || owner_id::text || '|' || name || '|' || state || '|' || storage_backend"
            " || '|' || object_format FROM repositories WHERE owner_id=" + owner + " AND name=" + name,
            "catalog row")
        binding = self.one(
            "SELECT repository_id::text || '|' || owner_id::text || '|' || name || '|' || object_format"
            " || '|' || history_incarnation::text || '|' || authority_epoch::text || '|' || group_epoch::text"
            " || '|' || backend_identity || '|' || state FROM ref_store_serving_repositories"
            " WHERE owner_id=" + owner + " AND name=" + name,
            "serving binding")
        gate = self.one(
            "SELECT repository_id::text || '|' || tenant_id::text || '|' || object_format || '|'"
            " || history_incarnation::text || '|' || authority_epoch::text || '|' || group_epoch::text"
            " || '|' || head_ref || '|' || revision::text FROM ref_store_core_gates"
            " WHERE repository_id=" + repository,
            "core gate")
        protocol = self.one(
            "SELECT repository_id::text || '|' || tenant_id::text || '|' || object_format || '|'"
            " || history_incarnation::text || '|' || authority_epoch::text || '|' || group_epoch::text"
            " || '|' || decision_required::text FROM ref_store_core_protocol_repos"
            " WHERE repository_id=" + repository,
            "decision protocol realm")
        catalog_fields = catalog.split("|")
        binding_fields = binding.split("|")
        gate_fields = gate.split("|")
        protocol_fields = protocol.split("|")
        assert len(catalog_fields) == 6, catalog
        assert len(binding_fields) == 9, binding
        assert len(gate_fields) == 8, gate
        assert len(protocol_fields) == 7, protocol
        catalog_id, catalog_owner, catalog_name, state, backend, object_format = catalog_fields
        (binding_id, binding_owner, binding_name, binding_format, history, authority_epoch,
         group_epoch, backend_identity, binding_state) = binding_fields
        (gate_id, gate_tenant, gate_format, gate_history, gate_authority,
         gate_group, head_ref, revision) = gate_fields
        (protocol_id, protocol_tenant, protocol_format, protocol_history,
         protocol_authority, protocol_group, decision_required) = protocol_fields
        assert catalog_id == binding_id == gate_id == protocol_id == repo_id, "authority rows name different repositories"
        assert catalog_owner == binding_owner == gate_tenant == protocol_tenant == owner_id, "authority owner mismatch"
        assert catalog_name == binding_name == expected_name, "authority name mismatch"
        assert state == "ready" and binding_state == "ready", (state, binding_state)
        assert backend == "pg_refstore", backend
        assert object_format == binding_format == gate_format == protocol_format, "object format differs across rows"
        assert history == gate_history == protocol_history, "history incarnation differs across authority rows"
        assert authority_epoch == gate_authority == protocol_authority, "authority epoch differs across rows"
        assert group_epoch == gate_group == protocol_group, "group epoch differs across rows"
        assert sha256_hex(backend_identity), "backend identity is not one lowercase SHA-256 digest"
        assert head_ref.startswith("refs/heads/"), "gate HEAD is not a branch ref: " + head_ref
        assert int(revision) >= 1 and decision_required == "t", (revision, decision_required)
        return {
            "counts": counts,
            "repository_id": repo_id,
            "catalog": catalog,
            "binding": binding,
            "gate": gate,
            "protocol": protocol,
            "object_format": object_format,
            "backend_identity": backend_identity,
            "history_incarnation": history,
            "authority_epoch": authority_epoch,
            "group_epoch": group_epoch,
            "head_ref": head_ref,
            "gate_revision": int(revision),
        }

    def authority_count_for_name(self, expected_name):
        owner_id = str(uuid.UUID(str(self.alice["user_id"])))
        name = quote_literal(expected_name)
        owner = quote_literal(owner_id)
        return self.one(
            "SELECT (SELECT count(*) FROM repositories WHERE owner_id=" + owner + " AND name=" + name + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_serving_repositories WHERE owner_id=" + owner
            + " AND name=" + name + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_core_gates g JOIN repositories r ON r.id=g.repository_id"
            " WHERE r.owner_id=" + owner + " AND r.name=" + name + ")::text"
            " || '|' || (SELECT count(*) FROM ref_store_core_protocol_repos p JOIN repositories r ON r.id=p.repository_id"
            " WHERE r.owner_id=" + owner + " AND r.name=" + name + ")::text",
            "authority counts for " + expected_name)

    # -- fixture-owned deferred COMMIT barrier ------------------------------
    def install_deferred_barrier(self, expected_name, owner_id, key):
        schema = self.barrier_schema
        self.barrier_key = int(key)
        assert 1 <= self.barrier_key < (1 << 31), "barrier advisory key is outside its safe bound"
        name = quote_literal(expected_name)
        owner = quote_literal(str(uuid.UUID(owner_id)))
        self.bounded_sql("CREATE TABLE " + schema + ".rootyard_143_barrier"
                         " (action text NOT NULL CHECK (action IN ('waiting','abort')))")
        self.bounded_sql("INSERT INTO " + schema + ".rootyard_143_barrier(action) VALUES ('waiting')")
        self.bounded_sql(
            "CREATE FUNCTION " + schema + ".rootyard_143_deferred_commit() RETURNS trigger LANGUAGE plpgsql AS $fn$"
            " DECLARE expires timestamptz := clock_timestamp() + interval '20 seconds';"
            " BEGIN"
            "   PERFORM pg_advisory_xact_lock(143, " + str(self.barrier_key) + ");"
            "   WHILE clock_timestamp() < expires LOOP"
            "     IF EXISTS (SELECT 1 FROM " + schema + ".rootyard_143_barrier WHERE action='abort') THEN"
            "       RAISE EXCEPTION 'rootyard #143 fixture aborted provisioning before COMMIT';"
            "     END IF;"
            "     PERFORM pg_sleep(0.05);"
            "   END LOOP;"
            "   RAISE EXCEPTION 'rootyard #143 fixture provisioning barrier timed out';"
            " END $fn$")
        self.bounded_sql(
            "CREATE CONSTRAINT TRIGGER rootyard_143_deferred_commit"
            " AFTER UPDATE ON " + schema + ".repositories"
            " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW"
            " WHEN (NEW.owner_id = " + owner + "::uuid AND NEW.name = " + name + " AND NEW.state = 'ready')"
            " EXECUTE FUNCTION " + schema + ".rootyard_143_deferred_commit()")

    def barrier_lock_rows(self):
        """Count granted/total advisory rows for this run's (143, key) lock.

        This is a read-only pg_locks observation. It never acquires the lock,
        so the probe cannot delay or abort the service's COMMIT.
        """
        return self.one(
            "SELECT count(*) FILTER (WHERE l.granted)::text || '|' || count(*)::text"
            " FROM pg_locks l JOIN pg_database d ON d.oid=l.database"
            " WHERE l.locktype='advisory' AND d.datname=current_database()"
            " AND l.classid=143 AND l.objid=" + str(self.barrier_key) + " AND l.objsubid IN (1,2)",
            "barrier lock rows")

    def barrier_reached(self):
        # A granted transaction-scoped lock in the dedicated (143, key)
        # advisory class is visible while the deferred COMMIT trigger executes.
        # The class cannot collide with the service's single-key backup or
        # sharding locks.
        return self.barrier_lock_rows() == "1|1"

    def wait_for_barrier(self, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.barrier_reached():
                return
            time.sleep(0.05)
        raise AssertionError("service never reached the fixture-owned deferred COMMIT barrier")

    def barrier_released(self):
        return self.barrier_lock_rows() == "0|0"

    def abort_barrier_and_wait(self, timeout=10):
        """Ask the abandoned transaction to roll back and prove its gate is released."""
        schema = self.barrier_schema
        self.bounded_sql("UPDATE " + schema + ".rootyard_143_barrier SET action='abort' WHERE action='waiting'")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.barrier_released():
                return
            time.sleep(0.05)
        # The service process is already gone. Terminate only the backend that
        # still holds this run's advisory key, never an unrelated session.
        pid = self.sql(
            "SELECT l.pid::text FROM pg_locks l JOIN pg_database d ON d.oid=l.database"
            " WHERE l.locktype='advisory' AND l.granted AND d.datname=current_database()"
            " AND l.classid=143 AND l.objid=" + str(self.barrier_key) + " AND l.objsubid IN (1,2) LIMIT 1")
        if pid:
            self.bounded_sql("SELECT pg_terminate_backend(" + quote_literal(pid) + "::int)")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.barrier_released():
                return
            time.sleep(0.05)
        raise AssertionError("fixture-owned advisory barrier was not released within its bound")

    def drop_deferred_barrier(self):
        schema = self.barrier_schema
        self.bounded_sql("UPDATE " + schema + ".rootyard_143_barrier SET action='abort' WHERE action='waiting'")
        self.bounded_sql("DROP TRIGGER IF EXISTS rootyard_143_deferred_commit ON " + schema + ".repositories")
        self.bounded_sql("DROP FUNCTION IF EXISTS " + schema + ".rootyard_143_deferred_commit()")
        self.bounded_sql("DROP TABLE IF EXISTS " + schema + ".rootyard_143_barrier")
        self.barrier_key = None

    # -- cases --------------------------------------------------------------
    def concurrent_same_owner_name_creates_converge_one_authority(self):
        name = "concurrent-create"
        payload = {"owner": "alice", "name": name, "object_format": "sha1"}
        workers = 8
        barrier = threading.Barrier(workers)

        def submit(_):
            barrier.wait(timeout=15)
            return self.http("/api/repos", token=self.alice, method="POST", body=payload)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            responses = list(pool.map(submit, range(workers)))
        statuses = [status for status, _, _ in responses]
        assert all(status in (200, 201, 409, 503, 504) for status in statuses), "unexpected create status: " + str(statuses)
        resolved = []
        for status, raw, _ in responses:
            attempts = 0
            while status in (409, 503, 504) and attempts < 3:
                time.sleep(0.05 * (attempts + 1))
                status, raw, _ = self.http("/api/repos", token=self.alice, method="POST", body=payload)
                attempts += 1
            resolved.append((status, raw))
        successes, conflicts = [], []
        for status, raw in resolved:
            if status in (200, 201):
                body = json.loads(raw)
                assert body.get("state") == "ready", body
                assert body.get("owner") == "alice" and body.get("name") == name, body
                assert body.get("storage_backend") == "pg_refstore", body
                successes.append((status, body))
            elif status == 409:
                conflict = json.loads(raw)
                assert isinstance(conflict.get("error"), str) and conflict["error"], conflict
                conflicts.append(conflict)
            else:
                raise AssertionError("concurrent create did not resolve: " + str(status))
        assert successes, "no concurrent create succeeded; statuses=" + str(statuses)
        ids = {body["id"] for _, body in successes}
        assert len(ids) == 1, "concurrent creates minted different identities: " + repr(ids)
        repo_id = ids.pop()
        assert sum(1 for status, _ in successes if status == 201) <= 1, "more than one create claimed creation"
        repo = next(body for _, body in successes if body["id"] == repo_id)
        # A same-format explicit conflict is allowed as an initial outcome, but
        # one final idempotent request must resolve to the same durable identity.
        for _conflict in conflicts:
            status, raw = self.post_create(payload, attempts=4)
            assert status == 200, "same-format retry was not idempotent: " + str(status)
            assert json.loads(raw)["id"] == repo_id
        got = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
        assert got["id"] == repo_id and got["state"] == "ready"
        facts = self.authority(repo, name)
        oid = self.push_and_clone(repo, name)
        return {"workers": workers, "initial_statuses": statuses,
                "resolved_statuses": [status for status, _ in resolved],
                "successful_ids": [repo_id], "explicit_conflicts": len(conflicts),
                "authority": facts, "ack_oid": oid, "clone_fsck": True}

    def concurrent_object_format_conflict_is_explicit_and_single_authority(self):
        name = "concurrent-format"
        formats = ["sha1", "sha256"] * 4
        barrier = threading.Barrier(len(formats))

        def submit(object_format):
            barrier.wait(timeout=15)
            payload = {"owner": "alice", "name": name, "object_format": object_format}
            return object_format, self.http("/api/repos", token=self.alice, method="POST", body=payload)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(formats)) as pool:
            responses = list(pool.map(submit, formats))
        initial = [(fmt, status) for fmt, (status, _, _) in responses]
        assert all(status in (200, 201, 409, 503, 504) for _, status in initial), initial
        successes, conflicts = [], []
        for fmt, (status, raw, _) in responses:
            attempts = 0
            while status in (503, 504) and attempts < 4:
                time.sleep(0.05 * (attempts + 1))
                payload = {"owner": "alice", "name": name, "object_format": fmt}
                status, raw, _ = self.http("/api/repos", token=self.alice, method="POST", body=payload)
                attempts += 1
            if status in (200, 201):
                body = json.loads(raw)
                assert body.get("object_format") == fmt, body
                successes.append((fmt, body))
            elif status == 409:
                conflict = json.loads(raw)
                assert isinstance(conflict.get("error"), str) and conflict["error"], conflict
                conflicts.append((fmt, conflict))
            else:
                raise AssertionError("format race returned unexpected status " + str(status) + " for " + fmt)
        assert successes, "no object-format create succeeded: " + repr(initial)
        ids = {body["id"] for _, body in successes}
        assert len(ids) == 1, "object-format race minted different identities: " + repr(ids)
        repo_id = ids.pop()
        winner_format = next(body["object_format"] for _, body in successes if body["id"] == repo_id)
        assert winner_format in ("sha1", "sha256"), winner_format
        assert all(fmt == winner_format for fmt, _ in successes), "successful formats disagree with the durable row"
        # Committed-format responses must converge; every other format must be
        # an explicit terminal refusal, never a second repository/gate/binding.
        for fmt, _conflict in conflicts:
            payload = {"owner": "alice", "name": name, "object_format": fmt}
            status, raw = self.post_create(payload, attempts=4)
            if fmt == winner_format:
                assert status in (200, 201), "committed format was refused: " + str(status)
                assert json.loads(raw)["id"] == repo_id
            else:
                assert status == 409, "losing format was not explicitly refused: " + str(status)
                refusal = json.loads(raw)
                assert isinstance(refusal.get("error"), str) and refusal["error"], refusal
        repo = next(body for _, body in successes if body["id"] == repo_id)
        got = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
        assert got["id"] == repo_id and got["object_format"] == winner_format
        facts = self.authority(repo, name)
        assert facts["object_format"] == winner_format
        if winner_format == "sha256":
            self.probe_sha256()
        oid = self.push_and_clone(repo, name, winner_format)
        return {"initial_statuses": initial, "winner_format": winner_format,
                "successful_ids": [repo_id], "explicit_conflicts": len(conflicts),
                "authority": facts, "ack_oid": oid, "clone_fsck": True}

    def create_retry_and_service_restart_preserve_head_and_authority(self):
        name = "retry-head"
        repo, created_status = self.create(name, self.alice)
        assert created_status in (201, 202)
        remote = self.base + repo["clone_path"]
        work = self.root / (name + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        payload_files = {"topic.txt": "topic bytes survived restart\n"}
        oid = self.commit_files(work, "first topic branch", payload_files)
        self.git("push", "origin", "HEAD:refs/heads/topic", cwd=work, token=self.alice)
        self.assert_ref(remote, "refs/heads/topic", oid)
        before = self.authority(repo, name)
        assert before["head_ref"] == "refs/heads/topic", before["head_ref"]
        old_pid = self.proc.pid
        self.stop(hard=True)
        self.start(label="provisioning-restart")
        assert self.proc.pid != old_pid
        retry = {"owner": "alice", "name": name, "object_format": "sha1"}
        status, raw = self.post_create(retry, attempts=4)
        assert status == 200, "restart retry minted a second creation: " + str(status)
        replay = json.loads(raw)
        assert replay["id"] == repo["id"] and replay["state"] == "ready", replay
        after = self.authority(repo, name)
        assert after == before, "restart retry changed the authority snapshot"
        got = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
        assert got["id"] == repo["id"] and got["state"] == "ready"
        self.exact_clone(remote, self.root / (name + "-clone"), oid, "sha1", payload_files, self.reader)
        second = self.commit_files(work, "second branch after restart", {"second.txt": "second\n"})
        pushed = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/second",
                          cwd=work, token=self.alice, check=False)
        assert pushed.returncode == 0, json.dumps(serving.git_failure(pushed))
        after_push = self.authority(repo, name)
        assert after_push["head_ref"] == "refs/heads/topic", "a later branch push changed the preserved HEAD"
        assert after_push["history_incarnation"] == before["history_incarnation"]
        assert after_push["backend_identity"] == before["backend_identity"]
        assert after_push["gate_revision"] >= before["gate_revision"]
        self.assert_ref(remote, "refs/heads/second", second)
        return {"repository_id": repo["id"], "old_pid": old_pid, "restarted_pid": self.proc.pid,
                "retry_status": status, "head_ref": after_push["head_ref"],
                "authority_unchanged": after == before, "history_incarnation": before["history_incarnation"],
                "backend_identity": before["backend_identity"], "ack_oid": oid, "clone_fsck": True}

    def lost_create_ack_proxy_retry_resolves_one_authority(self):
        name = "lost-create-ack"
        payload = {"owner": "alice", "name": name, "object_format": "sha1"}
        proxy = AckLossProxy(self.base)
        proxy.start()
        client_result = self.post_through_ack_loss_proxy(proxy, payload)
        record = proxy.join()
        assert record["status"] == 201, "backend did not acknowledge a committed create: " + str(record["status"])
        committed = json.loads(record["body"])
        assert committed.get("state") == "ready" and committed.get("name") == name, committed
        assert client_result in ("RemoteDisconnected", "ConnectionReset"), client_result
        repo_id = committed["id"]
        status, raw = self.post_create(payload, attempts=4)
        assert status == 200, "lost-ACK retry did not resolve the committed create: " + str(status)
        replay = json.loads(raw)
        assert replay["id"] == repo_id and replay["state"] == "ready", replay
        got = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
        assert got["id"] == repo_id
        facts = self.authority(replay, name)
        oid = self.push_and_clone(replay, name)
        return {"proxy_backend_status": record["status"], "client_result": client_result,
                "committed_repository_id": repo_id, "retry_status": status,
                "authority": facts, "ack_oid": oid, "clone_fsck": True}

    def deferred_commit_barrier_kill_rolls_back_and_retry_converges(self):
        name = "deferred-kill"
        payload = {"owner": "alice", "name": name, "object_format": "sha1"}
        owner_id = str(uuid.UUID(str(self.alice["user_id"])))
        key = random.SystemRandom().randrange(1, 1 << 31)
        response = {}
        thread_error = {}
        barrier_installed = False
        killed_pid = None
        half_ready_status = None
        half_ready_listed = None
        uncommitted_rows = None

        def submit():
            try:
                response["value"] = self.http("/api/repos", token=self.alice, method="POST", body=payload)
            except Exception as error:  # noqa: BLE001 - the kill is expected to break this request
                thread_error["value"] = error

        try:
            self.install_deferred_barrier(name, owner_id, key)
            barrier_installed = True
            worker = threading.Thread(target=submit, name="deferred-commit-create", daemon=True)
            worker.start()
            try:
                self.wait_for_barrier()
                # The service has written every row but has not committed. No
                # other session may serve or advertise a half-ready catalog row.
                half_ready_status, half_ready_raw, _ = self.get_repo_status("alice", name)
                assert half_ready_status == 404, (
                    "half-ready repository was served with status " + str(half_ready_status)
                    + ": " + repr(half_ready_raw[:200]))
                half_ready_listed = any(item.get("name") == name for item in self.listed_repos())
                assert not half_ready_listed, "half-ready repository appeared in the ready catalog list"
                uncommitted_rows = self.authority_count_for_name(name)
                assert uncommitted_rows == "0|0|0|0", "uncommitted provisioning rows were visible: " + uncommitted_rows
                killed_pid = self.proc.pid
                self.stop(hard=True)
            finally:
                try:
                    self.abort_barrier_and_wait()
                finally:
                    worker.join(timeout=20)
                    assert not worker.is_alive(), "blocked create client did not finish after the service was killed"
            assert "value" not in response, "create returned an acknowledgment although COMMIT was blocked"
            assert "value" in thread_error, "blocked create did not observe a lost connection: " + repr(response)
        except Exception:
            # Preserve the original failure, but do not leave a live service or
            # an installed trigger behind. Harness.cleanup also drops this
            # run's random schema. The fixture SQL itself is lock/statement
            # bounded, so this cannot wait forever.
            if self.proc is not None:
                try:
                    self.stop(hard=True)
                except Exception:
                    pass
            if barrier_installed:
                try:
                    self.drop_deferred_barrier()
                except Exception:
                    pass
            raise
        # Success path: prove the trigger/barrier are gone before the retry.
        self.drop_deferred_barrier()
        barrier_installed = False
        assert killed_pid is not None, "the service process was not killed at the deferred COMMIT barrier"
        # The killed transaction must have rolled back completely: a retry
        # starts from one clean durable intent, never from a pending half-state.
        after_abort = self.authority_count_for_name(name)
        assert after_abort == "0|0|0|0", "aborted provisioning left committed authority rows: " + after_abort
        self.start(label="after-deferred-kill")
        status, raw = self.post_create(payload, attempts=4)
        assert status == 201, "retry after rollback did not create a fresh authority: " + str(status)
        repo = json.loads(raw)
        assert repo["state"] == "ready" and repo["name"] == name
        got = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
        assert got["id"] == repo["id"] and got["state"] == "ready"
        facts = self.authority(repo, name)
        oid = self.push_and_clone(repo, name)
        return {"barrier": "fixture-owned deferred PostgreSQL constraint trigger at COMMIT",
                "killed_pid": killed_pid, "restarted_pid": self.proc.pid,
                "half_ready_lookup_status": half_ready_status, "half_ready_listed": half_ready_listed,
                "uncommitted_authority_counts": uncommitted_rows,
                "post_abort_authority_counts": after_abort,
                "client_result": type(thread_error["value"]).__name__,
                "retry_status": status, "authority": facts, "ack_oid": oid, "clone_fsck": True}


def report_result(harness, profile, blob_profile, selected, success, hashes):
    errors = []
    try:
        serving.validate_report_cases({"cases": harness.results}, selected)
    except serving.ProfileError as error:
        errors.append(str(error))
    if profile.source_digest() != profile.build["source_inputs_sha256"]:
        errors.append("production source changed during acceptance")
    if serving.sha256_file(profile.binary) != profile.build["binary_sha256"]:
        errors.append("executed binary changed during acceptance")
    if serving.sha256_file(profile.binary.with_suffix(".build.json")) != profile.receipt_sha256:
        errors.append("build receipt changed during acceptance")
    if input_hashes() != hashes:
        errors.append("harness/helper source changed during acceptance")
    report = {
        "kind": "rootyard/blob-provisioning-native-acceptance",
        "passed": bool(success and not errors),
        "qualification_kind": "clean-candidate" if profile.working_tree_clean else "dirty-diagnostic-only",
        "measurement_kind": "native_execution",
        "simulated_fields": False,
        "inputs_unchanged": not errors,
        "source_head": profile.build["workspace_commit"],
        "source_inputs_sha256": profile.build["source_inputs_sha256"],
        "binary_sha256": profile.build["binary_sha256"],
        "build_receipt_sha256": profile.receipt_sha256,
        "harness_sha256": hashes[Path(__file__).name],
        "harness_inputs_sha256": hashes,
        "git_sha256": profile.git_sha256,
        "blob_profile": blob_profile,
        "checkpoints": {"first": list(FIRST_CHECKPOINT), "second": list(SECOND_CHECKPOINT),
                        "selected": list(selected)},
        "expected_cases": list(selected),
        "case_count": len(harness.results),
        "expected_count": len(selected),
        "cases": harness.results,
        "skips": 0,
        "limitations": LIMITATIONS,
        "tool_versions": ops_provenance.tool_versions(),
    }
    if errors:
        report["binding_errors"] = errors
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute source-attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git, or ROOTYARD_GIT")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", action="append", choices=CASES, default=[],
                        help="run only this case (repeatable); the second checkpoint may be run alone")
    args = parser.parse_args(argv)
    selected = [name for name in CASES if not args.case or name in args.case]
    try:
        env = os.environ.copy()
        profile = serving.NativeProfile(args.binary, args.git, env)
        blob_profile = serving.check_blob_profile(env)
        serving.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        serving.need(shutil.which("psql"), "psql is required")
        serving.need(selected, "no cases selected; a zero-case run cannot be green")
        hashes = input_hashes()
    except Exception as error:
        report = {"kind": "rootyard/blob-provisioning-native-acceptance", "passed": False,
                  "preflight_failed": True, "error": str(error), "cases": [],
                  "expected_cases": selected, "skips": 0, "limitations": LIMITATIONS}
        serving.write_report(args.report, report)
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    harness, success = ProvisioningHarness(args, profile, blob_profile), False
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
        report = report_result(harness, profile, blob_profile, selected, success, hashes)
        serving.write_report(args.report, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
