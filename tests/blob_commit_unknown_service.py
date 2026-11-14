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
asserted while the lock is still held. Releasing the lock lets the same
server-side COMMIT settle; the authenticated GET operations route then resolves
the same id. If settlement leaves a durable pending operation, the exact same
operation id and wire body are retried once and the final GET must be committed;
a permanent pending result fails the case. Exact persisted ref, gate, event,
terminal and pack rows are snapshotted rather than counted.

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
LIMITATIONS = list(blob.LIMITATIONS) + [
    "The COMMIT ambiguity is fixture-owned PostgreSQL deferred-trigger/advisory-lock timing, not a kernel or power-loss claim.",
    "The harness waits for the service's own verifier deadline; it does not inject a product success or override the wire verdict.",
    "A settled pending GET is not resolved acceptance; the case retries the exact same operation id and wire body and fails unless the final GET is committed with exactly one ref/gate/event/pack effect.",
]


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
        rid = str(uuid.UUID(repo_id))
        operation = str(uuid.UUID(operation))
        raw = self.sql(
            "SELECT to_jsonb(o)::text FROM ref_store_operations o "
            "WHERE o.repository_id='" + rid + "' AND o.operation_id='" + operation + "'")
        assert raw, "operation row is missing"
        return json.loads(raw)

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

    def _start_blocker(self, key, application_name):
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
                "WHERE a.application_name='" + application_name + "' AND l.locktype='advisory' AND l.granted"))
            if held == 1:
                return process
            time.sleep(0.05)
        process.terminate()
        process.wait(timeout=5)
        raise AssertionError("fixture advisory lock was not acquired")

    def _release_blocker(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def _waiting_commit_pid(self):
        return self.sql(
            "SELECT a.pid FROM pg_stat_activity a "
            "WHERE a.datname=current_database() AND a.state='active' "
            "AND regexp_replace(a.query, '\\s+', '', 'g') IN ('COMMIT','COMMIT;') "
            "AND a.wait_event_type='Lock' AND a.wait_event='advisory' LIMIT 1")

    def _await_waiting_commit(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pid = self._waiting_commit_pid()
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
            self._await_waiting_commit()
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

        operation_path = ("/api/repos/" + urllib.parse.quote(repo["owner"], safe="") + "/"
                          + urllib.parse.quote(repo["name"], safe="") + "/operations/" + operation)
        get_status, raw, headers = self.http(operation_path, token=self.alice)
        assert get_status == 200, "GET operation after release: " + str(get_status) + ": " + repr(raw[:300])
        assert blob.header_value(headers, "cache-control") == "no-store"
        view = json.loads(raw)
        assert view["operation_id"] == operation
        assert view["state"] in ("pending", "committed"), view

        retry_status = None
        retry_report_ok = False
        retry_unknown = False
        if view["state"] == "committed":
            resolved_by = "query"
        else:
            # All COMMIT statements settled while the operation is still
            # pending: the original transaction rolled back. This is a durable
            # no-effect state, never a resolved acceptance.
            settled = self.exact_ledger(repo["id"])
            assert rows(settled["refs"]) == rows(before["refs"]), "settled pending COMMIT moved a ref"
            assert rows(settled["gate"]) == rows(before["gate"]), "settled pending COMMIT moved the gate"
            assert rows(settled["events"]) == rows(before["events"]), "settled pending COMMIT wrote an event"
            settled_operations = rows(settled["operations"])
            assert len(settled_operations) == 2, settled_operations
            assert row_for(settled_operations, "operation_id", seed_operation["operation_id"]) == seed_operation
            settled_operation = self.operation_row(repo["id"], operation)
            assert row_for(settled_operations, "operation_id", operation) == settled_operation
            assert settled_operation["state"] == "pending", settled_operation
            assert settled_operation["terminal_result"] is None, settled_operation
            assert self.pack_identity(repo["id"], operation) == inflight_pack, \
                "pending settlement changed the durable pack identity"
            assert view["terminal"] is None, view

            # Retry exactly the same operation id and exact same wire bytes. A
            # new operation id is not a resolution of the original unknown.
            retry_status, retry_body, retry_headers = self._long_http(path, self.alice, body, operation)
            assert blob.header_value(retry_headers, "x-rootyard-operation") == operation, retry_headers
            if retry_status == 200:
                blob.assert_receive_report_ok(retry_body, "refs/heads/main")
                retry_report_ok = True
            else:
                assert retry_status == 503, ("same-operation retry returned an unexpected status: "
                                             + str(retry_status) + " body=" + repr(retry_body[:300]))
                retry_error = json.loads(retry_body)
                assert retry_error == {"error": "publication outcome is unknown; query the operation or inspect refs"}, retry_error
                for marker in (b"unpack ok", b"ok refs/heads/main", b"ng refs/heads/main"):
                    assert marker not in retry_body, "unknown retry carried a Git report: " + repr(retry_body[:300])
                retry_unknown = True

            # The final authenticated query is authoritative. A 503 retry that
            # still observes committed only proves a late original COMMIT; it is
            # not a retry resolution. A final pending state is unresolved.
            get_status, raw, headers = self.http(operation_path, token=self.alice)
            assert get_status == 200, "GET operation after retry: " + str(get_status) + ": " + repr(raw[:300])
            assert blob.header_value(headers, "cache-control") == "no-store"
            view = json.loads(raw)
            assert view["operation_id"] == operation
            if view["state"] == "pending":
                assert retry_unknown, "same-operation retry reported success but the operation stayed pending"
                raise AssertionError("permanent pending after exact same-operation retry: "
                                     "the operation never reached a committed terminal")
            assert view["state"] == "committed", "same-operation retry left a non-terminal state: " + str(view)
            resolved_by = "retry" if retry_report_ok else "query_after_retry"

        terminal = view["terminal"]
        assert terminal is not None, view

        resolved = self.exact_ledger(repo["id"])
        resolved_operation = self.operation_row(repo["id"], operation)
        resolved_pack = self.pack_identity(repo["id"], operation)
        assert resolved_pack == inflight_pack, "COMMIT settlement changed the durable pack identity"

        resolved_operations = rows(resolved["operations"])
        assert len(resolved_operations) == 2, resolved_operations
        assert row_for(resolved_operations, "operation_id", seed_operation["operation_id"]) == seed_operation
        assert row_for(resolved_operations, "operation_id", operation) == resolved_operation
        assert view["state"] == "committed", view

        ref_rows = rows(resolved["refs"])
        assert len(ref_rows) == 1, ref_rows
        ref_row = row_for(ref_rows, "ref_name", "refs/heads/main")
        assert ref_row["oid"] == new_oid and ref_row["revision"] == new_revision, ref_row
        gate_rows = rows(resolved["gate"])
        assert len(gate_rows) == 1, gate_rows
        gate_row = gate_rows[0]
        assert gate_row["revision"] == new_revision and gate_row["head_ref"] == "refs/heads/main", gate_row
        event_rows = rows(resolved["events"])
        assert len(event_rows) == len(rows(before["events"])) + 1, event_rows
        for prior_event in rows(before["events"]):
            assert row_for(event_rows, "event_id", prior_event["event_id"]) == prior_event, \
                "an existing event changed during COMMIT settlement"
        event = row_for(event_rows, "operation_id", operation)
        assert event["outcome"] == "committed" and event["revision"] == new_revision, event
        assert event["payload"] == terminal, "event payload differs from the queried terminal"
        assert resolved_operation["state"] == "committed", resolved_operation
        assert resolved_operation["terminal_result"] == terminal, resolved_operation
        assert terminal["kind"] == "committed" and terminal["revision"] == new_revision, terminal
        assert terminal["head_ref"] == "refs/heads/main", terminal
        assert len(terminal["refs"]) == 1, terminal
        assert terminal["refs"][0]["name"] == "refs/heads/main", terminal
        assert terminal["refs"][0]["new_oid"] == new_oid, terminal
        publications = rows(inflight_pack["publications"])
        artifacts = rows(inflight_pack["artifacts"])
        assert len(publications) == 1, publications
        assert len(artifacts) == 2, artifacts
        registrations = terminal["registrations"]
        assert len(registrations) == 1, terminal
        assert {(item["pack_id"], item["registration_id"], item["artifact_set_digest"])
                for item in registrations} == {(item["pack_id"], item["registration_id"],
                                                item["artifact_set_digest"]) for item in publications}

        # Authenticated operation lookup is issuer/admin only. These are
        # denials, never operation detail or a terminal body.
        def denied(lookup_path, token=None, codes=(401, 403, 404)):
            code, raw, _ = self.http(lookup_path, token=token)
            assert code in codes, (code, raw[:300])
            body = json.loads(raw)
            assert set(body) == {"error"}, body
            assert "terminal" not in body and "operation_id" not in body, body

        denied(operation_path, codes=(401,))
        denied(operation_path, {"username": "alice", "token": "ryt_" + "0" * 64}, codes=(401,))
        denied(operation_path, self.bob, codes=(403, 404))
        other_repo, _ = self.create("commit-unknown-other", self.alice)
        other_path = ("/api/repos/" + urllib.parse.quote(other_repo["owner"], safe="") + "/"
                      + urllib.parse.quote(other_repo["name"], safe="") + "/operations/" + operation)
        denied(other_path, self.alice, codes=(404,))

        return {
            "operation": operation,
            "wire_status": wire_status,
            "wire_error": wire_error["error"],
            "resolved_state": view["state"],
            "resolved_by": resolved_by,
            "retry_status": retry_status,
            "retry_unknown": retry_unknown,
            "retry_report_ok": retry_report_ok,
            "operation_get_status": get_status,
            "commit_landed": True,
            "one_effect_checked": True,
            "base_revision": base_revision,
            "new_revision": new_revision,
            "ack_oid": new_oid,
            "exact_refs": rows(resolved["refs"]),
            "exact_gate": rows(resolved["gate"]),
            "exact_events": rows(resolved["events"]),
            "exact_terminal": terminal,
            "exact_operation": resolved_operation,
            "pack_identity": pack_identity_summary(resolved_pack),
            "refs_sha256": digest(resolved["refs"]),
            "gate_sha256": digest(resolved["gate"]),
            "events_sha256": digest(resolved["events"]),
            "terminal_sha256": digest(json.dumps(terminal, sort_keys=True, separators=(",", ":"))),
            "pack_identity_sha256": digest(json.dumps(resolved_pack, sort_keys=True, separators=(",", ":"))),
            "pack_registration_ids": [item["registration_id"] for item in rows(inflight_pack["publications"])],
            "pack_identity_unchanged": True,
            "exact_ref_gate_event_terminal_checked": True,
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
    try:
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
        checkpoint_sha = blob.sha256_file(Path(__file__))
        checkpoint_unchanged = checkpoint_sha == profile.checkpoint_sha256
        report["checkpoint_sha256"] = checkpoint_sha
        report["harness_inputs"] = {
            "blob_only_service_sha256": report["harness_sha256"],
            "checkpoint_sha256": checkpoint_sha,
        }
        report["limitations"] = LIMITATIONS
        if not checkpoint_unchanged:
            report["inputs_unchanged"] = False
            report["passed"] = False
            prior = report.get("binding_error")
            report["binding_error"] = ("checkpoint harness changed during native acceptance"
                                       + ("; " + prior if prior else ""))
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
