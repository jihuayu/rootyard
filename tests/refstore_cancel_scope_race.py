#!/usr/bin/env python3
"""Root-only real-PostgreSQL regressions for Cancel token-scope ordering.

Run this on Linux with the attested standalone CLI, real PostgreSQL 17,
the owned Blob profile and stock Git.

The fixture proves both orders of the documented late-scope contract:

* ``narrow_first_scope_denial_leaves_cancel_state_unchanged`` parks a real Cancel
  request on its selected private attempt's advisory key after HTTP preflight,
  commits a real restricted-token PATCH that removes ContentsWrite, then releases
  Cancel. Cancel must reach its late check, deny with 403, and leave the
  operation, decision, cancellation tombstones, refs, gate and events unchanged.

* ``cancel_first_late_scope_holds_until_terminal_commit`` parks a real Cancel
  transaction at a fixture-owned BEFORE UPDATE advisory barrier on
  ``ref_store_publication_decisions``. That barrier is after
  ``authorize_repository_late`` has taken the token row FOR SHARE. A concurrent
  real PATCH is observed blocked by that Cancel backend; it may commit only after
  Cancel commits its cancellation terminal and tombstones.

The barriers are actual PostgreSQL session/advisory locks observed through
``pg_stat_activity``/``pg_blocking_pids`` on distinct connections, not sleeps.
The only SQL fixtures are a bounded trigger/function, session advisory locks,
snapshots/assertions of the run-owned schema, and the existing role/token setup.
No ready repository, ACK, operation, A3 binding, terminal, cancellation or scope
row is fabricated by SQL.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_commit_unknown_service as checkpoint  # noqa: E402
import blob_only_service as blob  # noqa: E402

NARROW_FIRST = "narrow_first_scope_denial_leaves_cancel_state_unchanged"
CANCEL_FIRST = "cancel_first_late_scope_holds_until_terminal_commit"
CASES = (NARROW_FIRST, CANCEL_FIRST)

LIMITATIONS = [
    "Native fixture requires the attested standalone binary, real PostgreSQL, the owned Blob profile and trusted stock Git.",
    "The narrow-first barrier is the current private attempt's real operation advisory key, held by a separate PostgreSQL session. Public Cancel takes that key in its migration-152 lock set after the HTTP writable lookup; the scope PATCH then commits before the late check.",
    "The cancel-first barrier is a fixture-owned BEFORE UPDATE advisory trigger on ref_store_publication_decisions. It fires after authorize_repository_late has acquired the token row FOR SHARE, so a real concurrent PATCH is observed blocked by the Cancel backend until cancellation commits.",
    "Blocking and order are observed through pg_stat_activity and pg_blocking_pids on distinct connections; there is no sleep-only assertion.",
    "The pending cancellable operation comes from one real receive-pack COMMIT whose fixture-blocked backend is terminated before the deferred trigger is released. This is a durable pending state, not a fabricated operation, ACK or terminal.",
    "This is a bounded single-PostgreSQL fixture. It does not claim kernel, power-loss, network-partition or distributed behavior, and it makes no non-race product acceptance claim.",
]


def input_hashes():
    return blob.http_input_hashes()


class CancelScopeProfile(checkpoint.CheckpointProfile):
    def __init__(self, binary, git_flag, env):
        super().__init__(binary, git_flag, env)
        self.cancel_scope_sha256 = blob.sha256_file(Path(__file__))


class CancelScopeHarness(checkpoint.CheckpointHarness):
    def _operation_path(self, repo, operation):
        return ("/api/repos/" + urllib.parse.quote(repo["owner"], safe="") + "/"
                + urllib.parse.quote(repo["name"], safe="") + "/operations/" + operation)

    def _cancel_path(self, repo, operation):
        return self._operation_path(repo, operation) + "/cancel"

    def _operation_view(self, repo, operation):
        status, raw, headers = self.http(self._operation_path(repo, operation), token=self.alice)
        assert status == 200, "GET operation: " + str(status) + ": " + repr(raw[:300])
        assert blob.header_value(headers, "cache-control") == "no-store", headers
        data = json.loads(raw)
        assert data.get("operation_id") == operation, data
        return data

    def _decision_rows(self, repo, private_id):
        rid = str(uuid.UUID(repo["id"]))
        private_id = str(uuid.UUID(private_id))
        raw = self.sql(
            "SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.decision_id), '[]'::jsonb)::text "
            "FROM ref_store_publication_decisions d "
            "WHERE d.repository_id='" + rid + "' AND d.operation_id='" + private_id + "'")
        return checkpoint.rows(raw)

    def _scope_actions(self, repo, token_id):
        rid = str(uuid.UUID(repo["id"]))
        token_id = str(uuid.UUID(token_id))
        raw = self.sql(
            "SELECT coalesce(jsonb_agg(s.action ORDER BY s.action), '[]'::jsonb)::text "
            "FROM token_repository_scopes s "
            "WHERE s.token_id='" + token_id + "' AND s.repository_id='" + rid + "'")
        return set(checkpoint.rows(raw))

    def _issue_scope_token(self, repo, label):
        payload = {
            "display_name": label,
            "expires_in_days": 1,
            "read_only": False,
            "repository_grants": [{
                "repository_id": repo["id"],
                "actions": ["contents_read", "contents_write", "repo_read"],
            }],
            "namespace_grants": [],
        }
        status, raw, headers = self.http("/api/tokens", token=self.alice, method="POST", body=payload)
        assert status == 201, "POST /api/tokens: " + str(status) + ": " + repr(raw[:300])
        assert blob.header_value(headers, "cache-control") == "no-store", headers
        data = json.loads(raw)
        self.secrets.append(data["secret"])
        assert data.get("is_restricted") is True, data
        assert data.get("scope_version") == 1, data
        assert self._scope_actions(repo, data["id"]) == {"contents_read", "contents_write", "repo_read"}
        return {
            "username": "alice",
            "token": data["secret"],
            "id": data["id"],
            "scope_version": data["scope_version"],
        }

    def _narrow_payload(self, repo, expected_version, actions):
        return {
            "expected_scope_version": expected_version,
            "repository_grants": [{
                "repository_id": repo["id"],
                "actions": list(actions),
            }],
            "namespace_grants": [],
        }

    def _narrow_token(self, repo, token, actions):
        status, raw, _headers = self.http(
            "/api/tokens/" + token["id"],
            token=self.alice,
            method="PATCH",
            body=self._narrow_payload(repo, token["scope_version"], actions),
        )
        assert status == 200, "PATCH token scope: " + str(status) + ": " + repr(raw[:300])
        data = json.loads(raw)
        assert data.get("scope_version") == token["scope_version"] + 1, data
        grants = data.get("repository_grants") or []
        assert len(grants) == 1, grants
        assert set(grants[0].get("actions") or []) == set(actions), grants
        token["scope_version"] = data["scope_version"]
        return data

    def _start_blocker_sql(self, statement, application_name):
        self._validate_blocker_application_name(application_name)
        env = self.env.copy()
        env["PGDATABASE"] = self.db
        env["PGAPPNAME"] = application_name
        process = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
             "SET application_name='" + application_name + "'; " + statement
             + "; SELECT pg_sleep(300);"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._await_session(process, application_name)
        self._register_owned_blocker_or_reap(process, application_name)
        return process

    def _await_session(self, process, application_name, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, error = process.communicate()
                raise AssertionError(
                    "fixture psql session exited: "
                    + self.redact(error[:500].decode(errors="replace")))
            active = self.sql(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE application_name='" + application_name + "' "
                "AND datname=current_database() AND state='active'")
            held = self.sql(
                "SELECT count(*) FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid "
                "WHERE a.application_name='" + application_name + "' "
                "AND a.datname=current_database() AND l.locktype='advisory' AND l.granted")
            if active == "1" and held == "1":
                return
            time.sleep(0.05)
        self._reap_blocker_child(process)
        raise AssertionError("fixture psql session did not become active: " + application_name)

    def _session_pid(self, application_name):
        value = self.sql(
            "SELECT pid FROM pg_stat_activity "
            "WHERE application_name='" + application_name + "' "
            "AND datname=current_database() AND state='active' LIMIT 1")
        assert value, "fixture psql session is not active: " + application_name
        return int(value)

    def _await_blocked_by(self, blocker_pid, label, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.sql(
                "SELECT pid FROM pg_stat_activity "
                "WHERE datname=current_database() AND state='active' "
                "AND pid <> " + str(blocker_pid) + " "
                "AND wait_event_type='Lock' "
                "AND " + str(blocker_pid) + " = ANY(pg_blocking_pids(pid)) LIMIT 1")
            if value:
                return int(value)
            time.sleep(0.05)
        raise AssertionError("fixture backend never blocked on " + label)

    def _timed_http(self, path, token, method, body=None):
        status, raw, headers = self.http(path, token=token, method=method, body=body)
        return status, raw, headers, time.monotonic()

    def _pending_operation(self, label):
        """Create one real pending operation by aborting its fixture-blocked COMMIT."""
        repo, _remote, work, old_oid = self.seed(label, self.alice)
        new_oid = self.commit_files(
            work, "pending " + label, {label + ".txt": "real pending operation\n"})
        assert new_oid != old_oid
        pack = self.run(
            [str(self.profile.git), "--no-pager", "pack-objects", "--stdout", "--all"],
            cwd=work, data=b"").stdout
        assert pack.startswith(b"PACK") and len(pack) > 32, "trusted Git produced no pack stream"
        body = blob.receive_pack_request(old_oid, new_oid, "refs/heads/main", pack)
        operation = str(uuid.uuid4())
        key = uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF
        application_name = "rootyard-cancel-scope-commit-" + uuid.uuid4().hex
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        blocker = None
        try:
            self._create_commit_gate(key)
            blocker = self._start_blocker(key, application_name)
            future = executor.submit(
                self._long_http, repo["clone_path"] + "/git-receive-pack",
                self.alice, body, operation)
            commit_pid = self._await_waiting_commit(key)
            assert not future.done(), "receive-pack returned before the deferred COMMIT barrier"
            status, response, _headers = future.result(timeout=80)
            assert status == 503, ("pending fixture COMMIT status=" + str(status)
                                   + ": " + repr(response[:300]))
            blocked_pid = self._waiting_commit_pid(key)
            if blocked_pid:
                assert int(blocked_pid) == commit_pid, "fixture found a different blocked COMMIT backend"
                terminated = self.sql("SELECT pg_terminate_backend(" + str(commit_pid) + ")")
                assert terminated == "t", "fixture could not terminate the blocked COMMIT backend"
            self._release_blocker(blocker)
            blocker = None
        finally:
            if blocker is not None:
                self._release_blocker(blocker)
            executor.shutdown(wait=True, cancel_futures=False)
            self._await_commit_finished()
            self._drop_commit_gate()
        view = self._operation_view(repo, operation)
        assert view.get("state") == "pending", view
        assert view.get("terminal") is None, view
        return repo, operation

    def narrow_first_scope_denial_leaves_cancel_state_unchanged(self):
        repo, public_id = self._pending_operation("cancel-scope-narrow")
        token = self._issue_scope_token(repo, "cancel-narrow")
        _, attempt = self.current_public_attempt(repo["id"], public_id, "pending")
        private_id = attempt["private_id"]
        before_ledger = self.exact_ledger(repo["id"])
        before_tombstones = self.cancellation_snapshot(repo["id"], private_id)
        before_decisions = self._decision_rows(repo, private_id)
        before_view = self._operation_view(repo, public_id)
        assert before_view["state"] == "pending" and before_view["terminal"] is None, before_view
        assert len(before_decisions) == 1 and before_decisions[0]["state"] == "OPEN", before_decisions
        assert not before_tombstones["legacy"] and not before_tombstones["decision"], before_tombstones

        application_name = "rootyard-cancel-scope-op-" + uuid.uuid4().hex
        blocker = None
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            rid = str(uuid.UUID(repo["id"]))
            attempt_id = str(uuid.UUID(private_id))
            blocker = self._start_blocker_sql(
                "SELECT pg_advisory_lock(rootyard_ref_store_attempt_key("
                "'" + rid + "'::uuid, '" + attempt_id + "'::uuid))",
                application_name)
            blocker_pid = self._session_pid(application_name)
            cancel_future = executor.submit(
                self._timed_http, self._cancel_path(repo, public_id), token, "POST")
            cancel_pid = self._await_blocked_by(blocker_pid, "cancel private attempt advisory lock")
            assert not cancel_future.done(), "cancel finished before the operation barrier"
            assert self._operation_view(repo, public_id) == before_view, \
                "cancel changed the operation before the late scope check"
            self._narrow_token(repo, token, ("contents_read", "repo_read"))
            narrow_done = time.monotonic()
            assert not cancel_future.done(), "cancel finished before the narrowing PATCH committed"
            self._release_blocker(blocker)
            blocker = None
            status, raw, _headers, cancel_done = cancel_future.result(timeout=30)
            assert status == 403, ("late scope denial status=" + str(status)
                                   + ": " + repr(raw[:300]))
            assert json.loads(raw) == {"error": "publication is not authorized"}, raw
            assert cancel_done > narrow_done, "cancel did not deny after narrowing committed"
            assert self.exact_ledger(repo["id"]) == before_ledger, \
                "denied cancel changed refs/gate/events/public wrapper/private ledger"
            assert self.cancellation_snapshot(repo["id"], private_id) == before_tombstones, \
                "denied cancel wrote a cancellation tombstone"
            assert self._decision_rows(repo, private_id) == before_decisions, \
                "denied cancel changed the decision row"
            assert self._operation_view(repo, public_id) == before_view, \
                "denied cancel changed the operation view"
            assert self._scope_actions(repo, token["id"]) == {"contents_read", "repo_read"}, \
                "scope narrowing did not commit the expected grant set"
            return {
                "operation": public_id,
                "decision_id": before_decisions[0]["decision_id"],
                "cancel_pid": cancel_pid,
                "narrow_first": True,
                "denied_status": status,
                "exact_operation_terminal_tombstones_refs_gate_events_unchanged": True,
                "public_wrapper_and_private_attempt_unchanged": True,
                "scope_version": token["scope_version"],
                "remaining_scope_actions": sorted(self._scope_actions(repo, token["id"])),
            }
        finally:
            if blocker is not None:
                self._release_blocker(blocker)
            executor.shutdown(wait=True, cancel_futures=False)

    def cancel_first_late_scope_holds_until_terminal_commit(self):
        repo, public_id = self._pending_operation("cancel-scope-cancel")
        token = self._issue_scope_token(repo, "cancel-first")
        before_wrapper, before_attempt = self.current_public_attempt(repo["id"], public_id, "pending")
        private_id = before_attempt["private_id"]
        before_ledger = self.exact_ledger(repo["id"])
        before_view = self._operation_view(repo, public_id)
        before_decisions = self._decision_rows(repo, private_id)
        assert before_view["state"] == "pending" and before_view["terminal"] is None, before_view
        assert len(before_decisions) == 1 and before_decisions[0]["state"] == "OPEN", before_decisions
        assert self._scope_actions(repo, token["id"]) == {"contents_read", "contents_write", "repo_read"}

        key = uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF
        suffix = uuid.uuid4().hex
        function_name = "rootyard_cancel_scope_gate_" + suffix
        trigger_name = "rootyard_cancel_scope_gate_" + suffix
        application_name = "rootyard-cancel-scope-decision-" + uuid.uuid4().hex
        blocker = None
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        try:
            self.sql(
                "CREATE FUNCTION " + function_name + "() RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN PERFORM pg_advisory_xact_lock(" + str(key) + "); RETURN NEW; END $$; "
                "CREATE TRIGGER " + trigger_name + " BEFORE UPDATE ON ref_store_publication_decisions "
                "FOR EACH ROW EXECUTE FUNCTION " + function_name + "();")
            blocker = self._start_blocker_sql(
                "SELECT pg_advisory_lock(" + str(key) + ")", application_name)
            blocker_pid = self._session_pid(application_name)
            cancel_future = executor.submit(
                self._timed_http, self._cancel_path(repo, public_id), token, "POST")
            cancel_pid = self._await_blocked_by(blocker_pid, "cancel decision-write advisory barrier")
            assert not cancel_future.done(), "cancel finished before the decision barrier"
            assert self._operation_view(repo, public_id) == before_view, \
                "cancel terminal became visible before the decision barrier released"
            narrow_future = executor.submit(
                self._timed_http, "/api/tokens/" + token["id"], self.alice, "PATCH",
                self._narrow_payload(repo, token["scope_version"], ("contents_read", "repo_read")))
            narrow_pid = self._await_blocked_by(cancel_pid, "scope narrowing against late token FOR SHARE")
            assert not narrow_future.done(), "scope narrowing bypassed the late token lock"
            assert not cancel_future.done(), "cancel committed before the narrowing waiter was observed"
            self._release_blocker(blocker)
            blocker = None
            # Narrowing was observed blocked by this exact Cancel backend. It
            # cannot pass the target-token FOR UPDATE until Cancel releases the
            # FOR SHARE at commit, so the database order is Cancel then narrowing.
            cancel_status, cancel_raw, cancel_headers, _cancel_done = cancel_future.result(timeout=30)
            narrow_status, narrow_raw, _narrow_headers, _narrow_done = narrow_future.result(timeout=30)
            assert cancel_status == 200, ("cancel-first status=" + str(cancel_status)
                                          + ": " + repr(cancel_raw[:300]))
            cancel_view = json.loads(cancel_raw)
            assert cancel_view.get("operation_id") == public_id, cancel_view
            assert cancel_view.get("state") == "cancelled", cancel_view
            assert cancel_view.get("terminal") == {"state": "cancelled", "reason": "cancel_requested"}, cancel_view
            self.assert_private_id_hidden(cancel_raw, cancel_headers, private_id)
            assert narrow_status == 200, ("scope narrowing status=" + str(narrow_status)
                                         + ": " + repr(narrow_raw[:300]))
            narrowed = json.loads(narrow_raw)
            assert narrowed.get("scope_version") == token["scope_version"] + 1, narrowed
            grants = narrowed.get("repository_grants") or []
            assert len(grants) == 1 and set(grants[0].get("actions") or []) == {"contents_read", "repo_read"}, grants
            after_ledger = self.exact_ledger(repo["id"])
            assert checkpoint.rows(after_ledger["refs"]) == checkpoint.rows(before_ledger["refs"]), \
                "cancel-first changed refs"
            assert checkpoint.rows(after_ledger["gate"]) == checkpoint.rows(before_ledger["gate"]), \
                "cancel-first changed the gate"
            assert checkpoint.rows(after_ledger["events"]) == checkpoint.rows(before_ledger["events"]), \
                "cancel-first wrote an event"
            after_wrapper, after_attempt = self.current_public_attempt(repo["id"], public_id, "cancelled")
            assert after_attempt == before_attempt, "cancel changed the current private attempt mapping"
            assert after_wrapper == {
                **before_wrapper, "state": "cancelled", "cancelled_private_id": private_id,
            }, "cancel did not bind the same public wrapper to the private tombstone"
            assert after_ledger["attempt_retirements"] == before_ledger["attempt_retirements"], \
                "cancel changed retired attempts"
            after_decisions = self._decision_rows(repo, private_id)
            assert len(after_decisions) == 1 and after_decisions[0]["state"] == "CANCELLED", after_decisions
            cancelled_operation = self.operation_row(repo["id"], private_id)
            assert cancelled_operation["state"] == "cancelled", cancelled_operation
            assert cancelled_operation["terminal_result"] == {"state": "cancelled", "reason": "cancel_requested"}, \
                cancelled_operation
            tombstones = self.cancellation_snapshot(repo["id"], private_id)
            assert len(tombstones["legacy"]) == 1, tombstones
            assert len(tombstones["decision"]) == 1, tombstones
            decision = tombstones["decision"][0]
            assert tombstones["legacy"][0]["operation_id"] == decision["operation_id"] == private_id
            assert decision["decision_id"] == before_decisions[0]["decision_id"], decision
            assert decision["reason"] == "http_cancel_requested", decision
            assert decision["actor_id"] == self.alice["user_id"], decision
            assert self._scope_actions(repo, token["id"]) == {"contents_read", "repo_read"}, \
                "scope narrowing did not commit after the Cancel terminal"
            return {
                "operation": public_id,
                "decision_id": before_decisions[0]["decision_id"],
                "cancel_pid": cancel_pid,
                "narrow_pid": narrow_pid,
                "cancel_first": True,
                "cancel_status": cancel_status,
                "narrow_status": narrow_status,
                "narrow_blocked_by_cancel_backend": True,
                "cancel_terminal_committed_before_narrowing": True,
                "public_wrapper_bound_to_private_tombstones": True,
                "scope_version": narrowed["scope_version"],
                "remaining_scope_actions": sorted(self._scope_actions(repo, token["id"])),
            }
        finally:
            if blocker is not None:
                self._release_blocker(blocker)
            executor.shutdown(wait=True, cancel_futures=False)
            self.sql(
                "DROP TRIGGER IF EXISTS " + trigger_name + " ON ref_store_publication_decisions; "
                "DROP FUNCTION IF EXISTS " + function_name + "();")


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
        profile = CancelScopeProfile(str(Path(args.binary).resolve()), args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(shutil.which("psql"), "psql is required")
        selected = select_cases(args.case)
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/refstore-cancel-scope-race",
            "passed": False,
            "preflight_failed": True,
            "error": str(error),
            "cases": [],
            "expected_cases": [],
            "skips": 0,
            "limitations": LIMITATIONS,
            "harness_inputs_sha256": hashes or {},
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2

    args.binary = str(profile.binary)
    harness = CancelScopeHarness(args, profile, blob_profile)
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
            harness.results.append({
                "name": "cleanup",
                "status": "failed",
                "error": harness.redact(error),
            })
            success = False
        report = blob.build_report(harness, profile, blob_profile, selected, success)
        report["kind"] = "rootyard/refstore-cancel-scope-race"
        report["limitations"] = LIMITATIONS
        blob.bind_http_report(report, Path(__file__).name, hashes, profile)
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
