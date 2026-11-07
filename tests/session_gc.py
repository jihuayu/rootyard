#!/usr/bin/env python3
"""Native regression coverage for bounded expired browser-session/token GC.

The harness starts the real `rootyard` binary against the private PostgreSQL
fixture and speaks real HTTP. Expired browser history beyond one batch is seeded
with SQL so the volume is cheap; the login, logout, natural-expiry, active
session and concurrent authorization checks themselves use the real service.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness
from web_sessions import BrowserHarness

BATCH_LIMIT = 128
DEFAULT_RETENTION = "7 days"


class SessionGcHarness(BrowserHarness):
    def __init__(self, args):
        super().__init__(args)
        # One-second cadence keeps the drill fast; retention deliberately stays
        # at the production default of seven days so the retention gate is real.
        self.env.update(ROOTYARD_SESSION_GC_INTERVAL_SECONDS="1")
        self.worker = None
        self.worker_log = None
        self.limits.append(
            "Bulk expired browser rows are seeded with SQL; they are not claimed to be "
            "individual browser logins. Login/logout/natural-expiry rows are real."
        )

    # ---- bounded fixture helpers -------------------------------------------------
    def seed_browser_token(self, age="8 days", with_session=True, revoked=False):
        token_id = str(uuid.uuid4())
        digest = hashlib.sha256(("token-" + token_id).encode()).hexdigest()
        csrf = hashlib.sha256(("csrf-" + token_id).encode()).hexdigest()
        flag = "true" if revoked else "false"
        self.sql(
            "INSERT INTO tokens(id,user_id,digest,read_only,revoked,expires_at,kind) VALUES("
            f"'{token_id}','{self.alice['user_id']}',decode('{digest}','hex'),false,{flag},"
            f"clock_timestamp()-interval '{age}','browser')"
        )
        if with_session:
            self.sql(
                "INSERT INTO web_sessions(token_id,csrf_digest,expires_at,revoked) VALUES("
                f"'{token_id}',decode('{csrf}','hex'),clock_timestamp()-interval '{age}',{flag})"
            )
        return token_id

    def seed_bulk_expired(self, count, age="8 days"):
        user = self.alice["user_id"]
        self.sql(
            "WITH seeded AS (SELECT i FROM generate_series(1," + str(count) + ") i), "
            "inserted AS (INSERT INTO tokens(id,user_id,digest,read_only,revoked,expires_at,kind) "
            f"SELECT gen_random_uuid(),'{user}',"
            "decode(md5('bulk-token-'||i),'hex')||decode(md5('bulk-nonce-'||i),'hex'),"
            f"false,(i%2)=0,clock_timestamp()-interval '{age}','browser' FROM seeded RETURNING id) "
            "INSERT INTO web_sessions(token_id,csrf_digest,expires_at,revoked) "
            "SELECT id,decode(md5('bulk-csrf-'||id::text),'hex')||decode(md5('bulk-nonce2-'||id::text),'hex'),"
            f"clock_timestamp()-interval '{age}',false FROM inserted"
        )

    def counts(self):
        row = self.sql(
            "SELECT (SELECT count(*) FROM web_sessions),"
            " (SELECT count(*) FROM tokens WHERE kind='browser'),"
            " (SELECT count(*) FROM tokens WHERE kind='api'),"
            " (SELECT count(*) FROM web_sessions WHERE expires_at < clock_timestamp() - interval '"
            + DEFAULT_RETENTION
            + "'),"
            " (SELECT count(*) FROM tokens WHERE kind='browser' AND expires_at < clock_timestamp() - interval '"
            + DEFAULT_RETENTION
            + "')"
        )
        sessions, browser, api, expired_sessions, expired_browser = (int(v) for v in row.split("|"))
        return dict(
            sessions=sessions,
            browser_tokens=browser,
            api_tokens=api,
            expired_sessions=expired_sessions,
            expired_browser_tokens=expired_browser,
        )

    def newest_session_token(self):
        return self.sql("SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1")

    def backdate_newest_session(self, age="8 days"):
        token_id = self.newest_session_token()
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()-interval '{age}' WHERE id='{token_id}'")
        self.sql(f"UPDATE web_sessions SET expires_at=clock_timestamp()-interval '{age}' WHERE token_id='{token_id}'")
        return token_id

    def wait_for(self, predicate, description, timeout=45.0, poll=0.2, observe=None):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = predicate()
            if observe is not None:
                observe(last)
            if last:
                return last
            time.sleep(poll)
        raise AssertionError(f"timed out waiting for {description}; last observed {last!r}")

    def cookie_headers(self, cookies):
        return {"Cookie": self.cookie_header(cookies)}

    # ---- second GC worker --------------------------------------------------------
    def start_worker(self):
        self.worker_log = open(self.root / "worker.log", "ab")
        self.worker = subprocess.Popen(
            [self.args.binary, "worker"],
            env=self.env,
            stdout=self.worker_log,
            stderr=self.worker_log,
            start_new_session=True,
        )
        time.sleep(1.5)
        assert self.worker.poll() is None, "second PostgreSQL GC worker exited during startup"

    def stop_worker(self):
        if self.worker and self.worker.poll() is None:
            os.killpg(self.worker.pid, 15)
            try:
                self.worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.worker.pid, 9)
                self.worker.wait()
        self.worker = None
        if self.worker_log:
            self.worker_log.close()
            self.worker_log = None

    # ---- cases -------------------------------------------------------------------
    def expired_history_is_purged_in_bounded_batches(self):
        self.setup()
        self.api()
        user = self.alice["user_id"]
        repository = self.repo["id"]
        generation = self.sql(f"SELECT storage_generation FROM repositories WHERE id='{repository}'")

        # Real login rows: an active session that must survive, a real logout that
        # is revoked but not yet past expiry, and a naturally expired session.
        active_cookies, _, _ = self.sign_in()
        active_headers = self.cookie_headers(active_cookies)
        assert self.request("/web/repos", headers=active_headers)[0] == 200
        logout_cookies, _, _ = self.sign_in()
        logout_headers = self.cookie_headers(logout_cookies)
        assert self.request("/web/logout", "POST", headers={**logout_headers, "Origin": self.base})[0] == 303
        assert self.request("/web/repos", headers=logout_headers)[0] == 401
        natural_cookies, _, _ = self.sign_in()
        natural_token = self.backdate_newest_session()
        assert self.request("/web/repos", headers=self.cookie_headers(natural_cookies))[0] == 401
        # Five recently expired sessions: unusable for authentication but inside
        # the default seven-day retention window, so they must not be deleted.
        for _ in range(5):
            self.seed_browser_token(age="1 hour")

        # A child token still referenced by a durable Git operation root keeps
        # its metadata even when its expired session row is purged.
        referenced = self.seed_browser_token()
        self.sql(
            "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
            "storage_generation,evidence,outcome) VALUES("
            f"gen_random_uuid(),'{repository}','{user}','{referenced}','alice',999999,{generation},"
            "'{}'::jsonb,'recorded')"
        )
        # Orphan browser token: expired long ago with no web_sessions row.
        orphan = self.seed_browser_token(with_session=False)
        # API and operator-issued API credentials are never GC input.
        expired_api = self.account("create-token", "alice")
        expired_api_id = expired_api["token_id"]
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()-interval '8 days' WHERE id='{expired_api_id}'")
        operator = self.account("create-token", "alice")
        operator_id = operator["token_id"]
        self.sql(f"UPDATE tokens SET expires_at=clock_timestamp()-interval '8 days' WHERE id='{operator_id}'")
        self.sql(f"INSERT INTO cluster_operator_tokens(token_id,granted_by) VALUES('{operator_id}','gc-drill')")
        # A synthetic expired *browser* token retained only by the
        # cluster_operator_tokens foreign-key probe: the API token above is
        # excluded by kind alone and cannot prove that probe is in the SQL.
        cluster_browser = self.seed_browser_token()
        self.sql(
            "INSERT INTO cluster_operator_tokens(token_id,granted_by) VALUES("
            f"'{cluster_browser}','gc-drill')"
        )

        self.seed_bulk_expired(1000)
        seeded = self.counts()
        assert seeded["expired_sessions"] >= 1001, seeded
        observed = []
        self.wait_for(
            lambda: self.counts()["expired_sessions"] == 0,
            "expired session rows to drain",
            observe=lambda _: observed.append(self.counts()["expired_sessions"]),
        )
        # More than one 128-row batch must have been observed as an intermediate
        # non-empty state, proving the fixed batch never deletes the whole set at once.
        partial = [value for value in observed if 0 < value < seeded["expired_sessions"]]
        assert len(partial) >= 3, observed[:20]
        assert max(seeded["expired_sessions"] - value for value in observed) >= 1

        self.wait_for(
            lambda: self.counts()["expired_browser_tokens"] == 2,
            "unreferenced expired browser tokens to drain",
        )
        final = self.counts()
        # active + logout + five retained recent rows stay; natural expiry and the
        # 1000 seeded rows are gone.
        assert final["sessions"] == 7, final
        # seven retained sessions + the git_operations and
        # cluster_operator_tokens durable-reference child tokens
        assert final["browser_tokens"] == 9, final
        assert final["api_tokens"] == 5, final
        assert self.request("/web/repos", headers=active_headers)[0] == 200
        status, _, _ = self.request("/api/repos", headers={"Authorization": "Bearer " + self.alice["token"]})
        assert status == 200, status
        assert self.request("/web/repos", headers=logout_headers)[0] == 401
        # The retained-but-expired rows are still rows, not silently resurrected.
        assert self.sql(
            "SELECT count(*) FROM web_sessions WHERE expires_at < clock_timestamp() "
            "AND expires_at > clock_timestamp() - interval '7 days'"
        ) == "5"
        assert self.sql(f"SELECT count(*) FROM web_sessions WHERE token_id='{referenced}'") == "0"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{referenced}'") == "1"
        assert self.sql(f"SELECT count(*) FROM git_operations WHERE token_id='{referenced}'") == "1"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{orphan}'") == "0"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{natural_token}'") == "0"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{expired_api_id}' AND kind='api'") == "1"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{operator_id}' AND kind='api'") == "1"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{cluster_browser}'") == "1"
        assert self.sql(f"SELECT count(*) FROM web_sessions WHERE token_id='{cluster_browser}'") == "0"
        assert self.sql(
            f"SELECT count(*) FROM cluster_operator_tokens WHERE token_id='{cluster_browser}'"
        ) == "1"
        return {
            "seeded_expired_sessions": seeded["expired_sessions"],
            "batch_limit": BATCH_LIMIT,
            "observed_intermediate_batches": len(partial),
            "retained_unsafe_roots": ["git_operations", "cluster_operator_tokens"],
            "default_retention": DEFAULT_RETENTION,
        }

    def durable_reference_prefix_does_not_stall_the_token_cursor(self):
        # Runs against the server still running from the first case, so the
        # seven-day retention window is untouched here.
        self.expect("/health/ready", 200)
        user = self.alice["user_id"]
        batch_local = BATCH_LIMIT
        prefix = 140  # strictly more than one 128-candidate window
        # The oldest expired browser tokens in the (expires_at, id) order are
        # all pinned by a durable cluster_operator_tokens row, so a whole GC
        # candidate window is undeletable. They carry no web_sessions row, so
        # only the foreign-key probe can retain them.
        self.sql(
            "WITH seeded AS (SELECT i FROM generate_series(1," + str(prefix) + ") i), "
            "inserted AS (INSERT INTO tokens(id,user_id,digest,read_only,revoked,expires_at,kind) "
            f"SELECT gen_random_uuid(),'{user}',"
            "decode(md5('prefix-token-'||i),'hex')||decode(md5('prefix-nonce-'||i),'hex'),"
            "false,false,clock_timestamp()-interval '30 days','browser' FROM seeded RETURNING id) "
            "INSERT INTO cluster_operator_tokens(token_id,granted_by) "
            "SELECT id,'gc-prefix' FROM inserted"
        )
        # Ordinary expired children with a *later* expiry, i.e. strictly behind
        # the whole retained prefix in the GC order.
        ordinary = [self.seed_browser_token(age="8 days", with_session=False) for _ in range(3)]
        ordinary_ids = ",".join("'" + token_id + "'" for token_id in ordinary)
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id IN ({ordinary_ids})") == "3"
        assert self.sql(
            "SELECT count(*) FROM tokens t JOIN cluster_operator_tokens k ON k.token_id=t.id "
            "WHERE k.granted_by='gc-prefix' AND t.kind='browser' "
            "AND t.expires_at < clock_timestamp() - interval '" + DEFAULT_RETENTION + "'"
        ) == str(prefix)
        self.wait_for(
            lambda: self.sql(f"SELECT count(*) FROM tokens WHERE id IN ({ordinary_ids})") == "0",
            "the token cursor to pass a fully referenced candidate window and purge later "
            "ordinary expired children",
        )
        # Every retained token and its durable root survived the pass.
        retained = int(
            self.sql(
                "SELECT count(*) FROM tokens t JOIN cluster_operator_tokens k ON k.token_id=t.id "
                "WHERE k.granted_by='gc-prefix' AND t.kind='browser'"
            )
        )
        assert retained == prefix, retained
        assert self.sql("SELECT count(*) FROM cluster_operator_tokens WHERE granted_by='gc-prefix'") == str(prefix)
        assert self.sql(
            "SELECT count(*) FROM web_sessions s JOIN cluster_operator_tokens k ON k.token_id=s.token_id "
            "WHERE k.granted_by='gc-prefix'"
        ) == "0"
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{self.alice['token_id']}' AND kind='api'") == "1"
        status, _, _ = self.request("/api/repos", headers={"Authorization": "Bearer " + self.alice["token"]})
        assert status == 200, status
        return {
            "referenced_prefix_tokens": prefix,
            "batch_limit": batch_local,
            "windows_needed_for_prefix": (prefix + batch_local - 1) // batch_local,
            "ordinary_later_expiry_children_deleted": len(ordinary),
            "durable_root": "cluster_operator_tokens",
            "cursor_advanced_past_fully_referenced_window": True,
            "explain_evidence": "none; no scanned-row count or plan is claimed",
        }

    def two_workers_restart_and_concurrent_auth(self):
        held_cookies, _, _ = self.sign_in()
        held_headers = self.cookie_headers(held_cookies)
        assert self.request("/web/repos", headers=held_headers)[0] == 200
        self.start_worker()
        try:
            baseline = self.counts()
            self.seed_bulk_expired(300)
            errors = []
            lock = threading.Lock()

            def exercise():
                for _ in range(3):
                    try:
                        cookies, _, _ = self.sign_in()
                        headers = self.cookie_headers(cookies)
                        status, _, _ = self.request("/web/repos", headers=headers)
                        assert status == 200, status
                        status, _, _ = self.request(
                            "/web/logout", "POST", headers={**headers, "Origin": self.base}
                        )
                        assert status == 303, status
                        assert self.request("/web/repos", headers=headers)[0] == 401
                    except Exception as error:  # noqa: BLE001 - reported, not swallowed
                        with lock:
                            errors.append(repr(error))

            threads = [threading.Thread(target=exercise) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            assert not errors, errors
            assert self.request("/web/repos", headers=held_headers)[0] == 200
            self.wait_for(
                lambda: self.counts()["expired_sessions"] <= baseline["expired_sessions"],
                "both workers to drain the seeded batch",
            )
            after = self.counts()
            assert after["expired_sessions"] <= baseline["expired_sessions"], (baseline, after)
            assert after["expired_browser_tokens"] <= baseline["expired_browser_tokens"], (baseline, after)
            assert self.request("/web/repos", headers=held_headers)[0] == 200
            assert self.sql("SELECT count(*) FROM tokens WHERE id='" + self.alice["token_id"] + "'") == "1"
        finally:
            self.stop_worker()

        # Restart with zero retention: what was retained by the seven-day window
        # becomes eligible only after the new bounded cycle starts.
        self.seed_bulk_expired(10, age="1 minute")
        retained_before = int(
            self.sql("SELECT count(*) FROM web_sessions WHERE expires_at < clock_timestamp()")
        )
        assert retained_before >= 15, retained_before
        self.stop()
        self.env["ROOTYARD_SESSION_GC_RETENTION_SECONDS"] = "0"
        self.start()
        self.wait_for(
            lambda: self.sql("SELECT count(*) FROM web_sessions WHERE expires_at < clock_timestamp()") == "0",
            "restarted zero-retention cycle to drain expired rows",
        )
        assert self.sql("SELECT count(*) FROM tokens WHERE id='" + self.alice["token_id"] + "'") == "1"
        status, _, _ = self.request("/api/repos", headers={"Authorization": "Bearer " + self.alice["token"]})
        assert status == 200, status
        return {"second_worker": "rootyard worker", "concurrent_logins": 12, "restart_retention_seconds": 0}

    def gc_indexes_and_schema_contract(self):
        version = self.sql("SELECT max(version) FROM schema_migrations")
        assert version == "133", version
        expected = {
            "git_operations_token_actor_idx",
            "git_ref_admissions_token_actor_idx",
            "ci_checkout_jobs_issuer_token_idx",
            "ci_checkout_delegations_issuer_token_idx",
            "web_sessions_expiry_token_idx",
            "tokens_browser_expiry_idx",
        }
        rows = self.sql(
            "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() "
            "AND indexname IN (" + ",".join(f"'{name}'" for name in sorted(expected)) + ") ORDER BY indexname"
        )
        assert set(rows.splitlines()) == expected, rows
        partial = self.sql(
            "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() "
            "AND indexname='tokens_browser_expiry_idx'"
        )
        assert "WHERE (kind = 'browser'::text)" in partial, partial
        covering = self.sql(
            "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() "
            "AND indexname='web_sessions_expiry_token_idx'"
        )
        assert "(expires_at, token_id)" in covering and "WHERE" not in covering, covering
        assert self.sql("SELECT current_setting('server_version_num')::int >= 170000") == "t"
        return {"schema_version": int(version), "gc_indexes": sorted(expected), "partial_browser_index": True}

    def legacy_schema132_restore_gate(self):
        empty = self.root / "empty-backup"
        empty.mkdir(exist_ok=True)
        result = self.run(
            [
                self.args.binary,
                "restore",
                str(empty),
                "--isolated",
                "--trust-backup",
                "--allow-legacy-schema132",
            ],
            check=False,
        )
        # The option is parsed as a legacy schema132 opt-in, not rejected as usage.
        assert result.returncode != 0
        assert b"usage:" not in result.stderr, result.stderr[-400:]
        assert b"invalid manifest" in result.stderr or b"restore failed" in result.stderr, result.stderr[-400:]
        ambiguous = self.run(
            [
                self.args.binary,
                "restore",
                str(empty),
                "--isolated",
                "--trust-backup",
                "--allow-legacy-schema131",
                "--allow-legacy-schema132",
            ],
            check=False,
        )
        assert ambiguous.returncode != 0
        assert b"usage:" in ambiguous.stderr, ambiguous.stderr[-400:]
        assert not (self.root / ".data.rootyard-restoring").exists(), "failed restore left a guard"
        return {
            "schema132_opt_in_parsed": True,
            "ambiguous_legacy_options_rejected": True,
            "actual_format8_archive_roundtrip": "not run (needs a schema132/format8 producer binary)",
        }

    def cleanup(self):
        self.stop_worker()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = SessionGcHarness(args)
    passed = False
    failure_traceback = None
    try:
        harness.case("expired_history_purged_in_bounded_batches", harness.expired_history_is_purged_in_bounded_batches)
        harness.case("durable_reference_prefix_does_not_stall_token_cursor", harness.durable_reference_prefix_does_not_stall_the_token_cursor)
        harness.case("gc_indexes_and_schema_contract", harness.gc_indexes_and_schema_contract)
        harness.case("two_workers_restart_and_concurrent_auth", harness.two_workers_restart_and_concurrent_auth)
        harness.case("legacy_schema132_restore_gate", harness.legacy_schema132_restore_gate)
        passed = True
    except Exception as exc:
        failure_traceback = harness.redact(traceback.format_exc(limit=12))[-4000:]
        print(harness.redact(exc), file=sys.stderr)
        print(failure_traceback, file=sys.stderr)
    finally:
        harness.cleanup()
        report = {
            "passed": passed,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "failure_traceback": failure_traceback,
            "limitations": harness.limits,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
