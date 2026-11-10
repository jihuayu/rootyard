#!/usr/bin/env python3
"""Private metrics integration tests using an isolated PostgreSQL schema."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import urllib.error
import urllib.request
import uuid

from web_sessions import BrowserHarness

# Fixed enumerations mirrored from src/metrics_workers.rs. Database strings are
# never interpolated into a label: only these constant combinations are legal.
JOB_KINDS = [
    ("gitfs", "gitfs_stage_cleanup"),
    ("gitfs", "gitfs_repack"),
    ("gitfs", "gitfs_cache_hydrate"),
    ("gitfs", "gitfs_cache_evict"),
    ("pando", "pando_repack"),
    ("pando", "pando_cache_hydrate"),
    ("pando", "pando_cache_evict"),
]
JOB_STATES = ["queued", "due_queued", "retry_delayed", "running", "expired_running_lease", "failed"]
SCAN_STATES = ["missing_scan", "due_scan", "stale_generation"]
BACKENDS = ["gitfs", "pando"]


def fixed_labels():
    labels = {
        'state="provisioning"',
        'state="ready"',
        'state="recovering"',
        'state="pending"',
        'state="leased"',
        'outcome="success"',
        'outcome="failure"',
        'direction="received"',
        'direction="sent"',
    }
    for backend, kind in JOB_KINDS:
        for state in JOB_STATES:
            labels.add(f'backend="{backend}",kind="{kind}",state="{state}"')
        labels.add(f'backend="{backend}",kind="{kind}"')
    for backend in BACKENDS:
        for state in SCAN_STATES:
            labels.add(f'backend="{backend}",state="{state}"')
        labels.add(f'backend="{backend}"')
    return labels


class MetricsHarness(BrowserHarness):
    def __init__(self, args):
        super().__init__(args)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.metrics_port = s.getsockname()[1]
        self.env["ROOTYARD_METRICS_BIND"] = "127.0.0.1:" + str(self.metrics_port)
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        # Deterministic fixture: stored browser rows are seeded with SQL and must
        # still be there when the gauges are compared, so the loop stays off here.
        self.env["ROOTYARD_SESSION_GC"] = "false"

    def scrape(self):
        url = "http://127.0.0.1:" + str(self.metrics_port) + "/metrics"
        try:
            response = urllib.request.urlopen(url, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode(), {k.lower(): v for k, v in response.headers.items()}

    def verify(self):
        status, text, headers = self.scrape()
        assert status == 200
        assert headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
        assert headers["cache-control"] == "no-store"
        values = dict(line.split(" ", 1) for line in text.splitlines() if not line.startswith("#"))
        assert len(values) == 93, values
        for name in ("max_size", "size", "available", "busy", "waiting"):
            assert "rootyard_db_pool_" + name in values
        assert "rootyard_error_log_dropped_total" in values
        assert values["rootyard_postgres_up"] == "1"
        # GC counters and browser-session gauges are fixed, label-free series.
        for name in ("rootyard_session_gc_cycles_total", "rootyard_session_gc_session_rows_deleted_total",
                     "rootyard_session_gc_tokens_deleted_total", "rootyard_session_gc_failures_total",
                     "rootyard_browser_web_sessions", "rootyard_browser_tokens",
                     "rootyard_expired_browser_session_oldest_age_seconds",
                     "rootyard_expired_browser_token_oldest_age_seconds"):
            assert name in values, (name, sorted(values))
            assert not any(metric.startswith(name + "{") for metric in values), name
            assert float(values[name]) >= 0, (name, values)
        # Every fixed worker/maintenance series is exported even before any
        # workspace, job or repository scan exists, so dashboards never drift.
        for backend, kind in JOB_KINDS:
            for state in JOB_STATES:
                series = f'rootyard_storage_maintenance_jobs{{backend="{backend}",kind="{kind}",state="{state}"}}'
                assert series in values, (series, sorted(values))
            assert f'rootyard_storage_maintenance_oldest_queued_age_seconds{{backend="{backend}",kind="{kind}"}}' in values
        for backend in BACKENDS:
            for state in SCAN_STATES:
                assert f'rootyard_storage_maintenance_repos{{backend="{backend}",state="{state}"}}' in values
            assert f'rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{{backend="{backend}"}}' in values
        for name in ("rootyard_workspace_capture_oldest_age_seconds", "rootyard_workspace_capture_never_sampled",
                     "rootyard_workspace_lease_expired"):
            assert name in values, (name, sorted(values))
            assert not any(metric.startswith(name + "{") for metric in values), name
            assert float(values[name]) >= 0, (name, values)
        assert self.http("/metrics")[0] != 200, "Metrics leaked onto application listener"
        allowed = fixed_labels()
        for name, value in values.items():
            assert float(value) >= 0, (name, value)
            if "{" in name:
                base, label = name.split("{", 1)
                assert label.endswith("}"), name
                assert re.fullmatch(r"rootyard_[a-z_]+", base), name
                assert label[:-1] in allowed, name
            else:
                assert re.fullmatch(r"rootyard_[a-z_]+", name), name
        for secret in self.secrets + [self.alice["username"], str(self.root), self.db]:
            assert secret not in text
        return values

    def aggregates(self):
        ids = [str(uuid.uuid4()) for _ in range(3)]
        actor = self.sql("SELECT id FROM users WHERE username='alice'")
        for repo, state in zip(ids, ("ready", "provisioning", "recovering")):
            self.sql("INSERT INTO repositories(id,owner_id,name,state,next_retry_at,created_at) VALUES "
                     f"('{repo}','{actor}','private-{state}','{state}',now()+interval '1 day',now()-interval '2 minutes')")
        operation = str(uuid.uuid4())
        token = self.alice["token_id"]
        self.sql("INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome) "
                 f"VALUES ('{operation}','{ids[0]}','{actor}','{token}','alice',1,1,'{{}}','unknown')")
        event = "1" * 64
        self.sql("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid,created_at) "
                 f"VALUES ('{event}','{operation}','{ids[0]}',1,1,1,'refs/heads/private','{'0'*40}','{'1'*40}',now()-interval '1 minute')")
        self.sql(f"INSERT INTO event_deliveries(event_id,consumer) VALUES ('{event}','audit-log')")
        self.sql("INSERT INTO event_deliveries(event_id,consumer,state,lease_owner,lease_until) "
                 f"VALUES ('{event}','ref-index','leased','{uuid.uuid4()}',now()-interval '1 minute')")
        values = self.verify()
        for state in ("ready", "provisioning", "recovering"):
            assert values[f'rootyard_repositories{{state="{state}"}}'] == "1"
        assert values['rootyard_event_deliveries{state="pending"}'] == "1"
        assert values['rootyard_event_deliveries{state="leased"}'] == "1"
        assert values["rootyard_operations_unresolved"] == "1"
        assert values["rootyard_provisioning_backlog"] == "1"
        assert values["rootyard_provisioning_due"] == "0"
        assert float(values["rootyard_event_delivery_oldest_age_seconds"]) >= 60
        assert float(values["rootyard_provisioning_oldest_age_seconds"]) >= 120
        # Explicit synthetic resolution removes outstanding work without editing
        # historical unknown evidence or inventing successful Git receipts.
        resolution = str(uuid.uuid4())
        self.sql("INSERT INTO recovery_resolutions(id,repository_id,old_generation,new_generation,incident_revision,inspected_fingerprint,volume_id,snapshot,reason) "
                 f"VALUES ('{resolution}','{ids[0]}',1,2,0,'{'2'*64}','{uuid.uuid4()}','{{}}','synthetic metrics fixture')")
        self.sql("INSERT INTO operation_resolutions(operation_id,repository_id,resolution_id,operation_digest) "
                 f"VALUES ('{operation}','{ids[0]}','{resolution}','{'3'*64}')")
        assert self.verify()["rootyard_operations_unresolved"] == "0"
        assert self.sql(f"SELECT outcome FROM git_operations WHERE id='{operation}'") == "unknown"

    def seed_browser_row(self, expires, kind="browser", revoked=False, with_session=True):
        # Only digest columns are written: no plaintext secret is invented here.
        token_id = str(uuid.uuid4())
        digest = hashlib.sha256(("metrics-fixture-" + token_id).encode()).hexdigest()
        flag = "true" if revoked else "false"
        self.sql(
            "INSERT INTO tokens(id,user_id,digest,read_only,revoked,expires_at,kind) VALUES("
            f"'{token_id}','{self.alice['user_id']}',decode('{digest}','hex'),false,{flag},{expires},'{kind}')"
        )
        if with_session:
            self.sql(
                "INSERT INTO web_sessions(token_id,csrf_digest,expires_at,revoked) VALUES("
                f"'{token_id}',decode('{digest}','hex'),{expires},{flag})"
            )
        return token_id

    def browser_session_metrics(self):
        values = self.verify()
        for name in ("rootyard_browser_web_sessions", "rootyard_browser_tokens",
                     "rootyard_expired_browser_session_oldest_age_seconds",
                     "rootyard_expired_browser_token_oldest_age_seconds"):
            assert values[name] == "0", (name, values)

        # Real HTTP sign-in and sign-out through the service. Sign-out revokes the
        # row instead of deleting it, so the counts stay and no expired age appears.
        cookies, _, _ = self.sign_in()
        headers = {"Cookie": self.cookie_header(cookies)}
        assert self.request("/web/repos", headers=headers)[0] == 200
        assert self.request("/web/logout", "POST", headers={**headers, "Origin": self.base})[0] == 303
        assert self.request("/web/repos", headers=headers)[0] == 401
        revoked = self.verify()
        assert revoked["rootyard_browser_web_sessions"] == "1", revoked
        assert revoked["rootyard_browser_tokens"] == "1", revoked
        assert revoked["rootyard_expired_browser_session_oldest_age_seconds"] == "0", revoked
        assert revoked["rootyard_expired_browser_token_oldest_age_seconds"] == "0", revoked

        # Controlled history: two expired sessions, one active session, one
        # revoked-but-expired session and one expired API token.
        self.seed_browser_row("clock_timestamp() - interval '8 days'")
        self.seed_browser_row("clock_timestamp() - interval '2 hours'")
        self.seed_browser_row("clock_timestamp() + interval '1 hour'")
        self.seed_browser_row("clock_timestamp() - interval '3 days'", revoked=True)
        self.seed_browser_row("clock_timestamp() - interval '30 days'", kind="api", with_session=False)
        values = self.verify()
        assert values["rootyard_browser_web_sessions"] == self.sql(
            "SELECT count(*) FROM web_sessions s JOIN tokens t ON t.id=s.token_id WHERE t.kind='browser'")
        assert values["rootyard_browser_web_sessions"] == "5", values
        assert values["rootyard_browser_tokens"] == self.sql("SELECT count(*) FROM tokens WHERE kind='browser'")
        assert values["rootyard_browser_tokens"] == "5", values
        # The oldest expired row dominates; the active row and the expired API
        # token must move neither gauge.
        for name in ("rootyard_expired_browser_session_oldest_age_seconds",
                     "rootyard_expired_browser_token_oldest_age_seconds"):
            assert 8 * 24 * 3600 <= float(values[name]) < 9 * 24 * 3600, (name, values)
        # A disabled loop neither deletes rows nor fabricates cycles or failures.
        for name in ("rootyard_session_gc_cycles_total", "rootyard_session_gc_session_rows_deleted_total",
                     "rootyard_session_gc_tokens_deleted_total", "rootyard_session_gc_failures_total"):
            assert values[name] == "0", (name, values)
        return {
            "browser_web_sessions": int(values["rootyard_browser_web_sessions"]),
            "browser_tokens": int(values["rootyard_browser_tokens"]),
            "expired_session_oldest_age_seconds": float(values["rootyard_expired_browser_session_oldest_age_seconds"]),
            "expired_token_oldest_age_seconds": float(values["rootyard_expired_browser_token_oldest_age_seconds"]),
            "gc_disabled_counters": "0",
            "deletion_growth_and_failed_cycle_counters": "separate native drill tests/session_gc_metrics.py; not executed by this harness",
        }

    def database_failure(self):
        self.sql("ALTER TABLE event_deliveries RENAME TO metrics_hidden_deliveries")
        try:
            status, text, _ = self.scrape()
            assert status == 503
            assert "rootyard_postgres_up 0\n" in text
            for name in ("repositories", "operations_unresolved", "event_deliveries", "event_delivery_oldest",
                         "provisioning", "browser_web_sessions", "browser_tokens",
                         "expired_browser_session_oldest_age", "expired_browser_token_oldest_age",
                         "workspace_capture", "workspace_lease", "storage_maintenance"):
                assert "rootyard_" + name not in text
            # The process-local GC counters are retained, not reset or hidden.
            for name in ("rootyard_session_gc_cycles_total", "rootyard_session_gc_session_rows_deleted_total",
                         "rootyard_session_gc_tokens_deleted_total", "rootyard_session_gc_failures_total"):
                assert name in text, name
        finally:
            self.sql("ALTER TABLE metrics_hidden_deliveries RENAME TO event_deliveries")
        assert self.scrape()[0] == 200

    def reject_non_loopback(self):
        self.stop()
        self.env["ROOTYARD_METRICS_BIND"] = "0.0.0.0:9108"
        result = self.run([self.args.binary, "serve"], check=False)
        assert result.returncode != 0
        assert b"loopback" in result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = MetricsHarness(args)
    success = False
    try:
        for name, test in [("isolated_metrics_setup", harness.setup), ("fixed_private_format", harness.verify),
                           ("authoritative_aggregates", harness.aggregates),
                           ("browser_session_metrics", harness.browser_session_metrics),
                           ("database_failure_is_503", harness.database_failure),
                           ("non_loopback_rejected", harness.reject_non_loopback)]:
            harness.case(name, test)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            success = False
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=[
                          "Synthetic SQL aggregates and a missing-table fault do not simulate a PostgreSQL outage or production load.",
                          "Browser-session rows beyond the real HTTP login/logout are SQL seeds with GC disabled; "
                          "counter growth after real deletions and counter retention on a failed snapshot are covered by the separate "
                          "native drill tests/session_gc_metrics.py, which this harness does not execute.",
                      ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
