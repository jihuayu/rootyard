#!/usr/bin/env python3
"""Native metrics coverage for the bounded browser-session GC failure path.

The real `rootyard` binary runs this module's GC loop with a one-second cadence
and the private metrics listener. Rows are seeded with SQL (digests only). The
controlled token-pass failure is a temporary PostgreSQL trigger that raises
SQLSTATE 23503 only for `browser` rows, so the session pass really commits while
the token pass really fails. The final snapshot failure renames this harness's
own `event_deliveries` table and restores it in `finally`.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from session_gc import SessionGcHarness

GC_COUNTERS = (
    "rootyard_session_gc_cycles_total",
    "rootyard_session_gc_session_rows_deleted_total",
    "rootyard_session_gc_tokens_deleted_total",
    "rootyard_session_gc_failures_total",
)
DATABASE_GAUGES = (
    "rootyard_repositories",
    "rootyard_operations_unresolved",
    "rootyard_event_deliveries",
    "rootyard_event_delivery_oldest_age_seconds",
    "rootyard_provisioning_backlog",
    "rootyard_provisioning_due",
    "rootyard_provisioning_oldest_age_seconds",
    "rootyard_browser_web_sessions",
    "rootyard_browser_tokens",
    "rootyard_expired_browser_session_oldest_age_seconds",
    "rootyard_expired_browser_token_oldest_age_seconds",
)


class SessionGcMetricsHarness(SessionGcHarness):
    def __init__(self, args):
        super().__init__(args)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.metrics_port = s.getsockname()[1]
        self.env["ROOTYARD_METRICS_BIND"] = "127.0.0.1:" + str(self.metrics_port)
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        self.limits.append(
            "The token-pass failure is a temporary local trigger raising SQLSTATE 23503 for browser rows, "
            "and the snapshot failure is this harness's own table rename; neither is a PostgreSQL outage."
        )

    def scrape(self):
        url = "http://127.0.0.1:" + str(self.metrics_port) + "/metrics"
        try:
            response = urllib.request.urlopen(url, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode(), {k.lower(): v for k, v in response.headers.items()}

    @staticmethod
    def samples(text):
        return {
            line.split(" ", 1)[0]: line.split(" ", 1)[1]
            for line in text.splitlines()
            if line and not line.startswith("#")
        }

    @staticmethod
    def series_present(samples, name):
        return name in samples or any(metric.startswith(name + "{") for metric in samples)

    def metrics(self):
        status, text, headers = self.scrape()
        assert status == 200, (status, text[:400])
        assert headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
        assert headers["cache-control"] == "no-store"
        values = dict(line.split(" ", 1) for line in text.splitlines() if line and not line.startswith("#"))
        # The coordinator adds one further process counter on the merged branch;
        # this drill asserts the fixed browser series rather than an exact total.
        assert len(values) >= 30, values
        assert values["rootyard_postgres_up"] == "1"
        return values

    def gc_counters(self):
        values = self.metrics()
        return {name: int(values[name]) for name in GC_COUNTERS}

    # ---- cases -------------------------------------------------------------------
    def setup_metrics(self):
        self.setup()
        self.api()
        values = self.metrics()
        assert values["rootyard_browser_web_sessions"] == "0", values
        assert values["rootyard_browser_tokens"] == "0", values
        assert self.http("/metrics")[0] != 200, "Metrics leaked onto the application listener"
        # The loop is enabled from process start, so setup may already have
        # completed empty cycles. Per-process counters are baselined, never
        # assumed zero or compared across a restart.
        counters = self.gc_counters()
        return {"metrics_series": len(values), "gc_counters_baseline": counters, "gc_interval_seconds": 1}

    def failed_token_pass_counts_committed_sessions(self):
        self.expect("/health/ready", 200)
        baseline = self.gc_counters()
        self.sql(
            "CREATE FUNCTION metrics_block_browser_token_gc() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF OLD.kind = 'browser' THEN "
            "RAISE EXCEPTION 'controlled metrics token GC fault' USING ERRCODE = '23503'; "
            "END IF; RETURN OLD; END $$"
        )
        self.sql(
            "CREATE TRIGGER metrics_block_browser_token_gc BEFORE DELETE ON tokens "
            "FOR EACH ROW EXECUTE FUNCTION metrics_block_browser_token_gc()"
        )
        try:
            blocked = self.seed_browser_token(age="8 days")
            assert self.sql(f"SELECT count(*) FROM web_sessions WHERE token_id='{blocked}'") == "1"
            assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{blocked}'") == "1"

            def failed_attempt():
                snap = self.gc_counters()
                sessions = snap["rootyard_session_gc_session_rows_deleted_total"] - baseline[
                    "rootyard_session_gc_session_rows_deleted_total"]
                failures = snap["rootyard_session_gc_failures_total"] - baseline[
                    "rootyard_session_gc_failures_total"]
                if sessions == 1 and failures >= 1:
                    return snap
                return None

            failed = self.wait_for(
                failed_attempt,
                "a failed token pass after the session pass committed",
                timeout=30,
            )
            assert failed["rootyard_session_gc_tokens_deleted_total"] == baseline[
                "rootyard_session_gc_tokens_deleted_total"], (baseline, failed)
            assert self.sql(f"SELECT count(*) FROM web_sessions WHERE token_id='{blocked}'") == "0"
            assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{blocked}'") == "1"
        finally:
            self.sql("DROP TRIGGER IF EXISTS metrics_block_browser_token_gc ON tokens")
            self.sql("DROP FUNCTION IF EXISTS metrics_block_browser_token_gc()")

        def token_pass_committed():
            snap = self.gc_counters()
            if snap["rootyard_session_gc_tokens_deleted_total"] > failed[
                "rootyard_session_gc_tokens_deleted_total"]:
                return snap
            return None

        committed = self.wait_for(
            token_pass_committed,
            "the token pass to commit after the controlled trigger was dropped",
            timeout=30,
        )
        assert committed["rootyard_session_gc_cycles_total"] > failed[
            "rootyard_session_gc_cycles_total"], (failed, committed)
        assert self.sql(f"SELECT count(*) FROM tokens WHERE id='{blocked}'") == "0"
        assert self.sql(f"SELECT count(*) FROM web_sessions WHERE token_id='{blocked}'") == "0"
        status, _, _ = self.request(
            "/api/repos", headers={"Authorization": "Bearer " + self.alice["token"]}
        )
        assert status == 200, status
        return {
            "baseline_counters": baseline,
            "failed_cycle_counters": failed,
            "recovered_counters": committed,
            "committed_session_rows": 1,
            "token_deleted_after_recovery": 1,
            "sql_fault": "BEFORE DELETE trigger raised SQLSTATE 23503 for browser rows",
        }

    def snapshot_failure_retains_process_gc_counters(self):
        self.expect("/health/ready", 200)
        healthy = self.metrics()
        for name in DATABASE_GAUGES:
            assert self.series_present(healthy, name), (name, sorted(healthy))
        before = self.gc_counters()
        self.sql("ALTER TABLE event_deliveries RENAME TO metrics_hidden_event_deliveries")
        try:
            status, text, headers = self.scrape()
            assert status == 503, (status, text[:400])
            assert headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
            samples = self.samples(text)
            assert samples["rootyard_postgres_up"] == "0"
            for name in DATABASE_GAUGES:
                assert not self.series_present(samples, name), name
            for name in GC_COUNTERS:
                assert name in samples, name
                # Same process, so these saturated counters cannot decrease.
                assert int(samples[name]) >= before[name], (name, before, samples[name])
            assert "rootyard_db_pool_max_size" in samples
        finally:
            self.sql("ALTER TABLE metrics_hidden_event_deliveries RENAME TO event_deliveries")
        recovered = self.metrics()
        for name in DATABASE_GAUGES:
            assert self.series_present(recovered, name), (name, sorted(recovered))
        return {
            "forced_snapshot_failure": "event_deliveries renamed",
            "gc_counters_retained": list(GC_COUNTERS),
            "database_gauges_omitted": list(DATABASE_GAUGES),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = SessionGcMetricsHarness(args)
    passed = False
    failure_traceback = None
    try:
        harness.case("session_gc_metrics_setup", harness.setup_metrics)
        harness.case(
            "failed_token_pass_keeps_committed_session_deletion",
            harness.failed_token_pass_counts_committed_sessions,
        )
        harness.case(
            "snapshot_failure_retains_process_gc_counters",
            harness.snapshot_failure_retains_process_gc_counters,
        )
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
