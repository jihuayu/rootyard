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

from e2e import Harness


class MetricsHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.metrics_port = s.getsockname()[1]
        self.env["ROOTYARD_METRICS_BIND"] = "127.0.0.1:" + str(self.metrics_port)
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"

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
        assert len(values) == 23, values
        for name in ("max_size", "size", "available", "busy", "waiting"):
            assert "rootyard_db_pool_" + name in values
        assert "rootyard_error_log_dropped_total" in values
        assert values["rootyard_postgres_up"] == "1"
        assert self.http("/metrics")[0] != 200, "Metrics leaked onto application listener"
        for name, value in values.items():
            assert re.fullmatch(r"rootyard_[a-z_]+(?:\{(?:state|outcome|direction)=\"(?:ready|recovering|provisioning|pending|leased|success|failure|received|sent)\"\})?", name), name
            assert float(value) >= 0
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

    def database_failure(self):
        self.sql("ALTER TABLE event_deliveries RENAME TO metrics_hidden_deliveries")
        try:
            status, text, _ = self.scrape()
            assert status == 503
            assert "rootyard_postgres_up 0\n" in text
            for name in ("repositories", "operations_unresolved", "event_deliveries", "event_delivery_oldest", "provisioning"):
                assert "rootyard_" + name not in text
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
                           ("authoritative_aggregates", harness.aggregates), ("database_failure_is_503", harness.database_failure),
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
                      limitations=["Synthetic SQL aggregates and a missing-table fault do not simulate a PostgreSQL outage or production load."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
