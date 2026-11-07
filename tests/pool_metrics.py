#!/usr/bin/env python3
"""Actual-service PostgreSQL pool gauge saturation and recovery test."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request

from e2e import Harness
from forge import ForgeHarness

POOL_NAMES = (
    "rootyard_db_pool_max_size",
    "rootyard_db_pool_size",
    "rootyard_db_pool_available",
    "rootyard_db_pool_busy",
    "rootyard_db_pool_waiting",
)


class PoolHarness(Harness):
    # Reuse ForgeHarness's real psql transaction helper; this test does not model
    # PostgreSQL locking or pool behavior in Python.
    held_transaction = ForgeHarness.held_transaction

    def __init__(self, args):
        super().__init__(args)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.metrics_port = s.getsockname()[1]
        self.env["ROOTYARD_METRICS_BIND"] = "127.0.0.1:" + str(self.metrics_port)
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        self.evidence = {}
        self.saturated = None
        self.recovered = None

    def scrape(self):
        url = "http://127.0.0.1:" + str(self.metrics_port) + "/metrics"
        try:
            response = urllib.request.urlopen(url, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode(), {k.lower(): v for k, v in response.headers.items()}

    def metrics(self):
        status, text, headers = self.scrape()
        assert headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8", headers
        assert headers["cache-control"] == "no-store", headers
        values = dict(line.split(" ", 1) for line in text.splitlines() if not line.startswith("#"))
        return status, text, values

    @staticmethod
    def selected(values):
        return {name: values[name] for name in POOL_NAMES + ("rootyard_postgres_up",) if name in values}

    def setup(self):
        super().setup()
        status, body, _ = self.http("/api/repos", token=self.alice, method="POST", body={"name": "pool"})
        assert status == 201, f"repository creation returned {status}"
        self.repo = json.loads(body)
        self.issues_path = "/api/repos/alice/pool/issues"
        assert self.http(self.issues_path, token=self.alice)[0] == 200
        status, _, values = self.metrics()
        assert status == 200, f"baseline metrics scrape returned {status}"
        assert set(POOL_NAMES) <= set(values), values
        assert int(values["rootyard_db_pool_busy"]) == (
            int(values["rootyard_db_pool_size"]) - int(values["rootyard_db_pool_available"])
        )
        self.evidence["baseline"] = dict(http_status=status, raw_values=self.selected(values))
        return dict(repository="ready", metrics_listener="owned loopback port")

    def wait_for_lock_waiters(self, target):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            waiting = int(self.sql(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE application_name='rootyard' AND wait_event_type='Lock'"
            ))
            if waiting >= target:
                return waiting
            time.sleep(.02)
        raise AssertionError(f"only {waiting} database lock waiters reached; {target} required")

    def saturation(self):
        futures = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)
        try:
            with self.held_transaction(
                f"SELECT id FROM repositories WHERE id='{self.repo['id']}' FOR UPDATE"
            ):
                futures = [
                    executor.submit(self.http, self.issues_path, token=self.alice)
                    for _ in range(32)
                ]
                observed_waiters = self.wait_for_lock_waiters(16)
                time.sleep(.2)
                status, text, values = self.metrics()
                maximum = int(values["rootyard_db_pool_max_size"])
                size = int(values["rootyard_db_pool_size"])
                available = int(values["rootyard_db_pool_available"])
                busy = int(values["rootyard_db_pool_busy"])
                waiting = int(values["rootyard_db_pool_waiting"])
                assert maximum > 0
                assert size == maximum, (size, maximum)
                assert available == 0, values
                assert busy == size - available
                assert busy > 0, values
                assert waiting > 0, values
                assert busy + waiting >= 32, values
                assert int(values["rootyard_postgres_up"]) == (1 if status == 200 else 0)
                if status == 503:
                    # The saturated scrape may fail closed because every pooled
                    # session is blocked, but it must still export local gauges.
                    assert "rootyard_repositories" not in text
                self.saturated = dict(
                    http_status=status,
                    database_lock_waiters=observed_waiters,
                    raw_values=self.selected(values),
                )
                self.evidence["saturated"] = self.saturated
        finally:
            executor.shutdown(wait=True)
        results = [future.result() for future in futures]
        statuses = [result[0] for result in results]
        assert all(code in (200, 503) for code in statuses), statuses
        assert 503 in statuses, statuses
        self.evidence["api_responses"] = {
            "200": statuses.count(200),
            "503": statuses.count(503),
            "other": sorted({code for code in statuses if code not in (200, 503)}),
        }
        return dict(**self.saturated, api_responses=self.evidence["api_responses"])

    def capacity_returns(self):
        deadline = time.monotonic() + 20
        last = {}
        while time.monotonic() < deadline:
            status, _, values = self.metrics()
            last = values
            if status == 200:
                maximum = int(values["rootyard_db_pool_max_size"])
                size = int(values["rootyard_db_pool_size"])
                available = int(values["rootyard_db_pool_available"])
                busy = int(values["rootyard_db_pool_busy"])
                waiting = int(values["rootyard_db_pool_waiting"])
                if busy == 0 and waiting == 0 and available == maximum == size:
                    self.recovered = dict(http_status=status, raw_values=self.selected(values))
                    self.evidence["recovered"] = self.recovered
                    return dict(**self.recovered, api_responses=self.evidence["api_responses"])
            time.sleep(.1)
        raise AssertionError(self.redact(f"pool capacity did not return: {last}"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = PoolHarness(args)
    success = False
    try:
        for name, test in [
            ("fresh_schema_actual_service", harness.setup),
            ("actual_pool_saturation_gauges", harness.saturation),
            ("capacity_returns_after_unlock", harness.capacity_returns),
        ]:
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
        report = dict(
            passed=success,
            cases=harness.results,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            actual_pool_metrics=harness.evidence,
            limitations=[
                "Loopback actual-service test with a synthetic held row lock; it is not a PostgreSQL outage, production load or monitoring-system integration test.",
                "A saturated-pool scrape may itself return 503 because all 16 pooled sessions are blocked; process-local pool gauges are still exported while database-derived gauges are omitted.",
                "Run only against a binary built from this implementation; an older binary without the pool gauges cannot pass.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
