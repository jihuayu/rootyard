#!/usr/bin/env python3
"""Native acceptance for worker backlog, capture lag, lease and repair metrics.

Runs the real service on an owned loopback metrics port against a disposable
PostgreSQL schema. Repositories and the first workspace are created through the
real HTTP API; job rows, an extra ready workspace without capture state, an
expired lease, past capture timestamps and scheduled-scan metadata are controlled
SQL fixtures. Those fixtures prove aggregation and label hygiene, not that a
maintenance job executed or that a repository scan ran.

With ROOTYARD_TEST_WORKSPACE_FUSE=1 the child runs in FUSE mount mode and one
case additionally checks that the real background capture loop refreshes
`scanned_at` and that the exported capture age recovers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from metrics import BACKENDS, JOB_KINDS, JOB_STATES, SCAN_STATES, MetricsHarness

REPO_NAME = "worker-metrics"


class WorkerHarness(MetricsHarness):
    def __init__(self, args):
        super().__init__(args)
        # The scheduler is disabled so seeded job rows stay exactly as written;
        # this test asserts the exposition, not job execution.
        self.env["ROOTYARD_STORAGE_MAINTENANCE"] = "false"
        # The metrics router receives this parsed policy value from `serve`.
        self.env["ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS"] = "60"
        self.fuse = os.environ.get("ROOTYARD_TEST_WORKSPACE_FUSE") == "1"
        if self.fuse:
            self.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = "fuse"

    # -- helpers ---------------------------------------------------------
    def volume_id(self):
        return (self.root / ".volume-id").read_text().strip()

    def create_repo(self):
        body = {"name": REPO_NAME}
        return json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice, body=body))["id"]

    def create_workspace(self, agent_id):
        body = {"owner": "alice", "repository": REPO_NAME, "agent_id": agent_id}
        headers = {"Idempotency-Key": agent_id}
        return json.loads(
            self.expect("/api/workspaces", 201, method="POST", token=self.alice, body=body, extra_headers=headers)
        )["id"]

    def seed_workspace(self, repo, agent_id, lease):
        workspace = str(uuid.uuid4())
        self.sql(
            "INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until) "
            f"VALUES('{workspace}','{repo}','alice','{REPO_NAME}','{agent_id}','{self.alice['user_id']}',"
            f"'ready','{self.volume_id()}',clock_timestamp()+{lease})"
        )
        return workspace

    def seed_job(self, repo, kind, state, not_before, created_at, lease_until=None, attempt=0):
        owner = "NULL" if lease_until is None else f"'{uuid.uuid4()}'"
        lease = "NULL" if lease_until is None else f"clock_timestamp()+{lease_until}"
        self.sql(
            "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,state,repository_generation,"
            "attempt,lease_owner,lease_until,not_before,created_at) VALUES("
            f"'{uuid.uuid4()}','{repo}','{self.alice['user_id']}','{kind}','{state}',1,{attempt},"
            f"{owner},{lease},clock_timestamp()+{not_before},clock_timestamp()+{created_at})"
        )

    # -- cases -----------------------------------------------------------
    def worker_metrics(self):
        repo = self.create_repo()
        tenant = self.alice["user_id"]
        volume = self.volume_id()
        # Real API creation writes a capture baseline before the 201 response.
        baseline = self.create_workspace("agent-metrics-baseline")
        self.sql(
            f"UPDATE workspaces SET lease_until=clock_timestamp()+interval '2 hours' WHERE id='{baseline}'"
        )
        self.sql(
            f"UPDATE workspace_capture_state SET scanned_at=clock_timestamp()-interval '3 hours' "
            f"WHERE workspace_id='{baseline}'"
        )
        # No capture_state row at all: counted separately, never as old lag.
        never = self.seed_workspace(repo, "agent-metrics-never", "interval '2 hours'")
        # Ready on this host but the lease already passed: not capture lag.
        expired = self.seed_workspace(repo, "agent-metrics-expired", "interval '-1 hour'")
        assert self.sql(f"SELECT count(*) FROM workspace_capture_state WHERE workspace_id='{never}'") == "0"
        self.seed_job(repo, "gitfs_repack", "queued", "interval '-1 minute'", "interval '-5 minutes'")
        self.seed_job(repo, "gitfs_stage_cleanup", "queued", "interval '1 hour'", "interval '-10 minutes'", attempt=1)
        self.seed_job(repo, "gitfs_cache_hydrate", "running", "interval '0 seconds'", "interval '-1 minute'",
                      lease_until="interval '5 minutes'")
        self.seed_job(repo, "gitfs_cache_evict", "running", "interval '0 seconds'", "interval '-1 minute'",
                      lease_until="interval '-5 minutes'")
        self.seed_job(repo, "pando_cache_hydrate", "failed", "interval '0 seconds'", "interval '-20 minutes'", attempt=5)
        self.seed_job(repo, "pando_repack", "queued", "interval '-2 minutes'", "interval '-10 minutes'")
        values = self.verify()
        expected = {
            ("gitfs", "gitfs_repack"): {"queued": 1, "due_queued": 1, "retry_delayed": 0, "running": 0,
                                        "expired_running_lease": 0, "failed": 0},
            ("gitfs", "gitfs_stage_cleanup"): {"queued": 1, "due_queued": 0, "retry_delayed": 1, "running": 0,
                                               "expired_running_lease": 0, "failed": 0},
            ("gitfs", "gitfs_cache_hydrate"): {"queued": 0, "due_queued": 0, "retry_delayed": 0, "running": 1,
                                               "expired_running_lease": 0, "failed": 0},
            ("gitfs", "gitfs_cache_evict"): {"queued": 0, "due_queued": 0, "retry_delayed": 0, "running": 0,
                                             "expired_running_lease": 1, "failed": 0},
            ("pando", "pando_cache_hydrate"): {"queued": 0, "due_queued": 0, "retry_delayed": 0, "running": 0,
                                               "expired_running_lease": 0, "failed": 1},
            ("pando", "pando_repack"): {"queued": 1, "due_queued": 1, "retry_delayed": 0, "running": 0,
                                        "expired_running_lease": 0, "failed": 0},
            ("pando", "pando_cache_evict"): {"queued": 0, "due_queued": 0, "retry_delayed": 0, "running": 0,
                                             "expired_running_lease": 0, "failed": 0},
        }
        for backend, kind in JOB_KINDS:
            for state in JOB_STATES:
                series = f'rootyard_storage_maintenance_jobs{{backend="{backend}",kind="{kind}",state="{state}"}}'
                assert values[series] == str(expected[(backend, kind)][state]), (series, values[series])
        for backend, kind, minimum in (("gitfs", "gitfs_repack", 240), ("gitfs", "gitfs_stage_cleanup", 540),
                                       ("pando", "pando_repack", 540)):
            series = f'rootyard_storage_maintenance_oldest_queued_age_seconds{{backend="{backend}",kind="{kind}"}}'
            assert float(values[series]) >= minimum, (series, values[series])
        assert float(values['rootyard_storage_maintenance_oldest_queued_age_seconds{backend="pando",kind="pando_cache_hydrate"}']) == 0
        assert 3 * 3600 <= float(values["rootyard_workspace_capture_oldest_age_seconds"]) < 4 * 3600, values
        assert values["rootyard_workspace_capture_never_sampled"] == "1", values
        assert values["rootyard_workspace_lease_expired"] == "1", values
        # IDs and names never appear; only fixed labels do.
        text = self.scrape()[1]
        for identifier in (repo, baseline, never, expired, tenant, REPO_NAME):
            assert identifier not in text, identifier
        return {
            "repo_created_by_api": repo,
            "baseline_workspace_created_by_api": baseline,
            "never_sampled_workspaces": 1,
            "lease_expired_workspaces": 1,
            "capture_oldest_age_seconds": float(values["rootyard_workspace_capture_oldest_age_seconds"]),
            "seeded_job_rows": "metadata only; no maintenance job executed",
        }

    def repo_scan_state(self):
        repo = self.sql(f"SELECT id FROM repositories WHERE name='{REPO_NAME}' AND owner_id='{self.alice['user_id']}'")
        # The API repo is GitFS, ready and has one recorded scan for generation 1
        # from three periods ago.
        self.sql(
            "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation) "
            f"VALUES('{repo}','{self.alice['user_id']}',clock_timestamp()-interval '180 seconds',999) "
            "ON CONFLICT(repository_id) DO UPDATE SET last_scan_at=EXCLUDED.last_scan_at, "
            "last_scan_generation=EXCLUDED.last_scan_generation"
        )
        # A ready Pando repository with a serving pack state and one due scan.
        pando = str(uuid.uuid4())
        self.sql(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,next_retry_at,created_at) VALUES "
            f"('{pando}','{self.alice['user_id']}','{REPO_NAME}-pando','ready','pando',now()+interval '1 day',now())"
        )
        self.sql(
            "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,object_format,state) "
            f"VALUES('{pando}','{self.alice['user_id']}',1,'sha1','serving')"
        )
        self.sql(
            "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation) "
            f"VALUES('{pando}','{self.alice['user_id']}',clock_timestamp()-interval '120 seconds',1)"
        )
        # Ready Pando repositories without a serving state are not eligible.
        idle = str(uuid.uuid4())
        self.sql(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,next_retry_at,created_at) VALUES "
            f"('{idle}','{self.alice['user_id']}','{REPO_NAME}-idle','ready','pando',now()+interval '1 day',now())"
        )
        values = self.verify()
        assert values['rootyard_storage_maintenance_repos{backend="gitfs",state="missing_scan"}'] == "0", values
        assert values['rootyard_storage_maintenance_repos{backend="gitfs",state="due_scan"}'] == "1", values
        assert values['rootyard_storage_maintenance_repos{backend="gitfs",state="stale_generation"}'] == "1", values
        assert values['rootyard_storage_maintenance_repos{backend="pando",state="missing_scan"}'] == "0", values
        assert values['rootyard_storage_maintenance_repos{backend="pando",state="due_scan"}'] == "1", values
        assert values['rootyard_storage_maintenance_repos{backend="pando",state="stale_generation"}'] == "0", values
        gitfs_overdue = float(values['rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend="gitfs"}'])
        pando_overdue = float(values['rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend="pando"}'])
        assert 100 <= gitfs_overdue <= 190, gitfs_overdue
        assert 40 <= pando_overdue <= 100, pando_overdue
        return {
            "scan_period_seconds": 60,
            "gitfs_oldest_overdue_seconds": gitfs_overdue,
            "pando_oldest_overdue_seconds": pando_overdue,
            "ineligible_pando_rows_without_serving_state": 1,
            "scope": "cluster-wide eligible repositories; local shard-primary routing is not reproduced",
        }

    def worker_table_failure(self):
        self.sql("ALTER TABLE workspace_capture_state RENAME TO worker_hidden_capture_state")
        try:
            status, text, _ = self.scrape()
            assert status == 503
            assert "rootyard_postgres_up 0\n" in text
            for name in ("rootyard_workspace_capture", "rootyard_workspace_lease",
                         "rootyard_storage_maintenance"):
                assert name not in text, name
            # Process-local series survive the failed SQL snapshot.
            for name in ("rootyard_session_gc_cycles_total", "rootyard_session_gc_failures_total",
                         "rootyard_git_capacity", "rootyard_error_log_dropped_total"):
                assert name in text, name
        finally:
            self.sql("ALTER TABLE worker_hidden_capture_state RENAME TO workspace_capture_state")
        assert self.scrape()[0] == 200
        assert self.verify()["rootyard_workspace_capture_never_sampled"] == "1"

    def real_capture_refresh(self):
        volume = self.volume_id()
        workspace = self.create_workspace("agent-metrics-refresh")
        self.sql(
            f"UPDATE workspaces SET lease_until=clock_timestamp()+interval '2 hours' WHERE id='{workspace}'"
        )
        self.sql("UPDATE workspace_capture_state SET scanned_at=clock_timestamp()")
        self.sql(
            f"UPDATE workspace_capture_state SET scanned_at=clock_timestamp()-interval '2 hours' "
            f"WHERE workspace_id='{workspace}'"
        )
        deadline = time.monotonic() + 30
        age = float(self.verify()["rootyard_workspace_capture_oldest_age_seconds"])
        while age >= 120 and time.monotonic() < deadline:
            time.sleep(1)
            age = float(self.verify()["rootyard_workspace_capture_oldest_age_seconds"])
        assert age < 120, age
        refreshed = self.sql(f"SELECT count(*) FROM workspace_capture_state WHERE workspace_id='{workspace}' "
                             "AND scanned_at > clock_timestamp()-interval '2 minutes'")
        assert refreshed == "1", refreshed
        assert volume not in self.scrape()[1]
        return {"capture_oldest_age_seconds_after_scan": age,
                "note": "background capture refreshed scanned_at after a real filesystem scan"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = WorkerHarness(args)
    cases = [
        ("isolated_metrics_setup", harness.setup),
        ("fixed_private_format_zero_series", harness.verify),
        ("worker_job_and_capture_fixtures", harness.worker_metrics),
        ("repo_scan_state", harness.repo_scan_state),
        ("worker_table_failure_is_503", harness.worker_table_failure),
    ]
    if harness.fuse:
        cases.append(("real_capture_refresh", harness.real_capture_refresh))
    cases.append(("non_loopback_rejected", harness.reject_non_loopback))
    success = False
    try:
        for name, test in cases:
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
            limitations=[
                "Job states, capture timestamps, the missing capture row, the expired lease and scheduled-scan "
                "metadata are SQL fixtures; they are not proof that any maintenance job or repository scan executed.",
                "The scanner is not enabled, so the service cannot enqueue or run maintenance jobs during this test.",
                "Workspace capture lag is host-scoped to this process volume; maintenance gauges are cluster-wide "
                "eligible repositories and deliberately do not reproduce local shard-primary routing.",
                "The background capture refresh case only runs with ROOTYARD_TEST_WORKSPACE_FUSE=1 and a working "
                "FUSE mount; it is skipped otherwise.",
                "A renamed table proves fail-closed omission and process-series retention, not a PostgreSQL outage "
                "or a lock-timeout under production load.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
