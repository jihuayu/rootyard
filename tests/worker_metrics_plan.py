#!/usr/bin/env python3
"""Owned-PostgreSQL, SQL-only planner drill for the worker metrics query.

This does not run the service, execute a maintenance job, or touch a synthetic
schema's production history.  It creates a disposable schema, installs the real
schema135 partial covering index definition from
``migrations/135_storage_maintenance_metrics.sql``, fills it with 100,000
retained ``succeeded`` rows plus a handful of counted jobs, runs ``ANALYZE``,
and asks the *default* planner (no ``enable_seqscan=off`` and no other planner
override) for ``EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS)`` of the exact
``JOBS_SQL`` embedded in ``src/metrics_workers.rs``.

Passing this drill is evidence that the partial index is usable and naturally
selected for this shape at this size.  It is not production-load, query-latency
or cardinality evidence, and it does not prove migration 135 was applied to a
real deployment.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "135_storage_maintenance_metrics.sql"
SOURCE = ROOT / "src" / "metrics_workers.rs"
INDEX = "storage_maintenance_metrics"
ROWS = 100_000


def psql_env(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql") or not parts.hostname:
        raise SystemExit("ROOTYARD_TEST_DATABASE_URL must be a PostgreSQL URL")
    env = os.environ.copy()
    env.update(
        PGHOST=parts.hostname,
        PGPORT=str(parts.port or 5432),
        PGDATABASE=parts.path.lstrip("/"),
        PGUSER=urllib.parse.unquote(parts.username or ""),
        PGPASSWORD=urllib.parse.unquote(parts.password or ""),
        PGOPTIONS="-csearch_path=" + os.environ["_DRILL_SCHEMA"],
    )
    env.pop("DATABASE_URL", None)
    return env


def run(command, env, check=True):
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180)
    if check and result.returncode:
        raise RuntimeError("planner drill command failed; private diagnostics suppressed")
    return result


def query(sql, env):
    result = run(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", sql], env)
    return result.stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    url = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
    if not url:
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    schema = "worker_metrics_plan_" + uuid.uuid4().hex
    os.environ["_DRILL_SCHEMA"] = schema
    env = psql_env(url)
    try:
        query("CREATE SCHEMA " + schema, env)
        # Minimal faithful shape: the real query references only these columns.
        query("""
            CREATE TABLE storage_maintenance_jobs (
                id UUID PRIMARY KEY,
                kind TEXT NOT NULL,
                state TEXT NOT NULL,
                not_before TIMESTAMPTZ NOT NULL,
                lease_until TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL
            )""", env)
        migration = MIGRATION.read_text()
        ddl = re.search(r"CREATE INDEX " + INDEX + r".*?;", migration, re.S)
        if ddl is None:
            raise RuntimeError("schema135 metrics index DDL not found")
        query(ddl.group(0), env)
        kinds = ["gitfs_stage_cleanup", "gitfs_repack", "gitfs_cache_hydrate",
                 "gitfs_cache_evict", "pando_repack", "pando_cache_hydrate",
                 "pando_cache_evict"]
        # 100,000 retained successful rows: the history the partial predicate
        # must skip.  None of these can match the metrics query.
        query(f"""
            INSERT INTO storage_maintenance_jobs
                (id, kind, state, not_before, lease_until, created_at)
            SELECT gen_random_uuid(),
                   (ARRAY[{','.join("'" + k + "'" for k in kinds)}])[1 + (i % 7)],
                   'succeeded', now() - (i || ' seconds')::interval, NULL,
                   now() - (i || ' seconds')::interval
              FROM generate_series(1, {ROWS}) AS i""", env)
        # A handful of counted jobs, including one expired running lease.
        query(f"""
            INSERT INTO storage_maintenance_jobs
                (id, kind, state, not_before, lease_until, created_at)
            VALUES
              (gen_random_uuid(), 'gitfs_repack', 'queued',
               now() - interval '1 minute', NULL, now() - interval '5 minutes'),
              (gen_random_uuid(), 'gitfs_repack', 'queued',
               now() + interval '1 hour', NULL, now() - interval '10 minutes'),
              (gen_random_uuid(), 'pando_repack', 'queued',
               now() - interval '2 minutes', NULL, now() - interval '10 minutes'),
              (gen_random_uuid(), 'gitfs_cache_hydrate', 'running',
               now(), now() + interval '5 minutes', now() - interval '1 minute'),
              (gen_random_uuid(), 'gitfs_cache_evict', 'running',
               now(), now() - interval '5 minutes', now() - interval '1 minute'),
              (gen_random_uuid(), 'pando_cache_hydrate', 'failed',
               now(), NULL, now() - interval '20 minutes')""", env)
        query("ANALYZE storage_maintenance_jobs", env)
        source = SOURCE.read_text()
        match = re.search(r'const JOBS_SQL: &str = r#"(.*?)"#;', source, re.S)
        if match is None:
            raise RuntimeError("JOBS_SQL not found in src/metrics_workers.rs")
        jobs_sql = match.group(1).strip()
        plan_raw = query("EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) " + jobs_sql, env)
        plan = json.loads(plan_raw)
        nodes = []
        def walk(node):
            nodes.append(node)
            for child in node.get("Plans", []):
                walk(child)
        walk(plan[0]["Plan"])
        index_only = [node for node in nodes
                      if node.get("Node Type") == "Index Only Scan"
                      and node.get("Index Name") == INDEX]
        seq_scans = [node for node in nodes
                     if node.get("Node Type") == "Seq Scan"
                     and node.get("Relation Name") == "storage_maintenance_jobs"]
        if not index_only:
            summary = [(node.get("Node Type"), node.get("Relation Name"),
                        node.get("Index Name"), node.get("Index Cond")) for node in nodes]
            raise AssertionError("default planner did not choose the schema135 partial index: " + repr(summary))
        if seq_scans:
            raise AssertionError("default planner still sequentially scans storage_maintenance_jobs")
        # The exact query must also return the expected small counts without the
        # succeeded history leaking into any state series.
        rows = query(jobs_sql.replace("\n", " "), env).splitlines()
        if len(rows) != 7:
            raise AssertionError("expected one row per fixed kind")
        totals = [sum(int(part) for part in row.split("|")[1:7]) for row in rows]
        if any(total > 10 for total in totals):
            raise AssertionError("succeeded history leaked into counted states")
        # Exact state semantics on the same real SQL: `running` is the total of
        # every running row, and `expired_running_lease` is its subset.
        query("TRUNCATE storage_maintenance_jobs", env)
        query("""
            INSERT INTO storage_maintenance_jobs
                (id, kind, state, not_before, lease_until, created_at)
            VALUES
              (gen_random_uuid(), 'gitfs_repack', 'queued',
               now() - interval '1 minute', NULL, now() - interval '5 minutes'),
              (gen_random_uuid(), 'gitfs_stage_cleanup', 'queued',
               now() + interval '1 hour', NULL, now() - interval '10 minutes'),
              (gen_random_uuid(), 'gitfs_cache_hydrate', 'running',
               now(), now() + interval '5 minutes', now() - interval '1 minute'),
              (gen_random_uuid(), 'gitfs_cache_evict', 'running',
               now(), now() - interval '5 minutes', now() - interval '1 minute'),
              (gen_random_uuid(), 'pando_cache_hydrate', 'failed',
               now(), NULL, now() - interval '20 minutes'),
              (gen_random_uuid(), 'pando_repack', 'queued',
               now() - interval '2 minutes', NULL, now() - interval '10 minutes')
            """, env)
        fixture_rows = query(jobs_sql.replace("\n", " "), env).splitlines()
        fixture = {parts[0]: [int(value) for value in parts[1:7]]
                   for parts in (row.split("|") for row in fixture_rows)}
        expected = {
            "gitfs_stage_cleanup": [1, 0, 1, 0, 0, 0],
            "gitfs_repack": [1, 1, 0, 0, 0, 0],
            "gitfs_cache_hydrate": [0, 0, 0, 1, 0, 0],
            "gitfs_cache_evict": [0, 0, 0, 1, 1, 0],
            "pando_repack": [1, 1, 0, 0, 0, 0],
            "pando_cache_hydrate": [0, 0, 0, 0, 0, 1],
            "pando_cache_evict": [0, 0, 0, 0, 0, 0],
        }
        if fixture != expected:
            raise AssertionError("worker metrics SQL fixture mismatch: " + repr(fixture))
        index_only_scan = index_only[0]
        result = {
            "planner": "default (no enable_seqscan or other planner override)",
            "rows_succeeded_history": ROWS,
            "rows_counted_jobs": 6,
            "plan_json_analyze_buffers": True,
            "index_only_scan": True,
            "index": INDEX,
            "node_type": index_only_scan["Node Type"],
            "index_cond": index_only_scan.get("Index Cond"),
            "heap_fetches": index_only_scan.get("Heap Fetches"),
            "actual_rows": index_only_scan.get("Actual Rows"),
            "shared_hit_blocks": index_only_scan.get("Shared Hit Blocks"),
            "sequence_scans_on_jobs": 0,
            "state_fixture": fixture,
            "state_fixture_running_includes_expired": True,
            "limitations": [
                "SQL-only planner drill on an owned disposable schema; it does not run the service or execute maintenance jobs.",
                "It installs the real schema135 index DDL but does not prove migration 135 was applied to a deployment.",
                "This is not production load, cardinality, latency or monitoring-integration evidence.",
            ],
        }
        print(json.dumps(result, indent=2))
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n")
    finally:
        try:
            query("DROP SCHEMA " + schema + " CASCADE", psql_env(url))
        except Exception:
            pass
        os.environ.pop("_DRILL_SCHEMA", None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
