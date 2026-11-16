#!/usr/bin/env python3
"""Offline regressions for #107 commit-unknown blocker database ownership.

These tests exercise the real ``CheckpointHarness._register_owned_blocker`` and
``_register_owned_blocker_or_reap`` methods without starting PostgreSQL, the
service, psql, or any network path. SQL answers are synthesized on a minimal
harness; reaping uses only short, locally owned Python children.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blob_commit_unknown_service import CheckpointHarness  # noqa: E402

APPLICATION_NAME = "rootyard-commit-gate-offline"
PID = 4242
BACKEND_START = "2026-11-16 00:00:00+00"

# Synthetic complete DSNs only: no real credentials or passwords. Every DSN
# carries a search_path query, so self.db is never a bare database name.
DSN_DEFAULT = (
    "postgresql://fixture@127.0.0.1:1/rootyard_test"
    "?options=-csearch_path%3Drootyard_fixture"
)
DSN_ESCAPED = (
    "postgresql://fixture@127.0.0.1:1/rootyard%2Fescaped"
    "?options=-csearch_path%3Drootyard_fixture"
)
DSN_QUERY_OVERRIDE = (
    "postgresql://fixture@127.0.0.1:1/url_path_db"
    "?dbname=actual_query_db&options=-csearch_path%3Drootyard_fixture"
)


class FakeSQL:
    """Only the two queries the ownership helper is allowed to issue."""

    def __init__(self, rows, current_database):
        self.rows = rows
        self.current_database = current_database
        self.calls = []

    def __call__(self, query, isolated=True):
        self.calls.append(query)
        if query == "SELECT current_database()":
            return self.current_database
        if "FROM pg_stat_activity" in query and "jsonb_agg" in query:
            return json.dumps(self.rows)
        raise AssertionError("offline ownership test issued an unexpected SQL query")


class LiveProcess:
    """Minimal live process stand-in for the positive registration path."""

    def __init__(self):
        self._rootyard_blocker_identity = None

    def poll(self):
        return None


class ExitedProcess:
    def poll(self):
        return 1


def row(database, pid=PID, backend_start=BACKEND_START):
    return {"pid": pid, "database": database, "backend_start": backend_start}


def harness(db, rows, current_database):
    fixture = object.__new__(CheckpointHarness)
    fixture.db = db
    fixture.sql = FakeSQL(rows, current_database)
    return fixture


def spawn_sleeper():
    """A real, short, locally owned Python child; never a psql or PG client."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    for stream in (child.stdout, child.stderr):
        if stream is not None:
            stream.close()


class BlockerDatabaseIdentityTest(unittest.TestCase):
    def test_complete_dsns_accept_the_connection_current_database_name(self):
        cases = (
            (DSN_DEFAULT, "rootyard_test"),
            (DSN_ESCAPED, "rootyard/escaped"),
            (DSN_QUERY_OVERRIDE, "actual_query_db"),
        )
        for dsn, current_database in cases:
            with self.subTest(current_database=current_database):
                fixture = harness(dsn, [row(current_database)], current_database)
                process = LiveProcess()
                identity = fixture._register_owned_blocker(process, APPLICATION_NAME)
                self.assertEqual(identity["database"], current_database)
                self.assertNotEqual(identity["database"], fixture.db)
                self.assertEqual(identity["application_name"], APPLICATION_NAME)
                self.assertEqual(identity["pid"], PID)
                self.assertEqual(identity["backend_start"], BACKEND_START)
                self.assertEqual(process._rootyard_blocker_identity, identity)
                self.assertIn("SELECT current_database()", fixture.sql.calls)

    def test_foreign_database_is_refused_and_only_the_owned_child_is_reaped(self):
        owned = spawn_sleeper()
        foreign = spawn_sleeper()
        try:
            fixture = harness(DSN_QUERY_OVERRIDE, [row("foreign_db")], "actual_query_db")
            with self.assertRaisesRegex(
                    AssertionError, "fixture blocker backend database is not owned"):
                fixture._register_owned_blocker_or_reap(owned, APPLICATION_NAME)
            self.assertIsNotNone(owned.poll(), "the rejected owned blocker child was not reaped")
            self.assertIsNone(foreign.poll(), "an unrelated child was reaped on registration failure")
            self.assertIsNone(getattr(owned, "_rootyard_blocker_identity", None))
        finally:
            stop_child(owned)
            stop_child(foreign)

    def test_remaining_identity_checks_still_reject_bad_rows(self):
        cases = (
            ("rootyard-commit-gate-bad!", [row("owned_db")],
             "application_name has unsafe characters"),
            (APPLICATION_NAME, [row("owned_db", pid=0)], "backend pid is invalid"),
            (APPLICATION_NAME, [row("owned_db", backend_start="")], "backend_start is missing"),
            (APPLICATION_NAME, [row("owned_db", backend_start="x';DROP")],
             "backend_start is not SQL-safe"),
            (APPLICATION_NAME, [row("owned_db"), row("owned_db")], "not a single backend"),
        )
        for application_name, rows, message in cases:
            with self.subTest(message=message):
                fixture = harness(DSN_ESCAPED, rows, "owned_db")
                with self.assertRaisesRegex(AssertionError, message):
                    fixture._register_owned_blocker(LiveProcess(), application_name)

        fixture = harness(DSN_ESCAPED, [row("owned_db")], "owned_db")
        with self.assertRaisesRegex(AssertionError, "child exited before ownership registration"):
            fixture._register_owned_blocker(ExitedProcess(), APPLICATION_NAME)


if __name__ == "__main__":
    unittest.main()
