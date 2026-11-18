#!/usr/bin/env python3
"""Pure boundary regressions for root-scope race deadline and cleanup state."""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import refstore_root_browse_http as fixture
import refstore_roots_http


class BlockerHandle:
    pass


class FakeSQL:
    def __init__(self):
        self._advisory_key_parts = fixture.RootBrowseHttpHarness._advisory_key_parts
        self.deadline = None

    def _sql_until(self, query, deadline):
        self.deadline = deadline
        return ""


class FakeBlocker:
    def __init__(self):
        self._root_scope_blocker = None
        self.stopped = False

    def _owned_blocker_pid(self, application_name, key, deadline):
        raise AssertionError("fixture SQL lookup failed")

    def _stop_local_process(self, process, deadline):
        self.stopped = True
        return True


class DeadlineTests(unittest.TestCase):
    def test_expired_sql_deadline_never_starts_subprocess(self):
        fake = SimpleNamespace(env={"PGDATABASE": "unused"}, db="unused")
        with mock.patch.object(fixture.subprocess, "run") as run:
            with self.assertRaisesRegex(AssertionError, "deadline exhausted"):
                fixture.RootBrowseHttpHarness._sql_until(fake, "SELECT 1", time.monotonic() - 1.0)
            run.assert_not_called()

    def test_remaining_deadline_is_forwarded_to_psql_timeout(self):
        fake = SimpleNamespace(env={}, db="unused")
        deadline = time.monotonic() + 2.0
        completed = SimpleNamespace(returncode=0, stdout=b"1")
        with mock.patch.object(fixture.subprocess, "run", return_value=completed) as run:
            self.assertEqual(fixture.RootBrowseHttpHarness._sql_until(fake, "SELECT 1", deadline), "1")
            timeout = run.call_args.kwargs["timeout"]
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 2.0)

    def test_commit_observation_uses_same_deadline(self):
        fake = FakeSQL()
        deadline = time.monotonic() + 2.0
        fixture.RootBrowseHttpHarness._waiting_commit_pid_until(fake, 123, deadline)
        self.assertEqual(fake.deadline, deadline)


class BlockerCleanupTests(unittest.TestCase):
    def test_sql_failure_still_reaps_local_process_and_keeps_handle(self):
        fake = FakeBlocker()
        handle = BlockerHandle()
        deadline = time.monotonic() + 0.15
        released = fixture.RootBrowseHttpHarness._release_owned_blocker(
            fake, handle, "rootyard-test-blocker", 123, deadline)
        self.assertFalse(released)
        self.assertTrue(fake.stopped)
        self.assertIs(fake._root_scope_blocker, handle)

    def test_startup_failure_retries_harness_retained_blocker(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        handle = BlockerHandle()
        fake._root_scope_blocker = handle
        fake._root_scope_unresolved = {
            "reason": "owned blocker startup could not be reconciled",
            "blocker": handle,
            "blocker_unresolved": True,
        }
        fake._release_owned_blocker = mock.Mock(return_value=True)
        released, remaining = fixture.RootBrowseHttpHarness._finalize_blocker_cleanup(
            fake, None, "rootyard-test-blocker", 123, time.monotonic() + 1.0)
        self.assertTrue(released)
        self.assertIsNone(remaining)
        fake._release_owned_blocker.assert_called_once()
        self.assertIs(fake._release_owned_blocker.call_args.args[0], handle)
        self.assertIsNone(fake._root_scope_unresolved)
        self.assertIsNone(fake._root_scope_blocker)

    def test_recovered_normal_release_clears_only_blocker_reason(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        handle = BlockerHandle()
        fake._root_scope_blocker = handle
        fake._root_scope_unresolved = {
            "reason": "owned blocker release could not be proven",
            "blocker": handle,
            "blocker_unresolved": True,
        }
        fake._release_owned_blocker = mock.Mock(return_value=True)
        released, remaining = fixture.RootBrowseHttpHarness._finalize_blocker_cleanup(
            fake, handle, "rootyard-test-blocker", 123, time.monotonic() + 1.0)
        self.assertTrue(released)
        self.assertIsNone(remaining)
        self.assertIsNone(fake._root_scope_unresolved)
        fake.stop = mock.Mock()
        fake._root_blob_gate = mock.Mock()
        fake._root_blob_gate.stop.return_value = True
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            fixture.RootBrowseHttpHarness.cleanup(fake)
            base_cleanup.assert_called_once_with()
            fake.stop.assert_called_once()
            fake._root_blob_gate.stop.assert_called_once()

    def test_unrelated_unresolved_reason_keeps_preservation(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        handle = BlockerHandle()
        fake._root_scope_blocker = handle
        fake._root_scope_unresolved = {
            "reason": "root request not settled",
            "blocker": None,
            "blocker_unresolved": False,
        }
        fake._release_owned_blocker = mock.Mock(return_value=True)
        released, remaining = fixture.RootBrowseHttpHarness._finalize_blocker_cleanup(
            fake, handle, "rootyard-test-blocker", 123, time.monotonic() + 1.0)
        self.assertTrue(released)
        self.assertIsNone(remaining)
        self.assertEqual(fake._root_scope_unresolved["reason"], "root request not settled")
        fake.stop = mock.Mock()
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            with self.assertRaises(AssertionError):
                fixture.RootBrowseHttpHarness.cleanup(fake)
            fake.stop.assert_called_once()
            base_cleanup.assert_not_called()
        self.assertEqual(fake._root_scope_unresolved["reason"], "root request not settled")

    def test_gate_stop_failure_preserves_scratch_and_schema(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        fake._root_scope_unresolved = None
        fake.stop = mock.Mock()
        fake._root_blob_gate = mock.Mock()
        fake._root_blob_gate.stop.return_value = False
        success = True
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            try:
                fixture.RootBrowseHttpHarness.cleanup(fake)
            except AssertionError:
                success = False
            fake.stop.assert_called_once()
            fake._root_blob_gate.stop.assert_called_once()
            base_cleanup.assert_not_called()
        self.assertFalse(success)
        self.assertIn("blob forward gate", fake._root_scope_unresolved["reason"])

    def test_gate_stop_exception_fails_cleanup_and_preserves(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        fake._root_scope_unresolved = None
        fake.stop = mock.Mock()
        fake._root_blob_gate = mock.Mock()
        fake._root_blob_gate.stop.side_effect = OSError("gate stop failed")
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            with self.assertRaises(AssertionError):
                fixture.RootBrowseHttpHarness.cleanup(fake)
            fake.stop.assert_called_once()
            base_cleanup.assert_not_called()
        self.assertIn("blob forward gate", fake._root_scope_unresolved["reason"])

    def test_unresolved_cleanup_preserves_scratch_and_schema(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        fake._root_scope_unresolved = {"reason": "fixture blocker not reaped"}
        fake.stop = mock.Mock()
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            with self.assertRaises(AssertionError):
                fixture.RootBrowseHttpHarness.cleanup(fake)
            fake.stop.assert_called_once()
            base_cleanup.assert_not_called()

    def test_confirmed_cleanup_uses_normal_harness_cleanup(self):
        fake = object.__new__(fixture.RootBrowseHttpHarness)
        fake._root_scope_unresolved = None
        fake.stop = mock.Mock()
        fake._root_blob_gate = mock.Mock()
        fake._root_blob_gate.stop.return_value = True
        with mock.patch.object(refstore_roots_http.RootsHttpHarness, "cleanup") as base_cleanup:
            fixture.RootBrowseHttpHarness.cleanup(fake)
            fake.stop.assert_called_once()
            fake._root_blob_gate.stop.assert_called_once()
            base_cleanup.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
