#!/usr/bin/env python3
"""Hermetic regressions for deleted-claim fixture setup and assertions.

The real ``DeletedClaimAcceptanceHarness`` constructor is used. Only the base
class external-resource initialization and the fixture's HTTP/Git operations are
replaced with in-memory fakes. No server, subprocess, database, Git fixture, or
network is started or contacted.
"""
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import repository_lifecycle_deleted_claim_acceptance as acceptance  # noqa: E402


class DeletedClaimFixtureInitializationTests(unittest.TestCase):
    def test_real_constructor_initializes_cache_before_first_fixture_read(self):
        base_init_calls = []
        roots = []

        def fake_base_init(harness, args):
            base_init_calls.append(args)
            root = Path(tempfile.mkdtemp(prefix="deleted-claim-init-"))
            roots.append(root)
            harness.root = root
            harness.base = "http://127.0.0.1:1"
            harness.env = {}
            harness.results = []
            harness.secrets = []
            harness.schema_created = False

        self.addCleanup(lambda: [shutil.rmtree(root, True) for root in roots])

        with mock.patch.object(acceptance.RepositoryLifecycleHarness, "__init__", fake_base_init):
            harness = acceptance.DeletedClaimAcceptanceHarness(
                types.SimpleNamespace(binary="unused")
            )

        # The constructor must explicitly own the cache attribute; a bare
        # getattr fallback in _create_fixture would hide unrelated errors.
        self.assertEqual(len(base_init_calls), 1)
        self.assertIn("fixture", vars(harness))
        self.assertIsNone(harness.fixture)

        harness.REPO_NAME = "deleted-claim"
        harness.CONTEXT = "ci/test"
        harness.HOOK_SECRET = "synthetic-secret"
        harness.alice = {"username": "alice", "token": "token"}
        harness.receiver = types.SimpleNamespace(url="http://127.0.0.1:2/hook")

        setup_calls = []

        def fake_setup():
            setup_calls.append(1)
            harness.schema_created = True
            # Keep the production cache protocol: setup starts with no fixture.
            harness.fixture = None

        harness.setup = fake_setup

        # The first registered case is static source inspection and must not
        # initialize the live fixture or call setup.
        contract = harness.source_claim_fence_contract()
        self.assertTrue(contract["early_lookup_deleted_filter"])
        self.assertEqual(setup_calls, [])
        self.assertIsNone(harness.fixture)

        repository_calls = []
        state = {"oid": 0, "pull": 0, "last_oid": None}

        def fake_create_repository(payload, token=None):
            repository_calls.append(payload)
            return {
                "id": "repo-id",
                "owner": "alice",
                "name": "deleted-claim",
                "state": "ready",
            }

        def fake_doc(path, code, token=None, **kwargs):
            if path.endswith("/webhooks"):
                return {"id": "hook-id"}
            if path.endswith("/trusted-contexts"):
                return None
            if path.endswith("/branch-rules"):
                return None
            if path.endswith("/pulls"):
                state["pull"] += 1
                return {"number": state["pull"], "head_oid": state["last_oid"]}
            raise AssertionError("unexpected injected API path")

        def fake_git(*args, cwd=None, token=None, check=True, env=None):
            if args[0] == "clone":
                Path(args[2]).mkdir(parents=True, exist_ok=True)
            if args[0] == "rev-parse":
                state["oid"] += 1
                state["last_oid"] = f"{state['oid']:040x}"
                return types.SimpleNamespace(stdout=state["last_oid"].encode())
            return types.SimpleNamespace(stdout=b"")

        def fake_wait_run(pull_number, head_oid, deadline=20.0):
            return {
                "id": f"run-{pull_number}",
                "job_id": f"job-{pull_number}",
                "head_oid": head_oid,
            }

        def fake_wait_pin(job_id, deadline=20.0):
            return True

        harness.create_repository = fake_create_repository
        harness.doc = fake_doc
        harness.git = fake_git
        harness._wait_run = fake_wait_run
        harness._wait_pin = fake_wait_pin

        first = harness._create_fixture()
        self.assertEqual(setup_calls, [1])
        self.assertEqual(len(repository_calls), 1)
        self.assertEqual(first["control_run"]["id"], "run-1")
        self.assertEqual(first["deleted_run"]["id"], "run-2")
        self.assertEqual(first["race_run"]["id"], "run-3")

        second = harness._create_fixture()
        self.assertIs(second, first)
        self.assertEqual(setup_calls, [1])
        self.assertEqual(len(repository_calls), 1)


class DeletedClaimReclaimTests(unittest.TestCase):
    def test_expiry_requires_a_strictly_past_whole_second(self):
        second = 1_700_000_000
        for microseconds in (499_999, 500_000, 999_999):
            now_ns = second * 1_000_000_000 + microseconds * 1_000
            for updated, state, expires, accepted in (
                ("run-id", "leased", second - 1, True),
                ("", "queued", second - 1, True),
                ("run-id", "leased", second, False),
                ("", "leased", second - 1, False),
            ):
                with self.subTest(
                    microseconds=microseconds, state=state, expires=expires, updated=bool(updated)
                ):
                    harness = object.__new__(acceptance.DeletedClaimAcceptanceHarness)
                    harness.sql = mock.Mock(return_value=updated)
                    harness.run_row = mock.Mock(return_value={
                        "state": state, "lease_expires_unix": expires,
                    })
                    with mock.patch.object(acceptance.time, "time_ns", return_value=now_ns):
                        if accepted:
                            self.assertIs(harness.expire_lease_metadata("run-id"), True)
                        else:
                            with self.assertRaises(AssertionError):
                                harness.expire_lease_metadata("run-id")
                    harness.sql.assert_called_once_with(
                        "UPDATE ci_runs SET lease_expires_unix="
                        "floor(extract(epoch FROM clock_timestamp()))::bigint-1,"
                        "updated_at=clock_timestamp() "
                        "WHERE id='run-id' AND state='leased' RETURNING id::text"
                    )
                    harness.run_row.assert_called_once_with("run-id")

    def test_denied_reclaim_keeps_exactly_the_preexisting_grant_rows(self):
        before = ["control-run|1|1", "control-run|2|2", "deleted-run|1|1"]
        for label, after in (
            ("unchanged", before.copy()),
            ("added", [*before, "deleted-run|2|2"]),
            ("replaced", [*before[:-1], "deleted-run|2|2"]),
            ("removed", before[:-1]),
        ):
            with self.subTest(rows=label):
                harness = object.__new__(acceptance.DeletedClaimAcceptanceHarness)
                harness.fixture = {"deleted_run": {"id": "deleted-run"}}
                harness.deleted = {"deleted": True}
                harness.diagnostics = acceptance.PhaseDiagnostics()
                harness.checkout_rows = mock.Mock(side_effect=(before, after))
                harness.run_row = mock.Mock(return_value={
                    "attempt": 1, "lease_generation": 1, "lease_expires_unix": 0,
                })
                harness._claim_raw = mock.Mock(return_value=(
                    404, b'{"error":"not found"}', {"cache-control": "no-store"},
                ))
                reclaim = harness.deleted_expired_lease_reclaim_denied_without_new_grant

                if label == "unchanged":
                    self.assertEqual(reclaim(), {
                        "expired_reclaim_status_after_delete": 404,
                        "checkout_rows_before": 3,
                        "checkout_rows_after": 3,
                        "no_new_hold": True,
                    })
                else:
                    with self.assertRaises(AssertionError):
                        reclaim()
                harness._claim_raw.assert_called_once_with("deleted-run", "deleted-expired-reclaim")


if __name__ == "__main__":
    unittest.main(verbosity=2)
