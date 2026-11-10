#!/usr/bin/env python3
"""Focused #188 regression: the manifest unknown_operations expectation.

Static/unit only: no native binary, PostgreSQL or Cargo is required. The Base
backup drill seeds one Git ``unknown`` row and no RefStore registry rows, so its
archive total is exactly 1; a harness that also seeds the RefStore registry must
expect one more nonterminal row per nonterminal fixture operation while never
counting a terminal replay (committed/rejected/cancelled) as unknown. These
tests pin that expectation model and the exact hook that consumes it.
"""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backup import (TERMINAL_OPERATION_STATES, BackupHarness,  # noqa: E402
                    repository_operation_counts)

GIT = "11111111-1111-4111-8111-111111111111"
CORE = "22222222-2222-4222-8222-222222222222"


class OperationCountsTest(unittest.TestCase):
    def test_base_model_is_exactly_one_git_unknown_and_terminal_ops_are_excluded(self):
        # The Base seed: one recovering repository with a real Git unknown row.
        counts = repository_operation_counts([GIT], [(GIT, "unknown")], [])
        self.assertEqual(counts, {GIT: (1, 0)})

    def test_hold_fixture_model_is_exactly_two_for_one_pending_parent(self):
        # The #188 case: the inherited terminal replay plus one pending parent.
        registry = [(CORE, "committed"), (CORE, "cancelled"), (CORE, "pending")]
        counts = repository_operation_counts([GIT, CORE], [(GIT, "unknown")], registry)
        self.assertEqual(counts, {GIT: (1, 0), CORE: (0, 1)})
        self.assertEqual(sum(unknown + terminal for unknown, terminal in counts.values()), 2)

    def test_terminal_only_registry_is_not_counted_as_unknown(self):
        # The terminal-only drill: the fixture's own ops are committed/cancelled.
        registry = [(CORE, "committed"), (CORE, "cancelled")]
        counts = repository_operation_counts([GIT, CORE], [(GIT, "unknown")], registry)
        self.assertEqual(counts, {GIT: (1, 0), CORE: (0, 0)})
        self.assertEqual(sum(unknown + terminal for unknown, terminal in counts.values()), 1)

    def test_committed_and_rejected_replays_are_never_unknown(self):
        outcomes = [(CORE, state) for state in TERMINAL_OPERATION_STATES]
        counts = repository_operation_counts([CORE], [], outcomes)
        self.assertEqual(counts, {CORE: (0, 0)})

    def test_every_nonterminal_state_counts_and_other_git_outcomes_do_not(self):
        counts = repository_operation_counts(
            [CORE], [(CORE, "recorded"), (CORE, "no_ref_changes"), (CORE, "unknown")],
            [(CORE, "pending"), (CORE, "pending"), (CORE, "committed")])
        self.assertEqual(counts, {CORE: (1, 2)})

    def test_unrecognised_states_fail_instead_of_being_counted(self):
        with self.assertRaisesRegex(AssertionError, "unknown RefStore operation state 'rolled_back'"):
            repository_operation_counts([CORE], [], [(CORE, "rolled_back")])
        with self.assertRaisesRegex(AssertionError, "unknown Git operation outcome 'lost'"):
            repository_operation_counts([CORE], [(CORE, "lost")], [])


def bare_harness(unknown_repo, operation_counts=None):
    """BackupHarness with only the attributes the hook reads (no DB/psql).

    With ``operation_counts`` the harness behaves like a registry-seeding
    subclass (``expected_repository_operations`` returns the captured model);
    otherwise the Base explicit 1-Git-unknown model applies.
    """
    harness = object.__new__(BackupHarness)
    harness.secrets = []
    harness.db = "postgresql://fixture:fixture@127.0.0.1:1/rootyard_test"
    harness.base_db = harness.db
    harness.unknown_repo = unknown_repo
    if operation_counts is not None:
        harness.expected_repository_operations = lambda: dict(operation_counts)
    return harness


def manifest(*repositories):
    return {"repositories": [{"id": repository, "unknown_operations": count}
                             for repository, count in repositories]}


class ManifestHookTest(unittest.TestCase):
    def test_base_hook_keeps_one_git_unknown_strict(self):
        harness = bare_harness(unknown_repo={"id": GIT})
        detail = harness.assert_manifest_unknown_operations(manifest((CORE, 0), (GIT, 1)))
        self.assertEqual(detail["expected_total"], 1)
        self.assertEqual(detail["actual_total"], 1)
        self.assertEqual(detail["expected_by_repository"], {GIT: 1})
        for archive in (manifest((GIT, 0)), manifest((GIT, 2)),
                        manifest((GIT, 2), ("33333333-3333-4333-8333-333333333333", 0))):
            with self.assertRaisesRegex(AssertionError, "manifest unknown_operations total is"):
                harness.assert_manifest_unknown_operations(archive)

    def test_seeded_registry_expects_two_and_reports_informative_diagnostics(self):
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        detail = harness.assert_manifest_unknown_operations(manifest((CORE, 1), (GIT, 1)))
        self.assertEqual(detail["expected_by_repository"], {GIT: 1, CORE: 1})
        self.assertEqual(detail["expected_total"], detail["actual_total"], 2)

    def test_dropped_pending_parent_is_a_loud_failure_not_a_waiver(self):
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        with self.assertRaisesRegex(
                AssertionError,
                r"manifest unknown_operations total is 1, expected 2 = "
                r'.*"ref_store_nonterminal": \{.*%s": 1\}' % CORE):
            harness.assert_manifest_unknown_operations(manifest((CORE, 0), (GIT, 1)))

    def test_terminal_replay_counted_as_unknown_is_rejected(self):
        # A production that counted seed committed/cancelled replays as unknown
        # would report 3 here; the fixture model is 2 and must fail exactly.
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        with self.assertRaisesRegex(AssertionError, "total is 3, expected 2"):
            harness.assert_manifest_unknown_operations(manifest((CORE, 2), (GIT, 1)))

    def test_per_repository_attribution_is_exact(self):
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        with self.assertRaisesRegex(
                AssertionError,
                r'disagree with the fixture model \(actual, expected\) = .*"%s": \[2, 1\]' % CORE):
            # Total agrees with the model (1 + 1 = 2); only the attribution is wrong.
            harness.assert_manifest_unknown_operations(manifest((CORE, 2), (GIT, 0)))

    def test_unknown_operations_on_an_unseeded_repository_fail(self):
        # The total (2) equals the fixture model, but the archive reports CORE's
        # pending parent under a repository no fixture row seeded: never waived.
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        other = "44444444-4444-4444-8444-444444444444"
        with self.assertRaisesRegex(AssertionError, "counted for unseeded repositories = .*" + other):
            harness.assert_manifest_unknown_operations(manifest((CORE, 0), (GIT, 1), (other, 1)))

    def test_missing_seeded_repository_is_not_silently_accepted(self):
        harness = bare_harness(unknown_repo={"id": GIT},
                               operation_counts={GIT: (1, 0), CORE: (0, 1)})
        with self.assertRaisesRegex(AssertionError, r'%s": \[null, 1\]' % CORE):
            harness.assert_manifest_unknown_operations(manifest((GIT, 2)))


if __name__ == "__main__":
    unittest.main()
