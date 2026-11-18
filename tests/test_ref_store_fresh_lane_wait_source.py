"""Offline source checks for the ignored fresh-lane wait regression.

The hosted test may not pass because a short timeout elapsed or because a task
was merely unfinished. It must observe the waiter's own backend active inside
the lane INSERT with `pg_blocking_pids` naming the fixture creator, then release
the creator and assert sequences 1 and 2 under bounded joins and cleanup.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / 'tests/ref_store_operations.rs'


class FreshLaneWaitSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = OPS.read_text()
        cls.probe = cls.source.split('const FRESH_LANE_WAIT_PROBE: &str =', 1)[1].split(';', 1)[0]
        cls.body = cls.source.split(
            'async fn fresh_lane_creation_waits_for_an_uncommitted_creator()', 1
        )[1].split('fn identity_with_lane(', 1)[0]

    def test_probe_is_one_positive_boolean_with_exact_backend_and_blocker(self):
        self.assertIn('SELECT EXISTS', self.probe)
        for marker in [
            "a.state='active'",
            "a.wait_event_type='Lock'",
            "a.query LIKE 'INSERT INTO ref_store_issuer_lanes%'",
            '$2 = ANY(pg_blocking_pids($1))',
        ]:
            self.assertIn(marker, self.probe)
        self.assertNotIn('UNION', self.probe)
        self.assertNotIn('is_finished', self.probe)
        self.assertNotIn('elapsed', self.probe)

    def test_both_backends_are_reported_before_the_real_reservation(self):
        self.assertEqual(self.body.count('SELECT pg_backend_pid()'), 2)
        self.assertIn('creator_pid_tx.send(pid)', self.body)
        self.assertIn('waiter_pid_tx.send(pid)', self.body)
        creator = self.body.split('let mut creator = tokio::spawn', 1)[1].split('let creator_pid =', 1)[0]
        self.assertLess(
            creator.index('INSERT INTO ref_store_issuer_lanes'),
            creator.index('creator_pid_tx.send(pid)'),
        )
        waiter = self.body.split('let mut waiter = tokio::spawn', 1)[1].split('let mut release_tx', 1)[0]
        self.assertLess(waiter.index('waiter_pid_tx.send(pid)'), waiter.index('reserve_sequence'))

    def test_wait_evidence_is_a_positive_observation_not_time_or_unfinished(self):
        self.assertIn(
            'query_one(FRESH_LANE_WAIT_PROBE, &[&waiter_pid, &creator_pid])',
            self.body,
        )
        markers = [
            'let observed: bool',
            'if observed',
            'break Ok::<(), anyhow::Error>(())',
            'sleep(Duration::from_millis(10))',
        ]
        positions = [self.body.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('timeout(WAIT, async {', self.body)
        self.assertIn('waiter never entered the fresh-lane INSERT blocked by the creator', self.body)
        self.assertNotIn('is_finished', self.body)
        self.assertNotIn('from_secs(2)', self.body)
        self.assertNotIn('blocked.is_err', self.body)

    def test_release_join_and_cleanup_are_bounded(self):
        self.assertIn('release_tx.take()', self.body)
        self.assertIn('release.send(())', self.body)
        self.assertIn('if outcome.is_err()', self.body)
        self.assertIn('creator.abort()', self.body)
        self.assertIn('waiter.abort()', self.body)
        self.assertIn('creator_joined', self.body)
        self.assertIn('waiter_joined', self.body)
        self.assertGreaterEqual(self.body.count('tokio::time::timeout(WAIT'), 8)
        self.assertLess(
            self.body.index('if outcome.is_err()'),
            self.body.index('teardown(&admin, &schema)'),
        )
        self.assertIn('assert_eq!(sequence, 1)', self.body)
        self.assertIn('assert_eq!(next.sequence(), 2)', self.body)
        self.assertIn('next reservation rollback timed out', self.body)


if __name__ == '__main__':
    unittest.main()
