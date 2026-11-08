import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import state_services_native_baseline as baseline


class NativeBaselineInputsTest(unittest.TestCase):
    def test_response_identity_and_same_origin_clone_path(self):
        identity = str(uuid.uuid4())
        valid = {'id': identity, 'name': 'fixture', 'clone_path': '/git/alice/fixture.git'}
        self.assertEqual(baseline.validate_repository(valid, 'fixture'), identity)
        for malicious in ('@outside.invalid/repo', '//outside.invalid/repo',
                          'https://outside.invalid/repo', '/git/alice/other.git'):
            with self.subTest(path=malicious), self.assertRaises(ValueError):
                baseline.validate_repository(dict(valid, clone_path=malicious), 'fixture')
        for value in ('../../outside', '/absolute', str(uuid.UUID(int=0)), 'invalid'):
            with self.subTest(identity=value), self.assertRaises(ValueError):
                baseline.validate_repository(dict(valid, id=value), 'fixture')
        with self.assertRaises(ValueError):
            baseline.validate_repository(valid, 'fixture', str(uuid.uuid4()))

    def test_cache_cleanup_rejects_escape_and_symlinks(self):
        identity = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as owned, tempfile.TemporaryDirectory() as outside:
            root = Path(owned)
            parent = root / 'data' / 'pando-cache'
            parent.mkdir(parents=True)
            self.assertEqual(baseline.owned_cache_path(root, identity), parent / identity)
            (parent / identity).symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                baseline.owned_cache_path(root, identity)
            (parent / identity).unlink()
            parent.rmdir()
            parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                baseline.owned_cache_path(root, identity)
            for value in ('../../outside', '/absolute', 'invalid'):
                with self.subTest(identity=value), self.assertRaises(ValueError):
                    baseline.owned_cache_path(root, value)


def exposition(overrides=None):
    """Minimal valid exporter body for the fixed baseline series."""
    lines = ['# HELP rootyard_git_capacity Configured concurrent native Git capacity.',
             '# TYPE rootyard_git_capacity gauge', 'rootyard_git_capacity 8']
    for phase in baseline.PHASE_LABELS:
        sample = (overrides or {}).get(phase, {})
        total = sample.get('observations', 0)
        outcomes = {name: sample.get(name, 0) for name in baseline.OUTCOME_LABELS}
        assert sum(outcomes.values()) == total
        lines.append('rootyard_baseline_phase_observations_total{phase="%s"} %d' % (phase, total))
        for name in baseline.OUTCOME_LABELS:
            lines.append('rootyard_baseline_phase_outcomes_total{phase="%s",outcome="%s"} %d'
                         % (phase, name, outcomes[name]))
        for label in baseline.BUCKET_LABELS:
            lines.append('rootyard_baseline_phase_duration_seconds_bucket{phase="%s",le="%s"} %d'
                         % (phase, label, total))
        lines.append('rootyard_baseline_phase_duration_seconds_sum{phase="%s"} %f'
                     % (phase, sample.get('sum', 0.0)))
        lines.append('rootyard_baseline_phase_duration_seconds_count{phase="%s"} %d' % (phase, total))
        lines.append('rootyard_baseline_phase_bytes_total{phase="%s"} %d' % (phase, sample.get('bytes', 0)))
    return '\n'.join(lines) + '\n'


class PhaseMetricsParseTest(unittest.TestCase):
    def test_valid_cumulative_histogram_is_parsed(self):
        parsed = baseline.parse_phase_metrics(exposition({'state_row': {
            'observations': 3, 'ok': 2, 'error': 1, 'sum': 1.5, 'bytes': 4096}}))
        self.assertEqual(set(parsed['phases']), set(baseline.PHASE_LABELS))
        entry = parsed['phases']['state_row']
        self.assertEqual(entry['observations'], 3)
        self.assertEqual(entry['count'], 3)
        self.assertEqual(entry['outcomes'], {'ok': 2, 'error': 1, 'cancelled': 0})
        self.assertEqual(entry['sum_seconds'], 1.5)
        self.assertEqual(entry['bytes'], 4096)
        self.assertEqual(set(entry['buckets']), set(baseline.BUCKET_LABELS))
        self.assertEqual(entry['buckets']['+Inf'], 3)
        self.assertEqual(parsed['phases']['remote_get']['observations'], 0)

    def test_foreign_metrics_only_means_feature_disabled(self):
        text = '# TYPE rootyard_git_capacity gauge\nrootyard_git_capacity 8\nrootyard_postgres_up 1\n'
        self.assertIsNone(baseline.parse_phase_metrics(text))
        self.assertIsNone(baseline.parse_phase_metrics(''))

    def test_unexpected_labels_and_series_are_rejected(self):
        body = exposition()
        mutations = [
            body + 'rootyard_baseline_phase_observations_total{phase="invented"} 1\n',
            body + 'rootyard_baseline_phase_outcomes_total{phase="state_row",outcome="timeout"} 1\n',
            body + 'rootyard_baseline_phase_duration_seconds_bucket{phase="state_row",le="7"} 1\n',
            body + 'rootyard_baseline_phase_observations_total{phase="state_row",repo="r"} 1\n',
            body + 'rootyard_baseline_phase_observations_total{outcome="ok"} 1\n',
            body + 'rootyard_baseline_phase_unknown_total{phase="state_row"} 1\n',
            body + 'rootyard_baseline_phase_bytes_total{phase="state_row"} 1\n',
            body + 'rootyard_baseline_phase_observations_total{phase="state_row" 1\n',
        ]
        for text in mutations:
            with self.subTest(mutation=text[-70:]), self.assertRaises(ValueError):
                baseline.parse_phase_metrics(text)

    def test_nonfinite_negative_and_fractional_counters_are_rejected(self):
        for value in ('nan', 'inf', '-1', '1.5', 'abc'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                baseline.parse_phase_metrics(
                    exposition() + 'rootyard_baseline_phase_bytes_total{phase="state_row"} ' + value + '\n')

    def test_inconsistent_histogram_and_outcome_totals_are_rejected(self):
        body = exposition({'remote_put': {'observations': 2, 'ok': 2, 'sum': 0.5, 'bytes': 10}})
        non_cumulative = body.replace(
            'rootyard_baseline_phase_duration_seconds_bucket{phase="remote_put",le="0.05"} 2',
            'rootyard_baseline_phase_duration_seconds_bucket{phase="remote_put",le="0.05"} 0')
        with self.assertRaises(ValueError):
            baseline.parse_phase_metrics(non_cumulative)
        wrong_inf = body.replace(
            'rootyard_baseline_phase_duration_seconds_bucket{phase="remote_put",le="+Inf"} 2',
            'rootyard_baseline_phase_duration_seconds_bucket{phase="remote_put",le="+Inf"} 1')
        with self.assertRaises(ValueError):
            baseline.parse_phase_metrics(wrong_inf)
        wrong_outcomes = body.replace(
            'rootyard_baseline_phase_outcomes_total{phase="remote_put",outcome="ok"} 2',
            'rootyard_baseline_phase_outcomes_total{phase="remote_put",outcome="ok"} 1')
        with self.assertRaises(ValueError):
            baseline.parse_phase_metrics(wrong_outcomes)
        missing_phase = body.replace(
            'rootyard_baseline_phase_observations_total{phase="remote_get"} 0\n', '')
        with self.assertRaises(ValueError):
            baseline.parse_phase_metrics(missing_phase)


class PhaseMetricsDeltaTest(unittest.TestCase):
    @staticmethod
    def snapshot(identity, overrides):
        return {'identity': identity, 'sample': baseline.parse_phase_metrics(exposition(overrides))}

    def test_delta_is_per_phase_and_never_negative(self):
        identity = {'pid': 4242, 'starttime': 99}
        before = self.snapshot(identity, {'remote_put': {'observations': 1, 'ok': 1, 'sum': 0.5, 'bytes': 10}})
        after = self.snapshot(identity, {'remote_put': {'observations': 4, 'ok': 3, 'error': 1,
                                                       'sum': 2.0, 'bytes': 40}})
        delta = baseline.sample_delta(before, after)
        self.assertEqual(delta['remote_put']['observations'], 3)
        self.assertEqual(delta['remote_put']['outcomes'], {'ok': 2, 'error': 1, 'cancelled': 0})
        self.assertEqual(delta['remote_put']['bytes'], 30)
        self.assertEqual(delta['remote_put']['duration_seconds']['sum'], 1.5)
        self.assertEqual(delta['remote_put']['duration_seconds']['count'], 3)
        self.assertEqual(delta['state_row']['observations'], 0)

    def test_restart_and_regression_are_not_reported_as_deltas(self):
        before = self.snapshot({'pid': 1, 'starttime': 10},
                               {'remote_put': {'observations': 5, 'ok': 5, 'sum': 2.0, 'bytes': 50}})
        restarted = self.snapshot({'pid': 2, 'starttime': 11},
                                  {'remote_put': {'observations': 1, 'ok': 1, 'sum': 0.1, 'bytes': 10}})
        with self.assertRaises(baseline.MetricsRestart):
            baseline.sample_delta(before, restarted)
        same_process = self.snapshot({'pid': 1, 'starttime': 10},
                                     {'remote_put': {'observations': 4, 'ok': 4, 'sum': 1.0, 'bytes': 40}})
        with self.assertRaises(ValueError):
            baseline.sample_delta(before, same_process)

    def test_skip_and_unavailable_markers_never_scrape(self):
        capture = baseline.PhaseMetricsCapture(0)

        def forbidden(pid):
            raise AssertionError('a skipped or unavailable case must not scrape')

        capture._scrape = forbidden
        skipped = {'status': 'offline', 'reason': 'service stopped'}
        self.assertEqual(capture.close_case(None, skipped), skipped)
        capture.status = 'feature_disabled'
        capture.reason = 'no baseline series'
        self.assertEqual(capture.open_case(1234), {'status': 'feature_disabled', 'reason': 'no baseline series'})

    def test_allocated_metrics_port_is_private_and_usable(self):
        port = baseline.loopback_metrics_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1023)
        self.assertLess(port, 65536)
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', port))


if __name__ == '__main__':
    unittest.main()
