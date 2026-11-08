#!/usr/bin/env python3
"""Focused diagnostics tests for backup_ci_checkouts.

Static/unit only: no native binary, PostgreSQL or Cargo is required. These
cover the failure-reporting contract that turned a bare assertion into an
empty CI error, without weakening any fixture assertion.
"""
import argparse
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_ci_checkouts as module  # noqa: E402
from backup_ci_checkouts import BackupCaseFailure, CheckoutBackupHarness  # noqa: E402


def bare_harness(root):
    """Harness with only the diagnostics state, avoiding DB/psql construction."""
    harness = object.__new__(CheckoutBackupHarness)
    harness.root = Path(root)
    harness.secrets = []
    harness.base_db = 'postgresql://fixture:fixture@127.0.0.1:1/rootyard_test'
    harness.db = harness.base_db + '?options=-csearch_path%3Dfixture'
    harness.step_name = 'archive_manifest_and_legacy_opt_in_rejection'
    harness.last_process = None
    return harness


class FailureDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_timeout_argv_basic_secret_is_never_formatted(self):
        # Deliberately unregistered Basic credential: it must not leak through
        # str(TimeoutExpired), cmd or args even without redaction knowing it.
        basic = base64.b64encode(b'alice:checkout-job-secret').decode()
        argv = ['git', '-c', 'http.extraHeader=Authorization: Basic ' + basic, 'sync']
        error = subprocess_timeout(argv, 60, stderr=b'fatal: helper timed out')
        harness = bare_harness(self.root)
        (self.root / 'server.log').write_text('server started')
        harness._record_process_failure(argv, error)
        text = harness.failure_detail(error)
        self.assertIn('TimeoutExpired: command exceeded 60s', text)
        self.assertIn('fatal: helper timed out', text)
        self.assertNotIn(basic, text)
        self.assertNotIn('checkout-job-secret', text)
        self.assertNotIn('http.extraHeader', text)
        self.assertNotIn('Authorization', text)
        self.assertNotIn("'-c'", text)

    def test_called_process_error_cmd_is_never_formatted(self):
        basic = base64.b64encode(b'alice:checkout-job-secret').decode()
        argv = ['git', '-c', 'http.extraHeader=Authorization: Basic ' + basic, 'fetch']
        error = module.subprocess.CalledProcessError(1, argv, stderr=b'fatal: bad ref')
        harness = bare_harness(self.root)
        harness._record_process_failure(argv, error)
        text = harness.failure_detail(error)
        self.assertIn('CalledProcessError: command exited 1', text)
        self.assertIn('fatal: bad ref', text)
        self.assertNotIn(basic, text)
        self.assertNotIn('http.extraHeader', text)

    def test_bare_assertion_reports_step_and_source_line(self):
        harness = bare_harness(self.root)
        try:
            assert 13 == 11
        except AssertionError as error:
            text = harness.failure_detail(error)
        self.assertIn('AssertionError raised without a message', text)
        self.assertIn('step: archive_manifest_and_legacy_opt_in_rejection', text)
        self.assertIn('test_backup_ci_diagnostics.py:', text)
        self.assertIn('assert 13 == 11', text)

    def test_checkout_job_basic_credential_is_registered_for_redaction(self):
        harness = bare_harness(self.root)
        harness.register_token('alice', 'checkout-job-secret')
        basic = base64.b64encode(b'alice:checkout-job-secret').decode()
        redacted = harness.redact('raw checkout-job-secret basic ' + basic)
        self.assertNotIn('checkout-job-secret', redacted)
        self.assertNotIn(basic, redacted)
        self.assertIn('[REDACTED]', redacted)

    def test_inner_cleanup_failure_keeps_original_failure_first(self):
        args = argparse.Namespace(binary='binary', legacy_binary='legacy', report=None, keep=False)
        with mock.patch.object(module, 'CheckoutBackupHarness', _ExplodingInnerHarness):
            with self.assertRaises(BackupCaseFailure) as caught:
                module.legacy_restore(args)
        text = str(caught.exception)
        self.assertIn('legacy archive manifest mismatch', text)
        self.assertIn('legacy case cleanup failed: fixture removal exploded', text)
        self.assertLess(text.index('legacy archive manifest mismatch'),
                        text.index('legacy case cleanup failed'))

    def test_cleanup_failure_still_writes_failed_json_report(self):
        binary = self.root / 'rootyard'
        binary.write_bytes(b'current-binary')
        legacy = self.root / 'rootyard-schema007'
        legacy.write_bytes(b'legacy-binary')
        report = self.root / 'results' / 'backup-ci-checkouts.json'
        argv = ['backup_ci_checkouts.py', '--binary', str(binary),
                '--legacy-binary', str(legacy), '--report', str(report)]
        with mock.patch.object(module, 'CheckoutBackupHarness', _FailingOuterHarness), \
                mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.dict(os.environ, {'ROOTYARD_TEST_DATABASE_URL': 'postgresql://fixture:fixture@127.0.0.1:1/rootyard_test'}):
            self.assertEqual(module.main(), 1)
        data = json.loads(report.read_text())
        self.assertFalse(data['passed'])
        self.assertIn('restored checkout authority mismatch', data['failure'])
        self.assertEqual([case['name'] for case in data['cases']],
                         ['current_checkout_authority_restore', 'cleanup'])
        self.assertEqual(data['cases'][0]['error'], data['failure'])
        self.assertIn('outer fixture cleanup exploded', data['cases'][1]['error'])


class _ExplodingInnerHarness:
    """Stands in for the legacy case's own harness."""

    def __init__(self, args):
        self.args = args
        self.step_name = 'startup'
        self.last_process = None

    def mark(self, name):
        self.step_name = name

    def setup(self):
        raise AssertionError('legacy archive manifest mismatch: format 13 != 4')

    def failure_detail(self, error):
        return f'{type(error).__name__}: {error}\nstep: {self.step_name}'

    def redact(self, value):
        return str(value)

    def cleanup(self):
        raise RuntimeError('fixture removal exploded')


class _FailingOuterHarness:
    """Stands in for the outer harness when its own case already failed."""

    def __init__(self, args):
        self.step_name = 'startup'
        self.results = []
        self.grants = self._grants

    def _grants(self):
        raise BackupCaseFailure('AssertionError: restored checkout authority mismatch\nstep: restored_rows')

    def case(self, name, fn):
        try:
            fn()
        except BackupCaseFailure:
            self.results.append(dict(name=name, status='failed', seconds=0.0, error=''))
            raise

    def failure_detail(self, error):
        raise AssertionError('outer stale diagnostics must not replace a sealed failure')

    def redact(self, value):
        return str(value)

    def cleanup(self):
        raise RuntimeError('outer fixture cleanup exploded')


def subprocess_timeout(argv, timeout, stderr=None):
    return module.subprocess.TimeoutExpired(argv, timeout, stderr=stderr)


if __name__ == '__main__':
    unittest.main()
