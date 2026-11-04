"""Offline regression tests: simulated curl outcomes, no Kafka or network needed."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("download_ci_kafka", ROOT / "scripts/download_ci_kafka.py")
kafka = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kafka)
PINNED_SHA512 = kafka.SHA512
PAYLOAD = b"small deterministic archive fixture"


class KafkaDownloadTests(unittest.TestCase):
    def setUp(self):
        # All test files stay in the checkout, including on failure.
        self.temporary = tempfile.TemporaryDirectory(prefix=".kafka-test-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.destination = self.directory / "kafka.tgz"
        self.calls = []
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(kafka, "SHA512", hashlib.sha512(PAYLOAD).hexdigest()))

    def runner(self, outcomes):
        outcomes = iter(outcomes)

        def run(command, *, check, timeout):
            self.calls.append(command)
            self.assertTrue(check)
            self.assertEqual(timeout, 65)
            self.assertEqual(command[:2], ["curl", "--disable"])
            for option, value in {
                "--connect-timeout": "10", "--max-time": "60",
                "--speed-limit": "1024", "--speed-time": "15", "--retry": "0",
                "--proto": "=https", "--proto-redir": "=https",
            }.items():
                self.assertEqual(command[command.index(option) + 1], value)
            self.assertIn("--fail", command)
            self.assertNotIn("--insecure", command)
            partial = Path(command[command.index("--output") + 1])
            self.assertFalse(partial.exists(), "failed attempts must not be resumed or reused")
            self.assertEqual(partial.parent.parent, self.directory)
            outcome = next(outcomes)
            partial.write_bytes(PAYLOAD if outcome == "ok" else b"partial or corrupt")
            if outcome == "timeout":
                raise subprocess.TimeoutExpired(command, timeout)
            if isinstance(outcome, int):
                raise subprocess.CalledProcessError(outcome, command)
            if outcome == "missing-curl":
                raise FileNotFoundError("curl")
            return subprocess.CompletedProcess(command, 0)

        return patch.object(kafka.subprocess, "run", side_effect=run)

    def assert_clean(self, published=False):
        self.assertEqual(list(self.directory.iterdir()), [self.destination] if published else [])

    def test_verified_primary_is_published(self):
        with self.runner(["ok"]):
            self.assertEqual(kafka.download(self.destination), self.destination)
        self.assertEqual(self.destination.read_bytes(), PAYLOAD)
        self.assertEqual(len(self.calls), 1)
        self.assert_clean(published=True)

    def test_transient_connection_failure_retries_same_source(self):
        with self.runner([7, "ok"]):
            kafka.download(self.destination)
        self.assertEqual([call[-1] for call in self.calls], [kafka.URLS[0]] * 2)
        self.assert_clean(published=True)

    def test_timeout_connection_and_slow_response_use_verified_fallback(self):
        # curl exit 7 = connection failure; exit 28 = max-time/low-speed timeout.
        for failure in ("timeout", 7, 28):
            with self.subTest(failure=failure):
                self.calls.clear()
                with self.runner([failure, failure, "ok"]):
                    kafka.download(self.destination)
                self.assertEqual([call[-1] for call in self.calls],
                                 [kafka.URLS[0], kafka.URLS[0], kafka.URLS[1]])
                self.assertEqual(self.destination.read_bytes(), PAYLOAD)
                self.assert_clean(published=True)
                self.destination.unlink()

    def test_all_sources_fail_with_bounded_attempts_and_no_archive(self):
        with self.runner(["timeout", 28, 7, 22]):
            with self.assertRaisesRegex(RuntimeError, "4 bounded attempts"):
                kafka.download(self.destination)
        self.assertEqual(len(self.calls), 4)
        self.assert_clean()

    def test_checksum_mismatch_fails_closed_without_retry(self):
        with self.runner(["corrupt"]):
            with self.assertRaisesRegex(RuntimeError, "SHA512 mismatch"):
                kafka.download(self.destination)
        self.assertEqual(len(self.calls), 1)
        self.assert_clean()

    def test_fallback_must_pass_same_checksum(self):
        with self.runner([7, 7, "corrupt"]):
            with self.assertRaisesRegex(RuntimeError, "SHA512 mismatch"):
                kafka.download(self.destination)
        self.assertEqual(len(self.calls), 3)
        self.assert_clean()

    def test_failure_does_not_overwrite_existing_destination(self):
        self.destination.write_bytes(b"previous archive")
        with self.runner([28] * 4):
            with self.assertRaises(RuntimeError):
                kafka.download(self.destination)
        self.assertEqual(self.destination.read_bytes(), b"previous archive")
        self.assert_clean(published=True)

    def test_missing_curl_is_not_retried_and_cleans_partial_file(self):
        with self.runner(["missing-curl"]):
            with self.assertRaises(FileNotFoundError):
                kafka.download(self.destination)
        self.assertEqual(len(self.calls), 1)
        self.assert_clean()

    def test_cli_reports_failure_with_nonzero_exit(self):
        with patch.object(kafka.sys, "argv", ["download_ci_kafka.py", str(self.destination)]):
            with patch.object(kafka, "download", side_effect=RuntimeError("bounded failure")):
                self.assertEqual(kafka.main(), 1)

    def test_official_sources_and_fixed_version(self):
        self.assertEqual(PINNED_SHA512,
                         "f5ceba8a265ab6bb2d68362b1f6859a95e15d60ef92ba83b43fdf065b557dc18e98d6383"
                         "c15b9977320e25b3a2c8b6f11decb17b0fa6c0f163423793a0eb95cb")
        self.assertEqual(kafka.URLS, (
            "https://dlcdn.apache.org/kafka/4.4.0/kafka_2.13-4.4.0.tgz",
            "https://archive.apache.org/dist/kafka/4.4.0/kafka_2.13-4.4.0.tgz",
        ))


if __name__ == "__main__":
    unittest.main()
