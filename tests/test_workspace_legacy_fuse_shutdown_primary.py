#!/usr/bin/env python3
"""Hermetic tests for the exact fourth-case startup primary result.

These tests use temporary-directory log files only. They never start or signal
a process, read real ``/proc``, enter a namespace, mount FUSE, or touch a
service, database, network or container.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tests import workspace_legacy_fuse_shutdown_fifo as fifo
from tests import workspace_legacy_fuse_shutdown_support as support


def _oracle_log(test, body):
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    path = Path(directory.name) / "oracle.log"
    path.write_bytes(body)
    return path


class PrimaryOracleTest(unittest.TestCase):
    def test_correct_primary_with_positive_exit_is_accepted(self):
        evidence = fifo.assert_expected_primary_result(
            1, _oracle_log(self, b"rootyard: evidence\nError: HTTP 400: invalid request\n")
        )
        self.assertEqual(evidence, {"expected_primary": True, "primary_http_status": 400})

    def test_positive_exit_with_wrong_or_missing_primary_is_rejected(self):
        bodies = (
            b"Error: HTTP 503: service temporarily unavailable\n",
            b"rootyard: evidence\n",
            b"rootyard: rejected HTTP 400: invalid request\n",
            b"Error: HTTP 400: invalid request\n"
            b"Error: HTTP 503: service temporarily unavailable\n",
        )
        for index, body in enumerate(bodies):
            with self.subTest(index=index):
                with self.assertRaises(support.LegacyAcceptanceError):
                    fifo.assert_expected_primary_result(1, _oracle_log(self, body))

    def test_nonpositive_exit_is_rejected_even_with_expected_primary(self):
        log = _oracle_log(self, b"Error: HTTP 400: invalid request\n")
        for code in (0, -15, True, None):
            with self.subTest(code=code):
                with self.assertRaises(support.LegacyAcceptanceError):
                    fifo.assert_expected_primary_result(code, log)

    def test_trailing_space_after_expected_primary_is_rejected(self):
        log = _oracle_log(self, b"Error: HTTP 400: invalid request \n")
        with self.assertRaises(support.LegacyAcceptanceError):
            fifo.assert_expected_primary_result(1, log)

    def test_trailing_tab_after_expected_primary_is_rejected(self):
        log = _oracle_log(self, b"Error: HTTP 400: invalid request\t\n")
        with self.assertRaises(support.LegacyAcceptanceError):
            fifo.assert_expected_primary_result(1, log)

    def test_crlf_terminated_expected_primary_is_accepted(self):
        log = _oracle_log(self, b"Error: HTTP 400: invalid request\r\n")
        evidence = fifo.assert_expected_primary_result(1, log)
        self.assertEqual(evidence, {"expected_primary": True, "primary_http_status": 400})


if __name__ == "__main__":
    unittest.main()
