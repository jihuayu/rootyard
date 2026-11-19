#!/usr/bin/env python3
"""Pure duplicate-key tests for the issue #21 canonical Vault report reader.

No Vault, PostgreSQL, Docker, Git, network, product binary, compiler, Cargo or
CI is started.  The raw report is a temporary JSON file; source/binary/receipt
validation is mocked only in the no-duplicate control case.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_ci_report as adapter  # noqa: E402
from test_pando_vault_rotation_ci_report import (  # noqa: E402
    good_raw,
    make_args,
    validated_facts,
)


def report_text(validated):
    return json.dumps(good_raw(validated), indent=2) + "\n"


def duplicate_before(text, line, duplicate_line):
    needle = "\n" + line
    assert text.count(needle) == 1, line
    return text.replace(
        needle, "\n" + duplicate_line + ",\n" + line, 1)


def duplicate_after(text, line, duplicate_line):
    needle = "\n" + line
    assert text.count(needle) == 1, line
    return text.replace(
        needle, "\n" + line + ",\n" + duplicate_line, 1)


class DuplicateKeyTest(unittest.TestCase):
    def setUp(self):
        self.validated = validated_facts()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.raw = self.root / "raw.json"
        self.output = self.root / "out.json"

    def write(self, text):
        self.raw.write_text(text)
        return text

    def assert_duplicate_rejected(self, text):
        self.write(text)
        with self.assertRaises(adapter.ProjectionError) as caught:
            adapter.collect(make_args(self.raw, self.output), environ={})
        self.assertEqual(caught.exception.code, "raw_report_duplicate_key")
        self.assertEqual(str(caught.exception), "raw_report_duplicate_key")
        self.assertFalse(self.output.exists())
        return caught.exception

    def test_top_level_passed_duplicate_cannot_last_value_override(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text, '  "passed": true', '  "passed": false'))

    def test_top_level_passed_duplicate_cannot_hide_failure(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_after(
            text, '  "passed": true', '  "passed": false'))

    def test_top_level_status_duplicate_cannot_last_value_override(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text, '  "status": "passed"', '  "status": "failed"'))

    def test_schema_duplicate_cannot_last_value_override(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text,
            '  "schema": "rootyard/issue21-derived-vault-rotation/v1"',
            '  "schema": "rootyard/issue21-derived-vault-rotation/v2"'))

    def test_binding_digest_duplicate_cannot_last_value_override(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text,
            '    "binary_sha256": "' + self.validated["binary_sha256"] + '"',
            '    "binary_sha256": "' + "0" * 64 + '"'))

    def test_nested_case_record_duplicate_is_rejected(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text,
            '      "id": "' + adapter.CASE_IDS[0] + '"',
            '      "id": "' + adapter.CASE_IDS[0] + '"'))

    def test_nested_cleanup_record_duplicate_is_rejected(self):
        text = report_text(self.validated)
        self.assert_duplicate_rejected(duplicate_before(
            text, '    "cleanup_ok": true', '    "cleanup_ok": false'))

    def test_error_carries_no_key_value_body_or_path(self):
        text = report_text(self.validated)
        text = duplicate_before(
            text, '  "schema": "rootyard/issue21-derived-vault-rotation/v1"',
            '  "schema": "duplicate-value-marker"')
        error = self.assert_duplicate_rejected(text)
        message = str(error)
        for leaked in ("duplicate-value-marker", "schema", str(self.root),
                       self.raw.read_text()):
            self.assertNotIn(leaked, message)

    def test_cli_reports_only_the_fixed_duplicate_code(self):
        text = report_text(self.validated)
        self.write(duplicate_before(
            text, '  "status": "passed"', '  "status": "failed"'))
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = adapter.main([
                "--source-root", str(self.root),
                "--binary", str(self.root / "rootyard-pando-lab"),
                "--receipt", str(self.root / "receipt.json"),
                "--expected-commit", "a" * 40,
                "--raw-report", str(self.raw),
                "--output", str(self.output),
            ])
        self.assertEqual(code, 1)
        self.assertEqual(
            stderr.getvalue(),
            "pando_vault_rotation_ci_report: raw_report_duplicate_key\n")
        for leaked in ("status", "passed", str(self.root)):
            self.assertNotIn(leaked, stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_report_without_duplicates_still_projects(self):
        self.write(report_text(self.validated))
        with mock.patch.object(adapter.rotation, "validate_inputs",
                               return_value=self.validated):
            projection = adapter.collect(
                make_args(self.raw, self.output), environ={})
        self.assertIs(projection["passed"], True)
        self.assertEqual(projection["case_count"], 5)
        self.assertTrue(self.output.is_file())


if __name__ == "__main__":
    unittest.main()
