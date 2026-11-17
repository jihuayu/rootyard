#!/usr/bin/env python3
"""Pure contracts for the bounded source/receipt child adapter.

Only a fake clock and fake runner are used; no Git, receipt validation, child
process, Docker, database or network is started.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

TESTS = Path(__file__).resolve().parent
for entry in (str(TESTS), str(TESTS.parent / "scripts")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from pando_vault_rotation_budget import Budget  # noqa: E402
import pando_vault_rotation_source as source  # noqa: E402
import pando_vault_rotation_source_child as source_child  # noqa: E402
from pando_vault_rotation_support import Completed, QualificationError  # noqa: E402

A = "a" * 40
B = "b" * 40
C = "c" * 64
D = "d" * 64


class Clock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        if not self.responses:
            raise AssertionError("unexpected source child")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def result(payload, returncode=0):
    raw = json.dumps(payload, sort_keys=True).encode()
    return Completed(["child"], returncode, raw, b"")


def ok_payload(**overrides):
    value = {
        "ok": True,
        "code": None,
        "stage": "binding",
        "source_commit": A,
        "source_tree": B,
        "source_clean": True,
        "binary_sha256": C,
        "receipt_sha256": D,
    }
    value.update(overrides)
    return value


def inputs():
    return {
        "source_root": Path("/source"),
        "source_commit": A,
        "source_tree": B,
        "binary": Path("/binary"),
        "receipt": Path("/receipt"),
        "binary_sha256": C,
        "receipt_sha256": D,
        "harness_sha256": "e" * 64,
    }


class SourceValidateTest(unittest.TestCase):
    def test_success_is_parsed_from_the_bounded_child_only(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        clock.advance(30)
        runner = FakeRunner([result(ok_payload())])
        payload = source.validate(
            runner, budget, source_root=Path("/source"),
            expected_commit=A, binary=Path("/binary"),
            receipt=Path("/receipt"), expected_binary_sha256=None)
        self.assertEqual(payload["source_commit"], A)
        self.assertEqual(payload["binary_sha256"], C)
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv[1:3], [str(source.CHILD_SCRIPT), "validate"])
        self.assertEqual(kwargs["timeout"], 50.0)
        self.assertEqual(kwargs["stage"], "binding")

    def test_fixed_child_code_is_preserved_without_raw_text(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([result({
            "ok": False, "code": "receipt_pando_artifact_mismatch",
            "stage": "binding"})])
        with self.assertRaises(QualificationError) as caught:
            source.validate(
                runner, budget, source_root=Path("/source"),
                expected_commit=A, binary=Path("/binary"),
                receipt=Path("/receipt"))
        self.assertEqual(caught.exception.code,
                         "receipt_pando_artifact_mismatch")

    def test_nonzero_malformed_and_oversized_outputs_fail_closed(self):
        for response in (
            Completed(["child"], 1, b"{}", b""),
            result({"ok": True}),
            Completed(["child"], 0, b"x" * (source.MAX_BINDING_BYTES + 1), b""),
            Completed(["child"], 0, b"not-json", b""),
        ):
            with self.subTest(response=response.stdout[:16]):
                clock = Clock()
                budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
                runner = FakeRunner([response])
                with self.assertRaises(QualificationError) as caught:
                    source.validate(
                        runner, budget, source_root=Path("/source"),
                        expected_commit=A, binary=Path("/binary"),
                        receipt=Path("/receipt"))
                self.assertEqual(caught.exception.code, "binding_unavailable")

    def test_expired_budget_never_starts_the_source_child(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([])
        clock.advance(80)
        with self.assertRaises(QualificationError) as caught:
            source.validate(
                runner, budget, source_root=Path("/source"),
                expected_commit=A, binary=Path("/binary"),
                receipt=Path("/receipt"))
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(runner.calls, [])

    def test_child_timeout_is_not_replaced_by_a_success_binding(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([QualificationError("subprocess_timeout", "binding")])
        with self.assertRaises(QualificationError) as caught:
            source.validate(
                runner, budget, source_root=Path("/source"),
                expected_commit=A, binary=Path("/binary"),
                receipt=Path("/receipt"))
        self.assertEqual(caught.exception.code, "binding_unavailable")


class SourceSnapshotTest(unittest.TestCase):
    def test_snapshot_compares_every_bound_digest(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([result(ok_payload())])
        payload = source.snapshot(runner, budget, inputs())
        self.assertEqual(payload["receipt_sha256"], D)
        argv, _kwargs = runner.calls[0]
        self.assertEqual(argv[1:3], [str(source.CHILD_SCRIPT), "snapshot"])
        self.assertEqual(len(argv), 10)

    def test_snapshot_digest_mismatch_is_fixed(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([result(ok_payload(binary_sha256="f" * 64))])
        with self.assertRaises(QualificationError) as caught:
            source.snapshot(runner, budget, inputs())
        self.assertEqual(caught.exception.code, "binary_binding_changed")

    def test_snapshot_child_failure_is_fixed(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock, error_factory=QualificationError)
        runner = FakeRunner([result({
            "ok": False, "code": "source_became_dirty", "stage": "binding"})])
        with self.assertRaises(QualificationError) as caught:
            source.snapshot(runner, budget, inputs())
        self.assertEqual(caught.exception.code, "source_became_dirty")


class SourceChildArtifactTest(unittest.TestCase):
    def test_v1_and_v2_pando_artifact_codes_match_the_legacy_gate(self):
        v1 = SimpleNamespace(
            schema="v1",
            payload={"version": 1},
            artifacts=({"kind": "bin", "target": "rootyard-pando-lab"},),
        )
        self.assertEqual(
            source_child._pando_artifact(v1, C),
            "receipt_pando_receipt_not_v2")

        v2 = SimpleNamespace(
            schema="v2",
            payload={"receipt_schema": "rootyard/native-build-receipt/v2"},
            artifacts=(),
        )
        self.assertEqual(
            source_child._pando_artifact(v2, C),
            "receipt_pando_artifact_missing")

        wrong = SimpleNamespace(
            schema="v2",
            payload={"receipt_schema": "rootyard/native-build-receipt/v2"},
            artifacts=({
                "kind": "bin",
                "target": "rootyard-pando-lab",
                "executable_sha256": "f" * 64,
            },),
        )
        self.assertEqual(
            source_child._pando_artifact(wrong, C),
            "receipt_pando_artifact_mismatch")
        good = SimpleNamespace(
            schema="v2",
            payload={"receipt_schema": "rootyard/native-build-receipt/v2"},
            artifacts=({
                "kind": "bin",
                "target": "rootyard-pando-lab",
                "executable_sha256": C,
            },),
        )
        self.assertIsNone(source_child._pando_artifact(good, C))


if __name__ == "__main__":
    unittest.main()
