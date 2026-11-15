#!/usr/bin/env python3
"""Pure failure-boundary tests for the focused legacy135 qualification gate.

No Docker daemon, Vault, PostgreSQL, HTTP provider, Cargo, native binary or
archive is used.  The tests cover the boundaries that make a hosted green
meaningful: exact seven-case selection, receipt/source anchors, ownership-safe
provider cleanup, binding drift and secret-free reports.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import legacy135_qualification as gate  # noqa: E402


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if not self.results:
            raise AssertionError("unexpected docker call")
        return self.results.pop(0)


def owned_state(cid="a" * 64, nonce="b" * 12, uid=None):
    return {
        "kind": gate.VAULT_KIND,
        "goal": gate.VAULT_GOAL,
        "nonce": nonce,
        "uid": os.getuid() if uid is None else uid,
        "container_id": cid,
        "container_name": "rootyard-legacy135-vault-" + nonce,
        "image": gate.VAULT_IMAGE,
    }


def labels(state):
    return {
        "rootyard.fixture.kind": state["kind"],
        "rootyard.fixture.nonce": state["nonce"],
        "rootyard.fixture.goal": state["goal"],
        "rootyard.fixture.uid": str(state["uid"]),
    }


def report_inputs():
    return {
        "expected_candidate_sha256": "a" * 64,
        "expected_producer_sha256": "b" * 64,
        "expected_candidate_commit": "c" * 40,
    }


def valid_report():
    return {
        "passed": True,
        "cases": [
            {"name": name, "status": "passed", "detail": "secret-bearing detail"}
            for name in gate.required_cases()
        ],
        "reviewed_target_schema": gate.LEGACY135_CURRENT_TARGET.target_schema,
        "reviewed_target_format": gate.LEGACY135_CURRENT_TARGET.target_format,
        "binary_sha256": "a" * 64,
        "legacy_binary_sha256": "b" * 64,
        "harness_git_head": "c" * 40,
    }


class CaseContractTest(unittest.TestCase):
    def test_required_cases_are_exact_and_derive_the_target_name(self):
        cases = gate.required_cases()
        self.assertEqual(len(cases), 7)
        self.assertEqual(cases[0], "create_real_schema135_pando_source")
        self.assertIn(
            "candidate_restores_schema%s_one_new_authority"
            % gate.CURRENT_SCHEMA_VERSION,
            cases,
        )
        self.assertEqual(
            cases[-2:],
            ("restored_service_git_and_session_boundaries",
             "source_authority_and_remote_objects_remain_available"),
        )

    def test_report_projects_only_names_and_green_statuses(self):
        parsed = gate.parse_legacy_report(json.dumps(valid_report()), report_inputs())
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["case_count"], 7)
        text = json.dumps(parsed)
        self.assertNotIn("secret-bearing detail", text)
        self.assertNotIn("detail", text)
        self.assertEqual([case["status"] for case in parsed["cases"]], ["passed"] * 7)

    def test_progress_lines_before_terminal_report_are_tolerated(self):
        raw = "create_real_schema135_pando_source: passed\n" + json.dumps(valid_report())
        parsed = gate.parse_legacy_report(raw, report_inputs())
        self.assertEqual(parsed["case_count"], 7)

    def test_missing_extra_duplicate_skipped_and_target_drift_fail(self):
        variants = []
        missing = valid_report()
        missing["cases"] = missing["cases"][:-1]
        variants.append((missing, "legacy_case_count_invalid"))
        extra = valid_report()
        extra["cases"].append({"name": "extra", "status": "passed"})
        variants.append((extra, "legacy_case_count_invalid"))
        duplicate = valid_report()
        duplicate["cases"][-1] = dict(duplicate["cases"][0])
        variants.append((duplicate, "legacy_cases_mismatch"))
        skipped = valid_report()
        skipped["cases"][2]["status"] = "skipped"
        variants.append((skipped, "legacy_case_not_green"))
        target = valid_report()
        target["reviewed_target_schema"] = 148
        variants.append((target, "legacy_target_schema_mismatch"))
        for raw, code in variants:
            with self.subTest(code=code):
                with self.assertRaises(gate.QualificationError) as caught:
                    gate.parse_legacy_report(json.dumps(raw), report_inputs())
                self.assertEqual(caught.exception.code, code)

    def test_non_json_or_not_passed_report_is_static_failure(self):
        for raw, code in (("not-json", "legacy_report_invalid"),
                          (json.dumps({"passed": False}), "legacy_report_not_passed")):
            with self.subTest(code=code):
                with self.assertRaises(gate.QualificationError) as caught:
                    gate.parse_legacy_report(raw, report_inputs())
                self.assertEqual(caught.exception.code, code)

    def test_candidate_and_producer_hash_drift_fail(self):
        raw = valid_report()
        raw["binary_sha256"] = "d" * 64
        with self.assertRaises(gate.QualificationError) as caught:
            gate.parse_legacy_report(json.dumps(raw), report_inputs())
        self.assertEqual(caught.exception.code, "legacy_candidate_sha_mismatch")
        raw = valid_report()
        raw["legacy_binary_sha256"] = "d" * 64
        with self.assertRaises(gate.QualificationError) as caught:
            gate.parse_legacy_report(json.dumps(raw), report_inputs())
        self.assertEqual(caught.exception.code, "legacy_producer_sha_mismatch")


class BindingAndCaptureTest(unittest.TestCase):
    def test_binding_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_text("one")
            before = {"files": {str(path): gate.sha256_file(path)}}
            path.write_text("two")
            after = {"files": {str(path): gate.sha256_file(path)}}
            with self.assertRaises(gate.QualificationError) as caught:
                gate.require_binding_unchanged(before, after)
            self.assertEqual(caught.exception.code, "binding_changed")

    def test_invoke_legacy_never_passes_the_unsafe_report_option(self):
        captured = {}

        def fake_run_main(contract, argv=None):
            captured["contract"] = contract
            captured["argv"] = argv
            return 0

        with mock.patch.object(gate.legacy, "run_main", fake_run_main):
            code, stdout, stderr = gate.invoke_legacy({
                "candidate_binary": Path("/tmp/candidate"),
                "producer_binary": Path("/tmp/producer"),
            })
        self.assertEqual(code, 0)
        self.assertNotIn("--report", captured["argv"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertIs(captured["contract"], gate.LEGACY135_CURRENT_TARGET)

    def test_secret_bearing_unexpected_error_is_not_projected(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "qualification.json"
            args = argparse.Namespace(
                report=str(report),
                provider_report=None,
                vault_state=str(Path(temporary) / "vault-state.json"),
            )
            secret = "provider-token-that-must-not-escape"
            stderr = io.StringIO()
            with mock.patch.object(gate, "validate_inputs",
                                   side_effect=RuntimeError(secret)), \
                    mock.patch.object(gate, "validate_object_store_environment"), \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(gate.run_qualification(args), 1)
            text = report.read_text() + stderr.getvalue()
            self.assertNotIn(secret, text)
            self.assertNotIn("RuntimeError", text)
            self.assertIn("unexpected_error", text)


class ProviderOwnershipTest(unittest.TestCase):
    def test_cleanup_removes_only_the_exact_labelled_container(self):
        state = owned_state()
        runner = FakeRunner([
            Result(0, (state["container_id"] + "\n").encode()),
            Result(0, json.dumps(labels(state)).encode()),
            Result(0),
        ])
        self.assertEqual(gate.remove_owned_container(runner, state), "stopped")
        self.assertEqual(runner.calls[-1],
                         ["docker", "rm", "-f", "--", state["container_id"]])

    def test_cleanup_refuses_a_foreign_container_id(self):
        state = owned_state()
        runner = FakeRunner([Result(0, (("f" * 64) + "\n").encode())])
        with self.assertRaises(gate.QualificationError) as caught:
            gate.remove_owned_container(runner, state)
        self.assertEqual(caught.exception.code, "vault_cleanup_id_mismatch")
        self.assertFalse(any(call[1:2] == ["rm"] for call in runner.calls))

    def test_cleanup_refuses_mismatched_ownership_labels(self):
        state = owned_state()
        wrong = labels(state)
        wrong["rootyard.fixture.nonce"] = "c" * 12
        runner = FakeRunner([
            Result(0, (state["container_id"] + "\n").encode()),
            Result(0, json.dumps(wrong).encode()),
        ])
        with self.assertRaises(gate.QualificationError) as caught:
            gate.remove_owned_container(runner, state)
        self.assertEqual(caught.exception.code, "vault_cleanup_label_mismatch")
        self.assertFalse(any(call[1:2] == ["rm"] for call in runner.calls))

    def test_cleanup_refuses_an_unreadable_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            state.write_text("not-json")
            with self.assertRaises(gate.QualificationError) as caught:
                gate.cleanup_owned_state(state)
            self.assertEqual(caught.exception.code, "vault_state_invalid")
            self.assertTrue(state.exists())

    def test_safe_provider_record_excludes_locator_and_tokens(self):
        fixture = gate.VaultFixture("/tmp/state", runner=FakeRunner([]))
        fixture.container_id = "a" * 64
        fixture.host_url = "http://127.0.0.1:12345"
        fixture.root_token = "root-secret"
        fixture.service_token = "service-secret"
        fixture.prepared = True
        fixture.version = gate.VAULT_VERSION
        text = json.dumps(fixture.safe_record("stopped"))
        for forbidden in ("root-secret", "service-secret", "127.0.0.1",
                          "12345", "rootyard-legacy135-"):
            self.assertNotIn(forbidden, text)

    def test_service_policy_is_limited_to_the_transit_key_operations(self):
        policy = gate.service_policy("rootyard-legacy135-abc")
        self.assertNotIn('path "sys/', policy)
        self.assertNotIn('path "transit/keys"', policy)
        self.assertIn('transit/encrypt/rootyard-legacy135-abc', policy)
        self.assertIn('transit/decrypt/rootyard-legacy135-abc', policy)
        self.assertIn('transit/rewrap/rootyard-legacy135-abc', policy)
        self.assertIn('transit/keys/rootyard-legacy135-abc/rotate', policy)

    def test_cleanup_cli_does_not_require_acceptance_inputs(self):
        args = gate.parse_args(["--cleanup-owned-state", "/tmp/owned-state.json"])
        self.assertEqual(args.cleanup_owned_state, "/tmp/owned-state.json")


if __name__ == "__main__":
    unittest.main()
