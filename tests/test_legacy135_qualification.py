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
    def __init__(self, results, on_call=None):
        self.results = list(results)
        self.calls = []
        self.on_call = on_call

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.on_call is not None:
            self.on_call(list(argv))
        if not self.results:
            raise AssertionError("unexpected docker call")
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def owned_state(cid="a" * 64, nonce="b" * 12, uid=None, phase="created"):
    return {
        "schema": gate.OWNERSHIP_SCHEMA,
        "phase": phase,
        "kind": gate.VAULT_KIND,
        "goal": gate.VAULT_GOAL,
        "nonce": nonce,
        "uid": os.getuid() if uid is None else uid,
        "container_id": cid if phase == "created" else None,
        "container_name": gate.expected_container_name(nonce),
        "image": gate.VAULT_IMAGE,
    }


def image_result():
    return Result(0, (json.dumps([gate.VAULT_IMAGE]) + "\n").encode())


def inspect_results(state, image=None, label_values=None):
    cid = state["container_id"]
    return [
        Result(0, (cid + "\n").encode()),
        Result(0, ((image or state["image"]) + "\n").encode()),
        Result(0, json.dumps(label_values or labels(state)).encode()),
    ]


def ps_result(state, cid=None):
    cid = cid or state["container_id"]
    return Result(0, (cid + "\t" + state["container_name"] + "\n").encode())


def fixture_for(path, runner, nonce=None):
    value = gate.VaultFixture(
        path, runner=runner, token_factory=lambda _: "root-token",
        sleep=lambda _: None)
    if nonce is not None:
        value.nonce = nonce
        value.container_name = gate.expected_container_name(nonce)
        value.key_name = "rootyard-legacy135-" + nonce
        value.policy_name = "rootyard-legacy135-service-" + nonce
    return value


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
        runner = FakeRunner(inspect_results(state) + [Result(0)])
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
        runner = FakeRunner(inspect_results(state, label_values=wrong))
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

    def test_intent_is_persisted_before_docker_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            phase_at_run = {}

            def watch(argv):
                if argv[:2] == ["docker", "run"]:
                    persisted = json.loads(state.read_text())
                    phase_at_run.update(persisted)

            runner = FakeRunner([
                image_result(),
                Result(1),
                Result(0, b""),
            ], on_call=watch)
            fixture = gate.VaultFixture(
                state, runner=runner, token_factory=lambda _: "root-token",
                sleep=lambda _: None)
            with self.assertRaises(gate.QualificationError) as caught:
                fixture.start()
            self.assertEqual(caught.exception.code, "vault_start_failed")
            self.assertEqual(phase_at_run["phase"], "intent")
            self.assertIsNone(phase_at_run["container_id"])
            self.assertTrue(state.exists())
            self.assertEqual(gate.cleanup_owned_state(
                state, runner=FakeRunner([Result(0, b"")])), 0)
            self.assertFalse(state.exists())

    def test_create_then_timeout_reconciles_and_cleanup_removes_exact_id(self):
        state = owned_state(nonce="123456789abc")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                gate.QualificationError("docker_process_failed"),
                ps_result(state),
                *inspect_results(state),
            ])
            fixture = fixture_for(path, runner, state["nonce"])
            with self.assertRaises(gate.QualificationError) as caught:
                fixture.start()
            self.assertEqual(caught.exception.code, "docker_process_failed")
            persisted = json.loads(path.read_text())
            self.assertEqual(persisted["phase"], "created")
            self.assertEqual(persisted["container_id"], state["container_id"])
            cleanup = FakeRunner(inspect_results(state) + [Result(0)])
            self.assertEqual(gate.cleanup_owned_state(path, runner=cleanup), 0)
            self.assertEqual(cleanup.calls[-1],
                             ["docker", "rm", "-f", "--", state["container_id"]])
            self.assertFalse(path.exists())

    def test_create_then_nonzero_reconciles_and_cleanup_removes_exact_id(self):
        state = owned_state(nonce="123456789abd")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(1),
                ps_result(state),
                *inspect_results(state),
            ])
            fixture = fixture_for(path, runner, state["nonce"])
            with self.assertRaises(gate.QualificationError) as caught:
                fixture.start()
            self.assertEqual(caught.exception.code, "vault_start_failed")
            self.assertEqual(json.loads(path.read_text())["container_id"],
                             state["container_id"])
            cleanup = FakeRunner(inspect_results(state) + [Result(0)])
            self.assertEqual(gate.cleanup_owned_state(path, runner=cleanup), 0)
            self.assertEqual(cleanup.calls[-1],
                             ["docker", "rm", "-f", "--", state["container_id"]])

    def test_malformed_id_reconciles_and_cleanup_removes_exact_id(self):
        state = owned_state(nonce="123456789abe")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(0, b"not-a-container-id\n"),
                ps_result(state),
                *inspect_results(state),
            ])
            fixture = fixture_for(path, runner, state["nonce"])
            with self.assertRaises(gate.QualificationError) as caught:
                fixture.start()
            self.assertEqual(caught.exception.code, "vault_container_id_invalid")
            self.assertEqual(json.loads(path.read_text())["container_id"],
                             state["container_id"])
            cleanup = FakeRunner(inspect_results(state) + [Result(0)])
            self.assertEqual(gate.cleanup_owned_state(path, runner=cleanup), 0)

    def test_mismatched_ownership_fails_closed_and_preserves_state(self):
        state = owned_state(nonce="123456789abf")
        wrong_image = "hashicorp/vault:latest"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(0, (state["container_id"] + "\n").encode()),
                *inspect_results(state, image=wrong_image),
                ps_result(state),
                *inspect_results(state, image=wrong_image),
            ])
            fixture = fixture_for(path, runner, state["nonce"])
            with self.assertRaises(gate.QualificationError) as caught:
                fixture.start()
            self.assertEqual(caught.exception.code,
                             "vault_ownership_image_mismatch")
            self.assertTrue(path.exists())
            cleanup = FakeRunner([
                ps_result(state),
                *inspect_results(state, image=wrong_image),
            ])
            with self.assertRaises(gate.QualificationError) as cleanup_error:
                gate.cleanup_owned_state(path, runner=cleanup)
            self.assertEqual(cleanup_error.exception.code,
                             "vault_cleanup_image_mismatch")
            self.assertTrue(path.exists())

    def test_zero_container_is_honest_no_resource(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(1),
                Result(0, b""),
            ])
            fixture = gate.VaultFixture(
                path, runner=runner, token_factory=lambda _: "root-token",
                sleep=lambda _: None)
            with self.assertRaises(gate.QualificationError):
                fixture.start()
            self.assertEqual(json.loads(path.read_text())["phase"], "intent")
            self.assertEqual(gate.cleanup_owned_state(
                path, runner=FakeRunner([Result(0, b"")])), 0)
            self.assertFalse(path.exists())

    def test_daemon_uncertainty_preserves_intent_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(1),
                Result(1, b"", b"daemon unavailable"),
            ])
            fixture = gate.VaultFixture(
                path, runner=runner, token_factory=lambda _: "root-token",
                sleep=lambda _: None)
            with self.assertRaises(gate.QualificationError):
                fixture.start()
            self.assertEqual(json.loads(path.read_text())["phase"], "intent")
            with self.assertRaises(gate.QualificationError) as caught:
                gate.cleanup_owned_state(
                    path, runner=FakeRunner([Result(1, b"", b"uncertain")]))
            self.assertEqual(caught.exception.code,
                             "vault_cleanup_name_query_failed")
            self.assertTrue(path.exists())

    def test_effective_publication_requires_exact_ipv4_loopback(self):
        self.assertEqual(gate.published_loopback_url(["127.0.0.1:8201"]),
                         "http://127.0.0.1:8201")
        for published in (
            "0.0.0.0:8201",
            "[::]:8201",
            "::1:8201",
            "localhost:8201",
            "192.168.1.5:8201",
            "127.0.0.2:8201",
        ):
            with self.subTest(published=published):
                with self.assertRaises(gate.QualificationError) as caught:
                    gate.published_loopback_url([published])
                self.assertEqual(caught.exception.code, "vault_port_not_loopback")
        for published in ("127.0.0.1", "127.0.0.1:not-a-port",
                          "127.0.0.1:0", "127.0.0.1:65536"):
            with self.subTest(published=published):
                with self.assertRaises(gate.QualificationError) as caught:
                    gate.published_loopback_url([published])
                self.assertEqual(caught.exception.code, "vault_port_invalid")

    def test_wildcard_publication_fails_before_vault_api(self):
        state = owned_state(nonce="123456789ab0")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            runner = FakeRunner([
                image_result(),
                Result(0, (state["container_id"] + "\n").encode()),
                *inspect_results(state),
                Result(0, b"0.0.0.0:12345\n"),
            ])
            fixture = fixture_for(path, runner, state["nonce"])
            with mock.patch.object(
                    gate.urllib.request, "urlopen",
                    side_effect=AssertionError("Vault API must not be called")):
                with self.assertRaises(gate.QualificationError) as caught:
                    fixture.start()
            self.assertEqual(caught.exception.code, "vault_port_not_loopback")
            self.assertIsNone(fixture.host_url)
            self.assertTrue(path.exists())

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
