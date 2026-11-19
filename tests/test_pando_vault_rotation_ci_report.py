#!/usr/bin/env python3
"""Pure contract tests for the issue #21 Vault native-gate projection.

No Vault, PostgreSQL, Docker, Git, network, product binary, compiler, Cargo or
CI is started.  File inputs live only in owned temporary directories, and the
single source/binary/receipt validator is mocked with finite facts.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation as rotation  # noqa: E402
import pando_vault_rotation_ci_report as adapter  # noqa: E402


def validated_facts():
    return {
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "source_clean": True,
        "binary_sha256": "c" * 64,
        "receipt_sha256": "d" * 64,
        "harness_sha256": "e" * 64,
    }


def cleanup_facts():
    return {
        "vault_owned": True,
        "vault_stopped": True,
        "container_absent": True,
        "postgres_owned": True,
        "postgres_created": True,
        "postgres_dropped": True,
        "database_absent": True,
        "root_owned": True,
        "root_removed": True,
        "root_absent": True,
        "server_stopped": True,
        "cleanup_ok": True,
        "credential_released": True,
        "pg_major": 17,
        "image_digest_sha256": "f" * 64,
        "vault_version": "2.2.2",
        "no_global_cleanup": True,
        "raw_logs_persisted": False,
    }


def good_raw(validated):
    cleanup = cleanup_facts()
    cases = [
        {"id": case_id, "status": "passed", "facts": {}}
        for case_id in adapter.CASE_IDS[:-1]
    ]
    cases.append({
        "id": adapter.CLEANUP_CASE_ID,
        "status": "passed",
        "code": None,
        "facts": cleanup,
    })
    return {
        "schema": adapter.REPORT_SCHEMA,
        "passed": True,
        "status": "passed",
        "case_count": 5,
        "cases": cases,
        "binding": {
            "source_commit": validated["source_commit"],
            "source_tree": validated["source_tree"],
            "source_clean": True,
            "binary_sha256": validated["binary_sha256"],
            "receipt_sha256": validated["receipt_sha256"],
            "harness_sha256": validated["harness_sha256"],
        },
        "cleanup": copy.deepcopy(cleanup),
        "limitations": list(rotation.ALLOWED_LIMITATIONS),
    }


def make_args(raw_report, output):
    return adapter.parse_args([
        "--source-root", str(Path(raw_report).parent),
        "--binary", str(Path(raw_report).parent / "rootyard-pando-lab"),
        "--receipt", str(Path(raw_report).parent / "receipt.json"),
        "--expected-commit", "a" * 40,
        "--raw-report", str(raw_report),
        "--output", str(output),
    ])


def write_raw(path, payload):
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    Path(path).write_bytes(data)
    return data


class ProjectionContractTest(unittest.TestCase):
    def setUp(self):
        self.validated = validated_facts()

    def project(self, payload, validated=None, secrets=()):
        return adapter.project(
            payload, "9" * 64, "a" * 40,
            self.validated if validated is None else validated,
            secrets=secrets,
        )

    def reject(self, code, payload, validated=None, secrets=()):
        with self.assertRaises(adapter.ProjectionError) as caught:
            self.project(payload, validated=validated, secrets=secrets)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_projects_exactly_five_named_passed_cases_to_fixed_fields(self):
        projection = self.project(good_raw(self.validated))
        self.assertEqual(set(projection), {
            "passed", "binary_sha256", "source_head", "cases",
            "case_count", "raw_report_sha256",
        })
        self.assertIs(projection["passed"], True)
        self.assertEqual(projection["binary_sha256"], "c" * 64)
        self.assertEqual(projection["source_head"], "a" * 40)
        self.assertEqual(projection["case_count"], 5)
        self.assertEqual(projection["raw_report_sha256"], "9" * 64)
        self.assertEqual(
            [case["name"] for case in projection["cases"]],
            list(adapter.CASE_IDS),
        )
        self.assertTrue(all(case["status"] == "passed"
                            for case in projection["cases"]))
        self.assertTrue(all(set(case) == {"name", "status"}
                            for case in projection["cases"]))

    def test_uses_validated_source_identity_not_raw_input_alone(self):
        payload = good_raw(self.validated)
        projection = self.project(payload)
        self.assertEqual(projection["source_head"], self.validated["source_commit"])
        changed = validated_facts()
        changed["source_commit"] = "1" * 40
        self.reject("validated_source_commit_mismatch", payload, changed)

    def test_requires_all_five_in_order(self):
        payload = good_raw(self.validated)
        payload["cases"] = payload["cases"][:4]
        payload["case_count"] = 4
        self.reject("raw_report_case_count_mismatch", payload)
        payload = good_raw(self.validated)
        payload["case_count"] = "5"
        self.reject("raw_report_case_count_mismatch", payload)

    def test_duplicate_case_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"][1] = copy.deepcopy(payload["cases"][0])
        self.reject("raw_report_case_order_mismatch", payload)

    def test_missing_case_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"].pop()
        self.reject("raw_report_case_count_mismatch", payload)

    def test_extra_case_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"].append(copy.deepcopy(payload["cases"][0]))
        payload["case_count"] = 6
        self.reject("raw_report_case_count_mismatch", payload)

    def test_foreign_case_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"][3]["id"] = "foreign_case"
        self.reject("raw_report_case_order_mismatch", payload)

    def test_unknown_case_status_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"][2]["status"] = "skipped"
        self.reject("raw_report_case_not_passed", payload)

    def test_raw_failure_cannot_be_projected_as_pass(self):
        payload = good_raw(self.validated)
        payload["passed"] = False
        payload["status"] = "failed"
        self.reject("raw_report_not_passed", payload)
        payload = good_raw(self.validated)
        payload["error_code"] = "mandatory_case_failed"
        payload["stage"] = "case"
        self.reject("raw_report_failure_fields_present", payload)

    def test_schema_must_be_the_canonical_v1_schema(self):
        payload = good_raw(self.validated)
        payload["schema"] = "rootyard/issue21-derived-vault-rotation/v2"
        self.reject("raw_report_schema_mismatch", payload)

    def test_limitations_must_be_the_registered_set(self):
        payload = good_raw(self.validated)
        payload["limitations"] = []
        self.reject("raw_report_limitations_invalid", payload)

    def test_unreadable_binding_shape_is_rejected(self):
        payload = good_raw(self.validated)
        payload["binding"] = []
        self.reject("raw_report_binding_invalid", payload)

    def test_missing_binding_field_is_rejected(self):
        payload = good_raw(self.validated)
        del payload["binding"]["source_tree"]
        self.reject("raw_report_binding_fields_invalid", payload)

    def test_mismatched_binding_digests_are_rejected(self):
        for key in ("binary_sha256", "receipt_sha256", "harness_sha256"):
            payload = good_raw(self.validated)
            payload["binding"][key] = "0" * 64
            self.reject("binding_" + key + "_mismatch", payload)

    def test_mismatched_commit_is_rejected(self):
        payload = good_raw(self.validated)
        payload["binding"]["source_commit"] = "1" * 40
        self.reject("binding_source_commit_mismatch", payload)

    def test_mismatched_tree_is_rejected(self):
        payload = good_raw(self.validated)
        payload["binding"]["source_tree"] = "1" * 40
        self.reject("binding_source_tree_mismatch", payload)

    def test_raw_binding_must_claim_clean_source(self):
        payload = good_raw(self.validated)
        payload["binding"]["source_clean"] = False
        self.reject("raw_report_binding_source_not_clean", payload)

    def test_validated_source_must_be_clean_and_tree_must_be_an_identity(self):
        changed = validated_facts()
        changed["source_clean"] = False
        self.reject("validated_source_not_clean",
                    good_raw(self.validated), changed)
        changed = validated_facts()
        changed["source_tree"] = "not-a-tree"
        self.reject("validated_source_invalid",
                    good_raw(self.validated), changed)

    def test_failed_cleanup_and_cleanup_case_cannot_pass(self):
        for target in ("cleanup", "case"):
            payload = good_raw(self.validated)
            if target == "cleanup":
                payload["cleanup"]["cleanup_ok"] = False
            else:
                payload["cases"][-1]["facts"]["cleanup_ok"] = False
            self.reject("raw_report_cleanup_not_truthful", payload)

    def test_unresolved_owned_resource_fact_cannot_pass(self):
        payload = good_raw(self.validated)
        for key in ("vault_stopped", "postgres_dropped", "root_removed",
                    "server_stopped", "container_absent", "database_absent",
                    "root_absent"):
            candidate = copy.deepcopy(payload)
            candidate["cleanup"][key] = False
            self.reject("raw_report_cleanup_not_truthful", candidate)

    def test_cleanup_missing_or_unknown_fact_is_rejected(self):
        payload = good_raw(self.validated)
        del payload["cleanup"]["postgres_dropped"]
        self.reject("raw_report_cleanup_missing", payload)
        payload = good_raw(self.validated)
        payload["cleanup"]["endpoint"] = "http://127.0.0.1"
        self.reject("raw_report_field_rejected", payload)

    def test_unknown_raw_field_is_rejected(self):
        payload = good_raw(self.validated)
        payload["token"] = "supersecretvalue"
        self.reject("raw_report_field_rejected", payload)

    def test_secret_bearing_value_is_rejected_without_echo(self):
        payload = good_raw(self.validated)
        payload["cases"][0]["facts"]["source"] = "postgresql://u:p@127.0.0.1/db"
        self.reject("raw_report_unsafe_value", payload)
        payload = good_raw(self.validated)
        payload["cases"][0]["facts"]["source"] = "supersecretvalue"
        self.reject("raw_report_secret_present", payload,
                    secrets=("supersecretvalue",))

    def test_unregistered_case_field_is_rejected(self):
        payload = good_raw(self.validated)
        payload["cases"][0]["name"] = adapter.CASE_IDS[0]
        self.reject("raw_report_field_rejected", payload)

    def test_invalid_raw_digest_is_rejected(self):
        with self.assertRaises(adapter.ProjectionError) as caught:
            adapter.project(good_raw(self.validated), "bad", "a" * 40,
                            self.validated)
        self.assertEqual(caught.exception.code, "raw_report_digest_invalid")

class CliAndFileContractTest(unittest.TestCase):
    def setUp(self):
        self.validated = validated_facts()

    def test_every_explicit_cli_argument_is_required(self):
        pairs = [
            ("--source-root", "/owned/source"),
            ("--binary", "/owned/rootyard-pando-lab"),
            ("--receipt", "/owned/receipt.json"),
            ("--expected-commit", "a" * 40),
            ("--raw-report", "/owned/raw.json"),
            ("--output", "/owned/output.json"),
        ]
        for index in range(len(pairs)):
            argv = [item for position, pair in enumerate(pairs)
                    if position != index for item in pair]
            with self.subTest(missing=pairs[index][0]):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        adapter.parse_args(argv)

    def test_collect_writes_deterministic_projection_and_preserves_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "pando-vault-rotation.json"
            output = root / "pando-vault-native-report.json"
            raw_bytes = write_raw(raw, good_raw(self.validated))
            raw_sha = hashlib.sha256(raw_bytes).hexdigest()
            args = make_args(raw, output)
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   return_value=self.validated):
                first = adapter.collect(args, environ={})
                first_bytes = output.read_bytes()
                second = adapter.collect(args, environ={})
                second_bytes = output.read_bytes()
            self.assertEqual(first, second)
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(first_bytes,
                             (json.dumps(second, indent=2, sort_keys=True)
                              + "\n").encode())
            self.assertEqual(first["raw_report_sha256"], raw_sha)
            self.assertEqual(raw.read_bytes(), raw_bytes)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_collect_failure_removes_stale_output_and_keeps_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "pando-vault-rotation.json"
            output = root / "pando-vault-native-report.json"
            payload = good_raw(self.validated)
            payload["cleanup"]["cleanup_ok"] = False
            raw_bytes = write_raw(raw, payload)
            output.write_text("stale passing projection")
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   return_value=self.validated):
                with self.assertRaises(adapter.ProjectionError) as caught:
                    adapter.collect(make_args(raw, output), environ={})
            self.assertEqual(caught.exception.code,
                             "raw_report_cleanup_not_truthful")
            self.assertFalse(output.exists())
            self.assertEqual(raw.read_bytes(), raw_bytes)

    def test_output_must_not_alias_the_canonical_raw_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "pando-vault-rotation.json"
            raw_bytes = write_raw(raw, good_raw(self.validated))
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   return_value=self.validated):
                with self.assertRaises(adapter.ProjectionError) as caught:
                    adapter.collect(make_args(raw, raw), environ={})
            self.assertEqual(caught.exception.code,
                             "output_aliases_raw_report")
            self.assertEqual(raw.read_bytes(), raw_bytes)

    def test_unreadable_raw_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(adapter.ProjectionError) as caught:
                adapter.collect(
                    make_args(root / "missing.json", root / "out.json"),
                    environ={})
            self.assertEqual(caught.exception.code, "raw_report_unreadable")

    def test_invalid_json_raw_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            raw.write_text("{not json")
            with self.assertRaises(adapter.ProjectionError) as caught:
                adapter.collect(make_args(raw, root / "out.json"), environ={})
            self.assertEqual(caught.exception.code, "raw_report_invalid_json")

    def test_non_object_raw_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            raw.write_text("[]")
            with self.assertRaises(adapter.ProjectionError) as caught:
                adapter.collect(make_args(raw, root / "out.json"), environ={})
            self.assertEqual(caught.exception.code, "raw_report_not_object")

    def test_cli_success_prints_only_finite_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            output = root / "out.json"
            write_raw(raw, good_raw(self.validated))
            argv = [
                "--source-root", str(root),
                "--binary", str(root / "rootyard-pando-lab"),
                "--receipt", str(root / "receipt.json"),
                "--expected-commit", "a" * 40,
                "--raw-report", str(raw),
                "--output", str(output),
            ]
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   return_value=self.validated):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = adapter.main(argv)
            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(json.loads(stdout.getvalue()),
                             {"passed": True, "case_count": 5})
            self.assertTrue(output.is_file())

    def test_cli_failure_prints_fixed_code_without_path_or_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            output = root / "out.json"
            payload = good_raw(self.validated)
            payload["token"] = "supersecretvalue"
            write_raw(raw, payload)
            argv = [
                "--source-root", str(root),
                "--binary", str(root / "rootyard-pando-lab"),
                "--receipt", str(root / "receipt.json"),
                "--expected-commit", "a" * 40,
                "--raw-report", str(raw),
                "--output", str(output),
            ]
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   return_value=self.validated):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = adapter.main(argv)
            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(),
                             "pando_vault_rotation_ci_report: "
                             "raw_report_field_rejected\n")
            self.assertNotIn("supersecretvalue", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertFalse(output.exists())

    def test_collect_does_not_echo_validator_exception_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            write_raw(raw, good_raw(self.validated))
            error = rotation.QualificationError("receipt_rejected", "binding")
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   side_effect=error):
                with self.assertRaises(adapter.ProjectionError) as caught:
                    adapter.collect(make_args(raw, root / "out.json"), environ={})
            self.assertEqual(caught.exception.code, "receipt_rejected")
            self.assertNotIn(str(root), str(caught.exception))
            unsafe = rotation.QualificationError(
                "secret " + str(root), "binding")
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   side_effect=unsafe):
                with self.assertRaises(adapter.ProjectionError) as caught:
                    adapter.collect(make_args(raw, root / "out.json"), environ={})
            self.assertEqual(caught.exception.code, "input_validation_failed")
            self.assertNotIn(str(root), str(caught.exception))

    def test_unexpected_validator_failure_is_fixed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.json"
            write_raw(raw, good_raw(self.validated))
            with mock.patch.object(adapter.rotation, "validate_inputs",
                                   side_effect=RuntimeError("untrusted body")):
                with self.assertRaises(adapter.ProjectionError) as caught:
                    adapter.collect(make_args(raw, root / "out.json"), environ={})
            self.assertEqual(caught.exception.code, "input_validation_failed")
            self.assertNotIn("untrusted", str(caught.exception))

    def test_harness_glob_covers_both_new_files(self):
        harness_names = {path.name for path in rotation._harness_files()}
        self.assertIn(Path(adapter.__file__).name, harness_names)
        self.assertIn(Path(__file__).name, harness_names)

if __name__ == "__main__":
    unittest.main()
