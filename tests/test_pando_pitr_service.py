"""Unit-test wrapper and pure reporting-boundary tests for Pando PITR acceptance (#77)."""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_service  # noqa: E402
import run_python_ci_tests  # noqa: E402
import runtime_binary  # noqa: E402
from test_native_build_receipt_v2 import ReceiptFixture  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40

# The hosted PR 258 Python suite step is the only place the workflow sets this
# exact opt-in.  The value is an authorization signal, never a write path.
FAILURE_CHECKPOINT_ENV = "ROOTYARD_PYTHON_CI_REPORT"
FAILURE_CHECKPOINT_OPT_IN = "test-results/python-ci-result.json"
FAILURE_CHECKPOINT_NAME = "pando-pitr-failure.json"
FAILURE_CHECKPOINT_MAX_BYTES = 4096
_FAILURE_CHECKPOINT_STAGES = frozenset({"preflight", "suite", "postflight", "report"})
_FAILURE_CHECKPOINT_CODES = frozenset({
    "binary_mismatch",
    "binary_missing",
    "binary_unreadable",
    "deadline_exceeded",
    "expect_commit_missing",
    "extra_invalid",
    "git_unavailable",
    "harness_missing",
    "harness_unreadable",
    "invalid_result",
    "mandatory_case_not_passed",
    "provenance_changed",
    "receipt_changed",
    "receipt_commit_mismatch",
    "receipt_config_digest_missing",
    "receipt_file_closure_missing",
    "receipt_invalid",
    "receipt_missing",
    "receipt_schema_not_v2",
    "receipt_toolchain_incomplete",
    "receipt_toolchain_missing",
    "receipt_unreadable",
    "report_invalid",
    "report_missing",
    "source_head_changed",
    "source_head_mismatch",
    "spec_invalid",
    "suite_failed",
    "suite_not_passed",
    "unexpected_failure",
})
_FAILURE_CHECKPOINT_STATUSES = frozenset({"passed", "failed", "missing"})
_FULL_SHA1 = re.compile(r"[0-9a-f]{40}")
_FULL_SHA256 = re.compile(r"[0-9a-f]{64}")


def _pitr_failure_checkpoint_enabled(environ=None) -> bool:
    """Return true only for the exact hosted PR 258 opt-in."""
    values = os.environ if environ is None else environ
    try:
        return values.get(FAILURE_CHECKPOINT_ENV) == FAILURE_CHECKPOINT_OPT_IN
    except Exception:
        return False


def _pitr_failure_checkpoint_path() -> Path:
    """Return the fixed in-repository checkpoint path; never use the env value."""
    return ROOT / "test-results" / FAILURE_CHECKPOINT_NAME


def _pitr_failure_checkpoint_source(expect_commit: str | None) -> tuple[str, str] | None:
    """Bind the checkpoint to the exact expected checkout commit and tree."""
    if not isinstance(expect_commit, str) or _FULL_SHA1.fullmatch(expect_commit) is None:
        return None
    try:
        binding = run_python_ci_tests._checkout_binding(expect_commit)
    except Exception:
        return None
    if not isinstance(binding, tuple) or len(binding) != 2:
        return None
    commit, tree = binding
    if (
        commit != expect_commit
        or not isinstance(tree, str)
        or _FULL_SHA1.fullmatch(tree) is None
    ):
        return None
    return commit, tree


def _pitr_failure_checkpoint_cases(report) -> list[dict]:
    """Project only the seven known cases and their closed status vocabulary."""
    names = tuple(pando_pitr_service.MANDATORY_CASES)
    statuses: dict[str, str] = {}
    records = report.get("cases") if isinstance(report, dict) else None
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            name = record.get("name")
            status = record.get("status")
            if name in names and status in _FAILURE_CHECKPOINT_STATUSES:
                statuses[name] = status
    return [
        {"name": name, "status": statuses.get(name, "missing")}
        for name in names
    ]


def _pitr_failure_checkpoint_stage_code(report) -> tuple[str, str]:
    """Map a failed report to a closed producer-defined stage/code pair."""
    if report is None:
        return "report", "report_missing"
    if not isinstance(report, dict):
        return "report", "report_invalid"
    failure = report.get("failure")
    if isinstance(failure, dict):
        stage = failure.get("phase")
        code = failure.get("code")
        if stage in _FAILURE_CHECKPOINT_STAGES and code in _FAILURE_CHECKPOINT_CODES:
            return stage, code
    if report.get("passed") is False:
        return "suite", "suite_not_passed"
    return "report", "report_invalid"


def _pitr_failure_checkpoint_record(
    report,
    *,
    expect_commit: str | None,
) -> dict | None:
    """Build the bounded checkpoint body for one pre-assert failure."""
    if isinstance(report, dict) and report.get("passed") is True:
        return None
    binding = _pitr_failure_checkpoint_source(expect_commit)
    if binding is None:
        return None
    stage, code = _pitr_failure_checkpoint_stage_code(report)
    record = {
        "passed": False,
        "source_commit": binding[0],
        "source_tree": binding[1],
        "stage": stage,
        "code": code,
        "cases": _pitr_failure_checkpoint_cases(report),
    }
    receipt_digest = report.get("build_receipt_sha256") if isinstance(report, dict) else None
    if isinstance(receipt_digest, str) and _FULL_SHA256.fullmatch(receipt_digest):
        record["build_receipt_sha256"] = receipt_digest
    return record


def _write_pitr_failure_checkpoint(
    report,
    *,
    expect_commit: str | None,
    environ=None,
) -> Path | None:
    """Best-effort atomic publication; never replace the original assertion."""
    try:
        if not _pitr_failure_checkpoint_enabled(environ):
            return None
        record = _pitr_failure_checkpoint_record(report, expect_commit=expect_commit)
        if record is None:
            return None
        payload = (
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if not payload or len(payload) > FAILURE_CHECKPOINT_MAX_BYTES:
            return None
        destination = _pitr_failure_checkpoint_path()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=f".{FAILURE_CHECKPOINT_NAME}.",
                delete=False,
            ) as output:
                temporary = Path(output.name)
                output.write(payload)
            temporary.replace(destination)
            temporary = None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink()
                except OSError:
                    pass
        return destination
    except Exception:
        return None


class PandoPitrEvidenceBoundaryTest(ReceiptFixture):
    """Prove the report accepts only exact, immutable, fully-passed evidence."""

    def setUp(self) -> None:
        super().setUp()
        self.commit = COMMIT
        self.receipt_path = self.binary.with_suffix(".build.json")
        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit), indent=2) + "\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.harness = self.root / "owned-harness.py"
        self.harness.write_text("HARNESS_VERSION = 1\n", encoding="utf-8")
        self.report_path = self.root / "pando-pitr-service.json"
        self.lib_source = (self.root / "src/lib.rs").read_text(encoding="utf-8")
        head_patch = mock.patch.object(
            pando_pitr_service,
            "_workspace_head",
            lambda source_root, phase="preflight": self.commit,
        )
        head_patch.start()
        self.addCleanup(head_patch.stop)

    def passing_results(self) -> dict:
        results = {name: True for name in pando_pitr_service.MANDATORY_CASES}
        results["passed"] = True
        return results

    def run_acceptance(self, suite=None, **overrides) -> dict:
        arguments = {
            "binary": str(self.binary),
            "build_receipt": str(self.receipt_path),
            "expect_commit": self.commit,
            "report_path": self.report_path,
            "source_root": self.root,
            "harness_files": [self.harness],
            "suite": suite or (lambda binary: self.passing_results()),
        }
        arguments.update(overrides)
        return pando_pitr_service.run_acceptance(**arguments)

    def assert_preflight_failure(self, report: dict, calls: list[str]) -> None:
        self.assertFalse(report["passed"])
        self.assertEqual([], calls)
        self.assertEqual(report["failure"]["phase"], "preflight")
        self.assertEqual(report["cases"], [
            {"name": name, "status": "missing"}
            for name in pando_pitr_service.MANDATORY_CASES
        ])

    def test_missing_binary_and_receipt_fail_before_the_suite(self) -> None:
        for missing in ("binary", "receipt"):
            with self.subTest(missing=missing):
                calls: list[str] = []

                def spy(binary: str) -> dict:
                    calls.append(binary)
                    return self.passing_results()

                overrides = (
                    {"binary": str(self.root / "missing-rootyard")}
                    if missing == "binary"
                    else {"build_receipt": str(self.root / "missing.build.json")}
                )
                report = self.run_acceptance(spy, **overrides)
                self.assert_preflight_failure(report, calls)

    def test_mismatched_binary_receipt_and_commit_fail_before_the_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        self.binary.write_bytes(b"tampered-binary")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        self.binary.write_bytes(b"native-binary")

        payload = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        payload["workspace_commit"] = "b" * 40
        self.receipt_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)

        self.receipt_path.write_text(
            json.dumps(self.make_v2(workspace_commit=self.commit)), encoding="utf-8"
        )
        report = self.run_acceptance(spy, expect_commit="b" * 40)
        self.assert_preflight_failure(report, calls)
        self.assertEqual(report["failure"]["code"], "source_head_mismatch")

    def test_legacy_v1_receipt_without_config_or_toolchain_is_rejected_before_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        self.receipt_path.write_text(
            json.dumps(self.v1_receipt(), indent=2) + "\n", encoding="utf-8"
        )
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        self.assertEqual(report["failure"]["code"], "receipt_schema_not_v2")

    def test_v2_missing_config_toolchain_or_file_closure_is_rejected_before_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        payload = self.make_v2(workspace_commit=self.commit)
        for field in ("config_digest", "toolchain", "bound_input_inventory"):
            with self.subTest(field=field):
                broken = dict(payload)
                del broken[field]
                self.receipt_path.write_text(
                    json.dumps(broken), encoding="utf-8"
                )
                report = self.run_acceptance(spy)
                self.assert_preflight_failure(report, calls)
                self.assertEqual(report["failure"]["phase"], "preflight")

    def test_v2_invalid_config_digest_is_rejected_before_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        payload = self.make_v2(workspace_commit=self.commit)
        payload["config_digest"] = "not-a-sha256"
        self.receipt_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        self.assertEqual(report["failure"]["code"], "receipt_invalid")

    def test_source_file_closure_drift_fails_before_the_suite(self) -> None:
        calls: list[str] = []

        def spy(binary: str) -> dict:
            calls.append(binary)
            return self.passing_results()

        (self.root / "src/lib.rs").write_text("pub fn changed() {}\n", encoding="utf-8")
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)
        (self.root / "src/lib.rs").write_text(self.lib_source, encoding="utf-8")

        (self.root / "src/main.rs").unlink()
        report = self.run_acceptance(spy)
        self.assert_preflight_failure(report, calls)

    def test_binary_mutation_during_suite_cannot_pass(self) -> None:
        def mutate(binary: str) -> dict:
            self.binary.write_bytes(b"mutated-during-suite")
            return self.passing_results()

        report = self.run_acceptance(mutate)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "postflight")
        self.assertFalse(report["provenance_unchanged"])
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))

    def test_harness_mutation_during_suite_cannot_pass(self) -> None:
        def mutate(binary: str) -> dict:
            self.harness.write_text("HARNESS_VERSION = 2\n", encoding="utf-8")
            return self.passing_results()

        report = self.run_acceptance(mutate)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "postflight")
        self.assertFalse(report["provenance_unchanged"])
        self.assertEqual(report["failure"]["code"], "provenance_changed")

    def test_legacy_v1_receipt_mutation_during_suite_cannot_pass(self) -> None:
        def mutate(binary: str) -> dict:
            self.receipt_path.write_text(
                json.dumps(self.v1_receipt()), encoding="utf-8"
            )
            return self.passing_results()

        report = self.run_acceptance(mutate)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "postflight")
        self.assertEqual(report["failure"]["code"], "receipt_schema_not_v2")
        self.assertFalse(report["provenance_unchanged"])

    def test_assertions_outside_live_suite_have_no_stage_marker(self) -> None:
        fault = mock.Mock(side_effect=AssertionError("outside live suite"))
        for boundary, patches, suite in (
            ("preflight", {"_preflight": fault}, None),
            ("postflight", {"_postflight": fault}, None),
            ("injected suite", {}, fault),
        ):
            with self.subTest(boundary=boundary):
                stderr = io.StringIO()
                with redirect_stderr(stderr), mock.patch.multiple(
                    pando_pitr_service, run_suite=mock.Mock(), **patches
                ):
                    report = self.run_acceptance(suite)
                    pando_pitr_service.run_suite.assert_not_called()
                self.assertEqual(stderr.getvalue(), "")
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"], {
                    "phase": "suite",
                    "code": "suite_failed",
                    "exception_class": "AssertionError",
                })
                self.assertEqual(
                    self.report_path.read_text(encoding="utf-8"),
                    json.dumps(report, indent=2) + "\n",
                )

    def test_false_or_missing_mandatory_case_cannot_pass(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                results = self.passing_results()
                if missing:
                    del results["pitr_epoch_rollback_fenced"]
                else:
                    results["clone_fail_closed_zero_deletes"] = False
                report = self.run_acceptance(lambda binary: results)
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure"]["phase"], "suite")
                self.assertEqual(report["failure"]["code"], "mandatory_case_not_passed")
                self.assertTrue(report["provenance_unchanged"])
                status = "missing" if missing else "failed"
                self.assertIn(
                    {"name": "pitr_epoch_rollback_fenced" if missing
                     else "clone_fail_closed_zero_deletes", "status": status},
                    report["cases"],
                )

    def test_deadline_exceeded_cannot_pass(self) -> None:
        report = self.run_acceptance(timeout=0)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["phase"], "suite")
        self.assertEqual(report["failure"]["code"], "deadline_exceeded")
        self.assertTrue(report["provenance_unchanged"])

    def test_passing_report_binds_cases_topology_and_provenance(self) -> None:
        report = self.run_acceptance()
        self.assertTrue(report["passed"])
        self.assertEqual(report["source_commit"], self.commit)
        self.assertEqual(report["source_head"], self.commit)
        self.assertEqual(report["binary_sha256"], pando_pitr_service.receipts.sha256_file(self.binary))
        self.assertEqual(
            report["build_receipt_sha256"],
            pando_pitr_service.receipts.sha256_file(self.receipt_path),
        )
        self.assertEqual(
            [case["name"] for case in report["cases"]],
            list(pando_pitr_service.MANDATORY_CASES),
        )
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        for name in pando_pitr_service.MANDATORY_CASES:
            self.assertIs(report[name], True)
        self.assertTrue(report["provenance_unchanged"])
        self.assertEqual(report["provenance"]["before"], report["provenance"]["after"])
        self.assertIn("harnesses", report["provenance"]["before"])
        self.assertEqual(report["receipt_schema"], "v2")
        self.assertTrue(report["config_digest"])
        self.assertTrue(report["bound_inputs_digest"])
        self.assertTrue(report["toolchain"]["target_triple"])
        self.assertTrue(report["toolchain"]["cargo_release"])
        self.assertTrue(report["toolchain"]["rustc_release"])
        topology = json.dumps(report["topology"]).lower()
        for marker in ("in-process", "not external", "logical pg_dump", "not physical"):
            self.assertIn(marker, topology)
        self.assertNotIn("cleanup_passed", report)
        self.assertNotIn("failure_traceback", report)
        self.assertEqual(json.loads(self.report_path.read_text(encoding="utf-8")), report)

    def test_ci_selects_the_evidence_binding_and_required_cases(self) -> None:
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        start = text.index("      - name: Exercise live Pando PITR fencing")
        end = text.index("\n      - name:", start + 1)
        step = text[start:end]
        for marker in (
            'python3 tests/pando_pitr_service.py',
            '--binary "$ROOTYARD_BIN"',
            '--build-receipt "$ROOTYARD_BUILD_RECEIPT"',
            '--expect-commit "$GITHUB_SHA"',
            "--report test-results/pando-pitr-service.json",
        ):
            self.assertIn(marker, step)

        manifest_start = text.index(
            "      - name: Bind native regressions to the built binary and source inputs"
        )
        manifest_end = text.index("\n      - name:", manifest_start + 1)
        manifest = text[manifest_start:manifest_end]
        self.assertIn(
            "--report pando_pitr=test-results/pando-pitr-service.json", manifest
        )
        for name in pando_pitr_service.MANDATORY_CASES:
            self.assertEqual(
                manifest.count(f"--require-case pando_pitr={name}"), 1, name
            )
        self.assertIn("--harness tests/pando_pitr_service.py", manifest)
        self.assertIn("--harness tests/test_pando_pitr_service.py", manifest)


class PandoPitrStageDiagnosticTest(unittest.TestCase):
    def test_marker_uses_the_stage_of_the_escaping_assertion(self) -> None:
        startup_error = AssertionError("fake startup detail")
        cleanup_error = AssertionError("fake cleanup detail")
        for cleanup_failure, stage, expected_error in (
            (None, "startup_fail_closed", startup_error),
            (cleanup_error, "cleanup", cleanup_error),
        ):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "suite"
                root.mkdir()
                operations = mock.Mock()
                operations.s3.endpoint = "fake-s3"
                operations.vault.endpoint = "fake-vault"
                operations.run_cmd.side_effect = startup_error
                operations.vault.close.side_effect = cleanup_failure
                admin_url = "postgresql://fixture.invalid/example"
                stderr = io.StringIO()
                with (
                    redirect_stderr(stderr),
                    mock.patch.dict(os.environ, {"ROOTYARD_TEST_DATABASE_URL": admin_url}, clear=True),
                    mock.patch.object(tempfile, "mkdtemp", return_value=str(root)),
                    mock.patch.multiple(
                        pando_pitr_service,
                        TrackingLoopbackS3=mock.Mock(return_value=operations.s3),
                        TrackingLoopbackVaultTransit=mock.Mock(return_value=operations.vault),
                        sql_query=operations.sql_query,
                        run_cmd=operations.run_cmd,
                    ),
                    self.assertRaises(AssertionError) as raised,
                ):
                    pando_pitr_service.run_suite("fake-rootyard")
                self.assertIs(raised.exception, expected_error)
                self.assertEqual(stderr.getvalue(), f"pando PITR live assertion stage ({stage})\n")
                self.assertEqual(operations.run_cmd.call_args.args[0], ["fake-rootyard", "migrate"])
                cleanup_calls = [mock.call.vault.close()]
                if cleanup_failure is None:
                    create_source, create_clone = operations.sql_query.call_args_list[:2]
                    source_db = create_source.args[1].split('"')[1]
                    clone_db = create_clone.args[1].split('"')[1]
                    cleanup_calls.extend([
                        mock.call.s3.close(),
                        mock.call.sql_query(admin_url, f'DROP DATABASE IF EXISTS "{clone_db}" WITH (FORCE);'),
                        mock.call.sql_query(admin_url, f'DROP DATABASE IF EXISTS "{source_db}" WITH (FORCE);'),
                    ])
                self.assertEqual(operations.mock_calls[3:], cleanup_calls)
                self.assertEqual(root.exists(), cleanup_failure is not None)

    def test_marker_flush_failure_preserves_the_original_assertion(self) -> None:
        original = AssertionError("fake setup detail")
        stderr = mock.Mock(wraps=io.StringIO())
        stderr.flush.side_effect = OSError("fake stderr failure")
        with (
            redirect_stderr(stderr),
            mock.patch.object(pando_pitr_service, "_run_live_suite", side_effect=original),
            self.assertRaises(AssertionError) as raised,
        ):
            pando_pitr_service.run_suite("fake-rootyard")
        self.assertIs(raised.exception, original)
        stderr.flush.assert_called_once_with()
        self.assertEqual(stderr.getvalue(), "pando PITR live assertion stage (setup)\n")

    def test_non_assertion_has_no_stage_marker(self) -> None:
        original = RuntimeError("fake suite detail")
        stderr = io.StringIO()
        with (
            redirect_stderr(stderr),
            mock.patch.object(pando_pitr_service, "_run_live_suite", side_effect=original),
            self.assertRaises(RuntimeError) as raised,
        ):
            pando_pitr_service.run_suite("fake-rootyard")
        self.assertIs(raised.exception, original)
        self.assertEqual(stderr.getvalue(), "")


class PandoPitrServiceTest(unittest.TestCase):
    def _assert_bound_report(self, report: dict) -> None:
        if not report.get("passed"):
            failure = report.get("failure") or {}
            self.fail(
                "bound PITR acceptance failed "
                f"({failure.get('phase', 'unknown')}/"
                f"{failure.get('code', 'unknown')}/"
                f"{failure.get('exception_class', 'unknown')})"
            )
        self.assertEqual(report.get("receipt_schema"), "v2")
        self.assertTrue(report.get("config_digest"))
        self.assertTrue(report.get("bound_inputs_digest"))
        toolchain = report.get("toolchain") or {}
        for field in ("target_triple", "cargo_release", "rustc_release"):
            self.assertTrue(toolchain.get(field), field)
        self.assertEqual(
            [case.get("name") for case in report.get("cases", [])],
            list(pando_pitr_service.MANDATORY_CASES),
        )
        for case in report.get("cases", []):
            self.assertEqual(case.get("status"), "passed")
        for name in pando_pitr_service.MANDATORY_CASES:
            self.assertIs(report.get(name), True)

    def test_pando_pitr_pg_dump_clone_and_retention_roots(self) -> None:
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        if os.name == "nt" and not in_ci:
            self.skipTest("live rootyard service tests target Linux runtime")
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            if in_ci:
                self.fail("ROOTYARD_TEST_DATABASE_URL is required in GitHub Actions")
            self.skipTest("ROOTYARD_TEST_DATABASE_URL is unset")
        try:
            binary = runtime_binary.select_runtime_binary_path()
        except runtime_binary.RuntimeBinarySelectionError as exc:
            message = f"prebuilt rootyard binary unavailable ({type(exc).__name__})"
            if in_ci:
                self.fail(message)
            self.skipTest(message)

        receipt_value = os.environ.get("ROOTYARD_BUILD_RECEIPT")
        receipt = Path(receipt_value) if receipt_value else binary.with_suffix(".build.json")
        if not receipt.is_file():
            message = "build receipt unavailable (receipt_missing)"
            if in_ci:
                self.fail(message)
            self.skipTest(message)
        expect_commit = (
            os.environ.get("ROOTYARD_EXPECTED_SOURCE_COMMIT")
            or os.environ.get("GITHUB_SHA")
        )
        if not expect_commit:
            message = "expected source commit unavailable (expect_commit_missing)"
            if in_ci:
                self.fail(message)
            self.skipTest(message)

        with tempfile.TemporaryDirectory(prefix="rootyard-pando-pitr-unittest-") as temporary:
            report_path = Path(temporary) / "pando-pitr-service.json"
            try:
                report = pando_pitr_service.run_acceptance(
                    binary=str(binary),
                    build_receipt=str(receipt),
                    expect_commit=expect_commit,
                    report_path=report_path,
                )
            except Exception as error:
                _write_pitr_failure_checkpoint(
                    None,
                    expect_commit=expect_commit,
                )
                self.fail(f"bound PITR acceptance failed ({type(error).__name__})")
            if not isinstance(report, dict) or report.get("passed") is not True:
                _write_pitr_failure_checkpoint(
                    report,
                    expect_commit=expect_commit,
                )
            self._assert_bound_report(report)
            try:
                written = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                self.fail(f"bound PITR report unreadable ({type(error).__name__})")
            self.assertEqual(written, report)

    def _bound_report(self) -> dict:
        return {
            "passed": True,
            "receipt_schema": "v2",
            "config_digest": "c" * 64,
            "bound_inputs_digest": "d" * 64,
            "toolchain": {
                "target_triple": "aarch64-unknown-linux-gnu",
                "cargo_release": "1.101.0",
                "rustc_release": "1.99.1",
            },
            "cases": [
                {"name": name, "status": "passed"}
                for name in pando_pitr_service.MANDATORY_CASES
            ],
            **{name: True for name in pando_pitr_service.MANDATORY_CASES},
        }

    def _run_live_wrapper(
        self,
        report: dict,
        *,
        expect_error: bool = False,
        extra_env: dict[str, str] | None = None,
    ):
        with tempfile.TemporaryDirectory(prefix="rootyard-pando-pitr-wrapper-test-") as temporary:
            binary = Path(temporary) / "rootyard"
            binary.write_bytes(b"prebuilt-binary")
            binary.chmod(0o755)
            receipt = Path(temporary) / "rootyard.build.json"
            receipt.write_text("{}", encoding="utf-8")
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": "b" * 40,
                "ROOTYARD_EXPECTED_SOURCE_COMMIT": COMMIT,
                "ROOTYARD_BUILD_RECEIPT": str(receipt),
                "ROOTYARD_TEST_DATABASE_URL": "postgresql://fixture.invalid/example",
            }
            env.update(extra_env or {})
            calls: list[dict] = []

            def fake_bound(**kwargs) -> dict:
                calls.append(kwargs)
                Path(kwargs["report_path"]).write_text(
                    json.dumps(report), encoding="utf-8"
                )
                return report

            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(runtime_binary, "select_runtime_binary_path",
                                      return_value=binary), \
                    mock.patch.object(pando_pitr_service, "run_acceptance",
                                      side_effect=fake_bound), \
                    mock.patch.object(pando_pitr_service, "run_suite",
                                      side_effect=AssertionError("direct suite bypass")):
                case = PandoPitrServiceTest(
                    "test_pando_pitr_pg_dump_clone_and_retention_roots"
                )
                if expect_error:
                    with self.assertRaises(AssertionError):
                        case.test_pando_pitr_pg_dump_clone_and_retention_roots()
                else:
                    case.test_pando_pitr_pg_dump_clone_and_retention_roots()
                self.assertEqual(len(calls), 1)
            return calls[0], binary, receipt

    def test_live_wrapper_calls_bound_entry_for_exact_binary_receipt_and_commit(self) -> None:
        kwargs, binary, receipt = self._run_live_wrapper(self._bound_report())
        self.assertEqual(kwargs["binary"], str(binary))
        self.assertEqual(kwargs["build_receipt"], str(receipt))
        self.assertEqual(kwargs["expect_commit"], COMMIT)
        report_path = Path(kwargs["report_path"])
        self.assertNotEqual(report_path, ROOT / "test-results" / "pando-pitr-service.json")
        self.assertIn("rootyard-pando-pitr-unittest-", str(report_path))

    def test_live_wrapper_does_not_fall_back_to_run_suite_on_preflight_refusal(self) -> None:
        self._run_live_wrapper(
            {
                "passed": False,
                "failure": {
                    "phase": "preflight",
                    "code": "receipt_schema_not_v2",
                    "exception_class": "EvidenceError",
                },
            },
            expect_error=True,
        )

    def test_live_wrapper_publishes_a_failed_report_only_under_the_exact_opt_in(self) -> None:
        failed = self._bound_report()
        failed["passed"] = False
        failed["failure"] = {
            "phase": "suite",
            "code": "mandatory_case_not_passed",
            "exception_class": "AssertionError",
        }
        failed["cases"][0]["status"] = "failed"
        with tempfile.TemporaryDirectory(
            prefix="rootyard-pando-pitr-checkpoint-test-"
        ) as checkpoint_root:
            root = Path(checkpoint_root)
            with mock.patch.object(sys.modules[__name__], "ROOT", root), \
                    mock.patch.object(
                        sys.modules[__name__],
                        "_pitr_failure_checkpoint_source",
                        return_value=(COMMIT, "b" * 40),
                    ):
                self._run_live_wrapper(
                    failed,
                    expect_error=True,
                    extra_env={FAILURE_CHECKPOINT_ENV: FAILURE_CHECKPOINT_OPT_IN},
                )
                checkpoint_path = root / "test-results" / FAILURE_CHECKPOINT_NAME
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                self.assertEqual(checkpoint["stage"], "suite")
                self.assertEqual(checkpoint["code"], "mandatory_case_not_passed")
                self.assertEqual(len(checkpoint["cases"]), 7)
                self.assertNotIn("AssertionError", checkpoint_path.read_text(encoding="utf-8"))

    def test_live_wrapper_rejects_incomplete_config_and_missing_mandatory_case(self) -> None:
        invalid = self._bound_report()
        invalid["config_digest"] = ""
        self._run_live_wrapper(invalid, expect_error=True)

        missing = self._bound_report()
        missing["cases"] = [
            case for case in missing["cases"]
            if case["name"] != "pitr_epoch_rollback_fenced"
        ]
        del missing["pitr_epoch_rollback_fenced"]
        self._run_live_wrapper(missing, expect_error=True)


class PandoPitrFailureCheckpointTest(unittest.TestCase):
    """Pure checks for the bounded pre-assert failure checkpoint."""

    TREE = "b" * 40
    RECEIPT_SHA256 = "e" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="rootyard-pando-pitr-checkpoint-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = sys.modules[__name__]
        self.enabled = {FAILURE_CHECKPOINT_ENV: FAILURE_CHECKPOINT_OPT_IN}
        self.target = self.root / "test-results" / FAILURE_CHECKPOINT_NAME
        for patcher in (
            mock.patch.object(self.module, "ROOT", self.root),
            mock.patch.object(
                self.module,
                "_pitr_failure_checkpoint_source",
                return_value=(COMMIT, self.TREE),
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def failed_report(self, *, failed_case: str | None = None) -> dict:
        cases = [
            {"name": name, "status": "passed"}
            for name in pando_pitr_service.MANDATORY_CASES
        ]
        if failed_case is not None:
            for case in cases:
                if case["name"] == failed_case:
                    case["status"] = "failed"
        return {
            "passed": False,
            "source_commit": "c" * 40,
            "source_head": "d" * 40,
            "build_receipt_sha256": self.RECEIPT_SHA256,
            "failure": {
                "phase": "suite",
                "code": "mandatory_case_not_passed",
                "exception_class": "AssertionError",
            },
            "cases": cases + [{"name": "not-a-known-case", "status": "failed"}],
            "private": "raw /tmp/path Exception detail",
        }

    def test_failed_report_writes_only_the_closed_bounded_projection(self) -> None:
        failed_case = "clone_fail_closed_zero_deletes"
        path = _write_pitr_failure_checkpoint(
            self.failed_report(failed_case=failed_case),
            expect_commit=COMMIT,
            environ=self.enabled,
        )
        self.assertEqual(path, self.target)
        data = self.target.read_bytes()
        self.assertLessEqual(len(data), FAILURE_CHECKPOINT_MAX_BYTES)
        checkpoint = json.loads(data)
        self.assertEqual(set(checkpoint), {
            "passed",
            "source_commit",
            "source_tree",
            "stage",
            "code",
            "build_receipt_sha256",
            "cases",
        })
        self.assertEqual(checkpoint["source_commit"], COMMIT)
        self.assertEqual(checkpoint["source_tree"], self.TREE)
        self.assertEqual((checkpoint["stage"], checkpoint["code"]), (
            "suite", "mandatory_case_not_passed",
        ))
        self.assertEqual(checkpoint["build_receipt_sha256"], self.RECEIPT_SHA256)
        self.assertEqual(
            [case["name"] for case in checkpoint["cases"]],
            list(pando_pitr_service.MANDATORY_CASES),
        )
        self.assertEqual(
            [case["status"] for case in checkpoint["cases"]].count("failed"), 1
        )
        for forbidden in (
            b"AssertionError",
            b"private",
            b"/tmp",
            b"not-a-known-case",
            b"raw",
        ):
            self.assertNotIn(forbidden, data)

    def test_disabled_or_clean_runs_do_not_write(self) -> None:
        report = self.failed_report()
        for environ in (
            {},
            {FAILURE_CHECKPOINT_ENV: ""},
            {FAILURE_CHECKPOINT_ENV: "test-results/other.json"},
            {FAILURE_CHECKPOINT_ENV: str(self.target)},
        ):
            with self.subTest(environ=environ):
                self.assertIsNone(_write_pitr_failure_checkpoint(
                    report,
                    expect_commit=COMMIT,
                    environ=environ,
                ))
                self.assertFalse(self.target.exists())
        clean = self.failed_report()
        clean["passed"] = True
        clean["failure"] = None
        clean["cases"] = [
            {"name": name, "status": "passed"}
            for name in pando_pitr_service.MANDATORY_CASES
        ]
        self.assertIsNone(_write_pitr_failure_checkpoint(
            clean,
            expect_commit=COMMIT,
            environ=self.enabled,
        ))
        self.assertFalse(self.target.exists())

    def test_missing_report_is_one_fixed_diagnostic(self) -> None:
        path = _write_pitr_failure_checkpoint(
            None,
            expect_commit=COMMIT,
            environ=self.enabled,
        )
        self.assertEqual(path, self.target)
        checkpoint = json.loads(self.target.read_bytes())
        self.assertEqual((checkpoint["stage"], checkpoint["code"]), (
            "report", "report_missing",
        ))
        self.assertEqual(
            checkpoint["cases"],
            [
                {"name": name, "status": "missing"}
                for name in pando_pitr_service.MANDATORY_CASES
            ],
        )
        self.assertNotIn("failure", checkpoint)

    def test_unbound_source_or_write_failure_is_silently_skipped(self) -> None:
        report = self.failed_report()
        with mock.patch.object(
            self.module, "_pitr_failure_checkpoint_source", return_value=None
        ):
            self.assertIsNone(_write_pitr_failure_checkpoint(
                report,
                expect_commit=COMMIT,
                environ=self.enabled,
            ))
        self.assertFalse(self.target.exists())

        self.target.parent.write_text("not a directory", encoding="utf-8")
        self.assertIsNone(_write_pitr_failure_checkpoint(
            report,
            expect_commit=COMMIT,
            environ=self.enabled,
        ))


if __name__ == "__main__":
    unittest.main()
