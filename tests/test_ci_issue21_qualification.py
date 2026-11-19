#!/usr/bin/env python3
"""Static CI wiring and argument contracts for issue #21 qualification.

Everything here is a source, CLI-schema or mocked-data check.  It starts no
Docker, Vault, PostgreSQL, Cargo, compiler, Git fixture, network child or real
product process; the workflow is parsed as the checked-in text and the runner
receipt loader is replaced with finite facts.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.cases as cases  # noqa: E402
import pando_producer_pg.resources as resources  # noqa: E402
import pando_producer_pg.source as source  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402

CI = ROOT / ".github/workflows/ci.yml"
EXPORT_STEP = "Export immutable native artifact paths"
PG_STEP = "Run the 17 ignored Pando Local PostgreSQL producer cases"
PANDO_CLI_STEP = "Exercise Pando object store delta resolution, graph traversal, and differential export"
PANDO_PITR_STEP = "Exercise live Pando PITR fencing, retention roots, and pg_dump clone safety"
COLD_LFS_STEP = "Qualify #85 cold tenant LFS retention on owned Garage"
REMOTE_CAS_STEP = "Prove #29 tenant-scoped remote checkpoint restore/fork refusal on owned Garage"
UPLOAD_STEP = "Upload end-to-end report"
UPLOAD_ALLOWED_LOG = "test-results/ci-webhook-regressions.log"

# The 163-minute verify/lifecycle budget already contains the 28-minute owned
# Redis step, so it is not added again.  #304 contributes an independent
# 12-minute cold tenant LFS gate on owned Garage, and #29 contributes an
# independent 18-minute bounded owned-Garage named witness: 163 + 12 + 18 = 193.
VERIFY_BASE_BUDGET_MINUTES = 163
COLD_LFS_BUDGET_MINUTES = 12
REMOTE_CAS_BUDGET_MINUTES = 18


def _lines():
    return CI.read_text(encoding="utf-8").splitlines()


def _verify_lines():
    lines = _lines()
    start = lines.index("  verify:")
    end = lines.index("  container:")
    return lines[start:end]


def _job_scalar(lines, name):
    pattern = re.compile(r"^    " + re.escape(name) + r":\s*(.+?)\s*$")
    values = [match.group(1) for line in lines
              if (match := pattern.match(line))]
    if not values:
        return None
    if len(values) != 1:
        raise AssertionError(f"duplicate job scalar {name}")
    return _unquote(values[0])


def _job_env_keys(lines):
    keys = set()
    inside = False
    for line in lines:
        if re.match(r"^    env:\s*$", line):
            inside = True
            continue
        if inside:
            match = re.match(r"^      ([A-Z][A-Z0-9_]*):", line)
            if match:
                keys.add(match.group(1))
                continue
            if line.strip() and not line.startswith("      "):
                break
    return keys


def _collect_block(lines, index, minimum_indent):
    values = []
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            values.append("")
            index += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent < minimum_indent:
            break
        values.append(line[minimum_indent:])
        index += 1
    while values and not values[-1]:
        values.pop()
    return values, index


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_step(block):
    """Parse the small step subset used by this workflow."""
    data = {
        "name": None, "uses": None, "timeout-minutes": None,
        "if": None, "run": "", "env": {}, "with": {},
    }
    first = block[0][len("      - "):]
    lines = ["        " + first] + block[1:]
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^        ([A-Za-z0-9_-]+):(.*)$", line)
        if not match:
            index += 1
            continue
        key, rest = match.group(1), match.group(2).strip()
        if key in ("env", "with"):
            index += 1
            while index < len(lines):
                child = re.match(r"^          ([A-Za-z0-9_-]+):(.*)$",
                                 lines[index])
                if not child:
                    break
                child_key, child_rest = child.group(1), child.group(2).strip()
                if key == "with" and child_rest in ("|", "|-", ">-"):
                    values, index = _collect_block(lines, index + 1, 12)
                    data["with"][child_key] = "\n".join(values)
                    continue
                data[key][child_key] = _unquote(child_rest)
                index += 1
            continue
        if key == "run" and rest in ("|", "|-"):
            values, index = _collect_block(lines, index + 1, 10)
            data["run"] = "\n".join(values)
            continue
        data[key] = _unquote(rest)
        index += 1
    return data


def _steps(lines=None):
    lines = _verify_lines() if lines is None else lines
    start = lines.index("    steps:")
    starts = [index for index in range(start, len(lines))
              if lines[index].startswith("      - ")]
    result = []
    for position, index in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        result.append(_parse_step(lines[index:end]))
    return result


def _step(name, steps=None):
    steps = _steps() if steps is None else steps
    matches = [step for step in steps if (step.get("name") or "").startswith(name)]
    if len(matches) != 1:
        raise AssertionError(f"expected one step starting {name!r}, got {len(matches)}")
    return matches[0]


def _flag_values(run, flag):
    pattern = re.compile(
        re.escape(flag) + r"\s+(\"[^\"]*\"|\S+)"
    )
    return [match.group(1) for match in pattern.finditer(run)]


def _flag_value(run, flag):
    values = _flag_values(run, flag)
    if len(values) != 1:
        raise AssertionError(f"expected one {flag}, got {len(values)}")
    return values[0]


def _job_names():
    lines = _lines()
    start = lines.index("jobs:")
    return [match.group(1) for line in lines[start + 1:]
            if (match := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line))]


def _unsafe_upload_paths(paths):
    forbidden = (
        "command", "vault-state", "credential", ".env", "token", "raw",
        "cargo", "owned", "rootyard-pando-vault-rotation-", "/tmp/", "sql",
    )
    unsafe = []
    for path in paths:
        if path == UPLOAD_ALLOWED_LOG:
            continue
        lowered = path.lower()
        if any(marker in lowered for marker in forbidden):
            unsafe.append(path)
    return unsafe


class WorkflowWiringTest(unittest.TestCase):
    def test_verify_budget_includes_pg_vault_lifecycle_and_owned_redis(self):
        lines = _verify_lines()
        self.assertEqual(
            _job_scalar(lines, "timeout-minutes"),
            str(VERIFY_BASE_BUDGET_MINUTES + COLD_LFS_BUDGET_MINUTES
                + REMOTE_CAS_BUDGET_MINUTES),
        )
        cold_lfs = _step(COLD_LFS_STEP)
        self.assertEqual(
            cold_lfs["timeout-minutes"], str(COLD_LFS_BUDGET_MINUTES)
        )
        remote_cas = _step(REMOTE_CAS_STEP)
        self.assertEqual(
            remote_cas["timeout-minutes"], str(REMOTE_CAS_BUDGET_MINUTES)
        )
        pg = _step(PG_STEP)
        self.assertEqual(pg["timeout-minutes"], "10")
        vault = _step("Qualify pinned real Vault rotation and bind the Pando native gate")
        self.assertEqual(vault["timeout-minutes"], "20")
        redis = _step("Verify browse cache incarnation across restore with owned Redis")
        self.assertEqual(redis["timeout-minutes"], "28")
        for name in (
            "Exercise repository archive, rename aliases, soft-delete purge, and ownership transfer (#85)",
            "Exercise deleted webhook-claim fence (#85)",
            "Exercise literal Issue 85 purge-hold and alias acceptance",
        ):
            with self.subTest(step=name):
                self.assertEqual(_step(name)["timeout-minutes"], "10")
        self.assertIsNone(_step(PANDO_CLI_STEP)["timeout-minutes"])
        self.assertEqual(_step(PANDO_PITR_STEP)["timeout-minutes"], "10")

    def test_single_native_batch_exports_the_pando_receipt(self):
        steps = _steps()
        builds = [step for step in steps
                  if "python3 scripts/build_native_batch.py" in step["run"]]
        self.assertEqual(len(builds), 1)
        batch = builds[0]
        self.assertEqual(_flag_value(batch["run"], "--manifest-out"),
                         "test-results/native-build-batch.json")
        exports = [step for step in steps
                   if "python3 scripts/export_native_artifacts.py" in step["run"]]
        self.assertEqual(len(exports), 1)
        run = exports[0]["run"]
        self.assertEqual(_flag_value(run, "--manifest"),
                         "test-results/native-build-batch.json")
        self.assertEqual(
            _flag_values(run, "--bin"),
            [
                "rootyard=ROOTYARD_BIN",
                "rootyard-workspace-lab=ROOTYARD_WORKSPACE_LAB_BIN",
                "rootyard-view-lab=ROOTYARD_VIEW_LAB_BIN",
                "rootyard-pando-lab=ROOTYARD_PANDO_LAB_BIN",
                "rootyard-vfs-mount=ROOTYARD_VFS_MOUNT_BIN",
            ],
        )
        self.assertEqual(
            _flag_values(run, "--bin-receipt"),
            [
                "rootyard=ROOTYARD_BUILD_RECEIPT",
                "rootyard-pando-lab=ROOTYARD_PANDO_BUILD_RECEIPT",
            ],
        )
        exports_source = (ROOT / "scripts/export_native_artifacts.py").read_text()
        tree = ast.parse(exports_source)
        flags = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
        self.assertIn("--bin-receipt", flags)

    def test_pg_step_is_mandatory_after_export_and_bounded(self):
        steps = _steps()
        names = [step["name"] for step in steps]
        self.assertLess(names.index(EXPORT_STEP), names.index(PG_STEP))
        pg = _step(PG_STEP)
        self.assertIsNone(pg.get("if"))
        self.assertNotIn("continue-on-error", pg)
        self.assertEqual(pg["timeout-minutes"], "10")
        run = pg["run"]
        for expected in (
            'python3 scripts/run_pando_producer_pg.py \\',
            '--source-root "$GITHUB_WORKSPACE" \\',
            '--expected-commit "$GITHUB_SHA" \\',
            '--product-receipt "$ROOTYARD_PANDO_BUILD_RECEIPT" \\',
            "--report test-results/pando-producer-pg.json \\",
            "--timeout-seconds 540",
        ):
            self.assertIn(expected, run)
        self.assertNotIn("--prepare-only", run)
        self.assertNotIn("build_native", run)
        self.assertNotIn("cargo build", run)
        self.assertNotIn("cargo test", run)
        self.assertEqual(resources.ESCAPE_VARIABLES, (
            "PANDO_OBJECT_STORE_ROOT",
            "PANDO_KMS_KEYRING_DIR",
            "PANDO_KMS_PROVIDER",
            "ROOTYARD_OBJECT_STORE_ENDPOINT",
        ))
        job_env = _job_env_keys(_verify_lines())
        self.assertFalse(job_env.intersection(resources.ESCAPE_VARIABLES))
        self.assertFalse(set(pg["env"]).intersection(resources.ESCAPE_VARIABLES))

    def test_pg_runner_cli_and_case_inventory(self):
        config = runner.parse_args(
            [
                "--source-root", str(ROOT),
                "--expected-commit", "a" * 40,
                "--product-receipt", "pando.build.json",
                "--report", "test-results/pando-producer-pg.json",
                "--timeout-seconds", "540",
            ],
            environ={"ROOTYARD_TEST_DATABASE_URL": "postgresql://bootstrap/db"},
        )
        self.assertEqual(config.total_seconds, 540.0)
        self.assertEqual(config.cleanup_reserve_seconds, 90.0)
        self.assertFalse(config.prepare_only)
        self.assertEqual(config.report, Path("test-results/pando-producer-pg.json"))
        self.assertEqual(len(cases.CASE_NAMES), 17)
        self.assertEqual(len(set(cases.CASE_NAMES)), 17)
        family_counts = {}
        for _, family in cases.CASES:
            family_counts[family] = family_counts.get(family, 0) + 1
        self.assertEqual(family_counts, {"migration": 7, "repack": 5, "snapshot": 5})

    def test_pg_report_is_always_uploaded_and_unsafe_paths_are_rejected(self):
        upload = _step(UPLOAD_STEP)
        self.assertEqual(upload.get("if"), "always()")
        self.assertEqual(upload.get("uses"), "actions/upload-artifact@v4")
        paths = [line.strip() for line in upload["with"]["path"].splitlines()
                 if line.strip()]
        self.assertIn("test-results/pando-producer-pg.json", paths)
        self.assertIn("${{ env.ROOTYARD_PANDO_BUILD_RECEIPT }}", paths)
        self.assertIn("${{ env.ROOTYARD_BATCH_MANIFEST }}", paths)
        self.assertEqual(_unsafe_upload_paths(paths), [])
        self.assertEqual(
            _unsafe_upload_paths([
                "test-results/commands.json",
                "test-results/vault-state.json",
                "/tmp/rootyard-pando-vault-rotation-owned",
                "test-results/token.env",
                "test-results/producer.sql",
            ]),
            [
                "test-results/commands.json",
                "test-results/vault-state.json",
                "/tmp/rootyard-pando-vault-rotation-owned",
                "test-results/token.env",
                "test-results/producer.sql",
            ],
        )

    def test_no_extra_job_workflow_or_product_build(self):
        self.assertEqual(_job_names(), ["verify", "container"])
        steps = _steps()
        self.assertEqual(len([step for step in steps
                              if "python3 scripts/build_native_batch.py"
                              in step["run"]]), 1)
        pg_run = _step(PG_STEP)["run"]
        self.assertNotIn("build_native_batch.py", pg_run)
        self.assertNotIn("build_native.py", pg_run)


class RunnerContractTest(unittest.TestCase):
    def test_escape_variables_are_rejected_even_when_empty(self):
        for name in resources.ESCAPE_VARIABLES:
            with self.assertRaises(RunnerError) as caught:
                resources.require_escape_absent({name: ""})
            self.assertEqual(caught.exception.code, "escape_variable_present")

    def test_child_environment_owns_database_and_tmpdir(self):
        base = {
            "PANDO_OBJECT_STORE_ROOT": "/owned",
            "PANDO_KMS_KEYRING_DIR": "/keys",
            "PANDO_KMS_PROVIDER": "vault",
            "ROOTYARD_OBJECT_STORE_ENDPOINT": "http://owned",
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://bootstrap/db",
            "ROOTYARD_RESTORE_TEST_DATABASE_URL": "postgresql://restore/db",
            "DATABASE_URL": "postgresql://other/db",
            "KEEP": "yes",
        }
        postgres = SimpleNamespace(
            child_dsn=lambda: "postgresql://owned/db"
        )
        root = ROOT / "owned-root"
        child = resources.build_child_environment(base, postgres, root)
        for name in resources.ESCAPE_VARIABLES:
            self.assertNotIn(name, child)
        self.assertNotIn("ROOTYARD_RESTORE_TEST_DATABASE_URL", child)
        self.assertNotIn("DATABASE_URL", child)
        self.assertEqual(child["ROOTYARD_TEST_DATABASE_URL"],
                         "postgresql://owned/db")
        self.assertEqual(child["TMPDIR"], str(root.resolve()))
        self.assertEqual(child["KEEP"], "yes")
        self.assertIn("PANDO_OBJECT_STORE_ROOT", base)

    def test_missing_product_receipt_fails_before_setup(self):
        config = runner.Config(
            source_root=ROOT,
            expected_commit="a" * 40,
            expected_tree=None,
            report=Path("test-results/pando-producer-pg.json"),
            product_receipt=None,
            total_seconds=540.0,
            cleanup_reserve_seconds=90.0,
            selection_timeout_seconds=180.0,
            setup_timeout_seconds=120.0,
            case_timeout_seconds=60.0,
            prepare_only=False,
        )
        written = []
        with self.assertRaises(RunnerError) as caught:
            runner.run(
                config,
                environ={},
                write_report_fn=lambda path, report, forbidden_root=None:
                    written.append(report),
            )
        self.assertEqual(caught.exception.code, "product_receipt_missing")
        self.assertEqual(written, [])

    def test_wrong_or_missing_case_is_rejected(self):
        summary = (
            "running 1 test\n"
            "test pando_lab::repack::pg_tests::other ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.01s\n"
        )
        with self.assertRaises(RunnerError) as caught:
            cases.parse_libtest(summary, cases.CASE_NAMES[0])
        self.assertEqual(caught.exception.code, "case_mismatch")
        with self.assertRaises(RunnerError) as caught:
            cases.parse_libtest("running 0 tests\n", cases.CASE_NAMES[0])
        self.assertEqual(caught.exception.code, "zero_tests")

    def test_product_receipt_is_same_source_evidence_only(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "pando.build.json"
            receipt.write_text("{}\n")
            validated = SimpleNamespace(
                workspace_commit="a" * 40,
                source_inputs_sha256="b" * 64,
                artifacts=({"target": "rootyard-pando-lab", "kind": "bin"},),
                receipt_sha256="c" * 64,
            )
            with mock.patch.object(source, "load_receipt", return_value=validated) as load:
                result = source.validate_product_receipt(
                    str(receipt), ROOT, "a" * 40, "b" * 64
                )
            self.assertTrue(result["provided"])
            self.assertTrue(result["same_source"])
            self.assertFalse(result["used_as_test_binary_receipt"])
            self.assertFalse(result["attached_to_native_gate"])
            self.assertEqual(result["pando_artifact_present"], True)
            self.assertFalse(load.call_args.kwargs["infer_binary"])
            self.assertTrue(load.call_args.kwargs["forbid_implicit_build"])

            missing = SimpleNamespace(
                workspace_commit="a" * 40,
                source_inputs_sha256="b" * 64,
                artifacts=({"target": "rootyard", "kind": "bin"},),
                receipt_sha256="c" * 64,
            )
            with mock.patch.object(source, "load_receipt", return_value=missing):
                with self.assertRaises(RunnerError) as caught:
                    source.validate_product_receipt(
                        str(receipt), ROOT, "a" * 40, "b" * 64
                    )
            self.assertEqual(caught.exception.code,
                             "product_receipt_artifact_missing")


if __name__ == "__main__":
    unittest.main()
