#!/usr/bin/env python3
"""Offline inventory guard for the issue #35 CI wiring.

The native suites need Linux, PostgreSQL, Git and a Rust build.  This test is
deliberately offline: it fails closed if the workflow stops building the
relocated library-test harness before the CLI batch, stops running the direct
PostgreSQL start-gate runner and its independent job manifest, stops running
the eight-case HTTP matrix after the batch, drops an exact required case or
transitive harness digest, or uploads a raw test binary/log instead of only
safe JSON.
"""
import re
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
import ci_trust_boundaries as trust  # noqa: E402
import run_pg_start_gate as pg  # noqa: E402

CI_YML = ROOT / ".github/workflows/ci.yml"
MANIFEST_COMMAND = "python3 scripts/native_report_manifest.py --mode job"
LIB_BUILD = "python3 scripts/build_native_test.py"
PG_RUN = "python3 scripts/run_pg_start_gate.py"
BATCH = "python3 scripts/build_native_batch.py"
HTTP = (
    "python3 tests/ci_trust_boundaries.py --binary target/debug/rootyard "
    "--report test-results/ci-trust-boundaries.json "
    '--expected-commit "$GITHUB_SHA"'
)
PG_MANIFEST_MARKER = "--manifest-out test-results/native-pg-start-gate.json"
MAIN_MANIFEST_MARKER = "--manifest-out test-results/native-pr-gate.json"
PG_HARNESSES = (
    "scripts/run_pg_start_gate.py",
    "tests/test_pg_start_gate_runner.py",
    "src/sandbox/runner.rs",
    "scripts/build_native_test.py",
    "scripts/build_native.py",
    "scripts/native_report_manifest.py",
    ".github/workflows/ci.yml",
)
PRESERVED_GATES = (
    "python3 scripts/build_native_batch.py",
    "--report webhooks=test-results/webhooks.json",
    "--report browse=test-results/browse.json",
    "--report lfs_read_amplification=test-results/lfs-read-amplification.json",
    "--report lfs_split_tx_races=test-results/lfs-split-tx-races.json",
    "--report lfs_lock_policy=test-results/lfs-lock-policy.json",
    "--harness tests/lfs.py",
    "--harness tests/lfs_read_amplification.py",
    "--harness tests/lfs_split_tx_races.py",
    "--harness tests/lfs_lock_policy.py",
    "--fixture postgres=postgres:17",
)


def normalize(text):
    """Join YAML continuation lines into one whitespace-stable command string."""
    return " ".join(text.replace("\\", " ").split())


def step_containing(text, marker):
    start = text.index(marker)
    name = text.rfind("\n      - name:", 0, start)
    if name != -1:
        start = name + 1
    end = text.find("\n      - name:", start + 1)
    return text[start:] if end == -1 else text[start:end]


def manifest_step(text, marker):
    marker_index = text.index(marker)
    start = text.rindex(MANIFEST_COMMAND, 0, marker_index)
    end = text.find("\n      - name:", start)
    return text[start:] if end == -1 else text[start:end]


class Issue35CiWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = CI_YML.read_text(encoding="utf-8")
        self.pg_step = normalize(step_containing(self.text, PG_RUN))
        self.main_manifest = normalize(manifest_step(self.text, MAIN_MANIFEST_MARKER))
        # Shell quoting keeps case names with spaces as one argument; compare
        # the binding text without those quotes.
        self.main_manifest_cases = self.main_manifest.replace('"', "")

    def test_step_order_keeps_the_test_build_before_the_cli_batch(self):
        positions = [
            self.text.index(LIB_BUILD),
            self.text.index(PG_RUN),
            self.text.index(BATCH),
            self.text.index(HTTP),
            self.text.index(MAIN_MANIFEST_MARKER),
        ]
        self.assertEqual(positions, sorted(positions))
        for command in (LIB_BUILD, PG_RUN, BATCH, HTTP):
            self.assertEqual(
                self.text.count(command), 1, f"CI must run {command!r} exactly once"
            )

    def test_library_test_builder_uses_the_standard_ci_profile(self):
        step = normalize(step_containing(self.text, LIB_BUILD))
        for token in (
            "--lib",
            "--features pando-lab",
            "--strip-debuginfo",
            "--output test-results/rootyard-lib-tests",
        ):
            self.assertIn(token, step)
        self.assertLess(
            self.text.index(LIB_BUILD), self.text.index(BATCH),
            "the library-test builder cleans the rootyard package and must precede the CLI batch",
        )

    def test_pg_runner_and_separate_manifest_are_immediate_and_direct(self):
        self.assertLess(
            self.text.index(PG_RUN),
            self.text.index(BATCH),
            "the ignored PG test must run before the CLI batch rebuild",
        )
        self.assertIn(
            "python3 scripts/run_pg_start_gate.py "
            "--test-binary test-results/rootyard-lib-tests "
            "--build-receipt test-results/rootyard-lib-tests.build.json "
            "--report test-results/pg-start-gate.json "
            '--expected-commit "$GITHUB_SHA"',
            self.pg_step,
        )
        self.assertEqual(self.pg_step.count(MANIFEST_COMMAND), 1)
        self.assertLess(
            self.pg_step.index("python3 scripts/run_pg_start_gate.py"),
            self.pg_step.index(MANIFEST_COMMAND),
            "the independent PG manifest must consume the report in the same step",
        )
        for token in (
            PG_MANIFEST_MARKER,
            "--build-receipt test-results/rootyard-lib-tests.build.json",
            "--binary test-results/rootyard-lib-tests",
            "--report pg_start_gate=test-results/pg-start-gate.json",
            f"--require-case pg_start_gate={pg.CASE}",
            '--expect-commit "$GITHUB_SHA"',
        ):
            self.assertIn(token, self.pg_step)
        for harness in PG_HARNESSES:
            binding = f"--harness {harness}"
            self.assertEqual(
                self.pg_step.count(binding), 1,
                f"PG manifest must bind {binding!r} exactly once",
            )
        self.assertIsNone(
            re.search(r"(?<![\w-])--(?![\w-])", self.pg_step),
            "the direct runner must not receive a Cargo-style '--' separator",
        )
        self.assertEqual(
            pg._TEST_ARGS,
            ("--exact", pg.CASE, "--ignored", "--test-threads=1"),
        )
        self.assertNotIn("--", pg._TEST_ARGS)

    def test_http_matrix_runs_after_the_batch_and_before_the_manifest(self):
        self.assertEqual(self.text.count(HTTP), 1)
        self.assertLess(self.text.index(BATCH), self.text.index(HTTP))
        self.assertLess(self.text.index(HTTP), self.text.index(MAIN_MANIFEST_MARKER))

    def test_main_manifest_binds_the_exact_trust_report_cases_and_inputs(self):
        self.assertEqual(
            self.main_manifest.count(
                "--report ci_trust_boundaries=test-results/ci-trust-boundaries.json"
            ),
            1,
        )
        self.assertEqual(
            self.main_manifest_cases.count("--require-case ci_trust_boundaries="),
            len(trust.CASE_NAMES),
            "the manifest must require exactly the eight named trust cases",
        )
        for case in trust.CASE_NAMES:
            binding = f"--require-case ci_trust_boundaries={case}"
            self.assertEqual(
                self.main_manifest_cases.count(binding), 1,
                f"manifest must require {binding!r} exactly once",
            )
        for path in trust.PROVENANCE_INPUTS:
            binding = f"--harness {path}"
            self.assertEqual(
                self.main_manifest.count(binding), 1,
                f"manifest must bind {binding!r} exactly once",
            )
        self.assertEqual(
            trust.PROVENANCE_INPUTS,
            (
                "tests/ci_trust_boundaries.py",
                "tests/webhooks.py",
                "tests/pulls.py",
                "tests/forge.py",
                "tests/e2e.py",
                "tests/schema_baseline.py",
                "tests/webhook_tenant_matrix.py",
                "tests/native_evidence.py",
                "tests/owned_fuse_cleanup.py",
                "tests/source_bound_binary.py",
                "tests/ops_provenance.py",
                "tests/test_ci_trust_boundaries_privacy.py",
                "scripts/native_report_manifest.py",
                "scripts/native_build_receipt.py",
                "scripts/build_native.py",
                "scripts/build_native_batch.py",
                ".github/workflows/ci.yml",
            ),
        )

    def test_existing_native_gates_are_preserved(self):
        for token in PRESERVED_GATES:
            self.assertIn(token, self.text, f"existing native gate {token!r} was removed")
        self.assertEqual(
            self.text.count("--manifest-out test-results/native-pr-gate.json"), 1
        )
        self.assertEqual(self.text.count("--manifest-out test-results/native-build-batch.json"), 1)

    def test_upload_keeps_safe_json_and_excludes_the_pg_binary_and_raw_log(self):
        upload = self.text[self.text.index("Upload end-to-end report"):]
        self.assertIn("test-results/*.json", upload)
        self.assertIn("${{ env.ROOTYARD_BUILD_RECEIPT }}", upload)
        self.assertNotIn("test-results/rootyard-lib-tests\n", upload)
        self.assertNotIn("pg-start-gate.log", upload)
        self.assertNotIn("pg-start-gate.stdout", upload)


if __name__ == "__main__":
    unittest.main()
