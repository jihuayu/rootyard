#!/usr/bin/env python3
"""Pure CI environment contract for the #175 native build receipt.

The test loads the actual workflow and invokes the canonical receipt environment
normalizer.  It never runs Cargo, a compiler, the native binary, a service, a
network request, or a workflow.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "issue175-real-root-raft.yml"
sys.path.insert(0, str(ROOT / "scripts"))
import native_build_receipt as receipts  # noqa: E402

JOB_NAME = "real-root-raft"
CLIPPY_STEP = "Verify formatting and strict clippy"
BUILD_STEP = "Build the exact relocated root raft integration test"
LATER_STEPS = (
    BUILD_STEP,
    "Run the exact root raft integration test once",
    "Bind the sanitized report and source harnesses",
)
PROFILE_PREFIX = "CARGO_PROFILE_"


def load_job() -> dict:
    with WORKFLOW.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)
    return document["jobs"][JOB_NAME]


def step_by_name(job: dict, name: str) -> dict:
    for step in job["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"workflow step not found: {name}")


def effective_env(job: dict, step: dict) -> dict:
    environment = dict(job.get("env") or {})
    environment.update(step.get("env") or {})
    return environment


class NativeProfileEnvironmentContract(unittest.TestCase):
    def setUp(self) -> None:
        self.job = load_job()
        self.job_env = dict(self.job.get("env") or {})

    def test_historical_global_profile_variables_are_rejected(self) -> None:
        for variable in ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"):
            historical = dict(self.job_env)
            historical[variable] = "0"
            with self.subTest(variable=variable):
                with self.assertRaises(receipts.ReceiptError):
                    receipts.normalize_build_environment(historical)

    def test_native_build_environment_normalizes_jobs_without_profiles(self) -> None:
        build = step_by_name(self.job, BUILD_STEP)
        environment = effective_env(self.job, build)
        self.assertFalse(
            any(name.startswith(PROFILE_PREFIX) for name in environment),
            "native builder must not inherit profile variables",
        )
        normalized = receipts.normalize_build_environment(environment)
        self.assertEqual(normalized["jobs"], 2)
        self.assertEqual(normalized["cargo_args"], ["--jobs", "2"])
        self.assertEqual(normalized["build_options"], {"jobs": 2})
        self.assertNotIn("CARGO_BUILD_JOBS", normalized["environment"])
        self.assertEqual(normalized["environment"].get("CARGO_INCREMENTAL"), "0")

        run = build["run"]
        self.assertIn("--package-debug 0", run)
        self.assertIn("--strip-debuginfo", run)
        self.assertIn("--artifact-store", run)
        self.assertIn("--output", run)

    def test_direct_clippy_step_explicitly_sets_profile_zero(self) -> None:
        clippy = step_by_name(self.job, CLIPPY_STEP)
        environment = effective_env(self.job, clippy)
        self.assertEqual(environment.get("CARGO_PROFILE_DEV_DEBUG"), "0")
        self.assertEqual(environment.get("CARGO_PROFILE_TEST_DEBUG"), "0")
        self.assertIn("cargo fmt --all -- --check", clippy["run"])
        self.assertIn(
            "cargo clippy --locked --test ref_store_real_raft_backend -- -D warnings",
            clippy["run"],
        )

    def test_later_receipt_binding_steps_do_not_inherit_profiles(self) -> None:
        self.assertFalse(
            any(name.startswith(PROFILE_PREFIX) for name in self.job_env),
            "job-wide environment must not carry profile variables",
        )
        for name in LATER_STEPS:
            environment = effective_env(self.job, step_by_name(self.job, name))
            with self.subTest(step=name):
                self.assertFalse(
                    any(variable.startswith(PROFILE_PREFIX) for variable in environment),
                    f"{name} must not inherit profile variables",
                )

        bind = step_by_name(self.job, "Bind the sanitized report and source harnesses")
        self.assertEqual(bind["run"].count("--require-case"), 3)
        self.assertIn("--build-receipt", bind["run"])
        self.assertIn("--binary", bind["run"])
        self.assertIn("--expect-commit", bind["run"])
        self.assertIn("scripts/native_build_receipt.py", bind["run"])


if __name__ == "__main__":
    unittest.main()
