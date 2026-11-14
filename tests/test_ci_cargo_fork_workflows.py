#!/usr/bin/env python3
"""Static contracts for the formal Rust CI CargoFork wiring.

These tests read workflow text and parse YAML; they never run a workflow, Cargo,
a container, a database or a network request.
"""
from __future__ import annotations

import unittest
from pathlib import Path

try:  # PyYAML is optional on the runner; the structural checks never need it.
    import yaml
except ImportError:  # pragma: no cover - exercised on a minimal runner
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REVISION = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
RELEASE = "1.101.0"
SETUP = "scripts/install_ci_cargo_fork.sh install"
VERIFY = "scripts/install_ci_cargo_fork.sh verify"
CACHE_KEY = (
    "rootyard-cargo-fork-${{ runner.os }}-${{ runner.arch }}-${{ github.job }}-"
    "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b-1.99.1-v1"
)

# The first formal Cargo/build marker in each workflow.  It must appear after
# the shared setup, so no job can compile with whatever `cargo` was on PATH.
FIRST_CARGO = {
    "ci.yml": "cargo fmt --all",
    "refstore-protocol-acceptance.yml": "cargo test --locked --features pando-lab",
    "redis-contract.yml": "cargo clippy --locked --all-targets --features state-redis",
    "pando-lab.yml": "cargo fmt --all",
    "refcas-log.yml": "cargo fmt --manifest-path",
    "native-kernel-acceptance.yml": "cargo build --locked --bin rootyard",
    "candidate-release-acceptance.yml": "- name: Build the candidate binary once and record its receipt",
}

PRESERVE = {
    "ci.yml": (
        "postgres:17",
        "scripts/install_ci_native_tools.sh install",
        "scripts/build_native_batch.py",
        "python3 -m unittest discover -s tests -p 'test_*.py'",
        "test-results/native-pr-gate.json",
    ),
    "refstore-protocol-acceptance.yml": (
        "postgres:17",
        "scripts/owned_garage_fixture.sh start",
        "SESSION174_DATABASE_ADMIN_URL",
        "ref_store_retention_roots",
        "test-results/refstore/",
    ),
    "redis-contract.yml": (
        "redis:7.2.6-alpine",
        "scripts/check_redis_contract.py",
        "Swatinem/rust-cache@v2",
        "state-redis",
    ),
    "pando-lab.yml": (
        "scripts/test-pando-lab.sh",
        "postgresql",
        "pando-lab-evidence",
    ),
    "refcas-log.yml": (
        "crates/refcas-log",
        "CARGO_INCREMENTAL: '0'",
        "cargo test --locked --manifest-path",
    ),
    "native-kernel-acceptance.yml": (
        "scripts/native_kernel_cgroup_setup.sh",
        "ROOTYARD_TEST_CGROUP_ROOT",
        "cargo test --locked --lib sandbox",
        "ROOTYARD_NATIVE_RECEIPT",
    ),
    "candidate-release-acceptance.yml": (
        "PLAYWRIGHT_VERSION",
        "GARAGE_IMAGE",
        "tests/browser_ui.py",
        "tests/lfs_retention_acceptance.py",
        "test-results/candidate/browser/",
        "test-results/candidate/object-store/",
    ),
}


class CargoForkWorkflowTest(unittest.TestCase):
    def workflow(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_all_workflows_are_valid_yaml(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertNotIn("\t", text)
                self.assertTrue(text.startswith("name: "), path.name)
                if yaml is not None:
                    with path.open(encoding="utf-8") as stream:
                        document = yaml.safe_load(stream)
                    self.assertIsInstance(document, dict)

    def test_every_formal_rust_job_uses_the_shared_setup_before_cargo(self) -> None:
        for name, marker in FIRST_CARGO.items():
            with self.subTest(workflow=name):
                text = self.workflow(name)
                setup_index = text.index(SETUP)
                verify_index = text.index(VERIFY)
                rustup_index = text.index("rustup toolchain install 1.99.1")
                cache_index = text.index("uses: actions/cache@v4")
                cargo_index = text.index(marker)
                self.assertLess(rustup_index, setup_index)
                self.assertLess(cache_index, setup_index)
                self.assertLess(setup_index, verify_index)
                self.assertLess(verify_index, cargo_index)
                self.assertIn("--require-os linux", text)
                self.assertIn("--require-path", text)
                self.assertIn(REVISION, text)
                self.assertIn(RELEASE, text)
                self.assertIn(
                    "cargo -vV | grep -Fx 'commit-hash: " + REVISION + "'", text
                )
                self.assertIn(
                    "rustc -V | grep -Eq '^rustc 1\\.99\\.1 '", text
                )
                self.assertIn(CACHE_KEY, text)

    def test_candidate_runs_setup_for_both_native_jobs(self) -> None:
        text = self.workflow("candidate-release-acceptance.yml")
        self.assertEqual(text.count(SETUP), 2)
        self.assertEqual(text.count(VERIFY), 2)
        self.assertEqual(text.count("uses: actions/cache@v4"), 2)
        self.assertIn("path: /tmp/rootyard-cargo-fork", text)
        self.assertIn("--cache-dir /tmp/rootyard-cargo-fork", text)
        self.assertLess(text.index(SETUP), text.index("Install pinned Playwright client"))
        self.assertLess(text.index(SETUP), text.index("Build the candidate binary once"))
        self.assertLess(text.rindex(SETUP), text.rindex("Build the candidate binary once"))

    def test_refcas_no_longer_uses_the_rustup_plus_toolchain_form(self) -> None:
        text = self.workflow("refcas-log.yml")
        self.assertNotIn("cargo +1.99.1", text)
        for command in ("cargo fmt", "cargo clippy", "cargo test"):
            self.assertIn(command, text)
        self.assertIn("rustup default 1.99.1", text)

    def test_jobs_checks_services_and_budgets_are_preserved(self) -> None:
        for name, tokens in PRESERVE.items():
            text = self.workflow(name)
            for token in tokens:
                with self.subTest(workflow=name, token=token):
                    self.assertIn(token, text)
            self.assertIn("timeout-minutes:", text)

    def test_setup_does_not_introduce_database_or_object_store_changes(self) -> None:
        for name in FIRST_CARGO:
            text = self.workflow(name)
            with self.subTest(workflow=name):
                # The setup only changes tool selection. It must not add a
                # database/S3 endpoint, a new service, or a new job.
                self.assertNotIn("cargo-fork-db", text)
                self.assertNotIn("cargo-fork-s3", text)
                self.assertNotIn("containers:", text)
                self.assertNotIn("services:\n    cargo-fork", text)

    def test_no_hidden_setup_from_python_acceptance(self) -> None:
        for path in sorted((ROOT / "tests").glob("*.py")):
            if "cargo_fork" in path.name:
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(test=path.name):
                self.assertNotIn("install_ci_cargo_fork.sh", text)


if __name__ == "__main__":
    unittest.main()
