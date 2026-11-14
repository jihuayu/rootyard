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
        "scripts/export_native_artifacts.py",
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

    def test_candidate_builds_once_in_shared_cas_and_consumes_canonical_paths(self) -> None:
        text = self.workflow("candidate-release-acceptance.yml")
        builder = (
            "python3 scripts/build_native.py \\\n"
            "            --features pando-lab \\\n"
            "            --package-debug 0 \\\n"
            "            --strip-debuginfo \\\n"
            '            --artifact-store "$HOME/.cache/rootyard/native-artifacts" \\'
        )
        self.assertEqual(text.count(builder), 2)
        self.assertNotIn("target/debug/rootyard", text)
        self.assertNotIn("cp target/debug", text)
        self.assertEqual(text.count('--build-receipt "$ROOTYARD_BUILD_RECEIPT" \\'), 2)
        self.assertEqual(text.count('--binary "$ROOTYARD_BINARY" \\'), 6)
        self.assertIn(
            "cp -- \"$ROOTYARD_BUILD_RECEIPT\" test-results/candidate/browser/rootyard.build.json",
            text,
        )
        self.assertIn(
            "cp -- \"$ROOTYARD_BUILD_RECEIPT\" test-results/candidate/object-store/rootyard.build.json",
            text,
        )
        # The exported paths are the producer's own JSON fields, not a guessed
        # store layout. Both jobs validate them before writing $GITHUB_ENV.
        self.assertEqual(text.count('("binary", "ROOTYARD_BINARY")'), 2)
        self.assertEqual(text.count('("build_receipt", "ROOTYARD_BUILD_RECEIPT")'), 2)
        self.assertEqual(text.count('if receipt != Path(str(binary) + ".build.json"):'), 2)
        self.assertNotIn("json.dump", text)
        for artifact in ("candidate-browser", "candidate-object-store"):
            upload = text[text.index(f"name: {artifact}"):]
            upload = upload.split("if-no-files-found:", 1)[0]
            self.assertIn("test-results/candidate/", upload)
            self.assertNotIn("target/", upload)
            self.assertNotIn("native-artifacts", upload)

    def test_ci_consumes_immutable_batch_artifacts(self) -> None:
        text = self.workflow("ci.yml")
        self.assertIn(
            '--artifact-store "$HOME/.cache/rootyard/native-artifacts"', text
        )
        self.assertIn("scripts/export_native_artifacts.py", text)
        self.assertIn("--manifest test-results/native-build-batch.json", text)
        for variable in (
            "ROOTYARD_BIN",
            "ROOTYARD_WORKSPACE_LAB_BIN",
            "ROOTYARD_VIEW_LAB_BIN",
            "ROOTYARD_PANDO_LAB_BIN",
            "ROOTYARD_BUILD_RECEIPT",
            "ROOTYARD_SNAPSHOT_FIXTURE",
            "ROOTYARD_HOLDS_FIXTURE",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"${variable}", text)

        batch = text.index("Build native bins and RefStore fixtures in one batch")
        export = text.index("Export immutable native artifact paths")
        self.assertLess(batch, export)
        # The build step itself must use its literal --output paths; the exported
        # immutable paths only exist after the export step.
        self.assertNotIn("ROOTYARD_", text[batch:export])

        later = text[export:]
        for mutable in (
            "target/debug/rootyard",
            "target/debug/rootyard-workspace-lab",
            "target/debug/rootyard-view-lab",
            "target/debug/rootyard-pando-lab",
        ):
            with self.subTest(mutable=mutable):
                self.assertNotIn(mutable, later)

        manifest = text[text.index("python3 scripts/native_report_manifest.py --mode job"):]
        manifest = manifest.split("\n      - name:", 1)[0]
        self.assertIn('--build-receipt "$ROOTYARD_BUILD_RECEIPT"', manifest)
        self.assertIn('--binary "$ROOTYARD_BIN"', manifest)
        # The final report step must consume the exporter's exact manifest
        # identity, not re-derive it from whatever bytes are present later.
        self.assertIn('--expect-batch-manifest "$ROOTYARD_BATCH_MANIFEST"', manifest)
        self.assertIn(
            '--expect-batch-manifest-sha "$ROOTYARD_BATCH_MANIFEST_SHA256"', manifest
        )
        self.assertIn("test-results/native-pr-gate.json", manifest)

        upload = text[text.index("name: e2e-report"):]
        upload = upload.split("if-no-files-found:", 1)[0]
        self.assertIn("${{ env.ROOTYARD_BUILD_RECEIPT }}", upload)
        self.assertIn("${{ env.ROOTYARD_BATCH_MANIFEST }}", upload)
        self.assertNotIn("target/", upload)
        self.assertNotIn("native-artifacts", upload)

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
