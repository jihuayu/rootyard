"""Fail-closed contract tests for the native acceptance report manifest.

The candidate release gate and the per-pull-request binding step both use
``scripts/native_report_manifest.py``. These tests prove the gate rejects stale
binaries, failed cases, missing/empty logs, unrecorded fixtures and evidence
from another commit, and that the release gate requires one shared compiled
source digest.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native_report_manifest.py"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import native_build_receipt as receipts  # noqa: E402
import native_report_manifest as manifest_gate  # noqa: E402


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def workflow_batch_manifest_anchor_arguments():
    """Extract the job-mode collector's anchor flags from the real CI command."""
    text = CI_YML.read_text(encoding="utf-8")
    marker = "python3 scripts/native_report_manifest.py --mode job"
    start = text.index(marker)
    end = text.find("\n      - name:", start)
    command = text[start:] if end == -1 else text[start:end]
    tokens = shlex.split(command.replace("\\\n", " "))
    anchors = []
    for index, token in enumerate(tokens):
        if not token.startswith("--expect-batch-manifest"):
            continue
        if index + 1 >= len(tokens):
            raise AssertionError(f"{token} has no following value in ci.yml")
        anchors.append((token, tokens[index + 1]))
    return anchors


PANDO_SCHEMA_SQL = (
    "-- Separate namespace, never applied by Rootyard's production migration runner.\n"
    "CREATE SCHEMA IF NOT EXISTS pando_lab;\n"
    "CREATE TABLE IF NOT EXISTS pando_lab.repositories (\n"
    " id uuid PRIMARY KEY, generation bigint NOT NULL DEFAULT 0);\n"
)

WORKSPACE_CAPTURE_REQUIRED_CASES = (
    "__main__.WorkspaceCaptureAcceptance.test_capture_reaches_ids_beyond_fixed_prefix",
    "__main__.WorkspaceCaptureAcceptance.test_api_write_baseline_does_not_emit_spurious_capture",
    "__main__.WorkspaceCaptureAcceptance.test_large_inventory_keeps_single_tokio_worker_responsive",
    "__main__.WorkspaceCaptureAcceptance.test_scan_does_not_hold_row_lock_and_rejects_stale_revision",
    "__main__.WorkspaceCaptureAcceptance.test_scan_revalidates_lease_epoch_before_committing",
)

V2_PRODUCER_BINS = (
    "rootyard",
    "rootyard-pando-lab",
    "rootyard-vfs-mount",
    "rootyard-view-lab",
    "rootyard-workspace-lab",
)
V2_PRODUCER_TESTS = (
    "ref_store_snapshot_backup_fixture",
    "ref_store_holds_backup_fixture",
)


class ManifestFixture:
    """Ephemeral build receipt, binary, report and log in a temporary tree."""

    def __init__(self, root, commit="a" * 40, source_inputs="b" * 64):
        self.root = Path(root)
        self.commit = commit
        self.source_inputs = source_inputs
        self.binary = self.root / "target/debug/rootyard"
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_bytes(b"actual-rust-binary")
        self.receipt = self.root / "target/debug/rootyard.build.json"
        self.receipt.write_text(
            json.dumps(
                {
                    "version": 1,
                    "binary_sha256": digest(self.binary),
                    "source_inputs_sha256": source_inputs,
                    "workspace_commit": commit,
                    "rustc": "rustc 1.99.1",
                    "command": ["cargo", "build", "--locked", "--bin", "rootyard"],
                }
            )
        )
        self.harness = self.root / "tests/web_sessions.py"
        self.harness.parent.mkdir(parents=True, exist_ok=True)
        self.harness.write_text("# harness\n")
        (self.root / "Cargo.toml").write_text('[package]\nname = "rootyard"\n')
        (self.root / "Cargo.lock").write_text("version = 3\n")
        schema = self.root / "experimental/pando/schema.sql"
        schema.parent.mkdir(parents=True, exist_ok=True)
        schema.write_text(PANDO_SCHEMA_SQL)

    def enable_batch_receipt(self):
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        target_dir = str(self.binary.parent.parent.resolve())
        toolchain = {"rustc": receipt["rustc"], "cargo": "cargo 1.99.1"}
        architecture = {"target_triple": "x86_64-unknown-linux-gnu"}
        bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        bound_inputs = bound["bound_inputs"]
        batch_path = self.root / "test-results/native-build-batch.json"
        batch_path.parent.mkdir(parents=True, exist_ok=True)

        receipt["toolchain"] = toolchain
        receipt["architecture"] = architecture
        receipt["target_dir"] = target_dir
        receipt["bound_inputs"] = bound_inputs
        receipt["bound_input_inventory"] = bound["bound_input_inventory"]
        receipt["batch"] = {
            "kind": "rootyard/native-build-batch",
            "receipt_version": 1,
            "binary": "rootyard",
            "targets": ["rootyard", "rootyard"],
            "bound_inputs_sha256": bound_inputs["digest"],
            "manifest": str(batch_path.resolve()),
        }
        self.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

        manifest = {
            "kind": "rootyard/native-build-batch",
            "manifest_version": 1,
            "status": "passed",
            "source_commit": receipt["workspace_commit"],
            "source_inputs_sha256": receipt["source_inputs_sha256"],
            "toolchain": toolchain,
            "architecture": architecture,
            "target_directory": target_dir,
            "bound_inputs": bound_inputs,
            "clean": {"commands": 1},
            "build": {
                "commands": 1,
                "command": receipt["command"],
                "fresh_false_artifacts": [
                    {"kind": "lib", "target": "rootyard", "fresh": False},
                    {"kind": "bin", "target": "rootyard", "fresh": False},
                ],
            },
            "artifacts": [
                {
                    "kind": "bin",
                    "target": "rootyard",
                    "artifact": str(self.binary.resolve()),
                    "receipt": str(self.receipt.resolve()),
                    "fresh": False,
                    "implicit": False,
                    "sha256": digest(self.binary),
                }
            ],
        }
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return batch_path

    def _v2_toolchain(self):
        directory = self.root / "toolchain"
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("cargo", "rustc", "rustup"):
            (directory / name).write_bytes(("fake-" + name).encode())

        def identity(name, release, commit_hash):
            executable = directory / name
            return {
                "executable": str(executable),
                "executable_sha256": digest(executable),
                "version": f"{name} {release} (fake 2026-01-01)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": "x86_64-unknown-linux-gnu",
            }

        return {
            "cargo": identity("cargo", "1.101.0", "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"),
            "rustc": dict(
                identity("rustc", "1.99.1", "d" * 40),
                path_entry=str(directory / "rustc"),
                proxy=False,
            ),
            "rustup": {
                "executable": str(directory / "rustup"),
                "executable_sha256": digest(directory / "rustup"),
                "resolved_rustc": str(directory / "rustc"),
                "resolved_rustc_sha256": digest(directory / "rustc"),
            },
            "target_triple": "x86_64-unknown-linux-gnu",
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def enable_v2_receipt(self, *, lib_fresh=True, bin_fresh=False):
        for relative, content in (
            ("Cargo.toml", '[package]\nname = "rootyard"\n'),
            ("Cargo.lock", "version = 3\n"),
            ("src/lib.rs", "pub fn production() -> u8 { 1 }\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        profile = {
            "opt_level": "0",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": True,
            "test": False,
        }

        def event(name, kind, source, executable, fresh):
            target = {"name": name, "kind": [kind], "src_path": str(source)}
            payload = {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": target,
                "profile": profile,
                "fresh": fresh,
            }
            if executable is not None:
                payload["executable"] = str(executable)
            return payload

        artifacts = [
            receipts.cargo_artifact_record(
                event("rootyard", "lib", self.root / "src/lib.rs", None, lib_fresh),
                self.root,
            ),
            receipts.cargo_artifact_record(
                event("rootyard", "bin", self.root / "src/main.rs", self.binary, bin_fresh),
                self.root,
            ),
        ]
        bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        payload = receipts.make_receipt_v2(
            binary_path=self.binary,
            command=["cargo", "build", "--locked", "--bin", "rootyard"],
            profile="dev",
            artifacts=artifacts,
            toolchain=self._v2_toolchain(),
            bound_inputs=bound,
            workspace_commit=self.commit,
            target_dir=self.binary.parent.parent,
            target_triple="x86_64-unknown-linux-gnu",
            features="pando-lab",
        )
        self.source_inputs = payload["source_inputs_sha256"]
        self.receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return payload

    def enable_v2_batch_receipt(self, *, lib_fresh=True, bin_fresh=False):
        receipt = self.enable_v2_receipt(lib_fresh=lib_fresh, bin_fresh=bin_fresh)
        receipt["kind"] = "native-build-batch-bin"
        architecture = {
            "target_triple": receipt["target_triple"],
            "host": receipt["toolchain"]["rustc"]["host"],
        }
        batch_path = self.root / "test-results/native-build-batch.json"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        receipt["batch"] = {
            "kind": "rootyard/native-build-batch",
            "receipt_version": 2,
            "binary": "rootyard",
            "targets": [row["target"] for row in receipt["cargo_artifacts"]],
            "bound_inputs_sha256": receipt["bound_inputs"]["digest"],
            "manifest": str(batch_path.resolve()),
        }
        self.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        manifest = {
            "kind": "rootyard/native-build-batch",
            "manifest_version": 2,
            "status": "passed",
            "source_commit": receipt["workspace_commit"],
            "source_inputs_sha256": receipt["source_inputs_sha256"],
            "toolchain": receipt["toolchain"],
            "architecture": architecture,
            "target_directory": receipt["target_dir"],
            "bound_inputs": receipt["bound_inputs"],
            "build": {
                "command": receipt["command"],
                "cargo_artifacts": receipt["cargo_artifacts"],
            },
            "artifacts": [
                {
                    "kind": "bin",
                    "target": "rootyard",
                    "artifact": str(self.binary.resolve()),
                    "receipt": str(self.receipt.resolve()),
                    "fresh": bin_fresh,
                    "implicit": False,
                    "sha256": digest(self.binary),
                }
            ],
        }
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return batch_path

    def enable_v2_cas_batch_receipt(self, *, lib_fresh=True, bin_fresh=False):
        """Build the producer's v2 CAS layout: immutable snapshot plus aliases."""
        receipt = self.enable_v2_receipt(lib_fresh=lib_fresh, bin_fresh=bin_fresh)
        receipt["kind"] = "native-build-batch-bin"
        architecture = {
            "target_triple": receipt["target_triple"],
            "host": receipt["toolchain"]["rustc"]["host"],
        }
        original = self.binary
        sha = digest(original)
        commit = receipt["workspace_commit"]
        config_key = "f" * 64
        build_id = "cas-invocation"
        store = self.root / "artifact-store"
        object_path = store / "objects/sha256" / sha
        object_path.parent.mkdir(parents=True, exist_ok=True)
        object_path.write_bytes(original.read_bytes())
        os.chmod(object_path, 0o555)
        base = store / "snapshots" / commit / config_key / build_id
        base.mkdir(parents=True, exist_ok=True)
        binary = base / "rootyard"
        binary.write_bytes(object_path.read_bytes())
        os.chmod(binary, 0o555)
        canonical_receipt = base / "rootyard.receipt.json"
        build_receipt = base / "rootyard.build.json"
        batch_path = self.root / "test-results/native-build-batch.json"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "schema": "rootyard/native-artifact-store/v1",
            "root": str(store),
            "kind": "bin",
            "target": "rootyard",
            "implicit": False,
            "object": str(object_path),
            "binary": str(binary),
            "receipt": str(canonical_receipt),
            "build_receipt": str(build_receipt),
            "binary_sha256": sha,
            "config_key": config_key,
            "build_id": build_id,
            "method": "copy",
            "reused": False,
            "copied_bytes": len(original.read_bytes()),
            "output_alias": None,
        }
        receipt["artifact_store"] = record
        receipt["relocated_artifact"] = True
        receipt["original_artifact_sha256"] = sha
        receipt["batch"] = {
            "kind": "rootyard/native-build-batch",
            "receipt_version": 2,
            "binary": "rootyard",
            "targets": [row["target"] for row in receipt["cargo_artifacts"]],
            "bound_inputs_sha256": receipt["bound_inputs"]["digest"],
            "manifest": str(batch_path.resolve()),
        }
        payload = (json.dumps(receipt, indent=2) + "\n").encode()
        for path in (canonical_receipt, build_receipt):
            path.write_bytes(payload)
            os.chmod(path, 0o444)
        manifest = {
            "kind": "rootyard/native-build-batch",
            "manifest_version": 2,
            "status": "passed",
            "source_commit": receipt["workspace_commit"],
            "source_inputs_sha256": receipt["source_inputs_sha256"],
            "toolchain": receipt["toolchain"],
            "architecture": architecture,
            "target_directory": receipt["target_dir"],
            "bound_inputs": receipt["bound_inputs"],
            "build": {
                "command": receipt["command"],
                "cargo_artifacts": receipt["cargo_artifacts"],
            },
            "artifacts": [
                {
                    "kind": "bin",
                    "target": "rootyard",
                    "artifact": str(binary),
                    "original_artifact": str(original),
                    "original_artifact_sha256": sha,
                    "receipt": str(build_receipt),
                    "fresh": bin_fresh,
                    "implicit": False,
                    "sha256": sha,
                    "artifact_store": record,
                }
            ],
            "artifact_store": {
                "schema": "rootyard/native-artifact-store/v1",
                "root": str(store),
                "objects": [str(object_path)],
                "sealed": [record],
            },
        }
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.cas_binary = binary
        self.cas_receipt = build_receipt
        self.batch_path = batch_path
        self.binary = binary
        self.receipt = build_receipt
        return batch_path

    def enable_v2_producer_batch_receipt(self):
        """Build the real v2 batch cohort a bin receipt describes: lib+5 bins+2 tests."""
        self.enable_v2_receipt()
        dev_profile = {
            "opt_level": "0",
            "debuginfo": 2,
            "debug_assertions": True,
            "overflow_checks": True,
            "test": False,
        }
        test_profile = dict(dev_profile, test=True)

        def event(name, kind, source, executable, profile):
            target = {"name": name, "kind": [kind], "src_path": str(source)}
            payload = {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": target,
                "profile": profile,
                "fresh": False,
            }
            if executable is not None:
                payload["executable"] = str(executable)
            return payload

        lib = receipts.cargo_artifact_record(
            event("rootyard", "lib", self.root / "src/lib.rs", None, dev_profile),
            self.root,
        )
        bin_rows = []
        for name in V2_PRODUCER_BINS:
            if name == "rootyard":
                source = self.root / "src/main.rs"
                executable = self.binary
            else:
                source = self.root / "src/bin" / f"{name}.rs"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("fn main() {}\n")
                executable = self.root / "target/debug" / name
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(f"producer-bin-{name}".encode())
            bin_rows.append(
                receipts.cargo_artifact_record(
                    event(name, "bin", source, executable, dev_profile), self.root
                )
            )

        test_rows = []
        for name in V2_PRODUCER_TESTS:
            source = self.root / "tests" / f"{name}.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("#[test]\nfn executes() {}\n")
            executable = self.root / "target/debug" / name
            executable.write_bytes(f"producer-test-{name}".encode())
            test_rows.append(
                receipts.cargo_artifact_record(
                    event(name, "test", source, executable, test_profile), self.root
                )
            )

        app_rows = [lib] + bin_rows
        batch_rows = app_rows + test_rows
        bound = receipts.capture_bound_inputs(self.root, environ={"PATH": ""})
        target_dir = self.binary.parent.parent.resolve()
        command = [
            "cargo", "build", "--locked", "--profile", "test",
            "--config", f'build.target-dir = "{target_dir}"',
            *[item for name in V2_PRODUCER_BINS for item in ("--bin", name)],
            *[item for name in V2_PRODUCER_TESTS for item in ("--test", name)],
            "--features", "pando-lab",
            "--message-format=json-render-diagnostics",
        ]
        payload = receipts.make_receipt_v2(
            binary_path=self.binary,
            command=command,
            profile="test",
            artifacts=app_rows,
            toolchain=self._v2_toolchain(),
            bound_inputs=bound,
            workspace_commit=self.commit,
            target_dir=target_dir,
            target_triple="x86_64-unknown-linux-gnu",
            features="pando-lab",
        )
        self.source_inputs = payload["source_inputs_sha256"]
        batch_path = self.root / "test-results/native-build-batch.json"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        payload["kind"] = "native-build-batch-bin"
        payload["batch"] = {
            "kind": "rootyard/native-build-batch",
            "receipt_version": 2,
            "binary": "rootyard",
            "targets": [row["target"] for row in app_rows],
            "bound_inputs_sha256": payload["bound_inputs"]["digest"],
            "manifest": str(batch_path.resolve()),
        }
        self.receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        target_dir = Path(payload["target_dir"])
        artifacts = []
        for row in bin_rows:
            artifacts.append(
                {
                    "kind": "bin",
                    "target": row["target"],
                    "artifact": row["executable"],
                    "receipt": str(
                        self.receipt
                        if row["target"] == "rootyard"
                        else target_dir / "debug" / f"{row['target']}.build.json"
                    ),
                    "fresh": row["fresh"],
                    "sha256": row["executable_sha256"],
                    "package_id": row["package_id"],
                    "profile": row["profile"],
                    "source": row["source"],
                    "implicit": False,
                }
            )
        for row in test_rows:
            artifacts.append(
                {
                    "kind": "test",
                    "target": row["target"],
                    "artifact": row["executable"],
                    "original_artifact": row["executable"],
                    "original_artifact_sha256": row["executable_sha256"],
                    "receipt": str(target_dir / "debug" / f"{row['target']}.build.json"),
                    "fresh": row["fresh"],
                    "sha256": row["executable_sha256"],
                    "package_id": row["package_id"],
                    "profile": row["profile"],
                    "source": row["source"],
                    "source_sha256": row["source_sha256"],
                }
            )
        manifest = {
            "kind": "rootyard/native-build-batch",
            "manifest_version": 2,
            "status": "passed",
            "source_commit": payload["workspace_commit"],
            "source_inputs_sha256": payload["source_inputs_sha256"],
            "toolchain": payload["toolchain"],
            "target_triple": payload["target_triple"],
            "architecture": {
                "target_triple": payload["target_triple"],
                "host": payload["toolchain"]["rustc"]["host"],
            },
            "target_directory": payload["target_dir"],
            "cargo_package_id": "rootyard 0.1.0",
            "bound_inputs": payload["bound_inputs"],
            "build": {
                "command": payload["command"],
                "cargo_artifacts": batch_rows,
            },
            "artifacts": artifacts,
        }
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.batch_path = batch_path
        self.producer_app_rows = app_rows
        self.producer_batch_rows = batch_rows
        return batch_path

    def report(self, name="web_sessions", passed=True, binary_sha=None, case_status="passed", **extra):
        path = self.root / f"test-results/{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "passed": passed,
            "binary_sha256": binary_sha if binary_sha is not None else digest(self.binary),
            "cases": [{"name": "workflow", "status": case_status}],
            **extra,
        }
        path.write_text(json.dumps(payload))
        return path

    def log(self, text="201 event batches: passed\nconcurrent claim fence: passed\n"):
        path = self.root / "test-results/webhook-regressions.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def artifact_directory(self, job_name, manifest):
        """Mirror download-artifact: flatten a job's reports and logs by name."""
        data = json.loads(Path(manifest).read_text())
        directory = self.root / f"artifacts/{job_name}"
        directory.mkdir(parents=True, exist_ok=True)
        for records in (data.get("reports") or {}, data.get("logs") or {}):
            for record in records.values():
                source = Path(record["file"])
                target = directory / source.name
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.write_bytes(source.read_bytes())
        receipt = data.get("build_receipt") or {}
        receipt_source = Path(receipt["file"])
        receipt_target = directory / receipt_source.name
        if receipt_target.exists() or receipt_target.is_symlink():
            receipt_target.unlink()
        receipt_target.write_bytes(receipt_source.read_bytes())
        batch = receipt.get("batch_manifest")
        if isinstance(batch, dict):
            source = Path(batch["file"])
            target = directory / source.name
            if target.exists() or target.is_symlink():
                target.unlink()
            target.write_bytes(source.read_bytes())
        return directory

    def run(self, *arguments, expect=0, env=None):
        environment = os.environ.copy()
        environment.pop("GITHUB_SHA", None)
        for name in ("ROOTYARD_OBJECT_STORE_SECRET_KEY", "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
                     "ROOTYARD_FIXTURE_SECRET_KEY", "ROOTYARD_FIXTURE_ACCESS_KEY"):
            environment.pop(name, None)
        environment.update(env or {})
        process = subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, arguments)],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process.returncode != expect:
            raise AssertionError(
                f"expected exit {expect}, got {process.returncode}\n"
                f"stdout: {process.stdout[-2000:]}\nstderr: {process.stderr[-2000:]}"
            )
        return process

    def job(self, manifest_name="job.json", reports=None, log=None, extra=(), expect=0, env=None):
        reports = reports if reports is not None else {"web_sessions": self.report()}
        log = log if log is not None else self.log()
        manifest = self.root / f"manifests/{manifest_name}"
        arguments = [
            "--mode", "job",
            "--manifest-out", manifest,
            "--build-receipt", self.receipt,
            "--binary", self.binary,
            "--expect-commit", self.commit,
        ]
        for name, path in reports.items():
            arguments += ["--report", f"{name}={path}"]
        arguments += [
            "--log", f"webhook_regressions={log}",
            "--log-marker", "webhook_regressions=201 event batches: passed",
            "--log-marker", "webhook_regressions=concurrent claim fence: passed",
            "--harness", self.harness,
            "--fixture", "postgres=postgres:17",
            *extra,
        ]
        self.last_process = self.run(*arguments, expect=expect, env=env)
        return manifest


class TestJobManifest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ManifestFixture(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def rewrite_producer_command(self, batch_path, change):
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        command = list(receipt["command"])
        change(command)
        receipt["command"] = command
        manifest["build"]["command"] = command
        self.fixture.receipt.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        batch_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        return batch_path

    def test_accepts_evidence_bound_to_the_built_binary(self):
        manifest = json.loads(self.fixture.job().read_text())
        self.assertEqual(manifest["kind"], "rootyard/native-acceptance-job-manifest")
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(manifest["source_commit"], self.fixture.commit)
        self.assertEqual(manifest["source_inputs_sha256"], self.fixture.source_inputs)
        self.assertEqual(manifest["binary_sha256"], digest(self.fixture.binary))
        self.assertEqual(manifest["harnesses"], {str(self.fixture.harness): digest(self.fixture.harness)})
        self.assertEqual(manifest["fixtures"], {"postgres": "postgres:17"})
        self.assertEqual(sorted(manifest["reports"]), ["web_sessions"])
        self.assertEqual(manifest["logs"]["webhook_regressions"]["bytes"], len(self.fixture.log().read_bytes()))

    def test_accepts_browse_report_bound_to_the_source_head(self):
        report = self.fixture.report(name="browse", source_head=self.fixture.commit)
        manifest = json.loads(self.fixture.job(reports={"browse": report}).read_text())
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(manifest["reports"]["browse"]["case_names"], ["workflow"])

    def test_rejects_browse_report_without_a_source_head(self):
        report = self.fixture.report(name="browse")
        self.fixture.job(reports={"browse": report}, expect=1)
        self.assertIn("source_head is required", self.fixture.last_process.stderr)
        failed = json.loads((self.fixture.root / "manifests/job.json").read_text())
        self.assertEqual(failed["status"], "failed")

    def test_rejects_browse_report_from_another_source_head(self):
        report = self.fixture.report(name="browse", source_head="d" * 40)
        self.fixture.job(reports={"browse": report}, expect=1)
        self.assertIn("source_head is required", self.fixture.last_process.stderr)
        self.assertIn("d" * 40, self.fixture.last_process.stderr)

    def test_accepts_and_records_batch_manifest_provenance(self):
        batch_path = self.fixture.enable_batch_receipt()
        job = json.loads(self.fixture.job().read_text(encoding="utf-8"))

        self.assertEqual(job["status"], "passed")
        self.assertEqual(
            job["build_receipt"]["batch_manifest"],
            {
                "file": str(batch_path.resolve()),
                "sha256": digest(batch_path),
                "target": "rootyard",
            },
        )

    def test_accepts_v2_actual_freshness_true_false_and_mixed(self):
        for lib_fresh, bin_fresh in ((True, True), (False, False), (True, False), (False, True)):
            with self.subTest(lib_fresh=lib_fresh, bin_fresh=bin_fresh):
                self.fixture.enable_v2_receipt(lib_fresh=lib_fresh, bin_fresh=bin_fresh)
                job = json.loads(self.fixture.job().read_text(encoding="utf-8"))
                self.assertEqual(job["status"], "passed")
                receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
                self.assertEqual(
                    [row["fresh"] for row in receipt["cargo_artifacts"]],
                    [lib_fresh, bin_fresh],
                )

    def test_accepts_v2_batch_manifest_without_clean_or_rebuilt(self):
        batch_path = self.fixture.enable_v2_batch_receipt(lib_fresh=True, bin_fresh=False)
        job = json.loads(self.fixture.job().read_text(encoding="utf-8"))
        self.assertEqual(job["status"], "passed")
        self.assertEqual(job["build_receipt"]["batch_manifest"]["target"], "rootyard")
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        self.assertNotIn("clean", manifest)
        self.assertNotIn("fresh_false_artifacts", manifest["build"])
        self.assertNotIn("package_rebuilt", manifest)

    def test_accepts_v2_cas_batch_receipt_with_immutable_paths(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt(lib_fresh=True, bin_fresh=False)
        job = json.loads(self.fixture.job().read_text(encoding="utf-8"))
        self.assertEqual(job["status"], "passed")
        self.assertEqual(job["binary"], str(self.fixture.cas_binary))
        self.assertEqual(job["build_receipt"]["file"], str(self.fixture.cas_receipt))
        self.assertEqual(
            job["build_receipt"]["batch_manifest"]["file"], str(batch_path.resolve())
        )
        self.assertEqual(job["build_receipt"]["batch_manifest"]["target"], "rootyard")

    def test_accepts_exporter_expected_batch_manifest_sha_and_path(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        expected = digest(batch_path)
        job = json.loads(
            self.fixture.job(
                extra=(
                    "--expect-batch-manifest-sha", expected,
                    "--expect-batch-manifest-path", str(batch_path.resolve()),
                )
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(job["status"], "passed")
        self.assertEqual(job["build_receipt"]["batch_manifest"]["sha256"], expected)
        self.assertEqual(
            job["build_receipt"]["batch_manifest"]["file"], str(batch_path.resolve())
        )

    def test_accepts_v2_producer_architecture_dictionary_with_target_and_host(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["architecture"],
            {
                "target_triple": receipt["target_triple"],
                "host": receipt["toolchain"]["rustc"]["host"],
            },
        )
        job = json.loads(
            self.fixture.job(
                extra=(
                    "--expect-batch-manifest-path", str(batch_path.resolve()),
                    "--expect-batch-manifest-sha", digest(batch_path),
                )
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(job["status"], "passed")

    def test_rejects_v2_batch_architecture_target_mismatch(self):
        batch_path = self.fixture.enable_v2_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["architecture"]["target_triple"] = "aarch64-unknown-linux-gnu"
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "batch receipt manifest does not match the receipt",
            self.fixture.last_process.stderr,
        )
        failed = json.loads(
            (self.fixture.root / "manifests/job.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failed["status"], "failed")

    def test_rejects_v2_batch_architecture_host_mismatch(self):
        batch_path = self.fixture.enable_v2_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["architecture"]["host"] = "aarch64-unknown-linux-gnu"
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "batch receipt manifest does not match the receipt",
            self.fixture.last_process.stderr,
        )
        failed = json.loads(
            (self.fixture.root / "manifests/job.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failed["status"], "failed")

    def test_accepts_historical_v1_batch_architecture_shape(self):
        batch_path = self.fixture.enable_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        self.assertEqual(manifest["architecture"], receipt["architecture"])
        self.assertEqual(set(manifest["architecture"]), {"target_triple"})
        job = json.loads(self.fixture.job().read_text(encoding="utf-8"))
        self.assertEqual(job["status"], "passed")

    def test_accepts_v2_bin_receipt_with_producer_test_cohort(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        self.assertEqual(
            receipt["batch"]["targets"],
            [row["target"] for row in self.fixture.producer_app_rows],
        )
        self.assertEqual(
            [row["target"] for row in manifest["build"]["cargo_artifacts"]],
            [row["target"] for row in self.fixture.producer_batch_rows],
        )
        self.assertEqual(len(receipt["batch"]["targets"]), 6)
        self.assertEqual(len(manifest["build"]["cargo_artifacts"]), 8)
        command = receipt["command"]
        self.assertEqual(
            [command[index + 1] for index, token in enumerate(command) if token == "--bin"],
            list(V2_PRODUCER_BINS),
        )
        self.assertEqual(
            [command[index + 1] for index, token in enumerate(command) if token == "--test"],
            list(V2_PRODUCER_TESTS),
        )
        job = json.loads(
            self.fixture.job(
                extra=(
                    "--expect-batch-manifest-path", str(batch_path.resolve()),
                    "--expect-batch-manifest-sha", digest(batch_path),
                )
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(job["status"], "passed")

    def test_rejects_v2_bin_receipt_cohort_wrong_order(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        rows = manifest["build"]["cargo_artifacts"]
        rows[1], rows[2] = rows[2], rows[1]
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match receipt-kind lib/bin cohort",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_bin_receipt_cohort_wrong_kind(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][0]["kind"] = "lib-test"
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "bin receipt cohort must begin with the lib artifact",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_bin_receipt_cohort_foreign_target(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][1]["target"] = "rootyard-foreign"
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match receipt-kind lib/bin cohort",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_bin_receipt_unrequested_extra_bin_row(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        extra_row = dict(manifest["build"]["cargo_artifacts"][1])
        extra_row["target"] = "rootyard-unrequested"
        manifest["build"]["cargo_artifacts"].insert(-2, extra_row)
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match receipt-kind lib/bin cohort",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_bin_receipt_unrequested_extra_bin_artifact(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        extra_entry = dict(manifest["artifacts"][0])
        extra_entry["target"] = "rootyard-unrequested"
        manifest["artifacts"].append(extra_entry)
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "published bin artifacts do not match the batch bin cohort",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_bin_receipt_unrequested_extra_test_row(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        extra_row = dict(manifest["build"]["cargo_artifacts"][-1])
        extra_row["target"] = "foreign_extra_test"
        manifest["build"]["cargo_artifacts"].append(extra_row)
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        def request_extra_test(command):
            index = command.index("--features")
            command[index:index] = ["--test", "foreign_extra_test"]

        self.rewrite_producer_command(batch_path, request_extra_test)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "published test artifacts do not match the batch test cohort",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_test_row_that_differs_from_published_artifact(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][-1]["source_sha256"] = "0" * 64
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "source_sha256 does not match the build row",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_forged_test_row_and_published_entry_without_command_request(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        source_row = next(
            row for row in manifest["build"]["cargo_artifacts"]
            if row["kind"] == "test"
        )
        source_entry = next(
            entry for entry in manifest["artifacts"] if entry.get("kind") == "test"
        )
        manifest["build"]["cargo_artifacts"] = [
            row for row in manifest["build"]["cargo_artifacts"]
            if row["kind"] != "test"
        ]
        manifest["artifacts"] = [
            entry for entry in manifest["artifacts"]
            if entry.get("kind") != "test"
        ]
        forged_row = dict(source_row)
        forged_row["target"] = "foreign_extra_test"
        forged_entry = dict(source_entry)
        forged_entry["target"] = "foreign_extra_test"
        manifest["build"]["cargo_artifacts"].append(forged_row)
        manifest["artifacts"].append(forged_entry)
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        def drop_all_tests(command):
            while "--test" in command:
                index = command.index("--test")
                del command[index:index + 2]

        self.rewrite_producer_command(batch_path, drop_all_tests)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match recorded --test order",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_declared_test_order_mismatch(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()

        def swap_tests(command):
            positions = [index for index, token in enumerate(command) if token == "--test"]
            first, second = positions[0] + 1, positions[1] + 1
            command[first], command[second] = command[second], command[first]

        self.rewrite_producer_command(batch_path, swap_tests)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match recorded --test order",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_declared_test_missing_request(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()

        def drop_first_test(command):
            index = command.index("--test")
            del command[index:index + 2]

        self.rewrite_producer_command(batch_path, drop_first_test)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match recorded --test order",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_declared_test_duplicate_request(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()

        def duplicate_first_test(command):
            index = command.index("--test")
            command[index:index] = ["--test", V2_PRODUCER_TESTS[0]]

        self.rewrite_producer_command(batch_path, duplicate_first_test)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn("recorded --test repeats", self.fixture.last_process.stderr)

    def test_rejects_v2_declared_test_target_mismatch(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()

        def replace_first_test(command):
            index = command.index("--test")
            command[index + 1] = "foreign_test"

        self.rewrite_producer_command(batch_path, replace_first_test)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "do not match recorded --test order",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_recorded_test_equals_form(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()

        def use_equals_form(command):
            index = command.index("--test")
            command[index:index + 2] = [f"--test={V2_PRODUCER_TESTS[0]}"]

        self.rewrite_producer_command(batch_path, use_equals_form)
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn(
            "unsupported or malformed recorded --test flag",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_published_test_entry_missing_required_fields(self):
        batch_path = self.fixture.enable_v2_producer_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        for entry in manifest["artifacts"]:
            if entry.get("kind") != "test":
                continue
            for field in ("package_id", "profile", "source", "source_sha256"):
                entry.pop(field, None)
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.fixture.job(
            extra=(
                "--expect-batch-manifest-path", str(batch_path.resolve()),
                "--expect-batch-manifest-sha", digest(batch_path),
            ),
            expect=1,
        )
        self.assertIn("package_id is required", self.fixture.last_process.stderr)

    def test_fixture_rust_from_receipt_records_full_v1_and_v2_versions_without_compilers(self):
        # An empty PATH makes any accidental bare rustc/cargo probe fail; the
        # fixture must come from the already-validated receipt instead.
        v1_version = "rustc 1.99.1 (58cf8f9c3 2026-10-13)"
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ManifestFixture(temporary)
            receipt = json.loads(fixture.receipt.read_text(encoding="utf-8"))
            receipt["rustc"] = v1_version
            fixture.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            v1_job = json.loads(
                fixture.job(
                    extra=("--fixture-rust-from-receipt",),
                    env={"PATH": ""},
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(v1_job["fixtures"]["rust"], v1_version)
            self.assertEqual(v1_job["build_receipt"]["rustc"], v1_version)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ManifestFixture(temporary)
            batch_path = fixture.enable_v2_cas_batch_receipt()
            receipt = json.loads(fixture.receipt.read_text(encoding="utf-8"))
            v2_version = receipt["toolchain"]["rustc"]["version"]
            v2_job = json.loads(
                fixture.job(
                    extra=(
                        "--fixture-rust-from-receipt",
                        "--expect-batch-manifest-path", str(batch_path.resolve()),
                        "--expect-batch-manifest-sha", digest(batch_path),
                    ),
                    env={"PATH": ""},
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(v2_job["fixtures"]["rust"], v2_version)
            self.assertEqual(v2_job["build_receipt"]["rustc"], v2_version)
            self.assertEqual(
                v2_job["build_receipt"]["batch_manifest"]["file"],
                str(batch_path.resolve()),
            )
            self.assertEqual(
                v2_job["build_receipt"]["batch_manifest"]["sha256"],
                digest(batch_path),
            )

    def test_fixture_rust_from_receipt_reuses_fixture_safety_checks(self):
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        receipt["rustc"] = "rustc 1.99.1\nnot-a-single-line"
        self.fixture.receipt.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        self.fixture.job(
            extra=("--fixture-rust-from-receipt",),
            expect=1,
        )
        self.assertIn(
            "fixture rust: value is not a single safe line",
            self.fixture.last_process.stderr,
        )

    def test_fixture_rust_from_receipt_rejects_an_explicit_rust_fixture(self):
        self.fixture.job(
            extra=(
                "--fixture-rust-from-receipt",
                "--fixture", "rust=rustc 1.99.1 (caller supplied)",
            ),
            expect=1,
        )
        self.assertIn(
            "conflicts with an explicit --fixture rust=",
            self.fixture.last_process.stderr,
        )
        failed = json.loads(
            (self.fixture.root / "manifests/job.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failed["status"], "failed")

    def test_fixture_rust_from_receipt_is_rejected_in_release_mode(self):
        manifest = self.fixture.root / "manifests/release.json"
        process = self.fixture.run(
            "--mode", "release",
            "--manifest-out", manifest,
            "--expect-commit", self.fixture.commit,
            "--fixture-rust-from-receipt",
            expect=1,
        )
        self.assertIn(
            "--fixture-rust-from-receipt is only valid in job mode",
            process.stderr,
        )
        failed = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(failed["status"], "failed")

    def test_workflow_job_mode_anchor_flags_reach_the_real_argument_parser(self):
        anchors = workflow_batch_manifest_anchor_arguments()
        self.assertEqual(
            [
                ("--expect-batch-manifest-path", "$ROOTYARD_BATCH_MANIFEST"),
                ("--expect-batch-manifest-sha", "$ROOTYARD_BATCH_MANIFEST_SHA256"),
            ],
            anchors,
            "ci.yml must use the parser's complete, unambiguous anchor flags",
        )

        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        expected = digest(batch_path)
        replacements = {
            "$ROOTYARD_BATCH_MANIFEST": str(batch_path.resolve()),
            "$ROOTYARD_BATCH_MANIFEST_SHA256": expected,
        }
        extra = []
        for flag, environment_value in anchors:
            self.assertIn(environment_value, replacements)
            extra += [flag, replacements[environment_value]]

        job = json.loads(
            self.fixture.job(extra=tuple(extra)).read_text(encoding="utf-8")
        )
        self.assertEqual(job["status"], "passed")
        self.assertEqual(
            job["build_receipt"]["batch_manifest"]["file"], str(batch_path.resolve())
        )
        self.assertEqual(job["build_receipt"]["batch_manifest"]["sha256"], expected)

    def test_rejects_expected_manifest_sha_after_a_raw_metadata_change(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        expected = digest(batch_path)
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        # An unknown top-level field remains semantically acceptable to the
        # validator, so only the exporter-provided raw SHA can catch the rewrite.
        manifest["acceptance_note"] = "rewritten after export"
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.assertNotEqual(digest(batch_path), expected)

        self.fixture.job(extra=("--expect-batch-manifest-sha", expected), expect=1)

        self.assertIn(
            "SHA-256 does not match the exporter-validated SHA-256",
            self.fixture.last_process.stderr,
        )
        failed = json.loads((self.fixture.root / "manifests/job.json").read_text())
        self.assertEqual(failed["status"], "failed")

    def test_rejects_malformed_explicit_batch_manifest_anchors(self):
        self.fixture.enable_v2_cas_batch_receipt()
        for anchor in ("not-a-sha", "A" * 64, "a" * 63):
            with self.subTest(anchor=anchor):
                self.fixture.job(
                    extra=("--expect-batch-manifest-sha", anchor), expect=1
                )
                self.assertIn(
                    "64 lowercase hexadecimal characters",
                    self.fixture.last_process.stderr,
                )
        relative = "test-results/native-build-batch.json"
        self.fixture.job(
            extra=("--expect-batch-manifest-path", relative), expect=1
        )
        self.assertIn("must be absolute", self.fixture.last_process.stderr)

    def test_rejects_explicit_batch_manifest_anchor_without_a_batch_link(self):
        self.fixture.job(
            extra=("--expect-batch-manifest-sha", "a" * 64), expect=1
        )
        self.assertIn(
            "build receipt has no batch link", self.fixture.last_process.stderr
        )

    def test_batch_manifest_anchor_hashes_the_parsed_buffer_without_a_reread(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        receipt, validated, receipt_file, binary = manifest_gate.load_receipt(
            self.fixture.receipt, self.fixture.binary
        )
        raw = batch_path.read_bytes()
        expected = hashlib.sha256(raw).hexdigest()
        reads = []

        def read_batch_manifest_once(path):
            reads.append(Path(path))
            if len(reads) > 1:
                return b'{"kind": "rewritten-after-the-exporter-validated-it"}'
            return raw

        with mock.patch.object(Path, "read_bytes", read_batch_manifest_once):
            recorded = manifest_gate.verify_batch_receipt(
                receipt,
                validated,
                receipt_file,
                binary,
                expected_manifest_sha=expected,
                expected_manifest_path=str(batch_path),
            )

        self.assertEqual(recorded["sha256"], expected)
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0], batch_path.resolve())

    def test_rejects_cas_consumed_binary_that_is_not_the_sealed_snapshot(self):
        self.fixture.enable_v2_cas_batch_receipt()
        copy = self.fixture.root / "elsewhere/rootyard"
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(self.fixture.cas_binary.read_bytes())
        self.fixture.binary = copy
        self.fixture.job(expect=1)
        self.assertIn(
            "consumed binary is not the sealed canonical snapshot",
            self.fixture.last_process.stderr,
        )

    def test_rejects_cas_receipt_record_that_differs_from_the_manifest(self):
        self.fixture.enable_v2_cas_batch_receipt()
        receipt_path = self.fixture.cas_receipt
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        payload["artifact_store"]["target"] = "foreign"
        os.chmod(receipt_path, 0o644)
        receipt_path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(receipt_path, 0o444)
        self.fixture.job(expect=1)
        self.assertIn(
            "receipt artifact_store does not match the sealed manifest record",
            self.fixture.last_process.stderr,
        )

    def test_rejects_cas_manifest_row_rewritten_to_mutable_target_path(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["artifact"] = str(
            self.fixture.root / "target/debug/rootyard"
        )
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.fixture.job(expect=1)
        self.assertIn(
            "manifest artifact is not the sealed canonical snapshot",
            self.fixture.last_process.stderr,
        )

    def test_rejects_cas_manifest_without_a_sealed_record(self):
        batch_path = self.fixture.enable_v2_cas_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        del manifest["artifacts"][0]["artifact_store"]
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.fixture.job(expect=1)
        self.assertIn(
            "CAS artifacts entry must carry artifact_store",
            self.fixture.last_process.stderr,
        )

    def test_rejects_v2_manifest_freshness_not_matching_the_receipt(self):
        batch_path = self.fixture.enable_v2_batch_receipt(lib_fresh=True, bin_fresh=False)
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][1]["fresh"] = True
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.fixture.job(expect=1)
        self.assertIn("freshness does not match", self.fixture.last_process.stderr)

    def test_rejects_v2_manifest_freshness_that_is_not_a_json_boolean(self):
        batch_path = self.fixture.enable_v2_batch_receipt(lib_fresh=True, bin_fresh=False)
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][0]["fresh"] = "true"
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.fixture.job(expect=1)
        self.assertIn("fresh must be a JSON boolean", self.fixture.last_process.stderr)

    def test_rejects_v2_manifest_artifact_wrong_source_or_profile(self):
        batch_path = self.fixture.enable_v2_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][1]["source"] = "src/other.rs"
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.fixture.job(expect=1)
        self.assertIn("source does not match the receipt", self.fixture.last_process.stderr)

    def test_accepts_batch_receipt_copied_outside_target(self):
        self.fixture.enable_batch_receipt()
        copied_receipt = self.fixture.root / "test-results" / "rootyard.build.json"
        copied_receipt.parent.mkdir(parents=True, exist_ok=True)
        copied_receipt.write_bytes(self.fixture.receipt.read_bytes())
        self.fixture.receipt = copied_receipt
        job = json.loads(self.fixture.job().read_text(encoding="utf-8"))
        self.assertEqual(job["status"], "passed")
        self.assertEqual(job["build_receipt"]["file"], str(copied_receipt))

    def test_rejects_missing_batch_manifest(self):
        batch_manifest = self.fixture.enable_batch_receipt()
        Path(batch_manifest).unlink()

        self.fixture.job(expect=1)

        self.assertIn("batch receipt manifest", self.fixture.last_process.stderr)
        job_manifest_path = Path(self.fixture.root) / "manifests" / "job.json"
        job_manifest = json.loads(job_manifest_path.read_text())
        self.assertEqual(job_manifest["status"], "failed")

    def test_rejects_batch_manifest_not_bound_to_binary(self):
        batch_manifest = self.fixture.enable_batch_receipt()
        batch_manifest_path = Path(batch_manifest)
        data = json.loads(batch_manifest_path.read_text())
        data["artifacts"][0]["artifact"] = str(self.fixture.root / "elsewhere/rootyard")
        batch_manifest_path.write_text(json.dumps(data))

        self.fixture.job(expect=1)

        self.assertIn("exactly one entry", self.fixture.last_process.stderr)

    def test_rejects_duplicate_batch_artifacts_and_targets(self):
        batch_path = self.fixture.enable_batch_receipt()
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["fresh_false_artifacts"] = [
            {"kind": "lib", "target": "rootyard", "fresh": False},
            {"kind": "bin", "target": "rootyard", "fresh": False},
        ]
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        receipt = json.loads(self.fixture.receipt.read_text(encoding="utf-8"))
        receipt["batch"]["targets"] = ["rootyard", "rootyard"]
        self.fixture.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

        manifest["build"]["fresh_false_artifacts"].append(
            {"kind": "bin", "target": "rootyard", "fresh": False}
        )
        batch_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        receipt["batch"]["targets"].append("rootyard")
        self.fixture.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

        self.fixture.job(expect=1)

        self.assertIn("duplicate", self.fixture.last_process.stderr.lower())
    def test_accepts_reports_with_required_cases_present(self):
        report = self.fixture.report(name="workspace_capture")
        manifest = json.loads(report.read_text())
        manifest["cases"] = [{"name": case, "status": "passed"} for case in WORKSPACE_CAPTURE_REQUIRED_CASES]
        report.write_text(json.dumps(manifest))
        harness_path = self.fixture.root / "tests/workspace_capture_acceptance.py"
        harness_path.parent.mkdir(parents=True, exist_ok=True)
        harness_path.write_text("# harness\n")
        self.fixture.harness = harness_path
        extra = tuple(
            pair
            for case in WORKSPACE_CAPTURE_REQUIRED_CASES
            for pair in ("--require-case", f"workspace_capture={case}")
        )
        result = self.fixture.job(reports={"workspace_capture": report}, extra=extra)
        accepted = json.loads(result.read_text())
        self.assertEqual(accepted["status"], "passed")
        self.assertEqual(
            accepted["reports"]["workspace_capture"]["case_names"],
            list(WORKSPACE_CAPTURE_REQUIRED_CASES),
        )
        self.assertEqual(
            accepted["harnesses"],
            {str(harness_path): digest(harness_path)},
        )

    def test_fails_closed_when_required_case_is_absent(self):
        report = self.fixture.report(name="workspace_capture")
        manifest = json.loads(report.read_text())
        manifest["cases"] = [
            {"name": case, "status": "passed"} for case in WORKSPACE_CAPTURE_REQUIRED_CASES[:-1]
        ]
        report.write_text(json.dumps(manifest))
        harness_path = self.fixture.root / "tests/workspace_capture_acceptance.py"
        harness_path.parent.mkdir(parents=True, exist_ok=True)
        harness_path.write_text("# harness\n")
        self.fixture.harness = harness_path
        extra = tuple(
            pair
            for case in WORKSPACE_CAPTURE_REQUIRED_CASES
            for pair in ("--require-case", f"workspace_capture={case}")
        )
        self.fixture.job(reports={"workspace_capture": report}, extra=extra, expect=1)
        self.assertIn("required case", self.fixture.last_process.stderr)
        self.assertIn("is absent", self.fixture.last_process.stderr)
        failed = json.loads((self.fixture.root / "manifests/job.json").read_text())
        self.assertEqual(failed["status"], "failed")

    def test_rejects_report_from_another_binary(self):
        report = self.fixture.report(binary_sha="c" * 64)
        self.fixture.job(reports={"web_sessions": report}, expect=1)
        self.assertIn("binary digest does not match", self.fixture.last_process.stderr)
        manifest = json.loads((self.fixture.root / "manifests/job.json").read_text())
        self.assertEqual(manifest["status"], "failed")

    def test_rejects_failed_case_even_when_the_report_claims_success(self):
        report = self.fixture.report(case_status="failed")
        self.fixture.job(reports={"web_sessions": report}, expect=1)
        self.assertIn("is not passed", self.fixture.last_process.stderr)

    def test_rejects_empty_log_and_missing_marker(self):
        empty = self.fixture.log("")
        self.fixture.job(log=empty, expect=1)
        self.assertIn("empty output", self.fixture.last_process.stderr)
        partial = self.fixture.log("201 event batches: passed\n")
        self.fixture.job(log=partial, expect=1)
        self.assertIn("missing expected output", self.fixture.last_process.stderr)

    def test_rejects_receipt_from_another_commit(self):
        report = self.fixture.report()
        manifest = self.fixture.root / "manifests/other.json"
        process = self.fixture.run(
            "--mode", "job",
            "--manifest-out", manifest,
            "--build-receipt", self.fixture.receipt,
            "--binary", self.fixture.binary,
            "--expect-commit", "d" * 40,
            "--report", f"web_sessions={report}",
            "--harness", self.fixture.harness,
            expect=1,
        )
        self.assertIn("!= expected commit", process.stderr)

    def test_rejects_live_fixture_credential_in_artifacts(self):
        secret = "s3cr3t-fixture-key-value"
        report = self.fixture.report()
        report.write_text(report.read_text().replace('"cases"', f'"leak":"{secret}","cases"'))
        process = self.fixture.run(
            "--mode", "job",
            "--manifest-out", self.fixture.root / "manifests/leak.json",
            "--build-receipt", self.fixture.receipt,
            "--binary", self.fixture.binary,
            "--expect-commit", self.fixture.commit,
            "--report", f"web_sessions={report}",
            "--harness", self.fixture.harness,
            expect=1,
            env={"ROOTYARD_OBJECT_STORE_SECRET_KEY": secret},
        )
        self.assertIn("live fixture credential", process.stderr)


class TestReleaseGate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ManifestFixture(self.temporary.name)
        self.browser = self.fixture.job(
            "browser.json", reports={"browser_ui": self.fixture.report("browser_ui")}
        )
        self.store = self.fixture.job(
            "object-store.json",
            reports={
                "lfs_hydration": self.fixture.report("lfs_hydration"),
                "lfs_retention": self.fixture.report("lfs_retention"),
            },
            extra=("--fixture", "garage=garage 2.1.0", "--fixture", "git_lfs=git-lfs/3.6.1"),
        )
        self.staged = {
            "browser": self.fixture.artifact_directory("browser", self.browser),
            "object-store": self.fixture.artifact_directory("object-store", self.store),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def release(self, *arguments, fixtures=None, expect=0):
        fixtures = fixtures if fixtures is not None else {"garage": "2.1", "git_lfs": "3.6.1"}
        output = self.fixture.root / "candidate-release-gate.json"
        for index, value in enumerate(arguments):
            if value == "--job-manifest" and index + 1 < len(arguments):
                name, _, path = str(arguments[index + 1]).partition("=")
                if name not in self.staged:
                    self.staged[name] = self.fixture.artifact_directory(name, path)
        command = [
            "--mode", "release",
            "--manifest-out", output,
            "--expect-commit", self.fixture.commit,
            "--job-manifest", f"browser={self.browser}",
            "--job-manifest", f"object-store={self.store}",
            "--require-report", "browser_ui",
            "--require-report", "lfs_hydration",
        ]
        for name, directory in self.staged.items():
            command += ["--artifact-dir", f"{name}={directory}"]
        for name, substring in fixtures.items():
            command += ["--require-fixture", f"{name}={substring}"]
        process = self.fixture.run(*command, *arguments, expect=expect)
        return process, output

    def enable_batch_jobs(self):
        self.fixture.enable_batch_receipt()
        self.browser = self.fixture.job(
            "browser.json",
            reports={"browser_ui": self.fixture.report("browser_ui")},
        )
        self.store = self.fixture.job(
            "object-store.json",
            reports={
                "lfs_hydration": self.fixture.report("lfs_hydration"),
                "lfs_retention": self.fixture.report("lfs_retention"),
            },
            extra=(
                "--fixture", "garage=garage 2.1.0",
                "--fixture", "git_lfs=git-lfs/3.6.1",
            ),
        )
        self.staged = {
            "browser": self.fixture.artifact_directory("browser", self.browser),
            "object-store": self.fixture.artifact_directory("object-store", self.store),
        }

    def enable_v2_batch_jobs(self):
        self.fixture.enable_v2_batch_receipt(lib_fresh=True, bin_fresh=False)
        self.browser = self.fixture.job(
            "browser.json",
            reports={"browser_ui": self.fixture.report("browser_ui")},
        )
        self.store = self.fixture.job(
            "object-store.json",
            reports={
                "lfs_hydration": self.fixture.report("lfs_hydration"),
                "lfs_retention": self.fixture.report("lfs_retention"),
            },
            extra=(
                "--fixture", "garage=garage 2.1.0",
                "--fixture", "git_lfs=git-lfs/3.6.1",
            ),
        )
        self.staged = {
            "browser": self.fixture.artifact_directory("browser", self.browser),
            "object-store": self.fixture.artifact_directory("object-store", self.store),
        }

    def enable_v2_cas_batch_jobs(self):
        self.fixture.enable_v2_cas_batch_receipt()
        self.browser = self.fixture.job(
            "browser.json",
            reports={"browser_ui": self.fixture.report("browser_ui")},
        )
        self.store = self.fixture.job(
            "object-store.json",
            reports={
                "lfs_hydration": self.fixture.report("lfs_hydration"),
                "lfs_retention": self.fixture.report("lfs_retention"),
            },
            extra=(
                "--fixture", "garage=garage 2.1.0",
                "--fixture", "git_lfs=git-lfs/3.6.1",
            ),
        )
        self.staged = {
            "browser": self.fixture.artifact_directory("browser", self.browser),
            "object-store": self.fixture.artifact_directory("object-store", self.store),
        }

    def test_release_accepts_v2_cas_jobs_with_immutable_paths(self):
        self.enable_v2_cas_batch_jobs()
        process, gate_path = self.release()
        self.assertEqual(process.returncode, 0)
        gate = json.loads(gate_path.read_text())
        self.assertEqual(gate["status"], "passed")
        self.assertIn("build:receipt", gate["jobs"]["browser"]["artifacts"])
        self.assertIn("build:batch_manifest", gate["jobs"]["browser"]["artifacts"])

    def test_release_rejects_cas_row_pointing_at_a_mutable_binary(self):
        self.enable_v2_cas_batch_jobs()
        batch_path = self.staged["browser"] / "native-build-batch.json"
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["artifact"] = str(
            self.fixture.root / "target/debug/rootyard"
        )
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        job = json.loads(self.browser.read_text(encoding="utf-8"))
        job["build_receipt"]["batch_manifest"]["sha256"] = digest(batch_path)
        self.browser.write_text(json.dumps(job), encoding="utf-8")
        process, _ = self.release(expect=1)
        self.assertIn(
            "manifest artifact is not the sealed canonical snapshot",
            process.stderr,
        )

    def test_release_accepts_v2_batch_jobs_with_cache_hit_freshness(self):
        self.enable_v2_batch_jobs()
        process, gate_path = self.release()
        self.assertEqual(process.returncode, 0)
        gate = json.loads(gate_path.read_text())
        self.assertEqual(gate["status"], "passed")
        self.assertIn(
            "build:batch_manifest",
            gate["jobs"]["browser"]["artifacts"],
        )

    def test_release_rejects_v2_batch_manifest_tampered_freshness(self):
        self.enable_v2_batch_jobs()
        batch_path = self.staged["browser"] / "native-build-batch.json"
        manifest = json.loads(batch_path.read_text(encoding="utf-8"))
        manifest["build"]["cargo_artifacts"][1]["fresh"] = True
        batch_path.write_text(json.dumps(manifest), encoding="utf-8")
        job = json.loads(self.browser.read_text(encoding="utf-8"))
        job["build_receipt"]["batch_manifest"]["sha256"] = digest(batch_path)
        self.browser.write_text(json.dumps(job), encoding="utf-8")
        process, _ = self.release(expect=1)
        self.assertIn("freshness does not match", process.stderr)

    def test_release_verifies_downloaded_batch_manifest(self):
        self.enable_batch_jobs()
        process, gate_path = self.release()
        self.assertEqual(process.returncode, 0)
        gate = json.loads(gate_path.read_text())
        self.assertIn(
            "build:batch_manifest",
            gate["jobs"]["browser"]["artifacts"],
        )
        self.assertIn(
            "build:receipt",
            gate["jobs"]["browser"]["artifacts"],
        )
        batch_path = self.staged["browser"] / "native-build-batch.json"
        original = batch_path.read_bytes()
        try:
            batch_path.unlink()
            process, _ = self.release(expect=1)
            self.assertIn("batch manifest", process.stderr)
            batch_path.write_bytes(original + b"\n")
            process, _ = self.release(expect=1)
            self.assertIn("downloaded file does not match the manifest sha256", process.stderr)
        finally:
            batch_path.write_bytes(original)

    def test_release_rejects_removed_batch_manifest_pointer(self):
        self.enable_batch_jobs()
        data = json.loads(self.browser.read_text())
        del data["build_receipt"]["batch_manifest"]
        self.browser.write_text(json.dumps(data))
        process, _ = self.release(expect=1)
        self.assertIn(
            "requires a build_receipt.batch_manifest object",
            process.stderr,
        )

    def test_accepts_consistent_job_manifests(self):
        _, output = self.release()
        gate = json.loads(output.read_text())
        self.assertEqual(gate["kind"], "rootyard/candidate-release-gate")
        self.assertEqual(gate["status"], "passed")
        self.assertEqual(gate["source_commit"], self.fixture.commit)
        self.assertEqual(gate["source_inputs_sha256"], self.fixture.source_inputs)
        self.assertEqual(sorted(gate["jobs"]), ["browser", "object-store"])
        self.assertEqual(gate["fixtures"]["garage"], "garage 2.1.0")
        self.assertEqual(gate["reports"], ["browser_ui", "lfs_hydration", "lfs_retention"])
        self.assertEqual(
            sorted(gate["jobs"]["browser"]["artifacts"]),
            ["build:receipt", "log:webhook_regressions", "report:browser_ui"],
        )

    def test_rejects_missing_required_report_and_wrong_fixture_pin(self):
        process, _ = self.release("--require-report", "lfs_remote", expect=1)
        self.assertIn("required candidate reports are missing", process.stderr)
        process, _ = self.release(fixtures={"garage": "2.0"}, expect=1)
        self.assertIn("does not contain the required pin", process.stderr)

    def test_rejects_job_manifest_from_another_source_digest(self):
        other = ManifestFixture(self.fixture.root / "other", source_inputs="e" * 64)
        second = other.job("second.json", reports={"lfs_remote": other.report("lfs_remote")})
        process, _ = self.release(
            "--job-manifest", f"second={second}",
            "--require-report", "lfs_remote",
            expect=1,
        )
        self.assertIn("disagree on the compiled source-input digest", process.stderr)

    def test_rejects_harness_changed_after_the_job_ran(self):
        self.fixture.harness.write_text("# harness changed\n")
        process, _ = self.release(expect=1)
        self.assertIn("changed after the job ran", process.stderr)

    def test_rejects_report_tampered_after_manifest_generation(self):
        report = self.staged["browser"] / "browser_ui.json"
        report.write_text(report.read_text().replace('"passed": true', '"passed": false'))
        process, _ = self.release(expect=1)
        self.assertIn("does not match the manifest sha256", process.stderr)

    def test_rejects_missing_downloaded_report(self):
        (self.staged["object-store"] / "lfs_hydration.json").unlink()
        process, _ = self.release(expect=1)
        self.assertIn("is missing", process.stderr)

    def test_rejects_traversing_artifact_path(self):
        manifest = json.loads(self.store.read_text())
        manifest["reports"]["lfs_hydration"]["file"] = "../../lfs_hydration.json"
        self.store.write_text(json.dumps(manifest))
        process, _ = self.release(expect=1)
        self.assertIn("traverses out of its artifact", process.stderr)

    def test_rejects_symlinked_downloaded_artifact(self):
        staged = self.staged["browser"] / "browser_ui.json"
        outside = self.fixture.root / "elsewhere.json"
        outside.write_bytes(staged.read_bytes())
        staged.unlink()
        staged.symlink_to(outside)
        process, _ = self.release(expect=1)
        self.assertIn("is a symlink", process.stderr)


if __name__ == "__main__":
    unittest.main()
