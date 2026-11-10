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
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native_report_manifest.py"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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

    def enable_batch_receipt(self):
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        target_dir = str(self.binary.parent.parent.resolve())
        toolchain = {"rustc": receipt["rustc"], "cargo": "cargo 1.99.1"}
        architecture = {"target_triple": "x86_64-unknown-linux-gnu"}
        bound_inputs = {"digest": "c" * 64}
        batch_path = self.root / "test-results/native-build-batch.json"
        batch_path.parent.mkdir(parents=True, exist_ok=True)

        receipt["toolchain"] = toolchain
        receipt["architecture"] = architecture
        receipt["target_dir"] = target_dir
        receipt["bound_inputs"] = bound_inputs
        receipt["batch"] = {
            "kind": "rootyard/native-build-batch",
            "receipt_version": 1,
            "binary": "rootyard",
            "targets": ["rootyard", "rootyard"],
            "bound_inputs_sha256": "c" * 64,
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

    def job(self, manifest_name="job.json", reports=None, log=None, extra=(), expect=0):
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
        self.last_process = self.run(*arguments, expect=expect)
        return manifest


class TestJobManifest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ManifestFixture(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

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
