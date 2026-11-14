"""Cheap tests for the pinned Git LFS archive installation path.

The real 3.6.1 tarball contains git-lfs-3.6.1/git-lfs. These tests build a
synthetic tarball with that exact layout and prove the helper strips the top
directory, verifies the official-style checksum entry before installing, and
fails closed on a bad or missing checksum without leaving a binary behind.
No network, Git LFS install or real release archive is used.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/install_git_lfs.sh"


class InstallGitLfsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.destination = self.root / "bin"
        self.work.mkdir()
        self.source = self.root / "source/git-lfs-3.6.1"
        self.source.mkdir(parents=True)
        binary = self.source / "git-lfs"
        binary.write_text("#!/usr/bin/env bash\n[ \"$1\" = version ] && echo 'git-lfs/3.6.1 (test)'\nexit 0\n")
        binary.chmod(0o755)
        self.archive = self.work / "git-lfs-linux-amd64-v3.6.1.tar.gz"
        with tarfile.open(self.archive, "w:gz") as tar:
            tar.add(self.source, arcname="git-lfs-3.6.1")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.checksums = self.work / "sha256sums.txt"

    def tearDown(self):
        self.temporary.cleanup()

    def write_checksums(self, text):
        self.checksums.write_text(text)

    def run_helper(self, expect, *extra):
        process = subprocess.run(
            [str(SCRIPT), "--version", "3.6.1", "--destination", str(self.destination),
             "--work", str(self.work), "--archive", str(self.archive),
             "--checksums", str(self.checksums), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(expect, process.returncode,
                         f"stdout: {process.stdout}\nstderr: {process.stderr}")
        return process

    def test_strips_nested_release_directory_and_records_verified_hash(self):
        self.write_checksums(f"{self.digest}  git-lfs-linux-amd64-v3.6.1.tar.gz\n")
        sha_output = self.root / "git-lfs-tarball.sha256"
        process = self.run_helper(0, "--sha-output", str(sha_output))
        installed = self.destination / "git-lfs"
        self.assertTrue(installed.is_file())
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(self.digest, sha_output.read_text().strip())
        self.assertIn("official sha256", process.stdout)

    def test_rejects_checksum_mismatch_without_installing(self):
        self.write_checksums(f"{'0' * 64}  git-lfs-linux-amd64-v3.6.1.tar.gz\n")
        process = self.run_helper(1)
        self.assertIn("does not match the official", process.stderr)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_missing_checksum_entry_without_installing(self):
        self.write_checksums(f"{self.digest}  another-file.tar.gz\n")
        process = self.run_helper(1)
        self.assertIn("exactly one entry", process.stderr)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_archive_without_expected_nested_layout(self):
        flat = self.work / "git-lfs-linux-amd64-v3.6.1.tar.gz"
        flat.unlink()
        with tarfile.open(flat, "w:gz") as tar:
            tar.add(self.source / "git-lfs", arcname="git-lfs")
        self.archive = flat
        self.digest = hashlib.sha256(flat.read_bytes()).hexdigest()
        self.write_checksums(f"{self.digest}  git-lfs-linux-amd64-v3.6.1.tar.gz\n")
        process = self.run_helper(1)
        self.assertFalse((self.destination / "git-lfs").exists())
        self.assertNotEqual("", process.stderr)


    @staticmethod
    def pgp_signed_manifest(body_lines, trailing=""):
        body = "\n".join(body_lines)
        return (
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA256\n"
            "\n"
            f"{body}\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "\n"
            "iQIcBAEBCAAGBQJnUnoqAAoJEPVP5kgIgzWpHCUQALK8YOdgMu/MsQPs8MLgPNuZ\n"
            "=SrT+\n"
            "-----END PGP SIGNATURE-----\n"
            f"{trailing}"
        )

    def test_accepts_official_pgp_cleartext_sha256sums_asc_and_pinned_digest(self):
        self.checksums = self.work / "sha256sums.asc"
        self.write_checksums(
            self.pgp_signed_manifest([
                f"{'1' * 64} *git-lfs-darwin-amd64-v3.6.1.zip",
                f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz",
                f"{'2' * 64} *git-lfs-v3.6.1.tar.gz",
            ])
        )
        sha_output = self.root / "git-lfs-tarball.sha256"
        self.run_helper(
            0,
            "--expected-sha256",
            self.digest,
            "--sha-output",
            str(sha_output),
        )
        installed = self.destination / "git-lfs"
        self.assertTrue(installed.is_file())
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(self.digest, sha_output.read_text().strip())

    def test_downloads_sha256sums_asc_by_default_from_base_url(self):
        release_dir = self.root / "release"
        release_dir.mkdir()
        (release_dir / "git-lfs-linux-amd64-v3.6.1.tar.gz").write_bytes(self.archive.read_bytes())
        (release_dir / "sha256sums.asc").write_text(
            self.pgp_signed_manifest([f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz"])
        )
        fresh_work = self.root / "fresh-work"
        sha_output = self.root / "downloaded.sha256"
        process = subprocess.run(
            [
                str(SCRIPT),
                "--version",
                "3.6.1",
                "--destination",
                str(self.destination),
                "--work",
                str(fresh_work),
                "--base-url",
                release_dir.as_uri(),
                "--expected-sha256",
                self.digest,
                "--sha-output",
                str(sha_output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, process.returncode, f"stdout: {process.stdout}\nstderr: {process.stderr}")
        self.assertTrue((fresh_work / "sha256sums.asc").is_file())
        self.assertFalse((fresh_work / "sha256sums.txt").exists())
        self.assertEqual(self.digest, sha_output.read_text().strip())

    def test_rejects_unsigned_entry_outside_pgp_signed_body(self):
        self.checksums = self.work / "sha256sums.asc"
        self.write_checksums(
            self.pgp_signed_manifest(
                [f"{'1' * 64} *git-lfs-v3.6.1.tar.gz"],
                trailing=f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n",
            )
        )
        self.run_helper(1)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_truncated_pgp_manifest_without_end_signature(self):
        self.checksums = self.work / "sha256sums.asc"
        self.write_checksums(
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA256\n\n"
            f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "truncated\n"
        )
        self.run_helper(1)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_expected_sha256_pin_mismatch_without_installing(self):
        self.checksums = self.work / "sha256sums.asc"
        self.write_checksums(
            self.pgp_signed_manifest([f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz"])
        )
        other = ("a" if self.digest[0] != "a" else "b") * 64
        process = self.run_helper(1, "--expected-sha256", other)
        self.assertIn("pinned --expected-sha256", process.stderr)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_duplicate_manifest_entries_without_installing(self):
        self.write_checksums(
            f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n"
            f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n"
        )
        process = self.run_helper(1)
        self.assertIn("exactly one entry", process.stderr)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_unsigned_sha256sums_asc_without_pgp_framing(self):
        self.checksums = self.work / "sha256sums.asc"
        self.write_checksums(f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n")
        self.run_helper(1)
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_unsigned_default_downloaded_sha256sums_asc(self):
        release_dir = self.root / "unsigned-release"
        release_dir.mkdir()
        (release_dir / "git-lfs-linux-amd64-v3.6.1.tar.gz").write_bytes(self.archive.read_bytes())
        (release_dir / "sha256sums.asc").write_text(
            f"{self.digest} *git-lfs-linux-amd64-v3.6.1.tar.gz\n"
        )
        fresh_work = self.root / "unsigned-work"
        process = subprocess.run(
            [
                str(SCRIPT),
                "--version",
                "3.6.1",
                "--destination",
                str(self.destination),
                "--work",
                str(fresh_work),
                "--base-url",
                release_dir.as_uri(),
                "--expected-sha256",
                self.digest,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(1, process.returncode, f"stdout: {process.stdout}\nstderr: {process.stderr}")
        self.assertFalse((self.destination / "git-lfs").exists())

    def test_rejects_symlink_binary_inside_archive(self):
        target = self.root / "real-target"
        target.write_text("#!/usr/bin/env bash\necho 'git-lfs/3.6.1 (symlink)'\n")
        target.chmod(0o755)
        symlink_dir = self.root / "symlink-src/git-lfs-3.6.1"
        symlink_dir.mkdir(parents=True)
        (symlink_dir / "git-lfs").symlink_to(target)
        symlink_archive = self.work / "git-lfs-linux-amd64-v3.6.1.tar.gz"
        symlink_archive.unlink()
        with tarfile.open(symlink_archive, "w:gz") as tar:
            tar.add(symlink_dir, arcname="git-lfs-3.6.1", recursive=True)
        self.archive = symlink_archive
        self.digest = hashlib.sha256(symlink_archive.read_bytes()).hexdigest()
        self.write_checksums(f"{self.digest}  git-lfs-linux-amd64-v3.6.1.tar.gz\n")
        process = self.run_helper(1)
        self.assertIn("regular top-level git-lfs binary", process.stderr)
        self.assertFalse((self.destination / "git-lfs").exists())


class CandidateAndPrWorkflowWiringTest(unittest.TestCase):
    PINNED_LFS_SHA256 = "2138d2e405a12f1a088272e06790b76699b79cb90d0317b77aafaf35de908d76"

    def test_candidate_workflow_pins_lfs_digest_safe_directory_and_always_manifests(self):
        text = (ROOT / ".github/workflows/candidate-release-acceptance.yml").read_text(encoding="utf-8")
        self.assertIn(f'GIT_LFS_TARBALL_SHA256: "{self.PINNED_LFS_SHA256}"', text)
        self.assertIn('--expected-sha256 "$GIT_LFS_TARBALL_SHA256"', text)
        self.assertIn('--require-fixture-exact "git_lfs_tarball_sha256=$GIT_LFS_TARBALL_SHA256"', text)
        self.assertIn("GIT_CONFIG_KEY_0=safe.directory", text)
        self.assertIn("GIT_CONFIG_VALUE_0=$GITHUB_WORKSPACE", text)
        self.assertIn("ROOTYARD_TEST_EVIDENCE_DIR=$workspace/test-results/candidate/browser/evidence", text)
        self.assertNotIn("${{ github.workspace }}/test-results/candidate/browser/evidence", text)
        self.assertNotIn('test -s "${OBJECT_STORE_ENV_FILE:?}"', text)
        self.assertIn('extra_args+=(--fixture "object_store_env=")', text)
        self.assertIn("--require-case browser_ui=chromium_browser_workflow", text)
        self.assertIn('--fixture "browser_postgres_server_version=$postgres_server_version"', text)
        self.assertIn('--fixture "browser_postgres_client_version=$postgres_client_version"', text)
        self.assertIn('--fixture "object_store_postgres_server_version=$postgres_server_version"', text)
        self.assertIn('--fixture "object_store_postgres_client_version=$postgres_client_version"', text)
        self.assertNotIn('--fixture "postgres_server_version=', text)
        self.assertNotIn('--fixture "postgres_client_version=', text)
        self.assertEqual(2, text.count("--harness tests/owned_fuse_cleanup.py"))
        self.assertEqual(2, text.count("--harness scripts/build_native.py"))

    def test_release_manifest_accepts_debian_and_ubuntu_pgdg_psql_versions_across_jobs(self):
        from tests.test_native_report_manifest import ManifestFixture

        with tempfile.TemporaryDirectory() as tmp:
            fixture = ManifestFixture(tmp)
            browser_report = fixture.report("browser_ui")
            browser_manifest = fixture.job(
                "browser.json",
                reports={"browser_ui": browser_report},
                extra=(
                    "--fixture",
                    "browser_postgres_server_version=17.11 (Debian 17.11-1.pgdg120+1)",
                    "--fixture",
                    "browser_postgres_client_version=psql (PostgreSQL) 17.11 (Debian 17.11-0+deb13u1)",
                    "--fixture",
                    "rust=rustc 1.99.1 (58cf8f9c3 2026-10-13)",
                    "--fixture",
                    "playwright_version=1.49.0",
                    "--fixture",
                    "chromium_version=Chromium 131.0",
                ),
            )
            store_manifest = fixture.job(
                "object-store.json",
                reports={
                    "lfs_hydration": fixture.report("lfs_hydration"),
                    "lfs_remote": fixture.report("lfs_remote"),
                    "lfs_retention": fixture.report("lfs_retention"),
                },
                extra=(
                    "--fixture",
                    "object_store_postgres_server_version=17.11 (Debian 17.11-1.pgdg120+1)",
                    "--fixture",
                    "object_store_postgres_client_version=psql (PostgreSQL) 17.11 (Ubuntu 17.11-1.pgdg24.04+2)",
                    "--fixture",
                    "rust=rustc 1.99.1 (58cf8f9c3 2026-10-13)",
                    "--fixture",
                    "garage_version=2.1.0",
                    "--fixture",
                    "git_lfs_version=3.6.1",
                ),
            )
            browser_dir = fixture.artifact_directory("browser", browser_manifest)
            store_dir = fixture.artifact_directory("object-store", store_manifest)
            gate_out = fixture.root / "candidate-release-gate.json"
            fixture.run(
                "--mode",
                "release",
                "--manifest-out",
                gate_out,
                "--expect-commit",
                fixture.commit,
                "--artifact-dir",
                f"browser={browser_dir}",
                "--artifact-dir",
                f"object-store={store_dir}",
                "--job-manifest",
                f"browser={browser_manifest}",
                "--job-manifest",
                f"object-store={store_manifest}",
                "--require-report",
                "browser_ui",
                "--require-report",
                "lfs_hydration",
                "--require-report",
                "lfs_remote",
                "--require-report",
                "lfs_retention",
                "--require-fixture-exact",
                "garage_version=2.1.0",
                "--require-fixture-exact",
                "git_lfs_version=3.6.1",
                "--require-fixture-exact",
                "playwright_version=1.49.0",
                "--require-fixture",
                "chromium_version=Chromium",
                expect=0,
            )

    def test_ci_workflow_runs_and_binds_recent_native_regressions(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for report_key, report_path, harness in (
            ("webhook_pagination", "test-results/webhook-pagination.json", "tests/webhook_pagination.py"),
            ("webhook_pr_sync", "test-results/webhook-pr-sync.json", "tests/webhook_pr_sync.py"),
            ("web_repository_pagination", "test-results/web-repository-pagination.json", "tests/web_repository_pagination.py"),
            ("worker_diagnostics", "test-results/worker-diagnostics.json", "tests/worker_diagnostics.py"),
            ("lfs_read_amplification", "test-results/lfs-read-amplification.json", "tests/lfs_read_amplification.py"),
            ("lfs_split_tx_races", "test-results/lfs-split-tx-races.json", "tests/lfs_split_tx_races.py"),
        ):
            self.assertIn(f"python3 {harness} --binary target/debug/rootyard --report {report_path}", text)
            self.assertIn(f"--report {report_key}={report_path}", text)
            self.assertIn(f"--harness {harness}", text)
        for shared_lfs_harness in ("tests/lfs.py", "tests/lfs_remote_contract.py"):
            self.assertIn(f"--harness {shared_lfs_harness}", text)
        self.assertIn("--require-case lfs_read_amplification=read_amplification_and_offline_remote", text)
        self.assertIn("--require-case lfs_split_tx_races=split_tx_races_reauth_and_repair_dedup", text)
        self.assertIn("--harness scripts/build_native.py", text)
        self.assertIn("test-results/*-evidence/*.jsonl", text)

    def test_candidate_retention_step_unsets_object_store_without_empty_env_exports(self):
        import re

        lines = (
            ROOT / ".github/workflows/candidate-release-acceptance.yml"
        ).read_text(encoding="utf-8").splitlines()
        object_store_vars = (
            "ROOTYARD_OBJECT_STORE_ENDPOINT",
            "ROOTYARD_OBJECT_STORE_BUCKET",
            "ROOTYARD_OBJECT_STORE_REGION",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY",
            "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
        )
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            self.assertIsNone(
                re.match(r'^ROOTYARD_OBJECT_STORE_[A-Z0-9_]*:\s*(?:""|\'\')?\s*(?:#.*)?$', stripped),
                f"workflow must never export empty ROOTYARD_OBJECT_STORE_* in YAML env: {line!r}",
            )

        step_header = "      - name: Exercise LFS publication and retention without any remote object store"
        self.assertIn(step_header, lines)
        start = lines.index(step_header) + 1
        step_lines = []
        for line in lines[start:]:
            if line.startswith("      - ") or (line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip(" ")) < 8):
                break
            step_lines.append(line)

        self.assertFalse(
            any(line.startswith("        env:") for line in step_lines),
            "retention step must not declare a step-level env: block",
        )
        run_idx = step_lines.index("        run: |")
        run_lines = [
            line[10:]
            for line in step_lines[run_idx + 1:]
            if line.startswith("          ") and not line[10:].lstrip().startswith("#")
        ]
        harness_pos = next(
            i for i, cmd in enumerate(run_lines) if "tests/lfs_retention_acceptance.py" in cmd
        )
        prologue = "\n".join(run_lines[:harness_pos])
        unset_match = re.search(r"(?m)^unset\s+(.+)$", prologue)
        self.assertIsNotNone(unset_match, f"missing unset before lfs_retention_acceptance.py: {prologue!r}")
        unset_tokens = unset_match.group(1).split()
        for var in object_store_vars:
            self.assertIn(var, unset_tokens)

        after_unset = prologue[unset_match.end():]
        self.assertIn('test -z "${ROOTYARD_OBJECT_STORE_ENDPOINT+set}"', after_unset)
        self.assertIn('test -z "${ROOTYARD_OBJECT_STORE_BUCKET+set}"', after_unset)
        self.assertNotIn("ROOTYARD_OBJECT_STORE_ENDPOINT:-", prologue)
        self.assertNotIn("ROOTYARD_OBJECT_STORE_BUCKET:-", prologue)

        populated_env = {**os.environ, **{var: "inherited-value" for var in object_store_vars}}
        probe = subprocess.run(
            [
                "bash",
                "-c",
                prologue
                + '\npython3 -c \'import os, sys; sys.exit(1 if [k for k in os.environ if k.startswith("ROOTYARD_OBJECT_STORE_")] else 0)\'',
            ],
            env=populated_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, probe.returncode, f"stdout: {probe.stdout}\nstderr: {probe.stderr}")


if __name__ == "__main__":
    unittest.main()
