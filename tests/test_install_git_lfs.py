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


if __name__ == "__main__":
    unittest.main()
