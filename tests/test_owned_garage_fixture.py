"""Negative and positive guard tests for the owned Garage fixture cleanup.

These are cheap unit tests with a stub docker on PATH. They prove that stop()
refuses foreign paths, symlinks, non-owned directories and containers whose
labels/ID do not match the sentinel, without touching anything, and that an
actually owned sentinel/container pair is removed by id. The real fixture is
smoked by the coordinator after commit; no Docker daemon or image is needed.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/owned_garage_fixture.sh"


class FixtureGuardTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "docker.log"
        self.log.write_text("")
        docker = self.bin / "docker"
        docker.write_text(
            """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$STUB_DOCKER_LOG"
case "$*" in
  *'{{.Id}}'*) printf '%s\\n' "${STUB_CONTAINER_ID:?}" ;;
  *'rootyard.fixture.kind'*) printf '%s\\n' "${STUB_KIND:-owned-garage}" ;;
  *'rootyard.fixture.nonce'*) printf '%s\\n' "${STUB_NONCE:-}" ;;
  *'rootyard.fixture.directory'*) printf '%s\\n' "${STUB_PATH:-}" ;;
  *'rootyard.fixture.uid'*) printf '%s\\n' "${STUB_UID:-$(id -u)}" ;;
  *'rootyard.fixture.name'*) printf '%s\\n' "${STUB_NAME:-}" ;;
  rm*) exit 0 ;;
  *) exit 1 ;;
esac
"""
        )
        docker.chmod(0o755)
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["STUB_DOCKER_LOG"] = str(self.log)
        self.env.pop("GITHUB_WORKSPACE", None)
        self.env.pop("RUNNER_TEMP", None)
        self.cid = "c" * 64
        self.nonce = "n" * 32

    def tearDown(self):
        self.temporary.cleanup()

    def sentinel(self, directory, *, cid=None, nonce=None, kind="rootyard-owned-garage-fixture",
                 output_env="", name="owned-name"):
        directory.mkdir(parents=True, exist_ok=True)
        rows = {
            "kind": kind,
            "version": "1",
            "directory": str(directory),
            "uid": str(os.getuid()),
            "nonce": nonce if nonce is not None else self.nonce,
            "container_id": cid if cid is not None else self.cid,
            "container_name": name,
            "output_env": str(output_env),
        }
        path = directory / ".rootyard-owned-fixture"
        path.write_text("".join(f"{key}={value}\n" for key, value in rows.items()))
        path.chmod(0o600)
        return path

    def stub_container(self, directory, **overrides):
        values = {
            "STUB_CONTAINER_ID": self.cid,
            "STUB_NONCE": self.nonce,
            "STUB_PATH": str(directory),
            "STUB_UID": str(os.getuid()),
            "STUB_NAME": "owned-name",
            "STUB_KIND": "owned-garage",
        }
        values.update(overrides)
        return values

    def run_script(self, action, directory, expect, env=None):
        environment = self.env.copy()
        environment.update(self.stub_container(directory))
        environment.update(env or {})
        process = subprocess.run(
            [str(SCRIPT), action, "--directory", str(directory)],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(expect, process.returncode, process.stderr)
        return process

    def docker_calls(self):
        return self.log.read_text()

    def start(self, directory, expect, *extra, env=None):
        environment = self.env.copy()
        environment.update(env or {})
        process = subprocess.run(
            [str(SCRIPT), "start", "--directory", str(directory),
             "--output-env", str(self.root / "outside.env"), *extra],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(expect, process.returncode, process.stderr)
        return process

    def test_foreign_nonempty_directory_is_rejected_without_touching_it(self):
        directory = self.root / "foreign"
        directory.mkdir()
        keep = directory / "keep.txt"
        keep.write_text("caller data")
        process = self.run_script("stop", directory, 1)
        self.assertIn("no ownership sentinel", process.stderr)
        self.assertEqual("caller data", keep.read_text())
        self.assertNotIn(" rm ", f" {self.docker_calls()} ")

    def test_symlink_fixture_path_is_rejected_without_touching_target(self):
        target = self.root / "target"
        self.sentinel(target)
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        process = self.run_script("stop", link, 1)
        self.assertIn("symlink", process.stderr)
        self.assertTrue((target / ".rootyard-owned-fixture").is_file())
        self.assertNotIn(" rm ", f" {self.docker_calls()} ")

    def test_mismatched_container_label_is_rejected_before_removal(self):
        directory = self.root / "owned"
        self.sentinel(directory)
        process = self.run_script("stop", directory, 1, env={"STUB_NONCE": "x" * 32})
        self.assertIn("nonce does not match", process.stderr)
        self.assertTrue(directory.is_dir())
        self.assertNotIn(" rm ", f" {self.docker_calls()} ")

    def test_mismatched_container_id_is_rejected_before_removal(self):
        directory = self.root / "owned"
        self.sentinel(directory)
        process = self.run_script("stop", directory, 1, env={"STUB_CONTAINER_ID": "d" * 64})
        self.assertIn("resolved to", process.stderr)
        self.assertTrue(directory.is_dir())
        self.assertNotIn(" rm ", f" {self.docker_calls()} ")

    def test_owned_sentinel_and_container_are_removed_by_id(self):
        directory = self.root / "owned"
        env_file = self.root / "object-store.env"
        env_file.write_text("ROOTYARD_OBJECT_STORE_ENDPOINT=http://127.0.0.1:3900\n")
        env_file.chmod(0o600)
        self.sentinel(directory, output_env=env_file)
        process = self.run_script("stop", directory, 0)
        self.assertEqual("", process.stderr)
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse(env_file.exists())

    def test_empty_root_and_ancestor_paths_are_rejected(self):
        for path in ("", "/", str(self.root.parent)):
            process = subprocess.run(
                [str(SCRIPT), "stop", "--directory", path], env=self.env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(1, process.returncode, path)
            self.assertTrue(process.stderr.strip(), path)

    def test_start_rejects_preexisting_nonempty_path_before_docker(self):
        directory = self.root / "existing"
        directory.mkdir()
        (directory / "keep.txt").write_text("keep")
        process = self.start(directory, 1)
        self.assertIn("non-empty", process.stderr)
        self.assertEqual("", self.docker_calls())
        self.assertTrue((directory / "keep.txt").is_file())

    def test_start_rejects_symlink_path_before_docker(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        process = self.start(link, 1)
        self.assertIn("symlink", process.stderr)
        self.assertEqual("", self.docker_calls())


if __name__ == "__main__":
    unittest.main()
