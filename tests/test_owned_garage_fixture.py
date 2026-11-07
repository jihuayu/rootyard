"""Negative and positive guard tests for the owned Garage fixture cleanup.

These are cheap unit tests with a stub docker on PATH. They prove that stop()
refuses foreign paths, symlinks, non-owned directories and containers whose
labels/ID do not match the sentinel, without touching anything, and that an
actually owned sentinel/container pair is removed by id. They also prove the
cold-cache start path: an absent pinned image is pulled once, before any
inspect, and a failed pull fails closed while only the freshly created fixture
is removed. The real fixture is smoked by the coordinator after commit; no
Docker daemon, image pull or image cache mutation happens here.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/owned_garage_fixture.sh"
PINNED_IMAGE = (
    "dxflrs/garage:v2.1.0@sha256:"
    "4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a"
)
EXPECTED_DIGEST = "sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a"


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
            f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$STUB_DOCKER_LOG"
sentinel_field() {{ sed -n "s/^$1=//p" "${{STUB_SENTINEL:?}}" 2>/dev/null | head -n 1; }}
# STUB_IMAGE_STATE simulates the docker image cache: unset means the image is
# always present (a warm runner), a path means present only once that file
# exists, so a missing file is a cold cache.
image_present() {{ [ -z "${{STUB_IMAGE_STATE:-}}" ] || [ -e "$STUB_IMAGE_STATE" ]; }}
case "$*" in
  'image inspect'*)
    image_present || exit 1
    case "$*" in
      *'{{{{.Id}}}}'*) printf '%s\\n' 'sha256:fake-image-id' ;;
      *RepoDigests*) printf '%s\\n' 'dxflrs/garage@{EXPECTED_DIGEST}' ;;
      *) exit 1 ;;
    esac ;;
  'pull '*)
    printf '%s\\n' "stub pull: $2 (token=${{STUB_PULL_TOKEN:-none}})" >&2
    [ "${{STUB_PULL_EXIT:-0}}" -eq 0 ] || exit "${{STUB_PULL_EXIT}}"
    [ -n "${{STUB_IMAGE_STATE:-}}" ] && : >"$STUB_IMAGE_STATE"
    exit 0 ;;
  *'run --rm'*'--version'*) printf '%s\\n' 'garage v2.1.0 [features: bundled-libs]' ;;
  *'create --rm'*) printf '%s\\n' "${{STUB_CONTAINER_ID:?}}" ;;
  exec*)
    case "$*" in
      *'node id'*) printf '%s\\n' "$(printf 'b%.0s' {{1..64}})@127.0.0.1:3901" ;;
      *'key create'*) printf 'Key ID:         %s\\nSecret key:     %s\\nCreated:        2026-11-07\\n' "${{STUB_ACCESS_KEY:-GK0123456789abcdef01234567}}" "${{STUB_SECRET_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}}" ;;
      *) exit 0 ;;
    esac ;;
  *'{{{{.Id}}}}'*) printf '%s\\n' "${{STUB_CONTAINER_ID:?}}" ;;
  *'rootyard.fixture.kind'*) printf '%s\\n' "${{STUB_KIND:-owned-garage}}" ;;
  *'rootyard.fixture.nonce'*) printf '%s\\n' "${{STUB_NONCE:-$(sentinel_field nonce)}}" ;;
  *'rootyard.fixture.directory'*) printf '%s\\n' "${{STUB_PATH:-$(sentinel_field directory)}}" ;;
  *'rootyard.fixture.uid'*) printf '%s\\n' "${{STUB_UID:-$(sentinel_field uid)}}" ;;
  *'rootyard.fixture.name'*) printf '%s\\n' "${{STUB_NAME:-$(sentinel_field container_name)}}" ;;
  rm*) exit "${{STUB_RM_EXIT:-0}}" ;;
  start*) exit "${{STUB_START_EXIT:-0}}" ;;
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
        environment["STUB_SENTINEL"] = str(directory / ".rootyard-owned-fixture")
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
        environment["STUB_CONTAINER_ID"] = self.cid
        environment["STUB_SENTINEL"] = str(directory / ".rootyard-owned-fixture")
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

    def test_start_parses_padded_key_and_cleans_up_after_probe_failure(self):
        directory = self.root / "owned"
        access = "GK00112233445566778899aabb"
        secret = "cd" * 32
        process = self.start(
            directory, 1, "--port", "55982",
            env={
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "STUB_ACCESS_KEY": access,
                "STUB_SECRET_KEY": secret,
            },
        )
        combined = process.stdout + process.stderr
        self.assertNotIn("unbound variable", combined)
        self.assertNotIn("no access key", combined)
        self.assertNotIn("no secret key", combined)
        self.assertNotIn(secret, combined)
        allow = [line for line in self.docker_calls().splitlines() if "bucket allow" in line]
        self.assertEqual(1, len(allow), self.docker_calls())
        self.assertIn(f"--key {access} ", allow[0])
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_start_failure_after_container_create_cleans_only_minted_resources(self):
        directory = self.root / "owned"
        process = self.start(directory, 1, env={"STUB_START_EXIT": "1"})
        combined = process.stdout + process.stderr
        self.assertNotIn("unbound variable", combined)
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_failed_cleanup_reports_but_keeps_the_original_start_status(self):
        directory = self.root / "owned"
        process = self.start(
            directory, 7,
            env={"STUB_START_EXIT": "7", "STUB_RM_EXIT": "1"},
        )
        combined = process.stdout + process.stderr
        self.assertIn("start failed with status 7", process.stderr)
        self.assertIn(
            "cleanup of the owned fixture also failed with status 1", process.stderr)
        self.assertNotIn("unbound variable", combined)
        # The report is generic: no sentinel fields, env values or pull log text.
        for line in process.stderr.splitlines():
            self.assertTrue(line.startswith("owned garage fixture: "), line)
        self.assertNotIn("nonce=", combined)
        self.assertNotIn("ROOTYARD_", combined)
        # Cleanup was attempted but refused by the failing docker rm, so the
        # fixture is left intact for inspection rather than reported as removed.
        calls = self.docker_calls()
        self.assertIn(f"rm -f -- {self.cid}", calls)
        self.assertTrue((directory / ".rootyard-owned-fixture").is_file())
        self.assertFalse((self.root / "outside.env").exists())


class ColdCacheImageTest(FixtureGuardTest):
    """A fresh runner has an empty image cache; the helper must warm it itself."""

    def test_cold_cache_pulls_pinned_reference_before_first_inspect(self):
        directory = self.root / "cold"
        state = self.root / "image-state"
        process = self.start(
            directory, 1,
            env={
                "STUB_IMAGE_STATE": str(state),
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "STUB_PULL_TOKEN": "cold-cache-token",
            },
        )
        calls = self.docker_calls().splitlines()
        pulls = [index for index, line in enumerate(calls) if line.startswith("pull ")]
        self.assertEqual(1, len(pulls), self.docker_calls())
        self.assertEqual(f"pull {PINNED_IMAGE}", calls[pulls[0]])
        self.assertTrue(state.exists(), "the stub pull did not warm the simulated cache")
        inspects = [index for index, line in enumerate(calls) if line.startswith("image inspect")]
        self.assertTrue(inspects, self.docker_calls())
        self.assertLess(pulls[0], inspects[-1], self.docker_calls())
        creates = [index for index, line in enumerate(calls) if line.startswith("create --rm")]
        self.assertTrue(creates and creates[0] > pulls[0], self.docker_calls())
        combined = process.stdout + process.stderr
        self.assertNotIn("cold-cache-token", combined)
        self.assertNotIn(":latest", self.docker_calls())
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_warm_cache_never_pulls(self):
        directory = self.root / "warm"
        process = self.start(
            directory, 1,
            env={
                "STUB_IMAGE_STATE": str(self.log),  # present before start
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
            },
        )
        self.assertNotIn("pull ", self.docker_calls())
        self.assertIn("create --rm", self.docker_calls())
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_pull_failure_fails_closed_and_removes_only_the_new_fixture(self):
        directory = self.root / "cold"
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        keep = unrelated / "keep.txt"
        keep.write_text("unrelated caller data")
        sibling = self.root / "outside.env"
        process = self.start(
            directory, 1,
            env={
                "STUB_IMAGE_STATE": str(self.root / "absent-image"),
                "STUB_PULL_EXIT": "1",
                "ROOTYARD_FIXTURE_PULL_ATTEMPTS": "2",
                "ROOTYARD_FIXTURE_PULL_TIMEOUT": "5",
            },
        )
        combined = process.stdout + process.stderr
        self.assertIn("docker pull", combined)
        self.assertIn("after 2 attempt(s)", combined)
        self.assertNotIn("unbound variable", combined)
        calls = self.docker_calls()
        pulls = [line for line in calls.splitlines() if line.startswith("pull ")]
        self.assertEqual(2, len(pulls), calls)
        for line in pulls:
            self.assertEqual(f"pull {PINNED_IMAGE}", line)
        self.assertNotIn("create", calls)
        self.assertNotIn("run --rm", calls)
        self.assertNotIn(self.cid, calls)
        self.assertFalse(directory.exists())
        self.assertFalse((directory / ".rootyard-owned-fixture").exists())
        self.assertFalse(sibling.exists())
        self.assertEqual("unrelated caller data", keep.read_text())
        self.assertTrue(unrelated.is_dir())

    def test_absent_mutable_tag_is_refused_instead_of_pulled(self):
        directory = self.root / "cold"
        process = self.start(
            directory, 1, "--image", "dxflrs/garage:v2.1.0",
            env={"STUB_IMAGE_STATE": str(self.root / "absent-image")},
        )
        self.assertIn("only the pinned digest reference may be pulled", process.stderr)
        self.assertNotIn("pull", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())


if __name__ == "__main__":
    unittest.main()
