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
import re
import socket
import subprocess
import tempfile
import time
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
      *'node id'*)
        # Persistent probe count: STUB_NODE_HANG hangs one call, and the first
        # STUB_NODE_FAILS calls fail like a node id that is not readable yet.
        count=$(cat "${{STUB_NODE_COUNTER:?}}" 2>/dev/null || printf 0)
        count=$((count + 1))
        printf '%s\\n' "$count" >"${{STUB_NODE_COUNTER}}"
        [ "$count" -gt "${{STUB_NODE_HANG_AFTER:-0}}" ] || exec sleep 600
        [ "$count" -gt "${{STUB_NODE_FAILS:-0}}" ] || exit 1
        printf '%s\\n' "$(printf 'b%.0s' {{1..64}})@127.0.0.1:3901" ;;
      *' status'*)
        # Persistent, private RPC-handshake counter: node id is always readable,
        # but the first STUB_STATUS_FAILS read-only status calls fail the way a
        # not-yet-ready RPC listener does.
        count=$(cat "${{STUB_STATUS_COUNTER:?}}" 2>/dev/null || printf 0)
        count=$((count + 1))
        printf '%s\\n' "$count" >"${{STUB_STATUS_COUNTER}}"
        [ "$count" -gt "${{STUB_STATUS_HANG_AFTER:-0}}" ] || exec sleep 600
        [ "$count" -gt "${{STUB_STATUS_FAILS:-0}}" ] || {{ echo 'Error: unable to connect: Connection refused' >&2; exit 1; }}
        printf 'Healthy: 1/1 nodes connected\n' ;;
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
        self.env["STUB_STATUS_COUNTER"] = str(self.root / "status.count")
        self.env["STUB_NODE_COUNTER"] = str(self.root / "node.count")
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

    def held_dead_port(self):
        """A never-listening 127.0.0.1:0 port owned by this test, held until it ends."""
        self.holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.holder.bind(("127.0.0.1", 0))
        # Deliberately no listen(): a bound-but-unlistening port rejects every
        # connection, so the S3 readiness probe cannot be satisfied by anything
        # the test did not create (e.g. another service already on 3900).
        self.addCleanup(self.holder.close)
        return self.holder.getsockname()[1]

    def bound_start(self, directory, *extra, env=None):
        """Start on a port this test holds unlistening, instead of the shared default."""
        port = self.held_dead_port()
        return self.start(directory, 1, "--port", str(port), *extra, env=env), port

    def default_probe_port(self):
        """Port the helper probes when --port is absent: parsed from the script default."""
        source = SCRIPT.read_text()
        match = re.search(r'^port="?(\d+)"?$', source, re.MULTILINE)
        self.assertIsNotNone(match, "the helper no longer declares a default port")
        return int(match.group(1))

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
        # bound_start passes --port explicitly, pinned to one this test holds:
        # a real S3 service on the helper's default port (e.g. 127.0.0.1:3900)
        # cannot answer the probe and the expected start/cleanup failure stays
        # exact.
        process, _ = self.bound_start(
            directory,
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
        process, _ = self.bound_start(
            directory,
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

    def test_layout_mutation_waits_for_read_only_rpc_ready(self):
        # node id is readable immediately, but the RPC handshake fails twice
        # first: no layout mutation may be issued before a status succeeds.
        directory = self.root / "cold"
        process, _ = self.bound_start(
            directory,
            env={
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "ROOTYARD_FIXTURE_STARTUP_TIMEOUT": "3",
                "STUB_STATUS_FAILS": "2",
            },
        )
        calls = self.docker_calls().splitlines()
        statuses = [i for i, line in enumerate(calls) if line.endswith(" status")]
        nodes = [i for i, line in enumerate(calls) if line.endswith(" node id")]
        layouts = [i for i, line in enumerate(calls)
                   if " layout assign " in line or " layout apply " in line]
        self.assertEqual(3, len(statuses), self.docker_calls())
        self.assertTrue(nodes and nodes[0] < statuses[0], self.docker_calls())
        self.assertEqual(2, len(layouts), self.docker_calls())
        self.assertLess(statuses[-1], layouts[0], self.docker_calls())
        self.assertIn("layout assign -z dc1 -c 1G ", calls[layouts[0]])
        self.assertIn("layout apply --version 1", calls[layouts[1]])
        # start then proceeds past the layout to the (stubbed) S3 readiness
        # probe, which still fails closed because no responder listens, and the
        # owned fixture is cleaned up exactly as before.
        self.assertEqual(1, process.returncode, process.stderr)
        self.assertIn('S3 endpoint http://127.0.0.1:', process.stderr)
        self.assertNotIn("read-only 'garage status' handshake", process.stderr)
        self.assertIn(f"rm -f -- {self.cid}", self.docker_calls())
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())
        self.assertNotIn("pull ", self.docker_calls())

    def test_permanently_unavailable_rpc_fails_within_bound_and_cleans_up(self):
        # The RPC handshake never succeeds inside a short startup budget: start
        # fails closed well under a minute, performs no layout mutation, runs no
        # key creation, leaks nothing and reports no credential or configuration.
        directory = self.root / "cold"
        port = self.held_dead_port()
        started = time.monotonic()
        process = self.start(
            directory, 1, "--port", str(port),
            env={
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "ROOTYARD_FIXTURE_STARTUP_TIMEOUT": "2",
                "STUB_STATUS_FAILS": "1000000",
            },
        )
        self.assertLess(time.monotonic() - started, 20, "the startup budget was not honoured")
        calls = self.docker_calls()
        self.assertNotIn(" layout assign ", calls)
        self.assertNotIn(" layout apply ", calls)
        self.assertNotIn("key create", calls)
        self.assertNotIn("bucket create", calls)
        self.assertIn("read-only 'garage status' handshake", process.stderr)
        self.assertIn("within the 2s startup budget", process.stderr)
        combined = process.stdout + process.stderr
        self.assertNotIn("GK0123456789abcdef01234567", combined)
        self.assertNotIn("ROOTYARD_", combined)
        self.assertNotIn('"debug"', combined)
        attempts = int((self.root / "status.count").read_text().strip())
        self.assertGreater(attempts, 1, "the handshake was not retried within the budget")
        self.assertIn(f"rm -f -- {self.cid}", calls)
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_hung_rpc_probe_is_killed_within_the_short_budget(self):
        # The stub docker hosts `garage status` and hangs every call. This
        # proves the host-side stub (and the `timeout` wrapper around it) is
        # cleaned up within the 2s absolute budget, the call sequence issues no
        # layout/key mutation and stop runs. It does not observe whether a
        # remote process inside a real container exits: the stuck-probe process
        # is only signalled; removal is proven solely by the `rm -f` call.
        directory = self.root / "cold"
        port = self.held_dead_port()
        started = time.monotonic()
        process = self.start(
            directory, 1, "--port", str(port),
            env={
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "ROOTYARD_FIXTURE_STARTUP_TIMEOUT": "2",
                "STUB_STATUS_HANG_AFTER": "1000000",
            },
        )
        self.assertLess(time.monotonic() - started, 20, "a hung status call was not bounded")
        calls = self.docker_calls()
        self.assertNotIn(" layout assign ", calls)
        self.assertNotIn(" layout apply ", calls)
        self.assertNotIn("key create", calls)
        self.assertIn("read-only 'garage status' handshake", process.stderr)
        self.assertIn("within the 2s startup budget", process.stderr)
        self.assertEqual("", process.stdout)
        self.assertIn(f"rm -f -- {self.cid}", calls)
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_hung_node_id_probe_is_killed_within_the_short_budget(self):
        # The stub docker hosts `garage node id` and hangs its only attempt: no
        # status call and no layout mutation are issued, the host-side stub is
        # cleaned up, the failure names the node-id wait and stop runs. As with
        # the hung status case, a remote (in-container) process exit is not
        # observable here; only the `rm -f` call proves container removal.
        directory = self.root / "cold"
        port = self.held_dead_port()
        started = time.monotonic()
        process = self.start(
            directory, 1, "--port", str(port),
            env={
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
                "ROOTYARD_FIXTURE_STARTUP_TIMEOUT": "1",
                "STUB_NODE_HANG_AFTER": "1000000",
            },
        )
        self.assertLess(time.monotonic() - started, 20, "a hung node id call was not bounded")
        calls = self.docker_calls()
        self.assertNotIn(" status", calls)
        self.assertNotIn(" layout assign ", calls)
        self.assertNotIn(" layout apply ", calls)
        self.assertIn("'garage node id' within the 1s startup budget", process.stderr)
        self.assertIn(f"rm -f -- {self.cid}", calls)
        self.assertFalse(directory.exists())
        self.assertFalse((self.root / "outside.env").exists())

    def test_pinned_probe_port_is_the_one_bound_and_probed(self):
        # Guards the isolation above: the binding and probe endpoint must follow
        # the held port, never the helper's default, and the held socket must
        # not be listening (SO_ACCEPTCONN == 0, so the probe can only be refused).
        directory = self.root / "cold"
        default = self.default_probe_port()
        process, port = self.bound_start(
            directory,
            env={
                "STUB_IMAGE_STATE": str(self.root / "image-state"),
                "ROOTYARD_FIXTURE_PROBE_TIMEOUT": "1",
            },
        )
        self.assertNotEqual(default, port)
        self.assertEqual(0, self.holder.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
        calls = self.docker_calls()
        self.assertEqual([str(port)], re.findall(r"-p 127\.0\.0\.1:(\d+):3900", calls), calls)
        self.assertEqual([], re.findall(rf"-p 127\.0\.0\.1:{default}:3900", calls), calls)
        self.assertIn(f"rm -f -- {self.cid}", calls)
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
