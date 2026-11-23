#!/usr/bin/env python3
"""Blob-only standalone native acceptance (#143/#144): real HTTP + stock Git.
Contract: Root supplies --binary plus <binary>.build.json, an absolute trusted
--git/ROOTYARD_GIT, ROOTYARD_TEST_DATABASE_URL, and a strict
ROOTYARD_BLOB_{DRIVER=opendal,SERVICE=s3,ENDPOINT,REGION,BUCKET,ACCESS_KEY_ID,
SECRET_ACCESS_KEY[,SESSION_TOKEN]} profile. The harness owns the random schema,
ROOTYARD_SCRATCH_DIR, temp dir and serve-blob process groups. It never seeds a
ready repository with SQL. Every positive repository is created by POST
/api/repos and every Git result is an actual HTTP Smart-Git clone/push/fsck;
SSH is never exercised. The only SQL policy seed is a real branch-rule row on
an API-created repository; no SQL creates a ref, ACK or terminal. Reports carry
no DSN, token, S3 endpoint/credential, environment dump or raw server stderr.
"""
import argparse
import concurrent.futures
import gzip
import importlib.util
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import http_report_contract as _http_contract
import native_evidence
import ops_provenance
from e2e import Harness
CASES = ("fresh_create_replay_pg_refstore_binding_no_persistent_bare", "sha1_empty_clone_commit_push_second_clone_fsck_exact",
         "sha256_empty_clone_commit_push_second_clone_fsck_exact", "sigkill_after_ack_remove_scratch_restart_clone_exact",
         "wrong_read_only_scoped_foreign_writes_never_mutate", "concurrent_same_ref_one_winner_parseable_no_false_ok",
         "multi_ref_atomic_vs_accepted_subset_actual_git_push", "blob_unavailable_missing_bytes_never_acked_or_served",
         "registered_read_cycles_do_not_exhaust_retained_snapshot_quota", "exact_receive_post_replays_before_native_without_second_effect",
         "create_retry_preserves_the_first_pushed_default_branch",
         "server_side_mixed_ref_policy_atomic_then_subset_sha1_sha256")
BLOB_REQUIRED = ("ROOTYARD_BLOB_SERVICE", "ROOTYARD_BLOB_ENDPOINT", "ROOTYARD_BLOB_REGION", "ROOTYARD_BLOB_BUCKET", "ROOTYARD_BLOB_ACCESS_KEY_ID", "ROOTYARD_BLOB_SECRET_ACCESS_KEY")
SENSITIVE_ENV = ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "ROOTYARD_BLOB_SESSION_TOKEN", "ROOTYARD_BLOB_ACCESS_KEY_ID", "ROOTYARD_BLOB_ENDPOINT", "ROOTYARD_TEST_DATABASE_URL")
LIMITATIONS = ["serve-blob is an increment, not the default server; full equivalence is not claimed.", "LFS, web UI and pull/merge endpoints are outside this harness and remain unqualified.", "SHA-256 requires the Root-supplied trusted Git; missing support fails the case.", "The crash case is SIGKILL of this harness's process group after an ACK, not kernel/power-loss behavior.", "Blob corruption is not injected into the shared S3 fixture; unavailability uses a harmless wrong loopback endpoint and missing bytes use an isolated root prefix without stopping or mutating the shared provider.", "Blob deletion is disabled; failed-upload orphan objects under the fixture root are not reclaimed by this harness.", "Loopback HTTP and stock Git only; no SSH, HA, multi-host or provider failover is claimed.", "No SQL row creates a ready repository, ref, ACK or terminal; SQL inserts only the real branch-rule rows on API-created repositories and verifies the actual repository binding."]
class ProfileError(RuntimeError): pass


def _repo_create_status_code(prefix, code):
    if 400 <= code < 500:
        return prefix + "_status_4xx"
    if 500 <= code < 600:
        return prefix + "_status_5xx"
    return prefix + "_status_other"


def http_input_hashes():
    try:
        return _http_contract.hash_inputs(Path(__file__).resolve().parents[1])
    except _http_contract.ContractError as error:
        raise ProfileError(str(error)) from None


def bind_http_report(report, direct_script, hashes_before, profile):
    """Attach the complete fixed Python HTTP input identity before publication.

    Only fixed, credential-free source hashes and the standalone CLI receipt
    identity are added. Existing case statuses are never rewritten.
    """
    hashes_now = http_input_hashes()
    direct_key = direct_script if direct_script in hashes_now else "tests/" + str(direct_script)
    report["checkpoint_sha256"] = hashes_now.get(direct_key)
    report["harness_inputs_sha256"] = hashes_now
    report["harness_inputs"] = {"before_sha256": dict(hashes_before), "input_hashes": hashes_now}
    errors = []
    if hashes_now != hashes_before:
        errors.append("harness/helper source changed during HTTP acceptance")
    if sha256_file(profile.binary) != profile.build["binary_sha256"]:
        errors.append("executed CLI changed during HTTP acceptance")
    receipt = profile.binary.with_suffix(".build.json")
    if not receipt.is_file() or sha256_file(receipt) != profile.receipt_sha256:
        errors.append("CLI build receipt changed during HTTP acceptance")
    if errors:
        report["inputs_unchanged"] = False
        report["passed"] = False
        prior = report.get("binding_error")
        report["binding_error"] = "; ".join(errors + ([prior] if prior else []))
    return report
def need(condition, message):
    if not condition:
        raise ProfileError(message)
def sha256_file(path):
    return ops_provenance.sha256_file(Path(path))
def sensitive_values(env):
    values = [env[name] for name in SENSITIVE_ENV if env.get(name)]
    password = urllib.parse.urlsplit(env.get("ROOTYARD_TEST_DATABASE_URL", "")).password
    return values + ([password] if password else [])
def resolve_git(flag, env):
    value = flag or env.get("ROOTYARD_GIT") or env.get("ROOTYARD_TEST_GIT")
    need(value, "--git or an absolute ROOTYARD_GIT/ROOTYARD_TEST_GIT is required")
    path = Path(value)
    need(path.is_absolute(), "trusted Git must be absolute")
    need(path.is_file() and os.access(path, os.X_OK), "trusted Git is not an executable file")
    resolved = path.resolve(strict=True)
    if flag and env.get("ROOTYARD_GIT"):
        need(resolved == Path(env["ROOTYARD_GIT"]).resolve(strict=True), "--git and ROOTYARD_GIT disagree")
    return resolved
class NativeProfile:
    def __init__(self, binary, git_flag, env):
        path = Path(binary)
        need(path.is_absolute(), "--binary must be an absolute path")
        need(path.is_file() and os.access(path, os.X_OK), "--binary is not an executable file")
        self.binary = path.resolve(strict=True)
        declared = env.get("ROOTYARD_BINARY")
        if declared:
            need(Path(declared).resolve(strict=True) == self.binary,
                 "ROOTYARD_BINARY disagrees with --binary; refusing to ignore --binary")
        try:
            validated = native_evidence.load_validated(self.binary)
        except Exception as error:
            raise ProfileError("build receipt rejected: " + str(error)) from None
        need(validated is not None, "an adjacent <binary>.build.json receipt is required")
        build = validated.payload
        expected = env.get("ROOTYARD_EXPECTED_SOURCE_COMMIT") or env.get("GITHUB_SHA")
        if expected:
            need(validated.workspace_commit == expected, "stale build receipt: workspace_commit mismatch")
        candidate = Path(__file__).resolve().parents[1]
        if validated.schema == "v2":
            # A copied/CAS snapshot is self-bound by its inventory.  Do not
            # require the mutable original executable, source tree or the
            # historical compiler to still exist on this acceptance host.
            need(validated.toolchain is not None, "v2 build receipt has no toolchain metadata")
            need(len(str(validated.source_inputs_sha256)) == 64, "source_inputs_sha256 is not a SHA-256")
            need(validated.binary_sha256 == sha256_file(self.binary), "build receipt binary_sha256 does not match the executed binary")
            self.source_digest = lambda: validated.source_inputs_sha256
            self.rustc = validated.toolchain["rustc"]["version"]
        else:
            need(all(build.get(field) for field in ("binary_sha256", "source_inputs_sha256", "workspace_commit", "rustc", "command")), "build receipt is incomplete")
            need(build["binary_sha256"] == sha256_file(self.binary), "build receipt binary_sha256 does not match the executed binary")
            need(len(str(build["source_inputs_sha256"])) == 64, "source_inputs_sha256 is not a SHA-256")
            spec = importlib.util.spec_from_file_location("blob_serving_source_binding", candidate / "scripts/build_native.py")
            binding = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(binding)
            self.source_digest = binding.source_digest
            need(self.source_digest() == build["source_inputs_sha256"], "executed binary does not match current candidate source inputs")
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=candidate, text=True).strip()
            need(head == build["workspace_commit"], "executed binary receipt does not match current candidate commit")
            self.rustc = build["rustc"]
        self.working_tree_clean = not subprocess.check_output(["git", "status", "--porcelain"], cwd=candidate, text=True).strip()
        self.build = build
        self.schema = validated.schema
        self.config_digest = validated.config_digest
        self.receipt_sha256 = validated.receipt_sha256
        self.git = resolve_git(git_flag, env)
        self.git_sha256 = sha256_file(self.git)
        self.harness_sha256 = sha256_file(Path(__file__))
def check_blob_profile(env):
    missing = [name for name in BLOB_REQUIRED if not env.get(name)]; need(not missing, "missing ROOTYARD_BLOB_* fields: " + ", ".join(missing))
    need(env.get("ROOTYARD_BLOB_DRIVER", "opendal") == "opendal", "ROOTYARD_BLOB_DRIVER must be opendal")
    need(env["ROOTYARD_BLOB_SERVICE"] == "s3", "ROOTYARD_BLOB_SERVICE must be s3")
    url = urllib.parse.urlsplit(env["ROOTYARD_BLOB_ENDPOINT"])
    need(url.scheme in ("http", "https") and bool(url.hostname), "ROOTYARD_BLOB_ENDPOINT is not an HTTP(S) origin")
    need(not url.username and not url.password, "ROOTYARD_BLOB_ENDPOINT must not contain credentials")
    need(url.path in ("", "/") and not url.query and not url.fragment, "ROOTYARD_BLOB_ENDPOINT must be origin only")
    loopback = url.hostname in ("127.0.0.1", "::1", "localhost")
    need(url.scheme == "https" or loopback, "ROOTYARD_BLOB_ENDPOINT requires HTTPS outside loopback")
    need(env["ROOTYARD_BLOB_ACCESS_KEY_ID"] and env["ROOTYARD_BLOB_SECRET_ACCESS_KEY"], "S3 credentials are empty")
    need(env.get("ROOTYARD_BLOB_DELETE", "") in ("", "disabled"), "Blob deletion must remain disabled")
    root = env.get("ROOTYARD_BLOB_ROOT", "")
    if root: need(not root.startswith("/") and not root.endswith("/") and all(part not in ("", ".", "..") for part in root.split("/")), "invalid ROOTYARD_BLOB_ROOT")
    return {"driver": "opendal", "service": "s3", "endpoint_scheme": url.scheme, "endpoint_loopback": loopback, "root_configured": bool(root), "delete_policy": "disabled"}
STARTUP_STAGES = frozenset((
    "spawn", "child_exit", "readiness_probe", "readiness_timeout",
    "post_ready", "stop_reclaim", "other",
))
EXIT_STATUSES = frozenset((
    "not_applicable", "exited_0", "exited_1", "exited_101", "signaled", "other_exit",
))
_PRIMARY_FAILURE_STAGES = frozenset(("child_exit", "readiness_timeout", "post_ready"))


def _closed_startup_stage(value):
    """Return a closed startup-stage label, never an arbitrary value."""
    return value if type(value) is str and value in STARTUP_STAGES else "other"


def _closed_exit_status(value):
    """Return a closed exit-status label, never an arbitrary value."""
    return value if type(value) is str and value in EXIT_STATUSES else "not_applicable"


def _exit_status_from_returncode(returncode):
    """Derive the closed exit status from an already-observed return code."""
    if type(returncode) is not int:
        return "other_exit"
    if returncode < 0:
        return "signaled"
    if returncode == 0:
        return "exited_0"
    if returncode == 1:
        return "exited_1"
    if returncode == 101:
        return "exited_101"
    return "other_exit"


class StartupProjection:
    """Closed, test-only observation of the existing ``start`` control flow.

    The object stores only finite labels and booleans.  It never stores the
    process, argv, environment, path, log, exception, message, traceback or
    return-code object itself.  ``safe_fields`` revalidates both labels.
    """

    __slots__ = ("_stage", "_exit_status", "failed", "touched", "in_stop")

    def __init__(self):
        self._stage = "other"
        self._exit_status = "not_applicable"
        self.failed = False
        self.touched = False
        self.in_stop = False

    def enter(self, stage):
        self._stage = _closed_startup_stage(stage)
        self._exit_status = "not_applicable"
        self.touched = True

    def child_exited(self, returncode):
        self._stage = "child_exit"
        self._exit_status = _exit_status_from_returncode(returncode)
        self.touched = True

    def enter_stop(self):
        self.in_stop = True

    def leave_stop(self):
        self.in_stop = False

    def mark_stop_reclaim(self):
        # A cleanup failure must not overwrite a known primary startup
        # failure; it is the fallback only when no such stage was observed.
        if self._stage not in _PRIMARY_FAILURE_STAGES:
            self._stage = "stop_reclaim"
            self._exit_status = "not_applicable"
        self.in_stop = False
        self.touched = True

    def safe_fields(self):
        stage = _closed_startup_stage(self._stage)
        status = _closed_exit_status(self._exit_status)
        if stage != "child_exit":
            status = "not_applicable"
        elif status == "not_applicable":
            status = "other_exit"
        return stage, status


class BlobOnlyHarness(Harness):
    def __init__(self, args, profile, blob_profile):
        super().__init__(args)
        self.profile, self.blob_profile = profile, blob_profile
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.askpass = self.root / "askpass.sh"
        self.askpass.write_text("""#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "$ROOTYARD_GIT_USERNAME" ;;
  *Password*) printf '%s\n' "$ROOTYARD_GIT_TOKEN" ;;
  *) exit 1 ;;
esac
""")
        self.askpass.chmod(0o700)
        self.env["ROOTYARD_GIT"] = str(profile.git)
        self.env["ROOTYARD_SCRATCH_DIR"] = str(self.scratch)
        self.env["GIT_HTTP_LOW_SPEED_LIMIT"] = "1"
        self.env["GIT_HTTP_LOW_SPEED_TIME"] = "30"
        self.env["PATH"] = str(profile.git.parent) + os.pathsep + self.env.get("PATH", "")
        self.secrets.extend(sensitive_values(os.environ))
        self.secrets.append(self.base)
        self.server_count = 0

    def prepare(self):
        if not self.schema_created: self.setup()
    def start(self, overrides=None, label="server", startup_projection=None,
              command=("serve-blob",), unset=()):
        if self.proc is not None:
            raise AssertionError("serve-blob is already running")
        if not isinstance(command, tuple) or not command or not all(
                type(part) is str and part for part in command):
            raise TypeError("command must be a non-empty tuple of fixed argv tokens")
        if not isinstance(unset, tuple) or not all(type(key) is str and key for key in unset):
            raise TypeError("unset must be a tuple of fixed environment names")
        command_line = " ".join(command)
        observation = startup_projection if type(startup_projection) is StartupProjection else None
        if observation is not None:
            observation.enter("spawn")
        completed = False
        try:
            env = self.env.copy()
            for key in unset:
                env.pop(key, None)
            env.update(overrides or {})
            self.server_count += 1
            self.log_path = self.root / (label + "-" + str(self.server_count) + ".log")
            self.log = open(self.log_path, "ab")
            self.proc = subprocess.Popen([str(self.profile.binary), *command], env=env,
                                         stdout=self.log, stderr=self.log, start_new_session=True)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if observation is not None:
                    observation.enter("readiness_probe")
                if self.proc.poll() is not None:
                    status = self.proc.returncode
                    if observation is not None:
                        observation.child_exited(status)
                        observation.enter_stop()
                    self.stop()
                    if observation is not None:
                        observation.leave_stop()
                    raise RuntimeError(command_line + " exited during startup with status " + str(status))
                try:
                    if self.http("/health/ready")[0] == 200:
                        if observation is not None:
                            observation.enter("post_ready")
                        assert sha256_file(self.profile.binary) == self.profile.build["binary_sha256"], "binary changed after attestation"
                        native_evidence.started(self)
                        completed = True
                        return
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.1)
            if observation is not None:
                observation.enter("readiness_timeout")
                observation.enter_stop()
            self.stop(hard=True)
            if observation is not None:
                observation.leave_stop()
            raise RuntimeError(command_line + " readiness timeout")
        finally:
            if observation is not None and not completed:
                observation.failed = True
                if observation.in_stop:
                    observation.mark_stop_reclaim()
    def git(self, *args, cwd=None, token=None, check=True, env=None):
        prefix = [str(self.profile.git), "--no-pager", "-c", "credential.helper=",
                  "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=30"]
        child = {key: self.env[key] for key in ("PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_HTTP_LOW_SPEED_LIMIT", "GIT_HTTP_LOW_SPEED_TIME", "LC_ALL") if key in self.env}
        if token:
            child.update(GIT_ASKPASS=str(self.askpass), GIT_ASKPASS_REQUIRE="force",
                         GIT_TERMINAL_PROMPT="0", ROOTYARD_GIT_USERNAME=token["username"],
                         ROOTYARD_GIT_TOKEN=token["token"])
        return self.run(prefix + list(args), cwd=cwd, check=check, env=child)
    def remote_refs(self, remote, token=None):
        token = token or self.alice
        refs = {}
        result = self.git("ls-remote", remote, token=token, check=False)
        if result.returncode:
            path = urllib.parse.urlsplit(remote).path.rstrip("/") + "/info/refs?service=git-upload-pack"
            code, raw, _ = self.http(path, token=token)
            raise AssertionError("ls-remote failed; authenticated advertisement status=" + str(code)
                                 + "; refusal=" + self.redact(raw[:500].decode(errors="replace")))
        for line in result.stdout.decode().splitlines():
            if "\t" in line:
                oid, name = line.split("\t", 1)
                refs[name] = oid
        return refs
    def post_repo(self, name, token, object_format="sha1", expect=(201, 202), basic=False, observer=None):
        try:
            code, raw, _ = self.http("/api/repos", token=token, method="POST", basic=basic,
                                     body={"name": name, "object_format": object_format})
        except (OSError, urllib.error.URLError):
            if observer: observer("post_send")
            raise
        if code not in expect:
            if observer: observer(_repo_create_status_code("post", code))
            assert code in expect, "POST /api/repos: " + str(code) + ": " + repr(raw[:200])
        try:
            created = json.loads(raw)
        except ValueError:
            if observer: observer("post_shape")
            raise
        if observer and not (isinstance(created, dict) and all(
                isinstance(created.get(field), str) and created.get(field) for field in ("id", "owner", "name"))):
            observer("post_shape")
        return code, created
    def await_ready(self, owner, name, token, observer=None):
        path = "/api/repos/" + urllib.parse.quote(owner, safe="") + "/" + urllib.parse.quote(name, safe="")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                code, raw, _ = self.http(path, token=token)
            except (OSError, urllib.error.URLError):
                if observer: observer("get_send")
                raise
            if code != 200:
                if observer: observer(_repo_create_status_code("get", code))
                assert code == 200, "GET " + path + ": " + str(code)
            try:
                data = json.loads(raw)
            except ValueError:
                if observer: observer("get_shape")
                raise
            if observer and not (isinstance(data, dict) and isinstance(data.get("state"), str)):
                observer("get_shape")
            if data.get("state") == "ready":
                return data
            if data.get("state") != "provisioning":
                if observer: observer("get_terminal_state")
                assert data.get("state") == "provisioning", data.get("state")
            time.sleep(0.1)
        if observer: observer("get_timeout")
        raise AssertionError("repository did not become ready within 30s")
    def create(self, name, token, object_format="sha1", observer=None):
        code, created = self.post_repo(name, token, object_format, observer=observer)
        if observer and not (isinstance(created, dict) and all(
                isinstance(created.get(field), str) and created.get(field) for field in ("id", "owner", "name"))):
            observer("post_shape")
        repo = self.await_ready(created["owner"], created["name"], token, observer=observer)
        if observer and not (
                isinstance(repo, dict)
                and isinstance(repo.get("id"), str) and repo.get("id")
                and isinstance(repo.get("owner"), str) and repo.get("owner")
                and isinstance(repo.get("name"), str) and repo.get("name")
                and isinstance(repo.get("storage_backend"), str) and repo.get("storage_backend")
                and isinstance(repo.get("object_format"), str) and repo.get("object_format")
                and isinstance(repo.get("clone_path"), str) and repo.get("clone_path")):
            observer("get_shape")
        if isinstance(repo, dict) and isinstance(created, dict):
            if repo.get("id") != created.get("id"):
                if observer: observer("identity_mismatch")
            if repo.get("storage_backend") != "pg_refstore":
                if observer: observer("backend_mismatch")
        assert repo["id"] == created["id"] and repo["storage_backend"] == "pg_refstore"
        if isinstance(repo, dict) and repo.get("object_format") != object_format:
            if observer: observer("object_format_mismatch")
        assert repo["object_format"] == object_format, repo.get("object_format")
        if observer:
            try:
                expected_clone = "/git/" + repo["owner"] + "/" + repo["name"] + ".git"
            except (KeyError, TypeError):
                pass
            else:
                if repo.get("clone_path") != expected_clone:
                    observer("clone_path_mismatch")
        assert repo["clone_path"] == "/git/" + repo["owner"] + "/" + repo["name"] + ".git"
        return repo, code
    def db_repo(self, repo_id):
        value = str(uuid.UUID(repo_id))
        return self.sql("SELECT storage_backend || '|' || storage_generation || '|' || object_format "
                        "FROM repositories WHERE id='" + value + "'")
    def no_bare(self, repo, stage):
        persistent = self.root / "data" / "repos"
        bares = list(persistent.glob("*.git")) if persistent.is_dir() else []
        assert not bares and not (persistent / (repo["id"] + ".git")).exists(), "persistent bare: " + stage
    def clone(self, remote, destination, token=None):
        process = self.git("clone", remote, str(destination), token=token, check=False)
        assert process.returncode == 0, "git clone: " + json.dumps(git_failure(process))
        return destination
    def configure(self, work):
        self.git("config", "user.name", "Blob Only", cwd=work)
        self.git("config", "user.email", "blob-only@example.invalid", cwd=work)
    def commit_files(self, work, message, files):
        for name, data in files.items():
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data) if isinstance(data, bytes) else path.write_text(data)
        self.git("add", "-A", cwd=work)
        self.git("commit", "-m", message, cwd=work)
        return self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    def commit_tree(self, work, parent, message):
        tree = self.git("rev-parse", parent + "^{tree}", cwd=work).stdout.decode().strip()
        return self.git("commit-tree", tree, "-p", parent, "-m", message, cwd=work).stdout.decode().strip()
    def seed(self, name, token=None, object_format="sha1"):
        token = token or self.alice
        repo, _ = self.create(name, token, object_format)
        remote = self.base + repo["clone_path"]
        work = self.root / (name + "-work")
        self.clone(remote, work, token)
        self.configure(work)
        oid = self.commit_files(work, "seed " + name, {"base.txt": "seed " + name + "\n"})
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=token)
        assert self.remote_refs(remote, token).get("refs/heads/main") == oid
        return repo, remote, work, oid
    def object_format(self, work):
        process = self.git("rev-parse", "--show-object-format", cwd=work, check=False)
        if process.returncode == 0:
            return process.stdout.decode().strip()
        return self.git("config", "--get", "extensions.objectFormat", cwd=work).stdout.decode().strip()
    def empty_clone(self, remote, destination, token=None):
        self.clone(remote, destination, token)
        assert self.git("symbolic-ref", "HEAD", cwd=destination).stdout.decode().strip() == "refs/heads/main"
        assert self.git("rev-parse", "--verify", "HEAD", cwd=destination, check=False).returncode != 0
    def exact_clone(self, remote, destination, oid, fmt, files, token=None):
        self.clone(remote, destination, token)
        assert self.object_format(destination) == fmt
        assert self.git("rev-parse", "HEAD", cwd=destination).stdout.decode().strip() == oid
        for name, expected in files.items():
            expected = expected.encode() if isinstance(expected, str) else expected
            assert (destination / name).read_bytes() == expected, "cloned content differs: " + name
        self.git("fsck", "--full", "--strict", cwd=destination)
    def assert_ref(self, remote, name, oid, token=None):
        assert self.remote_refs(remote, token).get(name) == oid, "remote ref is not the acknowledged OID: " + name
    def scoped_token(self, repo, name):
        payload = {"display_name": name, "expires_in_days": 1, "read_only": False,
                   "repository_grants": [{"repository_id": repo["id"],
                                          "actions": ["contents_read", "contents_write", "repo_read"]}],
                   "namespace_grants": []}
        code, raw, _ = self.http("/api/tokens", token=self.bob, method="POST", body=payload)
        assert code == 201, "POST /api/tokens: " + str(code) + ": " + repr(raw[:200])
        data = json.loads(raw)
        self.secrets.append(data["secret"])
        return {"username": "bob", "token": data["secret"]}
    def sha_roundtrip(self, fmt, name, files):
        repo, _ = self.create(name, self.alice, fmt)
        remote = self.base + repo["clone_path"]
        work = self.root / (name + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        assert self.object_format(work) == fmt
        oid = self.commit_files(work, fmt + " first", files)
        assert len(oid) == (40 if fmt == "sha1" else 64), oid
        pushed = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/main",
                          cwd=work, token=self.alice, check=False)
        assert pushed.returncode == 0, json.dumps(git_failure(pushed))
        assert push_success(parse_push(pushed.stdout.decode()), "refs/heads/main")
        self.assert_ref(remote, "refs/heads/main", oid)
        self.no_bare(repo, fmt + " push")
        self.exact_clone(remote, self.root / (name + "-clone"), oid, fmt, files, self.reader)
        return oid
def git_failure(process):
    text = (process.stderr or b"").decode(errors="replace").lower()
    markers = [marker for marker in ("non-fast-forward", "[rejected]", "fetch first", "authentication failed",
                                     "not found", "does not support", "could not resolve", "unable to access",
                                     "repository not found") if marker in text]
    return {"exit": process.returncode, "markers": markers}
def parse_push(text):
    entries = []
    for line in text.splitlines():
        if len(line) < 3 or line[0] not in "*+=!- " or "\t" not in line:
            continue
        parts = line.split("\t")
        refspec = parts[1] if len(parts) > 1 else ""
        entries.append({"flag": line[0], "target": refspec.rsplit(":", 1)[-1]})
    return entries
def push_success(entries, target):
    return any(entry["flag"] in "*+ " and entry["target"] == target for entry in entries)
def push_rejected(entries, target):
    return any(entry["flag"] == "!" and entry["target"] == target for entry in entries)
def fresh_create_replay_pg_refstore_binding_no_persistent_bare(self):
    self.prepare()
    repo, status = self.create("fresh", self.alice)
    binding = self.db_repo(repo["id"]).split("|")
    assert status in (201, 202) and repo["state"] == "ready" and binding[0] == "pg_refstore"
    assert int(binding[1]) >= 1 and binding[2] == "sha1", binding
    _, replay = self.post_repo("fresh", self.alice, expect=(200,), basic=True)
    assert replay["id"] == repo["id"] and replay["storage_backend"] == "pg_refstore"
    got = json.loads(self.expect("/api/repos/alice/fresh", 200, token=self.alice))
    assert got["id"] == repo["id"] and got["storage_backend"] == "pg_refstore"
    assert self.scratch.is_dir(), "ROOTYARD_SCRATCH_DIR is missing"
    self.no_bare(repo, "fresh create")
    self.expect(repo["clone_path"] + "/info/refs?service=git-upload-pack", 200, token=self.alice)
    return {"repository_id": repo["id"], "db_binding": binding, "basic_replay": True}
def sha1_empty_clone_commit_push_second_clone_fsck_exact(self):
    files = {"hello.txt": "sha1 hello\n", "payload.bin": random.Random(143).randbytes(256 * 1024)}
    oid = self.sha_roundtrip("sha1", "sha1", files)
    return {"oid": oid, "object_format": "sha1", "fsck": True}
def sha256_empty_clone_commit_push_second_clone_fsck_exact(self):
    probe = self.git("init", "--object-format=sha256", str(self.root / "sha256-probe"), check=False)
    assert probe.returncode == 0, "configured Git lacks sha256: " + json.dumps(git_failure(probe))
    files = {"sha256.txt": "sha256 hello\n", "payload.bin": random.Random(144).randbytes(256 * 1024)}
    oid = self.sha_roundtrip("sha256", "sha256", files)
    return {"oid": oid, "object_format": "sha256", "fsck": True}
def sigkill_after_ack_remove_scratch_restart_clone_exact(self):
    repo, remote, work, oid = self.seed("crash")
    old_pid = self.proc.pid
    self.assert_ref(remote, "refs/heads/main", oid)
    assert self.scratch.is_dir(), "scratch was not used before the crash"
    self.stop(hard=True)
    shutil.rmtree(self.scratch)
    assert not self.scratch.exists()
    self.start()
    assert self.proc.pid != old_pid
    self.exact_clone(remote, self.root / "crash-clone", oid, "sha1", {"base.txt": "seed crash\n"}, self.reader)
    assert self.scratch.is_dir(), "scratch was not recreated"
    self.assert_ref(remote, "refs/heads/main", oid, self.alice)
    self.no_bare(repo, "after scratch removal")
    return {"ack_oid": oid, "killed_pid": old_pid, "restarted_pid": self.proc.pid}
def wrong_read_only_scoped_foreign_writes_never_mutate(self):
    repo, remote, work, oid = self.seed("authz")
    before, upload = self.remote_refs(remote, self.alice), repo["clone_path"] + "/info/refs?service=git-upload-pack"
    self.expect(upload, 401)
    invalid = {"username": "alice", "token": "ryt_" + "0" * 64}
    self.expect(upload, 401, token=invalid)
    self.clone(remote, self.root / "authz-reader", self.reader)
    denied = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/readonly-denied",
                      cwd=work, token=self.reader, check=False)
    assert denied.returncode != 0 and not push_success(parse_push(denied.stdout.decode()), "refs/heads/readonly-denied")
    bob_repo, _ = self.create("bob-only", self.bob)
    scoped = self.scoped_token(bob_repo, "foreign")
    denied = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/foreign-denied",
                      cwd=work, token=scoped, check=False)
    assert denied.returncode != 0 and not push_success(parse_push(denied.stdout.decode()), "refs/heads/foreign-denied")
    assert self.git("clone", remote, str(self.root / "foreign-clone"), token=scoped, check=False).returncode != 0
    bob_work = self.root / "bob-work"
    self.clone(self.base + bob_repo["clone_path"], bob_work, self.bob)
    self.configure(bob_work)
    self.commit_files(bob_work, "bob own write", {"bob.txt": "bob\n"})
    own = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/main", cwd=bob_work, token=scoped, check=False)
    assert own.returncode == 0, "scoped write failed on its own repository"
    invalid_push = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/invalid-denied",
                            cwd=work, token=invalid, check=False)
    assert invalid_push.returncode != 0
    after = self.remote_refs(remote, self.alice)
    assert after.get("refs/heads/main") == oid and before.get("refs/heads/main") == oid
    assert not any(name.endswith(("readonly-denied", "foreign-denied", "invalid-denied")) for name in after)
    return {"read_only_denied": True, "invalid_denied": True, "foreign_scope_denied": True, "own_scope_write": True}
def concurrent_same_ref_one_winner_parseable_no_false_ok(self):
    repo, remote, work, base = self.seed("race")
    self.git("push", "origin", base + ":refs/heads/race", cwd=work, token=self.alice)
    clones, oids = [], []
    for label in ("a", "b"):
        destination = self.root / ("race-" + label)
        self.clone(remote, destination, self.alice)
        self.configure(destination)
        oids.append(self.commit_files(destination, "race " + label, {label + ".txt": label + "\n"}))
        clones.append(destination)
    barrier = threading.Barrier(2)
    operations = [str(uuid.uuid4()), str(uuid.uuid4())]
    def push(item):
        index, clone = item
        barrier.wait(timeout=10)
        return self.git("-c", "http.extraHeader=X-Rootyard-Operation: " + operations[index],
                        "push", "--porcelain", "origin", "HEAD:refs/heads/race",
                        cwd=clone, token=self.alice, check=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(push, enumerate(clones)))
    reports = [parse_push(result.stdout.decode()) for result in results]
    winners = [index for index, report in enumerate(reports) if push_success(report, "refs/heads/race")]
    assert len(winners) == 1, "expected exactly one successful same-ref push"
    loser = 1 - winners[0]
    stderr = (results[loser].stderr or b"").decode(errors="replace").lower()
    assert results[loser].returncode != 0
    if not (push_rejected(reports[loser], "refs/heads/race") or any(
            marker in stderr for marker in ("rejected", "non-fast-forward", "fetch first"))):
        status, body, _ = self.http("/api/repos/alice/race/operations/" + operations[loser], token=self.alice)
        raise AssertionError("no parseable rejection; loser=" + self.redact(stderr[:500])
                             + "; operation_status=" + str(status)
                             + "; operation=" + self.redact(body[:1000].decode(errors="replace")))
    winner_oid = oids[winners[0]]
    self.assert_ref(remote, "refs/heads/race", winner_oid)
    clone = self.root / "race-winner"
    process = self.git("clone", "--branch", "race", remote, str(clone), token=self.reader, check=False)
    assert process.returncode == 0, "race clone: " + json.dumps(git_failure(process))
    assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == winner_oid
    winner_file = ("a" if winners[0] == 0 else "b") + ".txt"
    assert (clone / winner_file).read_text() == winner_file[0] + "\n"
    self.git("fsck", "--full", "--strict", cwd=clone)
    # The native client may refuse its stale advertisement locally. Two direct
    # protocol requests ensure both operation identities reach receive-pack;
    # their pack streams and commit graphs are still produced by real Git.
    raw_ref = "refs/heads/raw-race"
    self.git("push", "origin", base + ":" + raw_ref, cwd=work, token=self.alice)
    bodies = []
    for index, source in enumerate(clones):
        pack = self.run([str(self.profile.git), "--no-pager", "pack-objects", "--stdout", "--all"],
                        cwd=source, data=b"").stdout
        assert pack.startswith(b"PACK"), "Git produced no race pack"
        bodies.append(receive_pack_request(base, oids[index], raw_ref, pack))
    raw_operations = [str(uuid.uuid4()), str(uuid.uuid4())]
    destination = repo["clone_path"] + "/git-receive-pack"
    raw_barrier = threading.Barrier(2)
    def post(index, wait=False):
        if wait:
            raw_barrier.wait(timeout=10)
        return self.http(destination, token=self.alice, method="POST", body=bodies[index],
                         content_type="application/x-git-receive-pack-request",
                         extra_headers={"X-Rootyard-Operation": raw_operations[index]})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        raw_results = list(pool.map(lambda index: post(index, True), (0, 1)))
    first_statuses = [result[0] for result in raw_results]
    raw_reports, durable_states = [], []
    for index, (status, body, headers) in enumerate(raw_results):
        operation_query = (" WHERE repository_id='" + str(uuid.UUID(repo["id"]))
                           + "' AND operation_id='" + raw_operations[index] + "'")
        state = self.sql("SELECT state FROM ref_store_operations" + operation_query)
        if status == 409:
            # A pre-admission revision race may have rolled its transaction
            # back. A pending row behind that 409 is the regression, never a
            # reason to retry or accept this run.
            assert not state, "409 left a durable operation instead of a terminal: " + state
            status, body, headers = post(index)
            state = self.sql("SELECT state FROM ref_store_operations" + operation_query)
        assert status == 200, "race POST status=" + str(status) + ", state=" + state
        assert header_value(headers, "x-rootyard-operation") == raw_operations[index]
        unpack, statuses = parse_receive_report(body)
        assert unpack == "unpack ok", unpack
        assert len(statuses) == 1, statuses
        if statuses[0] == "ok " + raw_ref:
            assert state == "committed", state
        else:
            assert statuses[0].startswith("ng " + raw_ref + " "), statuses
            assert state == "rejected", state
        durable_states.append(state)
        raw_reports.append(body)
    assert sorted(durable_states) == ["committed", "rejected"], durable_states
    counts = pg_replay_counts(self, repo["id"])
    for index in (0, 1):
        status, body, _ = post(index)
        assert status == 200 and body == raw_reports[index], "race terminal did not replay byte-for-byte"
    assert pg_replay_counts(self, repo["id"]) == counts, "race replay changed the ledger"
    raw_winner = durable_states.index("committed")
    self.assert_ref(remote, raw_ref, oids[raw_winner])
    return {"winner": winners[0], "winner_oid": winner_oid, "loser_rejected": True, "false_ok": False,
            "protocol_race_statuses": first_statuses, "protocol_race_states": durable_states,
            "protocol_terminals_replayed": True}
def multi_ref_atomic_vs_accepted_subset_actual_git_push(self):
    repo, remote, work, base = self.seed("atomic")
    advance = self.commit_tree(work, base, "advance")
    sibling = self.commit_tree(work, base, "sibling")
    self.git("push", "origin", advance + ":refs/heads/protected", cwd=work, token=self.alice)
    atomic = self.git("push", "--atomic", "--porcelain", "origin", advance + ":refs/heads/main",
                      sibling + ":refs/heads/protected", cwd=work, token=self.alice, check=False)
    assert atomic.returncode != 0, "atomic push accepted a non-fast-forward subset"
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/main") == base and refs.get("refs/heads/protected") == advance
    subset = self.git("push", "--porcelain", "origin", advance + ":refs/heads/main",
                      sibling + ":refs/heads/protected", cwd=work, token=self.alice, check=False)
    assert subset.returncode != 0
    entries = parse_push(subset.stdout.decode())
    assert push_success(entries, "refs/heads/main") and push_rejected(entries, "refs/heads/protected"), entries
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/main") == advance and refs.get("refs/heads/protected") == advance
    positive = self.git("push", "--atomic", "--porcelain", "origin", advance + ":refs/heads/atom-a",
                        sibling + ":refs/heads/atom-b", cwd=work, token=self.alice, check=False)
    assert positive.returncode == 0, "atomic positive push: " + json.dumps(git_failure(positive))
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/atom-a") == advance and refs.get("refs/heads/atom-b") == sibling
    atomic_rewind = self.git("push", "--atomic", "--porcelain", "origin", base + ":refs/heads/atom-a",
                             sibling + ":refs/heads/atom-c", cwd=work, token=self.alice, check=False)
    assert atomic_rewind.returncode != 0, "atomic rewind was accepted"
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/atom-a") == advance and "refs/heads/atom-c" not in refs
    subset_rewind = self.git("push", "--porcelain", "origin", base + ":refs/heads/atom-a",
                             sibling + ":refs/heads/atom-c", cwd=work, token=self.alice, check=False)
    assert subset_rewind.returncode != 0
    entries = parse_push(subset_rewind.stdout.decode())
    assert push_rejected(entries, "refs/heads/atom-a") and push_success(entries, "refs/heads/atom-c"), entries
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/atom-a") == advance and refs.get("refs/heads/atom-c") == sibling
    self.git("fsck", "--full", "--strict", cwd=work)
    return {"atomic_all_or_nothing": True, "accepted_subset_exact": True, "positive_atomic": True}
def blob_unavailable_missing_bytes_never_acked_or_served(self):
    repo, remote, work, oid = self.seed("blob")
    self.assert_ref(remote, "refs/heads/main", oid)
    self.stop()
    bounded = {"ROOTYARD_BLOB_TIMEOUT_MS": "2000", "ROOTYARD_BLOB_IO_TIMEOUT_MS": "2000",
               "ROOTYARD_BLOB_RETRY_MAX_TIMES": "1", "ROOTYARD_BLOB_ABORT_TIMEOUT_MS": "2000"}
    shutil.rmtree(self.scratch, ignore_errors=True); self.scratch.mkdir(mode=0o700)
    try:
        self.start(overrides={**bounded, "ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:1"}, label="blob-down")
        self.commit_files(work, "blob down", {"down.txt": "down\n"})
        pushed = self.git("push", "--porcelain", "origin", "HEAD:refs/heads/blob-down",
                          cwd=work, token=self.alice, check=False)
        assert pushed.returncode != 0, "push ACKed with an unavailable Blob provider"
        assert not push_success(parse_push(pushed.stdout.decode()), "refs/heads/blob-down")
        assert self.proc.poll() is None, "serve-blob crashed instead of failing closed"
    finally:
        self.stop(hard=True)
    prefix = os.environ.get("ROOTYARD_BLOB_ROOT", "").strip("/")
    shutil.rmtree(self.scratch, ignore_errors=True); self.scratch.mkdir(mode=0o700)
    try:
        self.start(overrides={**bounded, "ROOTYARD_BLOB_ROOT": (prefix + "/" if prefix else "") + "missing-" + uuid.uuid4().hex}, label="blob-missing")
        missing = self.git("clone", remote, str(self.root / "missing-clone"), token=self.reader, check=False)
        assert missing.returncode != 0, "clone served bytes from an empty Blob root"
        assert not (self.root / "missing-clone" / "base.txt").exists(), "missing Blob bytes were materialized"
    finally:
        self.stop(hard=True)
    self.start()
    refs = self.remote_refs(remote, self.alice)
    assert refs.get("refs/heads/main") == oid and "refs/heads/blob-down" not in refs
    self.exact_clone(remote, self.root / "blob-clone", oid, "sha1", {"base.txt": "seed blob\n"}, self.reader)
    return {"unavailable_push_rejected": True, "missing_bytes_clone_rejected": True, "ack_oid": oid}
ZERO_SHA1 = "0" * 40
def pkt_line(payload):
    return ("%04x" % (len(payload) + 4)).encode("ascii") + payload
def receive_pack_request(old, new, ref, pack, capabilities="report-status"):
    """Exactly one v1 Smart-HTTP receive-pack body: command pkt-line, flush, raw pack."""
    command = (old + " " + new + " " + ref + "\0" + capabilities + "\n").encode()
    return pkt_line(command) + b"0000" + pack
def parse_receive_report(raw):
    """Strict v1 report-status reader: (unpack line, ordered ref status lines)."""
    position, unpack, statuses, flushed = 0, None, [], False
    while position < len(raw):
        assert position + 4 <= len(raw), "truncated report pkt-line header"
        header = raw[position:position + 4]
        try:
            length = int(header.decode("ascii"), 16)
        except ValueError:
            raise AssertionError("report pkt-line length is not hex: " + repr(header)) from None
        position += 4
        if length == 0:
            flushed = True
            break
        assert 4 <= length <= 65520 and position + length - 4 <= len(raw), "invalid report pkt-line length"
        line = raw[position:position + length - 4].decode("utf-8")
        position += length - 4
        assert line.endswith("\n"), "report line has no newline"
        line = line[:-1]
        if line.startswith("unpack "):
            assert unpack is None, "report carries more than one unpack line"
            unpack = line
        else:
            statuses.append(line)
    assert flushed and position == len(raw), "report is not exactly one flushed pkt stream"
    assert unpack is not None, "report has no unpack line"
    return unpack, statuses
def assert_receive_report_ok(raw, ref):
    unpack, statuses = parse_receive_report(raw)
    assert unpack == "unpack ok", unpack
    assert statuses == ["ok " + ref], statuses
def header_value(headers, name):
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None
def pg_replay_counts(harness, repo_id):
    """Read-only ledger counters that a replayed receive must never advance."""
    rid = str(uuid.UUID(repo_id))
    query = " WHERE repository_id='" + rid + "'"
    return {"operations": harness.sql("SELECT count(*) FROM ref_store_operations" + query),
            "registrations": harness.sql("SELECT count(*) FROM ref_store_core_pack_publications" + query),
            "gate_rows": harness.sql("SELECT count(*) FROM ref_store_core_gates" + query),
            "gate": harness.sql("SELECT revision || '|' || pack_mode FROM ref_store_core_gates" + query)}
def registered_read_cycles_do_not_exhaust_retained_snapshot_quota(self):
    """>=130 real authenticated Smart-HTTP reads of registered packs create no retained A5a row."""
    self.prepare()
    repo, remote, work, oid = self.seed("reads", self.alice)
    second = self.commit_files(work, "reads second ref", {"second.txt": "second\n"})
    self.git("push", "origin", "HEAD:refs/heads/second", cwd=work, token=self.alice)
    cycles = 130
    for cycle in range(cycles):
        refs = self.remote_refs(remote, self.alice)
        assert refs.get("refs/heads/main") == oid, "ls-remote cycle " + str(cycle) + " did not ACK refs/heads/main"
        assert refs.get("refs/heads/second") == second, "ls-remote cycle " + str(cycle) + " did not ACK refs/heads/second"
    rid = str(uuid.UUID(repo["id"]))
    retained = {table: int(self.sql("SELECT count(*) FROM " + table + " WHERE repository_id='" + rid + "'"))
                for table in ("ref_store_core_snapshots", "ref_store_core_pins",
                              "ref_store_core_pack_snapshot_history", "ref_store_core_serving_reads")}
    assert retained["ref_store_core_snapshots"] == 0, "reads retained a permanent snapshot: " + str(retained)
    assert retained["ref_store_core_pins"] == 0, "reads retained a permanent pin: " + str(retained)
    assert retained["ref_store_core_pack_snapshot_history"] == 0, "reads appended permanent snapshot history: " + str(retained)
    assert retained["ref_store_core_serving_reads"] == 0, "transient serving read rows were not released: " + str(retained)
    publications = int(self.sql("SELECT count(*) FROM ref_store_core_pack_publications WHERE repository_id='" + rid + "'"))
    assert publications > 0, "no pack was ever registered, so the reads did not serve a real registered pack"
    self.exact_clone(remote, self.root / "reads-clone", oid, "sha1", {"base.txt": "seed reads\n"}, self.reader)
    return {"ls_remote_cycles": cycles, "ack_oid": oid, "second_ref_oid": second,
            "retained_rows": retained, "registrations": publications}
def exact_receive_post_replays_before_native_without_second_effect(self):
    """A raw v1 receive-pack POST is replayed from the persisted report; a reused id with a changed body is 409."""
    self.prepare()
    repo, _ = self.create("replay", self.alice)
    remote = self.base + repo["clone_path"]
    work = self.root / "replay-work"
    self.empty_clone(remote, work, self.alice)
    self.configure(work)
    payload = random.Random(146).randbytes(64 * 1024)
    files = {"main.txt": "first\n", "payload.bin": payload}
    oid = self.commit_files(work, "replay first", files)
    pack = self.run([str(self.profile.git), "--no-pager", "pack-objects", "--stdout", "--all"],
                    cwd=work, data=b"").stdout
    assert pack[:4] == b"PACK" and len(pack) > 32, "trusted Git produced no pack stream"
    body = receive_pack_request(ZERO_SHA1, oid, "refs/heads/main", pack)
    destination = repo["clone_path"] + "/git-receive-pack"
    operation = str(uuid.uuid4())
    headers = {"X-Rootyard-Operation": operation}
    barrier = threading.Barrier(2)
    def simultaneous_post(_):
        barrier.wait(timeout=10)
        return self.http(destination, token=self.alice, method="POST", body=body,
                         content_type="application/x-git-receive-pack-request", extra_headers=headers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        submitted = list(pool.map(simultaneous_post, (0, 1)))
    concurrent_statuses = [entry[0] for entry in submitted]
    assert 200 in concurrent_statuses, "no concurrent request completed: " + str(concurrent_statuses)
    assert all(code in (200, 503) for code in concurrent_statuses), "identical concurrent requests conflicted: " + str(concurrent_statuses)
    code, first, first_headers = next(entry for entry in submitted if entry[0] == 200)
    for status, response_body, response_headers in submitted:
        assert header_value(response_headers, "x-rootyard-operation") == operation
        if status == 200:
            assert response_body == first, "concurrent terminal reports differ"
        else:
            assert b"unpack ok" not in response_body, "pending was reported as success"
    assert_receive_report_ok(first, "refs/heads/main")
    assert header_value(first_headers, "x-rootyard-operation") == operation, first_headers
    assert self.remote_refs(remote, self.alice).get("refs/heads/main") == oid, "POST did not ACK the wire OID"
    counts = pg_replay_counts(self, repo["id"])
    assert counts["operations"] == "1", counts
    assert int(counts["registrations"]) >= 1, counts
    assert counts["gate"].endswith("|pack_verified"), counts
    # Exact retry of the same wire body under the same operation id: replay, not a second effect.
    retry_code, retry, retry_headers = self.http(destination, token=self.alice, method="POST", body=body,
                                                content_type="application/x-git-receive-pack-request",
                                                extra_headers=headers)
    assert retry_code == 200, "exact retry: " + str(retry_code) + ": " + repr(retry[:200])
    assert retry == first, "replayed report-status differs from the persisted report"
    assert header_value(retry_headers, "x-rootyard-operation") == operation, retry_headers
    assert pg_replay_counts(self, repo["id"]) == counts, "an exact replay advanced PG ledger counters"
    # Same operation id, different decoded body: conflict before any native effect.
    changed = self.commit_files(work, "replay changed", {"main.txt": "changed\n"})
    changed_pack = self.run([str(self.profile.git), "--no-pager", "pack-objects", "--stdout", "--all"],
                            cwd=work, data=b"").stdout
    changed_body = receive_pack_request(oid, changed, "refs/heads/main", changed_pack)
    conflict_code, conflict, _ = self.http(destination, token=self.alice, method="POST", body=changed_body,
                                          content_type="application/x-git-receive-pack-request",
                                          extra_headers=headers)
    assert conflict_code == 409, "changed body under a used operation id: " + str(conflict_code) + ": " + repr(conflict[:200])
    assert b"unpack ok" not in conflict and b"ok refs/heads/main" not in conflict, "409 carried a Git success report"
    assert self.remote_refs(remote, self.alice).get("refs/heads/main") == oid, "409 changed the authoritative ref"
    assert pg_replay_counts(self, repo["id"]) == counts, "409 advanced PG ledger counters"
    self.exact_clone(remote, self.root / "replay-clone", oid, "sha1", files, self.reader)
    # Gzip is decoded before the producer digest, so the same decoded body must also replay.
    gzip_code, gzip_body, _ = self.http(destination, token=self.alice, method="POST", body=gzip.compress(body),
                                       content_type="application/x-git-receive-pack-request",
                                       extra_headers={**headers, "Content-Encoding": "gzip"})
    assert gzip_code == 200, "gzip replay was refused: " + str(gzip_code)
    gzip_identical = gzip_body == first
    assert gzip_identical, "gzip retry did not replay the persisted report"
    assert pg_replay_counts(self, repo["id"]) == counts, "gzip replay advanced PG ledger counters"
    return {"operation": operation, "ack_oid": oid, "report_bytes": len(first),
            "ledger": counts, "exact_replay_identical": True, "changed_body_status": conflict_code,
            "gzip_replay_status": gzip_code, "gzip_replay_identical": gzip_identical,
            "concurrent_post_statuses": concurrent_statuses}
def create_retry_preserves_the_first_pushed_default_branch(self):
    repo, _ = self.create("head-retry", self.alice)
    remote = self.base + repo["clone_path"]
    work = self.root / "head-retry-work"
    self.empty_clone(remote, work, self.alice)
    self.configure(work)
    oid = self.commit_files(work, "first topic", {"topic.txt": "topic bytes\n"})
    self.git("push", "origin", "HEAD:refs/heads/topic", cwd=work, token=self.alice)
    rid = str(uuid.UUID(repo["id"]))
    before = self.sql("SELECT head_ref FROM ref_store_core_gates WHERE repository_id='" + rid + "'")
    assert before == "refs/heads/topic", "first push did not select topic as HEAD"
    _, replay = self.post_repo("head-retry", self.alice, expect=(200,))
    assert replay["id"] == repo["id"], "creation retry minted another authority"
    after = self.sql("SELECT head_ref FROM ref_store_core_gates WHERE repository_id='" + rid + "'")
    assert after == before, "creation retry changed HEAD"
    self.exact_clone(remote, self.root / "head-retry-clone", oid, "sha1", {"topic.txt": "topic bytes\n"}, self.reader)
    return {"repository_id": rid, "ack_oid": oid, "head_ref": after}
def server_side_mixed_ref_policy_atomic_then_subset_sha1_sha256(self):
    """Both fast-forward commands reach the server and the same policy rejects one."""
    protected = "refs/heads/main"
    allowed = "refs/heads/mixed-side"
    denied = {"name": protected, "outcome": "not_applied", "reason": "policy_denied"}
    formats = {}
    for fmt in ("sha1", "sha256"):
        name = "server-mixed-" + fmt
        repo, remote, work, base = self.seed(name, object_format=fmt)
        assert self.object_format(work) == fmt
        self.git("push", "origin", base + ":" + allowed, cwd=work, token=self.alice)
        before = self.remote_refs(remote, self.alice)
        assert before[protected] == before[allowed] == base
        repo_id = str(uuid.UUID(repo["id"]))
        repo_filter = " WHERE repository_id='" + repo_id + "'"
        rule = self.sql(
            "WITH inserted AS (INSERT INTO forge_branch_rules(tenant_id,repository_id,branch_ref,required_approvals) "
            "SELECT owner_id,id,'refs/heads/main',1 FROM repositories WHERE id='" + repo_id + "' "
            "RETURNING branch_ref) SELECT branch_ref FROM inserted")
        assert rule == protected, "approval rule was not installed on the fixture repository"
        revision = int(self.sql("SELECT revision FROM ref_store_core_gates" + repo_filter))
        reject_oid = self.commit_tree(work, base, "blocked candidate")
        accept_oid = self.commit_tree(work, base, "allowed candidate")
        repo_path = "/api/repos/" + urllib.parse.quote(repo["owner"], safe="") + "/" + name

        def push(atomic, expected_refs, expected_revision):
            operation = str(uuid.uuid4())
            options = ["--atomic"] if atomic else []
            result = self.git("-c", "http.extraHeader=X-Rootyard-Operation: " + operation,
                              "push", "--porcelain", *options, "origin",
                              reject_oid + ":" + protected, accept_oid + ":" + allowed,
                              cwd=work, token=self.alice, check=False)
            entries = parse_push(result.stdout.decode())
            assert result.returncode != 0 and push_rejected(entries, protected), entries
            allowed_verdict = push_rejected if atomic else push_success
            assert allowed_verdict(entries, allowed), entries

            status, raw, _ = self.http(repo_path + "/operations/" + operation, token=self.alice)
            assert status == 200, "GET operation status=" + str(status)
            view = json.loads(raw)
            kind = "rejected" if atomic else "committed"
            assert view["operation_id"] == operation and view["state"] == kind
            terminal = view["terminal"]
            assert terminal["kind"] == kind and terminal["repository_id"] == repo_id
            assert terminal["revision"] == expected_revision
            outcomes = {ref["name"]: ref for ref in terminal["refs"]}
            assert len(terminal["refs"]) == 2 and outcomes == {protected: denied, allowed: expected_refs}, outcomes

            reason = self.sql(
                "SELECT r.reject_code FROM ref_store_publication_decisions d "
                "JOIN ref_store_decision_refs r ON r.decision_id=d.decision_id "
                "WHERE d.repository_id='" + repo_id + "' AND d.operation_id='" + operation + "' "
                "AND r.ref_name='refs/heads/main' AND r.verdict='reject'")
            assert reason == "missing_approvals", reason
            assert int(self.sql("SELECT revision FROM ref_store_core_gates" + repo_filter)) == expected_revision

        push(True, {"name": allowed, "outcome": "not_applied", "reason": "policy_denied"}, revision)
        assert self.remote_refs(remote, self.alice) == before, "atomic push changed the advertised refs"
        push(False, {"name": allowed, "outcome": "applied", "old_oid": base, "new_oid": accept_oid}, revision + 1)
        assert self.remote_refs(remote, self.alice) == {**before, allowed: accept_oid}, "subset changed other refs"
        clone = self.root / (name + "-fresh")
        self.exact_clone(remote, clone, base, fmt, {"base.txt": "seed " + name + "\n"}, self.reader)
        side = self.git("rev-parse", "refs/remotes/origin/mixed-side", cwd=clone).stdout.decode().strip()
        assert side == accept_oid
        formats[fmt] = {"atomic_rolled_back": True, "subset_committed": True,
                        "protected_reason": "missing_approvals", "fresh_clone_fsck": True}
    return {"formats": formats}
for _case_name in CASES:
    setattr(BlobOnlyHarness, _case_name, globals()[_case_name])
def select_cases(names):
    if not names:
        return list(CASES)
    unknown = [name for name in names if name not in CASES]
    if unknown:
        raise ProfileError("unknown case(s): " + ", ".join(unknown))
    selected = [name for name in CASES if name in set(names)]
    if not selected:
        raise ProfileError("no cases selected; a zero-case run cannot be green")
    return selected
def validate_report_cases(report, expected):
    cases = report.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ProfileError("report has no executed cases")
    if [case.get("name") for case in cases] != list(expected):
        raise ProfileError("case inventory mismatch: " + repr([case.get("name") for case in cases]))
    for case in cases:
        if case.get("status") != "passed" or case.get("error") or case.get("trace"):
            raise ProfileError("case is not passed: " + str(case.get("name")))
    if report.get("failure_traceback"):
        raise ProfileError("report carries a failure traceback")
def build_report(harness, profile, blob_profile, expected, success):
    binding_error = None
    try:
        validate_report_cases({"cases": harness.results}, expected)
    except ProfileError as error:
        binding_error = str(error)
    inputs_unchanged = True
    if profile.source_digest() != profile.build["source_inputs_sha256"]:
        inputs_unchanged = False
        binding_error = "production source changed during native acceptance"
    if sha256_file(Path(__file__)) != profile.harness_sha256:
        inputs_unchanged = False
        binding_error = "harness source changed during native acceptance"
    report = {
        "qualification_kind": "clean-candidate" if profile.working_tree_clean else "dirty-diagnostic-only",
        "inputs_unchanged": inputs_unchanged,
        "kind": "rootyard/blob-only-native-acceptance", "passed": bool(success and not binding_error), "measurement_kind": "native_execution", "simulated_fields": False,
        "source_head": profile.build["workspace_commit"], "source_inputs_sha256": profile.build["source_inputs_sha256"],
        "binary_sha256": profile.build["binary_sha256"], "harness_sha256": profile.harness_sha256, "git_sha256": profile.git_sha256,
        "native_profile": {"attested": True, "receipt_schema": profile.schema, "binary_sha256": profile.build["binary_sha256"], "source_inputs_sha256": profile.build["source_inputs_sha256"], "config_digest": profile.config_digest, "workspace_commit": profile.build["workspace_commit"], "rustc": profile.rustc, "build_receipt_sha256": profile.receipt_sha256, "git_sha256": profile.git_sha256, "harness_sha256": profile.harness_sha256},
        "blob_profile": blob_profile, "expected_cases": list(expected), "case_count": len(harness.results), "expected_count": len(expected), "skips": 0, "pending_cases": [], "cases": harness.results,
        "limitations": LIMITATIONS,
        "runtime": {"git_version": harness.run([str(profile.git), "--version"]).stdout.decode().strip(), "tool_versions": ops_provenance.tool_versions()},
    }
    if binding_error: report["binding_error"] = binding_error
    return report
def write_report(path, payload):
    if not path:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path); parser.add_argument("--keep", action="store_true"); parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args(argv)
    env = os.environ.copy()
    try:
        profile = NativeProfile(args.binary, args.git, env)
        blob_profile = check_blob_profile(env)
        need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        need(shutil.which("psql"), "psql is required")
        selected = select_cases(args.case)
    except Exception as error:
        write_report(args.report, {"kind": "rootyard/blob-only-native-acceptance", "passed": False,
                                   "preflight_failed": True, "error": str(error), "cases": [],
                                   "expected_cases": [], "skips": 0, "limitations": LIMITATIONS})
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    harness = BlobOnlyHarness(args, profile, blob_profile)
    success = False
    try:
        if CASES[0] not in selected: harness.prepare()
        for name in selected:
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report = build_report(harness, profile, blob_profile, selected, success)
        write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1
if __name__ == "__main__":
    sys.exit(main())
