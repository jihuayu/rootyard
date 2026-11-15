#!/usr/bin/env python3
"""Focused #82 AC3 legacy format11/schema135 hosted qualification gate.

This wrapper owns one disposable Vault Transit provider for the lifetime of one
call to the reviewed ``tests/backup_legacy135_scopes.py`` harness.  It validates
the separately prepared current candidate (v2) and frozen schema135 producer
(v1 or v2) through the shared native-build receipt reader, then runs the real
seven-case legacy archive drill with the exact ``--allow-legacy-schema135``
selection.  It never builds, clones, restores by itself, or rewrites an archive.

The Vault root token and scoped service token live only in this process's RAM.
The Docker command receives the random dev root token through its environment,
never argv.  No credential file, provider log, request body, database URL or
raw server output is written to the qualification report.  The only persistent
provider state is an ownership record (container id/name/nonce/labels) used by
the workflow's job-owned cleanup step; it contains no credential.

This gate is intentionally narrow: it is not a generic acceptance platform and
does not qualify any other legacy schema or backup format.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SCRIPTS = ROOT / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import native_build_receipt as receipts  # noqa: E402
import backup_legacy132_sessions as legacy  # noqa: E402
from backup_legacy135_scopes import LEGACY135_CURRENT_TARGET  # noqa: E402
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION  # noqa: E402

VAULT_IMAGE = (
    "hashicorp/vault@sha256:"
    "44fa1e5a57d0bcf7fb163159872263b79a575e5dbfefd5b9bde1b7e4aada2f32"
)
VAULT_VERSION = "2.2.2"
VAULT_KIND = "owned-legacy135-vault"
VAULT_GOAL = "issue82"
VAULT_NONCE = re.compile(r"^[0-9a-f]{12}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
FROZEN_PRODUCER_COMMIT = "560e96f41f1d4670bfb5d2459af7af459eca4823"
FROZEN_SOURCE_FORMAT = 11
FROZEN_SOURCE_SCHEMA = 135
QUALIFICATION_SCHEMA = "rootyard/issue82-legacy135-qualification/v1"
PROVIDER_SCHEMA = "rootyard/issue82-legacy135-provider/v1"
OWNERSHIP_SCHEMA = "rootyard/issue82-legacy135-vault-ownership/v1"
CONTAINER_NAME_PREFIX = "rootyard-legacy135-vault-"
OBJECT_STORE_ENV = (
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
)
KMS_ENV = (
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_MOUNT",
    "ROOTYARD_KMS_VAULT_KEY",
)


class QualificationError(RuntimeError):
    """A stable failure code; raw exception text is never reported."""

    def __init__(self, code, stage=None):
        self.code = code
        self.stage = stage
        super().__init__(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def required_cases():
    target = LEGACY135_CURRENT_TARGET.target_schema
    return (
        "create_real_schema135_pando_source",
        "legacy_binary_writes_format11_schema135_archive",
        "candidate_cli_usage_and_mixed_legacy_flags",
        "candidate_rejects_without_schema135_opt_in",
        "candidate_restores_schema%s_one_new_authority" % target,
        "restored_service_git_and_session_boundaries",
        "source_authority_and_remote_objects_remain_available",
    )


def _safe_path(path):
    return str(Path(path).resolve())


def _inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def _require(condition, code, stage=None):
    if not condition:
        raise QualificationError(code, stage)


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        raise QualificationError("source_unreadable") from None


def verify_frozen_source(source_root):
    """Prove the frozen producer source is exactly format11/schema135.

    Git identity is checked by the caller through the shared receipt helper.
    This function reads only the source catalog/migration declarations and the
    migration filenames; it never builds or executes that source.
    """
    source_root = Path(source_root)
    db = _read(source_root / "src" / "db.rs")
    versions_match = re.search(
        r"pub const SCHEMA_VERSIONS:\s*&\[i32\]\s*=\s*&\[([0-9,\s]+)\];", db)
    _require(versions_match is not None, "frozen_schema_versions_missing")
    versions = [int(item.strip()) for item in versions_match.group(1).split(",")
                if item.strip()]
    migration_pairs = re.findall(
        r'\((\d+),\s*include_str!\("\.\./migrations/([^"]+)"\)\)', db)
    migrations = [int(version) for version, _ in migration_pairs]
    _require(versions == [1] + migrations, "frozen_schema_versions_inconsistent")
    _require(versions and versions[-1] == FROZEN_SOURCE_SCHEMA,
             "frozen_schema_not_135")
    _require(FROZEN_SOURCE_SCHEMA + 1 not in versions,
             "frozen_source_contains_schema136")
    names = sorted(path.name for path in (source_root / "migrations").glob("*.sql"))
    _require(any(name.startswith("135_") for name in names),
             "frozen_schema135_migration_missing")
    _require(not any(name.startswith("136_") for name in names),
             "frozen_schema136_migration_present")
    catalog = _read(source_root / "src" / "backup" / "catalog.rs")
    format_match = re.search(r"pub\(super\) const FORMAT:\s*u32\s*=\s*(\d+);", catalog)
    _require(format_match is not None, "frozen_format_missing")
    _require(int(format_match.group(1)) == FROZEN_SOURCE_FORMAT,
             "frozen_format_not_11")
    return {
        "format": FROZEN_SOURCE_FORMAT,
        "schema": FROZEN_SOURCE_SCHEMA,
        "schema_versions": versions,
        "schema136_absent": True,
    }


def _source_identity(source_root, expected_commit, code_prefix):
    try:
        state = receipts.require_clean_git_state(source_root)
    except receipts.ReceiptError:
        raise QualificationError(code_prefix + "_source_dirty") from None
    if state["commit"] != expected_commit:
        raise QualificationError(code_prefix + "_source_commit_mismatch")
    return {
        "commit": state["commit"],
        "tree": state["tree"],
        "clean": True,
    }


def validate_inputs(args):
    """Validate all explicit binaries, receipts, sources and role separation."""
    candidate_binary = Path(args.candidate_binary).resolve()
    candidate_receipt = Path(args.candidate_receipt).resolve()
    candidate_root = Path(args.candidate_source_root).resolve()
    producer_binary = Path(args.producer_binary).resolve()
    producer_receipt = Path(args.producer_receipt).resolve()
    producer_root = Path(args.producer_source_root).resolve()

    for label, path in (("candidate_binary", candidate_binary),
                        ("candidate_receipt", candidate_receipt),
                        ("producer_binary", producer_binary),
                        ("producer_receipt", producer_receipt)):
        _require(path.is_file(), "missing_" + label)
    _require(candidate_root.is_dir(), "missing_candidate_source_root")
    _require(producer_root.is_dir(), "missing_producer_source_root")
    _require(COMMIT.fullmatch(args.expected_candidate_commit) is not None,
             "invalid_expected_candidate_commit")
    _require(COMMIT.fullmatch(args.expected_producer_commit) is not None,
             "invalid_expected_producer_commit")
    _require(args.expected_producer_commit == FROZEN_PRODUCER_COMMIT,
             "producer_commit_not_frozen_560")
    _require(SHA256.fullmatch(args.expected_candidate_sha256) is not None,
             "invalid_expected_candidate_sha256")
    _require(SHA256.fullmatch(args.expected_producer_sha256) is not None,
             "invalid_expected_producer_sha256")

    if _inside(producer_root, candidate_root) or _inside(candidate_root, producer_root):
        raise QualificationError("source_roles_not_disjoint")
    if (_inside(producer_binary, candidate_root) or
            _inside(producer_receipt, candidate_root) or
            _inside(candidate_binary, producer_root) or
            _inside(candidate_receipt, producer_root)):
        raise QualificationError("binary_receipt_roles_not_disjoint")
    if candidate_binary == producer_binary or candidate_receipt == producer_receipt:
        raise QualificationError("candidate_and_producer_paths_reused")

    candidate_source = _source_identity(
        candidate_root, args.expected_candidate_commit, "candidate")
    producer_source = _source_identity(
        producer_root, args.expected_producer_commit, "producer")
    frozen = verify_frozen_source(producer_root)

    try:
        candidate = receipts.load_receipt(
            candidate_receipt,
            source_root=candidate_root,
            binary_path=candidate_binary,
            expected_commit=args.expected_candidate_commit,
            expected_binary_sha256=args.expected_candidate_sha256,
            forbid_implicit_build=True,
        )
    except receipts.ReceiptError:
        raise QualificationError("candidate_receipt_rejected") from None
    _require(candidate.schema == "v2", "candidate_receipt_not_v2")
    try:
        producer = receipts.load_receipt(
            producer_receipt,
            source_root=producer_root,
            binary_path=producer_binary,
            expected_commit=args.expected_producer_commit,
            expected_binary_sha256=args.expected_producer_sha256,
            forbid_implicit_build=True,
        )
    except receipts.ReceiptError:
        raise QualificationError("producer_receipt_rejected") from None
    _require(producer.schema in ("v1", "v2"), "producer_receipt_schema_invalid")

    if candidate.workspace_commit != args.expected_candidate_commit:
        raise QualificationError("candidate_receipt_commit_mismatch")
    if producer.workspace_commit != args.expected_producer_commit:
        raise QualificationError("producer_receipt_commit_mismatch")
    if candidate.binary_sha256 != args.expected_candidate_sha256:
        raise QualificationError("candidate_receipt_binary_mismatch")
    if producer.binary_sha256 != args.expected_producer_sha256:
        raise QualificationError("producer_receipt_binary_mismatch")

    return {
        "candidate_binary": candidate_binary,
        "candidate_receipt": candidate_receipt,
        "candidate_source": candidate_source,
        "candidate_receipt_schema": candidate.schema,
        "producer_binary": producer_binary,
        "producer_receipt": producer_receipt,
        "producer_source": producer_source,
        "producer_receipt_schema": producer.schema,
        "frozen_source": frozen,
        "candidate_receipt_sha256": candidate.receipt_sha256,
        "producer_receipt_sha256": producer.receipt_sha256,
    }


def binding_snapshot(inputs, args):
    files = [
        TESTS / "backup_legacy135_scopes.py",
        TESTS / "backup_legacy132_sessions.py",
        TESTS / "schema_baseline.py",
        TESTS / "legacy135_qualification.py",
        inputs["candidate_binary"],
        inputs["candidate_receipt"],
        inputs["producer_binary"],
        inputs["producer_receipt"],
    ]
    for optional in (args.workflow_path, args.collector_path):
        if optional:
            files.append(Path(optional).resolve())
    hashes = {}
    for path in files:
        _require(path.is_file(), "binding_input_missing")
        hashes[str(path)] = sha256_file(path)
    return {
        "files": hashes,
        "candidate_source": _source_identity(
            Path(args.candidate_source_root).resolve(),
            args.expected_candidate_commit, "candidate"),
        "producer_source": _source_identity(
            Path(args.producer_source_root).resolve(),
            args.expected_producer_commit, "producer"),
    }


def require_binding_unchanged(before, after):
    if before != after:
        raise QualificationError("binding_changed")


@contextlib.contextmanager
def devnull_server_logs():
    """Discard only the owned harness server diagnostic log writes.

    The shared Harness opens ``<fixture>/server.log``.  A symlink to /dev/null
    preserves the real process/readiness/cleanup assertions while preventing a
    provider locator, SQL or raw runtime output from becoming a file artifact.
    """
    original = legacy.LegacyArchiveHarness

    class QuietLegacyArchiveHarness(original):
        def __init__(self, args, contract):
            super().__init__(args, contract)
            log_path = self.root / "server.log"
            if not log_path.exists():
                log_path.symlink_to(os.devnull)

    legacy.LegacyArchiveHarness = QuietLegacyArchiveHarness
    try:
        yield
    finally:
        legacy.LegacyArchiveHarness = original


def invoke_legacy(inputs):
    """Run the real shared harness in-process; never pass its unsafe --report."""
    argv = [
        "--binary", str(inputs["candidate_binary"]),
        "--legacy-binary", str(inputs["producer_binary"]),
    ]
    stdout = io.StringIO()
    stderr = io.StringIO()
    with devnull_server_logs():
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = legacy.run_main(LEGACY135_CURRENT_TARGET, argv=argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _terminal_json_object(raw):
    """Read the final JSON object after the harness's own progress lines."""
    text = raw.strip()
    if not text:
        raise QualificationError("legacy_report_invalid")
    decoder = json.JSONDecoder()
    for index in range(len(text) - 1, -1, -1):
        if text[index] != "{":
            continue
        try:
            value, end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if end == len(text[index:]):
            return value
    raise QualificationError("legacy_report_invalid")


def parse_legacy_report(raw, inputs):
    report = _terminal_json_object(raw)
    if not isinstance(report, dict):
        raise QualificationError("legacy_report_invalid")
    if report.get("passed") is not True:
        raise QualificationError("legacy_report_not_passed")
    expected = list(required_cases())
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected):
        raise QualificationError("legacy_case_count_invalid")
    projected = []
    names = []
    for case in cases:
        if not isinstance(case, dict):
            raise QualificationError("legacy_case_shape_invalid")
        name, status = case.get("name"), case.get("status")
        if not isinstance(name, str) or status not in ("passed",):
            raise QualificationError("legacy_case_not_green")
        names.append(name)
        projected.append({"name": name, "status": status})
    if names != expected:
        raise QualificationError("legacy_cases_mismatch")
    target = LEGACY135_CURRENT_TARGET
    if report.get("reviewed_target_schema") != target.target_schema:
        raise QualificationError("legacy_target_schema_mismatch")
    if report.get("reviewed_target_format") != target.target_format:
        raise QualificationError("legacy_target_format_mismatch")
    if target.target_schema != CURRENT_SCHEMA_VERSION:
        raise QualificationError("current_schema_constant_mismatch")
    if target.target_format != CURRENT_BACKUP_FORMAT:
        raise QualificationError("current_format_constant_mismatch")
    if report.get("binary_sha256") != inputs["expected_candidate_sha256"]:
        raise QualificationError("legacy_candidate_sha_mismatch")
    if report.get("legacy_binary_sha256") != inputs["expected_producer_sha256"]:
        raise QualificationError("legacy_producer_sha_mismatch")
    if report.get("harness_git_head") != inputs["expected_candidate_commit"]:
        raise QualificationError("legacy_harness_commit_mismatch")
    return {
        "passed": True,
        "cases": projected,
        "case_count": len(projected),
        "schema_version": report.get("reviewed_target_schema"),
        "target_format": report.get("reviewed_target_format"),
        "candidate_binary_sha256": report.get("binary_sha256"),
        "producer_binary_sha256": report.get("legacy_binary_sha256"),
        "harness_git_head": report.get("harness_git_head"),
    }


def validate_object_store_environment():
    missing = [name for name in OBJECT_STORE_ENV if not os.environ.get(name)]
    if missing:
        raise QualificationError("object_store_environment_missing")


def service_policy(key_name):
    """Least-privilege policy for the operations used by this harness."""
    paths = {
        "encrypt": "update",
        "decrypt": "update",
        "rewrap": "update",
    }
    lines = [
        'path "transit/%s/%s" { capabilities = ["%s"] }' % (action, key_name, capability)
        for action, capability in paths.items()
    ]
    lines.append(
        'path "transit/keys/%s" { capabilities = ["read"] }' % key_name)
    lines.append(
        'path "transit/keys/%s/rotate" { capabilities = ["update"] }' % key_name)
    return "\n".join(lines) + "\n"


def expected_container_name(nonce):
    return CONTAINER_NAME_PREFIX + nonce


def _validate_state(state):
    """Validate the public ownership record; never treat ambiguity as clean."""
    if not isinstance(state, dict):
        raise QualificationError("vault_state_invalid")
    schema = state.get("schema")
    if schema is not None and schema != OWNERSHIP_SCHEMA:
        raise QualificationError("vault_state_schema_invalid")
    if state.get("kind") != VAULT_KIND or state.get("goal") != VAULT_GOAL:
        raise QualificationError("vault_state_kind_mismatch")
    nonce = state.get("nonce")
    if not isinstance(nonce, str) or VAULT_NONCE.fullmatch(nonce) is None:
        raise QualificationError("vault_state_nonce_invalid")
    if state.get("uid") != os.getuid():
        raise QualificationError("vault_state_uid_mismatch")
    name = state.get("container_name")
    if name != expected_container_name(nonce):
        raise QualificationError("vault_state_name_mismatch")
    image = state.get("image")
    if image != VAULT_IMAGE:
        raise QualificationError("vault_state_image_mismatch")
    phase = state.get("phase")
    container_id = state.get("container_id")
    if phase is None:
        phase = "created" if container_id else "intent"
    if phase not in ("intent", "created"):
        raise QualificationError("vault_state_phase_invalid")
    if phase == "intent":
        if container_id is not None:
            raise QualificationError("vault_state_container_invalid")
    elif not isinstance(container_id, str) or CONTAINER_ID.fullmatch(container_id) is None:
        raise QualificationError("vault_state_container_invalid")
    return dict(state, phase=phase)


class DockerRunner:
    """Small bounded wrapper; output stays in RAM and is never logged."""

    def __init__(self, timeout=60):
        self.timeout = timeout

    def run(self, argv, env=None, input=None, timeout=None):
        try:
            return subprocess.run(
                argv,
                env=env,
                input=input,
                stdin=subprocess.DEVNULL if input is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout if timeout is None else timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise QualificationError("docker_process_failed") from None


def _inspect_owned_container(runner, state, container_id, prefix):
    """Verify full ID, pinned image and all ownership labels."""
    id_result = runner.run([
        "docker", "inspect", "--type", "container", "--format", "{{.Id}}",
        container_id])
    if id_result.returncode != 0:
        raise QualificationError(prefix + "_unverified")
    actual = id_result.stdout.decode(errors="replace").strip()
    if actual != container_id:
        raise QualificationError(prefix + "_id_mismatch")
    image_result = runner.run([
        "docker", "inspect", "--type", "container",
        "--format", "{{.Config.Image}}", container_id])
    if image_result.returncode != 0:
        raise QualificationError(prefix + "_unverified")
    image = image_result.stdout.decode(errors="replace").strip()
    if image != state["image"]:
        raise QualificationError(prefix + "_image_mismatch")
    labels_result = runner.run([
        "docker", "inspect", "--type", "container",
        "--format", "{{json .Config.Labels}}", container_id])
    if labels_result.returncode != 0:
        raise QualificationError(prefix + "_labels_unreadable")
    try:
        labels = json.loads(labels_result.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise QualificationError(prefix + "_labels_invalid") from None
    if not isinstance(labels, dict):
        raise QualificationError(prefix + "_labels_invalid")
    expected = {
        "rootyard.fixture.kind": state["kind"],
        "rootyard.fixture.nonce": state["nonce"],
        "rootyard.fixture.goal": state["goal"],
        "rootyard.fixture.uid": str(state["uid"]),
    }
    if any(labels.get(key) != value for key, value in expected.items()):
        raise QualificationError(prefix + "_label_mismatch")
    return container_id


def _find_owned_container_by_name(runner, state, prefix):
    """Reconcile only the exact nonce-derived name, never a prefix."""
    state = _validate_state(state)
    name = state["container_name"]
    result = runner.run([
        "docker", "ps", "-a", "--no-trunc",
        "--filter", "name=^/" + name + "$",
        "--format", "{{.ID}}\t{{.Names}}",
    ])
    if result.returncode != 0:
        raise QualificationError(prefix + "_name_query_failed")
    rows = []
    for line in result.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" not in line:
            raise QualificationError(prefix + "_name_query_invalid")
        container_id, actual_name = line.split("\t", 1)
        if actual_name != name:
            raise QualificationError(prefix + "_name_ambiguous")
        rows.append(container_id)
    if not rows:
        return None
    if len(rows) != 1:
        raise QualificationError(prefix + "_name_ambiguous")
    container_id = rows[0]
    if CONTAINER_ID.fullmatch(container_id) is None:
        raise QualificationError(prefix + "_container_id_invalid")
    return _inspect_owned_container(runner, state, container_id, prefix)


def _resolve_owned_container(runner, state, prefix):
    """Resolve a recorded ID or exact name to one verified owned container."""
    state = _validate_state(state)
    recorded = state.get("container_id")
    if recorded:
        try:
            return _inspect_owned_container(runner, state, recorded, prefix)
        except QualificationError as error:
            if error.code != prefix + "_unverified":
                raise
            # Only an unreadable/absent ID falls back to exact-name recovery.
            # Identity/image/label mismatch remains fail-closed.
    found = _find_owned_container_by_name(runner, state, prefix)
    if found is None:
        return None
    if recorded and found != recorded:
        raise QualificationError(prefix + "_id_mismatch")
    return found


class VaultFixture:
    """One exact-owned ephemeral Vault Transit provider."""

    def __init__(self, state_path, runner=None, image=VAULT_IMAGE,
                 token_factory=None, sleep=None):
        self.state_path = Path(state_path)
        self.runner = runner or DockerRunner()
        self.image = image
        self.token_factory = token_factory or secrets.token_urlsafe
        self.sleep = sleep or time.sleep
        self.nonce = secrets.token_hex(6)
        self.container_name = expected_container_name(self.nonce)
        self.key_name = "rootyard-legacy135-" + self.nonce
        self.policy_name = "rootyard-legacy135-service-" + self.nonce
        self.container_id = None
        self.host_url = None
        self.root_token = None
        self.service_token = None
        self.version = None
        self.prepared = False
        self.state_written = False
        self.phase = None
        self.reconciliation = "not_needed"

    def safe_state(self, phase=None):
        return {
            "schema": OWNERSHIP_SCHEMA,
            "phase": phase or self.phase or (
                "created" if self.container_id else "intent"),
            "kind": VAULT_KIND,
            "goal": VAULT_GOAL,
            "nonce": self.nonce,
            "uid": os.getuid(),
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
        }

    def write_state(self, phase):
        state = self.safe_state(phase)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(self.state_path.name + ".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_path)
        self.state_written = True
        self.phase = phase

    def remove_state(self):
        with contextlib.suppress(FileNotFoundError):
            self.state_path.unlink()
        self.state_written = False
        self.phase = None

    def _image_digests(self):
        result = self.runner.run(
            ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", self.image])
        if result.returncode != 0:
            return None
        try:
            digests = json.loads(result.stdout.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return digests if isinstance(digests, list) else None

    def ensure_image(self):
        digests = self._image_digests()
        if digests is None or self.image not in digests:
            result = self.runner.run(
                ["docker", "pull", self.image], timeout=300)
            if result.returncode != 0:
                raise QualificationError("vault_image_unavailable")
            digests = self._image_digests()
        if digests is None or self.image not in digests:
            raise QualificationError("vault_image_digest_unverified")

    def api(self, method, path, payload=None, token=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(
            self.host_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(1024 * 1024)
        except (urllib.error.URLError, OSError, ValueError):
            raise QualificationError("vault_api_failed") from None
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("vault_api_invalid") from None
        if not isinstance(value, dict):
            raise QualificationError("vault_api_invalid")
        return value

    def health(self):
        value = self.api("GET", "/v1/sys/health")
        return (value.get("initialized") is True and
                value.get("sealed") is False and
                value.get("version") == VAULT_VERSION)

    def reconcile_creation(self):
        """Recover only this invocation's exact-named container, or stay unresolved."""
        self.container_id = None
        try:
            found = _find_owned_container_by_name(
                self.runner, self.safe_state("intent"), "vault_ownership")
        except QualificationError:
            self.reconciliation = "unresolved"
            return
        if found is None:
            self.reconciliation = "no_resource"
            return
        self.container_id = found
        try:
            self.write_state("created")
        except OSError:
            self.reconciliation = "state_write_failed"
            return
        self.reconciliation = "recorded"

    def start(self):
        self.ensure_image()
        root_token = self.token_factory(40)
        self.root_token = root_token
        environment = os.environ.copy()
        environment["VAULT_DEV_ROOT_TOKEN_ID"] = root_token
        environment["VAULT_DEV_LISTEN_ADDRESS"] = "0.0.0.0:8200"
        command = [
            "docker", "run", "-d", "--rm", "--name", self.container_name,
            "--label", "rootyard.fixture.kind=" + VAULT_KIND,
            "--label", "rootyard.fixture.nonce=" + self.nonce,
            "--label", "rootyard.fixture.goal=" + VAULT_GOAL,
            "--label", "rootyard.fixture.uid=" + str(os.getuid()),
            "--log-driver", "none", "--cap-add", "IPC_LOCK",
            "-p", "127.0.0.1::8200",
            "-e", "VAULT_DEV_ROOT_TOKEN_ID",
            "-e", "VAULT_DEV_LISTEN_ADDRESS",
            self.image, "server", "-dev",
        ]
        try:
            self.write_state("intent")
        except OSError:
            raise QualificationError("vault_state_write_failed") from None
        try:
            result = self.runner.run(command, env=environment)
        except QualificationError:
            self.reconcile_creation()
            raise
        if result.returncode != 0:
            self.reconcile_creation()
            raise QualificationError("vault_start_failed")
        container_id = result.stdout.decode(errors="replace").strip()
        if CONTAINER_ID.fullmatch(container_id) is None:
            self.reconcile_creation()
            raise QualificationError("vault_container_id_invalid")
        try:
            _inspect_owned_container(
                self.runner, self.safe_state("intent"), container_id,
                "vault_ownership")
        except QualificationError:
            self.reconcile_creation()
            raise
        self.container_id = container_id
        try:
            self.write_state("created")
        except OSError:
            raise QualificationError("vault_state_write_failed") from None
        ports = self.runner.run(
            ["docker", "port", self.container_name, "8200/tcp"])
        if ports.returncode != 0:
            raise QualificationError("vault_port_failed")
        lines = ports.stdout.decode(errors="replace").splitlines()
        if not lines or ":" not in lines[0]:
            raise QualificationError("vault_port_invalid")
        host, port = lines[0].rsplit(":", 1)
        if host.strip() not in ("127.0.0.1", "0.0.0.0"):
            raise QualificationError("vault_port_not_loopback")
        if not port.isdigit():
            raise QualificationError("vault_port_invalid")
        self.host_url = "http://127.0.0.1:" + port
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if self.health():
                    break
            except QualificationError:
                pass
            self.sleep(0.2)
        else:
            raise QualificationError("vault_health_timeout")
        self.version = VAULT_VERSION

    def prepare(self):
        if not self.root_token:
            raise QualificationError("vault_root_token_missing")
        self.api("POST", "/v1/sys/mounts/transit", {"type": "transit"},
                 token=self.root_token)
        self.api("POST", "/v1/transit/keys/" + self.key_name,
                 {"type": "aes256-gcm96"}, token=self.root_token)
        self.api("PUT", "/v1/sys/policies/acl/" + self.policy_name,
                 {"policy": service_policy(self.key_name)}, token=self.root_token)
        result = self.api("POST", "/v1/auth/token/create", {
            "policies": [self.policy_name],
            "no_default_policy": True,
            "ttl": "2h",
            "renewable": False,
        }, token=self.root_token)
        token = (result.get("auth") or {}).get("client_token")
        if not isinstance(token, str) or not token:
            raise QualificationError("vault_service_token_missing")
        self.service_token = token
        plain = os.urandom(32)
        encoded = base64.b64encode(plain).decode()
        encrypted = self.api(
            "POST", "/v1/transit/encrypt/" + self.key_name,
            {"plaintext": encoded}, token=self.service_token)
        ciphertext = (encrypted.get("data") or {}).get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext:
            raise QualificationError("vault_transit_encrypt_failed")
        decrypted = self.api(
            "POST", "/v1/transit/decrypt/" + self.key_name,
            {"ciphertext": ciphertext}, token=self.service_token)
        if (decrypted.get("data") or {}).get("plaintext") != encoded:
            raise QualificationError("vault_transit_roundtrip_failed")
        rewrapped = self.api(
            "POST", "/v1/transit/rewrap/" + self.key_name,
            {"ciphertext": ciphertext}, token=self.service_token)
        ciphertext2 = (rewrapped.get("data") or {}).get("ciphertext")
        if not isinstance(ciphertext2, str) or not ciphertext2:
            raise QualificationError("vault_transit_rewrap_failed")
        decrypted2 = self.api(
            "POST", "/v1/transit/decrypt/" + self.key_name,
            {"ciphertext": ciphertext2}, token=self.service_token)
        if (decrypted2.get("data") or {}).get("plaintext") != encoded:
            raise QualificationError("vault_transit_rewrap_roundtrip_failed")
        self.root_token = None
        self.prepared = True

    def environment(self):
        if not self.prepared or not self.service_token or not self.host_url:
            raise QualificationError("vault_not_prepared")
        return {
            "ROOTYARD_KMS_VAULT_URL": self.host_url,
            "ROOTYARD_KMS_VAULT_TOKEN": self.service_token,
            "ROOTYARD_KMS_VAULT_MOUNT": "transit",
            "ROOTYARD_KMS_VAULT_KEY": self.key_name,
        }

    def release_credentials(self):
        self.service_token = None
        self.root_token = None

    def safe_record(self, cleanup):
        return {
            "schema": PROVIDER_SCHEMA,
            "kind": "owned-loopback-vault-transit",
            "image_digest": self.image,
            "vault_version": self.version,
            "transit_round_trip": self.prepared,
            "service_policy_scoped": self.prepared,
            "owned_container": (self.container_id is not None or
                                self.state_written),
            "ownership_recorded": self.state_written,
            "reconciliation": self.reconciliation,
            "raw_logs_persisted": False,
            "credential_file_written": False,
            "cleanup": cleanup,
        }

    def stop(self):
        state = _validate_state(self.safe_state(
            "created" if self.container_id else "intent"))
        remove_owned_container(self.runner, state)
        self.remove_state()
        return "stopped"


def remove_owned_container(runner, state):
    """Remove exactly the verified owned container; never a broad purge."""
    state = _validate_state(state)
    container_id = _resolve_owned_container(runner, state, "vault_cleanup")
    if container_id is None:
        return "absent"
    remove = runner.run(["docker", "rm", "-f", "--", container_id])
    if remove.returncode != 0:
        raise QualificationError("vault_cleanup_failed")
    return "stopped"


def cleanup_owned_state(state_path, runner=None):
    """Remove exact owned state; absence means launch never started."""
    path = Path(state_path)
    if not path.exists():
        # start() persists the intent record before docker run.  A created
        # container therefore always has a state file; absence is the honest
        # zero-container case (or a verified prior cleanup), never an
        # ambiguous creation.
        return 0
    try:
        state = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise QualificationError("vault_state_invalid") from None
    remove_owned_container(runner or DockerRunner(), state)
    path.unlink()
    return 0


def _base_report():
    return {
        "schema": QUALIFICATION_SCHEMA,
        "kind": "rootyard/issue82-legacy135-qualification",
        "issue": 82,
        "qualification_claim": False,
        "note": "No actual restore is claimed unless this report is passed in a hosted run.",
    }


def _write(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _failure_report(error, stage=None):
    report = _base_report()
    report.update({
        "passed": False,
        "error_code": error.code if isinstance(error, QualificationError) else "unexpected_error",
        "stage": (error.stage if isinstance(error, QualificationError) else stage) or stage,
        "provider_cleanup_deferred": True,
    })
    return report


def run_qualification(args):
    inputs = None
    provider = None
    provider_started = False
    report_path = Path(args.report)
    provider_path = Path(args.provider_report) if args.provider_report else None
    try:
        inputs = validate_inputs(args)
        validate_object_store_environment()
        before = binding_snapshot(inputs, args)
        provider = VaultFixture(args.vault_state)
        provider.start()
        provider_started = True
        provider.prepare()
        provider_environment = provider.environment()
        previous = {name: os.environ.get(name) for name in KMS_ENV}
        try:
            os.environ.update(provider_environment)
            code, stdout, _stderr = invoke_legacy(inputs)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            provider.release_credentials()
        if code != 0:
            raise QualificationError("legacy_run_failed")
        parsed = parse_legacy_report(stdout, {
            "expected_candidate_sha256": args.expected_candidate_sha256,
            "expected_producer_sha256": args.expected_producer_sha256,
            "expected_candidate_commit": args.expected_candidate_commit,
        })
        after = binding_snapshot(inputs, args)
        require_binding_unchanged(before, after)
        cleanup = provider.stop()
        report = _base_report()
        report.update({
            "passed": True,
            "qualification_claim": True,
            "candidate": {
                "binary_sha256": args.expected_candidate_sha256,
                "receipt_sha256": inputs["candidate_receipt_sha256"],
                "receipt_schema": inputs["candidate_receipt_schema"],
                "source": inputs["candidate_source"],
                "source_root": str(Path(args.candidate_source_root).resolve()),
            },
            "producer": {
                "binary_sha256": args.expected_producer_sha256,
                "receipt_sha256": inputs["producer_receipt_sha256"],
                "receipt_schema": inputs["producer_receipt_schema"],
                "source": inputs["producer_source"],
                "source_root": str(Path(args.producer_source_root).resolve()),
                "source_format": FROZEN_SOURCE_FORMAT,
                "source_schema": FROZEN_SOURCE_SCHEMA,
                "frozen_source_commit": FROZEN_PRODUCER_COMMIT,
                "historical_binary_sha256_asserted": False,
            },
            "target": {
                "schema": LEGACY135_CURRENT_TARGET.target_schema,
                "format": LEGACY135_CURRENT_TARGET.target_format,
            },
            "provider": provider.safe_record(cleanup),
            "cases": parsed["cases"],
            "case_count": parsed["case_count"],
            "bindings": after,
        })
        if provider_path:
            _write(provider_path, provider.safe_record(cleanup))
        _write(report_path, report)
        print(json.dumps({"passed": True, "case_count": parsed["case_count"],
                          "schema": report["target"]["schema"],
                          "format": report["target"]["format"]}, sort_keys=True))
        return 0
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = _failure_report(error)
        if provider is not None and (
                provider_started or provider.container_id is not None or
                provider.state_written):
            report["provider"] = provider.safe_record("deferred")
            if provider_path:
                try:
                    _write(provider_path, report["provider"])
                except OSError:
                    pass
            # The exact ownership state remains for the workflow's always() cleanup.
            report["provider_cleanup_deferred"] = True
        try:
            _write(report_path, report)
        except OSError:
            pass
        print(json.dumps({"passed": False, "error_code": report["error_code"]},
                         sort_keys=True), file=sys.stderr)
        return 1
    finally:
        if provider is not None:
            provider.release_credentials()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-binary")
    parser.add_argument("--candidate-receipt")
    parser.add_argument("--candidate-source-root")
    parser.add_argument("--expected-candidate-commit")
    parser.add_argument("--expected-candidate-sha256")
    parser.add_argument("--producer-binary")
    parser.add_argument("--producer-receipt")
    parser.add_argument("--producer-source-root")
    parser.add_argument("--expected-producer-commit", default=FROZEN_PRODUCER_COMMIT)
    parser.add_argument("--expected-producer-sha256")
    parser.add_argument("--vault-state")
    parser.add_argument("--report")
    parser.add_argument("--provider-report")
    parser.add_argument("--workflow-path")
    parser.add_argument("--collector-path")
    parser.add_argument("--cleanup-owned-state", metavar="STATE",
                        help="remove exactly the Vault container recorded by a "
                             "previous invocation and exit; no acceptance runs")
    args = parser.parse_args(argv)
    if args.cleanup_owned_state:
        return args
    required = (
        "candidate_binary", "candidate_receipt", "candidate_source_root",
        "expected_candidate_commit", "expected_candidate_sha256",
        "producer_binary", "producer_receipt", "producer_source_root",
        "expected_producer_sha256", "vault_state", "report",
    )
    missing = [name for name in required if not getattr(args, name)]
    if missing:
        parser.error("missing required arguments: " + ", ".join(
            "--" + name.replace("_", "-") for name in missing))
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.cleanup_owned_state:
        try:
            return cleanup_owned_state(args.cleanup_owned_state)
        except QualificationError as error:
            print("legacy135 qualification cleanup: " + error.code, file=sys.stderr)
            return 1
    return run_qualification(args)


if __name__ == "__main__":
    sys.exit(main())
