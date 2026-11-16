#!/usr/bin/env python3
"""Sanitized subprocess, environment, cache and report helpers.

No helper in this module writes raw child output, provider bodies, SQL rows,
DSNs, tokens, pack bytes or environment dumps.  Failures are projected to a
small fixed code and phase.  Cache eviction is limited to the exact owned
repository pack/idx files and is always performed before a cold provider probe
so a warm plaintext cache cannot be mistaken for provider success.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from pando_vault_rotation_fixture import FixtureError
from pando_vault_rotation_fixture_resources import NONCE_RE

CASES = (
    "vault_fixture_and_app_capability_boundary",
    "authentic_envelope_digest_and_cold_read",
    "admin_rotated_target_interrupted_resume_and_new_write",
    "wrong_key_ciphertext_envelope_and_provider_revocation_fail_closed",
    "owned_resource_cleanup",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SAFE_STRING_RE = re.compile(r"^[a-z0-9][a-z0-9_./:@-]{0,127}$")
MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 256 * 1024
REMOTE_ENV_PREFIXES = (
    "ROOTYARD_OBJECT_STORE_",
    "PANDO_OBJECT_STORE_",
    "ROOTYARD_KMS_",
    "PANDO_KMS_",
)


class QualificationError(RuntimeError):
    """A fixed, report-safe qualification failure."""

    def __init__(self, code, stage=None):
        self.code = code
        self.stage = stage
        super().__init__(code)


def require(condition, code, stage=None):
    if not condition:
        raise QualificationError(code, stage)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_uuid(value):
    return isinstance(value, str) and UUID_RE.fullmatch(value) is not None


class Completed:
    def __init__(self, argv, returncode, stdout, stderr):
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stdout = stdout[:MAX_STDOUT]
        self.stderr = stderr[:MAX_STDERR]


class Runner:
    """Bounded subprocess wrapper whose output never leaves RAM."""

    def __init__(self, timeout=90):
        self.timeout = timeout

    def run(self, argv, env=None, input=None, timeout=None, stage="subprocess", cwd=None):
        argv = [str(item) for item in argv]
        try:
            result = subprocess.run(
                argv,
                env=env,
                input=input,
                stdin=subprocess.DEVNULL if input is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout if timeout is None else timeout,
                check=False,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired:
            raise QualificationError("subprocess_timeout", stage) from None
        except (OSError, subprocess.SubprocessError):
            raise QualificationError("subprocess_failed", stage) from None
        return Completed(argv, result.returncode, result.stdout, result.stderr)

    def ok(self, argv, env=None, input=None, timeout=None, stage="subprocess", cwd=None):
        result = self.run(argv, env=env, input=input, timeout=timeout, stage=stage, cwd=cwd)
        if result.returncode != 0:
            raise QualificationError(stage + "_failed", stage)
        return result

    def json(self, argv, env=None, timeout=None, stage="subprocess"):
        result = self.ok(argv, env=env, timeout=timeout, stage=stage)
        text = result.stdout.decode(errors="replace").strip()
        if not text:
            raise QualificationError(stage + "_output_empty", stage)
        line = text.splitlines()[-1]
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raise QualificationError(stage + "_output_invalid", stage) from None
        if not isinstance(value, dict):
            raise QualificationError(stage + "_output_invalid", stage)
        return value


def child_environment(base, postgres, root, vault_environment, git):
    """Build a hermetic Pando child environment; secrets remain env-only."""
    env = dict(base)
    for name in list(env):
        if name.startswith(REMOTE_ENV_PREFIXES) and name not in vault_environment:
            env.pop(name, None)
    for name in (
        "ROOTYARD_OBJECT_STORE_ENDPOINT",
        "ROOTYARD_OBJECT_STORE_BUCKET",
        "ROOTYARD_OBJECT_STORE_REGION",
        "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
        "ROOTYARD_OBJECT_STORE_SECRET_KEY",
        "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
        "PANDO_OBJECT_STORE_ROOT",
        "PANDO_OBJECT_STORE_BUCKET",
        "PANDO_KMS_KEYRING_DIR",
        "DATABASE_URL",
        "ROOTYARD_TEST_DATABASE_URL",
        "ROOTYARD_RESTORE_TEST_DATABASE_URL",
    ):
        env.pop(name, None)
    if not isinstance(vault_environment, dict):
        raise QualificationError("vault_environment_missing", "setup")
    required = {
        "PANDO_KMS_VAULT_URL", "PANDO_KMS_VAULT_TOKEN",
        "PANDO_KMS_VAULT_MOUNT", "PANDO_KMS_VAULT_KEY",
    }
    if not required <= set(vault_environment):
        raise QualificationError("vault_environment_incomplete", "setup")
    env.update(vault_environment)
    env.update({
        "PANDO_SYNTHETIC_ONLY": "1",
        "PANDO_KMS_PROVIDER": "vault-transit",
        "PANDO_ROOT": str(root),
        "PANDO_GIT": str(git),
        "PANDO_LISTEN": "127.0.0.1:0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_DATE": "2026-11-17T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-11-17T00:00:00Z",
        "LC_ALL": "C",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    })
    env.update(postgres.child_environment())
    return env


def _owned_cache_paths(root, repo, pack_ids):
    require(valid_uuid(repo), "cache_repo_invalid", "cache")
    base = Path(root).resolve()
    directory = base / "objects" / repo
    require(directory.parent == base / "objects", "cache_path_invalid", "cache")
    paths = []
    for pack in pack_ids:
        require(valid_uuid(pack), "cache_pack_invalid", "cache")
        paths.extend([directory / (pack + ".pack"), directory / (pack + ".idx")])
    return paths


def evict_plaintext_cache(root, repo, pack_ids):
    """Remove only owned repo pack/idx files; return a count and absence fact."""
    removed = 0
    for path in _owned_cache_paths(root, repo, pack_ids):
        with _suppress_os():
            path.unlink()
            removed += 1
    absent = cache_absent(root, repo, pack_ids)
    require(absent, "cache_eviction_failed", "cache")
    return {"cache_files_removed": removed, "plaintext_cache_absent": absent}


def cache_absent(root, repo, pack_ids):
    return not any(path.exists() for path in _owned_cache_paths(root, repo, pack_ids))


def _suppress_os():
    import contextlib
    return contextlib.suppress(FileNotFoundError)


def local_authority_absent(root, repo):
    require(valid_uuid(repo), "local_authority_repo_invalid", "local_authority")
    directory = Path(root) / "kms" / repo
    if not directory.is_dir():
        return True
    forbidden = {"kms_policy.json", "keyring.json"}
    for path in directory.iterdir():
        if path.name in forbidden or path.name.endswith(".key"):
            return False
    return True


def read_manifest(root, repo, pack_id):
    require(valid_uuid(repo) and valid_uuid(pack_id), "manifest_identity_invalid", "manifest")
    base = Path(root).resolve()
    path = base / "manifests" / repo / (pack_id + ".json")
    require(path.is_file(), "manifest_missing", "manifest")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise QualificationError("manifest_invalid", "manifest") from None
    required = {
        "repo", "pack_id", "pack_key", "idx_key", "pack_sha256", "idx_sha256",
        "pack_bytes", "idx_bytes", "object_count", "encryption_mode",
        "ciphertext_sha256", "ciphertext_bytes", "cipher_suite",
    }
    if not isinstance(value, dict) or not required <= set(value):
        raise QualificationError("manifest_shape_invalid", "manifest")
    if value.get("repo") != repo or value.get("pack_id") != pack_id:
        raise QualificationError("manifest_identity_mismatch", "manifest")
    for name in ("pack_sha256", "idx_sha256", "ciphertext_sha256"):
        if not isinstance(value.get(name), str) or not SHA256_RE.fullmatch(value[name]):
            raise QualificationError("manifest_digest_invalid", "manifest")
    for name in ("pack_bytes", "idx_bytes", "ciphertext_bytes", "object_count"):
        if not isinstance(value.get(name), int) or value[name] < 0:
            raise QualificationError("manifest_size_invalid", "manifest")
    if value.get("encryption_mode") != "authenticated-envelope-v1":
        raise QualificationError("manifest_encryption_mode_invalid", "manifest")
    for key in ("pack_key", "idx_key"):
        if not isinstance(value[key], str) or not value[key]:
            raise QualificationError("manifest_path_invalid", "manifest")
        candidate = (base / value[key]).resolve()
        if base not in candidate.parents:
            raise QualificationError("manifest_path_escape", "manifest")
    return value


def read_cipher(root, manifest):
    path = (Path(root).resolve() / manifest["pack_key"]).resolve()
    require(path.is_file(), "cipher_missing", "cipher")
    data = path.read_bytes()
    require(len(data) == manifest["ciphertext_bytes"], "cipher_length_mismatch", "cipher")
    require(sha256_bytes(data) == manifest["ciphertext_sha256"],
            "cipher_digest_mismatch", "cipher")
    return data


def mirror_path(root, repo, pack_id):
    require(valid_uuid(repo) and valid_uuid(pack_id), "mirror_identity_invalid", "mirror")
    return Path(root) / "object_store" / "envelopes" / repo / (pack_id + ".json")


def read_mirror(root, repo, pack_id):
    path = mirror_path(root, repo, pack_id)
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


ALLOWED_KEYS = {
    "schema", "passed", "status", "case", "id", "cases", "case_count", "facts", "code",
    "error_code", "stage", "binding", "cleanup", "limitations", "source",
    "binary", "receipt", "harness", "source_commit", "source_tree",
    "source_clean", "binary_sha256", "receipt_sha256", "harness_sha256",
    "image_digest_sha256", "vault_version", "key_type", "derived",
    "latest_version", "min_decryption_version", "app_wrap_unwrap_rewrap",
    "app_master_rotate_denied", "app_delete_denied", "app_config_denied",
    "app_token_admin_denied", "app_policy_admin_denied", "latest_unchanged",
    "owned_container", "credential_file_written", "packs", "pack_count",
    "packs_checked", "packs_verified", "ciphertext_sha256", "ciphertext_bytes",
    "plaintext_sha256", "plaintext_bytes", "pack_sha256", "idx_sha256",
    "envelope_provider_kind", "envelope_key_version", "envelope_key_versions",
    "envelope_mac_sha256", "envelope_ciphertext_matches_manifest",
    "pandoenc_prefix", "plaintext_marker_absent", "cold_object_store_get",
    "cold_kms_verify", "cold_http_clone", "cache_evicted_before_probe",
    "cache_absent_after_failure", "plaintext_cache_absent",
    "provider_latest_version",
    "rotation_state", "rotation_target_version", "rotation_completed_packs",
    "rotation_total_packs", "rotation_failed", "rotation_contract",
    "rotation_write_epoch_positive", "completed_pack_count", "v1_pack_count",
    "v2_pack_count", "midpoint_old_v1_cold_read", "midpoint_rewrapped_v2_cold_read",
    "new_write_v2", "new_write_not_latest", "resume_rewrapped_this_invocation",
    "resume_completed", "old_and_new_cold_read", "post_completed_v2",
    "ciphertext_unchanged", "fresh_process", "wrong_key_exists",
    "wrong_key_scoped", "wrong_key_denied", "ciphertext_tamper_denied",
    "db_envelope_tamper_denied", "mirror_tamper_repaired",
    "mirror_missing_repaired", "app_revocation_denied", "cas_unchanged",
    "db_unchanged", "local_authority_absent", "restore_verified",
    "revocation_last", "vault_owned", "vault_stopped", "container_absent",
    "postgres_owned", "postgres_created", "postgres_dropped",
    "database_absent", "root_owned", "root_created", "root_removed",
    "root_absent", "cleanup_ok", "server_stopped", "pg_major", "loopback",
    "owned", "prechecked_absent", "created", "dropped", "removed",
    "absolute_private_root", "raw_logs_persisted", "no_global_cleanup",
    "credential_released",
    "local_cas_only", "s3_rotation_unsupported", "hsm_not_claimed",
    "fips_not_claimed", "production_durability_not_claimed",
    "envelope_count", "manifest_count", "known_plaintext_absent",
    "expected_version", "to_key_version", "from_key_version",
    "rotation_identity_same", "app_rotate_denied", "latest_version_value",
}
ALLOWED_LIMITATIONS = (
    "local_cas_only",
    "s3_rotation_unsupported",
    "hsm_not_claimed",
    "fips_not_claimed",
    "production_durability_not_claimed",
)


def sanitize_report(value):
    """Accept only fixed names, counts, digests and booleans."""
    if type(value) is bool or value is None:
        return value
    if type(value) is int:
        require(0 <= value <= 10**12, "report_integer_rejected", "report")
        return value
    if isinstance(value, str):
        require(SAFE_STRING_RE.fullmatch(value) is not None,
                "report_string_rejected", "report")
        return value
    if isinstance(value, list):
        return [sanitize_report(item) for item in value]
    if isinstance(value, dict):
        require(set(value) <= ALLOWED_KEYS, "report_field_rejected", "report")
        return {key: sanitize_report(item) for key, item in value.items()}
    raise QualificationError("report_type_rejected", "report")


def atomic_write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False
