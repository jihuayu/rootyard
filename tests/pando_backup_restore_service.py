#!/usr/bin/env python3
"""AC2 Pando offline archive / isolated restore service acceptance.

The source is a real prebuilt Rootyard service on an owned PostgreSQL 17
fixture, real Garage and real Vault Transit.  It provisions a normal Pando
repository, pins the serving closure, stops every writer, takes a format-23
Pando-only offline archive through the shipped CLI, and restores it into a
second fresh owned PG17 database/data directory.  The restored Pando authority,
closure, pins, Git reads/writes and owner/read-only/revoked tokens are checked
without manufacturing SQL authority state.

One pass-through proxy is started before the first source migration/attestation
and the same endpoint identity is used for source probes, backup/verify, restore,
readback and the fresh pin.  The proxy is armed only for one known Pando object
GET during the selected failed export.  The failed archive must leave a
documented partial, never publish COMPLETE, and leave source state unchanged; a
fresh-path retry must verify and restore successfully.  The offline backup path
has no attestation gate and no pre-GET refusal is claimed.  All process output
stays in RAM or is discarded.  Provider/DB/token values never enter argv,
reports or exceptions.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import native_build_receipt as receipts  # noqa: E402
import pando_pitr_service as binding  # noqa: E402
import pando_pitr_physical_service as ac1  # noqa: E402
from pando_pitr_physical_pg import PhysicalPitrFixture  # noqa: E402

AC2_MANDATORY_CASES = (
    "archive_format_23_pando_only_and_backup_verify_passed",
    "restore_authority_rotated_once_and_restore_generation_incremented_once",
    "old_authority_claim_not_reused_and_new_closure_readable",
    "source_and_restored_permissions_preserved",
    "active_pin_reissued_under_new_authority_and_closure_remains_readable",
    "single_export_failure_not_published_then_fresh_path_retry_passed",
    "all_owned_resources_cleaned",
)
AC2_TOPOLOGY = {
    "rootyard": "actual prebuilt Rootyard service and stock Git over loopback HTTP",
    "source_pg": "owned PG17 primary fixture with real Pando serving-pack closure",
    "target_pg": "second fresh owned PG17 primary fixture used only as an empty isolated restore database",
    "object_store": "real owned Garage fixture via supplied ROOTYARD_OBJECT_STORE_* environment",
    "vault": "real Vault Transit fixture via supplied ROOTYARD_KMS_VAULT_* environment",
    "archive": "shipped offline format-23 Pando-only archive, backup-verify and isolated restore",
    "scope": "AC2 Pando archive/restore authority, closure, pin, auth and one bounded export-failure slice only",
}
AC2_LIMITATIONS = (
    "Requires an actual source/config-bound prebuilt Rootyard binary and Root-supplied real Garage/Vault fixtures.",
    "Format 23 Pando-only archives are exercised; format-24 paired Blob/RefStore, #169 durability, RPO/RTO and cross-provider migration are out of scope.",
    "The failed export gate is a single bounded proxy failure for one known Pando object GET, not a fault matrix; the offline backup path has no pre-GET attestation gate and no such refusal is claimed.",
    "Reports contain only fixed booleans/counts/hashes; SQL bodies, locators, credentials, object bytes and raw process output are excluded.",
    "A successful run is AC2 source execution evidence only; Issue #77 remains open until all required actual regressions and original AC evidence pass.",
)
AC2_SPEC = binding.AcceptanceSpec(
    kind="rootyard/pando-backup-restore-service-acceptance",
    mandatory_cases=AC2_MANDATORY_CASES,
    topology=AC2_TOPOLOGY,
    limitations=AC2_LIMITATIONS,
)
HARNESS_FILES = tuple(dict.fromkeys((
    *ac1.HARNESS_FILES,
    ROOT / "tests/pando_backup_restore_service.py",
    ROOT / "tests/test_pando_backup_restore_service.py",
)))
MAX_GATE_FAILURES = 64
DEFAULT_TIMEOUT_SECONDS = 1800.0


def _endpoint_hash(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()


def _same_provider_endpoint(environments: list[dict[str, str]]) -> bool:
    values = [env.get("ROOTYARD_OBJECT_STORE_ENDPOINT") for env in environments]
    return bool(values) and all(isinstance(value, str) and value for value in values) and len(set(values)) == 1


def _git_try(args: list[str], *, env: dict[str, str], cwd: Path | None = None,
             timeout: float = 120.0) -> int:
    try:
        result = subprocess.run(
            ["git", *args], env=env, cwd=cwd, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ac1.PhysicalFailure("permissions", "git_probe_failed") from None
    return result.returncode


def _pando_refs(db_url: str, repo_id: str) -> list[dict]:
    value = ac1._sql_json(
        db_url,
        "SELECT coalesce(json_agg(t), '[]'::json) FROM ("
        "SELECT ref_name,oid FROM pando_refs WHERE repository_id='"
        + repo_id + "' ORDER BY ref_name) t",
        30,
    )
    return value if isinstance(value, list) else []


def _head_ref(db_url: str, repo_id: str) -> str:
    return ac1._sql_scalar(
        db_url,
        f"SELECT head_ref FROM pando_repository_states WHERE repository_id='{repo_id}'",
        30,
    )


def _authority_row(db_url: str) -> dict:
    value = ac1._sql_json(
        db_url,
        "SELECT row_to_json(t) FROM (SELECT authority_id::text, generation, "
        "restore_generation, authority_epoch, remote_delete_fenced, "
        "remote_delete_fence_reason FROM pando_storage_authorities WHERE singleton) t",
        30,
    )
    if not isinstance(value, dict):
        raise ac1.PhysicalFailure("authority", "row_invalid")
    return value


def _source_state(db_url: str, authority: str, repo_id: str) -> dict:
    artifacts = ac1._sql_json(
        db_url,
        "SELECT coalesce(json_agg(t), '[]'::json) FROM (SELECT namespace, sha256, "
        "state, object_generation, remote_path FROM pando_remote_artifacts "
        f"WHERE authority_id='{authority}' ORDER BY namespace, sha256) t",
        30,
    )
    roots = ac1._sql_json(
        db_url,
        "SELECT coalesce(json_agg(t), '[]'::json) FROM (SELECT id, state, "
        "restore_generation, external_lsn FROM pando_retention_roots "
        f"WHERE authority_id='{authority}' ORDER BY id) t",
        30,
    )
    return {
        "authority": _authority_row(db_url),
        "refs": _pando_refs(db_url, repo_id),
        "head_ref": _head_ref(db_url, repo_id),
        "pack_ids": ac1._sql_scalar(
            db_url,
            f"SELECT array_to_string(pack_ids, ',') FROM pando_repository_states WHERE repository_id='{repo_id}'",
            30,
        ),
        "artifacts": artifacts if isinstance(artifacts, list) else [],
        "roots": roots if isinstance(roots, list) else [],
    }


def _artifact_sets(probe: ac1._ArtifactProbe, rows: dict) -> tuple[list[dict], set[tuple[str, str]]]:
    captured = (
        ac1._probe_artifacts(probe, rows.get("live", []), "live")
        + ac1._probe_artifacts(probe, rows.get("pinned", []), "pinned")
    )
    return captured, {(item["content_sha256"], item["byte_sha256"]) for item in captured}


def _run_backup_gate(binary: str, env: dict[str, str], destination: Path,
                     proxy) -> tuple[int, bool]:
    try:
        process = subprocess.Popen(
            [binary, "backup", str(destination), "--offline"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise ac1.PhysicalFailure("backup_failure", "spawn_failed") from None
    try:
        try:
            proxy.wait_for_gets(1, timeout=90)
        except RuntimeError:
            raise ac1.PhysicalFailure("backup_failure", "gate_timeout") from None
        proxy.release_gated()
        try:
            process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            _kill_group(process)
            raise ac1.PhysicalFailure("backup_failure", "timeout") from None
        return process.returncode, True
    except Exception:
        _kill_group(process)
        raise


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def _release_failure_gate(proxy) -> None:
    proxy.disarm()
    proxy.release_gated()
    with proxy.get_condition:
        proxy.fail_gets_remaining = 0
        proxy.gate_next_get = False


def _partials(parent: Path) -> list[Path]:
    return sorted(
        path for path in parent.iterdir()
        if path.is_dir() and path.name.startswith(".rootyard-backup-")
        and path.name.endswith(".partial")
    )


def _source_archive_facts(archive: Path) -> dict:
    try:
        manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ac1.PhysicalFailure("archive", "manifest_invalid") from None
    if not isinstance(manifest, dict):
        raise ac1.PhysicalFailure("archive", "manifest_invalid")
    return {
        "format": manifest.get("format"),
        "pando_only": manifest.get("blob_closure") is None,
        "complete": (archive / "COMPLETE").is_file(),
        "schema_versions": manifest.get("schema_versions"),
    }


def _permission_checks(binary: str, service, remote: str, token_owner: str,
                       token_reader: str, token_revoked: str, base_env: dict[str, str],
                       root: Path) -> dict:
    owner_read = False
    reader_read = False
    reader_write_denied = False
    revoked_denied = False
    owner_clone = root / "owner-clone"
    reader_clone = root / "reader-clone"
    try:
        ac1._git_clone(remote, token_owner, base_env, owner_clone)
        ac1._git(["fsck", "--full", "--strict"], env=ac1._git_clean_env(base_env), cwd=owner_clone)
        owner_read = True
        ac1._git_clone(remote, token_reader, base_env, reader_clone)
        ac1._git(["fsck", "--full", "--strict"], env=ac1._git_clean_env(base_env), cwd=reader_clone)
        reader_read = True
        (reader_clone / "reader-denied.txt").write_text("reader must not write\n")
        ac1._git(["add", "reader-denied.txt"], env=ac1._git_clean_env(base_env), cwd=reader_clone)
        ac1._git(["commit", "-m", "reader denied"], env=ac1._git_clean_env(base_env), cwd=reader_clone)
        reader_write_denied = _git_try(
            ["push", "origin", "HEAD:refs/heads/reader-denied"],
            env=ac1._git_env(base_env, remote, token_reader), cwd=reader_clone,
        ) != 0
        revoked_denied = _git_try(
            ["ls-remote", "origin"],
            env=ac1._git_env(base_env, remote, token_revoked), cwd=owner_clone,
        ) != 0
    except ac1.PhysicalFailure:
        raise
    return {
        "owner_read": owner_read,
        "reader_read": reader_read,
        "reader_write_denied": reader_write_denied,
        "revoked_denied": revoked_denied,
    }


def _run_ac2_scenario(binary: str, pg_bin: Path, environ: dict[str, str],
                      extra: dict) -> dict[str, bool]:
    cases = {name: False for name in AC2_MANDATORY_CASES}
    extra.update({"ac2_cases": list(AC2_MANDATORY_CASES), "remaining_ac2": "run all existing affected regressions and original AC evidence"})
    private_root = None
    source_fixture = None
    target_fixture = None
    source_service = None
    restored_service = None
    proxy = None
    source_cleanup = None
    target_cleanup = None
    try:
        config, provider_meta = ac1.preflight_providers(environ)
        extra["providers"] = provider_meta
        for tool in ("psql", "git"):
            if not shutil.which(tool):
                raise ac1.PhysicalFailure("precondition", "required_cli_missing")
        proxy = ac1.CountingProxy(*ac1._s3_endpoint(config.endpoint)[:2])
        proxy.start()
        proxy_endpoint = f"http://127.0.0.1:{proxy.port}"
        provider_config = replace(config, endpoint=proxy_endpoint)
        private_root = Path(tempfile.mkdtemp(prefix="rootyard-ac2-backup-restore-"))
        private_root.chmod(0o700)
        source_data = private_root / "source-data"
        source_data.mkdir(mode=0o700)
        restore_data = private_root / "restored-data"
        source_work = private_root / "source-work"
        source_fixture = PhysicalPitrFixture(pg_bin, scratch_parent=private_root / "pg-source")
        target_fixture = PhysicalPitrFixture(pg_bin, scratch_parent=private_root / "pg-target")
        source_fixture.start_primary()
        target_fixture.start_primary()

        source_env = dict(environ)
        source_env.update({
            "ROOTYARD_OBJECT_STORE_ENDPOINT": proxy_endpoint,
            "DATABASE_URL": source_fixture.primary_url,
            "ROOTYARD_DATA_DIR": str(source_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "false",
            "ROOTYARD_STORAGE_MAINTENANCE": "false",
            "ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS": "1",
            "ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS": "1",
            "ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS": "5",
            "ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS": "1",
            "ROOTYARD_OUTBOX_WORKER": "false",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        })
        git_base = ac1._git_clean_env(source_env)
        ac1._cli(binary, ["migrate"], source_env, json_output=False)
        alice = ac1._cli(binary, ["create-user", "alice"], source_env)
        owner_token = alice.get("token")
        reader = ac1._cli(binary, ["create-token", "alice", "--read-only"], source_env)
        revoked = ac1._cli(binary, ["create-token", "alice"], source_env)
        reader_token = reader.get("token")
        revoked_token = revoked.get("token")
        revoked_id = revoked.get("token_id")
        if not all(isinstance(value, str) and value for value in (
            owner_token, reader_token, revoked_token, revoked_id
        )):
            raise ac1.PhysicalFailure("permissions", "token_missing")
        ac1._cli(binary, ["revoke-token", revoked_id], source_env, json_output=False)

        source_service = ac1._Service(binary, source_env)
        source_service.start()
        code, repo = source_service.http_json(
            "/api/repos", owner_token, method="POST", payload={"name": "ac2-backup"})
        if code not in (200, 201, 202) or not isinstance(repo.get("id"), str):
            raise ac1.PhysicalFailure("provision", "repository_create_failed")
        repo_id = repo["id"]
        ac1._wait_until(
            lambda: ac1._sql_scalar(
                source_fixture.primary_url,
                f"SELECT state FROM repositories WHERE id='{repo_id}'", 30) == "ready",
            60.0, "provision", "repository_not_ready")
        ac1._git(["init", "--initial-branch=main", str(source_work)], env=git_base)
        ac1._git(["config", "user.name", "AC2 Service"], env=git_base, cwd=source_work)
        ac1._git(["config", "user.email", "ac2@example.invalid"], env=git_base, cwd=source_work)
        source_remote = source_service.base_url + repo["clone_path"]
        (source_work / "base.txt").write_text("ac2 backup/restore base\n")
        ac1._git(["add", "base.txt"], env=git_base, cwd=source_work)
        ac1._git(["commit", "-m", "base"], env=git_base, cwd=source_work)
        ac1._git(["push", "origin", "HEAD:refs/heads/main"], env=ac1._git_env(git_base, source_remote, owner_token), cwd=source_work)
        source_service.stop()
        cutover = ac1._cli(binary, ["pando-transition", "cutover", "--repository", repo_id], source_env)
        if cutover.get("direction") != "gitfs_to_pando":
            raise ac1.PhysicalFailure("cutover", "direction_mismatch")
        ac1._wait_until(
            lambda: ac1._sql_scalar(
                source_fixture.primary_url,
                f"SELECT storage_backend || '/' || transition_state FROM repositories WHERE id='{repo_id}'",
                30) == "pando/stable",
            60.0, "cutover", "backend_not_stable")
        source_service = ac1._Service(binary, {**source_env, "ROOTYARD_STORAGE_MAINTENANCE": "false"})
        source_service.start()
        source_remote = source_service.base_url + repo["clone_path"]
        for index in (1, 2, 3):
            (source_work / f"pando-{index}.txt").write_text(f"ac2 pando {index}\n")
            ac1._git(["add", f"pando-{index}.txt"], env=git_base, cwd=source_work)
            ac1._git(["commit", "-m", f"pando {index}"], env=git_base, cwd=source_work)
            ac1._git(["push", "origin", "HEAD:refs/heads/main"],
                     env=ac1._git_env(git_base, source_remote, owner_token), cwd=source_work)
        ac1._wait_until(
            lambda: ac1._sql_int(
                source_fixture.primary_url,
                f"SELECT cardinality(pack_ids) FROM pando_repository_states WHERE repository_id='{repo_id}'",
                30) >= 1,
            60.0, "pando", "pack_closure_missing")
        if ac1._sql_int(
            source_fixture.primary_url,
            "SELECT count(*) FROM ref_store_serving_repositories", 30) != 0:
            raise ac1.PhysicalFailure("format", "refstore_serving_present")

        owner_id = ac1._sql_scalar(
            source_fixture.primary_url,
            f"SELECT owner_id::text FROM repositories WHERE id='{repo_id}'", 30)
        authority = ac1._sql_scalar(
            source_fixture.primary_url,
            "SELECT authority_id::text FROM pando_storage_authorities WHERE singleton", 30)
        source_permissions = _permission_checks(
            binary, source_service, source_remote, owner_token, reader_token,
            revoked_token, git_base, private_root / "source-auth")
        source_permissions["owner_write"] = True  # the real Pando pushes above succeeded
        source_authority_before = _authority_row(source_fixture.primary_url)
        source_refs_before = _pando_refs(source_fixture.primary_url, repo_id)
        source_head_before = _head_ref(source_fixture.primary_url, repo_id)
        pin = ac1._cli(
            binary,
            ["pando-authority", "pin-recovery-point", "--tenant", owner_id,
             "--repository", repo_id, "--kind", "pitr_recovery_point",
             "--note", "ac2-source-closure", "--ttl-seconds", "3600"],
            source_env,
        )
        old_root_id = pin.get("id")
        if not isinstance(old_root_id, str) or not pin.get("external_lsn") or int(pin.get("manifest_count", 0)) < 1:
            raise ac1.PhysicalFailure("pin", "source_pin_missing")
        rows = ac1._artifact_rows(source_fixture.primary_url, authority, owner_id, repo_id)
        source_probe, source_probe_set = _artifact_sets(ac1._ArtifactProbe(provider_config), rows)
        if not source_probe:
            raise ac1.PhysicalFailure("garage", "protected_objects_missing")
        source_status = ac1._cli(binary, ["pando-authority", "status"], source_env)
        source_proof, source_local = ac1._status_backend_identity(source_status)
        if not source_proof or source_proof != source_local:
            raise ac1.PhysicalFailure("identity", "source_backend_identity_mismatch")
        extra["source_pin"] = {"manifest_count": int(pin["manifest_count"]), "external_lsn_present": True}
        extra["source_probe_count"] = len(source_probe)
        extra["source_protected_objects"] = source_probe
        source_service.stop()
        state_before_export = _source_state(source_fixture.primary_url, authority, repo_id)

        archive_parent = private_root / "archives"
        archive_parent.mkdir(mode=0o700)
        failed_archive = archive_parent / "failed-archive"
        live_leaf = rows["live"][0]["remote_path"].rsplit("/", 1)[-1]
        proxy.arm(live_leaf, None)
        proxy.prepare_gate(fail=True)
        with proxy.get_condition:
            proxy.fail_gets_remaining = MAX_GATE_FAILURES
        try:
            failure_returncode, failure_get_hit = _run_backup_gate(
                binary, source_env, failed_archive, proxy)
        finally:
            _release_failure_gate(proxy)
        if failure_returncode == 0:
            raise ac1.PhysicalFailure("backup_failure", "unexpected_success")
        if not failure_get_hit:
            raise ac1.PhysicalFailure("backup_failure", "known_get_not_observed")
        if proxy.armed:
            raise ac1.PhysicalFailure("backup_failure", "gate_not_disarmed")
        if failed_archive.exists():
            raise ac1.PhysicalFailure("backup_failure", "destination_published")
        partials = _partials(archive_parent)
        if not partials or any((path / "COMPLETE").exists() for path in partials):
            raise ac1.PhysicalFailure("backup_failure", "partial_missing_or_complete")
        if proxy.method_counts.get("DELETE", 0) != 0:
            raise ac1.PhysicalFailure("backup_failure", "delete_observed")
        if _source_state(source_fixture.primary_url, authority, repo_id) != state_before_export:
            raise ac1.PhysicalFailure("backup_failure", "source_mutated")
        extra["export_failure"] = {
            "returncode_nonzero": True,
            "known_target_get_observed": failure_get_hit,
            "failure_mode": "known_object_get_502",
            "fault_armed_only_for_selected_failed_export": True,
            "gate_disarmed_after_failure": True,
            "partial_count": len(partials),
            "complete_published": False,
            "delete_method_count": proxy.method_counts.get("DELETE", 0),
            "source_state_unchanged": True,
        }

        archive = archive_parent / "archive-ok"
        backup_result = ac1._cli(binary, ["backup", str(archive), "--offline"], source_env, timeout=600)
        if backup_result.get("format") != 23 or backup_result.get("complete") is not True or backup_result.get("blob_artifacts", 0) != 0:
            raise ac1.PhysicalFailure("archive", "format23_not_selected")
        verified = ac1._cli(binary, ["backup-verify", str(archive)], source_env, timeout=300)
        if verified.get("checksums_verified") is not True:
            raise ac1.PhysicalFailure("archive", "verify_failed")
        archive_facts = _source_archive_facts(archive)
        if archive_facts.get("format") != 23 or archive_facts.get("pando_only") is not True or archive_facts.get("complete") is not True:
            raise ac1.PhysicalFailure("archive", "manifest_not_pando_only")
        if _source_state(source_fixture.primary_url, authority, repo_id) != state_before_export:
            raise ac1.PhysicalFailure("archive", "source_mutated_by_backup")
        cases["archive_format_23_pando_only_and_backup_verify_passed"] = True
        cases["single_export_failure_not_published_then_fresh_path_retry_passed"] = True
        extra["archive"] = {
            "format": archive_facts["format"],
            "pando_only": archive_facts["pando_only"],
            "backup_verify_passed": True,
            "partials_retained_until_cleanup": len(partials),
            "source_state_unchanged": True,
        }

        restore_env = {
            **source_env,
            "DATABASE_URL": target_fixture.primary_url,
            "ROOTYARD_DATA_DIR": str(restore_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "false",
            "ROOTYARD_STORAGE_MAINTENANCE": "false",
        }
        if provider_config.endpoint != proxy_endpoint or not _same_provider_endpoint([source_env, restore_env]):
            raise ac1.PhysicalFailure("identity", "provider_endpoint_changed")
        restored = ac1._cli(binary, ["restore", str(archive), "--isolated", "--trust-backup"], restore_env, timeout=600)
        if restored.get("restored") is not True or restored.get("started_service") is not False:
            raise ac1.PhysicalFailure("restore", "restore_summary_invalid")
        target_authority = _authority_row(target_fixture.primary_url)
        old_authority = source_authority_before["authority_id"]
        new_authority = target_authority["authority_id"]
        old_artifacts = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_remote_artifacts WHERE authority_id='{old_authority}'", 30)
        old_manifests = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_manifest_artifacts WHERE authority_id='{old_authority}'", 30)
        old_roots = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_retention_roots WHERE authority_id='{old_authority}'", 30)
        old_root_live = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_retention_roots WHERE id='{old_root_id}'", 30)
        new_artifacts = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_remote_artifacts WHERE authority_id='{new_authority}'", 30)
        new_manifests = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_manifest_artifacts WHERE authority_id='{new_authority}'", 30)
        if not (
            new_authority != old_authority
            and target_authority["generation"] == 1
            and target_authority["restore_generation"] == source_authority_before["restore_generation"] + 1
            and target_authority["authority_epoch"] == 1
            and target_authority["remote_delete_fenced"] is False
        ):
            raise ac1.PhysicalFailure("restore", "authority_rotation_invalid")
        if old_artifacts or old_manifests or old_roots or old_root_live:
            raise ac1.PhysicalFailure("restore", "old_authority_rows_present")
        if new_artifacts < 1 or new_manifests < 1:
            raise ac1.PhysicalFailure("restore", "new_closure_missing")
        target_refs = _pando_refs(target_fixture.primary_url, repo_id)
        target_head = _head_ref(target_fixture.primary_url, repo_id)
        if target_refs != source_refs_before or target_head != source_head_before:
            raise ac1.PhysicalFailure("restore", "refs_head_mismatch")
        cases["restore_authority_rotated_once_and_restore_generation_incremented_once"] = True
        old_claims_absent = True
        extra["authority"] = {
            "authority_rotated": True,
            "generation_reset": 1,
            "restore_generation_incremented_once": True,
            "fresh_epoch": 1,
            "fenced": False,
            "old_authority_artifact_rows_absent": old_artifacts == 0,
            "old_authority_manifest_rows_absent": old_manifests == 0,
            "old_authority_retention_rows_absent": old_roots == 0,
            "old_pin_root_not_live": old_root_live == 0,
            "new_authority_artifact_rows": new_artifacts,
            "new_authority_manifest_rows": new_manifests,
            "refs_and_head_identical": True,
        }

        restored_service = ac1._Service(binary, restore_env)
        restored_service.start()
        restored_remote = restored_service.base_url + repo["clone_path"]
        restored_permissions = _permission_checks(
            binary, restored_service, restored_remote, owner_token, reader_token,
            revoked_token, ac1._git_clean_env(restore_env), private_root / "restored-auth")
        restored_owner_clone = private_root / "restored-auth" / "owner-clone"
        owner_write = False
        try:
            (restored_owner_clone / "restored-write.txt").write_text("supported restored write\n")
            ac1._git(["add", "restored-write.txt"], env=ac1._git_clean_env(restore_env), cwd=restored_owner_clone)
            ac1._git(["commit", "-m", "restored write"], env=ac1._git_clean_env(restore_env), cwd=restored_owner_clone)
            ac1._git(["push", "origin", "HEAD:refs/heads/main"],
                     env=ac1._git_env(ac1._git_clean_env(restore_env), restored_remote, owner_token),
                     cwd=restored_owner_clone)
            owner_write = True
        except ac1.PhysicalFailure:
            owner_write = False
        restored_permissions["owner_write"] = owner_write
        source_permissions_ok = all(source_permissions.values())
        restored_permissions_ok = all(restored_permissions.values())
        if not (source_permissions_ok and restored_permissions_ok):
            raise ac1.PhysicalFailure("permissions", "owner_reader_revoked_mismatch")
        cases["source_and_restored_permissions_preserved"] = True
        extra["permissions"] = {"source": source_permissions, "restored": restored_permissions}

        new_pin = ac1._cli(
            binary,
            ["pando-authority", "pin-recovery-point", "--tenant", owner_id,
             "--repository", repo_id, "--kind", "pitr_recovery_point",
             "--note", "ac2-restored-closure", "--ttl-seconds", "3600"],
            restore_env,
        )
        new_root_id = new_pin.get("id")
        if not isinstance(new_root_id, str) or new_root_id == old_root_id:
            raise ac1.PhysicalFailure("pin", "restored_pin_missing")
        if not new_pin.get("external_lsn") or int(new_pin.get("manifest_count", 0)) < 1:
            raise ac1.PhysicalFailure("pin", "restored_pin_empty")
        new_root_live = ac1._sql_int(
            target_fixture.primary_url,
            f"SELECT count(*) FROM pando_retention_roots WHERE id='{new_root_id}' AND state='active'", 30)
        if new_root_live != 1:
            raise ac1.PhysicalFailure("pin", "restored_pin_not_active")
        target_status = ac1._cli(binary, ["pando-authority", "status"], restore_env)
        target_proof, target_local = ac1._status_backend_identity(target_status)
        if not target_proof or target_proof != target_local or target_proof != source_proof:
            raise ac1.PhysicalFailure("identity", "restored_backend_identity_mismatch")
        extra["endpoint_identity"] = {
            "single_pass_through_proxy_before_source": True,
            "source_and_restore_env_identical": _same_provider_endpoint([source_env, restore_env]),
            "normal_failed_retry_verify_restore_new_pin_same": True,
            "source_proof_matches_local": True,
            "restored_proof_matches_source": True,
            "backend_identity_sha256": ac1._identity_hash(source_proof),
            "proxy_endpoint_sha256": _endpoint_hash(proxy_endpoint),
            "fault_armed_only_for_selected_failed_export": True,
            "offline_backup_pre_get_attestation_gate": False,
        }
        target_rows = ac1._artifact_rows(
            target_fixture.primary_url, new_authority, owner_id, repo_id)
        target_probe, target_probe_set = _artifact_sets(ac1._ArtifactProbe(provider_config), target_rows)
        if not target_probe or not source_probe_set.issubset(target_probe_set):
            raise ac1.PhysicalFailure("garage", "restored_closure_not_readable")
        cases["old_authority_claim_not_reused_and_new_closure_readable"] = old_claims_absent
        cases["active_pin_reissued_under_new_authority_and_closure_remains_readable"] = True
        extra["restored_pin"] = {
            "new_root_active": True,
            "old_root_absent": old_root_live == 0,
            "manifest_count": int(new_pin["manifest_count"]),
            "closure_probe_count": len(target_probe),
            "source_probe_covered": source_probe_set.issubset(target_probe_set),
        }
        extra["restored_protected_objects"] = target_probe
    except ac1.PhysicalFailure as error:
        extra["physical_failure"] = {"stage": error.stage, "code": error.code}
    except Exception as error:
        extra["physical_failure"] = {
            "stage": "internal", "code": "unexpected", "exception_class": type(error).__name__}
    finally:
        services_stopped = True
        for service in (restored_service, source_service):
            if service is not None:
                try:
                    service.stop()
                except Exception:
                    services_stopped = False
        proxy_stopped = True
        final_delete_count = proxy.method_counts.get("DELETE", 0) if proxy is not None else 0
        extra["delete_method_count_before_cleanup"] = final_delete_count
        if final_delete_count != 0 and "physical_failure" not in extra:
            extra["physical_failure"] = {"stage": "provider", "code": "delete_observed"}
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:
                proxy_stopped = False
        for fixture, label in ((target_fixture, "target"), (source_fixture, "source")):
            if fixture is not None:
                try:
                    cleanup = fixture.cleanup()
                except Exception:
                    cleanup = {"passed": False}
                if label == "target":
                    target_cleanup = cleanup
                else:
                    source_cleanup = cleanup
        fixtures_ok = all(
            isinstance(status, dict) and status.get("passed") is True
            for status in (source_cleanup, target_cleanup)
        )
        if services_stopped and proxy_stopped and fixtures_ok and private_root is not None:
            try:
                shutil.rmtree(private_root)
                private_root = None
            except OSError:
                pass
        cleanup_ok = bool(
            services_stopped and proxy_stopped and fixtures_ok
            and private_root is None
        )
        cases["all_owned_resources_cleaned"] = cleanup_ok
        extra["cleanup"] = {
            "services_stopped": services_stopped,
            "proxy_stopped": proxy_stopped,
            "source_fixture": source_cleanup,
            "target_fixture": target_cleanup,
            "private_scratch_removed": private_root is None,
        }
        if not cleanup_ok and "physical_failure" not in extra:
            extra["physical_failure"] = {"stage": "cleanup", "code": "owned_resource_cleanup_failed"}
        cases["passed"] = (
            "physical_failure" not in extra
            and all(cases[name] for name in AC2_MANDATORY_CASES)
        )
    return cases


def run_ac2_suite(binary: str, pg_bin: Path, environ: dict[str, str] | None = None) -> tuple[dict[str, bool], dict]:
    extra: dict = {}
    cases = _run_ac2_scenario(binary, pg_bin, os.environ if environ is None else environ, extra)
    return cases, extra


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--build-receipt", required=True)
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--pg-bin", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    extra: dict = {}
    try:
        extra["source_tree"] = receipts.git_state(ROOT).get("tree")
    except Exception:
        extra["source_tree"] = None

    def suite(binary: str) -> dict:
        return _run_ac2_scenario(binary, args.pg_bin, os.environ, extra)

    try:
        report = binding.run_acceptance(
            binary=args.binary,
            build_receipt=args.build_receipt,
            expect_commit=args.expect_commit,
            report_path=args.report,
            timeout=args.timeout,
            harness_files=list(HARNESS_FILES),
            suite=suite,
            spec=AC2_SPEC,
            extra_report=extra,
        )
    except OSError:
        print("Pando backup/restore service acceptance: report write failed", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"Pando backup/restore service acceptance: failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print(json.dumps({
        "kind": report.get("kind"),
        "passed": report.get("passed"),
        "failure": report.get("failure"),
        "cases": report.get("cases"),
        "physical_failure": report.get("physical_failure"),
        "cleanup": report.get("cleanup"),
    }, sort_keys=True))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
