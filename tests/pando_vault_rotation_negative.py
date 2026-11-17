#!/usr/bin/env python3
"""Negative and cleanup cases for the issue #21 Vault rotation harness.

Every mutated byte/row is restored in a ``finally`` block before the next
probe.  Each cold negative probe evicts the exact owned plaintext pack/idx
cache and asserts it remains absent after the failure, so provider failure is
never inferred from a warm cache.  The application token revocation is last;
cleanup is exact-owned, bounded and makes an unresolved resource fail overall.
"""
from __future__ import annotations

from pathlib import Path
import stat

from pando_vault_rotation_fixture import FixtureError
from pando_vault_rotation_mirror import read_complete_mirror
from pando_vault_rotation_support import (
    CASES,
    QualificationError,
    cache_absent,
    local_authority_absent,
    require,
    sha256_bytes,
    sha256_file,
)


def _cas_snapshot(ctx):
    result = {}
    for pack in ctx.pack_ids:
        cipher = ctx.cipher(pack)
        result[pack] = {
            "ciphertext_sha256": sha256_bytes(cipher),
            "ciphertext_bytes": len(cipher),
        }
    return result


def _db_snapshot(ctx):
    return {
        pack: {
            "key_version": ctx.envelope(pack)["key_version"],
            "envelope_mac": ctx.envelope(pack)["envelope_mac"],
            "ciphertext_sha256": ctx.envelope(pack)["ciphertext_sha256"],
        }
        for pack in ctx.pack_ids
    }


def _require_cas_unchanged(ctx, before):
    for pack, saved in before.items():
        cipher = ctx.cipher(pack)
        require(sha256_bytes(cipher) == saved["ciphertext_sha256"]
                and len(cipher) == saved["ciphertext_bytes"],
                "cas_ciphertext_changed", "fail_closed")
    return True


def _require_db_unchanged(ctx, before):
    for pack, saved in before.items():
        envelope = ctx.envelope(pack)
        require(envelope["key_version"] == saved["key_version"]
                and envelope["envelope_mac"] == saved["envelope_mac"]
                and envelope["ciphertext_sha256"] == saved["ciphertext_sha256"],
                "db_envelope_authority_changed", "fail_closed")
    return True


def _negative_verify(ctx, env, stage):
    ctx.evict()
    result = ctx.run_status(["kms-verify", ctx.repo], env=env, stage=stage)
    require(result.returncode != 0, stage + "_unexpected_success", stage)
    require(cache_absent(ctx.root.path, ctx.repo, ctx.pack_ids),
            stage + "_created_plaintext_cache", stage)
    require(local_authority_absent(ctx.root.path, ctx.repo),
            stage + "_created_local_authority", stage)
    return True


def _negative_get(ctx, pack, env, stage):
    ctx.evict([pack])
    result = ctx.run_status(["object-store-get", ctx.repo, pack], env=env, stage=stage)
    require(result.returncode != 0, stage + "_unexpected_success", stage)
    require(cache_absent(ctx.root.path, ctx.repo, [pack]),
            stage + "_created_plaintext_cache", stage)
    require(local_authority_absent(ctx.root.path, ctx.repo),
            stage + "_created_local_authority", stage)
    return True


def _alternate_hex(value):
    return "0" * 64 if value != "0" * 64 else "1" * 64


def probe_db_envelope_field_tamper(ctx, pack, field, stage, canonical=None):
    """Tamper one DB envelope field, prove both cold consumers fail, restore.

    The complete healthy mirror must match the original DB/manifest record
    before mutation.  ``envelope_mac`` and ``ciphertext_sha256`` are changed in
    separate probes so a MAC-only failure cannot be explained by a digest
    mismatch.  The exact DB row is restored in ``finally`` even when a probe
    raises.
    """
    require(field in ("envelope_mac", "ciphertext_sha256"),
            "db_tamper_field_invalid", stage)
    envelope = ctx.envelope(pack)
    original_mac = envelope.get("envelope_mac")
    original_cipher_sha = envelope.get("ciphertext_sha256")
    for value in (original_mac, original_cipher_sha):
        require(isinstance(value, str) and len(value) == 64
                and all(char in "0123456789abcdef" for char in value),
                "db_envelope_original_invalid", stage)
    _path, before_mirror, _record = read_complete_mirror(
        ctx, pack, canonical, db=envelope, stage=stage)
    before_cipher = ctx.cipher(pack)
    alternate = _alternate_hex(envelope[field])
    require(alternate != envelope[field], "db_tamper_value_unchanged", stage)
    mac = alternate if field == "envelope_mac" else original_mac
    cipher_sha = alternate if field == "ciphertext_sha256" else original_cipher_sha
    try:
        ctx.psql.set_envelope_auth(ctx.repo, pack, mac, cipher_sha)
        tampered = ctx.envelope(pack)
        require(tampered.get("envelope_mac") == mac
                and tampered.get("ciphertext_sha256") == cipher_sha,
                "db_envelope_tamper_not_applied", stage)
        if field == "envelope_mac":
            require(tampered.get("ciphertext_sha256") == original_cipher_sha,
                    "db_mac_tamper_changed_digest", stage)
        else:
            require(tampered.get("envelope_mac") == original_mac,
                    "db_digest_tamper_changed_mac", stage)
        read_complete_mirror(ctx, pack, canonical, db=envelope, stage=stage)
        _negative_verify(ctx, ctx.environment, stage + "_verify")
        _negative_get(ctx, pack, ctx.environment, stage + "_get")
        after_cipher = ctx.cipher(pack)
        require(sha256_bytes(after_cipher) == sha256_bytes(before_cipher)
                and len(after_cipher) == len(before_cipher),
                "db_tamper_changed_ciphertext", stage)
        _after_path, after_mirror, _after_record = read_complete_mirror(
            ctx, pack, canonical, db=envelope, stage=stage)
        require(after_mirror == before_mirror,
                "db_tamper_changed_healthy_mirror", stage)
        require(cache_absent(ctx.root.path, ctx.repo, [pack]),
                stage + "_created_plaintext_cache", stage)
        require(local_authority_absent(ctx.root.path, ctx.repo),
                stage + "_created_local_authority", stage)
        return True
    finally:
        ctx.psql.restore_envelope_auth(
            ctx.repo, pack, original_mac, original_cipher_sha)
        restored = ctx.envelope(pack)
        require(restored.get("envelope_mac") == original_mac
                and restored.get("ciphertext_sha256") == original_cipher_sha,
                "db_envelope_restore_failed", stage)


def case_wrong_key_ciphertext_envelope_and_provider_revocation(ctx):
    before_cas = _cas_snapshot(ctx)
    before_db = _db_snapshot(ctx)
    pack = ctx.pack_ids[0]
    canonical_mirror_path, _canonical_mirror_bytes, canonical_mirror = (
        read_complete_mirror(ctx, pack, stage="mirror_baseline"))
    latest = ctx.fixture.key_metadata()["latest_version"]
    require(latest == 3, "negative_baseline_latest_invalid", "fail_closed")
    wrong_metadata = ctx.fixture.create_wrong_key()
    require(wrong_metadata["derived"] is True
            and wrong_metadata["type"] == "aes256-gcm96",
            "wrong_key_not_derived_aes", "wrong_key")
    wrong_scoped = ctx.fixture.probe_scoped_key(ctx.fixture.wrong_key_name)
    require(wrong_scoped["encrypt_decrypt_rewrap"] is True,
            "wrong_key_not_usable", "wrong_key")
    wrong_env = dict(ctx.environment)
    wrong_env.update(ctx.fixture.environment(ctx.fixture.wrong_key_name))
    require(wrong_env["PANDO_KMS_VAULT_KEY"] == ctx.fixture.wrong_key_name,
            "wrong_key_environment_not_selected", "wrong_key")
    ctx.cold_verify()
    _negative_verify(ctx, wrong_env, "wrong_key_verify")
    _negative_get(ctx, ctx.pack_ids[0], wrong_env, "wrong_key_get")
    _require_cas_unchanged(ctx, before_cas)
    _require_db_unchanged(ctx, before_db)
    ctx.evict()
    ctx.cold_verify()
    ctx.cold_get(ctx.pack_ids[0])
    wrong_key_denied = True

    manifest = ctx.manifest(pack)
    cipher_path = (ctx.root.path / manifest["pack_key"]).resolve()
    original = cipher_path.read_bytes()
    mode = stat.S_IMODE(cipher_path.stat().st_mode)
    tampered = bytearray(original)
    tampered[-1] ^= 0x55
    ciphertext_tamper_denied = False
    ciphertext_restored = False
    try:
        cipher_path.chmod(0o600)
        cipher_path.write_bytes(bytes(tampered))
        cipher_path.chmod(mode)
        require(sha256_bytes(bytes(tampered)) != manifest["ciphertext_sha256"],
                "cipher_tamper_did_not_change_digest", "ciphertext_tamper")
        _negative_verify(ctx, ctx.environment, "ciphertext_tamper_verify")
        _negative_get(ctx, pack, ctx.environment, "ciphertext_tamper_get")
        _require_db_unchanged(ctx, before_db)
        ciphertext_tamper_denied = True
    finally:
        cipher_path.write_bytes(original)
        cipher_path.chmod(mode)
        ciphertext_restored = (sha256_bytes(cipher_path.read_bytes())
                               == manifest["ciphertext_sha256"])
    require(ciphertext_restored, "ciphertext_restore_failed", "ciphertext_tamper")
    ctx.evict([pack])
    ctx.cold_get(pack)
    ctx.cold_verify()

    mac_only_denied = probe_db_envelope_field_tamper(
        ctx, pack, "envelope_mac", "db_envelope_mac_tamper", canonical_mirror)
    ctx.evict([pack])
    ctx.cold_get(pack)
    ctx.cold_verify()
    digest_only_denied = probe_db_envelope_field_tamper(
        ctx, pack, "ciphertext_sha256", "db_envelope_digest_tamper",
        canonical_mirror)
    require(mac_only_denied and digest_only_denied,
            "db_envelope_tamper_not_denied", "db_envelope_tamper")
    ctx.evict([pack])
    ctx.cold_get(pack)
    ctx.cold_verify()

    mirror = canonical_mirror_path
    mirror.chmod(0o600)
    mirror.write_bytes(b'{"schema":"broken","envelope_mac":"' + b"0" * 64 + b'"}\n')
    ctx.evict([pack])
    ctx.cold_get(pack)
    _repair_path, _repaired_bytes, repaired = read_complete_mirror(
        ctx, pack, canonical_mirror, stage="mirror_repair")
    require(repaired == canonical_mirror,
            "mirror_tamper_not_full_repaired_from_db", "mirror_repair")
    mirror_tamper_repaired = True
    mirror.unlink()
    ctx.evict([pack])
    ctx.cold_get(pack)
    require(mirror.is_file(), "missing_mirror_not_recreated", "mirror_repair")
    _repair_path, _repaired_bytes, repaired = read_complete_mirror(
        ctx, pack, canonical_mirror, stage="mirror_repair")
    require(repaired == canonical_mirror,
            "missing_mirror_not_full_repaired_from_db", "mirror_repair")
    mirror_missing_repaired = True
    ctx.cold_verify()

    before_revoke = _cas_snapshot(ctx)
    before_revoke_db = _db_snapshot(ctx)
    ctx.status()
    ctx.fixture.revoke_scoped_token()
    _negative_verify(ctx, ctx.environment, "revoked_token_verify")
    _negative_get(ctx, pack, ctx.environment, "revoked_token_get")
    _require_cas_unchanged(ctx, before_revoke)
    _require_db_unchanged(ctx, before_revoke_db)
    require(ctx.fixture.key_metadata()["latest_version"] == latest,
            "revocation_changed_master_version", "revocation")
    require(local_authority_absent(ctx.root.path, ctx.repo),
            "revocation_created_local_authority", "revocation")
    return {
        "id": CASES[3],
        "status": "passed",
        "facts": {
            "wrong_key_exists": True,
            "wrong_key_scoped": True,
            "wrong_key_denied": wrong_key_denied,
            "ciphertext_tamper_denied": ciphertext_tamper_denied,
            "db_envelope_tamper_denied": bool(mac_only_denied and digest_only_denied),
            "restore_verified": True,
            "mirror_tamper_repaired": mirror_tamper_repaired,
            "mirror_missing_repaired": mirror_missing_repaired,
            "app_revocation_denied": True,
            "cas_unchanged": True,
            "db_unchanged": True,
            "local_authority_absent": True,
            "cache_absent_after_failure": True,
            "provider_latest_version": latest,
            "revocation_last": True,
        },
    }


def case_owned_resource_cleanup(ctx):
    budget = getattr(ctx, "budget", None)
    server_stopped = True
    if ctx.server is not None:
        try:
            server_stopped = ctx.server.stop()
        except (QualificationError, FixtureError, OSError):
            server_stopped = False
        if getattr(ctx.server, "process", None) is not None:
            server_stopped = False
    vault_owned = bool(ctx.fixture is not None
                       and (ctx.fixture.container_id is not None
                            or ctx.fixture.state_written))
    vault_stopped = True
    container_absent = True
    if ctx.fixture is not None:
        try:
            result = ctx.fixture.stop()
            vault_stopped = result in ("stopped", "absent")
            container_absent = not ctx.fixture.state_path.exists()
        except (FixtureError, QualificationError, OSError):
            vault_stopped = False
            container_absent = False
    postgres_owned = bool(ctx.postgres is not None
                          and ctx.postgres.prechecked_absent)
    postgres_dropped = True
    database_absent = True
    if ctx.postgres is not None and ctx.postgres.prechecked_absent:
        try:
            postgres_dropped = ctx.postgres.drop()
        except (FixtureError, QualificationError, OSError):
            postgres_dropped = False
            database_absent = False
    elif ctx.postgres is None:
        postgres_dropped = True
    root_owned = bool(ctx.root is not None and ctx.root.created)
    root_removed = True
    root_absent = True
    live_writer_unresolved = bool(getattr(
        getattr(ctx, "runner", None), "unresolved_children", False))
    safe_to_remove_root = bool(
        server_stopped and vault_stopped and postgres_dropped
        and not live_writer_unresolved)
    if root_owned and safe_to_remove_root:
        try:
            if budget is not None:
                budget.require("cleanup")
            root_removed = ctx.root.remove()
            root_absent = not ctx.root.path.exists()
        except (FixtureError, QualificationError, OSError):
            root_removed = False
            root_absent = False
    elif root_owned:
        root_removed = False
        root_absent = False
    vault_ok = not vault_owned or (vault_stopped and container_absent)
    postgres_ok = not postgres_owned or (postgres_dropped and database_absent)
    root_ok = not root_owned or (root_removed and root_absent)
    cleanup_ok = bool(server_stopped and vault_ok and postgres_ok and root_ok)
    facts = {
        "vault_owned": vault_owned,
        "vault_stopped": vault_stopped,
        "container_absent": container_absent,
        "postgres_owned": postgres_owned,
        "postgres_created": bool(ctx.postgres is not None and ctx.postgres.created),
        "postgres_dropped": postgres_dropped,
        "database_absent": database_absent,
        "root_owned": root_owned,
        "root_removed": root_removed,
        "root_absent": root_absent,
        "server_stopped": server_stopped,
        "cleanup_ok": cleanup_ok,
        "credential_released": vault_stopped if vault_owned else True,
        "pg_major": ctx.postgres.major if ctx.postgres is not None else None,
        "image_digest_sha256": (
            getattr(ctx.fixture, "image", "").rsplit("@sha256:", 1)[-1]
            if ctx.fixture is not None and getattr(ctx.fixture, "image", "")
            else None),
        "vault_version": ctx.fixture.version if ctx.fixture is not None else None,
        "no_global_cleanup": True,
        "raw_logs_persisted": False,
    }
    return {
        "id": CASES[4],
        "status": "passed" if cleanup_ok else "failed",
        "code": None if cleanup_ok else "owned_resource_cleanup_unresolved",
        "facts": facts,
    }
