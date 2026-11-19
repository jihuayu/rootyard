#!/usr/bin/env python3
"""Positive issue #21 cases: fixture boundary, authentic cold read and rotation.

The source cases are authored against the current 2aead command/DB/envelope
semantics and are not executed by the unit-test suite.  They use only the
existing ``rootyard-pando-lab`` CLI, Git pushes over the lab HTTP server, the
database loader and the owned Vault Transit provider.  They never call the
local ``kms-revoke-*`` mutations under Vault and never call app-side master
rotate.
"""
from __future__ import annotations

from pando_vault_rotation_support import (
    CASES,
    QualificationError,
    require,
    sha256_bytes,
    sha256_file,
    valid_uuid,
)

EXISTING_TARGET_CONTRACT = "existing-vault-version/v1"


def _envelope_fact(envelope):
    return {
        "provider": envelope.get("provider_kind"),
        "key_version": envelope.get("key_version"),
        "mac_sha256": sha256_bytes(str(envelope.get("envelope_mac")).encode()),
    }


def record_baseline(ctx):
    """Read exact ciphertext/digest facts for every initial v1 pack."""
    ctx.refresh_packs()
    baseline = {}
    for pack in ctx.pack_ids:
        manifest = ctx.manifest(pack)
        envelope = ctx.envelope(pack)
        cipher = ctx.cipher(pack)
        require(cipher.startswith(b"PANDOENC") and not cipher.startswith(b"PACK"),
                "baseline_pandoenc_prefix_missing", "baseline")
        require(manifest["encryption_mode"] == "authenticated-envelope-v1",
                "baseline_manifest_mode_invalid", "baseline")
        require(envelope.get("provider_kind") == "vault-transit"
                and envelope.get("key_version") == 1,
                "baseline_envelope_not_v1_vault", "baseline")
        require(envelope.get("ciphertext_sha256") == manifest["ciphertext_sha256"]
                and envelope.get("ciphertext_bytes") == manifest["ciphertext_bytes"]
                == len(cipher),
                "baseline_envelope_ciphertext_mismatch", "baseline")
        require(manifest["pack_sha256"] == envelope.get("plaintext_sha256"),
                "baseline_plaintext_digest_mismatch", "baseline")
        require(sha256_bytes(cipher) == manifest["ciphertext_sha256"],
                "baseline_cipher_digest_mismatch", "baseline")
        for marker in ctx.markers:
            require(marker.encode() not in cipher, "baseline_plaintext_marker_present",
                    "baseline")
        baseline[pack] = {
            "ciphertext_sha256": manifest["ciphertext_sha256"],
            "ciphertext_bytes": manifest["ciphertext_bytes"],
            "pack_sha256": manifest["pack_sha256"],
            "idx_sha256": manifest["idx_sha256"],
            "envelope_mac": envelope.get("envelope_mac"),
        }
    ctx.baseline = baseline
    return baseline


def case_fixture_and_app_capability_boundary(ctx):
    metadata = ctx.fixture.key_metadata()
    require(metadata["latest_version"] == 1, "fixture_initial_version_not_one",
            "capability")
    result = ctx.fixture.verify_app_capabilities()
    after = ctx.fixture.key_metadata()
    require(after["latest_version"] == 1, "app_denied_rotate_changed_master",
            "capability")
    require(result["delete_denied"] and result["config_denied"]
            and result["token_admin_denied"] and result["policy_admin_denied"],
            "app_admin_capability_not_denied", "capability")
    return {
        "id": CASES[0],
        "status": "passed",
        "facts": {
            "image_digest_sha256": ctx.fixture.image.rsplit("@sha256:", 1)[-1],
            "vault_version": ctx.fixture.version,
            "key_type": metadata["type"],
            "derived": metadata["derived"],
            "latest_version": metadata["latest_version"],
            "min_decryption_version": metadata["min_decryption_version"],
            "app_wrap_unwrap_rewrap": result["encrypt_decrypt_rewrap"],
            "app_master_rotate_denied": result["rotate_denied"],
            "app_delete_denied": result["delete_denied"],
            "app_config_denied": result["config_denied"],
            "app_token_admin_denied": result["token_admin_denied"],
            "app_policy_admin_denied": result["policy_admin_denied"],
            "latest_unchanged": result["latest_unchanged"],
            "credential_file_written": False,
            "raw_logs_persisted": False,
        },
    }


def case_authentic_envelope_digest_and_cold_read(ctx):
    baseline = record_baseline(ctx)
    for pack in ctx.pack_ids:
        manifest = ctx.manifest(pack)
        cipher = ctx.cipher(pack)
        envelope = ctx.envelope(pack)
        require(manifest["ciphertext_sha256"] == sha256_bytes(cipher),
                "manifest_cipher_digest_mismatch", "authentic_envelope")
        require(manifest["ciphertext_bytes"] == len(cipher),
                "manifest_cipher_length_mismatch", "authentic_envelope")
        require(envelope["ciphertext_sha256"] == manifest["ciphertext_sha256"],
                "envelope_cipher_digest_mismatch", "authentic_envelope")
        require(cipher.startswith(b"PANDOENC") and not cipher.startswith(b"PACK"),
                "pandoenc_prefix_missing", "authentic_envelope")
        for marker in ctx.markers:
            require(marker.encode() not in cipher, "plaintext_marker_present",
                    "authentic_envelope")
        report = ctx.cold_get(pack)
        require(report["pack_sha256"] == manifest["pack_sha256"],
                "cold_get_plaintext_manifest_mismatch", "authentic_envelope")
        verify = ctx.cold_verify()
        require(verify["provider_kind"] == "vault-transit"
                and verify["provider_latest_version"] == 1,
                "cold_verify_provider_identity_mismatch", "authentic_envelope")
    ctx.refresh_packs()
    ctx.evict()
    store = ctx.cli(["object-store-verify", ctx.repo], stage="object_store_verify")
    require(store.get("verified") is True
            and store.get("packs_verified") == len(ctx.pack_ids),
            "object_store_verify_cold_failed", "authentic_envelope")
    clone = ctx.cold_clone("clone-authentic")
    require(ctx.git.show(clone, "HEAD") == ctx.markers[1],
            "http_clone_latest_content_mismatch", "authentic_envelope")
    require(ctx.git.show(clone, "HEAD~1") == ctx.markers[0],
            "http_clone_history_content_mismatch", "authentic_envelope")
    baseline = ctx.baseline
    return {
        "id": CASES[1],
        "status": "passed",
        "facts": {
            "pack_count": len(ctx.pack_ids),
            "ciphertext_sha256": [baseline[p]["ciphertext_sha256"] for p in ctx.pack_ids],
            "ciphertext_bytes": [baseline[p]["ciphertext_bytes"] for p in ctx.pack_ids],
            "plaintext_sha256": [baseline[p]["pack_sha256"] for p in ctx.pack_ids],
            "envelope_key_versions": [1 for _ in ctx.pack_ids],
            "pandoenc_prefix": True,
            "known_plaintext_absent": True,
            "envelope_ciphertext_matches_manifest": True,
            "cold_kms_verify": True,
            "cold_object_store_get": True,
            "cold_http_clone": True,
            "cache_evicted_before_probe": True,
            "plaintext_cache_absent": True,
        },
    }


def _cipher_fact(ctx, pack):
    cipher = ctx.cipher(pack)
    return {
        "ciphertext_sha256": sha256_bytes(cipher),
        "ciphertext_bytes": len(cipher),
    }


def _require_cipher_unchanged(ctx, baseline):
    for pack in ctx.pack_ids:
        cipher = ctx.cipher(pack)
        saved = baseline[pack]
        require(sha256_bytes(cipher) == saved["ciphertext_sha256"]
                and len(cipher) == saved["ciphertext_bytes"],
                "ciphertext_changed_during_rewrap", "rotation")
    return True


def validate_interrupt_checkpoint(checkpoint, expected_targets, report=None):
    """Validate the actual IN_PROGRESS checkpoint against the pre-run pack set.

    The real Vault selector snapshots every current manifest pack into
    ``target_pack_ids``.  With ``--fail-after-packs 1`` exactly one existing
    target is completed and the next remaining target is recorded as failed.
    Foreign/duplicate IDs and report counts that do not match the checkpoint are
    rejected rather than accepting a merely nonempty state.
    """
    stage = "rotation"
    require(isinstance(checkpoint, dict), "rotation_checkpoint_missing", stage)
    targets = checkpoint.get("target_pack_ids")
    completed = checkpoint.get("completed_pack_ids")
    failed = checkpoint.get("failed_pack_id")
    require(isinstance(targets, list) and bool(targets)
            and all(valid_uuid(item) for item in targets),
            "rotation_target_ids_invalid", stage)
    require(len(targets) == len(set(targets)), "rotation_target_duplicate", stage)
    require(set(targets) == set(expected_targets),
            "rotation_target_set_mismatch", stage)
    require(isinstance(completed, list)
            and all(valid_uuid(item) for item in completed),
            "rotation_completed_ids_invalid", stage)
    require(len(completed) == len(set(completed)),
            "rotation_completed_duplicate", stage)
    require(len(completed) == 1, "rotation_completed_count_invalid", stage)
    require(set(completed) <= set(targets), "rotation_completed_foreign", stage)
    require(isinstance(failed, str) and valid_uuid(failed),
            "rotation_failed_id_invalid", stage)
    require(failed in set(targets), "rotation_failed_foreign", stage)
    require(failed not in set(completed), "rotation_failed_completed", stage)
    remaining = set(targets) - set(completed)
    require(failed in remaining, "rotation_failed_not_remaining", stage)
    if report is not None:
        require(isinstance(report, dict), "rotation_report_missing", stage)
        require(report.get("rotation_total_packs") == len(targets),
                "rotation_total_count_inconsistent", stage)
        require(report.get("rotation_completed_packs") == len(completed),
                "rotation_completed_count_inconsistent", stage)
    return {
        "targets": list(targets),
        "completed": list(completed),
        "failed": failed,
        "remaining": sorted(remaining),
    }


def case_admin_rotated_target_interrupted_resume_and_new_write(ctx):
    baseline = dict(ctx.baseline)
    metadata = ctx.fixture.admin_rotate()
    require(metadata["latest_version"] == 2, "admin_rotate_version_not_two",
            "rotation")
    status = ctx.status()
    require(status.get("provider_latest_version") == 2,
            "status_latest_version_not_two", "rotation")
    app_after = ctx.fixture.probe_scoped_key(ctx.fixture.key_name)
    require(app_after["rotate_denied"] and app_after["latest_unchanged"],
            "app_rotate_not_denied_after_admin_rotate", "rotation")
    expected_targets = list(ctx.refresh_packs())
    require(len(expected_targets) >= 2, "initial_pack_count_insufficient", "rotation")
    require(len(expected_targets) == len(set(expected_targets)),
            "initial_pack_duplicate", "rotation")
    interrupt = ctx.run_status(
        ["kms-rotate", ctx.repo, "--target-version", "2", "--fail-after-packs", "1"],
        stage="rotation_interrupt")
    require(interrupt.returncode != 0, "rotation_interrupt_did_not_fail", "rotation")
    mid = ctx.status()
    rotation = mid.get("active_rotation")
    require(isinstance(rotation, dict), "rotation_checkpoint_missing", "rotation")
    require(rotation.get("state") == "IN_PROGRESS", "rotation_not_in_progress",
            "rotation")
    require(rotation.get("to_key_version") == 2
            and rotation.get("expected_to_version") == 2,
            "rotation_target_version_invalid", "rotation")
    require(rotation.get("target_contract") == EXISTING_TARGET_CONTRACT,
            "rotation_contract_invalid", "rotation")
    require((rotation.get("write_epoch") or 0) >= 1, "rotation_write_epoch_missing",
            "rotation")
    require(rotation.get("to_key_id") == rotation.get("from_key_id"),
            "rotation_identity_changed", "rotation")
    require(mid.get("policy") is None, "vault_status_exposed_local_policy", "rotation")
    require(mid.get("provider_latest_version") == 2,
            "midpoint_latest_version_invalid", "rotation")
    oracle = validate_interrupt_checkpoint(rotation, expected_targets, mid)
    completed = oracle["completed"]
    targets = oracle["targets"]
    failed = oracle["failed"]
    completed_pack = completed[0]
    v1_pack = failed
    require(ctx.envelope(completed_pack)["key_version"] == 2,
            "completed_pack_not_rewrapped", "rotation")
    require(ctx.envelope(v1_pack)["key_version"] == 1,
            "midpoint_v1_pack_already_rewrapped", "rotation")
    ctx.cold_get(completed_pack)
    ctx.cold_get(v1_pack)
    ctx.cold_verify()
    metadata = ctx.fixture.admin_rotate()
    require(metadata["latest_version"] == 3, "admin_rotate_version_not_three",
            "rotation")
    app_latest = ctx.fixture.probe_scoped_key(ctx.fixture.key_name)
    require(app_latest["rotate_denied"] and app_latest["latest_unchanged"],
            "app_rotate_not_denied_after_latest_three", "rotation")
    require(ctx.fixture.key_metadata()["latest_version"] == 3,
            "app_changed_administrator_version", "rotation")
    before_write = set(ctx.refresh_packs())
    ctx.commit_and_push(2, "rotation gamma")
    after_write = set(ctx.refresh_packs())
    new_packs = sorted(after_write - before_write)
    require(len(new_packs) == 1, "new_write_pack_count_invalid", "rotation")
    new_pack = new_packs[0]
    new_envelope = ctx.envelope(new_pack)
    require(new_envelope.get("provider_kind") == "vault-transit"
            and new_envelope.get("key_version") == 2,
            "new_write_not_pinned_to_checkpoint", "rotation")
    require(new_envelope.get("key_version") != metadata["latest_version"],
            "new_write_used_latest_instead_of_checkpoint", "rotation")
    baseline[new_pack] = _cipher_fact(ctx, new_pack)
    ctx.cold_get(new_pack)
    ctx.cold_verify()
    expected_remaining = set(targets) - set(completed)
    current = ctx.refresh_packs()
    remaining_v1 = [pack for pack in current
                    if ctx.envelope(pack)["key_version"] == 1]
    require(set(remaining_v1) == expected_remaining,
            "resume_remaining_v1_set_invalid", "resume")
    require(failed in set(remaining_v1),
            "resume_failed_pack_not_remaining_v1", "resume")
    resume = ctx.cli(["kms-rotate", ctx.repo, "--resume"], stage="rotation_resume")
    require(resume.get("new_key_version") == 2, "resume_target_version_invalid",
            "resume")
    require(resume.get("envelopes_rewrapped") == len(remaining_v1),
            "resume_rewrapped_count_not_this_run", "resume")
    require(resume.get("envelopes_verified") == len(current),
            "resume_verified_count_invalid", "resume")
    require(resume.get("previous_key_version") == 2,
            "resume_previous_version_invalid", "resume")
    require(resume.get("new_key_id") == mid["active_rotation"]["to_key_id"],
            "resume_identity_changed", "resume")
    done = ctx.status()
    final_rotation = done.get("active_rotation")
    require(isinstance(final_rotation, dict), "completed_checkpoint_missing",
            "resume")
    require(final_rotation.get("state") == "COMPLETED", "rotation_not_completed",
            "resume")
    require(set(final_rotation.get("target_pack_ids") or []) == set(current),
            "completed_target_set_invalid", "resume")
    require(set(final_rotation.get("completed_pack_ids") or []) == set(current),
            "completed_pack_set_invalid", "resume")
    require(done.get("provider_latest_version") == 3,
            "latest_version_changed_during_resume", "resume")
    _require_cipher_unchanged(ctx, baseline)
    ctx.cold_verify()
    for pack in current:
        ctx.cold_get(pack)
    clone = ctx.cold_clone("clone-completed")
    require(ctx.git.show(clone, "HEAD") == ctx.markers[2],
            "completed_clone_latest_mismatch", "resume")
    before_post = set(ctx.refresh_packs())
    ctx.commit_and_push(3, "rotation delta")
    post_packs = sorted(set(ctx.refresh_packs()) - before_post)
    require(len(post_packs) == 1, "post_completed_write_count_invalid", "resume")
    post_pack = post_packs[0]
    post_envelope = ctx.envelope(post_pack)
    require(post_envelope.get("key_version") == 2,
            "post_completed_write_not_pinned", "resume")
    require(ctx.fixture.key_metadata()["latest_version"] == 3,
            "post_completed_write_changed_master", "resume")
    baseline[post_pack] = _cipher_fact(ctx, post_pack)
    ctx.cold_get(post_pack)
    ctx.cold_verify()
    _require_cipher_unchanged(ctx, baseline)
    final = ctx.refresh_packs()
    return {
        "id": CASES[2],
        "status": "passed",
        "facts": {
            "rotation_state": "completed",
            "rotation_target_version": 2,
            "rotation_completed_packs": len(
                final_rotation.get("completed_pack_ids") or []),
            "rotation_total_packs": len(
                final_rotation.get("target_pack_ids") or []),
            "rotation_failed": True,
            "rotation_contract": EXISTING_TARGET_CONTRACT,
            "rotation_write_epoch_positive": True,
            "completed_pack_count": len(completed),
            "v1_pack_count": len(remaining_v1),
            "v2_pack_count": len(completed),
            "midpoint_old_v1_cold_read": True,
            "midpoint_rewrapped_v2_cold_read": True,
            "new_write_v2": True,
            "new_write_not_latest": True,
            "resume_rewrapped_this_invocation": len(remaining_v1),
            "resume_completed": True,
            "old_and_new_cold_read": True,
            "post_completed_v2": True,
            "ciphertext_unchanged": True,
            "provider_latest_version": 3,
            "app_rotate_denied": True,
            "latest_unchanged": True,
            "fresh_process": True,
            "pack_count": len(final),
        },
    }
