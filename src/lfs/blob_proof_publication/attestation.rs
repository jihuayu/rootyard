//! Durable, replayable LFS pointer publication attestation & pre-receive decision gate (`Refs #145`).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant as StdInstant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::locks_store::{collect_touched_paths, run_git_quarantined};
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::transfer::{LfsTransferContext, resolve_and_verify_remote_blob};
use super::types::{
    AttestationOutcome, AttestedLfsPointer, LfsBlobError, LfsPointerAttestation, LfsProofRejectCode, LfsRefUpdateSpec,
    PointerInspection, compute_attestation_digest, compute_pointer_receipt_digest, compute_ref_updates_digest,
    inspect_candidate_lfs_pointer,
};

const MAX_INSPECTED_OBJECTS: usize = 20_000;
const MAX_SMALL_BLOBS: usize = 4_096;
const MAX_POINTER_CANDIDATE_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsPushAttestationRequest {
    pub operation_id: Uuid,
    pub updates: Vec<LfsRefUpdateSpec>,
    pub git_object_dir: Option<String>,
    pub git_alternate_object_dirs: Option<String>,
}

impl PgLfsBlobStore {
    pub async fn load_attestation(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<LfsPointerAttestation>, LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT payload_json FROM lfs_pointer_attestations WHERE repository_id=$1 AND operation_id=$2",
                &[&repository_id, &operation_id],
            )
            .await
            .map_err(pg_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let val: serde_json::Value = r.get(0);
        let att: LfsPointerAttestation = serde_json::from_value(val)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        att.verify_integrity()?;
        Ok(Some(att))
    }

    pub async fn persist_attestation(
        &self,
        att: &LfsPointerAttestation,
    ) -> Result<(LfsPointerAttestation, bool), LfsBlobError> {
        att.verify_integrity()?;
        let payload_json = serde_json::to_value(att)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        let inserted = tx
            .execute(
                "INSERT INTO lfs_pointer_attestations(
                    repository_id, operation_id, attestation_id, tenant_id, actor_id,
                    object_format, ref_updates_digest, proof_digest, payload_json
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                 ON CONFLICT (repository_id, operation_id) DO NOTHING",
                &[
                    &att.repository_id,
                    &att.operation_id,
                    &att.attestation_id,
                    &att.tenant_id,
                    &att.actor_id,
                    &att.object_format,
                    &att.ref_updates_digest,
                    &att.proof_digest,
                    &payload_json,
                ],
            )
            .await
            .map_err(pg_err)?;
        if inserted == 1 {
            tx.commit().await.map_err(pg_err)?;
            return Ok((att.clone(), false));
        }
        let row = tx
            .query_one(
                "SELECT payload_json FROM lfs_pointer_attestations WHERE repository_id=$1 AND operation_id=$2",
                &[&att.repository_id, &att.operation_id],
            )
            .await
            .map_err(pg_err)?;
        let existing: LfsPointerAttestation = serde_json::from_value(row.get(0))
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        existing.verify_integrity()?;
        if existing.actor_id != att.actor_id
            || existing.ref_updates_digest != att.ref_updates_digest
            || existing.proof_digest != att.proof_digest
        {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "conflicting LFS pointer attestation payload for operation_id",
            ));
        }
        tx.commit().await.map_err(pg_err)?;
        Ok((existing, true))
    }
}

fn valid_git_oid_for_format(oid: &str, fmt: GitObjectFormat) -> bool {
    let expected_len = match fmt {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    oid.len() == expected_len && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Evaluates a Git push during the decision / pre-receive phase:
/// 1. Enforces fail-closed remote OpenDAL `BlobStore` presence & authoritative write role.
/// 2. Replays deterministically if `(repository_id, operation_id)` was already attested, re-proving
///    live remote bytes on every attested `BlobLocator` + active `SharedLfsHoldGrant`.
/// 3. Enforces repository path locks (`LockedPathConflict`) across new commits and tree diffs/deletes.
/// 4. Inspects newly reachable Git blobs (`<= 1024`B), rejecting malformed pointers, missing/wrong-size
///    objects, or unauthorized cross-owner holds, and issues a durable `LfsPointerAttestation`.
pub async fn attest_and_authorize_push(
    ctx: &LfsTransferContext<'_>,
    req: &LfsPushAttestationRequest,
) -> Result<AttestationOutcome, LfsBlobError> {
    let _ = ctx.gate.require_store()?;
    if !ctx.access.role.allows_write() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedCollaborator,
            "write role required to publish Git refs and LFS pointers",
        ));
    }
    if req.operation_id.is_nil() || req.updates.is_empty() {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "operation_id and ref updates are required"));
    }
    for u in &req.updates {
        if u.ref_name.is_empty()
            || !valid_git_oid_for_format(&u.old_oid, ctx.realm.object_format)
            || !valid_git_oid_for_format(&u.new_oid, ctx.realm.object_format)
        {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid ref_name or Git OID format"));
        }
    }

    let ref_updates_digest = compute_ref_updates_digest(&req.updates);
    if let Some(existing) = ctx.pg.load_attestation(ctx.realm.repository_id, req.operation_id).await? {
        if existing.actor_id != ctx.access.actor_id || existing.ref_updates_digest != ref_updates_digest {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "replay request actor or ref_updates_digest disagrees with stored attestation",
            ));
        }
        let dl = StdInstant::now() + ctx.timeout;
        for ptr in &existing.pointers {
            let (rec, _, _) = resolve_and_verify_remote_blob(ctx, &ptr.oid_sha256, ptr.size_bytes, dl).await?;
            if rec.locator != ptr.locator || rec.hold_id != ptr.hold_id {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::AttestationEquivocation,
                    "replayed attestation locator or hold drifted from live inventory",
                ));
            }
        }
        return Ok(AttestationOutcome::Replayed(existing));
    }

    let bare = Path::new(&ctx.realm.bare_git_dir);
    let obj_dir = req.git_object_dir.as_deref();
    let alt_dirs = req.git_alternate_object_dirs.as_deref();

    let touched_paths = collect_touched_paths(bare, obj_dir, alt_dirs, ctx.timeout, &req.updates).await?;
    if let Some((locked_path, owner_name)) =
        ctx.pg.find_conflicting_lock(ctx.realm.repository_id, ctx.access.actor_id, &touched_paths).await?
    {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::LockedPathConflict,
            format!("push modifies locked path `{locked_path}` owned by `{owner_name}`"),
        ));
    }

    let mut objects = BTreeSet::new();
    for u in &req.updates {
        if u.new_oid.bytes().all(|b| b == b'0') {
            continue;
        }
        let not_old = format!("^{}", u.old_oid);
        let mut args = vec!["rev-list", "--objects", &u.new_oid];
        if u.old_oid.bytes().any(|b| b != b'0') {
            args.push(&not_old);
        } else {
            args.extend(["--not", "--all"]);
        }
        let raw = run_git_quarantined(bare, obj_dir, alt_dirs, ctx.timeout, &args, &[]).await?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 git rev-list"))?;
        for line in text.lines() {
            let oid = line.split_once(' ').map_or(line, |(o, _)| o);
            if !valid_git_oid_for_format(oid, ctx.realm.object_format) {
                return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid OID in rev-list"));
            }
            objects.insert(oid.to_owned());
            if objects.len() > MAX_INSPECTED_OBJECTS {
                return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "exceeded MAX_INSPECTED_OBJECTS"));
            }
        }
    }

    let mut attested_pointers = Vec::new();
    if !objects.is_empty() {
        let check_in = objects.into_iter().collect::<Vec<_>>().join("\n") + "\n";
        let meta_raw = run_git_quarantined(
            bare,
            obj_dir,
            alt_dirs,
            ctx.timeout,
            &["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            check_in.as_bytes(),
        )
        .await?;
        let mut small_blobs = Vec::new();
        for line in std::str::from_utf8(&meta_raw)
            .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 batch-check"))?
            .lines()
        {
            let mut parts = line.split_whitespace();
            let (Some(oid), Some(kind), Some(sz_str)) = (parts.next(), parts.next(), parts.next()) else {
                return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "malformed batch-check line"));
            };
            let sz: usize =
                sz_str.parse().map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad blob size"))?;
            if kind == "blob" && sz <= MAX_POINTER_CANDIDATE_BYTES {
                small_blobs.push(oid.to_owned());
                if small_blobs.len() > MAX_SMALL_BLOBS {
                    return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "exceeded MAX_SMALL_BLOBS"));
                }
            }
        }

        for git_blob_oid in small_blobs {
            let blob_bytes =
                run_git_quarantined(bare, obj_dir, alt_dirs, ctx.timeout, &["cat-file", "blob", &git_blob_oid], &[])
                    .await?;
            match inspect_candidate_lfs_pointer(&blob_bytes) {
                PointerInspection::NonPointer => continue,
                PointerInspection::Malformed(reason) => {
                    return Err(LfsBlobError::new(LfsProofRejectCode::MalformedLfsPointer, reason));
                }
                PointerInspection::Valid(spec) => {
                    let dl = StdInstant::now() + ctx.timeout;
                    let (rec, resolution, _) =
                        resolve_and_verify_remote_blob(ctx, &spec.oid, spec.size, dl).await?;
                    let receipt_digest = compute_pointer_receipt_digest(
                        &spec.oid,
                        spec.size,
                        &rec.locator,
                        &rec.backend_identity_hex,
                        rec.hold_id,
                    );
                    attested_pointers.push(AttestedLfsPointer {
                        git_blob_oid,
                        oid_sha256: spec.oid,
                        size_bytes: spec.size,
                        locator: rec.locator,
                        backend_identity_hex: rec.backend_identity_hex,
                        hold_id: rec.hold_id,
                        resolution,
                        receipt_digest,
                    });
                }
            }
        }
    }

    attested_pointers.sort_unstable_by(|a, b| {
        (&a.git_blob_oid, &a.oid_sha256, a.size_bytes).cmp(&(&b.git_blob_oid, &b.oid_sha256, b.size_bytes))
    });
    let fmt_name = match ctx.realm.object_format {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    };
    let proof_digest = compute_attestation_digest(
        req.operation_id,
        ctx.realm.owner_tenant_id,
        ctx.realm.repository_id,
        ctx.access.actor_id,
        fmt_name,
        &ref_updates_digest,
        &attested_pointers,
    );
    let att = LfsPointerAttestation {
        attestation_id: Uuid::new_v4(),
        operation_id: req.operation_id,
        tenant_id: ctx.realm.owner_tenant_id,
        repository_id: ctx.realm.repository_id,
        actor_id: ctx.access.actor_id,
        access_mode: ctx.access.mode.clone(),
        object_format: fmt_name.to_owned(),
        ref_updates_digest,
        pointers: attested_pointers,
        proof_digest,
    };
    let (saved, replayed) = ctx.pg.persist_attestation(&att).await?;
    Ok(if replayed { AttestationOutcome::Replayed(saved) } else { AttestationOutcome::Issued(saved) })
}
