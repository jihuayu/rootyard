//! Complete durable hold/root pack-set binding and PG/Raft cursor `group_epoch`
//! cross-verification across backup and restore (#153).

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::ref_store::core::state_machine::{RefCasSnapshot, SmHoldState, SmPinState, SmRootState};

use super::types::{
    BackupRetentionHoldRecord, BlobArtifactEntry, ExpectedPackPairSpec, PairedBackupError, PgRepositoryRowProof,
    sha256_json_tagged, validate_hex64,
};

/// Domain-tagged 64-hex SHA-256 over the canonical sorted set of paired `(pack, idx)` artifacts.
pub fn compute_canonical_pack_set_digest(packs: &[ExpectedPackPairSpec]) -> Result<String, PairedBackupError> {
    if packs.is_empty() {
        return Err(PairedBackupError::BlobClosureIncomplete("repository pack closure cannot be empty".into()));
    }
    let mut sorted = packs.to_vec();
    sorted.sort();
    let mut seen_ids = BTreeSet::new();
    for p in &sorted {
        if p.pack_id.is_nil()
            || !seen_ids.insert(p.pack_id)
            || !validate_hex64(&p.pack_sha256)
            || !validate_hex64(&p.idx_sha256)
            || p.pack_bytes == 0
            || p.idx_bytes == 0
        {
            return Err(PairedBackupError::BlobClosureIncomplete(
                "invalid or duplicate ExpectedPackPairSpec in closure".into(),
            ));
        }
    }
    sha256_json_tagged(b"rootyard-complete-pack-set-v1", &sorted)
}

/// Ensure a backup registration spec covers every live durable hold, active snapshot pin,
/// and active retention root already recorded in Raft for `repository_id`.
pub fn verify_registration_spec_completeness(
    pre_snap: &RefCasSnapshot,
    repository_id: Uuid,
    sorted_packs: &[ExpectedPackPairSpec],
) -> Result<Vec<String>, PairedBackupError> {
    let declared_artifacts: BTreeSet<(String, u64)> = sorted_packs
        .iter()
        .flat_map(|p| [(p.pack_sha256.clone(), p.pack_bytes), (p.idx_sha256.clone(), p.idx_bytes)])
        .collect();
    let declared_pack_shas: BTreeSet<String> = sorted_packs.iter().map(|p| p.pack_sha256.clone()).collect();

    for h in pre_snap.body.holds.iter().filter(|h| h.repository_id == repository_id && h.state != SmHoldState::Retired)
    {
        if !declared_artifacts.contains(&(h.artifact_digest.clone(), h.declared_bytes as u64)) {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "registration spec omits live durable hold artifact {}",
                h.artifact_digest
            )));
        }
    }
    for pin in pre_snap.body.pins.iter().filter(|p| p.repository_id == repository_id && p.state == SmPinState::Active) {
        if let Some(sr) = pre_snap.body.snapshots.iter().find(|s| s.snapshot_id == pin.snapshot_id) {
            for pd in &sr.pack_digests {
                if !declared_pack_shas.contains(pd) {
                    return Err(PairedBackupError::BlobClosureIncomplete(format!(
                        "registration spec omits pack {pd} referenced by active snapshot pin"
                    )));
                }
            }
        }
    }
    for rt in pre_snap.body.roots.iter().filter(|r| r.repository_id == repository_id && r.state == SmRootState::Active)
    {
        if let Some(sr) = pre_snap.body.snapshots.iter().find(|s| s.snapshot_id == rt.source_snapshot_id) {
            for pd in &sr.pack_digests {
                if !declared_pack_shas.contains(pd) {
                    return Err(PairedBackupError::BlobClosureIncomplete(format!(
                        "registration spec omits pack {pd} referenced by active retention root"
                    )));
                }
            }
        }
    }
    Ok(declared_pack_shas.into_iter().collect())
}

/// Extract uniform `(history_incarnation, group_epoch)` from a Raft group's gates.
pub fn extract_raft_group_realm(snap: &RefCasSnapshot) -> Result<(Uuid, i64), PairedBackupError> {
    let first = snap
        .body
        .gates
        .first()
        .ok_or(PairedBackupError::IncompleteCut("Raft snapshot contains zero repository gates"))?;
    if first.history_incarnation.is_nil() || first.group_epoch <= 0 {
        return Err(PairedBackupError::CutpointSkew(
            "Raft gate has nil incarnation or non-positive group_epoch".into(),
        ));
    }
    for gate in &snap.body.gates {
        if gate.history_incarnation != first.history_incarnation || gate.group_epoch != first.group_epoch {
            return Err(PairedBackupError::CutpointSkew(
                "Raft snapshot gates disagree on history_incarnation or group_epoch".into(),
            ));
        }
    }
    Ok((first.history_incarnation, first.group_epoch))
}

/// Bind and verify exported/archived Blob closure entries against the COMPLETE pack set
/// derived from durable Raft holds, snapshots, pins, and active retention roots.
pub fn verify_blob_closure_against_durable_raft(
    snap: &RefCasSnapshot,
    backup_holds: &[BackupRetentionHoldRecord],
    entries: &[BlobArtifactEntry],
    repositories: &[PgRepositoryRowProof],
) -> Result<(), PairedBackupError> {
    let known_repos: BTreeSet<Uuid> = repositories.iter().map(|r| r.repository_id).collect();
    for entry in entries {
        if !known_repos.contains(&entry.repository_id) {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "Blob artifact references unknown repository {}",
                entry.repository_id
            )));
        }
    }

    for repo in repositories {
        let hold_rec = backup_holds
            .iter()
            .find(|h| h.repository_id == repo.repository_id && h.tenant_id == repo.tenant_id)
            .ok_or_else(|| {
                PairedBackupError::BlobClosureIncomplete(format!(
                    "missing backup hold record for repository {}",
                    repo.repository_id
                ))
            })?;
        let root =
            snap.body.roots.iter().find(|r| r.root_id == hold_rec.root_id).ok_or_else(|| {
                PairedBackupError::BlobClosureIncomplete("durable retention root missing in Raft".into())
            })?;
        if root.state != SmRootState::Active
            || root.repository_id != repo.repository_id
            || root.tenant_id != repo.tenant_id
            || root.source_snapshot_id != hold_rec.snapshot_id
            || root.source_pin_id != hold_rec.pin_id
            || root.bound_hold_ids != hold_rec.hold_ids
            || root.pack_set_digest != hold_rec.pack_set_digest
            || root.bound_hold_ids.is_empty()
        {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "durable retention root {} inactive or mismatched against hold record",
                hold_rec.root_id
            )));
        }
        let pin = snap
            .body
            .pins
            .iter()
            .find(|p| p.pin_id == hold_rec.pin_id)
            .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("durable backup pin missing in Raft".into()))?;
        if pin.state != SmPinState::Active || pin.snapshot_id != hold_rec.snapshot_id {
            return Err(PairedBackupError::BlobClosureIncomplete("durable backup pin released or mismatched".into()));
        }
        let snap_rec = snap
            .body
            .snapshots
            .iter()
            .find(|s| s.snapshot_id == hold_rec.snapshot_id)
            .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("durable snapshot missing in Raft".into()))?;

        let mut durable_held_artifacts: BTreeSet<(String, u64)> = BTreeSet::new();
        for hid in &root.bound_hold_ids {
            let he = snap
                .body
                .holds
                .iter()
                .find(|h| h.hold_id == *hid)
                .ok_or_else(|| PairedBackupError::BlobClosureIncomplete(format!("durable hold {hid} missing")))?;
            if he.state == SmHoldState::Retired
                || he.repository_id != repo.repository_id
                || he.tenant_id != repo.tenant_id
                || he.declared_bytes <= 0
            {
                return Err(PairedBackupError::BlobClosureIncomplete(format!(
                    "durable hold {hid} retired or mismatched scope"
                )));
            }
            durable_held_artifacts.insert((he.artifact_digest.clone(), he.declared_bytes as u64));
        }
        let mut all_live_repo_holds: BTreeSet<(String, u64)> = BTreeSet::new();
        for he in
            snap.body.holds.iter().filter(|h| h.repository_id == repo.repository_id && h.state != SmHoldState::Retired)
        {
            if he.declared_bytes <= 0 {
                return Err(PairedBackupError::BlobClosureIncomplete("live hold has non-positive bytes".into()));
            }
            all_live_repo_holds.insert((he.artifact_digest.clone(), he.declared_bytes as u64));
        }
        let mut all_live_pinned_packs: BTreeSet<String> = snap_rec.pack_digests.iter().cloned().collect();
        for live_pin in
            snap.body.pins.iter().filter(|p| p.repository_id == repo.repository_id && p.state == SmPinState::Active)
        {
            let ps = snap
                .body
                .snapshots
                .iter()
                .find(|s| s.snapshot_id == live_pin.snapshot_id)
                .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("active pin missing snapshot".into()))?;
            all_live_pinned_packs.extend(ps.pack_digests.iter().cloned());
        }
        for live_root in
            snap.body.roots.iter().filter(|r| r.repository_id == repo.repository_id && r.state == SmRootState::Active)
        {
            let rs = snap
                .body
                .snapshots
                .iter()
                .find(|s| s.snapshot_id == live_root.source_snapshot_id)
                .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("active root missing snapshot".into()))?;
            all_live_pinned_packs.extend(rs.pack_digests.iter().cloned());
        }

        type PairSides<'a> = (Option<&'a BlobArtifactEntry>, Option<&'a BlobArtifactEntry>);
        let mut by_pack: BTreeMap<Uuid, PairSides<'_>> = BTreeMap::new();
        for e in entries.iter().filter(|e| e.repository_id == repo.repository_id) {
            if e.tenant_id != repo.tenant_id {
                return Err(PairedBackupError::TenantOrRepoMismatch("artifact tenant mismatches repository".into()));
            }
            let slot = by_pack.entry(e.pack_id).or_default();
            match e.role.as_str() {
                "pack" => {
                    if slot.0.replace(e).is_some() {
                        return Err(PairedBackupError::BlobClosureIncomplete("duplicate .pack for pack_id".into()));
                    }
                }
                "idx" => {
                    if slot.1.replace(e).is_some() {
                        return Err(PairedBackupError::BlobClosureIncomplete("duplicate .idx for pack_id".into()));
                    }
                }
                other => {
                    return Err(PairedBackupError::BlobClosureIncomplete(format!("invalid artifact role {other}")));
                }
            }
        }
        if by_pack.is_empty() {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "repository {} has zero Blob pack pairs in closure",
                repo.repository_id
            )));
        }

        let mut actual_pack_digests = BTreeSet::new();
        let mut actual_held_artifacts = BTreeSet::new();
        let mut derived_specs = Vec::with_capacity(by_pack.len());
        for (&pack_id, &(p_opt, i_opt)) in &by_pack {
            let p = p_opt.ok_or_else(|| {
                PairedBackupError::BlobClosureIncomplete(format!("pack {pack_id} missing .pack side"))
            })?;
            let i = i_opt
                .ok_or_else(|| PairedBackupError::BlobClosureIncomplete(format!("pack {pack_id} missing .idx side")))?;
            actual_pack_digests.insert(p.sha256.clone());
            actual_held_artifacts.insert((p.sha256.clone(), p.length));
            actual_held_artifacts.insert((i.sha256.clone(), i.length));
            derived_specs.push(ExpectedPackPairSpec {
                pack_id,
                pack_sha256: p.sha256.clone(),
                pack_bytes: p.length,
                idx_sha256: i.sha256.clone(),
                idx_bytes: i.length,
            });
        }
        let expected_snap_packs: BTreeSet<String> = snap_rec.pack_digests.iter().cloned().collect();

        if actual_pack_digests != expected_snap_packs || actual_pack_digests != all_live_pinned_packs {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "Blob pack closure ({} packs) missing or extra packs vs durable pins/roots ({} packs)",
                actual_pack_digests.len(),
                all_live_pinned_packs.len()
            )));
        }
        if actual_held_artifacts != durable_held_artifacts || actual_held_artifacts != all_live_repo_holds {
            return Err(PairedBackupError::BlobClosureIncomplete(
                "Blob (.pack + .idx) digests/lengths disagree with durable Raft holds/roots".into(),
            ));
        }
        let actual_set_digest = compute_canonical_pack_set_digest(&derived_specs)?;
        if actual_set_digest != root.pack_set_digest {
            return Err(PairedBackupError::BlobClosureIncomplete(
                "Blob closure pack_set_digest disagrees with active durable retention root".into(),
            ));
        }
    }
    Ok(())
}
