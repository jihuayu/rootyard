//! Ledger staging and CAS ref-mutation helpers for `StreamingGrowthEngine`.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use super::{
    admission_types::AdmissionRejection,
    git_ops::ObjectFormat,
    git_views::is_reserved_ref_name,
    growth_types::{GrowthEngineError, RefMutation, VerifiedPackRecord},
    ledger_retention::RetentionLedger,
    ledger_types::{LedgerEntryKind, LedgerRetentionError},
    limits::{MAX_REF_NAME_BYTES, PandoCapacityContract, RESERVED_GIT_OPEN_FDS},
};

fn record_pack_entries(
    ledger: &mut RetentionLedger,
    pack_id: Uuid,
    reg_id: Uuid,
    op_id: Option<Uuid>,
    epoch: u64,
) -> Result<(), GrowthEngineError> {
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(pack_id), op_id, 512, epoch)?;
    ledger.record_entry(reg_id, LedgerEntryKind::Registration, Some(pack_id), op_id, 1024, epoch)?;
    Ok(())
}

pub(super) fn stage_compaction_ledger(
    ledger: &RetentionLedger,
    compaction_epoch: u64,
    target_ids: &BTreeSet<Uuid>,
    pack_id: Uuid,
    registration_id: Uuid,
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    next_ledger.record_compaction_superseded(compaction_epoch, target_ids);
    record_pack_entries(&mut next_ledger, pack_id, registration_id, None, compaction_epoch)?;
    Ok(next_ledger)
}

pub(super) fn stage_push_ledger(
    ledger: &RetentionLedger,
    operation_id: Uuid,
    commit_epoch: u64,
    uploaded_records: &[VerifiedPackRecord],
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    for rec in uploaded_records {
        record_pack_entries(&mut next_ledger, rec.pack_id, rec.registration_id, Some(operation_id), commit_epoch)?;
    }
    next_ledger.record_entry(
        Uuid::new_v4(),
        LedgerEntryKind::Receipt,
        uploaded_records.first().map(|r| r.pack_id),
        Some(operation_id),
        512,
        commit_epoch,
    )?;
    Ok(next_ledger)
}

pub(super) fn validate_mutations(
    format: ObjectFormat,
    max_plan_refs: usize,
    mutations: &[RefMutation],
) -> Result<(), GrowthEngineError> {
    if mutations.is_empty() || mutations.len() > max_plan_refs {
        return Err(GrowthEngineError::InvalidInput("ref_mutations must be 1..=max_plan_refs"));
    }
    let mut seen = BTreeSet::new();
    for m in mutations {
        if !m.ref_name.starts_with("refs/")
            || m.ref_name.len() > MAX_REF_NAME_BYTES
            || m.ref_name.contains('\0')
            || is_reserved_ref_name(&m.ref_name)
            || m.ref_name.contains("..")
            || !seen.insert(&m.ref_name)
        {
            return Err(GrowthEngineError::InvalidInput("invalid, oversized, reserved, or duplicate ref name"));
        }
        if !(format.is_valid_oid(&m.old_oid) || format.is_zero_oid(&m.old_oid)) {
            return Err(GrowthEngineError::InvalidInput("invalid old_oid format"));
        }
        if !(format.is_valid_oid(&m.new_oid) || format.is_zero_oid(&m.new_oid)) {
            return Err(GrowthEngineError::InvalidInput("invalid new_oid format"));
        }
    }
    Ok(())
}

pub(super) fn apply_cas_mutations(
    format: ObjectFormat,
    base_refs: &BTreeMap<String, String>,
    mutations: &[RefMutation],
) -> Result<BTreeMap<String, String>, GrowthEngineError> {
    let mut next = base_refs.clone();
    for m in mutations {
        let current = next.get(&m.ref_name).map(String::as_str);
        let old_matches =
            if format.is_zero_oid(&m.old_oid) { current.is_none() } else { current == Some(m.old_oid.as_str()) };
        if !old_matches {
            return Err(GrowthEngineError::CasPreconditionFailed { ref_name: m.ref_name.clone() });
        }
        if format.is_zero_oid(&m.new_oid) {
            next.remove(&m.ref_name);
        } else {
            next.insert(m.ref_name.clone(), m.new_oid.clone());
        }
    }
    Ok(next)
}

pub(super) fn resident_ref_and_hold_bytes(
    acked_refs: &BTreeMap<String, String>,
    pinned_commits: &BTreeMap<Uuid, String>,
    ledger: &RetentionLedger,
) -> u64 {
    let ref_b: u64 = acked_refs.iter().map(|(r, o)| (r.len() as u64).saturating_add(o.len() as u64)).sum();
    let pin_b: u64 = pinned_commits.values().map(|o| 16u64.saturating_add(o.len() as u64)).sum();
    ref_b.saturating_add(pin_b).saturating_add(ledger.resident_hold_bytes())
}

pub(super) fn check_ref_and_hold_bytes(
    limit: u64,
    next_total: u64,
    current_total: u64,
) -> Result<(), GrowthEngineError> {
    if next_total > limit {
        return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
            resource: "ref_and_hold_bytes",
            current: current_total,
            limit,
        }));
    }
    Ok(())
}

pub(super) fn check_commit_window_bounds(
    c: &PandoCapacityContract,
    active: &[VerifiedPackRecord],
    added: &[VerifiedPackRecord],
) -> Result<(), GrowthEngineError> {
    if added.is_empty() {
        return Ok(());
    }
    let fail = |r| Err(GrowthEngineError::Admission(r));
    let next_pairs = active.len().saturating_add(added.len());
    if next_pairs > c.streaming.max_active_frontier_packs {
        return fail(AdmissionRejection::PackCountLimitReached {
            active: active.len(),
            new_packs: added.len(),
            limit: c.streaming.max_active_frontier_packs,
        });
    }
    let sum = |ps: &[VerifiedPackRecord]| -> (u64, u64) {
        (ps.iter().map(VerifiedPackRecord::total_bytes).sum(), ps.iter().map(|p| p.object_count).sum())
    };
    let ((cb, co), (ab, ao)) = (sum(active), sum(added));
    let (next_bytes, next_objects) = (cb.saturating_add(ab), co.saturating_add(ao));
    if next_bytes > c.verifier.max_total_bytes_per_window {
        return fail(AdmissionRejection::PackBytesExceeded {
            requested: next_bytes,
            limit: c.verifier.max_total_bytes_per_window,
        });
    }
    if next_objects > c.verifier.max_objects_per_window {
        return fail(AdmissionRejection::TooManyObjects {
            requested: next_objects,
            limit: c.verifier.max_objects_per_window,
        });
    }
    let next_workspace = next_bytes.saturating_mul(2);
    if next_workspace > c.verifier.view_max_logical_bytes {
        return fail(AdmissionRejection::WorkspaceBudgetExceeded {
            requested: next_workspace,
            limit: c.verifier.view_max_logical_bytes,
        });
    }
    let next_fds = (next_pairs as u64).saturating_mul(2).saturating_add(RESERVED_GIT_OPEN_FDS);
    if next_fds > c.verifier.git_nofile {
        return fail(AdmissionRejection::FdBudgetExceeded { requested: next_fds, limit: c.verifier.git_nofile });
    }
    Ok(())
}
