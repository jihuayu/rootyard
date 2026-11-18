//! Unified DeletionProof builder & independent fail-closed verifier (#122).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::ref_version::pack_cover::PackRetentionState;

use super::{
    SafeGcError,
    model::{
        AuthorityLane, CandidatePackTarget, DecisionState, GlobalHoldEntry, GlobalHoldState, GroupClosureReceipt,
        InFlightDecisionRecord, LiveRefRoot, MAX_CANDIDATES_PER_SWEEP, MAX_DELETION_ROOTS, MAX_GLOBAL_HOLDS,
        MAX_GROUPS_PER_PROOF, MAX_IN_FLIGHT_DECISIONS, MAX_PACKS_PER_CLOSURE, PairedCursorReconciliation,
        ProducerReconciliationEntry, RetentionProducer, SAFE_GC_SCHEMA_VERSION, SafeGcArmReceipt, SafeGcObjectFormat,
        SourceFreshness, check_missing_producers, validate_bounded_name, validate_non_zero_oid, validate_sha256_hex,
    },
    proof_digest::{compute_group_receipt_digest, compute_proof_digest},
    quiescence::ReaderQuiescenceObservation,
    retention_bridge::{PackCoverBridgeInputs, build_pack_cover_retention_index, require_pack_cover_gc_eligible},
};

#[derive(Clone, Debug)]
pub struct DeletionProofInputs {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub object_format: SafeGcObjectFormat,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub membership_generation: u64,
    pub membership_digest: String,
    pub live_ref_seq: u64,
    pub arm_receipt: SafeGcArmReceipt,
    pub reader_quiescence: ReaderQuiescenceObservation,
    pub live_refs: Vec<LiveRefRoot>,
    pub producers: Vec<ProducerReconciliationEntry>,
    pub global_holds: Vec<GlobalHoldEntry>,
    pub in_flight_decisions: Vec<InFlightDecisionRecord>,
    pub paired_cursors: PairedCursorReconciliation,
    pub group_receipts: Vec<GroupClosureReceipt>,
    pub candidates: Vec<CandidatePackTarget>,
}

/// Self-contained cryptographic deletion proof verified prior to any delete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionProof {
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub object_format: SafeGcObjectFormat,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub membership_generation: u64,
    pub membership_digest: String,
    pub live_ref_seq: u64,
    pub lane: AuthorityLane,
    pub reader_quiescence: ReaderQuiescenceObservation,
    pub live_refs: Vec<LiveRefRoot>,
    pub producers: Vec<ProducerReconciliationEntry>,
    pub global_holds: Vec<GlobalHoldEntry>,
    pub in_flight_decisions: Vec<InFlightDecisionRecord>,
    pub paired_cursors: PairedCursorReconciliation,
    pub group_receipts: Vec<GroupClosureReceipt>,
    pub candidates: Vec<CandidatePackTarget>,
    pub proof_digest: String,
}

pub fn seal_group_receipt(mut receipt: GroupClosureReceipt) -> Result<GroupClosureReceipt, SafeGcError> {
    validate_bounded_name("group_id", &receipt.group_id)?;
    if receipt.retired_pack_ids.len() > MAX_PACKS_PER_CLOSURE
        || receipt.replacement_pack_ids.len() > MAX_PACKS_PER_CLOSURE
    {
        return Err(SafeGcError::InvalidInput("group receipt exceeds pack closure limit".into()));
    }
    receipt.receipt_digest = compute_group_receipt_digest(&receipt);
    Ok(receipt)
}

pub fn build_and_verify_deletion_proof(inputs: DeletionProofInputs) -> Result<DeletionProof, SafeGcError> {
    inputs.arm_receipt.validate()?;
    if inputs.arm_receipt.tenant_id != inputs.tenant_id
        || inputs.arm_receipt.repo_id != inputs.repo_id
        || inputs.arm_receipt.history_id != inputs.history_id
        || inputs.arm_receipt.incarnation_id != inputs.incarnation_id
        || inputs.arm_receipt.incarnation_epoch != inputs.incarnation_epoch
    {
        return Err(SafeGcError::ArmingRejected("arm receipt scope disagrees with deletion proof"));
    }
    let mut proof = DeletionProof {
        schema_version: SAFE_GC_SCHEMA_VERSION,
        tenant_id: inputs.tenant_id,
        repo_id: inputs.repo_id,
        history_id: inputs.history_id,
        object_format: inputs.object_format,
        incarnation_id: inputs.incarnation_id,
        incarnation_epoch: inputs.incarnation_epoch,
        membership_generation: inputs.membership_generation,
        membership_digest: inputs.membership_digest,
        live_ref_seq: inputs.live_ref_seq,
        lane: inputs.arm_receipt.lane,
        reader_quiescence: inputs.reader_quiescence,
        live_refs: inputs.live_refs,
        producers: inputs.producers,
        global_holds: inputs.global_holds,
        in_flight_decisions: inputs.in_flight_decisions,
        paired_cursors: inputs.paired_cursors,
        group_receipts: inputs.group_receipts,
        candidates: inputs.candidates,
        proof_digest: String::new(),
    };
    proof.proof_digest = compute_proof_digest(&proof);
    verify_deletion_proof(&proof)?;
    Ok(proof)
}

pub fn verify_deletion_proof(proof: &DeletionProof) -> Result<(), SafeGcError> {
    check_proof_bounds_and_seal(proof)?;
    let require_pg_barrier = matches!(proof.lane, AuthorityLane::SingleNodePg { .. });
    proof.reader_quiescence.verify_quiesced(require_pg_barrier)?;

    let mut protected_oids = BTreeSet::new();
    let mut protected_packs = BTreeSet::new();
    let mut protected_keys = BTreeSet::new();

    collect_live_refs(proof, &mut protected_oids)?;
    collect_producers(proof, &mut protected_oids, &mut protected_packs)?;
    collect_holds(proof, &mut protected_oids, &mut protected_packs, &mut protected_keys)?;
    collect_decisions(proof, &mut protected_oids, &mut protected_packs)?;
    verify_paired_cursors(&proof.paired_cursors)?;
    proof.lane.verify_cursor_coverage(proof.live_ref_seq, &proof.paired_cursors)?;
    verify_candidates_and_pack_cover(proof, &protected_oids, &protected_packs, &protected_keys, require_pg_barrier)
}

fn check_proof_bounds_and_seal(proof: &DeletionProof) -> Result<(), SafeGcError> {
    if proof.schema_version != SAFE_GC_SCHEMA_VERSION
        || proof.tenant_id.is_nil()
        || proof.repo_id.is_nil()
        || proof.history_id.is_nil()
        || proof.incarnation_id.is_nil()
        || proof.incarnation_epoch == 0
        || proof.membership_generation == 0
    {
        return Err(SafeGcError::IncompleteProof("invalid deletion proof header"));
    }
    validate_sha256_hex(&proof.membership_digest)?;
    if proof.live_refs.len() > MAX_DELETION_ROOTS
        || proof.global_holds.len() > MAX_GLOBAL_HOLDS
        || proof.in_flight_decisions.len() > MAX_IN_FLIGHT_DECISIONS
        || proof.group_receipts.len() > MAX_GROUPS_PER_PROOF
        || proof.candidates.len() > MAX_CANDIDATES_PER_SWEEP
    {
        return Err(SafeGcError::InvalidInput("deletion proof exceeds bounded limits".into()));
    }
    proof.lane.validate_for_destructive_gc()?;
    if proof.proof_digest != compute_proof_digest(proof) {
        return Err(SafeGcError::ProofDigestMismatch);
    }
    Ok(())
}

fn collect_live_refs(p: &DeletionProof, protected_oids: &mut BTreeSet<String>) -> Result<(), SafeGcError> {
    for r in &p.live_refs {
        validate_bounded_name("ref_name", &r.ref_name)?;
        if !r.ref_name.starts_with("refs/") {
            return Err(SafeGcError::InvalidInput("live ref must start with refs/".into()));
        }
        validate_non_zero_oid(p.object_format, &r.target_oid)?;
        if r.version_seq > p.live_ref_seq {
            return Err(SafeGcError::ConcurrentRetentionRace("live ref sequence exceeds snapshot seq"));
        }
        protected_oids.insert(r.target_oid.clone());
    }
    Ok(())
}

fn collect_producers(
    p: &DeletionProof,
    protected_oids: &mut BTreeSet<String>,
    protected_packs: &mut BTreeSet<Uuid>,
) -> Result<(), SafeGcError> {
    let mut seen: BTreeSet<RetentionProducer> = BTreeSet::new();
    let mut root_budget = p.live_refs.len();
    for entry in &p.producers {
        if !seen.insert(entry.producer) {
            return Err(SafeGcError::InvalidInput("duplicate retention producer entry".into()));
        }
        if entry.freshness != SourceFreshness::Reconciled {
            return Err(SafeGcError::IncompleteProof("producer retention state is not reconciled"));
        }
        if entry.observed_cursor_seq < entry.required_cursor_seq
            || entry.authority_epoch != entry.expected_authority_epoch
            || entry.expected_authority_epoch < p.incarnation_epoch
        {
            return Err(SafeGcError::IncompleteProof("producer cursor or epoch is stale/lagging"));
        }
        root_budget = root_budget
            .checked_add(entry.root_oids.len())
            .filter(|&n| n <= MAX_DELETION_ROOTS)
            .ok_or_else(|| SafeGcError::InvalidInput("retention roots exceed bound".into()))?;
        for oid in &entry.root_oids {
            validate_non_zero_oid(p.object_format, oid)?;
            protected_oids.insert(oid.clone());
        }
        if entry.pinned_pack_ids.len() > MAX_PACKS_PER_CLOSURE {
            return Err(SafeGcError::InvalidInput("producer pinned packs exceed limit".into()));
        }
        protected_packs.extend(entry.pinned_pack_ids.iter().copied());
    }
    check_missing_producers(&seen)
}

fn collect_holds(
    p: &DeletionProof,
    protected_oids: &mut BTreeSet<String>,
    protected_packs: &mut BTreeSet<Uuid>,
    protected_keys: &mut BTreeSet<String>,
) -> Result<(), SafeGcError> {
    for h in &p.global_holds {
        if h.hold_id.is_nil() || h.tenant_id != p.tenant_id || h.repo_id != p.repo_id {
            return Err(SafeGcError::InvalidInput("global hold cross-tenant/repo mismatch".into()));
        }
        match h.state {
            GlobalHoldState::Unknown => {
                return Err(SafeGcError::IncompleteProof("global hold status is unknown"));
            }
            GlobalHoldState::Active => {
                for oid in &h.protected_oids {
                    validate_non_zero_oid(p.object_format, oid)?;
                    protected_oids.insert(oid.clone());
                }
                protected_packs.extend(h.protected_pack_ids.iter().copied());
                for k in &h.protected_physical_keys {
                    validate_bounded_name("protected_physical_key", k)?;
                    protected_keys.insert(k.clone());
                }
            }
            GlobalHoldState::Released { released_at_seq } => {
                if released_at_seq > p.paired_cursors.pg_applied_seq
                    || released_at_seq > p.paired_cursors.refcas_applied_index
                {
                    return Err(SafeGcError::ConcurrentRetentionRace("hold release sequence overtakes paired cursors"));
                }
            }
        }
    }
    Ok(())
}

fn collect_decisions(
    p: &DeletionProof,
    protected_oids: &mut BTreeSet<String>,
    protected_packs: &mut BTreeSet<Uuid>,
) -> Result<(), SafeGcError> {
    for d in &p.in_flight_decisions {
        if d.decision_id.is_nil() {
            return Err(SafeGcError::InvalidInput("nil in-flight decision id".into()));
        }
        match d.state {
            DecisionState::Unknown => {
                return Err(SafeGcError::IncompleteProof("in-flight decision state unknown"));
            }
            DecisionState::Pending => {
                for oid in &d.protected_oids {
                    validate_non_zero_oid(p.object_format, oid)?;
                    protected_oids.insert(oid.clone());
                }
                protected_packs.extend(d.protected_pack_ids.iter().copied());
            }
            DecisionState::Committed | DecisionState::Cancelled => {}
        }
    }
    Ok(())
}

fn verify_paired_cursors(c: &PairedCursorReconciliation) -> Result<(), SafeGcError> {
    if c.pg_freshness != SourceFreshness::Reconciled || c.pg_applied_seq < c.pg_required_seq {
        return Err(SafeGcError::IncompleteProof("PG retention cursor lagging or unreconciled"));
    }
    if c.refcas_freshness != SourceFreshness::Reconciled || c.refcas_applied_index < c.refcas_required_index {
        return Err(SafeGcError::IncompleteProof("Ref-CAS paired cursor lagging or unreconciled"));
    }
    Ok(())
}

fn verify_candidates_and_pack_cover(
    p: &DeletionProof,
    protected_oids: &BTreeSet<String>,
    protected_packs: &BTreeSet<Uuid>,
    protected_keys: &BTreeSet<String>,
    require_pg_barrier: bool,
) -> Result<(), SafeGcError> {
    let candidate_pack_ids: BTreeSet<Uuid> = p.candidates.iter().map(|c| c.pack_id).collect();
    let mut receipts_by_group: BTreeMap<&str, Vec<&GroupClosureReceipt>> = BTreeMap::new();
    for gr in &p.group_receipts {
        validate_bounded_name("group_id", &gr.group_id)?;
        if gr.receipt_digest != compute_group_receipt_digest(gr) {
            return Err(SafeGcError::IncompleteProof("group closure receipt digest mismatch"));
        }
        if !gr.replacement_closure_verified
            || gr.replacement_pack_ids.is_empty()
            || gr.retired_at_generation == 0
            || gr.retired_at_generation > p.membership_generation
        {
            return Err(SafeGcError::IncompleteProof("group closure not verified or retirement generation invalid"));
        }
        gr.reader_quiescence.verify_quiesced(require_pg_barrier)?;
        receipts_by_group.entry(gr.group_id.as_str()).or_default().push(gr);
    }

    let tombstoned_none = BTreeSet::new();
    let cover_index = build_pack_cover_retention_index(&PackCoverBridgeInputs {
        incarnation_epoch: p.incarnation_epoch,
        lane: &p.lane,
        live_refs: &p.live_refs,
        producers: &p.producers,
        global_holds: &p.global_holds,
        in_flight_decisions: &p.in_flight_decisions,
        paired_cursors: &p.paired_cursors,
        group_receipts: &p.group_receipts,
        reader_quiescence: &p.reader_quiescence,
        active_reader_leases: &[],
        tombstoned_pack_ids: &tombstoned_none,
    });

    let mut seen_roles = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    for c in &p.candidates {
        if !matches!(c.key_role.as_str(), "pack" | "idx") || c.provider_generation <= 0 || c.key_epoch == 0 {
            return Err(SafeGcError::InvalidInput("candidate key_role or generation invalid".into()));
        }
        validate_bounded_name("group_id", &c.group_id)?;
        validate_bounded_name("physical_key", &c.physical_key)?;
        validate_sha256_hex(&c.object_sha256)?;
        if !seen_roles.insert((c.pack_id, c.key_role.as_str())) {
            return Err(SafeGcError::InvalidInput("duplicate (pack_id, key_role) candidate".into()));
        }
        if !seen_keys.insert(c.physical_key.as_str()) {
            return Err(SafeGcError::InvalidInput("duplicate candidate physical_key".into()));
        }
        if c.retention_state != PackRetentionState::GcEligible {
            return Err(SafeGcError::IncompleteProof("candidate retention_state is not GcEligible (#184)"));
        }
        let group_list = receipts_by_group
            .get(c.group_id.as_str())
            .ok_or(SafeGcError::IncompleteProof("candidate missing reconciled group closure receipt"))?;
        let retiring_receipt = group_list
            .iter()
            .find(|gr| gr.retired_pack_ids.contains(&c.pack_id))
            .ok_or(SafeGcError::IncompleteProof("candidate not retired in group receipt"))?;
        // A candidate cannot be the surviving replacement of any receipt unless a later receipt retired it.
        if group_list.iter().any(|gr| {
            gr.replacement_pack_ids.contains(&c.pack_id)
                && gr.retired_at_generation >= retiring_receipt.retired_at_generation
        }) || retiring_receipt.replacement_pack_ids.iter().any(|id| {
            candidate_pack_ids.contains(id) && !group_list.iter().any(|later| later.retired_pack_ids.contains(id))
        }) {
            return Err(SafeGcError::ProtectionOverlap("candidate overlaps unretired replacement pack".into()));
        }
        if protected_packs.contains(&c.pack_id) || protected_keys.contains(&c.physical_key) {
            return Err(SafeGcError::ProtectionOverlap("candidate pack/key is protected".into()));
        }
        let replaced_oids: BTreeSet<&str> = retiring_receipt.replacement_oids.iter().map(String::as_str).collect();
        let mut unreplaced_oids = Vec::new();
        for oid in &c.contained_oids {
            validate_non_zero_oid(p.object_format, oid)?;
            if !replaced_oids.contains(oid.as_str()) {
                if protected_oids.contains(oid) {
                    return Err(SafeGcError::ProtectionOverlap(format!(
                        "candidate object {oid} still reachable/pinned and absent from replacement"
                    )));
                }
                unreplaced_oids.push(oid.clone());
            }
        }
        let _ = require_pack_cover_gc_eligible(&cover_index, c.pack_id, &unreplaced_oids)?;
    }
    Ok(())
}
