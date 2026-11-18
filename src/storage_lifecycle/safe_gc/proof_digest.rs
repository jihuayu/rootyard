//! Canonical SHA-256 preimage encoding for DeletionProof & GroupClosureReceipt (#122).

use sha2::{Digest, Sha256};

use super::{
    model::{
        GlobalHoldEntry, GlobalHoldState, GroupClosureReceipt, InFlightDecisionRecord, LiveRefRoot,
        PairedCursorReconciliation, ProducerReconciliationEntry, SourceFreshness, encode_len_bytes,
    },
    proof::DeletionProof,
};

pub fn compute_group_receipt_digest(r: &GroupClosureReceipt) -> String {
    let mut h = Sha256::new();
    h.update(b"safe-gc-group-v1|");
    encode_len_bytes(&mut h, r.group_id.as_bytes());
    h.update(r.epoch.to_be_bytes());
    h.update((r.retired_pack_ids.len() as u64).to_be_bytes());
    for id in &r.retired_pack_ids {
        h.update(id.as_bytes());
    }
    h.update((r.replacement_pack_ids.len() as u64).to_be_bytes());
    for id in &r.replacement_pack_ids {
        h.update(id.as_bytes());
    }
    h.update([u8::from(r.replacement_closure_verified), u8::from(r.quiesced)]);
    hex::encode(h.finalize())
}

pub fn compute_proof_digest(p: &DeletionProof) -> String {
    let mut h = Sha256::new();
    h.update(b"safe-gc-proof-v1|");
    h.update(p.schema_version.to_be_bytes());
    h.update(p.tenant_id.as_bytes());
    h.update(p.repo_id.as_bytes());
    h.update(p.history_id.as_bytes());
    encode_len_bytes(&mut h, p.object_format.as_str().as_bytes());
    h.update(p.incarnation_id.as_bytes());
    h.update(p.incarnation_epoch.to_be_bytes());
    h.update(p.live_ref_seq.to_be_bytes());
    p.lane.encode_canonical(&mut h);
    encode_live_refs(&mut h, &p.live_refs);
    encode_producers(&mut h, &p.producers);
    encode_holds(&mut h, &p.global_holds);
    encode_decisions(&mut h, &p.in_flight_decisions);
    encode_cursors(&mut h, &p.paired_cursors);
    h.update((p.group_receipts.len() as u64).to_be_bytes());
    for gr in &p.group_receipts {
        encode_len_bytes(&mut h, gr.group_id.as_bytes());
        encode_len_bytes(&mut h, gr.receipt_digest.as_bytes());
    }
    h.update((p.candidates.len() as u64).to_be_bytes());
    for c in &p.candidates {
        h.update(c.pack_id.as_bytes());
        encode_len_bytes(&mut h, c.group_id.as_bytes());
        encode_len_bytes(&mut h, c.physical_key.as_bytes());
        encode_len_bytes(&mut h, c.object_sha256.as_bytes());
        h.update(c.key_epoch.to_be_bytes());
        h.update((c.contained_oids.len() as u64).to_be_bytes());
        for oid in &c.contained_oids {
            encode_len_bytes(&mut h, oid.as_bytes());
        }
    }
    hex::encode(h.finalize())
}

fn encode_live_refs(h: &mut Sha256, refs: &[LiveRefRoot]) {
    h.update((refs.len() as u64).to_be_bytes());
    for r in refs {
        encode_len_bytes(h, r.ref_name.as_bytes());
        encode_len_bytes(h, r.target_oid.as_bytes());
        h.update(r.version_seq.to_be_bytes());
    }
}

fn encode_producers(h: &mut Sha256, items: &[ProducerReconciliationEntry]) {
    h.update((items.len() as u64).to_be_bytes());
    for p in items {
        encode_len_bytes(h, p.producer.as_str().as_bytes());
        encode_freshness(h, p.freshness);
        h.update(p.observed_cursor_seq.to_be_bytes());
        h.update(p.required_cursor_seq.to_be_bytes());
        h.update(p.authority_epoch.to_be_bytes());
        h.update(p.expected_authority_epoch.to_be_bytes());
        h.update((p.root_oids.len() as u64).to_be_bytes());
        for o in &p.root_oids {
            encode_len_bytes(h, o.as_bytes());
        }
        h.update((p.pinned_pack_ids.len() as u64).to_be_bytes());
        for id in &p.pinned_pack_ids {
            h.update(id.as_bytes());
        }
    }
}

fn encode_holds(h: &mut Sha256, holds: &[GlobalHoldEntry]) {
    h.update((holds.len() as u64).to_be_bytes());
    for g in holds {
        h.update(g.hold_id.as_bytes());
        h.update(g.tenant_id.as_bytes());
        h.update(g.repo_id.as_bytes());
        h.update(g.incarnation_epoch.to_be_bytes());
        h.update(g.registered_seq.to_be_bytes());
        match g.state {
            GlobalHoldState::Active => h.update([1]),
            GlobalHoldState::Released { released_at_seq } => {
                h.update([2]);
                h.update(released_at_seq.to_be_bytes());
            }
            GlobalHoldState::Unknown => h.update([3]),
        }
        h.update((g.protected_pack_ids.len() as u64).to_be_bytes());
        for id in &g.protected_pack_ids {
            h.update(id.as_bytes());
        }
        h.update((g.protected_oids.len() as u64).to_be_bytes());
        for o in &g.protected_oids {
            encode_len_bytes(h, o.as_bytes());
        }
        h.update((g.protected_physical_keys.len() as u64).to_be_bytes());
        for k in &g.protected_physical_keys {
            encode_len_bytes(h, k.as_bytes());
        }
    }
}

fn encode_decisions(h: &mut Sha256, decisions: &[InFlightDecisionRecord]) {
    h.update((decisions.len() as u64).to_be_bytes());
    for d in decisions {
        h.update(d.decision_id.as_bytes());
        h.update([d.kind as u8, d.state as u8]);
        h.update(d.snapshot_seq.to_be_bytes());
        h.update((d.protected_pack_ids.len() as u64).to_be_bytes());
        for id in &d.protected_pack_ids {
            h.update(id.as_bytes());
        }
        h.update((d.protected_oids.len() as u64).to_be_bytes());
        for o in &d.protected_oids {
            encode_len_bytes(h, o.as_bytes());
        }
    }
}

fn encode_cursors(h: &mut Sha256, c: &PairedCursorReconciliation) {
    encode_freshness(h, c.pg_freshness);
    encode_freshness(h, c.refcas_freshness);
    h.update(c.pg_applied_seq.to_be_bytes());
    h.update(c.pg_required_seq.to_be_bytes());
    h.update(c.refcas_applied_index.to_be_bytes());
    h.update(c.refcas_required_index.to_be_bytes());
}

fn encode_freshness(h: &mut Sha256, f: SourceFreshness) {
    match f {
        SourceFreshness::Reconciled => h.update([1]),
        SourceFreshness::Unknown => h.update([2]),
        SourceFreshness::Stale => h.update([3]),
        SourceFreshness::Lagging { behind_seq } => {
            h.update([4]);
            h.update(behind_seq.to_be_bytes());
        }
        SourceFreshness::Unavailable => h.update([5]),
    }
}
