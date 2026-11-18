//! Authoritative live-barrier & active step-fence verification (#122).

use std::collections::BTreeSet;

use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    domain::{DeleteAuthorizationTicket, GcAuditEvent, StagedUploadState},
    model::{AuthorityLane, CandidatePackTarget, DecisionState, GlobalHoldState, LiveRefRoot, SourceFreshness},
    proof::{DeletionProof, seal_group_receipt},
    retention_bridge::{PackCoverBridgeInputs, build_pack_cover_retention_index, require_pack_cover_gc_eligible},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot},
};

impl DurableSafeGcAuthority {
    pub fn verify_active_step_ticket(&self, ticket: &DeleteAuthorizationTicket) -> Result<(), SafeGcError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if ticket.is_staging_cleanup_only() {
            return guard.verify_staging_cleanup_ticket(ticket);
        }
        let Some(batch) = guard.pending_delete.as_ref().filter(|b| b.batch_id == ticket.batch_id()) else {
            return Err(SafeGcError::StaleDeleterFenced("pending delete batch absent or completed during delete"));
        };
        if batch.incarnation_id != guard.authority.incarnation_id
            || batch.incarnation_epoch != guard.authority.incarnation_epoch
            || batch.lease_epoch != guard.authority.lease_epoch
            || ticket.lease_epoch() != guard.authority.lease_epoch
        {
            return Err(SafeGcError::StaleDeleterFenced(
                "batch or ticket epoch does not exactly equal live authority epoch",
            ));
        }
        if batch.active_step_fence.as_ref() != Some(&(ticket.step_fence_id(), ticket.physical_key().to_owned())) {
            return Err(SafeGcError::StaleDeleterFenced("active step fence superseded or cleared"));
        }
        guard.require_live_barrier(
            ticket.incarnation_id(),
            ticket.incarnation_epoch(),
            ticket.lease_epoch(),
            &batch.proof,
        )?;
        if guard.authority.membership_generation != ticket.membership_generation()
            || guard.compute_membership_digest() != ticket.membership_digest()
        {
            return Err(SafeGcError::MembershipOrRootDrift("membership drifted after step ticket mint".into()));
        }
        guard.key_registry.assert_delete_allowed(ticket.physical_key(), ticket.incarnation_epoch())?;
        let matching_loc =
            guard.retired_packs.iter().find(|p| p.pack_id == ticket.pack_id()).and_then(|p| match ticket.key_role() {
                "pack" if p.pack_key.object_path == ticket.physical_key() => Some(&p.pack_locator),
                "idx" if p.idx_key.object_path == ticket.physical_key() => Some(&p.idx_locator),
                _ => None,
            });
        if matching_loc != Some(ticket.locator()) {
            return Err(SafeGcError::StaleDeleterFenced("retired locator drifted after ticket mint"));
        }
        Ok(())
    }
}

impl SafeGcRepoSnapshot {
    pub(super) fn register_initial_keys(&mut self) -> Result<(), SafeGcError> {
        for p in self.active_packs.iter().chain(self.retired_packs.iter()) {
            if !self.key_registry.keys_by_path.contains_key(&p.pack_key.object_path) {
                self.key_registry.register_verified_key(p.pack_key.clone())?;
            }
            if !self.key_registry.keys_by_path.contains_key(&p.idx_key.object_path) {
                self.key_registry.register_verified_key(p.idx_key.clone())?;
            }
        }
        Ok(())
    }

    pub(super) fn refresh_group_receipts_quiescence(&mut self) -> Result<(), SafeGcError> {
        let cur_gen = self.authority.membership_generation;
        self.reader_leases.refresh_drain_watermark(cur_gen);
        for idx in 0..self.group_receipts.len() {
            let cur = &self.group_receipts[idx];
            let min_active =
                self.reader_leases.active_leases.values().map(|l| l.pinned_generation).min().unwrap_or(cur_gen);
            let blocking =
                self.reader_leases.blocking_readers_for_packs(&cur.retired_pack_ids, cur.retired_at_generation);
            let rq = &cur.reader_quiescence;
            if rq.observed_seq > 0
                && rq.min_active_reader_generation == min_active
                && rq.active_blocking_readers == blocking
                && rq.drain_watermark_generation == self.reader_leases.completed_drain_generation
                && rq.pg_exclusive_reader_barrier_epoch == self.reader_leases.pg_exclusive_barrier_epoch
            {
                continue;
            }
            let retired_ids = cur.retired_pack_ids.clone();
            let ret_gen = cur.retired_at_generation;
            let obs = self.reader_leases.observe_for_retirement(&retired_ids, ret_gen, cur_gen)?;
            let mut updated = self.group_receipts[idx].clone();
            updated.reader_quiescence = obs;
            self.group_receipts[idx] = seal_group_receipt(updated)?;
        }
        Ok(())
    }

    pub(super) fn verify_staging_cleanup_ticket(&self, ticket: &DeleteAuthorizationTicket) -> Result<(), SafeGcError> {
        let arm = self.gc_mode.require_armed()?;
        if ticket.proof_digest() != arm.arm_digest
            || arm.incarnation_id != self.authority.incarnation_id
            || arm.incarnation_epoch != self.authority.incarnation_epoch
            || self.authority.incarnation_id != ticket.incarnation_id()
            || self.authority.incarnation_epoch != ticket.incarnation_epoch()
            || self.authority.lease_epoch != ticket.lease_epoch()
        {
            return Err(SafeGcError::StaleDeleterFenced(
                "staging cleanup ticket fenced by exact epoch or arm_digest mismatch",
            ));
        }
        if self
            .active_packs
            .iter()
            .chain(self.retired_packs.iter())
            .any(|p| p.pack_key.object_path == ticket.physical_key() || p.idx_key.object_path == ticket.physical_key())
        {
            return Err(SafeGcError::ProtectionOverlap("staging cleanup refused on serving/retired key".into()));
        }
        let st = self.key_registry.keys_by_path.get(ticket.physical_key()).map(|k| k.state);
        if st != Some(KeyLifecycleState::CompactionStaging) {
            return Err(SafeGcError::ProtectionOverlap("staging cleanup requires CompactionStaging state".into()));
        }
        let exists = self.staged_uploads.iter().any(|u| {
            u.op_id == ticket.batch_id()
                && u.state == StagedUploadState::AbandonedPendingCleanup
                && ((u.pack_key.object_path == ticket.physical_key() && &u.pack_locator == ticket.locator())
                    || (u.idx_key.object_path == ticket.physical_key() && &u.idx_locator == ticket.locator()))
        });
        if !exists {
            return Err(SafeGcError::StaleDeleterFenced("abandoned staging upload record missing"));
        }
        Ok(())
    }

    pub(super) fn push_audit(&mut self, action: &str, target: &str) {
        let seq = self.audit_log.last().map_or(1, |e| e.seq + 1);
        self.audit_log.push(GcAuditEvent {
            seq,
            incarnation_epoch: self.authority.incarnation_epoch,
            action: action.to_owned(),
            target: target.to_owned(),
        });
    }

    pub(super) fn require_live_barrier(
        &self,
        deleter_incarnation_id: Uuid,
        deleter_incarnation_epoch: u64,
        deleter_lease_epoch: u64,
        proof: &DeletionProof,
    ) -> Result<(), SafeGcError> {
        let arm = self.gc_mode.require_armed()?;
        if proof.tenant_id != self.authority.tenant_id
            || proof.repo_id != self.authority.repo_id
            || proof.history_id != self.authority.history_id
            || proof.object_format != self.object_format
        {
            return Err(SafeGcError::IncompleteProof("deletion proof scope/format disagrees with live repository"));
        }
        if deleter_incarnation_epoch != self.authority.incarnation_epoch
            || deleter_incarnation_id != self.authority.incarnation_id
            || arm.incarnation_epoch != self.authority.incarnation_epoch
            || proof.incarnation_id != self.authority.incarnation_id
            || proof.incarnation_epoch != self.authority.incarnation_epoch
        {
            return Err(SafeGcError::StaleIncarnation("authority incarnation rotated"));
        }
        if deleter_lease_epoch != self.authority.lease_epoch {
            return Err(SafeGcError::StaleDeleterFenced(
                "deleter lease_epoch does not exactly equal live authority lease_epoch",
            ));
        }
        if proof.lane != arm.lane {
            return Err(SafeGcError::DistributedPrereqsMissing("proof lane disagrees with armed authority lane"));
        }
        if let AuthorityLane::SingleNodePg { pg_gc_fence_epoch, reader_barrier_epoch, .. } = arm.lane
            && (pg_gc_fence_epoch != reader_barrier_epoch
                || self.reader_leases.pg_exclusive_barrier_epoch != Some(reader_barrier_epoch))
        {
            return Err(SafeGcError::StaleDeleterFenced(
                "SingleNodePg live fence epoch does not exactly equal armed barrier epoch",
            ));
        }
        if (proof.reader_quiescence.pg_exclusive_reader_barrier_epoch.is_some()
            || self.reader_leases.pg_exclusive_barrier_epoch.is_some())
            && (proof.reader_quiescence.pg_exclusive_reader_barrier_epoch.is_none()
                || proof.reader_quiescence.pg_exclusive_reader_barrier_epoch
                    != self.reader_leases.pg_exclusive_barrier_epoch)
        {
            return Err(SafeGcError::StaleDeleterFenced(
                "live PG gc_epoch fence missing or does not exactly equal deletion proof barrier epoch",
            ));
        }
        if proof.membership_generation != self.authority.membership_generation
            || proof.membership_digest != self.compute_membership_digest()
        {
            return Err(SafeGcError::MembershipOrRootDrift("membership generation/digest drifted after proof".into()));
        }
        if self.authority.live_ref_seq != proof.live_ref_seq
            || sorted_refs(&self.live_refs) != sorted_refs(&proof.live_refs)
        {
            return Err(SafeGcError::ConcurrentRetentionRace("live refs mutated or omitted from proof"));
        }
        arm.lane.verify_cursor_coverage(
            self.authority.history_id,
            self.authority.live_ref_seq,
            &self.paired_cursors,
        )?;
        self.verify_authoritative_candidates_and_live_state(proof, &arm.lane)
    }

    fn verify_authoritative_candidates_and_live_state(
        &self,
        proof: &DeletionProof,
        lane: &AuthorityLane,
    ) -> Result<(), SafeGcError> {
        let require_pg_barrier = matches!(lane, AuthorityLane::SingleNodePg { .. });
        proof.reader_quiescence.verify_quiesced(require_pg_barrier)?;
        for pg_gr in &proof.group_receipts {
            if !self.group_receipts.iter().any(|live_gr| live_gr == pg_gr) {
                return Err(SafeGcError::IncompleteProof("proof group receipt missing or drifted from authority"));
            }
            for &rep_id in &pg_gr.replacement_pack_ids {
                if !self.replacement_reaches_active_closure(rep_id, 0) {
                    return Err(SafeGcError::IncompleteProof("replacement pack closure is no longer live"));
                }
            }
        }
        let cand_ids: BTreeSet<Uuid> = proof.candidates.iter().map(|c| c.pack_id).collect();
        let cand_id_vec: Vec<Uuid> = cand_ids.iter().copied().collect();
        if self.reader_leases.blocking_readers_for_packs(&cand_id_vec, self.authority.membership_generation) > 0 {
            return Err(SafeGcError::ReaderQuiescenceUnverified("concurrent reader lease blocks candidate pack"));
        }
        for c in &proof.candidates {
            verify_candidate_matches_retired(self, c)?;
        }
        self.check_live_holds_producers_and_pack_cover(proof, lane, &cand_ids)
    }

    fn replacement_reaches_active_closure(&self, pack_id: Uuid, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        if self.active_packs.iter().any(|p| p.pack_id == pack_id) {
            return true;
        }
        self.group_receipts
            .iter()
            .filter(|gr| gr.replacement_closure_verified && gr.retired_pack_ids.contains(&pack_id))
            .any(|gr| {
                !gr.replacement_pack_ids.is_empty()
                    && gr
                        .replacement_pack_ids
                        .iter()
                        .all(|&next| self.replacement_reaches_active_closure(next, depth + 1))
            })
    }

    fn check_live_holds_producers_and_pack_cover(
        &self,
        proof: &DeletionProof,
        lane: &AuthorityLane,
        cand_ids: &BTreeSet<Uuid>,
    ) -> Result<(), SafeGcError> {
        let active_oids: BTreeSet<&str> =
            self.active_packs.iter().flat_map(|p| p.contained_oids.iter().map(String::as_str)).collect();
        let cand_keys: BTreeSet<&str> = proof.candidates.iter().map(|c| c.physical_key.as_str()).collect();
        let cand_oids: BTreeSet<&str> = proof
            .candidates
            .iter()
            .flat_map(|c| c.contained_oids.iter().map(String::as_str))
            .filter(|o| !active_oids.contains(o))
            .collect();
        if self.active_packs.iter().any(|p| cand_ids.contains(&p.pack_id)) {
            return Err(SafeGcError::ProtectionOverlap("candidate is still in active serving set".into()));
        }
        if self.live_refs.iter().any(|r| cand_oids.contains(r.target_oid.as_str())) {
            return Err(SafeGcError::ConcurrentRetentionRace("live ref now references candidate"));
        }
        for p in &self.producers {
            if p.freshness != SourceFreshness::Reconciled
                || p.observed_cursor_seq < p.required_cursor_seq
                || p.authority_epoch != self.authority.incarnation_epoch
                || p.expected_authority_epoch != self.authority.incarnation_epoch
            {
                return Err(SafeGcError::ConcurrentRetentionRace("live producer lagged or epoch drifted"));
            }
            if p.pinned_pack_ids.iter().any(|id| cand_ids.contains(id))
                || p.root_oids.iter().any(|o| cand_oids.contains(o.as_str()))
            {
                return Err(SafeGcError::ConcurrentRetentionRace("producer concurrently pinned candidate"));
            }
        }
        for h in &self.global_holds {
            match h.state {
                GlobalHoldState::Unknown => return Err(SafeGcError::ConcurrentRetentionRace("live hold unknown")),
                GlobalHoldState::Active => {
                    if h.protected_pack_ids.iter().any(|id| cand_ids.contains(id))
                        || h.protected_physical_keys.iter().any(|k| cand_keys.contains(k.as_str()))
                        || h.protected_oids.iter().any(|o| cand_oids.contains(o.as_str()))
                    {
                        return Err(SafeGcError::ConcurrentRetentionRace("active global hold covers candidate"));
                    }
                }
                GlobalHoldState::Released { released_at_seq } => {
                    let is_dist = matches!(lane, AuthorityLane::DistributedRefCas { .. });
                    if released_at_seq > self.paired_cursors.pg_applied_seq
                        || (is_dist && released_at_seq > self.paired_cursors.refcas_applied_index)
                    {
                        return Err(SafeGcError::ConcurrentRetentionRace("release-before-register cursor gap"));
                    }
                }
            }
        }
        for d in &self.in_flight_decisions {
            if d.state == DecisionState::Unknown
                || (d.state == DecisionState::Pending
                    && (d.protected_pack_ids.iter().any(|id| cand_ids.contains(id))
                        || d.protected_oids.iter().any(|o| cand_oids.contains(o.as_str()))))
            {
                return Err(SafeGcError::ConcurrentRetentionRace("in-flight decision protects candidate"));
            }
        }
        if self.paired_cursors.pg_freshness != SourceFreshness::Reconciled
            || self.paired_cursors.pg_applied_seq < self.paired_cursors.pg_required_seq
            || self.paired_cursors.refcas_freshness != SourceFreshness::Reconciled
            || self.paired_cursors.refcas_applied_index < self.paired_cursors.refcas_required_index
        {
            return Err(SafeGcError::ConcurrentRetentionRace("paired cursors drifted/lagging"));
        }
        let active_leases: Vec<_> = self.reader_leases.active_leases.values().cloned().collect();
        let tombstoned_none = BTreeSet::new();
        let live_index = build_pack_cover_retention_index(&PackCoverBridgeInputs {
            incarnation_epoch: self.authority.incarnation_epoch,
            lane,
            live_refs: &self.live_refs,
            producers: &self.producers,
            global_holds: &self.global_holds,
            in_flight_decisions: &self.in_flight_decisions,
            paired_cursors: &self.paired_cursors,
            group_receipts: &self.group_receipts,
            reader_quiescence: &proof.reader_quiescence,
            active_reader_leases: &active_leases,
            tombstoned_pack_ids: &tombstoned_none,
        });
        for c in &proof.candidates {
            if self.key_registry.deleted_tombstones.contains(&c.physical_key) {
                continue;
            }
            let unreplaced: Vec<String> =
                c.contained_oids.iter().filter(|o| !active_oids.contains(o.as_str())).cloned().collect();
            let _ = require_pack_cover_gc_eligible(&live_index, c.pack_id, &unreplaced)?;
        }
        Ok(())
    }
}

fn verify_candidate_matches_retired(snap: &SafeGcRepoSnapshot, c: &CandidatePackTarget) -> Result<(), SafeGcError> {
    // Allow already-tombstoned keys during crash-recovery batch resumption when the other half of the pair is still pending.
    if snap.key_registry.deleted_tombstones.contains(&c.physical_key) {
        return Ok(());
    }
    let Some(ret) = snap.retired_packs.iter().find(|p| p.pack_id == c.pack_id && p.group_id == c.group_id) else {
        return Err(SafeGcError::IncompleteProof(
            "candidate pack_id/group_id missing from authoritative retired_packs",
        ));
    };
    let (key, loc) = match c.key_role.as_str() {
        "pack" => (&ret.pack_key, &ret.pack_locator),
        "idx" => (&ret.idx_key, &ret.idx_locator),
        _ => return Err(SafeGcError::InvalidInput("invalid candidate key_role".into())),
    };
    if c.physical_key != key.object_path
        || c.object_sha256 != key.object_sha256
        || c.remote_etag != loc.remote_etag
        || c.remote_version_id != loc.remote_version_id
        || c.key_epoch != key.incarnation_epoch
        || c.provider_generation != loc.generation
    {
        return Err(SafeGcError::IncompleteProof(
            "candidate physical key/digest/version/epoch disagrees with authority",
        ));
    }
    let exp_oids: BTreeSet<&str> = ret.contained_oids.iter().map(String::as_str).collect();
    let got_oids: BTreeSet<&str> = c.contained_oids.iter().map(String::as_str).collect();
    if exp_oids != got_oids {
        return Err(SafeGcError::IncompleteProof("candidate contained_oids disagrees with authoritative retired pack"));
    }
    Ok(())
}

fn sorted_refs(refs: &[LiveRefRoot]) -> BTreeSet<(&str, &str, u64)> {
    refs.iter().map(|r| (r.ref_name.as_str(), r.target_oid.as_str(), r.version_seq)).collect()
}
