//! Three-party write freeze (app, worker, deleter), unknown in-flight drain,
//! durable WAL/quorum backup closure/hold registration, `CloseAuthScope` barriers,
//! and receipt-gated thaw (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use uuid::Uuid;

use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, ApplyResponse, CancelCommand, CloseAuthScopeCommand, CreateSnapshotPinCommand,
    RefCasCommand, RegisterRootCommand, ScopeLifecycle, SmHoldState, SmRootState, WireHoldArtifactSpec,
    WireOperationIdentity,
};
use crate::ref_store::{GitObjectFormat, IssuerLane};

use super::backup::stream_sha256_file;
use super::closure_bind::{compute_canonical_pack_set_digest, verify_registration_spec_completeness};
use super::raft_barrier::{
    DurableFreezeBarrierProof, DurableRaftApplyReceipt, DurableRaftBackend, SealedArchiveReceipt,
};
use super::types::{
    BackupRetentionHoldRecord, COMPLETE_MARKER, CloseScopeBarrierReceipt, ExpectedPackPairSpec, FreezePartyStatus,
    PairedBackupError, sha256_json_tagged,
};

#[derive(Clone, Debug)]
pub struct InFlightOperation {
    pub repository_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: IssuerLane,
    pub sequence: i64,
    pub operation_id: Uuid,
    pub request_digest: String,
    pub decision_id: Option<Uuid>,
    pub settled_committed: bool,
}

#[derive(Clone, Debug)]
pub struct RepoBackupRegistrationSpec {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub backend_identity: String,
    pub expected_packs: Vec<ExpectedPackPairSpec>,
}

/// Coordinates tri-party backup freeze/thaw gated on durable Raft WAL/quorum state
/// and verified archive sealing receipts, without pausing Raft consensus/elections.
#[derive(Clone, Debug)]
pub struct TriPartyBackupCoordinator {
    status: FreezePartyStatus,
    active_barrier: Option<DurableFreezeBarrierProof>,
    registered_backup_holds: Vec<BackupRetentionHoldRecord>,
    in_flight: Vec<InFlightOperation>,
}

impl TriPartyBackupCoordinator {
    pub fn new(fenced_deleter_epoch: u64, app_fence_seq: u64) -> Self {
        Self {
            status: FreezePartyStatus {
                app_paused: false,
                worker_paused: false,
                deleter_fenced: false,
                consensus_replication_active: true,
                leader_election_active: true,
                fenced_deleter_epoch,
                app_fence_seq,
                worker_drain_settled: 0,
                unknown_ops_resolved: 0,
            },
            active_barrier: None,
            registered_backup_holds: Vec::new(),
            in_flight: Vec::new(),
        }
    }

    pub fn track_in_flight(&mut self, op: InFlightOperation) {
        self.in_flight.push(op);
    }

    pub fn admit_app_write(&self) -> Result<(), PairedBackupError> {
        if self.status.app_paused {
            return Err(PairedBackupError::FreezeNotHeld("app writes frozen for paired backup barrier"));
        }
        Ok(())
    }

    pub fn admit_worker_lease(&self) -> Result<(), PairedBackupError> {
        if self.status.worker_paused {
            return Err(PairedBackupError::FreezeNotHeld("background workers frozen for paired backup barrier"));
        }
        Ok(())
    }

    pub fn admit_deleter(&self, deleter_epoch: u64) -> Result<(), PairedBackupError> {
        if self.status.deleter_fenced || deleter_epoch < self.status.fenced_deleter_epoch {
            return Err(PairedBackupError::DeleterNotFenced("deleter fenced during backup or superseded epoch"));
        }
        Ok(())
    }

    pub fn status(&self) -> &FreezePartyStatus {
        &self.status
    }

    pub fn active_barrier(&self) -> Option<&DurableFreezeBarrierProof> {
        self.active_barrier.as_ref()
    }

    pub fn registered_holds(&self) -> &[BackupRetentionHoldRecord] {
        &self.registered_backup_holds
    }

    /// Freeze app, worker, and deleter; drain/settle unknown in-flight operations;
    /// register durable backup pin+holds+root (both `.pack` and `.idx`); close scopes;
    /// and verify durable Raft WAL snapshot before committing the freeze barrier.
    pub fn freeze_drain_and_register(
        &mut self,
        raft: &mut impl DurableRaftBackend,
        repos: &[RepoBackupRegistrationSpec],
        scope_authz_floor: i64,
        settle_unknown: bool,
    ) -> Result<DurableFreezeBarrierProof, PairedBackupError> {
        if repos.is_empty() || scope_authz_floor <= 0 {
            return Err(PairedBackupError::InvalidArgument("repos must be non-empty and authz_floor positive"));
        }
        let unresolved_raw = self.in_flight.iter().filter(|op| !op.settled_committed).count();
        if unresolved_raw > 0 && !settle_unknown {
            return Err(PairedBackupError::UnknownInFlightOperations(unresolved_raw));
        }

        let mut next_status = self.status.clone();
        next_status.deleter_fenced = true;
        next_status.fenced_deleter_epoch = next_status.fenced_deleter_epoch.saturating_add(1);
        next_status.app_paused = true;
        next_status.app_fence_seq = next_status.app_fence_seq.saturating_add(1);
        next_status.worker_paused = true;

        let mut apply_receipts: Vec<DurableRaftApplyReceipt> = Vec::new();
        let pending_ops = self.in_flight.clone();
        for op in pending_ops {
            if op.settled_committed {
                next_status.worker_drain_settled += 1;
            } else {
                let tick = raft.durable_state_machine().logical_clock_floor().saturating_add(1);
                let cmd = RefCasCommand::Cancel(CancelCommand {
                    identity: WireOperationIdentity {
                        repository_id: op.repository_id,
                        issuer_id: op.issuer_id,
                        lane: op.lane.as_str().to_owned(),
                        sequence: op.sequence,
                        operation_id: op.operation_id,
                        digest: op.request_digest,
                    },
                    reason: Some("paired_backup_drain_unknown".into()),
                    logical_tick: tick,
                });
                let (receipt, _) = raft.commit_and_apply(cmd)?;
                receipt.verify(None)?;
                apply_receipts.push(receipt);
                next_status.unknown_ops_resolved += 1;
            }
        }

        let mut holds = Vec::with_capacity(repos.len());
        for spec in repos {
            let hold_rec = self.register_backup_closure_hold(raft, spec, &mut apply_receipts)?;
            holds.push(hold_rec);
        }

        let mut close_receipts = Vec::new();
        for spec in repos {
            let mut scope_ids = BTreeSet::new();
            scope_ids.insert(("repo_lifecycle", spec.repository_id));
            scope_ids.insert(("authority", spec.authority_id));
            for (kind, sid) in scope_ids {
                let tick = raft.durable_state_machine().logical_clock_floor().saturating_add(1);
                let cmd = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
                    scope_kind: kind.to_owned(),
                    scope_id: sid,
                    repository_id: Some(spec.repository_id),
                    tenant_id: Some(spec.tenant_id),
                    lifecycle: ScopeLifecycle::Closed,
                    authz_floor: scope_authz_floor,
                    change_id: Uuid::new_v4(),
                    logical_tick: tick,
                });
                let (apply_rec, resp) = raft.commit_and_apply(cmd)?;
                apply_rec.verify(None)?;
                let log_id = apply_rec.log_id;
                apply_receipts.push(apply_rec);

                let ApplyResponse::AuthScopeClosed {
                    scope_kind,
                    scope_id,
                    lifecycle,
                    authz_floor,
                    open_decision_ids,
                    pending_operation_ids,
                    ..
                } = resp
                else {
                    return Err(PairedBackupError::StateMachine("unexpected response for CloseAuthScope".into()));
                };
                if !open_decision_ids.is_empty() || !pending_operation_ids.is_empty() {
                    return Err(PairedBackupError::UnknownInFlightOperations(
                        open_decision_ids.len() + pending_operation_ids.len(),
                    ));
                }
                let receipt = CloseScopeBarrierReceipt {
                    scope_kind,
                    scope_id,
                    repository_id: Some(spec.repository_id),
                    tenant_id: Some(spec.tenant_id),
                    lifecycle,
                    authz_floor,
                    raft_log_index: log_id.index,
                    raft_log_term: log_id.term,
                    pending_operation_ids,
                    open_decision_ids,
                    receipt_digest: String::new(),
                }
                .seal()?;
                receipt.verify()?;
                close_receipts.push(receipt);
            }
        }

        let (durable_snap, durable_digest) = raft.durable_state()?;
        let barrier_log_id =
            apply_receipts.last().map(|r| r.log_id).ok_or(PairedBackupError::FreezeNotHeld("empty barrier log"))?;
        let proof = DurableFreezeBarrierProof {
            barrier_id: Uuid::new_v4(),
            status: next_status.clone(),
            barrier_log_id,
            barrier_state_digest: durable_digest.clone(),
            apply_receipts,
            close_receipts,
            backup_holds: holds.clone(),
            proof_digest: String::new(),
        }
        .seal()?;
        proof.verify_against_raft(&durable_snap, &durable_digest)?;

        self.in_flight.clear();
        self.status = next_status;
        self.registered_backup_holds = holds;
        self.active_barrier = Some(proof.clone());
        Ok(proof)
    }

    /// Thaw app, worker, and deleter ONLY after verifying the active durable freeze barrier,
    /// the sealed archive receipt, on-disk `verify_backup_archive` (`COMPLETE` + manifest + Blobs),
    /// and durable Raft WAL state preserving active backup holds/roots and closed auth scopes.
    pub fn unfreeze_after_backup(
        &mut self,
        raft: &dyn DurableRaftBackend,
        archive_dir: &Path,
        seal_receipt: &SealedArchiveReceipt,
    ) -> Result<(), PairedBackupError> {
        let barrier = self
            .active_barrier
            .as_ref()
            .ok_or(PairedBackupError::FreezeNotHeld("cannot unfreeze without an active durable freeze barrier"))?;
        barrier.verify()?;
        seal_receipt.verify()?;
        if seal_receipt.barrier_id != barrier.barrier_id
            || seal_receipt.fenced_deleter_epoch != barrier.status.fenced_deleter_epoch
            || seal_receipt.app_fence_seq != barrier.status.app_fence_seq
            || seal_receipt.barrier_log_id != barrier.barrier_log_id
            || seal_receipt.barrier_state_digest != barrier.barrier_state_digest
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "sealed archive receipt does not match active durable freeze barrier",
            ));
        }

        let manifest = super::restore::verify_backup_archive(archive_dir, None)?;
        let (_, complete_sha) = stream_sha256_file(&archive_dir.join(COMPLETE_MARKER))?;
        if manifest.backup_id != seal_receipt.backup_id
            || manifest.paired_cut_digest != seal_receipt.paired_cut_digest
            || complete_sha != seal_receipt.complete_marker_sha256
        {
            return Err(PairedBackupError::IncompleteCut(
                "archive manifest or COMPLETE marker disagrees with SealedArchiveReceipt",
            ));
        }

        let (durable_snap, _) = raft.durable_state()?;
        durable_snap.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let Some(last_durable) = durable_snap.body.last_applied else {
            return Err(PairedBackupError::FreezeNotHeld("durable Raft WAL has no applied entries at thaw"));
        };
        if (last_durable.term, last_durable.index) < (barrier.barrier_log_id.term, barrier.barrier_log_id.index) {
            return Err(PairedBackupError::FreezeNotHeld(
                "durable Raft WAL lags behind freeze barrier log_id; refusing thaw on volatile apply",
            ));
        }
        for rid in &seal_receipt.root_ids {
            if !durable_snap.body.roots.iter().any(|r| r.root_id == *rid && r.state == SmRootState::Active) {
                return Err(PairedBackupError::FreezeNotHeld(
                    "backup retention root missing or inactive in durable WAL",
                ));
            }
        }
        for hid in &seal_receipt.hold_ids {
            if !durable_snap.body.holds.iter().any(|h| h.hold_id == *hid && h.state != SmHoldState::Retired) {
                return Err(PairedBackupError::FreezeNotHeld("backup hold missing or retired in durable WAL"));
            }
        }
        for cr in &barrier.close_receipts {
            let found = durable_snap.body.scope_floors.iter().any(|s| {
                s.key.scope_kind == cr.scope_kind
                    && s.key.scope_id == cr.scope_id
                    && s.lifecycle == ScopeLifecycle::Closed
                    && s.authz_floor >= cr.authz_floor
            });
            if !found {
                return Err(PairedBackupError::ScopeNotClosed(
                    "closed auth scope missing from durable WAL at thaw".into(),
                ));
            }
        }

        self.status.app_paused = false;
        self.status.worker_paused = false;
        self.status.deleter_fenced = false;
        self.active_barrier = None;
        Ok(())
    }

    pub(super) fn register_backup_closure_hold(
        &self,
        raft: &mut impl DurableRaftBackend,
        spec: &RepoBackupRegistrationSpec,
        apply_receipts: &mut Vec<DurableRaftApplyReceipt>,
    ) -> Result<BackupRetentionHoldRecord, PairedBackupError> {
        let pack_set_digest = compute_canonical_pack_set_digest(&spec.expected_packs)?;
        let mut sorted_packs = spec.expected_packs.clone();
        sorted_packs.sort();

        let pre_snap =
            raft.durable_state_machine().snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let pack_digests = verify_registration_spec_completeness(&pre_snap, spec.repository_id, &sorted_packs)?;

        let gate_ver = raft
            .durable_state_machine()
            .read_gate_version(spec.repository_id)
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?
            .ok_or_else(|| PairedBackupError::StateMachine("missing repository gate before backup hold".into()))?;
        let gate_digest = gate_ver.digest().as_hex();
        let (snap_id, pin_id, root_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut hold_ids = Vec::with_capacity(sorted_packs.len() * 2);
        let mut wire_specs = Vec::with_capacity(sorted_packs.len() * 2);
        for (idx, (digest, bytes)) in sorted_packs
            .iter()
            .flat_map(|p| [(p.pack_sha256.as_str(), p.pack_bytes), (p.idx_sha256.as_str(), p.idx_bytes)])
            .enumerate()
        {
            let slot_i16 = i16::try_from(idx)
                .map_err(|_| PairedBackupError::InvalidArgument("backup hold slot exceeds i16::MAX"))?;
            let decl_b = i64::try_from(bytes)
                .map_err(|_| PairedBackupError::InvalidArgument("artifact byte length exceeds i64::MAX"))?;
            let hid = Uuid::new_v4();
            hold_ids.push(hid);
            wire_specs.push(WireHoldArtifactSpec {
                hold_id: hid,
                slot: slot_i16,
                artifact_digest: digest.to_owned(),
                declared_bytes: decl_b,
                logical_bytes: decl_b,
            });
        }
        let req_digest =
            |tag: &str| RequestDigest::of(tag, &[spec.repository_id.as_bytes(), snap_id.as_bytes()]).as_hex();

        let tick = raft.durable_state_machine().logical_clock_floor().saturating_add(1);
        let (pin_rec, _) = raft.commit_and_apply(RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
            request_id: Uuid::new_v4(),
            repository_id: spec.repository_id,
            tenant_id: spec.tenant_id,
            owner_id: spec.owner_id,
            purpose: MetadataPinPurpose::Backup,
            snapshot_id: snap_id,
            pin_id,
            object_format: spec.object_format,
            history_incarnation: spec.history_incarnation,
            authority_epoch: spec.authority_epoch,
            group_epoch: spec.group_epoch,
            expected_gate_digest: gate_digest.clone(),
            lease_ticks: 3600,
            logical_tick: tick,
            pack_digests,
            request_digest: req_digest("backup-pin"),
        }))?;
        pin_rec.verify(None)?;
        apply_receipts.push(pin_rec);

        let (hold_rec, _) = raft.commit_and_apply(RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: Uuid::new_v4(),
            consume_request_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            repository_id: spec.repository_id,
            tenant_id: spec.tenant_id,
            owner_id: spec.owner_id,
            authority_id: spec.authority_id,
            authority_generation: spec.authority_generation,
            purpose: "ref_publication".into(),
            backend_identity: spec.backend_identity.clone(),
            expected_gate_digest: gate_digest,
            artifacts: wire_specs,
        }))?;
        hold_rec.verify(None)?;
        apply_receipts.push(hold_rec);

        let refs_map = raft.durable_state_machine().read_refs(spec.repository_id);
        let refs_digest = sha256_json_tagged(b"backup-refs", &refs_map)?;
        let sel_digest = sha256_json_tagged(b"backup-sel", &BTreeMap::from([("pin", pin_id)]))?;
        let (root_rec, _) = raft.commit_and_apply(RefCasCommand::RegisterRoot(RegisterRootCommand {
            request_id: Uuid::new_v4(),
            root_id,
            operation_id: Uuid::new_v4(),
            repository_id: spec.repository_id,
            tenant_id: spec.tenant_id,
            owner_id: spec.owner_id,
            purpose: "backup".into(),
            business_intent_digest: req_digest("backup-intent"),
            object_format: spec.object_format,
            history_incarnation: spec.history_incarnation,
            authority_epoch: spec.authority_epoch,
            group_epoch: spec.group_epoch,
            source_snapshot_id: snap_id,
            source_pin_id: pin_id,
            source_pin_generation: 1,
            selector_kind: "snapshot".into(),
            selector_digest: sel_digest,
            refs_digest,
            pack_set_digest: pack_set_digest.clone(),
            bound_hold_ids: hold_ids.clone(),
            register_digest: req_digest("backup-register"),
            request_digest: req_digest("backup-root-req"),
        }))?;
        root_rec.verify(None)?;
        let raft_log_index = root_rec.log_id.index;
        apply_receipts.push(root_rec);

        Ok(BackupRetentionHoldRecord {
            repository_id: spec.repository_id,
            tenant_id: spec.tenant_id,
            snapshot_id: snap_id,
            pin_id,
            pin_generation: 1,
            root_id,
            hold_ids,
            pack_set_digest,
            raft_log_index,
        })
    }
}
