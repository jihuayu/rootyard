//! Three-party write freeze (app, worker, deleter), unknown in-flight drain,
//! durable backup closure/hold registration, and `CloseAuthScope` barriers (#153).

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, AppliedLogId, ApplyResponse, CancelCommand, CloseAuthScopeCommand,
    CreateSnapshotPinCommand, RefCasCommand, RefCasStateMachine, RegisterRootCommand, ScopeLifecycle,
    StateMachineError, WireHoldArtifactSpec, WireOperationIdentity,
};
use crate::ref_store::{GitObjectFormat, IssuerLane};

use super::types::{
    BackupRetentionHoldRecord, CloseScopeBarrierReceipt, FreezePartyStatus, PairedBackupError, sha256_json_tagged,
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
    pub pack_digests: Vec<String>,
    pub hold_specs: Vec<(String, i64, i64)>,
}

/// Coordinates tri-party backup freeze without pausing Raft consensus/elections.
#[derive(Clone, Debug)]
pub struct TriPartyBackupCoordinator {
    status: FreezePartyStatus,
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

    pub fn registered_holds(&self) -> &[BackupRetentionHoldRecord] {
        &self.registered_backup_holds
    }

    /// Freeze app, worker, and deleter; drain/settle unknown in-flight operations;
    /// register durable backup pin+holds+root before closing scopes; and capture
    /// immutable `CloseAuthScope` barrier receipts without stopping Raft consensus.
    pub fn freeze_drain_and_register(
        &mut self,
        sm: &mut RefCasStateMachine,
        log_term: u64,
        next_log_index: &mut u64,
        repos: &[RepoBackupRegistrationSpec],
        scope_authz_floor: i64,
        settle_unknown: bool,
    ) -> Result<Vec<CloseScopeBarrierReceipt>, PairedBackupError> {
        if repos.is_empty() || scope_authz_floor <= 0 {
            return Err(PairedBackupError::InvalidArgument("repos must be non-empty and authz_floor positive"));
        }
        self.status.deleter_fenced = true;
        self.status.fenced_deleter_epoch = self.status.fenced_deleter_epoch.saturating_add(1);
        self.status.app_paused = true;
        self.status.app_fence_seq = self.status.app_fence_seq.saturating_add(1);
        self.status.worker_paused = true;

        let unresolved_raw = self.in_flight.iter().filter(|op| !op.settled_committed).count();
        if unresolved_raw > 0 && !settle_unknown {
            return Err(PairedBackupError::UnknownInFlightOperations(unresolved_raw));
        }

        let mut drained = Vec::new();
        for op in self.in_flight.drain(..) {
            if op.settled_committed {
                self.status.worker_drain_settled += 1;
            } else {
                *next_log_index += 1;
                let tick = sm.logical_clock_floor().saturating_add(1);
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
                sm.apply(AppliedLogId { term: log_term, index: *next_log_index }, cmd)
                    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
                self.status.unknown_ops_resolved += 1;
            }
            drained.push(op.operation_id);
        }

        self.registered_backup_holds.clear();
        for spec in repos {
            let hold_rec = self.register_backup_closure_hold(sm, log_term, next_log_index, spec)?;
            self.registered_backup_holds.push(hold_rec);
        }

        let mut close_receipts = Vec::new();
        for spec in repos {
            let mut scope_ids = BTreeSet::new();
            scope_ids.insert(("repo_lifecycle", spec.repository_id));
            scope_ids.insert(("authority", spec.authority_id));
            for (kind, sid) in scope_ids {
                *next_log_index += 1;
                let log_id = AppliedLogId { term: log_term, index: *next_log_index };
                let cmd = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
                    scope_kind: kind.to_owned(),
                    scope_id: sid,
                    repository_id: Some(spec.repository_id),
                    tenant_id: Some(spec.tenant_id),
                    lifecycle: ScopeLifecycle::Closed,
                    authz_floor: scope_authz_floor,
                    change_id: Uuid::new_v4(),
                    logical_tick: sm.logical_clock_floor().saturating_add(1),
                });
                let resp = sm.apply(log_id, cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
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
        Ok(close_receipts)
    }

    pub fn unfreeze_after_backup(&mut self) -> Result<(), PairedBackupError> {
        if self.registered_backup_holds.is_empty() {
            return Err(PairedBackupError::IncompleteCut(
                "cannot unfreeze before durable backup closure/hold is registered",
            ));
        }
        self.status.app_paused = false;
        self.status.worker_paused = false;
        self.status.deleter_fenced = false;
        Ok(())
    }

    pub(super) fn register_backup_closure_hold(
        &self,
        sm: &mut RefCasStateMachine,
        log_term: u64,
        next_log_index: &mut u64,
        spec: &RepoBackupRegistrationSpec,
    ) -> Result<BackupRetentionHoldRecord, PairedBackupError> {
        let gate_ver = sm
            .read_gate_version(spec.repository_id)
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?
            .ok_or_else(|| PairedBackupError::StateMachine("missing repository gate before backup hold".into()))?;
        let gate_digest = gate_ver.digest().as_hex();
        let snap_id = Uuid::new_v4();
        let pin_id = Uuid::new_v4();
        let root_id = Uuid::new_v4();
        let mut hold_ids = Vec::with_capacity(spec.hold_specs.len());
        let mut wire_specs = Vec::with_capacity(spec.hold_specs.len());
        for (slot, (digest, decl_b, log_b)) in spec.hold_specs.iter().enumerate() {
            let slot_i16 = i16::try_from(slot)
                .map_err(|_| PairedBackupError::InvalidArgument("backup hold slot exceeds i16::MAX"))?;
            let hid = Uuid::new_v4();
            hold_ids.push(hid);
            wire_specs.push(WireHoldArtifactSpec {
                hold_id: hid,
                slot: slot_i16,
                artifact_digest: digest.clone(),
                declared_bytes: *decl_b,
                logical_bytes: *log_b,
            });
        }
        let req_digest =
            |tag: &str| RequestDigest::of(tag, &[spec.repository_id.as_bytes(), snap_id.as_bytes()]).as_hex();

        *next_log_index += 1;
        let tick = sm.logical_clock_floor().saturating_add(1);
        sm.apply(
            AppliedLogId { term: log_term, index: *next_log_index },
            RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
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
                pack_digests: spec.pack_digests.clone(),
                request_digest: req_digest("backup-pin"),
            }),
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

        let consume_req = Uuid::new_v4();
        *next_log_index += 1;
        sm.apply(
            AppliedLogId { term: log_term, index: *next_log_index },
            RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
                request_id: Uuid::new_v4(),
                consume_request_id: consume_req,
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
            }),
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

        let refs_map = sm.read_refs(spec.repository_id);
        let refs_digest = sha256_json_tagged(b"backup-refs", &refs_map)?;
        let pack_set_digest = sha256_json_tagged(b"backup-packs", &spec.pack_digests)?;
        let sel_digest = sha256_json_tagged(b"backup-sel", &BTreeMap::from([("pin", pin_id)]))?;
        *next_log_index += 1;
        sm.apply(
            AppliedLogId { term: log_term, index: *next_log_index },
            RefCasCommand::RegisterRoot(RegisterRootCommand {
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
                pack_set_digest,
                bound_hold_ids: hold_ids.clone(),
                register_digest: req_digest("backup-register"),
                request_digest: req_digest("backup-root-req"),
            }),
        )
        .map_err(|e: StateMachineError| PairedBackupError::StateMachine(e.to_string()))?;

        Ok(BackupRetentionHoldRecord {
            repository_id: spec.repository_id,
            tenant_id: spec.tenant_id,
            snapshot_id: snap_id,
            pin_id,
            pin_generation: 1,
            root_id,
            hold_ids,
            raft_log_index: *next_log_index,
        })
    }
}
