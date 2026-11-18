//! Production wiring of the paired-backup freeze, restored-incarnation and deleter-epoch
//! guards into the live maintenance, projection-worker and pack-deleter paths (#153).

use std::time::Instant;

use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::blob_store::{BlobLocator, opendal::BlobStore};
use crate::ref_store::core::state_machine::{ApplyResponse, RefCasCommand};

use super::admission_guard::IncarnationAdmissionGuard;
use super::durable_guarded_ops::{execute_deleter_guarded, require_unfrozen_pg_and_raft};
use super::mtls_raft::MtlsLiveRaftBackend;
use super::pg_cutpoint::pg_err;
use super::pg_restore_admission::verify_pg_live_incarnation;
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::verify_cutpoint_attestations;
use super::types::{
    DecisionExecutionTicket, DeleterLeaseTicket, NewIncarnationAuthority, PairedBackupError, WriterGrantTicket,
};

/// One claimed `ref_cas_projection_jobs` step bound to the restored incarnation it projects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProjectionTicket {
    pub job_key: String,
    pub cluster_incarnation: Uuid,
    pub history_incarnation: Uuid,
    pub group_id: i64,
    pub group_epoch: i64,
    pub authz_epoch: i64,
    pub applied_event_seq: u64,
}

impl WorkerProjectionTicket {
    pub fn validate(&self) -> Result<(), PairedBackupError> {
        if self.job_key.trim().is_empty() || self.job_key.len() > 256 {
            return Err(PairedBackupError::StaleDecisionRefused(Uuid::nil()));
        }
        if self.cluster_incarnation.is_nil() || self.history_incarnation.is_nil() || self.group_id < 0 {
            return Err(PairedBackupError::StaleIncarnation {
                field: "history_incarnation",
                expected: "non-nil restored incarnation".to_owned(),
                got: self.history_incarnation.to_string(),
            });
        }
        if self.group_epoch <= 0 || self.authz_epoch <= 0 {
            return Err(PairedBackupError::StaleGrantRefused(
                "projection worker step carries a pre-restore group/authz epoch",
            ));
        }
        Ok(())
    }
}

/// Fail-closed guard evaluated on every production write, projection-worker step and pack delete.
#[derive(Clone, Debug)]
pub struct PairedProductionRuntimeGuard {
    admission: IncarnationAdmissionGuard,
    frozen: bool,
    cluster_incarnation: Uuid,
    history_incarnation: Uuid,
}

impl PairedProductionRuntimeGuard {
    pub fn new(
        admission: IncarnationAdmissionGuard,
        frozen: bool,
        cluster_incarnation: Uuid,
        history_incarnation: Uuid,
    ) -> Self {
        Self { admission, frozen, cluster_incarnation, history_incarnation }
    }

    /// Bind the guard to the authoritative restored incarnation itself.
    pub fn from_live_authority(admission: IncarnationAdmissionGuard, frozen: bool) -> Self {
        let live = admission.live.clone();
        Self {
            admission,
            frozen,
            cluster_incarnation: live.new_cluster_incarnation,
            history_incarnation: live.new_history_incarnation,
        }
    }

    pub fn admission(&self) -> &IncarnationAdmissionGuard {
        &self.admission
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// The single freeze check every production mutation must pass first.
    pub fn require_unfrozen(&self) -> Result<(), PairedBackupError> {
        if self.frozen {
            return Err(PairedBackupError::FreezeNotHeld(
                "durable paired-backup freeze is active; production path refuses to write",
            ));
        }
        Ok(())
    }

    /// Gate a ref write: no active freeze, restored cluster/history incarnation, bumped epochs.
    pub fn commit_ref_write(&self, ticket: &WriterGrantTicket) -> Result<(), PairedBackupError> {
        self.require_unfrozen()?;
        if ticket.cluster_incarnation != self.cluster_incarnation {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: self.cluster_incarnation.to_string(),
                got: ticket.cluster_incarnation.to_string(),
            });
        }
        if ticket.history_incarnation != self.history_incarnation {
            return Err(PairedBackupError::StaleIncarnation {
                field: "history_incarnation",
                expected: self.history_incarnation.to_string(),
                got: ticket.history_incarnation.to_string(),
            });
        }
        self.admission.verify_writer_grant(ticket)
    }

    /// Gate a decision execution resurrected from a pre-backup snapshot.
    pub fn execute_decision(&self, ticket: &DecisionExecutionTicket) -> Result<(), PairedBackupError> {
        self.require_unfrozen()?;
        if ticket.history_incarnation != self.history_incarnation {
            return Err(PairedBackupError::StaleDecisionRefused(ticket.decision_id));
        }
        self.admission.verify_decision_execution(ticket)
    }

    /// Gate one `ref_cas_projection_jobs` worker step against freeze + restored incarnation.
    pub fn run_projection_worker_step(&self, ticket: &WorkerProjectionTicket) -> Result<(), PairedBackupError> {
        self.require_unfrozen()?;
        ticket.validate()?;
        if ticket.cluster_incarnation != self.cluster_incarnation {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: self.cluster_incarnation.to_string(),
                got: ticket.cluster_incarnation.to_string(),
            });
        }
        if ticket.history_incarnation != self.history_incarnation {
            return Err(PairedBackupError::StaleIncarnation {
                field: "history_incarnation",
                expected: self.history_incarnation.to_string(),
                got: ticket.history_incarnation.to_string(),
            });
        }
        if ticket.group_epoch < self.admission.live.new_group_epoch
            || ticket.authz_epoch < self.admission.live.new_authz_floor
        {
            return Err(PairedBackupError::StaleGrantRefused(
                "projection worker step races a superseded group/authz epoch",
            ));
        }
        Ok(())
    }

    /// Gate a fenced pack delete: freeze, durable deleter epoch, PG authority fence, then delete.
    pub async fn execute_fenced_pack_delete(
        &self,
        pool: &Pool,
        raft: &MtlsLiveRaftBackend,
        ticket: &DeleterLeaseTicket,
        store: &BlobStore,
        locator: &BlobLocator,
        deadline: Instant,
    ) -> Result<(), PairedBackupError> {
        self.require_unfrozen()?;
        self.admission.verify_deleter_lease(ticket)?;
        execute_deleter_guarded(pool, raft, ticket).await?;
        store.delete(locator, deadline).await.map_err(|e| {
            PairedBackupError::DeleterNotFenced(match e {
                crate::blob_store::BlobError::DeleteDisabled => "blob deletion is disabled in this profile",
                _ => "blob store refused the fenced pack delete",
            })
        })
    }

    /// Execute a live Ref-CAS write admitted by freeze + restored incarnation + PG live authority.
    pub async fn execute_live_ref_write(
        &self,
        pool: &Pool,
        raft: &mut MtlsLiveRaftBackend,
        repository_id: Uuid,
        grant: &WriterGrantTicket,
        decision: Option<&DecisionExecutionTicket>,
        cmd: RefCasCommand,
    ) -> Result<ApplyResponse, PairedBackupError> {
        self.commit_ref_write(grant)?;
        if let Some(d) = decision {
            self.execute_decision(d)?;
        }
        let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
        let _ = require_unfrozen_pg_and_raft(&**client, raft, repository_id).await?;
        verify_pg_live_incarnation(&client, repository_id, grant, decision, None).await?;
        let (_, resp) = raft.commit_and_apply(cmd)?;
        Ok(resp)
    }

    /// Execute one live projection-worker step admitted by PG authority and a majority cutpoint proof.
    pub async fn execute_live_projection_worker_step(
        &self,
        pool: &Pool,
        raft: &MtlsLiveRaftBackend,
        repository_id: Uuid,
        ticket: &WorkerProjectionTicket,
    ) -> Result<u64, PairedBackupError> {
        self.run_projection_worker_step(ticket)?;
        let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
        let live_floor = require_unfrozen_pg_and_raft(&**client, raft, repository_id).await?;
        if ticket.authz_epoch < live_floor {
            return Err(PairedBackupError::StaleGrantRefused(
                "projection worker authz_epoch below live PG repo_access floor",
            ));
        }
        let cluster_inc: Uuid = client
            .query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton = true", &[])
            .await
            .map_err(pg_err)?
            .get(0);
        if cluster_inc != ticket.cluster_incarnation {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: cluster_inc.to_string(),
                got: ticket.cluster_incarnation.to_string(),
            });
        }
        let (snap, state_digest) = raft.durable_state()?;
        let applied = snap
            .body
            .last_applied
            .ok_or(PairedBackupError::IncompleteCut("missing applied log entry for projection worker"))?;
        let voter_ids = raft.voter_ids();
        let mem_digest = raft.group_membership_digest();
        let attestations = raft.attest_group_cutpoint(ticket.group_epoch, &snap, &state_digest)?;
        verify_cutpoint_attestations(
            raft.group_id(),
            ticket.group_epoch,
            &voter_ids,
            &mem_digest,
            applied,
            &state_digest,
            &snap.checksum,
            &attestations,
        )?;
        let updated = client
            .execute(
                "UPDATE public.ref_cas_projection_cursors \
                 SET applied_event_seq = $1, applied_log_index = $2, applied_log_term = $3 \
                 WHERE group_id = $4 AND history_incarnation = $5 AND group_epoch = $6",
                &[
                    &(snap.body.next_event_seq as i64),
                    &(applied.index as i64),
                    &(applied.term as i64),
                    &ticket.group_id,
                    &ticket.history_incarnation,
                    &ticket.group_epoch,
                ],
            )
            .await
            .map_err(pg_err)?;
        if updated != 1 {
            return Err(PairedBackupError::CutpointSkew("projection cursor row missing or realm mismatch".into()));
        }
        Ok(snap.body.next_event_seq)
    }
}

/// Convenience constructor for the live process wiring: guard bound to `authority`, unfrozen.
pub fn production_guard_from_authority(authority: NewIncarnationAuthority) -> PairedProductionRuntimeGuard {
    PairedProductionRuntimeGuard::from_live_authority(IncarnationAdmissionGuard { live: authority }, false)
}
