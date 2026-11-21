//! Fail-closed in-memory incarnation admission guard refusing pre-backup writer grants,
//! pre-backup scoped decisions, and superseded deleter leases (#153).

use super::types::{
    DecisionExecutionTicket, DeleterLeaseTicket, NewIncarnationAuthority, PairedBackupError, WriterGrantTicket,
};

/// Fail-closed guard loaded into a restored cluster to refuse pre-backup credentials.
#[derive(Clone, Debug)]
pub struct IncarnationAdmissionGuard {
    pub live: NewIncarnationAuthority,
}

impl IncarnationAdmissionGuard {
    pub fn verify_writer_grant(&self, ticket: &WriterGrantTicket) -> Result<(), PairedBackupError> {
        if ticket.cluster_incarnation != self.live.new_cluster_incarnation
            || self.live.fenced_prior_incarnations.contains(&ticket.cluster_incarnation)
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: self.live.new_cluster_incarnation.to_string(),
                got: ticket.cluster_incarnation.to_string(),
            });
        }
        if ticket.history_incarnation != self.live.new_history_incarnation
            || self.live.fenced_prior_incarnations.contains(&ticket.history_incarnation)
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "history_incarnation",
                expected: self.live.new_history_incarnation.to_string(),
                got: ticket.history_incarnation.to_string(),
            });
        }
        if ticket.authority_epoch < self.live.new_authority_epoch || ticket.group_epoch < self.live.new_group_epoch {
            return Err(PairedBackupError::StaleGrantRefused(
                "authority_epoch or group_epoch from pre-backup incarnation",
            ));
        }
        if ticket.authz_epoch < self.live.new_authz_floor {
            return Err(PairedBackupError::StaleGrantRefused("authz_epoch below restored authz_floor"));
        }
        Ok(())
    }

    pub fn verify_decision_execution(&self, ticket: &DecisionExecutionTicket) -> Result<(), PairedBackupError> {
        if self.live.fenced_pre_backup_decision_ids.contains(&ticket.decision_id) {
            return Err(PairedBackupError::StaleDecisionRefused(ticket.decision_id));
        }
        if ticket.history_incarnation != self.live.new_history_incarnation
            || ticket.authority_epoch < self.live.new_authority_epoch
            || ticket.group_epoch < self.live.new_group_epoch
            || ticket.authz_epoch < self.live.new_authz_floor
        {
            return Err(PairedBackupError::StaleDecisionRefused(ticket.decision_id));
        }
        Ok(())
    }

    pub fn verify_deleter_lease(&self, ticket: &DeleterLeaseTicket) -> Result<(), PairedBackupError> {
        if ticket.cluster_incarnation != self.live.new_cluster_incarnation
            || ticket.storage_authority_id != self.live.new_storage_authority_id
        {
            return Err(PairedBackupError::StaleDeleterRefused("deleter belongs to pre-backup cluster/authority"));
        }
        if ticket.storage_generation < self.live.new_storage_generation
            || ticket.deleter_epoch < self.live.new_deleter_epoch
        {
            return Err(PairedBackupError::StaleDeleterRefused("deleter generation/epoch superseded by restore"));
        }
        Ok(())
    }

    /// Admission alias: refuse a pre-backup writer grant.
    pub fn admit_writer_grant(&self, ticket: &WriterGrantTicket) -> Result<(), PairedBackupError> {
        self.verify_writer_grant(ticket)
    }

    /// Admission alias: refuse a pre-backup scoped decision execution.
    pub fn admit_decision_execution(&self, ticket: &DecisionExecutionTicket) -> Result<(), PairedBackupError> {
        self.verify_decision_execution(ticket)
    }

    /// Admission alias: refuse a superseded deleter lease.
    pub fn admit_deleter_lease(&self, ticket: &DeleterLeaseTicket) -> Result<(), PairedBackupError> {
        self.verify_deleter_lease(ticket)
    }
}
