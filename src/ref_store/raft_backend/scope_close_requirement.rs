//! Committed successful close capability bound to one owned node trust identity.
//!
//! A [`ScopeCloseRequirement`] is minted only by the backend that owns a retained successful
//! `AuthScopeClosed`/`AuthScopeClosedV2` receipt. It binds the scope/floor/original close
//! coordinate to the complete `NodeTrust` and the exact Root application domain/version. The
//! type has private fields, no public constructor, and no `Deserialize`.

use rootyard_refcas_log::state_machine::ApplicationLogId;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{ScopeLifecycle, validate_scope_kind};
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::outcome::{RootRefCasApplied, RootRefCasOutcome};
use crate::ref_store::raft_backend::proposal::{ProposalId, ProposalLookup};
use crate::ref_store::raft_backend::realm::NodeTrust;
use crate::ref_store::raft_backend::reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION};

/// A committed successful close receipt bound to the owned node's complete trust identity.
///
/// This is owned-adapter coordinate consistency, not remote authorization or proof that
/// independently misconfigured clusters with identical labels are the same log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeCloseRequirement {
    trust: NodeTrust,
    application_domain: &'static str,
    application_version: u16,
    close_log_id: ApplicationLogId,
    scope_kind: String,
    scope_id: Uuid,
    required_authz_floor: i64,
}

impl ScopeCloseRequirement {
    /// Crate-private minting boundary. The caller must have already recovered an actual retained
    /// successful close receipt; this constructor additionally rejects impossible close semantics.
    pub(crate) fn from_verified_close(
        trust: NodeTrust,
        close_log_id: ApplicationLogId,
        scope_kind: String,
        scope_id: Uuid,
        lifecycle: ScopeLifecycle,
        required_authz_floor: i64,
    ) -> Result<Self, RaftBackendError> {
        if !matches!(lifecycle, ScopeLifecycle::Closing | ScopeLifecycle::Closed) {
            return Err(RaftBackendError::ScopeCloseNotRecoverable("close lifecycle is not Closing or Closed"));
        }
        if required_authz_floor <= 0 {
            return Err(RaftBackendError::ScopeCloseNotRecoverable("close authz_floor is not positive"));
        }
        if scope_id.is_nil() {
            return Err(RaftBackendError::ScopeCloseNotRecoverable("close scope_id is nil"));
        }
        validate_scope_kind(&scope_kind)
            .map_err(|_| RaftBackendError::ScopeCloseNotRecoverable("close scope_kind is unsupported"))?;
        Ok(Self {
            trust,
            application_domain: ROOT_REF_CAS_DOMAIN,
            application_version: ROOT_REF_CAS_VERSION,
            close_log_id,
            scope_kind,
            scope_id,
            required_authz_floor,
        })
    }

    pub(crate) fn validate_node_binding(&self, trust: &NodeTrust) -> Result<(), RaftBackendError> {
        if self.trust != *trust {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("node trust"));
        }
        if self.application_domain != ROOT_REF_CAS_DOMAIN || self.application_version != ROOT_REF_CAS_VERSION {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("application domain/version"));
        }
        Ok(())
    }

    pub fn trust(&self) -> &NodeTrust {
        &self.trust
    }

    pub fn application_domain(&self) -> &'static str {
        self.application_domain
    }

    pub fn application_version(&self) -> u16 {
        self.application_version
    }

    /// Original successful close decision coordinate, not a later retry coordinate.
    pub fn close_log_id(&self) -> ApplicationLogId {
        self.close_log_id
    }

    pub fn scope_kind(&self) -> &str {
        &self.scope_kind
    }

    pub fn scope_id(&self) -> Uuid {
        self.scope_id
    }

    pub fn required_authz_floor(&self) -> i64 {
        self.required_authz_floor
    }

    pub fn group_id(&self) -> &str {
        self.trust.group_id()
    }

    pub fn authority_id(&self) -> Uuid {
        self.trust.authority_id()
    }

    pub fn storage_generation(&self) -> u64 {
        self.trust.storage_generation()
    }
}

/// Mints a requirement only from a retained `Found` applied close decision.
pub(crate) fn scope_close_requirement_from_lookup(
    lookup: ProposalLookup,
    trust: NodeTrust,
    proposal_id: ProposalId,
) -> Result<ScopeCloseRequirement, RaftBackendError> {
    match lookup {
        ProposalLookup::Found { original_log_id, outcome, .. } => {
            let (scope_kind, scope_id, lifecycle, required_authz_floor) = match outcome {
                RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 {
                    scope_kind,
                    scope_id,
                    lifecycle,
                    authz_floor,
                    ..
                })
                | RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosed {
                    scope_kind,
                    scope_id,
                    lifecycle,
                    authz_floor,
                    ..
                }) => (scope_kind, scope_id, lifecycle, authz_floor),
                RootRefCasOutcome::Applied(_) => {
                    return Err(RaftBackendError::ScopeCloseNotRecoverable(
                        "retained decision is not a close acknowledgment",
                    ));
                }
                RootRefCasOutcome::Refused(_) => {
                    return Err(RaftBackendError::ScopeCloseNotRecoverable("retained decision is refused"));
                }
            };
            ScopeCloseRequirement::from_verified_close(
                trust,
                original_log_id,
                scope_kind,
                scope_id,
                lifecycle,
                required_authz_floor,
            )
        }
        ProposalLookup::Expired { .. } => Err(RaftBackendError::ScopeCloseNotRecoverable("close receipt expired")),
        ProposalLookup::NotObserved { .. } => Err(RaftBackendError::RecoveryNotObserved(proposal_id)),
        ProposalLookup::Invalid { reason, .. } => Err(RaftBackendError::InvalidProposal(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::state_machine::ScopeLifecycle;
    use crate::ref_store::raft_backend::outcome::{
        RootRefCasApplied, RootRefCasOutcome, RootRefCasRefusal, RootRefCasRefusalKind,
    };
    use crate::ref_store::raft_backend::proposal::{ProposalId, ProposalLookup};
    use crate::ref_store::raft_backend::scope_close::ScopeCloseDrainSummary;

    fn trust(group: &str, authority: Uuid, storage_generation: u64) -> NodeTrust {
        NodeTrust::new(group, authority, storage_generation).expect("trust")
    }

    fn proposal_id() -> ProposalId {
        ProposalId::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "group-a",
            1,
            Uuid::from_u128(4),
            1,
            1,
            crate::ref_store::GitObjectFormat::Sha256,
            0,
            Uuid::from_u128(5),
        )
        .expect("proposal")
    }

    #[test]
    fn requirement_rejects_impossible_close_shape_and_binds_all_trust_axes() {
        let authority = Uuid::from_u128(10);
        let base_trust = trust("group-a", authority, 1);
        let scope_id = Uuid::from_u128(20);
        let log_id = ApplicationLogId::new(1, 7);
        assert!(
            ScopeCloseRequirement::from_verified_close(
                base_trust.clone(),
                log_id,
                "token".into(),
                scope_id,
                ScopeLifecycle::Open,
                2,
            )
            .is_err()
        );
        assert!(
            ScopeCloseRequirement::from_verified_close(
                base_trust.clone(),
                log_id,
                "token".into(),
                scope_id,
                ScopeLifecycle::Closing,
                0,
            )
            .is_err()
        );
        assert!(
            ScopeCloseRequirement::from_verified_close(
                base_trust.clone(),
                log_id,
                "token".into(),
                Uuid::nil(),
                ScopeLifecycle::Closing,
                2,
            )
            .is_err()
        );
        assert!(
            ScopeCloseRequirement::from_verified_close(
                base_trust.clone(),
                log_id,
                "not-a-scope".into(),
                scope_id,
                ScopeLifecycle::Closing,
                2,
            )
            .is_err()
        );
        let required = ScopeCloseRequirement::from_verified_close(
            base_trust.clone(),
            log_id,
            "token".into(),
            scope_id,
            ScopeLifecycle::Closing,
            2,
        )
        .expect("requirement");
        assert!(required.validate_node_binding(&base_trust).is_ok());
        for changed in
            [trust("group-b", authority, 1), trust("group-a", Uuid::from_u128(11), 1), trust("group-a", authority, 2)]
        {
            assert!(matches!(
                required.validate_node_binding(&changed),
                Err(RaftBackendError::ScopeDrainBindingMismatch("node trust"))
            ));
        }
    }

    #[test]
    fn minting_accepts_only_retained_applied_closing_or_closed_close_receipts() {
        let trust = trust("group-a", Uuid::from_u128(10), 1);
        let proposal_id = proposal_id();
        let scope_id = Uuid::from_u128(20);
        let close_log = ApplicationLogId::new(1, 7);
        let compact = || {
            RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 {
                scope_kind: "token".into(),
                scope_id,
                lifecycle: ScopeLifecycle::Closing,
                authz_floor: 2,
                replayed: false,
                drain_summary: ScopeCloseDrainSummary::from_vectors(
                    "token",
                    scope_id,
                    ScopeLifecycle::Closing,
                    2,
                    &[],
                    &[],
                ),
            })
        };
        let found = |outcome| ProposalLookup::Found {
            proposal_id: proposal_id.clone(),
            command_digest_hex: "00".repeat(32),
            original_log_id: close_log,
            observed_log_id: ApplicationLogId::new(1, 8),
            outcome,
        };
        assert!(scope_close_requirement_from_lookup(found(compact()), trust.clone(), proposal_id.clone()).is_ok());
        let legacy = RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosed {
            scope_kind: "token".into(),
            scope_id,
            lifecycle: ScopeLifecycle::Closed,
            authz_floor: 3,
            replayed: true,
            open_decision_ids: vec![],
            pending_operation_ids: vec![],
        });
        assert!(scope_close_requirement_from_lookup(found(legacy), trust.clone(), proposal_id.clone()).is_ok());
        assert!(matches!(
            scope_close_requirement_from_lookup(
                found(RootRefCasOutcome::Applied(RootRefCasApplied::Noop)),
                trust.clone(),
                proposal_id.clone()
            ),
            Err(RaftBackendError::ScopeCloseNotRecoverable(_))
        ));
        assert!(matches!(
            scope_close_requirement_from_lookup(
                found(RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity))),
                trust.clone(),
                proposal_id.clone()
            ),
            Err(RaftBackendError::ScopeCloseNotRecoverable(_))
        ));
        assert!(matches!(
            scope_close_requirement_from_lookup(
                ProposalLookup::Expired { proposal_id: proposal_id.clone(), current_index: 40, expires_at_index: 32 },
                trust.clone(),
                proposal_id.clone()
            ),
            Err(RaftBackendError::ScopeCloseNotRecoverable(_))
        ));
        assert!(matches!(
            scope_close_requirement_from_lookup(
                ProposalLookup::NotObserved { proposal_id: proposal_id.clone(), current_index: 9 },
                trust.clone(),
                proposal_id.clone()
            ),
            Err(RaftBackendError::RecoveryNotObserved(_))
        ));
        assert!(matches!(
            scope_close_requirement_from_lookup(
                ProposalLookup::Invalid { proposal_id: proposal_id.clone(), reason: "malformed" },
                trust,
                proposal_id
            ),
            Err(RaftBackendError::InvalidProposal(_))
        ));
    }

    #[test]
    fn zero_floor_and_open_lifecycle_are_rejected_for_both_wire_shapes() {
        let trust = trust("group-a", Uuid::from_u128(10), 1);
        let proposal_id = proposal_id();
        let scope_id = Uuid::from_u128(20);
        for outcome in [
            RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 {
                scope_kind: "token".into(),
                scope_id,
                lifecycle: ScopeLifecycle::Open,
                authz_floor: 2,
                replayed: false,
                drain_summary: ScopeCloseDrainSummary::from_vectors(
                    "token",
                    scope_id,
                    ScopeLifecycle::Open,
                    2,
                    &[],
                    &[],
                ),
            }),
            RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosed {
                scope_kind: "token".into(),
                scope_id,
                lifecycle: ScopeLifecycle::Closed,
                authz_floor: 0,
                replayed: false,
                open_decision_ids: vec![],
                pending_operation_ids: vec![],
            }),
        ] {
            let lookup = ProposalLookup::Found {
                proposal_id: proposal_id.clone(),
                command_digest_hex: "00".repeat(32),
                original_log_id: ApplicationLogId::new(1, 7),
                observed_log_id: ApplicationLogId::new(1, 8),
                outcome,
            };
            assert!(matches!(
                scope_close_requirement_from_lookup(lookup, trust.clone(), proposal_id.clone()),
                Err(RaftBackendError::ScopeCloseNotRecoverable(_))
            ));
        }
    }
}
