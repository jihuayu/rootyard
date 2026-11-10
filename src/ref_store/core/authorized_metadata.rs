//! Decision-gated metadata commits. These receipts attest metadata only, never Git object bytes.
use super::command::CommitRefsRequest;
use super::contract::CoreGate;
use super::decision_commit::{self, RealmExpectation};
use super::metadata_subset::{self, MetadataSelection};
use super::pack_commit::AuthorizedCommitError;
use super::publication_decision::{self as decisions, ConsumptionRecord, DecisionError, PublicationAction};
use super::sql;
use super::terminal::{CommitRefsReceipt, CommitRejectCode, CommitRejection, RefCommitResult};
use crate::db::Identity;
use crate::ref_store::contract::{OperationState, RefStoreError};
use crate::ref_store::pg::{self, PgRefStore};
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use deadpool_postgres::Pool;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

pub enum MetadataDecisionPreparation {
    Prepared(Box<PreparedMetadataPublication>),
    Replayed(Box<CommitRefsReceipt>),
}

/// Only a committed install transaction can create this value.
pub struct PreparedMetadataPublication {
    request: CommitRefsRequest,
    actor: Identity,
    selected: decisions::MetadataSelectedDecision,
}

impl PreparedMetadataPublication {
    pub fn operation_id(&self) -> uuid::Uuid {
        self.request.identity().operation_id()
    }
    pub fn decision_id(&self) -> uuid::Uuid {
        self.selected.decision_id()
    }
    pub fn selection_digest(&self) -> &crate::ref_store::RequestDigest {
        self.selected.selection_digest()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PgAuthorizedMetadata;

impl PgAuthorizedMetadata {
    pub async fn prepare(
        &self,
        pool: &Pool,
        request: CommitRefsRequest,
        actor: &Identity,
        deadline: Instant,
    ) -> Result<MetadataDecisionPreparation, AuthorizedCommitError> {
        if request.identity().issuer_id() != actor.id {
            return Err(AuthorizedCommitError::Denied("issuer_mismatch"));
        }
        request.validate()?;
        let deadline = stage_deadline(deadline)?;
        let mut client = client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let outcome = timeout_at(deadline, async {
            pg::bound(&tx, deadline).await?;
            tx.batch_execute("SET LOCAL synchronous_commit='on'").await.map_err(pg::db_error)?;
            let begun = PgRefStore.begin(&tx, request.identity(), deadline).await?;
            if matches!(begun.record.state(), OperationState::Committed | OperationState::Rejected) {
                return Ok(MetadataDecisionPreparation::Replayed(Box::new(sql::replay_terminal(begun)?)));
            }
            if begun.record.state() == OperationState::Cancelled {
                return Err(AuthorizedCommitError::from(RefStoreError::Cancelled {
                    operation_id: request.identity().operation_id(),
                }));
            }
            let gate = lock(&tx, &request).await?;
            let selected =
                decisions::select_and_install_metadata(&tx, &request, actor, deadline).await.map_err(error)?;
            decision_commit::enable_fence(&tx, gate.repository_id()).await?;
            Ok::<_, AuthorizedCommitError>(MetadataDecisionPreparation::Prepared(Box::new(
                PreparedMetadataPublication { request: request.clone(), actor: actor.clone(), selected },
            )))
        })
        .await
        .unwrap_or(Err(AuthorizedCommitError::Timeout));
        match outcome {
            Ok(value) => {
                commit_bounded(tx, deadline, request.repository_id(), Some(request.identity().operation_id())).await?;
                Ok(value)
            }
            Err(value) => {
                rollback(tx).await;
                Err(value)
            }
        }
    }

    pub async fn commit(
        &self,
        pool: &Pool,
        prepared: &PreparedMetadataPublication,
        deadline: Instant,
    ) -> Result<CommitRefsReceipt, AuthorizedCommitError> {
        let deadline = stage_deadline(deadline)?;
        let request = &prepared.request;
        if request.identity().issuer_id() != prepared.actor.id {
            return Err(AuthorizedCommitError::Denied("issuer_mismatch"));
        }
        request.validate()?;
        let mut client = client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let outcome = timeout_at(deadline, async {
            pg::bound(&tx, deadline).await?;
            tx.batch_execute("SET LOCAL synchronous_commit='on'").await.map_err(pg::db_error)?;
            let begun = PgRefStore.begin(&tx, request.identity(), deadline).await?;
            match begun.record.state() {
                OperationState::Committed | OperationState::Rejected => return Ok(sql::replay_terminal(begun)?),
                OperationState::Cancelled => return Err(AuthorizedCommitError::from(RefStoreError::Cancelled {
                    operation_id: request.identity().operation_id(),
                })),
                OperationState::Pending if begun.created => return Err(AuthorizedCommitError::Unverifiable("metadata pending operation missing")),
                OperationState::Pending => {}
            }
            let gate = lock(&tx, request).await?;
            let checked = decisions::authorized_metadata_final_check(&tx, &prepared.selected, request,
                &prepared.actor, request.identity().operation_id(), deadline).await;
            let denied = match checked {
                Ok(ConsumptionRecord::Consumed { .. }) => None,
                Ok(ConsumptionRecord::Rejected { code, .. }) | Err(DecisionError::Denied(code)) => Some(code),
                Err(value) => return Err(error(value)),
            };
            let selection = if let Some(code) = denied {
                tx.execute("UPDATE ref_store_publication_decisions SET state='REJECTED',closed_code=$2,rejected_at=clock_timestamp()
                    WHERE decision_id=$1 AND state='OPEN'", &[&prepared.selected.decision_id(), &code.as_str()]).await.map_err(pg::db_error)?;
                MetadataSelection::Reject {
                    results: request.refs().iter().map(|update| RefCommitResult::NotApplied {
                        name: update.name().as_str().to_owned(), reason: rejection_reason(&prepared.selected, update.name().as_str()),
                    }).collect(),
                    rejection: CommitRejection { code: if prepared.selected.accepted_is_empty() { CommitRejectCode::NoRefApplied }
                        else { CommitRejectCode::PolicyDenied }, ref_name: None, expected: None, actual: None },
                }
            } else {
                let policy = request.refs().iter().filter(|update| !prepared.selected.accepted().iter().any(|accepted| accepted.name() == update.name()))
                    .map(|update| (update.name().as_str().to_owned(), rejection_reason(&prepared.selected, update.name().as_str())))
                    .collect::<BTreeMap<_, _>>();
                let selection = metadata_subset::select(request, gate.head_ref().as_str(), prepared.selected.captured(), &policy);
                let accepted = match &selection {
                    MetadataSelection::Commit { accepted, .. } => accepted.iter().map(|i| request.refs()[*i].name().as_str()).collect::<Vec<_>>(),
                    MetadataSelection::Reject { .. } => Vec::new(),
                };
                if accepted != prepared.selected.accepted().iter().map(|update| update.name().as_str()).collect::<Vec<_>>() {
                    return Err(AuthorizedCommitError::Unverifiable("metadata selection changed"));
                }
                selection
            };
            metadata_subset::commit_selection(&tx, request, &gate, selection, deadline).await.map_err(AuthorizedCommitError::from)
        }).await.unwrap_or(Err(AuthorizedCommitError::Timeout));
        match outcome {
            Ok(value) => {
                commit_bounded(tx, deadline, request.repository_id(), Some(request.identity().operation_id())).await?;
                Ok(value)
            }
            Err(value) => {
                rollback(tx).await;
                Err(value)
            }
        }
    }
}

async fn lock(tx: &Transaction<'_>, request: &CommitRefsRequest) -> Result<CoreGate, AuthorizedCommitError> {
    decisions::lock_source_tables(tx, &PublicationAction::Push).await.map_err(error)?;
    decisions::lock_usage(tx, request.repository_id(), request.tenant_id()).await.map_err(error)?;
    let gate = sql::gate_row(tx, request.repository_id(), true).await?.ok_or(RefStoreError::RepositoryNotFound)?;
    let mode: String = tx
        .query_one("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&request.repository_id()])
        .await
        .map_err(pg::db_error)?
        .get(0);
    if mode != "metadata_only" {
        return Err(AuthorizedCommitError::from(RefStoreError::Unsupported(
            "metadata writes require a metadata_only gate",
        )));
    }
    decision_commit::lock_and_enforce(tx, &RealmExpectation::from_gate(&gate)).await?;
    Ok(gate)
}

fn rejection_reason(selected: &decisions::MetadataSelectedDecision, name: &str) -> CommitRejectCode {
    let reason =
        selected.verdict_rows().iter().find(|(key, _)| key == name).and_then(|(_, value)| value.split(':').nth(1));
    match reason {
        Some("cas") => CommitRejectCode::OldOidMismatch,
        Some("prefix_conflict") => CommitRejectCode::PrefixConflict,
        Some("head_dependency") => CommitRejectCode::HeadDependencyMissing,
        _ => CommitRejectCode::PolicyDenied,
    }
}

fn error(value: DecisionError) -> AuthorizedCommitError {
    match value {
        DecisionError::Denied(code) => AuthorizedCommitError::Denied(code.as_str()),
        DecisionError::Contended(_) => AuthorizedCommitError::Contended("metadata authorization sources busy"),
        DecisionError::QuotaExceeded { .. } => AuthorizedCommitError::QuotaExceeded,
        DecisionError::Timeout => AuthorizedCommitError::Timeout,
        _ => AuthorizedCommitError::Unverifiable("metadata decision unavailable"),
    }
}

fn stage_deadline(value: Instant) -> Result<Instant, AuthorizedCommitError> {
    if value <= Instant::now() {
        Err(AuthorizedCommitError::Timeout)
    } else {
        Ok(value.min(Instant::now() + Duration::from_secs(30)))
    }
}

async fn client(pool: &Pool, deadline: Instant) -> Result<deadpool_postgres::Client, AuthorizedCommitError> {
    match timeout_at(deadline, pool.get()).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(AuthorizedCommitError::Timeout),
    }
}

async fn rollback(tx: Transaction<'_>) {
    let _cleanup = timeout_at(Instant::now() + Duration::from_secs(2), tx.rollback()).await;
}
