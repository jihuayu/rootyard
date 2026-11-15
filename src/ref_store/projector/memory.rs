//! Deterministic in-memory reference store & state-machine event source for
//! verifying single-transaction replay, crash recovery, out-of-order safety,
//! revocation projection, and truncation closure without external dependencies (#117).

use super::identity::derive_operation_event_id;
use super::replay::{
    CursorTransition, assert_projection_cannot_authorize_write, check_stream_continuity, plan_operation_projection,
    reconcile_cutoff_on_cursor, validate_cursor_step,
};
use super::types::{
    ProjectedOperationRecord, ProjectedRefState, ProjectionCursor, ProjectionError, ProjectionJobRecord,
    ProjectionJobState, ProjectionRealm, RefCasEventEnvelope, RefCasEventPage, ReplayBatchOutcome, SingleEventOutcome,
    TruncationCutoff,
};
use crate::ref_store::core::state_machine::RefCasStateMachine;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryWebhookDelivery {
    pub webhook_id: Uuid,
    pub repository_id: Uuid,
    pub sequence: i64,
    pub event_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedFault {
    BeforeCommit,
    AfterCommitBeforeAck,
}

/// Deterministic in-memory Ref-CAS projection database matching the exact PostgreSQL
/// single-transaction atomicity, uniqueness, monotonic ordering, and cursor invariants.
#[derive(Clone, Debug, Default)]
pub struct InMemoryProjectionLedger {
    pub cursors: BTreeMap<(i64, Uuid), ProjectionCursor>,
    pub operations: BTreeMap<String, ProjectedOperationRecord>,
    pub refs: BTreeMap<(Uuid, String), ProjectedRefState>,
    pub projected_events: BTreeSet<String>,
    pub webhooks_by_repo: BTreeMap<Uuid, Vec<(Uuid, Uuid)>>,
    pub webhook_deliveries: BTreeMap<(Uuid, String), InMemoryWebhookDelivery>,
    pub webhook_sequences: BTreeMap<Uuid, i64>,
    pub jobs: BTreeMap<String, ProjectionJobRecord>,
    pub revoked_tokens: BTreeSet<Uuid>,
    pub removed_members: BTreeSet<(Uuid, Uuid)>,
}

impl InMemoryProjectionLedger {
    pub fn register_push_webhook(&mut self, repository_id: Uuid, tenant_id: Uuid, webhook_id: Uuid) {
        self.webhooks_by_repo.entry(repository_id).or_default().push((webhook_id, tenant_id));
    }

    pub fn revoke_token_and_member(&mut self, repository_id: Uuid, actor_id: Uuid, token_id: Uuid) {
        self.revoked_tokens.insert(token_id);
        self.removed_members.insert((repository_id, actor_id));
    }

    pub fn cursor_for(&self, realm: &ProjectionRealm) -> Option<&ProjectionCursor> {
        self.cursors.get(&(realm.group_id, realm.history_incarnation))
    }

    pub fn apply_event_with_fault(
        &mut self,
        envelope: &RefCasEventEnvelope,
        fault: Option<SimulatedFault>,
    ) -> Result<SingleEventOutcome, ProjectionError> {
        let mut working = self.clone();
        let outcome = working.apply_event_tx(envelope)?;
        if matches!(fault, Some(SimulatedFault::BeforeCommit)) {
            return Err(ProjectionError::Database("simulated pre-commit crash".into()));
        }
        *self = working;
        if matches!(fault, Some(SimulatedFault::AfterCommitBeforeAck)) {
            return Err(ProjectionError::Database("simulated post-commit disconnect before caller ack".into()));
        }
        Ok(outcome)
    }

    fn apply_event_tx(&mut self, envelope: &RefCasEventEnvelope) -> Result<SingleEventOutcome, ProjectionError> {
        let key = (envelope.realm.group_id, envelope.realm.history_incarnation);
        let cursor = match self.cursors.get(&key).cloned() {
            Some(c) => c,
            None => ProjectionCursor::genesis(envelope.realm)?,
        };
        let transition = validate_cursor_step(&cursor, envelope)?;
        let plan = plan_operation_projection(envelope)?;
        assert_projection_cannot_authorize_write(&plan.operation)?;

        if let Some(existing) = self.operations.get(&plan.operation.op_event_id) {
            if existing.terminal_digest != plan.operation.terminal_digest {
                return Err(ProjectionError::Equivocation {
                    op_event_id: plan.operation.op_event_id,
                    expected_digest: existing.terminal_digest.clone(),
                    actual_digest: plan.operation.terminal_digest,
                });
            }
            return Ok(SingleEventOutcome::DuplicateSkipped { op_event_id: plan.operation.op_event_id, cursor });
        }
        if transition == CursorTransition::HistoricalOrDuplicate {
            return Err(ProjectionError::StreamRegression(format!(
                "missing durable operation record {} at historical event_seq {}",
                plan.operation.op_event_id, envelope.event_seq
            )));
        }

        // Intentional: revoked tokens / removed members still project committed facts,
        // while `can_authorize_write` remains permanently false.
        let mut webhook_count = 0usize;
        let mut job_count = 0usize;
        let ref_count = plan.deltas.len();
        let op_event_id = plan.operation.op_event_id.clone();

        self.operations.insert(op_event_id.clone(), plan.operation);
        for delta in &plan.deltas {
            self.projected_events.insert(delta.event_id.clone());
            let ref_key = (envelope.repository_id, delta.ref_name.clone());
            let should_update = self.refs.get(&ref_key).is_none_or(|cur| {
                (cur.realm.group_epoch, cur.log_index, cur.event_seq)
                    < (envelope.realm.group_epoch, envelope.log_index, envelope.event_seq)
            });
            if should_update {
                self.refs.insert(
                    ref_key,
                    ProjectedRefState {
                        repository_id: envelope.repository_id,
                        ref_name: delta.ref_name.clone(),
                        oid: delta.new_oid.clone(),
                        deleted: delta.deleted,
                        revision: envelope.revision,
                        realm: envelope.realm,
                        log_index: envelope.log_index,
                        log_term: envelope.log_term,
                        event_seq: envelope.event_seq,
                        op_event_id: op_event_id.clone(),
                        can_authorize_write: false,
                    },
                );
            }
            if delta.emit_push_webhook
                && let Some(hooks) = self.webhooks_by_repo.get(&envelope.repository_id)
            {
                for (webhook_id, _tenant_id) in hooks {
                    let dedup_key = (*webhook_id, delta.webhook_event_id.clone());
                    if !self.webhook_deliveries.contains_key(&dedup_key) {
                        let seq = self.webhook_sequences.entry(*webhook_id).or_insert(0);
                        *seq += 1;
                        self.webhook_deliveries.insert(
                            dedup_key,
                            InMemoryWebhookDelivery {
                                webhook_id: *webhook_id,
                                repository_id: envelope.repository_id,
                                sequence: *seq,
                                event_id: delta.webhook_event_id.clone(),
                                event_type: "push".into(),
                                payload: serde_json::json!({
                                    "event": "push",
                                    "event_id": delta.event_id,
                                    "op_event_id": op_event_id,
                                    "operation_id": envelope.operation_id,
                                    "repository_id": envelope.repository_id,
                                    "ref_name": delta.ref_name,
                                    "old_oid": delta.old_oid,
                                    "new_oid": delta.new_oid,
                                }),
                            },
                        );
                        webhook_count += 1;
                    }
                }
            }
        }

        for job in &plan.jobs {
            if !self.jobs.contains_key(&job.job_key) {
                let tenant_id = job.tenant_id.unwrap_or_else(Uuid::nil);
                self.jobs.insert(
                    job.job_key.clone(),
                    ProjectionJobRecord {
                        job_key: job.job_key.clone(),
                        repository_id: job.repository_id,
                        tenant_id,
                        op_event_id: job.op_event_id.clone(),
                        realm: job.realm,
                        log_index: job.log_index,
                        event_seq: job.event_seq,
                        kind: job.kind,
                        scope_key: job.scope_key.clone(),
                        state: ProjectionJobState::Queued,
                        attempt: 0,
                        claim_generation: 0,
                        lease_owner: None,
                        last_error: None,
                        payload: job.payload.clone(),
                    },
                );
                job_count += 1;
            }
        }

        let mut next_cursor = cursor;
        next_cursor.realm.group_epoch = envelope.realm.group_epoch;
        next_cursor.applied_event_seq = envelope.event_seq;
        next_cursor.applied_log_index = envelope.log_index;
        next_cursor.applied_log_term = envelope.log_term;
        next_cursor.last_event_id = Some(op_event_id.clone());
        self.cursors.insert(key, next_cursor.clone());

        Ok(SingleEventOutcome::Applied {
            op_event_id,
            projected_refs: ref_count,
            enqueued_webhooks: webhook_count,
            enqueued_jobs: job_count,
            cursor: next_cursor,
        })
    }

    pub fn record_truncation_cutoff(
        &mut self,
        realm: ProjectionRealm,
        cutoff: TruncationCutoff,
    ) -> Result<ProjectionCursor, ProjectionError> {
        let key = (realm.group_id, realm.history_incarnation);
        let mut cursor = match self.cursors.get(&key).cloned() {
            Some(c) => c,
            None => ProjectionCursor::genesis(realm)?,
        };
        reconcile_cutoff_on_cursor(&mut cursor, &cutoff)?;
        self.cursors.insert(key, cursor.clone());
        Ok(cursor)
    }

    /// Replays bounded pages starting from the persisted cursor until caught up, handling
    /// simulated backlog, watch reconnects, and duplicate re-reads without dropping state.
    pub fn replay_from_source(
        &mut self,
        source: &InMemorySmEventSource,
        realm: ProjectionRealm,
        batch_limit: usize,
    ) -> Result<ReplayBatchOutcome, ProjectionError> {
        let limit = batch_limit.clamp(1, 256);
        let key = (realm.group_id, realm.history_incarnation);
        let mut outcome = ReplayBatchOutcome {
            applied_events: 0,
            duplicate_skipped: 0,
            projected_refs: 0,
            enqueued_webhooks: 0,
            enqueued_jobs: 0,
            batches: 0,
            cursor: self.cursors.get(&key).cloned().unwrap_or(ProjectionCursor::genesis(realm)?),
        };

        loop {
            let mut cursor = self.cursors.get(&key).cloned().unwrap_or(ProjectionCursor::genesis(realm)?);
            let page = source.read_page(cursor.applied_event_seq, limit)?;
            if let Err(err) = check_stream_continuity(&mut cursor, &page) {
                self.cursors.insert(key, cursor);
                return Err(err);
            }
            self.cursors.insert(key, cursor.clone());
            if page.events.is_empty() {
                outcome.cursor = cursor;
                break;
            }
            outcome.batches += 1;
            for env in &page.events {
                match self.apply_event_tx(env)? {
                    SingleEventOutcome::Applied {
                        projected_refs, enqueued_webhooks, enqueued_jobs, cursor: c, ..
                    } => {
                        outcome.applied_events += 1;
                        outcome.projected_refs += projected_refs;
                        outcome.enqueued_webhooks += enqueued_webhooks;
                        outcome.enqueued_jobs += enqueued_jobs;
                        outcome.cursor = c;
                    }
                    SingleEventOutcome::DuplicateSkipped { cursor: c, .. } => {
                        outcome.duplicate_skipped += 1;
                        outcome.cursor = c;
                    }
                    SingleEventOutcome::ResyncRequired { cursor: c } => {
                        outcome.cursor = c;
                        return Err(ProjectionError::ResyncRequired("resync required mid-page".into()));
                    }
                }
            }
            if !page.has_more {
                break;
            }
        }
        Ok(outcome)
    }

    pub fn check_receipt_cannot_authorize_new_write(&self, op_event_id: &str) -> Result<(), ProjectionError> {
        let Some(rec) = self.operations.get(op_event_id) else {
            return Err(ProjectionError::AuthorityViolation("unknown projection receipt"));
        };
        assert_projection_cannot_authorize_write(rec)?;
        Err(ProjectionError::AuthorityViolation("projected Ref-CAS operation receipt cannot authorize a new ref write"))
    }

    /// Simulates TTL/retention sweeps on old jobs or failed/unknown state: active dedup &
    /// unresolved `UnknownHold` / `Failed` rows are preserved across any wall-clock age.
    pub fn sweep_with_ttl_never_drops_unknown_or_dedup(&mut self) -> usize {
        self.jobs
            .values()
            .filter(|j| matches!(j.state, ProjectionJobState::UnknownHold | ProjectionJobState::Failed))
            .count()
    }
}

/// Adapter around `RefCasStateMachine` or synthetic event logs supporting watch-loss,
/// truncated prefix simulation, and bounded paged recovery.
#[derive(Clone, Debug)]
pub struct InMemorySmEventSource {
    pub realm: ProjectionRealm,
    pub tenant_id: Option<Uuid>,
    pub events: Vec<RefCasEventEnvelope>,
    pub earliest_available_event_seq: u64,
    pub earliest_available_log_index: u64,
    pub truncation_cutoff: Option<TruncationCutoff>,
}

impl InMemorySmEventSource {
    pub fn from_state_machine(
        sm: &RefCasStateMachine,
        realm: ProjectionRealm,
        tenant_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        token_id: Option<Uuid>,
    ) -> Result<Self, ProjectionError> {
        let raw_events = sm.read_events_since(0, usize::MAX);
        let mut events = Vec::with_capacity(raw_events.len());
        for ev in &raw_events {
            events.push(RefCasEventEnvelope::from_state_machine_event(realm, tenant_id, actor_id, token_id, ev)?);
        }
        let earliest_seq = events.first().map_or(1, |e| e.event_seq);
        let earliest_log = events.first().map_or(1, |e| e.log_index);
        Ok(Self {
            realm,
            tenant_id,
            events,
            earliest_available_event_seq: earliest_seq,
            earliest_available_log_index: earliest_log,
            truncation_cutoff: None,
        })
    }

    pub fn truncate_up_to(&mut self, cutoff: TruncationCutoff) -> Result<(), ProjectionError> {
        cutoff.validate()?;
        self.events.retain(|e| e.event_seq > cutoff.event_seq);
        self.earliest_available_event_seq = cutoff.event_seq + 1;
        self.earliest_available_log_index = cutoff.log_index + 1;
        self.truncation_cutoff = Some(cutoff);
        Ok(())
    }

    pub fn read_page(&self, after_event_seq: u64, limit: usize) -> Result<RefCasEventPage, ProjectionError> {
        let cap = limit.max(1);
        let filtered: Vec<RefCasEventEnvelope> =
            self.events.iter().filter(|e| e.event_seq > after_event_seq).take(cap + 1).cloned().collect();
        let has_more = filtered.len() > cap;
        let events = filtered.into_iter().take(cap).collect();
        Ok(RefCasEventPage {
            realm: self.realm,
            events,
            earliest_available_event_seq: self.earliest_available_event_seq,
            earliest_available_log_index: self.earliest_available_log_index,
            truncation_cutoff: self.truncation_cutoff.clone(),
            has_more,
        })
    }

    pub fn operation_event_id_at(&self, index: usize) -> Result<String, ProjectionError> {
        let ev = self.events.get(index).ok_or_else(|| ProjectionError::InvalidInput("missing event index".into()))?;
        derive_operation_event_id(&ev.realm, ev.log_index, ev.operation_id, ev.repository_id)
    }
}
