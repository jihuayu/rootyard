"""Source-only guard for the standalone MemoryWake association (Refs #110/#111).

The runtime witness is intentionally separate: this file proves the production
trigger and the durable outbox bridge are ordered correctly without PostgreSQL,
Blob, native Git, a compiler or a network. The ignored PostgreSQL witness lives
in ``tests/outbox.rs``.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def body(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


class BlobGatewayMemoryWakeShapeTests(unittest.TestCase):
    def test_standalone_defaults_to_local_wake_and_only_reads_the_a4_opt_in(self):
        text = source("src/standalone.rs")
        self.assertIn("crate::dispatch::Signals::default()", text)
        self.assertIn("state.with_dispatch(dispatch.clone())", text)
        self.assertIn("let wake = dispatch.local.clone()", text)
        self.assertIn("let remote = dispatch.remote.clone()", text)
        self.assertIn("serve(router, pool, bind, check, dispatch).await", text)
        self.assertIn("crate::dispatch::Settings::standalone_from_env()", text)
        self.assertIn("crate::dispatch::publisher", text)
        for forbidden in (
            "ROOTYARD_WAKE_TRANSPORT",
            "ROOTYARD_WAKE_CHANNEL",
            "RedisWake",
            "KafkaWake",
            "Settings::from_env",
            "ServingCache::from_env",
        ):
            self.assertNotIn(forbidden, text)

    def test_standalone_scan_is_target_audit_only_and_skips_projection_jobs(self):
        dispatch = source("src/dispatch.rs")
        standalone = body(dispatch, "pub fn standalone()", "pub fn from_env()")
        self.assertIn("crate::events::TARGET_AUDIT_CONSUMER", standalone)
        self.assertNotIn("CONSUMERS.iter()", standalone)
        self.assertIn("target_audit_only: true", standalone)
        self.assertIn("projection_jobs: false", standalone)
        legacy = body(dispatch, "pub fn from_env()", "/// Runs independently")
        self.assertIn("target_audit_only: false", legacy)
        self.assertIn("projection_jobs: true", legacy)
        worker = body(dispatch, "pub async fn worker(", "/// Called outside the Git/PG commit path")
        self.assertIn("worker_once_with_lease_scoped", worker)
        self.assertIn("target_audit_only.then_some(crate::events::TARGET_AUDIT_KIND)", worker)
        self.assertIn("if settings.projection_jobs", worker)
        events = source("src/events.rs")
        self.assertIn('pub const TARGET_AUDIT_CONSUMER: &str = "audit-log"', events)
        self.assertIn('pub const TARGET_AUDIT_KIND: &str = "pg_refstore_core_commit_audit"', events)
        consumer = source("src/events/consumer.rs")
        claim = body(consumer, "async fn claim_scoped(", "async fn lock_valid_lease")
        for marker in (
            "$3::text IS NULL OR",
            "o.evidence->>'kind'=$3",
            "o.evidence->>'authority'='pg_refstore'",
            "o.evidence->>'delivery'='audit-log'",
            "o.evidence->>'source'='ref_store_core_events'",
            "o.evidence->>'repository_id'=e.repository_id::text",
            "o.evidence->>'storage_generation'=e.storage_generation::text",
            "o.evidence->>'core_operation_id'=e.operation_id::text",
            "o.evidence->>'core_revision'=e.operation_sequence::text",
            "o.evidence->>'core_outcome'='committed'",
        ):
            self.assertIn(marker, claim)
        scoped = body(consumer, "pub async fn worker_once_with_lease_scoped(", "async fn run_claims")
        self.assertIn("claim_scoped", scoped)

    def test_state_holds_only_a_unit_signal_not_event_data(self):
        text = source("src/blob_git_gateway/state.rs")
        accessors = source("src/blob_git_gateway/state/signals.rs")
        self.assertIn("dispatch: dispatch::Signals", text)
        self.assertIn("dispatch: dispatch::Signals::default()", text)
        self.assertIn("pub fn with_dispatch", accessors)
        self.assertIn("pub(in crate::blob_git_gateway) fn dispatch(&self)", accessors)
        signals = source("src/dispatch.rs")
        self.assertIn("#[derive(Clone, Default)]", signals)
        committed = body(signals, "pub fn committed(&self)", "}")
        self.assertIn("self.local.notify_one()", committed)
        self.assertIn("self.remote.notify_one()", committed)
        self.assertNotIn("Uuid", committed)
        self.assertNotIn("event", committed.lower())

    def test_trigger_requires_a_fresh_committed_terminal_with_audit_outbox(self):
        text = source("src/blob_git_gateway/publish.rs")
        legacy = body(text, "pub(super) async fn push(", "pub(super) async fn push_private(")
        self.assertIn(
            "decide(state, actor, (*plan).clone(), mode, serving.cluster_incarnation, None, deadline).await",
            legacy,
        )
        private = body(text, "pub(super) async fn push_private(", "async fn complete_private_probe(")
        receive = source("src/blob_git_gateway/receive.rs")
        self.assertIn("publish::push_private(&state, &serving, &receive, deadline).await", receive)
        fresh = body(private, "Start::Fresh { plan, _token: token }", "Start::Terminal(_)")
        self.assertIn(
            "publish_admitted_attempt(state, verified, &public_request, &plan, &token, deadline).await?", fresh
        )
        probe = body(text, "async fn complete_private_probe(", "async fn repository_owner(")
        self.assertIn(
            "operation::Probe::Replay { terminal, private_id } => Ok(PrivatePushOutcome::Terminal { terminal, private_id })",
            probe,
        )
        retired = body(text, "pub(super) async fn retire_slot_one(", "async fn publish_admitted_attempt(")
        self.assertIn(
            "publish_admitted_attempt(state, verified, public_request, &plan, &token, deadline).await?", retired
        )
        admitted = body(text, "async fn publish_admitted_attempt(", "async fn load_terminal_record(")
        self.assertIn("Some(public_request)", body(admitted, "decide(", ".await"))
        for path, publication in (("legacy", legacy), ("private", admitted)):
            with self.subTest(path=path):
                wake = body(publication, "Ok((terminal, notify)) => {", "state.dispatch().committed();")
                self.assertIn("if notify {", wake)
                self.assertLess(publication.index("decide("), publication.index("Ok((terminal, notify))"))
        self.assertEqual(text.count("state.dispatch().committed()"), 2)
        predicate = body(text, "fn should_notify", "/// The authorized A4 facade")
        self.assertIn("terminal.is_committed() && !replayed && audit_enqueued", predicate)
        decide = body(text, "async fn decide(", "/// The one trigger predicate")
        self.assertIn("Some(public) => adapter.prepare_private(state.pool(), plan, public, deadline).await", decide)
        self.assertIn("None => adapter.prepare(state.pool(), plan, deadline).await", decide)
        self.assertIn("PrepareOutcome::Replayed(receipt) => return Ok((receipt.terminal, false))", decide)
        self.assertIn("should_notify(&receipt.terminal, receipt.replayed, receipt.audit_enqueued)", decide)
        self.assertLess(decide.index(".commit_with_expected_cluster_incarnation("), decide.index("should_notify("))

    def test_core_commit_enqueues_audit_projection_in_the_same_transaction(self):
        text = source("src/ref_store/core/pack_commit/authorized/commit.rs")
        inner = body(text, "async fn commit_inner(", "async fn commit_in_tx(")
        self.assertIn("commit_in_tx(&tx, verified, backend_identity, expected_cluster_incarnation, deadline)", inner)
        self.assertLess(inner.index("commit_in_tx(&tx,"), inner.index("commit_bounded(tx,"))
        self.assertLess(inner.index("commit_bounded(tx,"), inner.index("Ok(receipt)\n"))
        commit = body(text, "async fn commit_in_tx(", "fn audit_changes(")
        committed = body(commit, "let committed = if terminal.is_committed()", "TerminalOutcome::Rejected")
        core_write = body(committed, "pg_commit::write_verified_commit(", ".await?;")
        self.assertIn("tx,", core_write)
        enqueue = body(committed, "if let Some(incarnation) = captured_cluster_incarnation", ".await?;")
        for marker in (
            "audit_enqueued = enqueue_core_audit(",
            "tx,",
            "selection.actor()",
            "&committed.terminal",
            "backend_identity",
            "incarnation,",
        ):
            self.assertIn(marker, enqueue)
        self.assertLess(committed.index("write_verified_commit("), committed.index("enqueue_core_audit("))
        receipt = body(text, "fn receipt(", "record: value.record,")
        self.assertIn("!value.replayed && value.terminal.is_committed()", receipt)
        self.assertIn("audit_enqueued: audit_enqueued && fresh_committed", receipt)
        helper = body(text, "async fn enqueue_core_audit(", "fn receipt(")
        self.assertIn('"kind": "pg_refstore_core_commit_audit"', helper)
        self.assertIn("crate::events::publish_core_commit_audit_in_tx", helper)
        self.assertIn("terminal.revision", helper)
        self.assertIn("audit_changes(format, &terminal.refs)", helper)
        self.assertIn("r.storage_backend", helper)
        self.assertIn("r.storage_generation", helper)
        self.assertIn("r.deleted_at IS NULL", helper)
        self.assertIn("ref_store_serving_repositories", helper)
        self.assertIn("repository_ref_projection", helper)
        self.assertIn("ref_store_core_events", helper)
        self.assertIn("b.backend_identity", helper)
        self.assertIn("backend_identity", helper)
        self.assertIn("core_outcome", helper)
        # The helper must consume the captured-and-compared value, never read a
        # then-current incarnation after core mutation.
        self.assertIn("restore_incarnation: Uuid", helper)
        self.assertIn("restore_incarnation", helper)
        self.assertNotIn("FROM cluster_authority", helper)
        self.assertNotIn("None => tx", helper)
        self.assertIn("RefStoreError::GateConflict", helper)
        self.assertIn("RefStoreError::IdentityConflict", helper)
        self.assertNotIn("SAVEPOINT", helper)
        self.assertNotIn("id != operation.id", helper)
        self.assertIn("if changes.is_empty() {\n        return Ok(false);", helper)
        changes = body(text, "fn audit_changes(", "async fn enqueue_core_audit(")
        self.assertIn("RefCommitResult::NotApplied { .. } => None", changes)
        self.assertIn("old_oid.clone().unwrap_or_else", changes)
        self.assertIn("new_oid.clone().unwrap_or_else", changes)

    def test_existing_worker_scan_gets_only_the_audit_delivery(self):
        text = source("src/events.rs")
        bridge = body(text, "pub async fn publish_core_commit_audit_in_tx(", "async fn publish_in_tx_guarded(")
        self.assertIn("operation.outcome != \"recorded\"", bridge)
        self.assertIn("if changes.is_empty()", bridge)
        self.assertNotIn("foreign_kind", bridge)
        self.assertNotIn("SELECT count(*) FROM git_operations", bridge)
        self.assertIn("(repository_id=$1 AND storage_generation=$2 AND sequence=$3) OR id=$4", bridge)
        self.assertIn("row.get::<_, Uuid>(0) == operation.id", bridge)
        self.assertIn("row.get::<_, Option<Uuid>>(4) == Some(operation.actor_id)", bridge)
        self.assertIn('row.get::<_, String>(8) == "recorded"', bridge)
        self.assertIn("row.get::<_, serde_json::Value>(9) == operation.evidence", bridge)
        self.assertIn("return Err(crate::ref_store::contract::RefStoreError::IdentityConflict)", bridge)
        self.assertIn("publish_in_tx_guarded(tx, operation, changes, None, None, false)", bridge)
        guarded = body(text, "async fn publish_in_tx_guarded(", "pub async fn process_ref_cas_projection_jobs(")
        self.assertIn("if enqueue_ref_index", guarded)
        self.assertIn("VALUES($1,'audit-log')", guarded)
        # The audit-only path must never enqueue the legacy ref-index effect.
        self.assertNotIn("VALUES($1,'audit-log'),($1,'ref-index')", guarded)

    def test_restore_incarnation_is_threaded_from_authorized_serving(self):
        publish = source("src/blob_git_gateway/publish.rs")
        private = body(publish, "pub(super) async fn push_private(", "async fn complete_private_probe(")
        self.assertIn("public_attempt_request_from_serving(\n                    serving,", private)
        request = body(publish, "fn public_attempt_request_from_serving(", "fn slot_zero_admission_request(")
        self.assertIn("restore_incarnation: serving.cluster_incarnation", request)
        admitted = body(publish, "async fn publish_admitted_attempt(", "async fn load_terminal_record(")
        self.assertIn("public_request.restore_incarnation,", body(admitted, "decide(", ".await"))
        decide = body(publish, "async fn decide(", "/// The one trigger predicate")
        self.assertIn(
            ".commit_with_expected_cluster_incarnation(state.pool(), &verified, expected_cluster_incarnation, deadline)",
            decide,
        )

        commit = source("src/ref_store/core/pack_commit/authorized/commit.rs")
        serving = body(commit, "pub async fn commit_with_expected_cluster_incarnation(", "async fn commit_inner(")
        self.assertIn("self.commit_inner(pool, verified, Some(expected_cluster_incarnation), deadline).await", serving)
        tx = body(commit, "async fn commit_in_tx(", "fn audit_changes(")
        public = body(tx, "let captured_cluster_incarnation = if let Some(public) = public", "let cluster = match")
        self.assertIn(
            "expected_cluster_incarnation.is_some_and(|expected| expected != public.restore_incarnation)", public
        )
        self.assertLess(public.index("RestoreIncarnationMismatch"), public.index("lock_private_pending_attempt("))
        self.assertIn("lock_private_pending_attempt(tx, public, plan, deadline).await?;", public)
        lock = body(
            source("src/ref_store/pg/public_attempt.rs"),
            "pub(crate) async fn lock_private_pending_attempt(",
            "pub(crate) async fn lock_public_attempt(",
        )
        self.assertLess(lock.index("self.lock_public_attempt("), lock.index("lock_cluster_incarnation(tx)"))
        self.assertIn("if lock_cluster_incarnation(tx).await? != public.restore_incarnation", lock)
        locked_cluster = source("src/ref_store/core/pack_snapshot/serving_read_sql/sealed.rs")
        self.assertIn("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE", locked_cluster)
        self.assertLess(tx.index("lock_private_pending_attempt("), tx.index("lock_source_tables("))

        legacy = body(tx, "let cluster = match expected_cluster_incarnation", "lock_source_tables(")
        self.assertIn("crate::ref_store::pg::bound", legacy)
        self.assertLess(legacy.index("public_cluster_incarnation_nowait"), legacy.index("PgRefStore.begin"))
        self.assertIn("Some((current, expected))", legacy)
        pending = body(legacy, "OperationState::Pending => {", "cluster.map(")
        self.assertIn("cluster.is_some_and(|(current, expected)| current != expected)", pending)
        self.assertIn("RestoreIncarnationMismatch", pending)
        replay = body(legacy, "OperationState::Committed | OperationState::Rejected", "OperationState::Cancelled")
        self.assertIn("return Ok(receipt(pg::replay_terminal(begun)?, *selection.selection_digest(), false))", replay)
        self.assertIn("cluster.map(|(current, _)| current)", legacy)
        audit = body(commit, "async fn enqueue_core_audit(", "fn receipt(")
        self.assertIn("restore_incarnation: Uuid", audit)
        self.assertNotIn("captured_restore_incarnation", audit)
        self.assertNotIn("Some(incarnation) => incarnation", audit)
        self.assertNotIn("None => tx", audit)
        self.assertNotIn("FROM cluster_authority", audit)

        contract = source("src/ref_store/contract.rs")
        self.assertIn("RestoreIncarnationMismatch", contract)
        gateway = source("src/blob_git_gateway/error.rs")
        self.assertIn("Ref::RestoreIncarnationMismatch =>", gateway)
        self.assertIn('Self::Unavailable("repository authority changed; retry the same operation")', gateway)

    def test_generic_commit_does_not_opt_into_the_target_audit_wake(self):
        text = source("src/ref_store/core/pack_commit/authorized/commit.rs")
        generic = body(text, "pub async fn commit(", "/// Final A4 commit")
        self.assertIn("self.commit_inner(pool, verified, None, deadline).await", generic)
        self.assertNotIn("commit_with_expected_cluster_incarnation", generic)
        tx = body(text, "async fn commit_in_tx(", "fn audit_changes(")
        private = body(tx, "let captured_cluster_incarnation = if let Some(public) = public", "let cluster = match")
        self.assertRegex(
            private, r"lock_private_pending_attempt\(tx, public, plan, deadline\)\.await\?;\s+"
            r"expected_cluster_incarnation\s+\} else \{"
        )
        legacy = body(tx, "let cluster = match expected_cluster_incarnation", "lock_source_tables(")
        self.assertIn("None => None,", legacy)
        self.assertIn("cluster.map(|(current, _)| current)", legacy)
        self.assertEqual(tx.count("enqueue_core_audit("), 1)
        self.assertLess(
            tx.index("if let Some(incarnation) = captured_cluster_incarnation"),
            tx.index("enqueue_core_audit("),
        )
        self.assertNotIn("SELECT incarnation FROM cluster_authority", tx)
        helper = body(text, "async fn enqueue_core_audit(", "fn receipt(")
        self.assertNotIn("FROM cluster_authority", helper)

    def test_audit_projection_is_not_a_legacy_push_webhook_or_ref_index_event(self):
        bridge = source("src/events.rs")
        bridge = body(bridge, "pub async fn publish_core_commit_audit_in_tx(", "async fn publish_in_tx_guarded(")
        self.assertIn("None, None, false", bridge)
        webhooks = source("src/webhooks/ingestion.rs")
        self.assertEqual(webhooks.count("o.evidence->>'kind'"), 2)
        self.assertIn("<> 'pg_refstore_core_commit_audit'", webhooks)
        events = source("src/events.rs")
        guarded = body(events, "async fn publish_in_tx_guarded(", "pub async fn process_ref_cas_projection_jobs(")
        self.assertIn("if enqueue_ref_index", guarded)
        self.assertNotIn("VALUES($1,'audit-log'),($1,'ref-index')", guarded)

    def test_worker_keeps_bounded_listen_and_postgres_poll(self):
        text = source("src/dispatch.rs")
        worker = body(text, "pub async fn worker(", "/// Called outside the Git/PG commit path")
        self.assertIn("tokio::time::interval(settings.poll)", worker)
        self.assertIn("signal.notified()", worker)
        self.assertIn("stop.cancelled()", worker)
        self.assertIn("crate::events::worker_once_with_lease_scoped", worker)
        self.assertIn("crate::events::process_ref_cas_projection_jobs", worker)


if __name__ == "__main__":
    unittest.main()
