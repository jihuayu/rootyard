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
    def test_standalone_uses_one_local_signal_set_and_no_external_transport(self):
        text = source("src/standalone.rs")
        self.assertIn("crate::dispatch::Signals::default()", text)
        self.assertIn("state.with_dispatch(dispatch.clone())", text)
        self.assertIn("let wake = dispatch.local.clone()", text)
        self.assertIn("serve(router, pool, bind, check, wake).await", text)
        self.assertIn("crate::dispatch::Settings::standalone()", text)
        self.assertIn("wake,", text)
        for forbidden in (
            "ROOTYARD_WAKE_TRANSPORT",
            "RedisWake",
            "KafkaWake",
            "Settings::from_env",
            "ServingCache::from_env",
        ):
            self.assertNotIn(forbidden, text)

    def test_state_holds_only_a_unit_signal_not_event_data(self):
        text = source("src/blob_git_gateway/state.rs")
        self.assertIn("dispatch: dispatch::Signals", text)
        self.assertIn("dispatch: dispatch::Signals::default()", text)
        self.assertIn("pub fn with_dispatch", text)
        self.assertIn("pub(super) fn dispatch(&self)", text)
        signals = source("src/dispatch.rs")
        self.assertIn("#[derive(Clone, Default)]", signals)
        committed = body(signals, "pub fn committed(&self)", "}")
        self.assertIn("self.local.notify_one()", committed)
        self.assertIn("self.remote.notify_one()", committed)
        self.assertNotIn("Uuid", committed)
        self.assertNotIn("event", committed.lower())

    def test_trigger_requires_a_fresh_committed_terminal_with_audit_outbox(self):
        text = source("src/blob_git_gateway/publish.rs")
        push = body(text, "Start::Fresh { plan, _token: token }", "async fn repository_owner")
        self.assertIn("decide(state, actor, (*plan).clone(), mode, deadline).await", push)
        self.assertLess(push.index("decide(state"), push.index("if notify"))
        self.assertLess(push.index("if notify"), push.index("state.dispatch().committed()"))
        predicate = body(text, "fn should_notify", "/// The authorized A4 facade")
        self.assertIn("terminal.is_committed()", predicate)
        self.assertIn("!replayed", predicate)
        self.assertIn("audit_enqueued", predicate)
        decide = body(text, "async fn decide(", "/// The one trigger predicate")
        self.assertIn("PrepareOutcome::Replayed(receipt) => return Ok((receipt.terminal, false))", decide)
        self.assertIn("receipt.replayed", decide)
        self.assertIn("receipt.audit_enqueued", decide)

    def test_core_commit_enqueues_audit_projection_in_the_same_transaction(self):
        text = source("src/ref_store/core/pack_commit/authorized/commit.rs")
        commit = body(text, "async fn commit_in_tx(", "fn audit_changes(")
        self.assertIn("pg_commit::write_verified_commit(", commit)
        self.assertIn("enqueue_core_audit(", commit)
        self.assertIn("selection.actor()", commit)
        self.assertIn("&committed.terminal", commit)
        self.assertIn("backend_identity", commit)
        self.assertLess(commit.index("write_verified_commit("), commit.index("enqueue_core_audit("))
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
        self.assertIn("FROM cluster_authority", helper)
        self.assertIn("restore_incarnation", helper)
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
        self.assertIn("foreign_kind", bridge)
        self.assertIn("COALESCE(evidence->>'kind','')", bridge)
        self.assertIn("row.get::<_, Uuid>(0) == operation.id", bridge)
        self.assertIn("row.get::<_, Option<Uuid>>(4) == Some(operation.actor_id)", bridge)
        self.assertIn('row.get::<_, String>(8) == "recorded"', bridge)
        self.assertIn("row.get::<_, serde_json::Value>(9) == operation.evidence", bridge)
        self.assertIn("return Err(crate::ref_store::contract::RefStoreError::IdentityConflict)", bridge)
        self.assertIn("publish_in_tx_guarded(tx, operation, changes, None, None, false)", bridge)
        guarded = body(text, "async fn publish_in_tx_guarded(", "fn claim_from_row")
        self.assertIn("if enqueue_ref_index", guarded)
        self.assertIn("VALUES($1,'audit-log')", guarded)
        # The audit-only path must never enqueue the legacy ref-index effect.
        self.assertNotIn("VALUES($1,'audit-log'),($1,'ref-index')", guarded)

    def test_audit_projection_is_not_a_legacy_push_webhook_or_ref_index_event(self):
        bridge = source("src/events.rs")
        bridge = body(bridge, "pub async fn publish_core_commit_audit_in_tx(", "async fn publish_in_tx_guarded(")
        self.assertIn("None, None, false", bridge)
        webhooks = source("src/webhooks/ingestion.rs")
        self.assertEqual(webhooks.count("o.evidence->>'kind'"), 2)
        self.assertIn("<> 'pg_refstore_core_commit_audit'", webhooks)
        events = source("src/events.rs")
        guarded = body(events, "async fn publish_in_tx_guarded(", "fn claim_from_row")
        self.assertIn("if enqueue_ref_index", guarded)
        self.assertNotIn("VALUES($1,'audit-log'),($1,'ref-index')", guarded)

    def test_worker_keeps_bounded_listen_and_postgres_poll(self):
        text = source("src/dispatch.rs")
        worker = body(text, "pub async fn worker(", "/// Called outside the Git/PG commit path")
        self.assertIn("tokio::time::interval(settings.poll)", worker)
        self.assertIn("signal.notified()", worker)
        self.assertIn("stop.cancelled()", worker)
        self.assertIn("crate::events::worker_once_with_lease", worker)
        self.assertIn("crate::events::process_ref_cas_projection_jobs", worker)


if __name__ == "__main__":
    unittest.main()
