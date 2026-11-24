"""Pure source guards for the activation-safe #42 private receive finish path.

No Rust, Cargo, PostgreSQL, Blob, native Git, service or network is used. These
checks pin the intended normal receive orchestration: migration-152 early
probe/finish for an existing private wrapper, the terminal mirror before any
ACK, bounded rotation from the same VerifiedReceive, and the private fresh
entry and receipt boundary.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECEIVE = ROOT / "src/blob_git_gateway/receive.rs"
OPERATION = ROOT / "src/blob_git_gateway/operation.rs"
PUBLISH = ROOT / "src/blob_git_gateway/publish.rs"
PUBLIC_ATTEMPT = ROOT / "src/ref_store/pg/public_attempt.rs"
RECEIPT = ROOT / "src/namespace_service/push_causal_stream/gateway_durable_replay.rs"


def production(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


def slice_between(source: str, start: str, end: str) -> str:
    assert start in source, start
    assert end in source, end
    return source.split(start, 1)[1].split(end, 1)[0]


class PrivateReceiveFinishSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receive = RECEIVE.read_text()
        cls.receive_prod = production(cls.receive)
        cls.operation = OPERATION.read_text()
        cls.publish = PUBLISH.read_text()
        cls.public_attempt = PUBLIC_ATTEMPT.read_text()
        cls.receipt = RECEIPT.read_text()

    def test_receive_consults_m152_before_native_and_selects_private_fresh_entry(self):
        source = self.receive_prod
        self.assertIn("operation::probe_public(", source)
        self.assertIn("operation::Probe::Finish", source)
        self.assertIn("publish::finish_public_terminal(", source)
        self.assertIn("publish::retire_slot_one(", source)
        # Fresh identifiers are admitted only through the private entry after
        # native ingestion; the legacy writer is no longer selected.
        self.assertIn("publish::push_private(", source)
        self.assertNotIn("publish::push(", source)
        self.assertNotIn("operation::probe(", source)
        self.assertLess(source.index("operation::probe_public("), source.index("native::run_capture("))
        self.assertLess(source.index("native::run_capture("), source.index("publish::push_private("))

    def test_pending_wrapper_with_terminal_private_is_finish_not_replay(self):
        probe = slice_between(self.operation, "pub(super) async fn probe_public(", "pub(super) fn classify(")
        self.assertIn("lock_public_attempt(", probe)
        self.assertIn("lock_operation(", probe)
        self.assertIn("lookup_public_attempt_finish(", probe)
        self.assertIn("lookup_public_private_in_tx(", probe)
        self.assertIn("LegacyPath", probe)
        self.assertIn("lookup_in_tx(", probe)
        self.assertIn("(OperationState::Pending, Claim::Replay(terminal)) => Ok(Probe::Finish", probe)
        self.assertIn("(OperationState::Pending, Claim::Cancelled(reason)) =>", probe)
        self.assertIn("Ok(Probe::FinishCancelled { reason })", probe)
        self.assertIn("(_, Claim::Replay(terminal)) => Ok(Probe::Replay", probe)
        self.assertNotIn("get_legacy_locked(", probe)
        self.assertNotIn("admit_slot_zero_in_tx(", probe)

    def test_private_route_has_one_pre_admission_pause_after_baseline(self):
        private = slice_between(
            self.publish,
            "pub(super) async fn push_private(",
            "async fn complete_private_probe(",
        )
        pause = "state.pause_before_admission(verified.operation_id()).await;"
        self.assertEqual(private.count(pause), 1)
        self.assertIn("if rebases == 0 {", private)
        self.assertLess(private.index("capture_baseline("), private.index(pause))
        self.assertLess(private.index(pause), private.index("operation::probe_public("))
        self.assertLess(private.index(pause), private.index("begin_slot_zero("))
        self.assertEqual(private.count("state.pause_after_admission(verified.operation_id()).await;"), 1)
        self.assertLess(
            private.index("Start::Fresh { plan, _token: token }"),
            private.index("state.pause_after_admission(verified.operation_id()).await;"),
        )

    def test_native_failure_never_closes_a_private_pending_operation_with_raw_ng(self):
        block = slice_between(
            self.receive_prod,
            "if !captured.success {",
            "let new_pairs = collect_pairs",
        )
        self.assertIn("operation::probe_public(", block)
        self.assertIn("operation::Probe::Fresh =>", block)
        self.assertIn("pending_retirement.is_some()", block)
        self.assertIn("operation::Probe::Pending => return Err(GatewayError::OutcomeUnknown)", block)
        self.assertIn("operation::Probe::Finish { terminal, private_id, record, .. } =>", block)
        self.assertIn("PublicAttemptTerminalOutcome::RetirementRequired(_) =>", block)
        self.assertIn("return Err(GatewayError::OutcomeUnknown)", block)
        self.assertIn('GatewayError::Conflict("operation cancellation requires reconciliation")', block)
        self.assertIn("native_report_is_rejection(&captured.stdout)", block)
        self.assertLess(
            block.index("operation::probe_public("),
            block.index("native_report_is_rejection(&captured.stdout)"),
            "the raw child report must be gated by the authoritative public probe",
        )

    def test_mirror_rechecks_current_write_authority_before_its_owner_commit(self):
        mirror = slice_between(
            self.publish,
            "async fn mirror_public_terminal_with_request(",
            "/// The terminal produced",
        )
        self.assertIn("lock_public_attempt(&tx, public_request, record.identity().operation_id()", mirror)
        self.assertIn("lookup_public_attempt_finish(&tx, public_request, deadline)", mirror)
        self.assertIn("found.wrapper_state == OperationState::Pending", mirror)
        self.assertIn("crate::ref_store::serving::lookup_in_tx(", mirror)
        self.assertIn("fresh.gate.repository_id() != public_request.repository_id", mirror)
        self.assertIn("fresh.gate.tenant_id() != public_request.admission_owner_id", mirror)
        self.assertIn("fresh.cluster_incarnation != public_request.restore_incarnation", mirror)
        self.assertIn("RealmExpectation::from_gate(&fresh.gate)", mirror)
        self.assertIn("mirror_public_attempt_terminal_in_tx(", mirror)
        self.assertIn("commit_deadpool_bounded(tx, deadline).await?", mirror)
        self.assertIn("rollback_deadpool_bounded(tx, deadline).await", mirror)
        self.assertLess(
            mirror.index("lookup_in_tx("),
            mirror.index("mirror_public_attempt_terminal_in_tx("),
            "owner auth must precede the mirror mutation",
        )
        self.assertNotIn("loop {", mirror)
        self.assertNotIn("private_id", mirror)
        self.assertNotIn("format!(", mirror)
        self.assertNotIn("&**tx", mirror, "the owned mirror transaction must use &tx deref coercion")
        preflight = slice_between(
            self.publish,
            "async fn slot_zero_public_preflight(",
            "/// One fresh slot-zero admission transaction",
        )
        self.assertIn("lock_public_attempt(&**tx", preflight)
        self.assertIn("lookup_in_tx(&**tx", preflight)

    def test_private_fresh_entry_selects_begin_slot_zero_and_never_the_legacy_writer(self):
        private = slice_between(
            self.publish,
            "pub(super) async fn push_private(",
            "async fn complete_private_probe(",
        )
        self.assertIn("operation::probe_public(", private)
        self.assertIn("begin_slot_zero(", private)
        self.assertIn("Start::Fresh { plan, _token: token }", private)
        self.assertIn("publish_admitted_attempt(state, verified, &public_request, &plan, &token, deadline)", private)
        final = slice_between(self.publish, "async fn publish_admitted_attempt(", "/// Load one immutable private terminal record")
        self.assertIn("publish_pair(state, plan, planned.pack_id(), pair, Some(public_request), deadline)", final)
        self.assertIn("decide(state, verified.actor(), plan.clone(), verified.mode(), Some(public_request), deadline)", final)
        self.assertIn(".reject_superseded_private(state.pool(), token, plan, verified.actor(), public_request, deadline)", final)
        self.assertIn("mirror_public_terminal_with_request(", private)
        self.assertIn("verified.actor(),", private)
        self.assertIn("PrivatePushOutcome::Terminal", private)
        self.assertIn("Start::Terminal(_)", private)
        self.assertNotIn("begin_fresh(", private)
        self.assertNotIn("\n            begin(\n", private)
        self.assertNotIn("publish::push(", self.receive_prod)
        self.assertIn(
            "publish::push_private(&state, &serving, &receive, deadline).await;",
            self.receive_prod,
        )

    def test_known_replay_requires_the_m152_marker_and_has_no_unused_binding(self):
        probe = slice_between(self.operation, "pub(super) async fn probe_public(", "pub(super) fn classify(")
        self.assertIn("PublicAttemptFinishLookup::LegacyPath", probe)
        self.assertIn("lookup_in_tx(", probe)
        self.assertIn("Claim::Replay(terminal) => Ok(Probe::Replay { terminal, private_id: None })", probe)
        self.assertNotIn("get_legacy_locked(", probe)

        replay = slice_between(
            self.publish,
            "async fn replay_slot_zero_claim(",
            "/// What one fresh-write transaction decided",
        )
        self.assertNotIn("let repository_id = public_request.repository_id;", replay)
        self.assertIn("lookup_public_private_in_tx(", replay)

    def test_finish_lookup_only_relaxes_the_exact_pending_terminal_window(self):
        status = slice_between(self.public_attempt, "fn evaluate_status(", "fn evaluate(snapshot: RawSnapshot")
        self.assertIn("validate_current_attempts(&snapshot, wrapper, state, false)", status)
        ordinary = slice_between(self.public_attempt, "fn evaluate(snapshot: RawSnapshot", "/// Finish-side evaluation")
        self.assertIn("validate_current_attempts(&snapshot, wrapper, state, false)", ordinary)
        finish = slice_between(self.public_attempt, "fn evaluate_finish(", "/// The one current/retired attempt proof")
        self.assertIn("validate_current_attempts(&snapshot, wrapper, state, true)", finish)
        current = slice_between(self.public_attempt, "fn validate_current(", "fn validate_retired(")
        self.assertIn("if !allow_finish || state != OperationState::Pending", current)
        self.assertIn("OperationState::Committed | OperationState::Rejected =>", current)
        self.assertIn("OperationState::Cancelled =>", current)
        self.assertIn("wrapper.cancelled_private_id.is_some()", current)

    def test_terminal_mirror_precedes_ack_and_retirement_keeps_one_semantic_receive(self):
        source = self.receive_prod
        finish = slice_between(source, "operation::Probe::Finish {", "operation::Probe::FinishCancelled")
        self.assertIn("publish::finish_public_terminal(", finish)
        self.assertIn("PublicAttemptTerminalOutcome::Mirrored", finish)
        self.assertIn("materialize_durable_gateway_receipt(receipt_args(false, Some(private_id)))", finish)
        self.assertIn("PublicAttemptTerminalOutcome::RetirementRequired", finish)
        self.assertIn("pending_retirement = Some((evidence, retirement));", finish)
        self.assertLess(finish.index("finish_public_terminal("), finish.index("committed_response("))

        retire = slice_between(source, "if let Some((evidence, retirement)) = pending_retirement {", "let published = publish::push_private(")
        self.assertIn("publish::retire_slot_one(&state, &refreshed, &receive, &evidence, &retirement, deadline)", retire)
        self.assertIn("refreshed.gate.repository_id() != repository_id", retire)
        self.assertIn("refreshed.cluster_incarnation != serving.cluster_incarnation", retire)
        self.assertIn("materialize_durable_gateway_receipt(receipt_args(true, Some(retired.private_id)))", retire)
        self.assertIn("committed_response(CommittedResponse", retire)
        self.assertIn("let published = publish::push_private(&state, &serving, &receive, deadline).await;", source)
        self.assertNotIn("rotate_slot_one(", source)
        self.assertNotIn("SlotOneReceive", source)

    def test_retirement_captures_a_fresh_baseline_and_rotates_only_exact_rejections(self):
        retire = slice_between(self.publish, "pub(super) async fn retire_slot_one(", "async fn publish_admitted_attempt(")
        self.assertIn("capture_baseline(state, serving.gate.repository_id(), serving.gate.tenant_id(), deadline)", retire)
        self.assertIn("admission_realm_matches_serving(&baseline, serving)", retire)
        self.assertIn("SlotOneReceive::from_verified_rejection(", retire)
        self.assertIn("let public_request = handoff.public();", retire)
        self.assertIn("slot_one::rotate_slot_one(state, serving, &handoff, &baseline, deadline)", retire)
        self.assertIn("publish_admitted_attempt(state, verified, public_request, &plan, &token, deadline)", retire)
        self.assertIn("mirror_public_terminal_with_request(", retire)
        self.assertIn("verified.actor(),", retire)
        self.assertIn("Admission::Fresh { plan, token, receipt }", retire)
        self.assertIn("return Err(GatewayError::OutcomeUnknown);", retire)
        self.assertIn("while evidence.current.slot < 2", retire)
        self.assertIn("found != private_id || refreshed.current.slot != receipt.slot", retire)
        self.assertNotIn("rebases", retire)
        self.assertNotIn("begin_fresh(", retire)

        mirror = slice_between(self.publish, "async fn mirror_public_terminal_with_request(", "/// The terminal produced")
        self.assertIn("mirror_public_attempt_terminal_in_tx(", mirror)
        self.assertIn("PublicAttemptTerminalOutcome::Mirrored(receipt)", mirror)
        self.assertIn("commit_deadpool_bounded(tx, deadline).await?", mirror)
        self.assertIn("rollback_deadpool_bounded(tx, deadline).await?", mirror)
        self.assertIn("RetirementRequired", mirror)

    def test_receipt_keeps_public_key_and_loads_private_durable_rows(self):
        self.assertIn("pub private_operation_id: Option<Uuid>", self.receipt)
        self.assertIn("let durable_operation_id = args.private_operation_id.unwrap_or(args.operation_id);", self.receipt)
        self.assertIn("load_decision_or_gate_meta(&client, args.repository_id, durable_operation_id", self.receipt)
        self.assertIn("load_all_operation_pack_pairs(&client, args.repository_id, durable_operation_id", self.receipt)
        self.assertIn("operation_id: args.operation_id", self.receipt)
        self.assertIn("push_observed_gateway_receipt(args.operation_id", self.receipt)
        self.assertNotIn("receipt.operation_id = durable_operation_id", self.receipt)
        self.assertIn("private_operation_id: private_id", self.receive_prod)
        self.assertIn("receipt_args(true, private_id)", self.receive_prod)
        self.assertIn("receipt_args(false, private_id)", self.receive_prod)

    def test_receipt_rejects_wrong_private_event_and_realm_substitution(self):
        binding = slice_between(
            self.receipt,
            "async fn require_public_private_binding(",
            "/// Preserve the independently proven legacy-only",
        )
        self.assertIn("a.slot = w.current_slot", binding)
        self.assertIn("current_private != private_id", binding)
        self.assertIn("wrapper_backend.as_str() != backend_hex", binding)
        self.assertIn("rootyard_ref_store_attempt_current_scope(w)", binding)
        self.assertIn("rootyard_ref_store_verify_public_operation($1,$2)", binding)
        self.assertIn("private_event != wrapper_event", binding)
        self.assertIn('"private receipt current attempt substitution"', binding)
        self.assertIn('"private receipt backend substitution"', binding)
        self.assertIn('"private receipt event substitution"', binding)
        self.assertIn('"private receipt realm substitution"', self.receipt)
        self.assertIn(
            "require_public_private_binding(", self.receipt
        )
        self.assertIn(
            "reject_private_claim_for_legacy_receipt(", self.receipt
        )
        self.assertIn("durable_operation_id = args.private_operation_id.unwrap_or(args.operation_id)", self.receipt)
        self.assertLess(
            self.receipt.index("require_public_private_binding("),
            self.receipt.index("FROM ref_store_operations"),
            "the public/private binding must be checked before loading the private receipt rows",
        )

    def test_finish_cancellation_fails_closed_without_a_false_ack(self):
        finish_cancel = slice_between(self.receive_prod, "operation::Probe::FinishCancelled", "// Reclaim sweeping")
        self.assertIn('GatewayError::Conflict("operation cancellation requires reconciliation")', finish_cancel)
        self.assertNotIn("committed_response(", finish_cancel)
        self.assertNotIn("terminal_response(", finish_cancel)

    def test_private_identifier_and_unknown_commit_remain_typed_and_redacted(self):
        probe = slice_between(self.operation, "pub(super) async fn probe_public(", "pub(super) fn classify(")
        self.assertIn('GatewayError::Conflict("operation identifier is already a private attempt")', probe)
        self.assertIn("Timeout", probe)
        self.assertIn("tx.rollback()", probe)
        self.assertNotIn("private_id.to_string()", probe)
        mirror = slice_between(self.publish, "async fn mirror_public_terminal_with_request(", "/// The terminal produced")
        self.assertIn("commit_deadpool_bounded(tx, deadline).await?", mirror)
        self.assertNotIn("private_id", mirror)
        commit = slice_between(self.publish, "async fn commit_deadpool_bounded(", "fn start_from_claim(")
        self.assertIn("Err(_) => Err(GatewayError::OutcomeUnknown)", commit)


if __name__ == "__main__":
    unittest.main()
