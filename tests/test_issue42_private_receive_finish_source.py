"""Pure source guards for the activation-safe #42 private receive finish path.

No Rust, Cargo, PostgreSQL, Blob, native Git, service or network is used. These
checks pin the intended normal receive orchestration: migration-152 early
probe/finish for an existing private wrapper, the reviewed terminal mirror
before any ACK, exactly one slot-one late retirement from the same
VerifiedReceive, the public/private receipt boundary, and the still-legacy
fresh entry.
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

    def test_receive_consults_m152_before_native_but_keeps_the_legacy_fresh_entry(self):
        source = self.receive_prod
        self.assertIn("operation::probe_public(", source)
        self.assertIn("operation::Probe::Finish", source)
        self.assertIn("publish::finish_public_terminal(", source)
        self.assertIn("publish::retire_slot_one(", source)
        # Fresh identifiers still use the reviewed legacy entry; the private
        # path only completes an already-existing wrapper.
        self.assertIn("publish::push(", source)
        self.assertIn("operation::probe(", source)
        self.assertLess(source.index("operation::probe_public("), source.index("operation::probe("))
        self.assertLess(source.index("operation::probe_public("), source.index("native::run_capture("))

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

        retire = slice_between(source, "if let Some((evidence, retirement)) = pending_retirement {", "let published = publish::push(")
        self.assertIn("publish::retire_slot_one(&state, &refreshed, &receive, &evidence, &retirement, deadline)", retire)
        self.assertIn("refreshed.gate.repository_id() != repository_id", retire)
        self.assertIn("refreshed.cluster_incarnation != serving.cluster_incarnation", retire)
        self.assertIn("materialize_durable_gateway_receipt(receipt_args(true, Some(retired.private_id)))", retire)
        self.assertIn("committed_response(CommittedResponse", retire)
        self.assertNotIn("rotate_slot_one(", source)
        self.assertNotIn("SlotOneReceive", source)

    def test_slot_one_retirement_captures_a_fresh_baseline_and_never_retries(self):
        retire = slice_between(self.publish, "pub(super) async fn retire_slot_one(", "/// Load one immutable private terminal record")
        self.assertIn("capture_baseline(state, serving.gate.repository_id(), serving.gate.tenant_id(), deadline)", retire)
        self.assertIn("admission_realm_matches_serving(&baseline, serving)", retire)
        self.assertIn("SlotOneReceive::from_verified_slot_zero(", retire)
        self.assertIn("handoff.public().clone()", retire)
        self.assertIn("slot_one::rotate_slot_one(state, serving, &handoff, &baseline, deadline)", retire)
        self.assertIn("publish_pair(state, &plan, planned.pack_id(), pair, deadline)", retire)
        self.assertIn("decide(state, verified.actor(), (*plan).clone(), verified.mode(), deadline)", retire)
        self.assertIn("mirror_public_terminal_with_request(state, &public_request, &record, deadline)", retire)
        self.assertIn("slot_one::SlotOneAdmission::Replayed(_) => Err(GatewayError::OutcomeUnknown)", retire)
        self.assertNotIn("loop {", retire)
        self.assertNotIn("rebases", retire)
        self.assertNotIn("begin_fresh(", retire)

        mirror = slice_between(self.publish, "async fn mirror_public_terminal_with_request(", "/// The one terminal produced")
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
        self.assertIn("receipt_args(false, None)", self.receive_prod)
        self.assertIn("receipt_args(true, None)", self.receive_prod)

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
        mirror = slice_between(self.publish, "async fn mirror_public_terminal_with_request(", "/// The one terminal produced")
        self.assertIn("commit_deadpool_bounded(tx, deadline).await?", mirror)
        self.assertNotIn("private_id", mirror)
        commit = slice_between(self.publish, "async fn commit_deadpool_bounded(", "fn start_from_claim(")
        self.assertIn("Err(_) => Err(GatewayError::OutcomeUnknown)", commit)


if __name__ == "__main__":
    unittest.main()
