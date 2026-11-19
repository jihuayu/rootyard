"""Pure source checks for the private gateway slot-one PG/Blob checkpoint.

No Cargo, database, Blob service, Git child or network is used. These checks pin
the ignored real-fixture cases, the producer-derived body seam, the exact
fresh/readback assertions, the revoked-fresh and later-gate replay transitions,
and the unchanged legacy receive route.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "src/ref_store/pg/slot_one/tests/native/gateway.rs"
NATIVE = ROOT / "src/ref_store/pg/slot_one/tests/native.rs"
RETIREMENT = ROOT / "src/ref_store/pg/slot_one/tests/native/retirement.rs"
READBACK = ROOT / "src/ref_store/pg/slot_one/tests/native/readback.rs"
SUPPORT = ROOT / "src/blob_git_gateway/slot_one_acceptance_support.rs"
RECEIVE = ROOT / "src/blob_git_gateway/receive.rs"
SLOT_ONE = ROOT / "src/blob_git_gateway/publish/slot_one.rs"
MOD = ROOT / "src/blob_git_gateway/mod.rs"

CASES = (
    "slot_one_handoff_commits_fresh_private_attempt_on_real_a3_a4_a5",
    "slot_one_handoff_revoked_fresh_rolls_back_and_replays_after_later_gate",
)


def production(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


class SlotOneHandoffPostgresSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gateway = GATEWAY.read_text()
        cls.native = NATIVE.read_text()
        cls.retirement = RETIREMENT.read_text()
        cls.readback = READBACK.read_text()
        cls.support = SUPPORT.read_text()
        cls.receive = RECEIVE.read_text()
        cls.slot_one = SLOT_ONE.read_text()
        cls.mod = MOD.read_text()

    def test_two_cases_are_ignored_and_hard_fail_without_owned_fixture(self):
        self.assertEqual(self.gateway.count("#[tokio::test]"), 2)
        self.assertEqual(self.gateway.count('#[ignore = "requires real PostgreSQL 17'), 2)
        self.assertIn("setup::{require_owned_disposable_fixture, require_postgres_17}", self.gateway)
        self.assertIn("require_owned_disposable_fixture()?;", self.gateway)
        self.assertIn("require_postgres_17(&db).await?;", self.gateway)
        self.assertIn("Db::setup().await?", self.gateway)
        self.assertEqual(self.gateway.count("db.finish(outcome).await"), 2)
        for name in CASES:
            self.assertIn(f"async fn {name}()", self.gateway)
        self.assertIn("mod gateway;", self.native)

    def test_subject_is_the_private_gateway_handoff_and_real_staged_bytes(self):
        self.assertIn("SlotOneReceive::from_verified_slot_zero", self.slot_one)
        self.assertIn("pub(in crate::blob_git_gateway) async fn rotate_slot_one(", self.slot_one)
        self.assertIn("SlotOneReceive::from_verified_slot_zero", self.support)
        self.assertIn("rotate_slot_one(state, serving, &handoff, baseline, deadline)", self.support)
        self.assertIn("let pair = Pair::stage(pack.to_path_buf(), idx.to_path_buf(), public_id).await?;", self.support)
        self.assertIn("public wire digest is derived by the", self.retirement)
        self.assertIn("acceptance::write_producer_body(", self.retirement)
        self.assertIn("acceptance::producer_request_digest(", self.retirement)
        self.assertIn("receive::producer_request_digest(", self.support)
        self.assertIn("receive::verified_receive_from_test_wire(", self.support)
        self.assertIn("#[cfg(test)]\npub(crate) mod slot_one_acceptance_support;", self.mod)

    def test_retirement_boundary_uses_independent_private_evidence(self):
        self.assertIn("private_evidence: PublicAttemptEvidence", self.native)
        self.assertIn(
            "private_retirement_evidence(db, &public, &admission, &retirement)",
            self.retirement,
        )
        self.assertIn("let evidence = &retired.private_evidence;", self.gateway)
        self.assertNotIn("PublicAttemptLookup::Rejected", self.gateway)
        self.assertIn("wrapper_state == OperationState::Pending.as_str()", self.readback)
        self.assertIn("retirement private operation is not rejected", self.readback)
        self.assertIn("retirement private event differs from the selected retirement", self.readback)
        self.assertIn(
            "blob_git_gateway::{BlobGitConfig, BlobGitState, GatewayError, slot_one_acceptance_support as acceptance}",
            self.gateway,
        )
        self.assertNotIn("error::GatewayError", self.gateway)

    def test_replay_uses_historical_baseline_and_full_repository_snapshot(self):
        case = self.gateway.split(CASES[1], 1)[1]
        self.assertIn(
            "baseline.gate().revision() < replay_baseline.gate().revision()",
            case,
        )
        historical = case.split("// Pass the pre-advance historical baseline", 1)
        self.assertEqual(len(historical), 2)
        self.assertIn("&baseline,", historical[1].split("let replay_receipt", 1)[0])
        self.assertIn("assert_snapshot_invariants(&before_replay)", case)
        self.assertIn("assert_snapshot_invariants(&after_replay)", case)
        self.assertIn("assert_snapshot_invariants(&after_refused_replay)", case)
        self.assertIn("assert_snapshot_invariants(&after_restored_replay)", case)
        self.assertIn("'head'", self.gateway)
        self.assertIn("'counts'", self.gateway)
        self.assertNotIn("o.operation_id IN", self.gateway)
        self.assertNotIn("s.operation_id IN", self.gateway)
        self.assertNotIn("e.operation_id IN", self.gateway)
        self.assertIn('anyhow!("public attempt lookup failed")', self.gateway)
        self.assertIn('anyhow!("committed slot-one terminal mirror failed")', self.gateway)
        self.assertNotIn("public attempt lookup failed: {error:?}", self.gateway)
        self.assertNotIn("committed slot-one terminal mirror failed: {error:?}", self.gateway)
        self.assertNotIn("P0 operation lookup failed: {error:?}", self.retirement)
        self.assertNotIn("public terminal mirror failed: {error:?}", self.retirement)

    def test_receive_stays_on_legacy_publish_push(self):
        production_receive = production(self.receive)
        self.assertIn("publish::push(", production_receive)
        self.assertNotIn("rotate_slot_one(", production_receive)
        self.assertNotIn("SlotOneReceive", production_receive)

    def test_fresh_case_asserts_commit_wrapper_terminal_sequence_and_refs(self):
        case = self.gateway.split(CASES[0], 1)[1].split(CASES[1], 1)[0]
        for marker in (
            "acceptance::rotate_direct(",
            "stage(&db, &store, &plan, &retired.p0_files).await?;",
            "authorized_commit(&db, &store, &git, &retired.actor, plan.clone()).await?;",
            "assert_a5_after_rotation(&db, &store, &retired, &plan).await?;",
            "mirror_committed_terminal(&db, &retired.public, &p2_record).await?;",
            "wrapper.current_slot == 1",
            "wrapper.state == \"committed\"",
            "wrapper.retired_event_id == Some(retired.retirement.event_id)",
            "PublicAttemptLookup::Committed(evidence)",
            "slot_one.sequence > slot_zero.sequence",
            "slot_one.base_revision == retired.gate.revision()",
            "stored_ref(&db, retired.repository.id, REF_RETRY)",
            "stored_ref(&db, retired.repository.id, \"refs/heads/main\")",
            "stored_ref(&db, retired.repository.id, REF_SIDE)",
        ):
            self.assertIn(marker, case)

    def test_second_case_revokes_restores_and_replays_after_later_gate(self):
        case = self.gateway.split(CASES[1], 1)[1]
        for marker in (
            "revoke_identity(&db.pool, &retired.actor).await?;",
            "matches!(refused, Err(GatewayError::Unauthorized))",
            "ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await? == retired_snapshot",
            "issue_identity(&db.pool, &retired.actor.username).await?",
            "advance_gate(&db, &store, &git, &retired, &restored).await?",
            "capture_baseline(&db, retired.repository.id, retired.verified.tenant).await?",
            "acceptance::Admission::Replayed(receipt)",
            "replay_receipt.private_id == fresh.private_id",
            "operation_event_id(&db, retired.repository.id, retired.admission.private_id)",
            "revoke_identity(&db.pool, &restored).await?",
            "matches!(refused_replay, Err(GatewayError::Unauthorized))",
            "issue_identity(&db.pool, &retired.actor.username).await?",
        ):
            self.assertIn(marker, case)
        self.assertIn("const LEDGER_SNAPSHOT", self.gateway)
        for table in (
            "ref_store_public_operations",
            "ref_store_private_attempts",
            "ref_store_operations",
            "ref_store_serving_operations",
            "ref_store_core_events",
            "ref_store_core_refs",
            "ref_store_core_gates",
            "ref_store_issuer_lanes",
            "ref_store_core_pack_publications",
        ):
            self.assertIn(table, self.gateway)

    def test_no_sleep_or_token_output_and_route_is_unselected(self):
        self.assertNotIn("sleep(", self.gateway)
        self.assertNotIn("println!", self.gateway)
        self.assertNotIn("ryt_", self.gateway)
        self.assertNotIn("DATABASE_URL", self.gateway)
        self.assertIn('if producer_request {', self.retirement)
        self.assertIn('wire_digest(format, REF_RETRY, None, &retry_oid, CommitMode::Atomic)', self.retirement)


if __name__ == "__main__":
    unittest.main()
