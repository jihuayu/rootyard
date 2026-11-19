"""Pure source guards for conservative #42 gateway reclaim settlement.

No Rust, Cargo, PostgreSQL, Blob, service or network is used. These checks pin
the narrow safety boundary before a broader public-ledger/private-attempt
correlation model exists: hold paths are backend-scoped, a run only touches its
own repository/backend record, and an unproven attempt is never relabelled as
aborted or deleted.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SWEEPER = ROOT / "src/namespace_service/push_causal_stream/reclaim_sweeper.rs"
RECLAIM = ROOT / "src/namespace_service/push_causal_stream/reclaim.rs"


def slice_between(source: str, start: str, end: str) -> str:
    assert start in source, start
    assert end in source, end
    return source.split(start, 1)[1].split(end, 1)[0]


class PrivateReclaimSettlementSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sweeper = SWEEPER.read_text()
        cls.reclaim = RECLAIM.read_text()

    def test_hold_paths_are_scoped_to_the_opened_backend(self):
        query = slice_between(self.sweeper, "pub async fn query_operation_hold_blob_paths(", "/// Authoritatively verify")
        self.assertIn("WHERE repository_id = $1 AND operation_id = $2 AND backend_identity = $3", query)
        self.assertIn("&backend_hex", query)

    def test_immediate_settlement_refuses_a_foreign_repository_or_backend(self):
        settle = slice_between(self.sweeper, "pub async fn settle_aborted_gateway_reclaim(", "/// Startup & request-entry recovery consumer")
        self.assertIn("existing.repository_id != repository_id", settle)
        self.assertIn("existing.backend_identity.as_str() != backend_hex", settle)
        self.assertLess(
            settle.index("existing.repository_id != repository_id"),
            settle.index("is_operation_proven_aborted_and_unreferenced("),
            "ownership must be checked before proof/deletion",
        )

    def test_unproven_abort_keeps_recoverable_paths_and_is_not_relabelled_aborted(self):
        settle = slice_between(self.sweeper, "pub async fn settle_aborted_gateway_reclaim(", "/// Startup & request-entry recovery consumer")
        self.assertIn("let proven = is_operation_proven_aborted_and_unreferenced(", settle)
        self.assertIn("fallback_state == UploadReclaimState::AbortUnpromoted && !proven", settle)
        self.assertIn("UploadReclaimState::OutcomeUnknown", settle)
        self.assertIn("if proven", settle)
        self.assertIn("delete_and_verify_absent(&op, &all_paths, dl)", settle)
        self.assertLess(
            settle.index("let proven = is_operation_proven_aborted_and_unreferenced("),
            settle.index("let updated = ledger.transition("),
            "proof must precede any state label",
        )
        self.assertLess(
            settle.index("let updated = ledger.transition("),
            settle.index("if proven"),
            "deletion/terminal relabel must follow the transition of the conservative state",
        )

    def test_sweeper_uses_the_same_proof_and_same_backend_scoped_paths(self):
        sweep = slice_between(self.sweeper, "pub async fn sweep_gateway_reclaim_ledger(", "async fn delete_and_verify_absent")
        self.assertIn("rec.backend_identity != backend_hex", sweep)
        self.assertIn("query_operation_hold_blob_paths(pool, rec.repository_id, rec.operation_id, backend_hex, deadline)", sweep)
        self.assertIn("is_operation_proven_aborted_and_unreferenced(pool, rid, oid, deadline)", sweep)
        self.assertIn("delete_and_verify_absent(&op, &all_paths, deadline)", sweep)
        self.assertIn("mark_reclaimed_if_proven_aborted(oid, true)", sweep)
        self.assertLess(
            sweep.index("is_operation_proven_aborted_and_unreferenced("),
            sweep.index("delete_and_verify_absent("),
        )

    def test_public_ledger_key_and_unproven_deletion_guard_are_unchanged(self):
        self.assertIn("format!(\"reclaim-{operation_id}.json\")", self.reclaim)
        mark = slice_between(self.reclaim, "pub fn mark_reclaimed_if_proven_aborted(", "pub fn load(")
        self.assertIn("if !operation_proven_aborted", mark)
        self.assertIn("cannot reclaim partial/unknown staged blobs before operation terminal abort is proven", mark)


if __name__ == "__main__":
    unittest.main()
