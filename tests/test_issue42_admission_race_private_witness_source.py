"""Pure source guards for the #174 same-ref race witness on the private route.

No Rust, Cargo, PostgreSQL, Git, Blob, service or network is used. These checks
pin the witness's public-wrapper/current-private lookup and its winner/loser
terminal/event expectations without changing the stock Git report assertions.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RACE = ROOT / "src/blob_git_gateway/admission_race_acceptance.rs"


def slice_between(source: str, start: str, end: str) -> str:
    assert start in source, start
    assert end in source, end
    return source.split(start, 1)[1].split(end, 1)[0]


class AdmissionRacePrivateWitnessSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = RACE.read_text()

    def test_operation_row_uses_public_wrapper_then_current_private_operation(self):
        helper = slice_between(self.source, "async fn operation_row(", "async fn core_event(")
        self.assertIn("FROM ref_store_public_operations w", helper)
        self.assertIn("JOIN ref_store_private_attempts a", helper)
        self.assertIn("a.slot = w.current_slot", helper)
        self.assertIn("WHERE w.repository_id = $1 AND w.public_id = $2", helper)
        self.assertIn("FROM ref_store_operations o", helper)
        self.assertIn("WHERE o.repository_id = $1 AND o.operation_id = $2", helper)
        self.assertIn("operation_id != private_id", helper)
        self.assertIn("operation_issuer != wrapper_issuer", helper)
        self.assertIn("operation_digest != plan_digest", helper)
        self.assertIn("operation_state != wrapper_state", helper)
        self.assertIn("private_event != Some(wrapper_event)", helper)
        self.assertIn("event_payload.as_ref() != Some(terminal)", helper)
        self.assertIn("rootyard_ref_store_verify_public_operation($1,$2)", helper)
        self.assertIn("failed exact wrapper evidence verification", helper)
        self.assertIn('"cancelled" =>', helper)
        self.assertNotIn(
            "SELECT state, terminal_result FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
            helper,
        )

    def test_operation_row_rejects_legacy_or_wrapper_only_evidence(self):
        helper = slice_between(self.source, "async fn operation_row(", "async fn core_event(")
        fallback = slice_between(helper, "let Some(wrapper) = wrapper else {", "let wrapper_issuer:")
        self.assertIn("FROM ref_store_operations", fallback)
        self.assertIn("FROM ref_store_cancellations", fallback)
        self.assertIn("FROM ref_store_private_attempts", fallback)
        self.assertIn("legacy/private evidence without a current wrapper", fallback)
        self.assertIn("has no exact private operation", helper)
        self.assertIn("has no current private attempt", fallback)
        self.assertIn("FROM ref_store_public_operations", fallback)
        self.assertIn("public_id = $2", fallback)
        self.assertIn("pending public wrapper", helper)
        self.assertIn("terminal/event evidence", helper)
        self.assertIn("is cancelled; the race witness accepts no cancellation", helper)

    def test_core_event_and_winner_loser_revisions_are_private_and_narrow(self):
        event = slice_between(self.source, "async fn core_event(", "/// Parse only a real Git `report-status`")
        self.assertIn("FROM ref_store_public_operations w", event)
        self.assertIn("a.slot = w.current_slot", event)
        self.assertIn("e.operation_id = a.private_id", event)
        self.assertIn("w.event_id = e.event_id", event)
        self.assertIn("w.state IN ('committed', 'rejected')", event)

        case = slice_between(self.source, "let revision_after = gate_revision(db, repository_id).await?;", "let durable_main = durable_main")
        self.assertIn("core_event(db, repository_id, winner_operation)", case)
        self.assertIn("core_event(db, repository_id, loser_operation)", case)
        self.assertIn('winner_event_outcome == "committed"', case)
        self.assertIn('loser_event_outcome == "rejected"', case)
        self.assertIn("winner_event_revision == revision_before + 1", case)
        self.assertIn("loser_event_revision == revision_before + 1", case)

    def test_native_stock_stale_report_assertions_are_unchanged(self):
        for marker in (
            'loser_text.contains("[rejected]") && loser_text.contains("stale info")',
            'winner_verdicts == vec![(SEED_REF.to_owned(), None)]',
            'loser_verdicts == vec![(SEED_REF.to_owned(), Some("stale info".to_owned()))]',
            "*reason == CommitRejectCode::OldOidMismatch",
            'winner_state == "committed"',
            'loser_state == "rejected"',
        ):
            self.assertIn(marker, self.source)


if __name__ == "__main__":
    unittest.main()
