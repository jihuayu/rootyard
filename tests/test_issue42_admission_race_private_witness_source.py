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


    def test_case18_uses_owned_cleanup_shell_before_schema_teardown(self):
        entry = slice_between(
            self.source,
            "async fn pre_admission_revision_mismatch_rebases_to_old_oid_mismatch()",
            "async fn post_admission_independent_refs_both_commit()",
        )
        self.assertLess(entry.index("prepare()?;"), entry.index("Db::setup().await?"))
        self.assertLess(
            entry.index("require_per_run_blob_prefix()?;"), entry.index("Db::setup().await?")
        )
        self.assertLess(entry.index("require_owned_disposable_blob_fixture()?;"), entry.index("Db::setup().await?"))
        self.assertIn("let mut resources = WitnessResources::default();", entry)
        self.assertLess(entry.index("Db::setup().await?"), entry.index("let mut resources = WitnessResources::default();"))
        self.assertIn(".catch_unwind()", entry)
        self.assertIn("resources.teardown(&db, &mut fence)", entry)
        self.assertIn("resources.seal_failed_cleanup(&db)", entry)
        self.assertLess(entry.index("resources.teardown(&db, &mut fence)"), entry.index("drop(fence);"))
        self.assertIn("Err(payload) => std::panic::resume_unwind(payload)", entry)
        self.assertNotIn("db.finish(", entry)

        teardown = slice_between(
            self.source,
            "async fn teardown(&mut self, db: &Db, fence: &mut Vec<deadpool_postgres::Client>)",
            "async fn seal_failed_cleanup",
        )
        self.assertLess(teardown.index("self.drain_pushes().await;"), teardown.index("self.drain_server("))
        self.assertLess(teardown.index("self.drain_server("), teardown.index("db.pool.close();"))
        self.assertLess(teardown.index("db.pool.close();"), teardown.index("db.teardown()"))
        self.assertIn("witness pool checkout fence failed; schema retained", teardown)
        self.assertIn("witness pool roundtrip failed; schema retained", teardown)
        self.assertIn("witness cleanup deadline elapsed; schema retained", teardown)

    def test_case18_owns_server_pause_and_push_handles(self):
        case = slice_between(self.source, "async fn case(db: &Db, resources: &mut WitnessResources", "async fn durable_main")
        self.assertNotIn("ServerGuard", case)
        self.assertNotIn("let mut loser_push", case)
        self.assertNotIn("db.finish(", case)
        self.assertIn("resources.pause.insert(", case)
        self.assertIn("resources.scratch.insert(", case)
        self.assertIn("resources.work.insert(", case)
        self.assertIn("resources.shutdown = Some(shutdown);", case)
        self.assertIn("resources.server = Some(", case)
        self.assertIn("resources.second_push = Some(spawn_push(", case)
        self.assertIn("resources.first_push = Some(spawn_push(", case)
        self.assertIn("resources.second_push.as_mut()", case)
        self.assertIn("resources.first_push.as_mut()", case)
        self.assertIn("pause.release();", case)
        self.assertLess(case.index("pause.release();"), case.index("resources.second_push = None;"))

if __name__ == "__main__":
    unittest.main()
