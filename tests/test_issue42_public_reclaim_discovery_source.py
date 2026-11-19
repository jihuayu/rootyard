"""Pure source/oracle guards for read-only #42 public reclaim discovery.

No Rust, Cargo, PostgreSQL, Blob, filesystem scratch, service or network is
used. These checks pin the new crate-private discovery seam: exact migration-152
attempt validation, both slots independent of any local scratch, exact
migration-141/142 hold joins, four explicit non-deletable hold dispositions,
and deterministic owner-visible fixtures for the audit cases.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / "src/ref_store/pg.rs"
PUBLIC_ATTEMPT = ROOT / "src/ref_store/pg/public_attempt.rs"
DISCOVERY = ROOT / "src/ref_store/pg/public_reclaim.rs"
NATIVE = ROOT / "src/ref_store/pg/slot_one/tests/native.rs"
NATIVE_RECLAIM = ROOT / "src/ref_store/pg/slot_one/tests/native/reclaim.rs"
CHECKPOINT = ROOT / "scripts/refstore_issue42_slot_one_checkpoint.py"
READBACK = ROOT / "src/ref_store/pg/slot_one/tests/native/readback.rs"
RETIREMENT = ROOT / "src/ref_store/pg/slot_one/tests/native/retirement.rs"
ROTATION = ROOT / "src/ref_store/pg/slot_one/tests/native/rotation.rs"
HTTP_FIXTURE = ROOT / "src/blob_git_gateway/session_http_acceptance/public_operation_tests.rs"


def production(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


class PublicReclaimDiscoverySourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = PG.read_text()
        cls.public_attempt = PUBLIC_ATTEMPT.read_text()
        cls.discovery = DISCOVERY.read_text()
        cls.production = production(cls.discovery)
        cls.native = NATIVE.read_text()
        cls.native_reclaim = NATIVE_RECLAIM.read_text()
        cls.checkpoint = CHECKPOINT.read_text()
        cls.readback = READBACK.read_text()
        cls.retirement = RETIREMENT.read_text()
        cls.rotation = ROTATION.read_text()
        cls.http_fixture = HTTP_FIXTURE.read_text()

    def test_module_is_crate_private_and_read_only(self):
        self.assertIn("#[allow(dead_code)]\npub(crate) mod public_reclaim;", self.pg)
        self.assertIn("pub(crate) async fn discover_public_reclaim(", self.discovery)
        self.assertIn("pub(crate) enum PublicReclaimLookup", self.discovery)
        self.assertIn("pub(crate) struct PublicReclaimDiscovery", self.discovery)
        self.assertIn("pub(crate) struct PublicReclaimSlot", self.discovery)
        self.assertIn("pub(crate) struct PublicReclaimHold", self.discovery)
        # The signature has no scratch/local ledger/provider capability.
        signature = self.discovery.split("pub(crate) async fn discover_public_reclaim(", 1)[1].split(")", 1)[0]
        for forbidden in ("scratch", "Path", "BlobStore", "Operator", "ledger_dir"):
            self.assertNotIn(forbidden, signature)
        for forbidden in (
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "TRUNCATE ",
            "ALTER TABLE",
            "CREATE TABLE",
            "DROP TABLE",
        ):
            self.assertNotIn(forbidden, self.production)
        self.assertNotIn("op.head(", self.production)
        self.assertNotIn("op.delete(", self.production)
        self.assertNotIn("Lease", self.production)
        self.assertNotIn("lease(", self.production)

    def test_reuses_the_exact_public_attempt_validator(self):
        method = self.discovery.split("pub(crate) async fn discover_public_reclaim(", 1)[1]
        self.assertIn("self.lookup_public_attempt(tx, request, deadline).await?", method)
        self.assertIn("PublicAttemptLookup::Unknown", method)
        self.assertIn("PublicAttemptLookup::PrivateIdentifier", method)
        self.assertIn("PublicAttemptLookup::LegacyPath", method)
        self.assertIn("PublicAttemptLookup::Pending", method)
        self.assertIn("PublicAttemptLookup::Committed", method)
        self.assertIn("PublicAttemptLookup::Rejected", method)
        self.assertIn("PublicAttemptLookup::Cancelled", method)
        # Retired slot zero and current slot one are both selected from the
        # validator's evidence; neither path consults local state.
        self.assertIn("if let Some(retired) = evidence.retired.as_ref()", method)
        self.assertIn("private_ids.push(retired.private_id);", method)

    def test_discovery_proves_one_read_only_repeatable_read_snapshot(self):
        method = self.discovery.split("pub(crate) async fn discover_public_reclaim(", 1)[1]
        self.assertIn("require_stable_snapshot(tx, deadline).await?", method)
        self.assertLess(
            method.index("require_stable_snapshot("),
            method.index("self.lookup_public_attempt("),
            "isolation/catalog proof must precede the validator read",
        )
        self.assertIn("current_setting('transaction_isolation')", self.production)
        self.assertIn("current_setting('transaction_read_only')", self.production)
        self.assertIn('isolation != "repeatable read"', self.production)
        self.assertIn('read_only != "on"', self.production)
        self.assertIn("public reclaim discovery requires a read-only repeatable read transaction", self.production)
        self.assertIn("public reclaim discovery requires migrations 141 and 142", self.production)
        self.assertIn("timeout_at(deadline, tx.query_one(SNAPSHOT_AND_CATALOG_PROBE", self.production)
        for relation in (
            "artifact_holds",
            "artifact_hold_requests",
            "artifact_hold_consume_receipts",
            "ref_store_core_pack_artifacts",
            "ref_store_core_pack_publications",
        ):
            self.assertIn(f"to_regclass('{relation}') IS NOT NULL", self.production)
        # Both reads use the same caller-owned transaction and absolute deadline.
        self.assertIn("self.lookup_public_attempt(tx, request, deadline)", method)
        self.assertIn("read_hold_rows(tx, request, &evidence, deadline)", method)

    def test_hold_query_is_exact_scope_and_exact_join(self):
        sql = self.discovery.split('const SELECT_RECLAIM_HOLDS: &str = r#"', 1)[1].split('"#;', 1)[0]
        self.assertIn("WHERE h.repository_id = $1", sql)
        self.assertIn("AND h.operation_id = ANY($2::uuid[])", sql)
        self.assertNotIn("h.backend_identity =", sql)
        self.assertIn("'backend_identity', h.backend_identity", sql)
        self.assertIn("LEFT JOIN artifact_hold_requests r ON r.request_id = h.request_id", sql)
        self.assertIn("LEFT JOIN artifact_hold_consume_receipts c ON c.hold_id = h.hold_id", sql)
        self.assertIn(
            "ON a.acquire_request_id = h.request_id AND a.hold_id = h.hold_id",
            sql,
        )
        self.assertIn("LEFT JOIN ref_store_core_pack_publications p ON p.registration_id = a.registration_id", sql)
        for column in (
            "h.storage_tenant_id",
            "h.authority_id",
            "h.authority_generation",
            "h.attempt_id",
            "a.registration_id",
            "a.role",
            "a.slot",
            "a.consume_request_id",
            "p.parent_digest",
            "p.plan_operation_id",
            "p.backend_identity",
        ):
            self.assertIn(column, sql)
        self.assertLess(
            self.discovery.index("self.lookup_public_attempt("),
            self.discovery.index("tx.query(\n            SELECT_RECLAIM_HOLDS"),
            "the durable attempt proof must precede hold reads",
        )
        self.assertIn(
            "&[&request.repository_id, &private_ids, &limit]",
            self.production,
        )
        self.assertIn("LIMIT $3", sql)

    def test_backend_mismatch_is_surfaced_not_filtered(self):
        sql = self.discovery.split('const SELECT_RECLAIM_HOLDS: &str = r#"', 1)[1].split('"#;', 1)[0]
        self.assertNotIn("AND h.backend_identity = $2", sql)
        self.assertIn("'backend_identity', h.backend_identity", sql)
        validation = self.discovery.split("fn validate_hold(", 1)[1].split("\n#[derive(Clone, Deserialize)]", 1)[0]
        self.assertIn("hold.backend_identity != request.backend_identity", validation)
        self.assertIn("RequestScopeMismatch", validation)
        self.assertIn("fn backend_mismatch_is_unresolved_not_omitted()", self.discovery)
        self.assertIn('"a mismatched backend hold must not disappear"', self.discovery)

    def test_scope_and_plan_bindings_never_certify_on_mismatch(self):
        validation = self.discovery.split("fn validate_hold(", 1)[1].split("\n#[derive(Clone, Deserialize)]", 1)[0]
        for marker in (
            "req.repository_id != request.repository_id",
            "req.tenant_id != request.admission_owner_id",
            "req.history_incarnation != request.history_incarnation",
            "req.authority_epoch != request.authority_epoch",
            "req.group_epoch != request.group_epoch",
            "req.backend_identity != request.backend_identity",
            "req.operation_issuer_id != request.issuer_id",
            "req.operation_lane != attempt.lane.as_str()",
            "req.operation_sequence != attempt.sequence",
            "req.operation_id != attempt.private_id",
            "req.operation_digest != attempt.plan_digest.as_hex()",
            "hold.operation_digest != attempt.plan_digest.as_hex()",
            "publication.parent_digest != attempt.plan_digest.as_hex()",
            "publication.plan_operation_id != attempt.private_id",
            "publication.backend_identity != hold.backend_identity",
            "receipt.consume_request_id.is_nil()",
            "artifact.consume_request_id != receipt.consume_request_id",
        ):
            self.assertIn(marker, validation)
        for reason in (
            "MissingRequest",
            "RequestScopeMismatch",
            "InvalidLocator",
            "MissingReceipt",
            "ReceiptMismatch",
            "ArtifactMismatch",
            "RegistrationMismatch",
            "PairIncomplete",
        ):
            self.assertIn(reason, self.discovery)

    def test_statuses_are_explicit_and_registered_pairs_are_retained(self):
        for status in ("Unconsumed", "Consumed", "Registered", "Unresolved"):
            self.assertIn(status, self.production)
        self.assertIn("registration_pack: BTreeMap<Uuid, Uuid>", self.discovery)
        self.assertIn("indexes.len() == 2", self.discovery)
        self.assertIn("roles.contains(&PublicReclaimArtifactRole::Pack)", self.discovery)
        self.assertIn("roles.contains(&PublicReclaimArtifactRole::Index)", self.discovery)
        self.assertIn("Migration-142 publications are retention roots", self.discovery)
        self.assertIn("Consumption is not quiescence", self.discovery)
        # No deletion or eligibility capability is exposed.
        for forbidden in ("fn delete", "fn reclaim", "fn eligible_for_delete", "DeletionCapability"):
            self.assertNotIn(forbidden, self.discovery)

    def test_both_slots_are_reported_even_with_zero_holds(self):
        self.assertIn("attempts.sort_by_key(|attempt| attempt.slot);", self.discovery)
        self.assertIn("let rows = by_slot.remove(&attempt.slot).unwrap_or_default();", self.discovery)
        self.assertIn("holds: Vec<PublicReclaimHold>", self.discovery)
        self.assertIn("slots.push(PublicReclaimSlot", self.discovery)
        self.assertIn("fn zero_actual_holds_still_reports_both_attempt_slots()", self.discovery)

    def test_deterministic_oracle_cases_are_present(self):
        for case in (
            "same_bytes_in_two_slots_are_discovered_independently",
            "wrong_scope_hold_is_unresolved_not_certified",
            "zero_actual_holds_still_reports_both_attempt_slots",
            "pending_and_legacy_markers_are_distinct_from_discovery",
            "unconsumed_and_consumed_are_distinct_from_registered",
            "partial_registration_pair_is_unresolved_not_certified",
            "backend_mismatch_is_unresolved_not_omitted",
            "hold_inventory_cap_accepts_exactly_cap_and_refuses_cap_plus_one",
        ):
            self.assertIn(f"fn {case}()", self.discovery)
        self.assertIn('"b".repeat(64)', self.discovery)
        self.assertIn("PublicReclaimLookup::LegacyPath", self.discovery)
        self.assertIn("OperationState::Pending", self.discovery)

    def test_discovery_value_is_sealed_and_not_constructible_outside_module(self):
        self.assertIn("Found(PublicReclaimDiscovery)", self.production)
        for name in ("PublicReclaimDiscovery", "PublicReclaimSlot", "PublicReclaimHold"):
            header = f"pub(crate) struct {name} {{"
            self.assertIn(header, self.production)
            body = self.production.split(header, 1)[1].split("}", 1)[0]
            self.assertNotIn("\n    pub ", body, f"{name} must expose no public mutable fields")
        self.assertNotIn("impl PublicReclaimDiscovery {", self.production)
        for forbidden in (
            "impl Default for PublicReclaimDiscovery",
            "impl From<",
            "impl TryFrom<",
            "pub fn new(",
            "pub(crate) fn new(",
        ):
            self.assertNotIn(forbidden, self.production)
        # The raw-row projection helper is compiled only for internal tests.
        self.assertNotIn("fn project_lookup(", self.production)
        self.assertIn("#[cfg(test)]\nmod tests {", self.discovery)
        self.assertIn("fn project_lookup(", self.discovery)
        self.assertIn(
            "A successful bounded read does not imply quiescence",
            self.production,
        )
        self.assertIn("does not grant deletion authority", self.production)
        self.assertIn("does not prove completion", self.production)

    def test_hold_inventory_is_capped_by_repo_max_holds_without_truncation(self):
        sql = self.discovery.split('const SELECT_RECLAIM_HOLDS: &str = r#"', 1)[1].split('"#;', 1)[0]
        self.assertIn("use crate::ref_store::core::artifact_hold::REPO_MAX_HOLDS;", self.production)
        self.assertIn("LIMIT $3", sql)
        self.assertIn("let cap = usize::try_from(REPO_MAX_HOLDS)", self.production)
        self.assertIn("let limit = cap.checked_add(1)", self.production)
        self.assertIn("let limit = i64::try_from(limit)", self.production)
        self.assertIn("ensure_hold_inventory_within_cap(rows.len(), cap)?;", self.production)
        self.assertIn("fn ensure_hold_inventory_within_cap(rows: usize, cap: usize)", self.production)
        self.assertIn("public reclaim discovery hold inventory exceeds the repository cap", self.production)
        self.assertIn("retained all-history repository hold", self.production)
        self.assertIn("ceiling, not an active-only count", self.production)
        self.assertIn("one row per retained hold", self.production)
        # The cap+1 check must happen before any row is decoded/projected.
        self.assertLess(
            self.production.index("ensure_hold_inventory_within_cap(rows.len(), cap)?"),
            self.production.index("serde_json::from_value::<RawReclaimRow>"),
            "over-cap rows must be refused before decoding",
        )
        self.assertIn("fn hold_inventory_cap_accepts_exactly_cap_and_refuses_cap_plus_one()", self.discovery)
        self.assertNotIn("LIMIT cap", self.production)
        self.assertNotIn("truncate(", self.production)

    def test_reviewed_native_compile_prerequisites_are_present(self):
        self.assertIn(
            "core::pack_commit::{CapturedRef, PackCommitPlan, PackCommitTerminal}",
            self.readback,
        )
        self.assertNotIn(
            "CapturedRef, IssuerLane, OperationLookup, OperationRecord, OperationState",
            self.readback,
        )
        self.assertIn("RefUpdate, TerminalKind", self.retirement)
        self.assertEqual(
            self.retirement.count("tokio_postgres::Client::transaction(&mut client)"),
            1,
        )
        self.assertEqual(
            self.rotation.count("tokio_postgres::Client::transaction(&mut client)"),
            2,
        )
        self.assertIn(
            "backend_identity: gateway.store.backend_identity().as_hex().to_owned(),",
            self.http_fixture,
        )

    def test_hosted_witness_is_owned_ignored_and_keeps_existing_cases(self):
        self.assertIn("mod reclaim;", self.native)
        self.assertIn("slot_zero_rejection_selects_retirement_on_real_a3_a4", self.native)
        self.assertIn("slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5", self.native)
        self.assertIn(
            "slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5",
            self.checkpoint,
        )
        self.assertNotIn("public_reclaim_discovery_reads_both_real_slots_read_only", self.checkpoint)
        self.assertIn(
            "async fn public_reclaim_discovery_reads_both_real_slots_read_only()",
            self.native_reclaim,
        )
        self.assertIn("#[tokio::test]", self.native_reclaim)
        self.assertIn(
            '#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]',
            self.native_reclaim,
        )
        for marker in (
            "require_owned_disposable_fixture()?",
            "db::Db::setup().await?",
            "require_postgres_17(&db).await?",
            "retire_p0(&db, &store, &git).await?",
            "rotate_and_commit(&db, &store, &git, &retired).await?",
            "mirror_p2_terminal_and_prove_replay(&db, &retired, &rotation).await?",
            "db.finish(outcome).await",
        ):
            self.assertIn(marker, self.native_reclaim)
        for forbidden in (
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "TRUNCATE ",
            "store.delete",
            "store.put",
            "new_upload",
            "consume_and_upload",
            "register_publication",
            "op.delete",
            "sleep(",
        ):
            self.assertNotIn(forbidden, self.native_reclaim)

    def test_hosted_witness_uses_explicit_read_only_repeatable_read_and_refusals(self):
        source = self.native_reclaim
        self.assertIn("IsolationLevel::RepeatableRead", source)
        self.assertIn("IsolationLevel::ReadCommitted", source)
        self.assertIn(".read_only(true)", source)
        self.assertIn(".read_only(read_only)", source)
        self.assertIn("IsolationLevel::RepeatableRead, false", source)
        self.assertIn("is_stable_snapshot_refusal", source)
        self.assertIn("PgRefStore.discover_public_reclaim", source)
        self.assertIn("PublicReclaimLookup::Found", source)
        self.assertIn("found.test_view()", source)
        self.assertLess(
            source.index("assert_wrong_mode_refused(db, &retired.public, IsolationLevel::RepeatableRead, false)"),
            source.index("read_discovery(db, &retired.public)"),
            "writable repeatable-read rejection must precede the successful snapshot",
        )
        self.assertLess(
            source.index("assert_wrong_mode_refused(db, &retired.public, IsolationLevel::ReadCommitted, true)"),
            source.index("read_discovery(db, &retired.public)"),
            "wrong-isolation read-only rejection must precede the successful snapshot",
        )

    def test_hosted_witness_asserts_real_lanes_objects_and_no_mutation(self):
        source = self.native_reclaim
        for marker in (
            "artifact_hold_consume_receipts",
            "ref_store_core_pack_artifacts",
            "ref_store_core_pack_publications",
            "ref_store_private_attempts",
            "pa.public_id=$2",
            "h.operation_id=ANY($3::uuid[])",
            "p.parent_digest,p.backend_identity,a.consume_request_id",
            "publication_parent == plan_digest",
            "artifact_consume == consume_request_id",
            "PublicReclaimHoldDisposition::Registered",
            ".head(&hold.locator",
            "slot_zero.private_id == retired.admission.private_id",
            "slot_one.private_id == p2.private_id",
            "slot_zero.state == OperationState::Rejected",
            "slot_one.state == OperationState::Committed",
            "before == after",
        ):
            self.assertIn(marker, source)
        self.assertIn("async fn reader_state(", source)
        for table in (
            "ref_store_core_refs",
            "ref_store_core_gates",
            "ref_store_public_operations",
            "ref_store_private_attempts",
            "ref_store_operations",
            "ref_store_core_events",
            "artifact_hold_requests",
            "artifact_holds",
            "artifact_hold_consume_receipts",
            "ref_store_core_pack_publications",
            "ref_store_core_pack_artifacts",
            "ref_store_core_pack_memberships",
        ):
            self.assertIn(table, source)
        self.assertIn("does not assert quiescence", source)
        self.assertIn("deletion authority", source)
        self.assertIn("production witness remains unwired", source)

    def test_test_only_inspector_is_cfg_test_and_not_in_production(self):
        self.assertNotIn("PublicReclaimTestView", self.production)
        self.assertNotIn("fn test_view(", self.production)
        self.assertNotIn("fn is_stable_snapshot_refusal(", self.production)
        self.assertIn(
            "#[cfg(test)]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub(crate) struct PublicReclaimTestView",
            self.discovery,
        )
        self.assertIn("#[cfg(test)]\nimpl PublicReclaimDiscovery", self.discovery)
        self.assertIn("#[cfg(test)]\npub(crate) fn is_stable_snapshot_refusal", self.discovery)
        self.assertIn("no mutable reference", self.discovery)

    def test_debug_output_does_not_expose_private_or_physical_identities(self):
        for marker in (
            '.field("public_id", &"<redacted>")',
            '.field("private_id", &"<redacted>")',
            '.field("plan_digest", &"<redacted>")',
            '.field("proof_digest", &"<redacted>")',
            '.field("event_id", &self.event_id.map(|_| "<redacted>"))',
            '.field("request_id", &"<redacted>")',
            '.field("hold_id", &"<redacted>")',
            '.field("backend_identity", &"<redacted>")',
            '.field("storage_attempt_id", &"<redacted>")',
            '.field("content_sha256", &"<redacted>")',
        ):
            self.assertIn(marker, self.discovery)
        self.assertIn('.field("registration_id", &"<redacted>")', self.discovery)
        self.assertIn('.field("pack_id", &"<redacted>")', self.discovery)
        # Marker variants remain data-free.
        markers = self.discovery.split("pub(crate) enum PublicReclaimLookup", 1)[1].split("}", 1)[0]
        self.assertNotIn("Uuid", markers)
        self.assertNotIn("Vec<", markers)

    def test_public_attempt_validator_is_still_the_shared_authority(self):
        self.assertIn("pub(crate) async fn lookup_public_attempt(", self.public_attempt)
        self.assertIn("fn validate_current_attempts(", self.public_attempt)
        self.assertIn("fn validate_retired(", self.public_attempt)
        self.assertIn("revision_mismatch_rejection", self.public_attempt)
        self.assertIn("rootyard_ref_store_attempt_has_binding(w, a)", self.public_attempt)


if __name__ == "__main__":
    unittest.main()
