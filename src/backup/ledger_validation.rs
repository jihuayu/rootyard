//! SQL, row decoding and the deadline-bounded source validator of the paired
//! archive.
//!
//! [`validate_source`] runs on the *caller's* `GenericClient` — during backup
//! that is the exported-snapshot `REPEATABLE READ` transaction, during restore
//! the restored database — and every read shares the caller's absolute
//! deadline. It opens no connection, begins no transaction and takes no second
//! snapshot. All decisions live in the pure [`super::ledger_sets`] checkers.
//!
//! The reads are deliberately independent of the artifact rows:
//!
//! 1. the deployed realm of every `pg_refstore` repository (serving binding and
//!    core gate must agree with each other and with the repository owner);
//! 2. every declared set row (membership, A5 snapshot packs, retained root
//!    packs, serving read leases) with its publication, the actual repository
//!    and core gate tenants, its artifacts, the acquire request, the durable
//!    holds and the consume receipts;
//! 3. every pack-verified A5 snapshot header with its descriptors;
//! 4. every retained root capture with its complete pack rows, re-proven by the
//!    core's own `retention_root` capture validator on this same transaction;
//! 5. every transient serving read capture header with its own refs, complete
//!    pack descriptors and artifact rows (migration 146), re-proven by the core's
//!    own serving-read re-derivation (`pack_snapshot::check_membership`,
//!    `check_canonical_serving`); a header with no packs and a descriptor whose
//!    header is missing are both enumerated, never joined away;
//! 6. root heads and release tombstones, so a lost capture is visible;
//! 7. the declared rows of registrations that (2) cannot see at all.
use super::ledger_sets::{
    ActualRepository, DeclaredPair, HoldRow, PairArtifact, PublishedPack, Realm, ReceiptRow, RequestRow,
    RetainedArtifact, RetainedPack, RootCapture, RootHead, RootProof, RootTombstone, SnapshotSet, SourceSets,
};
use super::*;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::ArtifactSetDigest;
use crate::ref_store::core::retention_root;
use std::collections::BTreeMap;
use tokio_postgres::GenericClient;

const TIMED_OUT: &str = "source artifact validator deadline exceeded";
const CAPTURE_UNPROVEN: &str = "retained root capture cannot be re-proven";

/// Every declared set row: source kind, declaring header and the complete pack
/// descriptor it stored. Only `pg_refstore` repositories declare packs, and each
/// kind is enumerated from its own table, never from the artifact rows, so a
/// missing pair cannot shrink the declared set:
///
/// * `membership`: the live pack set of the core gate;
/// * `snapshot_packs`: an A5 snapshot pack set;
/// * `root_packs`: a retained root (active or released; a release-before-register
///   tombstone has no capture row and therefore declares nothing);
/// * `serving_read_packs`: a transient serving read lease.
///
/// Each set row carries its own artifact-set digest and joined revision, so a
/// partial or re-pointed row is a mismatch instead of being averaged away.
pub(super) const DECLARED_SETS: &str = "WITH scoped AS (
           SELECT 'membership'::text source,p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_pack_memberships p
            UNION ALL
           SELECT 'snapshot_packs',p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_snapshot_packs p
            UNION ALL
           SELECT 'root_packs',p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,p.joined_revision
             FROM public.ref_store_core_root_packs p
            UNION ALL
           SELECT 'serving_read_packs',s.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_serving_read_packs p
             JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id),
         declared AS (
           SELECT s.* FROM scoped s
             JOIN public.repositories r ON r.id=s.repository_id AND r.storage_backend='pg_refstore'),
         sets AS (
           SELECT d.repository_id,d.pack_id,d.registration_id,
                  array_agg(DISTINCT d.source ORDER BY d.source) declared_by,
                  array_agg(DISTINCT d.source||'='||d.artifact_set_digest||'@'||d.joined_revision ORDER BY d.source||'='||d.artifact_set_digest||'@'||d.joined_revision)
                    declared_sets
             FROM declared d
            GROUP BY d.repository_id,d.pack_id,d.registration_id),
         published AS (
           SELECT s.*,g.registration_id IS NOT NULL registered,
                  g.repository_id publication_repository_id,g.pack_id publication_pack_id,
                  g.tenant_id,g.owner_id,ge.tenant_id gate_tenant_id,r.owner_id actual_repository_owner,
                  g.history_incarnation,g.authority_epoch,g.group_epoch,g.object_format,
                  g.gate_revision,g.acquire_request_id,g.consume_request_id,g.artifact_set_digest publication_digest,
                  ARRAY(SELECT DISTINCT q.operation_id FROM public.artifact_holds h
                          JOIN public.artifact_hold_requests q ON q.request_id=h.request_id
                         WHERE h.hold_id IN (
                           SELECT f.hold_id FROM public.ref_store_core_pack_artifacts f
                            WHERE f.registration_id=s.registration_id)) issuer_operations
             FROM sets s
             LEFT JOIN public.ref_store_core_pack_publications g
               ON g.registration_id=s.registration_id AND g.repository_id=s.repository_id AND g.pack_id=s.pack_id
             LEFT JOIN public.repositories r ON r.id=s.repository_id
             LEFT JOIN public.ref_store_core_gates ge ON ge.repository_id=s.repository_id)";

/// The header-only declared rows (no artifact join) for
/// [`super::ledger::inventory`]: [`DECLARED_COLUMNS`] (0..19) plus the artifact
/// sentinel `NULL::text AS role` (20). [`decode_declared`] stops at a `role` of
/// `None` and never reads 21.., so this deliberately is *not* a mirror of
/// [`ARTIFACT_COLUMNS`]: only the "no artifact" sentinel is supplied.
pub(super) fn declared_sql() -> String {
    format!(
        "{DECLARED_SETS}
         SELECT {DECLARED_COLUMNS},{ARTIFACT_SENTINEL}
           FROM published p
          ORDER BY p.repository_id,p.pack_id,p.registration_id"
    )
}

/// The registration columns of a declared set, used by both declared reads.
/// Positions (the `ORDER BY` key block first):
///
/// * 0..2 `(repository_id, pack_id, registration_id)` key, 3 registered;
/// * 4 publication tenant, 5 publication owner (the A3 pack producer);
/// * 6..12 realm (`history_incarnation`, `authority_epoch`, `group_epoch`,
///   `object_format`), gate revision, acquire and consume request;
/// * 13 publication digest, 14 declaring set kinds, 15 declaring sets;
/// * 16 actual `repositories.owner_id`, 17 core gate `tenant_id`;
/// * 18..19 the publication's own repository and pack.
const DECLARED_COLUMNS: &str = "p.repository_id,p.pack_id,p.registration_id,p.registered,p.tenant_id,p.owner_id,
        p.history_incarnation,p.authority_epoch,p.group_epoch,p.object_format,p.gate_revision,p.acquire_request_id,
        p.consume_request_id,p.publication_digest,p.declared_by,p.declared_sets,
        p.actual_repository_owner,p.gate_tenant_id,p.publication_repository_id,p.publication_pack_id";

/// The artifact columns of one declared registration (LEFT JOINed, so a missing
/// artifact, acquire request, hold or receipt is a NULL row rather than a
/// shrunk result). Positions 20..:
///
/// * 20..29 artifact row (`role`, `slot`, `hold_id`, acquire/consume request,
///   provider, backend identity, sha256, length, locator tenant);
/// * 30..31 the artifact row's own repository and pack (not in the locator
///   digest, so each is judged against the declared key);
/// * 32..35 acquire request (`request_id`, repository, tenant, owner) joined on
///   the hold's `request_id`;
/// * 36..48 hold (`request_id`, slot, repository, provider, backend identity,
///   storage tenant, authority id, authority generation, attempt, namespace,
///   sha256, length, tenant), then 49 hold owner;
/// * 50 receipt present, 51..53 consume receipt repository/tenant/owner (same
///   hold/request/consume ids as before), 54 receipts of this exact
///   hold/consume pair (outside the inner joins), 55 live issuer operation,
///   56 the hold's target slot.
const ARTIFACT_COLUMNS: &str = "a.role,a.slot,a.hold_id,a.acquire_request_id,a.consume_request_id,a.provider,
        a.backend_identity,a.sha256,a.content_length,a.tenant_id,a.repository_id,a.pack_id,
        q.request_id,q.repository_id,q.tenant_id,q.owner_id,
        h.request_id,h.slot,h.repository_id,h.provider,h.backend_identity,h.storage_tenant_id,
        h.authority_id,h.authority_generation,h.attempt_id,h.namespace,h.sha256,h.content_length,h.tenant_id,
        h.owner_id,
        c.hold_id IS NOT NULL,c.repository_id,c.tenant_id,c.owner_id,
        (SELECT count(*) FROM public.artifact_hold_consume_receipts x
           WHERE x.consume_request_id=a.consume_request_id AND x.hold_id=a.hold_id),
        COALESCE(h.operation_id=ANY(p.issuer_operations),FALSE),h.slot";

/// The absent-artifact sentinel of [`declared_sql`], the only extra column the
/// header-only shape needs.
const ARTIFACT_SENTINEL: &str = "NULL::text AS role";

/// Every declared registration with its publication, artifacts, durable hold
/// and consume receipt, optionally restricted to `ids` (a `uuid[]` parameter).
pub(super) fn declared_query(restrict: bool) -> String {
    let (wanted, join) = if restrict {
        (
            ", wanted AS (SELECT unnest($1::uuid[]) registration_id)",
            " JOIN wanted w ON w.registration_id=p.registration_id",
        )
    } else {
        ("", "")
    };
    format!(
        "{DECLARED_SETS}{wanted}
         SELECT {DECLARED_COLUMNS},{ARTIFACT_COLUMNS}
           FROM published p{join}
           LEFT JOIN public.ref_store_core_pack_artifacts a ON a.registration_id=p.registration_id
           LEFT JOIN public.artifact_holds h ON h.hold_id=a.hold_id AND h.request_id=a.acquire_request_id
           LEFT JOIN public.artifact_hold_requests q ON q.request_id=h.request_id
           LEFT JOIN public.artifact_hold_consume_receipts c ON c.hold_id=a.hold_id
             AND c.consume_request_id=a.consume_request_id AND c.request_id=a.acquire_request_id
          ORDER BY p.repository_id,p.pack_id,p.registration_id,a.slot"
    )
}

/// A5 snapshots in pack-verified mode with their declared descriptors.
const SNAPSHOTS: &str = "SELECT s.repository_id,s.snapshot_id,s.tenant_id,s.history_incarnation,s.authority_epoch,
            s.group_epoch,s.object_format,s.pack_mode,s.pack_count,s.membership_digest,
            p.pack_id,p.registration_id,p.artifact_set_digest,p.joined_revision
       FROM public.ref_store_core_snapshots s
       LEFT JOIN public.ref_store_core_snapshot_packs p ON p.snapshot_id=s.snapshot_id
      WHERE s.pack_mode='pack_verified'
      ORDER BY s.repository_id,s.snapshot_id,p.pack_id";

/// Retained root captures with their complete pack rows.
const ROOTS: &str = "SELECT r.repository_id,r.root_id,r.generation,r.tenant_id,r.history_incarnation,
            r.authority_epoch,r.group_epoch,r.object_format,r.ref_count,r.oid_count,r.pack_count,r.refs_digest,
            r.pack_set_digest,r.register_digest,r.owner_id,r.purpose,r.business_intent_digest,r.selector_kind,
            r.head_ref,r.head_oid,r.native_binding_digest,
            k.pack_id,k.registration_id,k.artifact_set_digest,k.joined_revision,
            k.pack_slot,k.pack_hold_id,k.pack_storage_tenant_id,k.pack_authority_id,k.pack_authority_generation,
            k.pack_attempt_id,k.pack_namespace,k.pack_sha256,k.pack_length,k.pack_provider,k.pack_backend_identity,
            k.pack_verified_sha256,k.pack_verified_length,
            k.idx_slot,k.idx_hold_id,k.idx_storage_tenant_id,k.idx_authority_id,k.idx_authority_generation,
            k.idx_attempt_id,k.idx_namespace,k.idx_sha256,k.idx_length,k.idx_provider,k.idx_backend_identity,
            k.idx_verified_sha256,k.idx_verified_length
       FROM public.ref_store_core_roots r
       LEFT JOIN public.ref_store_core_root_packs k
         ON k.repository_id=r.repository_id AND k.root_id=r.root_id AND k.generation=r.generation
      ORDER BY r.repository_id,r.root_id,k.pack_id";

const ROOT_REFS: &str = "SELECT repository_id,root_id,generation,ref_name,oid FROM public.ref_store_core_root_refs
       ORDER BY repository_id,root_id,generation,ref_name";

const ROOT_OIDS: &str = "SELECT repository_id,root_id,generation,ordinal,oid FROM public.ref_store_core_root_oids
       ORDER BY repository_id,root_id,generation,ordinal";

const HEADS: &str = "SELECT repository_id,root_id,tenant_id,owner_id,purpose,business_intent_digest,
            register_digest,state,last_generation
       FROM public.ref_store_core_root_heads ORDER BY repository_id,root_id";

const TOMBSTONES: &str = "SELECT repository_id,root_id,generation,tenant_id,owner_id,purpose,
            business_intent_digest,expected_register_digest,release_digest
       FROM public.ref_store_core_root_tombstones ORDER BY repository_id,root_id";

/// One deployed `pg_refstore` repository: its serving binding and core gate.
const REALM: &str = "SELECT r.id,b.owner_id,b.object_format,b.history_incarnation,b.authority_epoch,b.group_epoch,
            g.tenant_id,g.object_format,g.history_incarnation,g.authority_epoch,g.group_epoch
       FROM public.repositories r
       LEFT JOIN public.ref_store_serving_repositories b ON b.repository_id=r.id
       LEFT JOIN public.ref_store_core_gates g ON g.repository_id=r.id
      WHERE r.storage_backend='pg_refstore'
      ORDER BY r.id";

/// Fail-closed source ledger validation on the caller's exported-snapshot
/// transaction: one validator, no new transaction, no second snapshot, no clock
/// reset. Every read shares the caller's absolute `deadline`.
pub(super) async fn validate_source(
    client: &(impl GenericClient + Sync),
    deadline: tokio::time::Instant,
) -> Result<()> {
    let mut sets = SourceSets {
        declared: decode_declared(&rows(client, &declared_query(false), &[], deadline).await?)?,
        serving_reads: super::ledger_serving_reads::decode_serving_reads(client, deadline).await?,
        ..Default::default()
    };
    sets.snapshots = decode_snapshots(rows(client, SNAPSHOTS, &[], deadline).await?)?;
    let refs = rows(client, ROOT_REFS, &[], deadline).await?;
    let oids = rows(client, ROOT_OIDS, &[], deadline).await?;
    sets.roots = decode_roots(rows(client, ROOTS, &[], deadline).await?, &refs, &oids)?;
    for root in &mut sets.roots {
        root.proof = prove_capture(client, root, deadline).await?;
    }
    sets.heads = decode_heads(rows(client, HEADS, &[], deadline).await?);
    sets.tombstones = decode_tombstones(rows(client, TOMBSTONES, &[], deadline).await?);
    let missing = super::ledger_sets::undeclared(&sets.declared, &sets.snapshots, &sets.roots, &sets.serving_reads);
    if !missing.is_empty() {
        let ids = missing.iter().map(|id| id as &(dyn tokio_postgres::types::ToSql + Sync)).collect::<Vec<_>>();
        let orphans = decode_declared(&rows(client, &declared_query(true), &ids, deadline).await?)?;
        sets.declared.extend(orphans.into_iter().filter(|pair| missing.contains(&pair.registration_id)));
    }
    let mut violations = sets.violations();
    violations.extend(realm_violations(rows(client, REALM, &[], deadline).await?));
    violations.sort();
    violations.dedup();
    // The only construction site of the typed refusal: every SQL read, decode,
    // timeout, root proof and backend error above propagates as itself instead.
    match LedgerValidationRefusal::of(&violations) {
        Some(refusal) => Err(anyhow::Error::new(refusal)),
        None => Ok(()),
    }
}

/// The fixed summary code of a violation prefix outside [`VIOLATION_CODES`].
/// The input prefix is never echoed.
pub const OTHER_VIOLATION_CODE: &str = "other";

/// The source artifact ledger is inconsistent: [`validate_source`] completed
/// every read and check and found a non-empty, sorted, de-duplicated violation
/// set. Its only constructor, [`Self::of`], is called at that final branch and
/// nowhere else, and no field is public, so a generic backup, query, decode,
/// timeout, root-proof, backend or filesystem error can never be constructed
/// as this type and never reaches the CLI's typed classification.
///
/// The public summary is bounded on purpose: the total count and the sorted,
/// unique summary codes. Violation ids, free-form reason tails, raw messages,
/// SQL, paths and credentials are never retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerValidationRefusal {
    count: usize,
    codes: Vec<&'static str>,
}

impl LedgerValidationRefusal {
    /// `None` for the consistent empty set, else the typed refusal carrying
    /// only the count and the sorted, unique summary codes.
    fn of(violations: &[String]) -> Option<Self> {
        if violations.is_empty() {
            return None;
        }
        Some(Self { count: violations.len(), codes: summary_codes(violations.iter().map(String::as_str)) })
    }

    /// The total number of distinct violations.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Sorted, unique summary codes: a fixed vocabulary, never an id or reason
    /// tail.
    pub fn codes(&self) -> &[&'static str] {
        &self.codes
    }

    /// The one deterministic, fixed-vocabulary summary the CLI appends.
    pub fn diagnostic(&self) -> String {
        format!("source artifact ledger is inconsistent ({} violations; codes: {})", self.count, self.codes.join(","))
    }
}

impl std::fmt::Display for LedgerValidationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}

impl std::error::Error for LedgerValidationRefusal {}

/// A whole-line known violation: the exact prefix such a line starts with.
struct ViolationCode {
    prefix: &'static str,
    code: &'static str,
}

/// Every violation line the checkers can emit, matched as the whole text before
/// the first `:`. The prefixes are listed longest first within a family, so the
/// first match is decisive even for a discriminator that itself contains `:`
/// (an artifact `role:slot` of the `owner_scope_mismatch` line). Derived from
/// `ledger_sets`, `ledger_sets/declared_owner_scope`, `ledger_sets/root_lifetime`,
/// `ledger_sets/serving_reads` and [`realm_violations`]; a prefix missing here
/// is collapsed to [`OTHER_VIOLATION_CODE`] and cannot be spoofed.
const VIOLATION_CODES: [ViolationCode; 38] = [
    ViolationCode { prefix: "serving_read_artifact_mismatch", code: "serving_read_artifact_mismatch" },
    ViolationCode { prefix: "serving_read_backend_mismatch", code: "serving_read_backend_mismatch" },
    ViolationCode { prefix: "serving_read_capture_mismatch", code: "serving_read_capture_mismatch" },
    ViolationCode { prefix: "serving_read_membership_mismatch", code: "serving_read_membership_mismatch" },
    ViolationCode { prefix: "serving_read_pack_mismatch", code: "serving_read_pack_mismatch" },
    ViolationCode { prefix: "serving_read_pack_missing", code: "serving_read_pack_missing" },
    ViolationCode { prefix: "serving_read_realm_mismatch", code: "serving_read_realm_mismatch" },
    ViolationCode { prefix: "serving_read_unregistered_pack", code: "serving_read_unregistered_pack" },
    ViolationCode { prefix: "serving_read_orphan", code: "serving_read_orphan" },
    ViolationCode { prefix: "snapshot_membership_mismatch", code: "snapshot_membership_mismatch" },
    ViolationCode { prefix: "snapshot_set_mismatch", code: "snapshot_set_mismatch" },
    ViolationCode { prefix: "root_tombstone_without_head", code: "root_tombstone_without_head" },
    ViolationCode { prefix: "root_tombstone_mismatch", code: "root_tombstone_mismatch" },
    ViolationCode { prefix: "root_selector_mismatch", code: "root_selector_mismatch" },
    ViolationCode { prefix: "root_capture_mismatch", code: "root_capture_mismatch" },
    ViolationCode { prefix: "root_capture_missing", code: "root_capture_missing" },
    ViolationCode { prefix: "root_capture_invalid", code: "root_capture_invalid" },
    ViolationCode { prefix: "root_pack_set_mismatch", code: "root_pack_set_mismatch" },
    ViolationCode { prefix: "root_head_mismatch", code: "root_head_mismatch" },
    ViolationCode { prefix: "root_head_missing", code: "root_head_missing" },
    ViolationCode { prefix: "root_refs_mismatch", code: "root_refs_mismatch" },
    ViolationCode { prefix: "root_set_mismatch", code: "root_set_mismatch" },
    ViolationCode { prefix: "unregistered_publication", code: "unregistered_publication" },
    ViolationCode { prefix: "canonical_pair_mismatch", code: "canonical_pair_mismatch" },
    ViolationCode { prefix: "publication_binding_mismatch", code: "publication_binding_mismatch" },
    ViolationCode { prefix: "owner_scope_mismatch", code: "owner_scope_mismatch" },
    // The whole publication-key line: its key holds no `:` itself.
    ViolationCode { prefix: "publication_key", code: "publication_key" },
    ViolationCode { prefix: "declared_set_digest_mismatch", code: "declared_set_digest_mismatch" },
    ViolationCode { prefix: "declared_joined_revision_mismatch", code: "declared_joined_revision_mismatch" },
    ViolationCode { prefix: "missing_artifacts", code: "missing_artifacts" },
    ViolationCode { prefix: "incomplete_pair", code: "incomplete_pair" },
    ViolationCode { prefix: "extra_artifacts", code: "extra_artifacts" },
    ViolationCode { prefix: "illegal_roles", code: "illegal_roles" },
    ViolationCode { prefix: "foreign_hold_binding", code: "foreign_hold_binding" },
    ViolationCode { prefix: "missing_receipt", code: "missing_receipt" },
    ViolationCode { prefix: "hold_mismatch", code: "hold_mismatch" },
    ViolationCode { prefix: "repository_realm_mismatch", code: "repository_realm_mismatch" },
    // The fixed fallback must stay last.
    ViolationCode { prefix: OTHER_VIOLATION_CODE, code: OTHER_VIOLATION_CODE },
];

/// The allowlisted summary code of one violation line: the text before its first
/// `:`, exactly one [`VIOLATION_CODES`] prefix, else the fixed
/// [`OTHER_VIOLATION_CODE`]. Never echoes the input.
pub fn violation_code(line: &str) -> &'static str {
    let prefix = line.split(':').next().unwrap_or("");
    VIOLATION_CODES.iter().find(|code| code.prefix == prefix).map_or(OTHER_VIOLATION_CODE, |code| code.code)
}

/// The sorted, unique summary codes of `lines` in first-seen order.
fn summary_codes<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<&'static str> {
    let mut codes = lines.map(violation_code).collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    codes
}

/// Re-prove one retained capture with the core's own validator (`register`'s
/// algorithm, private row structs included) on the same client and under the
/// same absolute deadline: no new connection, no `BEGIN`, no second snapshot.
async fn prove_capture(
    client: &(impl GenericClient + Sync),
    root: &RootCapture,
    deadline: tokio::time::Instant,
) -> Result<Option<RootProof>> {
    let proven = tokio::time::timeout_at(
        deadline,
        retention_root::validate_capture(client, root.repository_id, root.root_id, root.generation),
    )
    .await
    .context(TIMED_OUT)?;
    capture_proof(proven)
}

/// The capture validator's outcome as a proof: `Ok(None)` stays proof-less (the
/// ledger then reports `root_capture_invalid`), every inner refusal propagates
/// as an ordinary error under fixed context, never reclassified.
fn capture_proof(
    proven: Result<Option<retention_root::ValidatedCapture>, retention_root::RootError>,
) -> Result<Option<RootProof>> {
    match proven {
        Ok(Some(capture)) => Ok(Some(RootProof {
            tenant_id: capture.tenant_id(),
            owner_id: capture.owner_id(),
            purpose: capture.purpose().as_str().to_owned(),
            business_intent_digest: capture.business_intent_digest_hex().to_owned(),
            register_digest: capture.register_digest_hex().to_owned(),
            head_ref: capture.head_ref().to_owned(),
            head_oid: capture.head_oid_hex().map(str::to_owned),
            selector_kind: capture.selector_kind().as_str().to_owned(),
            oids: capture.root_oids().to_vec(),
            refs_digest: capture.refs_digest_hex().to_owned(),
            pack_set_digest: capture.pack_set_digest_hex().to_owned(),
            native_binding_digest: capture.native_binding_digest_hex().to_owned(),
        })),
        // A missing capture is the ledger's own `root_capture_invalid` decision.
        Ok(None) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error).context(CAPTURE_UNPROVEN)),
    }
}

/// One read on the caller's client under the caller's absolute deadline.
pub(super) async fn rows(
    client: &(impl GenericClient + Sync),
    statement: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    deadline: tokio::time::Instant,
) -> Result<Vec<tokio_postgres::Row>> {
    let rows = tokio::time::timeout_at(deadline, client.query(statement, params)).await.context(TIMED_OUT)?;
    rows.context("source artifact ledger cannot be read")
}

/// A deployment-level violation per repository whose serving binding and core
/// gate do not share one realm, or do not match the repository owner/format.
/// A registration can never be read in the wrong realm.
fn realm_violations(rows: Vec<tokio_postgres::Row>) -> Vec<String> {
    let mut lines = Vec::new();
    for row in rows {
        let binding: Option<(Uuid, String, Uuid, i64, i64)> =
            row.get::<_, Option<Uuid>>(1).map(|_| (row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)));
        let gate: Option<(Uuid, String, Uuid, i64, i64)> =
            row.get::<_, Option<String>>(7).map(|_| (row.get(6), row.get(7), row.get(8), row.get(9), row.get(10)));
        if binding.is_none() || binding != gate {
            lines.push(format!("repository_realm_mismatch:{}", row.get::<_, Uuid>(0)));
        }
    }
    lines
}

fn length_of(row: &tokio_postgres::Row, column: usize) -> Result<u64> {
    u64::try_from(row.get::<_, i64>(column)).context("negative artifact length")
}

pub(super) fn decode_declared(rows: &[tokio_postgres::Row]) -> Result<Vec<DeclaredPair>> {
    let mut pairs: BTreeMap<(Uuid, Uuid, Uuid), DeclaredPair> = BTreeMap::new();
    for row in rows {
        let key: (Uuid, Uuid, Uuid) = (row.get(0), row.get(1), row.get(2));
        let head = pairs.keys().next_back().copied() != Some(key);
        let registered = row.get::<_, bool>(3);
        let pair = pairs.entry(key).or_default();
        if head {
            pair.repository_id = key.0;
            pair.pack_id = key.1;
            pair.registration_id = key.2;
            pair.declared_by = row.get(14);
            pair.declared_sets = decode_sets(&row.get::<_, Vec<String>>(15))?;
            pair.actual = ActualRepository { owner_id: row.get(16), gate_tenant_id: row.get(17) };
            if registered {
                pair.publication = Some(decode_publication(row)?);
            }
        }
        let Some(role) = row.get::<_, Option<String>>(20) else { continue };
        let hold = match row.get::<_, Option<Uuid>>(36) {
            Some(request_id) => Some(HoldRow {
                request_id,
                slot: row.get(37),
                repository_id: row.get(38),
                provider: row.get(39),
                backend_identity: row.get(40),
                storage_tenant_id: row.get(41),
                authority_id: row.get(42),
                generation: row.get(43),
                attempt_id: row.get(44),
                namespace: row.get(45),
                sha256: row.get(46),
                length: length_of(row, 47).context("negative hold length")?,
                // The durable hold's own tenant column, never the artifact's.
                tenant_id: row.get(48),
                owner_id: row.get(49),
            }),
            None => None,
        };
        pair.artifacts.push(PairArtifact {
            role,
            slot: row.get(21),
            hold_id: row.get(22),
            acquire_request_id: row.get(23),
            consume_request_id: row.get(24),
            provider: row.get(25),
            backend_identity: row.get(26),
            sha256: row.get(27),
            length: length_of(row, 28)?,
            tenant_id: row.get(29),
            repository_id: row.get(30),
            pack_id: row.get(31),
            authority_id: row.get(42),
            generation: row.get(43),
            attempt_id: row.get(44),
            namespace: row.get(45),
            request: row.get::<_, Option<Uuid>>(32).map(|_| RequestRow {
                repository_id: row.get(33),
                tenant_id: row.get(34),
                owner_id: row.get(35),
            }),
            hold,
            // A present receipt needs its complete scope: a partial row is
            // refused, never decoded as an absent receipt.
            receipt: row.get(50),
            receipt_scope: decode_receipt(row)?,
            issuer_operation: row.get(55),
            hold_slot: row.get(56),
        });
    }
    let mut pairs = pairs.into_values().collect::<Vec<_>>();
    for pair in &mut pairs {
        pair.scope = super::ledger_sets::declared_violations(pair);
    }
    Ok(pairs)
}

/// The publication of one declared registration, joined on the three-key
/// identity. Its own repository and pack are decoded next to the key so a
/// re-pointed publication is a mismatch, never hidden by the join.
fn decode_publication(row: &tokio_postgres::Row) -> Result<PublishedPack> {
    let stored: String = row.get(13);
    let parsed: RequestDigest = stored.parse().context("stored publication digest is invalid")?;
    Ok(PublishedPack {
        repository_id: row.get(18),
        pack_id: row.get(19),
        tenant_id: row.get(4),
        owner_id: row.get(5),
        history_incarnation: row.get(6),
        authority_epoch: row.get(7),
        group_epoch: row.get(8),
        object_format: row.get(9),
        gate_revision: row.get(10),
        acquire_request_id: row.get(11),
        consume_request_id: row.get(12),
        digest: ArtifactSetDigest::from_digest(parsed).as_hex(),
    })
}

/// The complete scope of a present consume receipt; a present but incomplete
/// scope is refused instead of being treated as a missing receipt.
fn decode_receipt(row: &tokio_postgres::Row) -> Result<Option<ReceiptRow>> {
    if !row.get::<_, bool>(50) {
        return Ok(None);
    }
    let scope = (row.get::<_, Option<Uuid>>(51), row.get::<_, Option<Uuid>>(52), row.get::<_, Option<Uuid>>(53));
    let receipt = match scope {
        (Some(repository_id), Some(tenant_id), Some(owner_id)) => ReceiptRow { repository_id, tenant_id, owner_id },
        _ => bail!("stored consume receipt has an incomplete scope"),
    };
    ensure!(row.get::<_, i64>(54) == 1, "stored consume receipt is not exactly identified by its hold and consume id");
    Ok(Some(receipt))
}

/// Split the `source=digest@joined_revision` strings of one declaring row.
fn decode_sets(sets: &[String]) -> Result<Vec<(String, String, i64)>> {
    sets.iter()
        .map(|set| {
            let (source, rest) = set.split_once('=').context("stored declared set is malformed")?;
            let (digest, joined) = rest.split_once('@').context("stored declared set is malformed")?;
            let joined = joined.parse::<i64>().context("stored declared joined revision is invalid")?;
            Ok((source.to_owned(), digest.to_owned(), joined))
        })
        .collect()
}

/// The realm columns of a snapshot (`tenant,hinc,ae,ge,format`) or root row.
fn realm_of(row: &tokio_postgres::Row, tenant: usize, format: usize) -> Realm {
    Realm {
        tenant_id: row.get(tenant),
        history_incarnation: row.get(tenant + 1),
        authority_epoch: row.get(tenant + 2),
        group_epoch: row.get(tenant + 3),
        object_format: row.get(format),
    }
}

fn decode_snapshots(rows: Vec<tokio_postgres::Row>) -> Result<Vec<SnapshotSet>> {
    let mut sets: Vec<SnapshotSet> = Vec::new();
    for row in rows {
        let id: (Uuid, Uuid) = (row.get(0), row.get(1));
        if sets.last().map(|set| (set.repository_id, set.snapshot_id)) != Some(id) {
            sets.push(SnapshotSet {
                repository_id: id.0,
                snapshot_id: id.1,
                realm: realm_of(&row, 2, 6),
                pack_mode: row.get(7),
                pack_count: row.get(8),
                membership_digest: row.get(9),
                packs: Vec::new(),
            });
        }
        if let Some(pack_id) = row.get::<_, Option<Uuid>>(10) {
            sets.last_mut().unwrap().packs.push((pack_id, row.get(11), row.get(12), row.get(13)));
        }
    }
    Ok(sets)
}

fn retained(row: &tokio_postgres::Row, start: usize) -> RetainedArtifact {
    RetainedArtifact {
        slot: row.get(start),
        hold_id: row.get(start + 1),
        tenant_id: row.get(start + 2),
        authority_id: row.get(start + 3),
        generation: row.get(start + 4),
        attempt_id: row.get(start + 5),
        namespace: row.get(start + 6),
        sha256: row.get(start + 7),
        length: row.get(start + 8),
        provider: row.get(start + 9),
        backend_identity: row.get(start + 10),
        verified_sha256: row.get(start + 11),
        verified_length: row.get(start + 12),
    }
}

fn decode_roots(
    rows: Vec<tokio_postgres::Row>,
    refs: &[tokio_postgres::Row],
    oids: &[tokio_postgres::Row],
) -> Result<Vec<RootCapture>> {
    let mut roots: Vec<RootCapture> = Vec::new();
    for row in rows {
        let id: (Uuid, Uuid) = (row.get(0), row.get(1));
        let owned = |r: &tokio_postgres::Row| r.get::<_, Uuid>(0) == id.0 && r.get::<_, Uuid>(1) == id.1;
        let generation: i64 = row.get(2);
        if roots.last().map(|root| (root.repository_id, root.root_id)) != Some(id) {
            roots.push(RootCapture {
                repository_id: id.0,
                root_id: id.1,
                generation,
                tenant_id: row.get(3),
                owner_id: row.get(14),
                purpose: row.get(15),
                business_intent_digest: row.get(16),
                realm: realm_of(&row, 3, 7),
                ref_count: row.get(8),
                oid_count: row.get(9),
                pack_count: row.get(10),
                refs_digest: row.get(11),
                pack_set_digest: row.get(12),
                register_digest: row.get(13),
                selector_kind: row.get(17),
                head_ref: row.get(18),
                head_oid: row.get(19),
                native_binding_digest: row.get(20),
                refs: refs.iter().filter(|r| owned(r)).map(|r| (r.get(3), r.get(4))).collect(),
                oids: oids.iter().filter(|r| owned(r)).map(|r| (r.get(3), r.get(4))).collect(),
                proof: None,
                packs: Vec::new(),
            });
        }
        if let Some(pack_id) = row.get::<_, Option<Uuid>>(21) {
            roots.last_mut().unwrap().packs.push(RetainedPack {
                pack_id,
                registration_id: row.get(22),
                artifact_set_digest: row.get(23),
                joined_revision: row.get(24),
                pack: retained(&row, 25),
                idx: retained(&row, 38),
            });
        }
    }
    Ok(roots)
}

fn decode_heads(rows: Vec<tokio_postgres::Row>) -> Vec<RootHead> {
    rows.iter()
        .map(|row| RootHead {
            repository_id: row.get(0),
            root_id: row.get(1),
            tenant_id: row.get(2),
            owner_id: row.get(3),
            purpose: row.get(4),
            business_intent_digest: row.get(5),
            register_digest: row.get(6),
            state: row.get(7),
            last_generation: row.get(8),
        })
        .collect()
}

fn decode_tombstones(rows: Vec<tokio_postgres::Row>) -> Vec<RootTombstone> {
    rows.iter()
        .map(|row| RootTombstone {
            repository_id: row.get(0),
            root_id: row.get(1),
            generation: row.get(2),
            tenant_id: row.get(3),
            owner_id: row.get(4),
            purpose: row.get(5),
            business_intent_digest: row.get(6),
            expected_register_digest: row.get(7),
            release_digest: row.get(8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// Every prefix the checkers can emit maps to itself, the fallback stays
    /// `other`, and no line ever leaks its id, reason tail or an unknown prefix.
    #[test]
    fn the_typed_refusal_exposes_only_count_and_summary_codes() {
        let violations = lines(&[
            "canonical_pair_mismatch:00000000-0000-0000-0000-000000000001:secret/reason:tail",
            "root_set_mismatch:00000000-0000-0000-0000-000000000002:bad_free_text",
            "canonical_pair_mismatch:another:pair",
            "canonical_pair:not-a-known-prefix",
            "cd_secret:postgres://user:password@host/db",
            "owner_scope_mismatch:a:b:c:pack:0",
            "publication_key:a:b:c",
            "",
        ]);
        let refusal = LedgerValidationRefusal::of(&violations).expect("a non-empty set is a refusal");
        assert_eq!(refusal.count(), 8);
        assert_eq!(
            refusal.codes(),
            [
                "canonical_pair_mismatch",
                OTHER_VIOLATION_CODE,
                "owner_scope_mismatch",
                "publication_key",
                "root_set_mismatch"
            ]
        );
        assert_eq!(
            refusal.diagnostic(),
            "source artifact ledger is inconsistent (8 violations; codes: canonical_pair_mismatch,other,owner_scope_mismatch,publication_key,root_set_mismatch)"
        );
        for leaked in ["00000000", "secret", "postgres", "cd_secret", "pack:0", "reason"] {
            assert!(!refusal.diagnostic().contains(leaked), "{leaked} leaked: {}", refusal.diagnostic());
        }
        // Every allowlisted code is reachable from its own line and is never `other`.
        for entry in &VIOLATION_CODES[..VIOLATION_CODES.len() - 1] {
            assert_ne!(entry.code, OTHER_VIOLATION_CODE);
            assert_eq!(violation_code(&format!("{}:id", entry.prefix)), entry.code, "{}", entry.prefix);
        }
        assert_eq!(violation_code(&format!("{OTHER_VIOLATION_CODE}:id")), OTHER_VIOLATION_CODE);
        let all = VIOLATION_CODES.map(|entry| format!("{}:id", entry.prefix));
        assert_eq!(summary_codes(all.iter().map(String::as_str)).len(), VIOLATION_CODES.len());
        assert!(LedgerValidationRefusal::of(&[]).is_none());
        assert!(LedgerValidationRefusal::of(&lines(&["", ""])).is_some());
    }

    /// A real damaged set becomes the typed refusal through its only
    /// construction site, while any other failure (even one whose text looks
    /// like the summary) stays foreign to the type.
    #[test]
    fn a_real_violation_set_becomes_the_typed_refusal_and_a_deeper_error_stays_generic() {
        // The released root is dropped so only the damaged membership remains.
        let mut sets = super::super::ledger_sets::ledger_sets_tests::valid_source_without(&["idx"]);
        sets.roots.clear();
        sets.heads.clear();
        sets.tombstones.clear();
        sets.declared[0].publication.as_mut().unwrap().digest = "00".repeat(32);
        let violations = sets.violations();
        let mut codes = violations.iter().map(|line| violation_code(line)).collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert!(codes.contains(&"canonical_pair_mismatch") && codes.contains(&"incomplete_pair"), "{violations:?}");
        let error = prove(violations.clone()).unwrap_err().context("wrapped");
        let found = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<LedgerValidationRefusal>())
            .expect("the typed cause is found through its context");
        assert_eq!(found.codes(), codes);
        assert_eq!(found.count(), violations.len());
        // A different failure underneath the same context is not the refusal.
        let error = anyhow::anyhow!("source artifact ledger cannot be archived: Caused by: {}", {
            let refusal = LedgerValidationRefusal::of(&violations).unwrap();
            refusal.diagnostic()
        })
        .context("source artifact ledger cannot be archived");
        assert!(error.chain().all(|cause| cause.downcast_ref::<LedgerValidationRefusal>().is_none()));
    }

    /// [`capture_proof`] (called by [`prove_capture`]) only erases a *missing*
    /// capture: a core refusal stays an ordinary error carrying its own typed
    /// cause and is never turned into the ledger's typed refusal.
    #[test]
    fn an_unprovable_root_capture_propagates_and_a_missing_one_stays_proof_less() {
        use crate::ref_store::contract::RefStoreError;
        assert!(capture_proof(Ok(None)).expect("a missing capture is not an error").is_none());
        let error = capture_proof(Err(retention_root::RootError::Store(RefStoreError::Timeout)))
            .expect_err("a refused capture must propagate");
        assert!(error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<retention_root::RootError>(),
                Some(retention_root::RootError::Store(RefStoreError::Timeout))
            )
        }));
        assert!(error.chain().all(|cause| cause.downcast_ref::<LedgerValidationRefusal>().is_none()));
        assert_eq!(error.to_string(), CAPTURE_UNPROVEN);
    }

    /// Calls [`validate_source`]'s final branch: refused iff a violation exists.
    fn prove(violations: Vec<String>) -> anyhow::Result<()> {
        match LedgerValidationRefusal::of(&violations) {
            Some(refusal) => Err(anyhow::Error::new(refusal)),
            None => Ok(()),
        }
    }
}
