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

#[cfg(test)]
mod pg_tests;
mod refusal;
mod sql;
pub use self::refusal::LedgerValidationRefusal;
pub(super) use self::sql::*;

const TIMED_OUT: &str = "source artifact validator deadline exceeded";
const CAPTURE_UNPROVEN: &str = "retained root capture cannot be re-proven";

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
}
