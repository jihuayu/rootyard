//! The serving-read SQL and row decoder of the source ledger validation.
//!
//! [`decode_serving_reads`] runs on the *caller's* `GenericClient` — during
//! backup that is the exported-snapshot `REPEATABLE READ` transaction, during
//! restore the restored database — and every read shares the caller's absolute
//! deadline. It opens no connection, begins no transaction and takes no second
//! snapshot, lock, lease or timeout of its own. All decisions live in the pure
//! [`super::ledger_sets::serving_reads`] checkers.
use super::ledger_sets::serving_reads::{
    ServingReadArtifact, ServingReadDescriptor, ServingReadHeader, ServingReadLane, ServingReadScan, ServingReads,
};
use super::ledger_validation::rows;
use crate::ref_store::core::pack_snapshot::ServingReadRow;
use anyhow::Result;
use std::collections::BTreeMap;
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Every stored serving read header (migration 146), in the
/// `serving_read_sql::READ_COLUMNS` order plus `(repository_id,pin_id)`.
const SERVING_READS: &str = "SELECT pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,
            object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest,
            head_ref,head_oid,ref_count,refs_digest,pack_count,membership_digest,snapshot_digest,logical_bytes,
            (extract(epoch FROM expires_at)*1000000)::bigint,expires_at <= clock_timestamp()
       FROM public.ref_store_core_serving_reads ORDER BY repository_id,pin_id";

/// The lane of every repository that carries any serving read row: its own
/// backend/owner and its serving binding and core gate, left-joined (a missing
/// row is a violation, not a shrunk result).
const SERVING_READ_LANES: &str = "SELECT r.id,r.storage_backend,r.owner_id,
            b.owner_id,b.object_format,b.history_incarnation,b.authority_epoch,b.group_epoch,b.backend_identity,b.state,
            g.tenant_id,g.object_format,g.history_incarnation,g.authority_epoch,g.group_epoch
       FROM public.repositories r
       LEFT JOIN public.ref_store_serving_repositories b ON b.repository_id=r.id
       LEFT JOIN public.ref_store_core_gates g ON g.repository_id=r.id
      WHERE r.id IN (SELECT repository_id FROM public.ref_store_core_serving_reads
                     UNION SELECT s.repository_id FROM public.ref_store_core_serving_read_packs p
                       JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id
                     UNION SELECT s.repository_id FROM public.ref_store_core_serving_read_artifacts a
                       JOIN public.ref_store_core_serving_reads s ON s.pin_id=a.pin_id)
       ORDER BY r.id";

/// The captured refs of every serving read, with their header's repository.
const SERVING_READ_REFS: &str = "SELECT s.repository_id,f.pin_id,f.ref_name,f.oid
       FROM public.ref_store_core_serving_read_refs f
       JOIN public.ref_store_core_serving_reads s ON s.pin_id=f.pin_id
      ORDER BY s.repository_id,f.pin_id,f.ref_name";

/// The complete pack descriptors of every serving read.
const SERVING_READ_PACKS: &str = "SELECT s.repository_id,p.pin_id,p.pack_id,p.registration_id,
            p.artifact_set_digest,p.joined_revision
       FROM public.ref_store_core_serving_read_packs p
       JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id
      ORDER BY s.repository_id,p.pin_id,p.pack_id";

/// The full physical identity of every captured serving read artifact.
const SERVING_READ_ARTIFACTS: &str = "SELECT s.repository_id,a.pin_id,a.pack_id,a.role,a.slot,a.hold_id,
            a.locator_tenant_id,a.locator_authority_id,a.locator_authority_generation,a.locator_attempt_id,
            a.locator_namespace,a.locator_sha256,a.locator_length,a.provider,a.backend_identity,
            a.verified_sha256,a.verified_length
       FROM public.ref_store_core_serving_read_artifacts a
       JOIN public.ref_store_core_serving_reads s ON s.pin_id=a.pin_id
      ORDER BY s.repository_id,a.pin_id,a.pack_id,a.slot";

/// The `(repository_id, pin_id)` of every serving read that owns any row: every
/// header, plus every pin named by a captured ref, pack descriptor or artifact
/// row **whose header exists** (each child query inner-joins the header).
///
/// Child pins with no header are *not* enumerated here; they are found by
/// [`SERVING_READ_ORPHAN_CHILDREN`] and reported on their own pin.
const SERVING_READ_ORPHANS: &str = "SELECT repository_id,pin_id FROM public.ref_store_core_serving_reads
        UNION
       SELECT s.repository_id,p.pin_id FROM public.ref_store_core_serving_read_packs p
         JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id
        UNION
       SELECT s.repository_id,a.pin_id FROM public.ref_store_core_serving_read_artifacts a
         JOIN public.ref_store_core_serving_reads s ON s.pin_id=a.pin_id
        UNION
       SELECT s.repository_id,f.pin_id FROM public.ref_store_core_serving_read_refs f
         JOIN public.ref_store_core_serving_reads s ON s.pin_id=f.pin_id";

/// The `pin_id` of every pack descriptor, artifact or ref row whose serving read
/// header is absent (`NOT EXISTS` per child table, no join to the header).
const SERVING_READ_ORPHAN_CHILDREN: &str = "SELECT p.pin_id FROM public.ref_store_core_serving_read_packs p
        WHERE NOT EXISTS (SELECT 1 FROM public.ref_store_core_serving_reads s WHERE s.pin_id=p.pin_id)
        UNION
       SELECT a.pin_id FROM public.ref_store_core_serving_read_artifacts a
        WHERE NOT EXISTS (SELECT 1 FROM public.ref_store_core_serving_reads s WHERE s.pin_id=a.pin_id)
        UNION
       SELECT f.pin_id FROM public.ref_store_core_serving_read_refs f
        WHERE NOT EXISTS (SELECT 1 FROM public.ref_store_core_serving_reads s WHERE s.pin_id=f.pin_id)";

/// Every serving read header with its lanes, its own rows and the bare headers
/// of every pin that owns a row. All reads share one absolute deadline on the
/// caller's client: no lock, no new capture, no Blob/Git/manifest IO.
pub(super) async fn decode_serving_reads(
    client: &(impl GenericClient + Sync),
    deadline: tokio::time::Instant,
) -> Result<ServingReads> {
    let headers = rows(client, SERVING_READS, &[], deadline).await?;
    let headers = headers.iter().map(serving_read_row).collect::<Vec<_>>();
    let lanes = rows(client, SERVING_READ_LANES, &[], deadline).await?.iter().map(serving_lane).collect();
    let found =
        rows(client, SERVING_READ_ORPHANS, &[], deadline).await?.iter().map(|row| (row.get(0), row.get(1))).collect();
    // Child rows are attached to their header by pin only; an unmatched child is
    // reported by `from_scan`, never dropped by a join.
    let mut refs: BTreeMap<Uuid, Vec<(String, String)>> = BTreeMap::new();
    let mut packs: BTreeMap<Uuid, Vec<ServingReadDescriptor>> = BTreeMap::new();
    let mut artifacts: BTreeMap<Uuid, Vec<ServingReadArtifact>> = BTreeMap::new();
    for row in rows(client, SERVING_READ_REFS, &[], deadline).await? {
        refs.entry(row.get(1)).or_default().push((row.get(2), row.get(3)));
    }
    for row in rows(client, SERVING_READ_PACKS, &[], deadline).await? {
        packs.entry(row.get(1)).or_default().push(serving_descriptor(&row));
    }
    for row in rows(client, SERVING_READ_ARTIFACTS, &[], deadline).await? {
        artifacts.entry(row.get(1)).or_default().push(serving_artifact(&row));
    }
    let mut violations = Vec::new();
    let orphan_pins: Vec<Uuid> =
        rows(client, SERVING_READ_ORPHAN_CHILDREN, &[], deadline).await?.iter().map(|row| row.get(0)).collect();
    for pin in orphan_pins {
        violations.push(format!("serving_read_orphan:{pin}"));
    }
    for (pin, rows) in &packs {
        if !headers.iter().any(|header| header.row.pin_id == *pin) {
            let first = &rows[0];
            violations.push(format!("serving_read_orphan:{pin}:{}:{}", first.pack_id, first.registration_id));
        }
    }
    Ok(ServingReads::from_scan(ServingReadScan { headers, found, lanes, violations, refs, packs, artifacts }))
}

/// One stored header in the `serving_read_sql::READ_COLUMNS` order; its lane and
/// child rows are filled by the scan.
fn serving_read_row(row: &tokio_postgres::Row) -> ServingReadHeader {
    let count = |column: usize| i64::from(row.get::<_, i32>(column));
    ServingReadHeader {
        row: ServingReadRow {
            pin_id: row.get(0),
            snapshot_id: row.get(1),
            generation: row.get(2),
            repository_id: row.get(3),
            tenant_id: row.get(4),
            owner_id: row.get(5),
            purpose: row.get(6),
            object_format: row.get(7),
            history_incarnation: row.get(8),
            authority_epoch: row.get(9),
            group_epoch: row.get(10),
            backend_identity: row.get(11),
            gate_revision: row.get(12),
            gate_digest: row.get(13),
            head_ref: row.get(14),
            head_oid: row.get(15),
            ref_count: count(16),
            refs_digest: row.get(17),
            pack_count: count(18),
            membership_digest: row.get(19),
            snapshot_digest: row.get(20),
            logical_bytes: row.get(21),
            expires_at_unix_micros: row.get(22),
            expired: row.get(23),
        },
        lane: ServingReadLane::default(),
        refs: Vec::new(),
        packs: Vec::new(),
        artifacts: Vec::new(),
    }
}

/// One `SERVING_READ_LANES` row.
fn serving_lane(row: &tokio_postgres::Row) -> (Uuid, ServingReadLane) {
    let binding = row
        .get::<_, Option<Uuid>>(3)
        .map(|owner| (owner, row.get(4), row.get(5), row.get(6), row.get(7), row.get(8), row.get(9)));
    let gate =
        row.get::<_, Option<Uuid>>(10).map(|tenant| (tenant, row.get(11), row.get(12), row.get(13), row.get(14)));
    (row.get(0), ServingReadLane { storage_backend: row.get(1), repository_owner: row.get(2), binding, gate })
}

/// One `SERVING_READ_ARTIFACTS` row (column 0 is its repository).
fn serving_artifact(row: &tokio_postgres::Row) -> ServingReadArtifact {
    ServingReadArtifact {
        pack_id: row.get(2),
        role: row.get(3),
        slot: row.get(4),
        hold_id: row.get(5),
        locator_tenant_id: row.get(6),
        locator_authority_id: row.get(7),
        locator_authority_generation: row.get(8),
        locator_attempt_id: row.get(9),
        locator_namespace: row.get(10),
        locator_sha256: row.get(11),
        locator_length: row.get(12),
        provider: row.get(13),
        backend_identity: row.get(14),
        verified_sha256: row.get(15),
        verified_length: row.get(16),
    }
}

/// One `SERVING_READ_PACKS` row (column 0 is its repository).
fn serving_descriptor(row: &tokio_postgres::Row) -> ServingReadDescriptor {
    ServingReadDescriptor {
        pack_id: row.get(2),
        registration_id: row.get(3),
        artifact_set_digest: row.get(4),
        joined_revision: row.get(5),
    }
}
