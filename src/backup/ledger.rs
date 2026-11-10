//! Read-only, exact views of the `pg_refstore` artifact ledger.
//!
//! All ledger SQL for the Blob closure lives here, in the backup subtree. The
//! Blob byte layer never queries PostgreSQL. Every query is given the caller's
//! `GenericClient`, which is the *exported-snapshot* transaction during backup
//! or the restored database during restore, so both sides read exactly one cut.
//!
//! Fail-closed source validation: [`validate_source`] runs on that same
//! GenericClient (the exported-snapshot transaction, never a second snapshot or
//! a new connection) under the caller's absolute `deadline`. It enumerates every
//! registration that should be archived — a live membership, an A5 snapshot
//! pack set, a retained root pack set (active or released) or a serving read
//! lease — independently of the artifact rows, requires the exact legal
//! pack/idx pair, the publication's own hold binding and consume receipt, and
//! recomputes the artifact-set digest and the retained root/snapshot sets. Any
//! inconsistency refuses the backup before a byte is exported, so a corrupted
//! source can never produce a successful-looking archive with missing members.
//! The decisions are pure functions in [`super::ledger_sets`].
//!
//! The typed consume ACK is decoded with the real `ConsumeAck::decode` and its
//! nested `HoldArtifactIdentity` is compared field by field with the artifact
//! row, its hold row and its publication authority. No JSON key is guessed.

use super::*;
use crate::ref_store::artifact_hold::ConsumeAck;
use crate::ref_store::core::pack_commit::CapturedRef;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use std::collections::BTreeMap;
use tokio_postgres::GenericClient;

/// Canonical sorted closure row of one repository, exactly as the restored
/// PostgreSQL snapshot keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub repository_id: Uuid,
    pub registration_id: Uuid,
    pub pack_id: Uuid,
    pub role: String,
    pub slot: i32,
    pub hold_id: Uuid,
    pub acquire_request_id: Uuid,
    pub consume_request_id: Uuid,
    // Registered-artifact physical identity.
    pub provider: String,
    pub backend_identity: String,
    pub sha256: String,
    pub length: u64,
    // Original read-only locator (from the immutable hold).
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    /// Stored publication artifact-set digest, recorded only on rows that a
    /// declared set retained. Older archives and their closure comparisons keep
    /// exactly the same rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_set_digest: Option<String>,
    /// Declared set kinds that retained this registration, for the operator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_by: Vec<String>,
}

impl Artifact {
    /// Archive-relative path of the raw bytes: deterministic and unique.
    pub(super) fn archive_path(&self) -> String {
        format!("blob/{}/{}/{}.{}", self.repository_id, self.pack_id, self.role, self.role)
    }

    /// The exact original read-only locator. It is never a write capability.
    pub(super) fn locator(&self) -> Result<crate::blob_store::BlobLocator> {
        Ok(crate::blob_store::BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )?)
    }

    fn line(&self) -> String {
        format!("{self:?}")
    }
}

impl ledger_sets::DeclaredArtifact for Artifact {
    fn registration(&self) -> Uuid {
        self.registration_id
    }

    fn identity(&self) -> (Uuid, Uuid, Uuid) {
        (self.repository_id, self.pack_id, self.registration_id)
    }

    fn retain(&mut self, digest: Option<String>, sources: Vec<String>) {
        self.artifact_set_digest = digest;
        self.declared_by = sources;
    }
}

/// Whether the typed consume ACK body names another A3 owner than the pack
/// producer recorded in its own publication. An owner distinct from the
/// repository tenant is legal; an owner distinct from the producer is not.
pub(super) fn ack_owner_differs(ack: &ConsumeAck, producer: Uuid) -> bool {
    ack.owner_id != producer
}

/// Whether the typed consume ACK body names another repository than its own
/// publication.
pub(super) fn ack_repository_differs(ack: &ConsumeAck, repository_id: Uuid) -> bool {
    ack.repository_id != repository_id
}

/// Whether the typed consume ACK body names another tenant than its own
/// publication (i.e. than the actual repository tenant).
pub(super) fn ack_tenant_differs(ack: &ConsumeAck, repository_tenant: Uuid) -> bool {
    ack.tenant_id != repository_tenant
}

/// The typed consume ACK body agrees with its own publication: it names the
/// pack producer as its owner (never the repository tenant) and the actual
/// repository and tenant.
pub(super) fn ack_scope_differs(
    ack: &ConsumeAck,
    producer: Uuid,
    repository_id: Uuid,
    repository_tenant: Uuid,
) -> bool {
    ack_owner_differs(ack, producer)
        || ack_repository_differs(ack, repository_id)
        || ack_tenant_differs(ack, repository_tenant)
}

fn digest_lines(lines: &[String]) -> String {
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

pub(super) fn closure_of(artifacts: &[Artifact], backend: &str, provider: &str) -> BlobClosure {
    let repositories = artifacts.iter().map(|a| a.repository_id).collect::<std::collections::BTreeSet<_>>();
    BlobClosure {
        backend_identity: backend.to_owned(),
        provider: provider.to_owned(),
        repositories: repositories.len(),
        artifacts: artifacts.len(),
        bytes: artifacts.iter().map(|a| a.length).sum(),
        digest: digest_lines(&artifacts.iter().map(Artifact::line).collect::<Vec<_>>()),
    }
}

/// RefStore read state that a paired archive proves and a restore re-adopts
/// verbatim. The paired run must not change any of it: doing so would mutate
/// operation identities, event history or immutable A3/A4 authority that the
/// archive carries, and would make the restored snapshot diverge from its own
/// ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct TableDigest {
    rows: u64,
    sha256: String,
}

pub(super) type RefStoreCarry = BTreeMap<String, TableDigest>;

/// Hash rows incrementally from the same exported snapshot. PostgreSQL sorts
/// canonical JSON using byte collation and can spill the sort to disk; Rust
/// retains one bounded row instead of copying the operation history to RAM.
pub(super) async fn carry(
    client: &(impl GenericClient + Sync),
    deadline: tokio::time::Instant,
) -> Result<RefStoreCarry> {
    use futures_util::TryStreamExt;
    struct DigestWriter<'a>(&'a mut Sha256);
    impl std::io::Write for DigestWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut result = BTreeMap::new();
    for table in catalog::relations(FORMAT, true)?
        .into_iter()
        .filter(|name| name.starts_with("ref_store_") || name.starts_with("artifact_hold"))
    {
        let sql = format!(
            "SELECT CASE WHEN pg_column_size(encoded_row)<=8388608 THEN encoded_row ELSE NULL END \
             FROM (SELECT to_jsonb(t) AS encoded_row FROM public.\"{table}\" t) q \
             ORDER BY encoded_row::text COLLATE \"C\""
        );
        let stream = tokio::time::timeout_at(
            deadline,
            client.query_raw(&sql, std::iter::empty::<&(dyn tokio_postgres::types::ToSql + Sync)>()),
        )
        .await
        .context("ledger query deadline exceeded")??;
        futures_util::pin_mut!(stream);
        let mut digest = Sha256::new();
        let mut rows = 0u64;
        while let Some(row) =
            tokio::time::timeout_at(deadline, stream.try_next()).await.context("ledger digest deadline exceeded")??
        {
            let value: Option<serde_json::Value> = row.get(0);
            let value = value.context("ledger row exceeds the metadata byte ceiling")?;
            rows += 1;
            ensure!(rows <= MAX_ENTRIES as u64, "ledger row count exceeds its bound");
            serde_json::to_writer(DigestWriter(&mut digest), &value)?;
            digest.update(b"\n");
        }
        result.insert(table, TableDigest { rows, sha256: hex::encode(digest.finalize()) });
    }
    Ok(result)
}

/// Number of `pg_refstore` serving repositories in the snapshot. A non-zero
/// count forces the paired archive version.
pub(super) async fn serving_repositories(client: &(impl GenericClient + Sync)) -> Result<i64> {
    Ok(client
        .query_one("SELECT count(*) FROM public.repositories r WHERE r.storage_backend='pg_refstore'", &[])
        .await?
        .get(0))
}

/// Closed-cut refusal for the paired archive only: no write operation that is
/// still open may be able to add or change a published pack. A terminal
/// `unknown` result is preserved in the PG snapshot and its bytes stay in the
/// closure; this refuses a cut whose closure may still be growing.
async fn require_closed_cut(client: &(impl GenericClient + Sync), deadline: tokio::time::Instant) -> Result<()> {
    let open: i64 = tokio::time::timeout_at(
        deadline,
        client.query_one(
            "SELECT (SELECT count(*) FROM public.git_operations WHERE outcome IN ('pending','in-progress'))
                  + (SELECT count(*) FROM public.ref_store_operations WHERE state='pending')",
            &[],
        ),
    )
    .await
    .context("ledger query deadline exceeded")??
    .get(0);
    ensure!(open == 0, "paired backup requires every write operation to have reached a terminal result");
    Ok(())
}

/// The captured refs of a retained root, in canonical name order. This is the
/// set `refs_digest` of a root header was sealed over (the source snapshot
/// refs); selector OIDs are bound through the pack set and `source_read_digest`.
pub(super) fn captured_refs(format: &str, refs: Vec<(String, String)>) -> Option<Vec<CapturedRef>> {
    let format = GitObjectFormat::parse(format).ok()?;
    let mut by_name = BTreeMap::new();
    for (name, oid) in refs {
        let reference = CapturedRef::new(RefName::new(name).ok()?, GitOid::parse(format, &oid).ok()?).ok()?;
        by_name.insert(reference.name().to_owned(), reference);
    }
    Some(by_name.into_values().collect())
}

/// Exact artifact closure of one snapshot, in canonical order. Rows of declared
/// registrations are annotated with their stored publication artifact-set digest
/// and declaring set kinds, and only those registrations are returned when the
/// source declares any set; a source that declares nothing keeps every
/// `pg_refstore` artifact row. Every read shares the caller's absolute `deadline`.
pub(super) async fn inventory(
    client: &(impl GenericClient + Sync),
    backend: &str,
    provider: &str,
    deadline: tokio::time::Instant,
) -> Result<Vec<Artifact>> {
    require_closed_cut(client, deadline).await?;
    let invalid: bool = tokio::time::timeout_at(
        deadline,
        client.query_one(
            "SELECT EXISTS (SELECT 1 FROM public.repositories r LEFT JOIN public.ref_store_serving_repositories s \
         ON s.repository_id=r.id WHERE r.storage_backend='pg_refstore' AND (s.repository_id IS NULL \
         OR s.owner_id<>r.owner_id OR s.name<>r.name OR s.object_format<>r.object_format OR s.state<>'ready' \
         OR s.backend_identity<>$1 OR r.transition_state<>'stable'))",
            &[&backend],
        ),
    )
    .await
    .context("ledger query deadline exceeded")??
    .get(0);
    ensure!(!invalid, "a Blob repository lacks its exact ready serving binding");
    let artifacts = inventory_rows(client, deadline).await?;
    let declared = read(client, &ledger_validation::declared_sql(), deadline).await?;
    let artifacts = super::ledger_sets::SourceSets {
        declared: ledger_validation::decode_declared(&declared)?,
        ..Default::default()
    }
    .select(artifacts);
    for artifact in &artifacts {
        ensure!(
            artifact.provider == provider && artifact.backend_identity == backend,
            "artifact names a foreign backend"
        );
    }
    Ok(artifacts)
}

/// One read on the caller's client under the caller's absolute deadline.
async fn read(
    client: &(impl GenericClient + Sync),
    statement: &str,
    deadline: tokio::time::Instant,
) -> Result<Vec<tokio_postgres::Row>> {
    tokio::time::timeout_at(deadline, client.query(statement, &[]))
        .await
        .context("ledger query deadline exceeded")?
        .context("source artifact ledger cannot be read")
}

fn length_of(row: &tokio_postgres::Row, column: usize) -> Result<u64> {
    u64::try_from(row.get::<_, i64>(column)).context("negative artifact length")
}

/// Every `pg_refstore` artifact row exactly as stored, with its publication
/// scope, consume receipt and publisher provenance. The rows are raw:
/// `inventory` validates them through one decode path (the typed ACK and owner
/// scopes are refused there, before the declared selection can drop a row) and
/// the source validator reports a missing hold or receipt through its own SQL
/// instead of shrinking the list.
///
/// Positions: 0..11 and 25.. the artifact/hold/receipt columns of the archive
/// row; 12..13 publication realm; 14..20 hold coordinates; 21..24 the hold's
/// own provider/backend/sha256/length; 26 `consumed_at_unix_micros` (the body's
/// exact clock, compared after decoding); 27 the publication repository tenant;
/// 28 the publication owner (pack producer / A3 requester); 29..30 the
/// publication's own repository and pack; 31..34 the acquire request scope;
/// 35 the hold owner; 36..38 the consume receipt's own scope; 39 the exact
/// receipt identified by the hold and consume id.
async fn inventory_rows(client: &(impl GenericClient + Sync), deadline: tokio::time::Instant) -> Result<Vec<Artifact>> {
    let rows = read(
        client,
        "SELECT a.repository_id,a.registration_id,a.pack_id,a.role,a.slot,a.hold_id,a.acquire_request_id,
                    a.consume_request_id,a.provider,a.backend_identity,a.sha256,a.content_length,
                    p.history_incarnation,p.authority_epoch,h.authority_id,h.authority_generation,h.attempt_id,
                    h.namespace,h.tenant_id,h.storage_tenant_id,h.provider,h.backend_identity,h.sha256,
                    h.content_length,h.repository_id,c.body,c.consumed_at_unix_micros,
                    p.tenant_id,p.owner_id,p.repository_id,p.pack_id,
                    q.request_id,q.repository_id,q.tenant_id,q.owner_id,
                    h.owner_id,
                    c.repository_id,c.tenant_id,c.owner_id,
                    (SELECT count(*) FROM public.artifact_hold_consume_receipts x
                       WHERE x.consume_request_id=a.consume_request_id AND x.hold_id=a.hold_id)
               FROM public.ref_store_core_pack_artifacts a
               JOIN public.ref_store_core_pack_publications p ON p.registration_id=a.registration_id
               JOIN public.artifact_holds h ON h.hold_id=a.hold_id AND h.request_id=a.acquire_request_id
               JOIN public.artifact_hold_requests q ON q.request_id=h.request_id
               JOIN public.artifact_hold_consume_receipts c ON c.hold_id=a.hold_id
                 AND c.consume_request_id=a.consume_request_id AND c.request_id=a.acquire_request_id
              WHERE EXISTS (SELECT 1 FROM public.repositories r
                             WHERE r.id=a.repository_id AND r.storage_backend='pg_refstore')
              ORDER BY a.repository_id,a.pack_id,a.role",
        deadline,
    )
    .await?;
    let mut artifacts = Vec::with_capacity(rows.len());
    for row in rows {
        let body: String = row.get(25);
        let ack = ConsumeAck::decode(&body).map_err(|_| anyhow::anyhow!("stored consume receipt is not decodable"))?;
        let artifact = Artifact {
            repository_id: row.get(0),
            registration_id: row.get(1),
            pack_id: row.get(2),
            role: row.get(3),
            slot: ack.slot,
            hold_id: row.get(5),
            acquire_request_id: row.get(6),
            consume_request_id: row.get(7),
            provider: row.get(8),
            backend_identity: row.get(9),
            sha256: row.get(10),
            length: length_of(&row, 11)?,
            tenant_id: row.get(18),
            authority_id: row.get(14),
            generation: row.get(15),
            attempt_id: row.get(16),
            namespace: row.get(17),
            artifact_set_digest: None,
            declared_by: Vec::new(),
        };
        let length = i64::try_from(artifact.length).context("artifact length out of range")?;
        let held = &ack.artifact;
        // The typed nested hold identity must equal the registered row and the
        // durable hold row on every physical coordinate.
        ensure!(
            held.tenant_id == artifact.tenant_id
                && held.authority_id == artifact.authority_id
                && held.authority_generation == artifact.generation
                && held.attempt_id == artifact.attempt_id
                && held.namespace == artifact.namespace
                && held.sha256 == artifact.sha256
                && held.length == artifact.length
                && held.provider == artifact.provider
                && held.backend_identity == artifact.backend_identity,
            "consume receipt locator differs from the artifact ledger"
        );
        ensure!(
            ack.hold_id == artifact.hold_id
                && ack.request_id == artifact.acquire_request_id
                && ack.consume_request_id == artifact.consume_request_id
                && ack.repository_id == artifact.repository_id
                && ack.tenant_id == artifact.tenant_id
                && ack.history_incarnation == row.get::<_, Uuid>(12)
                && ack.authority_epoch == row.get::<_, i64>(13),
            "consume receipt scope differs from the artifact ledger"
        );
        ensure!(row.get::<_, i64>(26) == ack.consumed_at_unix_micros, "consume receipt clock differs from its body");
        ensure!(
            row.get::<_, Uuid>(19) == artifact.tenant_id
                && row.get::<_, Uuid>(24) == artifact.repository_id
                && row.get::<_, String>(20) == artifact.provider
                && row.get::<_, String>(21) == artifact.backend_identity
                && row.get::<_, String>(22) == artifact.sha256
                && row.get::<_, i64>(23) == length,
            "artifact row and its durable hold disagree on physical identity"
        );
        require_publisher_scope(&row, &ack, &artifact)?;
        ensure!(
            (artifact.slot == 0) == (artifact.role == "pack") && (artifact.slot == 1) == (artifact.role == "idx"),
            "artifact role and slot disagree"
        );
        ensure!(artifact.length > 0 && !artifact.attempt_id.is_nil(), "artifact has no positive length/attempt");
        artifacts.push(artifact);
    }
    ensure!(
        artifacts.windows(2).all(|pair| {
            (pair[0].repository_id, pair[0].pack_id, &pair[0].role)
                < (pair[1].repository_id, pair[1].pack_id, &pair[1].role)
        }),
        "Blob closure rows are not unique and sorted"
    );
    Ok(artifacts)
}

/// One artifact row's publisher scope: the publication tenant is the actual
/// repository tenant (`repositories` owner and core gate tenant), the
/// publication owner is the A3 pack producer of the acquire request, both
/// durable holds, both consume receipts and the typed ACK body, and the
/// artifact row's repository/pack are the publication's own key. Every one of
/// these is refused here, on the single joined row, before the declared
/// selection can drop it.
fn require_publisher_scope(row: &tokio_postgres::Row, ack: &ConsumeAck, artifact: &Artifact) -> Result<()> {
    let tenant: Uuid = row.get(27);
    let producer: Uuid = row.get(28);
    let published = |repository_id: Uuid, tenant_id: Uuid, owner_id: Uuid| {
        repository_id == artifact.repository_id
            && repository_id == row.get::<_, Uuid>(29)
            && tenant_id == tenant
            && owner_id == producer
    };
    ensure!(
        row.get::<_, Uuid>(30) == artifact.pack_id
            && tenant == artifact.tenant_id
            && published(row.get(32), row.get(33), row.get(34))
            && published(artifact.repository_id, row.get(19), row.get(35))
            && published(row.get(36), row.get(37), row.get(38))
            && row.get::<_, i64>(39) == 1,
        "artifact scope differs from its publication repository tenant and producer"
    );
    ensure!(
        !ack_scope_differs(ack, producer, artifact.repository_id, tenant),
        "consume receipt names another producer, repository or tenant than its publication"
    );
    Ok(())
}
