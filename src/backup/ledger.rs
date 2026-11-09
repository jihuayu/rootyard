//! Read-only, exact views of the `pg_refstore` artifact ledger.
//!
//! All ledger SQL for the Blob closure lives here, in the backup subtree. The
//! Blob byte layer never queries PostgreSQL. Every query is given the caller's
//! `GenericClient`, which is the *exported-snapshot* transaction during backup
//! or the restored database during restore, so both sides read exactly one cut.
//!
//! The typed consume ACK is decoded with the real `ConsumeAck::decode` and its
//! nested `HoldArtifactIdentity` is compared field by field with the artifact
//! row, its hold row and its publication authority. No JSON key is guessed.

use super::*;
use crate::ref_store::artifact_hold::ConsumeAck;
use serde_json::Value;
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
pub(super) async fn carry(client: &(impl GenericClient + Sync)) -> Result<RefStoreCarry> {
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
            "SELECT CASE WHEN pg_column_size(row)<=8388608 THEN row ELSE NULL END \
             FROM (SELECT to_jsonb(t) AS row FROM public.\"{table}\" t) q \
             ORDER BY row::text COLLATE \"C\""
        );
        let stream = client.query_raw(&sql, std::iter::empty::<&(dyn tokio_postgres::types::ToSql + Sync)>()).await?;
        futures_util::pin_mut!(stream);
        let mut digest = Sha256::new();
        let mut rows = 0u64;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
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
async fn require_closed_cut(client: &(impl GenericClient + Sync)) -> Result<()> {
    let open: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM public.git_operations WHERE outcome IN ('pending','in-progress'))
                  + (SELECT count(*) FROM public.ref_store_operations WHERE state='pending')",
            &[],
        )
        .await?
        .get(0);
    ensure!(open == 0, "paired backup requires every write operation to have reached a terminal result");
    Ok(())
}

/// Exact artifact closure of one snapshot, in canonical order.
pub(super) async fn inventory(
    client: &(impl GenericClient + Sync),
    backend: &str,
    provider: &str,
) -> Result<Vec<Artifact>> {
    require_closed_cut(client).await?;
    let invalid: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM public.repositories r LEFT JOIN public.ref_store_serving_repositories s \
         ON s.repository_id=r.id WHERE r.storage_backend='pg_refstore' AND (s.repository_id IS NULL \
         OR s.owner_id<>r.owner_id OR s.name<>r.name OR s.object_format<>r.object_format OR s.state<>'ready' \
         OR s.backend_identity<>$1 OR r.transition_state<>'stable'))",
            &[&backend],
        )
        .await?
        .get(0);
    ensure!(!invalid, "a Blob repository lacks its exact ready serving binding");
    let rows = client
        .query(
            "SELECT a.repository_id,a.registration_id,a.pack_id,a.role,a.hold_id,a.acquire_request_id,
                    a.consume_request_id,a.provider,a.backend_identity,a.sha256,a.content_length,
                    p.history_incarnation,p.authority_epoch,h.tenant_id,h.authority_id,
                    h.authority_generation,h.attempt_id,h.namespace,h.provider,h.backend_identity,
                    h.sha256,h.content_length,h.storage_tenant_id,h.repository_id,c.body
               FROM public.ref_store_core_pack_artifacts a
               JOIN public.ref_store_core_pack_publications p ON p.registration_id=a.registration_id
               JOIN public.artifact_holds h ON h.hold_id=a.hold_id AND h.request_id=a.acquire_request_id
               JOIN public.artifact_hold_consume_receipts c ON c.hold_id=a.hold_id
                 AND c.consume_request_id=a.consume_request_id AND c.request_id=a.acquire_request_id
              WHERE EXISTS (SELECT 1 FROM public.repositories r
                             WHERE r.id=a.repository_id AND r.storage_backend='pg_refstore')
              ORDER BY a.repository_id,a.pack_id,a.role",
            &[],
        )
        .await?;
    let mut artifacts = Vec::with_capacity(rows.len());
    for row in rows {
        let body: String = row.get(24);
        let ack = ConsumeAck::decode(&body).map_err(|_| anyhow::anyhow!("stored consume receipt is not decodable"))?;
        let artifact = Artifact {
            repository_id: row.get(0),
            registration_id: row.get(1),
            pack_id: row.get(2),
            role: row.get(3),
            hold_id: row.get(4),
            acquire_request_id: row.get(5),
            consume_request_id: row.get(6),
            provider: row.get(7),
            backend_identity: row.get(8),
            sha256: row.get(9),
            length: u64::try_from(row.get::<_, i64>(10)).context("negative artifact length")?,
            tenant_id: row.get(13),
            authority_id: row.get(14),
            generation: row.get(15),
            attempt_id: row.get(16),
            namespace: row.get(17),
            slot: ack.slot,
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
                && ack.history_incarnation == row.get::<_, Uuid>(11)
                && ack.authority_epoch == row.get::<_, i64>(12),
            "consume receipt scope differs from the artifact ledger"
        );
        ensure!(
            row.get::<_, Uuid>(22) == artifact.tenant_id
                && row.get::<_, Uuid>(23) == artifact.repository_id
                && row.get::<_, String>(18) == artifact.provider
                && row.get::<_, String>(19) == artifact.backend_identity
                && row.get::<_, String>(20) == artifact.sha256
                && row.get::<_, i64>(21) == length,
            "artifact row and its durable hold disagree on physical identity"
        );
        ensure!(
            (artifact.slot == 0) == (artifact.role == "pack") && (artifact.slot == 1) == (artifact.role == "idx"),
            "artifact role and slot disagree"
        );
        ensure!(
            artifact.provider == provider && artifact.backend_identity == backend,
            "artifact names a foreign backend"
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
