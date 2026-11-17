//! Publication-gated migration producer plumbing.
//!
//! One dedicated publication-shared PostgreSQL session is opened before the DB
//! checkpoint is read and is retained until the final authority transaction.
//! Provider selection, Git pack staging, filesystem sealing and partial-parity
//! verification all run outside SQL on that same session. The final short
//! transaction re-reads the repository contract and rotation checkpoint before
//! committing the Pando rows together with the prepared local-CAS pair.

use super::super::{Config, Pack, Snapshot};
use anyhow::{Result, bail, ensure};
use std::collections::BTreeMap;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

use super::super::{lifecycle, object_store};

/// Selected DB target and the dedicated gate-owning session.
pub(super) struct ProducerSession {
    session: lifecycle::publication::PgSession,
    checkpoint: Option<lifecycle::rotation::KmsRotationCheckpoint>,
    needs_prepared: bool,
}

/// Repository state that must still be true when the final transaction runs.
pub(super) struct ExpectedRepoState<'a> {
    pub generation: i64,
    pub storage_generation: i64,
    pub storage_backend: &'static str,
    pub migration_state: &'static str,
    pub write_paused: bool,
    pub gitfs_path: &'a str,
}

impl ProducerSession {
    /// Acquire the publication-shared gate, then read the authoritative DB
    /// checkpoint. Never acquire a runner lock after this point.
    pub(super) async fn begin(config: &Config, repo: Uuid) -> Result<Self> {
        let session = lifecycle::publication::writer_session(config, repo).await?;
        let checkpoint = lifecycle::publication::active_rotation(session.client(), repo).await?;
        let selected = lifecycle::provider_selection::selected_kind()?;
        let needs_prepared = needs_prepared_encryption(checkpoint.is_some(), selected);
        Ok(Self { session, checkpoint, needs_prepared })
    }

    pub(super) fn checkpoint(&self) -> Option<&lifecycle::rotation::KmsRotationCheckpoint> {
        self.checkpoint.as_ref()
    }

    pub(super) fn needs_prepared(&self) -> bool {
        self.needs_prepared
    }

    pub(super) fn client_mut(&mut self) -> &mut Client {
        self.session.client_mut()
    }

    /// The composed remote mode has no staged prepare API in this checkpoint.
    /// Refuse only the exact mode that would otherwise claim an authenticated
    /// object-store publication, and do it before any authority mutation.
    pub(super) fn ensure_composed_mode_supported(&self) -> Result<()> {
        ensure_composed_supported(self.needs_prepared, object_store::remote_enabled())
    }

    /// Provider work and immutable CAS writes happen outside SQL. Exact retry
    /// recovery is performed by the shared factory before any reseal.
    pub(super) async fn prepare(
        &self,
        config: &Config,
        repo: Uuid,
        pack: &Pack,
    ) -> Result<Option<object_store::PreparedPackPublication>> {
        if !self.needs_prepared {
            return Ok(None);
        }
        Ok(Some(
            object_store::prepare_known_pack_publication(
                config,
                self.session.client(),
                repo,
                pack,
                self.checkpoint.as_ref(),
                "hot",
            )
            .await?,
        ))
    }
}

pub(super) fn needs_prepared_encryption(
    has_checkpoint: bool,
    selected: lifecycle::provider_selection::PandoProviderSelection,
) -> bool {
    has_checkpoint || selected == lifecycle::provider_selection::PandoProviderSelection::VaultTransit
}

pub(super) fn ensure_composed_supported(needs_prepared: bool, remote_enabled: bool) -> Result<()> {
    ensure!(
        !needs_prepared || !remote_enabled,
        "composed authenticated migration publication is unsupported with ROOTYARD_OBJECT_STORE_ENDPOINT; the prepared helper is local CAS only, so no local fallback and no separate remote object-store claim is made"
    );
    Ok(())
}

/// Read the repository snapshot on the owned gate session rather than through
/// an independent pool client. This is the base the final transaction must
/// still match.
pub(super) async fn read_snapshot(client: &mut Client, repo: Uuid) -> Result<Snapshot> {
    let t = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let row =
        t.query_one("SELECT generation,storage_generation FROM pando_lab.repositories WHERE id=$1", &[&repo]).await?;
    let refs = t
        .query("SELECT name,oid FROM pando_lab.refs WHERE repo=$1 ORDER BY name", &[&repo])
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect::<BTreeMap<_, _>>();
    let packs = t
        .query(
            "SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| Pack { id: r.get(0), pack_sha256: r.get(1), idx_sha256: r.get(2) })
        .collect();
    t.commit().await?;
    Ok(Snapshot { repo, generation: row.get(0), storage_generation: row.get(1), refs, packs })
}

/// Lock and re-read the repository contract inside the final transaction.
pub(super) async fn lock_repo_and_validate(
    t: &Transaction<'_>,
    repo: Uuid,
    expected: &ExpectedRepoState<'_>,
) -> Result<()> {
    let row = t
        .query_one(
            "SELECT generation,storage_generation,storage_backend,migration_state,write_paused,gitfs_path \
             FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
            &[&repo],
        )
        .await?;
    let generation: i64 = row.get(0);
    let storage_generation: i64 = row.get(1);
    let backend: String = row.get(2);
    let migration_state: String = row.get(3);
    let write_paused: bool = row.get(4);
    let gitfs_path: Option<String> = row.get(5);
    ensure!(
        generation == expected.generation,
        "Pando repository generation changed after migration preparation: expected {}, found {}",
        expected.generation,
        generation
    );
    ensure!(
        storage_generation == expected.storage_generation,
        "Pando repository storage_generation changed after migration preparation: expected {}, found {}",
        expected.storage_generation,
        storage_generation
    );
    ensure!(
        backend == expected.storage_backend,
        "Pando repository storage backend changed after migration preparation: expected {}, found {}",
        expected.storage_backend,
        backend
    );
    ensure!(
        migration_state == expected.migration_state,
        "Pando migration phase changed after migration preparation: expected {}, found {}",
        expected.migration_state,
        migration_state
    );
    ensure!(write_paused == expected.write_paused, "Pando repository write_paused changed after migration preparation");
    ensure!(
        gitfs_path.as_deref() == Some(expected.gitfs_path),
        "Pando repository GitFS path changed after migration preparation: expected {}, found {:?}",
        expected.gitfs_path,
        gitfs_path
    );
    Ok(())
}

/// Prove that no ref or pack authority changed between the projected parity
/// check and this transaction.
pub(super) async fn ensure_snapshot_unchanged(t: &Transaction<'_>, repo: Uuid, base: &Snapshot) -> Result<()> {
    let refs = t
        .query("SELECT name,oid FROM pando_lab.refs WHERE repo=$1 ORDER BY name", &[&repo])
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect::<BTreeMap<_, _>>();
    ensure!(refs == base.refs, "Pando refs changed after migration parity preparation");
    let packs = t
        .query(
            "SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| Pack { id: r.get(0), pack_sha256: r.get(1), idx_sha256: r.get(2) })
        .collect::<Vec<_>>();
    ensure!(
        packs.len() == base.packs.len()
            && packs.iter().zip(&base.packs).all(|(current, expected)| {
                current.id == expected.id
                    && current.pack_sha256 == expected.pack_sha256
                    && current.idx_sha256 == expected.idx_sha256
            }),
        "Pando manifests changed after migration parity preparation"
    );
    Ok(())
}

/// Compare the checkpoint selected before provider work with the fresh DB
/// checkpoint read inside the final transaction.
pub(super) fn ensure_target_unchanged(
    selected: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    fresh: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
) -> Result<()> {
    match (selected, fresh) {
        (None, None) => Ok(()),
        (Some(selected), Some(fresh)) => {
            ensure!(
                selected.rotation_id == fresh.rotation_id
                    && selected.state == fresh.state
                    && selected.write_epoch == fresh.write_epoch,
                "Pando rotation checkpoint changed after migration provider selection"
            );
            ensure!(
                selected.to_provider_kind == fresh.to_provider_kind
                    && selected.to_key_id == fresh.to_key_id
                    && selected.expected_version() == fresh.expected_version(),
                "Pando rotation target changed after migration provider selection"
            );
            Ok(())
        }
        (None, Some(_)) => bail!("an active Pando rotation checkpoint appeared after migration preparation"),
        (Some(_), None) => bail!("the active Pando rotation checkpoint disappeared after migration preparation"),
    }
}

/// Bind the authoritative DB winner receipt to the pack and to the final
/// authoritative checkpoint, including the existing-pair fast path.
pub(super) fn validate_receipt(
    receipt: &object_store::PublicationReceipt,
    repo: Uuid,
    pack: &Pack,
    fresh: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
) -> Result<()> {
    let manifest = receipt.manifest();
    ensure!(
        manifest.repo == repo
            && manifest.pack_id == pack.id
            && manifest.pack_sha256 == pack.pack_sha256
            && manifest.idx_sha256 == pack.idx_sha256,
        "Pando migration publication winner does not bind the staged pack identity"
    );
    if let Some(checkpoint) = fresh {
        let envelope = receipt.envelope();
        ensure!(
            envelope.provider_kind == checkpoint.to_provider_kind
                && envelope.key_id == checkpoint.to_key_id
                && envelope.key_version == checkpoint.expected_version(),
            "Pando migration publication winner does not match the final rotation target"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_encryption_activation_matrix_is_explicit() {
        assert!(!needs_prepared_encryption(false, lifecycle::provider_selection::PandoProviderSelection::Local));
        assert!(needs_prepared_encryption(false, lifecycle::provider_selection::PandoProviderSelection::VaultTransit));
        assert!(needs_prepared_encryption(true, lifecycle::provider_selection::PandoProviderSelection::Local));
        assert!(needs_prepared_encryption(true, lifecycle::provider_selection::PandoProviderSelection::VaultTransit));
    }

    #[test]
    fn composed_remote_boundary_is_narrow() {
        assert!(ensure_composed_supported(false, true).is_ok());
        assert!(ensure_composed_supported(true, false).is_ok());
        assert!(ensure_composed_supported(false, false).is_ok());
        assert!(ensure_composed_supported(true, true).is_err());
    }
}
