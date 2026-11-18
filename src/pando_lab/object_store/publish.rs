//! Prepared and DB-backed Pando pack publication entry points.

use super::super::{Config, Pack, delta, lifecycle};
use super::{
    ObjectStorePutOptions, ObjectStorePutReport, PreparedPackPublication, prepare_pack_files_sealed, remote_enabled,
    store_root,
};
use anyhow::{Result, ensure};
use tokio_postgres::Client;
use uuid::Uuid;
pub(crate) async fn prepare_known_pack_publication(
    config: &Config,
    client: &Client,
    repo: Uuid,
    pack: &Pack,
    checkpoint: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    storage_tier: &str,
) -> Result<PreparedPackPublication> {
    // The encrypted prepared hook currently produces local CAS only. Use the
    // exact same backend switch as ordinary put/get/verify before provider
    // selection, local sealing, or authoritative SQL publication.
    super::ensure_encrypted_hook_backend_supported(remote_enabled())?;
    let local_root = config.root.join("objects");
    let pack_bytes = std::fs::read(local_root.join(repo.to_string()).join(format!("{}.pack", pack.id)))?;
    let idx_bytes = std::fs::read(local_root.join(repo.to_string()).join(format!("{}.idx", pack.id)))?;
    ensure!(
        delta::sha256_hex(&pack_bytes) == pack.pack_sha256 && delta::sha256_hex(&idx_bytes) == pack.idx_sha256,
        "prepared pack or index digest does not match the known pack identity"
    );
    let opts = ObjectStorePutOptions {
        expected_pack_sha256: Some(pack.pack_sha256.clone()),
        expected_pack_bytes: Some(pack_bytes.len() as u64),
        ..Default::default()
    };
    let prepared = prepare_pack_files_sealed(
        &store_root(config),
        &local_root,
        repo,
        pack.id,
        &opts,
        storage_tier,
        checkpoint,
        Some(client),
    )
    .await?;
    let manifest = prepared.manifest();
    let envelope = prepared.envelope();
    ensure!(
        manifest.repo == repo
            && manifest.pack_id == pack.id
            && manifest.pack_sha256 == pack.pack_sha256
            && manifest.idx_sha256 == pack.idx_sha256,
        "prepared object-store manifest identity mismatch"
    );
    ensure!(
        envelope.encryption_mode == lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE,
        "prepared envelope is not authenticated"
    );
    if let Some(cp) = checkpoint {
        ensure!(
            envelope.provider_kind == cp.to_provider_kind
                && envelope.key_id == cp.to_key_id
                && envelope.key_version == cp.expected_version(),
            "prepared envelope does not match the authoritative rotation target"
        );
    }
    Ok(prepared)
}

pub(super) async fn put_pack_db_inner(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
    storage_tier: &str,
) -> Result<(ObjectStorePutReport, lifecycle::KmsEnvelopeRecord)> {
    // Composed remote publication is not this primitive. Keep the boundary
    // explicit instead of silently committing local CAS under an S3 endpoint.
    ensure!(
        !remote_enabled(),
        "direct local CAS publication is unsupported with ROOTYARD_OBJECT_STORE_ENDPOINT; standalone remote put must use the remote publication path"
    );
    let mut session = lifecycle::publication::writer_session(config, repo).await?;
    let checkpoint = lifecycle::publication::active_rotation(session.client(), repo).await?;
    // Provider selection, sealing and immutable CAS writes happen while this
    // dedicated session owns the shared publication gate, but outside SQL.
    let prepared = prepare_pack_files_sealed(
        &store_root(config),
        &config.root.join("objects"),
        repo,
        pack_id,
        opts,
        storage_tier,
        checkpoint.as_ref(),
        Some(session.client()),
    )
    .await?;
    let t = session.client_mut().transaction().await?;
    let receipt = prepared.publish_in(&t).await?;
    t.commit().await?;
    // The receipt is the DB winner. Mirror only after the known commit and
    // derive the returned report/envelope from the receipt, never the losing
    // prepared value.
    receipt.refresh_mirrors();
    Ok((receipt.report(), receipt.envelope().clone()))
}

pub(crate) async fn put_pack(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
) -> Result<ObjectStorePutReport> {
    if remote_enabled() {
        return super::super::remote::put(config, repo, pack_id, opts).await;
    }
    Ok(put_pack_db_inner(config, repo, pack_id, opts, "hot").await?.0)
}

pub(crate) async fn put_pack_and_seal_with_suite(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    cipher_suite: &str,
    storage_tier: &str,
) -> Result<lifecycle::KmsEnvelopeRecord> {
    let opts = ObjectStorePutOptions { cipher_suite: Some(cipher_suite.to_owned()), ..Default::default() };
    Ok(put_pack_db_inner(config, repo, pack_id, &opts, storage_tier).await?.1)
}
