//! Real metadata-only gate fixture for the authorized metadata facade.
//!
//! The gate is a fresh, unserved `metadata_only` core gate (no pack commit, no
//! native bytes); the per-repository decision protocol is explicitly
//! provisioned and the actor is a real API token authenticated through
//! `auth::authenticate`. Requests are real `CommitRefsRequest`s, never a
//! synthesized `PackCommitPlan` or native proof.
use super::auth::{self, Actor};
use anyhow::{Result, anyhow};
use rootyard::ref_store::core::authorized_metadata::{
    MetadataDecisionPreparation, PgAuthorizedMetadata, PreparedMetadataPublication,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::{CommitMode, CommitRefsRequest, CoreGateVersion};
use rootyard::ref_store::{GitObjectFormat, HeadUpdate, IssuerLane, RefUpdate};
use uuid::Uuid;

use crate::retention_roots_support::db::{Db, deadline};

pub struct MetadataWorld {
    pub db: Db,
    pub actor: Actor,
    pub repo: Uuid,
    pub tenant: Uuid,
    pub gate: CoreGateVersion,
}

pub async fn world() -> Result<MetadataWorld> {
    let db = Db::setup().await?;
    let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
    let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
    let expectation = RealmExpectation::new(
        repo,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("metadata protocol provisioning refused: {error:?}"))?;
    drop(client);
    let actor = auth::owner(&db.pool, tenant).await?;
    Ok(MetadataWorld { db, actor, repo, tenant, gate })
}

impl MetadataWorld {
    pub fn request(&self, refs: Vec<RefUpdate>, sequence: i64, lane: &str) -> Result<CommitRefsRequest> {
        Ok(CommitRefsRequest::new(
            self.repo,
            self.tenant,
            self.tenant,
            IssuerLane::new(lane)?,
            sequence,
            Uuid::new_v4(),
            self.gate.object_format(),
            self.gate.history_incarnation(),
            self.gate.authority_epoch(),
            self.gate.group_epoch(),
            self.gate.revision(),
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            refs,
        )?)
    }

    pub async fn prepare(&self, request: CommitRefsRequest) -> Result<PreparedMetadataPublication> {
        match PgAuthorizedMetadata
            .prepare(&self.db.pool, request, &self.actor.identity, deadline())
            .await
            .map_err(|error| anyhow!("metadata prepare refused: {error:?}"))?
        {
            MetadataDecisionPreparation::Prepared(prepared) => Ok(*prepared),
            MetadataDecisionPreparation::Replayed(_) => {
                Err(anyhow!("metadata prepare replayed instead of staging a pending request"))
            }
        }
    }

    pub async fn replay(&self, request: CommitRefsRequest) -> Result<rootyard::ref_store::core::CommitRefsReceipt> {
        match PgAuthorizedMetadata
            .prepare(&self.db.pool, request, &self.actor.identity, deadline())
            .await
            .map_err(|error| anyhow!("metadata replay refused: {error:?}"))?
        {
            MetadataDecisionPreparation::Replayed(receipt) => Ok(*receipt),
            MetadataDecisionPreparation::Prepared(_) => Err(anyhow!("metadata replay staged a fresh decision")),
        }
    }

    pub async fn commit(
        &self,
        prepared: &PreparedMetadataPublication,
    ) -> Result<rootyard::ref_store::core::CommitRefsReceipt> {
        PgAuthorizedMetadata
            .commit(&self.db.pool, prepared, deadline())
            .await
            .map_err(|error| anyhow!("metadata commit refused: {error:?}"))
    }
}

pub fn sample_oid(format: GitObjectFormat, byte: u8) -> String {
    let width = if format == GitObjectFormat::Sha1 { 20 } else { 32 };
    hex::encode(vec![byte; width])
}
