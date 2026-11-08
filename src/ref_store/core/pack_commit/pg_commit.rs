//! Registration and verified-commit transactions of the A4a slice.
//!
//! Registration binds one exact A3 two-artifact publish pair to one planned pack
//! pair under the same parent digest; the verified commit reuses the migration-138
//! lock prefix and writes refs + HEAD + membership + gate revision/mode +
//! operation terminal + event atomically, only with a verifier proof.
use super::artifact::{ArtifactLocator, ArtifactSetDigest, RegisteredArtifact, RegisteredPack};
use super::closure::PackClosureContext;
use super::context::PackCommitBaseline;
use super::contract::{ARTIFACTS_PER_PACK, PackArtifactRole, PackMode};
use super::error::{PackCommitError, PackCommitRejectCode};
use super::plan::{ContentDigest, PackCommitPlan, PlannedPack};
use super::proof::{PackClosureProof, refuse_unusable};
use super::receipt::{
    PackCommitReceipt, PackCommitTerminal, PackRegistrationAck, PackRegistrationReceipt, PackTerminalRegistration,
    ensure_pack_terminal_budget,
};
use super::registration;
use super::request::PackRegistrationRequest;
use super::usage::{Charge, apply as apply_quota, lock as lock_quota, plan as plan_quota};
use super::{pg, sql};
use crate::ref_store::contract::{OperationState, RefStoreError, TerminalOutcome, TerminalResult};
use crate::ref_store::core::artifact_hold::{ArtifactHoldPurpose, HoldScope, read_registration_ledger};
use crate::ref_store::core::terminal::RefCommitResult;
use crate::ref_store::core::types::RefTarget;
use crate::ref_store::pg::PgRefStore;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

impl pg::PgPackCommit {
    /// Register exactly one planned pack pair for one actual protected
    /// publication. Idempotent only for the exact same parent/pack/content/batch.
    ///
    /// An exact historical registration replays as a read-only receipt *before*
    /// any parent lock or quota charge, so a completed/cancelled parent (or a
    /// deleted business repository row) cannot break replay. The fresh path then
    /// redoes the same bounded immutable lookup after the exact 138 prefix and
    /// the quota locks, so no write can be inserted next to an existing one.
    pub async fn register_publication(
        &self,
        client: &mut Client,
        request: PackRegistrationRequest<'_>,
        deadline: Instant,
    ) -> Result<PackRegistrationReceipt, PackCommitError> {
        let plan = request.plan();
        let publication = request.publication();
        let replay = {
            let tx = begin_bounded(client, deadline).await?;
            let existing = pg::stage_bounded(
                deadline,
                registration::by_request(
                    &tx,
                    plan.scope(),
                    publication.acquire_request_id(),
                    publication.consume_request_id(),
                    request.planned_pack().registration_id(),
                    deadline,
                ),
            )
            .await;
            let _ = tx.rollback().await;
            existing?
        };
        if let Some(stored) = replay {
            return exact_replay(&stored, plan, &request);
        }
        let tx = begin_bounded(client, deadline).await?;
        let result = pg::stage_bounded(deadline, async {
            // Transaction-local durability: never inherit an external
            // synchronous_commit=off session/role/database policy.
            pg::set_ack_durability(&tx, deadline).await?;
            self.register_in_tx(&tx, &request, deadline).await
        })
        .await;
        match result {
            Ok(receipt) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn register_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &PackRegistrationRequest<'_>,
        deadline: Instant,
    ) -> Result<PackRegistrationReceipt, PackCommitError> {
        let plan = request.plan();
        let publication = request.publication();
        // Exact migration-138 prefix (operation key + repository existence +
        // issuer lane) held until COMMIT; a missing pending row is never created
        // here (typed refusal, whole transaction rolled back).
        pg::acquire_pending_prefix(tx, plan, deadline).await?;
        crate::ref_store::pg::bound(tx, deadline).await?;
        pg::ensure_repository(tx, plan.repository_id(), plan.tenant_id(), true).await?;
        // Tenant -> repository quota rows are locked BEFORE the core gate.
        let locked = lock_quota(tx, plan.repository_id(), plan.tenant_id()).await?;
        // Authoritative re-check of the same bounded immutable lookup before the
        // first persistent publication/artifact row.
        if let Some(stored) = registration::by_request(
            tx,
            plan.scope(),
            publication.acquire_request_id(),
            publication.consume_request_id(),
            request.planned_pack().registration_id(),
            deadline,
        )
        .await?
        {
            return exact_replay(&stored, plan, request);
        }
        let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
            .await?
            .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
        pg::ensure_gate_matches(plan, &gate, mode)?;
        crate::ref_store::pg::bound(tx, deadline).await?;
        let pack = registered_pack(tx, plan, request, &gate).await?;
        // One stable exact ACK: the fixed point of the retained logical charge is
        // encoded, so body, row column and quota counter agree bit for bit.
        let (ack, body) = stable_ack(plan, request, &gate, &pack)?;
        let quota = plan_quota(&locked, Charge::registration(body.len(), body.len())?)?;
        write_registration(tx, plan, request, &gate, &pack, &ack, &body).await?;
        sql::insert_history(
            tx,
            plan.repository_id(),
            plan.tenant_id(),
            "registered",
            &pack,
            plan.parent_digest(),
            gate.revision(),
            plan.identity().operation_id(),
            &body,
        )
        .await?;
        apply_quota(tx, &quota).await?;
        Ok(PackRegistrationReceipt { ack, replayed: false })
    }

    /// Commit the verified pending operation. Requires the exact durable Pending
    /// row and a proof that binds this plan and the freshly re-read context.
    pub async fn commit_verified_pending(
        &self,
        client: &mut Client,
        plan: &PackCommitPlan,
        token: &super::request::PackPendingToken,
        proof: &PackClosureProof,
        deadline: Instant,
    ) -> Result<PackCommitReceipt, PackCommitError> {
        if !token.binds(plan) {
            return Err(PackCommitError::Invalid("pending token does not bind this plan"));
        }
        let tx = begin_bounded(client, deadline).await?;
        let result = pg::stage_bounded(deadline, async {
            pg::set_ack_durability(&tx, deadline).await?;
            self.commit_in_tx(&tx, plan, proof, deadline).await
        })
        .await;
        match result {
            Ok(receipt) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn commit_in_tx(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        proof: &PackClosureProof,
        deadline: Instant,
    ) -> Result<PackCommitReceipt, PackCommitError> {
        // Exact 138 prefix (operation key, repository existence, issuer lane).
        let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
        match begun.record.state() {
            OperationState::Committed | OperationState::Rejected => {
                return if begun.created {
                    Err(pg::reject(
                        PackCommitRejectCode::AlreadyVerified,
                        "unexpected freshly created terminal operation",
                    ))
                } else {
                    pg::replay_terminal(begun)
                };
            }
            OperationState::Cancelled => {
                return Err(pg::reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
            }
            OperationState::Pending => {
                if begun.created {
                    return Err(pg::reject(
                        PackCommitRejectCode::PendingMissing,
                        "verified commit needs an existing Pending established by begin_pending",
                    ));
                }
            }
        }
        if begun.record.identity() != plan.identity() {
            return Err(PackCommitError::from(RefStoreError::DigestConflict));
        }
        crate::ref_store::pg::bound(tx, deadline).await?;
        pg::ensure_repository(tx, plan.repository_id(), plan.tenant_id(), true).await?;
        // Tenant -> repository quota rows are locked before the core gate.
        let locked = lock_quota(tx, plan.repository_id(), plan.tenant_id()).await?;
        let baseline = self.recheck_baseline(tx, plan, deadline).await?;
        if baseline.membership_digest() != plan.old_membership_digest() {
            return Err(pg::reject(PackCommitRejectCode::OldMembershipMismatch, "membership set changed"));
        }
        let new_packs = sql::registered_for_parent(tx, plan).await?;
        let context = PackClosureContext::capture(plan, &baseline, new_packs)?;
        let proof = refuse_unusable(Some(proof), plan, &context)?;
        ensure_pack_terminal_budget(plan)?;
        let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
            .await?
            .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
        pg::ensure_gate_matches(plan, &gate, mode)?;
        // Pure terminal/result: exact retained body sizes are known before the
        // first persistent ref/membership/history write.
        let prepared = prepare_commit(plan, &context, &gate)?;
        let history_body = proof.context_digest().as_hex();
        let terminal_bytes = prepared.terminal_body_bytes;
        let quota =
            plan_quota(&locked, Charge::membership(plan.packs().len() as i64, history_body.len(), terminal_bytes)?)?;
        crate::ref_store::pg::bound(tx, deadline).await?;
        let receipt = write_verified_commit(tx, plan, &history_body, &context, &gate, &prepared, deadline).await?;
        apply_quota(tx, &quota).await?;
        Ok(receipt)
    }

    async fn recheck_baseline(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<PackCommitBaseline, PackCommitError> {
        crate::ref_store::pg::bound(tx, deadline).await?;
        let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
            .await?
            .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
        pg::ensure_gate_matches(plan, &gate, mode)?;
        let refs = sql::capture_refs(tx, plan.repository_id(), gate.object_format(), 4096).await?;
        let old_packs = registration::old_memberships(tx, &gate, deadline).await?;
        PackCommitBaseline::new(gate.version(), mode, refs, old_packs)
    }
}

fn pack_total(pack: &RegisteredPack) -> Result<u64, PackCommitError> {
    pack.artifacts().iter().try_fold(0u64, |total, artifact| {
        total.checked_add(artifact.locator().length()).ok_or(PackCommitError::Invalid("artifact bytes overflowed"))
    })
}

/// Exact replay only: every requested identity, parent and planned content must
/// equal the stored registration. A global id that means a different request
/// (other parent/pack/A3 pair/content) is a typed `RegistrationConflict` with no
/// writes — never a replay of an unrelated old ACK.
fn exact_replay(
    stored: &registration::StoredRegistration,
    plan: &PackCommitPlan,
    request: &PackRegistrationRequest<'_>,
) -> Result<PackRegistrationReceipt, PackCommitError> {
    let ack = &stored.ack;
    let publication = request.publication();
    let planned = request.planned_pack();
    let planned_pack = planned.artifact(PackArtifactRole::Pack);
    let planned_idx = planned.artifact(PackArtifactRole::Idx);
    let pack = &stored.pack;
    let backend = publication_backend(publication)?;
    let actual_pair = pack.artifact(PackArtifactRole::Pack).hold_id()
        == request.artifact(PackArtifactRole::Pack).hold_id()
        && pack.artifact(PackArtifactRole::Idx).hold_id() == request.artifact(PackArtifactRole::Idx).hold_id()
        && pack.artifact(PackArtifactRole::Pack).locator().sha256() == planned_pack.content()
        && pack.artifact(PackArtifactRole::Pack).locator().length() == planned_pack.length()
        && pack.artifact(PackArtifactRole::Idx).locator().sha256() == planned_idx.content()
        && pack.artifact(PackArtifactRole::Idx).locator().length() == planned_idx.length()
        && pack.artifact(PackArtifactRole::Pack).backend_identity() == backend.as_str()
        && pack.artifact(PackArtifactRole::Idx).backend_identity() == backend.as_str()
        && request.artifacts().iter().all(|artifact| {
            let stored_artifact = pack.artifact(artifact.role());
            stored_artifact.locator().sha256() == artifact.sha256()
                && stored_artifact.locator().length() == artifact.length()
        });
    let exact = ack.registration_id == planned.registration_id()
        && ack.pack_id == planned.pack_id()
        && ack.acquire_request_id == publication.acquire_request_id()
        && ack.consume_request_id == publication.consume_request_id()
        && ack.repository_id == plan.repository_id()
        && ack.tenant_id == plan.tenant_id()
        && ack.plan_operation_id == plan.identity().operation_id()
        && ack.parent_digest == plan.parent_digest().as_hex()
        && ack.object_format == plan.object_format().as_str()
        && ack.history_incarnation == plan.history_incarnation()
        && ack.authority_epoch == plan.authority_epoch()
        && ack.group_epoch == plan.group_epoch()
        && ack.planned_pack_sha256 == planned_pack.content().as_str()
        && ack.planned_pack_length == planned_pack.length()
        && ack.planned_idx_sha256 == planned_idx.content().as_str()
        && ack.planned_idx_length == planned_idx.length()
        && ack.backend_identity == backend
        && actual_pair;
    if exact {
        Ok(stored.replay())
    } else {
        Err(pg::reject(
            PackCommitRejectCode::RegistrationConflict,
            "global registration id already names a different request",
        ))
    }
}

fn build_ack(
    plan: &PackCommitPlan,
    request: &PackRegistrationRequest<'_>,
    gate: &crate::ref_store::core::contract::CoreGate,
    pack: &RegisteredPack,
    logical_bytes: i64,
) -> Result<PackRegistrationAck, PackCommitError> {
    let planned = planned_pack_of(plan, pack.pack_id())?;
    let publication = request.publication();
    let pack_artifact = planned.artifact(PackArtifactRole::Pack);
    let idx_artifact = planned.artifact(PackArtifactRole::Idx);
    Ok(PackRegistrationAck {
        registration_id: pack.registration_id(),
        pack_id: pack.pack_id(),
        repository_id: plan.repository_id(),
        tenant_id: plan.tenant_id(),
        owner_id: plan.owner_id(),
        purpose: ArtifactHoldPurpose::RefPublication.as_str().to_owned(),
        object_format: plan.object_format().as_str().to_owned(),
        history_incarnation: plan.history_incarnation(),
        authority_epoch: plan.authority_epoch(),
        group_epoch: plan.group_epoch(),
        plan_operation_id: plan.identity().operation_id(),
        parent_digest: plan.parent_digest().as_hex(),
        gate_revision: gate.revision(),
        gate_digest: gate.digest().as_hex(),
        backend_identity: publication_backend(publication)?,
        planned_pack_sha256: pack_artifact.content().as_str().to_owned(),
        planned_pack_length: pack_artifact.length(),
        planned_idx_sha256: idx_artifact.content().as_str().to_owned(),
        planned_idx_length: idx_artifact.length(),
        artifact_set_digest: pack.artifact_set_digest().as_hex(),
        acquire_request_id: publication.acquire_request_id(),
        consume_request_id: publication.consume_request_id(),
        hold_ids: pack.artifacts().iter().map(RegisteredArtifact::hold_id).collect(),
        logical_bytes,
        candidate_packs: PackRegistrationAck::one_pair(),
    })
}

/// The ACK's `logical_bytes` must equal the value charged to the quota counters,
/// and the charge depends on the encoded body length. Iterate the bounded fixed
/// point (initialize 0, re-encode, recompute) and refuse before any write if it
/// does not stabilize within a strict small iteration cap.
fn stable_ack(
    plan: &PackCommitPlan,
    request: &PackRegistrationRequest<'_>,
    gate: &crate::ref_store::core::contract::CoreGate,
    pack: &RegisteredPack,
) -> Result<(PackRegistrationAck, String), PackCommitError> {
    let mut logical: i64 = 0;
    for _ in 0..8u8 {
        let ack = build_ack(plan, request, gate, pack, logical)?;
        ack.ensure_one_pair()?;
        let body = ack.encode()?;
        let target = Charge::registration(body.len(), body.len())?;
        if target.logical_bytes == logical {
            return Ok((ack, body));
        }
        logical = target.logical_bytes;
    }
    Err(PackCommitError::Capacity { limit: "ack_logical_fixed_point", bound: 8, actual: 8 })
}

fn planned_pack_of(plan: &PackCommitPlan, pack_id: Uuid) -> Result<&PlannedPack, PackCommitError> {
    plan.packs()
        .iter()
        .find(|pack| pack.pack_id() == pack_id)
        .ok_or_else(|| pg::reject(PackCommitRejectCode::RegistrationMissing, "pack is not planned"))
}

async fn registered_pack(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    request: &PackRegistrationRequest<'_>,
    gate: &crate::ref_store::core::contract::CoreGate,
) -> Result<RegisteredPack, PackCommitError> {
    let planned = planned_pack_of(plan, request.planned_pack().pack_id())?;
    let scope = HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|_| pg::reject(PackCommitRejectCode::TenantMismatch, "hold scope is invalid"))?;
    let publication = request.publication();
    // Explicit ledger type: no reliance on an untyped re-export.
    let ledger: crate::ref_store::core::artifact_hold::RegistrationLedger =
        read_registration_ledger(tx, &scope, publication.acquire_request_id(), publication.consume_request_id())
            .await
            .map_err(|_| pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 ledger read refused"))?;
    let ack = ledger.acquire_ack();
    if ack.operation_id != plan.identity().operation_id()
        || ack.operation_digest != plan.parent_digest().as_hex()
        || ack.gate_revision != gate.revision()
        || ack.gate_digest != gate.digest().as_hex()
        || ack.repository_id != plan.repository_id()
        || ack.tenant_id != plan.tenant_id()
        || ack.owner_id != plan.owner_id()
        || ack.artifact_count() != ARTIFACTS_PER_PACK
        || ack.consume_request_id != publication.consume_request_id()
    {
        return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 acquire batch does not bind this plan"));
    }
    if ack.backend_identity != publication_backend(publication)? {
        return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "publication backend differs from A3"));
    }
    // Full consume-receipt comparison: exactly the two receipts of this one A3
    // batch, each agreeing with the planned pair, the publication and the parent.
    let receipts: &[crate::ref_store::core::artifact_hold::ConsumeAck] = ledger.consume_receipts();
    if receipts.len() != ARTIFACTS_PER_PACK {
        return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 consume batch is not a pair"));
    }
    for receipt in receipts {
        let role = match receipt.slot {
            0 => PackArtifactRole::Pack,
            1 => PackArtifactRole::Idx,
            _ => return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 receipt slot is not a pair")),
        };
        let planned_artifact = planned.artifact(role);
        if receipt.request_id != publication.acquire_request_id()
            || receipt.consume_request_id != publication.consume_request_id()
            || receipt.hold_id != request.artifact(role).hold_id()
            || receipt.operation_id != plan.identity().operation_id()
            || receipt.operation_digest != plan.parent_digest().as_hex()
            || receipt.gate_revision != gate.revision()
            || receipt.gate_digest != gate.digest().as_hex()
            || receipt.repository_id != plan.repository_id()
            || receipt.tenant_id != plan.tenant_id()
            || receipt.owner_id != plan.owner_id()
            || receipt.artifact.sha256 != planned_artifact.content().as_str()
            || receipt.artifact.length != planned_artifact.length()
            || receipt.artifact.provider.is_empty()
        {
            return Err(pg::reject(
                PackCommitRejectCode::PublicationMismatch,
                "A3 consume receipt differs from the plan/publication",
            ));
        }
    }
    let mut artifacts = Vec::with_capacity(ARTIFACTS_PER_PACK);
    for hold in ack.holds() {
        let role = match hold.slot {
            0 => PackArtifactRole::Pack,
            1 => PackArtifactRole::Idx,
            _ => return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 slot is not a pair slot")),
        };
        let planned_artifact = planned.artifact(role);
        let identity = &hold.artifact;
        if identity.sha256 != planned_artifact.content().as_str()
            || identity.length != planned_artifact.length()
            || identity.provider.is_empty()
        {
            return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "A3 hold content differs from plan"));
        }
        if request.artifact(role).hold_id() != hold.hold_id {
            return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "publication hold differs from A3"));
        }
        let locator = ArtifactLocator::new(
            identity.tenant_id,
            identity.authority_id,
            identity.authority_generation,
            identity.attempt_id,
            identity.namespace.clone(),
            ContentDigest::parse(identity.sha256.clone())?,
            identity.length,
        )?;
        artifacts.push(RegisteredArtifact::new(
            role,
            hold.slot,
            hold.hold_id,
            locator.clone(),
            identity.provider.clone(),
            identity.backend_identity.clone(),
            locator.sha256().clone(),
            locator.length(),
        )?);
    }
    let digest = ArtifactSetDigest::of(&artifacts);
    RegisteredPack::new(planned.pack_id(), planned.registration_id(), digest, artifacts, None)
}

fn publication_backend(
    publication: &crate::blob_store::protected::ProtectedPublication,
) -> Result<String, PackCommitError> {
    let mut backend: Option<String> = None;
    for receipt in publication.receipts() {
        let identity = receipt.receipt().backend_identity().as_hex().to_owned();
        match &backend {
            None => backend = Some(identity),
            Some(existing) if existing != &identity => {
                return Err(pg::reject(PackCommitRejectCode::PublicationMismatch, "mixed publication backends"));
            }
            Some(_) => {}
        }
    }
    backend.ok_or_else(|| pg::reject(PackCommitRejectCode::PublicationMismatch, "empty publication"))
}

async fn write_registration(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    request: &PackRegistrationRequest<'_>,
    gate: &crate::ref_store::core::contract::CoreGate,
    pack: &RegisteredPack,
    ack: &PackRegistrationAck,
    body: &str,
) -> Result<(), PackCommitError> {
    let planned = planned_pack_of(plan, pack.pack_id())?;
    let total = pack_total(pack)?;
    tx.execute(
        "INSERT INTO ref_store_core_pack_publications(registration_id,pack_id,repository_id,tenant_id,owner_id,
             purpose,object_format,history_incarnation,authority_epoch,group_epoch,parent_digest,plan_operation_id,
             planned_pack_sha256,planned_pack_length,planned_idx_sha256,planned_idx_length,artifact_set_digest,
             acquire_request_id,consume_request_id,backend_identity,gate_revision,gate_digest,pack_mode,
             declared_bytes,logical_bytes,ack_body)
         VALUES($1,$2,$3,$4,$5,'ref_publication',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)",
        &[
            &pack.registration_id(),
            &pack.pack_id(),
            &plan.repository_id(),
            &plan.tenant_id(),
            &plan.owner_id(),
            &plan.object_format().as_str(),
            &plan.history_incarnation(),
            &plan.authority_epoch(),
            &plan.group_epoch(),
            &plan.parent_digest().as_hex(),
            &plan.identity().operation_id(),
            &planned.artifact(PackArtifactRole::Pack).content().as_str(),
            &i64::try_from(planned.artifact(PackArtifactRole::Pack).length())
                .map_err(|_| PackCommitError::Invalid("planned pack length exceeds i64"))?,
            &planned.artifact(PackArtifactRole::Idx).content().as_str(),
            &i64::try_from(planned.artifact(PackArtifactRole::Idx).length())
                .map_err(|_| PackCommitError::Invalid("planned idx length exceeds i64"))?,
            &pack.artifact_set_digest().as_hex(),
            &request.publication().acquire_request_id(),
            &request.publication().consume_request_id(),
            &publication_backend(request.publication())?,
            &gate.revision(),
            &gate.digest().as_hex(),
            &plan.expected().mode().as_str(),
            &i64::try_from(total).map_err(|_| PackCommitError::Invalid("artifact bytes exceed i64"))?,
            &ack.logical_bytes,
            &body,
        ],
    )
    .await
    .map_err(crate::ref_store::pg::db_error)?;
    for artifact in pack.artifacts() {
        let locator = artifact.locator();
        tx.execute(
            "INSERT INTO ref_store_core_pack_artifacts(registration_id,role,slot,hold_id,acquire_request_id,
                 consume_request_id,pack_id,repository_id,tenant_id,provider,backend_identity,namespace,sha256,
                 content_length,declared_bytes,logical_bytes)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[
                &pack.registration_id(),
                &artifact.role().as_str(),
                &artifact.slot(),
                &artifact.hold_id(),
                &request.publication().acquire_request_id(),
                &request.publication().consume_request_id(),
                &pack.pack_id(),
                &plan.repository_id(),
                &plan.tenant_id(),
                &artifact.provider(),
                &artifact.backend_identity(),
                &locator.namespace(),
                &locator.sha256().as_str(),
                &i64::try_from(locator.length()).map_err(|_| PackCommitError::Invalid("length exceeds i64"))?,
                &i64::try_from(locator.length()).map_err(|_| PackCommitError::Invalid("length exceeds i64"))?,
                &super::usage::retained_logical_bytes(&[], 1)?,
            ],
        )
        .await
        .map_err(crate::ref_store::pg::db_error)?;
    }
    Ok(())
}

/// Pure, pre-write commit content: the exact result refs, terminal and its
/// bounded canonical body. Nothing here touches the database.
struct PreparedCommit {
    new_revision: i64,
    new_head: String,
    terminal: PackCommitTerminal,
    result: TerminalResult,
    terminal_body_bytes: usize,
}

fn prepare_commit(
    plan: &PackCommitPlan,
    context: &PackClosureContext,
    gate: &crate::ref_store::core::contract::CoreGate,
) -> Result<PreparedCommit, PackCommitError> {
    let results = plan
        .refs()
        .iter()
        .map(|update| RefCommitResult::Applied {
            name: update.name().as_str().to_owned(),
            old_oid: update.precondition().oid().map(|oid| oid.as_hex()),
            new_oid: update.target().oid().map(|oid| oid.as_hex()),
        })
        .collect::<Vec<_>>();
    let registrations = context
        .new_packs()
        .iter()
        .map(|pack| PackTerminalRegistration {
            pack_id: pack.pack_id(),
            registration_id: pack.registration_id(),
            artifact_set_digest: pack.artifact_set_digest().as_hex(),
        })
        .collect::<Vec<_>>();
    let terminal = PackCommitTerminal::committed(
        plan.repository_id(),
        gate.revision() + 1,
        context.resulting_head().as_str().to_owned(),
        PackMode::PackVerified,
        results,
        registrations,
    );
    let result = terminal.to_terminal_result()?;
    let terminal_body_bytes = serde_json::to_vec(&terminal)
        .map_err(|_| PackCommitError::Invalid("pack commit terminal is not serializable"))?
        .len();
    Ok(PreparedCommit {
        new_revision: gate.revision() + 1,
        new_head: context.resulting_head().as_str().to_owned(),
        terminal,
        result,
        terminal_body_bytes,
    })
}

async fn write_verified_commit(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    history_body: &str,
    context: &PackClosureContext,
    gate: &crate::ref_store::core::contract::CoreGate,
    prepared: &PreparedCommit,
    deadline: Instant,
) -> Result<PackCommitReceipt, PackCommitError> {
    let new_revision = prepared.new_revision;
    let new_head = prepared.new_head.clone();
    for update in plan.refs() {
        let name = update.name().as_str();
        match update.target() {
            RefTarget::Delete => {
                let changed = tx
                    .execute(
                        "DELETE FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2",
                        &[&plan.repository_id(), &name],
                    )
                    .await
                    .map_err(crate::ref_store::pg::db_error)?;
                if changed != 1 {
                    return Err(PackCommitError::from(RefStoreError::Database(
                        "locked ref disappeared during delete".into(),
                    )));
                }
            }
            RefTarget::Oid(oid) => {
                tx.execute(
                    "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision)
                     VALUES($1,$2,$3,$4)
                     ON CONFLICT(repository_id,ref_name) DO UPDATE
                     SET oid=EXCLUDED.oid,revision=EXCLUDED.revision,updated_at=clock_timestamp()",
                    &[&plan.repository_id(), &name, &oid.as_hex(), &new_revision],
                )
                .await
                .map_err(crate::ref_store::pg::db_error)?;
            }
        }
    }
    let updated = tx
        .query_opt(
            "UPDATE ref_store_core_gates
             SET revision=$2,head_ref=$3,pack_mode='pack_verified',updated_at=clock_timestamp()
             WHERE repository_id=$1 AND revision=$4 AND pack_mode=$5
             RETURNING revision",
            &[&plan.repository_id(), &new_revision, &new_head, &gate.revision(), &plan.expected().mode().as_str()],
        )
        .await
        .map_err(crate::ref_store::pg::db_error)?;
    if updated.is_none() {
        return Err(PackCommitError::from(RefStoreError::Database(
            "gate revision/mode changed while its row was locked".into(),
        )));
    }
    for pack in context.new_packs() {
        sql::insert_membership(tx, plan.repository_id(), pack, new_revision).await?;
    }
    let receipt =
        PgRefStore.record_terminal(tx, plan.identity(), TerminalOutcome::Committed, &prepared.result, deadline).await?;
    crate::ref_store::core::sql::insert_event(
        tx,
        plan.repository_id(),
        new_revision,
        plan.identity().operation_id(),
        "committed",
        &prepared.result,
    )
    .await?;
    for pack in context.new_packs() {
        sql::insert_history(
            tx,
            plan.repository_id(),
            plan.tenant_id(),
            "committed",
            pack,
            plan.parent_digest(),
            new_revision,
            plan.identity().operation_id(),
            history_body,
        )
        .await?;
    }
    Ok(PackCommitReceipt { record: receipt.record, replayed: receipt.replayed, terminal: prepared.terminal.clone() })
}
