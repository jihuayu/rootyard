//! Test-only direct-handoff support for the real PostgreSQL/Blob slot-one
//! acceptance.
//!
//! The production handoff is crate-private and the producer-owned
//! [`VerifiedReceive`] can only be completed inside `receive`. This module adds
//! the minimum fixture seam: build the exact pkt-line command plus captured pack
//! bytes, derive the same producer digest the route derives, stage the actual
//! pack/idx files, and call the real [`SlotOneReceive`]/[`rotate_slot_one`].
//! It is compiled only under `#[cfg(test)]`, selects no route, and never
//! fabricates an authorization, plan, sequence, retirement or terminal.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    blob_git_gateway::{
        error::GatewayError,
        publish::{
            Pair,
            slot_one::{SlotOneAdmission, SlotOneReceive, rotate_slot_one},
        },
        receive,
        state::BlobGitState,
    },
    db::Identity,
    ref_store::{
        GitObjectFormat, OperationState, RequestDigest,
        core::pack_commit::PackCommitPlan,
        pg::{
            public_attempt::PublicAttemptEvidence, public_terminal::PublicAttemptRetirement,
            slot_one::SlotOneRotationReceipt,
        },
        serving::ServingRepository,
    },
};

/// Public-safe projection of one durable rotation receipt. The private UUID is
/// kept for exact SQL assertions but is never formatted into the test's error
/// messages or public terminal checks.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReceiptView {
    pub public_id: Uuid,
    pub private_id: Uuid,
    pub retired_private_id: Uuid,
    pub retired_event_id: Uuid,
    pub retired_event_revision: i64,
    pub sequence: i64,
    pub base_revision: i64,
    pub plan_digest: RequestDigest,
    pub proof_digest: RequestDigest,
    pub wire_digest: RequestDigest,
    pub state: OperationState,
    pub replayed: bool,
}

impl From<SlotOneRotationReceipt> for ReceiptView {
    fn from(receipt: SlotOneRotationReceipt) -> Self {
        Self {
            public_id: receipt.public_id,
            private_id: receipt.private_id,
            retired_private_id: receipt.retired_private_id,
            retired_event_id: receipt.retired_event_id,
            retired_event_revision: receipt.retired_event_revision,
            sequence: receipt.sequence,
            base_revision: receipt.base_revision,
            plan_digest: receipt.plan_digest,
            proof_digest: receipt.proof_digest,
            wire_digest: receipt.wire_digest,
            state: receipt.state,
            replayed: receipt.replayed,
        }
    }
}

/// One real gateway admission: fresh carries the canonical plan only after the
/// outer transaction acknowledged `COMMIT`; replay carries no plan, identity or
/// sequence.
pub(crate) enum Admission {
    Fresh { plan: PackCommitPlan, receipt: ReceiptView },
    Replayed(ReceiptView),
}

/// Write the exact decoded Smart-HTTP body the producer would have spooled:
/// one command pkt-line, a flush, then the captured pack bytes. No hashing or
/// provider IO happens here.
pub(crate) fn write_producer_body(
    body: &Path,
    pack: &Path,
    format: GitObjectFormat,
    ref_name: &str,
    old: Option<&str>,
    new: &str,
    atomic: bool,
) -> Result<()> {
    let old = old.map(str::to_owned).unwrap_or_else(|| "0".repeat(format.oid_hex_len()));
    let object_format = format!("object-format={}", format.as_str());
    let capabilities =
        if atomic { format!("report-status atomic {object_format}") } else { format!("report-status {object_format}") };
    let command = format!("{old} {new} {ref_name}\0{capabilities}\n");
    let mut bytes = Vec::with_capacity(command.len() + 4 + 4 + std::fs::metadata(pack)?.len() as usize);
    bytes.extend_from_slice(format!("{:04x}", command.len() + 4).as_bytes());
    bytes.extend_from_slice(command.as_bytes());
    bytes.extend_from_slice(b"0000");
    bytes.extend_from_slice(&std::fs::read(pack).with_context(|| "fixture producer body pack unreadable")?);
    std::fs::write(body, bytes).with_context(|| "fixture producer body write failed")?;
    Ok(())
}

/// Derive the producer request digest from the same exact body. This delegates
/// to the route's bounded parser and digest assembly; no independent command,
/// mode or digest vocabulary is introduced.
pub(crate) async fn producer_request_digest(
    repository_id: Uuid,
    operation: Uuid,
    format: GitObjectFormat,
    body: &Path,
    deadline: Instant,
) -> Result<RequestDigest, GatewayError> {
    receive::producer_request_digest(repository_id, operation, format, body, deadline).await
}

/// Stage the actual pack/idx bytes and call the real private handoff constructor
/// and rotation over the caller's already-authorized serving realm, evidence and
/// retirement. The caller supplies the current baseline; no capture, retry,
/// staging upload or authorized commit is hidden here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn rotate_direct(
    state: &BlobGitState,
    serving: &ServingRepository,
    actor: &Identity,
    public_id: Uuid,
    body: &Path,
    pack: &Path,
    idx: &Path,
    baseline: &crate::ref_store::core::pack_commit::PackCommitBaseline,
    evidence: &PublicAttemptEvidence,
    retirement: &PublicAttemptRetirement,
    deadline: Instant,
) -> Result<Admission, GatewayError> {
    let pair = Pair::stage(pack.to_path_buf(), idx.to_path_buf(), public_id).await?;
    let verified =
        receive::verified_receive_from_test_wire(actor, public_id, serving, body, vec![pair], deadline).await?;
    let backend_identity = state.store().backend_identity().as_hex().to_owned();
    let handoff =
        SlotOneReceive::from_verified_slot_zero(serving, &verified, baseline, backend_identity, evidence, retirement)?;
    let admission = rotate_slot_one(state, serving, &handoff, baseline, deadline).await?;
    Ok(match admission {
        SlotOneAdmission::Fresh { plan, receipt } => {
            Admission::Fresh { plan: *plan, receipt: ReceiptView::from(receipt) }
        }
        SlotOneAdmission::Replayed(receipt) => Admission::Replayed(ReceiptView::from(receipt)),
    })
}

/// Fixed, redacted mapping for test diagnostics; never includes a private UUID
/// or provider/SQL text.
pub(crate) fn refusal(error: GatewayError) -> anyhow::Error {
    anyhow!("private slot-one gateway refused: {}", error.message())
}
