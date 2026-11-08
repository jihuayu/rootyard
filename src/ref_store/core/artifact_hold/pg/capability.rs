//! Private minting surface of the upload capability (A3).
//!
//! [`ArtifactGrant`] and [`ConsumedArtifacts`] are *defined* here, inside the
//! private `pg::capability` module, and only re-exported read-only. Their
//! constructors are `pub(super)`, i.e. visible only inside `artifact_hold::pg`
//! (the owned PostgreSQL adapter) and its descendants - no sibling module of
//! `artifact_hold` can mint them any more, and no `pub(crate)` factory exists.
//!
//! Properties that keep this a capability rather than a receipt:
//!
//! * no `Clone`, `Serialize` or `Deserialize` implementation;
//! * the fields are private and the grant body is boxed and private, so the
//!   public type is a small handle over data no other module can name;
//! * the intents are owned by value and handed to the sealed raw writer only
//!   through [`ConsumedArtifacts::into_uploads`] (`pub(crate)`), which exists
//!   only after a positive consume `COMMIT` acknowledgement;
//! * a replay/unknown acquire returns an immutable ACK, never a grant.
//!
//! `Debug` prints the acquire/consume request ids and the artifact count only.
//! It never prints an intent, an attempt path, a locator, a digest or a backend
//! hex.
use crate::blob_store::UploadIntent;
use crate::ref_store::contract::OperationIdentity;
use crate::ref_store::core::artifact_hold::contract::{ArtifactHoldError, HoldScope, MAX_BATCH_ARTIFACTS};
use crate::ref_store::core::artifact_hold::receipt::{AcquireAck, ConsumeAck, HoldArtifactIdentity};
use std::fmt;
use uuid::Uuid;

/// One granted artifact: the durable hold and the single-use write intent.
pub(super) struct GrantedUpload {
    pub(super) hold_id: Uuid,
    pub(super) slot: i32,
    pub(super) intent: UploadIntent,
}

impl GrantedUpload {
    pub(super) fn new(hold_id: Uuid, slot: i32, intent: UploadIntent) -> Self {
        Self { hold_id, slot, intent }
    }
}

/// The private grant body. Boxing it keeps [`ArtifactGrant`] a pointer-sized
/// handle, so an [`AcquireOutcome`](super::AcquireOutcome) does not carry an
/// 800-byte variant.
struct GrantBody {
    scope: HoldScope,
    operation: OperationIdentity,
    ack: AcquireAck,
    uploads: Vec<GrantedUpload>,
}

/// Opaque upload authority over 1..=16 freshly acquired holds.
///
/// No public function hands out an [`UploadIntent`]; the only way to use the
/// intents is [`super::PgArtifactHoldStore::consume`], which first records the
/// durable one-shot consume receipt.
///
/// ```compile_fail
/// use rootyard::ref_store::artifact_hold::ArtifactGrant;
/// // `Clone` is deliberately not implemented for the upload capability.
/// let _clone: fn(&ArtifactGrant) -> ArtifactGrant = Clone::clone;
/// ```
///
/// ```compile_fail
/// use rootyard::ref_store::artifact_hold::ArtifactGrant;
/// // The mint is `pub(super)`: it is not nameable outside the adapter.
/// let _forge = ArtifactGrant::new;
/// ```
pub struct ArtifactGrant {
    body: Box<GrantBody>,
}

impl ArtifactGrant {
    /// Mint point, reachable only inside `artifact_hold::pg`.
    pub(super) fn new(
        scope: HoldScope,
        operation: OperationIdentity,
        ack: AcquireAck,
        uploads: Vec<GrantedUpload>,
    ) -> Self {
        Self { body: Box::new(GrantBody { scope, operation, ack, uploads }) }
    }

    pub fn request_id(&self) -> Uuid {
        self.body.ack.request_id
    }

    /// Stable consume id, allocated by the acquire itself. It can be read
    /// *before* the grant is moved into
    /// [`consume`](super::PgArtifactHoldStore::consume), so an unknown consume
    /// `COMMIT` is resolvable without inventing a new id.
    pub fn consume_request_id(&self) -> Uuid {
        self.body.ack.consume_request_id
    }

    /// Receipt-only view: ids and physical identity, never a write capability.
    pub fn ack(&self) -> &AcquireAck {
        &self.body.ack
    }

    pub fn artifact_count(&self) -> usize {
        self.body.uploads.len()
    }

    /// Consume-side hand-over. It first proves, entirely in memory, that the
    /// grant's intents, its immutable ACK, the trusted scope and the full parent
    /// operation tuple agree, and only then yields the parts. The caller still
    /// verifies the live 138 pending/cancel state and every locked hold row
    /// before any receipt is written.
    pub(super) fn into_checked_parts(
        self,
    ) -> Result<(HoldScope, OperationIdentity, AcquireAck, Vec<GrantedUpload>), ArtifactHoldError> {
        let GrantBody { scope, operation, ack, uploads } = *self.body;
        ack.ensure_batch_shape()?;
        ack.ensure_scope(&scope)?;
        ensure_parent_binding(&ack, &operation)?;
        if uploads.is_empty() || uploads.len() > MAX_BATCH_ARTIFACTS || uploads.len() != ack.artifacts.len() {
            return Err(ArtifactHoldError::LedgerIntegrity("grant batch shape differs from its immutable ACK"));
        }
        for (index, upload) in uploads.iter().enumerate() {
            let hold = &ack.artifacts[index];
            if upload.hold_id != hold.hold_id || upload.slot != hold.slot {
                return Err(ArtifactHoldError::HoldIdentityMismatch { hold_id: upload.hold_id });
            }
            if upload.intent.backend_identity().as_hex() != ack.backend_identity {
                return Err(ArtifactHoldError::BackendMismatch);
            }
            let derived = HoldArtifactIdentity::from_intent(hold.artifact.provider.as_str(), &upload.intent);
            if derived != hold.artifact {
                return Err(ArtifactHoldError::HoldIdentityMismatch { hold_id: upload.hold_id });
            }
        }
        Ok((scope, operation, ack, uploads))
    }
}

/// The immutable ACK must name exactly the parent operation tuple the grant
/// carries (`repo, tenant, issuer, lane, sequence, op id, digest`). This runs
/// before the adapter locks or qualifies any 138 pending row, so a different
/// pending operation can never qualify this grant.
fn ensure_parent_binding(ack: &AcquireAck, operation: &OperationIdentity) -> Result<(), ArtifactHoldError> {
    if ack.repository_id != operation.repository_id()
        || ack.issuer_id != operation.issuer_id()
        || ack.lane != operation.lane().as_str()
        || ack.sequence != operation.sequence()
        || ack.operation_id != operation.operation_id()
        || ack.operation_digest != operation.digest().as_hex()
    {
        return Err(ArtifactHoldError::ScopeMismatch("grant parent operation binding"));
    }
    Ok(())
}

impl fmt::Debug for ArtifactGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactGrant")
            .field("request_id", &self.body.ack.request_id)
            .field("consume_request_id", &self.body.ack.consume_request_id)
            .field("artifacts", &self.body.uploads.len())
            .field("upload_intents", &"<opaque, consumed by value>")
            .finish()
    }
}

/// The upload capability handed to the protected uploader after a consume ACK.
pub(crate) struct ConsumedUpload {
    pub(crate) hold_id: Uuid,
    pub(crate) slot: i32,
    pub(crate) intent: UploadIntent,
}

/// Durable one-shot consumption result: the immutable receipts plus the private
/// intents. It is deliberately not `Clone`, not `Debug`-printable in full,
/// serializable or constructible outside this module.
pub struct ConsumedArtifacts {
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
    acks: Vec<ConsumeAck>,
    uploads: Vec<ConsumedUpload>,
}

impl ConsumedArtifacts {
    /// Mint point, reachable only inside `artifact_hold::pg` after a positive
    /// consume `COMMIT` acknowledgement. Both ids are passed *directly* from the
    /// durable acquire ACK and its stable consume id; neither is derived from a
    /// Blob receipt nor accepted from a caller.
    pub(super) fn new(
        acquire_request_id: Uuid,
        consume_request_id: Uuid,
        acks: Vec<ConsumeAck>,
        uploads: Vec<ConsumedUpload>,
    ) -> Self {
        Self { acquire_request_id, consume_request_id, acks, uploads }
    }

    /// Stable, non-secret acquire UUID of the durable A3 acquire row that
    /// minted this consumption. Exposed so a later pack registration can bind
    /// the durable A3 rows directly.
    pub fn acquire_request_id(&self) -> Uuid {
        self.acquire_request_id
    }

    pub fn consume_request_id(&self) -> Uuid {
        self.consume_request_id
    }

    /// Immutable receipt-only view of this consumption.
    pub fn receipts(&self) -> &[ConsumeAck] {
        &self.acks
    }

    pub fn artifact_count(&self) -> usize {
        self.uploads.len()
    }

    /// One-shot hand-over to the protected uploader. The returned vector is
    /// ordered by stable slot; each element carries the opaque intent and the
    /// durable hold id. This is the only in-crate way to reach the intents, and
    /// the value exists only after a positive consume ACK.
    pub(crate) fn into_uploads(self) -> Vec<ConsumedUpload> {
        self.uploads
    }
}

impl fmt::Debug for ConsumedArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedArtifacts")
            .field("acquire_request_id", &self.acquire_request_id)
            .field("consume_request_id", &self.consume_request_id)
            .field("receipts", &self.acks.len())
            .field("artifacts", &self.uploads.len())
            .field("upload_intents", &"<opaque, consumed by value>")
            .finish()
    }
}
