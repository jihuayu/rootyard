//! The exact signed realm of one repository session token (#174).
//!
//! Every field is read from PostgreSQL during the request (or copied out of the
//! sealed serving proof) and re-validated by [`SessionRealm::new`]. Nothing here
//! comes from process start-up state, and the explicit [`AuthorityKind`] and
//! `group_id` make a standalone PostgreSQL RefStore distinguishable from a
//! future Raft Ref-CAS authority even when their epochs and revisions collide.
use uuid::Uuid;

use super::SessionTokenError;
use crate::ref_store::{
    GitObjectFormat,
    core::pack_snapshot::ProvenScope,
    serving::{AuthorityKind, ServingRepository},
};

/// Standalone PostgreSQL RefStore has no Raft group; `0` is the signed
/// "no group" value. A future grouped authority uses a non-zero id.
pub(crate) const STANDALONE_GROUP_ID: u64 = 0;

/// One validated realm value shape. Grouping the fields keeps the constructor
/// small and makes every construction site state the authority family and group
/// identity explicitly.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionRealmFields {
    pub(crate) tenant_id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) object_format: GitObjectFormat,
    pub(crate) history_incarnation: Uuid,
    pub(crate) authority: AuthorityKind,
    pub(crate) authority_epoch: i64,
    pub(crate) group_id: u64,
    pub(crate) group_epoch: i64,
    pub(crate) cluster_incarnation: Uuid,
}

/// The exact realm a token is bound to, as read from PostgreSQL during this
/// request. This type does not implement `Serialize` and has no public
/// constructor outside the crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRealm {
    pub(crate) tenant_id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) object_format: GitObjectFormat,
    pub(crate) history_incarnation: Uuid,
    pub(crate) authority: AuthorityKind,
    pub(crate) authority_epoch: i64,
    pub(crate) group_id: u64,
    pub(crate) group_epoch: i64,
    pub(crate) cluster_incarnation: Uuid,
}

/// Epoch floor/ceiling shared with the codec frame. PostgreSQL stores the
/// epochs as positive `BIGINT`, and the frame carries all 64 signed bits, so the
/// accepted range is exactly `BIGINT > 0` rather than an artificial `i32` cap.
pub(super) const MIN_EPOCH: i64 = 1;
pub(super) const MAX_EPOCH: i64 = i64::MAX;

impl SessionRealm {
    pub(crate) fn new(fields: SessionRealmFields) -> Result<Self, SessionTokenError> {
        if fields.tenant_id.is_nil()
            || fields.repository_id.is_nil()
            || fields.history_incarnation.is_nil()
            || fields.cluster_incarnation.is_nil()
            || !(MIN_EPOCH..=MAX_EPOCH).contains(&fields.authority_epoch)
            || !(MIN_EPOCH..=MAX_EPOCH).contains(&fields.group_epoch)
        {
            return Err(SessionTokenError::Invalid);
        }
        Ok(Self {
            tenant_id: fields.tenant_id,
            repository_id: fields.repository_id,
            object_format: fields.object_format,
            history_incarnation: fields.history_incarnation,
            authority: fields.authority,
            authority_epoch: fields.authority_epoch,
            group_id: fields.group_id,
            group_epoch: fields.group_epoch,
            cluster_incarnation: fields.cluster_incarnation,
        })
    }

    /// The realm a sealed serving proof states. Every field is the proof's own
    /// capture value, re-validated by [`Self::new`]; nothing is caller-chosen.
    /// Shared with the JSON read fence (`super::browse`).
    pub(crate) fn from_proof(scope: &ProvenScope, cluster_incarnation: Uuid) -> Result<Self, SessionTokenError> {
        Self::new(SessionRealmFields {
            tenant_id: scope.tenant_id(),
            repository_id: scope.repository_id(),
            object_format: scope.object_format(),
            history_incarnation: scope.history_incarnation(),
            authority: scope.authority_kind(),
            authority_epoch: scope.authority_epoch(),
            group_id: scope.group_id(),
            group_epoch: scope.group_epoch(),
            cluster_incarnation,
        })
    }

    /// The full realm one real serving lookup states, every field re-validated
    /// by [`Self::new`]. A standalone PostgreSQL authority has group id `0`.
    pub(super) fn from_serving(
        serving: &ServingRepository,
        cluster_incarnation: Uuid,
    ) -> Result<Self, SessionTokenError> {
        let gate = &serving.gate;
        Self::new(SessionRealmFields {
            tenant_id: gate.tenant_id(),
            repository_id: gate.repository_id(),
            object_format: gate.object_format(),
            history_incarnation: gate.history_incarnation(),
            authority: AuthorityKind::PgRefStore,
            authority_epoch: gate.authority_epoch(),
            group_id: STANDALONE_GROUP_ID,
            group_epoch: gate.group_epoch(),
            cluster_incarnation,
        })
    }

    /// Whether a live serving lookup still authorizes exactly this realm. The
    /// cluster incarnation is that lookup's own `NOWAIT` read, never a cache.
    pub(crate) fn matches_serving(&self, serving: &ServingRepository) -> bool {
        let gate = &serving.gate;
        self.tenant_id == gate.tenant_id()
            && self.repository_id == gate.repository_id()
            && self.object_format == gate.object_format()
            && self.history_incarnation == gate.history_incarnation()
            && self.authority == AuthorityKind::PgRefStore
            && self.authority_epoch == gate.authority_epoch()
            && self.group_id == STANDALONE_GROUP_ID
            && self.group_epoch == gate.group_epoch()
            && self.cluster_incarnation == serving.cluster_incarnation
    }
}
