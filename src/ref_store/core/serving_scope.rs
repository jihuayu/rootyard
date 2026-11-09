//! One strict, shared repository-authority predicate for the isolated core.
//!
//! Every fresh core mutation, read/pin, root/decision and pack-proof path must
//! classify the repository row through *this* module instead of comparing
//! `state`/`storage_backend` strings of its own. Two lanes exist and nothing
//! else is authority:
//!
//! * [`CoreLane::LegacyUnservedGitfs`] — the existing isolated fixture lane: an
//!   explicitly **unserved** `provisioning`/`gitfs`/`stable` repository with no
//!   Pando authority and no legacy ref projection. It stays strict; this lane
//!   never becomes a serving cutover.
//! * [`CoreLane::PgRefStore`] — the durable `pg_refstore` serving authority: a
//!   `ready`/`pg_refstore`/`stable` repository whose single migration-145
//!   serving binding is itself `ready` and whose realm (owner, object format,
//!   history incarnation, authority/group epochs) is exactly the locked core
//!   gate realm. The binding also names the digest of the **actually opened**
//!   Blob backend; [`LockedScope::require_serving`] additionally compares that
//!   stored digest with the identity of the live store, so a forged backend
//!   string or a stored hex value is never authority.
//!
//! A plain `repositories.state = 'ready'` row, a trusted `storage_backend`
//! string, an "ordinary" `repository_ref_projection` row or a Pando state row
//! are *not* authority. A ready `gitfs`/Pando repository is always refused for
//! fresh core mutations. The predicate reads the repository row under a shared
//! row lock first and the serving binding row second, so it keeps the frozen
//! lock order (repository -> binding -> gate) and cannot race a provisioning or
//! transition writer that needs the exclusive repository row.
//!
//! Migration 145 absent: the binding table cannot exist, so every legacy check
//! keeps its previous strict behaviour and no `pg_refstore` lane is admitted.
use super::contract::CoreGate;
use super::types::GitObjectFormat;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::pg;
use tokio_postgres::{Transaction, error::SqlState};
use uuid::Uuid;

pub(crate) const LEGACY_GITFS_BACKEND: &str = "gitfs";
pub(crate) const PG_REFSTORE_BACKEND: &str = "pg_refstore";
pub(crate) const UNSERVED_STATE: &str = "provisioning";
pub(crate) const READY_STATE: &str = "ready";
pub(crate) const STABLE_TRANSITION: &str = "stable";
/// Migration-145 durable serving binding/intent table.
pub(crate) const SERVING_BINDING_TABLE: &str = "ref_store_serving_repositories";
/// Exact legacy unavailable-state reason kept byte-for-byte for existing
/// fixtures that assert on it.
const UNSERVED_GITFS_REASON: &str = "repository is no longer an explicitly unserved stable gitfs core repository";
const LEGACY_AUTHORITY_REASON: &str = "repository has a live legacy Pando authority or legacy ref projection";
const NOT_SERVING_REASON: &str = "repository is not a ready stable pg_refstore serving authority";

/// Which durable core realm (never a serving decision) a caller observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreLane {
    LegacyUnservedGitfs,
    PgRefStore,
}

impl CoreLane {
    pub(crate) fn is_serving(self) -> bool {
        matches!(self, Self::PgRefStore)
    }
}

/// The exact durable realm a scope expects. Built from the locked gate or from
/// the caller's already validated plan/request; every field must match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreRealm {
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl CoreRealm {
    pub(crate) fn new(
        tenant_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Self {
        Self { tenant_id, object_format, history_incarnation, authority_epoch, group_epoch }
    }

    pub(crate) fn from_gate(gate: &CoreGate) -> Self {
        Self::new(
            gate.tenant_id(),
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )
    }

    pub(crate) fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub(crate) fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub(crate) fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub(crate) fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub(crate) fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
}

/// Which realm field differed, so each caller can keep its own typed error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RealmField {
    ObjectFormat,
    HistoryIncarnation,
    AuthorityEpoch,
    GroupEpoch,
}

/// Typed refusal of the shared predicate. Callers map this to their own error
/// type; no caller may widen it into "ready is enough".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScopeRefusal {
    /// The repository row exists but belongs to another owner namespace.
    Tenant,
    /// The durable realm differs on exactly this field.
    Realm(RealmField),
    /// A live legacy Pando authority or legacy ref projection exists.
    LegacyAuthority,
    /// Not the strict unserved `provisioning`/`gitfs`/`stable` fixture lane.
    NotUnservedGitfs,
    /// Not the ready `pg_refstore`/`stable` serving lane.
    NotServing,
    /// `pg_refstore` without the durable binding row.
    MissingBinding,
    /// The durable binding exists but is still `pending`.
    BindingNotReady,
    /// The stored physical backend digest is not the live store.
    BackendIdentity,
    /// The durable rows disagree with each other (database corruption).
    Inconsistent(&'static str),
}

impl ScopeRefusal {
    /// A fixed, non-secret reason for the caller's typed refusal.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Tenant => "repository belongs to another owner namespace",
            Self::Realm(RealmField::ObjectFormat) => "repository object format differs from the expected realm",
            Self::Realm(RealmField::HistoryIncarnation) => {
                "repository history incarnation differs from the expected realm"
            }
            Self::Realm(RealmField::AuthorityEpoch) => "repository authority epoch differs from the expected realm",
            Self::Realm(RealmField::GroupEpoch) => "repository group epoch differs from the expected realm",
            Self::LegacyAuthority => LEGACY_AUTHORITY_REASON,
            Self::NotUnservedGitfs => UNSERVED_GITFS_REASON,
            Self::NotServing => NOT_SERVING_REASON,
            Self::MissingBinding => "pg_refstore repository has no durable serving binding",
            Self::BindingNotReady => "pg_refstore serving binding is not ready",
            Self::BackendIdentity => "serving binding names a different Blob backend than the live store",
            Self::Inconsistent(reason) => reason,
        }
    }
}

/// The durable migration-145 serving binding of one repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServingBinding {
    repository_id: Uuid,
    owner_id: Uuid,
    name: String,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    backend_identity: String,
    ready: bool,
}

impl ServingBinding {
    fn from_row(repository_id: Uuid, row: &tokio_postgres::Row) -> Result<Self, RefStoreError> {
        let owner_id: Uuid = row.get(0);
        let name: String = row.get(1);
        let object_format: String = row.get(2);
        let history_incarnation: Uuid = row.get(3);
        let authority_epoch: i64 = row.get(4);
        let group_epoch: i64 = row.get(5);
        let backend_identity: String = row.get(6);
        let state: String = row.get(7);
        if repository_id.is_nil() || owner_id.is_nil() || history_incarnation.is_nil() {
            return Err(RefStoreError::Database("serving binding has a nil identity".into()));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RefStoreError::Database("serving binding epochs are out of range".into()));
        }
        let ready = match state.as_str() {
            "ready" => true,
            "pending" => false,
            other => {
                return Err(RefStoreError::Database(format!("unknown serving binding state {other:?}")));
            }
        };
        Ok(Self {
            repository_id,
            owner_id,
            name,
            object_format: GitObjectFormat::parse(&object_format)?,
            history_incarnation,
            authority_epoch,
            group_epoch,
            backend_identity,
            ready,
        })
    }

    pub(crate) fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub(crate) fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub(crate) fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub(crate) fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub(crate) fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
    /// Digest of the actually opened Blob backend; never a credential.
    pub(crate) fn backend_identity(&self) -> &str {
        &self.backend_identity
    }
    pub(crate) fn ready(&self) -> bool {
        self.ready
    }

    fn realm_matches(&self, realm: &CoreRealm) -> Result<(), ScopeRefusal> {
        if self.owner_id != realm.tenant_id() {
            return Err(ScopeRefusal::Tenant);
        }
        if self.object_format != realm.object_format() {
            return Err(ScopeRefusal::Realm(RealmField::ObjectFormat));
        }
        if self.history_incarnation != realm.history_incarnation() {
            return Err(ScopeRefusal::Realm(RealmField::HistoryIncarnation));
        }
        if self.authority_epoch != realm.authority_epoch() {
            return Err(ScopeRefusal::Realm(RealmField::AuthorityEpoch));
        }
        if self.group_epoch != realm.group_epoch() {
            return Err(ScopeRefusal::Realm(RealmField::GroupEpoch));
        }
        Ok(())
    }

    /// The durable binding must name exactly this repository row: id, owner
    /// namespace, repository name and object format. A binding copied onto a
    /// differently named/formatted row is a durable inconsistency.
    fn repository_matches(
        &self,
        repository_id: Uuid,
        owner_id: Uuid,
        name: &str,
        object_format: GitObjectFormat,
    ) -> Result<(), ScopeRefusal> {
        if self.repository_id != repository_id || self.owner_id != owner_id || self.name != name {
            return Err(ScopeRefusal::Inconsistent("serving binding names another repository"));
        }
        if self.object_format != object_format {
            return Err(ScopeRefusal::Inconsistent("serving binding object format differs from the repository"));
        }
        Ok(())
    }

    /// Exact realm of one already locked core gate. The binding is durable
    /// authority, so a disagreement is a database inconsistency (never a
    /// request-level rejection).
    fn gate_matches(&self, gate: &CoreGate) -> Result<(), ScopeRefusal> {
        if self.repository_id != gate.repository_id() {
            return Err(ScopeRefusal::Inconsistent("serving binding names another repository"));
        }
        self.realm_matches(&CoreRealm::from_gate(gate))
            .map_err(|_| ScopeRefusal::Inconsistent("serving binding realm differs from the locked core gate"))
    }
}

/// One repository row locked `FOR SHARE` (or `FOR UPDATE` during provisioning)
/// plus its optional durable serving binding, read in the frozen lock order.
pub(crate) struct LockedScope {
    repository_id: Uuid,
    owner_id: Uuid,
    name: String,
    object_format: GitObjectFormat,
    state: String,
    storage_backend: String,
    transition_state: String,
    storage_generation: i64,
    pando_authority: bool,
    legacy_refs: bool,
    binding: Option<ServingBinding>,
}

impl LockedScope {
    /// Lock and classify one repository. `None` is a missing repository row
    /// (callers keep their existing not-found behaviour).
    pub(crate) async fn lock(
        tx: &Transaction<'_>,
        repository_id: Uuid,
        for_update: bool,
    ) -> Result<Option<Self>, RefStoreError> {
        let query = format!(
            "SELECT r.owner_id,r.name,r.object_format,r.state,r.storage_backend,r.transition_state,
                    r.storage_generation,
                    EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id),
                    EXISTS(SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id)
             FROM repositories r WHERE r.id=$1{}",
            if for_update { " FOR UPDATE" } else { " FOR SHARE" }
        );
        let row = tx.query_opt(&query, &[&repository_id]).await.map_err(pg::db_error)?;
        let Some(row) = row else { return Ok(None) };
        let name: String = row.get(1);
        let object_format: String = row.get(2);
        let binding = binding_row(tx, repository_id, for_update).await?;
        Ok(Some(Self {
            repository_id,
            owner_id: row.get(0),
            name,
            object_format: GitObjectFormat::parse(&object_format)?,
            state: row.get(3),
            storage_backend: row.get(4),
            transition_state: row.get(5),
            storage_generation: row.get(6),
            pando_authority: row.get(7),
            legacy_refs: row.get(8),
            binding,
        }))
    }

    pub(crate) fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub(crate) fn state(&self) -> &str {
        &self.state
    }
    pub(crate) fn storage_backend(&self) -> &str {
        &self.storage_backend
    }
    pub(crate) fn transition_state(&self) -> &str {
        &self.transition_state
    }
    pub(crate) fn storage_generation(&self) -> i64 {
        self.storage_generation
    }
    pub(crate) fn pando_authority(&self) -> bool {
        self.pando_authority
    }
    pub(crate) fn legacy_refs(&self) -> bool {
        self.legacy_refs
    }
    pub(crate) fn binding(&self) -> Option<&ServingBinding> {
        self.binding.as_ref()
    }

    /// Lane + tenant check only. Used where a caller must keep its existing
    /// typed *rejection* for a differing object format/epoch instead of an
    /// infrastructure error (the exact CAS commit path).
    pub(crate) fn require_fresh_core_lane(&self, tenant_id: Uuid) -> Result<CoreLane, ScopeRefusal> {
        if self.owner_id != tenant_id {
            return Err(ScopeRefusal::Tenant);
        }
        if self.pando_authority || self.legacy_refs {
            return Err(ScopeRefusal::LegacyAuthority);
        }
        match self.storage_backend.as_str() {
            LEGACY_GITFS_BACKEND => {
                if self.state != UNSERVED_STATE || self.transition_state != STABLE_TRANSITION {
                    return Err(ScopeRefusal::NotUnservedGitfs);
                }
                if self.binding.is_some() {
                    return Err(ScopeRefusal::Inconsistent("a gitfs repository carries a pg_refstore serving binding"));
                }
                Ok(CoreLane::LegacyUnservedGitfs)
            }
            PG_REFSTORE_BACKEND => {
                let binding = self.binding.as_ref().ok_or(ScopeRefusal::MissingBinding)?;
                if !binding.ready() {
                    return Err(ScopeRefusal::BindingNotReady);
                }
                if self.state != READY_STATE || self.transition_state != STABLE_TRANSITION {
                    return Err(ScopeRefusal::NotServing);
                }
                binding.repository_matches(self.repository_id, self.owner_id, &self.name, self.object_format)?;
                Ok(CoreLane::PgRefStore)
            }
            _ => Err(ScopeRefusal::NotServing),
        }
    }

    /// Full fresh-core predicate over an expected realm.
    ///
    /// The legacy lane keeps its historical shape: the repository is only
    /// required to be an unserved `provisioning`/`gitfs`/`stable` row with the
    /// expected owner and format; the gate comparison that follows supplies the
    /// history/epoch proof. The `pg_refstore` lane additionally requires the
    /// durable binding to match the expected realm exactly, so a stale or
    /// foreign realm can never ride on a ready row.
    pub(crate) fn require_fresh_core(&self, realm: &CoreRealm) -> Result<CoreLane, ScopeRefusal> {
        let lane = self.require_fresh_core_lane(realm.tenant_id())?;
        if self.object_format != realm.object_format() {
            return Err(ScopeRefusal::Realm(RealmField::ObjectFormat));
        }
        if lane.is_serving() {
            let binding = self.binding.as_ref().ok_or(ScopeRefusal::MissingBinding)?;
            binding.realm_matches(realm)?;
        }
        Ok(lane)
    }

    /// Lane for creating/replaying the core gate + protocol realm.
    ///
    /// A brand-new `pg_refstore` intent is still `provisioning` with a
    /// `pending` binding, and a retry may already be `ready`; both must match
    /// the exact expectation realm. Any other combination is refused, so a
    /// caller cannot bypass the binding to bootstrap a second authority.
    pub(crate) fn require_bootstrap(&self, realm: &CoreRealm) -> Result<CoreLane, ScopeRefusal> {
        if self.owner_id != realm.tenant_id() {
            return Err(ScopeRefusal::Tenant);
        }
        if self.pando_authority || self.legacy_refs {
            return Err(ScopeRefusal::LegacyAuthority);
        }
        if self.transition_state != STABLE_TRANSITION {
            return Err(ScopeRefusal::NotUnservedGitfs);
        }
        match self.storage_backend.as_str() {
            LEGACY_GITFS_BACKEND => {
                if self.state != UNSERVED_STATE {
                    return Err(ScopeRefusal::NotUnservedGitfs);
                }
                if self.binding.is_some() {
                    return Err(ScopeRefusal::Inconsistent("a gitfs repository carries a pg_refstore serving binding"));
                }
                if self.object_format != realm.object_format() {
                    return Err(ScopeRefusal::Realm(RealmField::ObjectFormat));
                }
                Ok(CoreLane::LegacyUnservedGitfs)
            }
            PG_REFSTORE_BACKEND => {
                if self.state != UNSERVED_STATE && self.state != READY_STATE {
                    return Err(ScopeRefusal::NotServing);
                }
                let binding = self.binding.as_ref().ok_or(ScopeRefusal::MissingBinding)?;
                binding.repository_matches(self.repository_id, self.owner_id, &self.name, self.object_format)?;
                binding.realm_matches(realm)?;
                Ok(CoreLane::PgRefStore)
            }
            _ => Err(ScopeRefusal::NotServing),
        }
    }

    /// Durable binding must be exactly the locked gate realm.
    pub(crate) fn require_binding_matches_gate(&self, gate: &CoreGate) -> Result<CoreLane, ScopeRefusal> {
        match self.storage_backend.as_str() {
            LEGACY_GITFS_BACKEND => {
                if self.binding.is_some() {
                    return Err(ScopeRefusal::Inconsistent("a gitfs repository carries a pg_refstore serving binding"));
                }
                Ok(CoreLane::LegacyUnservedGitfs)
            }
            PG_REFSTORE_BACKEND => {
                let binding = self.binding.as_ref().ok_or(ScopeRefusal::MissingBinding)?;
                if !binding.ready() {
                    return Err(ScopeRefusal::BindingNotReady);
                }
                binding.repository_matches(self.repository_id, self.owner_id, &self.name, self.object_format)?;
                binding.gate_matches(gate)?;
                Ok(CoreLane::PgRefStore)
            }
            _ => Err(ScopeRefusal::NotServing),
        }
    }

    /// Active serving lane for the engine lookup: ready `pg_refstore`
    /// repository + ready durable binding of the same owner and format + the
    /// digest of the **actually opened** Blob backend. A bare ready row, a
    /// forged backend string or a stored hex value alone is never enough.
    pub(crate) fn require_serving(
        &self,
        tenant_id: Uuid,
        backend_identity_hex: &str,
    ) -> Result<&ServingBinding, ScopeRefusal> {
        if self.owner_id != tenant_id {
            return Err(ScopeRefusal::Tenant);
        }
        if self.pando_authority || self.legacy_refs {
            return Err(ScopeRefusal::LegacyAuthority);
        }
        if self.storage_backend != PG_REFSTORE_BACKEND {
            return Err(ScopeRefusal::NotServing);
        }
        if self.state != READY_STATE || self.transition_state != STABLE_TRANSITION {
            return Err(ScopeRefusal::NotServing);
        }
        let binding = self.binding.as_ref().ok_or(ScopeRefusal::MissingBinding)?;
        if !binding.ready() {
            return Err(ScopeRefusal::BindingNotReady);
        }
        binding.repository_matches(self.repository_id, self.owner_id, &self.name, self.object_format)?;
        if binding.backend_identity() != backend_identity_hex {
            return Err(ScopeRefusal::BackendIdentity);
        }
        Ok(binding)
    }
}

/// Read the durable serving binding `FOR SHARE` (`FOR UPDATE` when the caller
/// provisions). A missing migration-145 table means no binding can exist, so
/// the legacy strict lanes keep working on an older schema while the
/// `pg_refstore` lane stays impossible/fail-closed.
async fn binding_row(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    for_update: bool,
) -> Result<Option<ServingBinding>, RefStoreError> {
    let query = format!(
        "SELECT owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,state
         FROM {SERVING_BINDING_TABLE} WHERE repository_id=$1{}",
        if for_update { " FOR UPDATE" } else { " FOR SHARE" }
    );
    match tx.query_opt(&query, &[&repository_id]).await {
        Ok(row) => row.as_ref().map(|row| ServingBinding::from_row(repository_id, row)).transpose(),
        Err(error) if error.code() == Some(&SqlState::UNDEFINED_TABLE) => Ok(None),
        Err(error) => Err(pg::db_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> CoreRealm {
        CoreRealm::new(Uuid::from_bytes([2; 16]), GitObjectFormat::Sha1, Uuid::from_bytes([3; 16]), 1, 1)
    }

    fn binding() -> ServingBinding {
        ServingBinding {
            repository_id: Uuid::from_bytes([1; 16]),
            owner_id: Uuid::from_bytes([2; 16]),
            name: "demo".to_owned(),
            object_format: GitObjectFormat::Sha1,
            history_incarnation: Uuid::from_bytes([3; 16]),
            authority_epoch: 1,
            group_epoch: 1,
            backend_identity: "a".repeat(64),
            ready: true,
        }
    }

    fn scope(backend: &str, state: &str, binding: Option<ServingBinding>) -> LockedScope {
        LockedScope {
            repository_id: Uuid::from_bytes([1; 16]),
            owner_id: Uuid::from_bytes([2; 16]),
            name: "demo".to_owned(),
            object_format: GitObjectFormat::Sha1,
            state: state.to_owned(),
            storage_backend: backend.to_owned(),
            transition_state: STABLE_TRANSITION.to_owned(),
            storage_generation: 1,
            pando_authority: false,
            legacy_refs: false,
            binding,
        }
    }

    #[test]
    fn ready_gitfs_is_never_a_core_authority() {
        let ready = scope(LEGACY_GITFS_BACKEND, READY_STATE, None);
        assert_eq!(ready.require_fresh_core(&realm()), Err(ScopeRefusal::NotUnservedGitfs));
        assert_eq!(ready.require_bootstrap(&realm()), Err(ScopeRefusal::NotUnservedGitfs));
        assert_eq!(ready.require_serving(Uuid::from_bytes([2; 16]), &"a".repeat(64)), Err(ScopeRefusal::NotServing));
        let unserved = scope(LEGACY_GITFS_BACKEND, UNSERVED_STATE, None);
        assert_eq!(unserved.require_fresh_core(&realm()), Ok(CoreLane::LegacyUnservedGitfs));
        assert_eq!(unserved.require_serving(Uuid::from_bytes([2; 16]), &"a".repeat(64)), Err(ScopeRefusal::NotServing));
        assert_eq!(ScopeRefusal::NotUnservedGitfs.reason(), UNSERVED_GITFS_REASON);
    }

    #[test]
    fn pg_refstore_requires_a_matching_ready_binding_and_live_backend() {
        let tenant = Uuid::from_bytes([2; 16]);
        let missing = scope(PG_REFSTORE_BACKEND, READY_STATE, None);
        assert_eq!(missing.require_fresh_core(&realm()), Err(ScopeRefusal::MissingBinding));
        assert_eq!(missing.require_serving(tenant, &"a".repeat(64)), Err(ScopeRefusal::MissingBinding));
        let pending = scope(PG_REFSTORE_BACKEND, UNSERVED_STATE, Some(ServingBinding { ready: false, ..binding() }));
        assert_eq!(pending.require_fresh_core(&realm()), Err(ScopeRefusal::BindingNotReady));
        assert_eq!(pending.require_bootstrap(&realm()), Ok(CoreLane::PgRefStore));
        let ready = scope(PG_REFSTORE_BACKEND, READY_STATE, Some(binding()));
        assert_eq!(ready.require_fresh_core(&realm()), Ok(CoreLane::PgRefStore));
        assert_eq!(ready.require_serving(tenant, &"a".repeat(64)).map(|found| found.ready()), Ok(true));
        assert_eq!(ready.require_serving(tenant, &"b".repeat(64)).err(), Some(ScopeRefusal::BackendIdentity));
        assert_eq!(ready.require_serving(Uuid::from_bytes([9; 16]), &"a".repeat(64)).err(), Some(ScopeRefusal::Tenant));
        let wrong_history = scope(
            PG_REFSTORE_BACKEND,
            READY_STATE,
            Some(ServingBinding { history_incarnation: Uuid::from_bytes([4; 16]), ..binding() }),
        );
        assert_eq!(
            wrong_history.require_fresh_core(&realm()),
            Err(ScopeRefusal::Realm(RealmField::HistoryIncarnation))
        );
    }

    #[test]
    fn legacy_and_pando_authority_is_refused_in_both_lanes() {
        let legacy = scope(LEGACY_GITFS_BACKEND, UNSERVED_STATE, None);
        assert_eq!(legacy.require_fresh_core_lane(Uuid::from_bytes([9; 16])), Err(ScopeRefusal::Tenant));
        let mut pando = scope(LEGACY_GITFS_BACKEND, UNSERVED_STATE, None);
        pando.storage_backend = "pando".to_owned();
        pando.pando_authority = true;
        assert_eq!(pando.require_fresh_core(&realm()), Err(ScopeRefusal::LegacyAuthority));
        let mut projection = scope(LEGACY_GITFS_BACKEND, UNSERVED_STATE, None);
        projection.legacy_refs = true;
        assert_eq!(projection.require_bootstrap(&realm()), Err(ScopeRefusal::LegacyAuthority));
        let gitfs_binding = scope(LEGACY_GITFS_BACKEND, UNSERVED_STATE, Some(binding()));
        assert_eq!(
            gitfs_binding.require_fresh_core(&realm()),
            Err(ScopeRefusal::Inconsistent("a gitfs repository carries a pg_refstore serving binding"))
        );
    }
}
