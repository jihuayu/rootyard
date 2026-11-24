//! Narrow gate-owned read adapter for `GET /api/repos/{owner}/{name}/operations/{id}`.
//!
//! The route keeps the existing authenticated read-or-scoped-write-only serving
//! lookup and the fresh lookup/row locks, but deliberately takes no
//! migration-138 operation advisory key on the read-only path. This adapter
//! then distinguishes the durable public wrapper, a private attempt identifier,
//! an unknown identifier and a genuine legacy operation inside the same
//! caller-owned transaction and deadline.
//!
//! A public status is resolved first through the existing GET-only snapshot with
//! the authenticated live issuer marker, so the wrapper, selected attempt, live
//! realm and issuer/admin authorization are still proved before output. Only a
//! data-free issuer mismatch triggers the same current-role lookup as the legacy
//! resolver; a current owner/admin re-resolves with the explicit admin marker in
//! the same transaction. The role query takes the same `FOR SHARE` policy fences
//! as the legacy path, and a revocation blocks behind the transaction. No state
//! from the issuer-mismatch probe is returned.
//!
//! Every legacy fallthrough then reclassifies the exact UUID in one core
//! statement: the public wrapper, private claim and eligible legacy row share one
//! MVCC snapshot. A wholly absent migration 152 keeps the pre-152 legacy read; a
//! partial catalog fails closed. A wrapper that appears between the public probe
//! and the atomic classifier is a change, not a legacy payload.
use deadpool_postgres::Transaction;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    db::Identity,
    members::{models::Role, rbac::resolve_effective_role},
    ref_store::{
        OperationRecord, PgRefStore, RefStoreError,
        core::pack_commit::PackCommitError,
        pg::{
            LegacyStatusLookup,
            public_attempt::{
                PUBLIC_ATTEMPT_SCHEMA_REQUIRED, PublicOperationReadAuthorization, PublicOperationStatus,
                PublicOperationStatusLookup, PublicOperationStatusRequest,
            },
        },
    },
};

use super::error::GatewayError;

const OPERATION_FORBIDDEN: &str = "operation is visible only to its issuer or a current repository admin";
const OPERATION_CHANGED: &str = "operation identity changed during authorization; retry";

/// The two record shapes the public GET route may return. Neither carries a
/// private attempt identity or an unverified payload.
pub(super) enum OperationRead {
    Legacy(OperationRecord),
    Public(PublicOperationStatus),
}

pub(super) async fn resolve(
    tx: &Transaction<'_>,
    identity: &Identity,
    repository_id: Uuid,
    owner_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<OperationRead, GatewayError> {
    let live =
        request(repository_id, operation_id, PublicOperationReadAuthorization::LiveIssuer { issuer_id: identity.id });
    match PgRefStore.lookup_public_operation_status(tx, &live, deadline).await {
        Ok(PublicOperationStatusLookup::Found(status)) => Ok(OperationRead::Public(status)),
        // A private attempt identifier is indistinguishable from an unknown
        // public UUID on this route: both are opaque 404s after the repository
        // authorization above.
        Ok(PublicOperationStatusLookup::Unknown | PublicOperationStatusLookup::PrivateIdentifier) => {
            Err(GatewayError::NotFound)
        }
        Ok(PublicOperationStatusLookup::Forbidden) => {
            resolve_admin(tx, identity, repository_id, owner_id, operation_id, deadline).await
        }
        Ok(PublicOperationStatusLookup::LegacyPath) => {
            resolve_legacy_status(tx, identity, repository_id, owner_id, operation_id, deadline).await
        }
        Err(error) if missing_public_schema(&error) => {
            // The atomic classifier proves a wholly absent migration 152 and
            // preserves the pre-152 legacy read; a partial catalog fails closed.
            resolve_legacy_status(tx, identity, repository_id, owner_id, operation_id, deadline).await
        }
        Err(error) => Err(error.into()),
    }
}

async fn resolve_admin(
    tx: &Transaction<'_>,
    identity: &Identity,
    repository_id: Uuid,
    owner_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<OperationRead, GatewayError> {
    if !is_admin(effective_role(tx, repository_id, owner_id, identity.id, deadline).await?) {
        return Err(GatewayError::Forbidden(OPERATION_FORBIDDEN));
    }
    // The first statement returned only a data-free Forbidden marker. The role
    // rows stay FOR SHARE-locked through this transaction's rollback while the
    // authoritative admin-marked statement resolves the current state, matching
    // the legacy resolver's READ COMMITTED policy-fence behavior.
    let admin = request(repository_id, operation_id, PublicOperationReadAuthorization::RepositoryAdmin);
    match PgRefStore.lookup_public_operation_status(tx, &admin, deadline).await {
        Ok(PublicOperationStatusLookup::Found(status)) => Ok(OperationRead::Public(status)),
        // The issuer-mismatch probe already proved the wrapper existed; any
        // different marker is a durable race/integrity refusal, not a route.
        Ok(PublicOperationStatusLookup::Forbidden) => Err(GatewayError::Forbidden(OPERATION_FORBIDDEN)),
        Ok(
            PublicOperationStatusLookup::Unknown
            | PublicOperationStatusLookup::PrivateIdentifier
            | PublicOperationStatusLookup::LegacyPath,
        ) => Err(GatewayError::Conflict(OPERATION_CHANGED)),
        Err(error) => Err(error.into()),
    }
}

async fn resolve_legacy_status(
    tx: &Transaction<'_>,
    identity: &Identity,
    repository_id: Uuid,
    owner_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<OperationRead, GatewayError> {
    let record = match PgRefStore.get_legacy_status(tx, repository_id, operation_id, deadline).await? {
        LegacyStatusLookup::Legacy(record) => record,
        // The public probe said this UUID was legacy-only; a wrapper appearing
        // in the atomic classifier is a concurrent change, never a legacy row.
        LegacyStatusLookup::PublicWrapper => return Err(GatewayError::Conflict(OPERATION_CHANGED)),
        // Private and unknown identifiers are the same opaque 404. Neither
        // marker carries a private attempt id or terminal payload.
        LegacyStatusLookup::PrivateIdentifier | LegacyStatusLookup::Unknown => {
            return Err(GatewayError::NotFound);
        }
    };
    let role = effective_role(tx, repository_id, owner_id, identity.id, deadline).await?;
    if !operation_visible(record.identity().issuer_id(), identity.id, role) {
        return Err(GatewayError::Forbidden(OPERATION_FORBIDDEN));
    }
    Ok(OperationRead::Legacy(record))
}

async fn effective_role(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    owner_id: Uuid,
    actor_id: Uuid,
    deadline: Instant,
) -> Result<Option<Role>, GatewayError> {
    crate::ref_store::pg::bound(tx, deadline).await.map_err(GatewayError::from)?;
    resolve_effective_role(&**tx, repository_id, owner_id, actor_id)
        .await
        .map(|role| role.map(|(effective, _, _)| effective))
        .map_err(GatewayError::from)
}

fn request(
    repository_id: Uuid,
    public_id: Uuid,
    authorization: PublicOperationReadAuthorization,
) -> PublicOperationStatusRequest {
    PublicOperationStatusRequest { repository_id, public_id, authorization }
}

fn operation_visible(issuer_id: Uuid, actor_id: Uuid, role: Option<Role>) -> bool {
    issuer_id == actor_id || is_admin(role)
}

fn is_admin(role: Option<Role>) -> bool {
    role.is_some_and(|role| role >= Role::Admin)
}

fn missing_public_schema(error: &PackCommitError) -> bool {
    matches!(
        error,
        PackCommitError::RefStore(RefStoreError::Unsupported(reason))
            if *reason == PUBLIC_ATTEMPT_SCHEMA_REQUIRED
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_visibility_is_exact_issuer_or_current_admin() {
        let issuer = Uuid::from_u128(1);
        let actor = Uuid::from_u128(2);
        assert!(operation_visible(issuer, issuer, None));
        assert!(!operation_visible(issuer, actor, Some(Role::Write)));
        assert!(operation_visible(issuer, actor, Some(Role::Admin)));
        assert!(!operation_visible(issuer, actor, None));
    }

    #[test]
    fn only_the_exact_missing_schema_refusal_can_consider_legacy_fallback() {
        let exact = PackCommitError::from(RefStoreError::Unsupported(PUBLIC_ATTEMPT_SCHEMA_REQUIRED));
        assert!(missing_public_schema(&exact));
        for other in [
            PackCommitError::from(RefStoreError::Unsupported("another unsupported capability")),
            PackCommitError::from(RefStoreError::Database("catalog probe failed".into())),
            PackCommitError::from(RefStoreError::IdentityConflict),
            PackCommitError::from(RefStoreError::Timeout),
        ] {
            assert!(!missing_public_schema(&other), "{other:?} must not fall back");
        }
    }

    #[test]
    fn changed_and_forbidden_paths_keep_fixed_errors() {
        assert_eq!(
            GatewayError::Conflict(OPERATION_CHANGED),
            GatewayError::Conflict("operation identity changed during authorization; retry")
        );
        assert!(!OPERATION_FORBIDDEN.contains("uuid"));
        assert!(!OPERATION_CHANGED.contains("uuid"));
    }
}
