//! Narrow gate-owned read adapter for `GET /api/repos/{owner}/{name}/operations/{id}`.
//!
//! The route keeps the existing authenticated read-or-scoped-write-only serving
//! lookup and the migration-138 operation advisory key acquired before the fresh
//! lookup/row locks. This adapter then distinguishes the durable public wrapper,
//! a private attempt identifier, an unknown identifier and a genuine legacy
//! operation inside the same caller-owned transaction and deadline.
//!
//! A public status is first resolved with the authenticated live issuer marker.
//! Only a data-free issuer mismatch triggers the same current-role lookup as the
//! legacy resolver; a current owner/admin re-resolves the public status with the
//! explicit admin marker in the same transaction. The role query takes the same
//! `FOR SHARE` policy fences as the legacy path, and a revocation blocks behind
//! the transaction. No state from the issuer-mismatch probe is returned.
//!
//! A pre-migration-152 catalog may take the legacy path only when the status
//! lookup reports the exact schema refusal *and* an explicit catalog probe
//! proves the migration row and both relations absent. Every other
//! database/integrity/realm/unsupported/composite error fails closed.
use deadpool_postgres::Transaction;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    db::Identity,
    members::{models::Role, rbac::resolve_effective_role},
    ref_store::{
        OperationLookup, OperationRecord, PgRefStore, RefStoreError,
        core::pack_commit::PackCommitError,
        pg::public_attempt::{
            PUBLIC_ATTEMPT_SCHEMA_REQUIRED, PublicOperationReadAuthorization, PublicOperationStatus,
            PublicOperationStatusLookup, PublicOperationStatusRequest, public_attempt_catalog_absent,
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
    match PgRefStore.lookup_public_operation_status(&**tx, &live, deadline).await {
        Ok(PublicOperationStatusLookup::Found(status)) => Ok(OperationRead::Public(status)),
        Ok(PublicOperationStatusLookup::Unknown) => Err(GatewayError::NotFound),
        // A private attempt id is never handed to the legacy resolver.
        Ok(PublicOperationStatusLookup::PrivateIdentifier) => Err(private_conflict()),
        Ok(PublicOperationStatusLookup::Forbidden) => {
            resolve_admin(tx, identity, repository_id, owner_id, operation_id, deadline).await
        }
        Ok(PublicOperationStatusLookup::LegacyPath) => {
            resolve_legacy(tx, identity, repository_id, owner_id, operation_id, deadline).await
        }
        Err(error) if missing_public_schema(&error) => {
            let absent = public_attempt_catalog_absent(&**tx, deadline).await.map_err(GatewayError::from)?;
            if absent {
                resolve_legacy(tx, identity, repository_id, owner_id, operation_id, deadline).await
            } else {
                Err(error.into())
            }
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
    match PgRefStore.lookup_public_operation_status(&**tx, &admin, deadline).await {
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

async fn resolve_legacy(
    tx: &Transaction<'_>,
    identity: &Identity,
    repository_id: Uuid,
    owner_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<OperationRead, GatewayError> {
    let record = match PgRefStore.get_legacy_locked(&**tx, repository_id, operation_id, deadline).await? {
        OperationLookup::Known(record) => record,
        OperationLookup::Unknown => return Err(GatewayError::NotFound),
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
    crate::ref_store::pg::bound(&**tx, deadline).await.map_err(GatewayError::from)?;
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

fn private_conflict() -> GatewayError {
    // The shared RefStore -> GatewayError mapping for IdentityConflict.
    GatewayError::Conflict("operation identity conflicts with a durable record")
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
    fn private_and_changed_identifiers_use_fixed_conflicts() {
        assert_eq!(private_conflict(), GatewayError::Conflict("operation identity conflicts with a durable record"));
        assert_eq!(
            GatewayError::Conflict(OPERATION_CHANGED),
            GatewayError::Conflict("operation identity changed during authorization; retry")
        );
        assert!(!OPERATION_FORBIDDEN.contains("uuid"));
    }
}
