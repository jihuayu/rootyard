//! The one advisory commit-preview payload cache of the Blob gateway.
//!
//! The gateway remains authority-first. This module is reached only after the
//! normal [`super::browse::BrowseSession`] pipeline has authenticated the live
//! token, admitted the request, authorized the repository through the shared
//! serving lookup, captured and incarnation-fenced the RefStore view,
//! materialized the sealed pack closure, revalidated the read authorization,
//! and the caller has proved the exact object id is part of the captured
//! reachable closure and is a commit. It only avoids repeating the immutable
//! native metadata/diff computation for that same exact commit.
//!
//! A cache entry carries no ref, reachability, reachable-closure, pin, session,
//! token, hold, root, quota or durable-byte fact. It is the existing bounded
//! typed [`CachedCommitDetail`] payload (a lossless mirror of [`CommitDetail`])
//! whose OID is rechecked before use. Every hit still runs the existing final
//! authorization, capture-incarnation and session output fence in
//! [`super::browse::finalize`]. A miss, corrupt value, absent
//! cache, unqualified key or backend error falls straight back to the real
//! origin computation; the cache can never make a read succeed or fail on its
//! own.
use std::{future::Future, sync::Arc};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{browse::BrowseSession, error::GatewayError};
use crate::{
    browse::{cache_models::CachedCommitDetail, models::CommitDetail},
    cache_wake::{CacheKey, CacheKeyParts, CacheKind, ServingCache},
    ref_store::{GitObjectFormat, GitOid, core::serving_scope::PG_REFSTORE_BACKEND},
};

/// Explicit authority domain for the only backend this gateway serves. It is
/// the shared recognized PgRefStore backend token, never inferred from a client
/// value or defaulted from an unknown storage backend.
const CACHE_AUTHORITY: &str = PG_REFSTORE_BACKEND;
/// Key schema version; bumping it invalidates every prior payload shape.
const CACHE_SCHEMA: u16 = 1;

/// The exact authorized gate domains that isolate one commit-preview payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommitPreviewScope {
    environment: String,
    tenant: Uuid,
    repo: Uuid,
    history_incarnation: Uuid,
    object_format: GitObjectFormat,
    storage_generation: i64,
    gate_revision: i64,
    restore_incarnation: Uuid,
}

impl CommitPreviewScope {
    /// Build the scope from facts already proved by `BrowseSession::open`.
    /// A missing/nil anchor or non-positive captured revision is not qualified,
    /// so the caller uses the ordinary origin path instead.
    pub(super) fn from_session(session: &BrowseSession) -> Option<Self> {
        let gate_revision = session.capture_gate_revision.filter(|revision| *revision > 0)?;
        let restore_incarnation = session.capture_incarnation().filter(|incarnation| !incarnation.is_nil())?;
        if session.tenant_id.is_nil() || session.repository_id.is_nil() || session.history_incarnation.is_nil() {
            return None;
        }
        let environment = crate::browse::cache::cache_environment().ok()?;
        Some(Self {
            environment,
            tenant: session.tenant_id,
            repo: session.repository_id,
            history_incarnation: session.history_incarnation,
            object_format: session.format,
            storage_generation: session.storage_generation,
            gate_revision,
            restore_incarnation,
        })
    }

    /// A bounded, typed key for one already-validated exact OID. The OID keeps
    /// its full native length and is never abbreviated; the discriminator is
    /// hashed by [`CacheKey`], so the raw id is not exported in the key text.
    fn key(&self, oid: &str) -> Option<CacheKey> {
        // The native-format parser rejects short, uppercase and all-zero ids.
        GitOid::parse(self.object_format, oid).ok()?;
        let discriminator =
            format!("commit-preview:v{CACHE_SCHEMA}:{}:{}:{oid}", self.object_format.as_str(), oid.len());
        CacheKey::new(CacheKeyParts {
            environment: &self.environment,
            authority: CACHE_AUTHORITY,
            schema: CACHE_SCHEMA,
            history_incarnation: self.history_incarnation,
            tenant: self.tenant,
            repo: self.repo,
            kind: CacheKind::GitObjectPreview,
            version: self.version(),
            discriminator: &discriminator,
        })
        .ok()
    }

    /// Fold storage generation, the captured live gate revision, object format
    /// and the restore cluster incarnation into the key's numeric version.
    /// Every one of them changes the domain; none is defaulted away.
    fn version(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"rootyard:blob-gateway:commit-preview:version:v1");
        hasher.update(self.object_format.as_str().as_bytes());
        hasher.update(self.storage_generation.to_be_bytes());
        hasher.update(self.gate_revision.to_be_bytes());
        hasher.update(self.restore_incarnation.as_bytes());
        let digest = hasher.finalize();
        u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 digest has at least eight bytes"))
    }
}

/// Read one immutable commit payload from the advisory cache, otherwise compute
/// it through `load` and make a best-effort bounded fill.
///
/// `load` is the existing origin computation. It is invoked for every miss,
/// corrupt/unqualified value, absent cache and backend read error. A cache
/// write failure is ignored. A cached value is returned only when its full OID
/// equals the requested one; the caller still runs the final authority/output
/// fence after this function returns.
pub(super) async fn cached_commit_detail<F, Fut>(
    cache: Option<Arc<ServingCache>>,
    scope: Option<CommitPreviewScope>,
    oid: &str,
    load: F,
) -> Result<CommitDetail, GatewayError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<CommitDetail, GatewayError>>,
{
    let Some(cache) = cache else {
        return load().await;
    };
    let Some(key) = scope.as_ref().and_then(|scope| scope.key(oid)) else {
        return load().await;
    };
    if let Some(cached) = cache.get_json::<CachedCommitDetail>(&key).await {
        if cached.oid == oid {
            return Ok(CommitDetail::from(cached));
        }
        // Same key but another OID is a corrupt/stale value: remove it and let
        // the real origin answer this request.
        cache.delete_key(&key).await;
    }
    let detail = load().await?;
    if detail.summary.oid == oid {
        let cached = CachedCommitDetail::from(&detail);
        cache.put_json(&key, &cached, None).await;
    }
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browse::models::CommitSummary;

    fn scope() -> CommitPreviewScope {
        CommitPreviewScope {
            environment: "test".to_owned(),
            tenant: Uuid::from_u128(1),
            repo: Uuid::from_u128(2),
            history_incarnation: Uuid::from_u128(3),
            object_format: GitObjectFormat::Sha1,
            storage_generation: 4,
            gate_revision: 5,
            restore_incarnation: Uuid::from_u128(6),
        }
    }

    fn detail(oid: &str) -> CommitDetail {
        CommitDetail {
            summary: CommitSummary {
                oid: oid.to_owned(),
                tree_oid: "b".repeat(40),
                parents: Vec::new(),
                author_name: "A".to_owned(),
                author_email: "a@example.invalid".to_owned(),
                authored_at: 1,
                committer_name: "C".to_owned(),
                committer_email: "c@example.invalid".to_owned(),
                committed_at: 2,
                subject: "subject".to_owned(),
                message: "subject".to_owned(),
            },
            changed_paths: vec!["a.txt".to_owned()],
        }
    }

    #[tokio::test]
    async fn exact_oid_hits_memory_without_recomputing_and_miss_falls_back() {
        let cache = Arc::new(ServingCache::standalone_memory().expect("memory cache"));
        let oid = "a".repeat(40);
        let key = scope().key(&oid).expect("qualified key");
        let cached = CachedCommitDetail::from(&detail(&oid));
        cache.put_json(&key, &cached, None).await;

        let mut loads = 0u32;
        let hit = cached_commit_detail(Some(cache.clone()), Some(scope()), &oid, || async {
            loads += 1;
            Ok(detail(&oid))
        })
        .await
        .expect("hit");
        assert_eq!(hit, detail(&oid));
        assert_eq!(loads, 0, "a valid cache hit must not recompute the immutable payload");

        let other = "b".repeat(40);
        let other_key = scope().key(&other).expect("qualified key");
        // A same-key value for another OID is corrupt/stale and must not be
        // served; the helper drops it and runs the real origin computation.
        let wrong_oid = CachedCommitDetail::from(&detail(&oid));
        cache.put_json(&other_key, &wrong_oid, None).await;
        let mut loads = 0u32;
        let origin = cached_commit_detail(Some(cache.clone()), Some(scope()), &other, || async {
            loads += 1;
            Ok(detail(&other))
        })
        .await
        .expect("origin");
        assert_eq!(origin, detail(&other));
        assert_eq!(loads, 1, "a miss must use the same real origin computation");
        let refreshed = cache.get_json::<CachedCommitDetail>(&other_key).await.expect("origin refill");
        assert_eq!(refreshed.oid, other, "the invalid value must be replaced by the origin result");

        let mut loads = 0u32;
        let absent_scope = cached_commit_detail(None, Some(scope()), &other, || async {
            loads += 1;
            Ok(detail(&other))
        })
        .await
        .expect("no cache");
        assert_eq!(absent_scope, detail(&other));
        assert_eq!(loads, 1, "an absent cache must use the same real origin computation");
    }

    #[test]
    fn key_covers_every_gate_domain_and_never_embeds_the_oid_or_a_credential() {
        let oid = "a".repeat(40);
        let base = scope();
        let base_key = base.key(&oid).expect("qualified key");
        let text = base_key.as_str();
        assert!(text.contains(":pg_refstore:"));
        assert!(text.contains(":git-object-preview:"));
        assert!(!text.contains(oid.as_str()));
        assert!(!text.contains("Bearer"));
        assert!(!text.contains("ryt_"));

        let variants = [
            CommitPreviewScope { environment: "other".to_owned(), ..base.clone() },
            CommitPreviewScope { tenant: Uuid::from_u128(11), ..base.clone() },
            CommitPreviewScope { repo: Uuid::from_u128(12), ..base.clone() },
            CommitPreviewScope { history_incarnation: Uuid::from_u128(13), ..base.clone() },
            CommitPreviewScope { object_format: GitObjectFormat::Sha256, ..base.clone() },
            CommitPreviewScope { storage_generation: 14, ..base.clone() },
            CommitPreviewScope { gate_revision: 15, ..base.clone() },
            CommitPreviewScope { restore_incarnation: Uuid::from_u128(16), ..base.clone() },
        ];
        for variant in variants {
            let variant_oid =
                if variant.object_format == GitObjectFormat::Sha256 { "c".repeat(64) } else { oid.clone() };
            assert_ne!(variant.key(&variant_oid).expect("qualified").as_str(), text);
        }
        assert!(base.key(&oid[..12]).is_none(), "an abbreviated id is never qualified");
        assert!(base.key(&"A".repeat(40)).is_none(), "an uppercase id is never qualified");
        assert!(base.key(&"0".repeat(40)).is_none(), "the zero id is never qualified");
    }
}
