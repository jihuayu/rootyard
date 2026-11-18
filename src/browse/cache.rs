//! Authz-first, origin-verified advisory cache helpers for browse handlers.
use crate::{
    AppState, Error, auth,
    browse::{
        cache_models::{
            CachedBlobResponse, CachedCommitDetail, CachedRefSnapshotHint, CachedRefTipHint, CachedTreeResponse,
        },
        git_read,
        handlers::acquire_git_slot,
        models::{self, BlobResponse, CommitDetail, RefsResponse, TreeResponse},
    },
    cache_wake::{CacheKey, CacheKeyParts, CacheKind, OriginError, ServingCache, validate_scope_token},
    db::Identity,
    token_scopes::RepoAction,
};
use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrowseRepoScope {
    pub repo_id: Uuid,
    pub tenant_id: Uuid,
    pub environment: String,
    pub authority: &'static str,
    pub history_incarnation: Uuid,
    pub storage_generation: i64,
}

impl BrowseRepoScope {
    pub(crate) fn cache_key(&self, kind: CacheKind, discriminator: &str) -> Result<CacheKey, Error> {
        let version = u64::try_from(self.storage_generation).unwrap_or(0);
        CacheKey::new(CacheKeyParts {
            environment: &self.environment,
            authority: self.authority,
            schema: 1,
            history_incarnation: self.history_incarnation,
            tenant: self.tenant_id,
            repo: self.repo_id,
            kind,
            version,
            discriminator,
        })
        .map_err(Error::internal)
    }
}

pub(crate) fn authority_token(storage_backend: &str) -> &'static str {
    match storage_backend {
        "pando" => "pando",
        "gitfs" => "gitfs",
        _ => "git-native",
    }
}

pub(crate) fn compute_history_incarnation(
    volume_id: Uuid,
    repo_id: Uuid,
    authority: &str,
    object_format: &str,
    transition_epoch: i64,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard:browse:history-incarnation:v1:");
    hasher.update(volume_id.as_bytes());
    hasher.update(repo_id.as_bytes());
    hasher.update([0]);
    hasher.update(authority.as_bytes());
    hasher.update([0]);
    hasher.update(object_format.as_bytes());
    hasher.update(transition_epoch.to_be_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 16] = digest[..16].try_into().expect("sha256 digest has at least 16 bytes");
    Uuid::from_bytes(bytes)
}

const INVALID_CACHE_ENVIRONMENT: &str = "invalid cache environment";

/// Parse the one environment scope value. Only an absent variable selects the
/// documented default. A present empty, malformed, overlong, uppercase, or
/// non-Unicode value fails closed before the caller can touch the cache.
fn parse_cache_environment(raw: Result<String, std::env::VarError>) -> Result<String, &'static str> {
    match raw {
        Ok(value) => {
            validate_scope_token("environment", &value).map_err(|_| INVALID_CACHE_ENVIRONMENT)?;
            Ok(value)
        }
        Err(std::env::VarError::NotPresent) => Ok("serving".to_owned()),
        Err(std::env::VarError::NotUnicode(_)) => Err(INVALID_CACHE_ENVIRONMENT),
    }
}

fn cache_environment() -> Result<String, Error> {
    parse_cache_environment(std::env::var("ROOTYARD_CACHE_ENVIRONMENT")).map_err(Error::internal)
}

fn hashed_discriminator(tag: &str, parts: &[Option<&str>], limit: Option<usize>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    for item in parts {
        match item {
            Some(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    match limit {
        Some(n) => {
            hasher.update([1]);
            hasher.update((n as u64).to_be_bytes());
        }
        None => hasher.update([0]),
    }
    format!("{tag}:{}", hex::encode(hasher.finalize()))
}

fn is_origin_fault(err: &Error) -> bool {
    err.0.is_server_error()
}

fn map_origin_error(err: OriginError<Error>) -> Error {
    match err {
        OriginError::Origin(err) => err,
        OriginError::Busy | OriginError::CircuitOpen => {
            Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
        }
        OriginError::Deadline => Error::timeout(),
    }
}

pub(crate) struct BrowseContext {
    pub state: Arc<AppState>,
    pub cache: Arc<ServingCache>,
    pub scope: BrowseRepoScope,
    pub actor: Identity,
}

/// Authorize read access and load the repository's cache isolation scope in one
/// PostgreSQL transaction before reading any advisory cache entry.
pub(crate) async fn authorize_and_scope(
    state: Arc<AppState>,
    cache: Arc<ServingCache>,
    actor: Identity,
    owner: &str,
    name: &str,
) -> Result<BrowseContext, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_with_role(&tx, &actor, owner, name, auth::Role::Read, RepoAction::ContentsRead).await?;
    let row = tx
        .query_one(
            "SELECT storage_generation, storage_backend, object_format, backend_transition_epoch \
             FROM repositories WHERE id = $1",
            &[&access.repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let storage_generation: i64 = row.get("storage_generation");
    let storage_backend: &str = row.get("storage_backend");
    let object_format: &str = row.get("object_format");
    let epoch: i64 = row.get("backend_transition_epoch");
    auth::finish_tx(tx, &actor, false).await?;
    let authority = authority_token(storage_backend);
    let history_incarnation =
        compute_history_incarnation(state.storage.volume_id, access.repo_id, authority, object_format, epoch);
    let environment = cache_environment()?;
    let scope = BrowseRepoScope {
        repo_id: access.repo_id,
        tenant_id: access.owner_id,
        environment,
        authority,
        history_incarnation,
        storage_generation,
    };
    Ok(BrowseContext { state, cache, scope, actor })
}

async fn run_origin_git<T, F, Fut>(
    state: Arc<AppState>,
    repo_id: Uuid,
    actor: Identity,
    operation: F,
) -> Result<T, Error>
where
    F: FnOnce(Arc<AppState>) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let _permit = acquire_git_slot(&state)?;
    let deadline = Instant::now() + state.config.git_timeout;
    let lease = crate::storage::read_leases::shared(&state.pool, repo_id, deadline).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, RepoAction::ContentsRead, auth::Role::Read).await?;
    let value = lease.guard(operation(state.clone())).await??;
    lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, RepoAction::ContentsRead, auth::Role::Read).await?;
    Ok(value)
}

async fn resolve_verified_root_oid(ctx: &BrowseContext, oid_or_spec: Option<&str>) -> Result<String, Error> {
    if let Some(oid) = oid_or_spec
        && models::valid_non_zero_oid(oid)
    {
        return Ok(oid.to_owned());
    }
    let spec = oid_or_spec.unwrap_or("HEAD");
    if !models::valid_revision_spec(spec) {
        return Err(Error::bad_request());
    }
    let tip_key =
        ctx.scope.cache_key(CacheKind::RefSnapshotHint, &hashed_discriminator("ref-tip", &[Some(spec)], None))?;
    let cached_tip = ctx.cache.get_json::<CachedRefTipHint>(&tip_key).await;
    let spec_owned = spec.to_owned();
    let repo_id = ctx.scope.repo_id;
    let resolved_oid = run_origin_git(ctx.state.clone(), repo_id, ctx.actor.clone(), move |st| async move {
        git_read::resolve_commit_oid(&st, repo_id, &spec_owned).await
    })
    .await?;
    let is_fresh = cached_tip
        .as_ref()
        .is_some_and(|hint| hint.spec == spec && hint.resolved_oid == resolved_oid);
    if !is_fresh {
        ctx.cache
            .put_json(&tip_key, &CachedRefTipHint { spec: spec.to_owned(), resolved_oid: resolved_oid.clone() }, None)
            .await;
    }
    Ok(resolved_oid)
}

/// Advisory `RefSnapshotHint` read paired with mandatory origin verification.
pub(crate) async fn reconcile_ref_snapshot_hint(
    cache: &ServingCache,
    key: &CacheKey,
    authoritative: &RefsResponse,
) {
    let expected = CachedRefSnapshotHint::from_model(authoritative);
    let cached = cache.get_json::<CachedRefSnapshotHint>(key).await;
    if cached.as_ref() != Some(&expected) {
        cache.put_json(key, &expected, None).await;
    }
}

pub(crate) async fn list_refs(
    ctx: BrowseContext,
    prefix: Option<&str>,
    after: Option<&str>,
    limit: usize,
) -> Result<RefsResponse, Error> {
    let key =
        ctx.scope.cache_key(CacheKind::RefSnapshotHint, &hashed_discriminator("refs", &[prefix, after], Some(limit)))?;
    let repo_id = ctx.scope.repo_id;
    let prefix_owned = prefix.map(str::to_owned);
    let after_owned = after.map(str::to_owned);
    let (head, filtered) = run_origin_git(ctx.state, repo_id, ctx.actor, move |st| async move {
        let head = git_read::read_head(&st, repo_id).await?;
        let filtered = git_read::page_refs(&st, repo_id, prefix_owned.as_deref(), after_owned.as_deref(), limit).await?;
        Ok((head, filtered))
    })
    .await?;
    let more = filtered.len() > limit;
    let items: Vec<_> = filtered.into_iter().take(limit).collect();
    let next_after = if more { items.last().map(|r| r.name.clone()) } else { None };
    let response = RefsResponse {
        repository_id: ctx.scope.repo_id,
        storage_generation: ctx.scope.storage_generation,
        head,
        items,
        next_after,
    };
    reconcile_ref_snapshot_hint(&ctx.cache, &key, &response).await;
    Ok(response)
}

pub(crate) async fn get_commit(ctx: BrowseContext, oid: String) -> Result<CommitDetail, Error> {
    let key = ctx.scope.cache_key(CacheKind::GitObjectPreview, &hashed_discriminator("commit", &[Some(&oid)], None))?;
    let BrowseContext { state, cache, scope, actor } = ctx;
    let repo_id = scope.repo_id;
    let (cached, _) = cache
        .get_or_load_json(&key, None, is_origin_fault, || async move {
            let detail = run_origin_git(state, repo_id, actor, move |st| async move {
                git_read::get_commit_detail(&st, repo_id, &oid).await
            })
            .await?;
            Ok(CachedCommitDetail::from(&detail))
        })
        .await
        .map_err(map_origin_error)?;
    Ok(CommitDetail::from(cached))
}

pub(crate) async fn get_tree(
    ctx: BrowseContext,
    oid_or_spec: Option<&str>,
    rel_path: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<TreeResponse, Error> {
    let root_oid = resolve_verified_root_oid(&ctx, oid_or_spec).await?;
    let disc = hashed_discriminator("tree", &[Some(&root_oid), Some(rel_path), after], Some(limit));
    let key = ctx.scope.cache_key(CacheKind::TreeListing, &disc)?;
    let BrowseContext { state, cache, scope, actor } = ctx;
    let rel_owned = rel_path.to_owned();
    let after_owned = after.map(str::to_owned);
    let repo_id = scope.repo_id;
    let (cached, _) = cache
        .get_or_load_json(&key, None, is_origin_fault, || async move {
            let tree = run_origin_git(state, repo_id, actor, move |st| async move {
                git_read::read_tree(&st, repo_id, Some(&root_oid), &rel_owned, after_owned.as_deref(), limit).await
            })
            .await?;
            Ok(CachedTreeResponse::from(&tree))
        })
        .await
        .map_err(map_origin_error)?;
    Ok(TreeResponse::from(cached))
}

pub(crate) async fn get_blob(ctx: BrowseContext, oid_or_spec: Option<&str>, clean_path: &str) -> Result<BlobResponse, Error> {
    let (disc, resolved_spec) = if clean_path.is_empty() {
        let oid = oid_or_spec.ok_or_else(Error::bad_request)?;
        if !models::valid_non_zero_oid(oid) {
            return Err(Error::bad_request());
        }
        (hashed_discriminator("blob-oid", &[Some(oid)], None), oid.to_owned())
    } else {
        let root_oid = resolve_verified_root_oid(&ctx, oid_or_spec).await?;
        let disc = hashed_discriminator("blob-path", &[Some(&root_oid), Some(clean_path)], None);
        (disc, root_oid)
    };
    let key = ctx.scope.cache_key(CacheKind::GitObjectPreview, &disc)?;
    let BrowseContext { state, cache, scope, actor } = ctx;
    let path_arg = (!clean_path.is_empty()).then(|| clean_path.to_owned());
    let repo_id = scope.repo_id;
    let (cached, _) = cache
        .get_or_load_json(&key, None, is_origin_fault, || async move {
            let blob = run_origin_git(state, repo_id, actor, move |st| async move {
                git_read::read_blob(&st, repo_id, Some(&resolved_spec), path_arg.as_deref()).await
            })
            .await?;
            Ok(CachedBlobResponse::from(&blob))
        })
        .await
        .map_err(map_origin_error)?;
    Ok(BlobResponse::from(cached))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browse::models::{HeadInfo, RefItem};

    fn sample_scope(authority: &'static str, generation: i64, epoch: i64) -> BrowseRepoScope {
        let volume = Uuid::from_u128(10);
        let repo = Uuid::from_u128(20);
        BrowseRepoScope {
            repo_id: repo,
            tenant_id: Uuid::from_u128(30),
            environment: "test".to_owned(),
            authority,
            history_incarnation: compute_history_incarnation(volume, repo, authority, "sha1", epoch),
            storage_generation: generation,
        }
    }

    #[test]
    fn cache_environment_defaults_only_when_absent() {
        assert_eq!(
            parse_cache_environment(Err(std::env::VarError::NotPresent)).unwrap(),
            "serving"
        );
    }

    #[test]
    fn cache_environment_preserves_valid_tokens_at_boundaries() {
        for token in ["a", "z9-_"] {
            assert_eq!(parse_cache_environment(Ok(token.to_owned())).unwrap(), token);
        }
        let boundary = "a".repeat(32);
        assert_eq!(parse_cache_environment(Ok(boundary.clone())).unwrap(), boundary);
    }

    #[test]
    fn cache_environment_rejects_present_invalid_values_with_fixed_error() {
        let invalid = [
            String::new(),
            "Production".to_owned(),
            "prod env".to_owned(),
            "prod/env".to_owned(),
            "a".repeat(33),
        ];
        for value in invalid {
            assert_eq!(parse_cache_environment(Ok(value)), Err(INVALID_CACHE_ENVIRONMENT));
        }
    }

    #[cfg(unix)]
    #[test]
    fn cache_environment_rejects_non_unicode_values_without_reading_process_env() {
        use std::os::unix::ffi::OsStringExt;
        let raw = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
        assert_eq!(
            parse_cache_environment(Err(std::env::VarError::NotUnicode(raw))),
            Err(INVALID_CACHE_ENVIRONMENT)
        );
    }

    #[test]
    fn scope_key_changes_with_authority_generation_and_transition_epoch() {
        let base = sample_scope("gitfs", 1, 0).cache_key(CacheKind::TreeListing, "disc").unwrap();
        let pando = sample_scope("pando", 1, 0).cache_key(CacheKind::TreeListing, "disc").unwrap();
        let gen2 = sample_scope("gitfs", 2, 0).cache_key(CacheKind::TreeListing, "disc").unwrap();
        let epoch1 = sample_scope("gitfs", 1, 1).cache_key(CacheKind::TreeListing, "disc").unwrap();
        assert_ne!(base, pando);
        assert_ne!(base, gen2);
        assert_ne!(base, epoch1);
        assert_eq!(Error::not_found().0.as_u16(), 404);
        assert!(!is_origin_fault(&Error::not_found()));
        assert!(is_origin_fault(&Error::timeout()));
        assert!(is_origin_fault(&Error(StatusCode::SERVICE_UNAVAILABLE, "err")));
    }

    #[tokio::test]
    async fn reconcile_ref_snapshot_hint_replaces_stale_advisory_cache() {
        let cache = ServingCache::standalone_memory().unwrap();
        let scope = sample_scope("gitfs", 3, 1);
        let key = scope.cache_key(CacheKind::RefSnapshotHint, &hashed_discriminator("refs", &[None, None], Some(50))).unwrap();
        let stale = RefsResponse {
            repository_id: scope.repo_id,
            storage_generation: 3,
            head: HeadInfo { kind: "symbolic".to_owned(), target: Some("refs/heads/main".to_owned()), oid: Some("1".repeat(40)) },
            items: vec![RefItem { name: "refs/heads/main".to_owned(), oid: "1".repeat(40), kind: "branch".to_owned(), peeled_oid: None }],
            next_after: None,
        };
        cache.put_json(&key, &CachedRefSnapshotHint::from_model(&stale), None).await;
        let fresh = RefsResponse {
            head: HeadInfo { oid: Some("2".repeat(40)), ..stale.head.clone() },
            items: vec![RefItem { oid: "2".repeat(40), ..stale.items[0].clone() }],
            ..stale
        };
        reconcile_ref_snapshot_hint(&cache, &key, &fresh).await;
        let stored = cache.get_json::<CachedRefSnapshotHint>(&key).await.unwrap();
        assert_eq!(stored, CachedRefSnapshotHint::from_model(&fresh));
    }
}
