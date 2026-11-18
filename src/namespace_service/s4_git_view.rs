//! Durable Namespace GitView projections for `pg_refstore` repositories.
//!
//! A `gitfs` view is a clone that lives under `workspace-service/views`. A
//! `pg_refstore` repository has no such directory, so an S4 view is instead one
//! non-expiring `PgRetentionRoots` capture of the mounted commit plus a
//! `s4_ci_retention.git_view_bindings` row. Nothing is written under
//! `workspace-service/views`; every bundle is projected in a disposable `0o700`
//! temporary tree that is removed before the response is returned.
//!
//! Creation materializes the verified packs into a disposable bare repository
//! *before* PostgreSQL is touched, so the projected object id is known when the
//! one and only transaction opens. Root registration, RBAC, the view row, its
//! history and the binding then commit together or not at all.
use super::s4_git_proc::{ScratchDir, git_clone, git_init_bare, git_text, with_scratch};
use crate::namespace_service::{handlers, views::{CreateView, View}};
use crate::ref_store::core::pack_commit::PackArtifactRole;
use crate::{AppState, Error, db::Identity, members::models::Role, token_scopes::RepoAction};
use axum::http::StatusCode;
use std::{
    fs,
    path::Path as FsPath,
};
use uuid::Uuid;

async fn run_git(
    git_bin: &FsPath,
    repo: &FsPath,
    args: &[&str],
    deadline: tokio::time::Instant,
) -> Result<String, Error> {
    git_text(git_bin, repo, args, deadline, "Git view projection failed").await
}

/// True only for repositories served on `pg_refstore`.
pub(crate) async fn is_refstore(state: &AppState, repository_id: Uuid) -> Result<bool, Error> {
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt("SELECT storage_backend FROM repositories WHERE id=$1", &[&repository_id])
        .await
        .map_err(Error::internal)?;
    Ok(row.is_some_and(|row| {
        row.get::<_, String>(0) == crate::ref_store::core::serving_scope::PG_REFSTORE_BACKEND
    }))
}

/// One prepared capture plus the identities needed after it is registered.
pub(super) struct Captured {
    producer: crate::ci_pins::s4_pin::Producer,
    prepared: crate::ci_pins::s4_pin::Prepared,
    repository_id: Uuid,
    tenant_id: Uuid,
    authority_epoch: i64,
    history_incarnation: Uuid,
    group_epoch: i64,
    cluster_incarnation: Uuid,
    object_format: String,
}

/// Prepare (durability-free) the capture of the mounted commit.
async fn capture(
    state: &AppState,
    actor: &Identity,
    mount: &handlers::Mount,
    deadline: tokio::time::Instant,
) -> Result<Captured, Error> {
    let producer = crate::ci_pins::s4_pin::Producer::open(state)?;
    let serving = crate::ref_store::serving::lookup(
        &state.pool,
        actor,
        &mount.owner,
        &mount.repository,
        false,
        producer.store.backend_identity(),
        deadline,
    )
    .await?;
    let intent = crate::ref_store::contract::RequestDigest::of(
        "s4-namespace-view-intent-v1",
        &[serving.repository.id.as_bytes(), mount.base_oid.as_bytes()],
    )
    .as_hex();
    let prepared = producer
        .capture(
            &state.pool,
            &serving,
            crate::ci_pins::s4_pin::CaptureSpec {
                purpose: crate::ref_store::RootPurpose::Namespace,
                business_intent: &intent,
                target_oid: &mount.base_oid,
            },
            deadline,
        )
        .await?;
    Ok(Captured {
        producer,
        prepared,
        repository_id: serving.repository.id,
        tenant_id: serving.gate.tenant_id(),
        authority_epoch: serving.gate.authority_epoch(),
        history_incarnation: serving.gate.history_incarnation(),
        group_epoch: serving.gate.group_epoch(),
        cluster_incarnation: serving.cluster_incarnation,
        object_format: serving.repository.object_format.clone(),
    })
}

/// Rebuild a disposable bare repository directly from the verified pack pairs of
/// the prepared candidate. No PostgreSQL row and no retention root exists yet.
async fn materialize_packs(
    state: &AppState,
    captured: &Captured,
    base_oid: &str,
    tree: &ScratchDir,
    deadline: tokio::time::Instant,
) -> Result<(), Error> {
    let bare = tree.bare();
    git_init_bare(&state.config.git, &bare, &captured.object_format, deadline).await?;
    let packs = bare.join("objects/pack");
    fs::create_dir_all(&packs).map_err(Error::internal)?;
    let std_deadline = std::time::Instant::now() + state.config.git_timeout;
    for pack in captured.prepared.request.candidate().packs() {
        let base = format!("pack-{}", pack.pack_id());
        for (role, suffix) in [(PackArtifactRole::Pack, "pack"), (PackArtifactRole::Idx, "idx")] {
            let locator = pack.artifact(role).locator().blob_locator().map_err(Error::internal)?;
            let destination = packs.join(format!("{base}.{suffix}"));
            captured
                .producer
                .store
                .get_to_file(&locator, &destination, std_deadline)
                .await
                .map_err(Error::internal)?;
        }
    }
    run_git(&state.config.git, &bare, &["update-ref", "refs/heads/main", base_oid], deadline).await?;
    Ok(())
}

/// Deterministic projection: the mounted commit itself, or the commit that
/// survives `--subdirectory-filter` for a non-empty `subdir`. Remote-tracking
/// refs are deleted first so they can never leak unrelated root files into a
/// bundle.
pub(crate) async fn project(
    git_bin: &FsPath,
    work: &FsPath,
    base: &str,
    subdir: &str,
    deadline: tokio::time::Instant,
) -> Result<String, Error> {
    run_git(git_bin, work, &["checkout", "-B", "projected", base], deadline).await?;
    let remotes = run_git(git_bin, work, &["for-each-ref", "--format=%(refname)", "refs/remotes"], deadline).await?;
    for reference in remotes.lines().filter(|line| !line.is_empty()) {
        let _ = run_git(git_bin, work, &["update-ref", "-d", reference], deadline).await;
    }
    if !subdir.is_empty() {
        let path = format!("{base}^{{tree}}:{subdir}");
        let kind = run_git(git_bin, work, &["cat-file", "-t", &path], deadline).await.map_err(|_| Error::bad_request())?;
        if kind.trim() != "tree" {
            return Err(Error::bad_request());
        }
        run_git(
            git_bin,
            work,
            &["filter-branch", "-f", "--subdirectory-filter", subdir, "--", "refs/heads/projected"],
            deadline,
        )
        .await?;
        let _ = run_git(git_bin, work, &["update-ref", "-d", "refs/original/refs/heads/projected"], deadline).await;
    }
    let projected = run_git(git_bin, work, &["rev-parse", "refs/heads/projected"], deadline).await?.trim().to_owned();
    run_git(git_bin, work, &["symbolic-ref", "HEAD", "refs/heads/projected"], deadline).await?;
    Ok(projected)
}

/// Verify that `base_oid` is a real commit of the mounted `pg_refstore`
/// repository. Used by namespace creation before a mount is recorded.
pub(crate) async fn verify_mounted_commit(
    state: &AppState,
    actor: &Identity,
    mount: &handlers::Mount,
) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let captured = capture(state, actor, mount, deadline).await.map_err(|_| Error::bad_request())?;
    let tree = ScratchDir::create("rootyard-s4-view")?;
    with_scratch(vec![tree.hold()], async {
        let checked = materialize_packs(state, &captured, &mount.base_oid, &tree, deadline).await;
        let snapshot_scope = captured.prepared.snapshot_scope;
        let snapshot = captured.prepared.snapshot;
        captured.producer.release_source_snapshot(&state.pool, snapshot_scope, &snapshot, deadline).await;
        checked.map_err(|_| Error::bad_request())?;
        let commit = format!("{}^{{commit}}", mount.base_oid);
        run_git(&state.config.git, &tree.bare(), &["cat-file", "-e", &commit], deadline)
            .await
            .map_err(|_| Error::bad_request())?;
        Ok(())
    })
    .await
}

/// Create one durable `pg_refstore` view: materialize, project, then one commit.
pub(super) async fn create(
    state: &AppState,
    actor: &Identity,
    namespace_id: Uuid,
    input: &CreateView,
    mount: &handlers::Mount,
    repository_id: Uuid,
) -> Result<(StatusCode, axum::Json<View>), Error> {
    crate::ci_pins::s4_schema::ensure_s4_schema(&state.pool).await?;
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let captured = capture(state, actor, mount, deadline).await?;
    let snapshot_scope = captured.prepared.snapshot_scope;
    let snapshot = captured.prepared.snapshot;
    let outcome: Result<(StatusCode, axum::Json<View>), Error> = async {
        if captured.repository_id != repository_id {
            return Err(Error::not_found());
        }
        let tree = ScratchDir::create("rootyard-s4-view")?;
        let projected = with_scratch(vec![tree.hold()], async {
            materialize_packs(state, &captured, &mount.base_oid, &tree, deadline).await?;
            git_clone(
                &state.config.git,
                &tree.bare(),
                &tree.work(),
                &["--no-local", "--no-hardlinks", "--no-tags"],
                deadline,
            )
            .await?;
            project(&state.config.git, &tree.work(), &mount.base_oid, &input.subdir, deadline).await
        })
        .await?;
        let vid = Uuid::new_v4();
        let root_id = captured.prepared.request.candidate().root_id();
        let register_digest = captured.prepared.request.candidate().register_digest().as_hex();
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        if crate::ci_pins::s4_authority::require_cluster_incarnation_nowait(&tx).await?
            != captured.cluster_incarnation
        {
            return Err(Error(StatusCode::CONFLICT, "cluster authority rotated"));
        }
        captured
            .producer
            .roots
            .register_serving_in_tx(
                &tx,
                captured.prepared.request.candidate(),
                captured.prepared.request.request_id(),
                captured.prepared.request.digest(),
                deadline,
            )
            .await
            .map_err(crate::ci_pins::s4_pin::root_error)?;
        captured
            .producer
            .roots
            .recheck_serving_source_pin_live_in_tx(&tx, &snapshot, deadline)
            .await
            .map_err(crate::ci_pins::s4_pin::root_error)?;
        let access = crate::auth::authorize_repo_with_role(
            &tx,
            actor,
            &mount.owner,
            &mount.repository,
            Role::Read,
            RepoAction::ContentsRead,
        )
        .await?;
        if access.repo_id != repository_id {
            return Err(Error::not_found());
        }
        tx.execute(
            "INSERT INTO workspace_views(id,namespace_id,repository_id,mount_path,subdir,source_oid,projected_oid,creator_id) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&vid, &namespace_id, &repository_id, &input.mount_path, &input.subdir, &mount.base_oid, &projected, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_view_history(view_id,source_oid,projected_oid,epoch) VALUES($1,$2,$3,1)",
            &[&vid, &mount.base_oid, &projected],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO s4_ci_retention.git_view_bindings \
             (view_id, namespace_id, repository_id, owner_tenant_id, mount_path, subdir, \
              source_oid, projected_oid, retention_root_id, register_digest_hex, \
              authority_epoch, history_incarnation, group_epoch, cluster_incarnation, state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'active')",
            &[
                &vid,
                &namespace_id,
                &repository_id,
                &captured.tenant_id,
                &input.mount_path,
                &input.subdir,
                &mount.base_oid,
                &projected,
                &root_id,
                &register_digest,
                &captured.authority_epoch,
                &captured.history_incarnation,
                &captured.group_epoch,
                &captured.cluster_incarnation,
            ],
        )
        .await
        .map_err(Error::internal)?;
        crate::auth::finish_tx(tx, actor, false).await?;
        drop(client);
        Ok((
            StatusCode::CREATED,
            axum::Json(View {
                id: vid,
                namespace_id,
                repository_id,
                mount_path: input.mount_path.clone(),
                subdir: input.subdir.clone(),
                source_oid: mount.base_oid.clone(),
                projected_oid: projected,
                epoch: 1,
            }),
        ))
    }
    .await;
    captured.producer.release_source_snapshot(&state.pool, snapshot_scope, &snapshot, deadline).await;
    outcome
}

/// Build one bundle from the retained root, never from `workspace-service/views`.
pub(super) async fn bundle(
    state: &AppState,
    view: &View,
    id: Uuid,
) -> Result<([(axum::http::HeaderName, &'static str); 2], Vec<u8>), Error> {
    crate::ci_pins::s4_schema::ensure_s4_schema(&state.pool).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let cluster_inc = crate::ci_pins::s4_authority::require_cluster_incarnation_nowait(&tx).await?;
    let binding = tx
        .query_opt(
            "SELECT b.retention_root_id, b.state, b.owner_tenant_id, b.cluster_incarnation \
             FROM s4_ci_retention.git_view_bindings b \
             JOIN ref_store_core_gates cg ON cg.repository_id=b.repository_id \
             WHERE b.view_id=$1 AND cg.authority_epoch=b.authority_epoch \
               AND cg.history_incarnation=b.history_incarnation AND cg.group_epoch=b.group_epoch",
            &[&id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if binding.get::<_, Uuid>(3) != cluster_inc {
        return Err(Error(StatusCode::CONFLICT, "cluster authority rotated"));
    }
    if binding.get::<_, String>(1) != "active" {
        return Err(Error(StatusCode::CONFLICT, "view binding is released"));
    }
    let owner_id: Uuid = tx
        .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&view.repository_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    if Some(owner_id) != binding.get::<_, Option<Uuid>>(2) {
        return Err(Error::not_found());
    }
    let _ = tx.rollback().await;
    drop(client);
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let producer = crate::ci_pins::s4_pin::Producer::open(state)?;
    let holder = crate::ci_pins::s4_transport::materialize(
        state,
        &producer.store,
        view.repository_id,
        binding.get(0),
        &view.source_oid,
        deadline,
    )
    .await?;
    let tree = ScratchDir::create("rootyard-s4-view")?;
    let bytes = with_scratch(vec![tree.hold(), holder.hold()], async {
        git_clone(
            &state.config.git,
            holder.path(),
            &tree.work(),
            &["--no-local", "--no-hardlinks", "--no-tags"],
            deadline,
        )
        .await?;
        let projected = project(&state.config.git, &tree.work(), &view.source_oid, &view.subdir, deadline).await?;
        if projected != view.projected_oid {
            return Err(Error(StatusCode::CONFLICT, "view projection no longer matches its recorded head"));
        }
        let file = tree.root().join("view.bundle");
        let file = file.to_str().ok_or_else(Error::bad_request)?;
        run_git(
            &state.config.git,
            &tree.work(),
            &["bundle", "create", file, "refs/heads/projected", "HEAD"],
            deadline,
        )
        .await?;
        fs::read(file).map_err(Error::internal)
    })
    .await?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "view bundle too large"));
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-git-bundle"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    ))
}
