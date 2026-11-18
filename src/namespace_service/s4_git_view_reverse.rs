//! Reverse import of a projected bundle into a `pg_refstore` repository.
//!
//! There is no GitFS working repository to mutate. The retained source root is
//! materialized into a disposable bare repository, the proposal bundle is
//! verified/fetched into a disposable clone, the projected tree is grafted back
//! under `subdir`, and the resulting commit becomes one new verified pack pair.
//! The ref update, artifact holds, registration, decision and changeset are all
//! the ordinary A4 core path; nothing here is a placeholder.
use super::reverse_git::{git, git_input, git_input_bytes, git_oid, verify_candidate_budget};
use crate::namespace_service::{
    changesets::{ChangeSet, Step},
    handlers::Mount,
    reverse::{ReverseInput, replace_tree},
    views::{self, View},
};
use crate::{
    AppState, Error,
    blob_store::protected::{ProtectedUploader, UploadSource},
    db::Identity,
    ref_store::{
        GitOid, HeadUpdate, IssuerLane, RefName, RefUpdate, RequestDigest,
        artifact_hold::{
            AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope,
            PgArtifactHoldStore,
        },
        core::{
            CommitMode,
            decision_commit::{PgDecisionProtocol, RealmExpectation},
            pack_commit::{
                AuthorizedCommitMode, ContentDigest, PackArtifactRole, PackCommitExpectation, PackCommitPlan,
                PackCommitScope, PackMembershipEntry, PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit,
                PlannedArtifact, PlannedPack, PrepareOutcome,
            },
        },
        tx::{begin_bounded, commit_bounded},
    },
};
use axum::{Json, http::StatusCode};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;

const HOLD_NAMESPACE: &str = "gateway-pack";
const ISSUER_LANE: &str = "s4-view-reverse";
const MAX_PACK_BYTES: usize = 32 * 1024 * 1024;

struct Scratch(PathBuf);

impl Scratch {
    fn create() -> Result<Self, Error> {
        let path = std::env::temp_dir().join(format!("rootyard-s4-reverse-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&path).map_err(Error::internal)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&path).map_err(Error::internal)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Binding {
    root_id: Uuid,
    source_oid: String,
    projected_oid: String,
    subdir: String,
    owner_tenant_id: Uuid,
    storage_generation: i64,
}

async fn load_binding(state: &AppState, view: &View) -> Result<Binding, Error> {
    crate::ci_pins::s4_schema::ensure_s4_schema(&state.pool).await?;
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            "SELECT b.retention_root_id, b.source_oid, b.projected_oid, b.subdir, b.owner_tenant_id, \
                    r.owner_id, r.storage_generation, r.state \
             FROM s4_ci_retention.git_view_bindings b JOIN repositories r ON r.id=b.repository_id \
             JOIN ref_store_core_gates cg ON cg.repository_id=b.repository_id \
             WHERE b.view_id=$1 AND b.state='active' AND b.repository_id=$2 \
               AND cg.authority_epoch=b.authority_epoch \
               AND cg.history_incarnation=b.history_incarnation AND cg.group_epoch=b.group_epoch",
            &[&view.id, &view.repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, String>(7) != "ready" || Some(row.get::<_, Uuid>(5)) != Some(row.get(4)) {
        return Err(Error::not_found());
    }
    Ok(Binding {
        root_id: row.get(0),
        source_oid: row.get(1),
        projected_oid: row.get(2),
        subdir: row.get(3),
        owner_tenant_id: row.get(4),
        storage_generation: row.get(6),
    })
}

fn write_bundle(path: &FsPath, bytes: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(Error::internal)?;
    file.write_all(bytes).map_err(Error::internal)?;
    file.sync_all().map_err(Error::internal)
}

fn new_pack(root: &FsPath, source: &FsPath, new_oid: &str, base_oid: &str) -> Result<(PathBuf, PathBuf), Error> {
    let objects = git(source, &["rev-list", "--objects", new_oid, "--not", base_oid])?;
    let pack = git_input_bytes(source, &["pack-objects", "--stdout"], &objects)?;
    if pack.is_empty() || pack.len() > MAX_PACK_BYTES {
        return Err(Error(axum::http::StatusCode::PAYLOAD_TOO_LARGE, "proposal pack exceeds 32 MiB"));
    }
    let pack_path = root.join("new.pack");
    let idx_path = root.join("new.idx");
    fs::write(&pack_path, &pack).map_err(Error::internal)?;
    git(
        source,
        &[
            "index-pack",
            "-o",
            idx_path.to_str().ok_or_else(Error::bad_request)?,
            pack_path.to_str().ok_or_else(Error::bad_request)?,
        ],
    )?;
    Ok((pack_path, idx_path))
}

fn planned_pack(pack: &[u8], idx: &[u8]) -> Result<(PlannedPack, Uuid), Error> {
    let pack_digest = ContentDigest::parse(hex::encode(Sha256::digest(pack))).map_err(Error::internal)?;
    let idx_digest = ContentDigest::parse(hex::encode(Sha256::digest(idx))).map_err(Error::internal)?;
    let pack_artifact = PlannedArtifact::new(PackArtifactRole::Pack, pack_digest, pack.len() as u64)
        .map_err(Error::internal)?;
    let idx_artifact =
        PlannedArtifact::new(PackArtifactRole::Idx, idx_digest, idx.len() as u64).map_err(Error::internal)?;
    let planned = PlannedPack::new(Uuid::new_v4(), Uuid::new_v4(), pack_artifact, idx_artifact)
        .map_err(Error::internal)?;
    let pack_id = planned.pack_id();
    Ok((planned, pack_id))
}

pub(super) async fn create(
    state: &AppState,
    actor: &Identity,
    view: &View,
    mount: &Mount,
    namespace_id: Uuid,
    input: &ReverseInput,
    bundle: &[u8],
) -> Result<(StatusCode, Json<ChangeSet>), Error> {
    let deadline = tokio::time::Instant::now() + state.config.git_timeout;
    let binding = load_binding(state, view).await?;
    if binding.source_oid != view.source_oid || mount.base_oid != binding.source_oid {
        return Err(Error::not_found());
    }
    let producer = crate::ci_pins::s4_pin::Producer::open(state)?;
    let holder = crate::ci_pins::s4_transport::materialize(
        state,
        &producer.store,
        view.repository_id,
        binding.root_id,
        &binding.source_oid,
        deadline,
    )
    .await?;
    let scratch = Scratch::create()?;
    let work = scratch.0.join("projected");
    let work_text = work.to_str().ok_or_else(Error::bad_request)?;
    let source_text = holder.path().to_str().ok_or_else(Error::bad_request)?;
    git(
        &scratch.0,
        &["clone", "--no-local", "--no-hardlinks", "--no-tags", source_text, work_text],
    )?;
    let projected = views::s4_git_view::project(&work, &binding.source_oid, &binding.subdir)?;
    if projected != binding.projected_oid {
        return Err(Error(StatusCode::CONFLICT, "view projection no longer matches its recorded head"));
    }
    let bundle_path = scratch.0.join("proposal.bundle");
    write_bundle(&bundle_path, bundle)?;
    let bundle_text = bundle_path.to_str().ok_or_else(Error::bad_request)?;
    git(&work, &["bundle", "verify", bundle_text])?;
    git(&work, &["fetch", "--no-tags", bundle_text, input.bundle_ref.as_str()])?;
    let candidate = git_oid(&work, &["rev-parse", "FETCH_HEAD^{commit}"])?;
    git(&work, &["merge-base", "--is-ancestor", binding.projected_oid.as_str(), candidate.as_str()])?;
    let candidate_bytes = verify_candidate_budget(&work, &candidate, &binding.projected_oid)?;
    git(&work, &["fsck", "--strict", "--no-reflogs", candidate.as_str()])?;
    let projected_tree = git_oid(&work, &["rev-parse", &format!("{candidate}^{{tree}}")])?;
    let old_projected_tree = git_oid(&work, &["rev-parse", &format!("{}^{{tree}}", binding.projected_oid)])?;
    if projected_tree == old_projected_tree {
        return Err(Error(StatusCode::CONFLICT, "projected tree is unchanged"));
    }
    let source = holder.path();
    let source_bytes = crate::storage::disk_bytes(source, state.config.max_repo_bytes).map_err(Error::internal)?;
    if source_bytes.saturating_add(candidate_bytes) > state.config.max_repo_bytes {
        return Err(Error(StatusCode::INSUFFICIENT_STORAGE, "repository quota reached"));
    }
    git(&work, &["update-ref", "refs/heads/reverse-import", candidate.as_str()])?;
    git(
        source,
        &["fetch", "--no-tags", "--no-write-fetch-head", work_text, "refs/heads/reverse-import"],
    )?;
    let old_tree = git_oid(source, &["rev-parse", &format!("{}^{{tree}}", binding.source_oid)])?;
    let new_tree = if binding.subdir.is_empty() {
        projected_tree
    } else {
        let parts: Vec<&str> = binding.subdir.split('/').collect();
        replace_tree(source, &old_tree, &parts, &projected_tree)?
    };
    let body = format!("{}\n", input.message);
    let new_oid = git_input(
        source,
        &["commit-tree", new_tree.as_str(), "-p", binding.source_oid.as_str()],
        body.as_bytes(),
        Some(actor.username.as_str()),
    )?;
    let (pack_path, idx_path) = new_pack(&scratch.0, source, &new_oid, &binding.source_oid)?;
    let pack = fs::read(&pack_path).map_err(Error::internal)?;
    let idx = fs::read(&idx_path).map_err(Error::internal)?;
    let (planned, pack_id) = planned_pack(&pack, &idx)?;
    let publication = Publication {
        namespace_id,
        view,
        mount,
        input,
        binding: &binding,
        new_oid: &new_oid,
        planned,
        pack_id,
        pack: &pack,
        idx: &idx,
        sources: [pack_path, idx_path],
    };
    publish(state, actor, &producer, publication, deadline).await
}

struct Publication<'a> {
    namespace_id: Uuid,
    view: &'a View,
    mount: &'a Mount,
    input: &'a ReverseInput,
    binding: &'a Binding,
    new_oid: &'a str,
    planned: PlannedPack,
    pack_id: Uuid,
    pack: &'a [u8],
    idx: &'a [u8],
    sources: [PathBuf; 2],
}

async fn publish(
    state: &AppState,
    actor: &Identity,
    producer: &crate::ci_pins::s4_pin::Producer,
    publication: Publication<'_>,
    deadline: tokio::time::Instant,
) -> Result<(StatusCode, Json<ChangeSet>), Error> {
    let Publication { namespace_id, view, mount, input, binding, new_oid, planned, pack_id, pack, idx, sources } =
        publication;
    let operation_id = Uuid::new_v4();
    let parts: [&[u8]; 6] = [
        view.id.as_bytes(),
        binding.source_oid.as_bytes(),
        new_oid.as_bytes(),
        input.source_ref.as_bytes(),
        pack,
        idx,
    ];
    let digest = RequestDigest::of("s4-view-reverse-v1", &parts);
    let lane = IssuerLane::new(ISSUER_LANE).map_err(Error::internal)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let baseline = PgPackCommit
        .capture_baseline(&mut client, view.repository_id, binding.owner_tenant_id, deadline)
        .await
        .map_err(Error::internal)?;
    // Idempotent: a repository provisioned by its creator already owns this
    // exact realm, and one that was never initialized gets it before the first
    // decision is written, so the A4 path is never refused for a missing realm.
    let gate = baseline.gate();
    let realm = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(Error::internal)?;
    PgDecisionProtocol
        .provision(&mut client, &realm, deadline)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "decision realm provisioning refused"))?;
    // The retained source root only ever records `refs/heads/main`, so the live
    // gate refs are the only truthful answer to "is this source ref still where
    // the recorded view says it is?".
    let live_tip = baseline
        .refs()
        .iter()
        .find(|r| r.name() == input.source_ref.as_str())
        .map(|r| r.oid_hex());
    if live_tip != Some(binding.source_oid.as_str()) {
        return Err(Error(StatusCode::CONFLICT, "source ref advanced"));
    }
    let memberships = baseline
        .old_packs()
        .iter()
        .map(PackMembershipEntry::from_pack)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::internal)?;
    let scope = PackCommitScope::new(
        view.repository_id,
        baseline.gate().tenant_id(),
        binding.owner_tenant_id,
        baseline.gate().object_format(),
        baseline.gate().history_incarnation(),
        baseline.gate().authority_epoch(),
        baseline.gate().group_epoch(),
    )
    .map_err(Error::internal)?;
    let expected = PackCommitExpectation::new(
        baseline.gate().revision(),
        *baseline.gate().digest(),
        baseline.mode(),
    )
    .map_err(Error::internal)?;
    let object_format = scope.object_format();
    let reference = RefUpdate::new(
        RefName::new(input.source_ref.clone()).map_err(|_| Error::bad_request())?,
        GitOid::precondition_value(object_format, &binding.source_oid).map_err(|_| Error::bad_request())?,
        GitOid::target_value(object_format, new_oid).map_err(|_| Error::bad_request())?,
    );
    let tx = begin_bounded(&mut client, deadline).await.map_err(Error::internal)?;
    tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(Error::internal)?;
    let reservation = crate::ref_store::PgRefStore
        .reserve_sequence(&tx, view.repository_id, actor.id, operation_id, &lane, deadline)
        .await
        .map_err(Error::internal)?;
    let identity = reservation.identity(digest).map_err(Error::internal)?;
    let plan = PackCommitPlan::new_with_mode(
        scope,
        identity,
        expected,
        HeadUpdate::Keep,
        vec![reference],
        baseline.membership_digest(),
        memberships,
        vec![planned],
        CommitMode::Atomic,
    )
    .map_err(Error::internal)?;
    let _pending = PgPackCommit
        .begin_serving_pending_in_tx(&tx, &plan, digest, deadline)
        .await
        .map_err(Error::internal)?;
    commit_bounded(tx, deadline, view.repository_id, Some(operation_id)).await.map_err(Error::internal)?;
    drop(client);
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
    .map_err(Error::internal)?;
    let specs = vec![
        ArtifactSpec::new(HOLD_NAMESPACE, hex::encode(Sha256::digest(pack)), pack.len() as u64)
            .map_err(Error::internal)?,
        ArtifactSpec::new(HOLD_NAMESPACE, hex::encode(Sha256::digest(idx)), idx.len() as u64)
            .map_err(Error::internal)?,
    ];
    let request = AcquireArtifactHoldsRequest::new(
        scope,
        plan.identity().clone(),
        Uuid::new_v4(),
        producer.store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        specs,
    )
    .map_err(Error::internal)?;
    let grant = {
        let mut hold_client = state.pool.get().await.map_err(Error::internal)?;
        match PgArtifactHoldStore.acquire(&mut hold_client, &producer.store, &request, deadline).await {
            Ok(AcquireOutcome::Granted { grant, .. }) => grant,
            Ok(AcquireOutcome::Replayed { .. }) => {
                return Err(Error(StatusCode::CONFLICT, "reverse import already consumed its artifact hold"));
            }
            Err(_) => return Err(Error::internal("artifact hold acquisition was refused")),
        }
    };
    let std_deadline = std::time::Instant::now() + state.config.git_timeout;
    let upload_sources = [UploadSource::new(sources[0].clone()), UploadSource::new(sources[1].clone())];
    let publication = ProtectedUploader::new(producer.store.clone())
        .consume_and_upload(&state.pool, grant, &upload_sources, std_deadline)
        .await
        .map_err(Error::internal)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let registration =
        PackRegistrationRequest::new(&plan, pack_id, &publication).map_err(Error::internal)?;
    PgPackCommit.register_publication(&mut client, registration, deadline).await.map_err(Error::internal)?;
    drop(client);
    let adapter = PgAuthorizedCommit::new(producer.store.clone(), state.config.git.clone()).map_err(Error::internal)?;
    let prepared = match adapter.prepare(&state.pool, plan, deadline).await.map_err(Error::internal)? {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(_) => {
            return Err(Error(StatusCode::CONFLICT, "reverse import operation was already terminal"));
        }
    };
    let selection = adapter
        .select(&state.pool, *prepared, actor, AuthorizedCommitMode::Atomic, deadline)
        .await
        .map_err(Error::internal)?;
    let verified = adapter.verify(selection, deadline).await.map_err(Error::internal)?;
    let receipt = adapter.commit(&state.pool, &verified, deadline).await.map_err(Error::internal)?;
    if !receipt.is_committed() {
        return Err(Error(StatusCode::CONFLICT, "reverse import was rejected"));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let changeset_id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO workspace_changesets(id,namespace_id,state,creator_id) VALUES($1,$2,'complete',$3)",
        &[&changeset_id, &namespace_id, &actor.id],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO workspace_changeset_steps(changeset_id,ordinal,repository_id,mount_path,owner_slug,repository_name,ref_name,old_oid,new_oid,storage_generation,applied) \
         VALUES($1,0,$2,$3,$4,$5,$6,$7,$8,$9,true)",
        &[
            &changeset_id,
            &view.repository_id,
            &mount.path,
            &mount.owner,
            &mount.repository,
            &input.source_ref,
            &binding.source_oid,
            &new_oid,
            &binding.storage_generation,
        ],
    )
    .await
    .map_err(Error::internal)?;
    crate::auth::finish_tx(tx, actor, false).await?;
    Ok((
        StatusCode::CREATED,
        Json(ChangeSet {
            id: changeset_id,
            namespace_id,
            state: "complete".to_owned(),
            creator_id: actor.id,
            reviewer_id: None,
            steps: vec![Step {
                ordinal: 0,
                repository_id: view.repository_id,
                mount_path: mount.path.clone(),
                owner: mount.owner.clone(),
                repository: mount.repository.clone(),
                ref_name: input.source_ref.clone(),
                old_oid: binding.source_oid.clone(),
                new_oid: new_oid.to_owned(),
                storage_generation: binding.storage_generation,
                applied: true,
            }],
        }),
    ))
}
