//! Safety regressions for live materializer auth checks and Arc<TempViewLease> detachment (Issue #184).
use super::*;
use crate::blob_store::budget::{ResourceContext, ResourceLimits};
use crate::blob_store::config::BlobProfile;
use crate::blob_store::disposable_view::DisposableViewRoot;
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::{BlobError, BlobLocator};
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::CommitMode;
use crate::ref_store::core::ref_version::*;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use anyhow::{Result, ensure};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone, Default)]
struct GatedS3 {
    objs: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    gate_next_get: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

async fn gated_s3_op(State(st): State<GatedS3>, method: Method, uri: Uri) -> Response {
    let k = uri.path().trim_start_matches('/').to_owned();
    if method == Method::GET && st.gate_next_get.swap(false, Ordering::SeqCst) {
        st.entered.notify_waiters();
        st.release.notified().await;
    }
    let Some(d) = st.objs.lock().expect("objs").get(&k).cloned() else {
        return (StatusCode::NOT_FOUND, [(header::CONTENT_LENGTH, "0".to_owned())], Body::empty()).into_response();
    };
    let len = d.len().to_string();
    let body = if method == Method::HEAD { Body::empty() } else { Body::from(d) };
    (StatusCode::OK, [(header::CONTENT_LENGTH, len), (header::ETAG, "\"e\"".to_owned())], body).into_response()
}

#[cfg(unix)]
const NULL_CFG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_CFG: &str = "NUL";

fn git_cmd(repo: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    let vars = format!(
        "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL={NULL_CFG} GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@e GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@e"
    );
    let si = if stdin.is_some() { Stdio::piped() } else { Stdio::null() };
    let mut ch = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs(vars.split(' ').filter_map(|s| s.split_once('=')))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(si)
        .spawn()?;
    if let Some(b) = stdin
        && let Some(mut s) = ch.stdin.take()
    {
        s.write_all(b)?;
    }
    let out = ch.wait_with_output()?;
    ensure!(out.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

struct SafetyFixture {
    _dir: TempDir,
    _srv: tokio::task::JoinHandle<()>,
    s3: GatedS3,
    views_dir: std::path::PathBuf,
    views: DisposableViewRoot,
    store: BlobStore,
    realm: RefVersionRealm,
    mr: RefName,
    vid: super::super::contract::VersionId,
    c1: GitOid,
    graph: VersionGraph,
    index: CoverHierarchyIndex,
    ret: RetentionClassificationIndex,
    req: FetchPlanRequest,
    plan: FetchPlan,
    proof: VerifiedFetchPlanProof,
}

impl Drop for SafetyFixture {
    fn drop(&mut self) {
        self._srv.abort();
    }
}

async fn setup_fixture() -> Result<SafetyFixture> {
    let (dir, u) = (TempDir::new()?, Uuid::new_v4);
    let repo = dir.path().join("src");
    let views_dir = dir.path().join("views");
    std::fs::create_dir_all(&repo)?;
    git_cmd(&repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(repo.join("f.txt"), "hello\n")?;
    git_cmd(&repo, &["add", "f.txt"], None)?;
    git_cmd(&repo, &["commit", "-m", "c1"], None)?;
    let realm = RefVersionRealm::new(u(), u(), u(), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let c1 = GitOid::parse(GitObjectFormat::Sha1, &git_cmd(&repo, &["rev-parse", "HEAD"], None)?)?;

    let pd = TempDir::new()?;
    let h = git_cmd(
        &repo,
        &["pack-objects", "--revs", "--quiet", pd.path().join("pack").to_str().unwrap()],
        Some(format!("{}\n", c1.as_hex()).as_bytes()),
    )?;
    let stem = format!("pack-{h}");
    let pk = std::fs::read(pd.path().join(format!("{stem}.pack")))?;
    let ix = std::fs::read(pd.path().join(format!("{stem}.idx")))?;
    let (ps, is) = (hex::encode(Sha256::digest(&pk)), hex::encode(Sha256::digest(&ix)));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let s3 = GatedS3::default();
    let app = Router::new().fallback(gated_s3_op).with_state(s3.clone());
    let _srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let limits = ResourceLimits::new(4, 4, 8 << 20)?;
    let profile = BlobProfile::memory_profile(limits).with_test_endpoint(&format!("http://{addr}"))?;
    let store = BlobStore::open_with_resources(profile, Arc::new(ResourceContext::new(limits)))?;
    let (t, r) = (realm.tenant_id(), realm.repository_id());
    let pl = BlobLocator::new(t, r, 1, u(), "packs", &ps, pk.len() as u64)?;
    let il = BlobLocator::new(t, r, 1, u(), "packs", &is, ix.len() as u64)?;
    {
        let mut g = s3.objs.lock().expect("objs");
        g.insert(format!("blob-test-bucket/{}", pl.path()), pk);
        g.insert(format!("blob-test-bucket/{}", il.path()), ix);
    }

    let mr = RefName::new("refs/heads/main")?;
    let d = RequestDigest::of("s", &[b"1"]);
    let op_id = u();
    let op = OperationDigestInput::new(
        realm,
        u(),
        u(),
        IssuerLane::new("m")?,
        1,
        op_id,
        1,
        d,
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![RefVersionIntent::new(
            mr.clone(),
            RefVersionKind::Publish,
            RefPrecondition::Absent,
            BaseRequestSelector::ExplicitAbsent,
            RefTarget::Oid(c1),
        )],
        d,
        vec![],
    );
    let od = operation_digest(&op)?;
    let vid = derive_candidate_version_id(&op, od, &mr, None)?;
    let pe = PackSetEntry::new(u(), u(), RequestDigest::of("p", &[ps.as_bytes()]))?;
    let vp = VerifiedClosurePack::new(
        pe,
        t,
        r,
        store.provider().as_str(),
        store.backend_identity().as_hex(),
        pl.length() + il.length(),
        2,
    )?;
    let csi = compute_commit_set_id(&CommitSetInput::new(
        realm,
        1,
        op_id,
        od,
        vec![CommitSetVersionEntry::new(mr.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(c1))],
        CommitSetHead::Absent,
    ))?;
    let v = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm,
        ref_name: mr.clone(),
        ref_generation: 1,
        operation_id: op_id,
        operation_digest: od,
        authority_seq: 1,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(c1),
        base_version_id: None,
        object_deps: vec![],
        pack_set_digest: compute_pack_set_digest(&[*vp.entry()])?,
        commit_set_id: csi,
    })?;
    let mut graph = VersionGraph::new();
    graph.insert_active(CausalVersionNode { record: v.clone(), own_packs: vec![vp.clone()] });
    let mem = compute_cover_membership_digest(&realm, 2, &[*vp.entry()])?;
    let mut index = CoverHierarchyIndex::new(realm, compute_cover_membership_digest(&realm, 1, &[])?)?;
    let cov = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: u(),
        realm,
        tier: CoverTier::Delta,
        pack: vp,
        artifacts: CoverArtifactPair {
            pack_stem: stem,
            pack_locator: pl,
            idx_locator: il,
            is_thin_pack: false,
            delta_base_cover_ids: vec![],
        },
        covered_versions: vec![vid],
        min_authority_seq: 1,
        max_authority_seq: 1,
        covered_commits: vec![CoverCommitLink {
            commit_oid: c1,
            parent_oids: vec![],
            version_id: vid,
            authority_seq: 1,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: mem,
        compaction_epoch: index.compaction_epoch(),
        worker_id: u(),
        operation_id: u(),
    })?;
    index.register_leaf_cover(cov.clone(), mem)?;
    let mut ret = RetentionClassificationIndex::new();
    ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: mr.clone(),
        version_id: vid,
        cover_ids: vec![cov.cover_id()],
    });

    let cut = StrongSnapshotCut {
        authority_seq: 1,
        snapshot_digest: d,
        membership_digest: index.membership_digest(),
        heads: BTreeMap::from([(mr.clone(), RefHead::from_committed(&v)?)]),
    };
    let auth = AuthorizationContext::for_realm(&realm, u(), u());
    let mut req = FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, realm, auth, ReadIsolationMode::StrongSnapshot);
    req.strong_cut = Some(cut.clone());
    req.wants = vec![WantTarget::Ref { ref_name: mr.clone() }];
    let FetchPlanOutcome::Planned(plan) = plan_fetch_covers(&req, &graph, &index, &ret)? else {
        anyhow::bail!("expected plan");
    };
    let plan = *plan;
    let proof = verify_fetch_plan_closure(&plan, req.consumer, &req.auth, Some(&cut), &graph, &index, &ret)?;
    let views = DisposableViewRoot::open(&views_dir, 4, 32 << 20, Duration::from_secs(60))?;
    Ok(SafetyFixture {
        _dir: dir,
        _srv,
        s3,
        views_dir,
        views,
        store,
        realm,
        mr,
        vid,
        c1,
        graph,
        index,
        ret,
        req,
        plan,
        proof,
    })
}

#[tokio::test]
async fn live_auth_revocation_epoch_visibility_and_actor_mismatch_reject_retained_proof() -> Result<()> {
    let f = setup_fixture().await?;
    let refs = [(f.mr.clone(), f.c1)];
    let dl = Instant::now() + Duration::from_secs(10);

    let mut revoked = f.req.auth.clone();
    revoked.revoked = true;
    ensure!(matches!(
        materialize_and_verify_fetch_plan(&f.store, &f.views, &f.proof, &f.plan, &revoked, &f.index, &[], &refs, dl)
            .await,
        Err(BlobVerifyError::Plan(FetchPlanError::AuthRevoked))
    ));

    let mut bumped_epoch = f.req.auth.clone();
    bumped_epoch.auth_epoch = 2;
    ensure!(matches!(
        materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &f.proof,
            &f.plan,
            &bumped_epoch,
            &f.index,
            &[],
            &refs,
            dl
        )
        .await,
        Err(BlobVerifyError::ProofMismatch)
    ));

    let other_actor = AuthorizationContext::for_realm(&f.realm, Uuid::new_v4(), f.req.auth.token_id);
    ensure!(matches!(
        materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &f.proof,
            &f.plan,
            &other_actor,
            &f.index,
            &[],
            &refs,
            dl
        )
        .await,
        Err(BlobVerifyError::ProofMismatch)
    ));

    let mut narrowed = f.req.auth.clone();
    narrowed.visibility = RefVisibilityPolicy::DenyList([f.mr.clone()].into_iter().collect());
    ensure!(matches!(
        materialize_and_verify_fetch_plan(&f.store, &f.views, &f.proof, &f.plan, &narrowed, &f.index, &[], &refs, dl)
            .await,
        Err(BlobVerifyError::Plan(FetchPlanError::HiddenRefDenied))
    ));

    // Mutating plan.isolation or delta_base_cover_ids must invalidate plan_digest, binds(), and materialization.
    let mut mut_iso_strong = f.plan.clone();
    mut_iso_strong.isolation =
        ReadIsolationMode::VersionClosure { version_id: f.vid, session_lower_bound: None, historical_pinned: false };
    ensure!(super::planner::compute_fetch_plan_digest(&mut_iso_strong)? != f.plan.plan_digest);
    ensure!(!f.proof.binds(&mut_iso_strong));
    ensure!(matches!(
        materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &f.proof,
            &mut_iso_strong,
            &f.req.auth,
            &f.index,
            &[],
            &refs,
            dl,
        )
        .await,
        Err(BlobVerifyError::ProofMismatch)
    ));

    let mut vs_auth = f.req.auth.clone();
    vs_auth.allow_non_common_time_set = true;
    vs_auth.allow_historical_pins = true;
    let mut vs_req = FetchPlanRequest::new(
        crate::ref_store::core::ref_version::read_mode::ReadConsumer::CrossRefCompare,
        f.realm,
        vs_auth.clone(),
        ReadIsolationMode::VersionSet { version_ids: vec![f.vid], session_lower_bound: None, historical_pinned: true },
    );
    vs_req.wants = vec![WantTarget::PinnedVersion { ref_name: f.mr.clone(), version_id: f.vid }];
    let FetchPlanOutcome::Planned(vs_plan) = plan_fetch_covers(&vs_req, &f.graph, &f.index, &f.ret)? else {
        anyhow::bail!("expected planned VersionSet outcome");
    };
    let vs_proof = verify_fetch_plan_closure(&vs_plan, vs_req.consumer, &vs_auth, None, &f.graph, &f.index, &f.ret)?;
    let mut forged_vs = *vs_plan;
    forged_vs.isolation =
        ReadIsolationMode::VersionClosure { version_id: f.vid, session_lower_bound: None, historical_pinned: false };
    ensure!(!vs_proof.binds(&forged_vs));
    ensure!(matches!(
        materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &vs_proof,
            &forged_vs,
            &vs_auth,
            &f.index,
            &[],
            &refs,
            dl
        )
        .await,
        Err(BlobVerifyError::ProofMismatch)
    ));

    let mut mut_bases = f.plan.clone();
    mut_bases.selected_covers[0].delta_base_cover_ids.push(Uuid::new_v4());
    ensure!(!f.proof.binds(&mut_bases));
    ensure!(matches!(
        materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &f.proof,
            &mut_bases,
            &f.req.auth,
            &f.index,
            &[],
            &refs,
            dl,
        )
        .await,
        Err(BlobVerifyError::ProofMismatch)
    ));

    ensure!(f.views.active_view_count() == 0 && f.views.total_reserved_bytes() == 0);
    let mat =
        materialize_and_verify_fetch_plan(&f.store, &f.views, &f.proof, &f.plan, &f.req.auth, &f.index, &[], &refs, dl)
            .await?;
    mat.reap();
    ensure!(f.views.active_view_count() == 0);
    let _ = (&f.graph, &f.ret);
    Ok(())
}

#[tokio::test]
async fn detached_timeout_preserves_temp_view_lease_until_background_transfer_settles() -> Result<()> {
    let f = setup_fixture().await?;
    let refs = [(f.mr.clone(), f.c1)];
    f.s3.gate_next_get.store(true, Ordering::SeqCst);

    {
        let mut fut = Box::pin(materialize_and_verify_fetch_plan(
            &f.store,
            &f.views,
            &f.proof,
            &f.plan,
            &f.req.auth,
            &f.index,
            &[],
            &refs,
            Instant::now() + Duration::from_secs(10),
        ));
        tokio::select! {
            res = &mut fut => anyhow::bail!("materializer finished before S3 GET gate entered: {:?}", res.err()),
            _ = f.s3.entered.notified() => {}
        }
        // Canceling/timing out the caller drops `fut`'s local `Arc<TempViewLease>`, yet the
        // detached `get_to_file_with_owner` task retains ownership & view dir until settled.
        ensure!(tokio::time::timeout(Duration::from_millis(20), &mut fut).await.is_err());
        drop(fut);
    }
    ensure!(f.views.active_view_count() == 1);
    ensure!(f.views.total_reserved_bytes() > 0);
    ensure!(std::fs::read_dir(&f.views_dir)?.count() == 1);

    f.s3.release.notify_waiters();
    for _ in 0..300 {
        if f.views.active_view_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ensure!(f.views.active_view_count() == 0 && f.views.total_reserved_bytes() == 0);
    ensure!(std::fs::read_dir(&f.views_dir)?.count() == 0);

    // Also prove internal deadline expiry returns `BlobVerifyError::Blob(BlobError::DeadlineExceeded)` and cleans up.
    f.s3.gate_next_get.store(true, Ordering::SeqCst);
    let err = materialize_and_verify_fetch_plan(
        &f.store,
        &f.views,
        &f.proof,
        &f.plan,
        &f.req.auth,
        &f.index,
        &[],
        &refs,
        Instant::now() + Duration::from_millis(250),
    )
    .await;
    ensure!(matches!(err, Err(BlobVerifyError::Blob(BlobError::DeadlineExceeded) | BlobVerifyError::DeadlineExceeded)));
    f.s3.release.notify_waiters();
    for _ in 0..300 {
        if f.views.active_view_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ensure!(f.views.active_view_count() == 0);
    Ok(())
}
