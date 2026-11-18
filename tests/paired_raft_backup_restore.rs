//! OpenDAL S3 + real stock Git (`SHA-1`/`SHA-256`) + live PG 17 integration tests (#153).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use deadpool_postgres::{Manager, Pool};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::blob_store::capacity_contract::git_ops::{UploadScope, upload_pack_pair};
use rootyard::blob_store::{config::BlobProfile, opendal::BlobStore};
use rootyard::db;
use rootyard::maintenance::paired_raft_backup::freeze_drain::RepoBackupRegistrationSpec;
use rootyard::maintenance::paired_raft_backup::{
    CloseScopeBarrierReceipt, DecisionExecutionTicket, DeleterLeaseTicket, PairedBackupError, PairedBackupManifest,
    PairedBackupRequest, PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof, PreparedBlobArtifact,
    RestoreTargetScope, TriPartyBackupCoordinator, WriterGrantTicket, capture_live_pg_backup, create_paired_backup,
    freeze_pg_deleter, git_verify::seed_commit_pack, restore_new_incarnation, restore_new_incarnation_with_pg,
    types::sha256_json_tagged, verify_backup_archive, verify_pg_live_incarnation,
};
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane,
    ScopeLifecycle, SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}
struct LoopbackS3 {
    endpoint: String,
    state: Arc<S3State>,
}

impl LoopbackS3 {
    fn new() -> Self {
        let (state, lis) = (Arc::new(S3State::default()), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        lis.set_nonblocking(true).unwrap();
        let (port, srv, (tx, rx)) =
            (lis.local_addr().unwrap().port(), Arc::clone(&state), std::sync::mpsc::sync_channel(1));
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let (l, _) = (tokio::net::TcpListener::from_std(lis).unwrap(), tx.send(()));
                let _ = axum::serve(l, axum::Router::new().fallback(handle_s3).with_state(srv)).await;
            });
        });
        rx.recv().unwrap();
        Self { endpoint: format!("http://127.0.0.1:{port}"), state }
    }

    fn open_store(&self, bucket: &str) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let spec = format!(
            "DRIVER=opendal SERVICE=s3 BUCKET={bucket} REGION=us-east-1 ROOT=paired-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=3 MAX_OBJECT_BYTES=67108864 ENDPOINT={}",
            self.endpoint
        );
        let mut saved = vec![("ROOTYARD_BLOB_KEYRING_DIR".into(), std::env::var_os("ROOTYARD_BLOB_KEYRING_DIR"))];
        unsafe { std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR") };
        for (k, v) in spec.split(' ').map(|kv| kv.split_once('=').unwrap()) {
            let ek = format!("ROOTYARD_BLOB_{k}");
            saved.push((ek.clone(), std::env::var_os(&ek)));
            unsafe { std::env::set_var(&ek, v) };
        }
        let res = BlobStore::open(BlobProfile::from_env()?);
        for (k, old) in saved {
            unsafe { if let Some(v) = old { std::env::set_var(&k, v) } else { std::env::remove_var(&k) } }
        }
        Ok(res?)
    }
}

async fn handle_s3(State(st): State<Arc<S3State>>, method: Method, uri: Uri, body: Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    let empty = |c: u16, t: &'static str| {
        Response::builder().status(c).header(header::CONNECTION, "close").body(Body::from(t)).unwrap()
    };
    if !key.contains('/') {
        return empty(200, "<ListBucketResult/>");
    }
    let ok = |b: &[u8], bd: Body| {
        Response::builder()
            .status(200u16)
            .header(header::CONNECTION, "close")
            .header("etag", format!("\"{}\"", &hex::encode(Sha256::digest(b))[..32]))
            .header("content-length", b.len())
            .body(bd)
            .unwrap()
    };
    match method {
        Method::PUT => {
            let r = ok(body.as_ref(), Body::empty());
            st.objects.lock().unwrap().insert(key, body.to_vec());
            r
        }
        Method::HEAD | Method::GET => st.objects.lock().unwrap().get(&key).cloned().map_or_else(
            || empty(404, ""),
            |d| ok(&d, if method == Method::HEAD { Body::empty() } else { Body::from(d.clone()) }),
        ),
        _ => empty(405, ""),
    }
}

struct Fixture {
    repo: Uuid,
    tenant: Uuid,
    history: Uuid,
    authority: Uuid,
    cluster_inc: Uuid,
    commit: String,
    sm: RefCasStateMachine,
    coord: TriPartyBackupCoordinator,
    receipts: Vec<CloseScopeBarrierReceipt>,
    pg_proof: PgCutpointProof,
    artifacts: Vec<PreparedBlobArtifact>,
}

fn dl() -> Instant {
    Instant::now() + Duration::from_secs(45)
}

fn wticket(c: Uuid, h: Uuid, ae: i64, ge: i64, az: i64) -> WriterGrantTicket {
    WriterGrantTicket {
        cluster_incarnation: c,
        history_incarnation: h,
        authority_epoch: ae,
        group_epoch: ge,
        authz_epoch: az,
    }
}

fn dticket(c: Uuid, a: Uuid, sg: i64, de: u64) -> DeleterLeaseTicket {
    DeleterLeaseTicket { cluster_incarnation: c, storage_authority_id: a, storage_generation: sg, deleter_epoch: de }
}

fn mk_req<'a>(
    f: &'a Fixture,
    s: &'a BlobStore,
    dir: &'a Path,
    dest: &'a Path,
    arts: Vec<PreparedBlobArtifact>,
) -> PairedBackupRequest<'a> {
    PairedBackupRequest {
        backup_id: Uuid::new_v4(),
        group_id: 1,
        group_membership_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        freeze: f.coord.status(),
        sm: &f.sm,
        close_receipts: f.receipts.clone(),
        backup_holds: f.coord.registered_holds().to_vec(),
        artifacts: arts,
        store: s,
        staging_dir: dir,
        destination: dest,
        deadline: dl(),
    }
}

async fn try_backup(
    f: &Fixture,
    s: &BlobStore,
    dir: &Path,
    name: &str,
    arts: Vec<PreparedBlobArtifact>,
    pg: Option<&PgCutpointProof>,
) -> std::result::Result<PairedBackupManifest, PairedBackupError> {
    let dest = dir.join(name);
    create_paired_backup(mk_req(f, s, dir, &dest, arts), pg).await
}

async fn build_fixture(store: &BlobStore, dir: &Path, fmt: GitObjectFormat) -> Result<Fixture> {
    let (u, pack_id) = (Uuid::new_v4, Uuid::new_v4());
    let (repo, tenant, issuer, history, authority, cluster_inc) = (u(), u(), u(), u(), u(), u());
    let (commit, p_path, i_path) =
        seed_commit_pack(&dir.join("seed"), fmt, "artifact.txt", b"rootyard paired raft blob backup payload\n", None)?;
    let up = upload_pack_pair(
        store,
        UploadScope { tenant_id: tenant, authority_id: authority, generation: 1 },
        &p_path,
        &i_path,
        dl(),
    )
    .await?;
    let mut sm = RefCasStateMachine::new();
    let init = CoreGateInit::new(repo, tenant, fmt, history, 2, 3, RefName::branch("refs/heads/main")?)?;
    let upd = RefUpdate::new(
        RefName::new("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(fmt, &commit)?),
    );
    let lane = IssuerLane::new("pack")?;
    let req = CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane.clone(),
        1,
        u(),
        fmt,
        history,
        2,
        3,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![upd],
    )?;
    let cmds = [
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 5,
        }),
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req),
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: 10,
        }),
    ];
    for (i, cmd) in cmds.into_iter().enumerate() {
        sm.apply(AppliedLogId { term: 1, index: (i + 1) as u64 }, cmd)?;
    }
    let (mut coord, mut log_idx) = (TriPartyBackupCoordinator::new(7, 4), 2u64);
    let spec = RepoBackupRegistrationSpec {
        repository_id: repo,
        tenant_id: tenant,
        owner_id: tenant,
        object_format: fmt,
        history_incarnation: history,
        authority_epoch: 2,
        group_epoch: 3,
        authority_id: authority,
        authority_generation: 1,
        backend_identity: store.backend_identity().as_hex().into(),
        pack_digests: vec![up.pack_sha256.clone()],
        hold_specs: vec![(up.pack_sha256.clone(), up.pack_length as i64, 512)],
    };
    let receipts = coord.freeze_drain_and_register(&mut sm, 1, &mut log_idx, &[spec], 15, true)?;
    let snap = sm.snapshot()?;
    let refs = BTreeMap::from([("refs/heads/main".into(), commit.clone())]);
    let pg_proof = PgCutpointProof {
        schema_head_version: 149,
        wal_lsn: "0/20A010".into(),
        snapshot_tx: "200:200:".into(),
        postgres_major_version: "17.4".into(),
        source_cluster_incarnation: cluster_inc,
        source_storage_authority_id: authority,
        source_storage_generation: 1,
        remote_delete_fenced: true,
        pending_decisions_count: 0,
        pending_outbox_count: 0,
        projection_cursors: vec![PgProjectionCursorCut {
            group_id: 1,
            history_incarnation: history,
            group_epoch: 3,
            applied_event_seq: snap.body.next_event_seq.saturating_sub(1) as i64,
            applied_log_index: log_idx as i64,
            applied_log_term: 1,
            last_event_id: None,
            stream_state: "active".into(),
        }],
        repositories: vec![PgRepositoryRowProof {
            repository_id: repo,
            tenant_id: tenant,
            name: "paired-demo".into(),
            object_format: fmt,
            storage_backend: "pg_refstore".into(),
            history_incarnation: history,
            authority_epoch: 2,
            group_epoch: 3,
            gate_revision: 2,
            refs_digest: sha256_json_tagged(b"rootyard-pg-refs-v1", &refs)?,
            refs,
        }],
        cutpoint_digest: String::new(),
    }
    .seal()?;
    let artifacts = [("pack", up.pack_receipt.locator()), ("idx", up.idx_receipt.locator())]
        .into_iter()
        .map(|(role, loc)| PreparedBlobArtifact {
            repository_id: repo,
            tenant_id: tenant,
            pack_id,
            object_format: fmt,
            role: role.into(),
            locator: loc.clone(),
        })
        .collect();
    Ok(Fixture { repo, tenant, history, authority, cluster_inc, commit, sm, coord, receipts, pg_proof, artifacts })
}

#[tokio::test]
async fn end_to_end_paired_backup_and_new_incarnation_restore_sha1_and_sha256() -> Result<()> {
    let s3 = LoopbackS3::new();
    let store = s3.open_store("paired-primary")?;
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let mut fix = build_fixture(&store, &dir.path().join("seed"), fmt).await?;
        let manifest =
            try_backup(&fix, &store, dir.path(), "archive", fix.artifacts.clone(), Some(&fix.pg_proof)).await?;
        assert_eq!(manifest.blob_closure.total_artifacts, 2);
        fix.coord.unfreeze_after_backup()?;
        assert!(fix.coord.admit_deleter(7).is_err());

        let scope = RestoreTargetScope {
            expected_tenant_id: Some(fix.tenant),
            expected_repository_id: Some(fix.repo),
            expected_backend_identity: Some(store.backend_identity().as_hex().into()),
        };
        let (out, new_sm, guard) =
            restore_new_incarnation(&dir.path().join("archive"), &dir.path().join("rw"), &store, &scope, dl()).await?;
        let inc = &out.incarnation;
        assert_ne!(inc.new_cluster_incarnation, fix.cluster_inc);
        assert_ne!(inc.new_storage_authority_id, fix.authority);
        assert_ne!(inc.new_history_incarnation, fix.history);
        assert_eq!((out.restored_blobs, out.git_verified_refs), (2, 1));
        assert_eq!(new_sm.read_refs(fix.repo).get("refs/heads/main").map(String::as_str), Some(fix.commit.as_str()));
        assert!(
            new_sm
                .read_scope_lifecycle(fix.repo)
                .is_some_and(|(lc, fl)| lc == ScopeLifecycle::Open && fl >= inc.new_authz_floor)
        );

        assert!(matches!(
            guard.verify_writer_grant(&wticket(fix.cluster_inc, fix.history, 2, 3, 10)),
            Err(PairedBackupError::StaleIncarnation { .. })
        ));
        assert!(matches!(
            guard.verify_deleter_lease(&dticket(fix.cluster_inc, fix.authority, 1, 7)),
            Err(PairedBackupError::StaleDeleterRefused(_))
        ));
        guard.verify_writer_grant(&wticket(
            inc.new_cluster_incarnation,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            inc.new_authz_floor,
        ))?;
        let stale_dec = DecisionExecutionTicket {
            decision_id: Uuid::new_v4(),
            history_incarnation: fix.history,
            authority_epoch: 2,
            group_epoch: 3,
            authz_epoch: 5,
        };
        assert!(guard.verify_decision_execution(&stale_dec).is_err());
        assert!(s3.state.objects.lock().unwrap().keys().any(|k| k.contains(&inc.new_storage_authority_id.to_string())));
    }
    Ok(())
}

#[tokio::test]
async fn negative_fail_closed_fault_matrix() -> Result<()> {
    let s3 = LoopbackS3::new();
    let (store, other) = (s3.open_store("paired-neg")?, s3.open_store("paired-wrong-bucket")?);
    let dir = TempDir::new()?;
    let mut fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;

    let mut skewed = fix.pg_proof.clone();
    skewed.projection_cursors[0].applied_log_index -= 1;
    skewed = skewed.seal()?;
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b1", fix.artifacts.clone(), None).await.unwrap_err(),
        PairedBackupError::IncompleteCut(_)
    ));
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b2", fix.artifacts.clone(), Some(&skewed)).await.unwrap_err(),
        PairedBackupError::CutpointSkew(_)
    ));
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b3", vec![fix.artifacts[0].clone()], Some(&fix.pg_proof))
            .await
            .unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));

    let good = dir.path().join("good");
    let manifest = try_backup(&fix, &store, dir.path(), "good", fix.artifacts.clone(), Some(&fix.pg_proof)).await?;
    fix.coord.unfreeze_after_backup()?;
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b4", fix.artifacts.clone(), Some(&fix.pg_proof)).await.unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    for (sub, st, sc) in [
        ("r1", &other, RestoreTargetScope::default()),
        ("r2", &store, RestoreTargetScope { expected_tenant_id: Some(Uuid::new_v4()), ..Default::default() }),
    ] {
        let e = restore_new_incarnation(&good, &dir.path().join(sub), st, &sc, dl()).await.unwrap_err();
        assert!(matches!(
            e,
            PairedBackupError::BackendIdentityMismatch { .. } | PairedBackupError::TenantOrRepoMismatch(_)
        ));
    }
    let blob_path = good.join(&manifest.blob_closure.entries[0].archive_rel_path);
    let orig = fs::read(&blob_path)?;
    let mut bad = orig.clone();
    bad[0] ^= 0x55;
    for bytes in [bad.as_slice(), &orig[..orig.len().saturating_sub(3)]] {
        fs::write(&blob_path, bytes)?;
        assert!(matches!(verify_backup_archive(&good, None).unwrap_err(), PairedBackupError::CorruptBlobOrDigest(_)));
    }
    fs::write(&blob_path, &orig)?;
    fs::remove_file(good.join("COMPLETE"))?;
    assert!(matches!(verify_backup_archive(&good, None).unwrap_err(), PairedBackupError::IncompleteCut(_)));
    Ok(())
}

async fn setup_pg(admin: &Pool, url: &str, prefix: &str) -> Result<(Pool, String)> {
    let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(6)
        .build()?;
    db::migrate(&pool).await?;
    Ok((pool, schema))
}

#[tokio::test]
#[ignore = "requires live PostgreSQL via ROOTYARD_TEST_DATABASE_URL"]
async fn pg17_live_paired_backup_and_clean_room_new_incarnation_restore() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&url)?;
    let ((src_pool, src_s), (dst_pool, dst_s)) =
        (setup_pg(&admin, &url, "paired_src").await?, setup_pg(&admin, &url, "paired_dst").await?);
    let res: Result<()> = async {
        let (s3, dir) = (LoopbackS3::new(), TempDir::new()?);
        let store = s3.open_store("paired-pg17")?;
        let fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;
        let (snap, applied, backend, mut src_c) = (fix.sm.snapshot()?, fix.sm.last_applied().unwrap(), store.backend_identity().as_hex().to_owned(), src_pool.get().await?);
        let (ev_seq, uname) = (snap.body.next_event_seq.saturating_sub(1) as i64, format!("u{}", &fix.tenant.simple().to_string()[..12]));
        src_c.batch_execute(&format!(
            "INSERT INTO users(id,username) VALUES('{t}','{uname}');
             INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format,transition_state) VALUES('{r}','{t}','paired-demo','provisioning','pg_refstore','sha256','stable');
             INSERT INTO ref_store_core_gates(repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision,pack_mode) VALUES('{r}','{t}','sha256','{h}',2,3,'refs/heads/main',2,'metadata_only');
             INSERT INTO ref_store_core_protocol_repos(repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,decision_required,roots_revision) VALUES('{r}','{t}','sha256','{h}',2,3,TRUE,0);
             INSERT INTO ref_store_serving_repositories(repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,state) VALUES('{r}','{t}','paired-demo','sha256','{h}',2,3,'{backend}','pending');
             UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id='{r}';
             UPDATE repositories SET state='ready' WHERE id='{r}';
             INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES('{r}','refs/heads/main','{c}',2);
             INSERT INTO ref_cas_projection_cursors(group_id,history_incarnation,group_epoch,applied_event_seq,applied_log_index,applied_log_term,stream_state) VALUES(1,'{h}',3,{ev_seq},{idx},{term},'active');",
            t = fix.tenant, r = fix.repo, h = fix.history, c = fix.commit, idx = applied.index - 1, term = applied.term
        )).await?;

        assert!(matches!(capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dir.path().join("p0"), fix.artifacts.clone())).await.unwrap_err(), PairedBackupError::DeleterNotFenced(_)));
        freeze_pg_deleter(&**src_c, "paired-backup-it").await?;
        assert!(matches!(capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dir.path().join("p1"), fix.artifacts.clone())).await.unwrap_err(), PairedBackupError::CutpointSkew(_)));
        src_c.execute("UPDATE ref_cas_projection_cursors SET applied_log_index=$1 WHERE group_id=1 AND history_incarnation=$2", &[&(applied.index as i64), &fix.history]).await?;

        let dest = dir.path().join("pg-archive");
        let manifest = capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dest, fix.artifacts.clone())).await?;
        let (mut dst_c, scope) = (dst_pool.get().await?, RestoreTargetScope { expected_tenant_id: Some(fix.tenant), expected_repository_id: Some(fix.repo), expected_backend_identity: Some(backend) });
        let (out, _, _) = restore_new_incarnation_with_pg(&dest, &dir.path().join("dst-work"), &store, &mut dst_c, &scope, dl()).await?;
        let inc = &out.incarnation;
        let row = dst_c.query_one("SELECT a.authority_id, a.remote_delete_fenced, c.incarnation, g.history_incarnation, sr.state, rr.root_kind FROM pando_storage_authorities a, cluster_authority c, ref_store_core_gates g, ref_store_serving_repositories sr, pando_retention_roots rr WHERE a.singleton=true AND c.singleton=true AND g.repository_id=$1 AND sr.repository_id=$1 AND rr.repository_id=$1", &[&fix.repo]).await?;
        ensure!(row.get::<_, Uuid>(0) == inc.new_storage_authority_id && !row.get::<_, bool>(1) && row.get::<_, Uuid>(2) == inc.new_cluster_incarnation && row.get::<_, Uuid>(3) == inc.new_history_incarnation && row.get::<_, String>(4) == "ready" && row.get::<_, String>(5) == "backup_snapshot");

        let g_ok = wticket(inc.new_cluster_incarnation, inc.new_history_incarnation, inc.new_authority_epoch, inc.new_group_epoch, inc.new_authz_floor);
        let d_ok = dticket(inc.new_cluster_incarnation, inc.new_storage_authority_id, inc.new_storage_generation, inc.new_deleter_epoch);
        verify_pg_live_incarnation(&dst_c, fix.repo, &g_ok, Some(&d_ok)).await?;
        let sc = &manifest.pg_cutpoint;
        let g_old = wticket(sc.source_cluster_incarnation, fix.history, 2, 3, 5);
        assert!(verify_pg_live_incarnation(&dst_c, fix.repo, &g_old, None).await.is_err());
        let d_old = dticket(sc.source_cluster_incarnation, sc.source_storage_authority_id, 1, 7);
        assert!(matches!(verify_pg_live_incarnation(&dst_c, fix.repo, &g_ok, Some(&d_old)).await.unwrap_err(), PairedBackupError::StaleDeleterRefused(_)));
        Ok(())
    }.await;
    if let Ok(adm) = admin.get().await {
        let _ = adm
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {src_s} CASCADE; DROP SCHEMA IF EXISTS {dst_s} CASCADE"))
            .await;
    }
    res
}
