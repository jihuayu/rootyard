//! Shared LoopbackS3 + 2-pack-pair + multi-group durable 3-voter WAL fixture for `#153` tests.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use deadpool_postgres::{Manager, Pool};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use rootyard::blob_store::capacity_contract::git_ops::{UploadScope, upload_pack_pair};
use rootyard::blob_store::{config::BlobProfile, opendal::BlobStore};
use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DeleterLeaseTicket, DurableFreezeBarrierProof, DurableRaftBackend, ExpectedGroupCursorCut, ExpectedPackPairSpec,
    PairedBackupError, PairedBackupManifest, PairedBackupRequest, PeerGroupBackupInput, PgCutpointProof,
    PgProjectionCursorCut, PgRepositoryRowProof, PreparedBlobArtifact, RepoBackupRegistrationSpec,
    SealedArchiveReceipt, TriPartyBackupCoordinator, WalSyncedRaftBackend, WriterGrantTicket, create_paired_backup,
    git_verify::seed_commit_pack, types::sha256_json_tagged,
};
use rootyard::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireCommitRefsRequest,
    WireGateInit,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
pub struct S3State {
    pub objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

pub struct LoopbackS3 {
    endpoint: String,
    pub state: Arc<S3State>,
}

pub struct S3EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(String, Option<std::ffi::OsString>)>,
}

impl Drop for S3EnvGuard {
    fn drop(&mut self) {
        for (k, old) in self.saved.drain(..) {
            unsafe {
                if let Some(v) = old {
                    std::env::set_var(&k, v);
                } else {
                    std::env::remove_var(&k);
                }
            }
        }
    }
}

impl Default for LoopbackS3 {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackS3 {
    pub fn apply_env(&self, bucket: &str) -> S3EnvGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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
        S3EnvGuard { _lock: lock, saved }
    }

    pub fn new() -> Self {
        let (state, lis) = (Arc::new(S3State::default()), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        lis.set_nonblocking(true).unwrap();
        let (port, srv, (tx, rx)) =
            (lis.local_addr().unwrap().port(), Arc::clone(&state), std::sync::mpsc::sync_channel(1));
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let (l, _) = (tokio::net::TcpListener::from_std(lis).unwrap(), tx.send(()));
                let router = axum::Router::new()
                    .fallback(handle_s3)
                    .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
                    .with_state(srv);
                let _ = axum::serve(l, router).await;
            });
        });
        rx.recv().unwrap();
        Self { endpoint: format!("http://127.0.0.1:{port}"), state }
    }

    pub fn open_store(&self, bucket: &str) -> Result<BlobStore> {
        let _env = self.apply_env(bucket);
        Ok(BlobStore::open(BlobProfile::from_env()?)?)
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

pub struct Fixture {
    pub repo: Uuid,
    pub tenant: Uuid,
    pub history: Uuid,
    pub authority: Uuid,
    pub cluster_inc: Uuid,
    pub pack_1_id: Uuid,
    pub pack_2_id: Uuid,
    pub commit: String,
    pub raft: WalSyncedRaftBackend,
    pub coord: TriPartyBackupCoordinator,
    pub barrier: DurableFreezeBarrierProof,
    pub pg_proof: PgCutpointProof,
    pub artifacts: Vec<PreparedBlobArtifact>,
}

pub struct PeerGroupFixture {
    pub group_id: i64,
    pub cut: ExpectedGroupCursorCut,
    pub raft: WalSyncedRaftBackend,
    pub barrier: DurableFreezeBarrierProof,
}

impl PeerGroupFixture {
    pub fn as_input(&self) -> PeerGroupBackupInput<'_> {
        PeerGroupBackupInput { group_id: self.group_id, freeze_barrier: &self.barrier, raft: &self.raft }
    }
}

pub fn dl() -> Instant {
    Instant::now() + Duration::from_secs(45)
}

pub fn wticket(c: Uuid, h: Uuid, ae: i64, ge: i64, az: i64) -> WriterGrantTicket {
    WriterGrantTicket {
        cluster_incarnation: c,
        history_incarnation: h,
        authority_epoch: ae,
        group_epoch: ge,
        authz_epoch: az,
    }
}

pub fn dticket(c: Uuid, a: Uuid, sg: i64, de: u64) -> DeleterLeaseTicket {
    DeleterLeaseTicket { cluster_incarnation: c, storage_authority_id: a, storage_generation: sg, deleter_epoch: de }
}

pub fn mk_req<'a>(
    f: &'a Fixture,
    s: &'a BlobStore,
    dir: &'a Path,
    dest: &'a Path,
    arts: Vec<PreparedBlobArtifact>,
    peer_groups: Vec<PeerGroupBackupInput<'a>>,
) -> PairedBackupRequest<'a> {
    PairedBackupRequest {
        backup_id: Uuid::new_v4(),
        group_id: 1,
        peer_groups,
        freeze_barrier: &f.barrier,
        raft: &f.raft,
        artifacts: arts,
        store: s,
        staging_dir: dir,
        destination: dest,
        deadline: dl(),
    }
}

pub async fn try_backup(
    f: &Fixture,
    s: &BlobStore,
    dir: &Path,
    name: &str,
    arts: Vec<PreparedBlobArtifact>,
    pg: Option<&PgCutpointProof>,
) -> std::result::Result<(PairedBackupManifest, SealedArchiveReceipt), PairedBackupError> {
    let dest = dir.join(name);
    create_paired_backup(mk_req(f, s, dir, &dest, arts, Vec::new()), pg).await
}

pub fn build_peer_group_fixture(
    dir: &Path,
    group_id: i64,
    group_epoch: i64,
    authority: Uuid,
) -> Result<PeerGroupFixture> {
    let (repo, tenant, issuer, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut raft = WalSyncedRaftBackend::open_group(dir.join(format!("peer-{group_id}.wal")), group_id, 1)?;
    let init = CoreGateInit::new(
        repo,
        tenant,
        GitObjectFormat::Sha256,
        history,
        2,
        group_epoch,
        RefName::branch("refs/heads/main")?,
    )?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 5,
    }))?;
    let upd = RefUpdate::new(
        RefName::new("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha256, &"b".repeat(64))?),
    );
    let req = CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        IssuerLane::new("peer")?,
        1,
        Uuid::new_v4(),
        GitObjectFormat::Sha256,
        history,
        2,
        group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![upd],
    )?;
    raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req),
        decision_id: None,
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick: 10,
    }))?;
    let mut coord = TriPartyBackupCoordinator::new(7, 4);
    let barrier = coord.freeze_peer_group_and_close(&mut raft, &[(repo, tenant, authority)], 15)?;
    let (snap, _) = raft.durable_state()?;
    let cut = ExpectedGroupCursorCut::from_verified_snapshot(group_id, &snap)?;
    Ok(PeerGroupFixture { group_id, cut, raft, barrier })
}

pub async fn build_fixture(store: &BlobStore, dir: &Path, fmt: GitObjectFormat) -> Result<Fixture> {
    let (u, pack_1_id, pack_2_id) = (Uuid::new_v4, Uuid::new_v4(), Uuid::new_v4());
    let (repo, tenant, issuer, history, authority, cluster_inc) = (u(), u(), u(), u(), u(), u());
    let seed_repo = dir.join("seed-git");
    let (c1, p1_path, i1_path) = seed_commit_pack(&seed_repo, fmt, "part1.txt", b"pack-pair-one\n", None)?;
    let (commit, p2_path, i2_path) = seed_commit_pack(&seed_repo, fmt, "part2.txt", b"pack-pair-two\n", Some(&c1))?;

    let scope = UploadScope { tenant_id: tenant, authority_id: authority, generation: 1 };
    let up1 = upload_pack_pair(store, scope, &p1_path, &i1_path, dl()).await?;
    let up2 = upload_pack_pair(store, scope, &p2_path, &i2_path, dl()).await?;

    let mut raft = WalSyncedRaftBackend::open_group(dir.join("raft.wal"), 1, 1)?;
    let init = CoreGateInit::new(repo, tenant, fmt, history, 2, 3, RefName::branch("refs/heads/main")?)?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 5,
    }))?;
    let upd = RefUpdate::new(
        RefName::new("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(fmt, &commit)?),
    );
    let req = CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        IssuerLane::new("pack")?,
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
    raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req),
        decision_id: None,
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick: 10,
    }))?;

    let expected_packs = vec![
        ExpectedPackPairSpec {
            pack_id: pack_1_id,
            pack_sha256: up1.pack_sha256.clone(),
            pack_bytes: up1.pack_length,
            idx_sha256: up1.idx_sha256.clone(),
            idx_bytes: up1.idx_length,
        },
        ExpectedPackPairSpec {
            pack_id: pack_2_id,
            pack_sha256: up2.pack_sha256.clone(),
            pack_bytes: up2.pack_length,
            idx_sha256: up2.idx_sha256.clone(),
            idx_bytes: up2.idx_length,
        },
    ];
    let mut coord = TriPartyBackupCoordinator::new(7, 4);
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
        expected_packs,
    };
    let barrier = coord.freeze_drain_and_register(&mut raft, &[spec], 15, true)?;
    let (snap, _) = raft.durable_state()?;
    let applied = snap.body.last_applied.unwrap();
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
        max_decision_scope_version: 20,
        pending_decisions_count: 0,
        pending_outbox_count: 0,
        projection_cursors: vec![PgProjectionCursorCut {
            group_id: 1,
            history_incarnation: history,
            group_epoch: 3,
            applied_event_seq: snap.body.next_event_seq as i64,
            applied_log_index: applied.index as i64,
            applied_log_term: applied.term as i64,
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
    let artifacts = [
        (pack_1_id, "pack", up1.pack_receipt.locator()),
        (pack_1_id, "idx", up1.idx_receipt.locator()),
        (pack_2_id, "pack", up2.pack_receipt.locator()),
        (pack_2_id, "idx", up2.idx_receipt.locator()),
    ]
    .into_iter()
    .map(|(pid, role, loc)| PreparedBlobArtifact {
        repository_id: repo,
        tenant_id: tenant,
        pack_id: pid,
        object_format: fmt,
        role: role.into(),
        locator: loc.clone(),
    })
    .collect();
    Ok(Fixture {
        repo,
        tenant,
        history,
        authority,
        cluster_inc,
        pack_1_id,
        pack_2_id,
        commit,
        raft,
        coord,
        barrier,
        pg_proof,
        artifacts,
    })
}

pub async fn setup_pg(admin: &Pool, url: &str, prefix: &str) -> Result<(Pool, String)> {
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
