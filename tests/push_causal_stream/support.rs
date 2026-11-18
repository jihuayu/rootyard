//! Real OpenDAL S3 + stock Git helper harness for `tests/push_causal_stream.rs` (#183).

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::Response,
};
use bytes::Bytes;
use rootyard::blob_store::{
    BlobLocator,
    capacity_contract::git_ops::{UploadScope, upload_pack_pair},
    config::BlobProfile,
    opendal::BlobStore,
};
use rootyard::namespace_service::push_causal_stream::PushAuthContext;
use rootyard::ref_store::contract::{IssuerLane, RequestDigest};
use rootyard::ref_store::core::contract::CommitMode;
use rootyard::ref_store::core::ref_version::*;
use rootyard::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use uuid::Uuid;

pub type S3Objects = Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>;

pub struct LoopbackS3 {
    pub endpoint: String,
    pub objects: S3Objects,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let objects = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
            let state = Arc::clone(&objects);
            let lis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            lis.set_nonblocking(true).unwrap();
            let port = lis.local_addr().unwrap().port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let tl = tokio::net::TcpListener::from_std(lis).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(tl, Router::new().fallback(handle_s3).with_state(state)).await;
                });
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), objects }
        })
    }

    pub fn key(loc: &BlobLocator) -> String {
        format!("push-causal-bucket/push-causal-it/{}", loc.path())
    }

    pub fn open_store(&self) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let ep = self.endpoint.as_str();
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=push-causal-bucket REGION=us-east-1 ROOT=push-causal-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=3 MAX_OBJECT_BYTES=16777216";
        let mut pairs: Vec<(String, Option<std::ffi::OsString>)> = spec
            .split(' ')
            .map(|s| s.split_once('=').unwrap())
            .map(|(k, v)| (format!("ROOTYARD_BLOB_{k}"), Some(v.into())))
            .collect();
        pairs.extend([("ROOTYARD_BLOB_ENDPOINT".into(), Some(ep.into())), ("ROOTYARD_BLOB_KEYRING_DIR".into(), None)]);
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.clone(), std::env::var_os(k))).collect();
        // SAFETY: serialized via ENV_LOCK across tests in this integration binary.
        let apply = |items: &[(String, Option<std::ffi::OsString>)]| unsafe {
            items.iter().for_each(
                |(k, v)| {
                    if let Some(x) = v { std::env::set_var(k, x) } else { std::env::remove_var(k) }
                },
            );
        };
        apply(&pairs);
        let res = BlobStore::open(BlobProfile::from_env()?);
        apply(&saved);
        Ok(res?)
    }
}

async fn handle_s3(State(objects): State<S3Objects>, method: Method, uri: Uri, body: Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return close_resp(StatusCode::OK, b"<ListBucketResult/>".to_vec());
    }
    match method {
        Method::PUT => {
            objects.lock().unwrap().insert(key, body.to_vec());
            close_resp(StatusCode::OK, Vec::new())
        }
        Method::GET | Method::HEAD => {
            if let Some(bytes) = objects.lock().unwrap().get(&key).cloned() {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, bytes.len())
                    .header(header::CONNECTION, "close")
                    .body(Body::from(if method == Method::HEAD { Vec::new() } else { bytes }))
                    .unwrap()
            } else {
                close_resp(StatusCode::NOT_FOUND, Vec::new())
            }
        }
        _ => close_resp(StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
    }
}

fn close_resp(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder().status(status).header(header::CONNECTION, "close").body(Body::from(body)).unwrap()
}

pub fn run_git(repo: &Path, args: &[&str], stdin_bytes: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C"]).arg(repo).args(args);
    cmd.env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG);
    cmd.stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(data) = stdin_bytes {
        child.stdin.take().unwrap().write_all(data)?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(out.stdout)
}

pub fn build_receive_wire(commands: &[(&str, &str, &str)], caps: &str, pack: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for (idx, (old, new, ref_name)) in commands.iter().enumerate() {
        let line =
            if idx == 0 { format!("{old} {new} {ref_name}\0{caps}\n") } else { format!("{old} {new} {ref_name}\n") };
        wire.extend_from_slice(format!("{:04x}", line.len() + 4).as_bytes());
        wire.extend_from_slice(line.as_bytes());
    }
    wire.extend_from_slice(b"0000");
    wire.extend_from_slice(pack);
    wire
}

pub fn mk_commit(work: &Path, file: &str, body: &str, msg: &str) -> Result<String> {
    std::fs::write(work.join(file), body)?;
    run_git(work, &["add", file], None)?;
    run_git(work, &["-c", "user.name=p", "-c", "user.email=p@e.test", "commit", "-m", msg], None)?;
    Ok(String::from_utf8(run_git(work, &["rev-parse", "HEAD"], None)?)?.trim().to_owned())
}

pub struct VersionGraphEntry {
    pub node: CausalVersionNode,
    pub digest_hex: String,
}

pub struct BaseVersionSpec<'a> {
    pub realm: RefVersionRealm,
    pub tenant: Uuid,
    pub repo: Uuid,
    pub seq: i64,
    pub oid_hex: &'a str,
    pub parent_v: Option<VersionId>,
    pub deps: Vec<VersionId>,
    pub pack_id: Uuid,
    pub reg_id: Uuid,
    pub pack_len: u64,
    pub backend_hex: &'a str,
    pub provider: &'a str,
}

pub fn build_base_version(s: BaseVersionSpec<'_>) -> VersionGraphEntry {
    let op_id = Uuid::new_v4();
    let ref_name = RefName::branch("refs/heads/main").unwrap();
    let oid = GitOid::parse(s.realm.object_format(), s.oid_hex).unwrap();
    let pack_digest = RequestDigest::of("pack", &[s.oid_hex.as_bytes(), &s.seq.to_be_bytes()]);
    let pentry = PackSetEntry::new(s.pack_id, s.reg_id, pack_digest).unwrap();
    let intent = RefVersionIntent::new(
        ref_name.clone(),
        RefVersionKind::Publish,
        s.parent_v.map_or(RefPrecondition::Absent, |_| RefPrecondition::Present(oid)),
        s.parent_v.map_or(BaseRequestSelector::ExplicitAbsent, BaseRequestSelector::Present),
        RefTarget::Oid(oid),
    );
    let op_in = OperationDigestInput::new(
        s.realm,
        s.tenant,
        Uuid::new_v4(),
        IssuerLane::new("push").unwrap(),
        s.seq,
        op_id,
        s.seq,
        RequestDigest::of("g", &[b"1"]),
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![intent],
        RequestDigest::of("m", &[b"1"]),
        vec![],
    );
    let op_dig = operation_digest(&op_in).unwrap();
    let vid = derive_candidate_version_id(&op_in, op_dig, &ref_name, s.parent_v.map(|_| 1u64)).unwrap();
    let cs = compute_commit_set_id(&CommitSetInput::new(
        s.realm,
        s.seq,
        op_id,
        op_dig,
        vec![CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(oid))],
        CommitSetHead::Absent,
    ))
    .unwrap();
    let rec = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm: s.realm,
        ref_name,
        ref_generation: if s.parent_v.is_some() { 2 } else { 1 },
        operation_id: op_id,
        operation_digest: op_dig,
        authority_seq: s.seq,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(oid),
        base_version_id: s.parent_v,
        object_deps: s.deps,
        pack_set_digest: compute_pack_set_digest(&[pentry]).unwrap(),
        commit_set_id: cs,
    })
    .unwrap();
    let vpack =
        VerifiedClosurePack::new(pentry, s.tenant, s.repo, s.provider, s.backend_hex, s.pack_len.max(2), 2).unwrap();
    VersionGraphEntry {
        node: CausalVersionNode { record: rec, own_packs: vec![vpack] },
        digest_hex: pack_digest.as_hex(),
    }
}

pub fn active_auth(actor: Uuid, allow_force: bool) -> PushAuthContext {
    PushAuthContext {
        actor_id: actor,
        token_scope_id: Some(Uuid::new_v4()),
        session_scope_id: Some(Uuid::new_v4()),
        lease_id: Some(Uuid::new_v4()),
        lease_expires_at_ms: Some(100_000),
        now_ms: 1_000,
        principal_authz_epoch: 10,
        min_required_authz_epoch: 1,
        write_authorized: true,
        allow_force_push: allow_force,
        allow_branch_delete: true,
        protected_branches: BTreeSet::new(),
        visible_refs: BTreeSet::new(),
    }
}

pub fn dl() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

pub type UploadedPair = (BlobLocator, String, u64, BlobLocator, String, u64);

pub async fn upload_git_pack(
    work: &Path,
    bare: &Path,
    revs: &str,
    name: &str,
    store: &BlobStore,
    tenant: Uuid,
    repo: Uuid,
) -> Result<UploadedPair> {
    let raw = run_git(work, &["pack-objects", "--revs", "--stdout"], Some(revs.as_bytes()))?;
    let p_path = bare.join(format!("objects/pack/{name}.pack"));
    let idx_path = bare.join(format!("objects/pack/{name}.idx"));
    run_git(bare, &["index-pack", "--stdin", "--strict", p_path.to_str().unwrap()], Some(&raw))?;
    let up = upload_pack_pair(
        store,
        UploadScope { tenant_id: tenant, authority_id: repo, generation: 1 },
        &p_path,
        &idx_path,
        dl(),
    )
    .await
    .unwrap();
    Ok((
        up.pack_receipt.locator().clone(),
        up.pack_sha256,
        up.pack_length,
        up.idx_receipt.locator().clone(),
        up.idx_sha256,
        up.idx_length,
    ))
}
