//! Shared versioned LoopbackS3 + real OpenDAL S3 + stock Git harness for Safe GC (#122).

use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Instant,
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::Response,
};
use bytes::Bytes;
use rootyard::{
    blob_store::{BlobLocator, config::BlobProfile, opendal::BlobStore},
    storage_lifecycle::safe_gc::{
        anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState},
        domain::{AuthorityRecord, BlobLocatorRecord},
        model::{
            GcMode, GlobalHoldEntry, GlobalHoldState, LiveRefRoot, PairedCursorReconciliation,
            ProducerReconciliationEntry, RetentionProducer, SafeGcObjectFormat, SourceFreshness,
        },
        provider_delete::OpenDalS3GcProvider,
        quiescence::ReaderLeaseRegistry,
        refcas_cut::RefCasReconciledCut,
        store::{SafeGcRepoSnapshot, ServingPackRecord},
    },
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub struct StoredS3Object {
    pub bytes: Vec<u8>,
    pub etag: String,
    pub version_id: String,
}

#[derive(Default)]
pub struct S3State {
    pub objects: Mutex<BTreeMap<String, StoredS3Object>>,
    pub fail_delete_substring: Mutex<Option<String>>,
    pub replace_same_len_on_head_substring: Mutex<Option<String>>,
    pub corrupt_next_put: AtomicBool,
    pub next_version_seq: AtomicUsize,
    pub put_requests: AtomicUsize,
    pub head_requests: AtomicUsize,
    pub delete_requests: AtomicUsize,
    pub conditional_delete_requests: AtomicUsize,
    pub unconditional_delete_rejections: AtomicUsize,
}

pub struct LoopbackS3 {
    pub endpoint: String,
    pub state: Arc<S3State>,
}

static S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn compute_etag(data: &[u8]) -> String {
    format!("\"{}\"", &hex::encode(Sha256::digest(data))[..32])
}

fn mint_version_id(seq: usize, data: &[u8]) -> String {
    format!("v1-{seq}-{}", &hex::encode(Sha256::digest(data))[..12])
}

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        S3.get_or_init(|| {
            let state = Arc::new(S3State::default());
            let srv = Arc::clone(&state);
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
            l.set_nonblocking(true).expect("nonblocking");
            let port = l.local_addr().expect("addr").port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let tl = tokio::net::TcpListener::from_std(l).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(tl, Router::new().fallback(handle_s3).with_state(srv)).await;
                });
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), state }
        })
    }

    fn key(loc: &BlobLocator) -> String {
        format!("safegc-test-bucket/safegc-it/{}", loc.path())
    }

    pub fn env_pairs(&self) -> Vec<(String, Option<std::ffi::OsString>)> {
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=safegc-test-bucket REGION=us-east-1 ROOT=safegc-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=3 MAX_OBJECT_BYTES=8388608";
        let mut pairs: Vec<(String, Option<std::ffi::OsString>)> = spec
            .split(' ')
            .map(|s| {
                let (k, v) = s.split_once('=').unwrap();
                (format!("ROOTYARD_BLOB_{k}"), Some(v.into()))
            })
            .collect();
        pairs.extend([
            ("ROOTYARD_BLOB_ENDPOINT".into(), Some(self.endpoint.as_str().into())),
            ("ROOTYARD_BLOB_KEYRING_DIR".into(), None),
        ]);
        pairs
    }

    fn with_blob_env<T>(&self, extra: &[(&str, Option<&str>)], f: impl FnOnce() -> Result<T>) -> Result<T> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut pairs = self.env_pairs();
        for &(k, v) in extra {
            pairs.push((k.to_owned(), v.map(Into::into)));
        }
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.clone(), std::env::var_os(k))).collect();
        let apply = |items: &[(String, Option<std::ffi::OsString>)]| unsafe {
            for (k, v) in items {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        };
        apply(&pairs);
        let out = f();
        apply(&saved);
        out
    }

    pub fn open_store_and_provider(&self) -> Result<(BlobStore, OpenDalS3GcProvider)> {
        self.with_blob_env(&[], || {
            let store = BlobStore::open(BlobProfile::from_env()?)?;
            let provider = OpenDalS3GcProvider::open_from_env(&store)?;
            Ok((store, provider))
        })
    }

    pub fn has_key(&self, loc: &BlobLocator) -> bool {
        self.state.objects.lock().unwrap().contains_key(&Self::key(loc))
    }

    pub fn get_stored(&self, loc: &BlobLocator) -> Option<StoredS3Object> {
        self.state.objects.lock().unwrap().get(&Self::key(loc)).cloned()
    }

    pub fn restore_stored(&self, loc: &BlobLocator, obj: StoredS3Object) {
        self.state.objects.lock().unwrap().insert(Self::key(loc), obj);
    }

    pub fn overwrite_same_length(&self, loc: &BlobLocator, fill: u8) -> StoredS3Object {
        let mut guard = self.state.objects.lock().unwrap();
        let cur = guard.get(&Self::key(loc)).expect("existing object").clone();
        let mut new_bytes = vec![fill; cur.bytes.len()];
        if new_bytes == cur.bytes && !new_bytes.is_empty() {
            new_bytes[0] ^= 0x5a;
        }
        let seq = self.state.next_version_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let next = StoredS3Object {
            etag: compute_etag(&new_bytes),
            version_id: mint_version_id(seq, &new_bytes),
            bytes: new_bytes,
        };
        guard.insert(Self::key(loc), next.clone());
        next
    }

    pub fn request_totals(&self) -> (usize, usize, usize) {
        (
            self.state.put_requests.load(Ordering::SeqCst),
            self.state.head_requests.load(Ordering::SeqCst),
            self.state.delete_requests.load(Ordering::SeqCst),
        )
    }
}

fn parse_query_version_id(u: &Uri) -> Option<String> {
    u.query()?.split('&').find_map(|kv| kv.strip_prefix("versionId=")).map(str::to_owned)
}

async fn handle_s3(State(st): State<Arc<S3State>>, m: Method, u: Uri, hdrs: HeaderMap, b: Bytes) -> Response {
    let key = u.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONNECTION, "close")
            .body(Body::from("<ListBucketResult/>"))
            .unwrap();
    }
    let query_vid = parse_query_version_id(&u);
    let if_match_hdr = hdrs.get(header::IF_MATCH).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let mut content_range: Option<String> = None;
    let mut resp_vid: Option<String> = None;

    let (status, tag, len, body) = match m {
        Method::PUT => {
            st.put_requests.fetch_add(1, Ordering::SeqCst);
            let mut data = b.to_vec();
            if st.corrupt_next_put.swap(false, Ordering::SeqCst) && !data.is_empty() {
                let mid = data.len() / 2;
                data[mid] ^= 0xff;
            }
            let seq = st.next_version_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let tag = compute_etag(&data);
            let vid = mint_version_id(seq, &data);
            resp_vid = Some(vid.clone());
            st.objects.lock().unwrap().insert(key, StoredS3Object { bytes: data, etag: tag.clone(), version_id: vid });
            (StatusCode::OK, Some(tag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => {
            if m == Method::HEAD {
                st.head_requests.fetch_add(1, Ordering::SeqCst);
            }
            let found = st.objects.lock().unwrap().get(&key).cloned();
            match found {
                Some(obj) => {
                    if query_vid.as_deref().is_some_and(|qv| qv != obj.version_id) {
                        (StatusCode::NOT_FOUND, None, 0, Body::empty())
                    } else if if_match_hdr.as_deref().is_some_and(|im| im != obj.etag) {
                        (StatusCode::PRECONDITION_FAILED, None, 0, Body::empty())
                    } else {
                        if m == Method::HEAD {
                            let should_replace = st
                                .replace_same_len_on_head_substring
                                .lock()
                                .unwrap()
                                .as_ref()
                                .is_some_and(|pat| key.contains(pat.as_str()));
                            if should_replace {
                                *st.replace_same_len_on_head_substring.lock().unwrap() = None;
                                let mut alt = obj.bytes.clone();
                                if let Some(first) = alt.first_mut() {
                                    *first ^= 0xa5;
                                }
                                let seq = st.next_version_seq.fetch_add(1, Ordering::SeqCst) + 1;
                                let replaced = StoredS3Object {
                                    etag: compute_etag(&alt),
                                    version_id: mint_version_id(seq, &alt),
                                    bytes: alt,
                                };
                                st.objects.lock().unwrap().insert(key.clone(), replaced);
                            }
                        }
                        resp_vid = Some(obj.version_id);
                        let d = obj.bytes;
                        let tag = Some(obj.etag);
                        if m == Method::GET
                            && let Some((s_str, e_str)) = hdrs
                                .get(header::RANGE)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|r| r.strip_prefix("bytes="))
                                .and_then(|r| r.split_once('-'))
                            && let Ok(start) = s_str.parse::<usize>()
                            && start < d.len()
                        {
                            let end = e_str.parse::<usize>().unwrap_or(d.len() - 1).min(d.len() - 1);
                            let slice = d[start..=end].to_vec();
                            content_range = Some(format!("bytes {start}-{end}/{}", d.len()));
                            (StatusCode::PARTIAL_CONTENT, tag, slice.len(), Body::from(slice))
                        } else {
                            (
                                StatusCode::OK,
                                tag,
                                d.len(),
                                if m == Method::HEAD { Body::empty() } else { Body::from(d) },
                            )
                        }
                    }
                }
                None => (StatusCode::NOT_FOUND, None, 0, Body::empty()),
            }
        }
        Method::DELETE => {
            st.delete_requests.fetch_add(1, Ordering::SeqCst);
            let Some(req_vid) = query_vid else {
                st.unconditional_delete_rejections.fetch_add(1, Ordering::SeqCst);
                return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::empty()).unwrap();
            };
            let Some(req_etag) = if_match_hdr else {
                st.unconditional_delete_rejections.fetch_add(1, Ordering::SeqCst);
                return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::empty()).unwrap();
            };
            st.conditional_delete_requests.fetch_add(1, Ordering::SeqCst);
            let should_fail =
                st.fail_delete_substring.lock().unwrap().as_ref().is_some_and(|pat| key.contains(pat.as_str()));
            if should_fail {
                (StatusCode::SERVICE_UNAVAILABLE, None, 0, Body::empty())
            } else {
                let mut guard = st.objects.lock().unwrap();
                match guard.get(&key) {
                    None => (StatusCode::NOT_FOUND, None, 0, Body::empty()),
                    Some(cur) if cur.version_id != req_vid || cur.etag != req_etag => {
                        (StatusCode::PRECONDITION_FAILED, None, 0, Body::empty())
                    }
                    Some(_) => {
                        guard.remove(&key);
                        (StatusCode::NO_CONTENT, None, 0, Body::empty())
                    }
                }
            }
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    };
    let mut rb = Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::CONNECTION, "close");
    if let Some(t) = tag {
        rb = rb.header(header::ETAG, t);
    }
    if let Some(vid) = resp_vid {
        rb = rb.header("x-amz-version-id", vid);
    }
    if let Some(cr) = content_range {
        rb = rb.header(header::CONTENT_RANGE, cr);
    }
    rb.body(body).unwrap()
}

pub fn git_cmd(repo: &Path, args: &[&str], stdin_data: Option<&str>) -> Result<String> {
    let null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let cfg = "core.hooksPath=/dev/null gc.auto=0 gc.autoDetach=false maintenance.auto=0 maintenance.autoDetach=false";
    let env_spec = "GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=safegc GIT_AUTHOR_EMAIL=safegc@example.com GIT_COMMITTER_NAME=safegc GIT_COMMITTER_EMAIL=safegc@example.com";
    let mut cmd = Command::new("git");
    cmd.args(cfg.split(' ').flat_map(|c| ["-c", c]))
        .args(["--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs(env_spec.split(' ').map(|s| s.split_once('=').unwrap()))
        .envs([("GIT_CONFIG_SYSTEM", null), ("GIT_CONFIG_GLOBAL", null)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn()?;
    if let Some(s) = stdin_data
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(s.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

pub async fn build_pack_via_opendal(
    provider: &OpenDalS3GcProvider,
    repo: &Path,
    stage: &Path,
    rev: &str,
    scope: (Uuid, Uuid, i64),
    deadline: Instant,
) -> Result<(BlobLocator, BlobLocatorRecord, BlobLocator, BlobLocatorRecord, String, Vec<String>)> {
    let raw_oids = git_cmd(repo, &["rev-list", "--objects", rev], None)?;
    let oids: Vec<String> = raw_oids.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_owned).collect();
    std::fs::create_dir_all(stage)?;
    let stdin_list = format!("{}\n", oids.join("\n"));
    let hash = git_cmd(repo, &["pack-objects", "-q", stage.join("p").to_str().unwrap()], Some(&stdin_list))?;
    let (pk, pk_rec) = provider
        .upload_pack_file(scope.0, scope.1, scope.2, "packs", &stage.join(format!("p-{hash}.pack")), deadline)
        .await?;
    let (ix, ix_rec) = provider
        .upload_pack_file(scope.0, scope.1, scope.2, "packs", &stage.join(format!("p-{hash}.idx")), deadline)
        .await?;
    let tip = git_cmd(repo, &["rev-parse", rev], None)?;
    Ok((pk, pk_rec, ix, ix_rec, tip, oids))
}

pub fn make_serving_record(
    reg: &mut AntiAbaKeyRegistry,
    auth: &AuthorityRecord,
    pl: BlobLocatorRecord,
    il: BlobLocatorRecord,
    oids: Vec<String>,
) -> ServingPackRecord {
    let scope = (auth.tenant_id, auth.repo_id, auth.history_id, 1);
    let mut mint =
        |role, sha: &str| reg.mint_immutable_key(scope, role, sha, KeyLifecycleState::ActiveServing).unwrap();
    ServingPackRecord {
        pack_id: Uuid::new_v4(),
        group_id: "g-main".into(),
        pack_key: mint("pack", &pl.sha256),
        idx_key: mint("idx", &il.sha256),
        pack_locator: pl,
        idx_locator: il,
        contained_oids: oids,
    }
}

pub fn build_snapshot(
    auth: AuthorityRecord,
    fmt: SafeGcObjectFormat,
    main_oid: String,
    active_packs: Vec<ServingPackRecord>,
    key_registry: AntiAbaKeyRegistry,
    refcas_cut: Option<RefCasReconciledCut>,
) -> SafeGcRepoSnapshot {
    let producers = RetentionProducer::ALL
        .iter()
        .map(|&p| ProducerReconciliationEntry {
            producer: p,
            freshness: SourceFreshness::Reconciled,
            observed_cursor_seq: 1,
            required_cursor_seq: 1,
            authority_epoch: 1,
            expected_authority_epoch: 1,
            root_oids: if p == RetentionProducer::Backup { vec![main_oid.clone()] } else { vec![] },
            pinned_pack_ids: vec![],
        })
        .collect();
    let idx = refcas_cut.as_ref().map_or(0, |c| c.sm_applied_log_index);
    SafeGcRepoSnapshot {
        authority: auth.clone(),
        object_format: fmt,
        gc_mode: GcMode::DisabledByDefault,
        live_refs: vec![LiveRefRoot {
            ref_name: "refs/heads/main".into(),
            target_oid: main_oid.clone(),
            version_seq: 1,
        }],
        active_packs,
        retired_packs: vec![],
        group_receipts: vec![],
        producers,
        global_holds: vec![GlobalHoldEntry {
            hold_id: Uuid::new_v4(),
            tenant_id: auth.tenant_id,
            repo_id: auth.repo_id,
            incarnation_epoch: 1,
            registered_seq: 1,
            state: GlobalHoldState::Active,
            protected_pack_ids: vec![],
            protected_oids: vec![main_oid],
            protected_physical_keys: vec![],
        }],
        in_flight_decisions: vec![],
        paired_cursors: PairedCursorReconciliation {
            pg_freshness: SourceFreshness::Reconciled,
            pg_applied_seq: 1,
            pg_required_seq: 1,
            refcas_freshness: SourceFreshness::Reconciled,
            refcas_applied_index: idx,
            refcas_required_index: idx,
            refcas_cut,
        },
        reader_leases: ReaderLeaseRegistry::new(),
        staged_uploads: vec![],
        key_registry,
        pending_delete: None,
        completed_batches: BTreeMap::new(),
        aborted_batches: BTreeMap::new(),
        reconciled_sources: Default::default(),
        audit_log: vec![],
    }
}
