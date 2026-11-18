//! Real OpenDAL S3 + BlobStore + stock Git (SHA-1 & SHA-256) Safe GC integration tests (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::Response,
};
use bytes::Bytes;
use rootyard::{
    blob_store::{config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore, *},
    storage_lifecycle::safe_gc::{
        SafeGcError, anti_aba::*, compaction::*, domain::*, executor::*, model::*, proof::*, store::*,
    },
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

type S3Map = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct LoopbackS3 {
    endpoint: String,
    objects: S3Map,
}

static S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    fn shared() -> &'static Self {
        S3.get_or_init(|| {
            let objects = Arc::new(Mutex::new(BTreeMap::new()));
            let state = Arc::clone(&objects);
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
            l.set_nonblocking(true).expect("nonblocking");
            let port = l.local_addr().expect("addr").port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                rt.block_on(async move {
                    let tl = tokio::net::TcpListener::from_std(l).unwrap();
                    let _ = tx.send(());
                    let _ = axum::serve(tl, Router::new().fallback(handle_s3).with_state(state)).await;
                });
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), objects }
        })
    }

    fn key(loc: &BlobLocator) -> String {
        format!("safegc-test-bucket/safegc-it/{}", loc.path())
    }

    fn open_store(&self) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let ep = self.endpoint.as_str();
        let spec = "DRIVER=opendal SERVICE=s3 BUCKET=safegc-test-bucket REGION=us-east-1 ROOT=safegc-it ACCESS_KEY_ID=test-ak SECRET_ACCESS_KEY=test-sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=3 MAX_OBJECT_BYTES=8388608";
        let mut pairs: Vec<(String, Option<std::ffi::OsString>)> = spec
            .split(' ')
            .map(|s| {
                let (k, v) = s.split_once('=').unwrap();
                (format!("ROOTYARD_BLOB_{k}"), Some(v.into()))
            })
            .collect();
        pairs.extend([("ROOTYARD_BLOB_ENDPOINT".into(), Some(ep.into())), ("ROOTYARD_BLOB_KEYRING_DIR".into(), None)]);
        let saved: Vec<_> = pairs.iter().map(|(k, _)| (k.clone(), std::env::var_os(k))).collect();
        let set_env = |items: &[(String, Option<std::ffi::OsString>)]| unsafe {
            items
                .iter()
                .for_each(|(k, v)| if let Some(x) = v { std::env::set_var(k, x) } else { std::env::remove_var(k) });
        };
        set_env(&pairs);
        let res = BlobStore::open(BlobProfile::from_env()?);
        set_env(&saved);
        Ok(res?)
    }

    fn has_key(&self, loc: &BlobLocator) -> bool {
        self.objects.lock().unwrap().contains_key(&Self::key(loc))
    }
}

async fn handle_s3(State(objs): State<S3Map>, m: Method, u: Uri, b: Bytes) -> Response {
    let key = u.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONNECTION, "close")
            .body(Body::from("<ListBucketResult/>"))
            .unwrap();
    }
    let etag = |d: &[u8]| format!("\"{}\"", &hex::encode(Sha256::digest(d))[..32]);
    let (st, tag, len, body) = match m {
        Method::PUT => {
            let tag = etag(&b);
            objs.lock().unwrap().insert(key, b.to_vec());
            (StatusCode::OK, Some(tag), 0, Body::empty())
        }
        Method::HEAD | Method::GET => match objs.lock().unwrap().get(&key).cloned() {
            Some(d) => {
                (StatusCode::OK, Some(etag(&d)), d.len(), if m == Method::HEAD { Body::empty() } else { Body::from(d) })
            }
            None => (StatusCode::NOT_FOUND, None, 0, Body::empty()),
        },
        Method::DELETE => {
            objs.lock().unwrap().remove(&key);
            (StatusCode::NO_CONTENT, None, 0, Body::empty())
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, None, 0, Body::empty()),
    };
    let mut rb = Response::builder()
        .status(st)
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::CONNECTION, "close");
    if let Some(t) = tag {
        rb = rb.header(header::ETAG, t);
    }
    rb.body(body).unwrap()
}

fn put_path_to_s3(
    tenant_id: Uuid,
    repo_id: Uuid,
    blob_gen: i64,
    p: &Path,
    flip: bool,
) -> Result<BlobLocator, SafeGcError> {
    let mut bytes = std::fs::read(p).map_err(|e| SafeGcError::Io(e.to_string()))?;
    let sha = hex::encode(Sha256::digest(&bytes));
    let loc = BlobLocator::new(tenant_id, repo_id, blob_gen, Uuid::new_v4(), "packs", &sha, bytes.len() as u64)?;
    if flip && !bytes.is_empty() {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
    }
    let s3 = LoopbackS3::shared();
    s3.objects.lock().unwrap().insert(LoopbackS3::key(&loc), bytes);
    Ok(loc)
}

struct TestS3Uploader {
    corrupt_pack: bool,
}

impl SafeGcCompactionUploader for TestS3Uploader {
    fn upload_compacted_pair<'a>(
        &'a self,
        _store: &'a BlobStore,
        scope: (Uuid, Uuid, i64),
        keys: (PhysicalBlobKey, PhysicalBlobKey),
        paths: (&'a Path, &'a Path),
        _deadline: Instant,
    ) -> SafeGcFuture<'a, UploadedCompactionPair> {
        Box::pin(async move {
            let pk = put_path_to_s3(scope.0, scope.1, scope.2, paths.0, self.corrupt_pack)?;
            let ix = put_path_to_s3(scope.0, scope.1, scope.2, paths.1, false)?;
            Ok(UploadedCompactionPair {
                pack_locator: BlobLocatorRecord::from_locator(&pk),
                idx_locator: BlobLocatorRecord::from_locator(&ix),
                pack_key: keys.0,
                idx_key: keys.1,
            })
        })
    }
}

struct S3FencedDeleteSink;

impl SafeGcDeleteBackend for S3FencedDeleteSink {
    fn delete_authorized<'a>(&'a self, ticket: &'a DeleteAuthorizationTicket, _dl: Instant) -> SafeGcFuture<'a, ()> {
        Box::pin(async move {
            if ticket.ticket_digest().len() != 64 || ticket.physical_key().is_empty() {
                return Err(SafeGcError::StaleDeleterFenced("invalid ticket"));
            }
            if let Some(loc_rec) = ticket.locator() {
                LoopbackS3::shared().objects.lock().unwrap().remove(&LoopbackS3::key(&loc_rec.to_locator()?));
            }
            Ok(())
        })
    }
}

fn git_cmd(repo: &Path, args: &[&str], stdin_data: Option<&str>) -> Result<String> {
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

fn build_pack_for_range(
    repo: &Path,
    stage: &Path,
    rev: &str,
    tenant: Uuid,
    repo_id: Uuid,
    blob_gen: i64,
) -> Result<(BlobLocator, BlobLocator, String, Vec<String>)> {
    let raw_oids = git_cmd(repo, &["rev-list", "--objects", rev], None)?;
    let oids: Vec<String> = raw_oids.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_owned).collect();
    std::fs::create_dir_all(stage)?;
    let stdin_list = format!("{}\n", oids.join("\n"));
    let hash = git_cmd(repo, &["pack-objects", "-q", stage.join("p").to_str().unwrap()], Some(&stdin_list))?;
    let pk = put_path_to_s3(tenant, repo_id, blob_gen, &stage.join(format!("p-{hash}.pack")), false)?;
    let ix = put_path_to_s3(tenant, repo_id, blob_gen, &stage.join(format!("p-{hash}.idx")), false)?;
    let tip = git_cmd(repo, &["rev-parse", rev], None)?;
    Ok((pk, ix, tip, oids))
}

fn make_serving_record(
    reg: &mut AntiAbaKeyRegistry,
    auth: &AuthorityRecord,
    pl: &BlobLocator,
    il: &BlobLocator,
    oids: Vec<String>,
) -> ServingPackRecord {
    let scope = (auth.tenant_id, auth.repo_id, auth.history_id, 1);
    let mut mint = |role, l: &BlobLocator| {
        reg.mint_immutable_key(scope, role, l.sha256(), KeyLifecycleState::ActiveServing).unwrap()
    };
    ServingPackRecord {
        pack_id: Uuid::new_v4(),
        group_id: "g-main".into(),
        pack_key: mint("pack", pl),
        idx_key: mint("idx", il),
        pack_locator: BlobLocatorRecord::from_locator(pl),
        idx_locator: BlobLocatorRecord::from_locator(il),
        contained_oids: oids,
    }
}

async fn compact_once(
    authority: &DurableSafeGcAuthority,
    store: &BlobStore,
    views: &DisposableViewRoot,
    corrupt_pack: bool,
    deadline: Instant,
) -> Result<SafeGcCompactionResult, SafeGcError> {
    let req = SafeGcCompactionRequest {
        op_id: Uuid::new_v4(),
        group_id: "g-main",
        blob_generation: 1,
        target_pack_ids: vec![],
        view_root: views,
        deadline,
        fault: CompactionFault::None,
    };
    execute_two_phase_compaction(authority, store, &TestS3Uploader { corrupt_pack }, req).await
}

fn build_sweep_req(auth: &AuthorityRecord, proof: DeletionProof, deadline: Instant) -> SafeGcSweepRequest {
    SafeGcSweepRequest {
        batch_id: Uuid::new_v4(),
        deleter_incarnation_id: auth.incarnation_id,
        deleter_incarnation_epoch: 1,
        deleter_lease_epoch: 1,
        proof,
        deadline,
        fault: DeleteFaultHook::None,
    }
}

fn build_snapshot(
    auth: AuthorityRecord,
    fmt: SafeGcObjectFormat,
    main_oid: String,
    active_packs: Vec<ServingPackRecord>,
    key_registry: AntiAbaKeyRegistry,
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
            refcas_applied_index: 1,
            refcas_required_index: 1,
        },
        key_registry,
        pending_delete: None,
        completed_batches: BTreeMap::new(),
        audit_log: vec![],
    }
}

#[tokio::test]
async fn real_s3_and_git_two_phase_compaction_retention_and_safe_gc_both_formats() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let store = s3.open_store()?;
    let dl = Instant::now() + Duration::from_secs(60);

    for (fmt, distributed) in [(SafeGcObjectFormat::Sha1, false), (SafeGcObjectFormat::Sha256, true)] {
        let dir = TempDir::new()?;
        let views = DisposableViewRoot::open(&dir.path().join("views"), 8, 64 * 1024 * 1024, Duration::from_secs(120))?;
        let git_repo = dir.path().join("src.git");
        std::fs::create_dir_all(&git_repo)?;
        git_cmd(&git_repo, &["init", "--object-format", fmt.as_str()], None)?;

        let auth = AuthorityRecord {
            tenant_id: Uuid::new_v4(),
            repo_id: Uuid::new_v4(),
            history_id: Uuid::new_v4(),
            incarnation_id: Uuid::new_v4(),
            incarnation_epoch: 1,
            membership_generation: 1,
            live_ref_seq: 1,
            lease_epoch: 1,
        };

        std::fs::write(git_repo.join("app.txt"), b"v1")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "live"], None)?;
        let (p1_loc, i1_loc, main_oid, p1_oids) =
            build_pack_for_range(&git_repo, &dir.path().join("s1"), "HEAD", auth.tenant_id, auth.repo_id, 1)?;

        // Orphan branch NOT referenced by any live ref or producer pin!
        git_cmd(&git_repo, &["checkout", "--orphan", "temp_orphan"], None)?;
        git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
        std::fs::remove_file(git_repo.join("app.txt"))?;
        std::fs::write(git_repo.join("orphan.txt"), b"ephemeral")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
        let (p2_loc, i2_loc, _orphan_oid, p2_oids) =
            build_pack_for_range(&git_repo, &dir.path().join("s2"), "HEAD", auth.tenant_id, auth.repo_id, 1)?;

        let mut reg = AntiAbaKeyRegistry::new();
        let srv1 = make_serving_record(&mut reg, &auth, &p1_loc, &i1_loc, p1_oids.clone());
        let srv2 = make_serving_record(&mut reg, &auth, &p2_loc, &i2_loc, p2_oids.clone());
        let snap = build_snapshot(auth.clone(), fmt, main_oid.clone(), vec![srv1, srv2.clone()], reg);
        let authority = DurableSafeGcAuthority::open_with_journal(dir.path().join("journal.json"), Some(snap))?;

        // Phase 1 failure: corrupted S3 upload fails readback & keeps old closure active!
        assert!(compact_once(&authority, &store, &views, true, dl).await.is_err());
        assert_eq!(authority.snapshot().active_packs.len(), 2);

        // Clean compaction succeeds readback + CAS while leaving old S3 blobs untouched!
        let ok_compact = compact_once(&authority, &store, &views, false, dl).await?;
        assert!(s3.has_key(&p1_loc) && s3.has_key(&p2_loc));
        let new_pk_loc = ok_compact.publish.replacement_pack.to_locator()?;
        assert!(s3.has_key(&new_pk_loc));

        // BlobStore::delete directly stays permanently disabled!
        assert!(matches!(store.delete(&p2_loc, dl).await, Err(BlobError::DeleteDisabled)));
        let ro_backend = BlobStoreReadbackBackend { store: &store };
        let live_snap = authority.snapshot();
        let lane = if distributed {
            AuthorityLane::DistributedRefCas {
                ref_cas_authority_id: auth.repo_id,
                quorum_epoch: 1,
                raft_commit_index: 1,
                quorum_verified: true,
                global_hold_bridge_verified: true,
                global_hold_bridge_seq: 1,
                remote_backup_root_verified: true,
                remote_backup_root_epoch: 1,
                async_projection_only: false,
            }
        } else {
            AuthorityLane::SingleNodePg { pg_authority_id: auth.repo_id, pg_tx_seq: 1, local_quiesced: true }
        };
        let arm =
            SafeGcArmReceipt::seal(auth.tenant_id, auth.repo_id, auth.history_id, auth.incarnation_id, 1, true, lane)?;

        // Delete ONLY srv2 (orphan pack whose OIDs are unreachable from main/producers/hold).
        let overlap_set: BTreeSet<_> = p1_oids.iter().cloned().collect();
        assert!(p2_oids.iter().all(|o| !overlap_set.contains(o)));
        let proof = build_and_verify_deletion_proof(DeletionProofInputs {
            tenant_id: auth.tenant_id,
            repo_id: auth.repo_id,
            history_id: auth.history_id,
            object_format: fmt,
            incarnation_id: auth.incarnation_id,
            incarnation_epoch: 1,
            live_ref_seq: live_snap.authority.live_ref_seq,
            arm_receipt: arm.clone(),
            live_refs: live_snap.live_refs.clone(),
            producers: live_snap.producers.clone(),
            global_holds: live_snap.global_holds.clone(),
            in_flight_decisions: vec![],
            paired_cursors: live_snap.paired_cursors.clone(),
            group_receipts: live_snap.group_receipts.clone(),
            candidates: vec![CandidatePackTarget {
                pack_id: srv2.pack_id,
                group_id: "g-main".into(),
                physical_key: srv2.pack_key.object_path.clone(),
                object_sha256: srv2.pack_key.object_sha256.clone(),
                key_epoch: 1,
                contained_oids: srv2.contained_oids.clone(),
            }],
        })?;

        assert!(matches!(
            execute_safe_gc_sweep(&authority, &ro_backend, build_sweep_req(&auth, proof.clone(), dl)).await,
            Err(SafeGcError::DestructiveGcDisabledByDefault)
        ));

        authority.set_gc_mode(GcMode::ArmedDestructive(arm))?;
        let report = execute_safe_gc_sweep(&authority, &S3FencedDeleteSink, build_sweep_req(&auth, proof, dl)).await?;
        assert_eq!(report.deleted_keys, vec![srv2.pack_key.object_path]);
        assert!(!s3.has_key(&p2_loc));
        assert!(s3.has_key(&new_pk_loc));

        // Verify readback & fsck of surviving active pack on LoopbackS3 passes stock git cleanly!
        let verify_dir = dir.path().join("verify-surviving");
        let new_ix_loc = ok_compact.publish.replacement_idx.to_locator()?;
        let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
        std::fs::create_dir_all(pk_dst.parent().unwrap())?;
        git_cmd(&verify_dir, &["init", "--bare", "--object-format", fmt.as_str()], None)?;
        store.get_to_file(&new_pk_loc, &pk_dst, dl).await?;
        store.get_to_file(&new_ix_loc, &ix_dst, dl).await?;
        git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
        git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;

        let (re_pk, _) = authority.mint_compaction_keys(1, p2_loc.sha256(), i2_loc.sha256())?;
        assert_ne!(re_pk.object_path, srv2.pack_key.object_path);
    }
    Ok(())
}
