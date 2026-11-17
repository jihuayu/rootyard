//! Real stock Git (SHA-1 & SHA-256) + OpenDAL Loopback S3 integration tests for Issue #184.
use anyhow::{Result, ensure};
use axum::http::{Method, StatusCode, Uri, header};
use axum::{Router, body::Body, extract::State, response::Response};
use rootyard::blob_store::{BlobLocator, config::BlobProfile, disposable_view::DisposableViewRoot, opendal::BlobStore};
use rootyard::ref_store::contract::{IssuerLane, RequestDigest};
use rootyard::ref_store::core::CommitMode;
use rootyard::ref_store::ref_version::{pack_cover::*, *};
use rootyard::ref_store::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, path::*, process::*, sync::*, time::*};
use tempfile::TempDir;
use uuid::Uuid;

#[cfg(unix)]
const NULL_CFG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_CFG: &str = "NUL";

type S3Map = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;
type CovPair = (VerifiedClosurePack, CoverArtifactPair);
type CovMeta = (Vec<VersionId>, (i64, i64), Vec<CoverCommitLink>, Vec<Uuid>, CoverMembershipDigest);
static S3: OnceLock<(String, S3Map)> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn s3() -> &'static (String, S3Map) {
    S3.get_or_init(|| {
        let (objs, l): (S3Map, _) = (Default::default(), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        l.set_nonblocking(true).unwrap();
        let (port, st, (tx, rx)) = (l.local_addr().unwrap().port(), Arc::clone(&objs), mpsc::sync_channel(1));
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            rt.block_on(async move {
                let _ = tx.send(());
                let svc = Router::new().fallback(handle_s3).with_state(st);
                let _ = axum::serve(tokio::net::TcpListener::from_std(l).unwrap(), svc).await;
            });
        });
        rx.recv().unwrap();
        (format!("http://127.0.0.1:{port}"), objs)
    })
}

async fn handle_s3(State(objs): State<S3Map>, m: Method, uri: Uri, body: bytes::Bytes) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return Response::new(Body::from("<ListBucketResult/>"));
    }
    let rsp = |st, d: &[u8], b| {
        let et = format!("\"{}\"", &hex::encode(Sha256::digest(d))[..32]);
        Response::builder().status(st).header(header::CONTENT_LENGTH, d.len()).header(header::ETAG, et).body(b).unwrap()
    };
    if m == Method::PUT {
        let v = body.to_vec();
        objs.lock().unwrap().insert(key, v.clone());
        return rsp(StatusCode::OK, &v, Body::empty());
    }
    match objs.lock().unwrap().get(&key).cloned() {
        Some(d) => rsp(StatusCode::OK, &d, if m == Method::HEAD { Body::empty() } else { Body::from(d.clone()) }),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())
            .unwrap(),
    }
}

fn open_s3_store() -> Result<BlobStore> {
    let ((ep, _), _g) = (s3(), ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner()));
    let s = format!(
        "DRIVER=opendal SERVICE=s3 BUCKET=pc-b REGION=us-east-1 ROOT=r ACCESS_KEY_ID=ak SECRET_ACCESS_KEY=sk ENCRYPTION_MODE=provider-managed RETRY_MAX_TIMES=0 MAX_OBJECT_BYTES=8388608 ENDPOINT={ep}"
    );
    // SAFETY: serialized via ENV_LOCK; this integration test binary only targets Loopback S3.
    unsafe {
        for (k, v) in s.split(' ').filter_map(|p| p.split_once('=')) {
            std::env::set_var(format!("ROOTYARD_BLOB_{k}"), v);
        }
        std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR");
    }
    Ok(BlobStore::open(BlobProfile::from_env()?)?)
}

fn git_raw(repo: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let v = format!(
        "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL={NULL_CFG} GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@e GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@e"
    );
    let si = if stdin.is_some() { Stdio::piped() } else { Stdio::null() };
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args)
        .envs(v.split(' ').filter_map(|s| s.split_once('=')));
    let mut ch = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(si).spawn()?;
    if let Some(b) = stdin
        && let Some(mut s) = ch.stdin.take()
    {
        s.write_all(b)?;
    }
    let out = ch.wait_with_output()?;
    ensure!(out.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(out.stdout)
}
fn git_str(repo: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    Ok(String::from_utf8(git_raw(repo, args, stdin)?)?.trim().to_owned())
}

struct Env {
    _dir: TempDir,
    repo: PathBuf,
    views: DisposableViewRoot,
    store: BlobStore,
    realm: RefVersionRealm,
    graph: VersionGraph,
    index: CoverHierarchyIndex,
    ret: RetentionClassificationIndex,
    seq: i64,
    entries: Vec<PackSetEntry>,
}

impl Env {
    fn new(fmt: GitObjectFormat) -> Result<Self> {
        let (dir, u) = (TempDir::new()?, Uuid::new_v4);
        let repo = dir.path().join("src");
        std::fs::create_dir_all(&repo)?;
        git_str(&repo, &["init", &format!("--object-format={}", fmt.as_str()), "--initial-branch=main"], None)?;
        let views = DisposableViewRoot::open(&dir.path().join("views"), 8, 64 << 20, Duration::from_secs(120))?;
        let realm = RefVersionRealm::new(u(), u(), u(), AuthorityKind::Pg, 1, 0, 1, fmt);
        let mem = compute_cover_membership_digest(&realm, 1, &[])?;
        Ok(Self {
            _dir: dir,
            repo,
            views,
            store: open_s3_store()?,
            realm,
            graph: VersionGraph::new(),
            index: CoverHierarchyIndex::new(realm, mem)?,
            ret: RetentionClassificationIndex::new(),
            seq: 0,
            entries: Vec::new(),
        })
    }
    fn commit(&self, f: &str, body: &str) -> Result<GitOid> {
        std::fs::write(self.repo.join(f), body)?;
        git_str(&self.repo, &["add", f], None)?;
        git_str(&self.repo, &["commit", "-m", f], None)?;
        Ok(GitOid::parse(self.realm.object_format(), &git_str(&self.repo, &["rev-parse", "HEAD"], None)?)?)
    }
    fn upload(&self, pk: Vec<u8>, ix: Vec<u8>, pack_stem: String, delta_base_cover_ids: Vec<Uuid>) -> Result<CovPair> {
        let (ps, is, u) = (hex::encode(Sha256::digest(&pk)), hex::encode(Sha256::digest(&ix)), Uuid::new_v4);
        let (t, r) = (self.realm.tenant_id(), self.realm.repository_id());
        let (pack_locator, idx_locator) = (
            BlobLocator::new(t, r, 1, u(), "packs", &ps, pk.len() as u64)?,
            BlobLocator::new(t, r, 1, u(), "packs", &is, ix.len() as u64)?,
        );
        let (len, prov, id, is_thin_pack) = (
            pack_locator.length() + idx_locator.length(),
            self.store.provider().as_str(),
            self.store.backend_identity().as_hex(),
            !delta_base_cover_ids.is_empty(),
        );
        let (pk_k, ix_k) = (format!("pc-b/r/{}", pack_locator.path()), format!("pc-b/r/{}", idx_locator.path()));
        s3().1.lock().unwrap().extend([(pk_k, pk), (ix_k, ix)]);
        let e = PackSetEntry::new(u(), u(), RequestDigest::of("a", &[ps.as_bytes(), is.as_bytes()]))?;
        let vp = VerifiedClosurePack::new(e, t, r, prov, id, len, 2)?;
        Ok((vp, CoverArtifactPair { pack_stem, pack_locator, idx_locator, is_thin_pack, delta_base_cover_ids }))
    }
    fn pack(&self, revs: &str) -> Result<CovPair> {
        let d = TempDir::new()?;
        let p = d.path().join("pack");
        let h =
            git_str(&self.repo, &["pack-objects", "--revs", "--quiet", p.to_str().unwrap()], Some(revs.as_bytes()))?;
        let s = format!("pack-{h}");
        self.upload(
            std::fs::read(d.path().join(format!("{s}.pack")))?,
            std::fs::read(d.path().join(format!("{s}.idx")))?,
            s,
            vec![],
        )
    }
    fn cov(&self, tier: CoverTier, (pack, artifacts): CovPair, m: CovMeta) -> Result<CoverHierarchyRecord> {
        let (covered_versions, (min_authority_seq, max_authority_seq), covered_commits, input_cover_ids, md) = m;
        let (realm, g, ep, u) =
            (self.realm, self.index.membership_generation() + 1, self.index.compaction_epoch(), Uuid::new_v4);
        let inp = CoverHierarchyRecordInput {
            cover_id: u(),
            realm,
            tier,
            pack,
            artifacts,
            covered_versions,
            min_authority_seq,
            max_authority_seq,
            covered_commits,
            input_cover_ids,
            membership_generation: g,
            membership_digest: md,
            compaction_epoch: ep,
            worker_id: u(),
            operation_id: u(),
        };
        Ok(CoverHierarchyRecord::seal(inp)?)
    }
    fn step(
        &mut self,
        m: CommitMode,
        rn_s: &str,
        base: Option<&VersionRecord>,
        c: GitOid,
        parent_oids: Vec<GitOid>,
        p: CovPair,
        object_deps: Vec<VersionId>,
    ) -> Result<(VersionRecord, CoverHierarchyRecord)> {
        self.seq += 1;
        let (authority_seq, ref_name, operation_id, realm, u) =
            (self.seq, RefName::new(rn_s)?, Uuid::new_v4(), self.realm, Uuid::new_v4);
        let d = RequestDigest::of("g", &[&authority_seq.to_be_bytes()]);
        let ref_generation = base.map_or(1, |b| b.ref_generation() + 1);
        let (kind, target) = (RefVersionKind::Publish, RefTarget::Oid(c));
        let pre = match base.map(VersionRecord::target) {
            Some(RefTarget::Oid(o)) => RefPrecondition::Present(*o),
            _ => RefPrecondition::Absent,
        };
        let sel = base.map_or(BaseRequestSelector::ExplicitAbsent, |b| BaseRequestSelector::Present(b.version_id()));
        let intent = RefVersionIntent::new(ref_name.clone(), kind, pre, sel, target.clone());
        let op = OperationDigestInput::new(
            realm,
            u(),
            u(),
            IssuerLane::new("m")?,
            authority_seq,
            operation_id,
            authority_seq,
            d,
            m,
            HeadUpdate::Keep,
            vec![intent],
            d,
            vec![],
        );
        let operation_digest = operation_digest(&op)?;
        let version_id =
            derive_candidate_version_id(&op, operation_digest, &ref_name, base.map(VersionRecord::ref_generation))?;
        let ce = CommitSetVersionEntry::new(ref_name.clone(), version_id, kind, target.clone());
        let cs =
            CommitSetInput::new(realm, authority_seq, operation_id, operation_digest, vec![ce], CommitSetHead::Absent);
        let commit_set_id = compute_commit_set_id(&cs)?;
        let (base_version_id, pack_set_digest) =
            (base.map(VersionRecord::version_id), compute_pack_set_digest(&[*p.0.entry()])?);
        let v = VersionRecord::seal(VersionRecordInput {
            version_id,
            realm,
            ref_name,
            ref_generation,
            operation_id,
            operation_digest,
            authority_seq,
            kind,
            target,
            base_version_id,
            object_deps,
            pack_set_digest,
            commit_set_id,
        })?;
        self.graph.insert_active(CausalVersionNode { record: v.clone(), own_packs: vec![p.0.clone()] });
        self.entries.push(*p.0.entry());
        let mem = compute_cover_membership_digest(&realm, self.index.membership_generation() + 1, &self.entries)?;
        let ln = CoverCommitLink { commit_oid: c, parent_oids, version_id, authority_seq };
        let cov =
            self.cov(CoverTier::Delta, p, (vec![version_id], (authority_seq, authority_seq), vec![ln], vec![], mem))?;
        self.index.register_leaf_cover(cov.clone(), mem)?;
        Ok((v, cov))
    }
    fn push(
        &mut self,
        r: &str,
        base: Option<&VersionRecord>,
        bc: Option<GitOid>,
        f: &str,
        txt: &str,
        deps: Vec<VersionId>,
    ) -> Result<(GitOid, VersionRecord, CoverHierarchyRecord)> {
        let c = self.commit(f, txt)?;
        let revs = bc.map_or_else(|| format!("{}\n", c.as_hex()), |b| format!("{}\n^{}\n", c.as_hex(), b.as_hex()));
        let (v, cov) = self.step(CommitMode::Atomic, r, base, c, bc.into_iter().collect(), self.pack(&revs)?, deps)?;
        Ok((c, v, cov))
    }
    fn compact(
        &mut self,
        ins: &[&CoverHierarchyRecord],
        tail: &CoverHierarchyRecord,
        tip: GitOid,
    ) -> Result<CoverHierarchyRecord> {
        let p = self.pack(&format!("{}\n", tip.as_hex()))?;
        let mem = compute_cover_membership_digest(
            &self.realm,
            self.index.membership_generation() + 1,
            &[*p.0.entry(), *tail.pack().entry()],
        )?;
        let vs: Vec<_> = ins.iter().flat_map(|c| c.covered_versions().iter().copied()).collect();
        let ls: Vec<_> = ins.iter().flat_map(|c| c.covered_commits().iter().cloned()).collect();
        let ids: Vec<_> = ins.iter().map(|c| c.cover_id()).collect();
        let cov = self.cov(CoverTier::Compacted, p, (vs, (1, 2), ls, ids, mem))?;
        self.index.publish_compacted_cover(
            cov.clone(),
            self.index.compaction_epoch(),
            self.index.membership_digest(),
            mem,
        )?;
        for l in ins {
            self.index.mark_retired_from_active(l.cover_id(), cov.cover_id(), true)?;
        }
        Ok(cov)
    }
    fn hold(&mut self, r: &RefName, v: &VersionRecord, covs: &[Uuid]) {
        self.ret.add_hold(CoverRetentionHold::ActiveRefHead {
            ref_name: r.clone(),
            version_id: v.version_id(),
            cover_ids: covs.to_vec(),
        });
    }
    fn cut(&self, items: &[(&RefName, &VersionRecord)]) -> Result<StrongSnapshotCut> {
        let heads = items.iter().map(|&(r, v)| Ok((r.clone(), RefHead::from_committed(v)?))).collect::<Result<_>>()?;
        Ok(StrongSnapshotCut {
            authority_seq: self.seq,
            snapshot_digest: RequestDigest::of("cut", &[&self.seq.to_be_bytes()]),
            membership_digest: self.index.membership_digest(),
            heads,
        })
    }
    fn req(&self, cut: Option<StrongSnapshotCut>, wants: Vec<WantTarget>, haves: Vec<GitOid>) -> FetchPlanRequest {
        let auth = AuthorizationContext::for_realm(&self.realm, Uuid::new_v4(), Uuid::new_v4());
        let mut r =
            FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, self.realm, auth, ReadIsolationMode::StrongSnapshot);
        r.strong_cut = cut;
        r.wants = wants;
        r.haves = HaveSpec { have_oids: haves, have_version_ids: vec![] };
        r.prefer_compacted_above_delta_count = 2;
        r
    }
    fn plan(&self, req: &FetchPlanRequest) -> Result<FetchPlan> {
        let FetchPlanOutcome::Planned(p) = plan_fetch_covers(req, &self.graph, &self.index, &self.ret)? else {
            anyhow::bail!("plan")
        };
        Ok(*p)
    }
    async fn mat(
        &self,
        r: &FetchPlanRequest,
        p: &FetchPlan,
        s: &[CoverArtifactPair],
        refs: &[(RefName, GitOid)],
    ) -> Result<()> {
        let (c, a, sc, g, x, rt) = (r.consumer, &r.auth, r.strong_cut.as_ref(), &self.graph, &self.index, &self.ret);
        let proof = verify_fetch_plan_closure(p, c, a, sc, g, x, rt)?;
        let dl = Instant::now() + Duration::from_secs(60);
        let mat = materialize_and_verify_fetch_plan(&self.store, &self.views, &proof, p, x, s, refs, dl).await?;
        ensure!(mat.reachable_object_count > 0);
        for (rf, o) in refs {
            ensure!(git_str(mat.repo_path()?, &["rev-parse", rf.as_str()], None)? == o.as_hex());
        }
        mat.reap();
        Ok(())
    }
}

#[tokio::test]
async fn sha1_and_sha256_compaction_thin_and_fault_fallback() -> Result<()> {
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut env = Env::new(fmt)?;
        let (pl, m) = ("base-line-data\n".repeat(120), "refs/heads/main");
        let (c1, v1, cov1) = env.push(m, None, None, "big.txt", &pl, vec![])?;
        let (c2, v2, cov2) = env.push(m, Some(&v1), Some(c1), "a.txt", "v2\n", vec![v1.version_id()])?;
        let (c3, v3, cov3) = env.push(m, Some(&v2), Some(c2), "a.txt", "v3\n", vec![v2.version_id()])?;
        let comp = env.compact(&[&cov1, &cov2], &cov3, c2)?;
        let ac = comp.artifacts().clone();
        let c4 = env.commit("big.txt", &format!("{pl}tail\n"))?;
        let revs = format!("{}\n^{}\n", c4.as_hex(), c3.as_hex());
        let thin =
            git_raw(&env.repo, &["pack-objects", "--revs", "--thin", "--stdout", "--quiet"], Some(revs.as_bytes()))?;
        let stem = format!("pack-{}", &hex::encode(Sha256::digest(&thin))[..fmt.oid_hex_len()]);
        let p4 = env.upload(thin, b"thin-idx".to_vec(), stem, vec![comp.cover_id(), cov3.cover_id()])?;
        let (v4, cov4) = env.step(CommitMode::Atomic, m, Some(&v3), c4, vec![c3], p4, vec![v3.version_id()])?;

        let (mr, wr) = (RefName::new(m)?, |r: &RefName| WantTarget::Ref { ref_name: r.clone() });
        env.hold(&mr, &v4, &[comp.cover_id(), cov3.cover_id(), cov4.cover_id()]);
        let cut = env.cut(&[(&mr, &v4)])?;
        let r1 = env.req(Some(cut), vec![wr(&mr)], vec![]);
        let cp = env.plan(&r1)?;
        let picked: Vec<_> = cp.selected_covers.iter().map(|c| c.cover_id).collect();
        ensure!(picked == [comp.cover_id(), cov3.cover_id(), cov4.cover_id()]);
        env.mat(&r1, &cp, &[], &[(mr.clone(), c4)]).await?;

        let wt = WantTarget::PinnedVersion { ref_name: mr.clone(), version_id: v4.version_id() };
        let mut inc = env.req(None, vec![wt], vec![c3]);
        inc.consumer = ReadConsumer::SingleRefBrowse;
        inc.isolation = ReadIsolationMode::VersionClosure {
            version_id: v4.version_id(),
            session_lower_bound: None,
            historical_pinned: false,
        };
        let tp = env.plan(&inc)?;
        ensure!(
            tp.selected_covers.len() == 1
                && tp.selected_covers[0].is_thin_pack
                && !tp.external_client_base_covers.is_empty()
        );
        env.mat(&inc, &tp, &[ac.clone(), cov3.artifacts().clone()], &[(mr.clone(), c4)]).await?;
        ensure!(env.mat(&inc, &tp, &[], &[(mr.clone(), c4)]).await.is_err());

        let key = format!("pc-b/r/{}", ac.pack_locator.path());
        if let Some(b) = s3().1.lock().unwrap().get_mut(&key) {
            let mid = b.len() / 2;
            b[mid] ^= 0xff;
        }
        ensure!(env.mat(&r1, &cp, &[], &[(mr.clone(), c4)]).await.is_err());
        s3().1.lock().unwrap().remove(&key);
        ensure!(env.mat(&r1, &cp, &[], &[(mr, c4)]).await.is_err());
        let q = CoverRetentionHold::QuarantineHold {
            incident_id: Uuid::new_v4(),
            pack_ids: vec![comp.pack().entry().pack_id()],
            cover_ids: vec![],
            cleared: false,
        };
        env.ret.add_hold(q);
        ensure!(matches!(
            plan_fetch_covers(&r1, &env.graph, &env.index, &env.ret)?,
            FetchPlanOutcome::FallbackToStrongSnapshot { reason: FallbackReason::RetentionLost, .. }
        ));
    }
    Ok(())
}

#[tokio::test]
async fn atomic_non_atomic_revoked_auth_and_cross_tenant_negative_cases() -> Result<()> {
    let mut env = Env::new(GitObjectFormat::Sha1)?;
    let (c1, v1, cov1) = env.push("refs/heads/protected", None, None, "m.txt", "1\n", vec![])?;
    let c2 = env.commit("m.txt", "2\n")?;
    let p2 = env.pack(&format!("{}\n^{}\n", c2.as_hex(), c1.as_hex()))?;
    let (v2, cov2) =
        env.step(CommitMode::AcceptedSubset, "refs/heads/main", None, c2, vec![c1], p2, vec![v1.version_id()])?;
    let (_, vh, cov_h) =
        env.push("refs/hidden/internal", None, Some(c2), "secret.txt", "topsecret\n", vec![v2.version_id()])?;

    let (mr, pr, hr) = (
        RefName::new("refs/heads/main")?,
        RefName::new("refs/heads/protected")?,
        RefName::new("refs/hidden/internal")?,
    );
    let wr = |r: &RefName| WantTarget::Ref { ref_name: r.clone() };
    env.hold(&mr, &v2, &[cov1.cover_id(), cov2.cover_id()]);
    env.hold(&pr, &v1, &[cov1.cover_id()]);
    env.hold(&hr, &vh, &[cov_h.cover_id()]);
    let cut = env.cut(&[(&mr, &v2), (&pr, &v1), (&hr, &vh)])?;

    let mut req = env.req(Some(cut.clone()), vec![wr(&mr), wr(&pr)], vec![]);
    req.allow_strong_fallback = false;
    req.auth.visibility = RefVisibilityPolicy::DenyList([hr.clone()].into_iter().collect());
    let ads = advertise_authorized_refs(&req.auth, &env.realm, &cut.heads.values().cloned().collect::<Vec<_>>())?;
    ensure!(ads.iter().all(|a| a.ref_name != hr) && ads.len() == 2);
    let p = env.plan(&req)?;
    env.mat(&req, &p, &[], &[(mr.clone(), c2), (pr, c1)]).await?;

    let neg = [
        (0, FetchPlanError::HiddenRefDenied),
        (1, FetchPlanError::AuthRevoked),
        (2, FetchPlanError::AuthRevoked),
        (3, FetchPlanError::TenantMismatch),
        (4, FetchPlanError::RealmMismatch),
    ];
    for (k, err) in neg {
        let mut b = req.clone();
        b.wants = vec![if k == 0 { wr(&hr) } else { wr(&mr) }];
        match k {
            1 => b.auth.revoked = true,
            2 => b.auth.auth_epoch = 0,
            3 => b.auth.tenant_id = Uuid::new_v4(),
            4 => b.auth.repository_id = Uuid::new_v4(),
            _ => {}
        }
        ensure!(plan_fetch_covers(&b, &env.graph, &env.index, &env.ret) == Err(err));
    }
    req.auth.visibility = RefVisibilityPolicy::AllAuthorized;
    req.auth.allow_non_common_time_set = true;
    req.consumer = ReadConsumer::CrossRefCompare;
    req.isolation = ReadIsolationMode::VersionSet {
        version_ids: vec![v1.version_id(), v2.version_id()],
        session_lower_bound: None,
        historical_pinned: false,
    };
    req.strong_cut = None;
    ensure!(!env.plan(&req)?.common_time);
    Ok(())
}
