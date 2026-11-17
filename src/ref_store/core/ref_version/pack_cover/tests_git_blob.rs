//! Stock Git (SHA-1 & SHA-256) + OpenDAL S3 Loopback BlobStore + DisposableViewRoot tests (Issue #184).
use super::*;
use crate::blob_store::BlobLocator;
use crate::blob_store::budget::{ResourceContext, ResourceLimits};
use crate::blob_store::config::BlobProfile;
use crate::blob_store::disposable_view::DisposableViewRoot;
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::test_support::deadline;
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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

type ObjMap = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

async fn s3_op(State(m): State<ObjMap>, method: Method, uri: Uri) -> Response {
    let k = uri.path().trim_start_matches('/');
    let Some(d) = m.lock().expect("objs").get(k).cloned() else {
        return (StatusCode::NOT_FOUND, [(header::CONTENT_LENGTH, "0".into())], Body::empty()).into_response();
    };
    let len = d.len().to_string();
    let body = if method == Method::HEAD { Body::empty() } else { Body::from(d) };
    (StatusCode::OK, [(header::CONTENT_LENGTH, len), (header::ETAG, "\"e\"".into())], body).into_response()
}

async fn s3_srv() -> Result<(String, ObjMap, tokio::task::JoinHandle<()>)> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let (addr, m) = (l.local_addr()?, Arc::new(Mutex::new(BTreeMap::new())));
    let app = Router::new().fallback(s3_op).with_state(m.clone());
    let h = tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    Ok((format!("http://{addr}"), m, h))
}

#[cfg(unix)]
const NULL_CFG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_CFG: &str = "NUL";

fn git_run(repo: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
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

struct MemEnv {
    _dir: TempDir,
    _srv: tokio::task::JoinHandle<()>,
    objs: ObjMap,
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

impl Drop for MemEnv {
    fn drop(&mut self) {
        self._srv.abort();
    }
}

impl MemEnv {
    async fn new(fmt: GitObjectFormat) -> Result<Self> {
        let (dir, u) = (TempDir::new()?, Uuid::new_v4);
        let repo = dir.path().join("src");
        std::fs::create_dir_all(&repo)?;
        git_run(&repo, &["init", &format!("--object-format={}", fmt.as_str()), "--initial-branch=main"], None)?;
        let views = DisposableViewRoot::open(&dir.path().join("views"), 8, 64 << 20, Duration::from_secs(120))?;
        let limits = ResourceLimits::new(4, 4, 8 << 20)?;
        let (ep, objs, _srv) = s3_srv().await?;
        let profile = BlobProfile::memory_profile(limits).with_test_endpoint(&ep)?;
        let store = BlobStore::open_with_resources(profile, Arc::new(ResourceContext::new(limits)))?;
        let realm = RefVersionRealm::new(u(), u(), u(), AuthorityKind::Pg, 1, 0, 1, fmt);
        let mem = compute_cover_membership_digest(&realm, 1, &[])?;
        Ok(Self {
            _dir: dir,
            _srv,
            objs,
            repo,
            views,
            store,
            realm,
            graph: VersionGraph::new(),
            index: CoverHierarchyIndex::new(realm, mem)?,
            ret: RetentionClassificationIndex::new(),
            seq: 0,
            entries: Vec::new(),
        })
    }

    fn s3_key(loc: &BlobLocator) -> String {
        format!("blob-test-bucket/{}", loc.path().trim_start_matches('/'))
    }

    fn commit(&self, f: &str, body: &str) -> Result<GitOid> {
        std::fs::write(self.repo.join(f), body)?;
        git_run(&self.repo, &["add", f], None)?;
        git_run(&self.repo, &["commit", "-m", f], None)?;
        self.oid()
    }

    fn oid(&self) -> Result<GitOid> {
        Ok(GitOid::parse(self.realm.object_format(), &git_run(&self.repo, &["rev-parse", "HEAD"], None)?)?)
    }

    async fn pack(&self, revs: &str) -> Result<(VerifiedClosurePack, CoverArtifactPair)> {
        let d = TempDir::new()?;
        let p = d.path().join("pack");
        let h =
            git_run(&self.repo, &["pack-objects", "--revs", "--quiet", p.to_str().unwrap()], Some(revs.as_bytes()))?;
        let stem = format!("pack-{h}");
        let pk = std::fs::read(d.path().join(format!("{stem}.pack")))?;
        let ix = std::fs::read(d.path().join(format!("{stem}.idx")))?;
        let (ps, is, u) = (hex::encode(Sha256::digest(&pk)), hex::encode(Sha256::digest(&ix)), Uuid::new_v4);
        let (t, r) = (self.realm.tenant_id(), self.realm.repository_id());
        let pl = BlobLocator::new(t, r, 1, u(), "packs", &ps, pk.len() as u64)?;
        let il = BlobLocator::new(t, r, 1, u(), "packs", &is, ix.len() as u64)?;
        {
            let mut g = self.objs.lock().expect("objs");
            g.insert(Self::s3_key(&pl), pk);
            g.insert(Self::s3_key(&il), ix);
        }
        let e = PackSetEntry::new(u(), u(), RequestDigest::of("a", &[ps.as_bytes(), is.as_bytes()]))?;
        let vp = VerifiedClosurePack::new(
            e,
            t,
            r,
            self.store.provider().as_str(),
            self.store.backend_identity().as_hex(),
            pl.length() + il.length(),
            2,
        )?;
        let art = CoverArtifactPair {
            pack_stem: stem,
            pack_locator: pl,
            idx_locator: il,
            is_thin_pack: false,
            delta_base_cover_ids: vec![],
        };
        Ok((vp, art))
    }

    async fn push(
        &mut self,
        rn_s: &str,
        base: Option<&VersionRecord>,
        bc: Option<GitOid>,
        f: &str,
        txt: &str,
        deps: Vec<VersionId>,
    ) -> Result<(GitOid, VersionRecord, CoverHierarchyRecord)> {
        let c = self.commit(f, txt)?;
        let revs = bc.map_or_else(|| format!("{}\n", c.as_hex()), |b| format!("{}\n^{}\n", c.as_hex(), b.as_hex()));
        let p = self.pack(&revs).await?;
        let (v, cov) = self.step(rn_s, base, c, p, &[c], deps)?;
        Ok((c, v, cov))
    }

    fn step(
        &mut self,
        rn_s: &str,
        base: Option<&VersionRecord>,
        c: GitOid,
        (vp, art): (VerifiedClosurePack, CoverArtifactPair),
        commits: &[GitOid],
        object_deps: Vec<VersionId>,
    ) -> Result<(VersionRecord, CoverHierarchyRecord)> {
        self.seq += 1;
        let (s, ref_name, op_id, realm, u) = (self.seq, RefName::new(rn_s)?, Uuid::new_v4(), self.realm, Uuid::new_v4);
        let d = RequestDigest::of("g", &[&s.to_be_bytes()]);
        let ref_generation = base.map_or(1, |b| b.ref_generation() + 1);
        let pre = base.and_then(|b| b.target().oid()).map_or(RefPrecondition::Absent, RefPrecondition::Present);
        let sel = base.map_or(BaseRequestSelector::ExplicitAbsent, |b| BaseRequestSelector::Present(b.version_id()));
        let intent = RefVersionIntent::new(ref_name.clone(), RefVersionKind::Publish, pre, sel, RefTarget::Oid(c));
        let op = OperationDigestInput::new(
            realm,
            u(),
            u(),
            IssuerLane::new("m")?,
            s,
            op_id,
            s,
            d,
            CommitMode::Atomic,
            HeadUpdate::Keep,
            vec![intent],
            d,
            vec![],
        );
        let od = operation_digest(&op)?;
        let vid = derive_candidate_version_id(&op, od, &ref_name, base.map(VersionRecord::ref_generation))?;
        let ce = CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(c));
        let csi = compute_commit_set_id(&CommitSetInput::new(realm, s, op_id, od, vec![ce], CommitSetHead::Absent))?;
        let v = VersionRecord::seal(VersionRecordInput {
            version_id: vid,
            realm,
            ref_name,
            ref_generation,
            operation_id: op_id,
            operation_digest: od,
            authority_seq: s,
            kind: RefVersionKind::Publish,
            target: RefTarget::Oid(c),
            base_version_id: base.map(VersionRecord::version_id),
            object_deps,
            pack_set_digest: compute_pack_set_digest(&[*vp.entry()])?,
            commit_set_id: csi,
        })?;
        self.graph.insert_active(CausalVersionNode { record: v.clone(), own_packs: vec![vp.clone()] });
        self.entries.push(*vp.entry());
        let g = self.index.membership_generation() + 1;
        let mem = compute_cover_membership_digest(&realm, g, &self.entries)?;
        let mut links = Vec::new();
        for &commit_oid in commits {
            let po = git_run(&self.repo, &["rev-list", "--parents", "-n", "1", &commit_oid.as_hex()], None)?;
            let parent_oids = po
                .split_whitespace()
                .skip(1)
                .map(|t| Ok(GitOid::parse(realm.object_format(), t)?))
                .collect::<Result<_>>()?;
            links.push(CoverCommitLink { commit_oid, parent_oids, version_id: vid, authority_seq: s });
        }
        let cov = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
            cover_id: u(),
            realm,
            tier: CoverTier::Delta,
            pack: vp,
            artifacts: art,
            covered_versions: vec![vid],
            min_authority_seq: s,
            max_authority_seq: s,
            covered_commits: links,
            input_cover_ids: vec![],
            membership_generation: g,
            membership_digest: mem,
            compaction_epoch: self.index.compaction_epoch(),
            worker_id: u(),
            operation_id: u(),
        })?;
        self.index.register_leaf_cover(cov.clone(), mem)?;
        Ok((v, cov))
    }

    async fn check(
        &self,
        req: &FetchPlanRequest,
        seeds: &[CoverArtifactPair],
        refs: &[(RefName, GitOid)],
    ) -> Result<Vec<Uuid>> {
        let FetchPlanOutcome::Planned(p) = plan_fetch_covers(req, &self.graph, &self.index, &self.ret)? else {
            anyhow::bail!("expected plan");
        };
        let proof = verify_fetch_plan_closure(
            &p,
            req.consumer,
            &req.auth,
            req.strong_cut.as_ref(),
            &self.graph,
            &self.index,
            &self.ret,
        )?;
        let mat = materialize_and_verify_fetch_plan(
            &self.store,
            &self.views,
            &proof,
            &p,
            &self.index,
            seeds,
            refs,
            deadline(),
        )
        .await?;
        ensure!(mat.reachable_object_count > 0);
        for (r, o) in refs {
            ensure!(git_run(mat.repo_path()?, &["rev-parse", r.as_str()], None)? == o.as_hex());
        }
        mat.reap();
        Ok(p.selected_covers.iter().map(|c| c.cover_id).collect())
    }
}

#[tokio::test]
async fn criss_cross_merge_deep_lag_pin_non_ff_and_memory_blob_faults() -> Result<()> {
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut env = MemEnv::new(fmt).await?;
        let (c1, mut pv, cov1) = env.push("refs/heads/main", None, None, "a.txt", "v1\n", vec![]).await?;
        let (mut pc, mut leaves, mut c3, mut v3) = (c1, vec![cov1.clone()], c1, pv.clone());
        for i in 2..=5 {
            let (c, v, cov) = env
                .push("refs/heads/main", Some(&pv), Some(pc), "a.txt", &format!("v{i}\n"), vec![pv.version_id()])
                .await?;
            if i == 3 {
                (c3, v3) = (c, v.clone());
            }
            (pc, pv) = (c, v);
            leaves.push(cov);
        }
        let (c4, c5, v5) = (leaves[3].covered_commits()[0].commit_oid, pc, pv);
        let comp_p = env.pack(&format!("{}\n", c4.as_hex())).await?;
        let comp_mem = compute_cover_membership_digest(
            &env.realm,
            env.index.membership_generation() + 1,
            &[*comp_p.0.entry(), *leaves[4].pack().entry()],
        )?;
        let ins = [&leaves[0], &leaves[1], &leaves[2], &leaves[3]];
        let comp = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
            cover_id: Uuid::new_v4(),
            realm: env.realm,
            tier: CoverTier::Compacted,
            pack: comp_p.0,
            artifacts: comp_p.1,
            covered_versions: ins.iter().flat_map(|c| c.covered_versions().iter().copied()).collect(),
            min_authority_seq: 1,
            max_authority_seq: 4,
            covered_commits: ins.iter().flat_map(|c| c.covered_commits().iter().cloned()).collect(),
            input_cover_ids: ins.iter().map(|c| c.cover_id()).collect(),
            membership_generation: env.index.membership_generation() + 1,
            membership_digest: comp_mem,
            compaction_epoch: env.index.compaction_epoch(),
            worker_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
        })?;
        env.index.publish_compacted_cover(
            comp.clone(),
            env.index.compaction_epoch(),
            env.index.membership_digest(),
            comp_mem,
        )?;
        for l in ins {
            env.index.mark_retired_from_active(l.cover_id(), comp.cover_id(), true)?;
        }

        git_run(&env.repo, &["checkout", "-b", "feature", &c3.as_hex()], None)?;
        let (f1, vf1, cov_f1) =
            env.push("refs/heads/feature", None, Some(c3), "f.txt", "f1\n", vec![v3.version_id()]).await?;
        git_run(&env.repo, &["merge", "--no-ff", "-m", "m1", &c5.as_hex()], None)?;
        let m1 = env.oid()?;
        git_run(&env.repo, &["checkout", "main"], None)?;
        git_run(&env.repo, &["merge", "--no-ff", "-m", "m2", &f1.as_hex()], None)?;
        let m2 = env.oid()?;
        git_run(&env.repo, &["merge", "--no-ff", "-m", "m3", &m1.as_hex()], None)?;
        let m3 = env.oid()?;
        let pm = env.pack(&format!("{}\n^{}\n^{}\n", m3.as_hex(), c5.as_hex(), f1.as_hex())).await?;
        let (vm3, cov_m) =
            env.step("refs/heads/main", Some(&v5), m3, pm, &[m1, m2, m3], vec![v5.version_id(), vf1.version_id()])?;

        git_run(&env.repo, &["checkout", "-b", "force", &c1.as_hex()], None)?;
        let (nf1, vn1, _) =
            env.push("refs/heads/force", None, Some(c1), "nf.txt", "old\n", vec![cov1.covered_versions()[0]]).await?;
        git_run(&env.repo, &["reset", "--hard", &c1.as_hex()], None)?;
        let (nf2, vn2, cov_n2) = env
            .push("refs/heads/force", Some(&vn1), Some(c1), "nf.txt", "new\n", vec![cov1.covered_versions()[0]])
            .await?;

        let (mr, fr, nr) =
            (RefName::new("refs/heads/main")?, RefName::new("refs/heads/feature")?, RefName::new("refs/heads/force")?);
        env.ret.add_hold(CoverRetentionHold::ActiveRefHead {
            ref_name: mr.clone(),
            version_id: vm3.version_id(),
            cover_ids: vec![comp.cover_id(), leaves[4].cover_id(), cov_f1.cover_id(), cov_m.cover_id()],
        });
        env.ret.add_hold(CoverRetentionHold::ActiveRefHead {
            ref_name: fr.clone(),
            version_id: vf1.version_id(),
            cover_ids: vec![comp.cover_id(), cov_f1.cover_id()],
        });
        env.ret.add_hold(CoverRetentionHold::ActiveRefHead {
            ref_name: nr.clone(),
            version_id: vn2.version_id(),
            cover_ids: vec![comp.cover_id(), cov_n2.cover_id()],
        });
        env.ret.add_hold(CoverRetentionHold::HistoricalCoverHold {
            hold_id: Uuid::new_v4(),
            cover_ids: vec![comp.cover_id()],
            version_ids: vec![v3.version_id()],
            active_readers: 1,
            released: false,
        });

        let heads = BTreeMap::from([
            (mr.clone(), RefHead::from_committed(&vm3)?),
            (fr.clone(), RefHead::from_committed(&vf1)?),
            (nr.clone(), RefHead::from_committed(&vn2)?),
        ]);
        let cut = StrongSnapshotCut {
            authority_seq: env.seq,
            snapshot_digest: RequestDigest::of("c", &[b"m"]),
            membership_digest: env.index.membership_digest(),
            heads,
        };
        let auth = || AuthorizationContext::for_realm(&env.realm, Uuid::new_v4(), Uuid::new_v4());
        let mut r1 =
            FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, env.realm, auth(), ReadIsolationMode::StrongSnapshot);
        r1.strong_cut = Some(cut.clone());
        r1.wants = vec![WantTarget::Ref { ref_name: mr.clone() }, WantTarget::Ref { ref_name: fr.clone() }];
        r1.prefer_compacted_above_delta_count = 2;
        let picked = env.check(&r1, &[], &[(mr.clone(), m3), (fr, f1)]).await?;
        ensure!(picked.contains(&comp.cover_id()) && leaves[..4].iter().all(|l| !picked.contains(&l.cover_id())));

        let mut r_pin = FetchPlanRequest::new(
            ReadConsumer::CiCheckoutPin,
            env.realm,
            auth(),
            ReadIsolationMode::VersionClosure {
                version_id: v3.version_id(),
                session_lower_bound: None,
                historical_pinned: true,
            },
        );
        r_pin.wants = vec![WantTarget::PinnedVersion { ref_name: mr.clone(), version_id: v3.version_id() }];
        ensure!(!env.check(&r_pin, &[], &[(mr.clone(), c3)]).await?.is_empty());

        let mut r_nff =
            FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, env.realm, auth(), ReadIsolationMode::StrongSnapshot);
        r_nff.strong_cut = Some(cut.clone());
        r_nff.wants = vec![WantTarget::Ref { ref_name: nr.clone() }];
        r_nff.haves = HaveSpec { have_oids: vec![nf1], have_version_ids: vec![] };
        ensure!(env.check(&r_nff, &[comp.artifacts().clone()], &[(nr, nf2)]).await? == vec![cov_n2.cover_id()]);

        let FetchPlanOutcome::Planned(cp) = plan_fetch_covers(&r1, &env.graph, &env.index, &env.ret)? else {
            anyhow::bail!("plan")
        };
        let proof =
            verify_fetch_plan_closure(&cp, r1.consumer, &r1.auth, Some(&cut), &env.graph, &env.index, &env.ret)?;
        let key = MemEnv::s3_key(&comp.artifacts().pack_locator);
        for rm in [false, true] {
            if rm {
                env.objs.lock().expect("objs").remove(&key);
            } else if let Some(b) = env.objs.lock().expect("objs").get_mut(&key) {
                let mid = b.len() / 2;
                b[mid] ^= 0xff;
            }
            ensure!(
                materialize_and_verify_fetch_plan(
                    &env.store,
                    &env.views,
                    &proof,
                    &cp,
                    &env.index,
                    &[],
                    &[(mr.clone(), m3)],
                    deadline()
                )
                .await
                .is_err()
            );
        }
    }
    Ok(())
}
