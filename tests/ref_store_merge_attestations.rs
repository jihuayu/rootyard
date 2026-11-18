mod retention_roots_support;

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::pack_commit::{
    MergeClaim, MergeStrategy, PackClosureContext, PackCommitBaseline, PackCommitError, PackCommitPlan, PackMode,
    PackVerifier, PgPackCommit, VerifiedMergeAttestation,
};
use rootyard::ref_store::{
    GitObjectFormat, GitOid, OperationLookup, OperationState, PgRefStore, RefName, RefPrecondition, RefTarget,
    RefUpdate,
};
use std::fmt::Write as _;

use retention_roots_support::common::open_store;
use retention_roots_support::db::{Db, deadline};
use retention_roots_support::git::{GitRepo, PairFiles, git_binary};
use retention_roots_support::pack::{closure, commit, draft, prove, publish, register};

const BASE: &str = "refs/heads/main";
const FAST_FORWARD: &str = "refs/heads/fast-forward";
const TOPIC: &str = "refs/heads/topic";

async fn tree(git: &GitRepo, entries: &[(&str, &str)]) -> Result<String> {
    let mut input = String::new();
    for (name, oid) in entries {
        writeln!(&mut input, "100644 blob {oid}\t{name}")?;
    }
    GitRepo::text(&git.run(&["mktree"], Some(input.as_bytes())).await?)
}

async fn commit_tree(git: &GitRepo, tree: &str, parents: &[&str], message: &str) -> Result<String> {
    let mut args = vec!["commit-tree", tree];
    for parent in parents {
        args.extend(["-p", *parent]);
    }
    args.extend(["-m", message]);
    GitRepo::text(&git.run(&args, None).await?)
}

async fn pack_objects(git: &GitRepo, scratch: &std::path::Path, name: &str, oids: &[&str]) -> Result<PairFiles> {
    let input = format!("{}\n", oids.join("\n"));
    let bytes = git.run(&["pack-objects", "--stdout"], Some(input.as_bytes())).await?;
    ensure!(bytes.starts_with(b"PACK"), "stock Git did not produce a candidate pack");
    let pack = scratch.join(format!("{name}.pack"));
    tokio::fs::write(&pack, bytes).await?;
    let path = pack.to_str().ok_or_else(|| anyhow!("candidate pack path is not UTF-8"))?;
    git.run(&["index-pack", path], None).await?;
    let idx = pack.with_extension("idx");
    ensure!(idx.is_file(), "stock Git did not produce the candidate index");
    Ok(PairFiles { pack, idx })
}

async fn indexed_objects(git: &GitRepo, pair: &PairFiles, format: GitObjectFormat) -> Result<Vec<GitOid>> {
    let index = pair.idx.to_str().ok_or_else(|| anyhow!("pack index path is not UTF-8"))?;
    let listing = git.run(&["verify-pack", "-v", index], None).await?;
    let listing = std::str::from_utf8(&listing)?;
    Ok(listing
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().next())
        .filter_map(|word| GitOid::parse(format, word).ok())
        .collect())
}

async fn register_pair(db: &Db, store: &BlobStore, plan: &PackCommitPlan, files: &PairFiles) -> Result<()> {
    let [pack] = plan.packs() else {
        return Err(anyhow!("the operation must plan one pack pair"));
    };
    let publication = publish(db, store, plan, files).await?;
    register(db, plan, pack.pack_id(), &publication).await
}

struct Source<'a> {
    db: &'a Db,
    store: &'a BlobStore,
    baseline: PackCommitBaseline,
    verifier: PackVerifier,
}

impl Source<'_> {
    async fn lookup(&self, plan: &PackCommitPlan) -> Result<OperationLookup> {
        let mut client = self.db.pool.get().await?;
        let tx = client.transaction().await?;
        let lookup = PgRefStore.get(&tx, plan.repository_id(), plan.identity().operation_id(), deadline()).await?;
        tx.rollback().await?;
        Ok(lookup)
    }

    async fn capture(&self) -> Result<PackCommitBaseline> {
        let gate = self.baseline.gate();
        let mut client = self.db.pool.get().await?;
        Ok(PgPackCommit.capture_baseline(&mut client, gate.repository_id(), gate.tenant_id(), deadline()).await?)
    }

    async fn seed_effects(&self, plan: &PackCommitPlan) -> Result<serde_json::Value> {
        let row = self
            .db
            .pool
            .get()
            .await?
            .query_one(
                "SELECT jsonb_build_object(
                    'gate', (SELECT to_jsonb(g) FROM ref_store_core_gates g WHERE repository_id=$1),
                    'refs', (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.ref_name)
                             FROM ref_store_core_refs r WHERE repository_id=$1),
                    'operations', (SELECT jsonb_agg(to_jsonb(o) ORDER BY o.operation_id)
                                   FROM ref_store_operations o WHERE repository_id=$1),
                    'publications', (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.registration_id)
                                     FROM ref_store_core_pack_publications p WHERE repository_id=$1),
                    'artifacts', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.registration_id,a.slot)
                                  FROM ref_store_core_pack_artifacts a WHERE repository_id=$1),
                    'memberships', (SELECT jsonb_agg(to_jsonb(m) ORDER BY m.pack_id)
                                    FROM ref_store_core_pack_memberships m WHERE repository_id=$1),
                    'history', (SELECT jsonb_agg(to_jsonb(h) ORDER BY h.history_id)
                                FROM ref_store_core_pack_history h WHERE repository_id=$1),
                    'events', (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_id)
                               FROM ref_store_core_events e WHERE repository_id=$1),
                    'repo_usage', (SELECT to_jsonb(u) FROM ref_store_core_pack_repo_usage u WHERE repository_id=$1),
                    'tenant_usage', (SELECT to_jsonb(u) FROM ref_store_core_pack_tenant_usage u WHERE tenant_id=$2))",
                &[&plan.repository_id(), &plan.tenant_id()],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    fn check_context(&self, context: &PackClosureContext, has_pair: bool) -> Result<()> {
        ensure!(
            context.old_refs() == self.baseline.refs()
                && context.old_packs() == self.baseline.old_packs()
                && context.old_membership_digest() == self.baseline.membership_digest(),
            "operation did not carry the exact captured refs and registered source packs"
        );
        ensure!(context.new_packs().len() == usize::from(has_pair), "unexpected candidate pack set");
        Ok(())
    }

    async fn attest(
        &self,
        sequence: i64,
        claim: &MergeClaim,
        candidate: GitOid,
        pair: Option<&PairFiles>,
    ) -> Result<Result<VerifiedMergeAttestation, PackCommitError>> {
        let update =
            RefUpdate::new(claim.base_ref.clone(), RefPrecondition::Present(claim.base_oid), RefTarget::Oid(candidate));
        let gate = self.baseline.gate();
        let files = pair.map(std::slice::from_ref).unwrap_or_default();
        let attempt =
            draft(self.db, gate.repository_id(), gate.tenant_id(), sequence, gate, vec![update], files).await?;
        if let Some(pair) = pair {
            register_pair(self.db, self.store, &attempt.plan, pair).await?;
        }
        let context = closure(self.db, &attempt.plan).await?;
        self.check_context(&context, pair.is_some())?;
        let before = self.lookup(&attempt.plan).await?;
        let OperationLookup::Known(record) = &before else {
            return Err(anyhow!("candidate operation is absent"));
        };
        ensure!(
            record.identity() == attempt.plan.identity()
                && record.state() == OperationState::Pending
                && record.terminal_result().is_none(),
            "candidate is not the expected pending operation"
        );
        ensure!(self.capture().await? == self.baseline, "staging changed the captured source");

        let result = self
            .verifier
            .attest_merge(&attempt.plan, &self.baseline, context.new_packs().to_vec(), claim, deadline().into_std())
            .await;

        ensure!(self.lookup(&attempt.plan).await? == before, "attestation changed the operation lookup");
        ensure!(self.capture().await? == self.baseline, "attestation changed refs, HEAD, revision or membership");
        if let Ok(attested) = &result {
            ensure!(attested.binds(&attempt.plan, claim), "attestation is not bound to the operation and claim");
            ensure!(attested.candidate_oid() == candidate, "attestation named a different candidate");
        }
        Ok(result)
    }
}

fn require_refusal(
    result: Result<VerifiedMergeAttestation, PackCommitError>,
    expected: &[&str],
    case: &str,
) -> Result<()> {
    ensure!(
        matches!(result, Err(PackCommitError::ProofUnavailable(reason)) if expected.contains(&reason)),
        "{case} did not produce the expected verifier refusal"
    );
    Ok(())
}

async fn exercise(db: &Db, store: &BlobStore, git: &GitRepo, format: GitObjectFormat) -> Result<()> {
    let root_blob = git.add_blob(b"common\n").await?;
    let base_blob = git.add_blob(b"base only\n").await?;
    let topic_blob = git.add_blob(b"topic only\n").await?;
    let fast_blob = git.add_blob(b"fast forward only\n").await?;
    let root_entry = ("root.txt", root_blob.as_str());
    let base_entry = ("base.txt", base_blob.as_str());
    let topic_entry = ("topic.txt", topic_blob.as_str());
    let fast_entry = ("fast.txt", fast_blob.as_str());

    let root_tree = tree(git, &[root_entry]).await?;
    let root = commit_tree(git, &root_tree, &[], "common ancestor").await?;
    let base_tree = tree(git, &[root_entry, base_entry]).await?;
    let base = commit_tree(git, &base_tree, &[&root], "base").await?;
    let fast_tree = tree(git, &[root_entry, base_entry, fast_entry]).await?;
    let fast_head = commit_tree(git, &fast_tree, &[&base], "fast-forward head").await?;
    let topic_tree = tree(git, &[root_entry, topic_entry]).await?;
    let topic_head = commit_tree(git, &topic_tree, &[&root], "divergent topic head").await?;

    let merged_tree = tree(git, &[root_entry, base_entry, topic_entry]).await?;
    let merged = commit_tree(git, &merged_tree, &[&base, &topic_head], "ordered merge").await?;
    let wrong_tree = commit_tree(git, &base_tree, &[&base, &topic_head], "wrong tree").await?;
    let wrong_parents = commit_tree(git, &merged_tree, &[&topic_head, &base], "reversed parents").await?;
    let replacement = format!("refs/replace/{merged}");

    let refs = [(BASE, &base), (FAST_FORWARD, &fast_head), (TOPIC, &topic_head), (replacement.as_str(), &base)];
    let mut updates = Vec::new();
    for (name, oid) in refs {
        git.update_ref(name, oid).await?;
        updates.push(RefUpdate::new(
            RefName::new(name)?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(format, oid)?),
        ));
    }
    let pair = git.pack_all("source").await?;
    let (tenant, repo) = db.business(format).await?;
    let gate = db.gate(repo, tenant, format).await?;
    let seed = draft(db, repo, tenant, 1, &gate, updates, std::slice::from_ref(&pair)).await?;
    register_pair(db, store, &seed.plan, &pair).await?;
    let context = closure(db, &seed.plan).await?;
    let proof = prove(store, &git.git, &seed.plan, &context).await?;
    let receipt = commit(db, &seed.plan, &seed.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "source refs did not commit freshly");

    let mut client = db.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
    drop(client);
    let ([active_pack], [registered_pack]) = (baseline.old_packs(), context.new_packs()) else {
        return Err(anyhow!("source must have one active pack from the seed registration"));
    };
    ensure!(
        baseline.gate().revision() == receipt.terminal.revision
            && baseline.mode() == PackMode::PackVerified
            && baseline.gate().head_ref().as_str() == BASE
            && baseline.refs() == context.resulting_refs()
            && active_pack.pack_id() == registered_pack.pack_id()
            && active_pack.registration_id() == registered_pack.registration_id()
            && active_pack.artifact_set_digest() == registered_pack.artifact_set_digest(),
        "source is not the committed PG ref and pack view"
    );
    ensure!(
        baseline
            .refs()
            .iter()
            .any(|reference| reference.name() == replacement.as_str() && reference.oid_hex() == base.as_str())
            && base_tree != merged_tree,
        "the captured replacement must redirect the clean merge to a different tree"
    );
    let verifier = PackVerifier::new(store.clone(), git.git.clone())?;
    let source = Source { db, store, baseline, verifier };

    let committed_lookup = OperationLookup::Known(receipt.record.clone());
    ensure!(source.lookup(&seed.plan).await? == committed_lookup, "seed lookup differs from the first receipt");
    let seed_effects = source.seed_effects(&seed.plan).await?;
    let replay = commit(db, &seed.plan, &seed.token, &proof).await?;
    ensure!(replay.is_committed() && replay.replayed, "exact seed commit did not replay the committed operation");
    ensure!(
        replay.record == receipt.record && replay.terminal == receipt.terminal,
        "seed replay changed the original identity, revision or terminal effects"
    );
    ensure!(source.lookup(&seed.plan).await? == committed_lookup, "seed replay changed the operation lookup");
    ensure!(
        source.seed_effects(&seed.plan).await? == seed_effects,
        "seed replay changed the refs, gate, operation or publication effects"
    );

    let base_oid = GitOid::parse(format, &base)?;
    let fast_oid = GitOid::parse(format, &fast_head)?;
    let fast_forward = MergeClaim {
        pull_number: 1,
        expected_version: 2,
        head_ref: RefName::branch(FAST_FORWARD)?,
        head_oid: fast_oid,
        base_ref: RefName::branch(BASE)?,
        base_oid,
        strategy: MergeStrategy::FastForward,
    };
    let fast_proof = source.attest(2, &fast_forward, fast_oid, None).await??;
    ensure!(fast_proof.tree_oid() == GitOid::parse(format, &fast_tree)?, "fast-forward tree differs from stock Git");

    let merge = MergeClaim {
        pull_number: 2,
        expected_version: 3,
        head_ref: RefName::branch(TOPIC)?,
        head_oid: GitOid::parse(format, &topic_head)?,
        base_ref: RefName::branch(BASE)?,
        base_oid,
        strategy: MergeStrategy::MergeCommit,
    };
    let scratch = tempfile::tempdir()?;
    let merged_oid = GitOid::parse(format, &merged)?;
    let merged_tree_oid = GitOid::parse(format, &merged_tree)?;
    let old_objects = indexed_objects(git, &pair, format).await?;
    ensure!(
        !old_objects.contains(&merged_oid) && !old_objects.contains(&merged_tree_oid),
        "candidate commit and generated tree leaked into the source pack"
    );
    let full_pair = pack_objects(git, scratch.path(), "merge", &[&merged, &merged_tree]).await?;
    let merge_proof = source.attest(3, &merge, merged_oid, Some(&full_pair)).await??;
    ensure!(
        merge_proof.tree_oid() == merged_tree_oid,
        "merge tree differs from the stock-Git tree despite replacement ref isolation"
    );

    let wrong_tree_pair = pack_objects(git, scratch.path(), "wrong-tree", &[&wrong_tree]).await?;
    let result = source.attest(4, &merge, GitOid::parse(format, &wrong_tree)?, Some(&wrong_tree_pair)).await?;
    require_refusal(result, &["merge candidate tree differs from the native merge tree"], "wrong tree")?;

    let wrong_parents_pair =
        pack_objects(git, scratch.path(), "wrong-parents", &[&wrong_parents, &merged_tree]).await?;
    let result = source.attest(5, &merge, GitOid::parse(format, &wrong_parents)?, Some(&wrong_parents_pair)).await?;
    require_refusal(result, &["merge candidate does not have the expected ordered parents"], "reversed parents")?;

    let incomplete_pair = pack_objects(git, scratch.path(), "missing-tree", &[&merged]).await?;
    ensure!(
        indexed_objects(git, &incomplete_pair, format).await? == [merged_oid],
        "missing-tree pack must contain only the exact clean merge commit"
    );
    let result = source.attest(6, &merge, merged_oid, Some(&incomplete_pair)).await?;
    require_refusal(
        result,
        &[
            "native Git refused the owned verification repository view",
            "native Git refused the registered pack closure",
        ],
        "missing generated tree",
    )
}

async fn exercise_format(format: GitObjectFormat) -> Result<()> {
    let store = open_store()?;
    let git = GitRepo::new(git_binary()?, format).await?;
    let db = Db::setup().await?;
    let outcome = exercise(&db, &store, &git, format).await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL, OpenDAL S3 and stock Git 2.43+"]
async fn sha1_stock_git_merge_attestations_are_read_only() -> Result<()> {
    exercise_format(GitObjectFormat::Sha1).await
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL, OpenDAL S3 and stock Git 2.43+"]
async fn sha256_stock_git_merge_attestations_are_read_only() -> Result<()> {
    exercise_format(GitObjectFormat::Sha256).await
}
