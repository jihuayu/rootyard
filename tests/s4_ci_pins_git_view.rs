//! S4 CI pin / Git view / reverse merge acceptance against real PG17, a
//! loopback S3 endpoint and native Git processes. Every case drives the public
//! HTTP routes; no SQL shortcut replaces an authorization or transport decision.
#[rustfmt::skip]
#[path = "s4_ci_pins_git_view_support/harness.rs"]
pub mod harness;
#[path = "s4_ci_pins_git_view_support/hold_regressions.rs"]
mod hold_regressions;
use anyhow::{Result, ensure};
use harness::{Cluster, Repository};
use hold_regressions::GateEpochRestoreGuard;
use reqwest::StatusCode;
use std::path::{Path, PathBuf};
use uuid::Uuid;

async fn clone_bundle(cluster: &Cluster, bytes: &[u8], format: &str) -> Result<PathBuf> {
    let root = cluster.scratch.join(format!("bundle-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&root)?;
    let bundle = root.join("view.bundle");
    std::fs::write(&bundle, bytes)?;
    let work = root.join("work");
    std::fs::create_dir_all(&work)?;
    let path = bundle.to_str().ok_or_else(|| anyhow::anyhow!("bundle path"))?;
    let proj = work.join("proj");
    if format == "sha256" {
        cluster.git.ok(&work, &["init", "--quiet", "--object-format=sha256", "proj"]).await?;
        cluster.git.ok(&proj, &["fetch", "--quiet", path, "refs/heads/projected:refs/heads/projected"]).await?;
        cluster.git.ok(&proj, &["checkout", "--quiet", "projected"]).await?;
        return Ok(proj);
    }
    cluster.git.ok(&work, &["clone", "--no-local", "--no-hardlinks", "--no-tags", path, "proj"]).await?;
    Ok(proj)
}

async fn proposal_bundle(cluster: &Cluster, work: &Path) -> Result<Vec<u8>> {
    cluster.git.ok(work, &["checkout", "--quiet", "-B", "projected"]).await?;
    let out = work.with_extension("proposal.bundle");
    let out_text = out.to_str().ok_or_else(|| anyhow::anyhow!("proposal path"))?;
    cluster.git.ok(work, &["bundle", "create", out_text, "refs/heads/projected"]).await?;
    Ok(std::fs::read(out)?)
}

async fn info_refs_status(cluster: &Cluster, repo: &Repository, target: &str, auth: Auth<'_>) -> Result<StatusCode> {
    let url = format!(
        "{}/ci/{}/git/{}/{}/info/refs?service=git-upload-pack",
        cluster.main, target, cluster.owner.username, repo.name
    );
    let request = reqwest::Client::new().get(url);
    let response = match auth {
        Auth::Basic { user, password } => request.basic_auth(user, Some(password)).send().await?,
        Auth::Bearer(token) => request.bearer_auth(token).send().await?,
    };
    Ok(response.status())
}

enum Auth<'a> {
    Basic { user: &'a str, password: &'a str },
    Bearer(&'a str),
}

async fn job_status(cluster: &Cluster, repo: &Repository, target: &str, token: &str) -> Result<StatusCode> {
    let auth = Auth::Basic { user: cluster.owner.username.as_str(), password: token };
    info_refs_status(cluster, repo, target, auth).await
}

async fn revoke(cluster: &Cluster, repo: &Repository, job: Uuid) -> Result<()> {
    let url = format!("{}/api/repos/{}/{}/ci-checkouts/{job}/revoke", cluster.main, cluster.owner.username, repo.name);
    let response = reqwest::Client::new().post(url).bearer_auth(&cluster.owner.token).send().await?;
    ensure!(response.status().is_success(), "revoke returned {}", response.status());
    Ok(())
}

async fn open_pack_stream(
    cluster: &Cluster,
    repo: &Repository,
    target: &str,
    token: &str,
) -> Result<reqwest::Response> {
    let want = format!("want {target}\n");
    let body = format!("{:04x}{want}00000009done\n", 4 + want.len());
    let url = format!("{}/ci/{}/git/{}/{}/git-upload-pack", cluster.main, target, cluster.owner.username, repo.name);
    let stream = reqwest::Client::new()
        .post(url)
        .basic_auth(&cluster.owner.username, Some(token))
        .header("Content-Type", "application/x-git-upload-pack-request")
        .body(body)
        .send()
        .await?;
    ensure!(stream.status().is_success(), "upload-pack returned {}", stream.status());
    Ok(stream)
}

/// Drain a pack response; `true` means the server aborted the stream.
async fn drain_pack(stream: &mut reqwest::Response, received: &mut usize) -> bool {
    loop {
        match stream.chunk().await {
            Ok(Some(chunk)) => *received += chunk.len(),
            Ok(None) => return false,
            Err(_) => return true,
        }
    }
}

async fn post_checkout(cluster: &Cluster, repo: &Repository, job: Uuid, target: &str, now: i64) -> Result<StatusCode> {
    let body = serde_json::json!({
        "job_id": job,
        "target_oid": target,
        "storage_generation": repo.generation,
        "mirror_audience": harness::AUDIENCE,
        "expires_unix": now + 600,
    });
    let url = format!("{}/api/repos/{}/{}/ci-checkouts", cluster.main, cluster.owner.username, repo.name);
    harness::post_status(&url, &cluster.owner.token, body).await
}

async fn job_and_grant_counts(cluster: &Cluster, job: Uuid) -> Result<(i64, i64)> {
    let row = cluster
        .pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM ci_checkout_jobs WHERE job_id=$1), \
                    (SELECT count(*) FROM s4_ci_retention.closure_grants WHERE job_id=$1)",
            &[&job],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_pin_retained_clone_survives_force_push_and_revocation() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let outcome = async {
        let repo = cluster.create_repository("pin-repo", "sha1").await?;
        let first = cluster.push_initial(&repo, &[("a.txt", "retained\n")]).await?;
        let job = Uuid::new_v4();
        let pinned = cluster.pin(&repo, job, &first).await?;
        ensure!(pinned["state"].as_str() == Some("pinned"), "pin response was not pinned: {pinned}");
        ensure!(pinned["target_oid"].as_str() == Some(first.as_str()), "pin stored another commit");
        let replay = cluster.pin(&repo, job, &first).await?;
        ensure!(replay["state"].as_str() == Some("pinned"), "pin replay was not idempotent: {replay}");
        let root_sql = "SELECT count(*) FROM ref_store_core_root_heads h \
             JOIN repositories r ON r.id=h.repository_id WHERE r.name=$1 AND h.state='active'";
        let roots: i64 = cluster.pool.get().await?.query_one(root_sql, &[&repo.name]).await?.get(0);
        ensure!(roots == 1, "an idempotent pin replay leaked {roots} active retention roots");
        let token = cluster.checkout(&repo, job, &first).await?;
        ensure!(token.starts_with("ryj_"), "checkout did not return a narrow job credential");
        ensure!(cluster.ci_clone(&repo, &first, &token).await? == first, "cold CI clone lost its pin");

        for auth in [
            Auth::Bearer(&cluster.owner.token),
            Auth::Basic { user: &cluster.owner.username, password: &cluster.owner.token },
        ] {
            let wide_user = info_refs_status(&cluster, &repo, &first, auth).await?;
            ensure!(wide_user == StatusCode::FORBIDDEN, "a wide user token reached CI transport: {wide_user}");
        }

        let upper = format!("want {}\n", first.to_ascii_uppercase());
        let pkt = format!("{:04x}{upper}00000009done\n", 4 + upper.len());
        let upper_url = format!(
            "{}/ci/{}/git/{}/{}/git-upload-pack",
            cluster.main, first, cluster.owner.username, repo.name
        );
        let upper_status = reqwest::Client::new()
            .post(upper_url)
            .basic_auth(&cluster.owner.username, Some(&token))
            .header("Content-Type", "application/x-git-upload-pack-request")
            .body(pkt)
            .send()
            .await?
            .status();
        ensure!(upper_status == StatusCode::FORBIDDEN, "an uppercase hex want was accepted: {upper_status}");

        let cancelled_job = Uuid::new_v4();
        let cancel_url = format!(
            "{}/api/repos/{}/{}/ci-checkouts/{cancelled_job}/cancel",
            cluster.main, cluster.owner.username, repo.name
        );
        let cancel = reqwest::Client::new().post(cancel_url).bearer_auth(&cluster.owner.token).send().await?;
        ensure!(cancel.status().is_success(), "pre-cancel returned {}", cancel.status());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        let cancelled_body = serde_json::json!({
            "job_id": cancelled_job,
            "target_oid": first,
            "storage_generation": repo.generation,
            "mirror_audience": harness::AUDIENCE,
            "expires_unix": now + 600,
        });
        let checkout_url = format!("{}/api/repos/{}/{}/ci-checkouts", cluster.main, cluster.owner.username, repo.name);
        let after_cancel = harness::post_status(&checkout_url, &cluster.owner.token, cancelled_body).await?;
        ensure!(after_cancel == StatusCode::CONFLICT, "a pre-cancelled plan was reissued: {after_cancel}");

        let second = cluster.force_push(&repo, "a.txt", "rewritten\n").await?;
        ensure!(second != first, "force push did not create a new commit");
        ensure!(
            cluster.ci_clone(&repo, &first, &token).await? == first,
            "the retained closure followed the live ref instead of the pin"
        );

        let wide = info_refs_status(&cluster, &repo, &first, Auth::Bearer("ryu_wide_credential")).await?;
        ensure!(wide == StatusCode::FORBIDDEN, "a wide user credential reached the CI transport: {wide}");
        let cross = job_status(&cluster, &repo, &second, &token).await?;
        ensure!(cross == StatusCode::UNAUTHORIZED, "a job credential escaped its target closure: {cross}");

        revoke(&cluster, &repo, job).await?;
        let after = job_status(&cluster, &repo, &first, &token).await?;
        ensure!(after == StatusCode::UNAUTHORIZED, "a revoked job credential still authorized a transfer");

        // A retained pack must stream in many bounded chunks. Releasing the pin
        // mid-stream has to end that stream instead of delivering every byte.
        let big = harness::incompressible(1_200_000);
        let big_oid = cluster.push_initial(&repo, &[("big.txt", big.as_str())]).await?;
        let stream_job = Uuid::new_v4();
        cluster.pin(&repo, stream_job, &big_oid).await?;
        let stream_token = cluster.checkout(&repo, stream_job, &big_oid).await?;
        let mut stream = open_pack_stream(&cluster, &repo, &big_oid, &stream_token).await?;
        let Some(chunk) = stream.chunk().await?.filter(|chunk| !chunk.is_empty()) else {
            return Err(anyhow::anyhow!("the pack stream produced no first chunk"));
        };
        let mut received = chunk.len();
        let released = reqwest::Client::new()
            .delete(format!(
                "{}/api/repos/{}/{}/ci-pins/{stream_job}",
                cluster.main, cluster.owner.username, repo.name
            ))
            .bearer_auth(&cluster.owner.token)
            .send()
            .await?;
        ensure!(released.status().is_success(), "mid-stream release returned {}", released.status());
        let stream_errored = drain_pack(&mut stream, &mut received).await;
        ensure!(
            stream_errored || received < 550_000,
            "the revoked stream delivered the complete retained pack ({received} bytes)"
        );
        let dead = job_status(&cluster, &repo, &big_oid, &stream_token).await?;
        ensure!(dead == StatusCode::UNAUTHORIZED, "a released stream credential still authorized info/refs");

        // A refused issuance must not leave a durable pin or job row behind: the
        // retention pin and the checkout registry roll back with one transaction.
        let bad_job = Uuid::new_v4();
        let body = serde_json::json!({
            "job_id": bad_job,
            "target_oid": big_oid,
            "storage_generation": repo.generation,
            "mirror_audience": harness::AUDIENCE,
            "expires_unix": 0,
        });
        let url = format!("{}/api/repos/{}/{}/ci-checkouts", cluster.main, cluster.owner.username, repo.name);
        let refused = harness::post_status(&url, &cluster.owner.token, body).await?;
        ensure!(refused == StatusCode::BAD_REQUEST, "a zero expiry was accepted: {refused}");
        let client = cluster.pool.get().await?;
        let job_sql = "SELECT count(*) FROM ci_checkout_jobs WHERE job_id=$1";
        let jobs: i64 = client.query_one(job_sql, &[&bad_job]).await?.get(0);
        let pin_sql = "SELECT count(*) FROM s4_ci_retention.ci_pins WHERE job_id=$1";
        let pins: i64 = client.query_one(pin_sql, &[&bad_job]).await?.get(0);
        ensure!(jobs == 0 && pins == 0, "a refused checkout left job={jobs} pin={pins} rows");

        // A pin released before checkout must never be turned into a job/grant.
        let released_first_job = Uuid::new_v4();
        cluster.pin(&repo, released_first_job, &first).await?;
        let released = reqwest::Client::new()
            .delete(format!(
                "{}/api/repos/{}/{}/ci-pins/{released_first_job}",
                cluster.main, cluster.owner.username, repo.name
            ))
            .bearer_auth(&cluster.owner.token)
            .send()
            .await?;
        ensure!(released.status().is_success(), "release-before-checkout returned {}", released.status());
        let after_release = post_checkout(&cluster, &repo, released_first_job, &first, now).await?;
        ensure!(after_release == StatusCode::CONFLICT, "a released pin was reissued: {after_release}");
        let (jobs, grants) = job_and_grant_counts(&cluster, released_first_job).await?;
        ensure!(jobs == 0 && grants == 0, "a released pin left job={jobs} grant={grants}");

        // A reused pin whose retained root was released must fail inside the
        // issuance transaction, before any job or closure grant is inserted.
        let root_released_job = Uuid::new_v4();
        cluster.pin(&repo, root_released_job, &first).await?;
        let mut releaser = cluster.pool.get().await?;
        let tx = releaser.transaction().await?;
        tx.execute(
            "UPDATE ref_store_core_root_heads h SET state='released', last_generation=2 \
             FROM s4_ci_retention.ci_pins p \
             WHERE h.repository_id=p.repository_id AND h.root_id=p.retention_root_id AND p.job_id=$1",
            &[&root_released_job],
        )
        .await?;
        tx.commit().await?;
        let after_root_release = post_checkout(&cluster, &repo, root_released_job, &first, now).await?;
        ensure!(
            after_root_release == StatusCode::CONFLICT,
            "a released root was reissued: {after_root_release}"
        );
        let (jobs, grants) = job_and_grant_counts(&cluster, root_released_job).await?;
        ensure!(jobs == 0 && grants == 0, "a released root left job={jobs} grant={grants}");

        // Bumping authority/history while a transfer streams must terminate it
        // and invalidate the same narrow credential for later requests.
        let epoch_job = Uuid::new_v4();
        cluster.pin(&repo, epoch_job, &big_oid).await?;
        let epoch_token = cluster.checkout(&repo, epoch_job, &big_oid).await?;
        let mut epoch_stream = open_pack_stream(&cluster, &repo, &big_oid, &epoch_token).await?;
        let Some(chunk) = epoch_stream.chunk().await?.filter(|chunk| !chunk.is_empty()) else {
            return Err(anyhow::anyhow!("the epoch pack stream produced no first chunk"));
        };
        let mut epoch_received = chunk.len();
        let gate_sql = "SELECT authority_epoch FROM ref_store_core_gates WHERE repository_id=$1";
        let old_epoch: i64 = cluster.pool.get().await?.query_one(gate_sql, &[&repo.id]).await?.get(0);
        let mut gate_guard =
            GateEpochRestoreGuard::rotate(&cluster.pool, repo.id, old_epoch + 1, Uuid::new_v4()).await?;
        let epoch_errored = drain_pack(&mut epoch_stream, &mut epoch_received).await;
        ensure!(
            epoch_errored || epoch_received < 550_000,
            "an epoch-bumped stream delivered the complete retained pack ({epoch_received} bytes)"
        );
        let epoch_dead = job_status(&cluster, &repo, &big_oid, &epoch_token).await?;
        ensure!(epoch_dead == StatusCode::UNAUTHORIZED, "an epoch-bumped credential still authorized");
        gate_guard.restore(&cluster.pool).await?;

        // Rotating the cluster anchor must end the stream and the credential.
        let cluster_job = Uuid::new_v4();
        cluster.pin(&repo, cluster_job, &big_oid).await?;
        let cluster_token = cluster.checkout(&repo, cluster_job, &big_oid).await?;
        let mut cluster_stream = open_pack_stream(&cluster, &repo, &big_oid, &cluster_token).await?;
        let Some(chunk) = cluster_stream.chunk().await?.filter(|chunk| !chunk.is_empty()) else {
            return Err(anyhow::anyhow!("the cluster pack stream produced no first chunk"));
        };
        let mut cluster_received = chunk.len();
        let mut authority_guard =
            hold_regressions::ClusterAuthorityRestoreGuard::rotate(&cluster.pool, Uuid::new_v4()).await?;
        let cluster_errored = drain_pack(&mut cluster_stream, &mut cluster_received).await;
        ensure!(
            cluster_errored || cluster_received < 550_000,
            "a rotated cluster anchor delivered the complete pack ({cluster_received} bytes)"
        );
        let cluster_dead = job_status(&cluster, &repo, &big_oid, &cluster_token).await?;
        ensure!(cluster_dead == StatusCode::UNAUTHORIZED, "a cluster-rotated credential still authorized");
        authority_guard.restore(&cluster.pool).await?;

        // pg_refstore identity is guarded, so no product API can move a
        // repository between tenants. Re-seat the same repository under a new
        // owner in one replica-role fixture transaction, keeping the old URL
        // resolvable, so the old job credential must lose the repository.
        let transfer_job = Uuid::new_v4();
        cluster.pin(&repo, transfer_job, &big_oid).await?;
        let transfer_token = cluster.checkout(&repo, transfer_job, &big_oid).await?;
        let live = job_status(&cluster, &repo, &big_oid, &transfer_token).await?;
        ensure!(live == StatusCode::OK, "a live credential was refused before the transfer: {live}");
        let new_username = format!("s4move{}", &Uuid::new_v4().simple().to_string()[..12]);
        let issued = rootyard::db::issue_token(&cluster.pool, &new_username, true, false).await;
        let issued = issued.map_err(|error| anyhow::anyhow!("issue token: {error}"))?;
        let issued_id = issued["user_id"].as_str().ok_or_else(|| anyhow::anyhow!("new user id"))?;
        let new_owner = Uuid::parse_str(issued_id)?;
        let mut mover = cluster.pool.get().await?;
        let tx = mover.transaction().await?;
        tx.execute("SET LOCAL session_replication_role = replica", &[]).await?;
        let parked = format!("moved{}", &Uuid::new_v4().simple().to_string()[..16]);
        let park = "UPDATE namespaces SET slug=$1 WHERE id=$2";
        tx.execute(park, &[&parked, &cluster.owner.identity.id]).await?;
        tx.execute(park, &[&cluster.owner.username, &new_owner]).await?;
        let move_sql = "WITH moved AS (UPDATE repositories SET owner_id=$1 WHERE name=$2 RETURNING id) \
             , gate AS (UPDATE ref_store_core_gates g SET tenant_id=$1 FROM moved m WHERE g.repository_id=m.id) \
             , realm AS (UPDATE ref_store_core_protocol_repos p SET tenant_id=$1 FROM moved m WHERE p.repository_id=m.id) \
             , binding AS (UPDATE ref_store_serving_repositories b SET owner_id=$1 FROM moved m WHERE b.repository_id=m.id) \
             SELECT count(*) FROM moved";
        let moved: i64 = tx.query_one(move_sql, &[&new_owner, &repo.name]).await?.get(0);
        tx.execute("SET LOCAL session_replication_role = origin", &[]).await?;
        tx.commit().await?;
        ensure!(moved == 1, "the ownership transfer moved {moved} repositories");
        let gone = job_status(&cluster, &repo, &big_oid, &transfer_token).await?;
        ensure!(
            gone == StatusCode::UNAUTHORIZED,
            "an old-tenant credential survived the ownership transfer: {gone}"
        );
        Ok(())
    }
    .await;
    cluster.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_git_view_bundle_is_projected_only_and_reverse_merges_the_subtree() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let outcome = async {
        let repo = cluster.create_repository("view-repo", "sha1").await?;
        let base = cluster.push_initial(&repo, &[("root.txt", "root\n"), ("dir/b.txt", "before\n")]).await?;

        let namespace = cluster.namespace(&repo, &base, "src").await?;
        let view = cluster.view(&namespace, "src", "dir").await?;
        let bundle = cluster.get_bundle(&view).await?;
        let tree = clone_bundle(&cluster, &bundle, "sha1").await?;
        ensure!(tree.join("b.txt").is_file(), "the projected bundle lost the selected subtree");
        ensure!(!tree.join("root.txt").exists(), "the projected bundle leaked a path outside the mount");
        let branch = cluster.git.text(&tree, &["rev-parse", "--abbrev-ref", "HEAD"]).await?;
        ensure!(branch == "projected", "the bundle checked out {branch}, not the projected ref");
        let http_tree = cluster.clone_view(&view, "sha1").await?;
        ensure!(http_tree.join("b.txt").is_file(), "the Smart HTTP view lost the selected subtree");
        ensure!(!http_tree.join("root.txt").exists(), "the Smart HTTP view leaked a path outside the mount");
        let http_branch = cluster.git.text(&http_tree, &["rev-parse", "--abbrev-ref", "HEAD"]).await?;
        ensure!(http_branch == "projected", "the Smart HTTP view checked out {http_branch}, not projected");
        ensure!(
            !cluster.scratch.join("data/workspace-service/views").exists(),
            "the git view leaked a durable workspace-service copy"
        );
        let view_id = Uuid::parse_str(&view)?;
        let client = cluster.pool.get().await?;
        let binding_sql = "SELECT count(*) FROM s4_ci_retention.git_view_bindings b \
             JOIN ref_store_core_root_heads h ON h.repository_id=b.repository_id AND h.root_id=b.retention_root_id \
             WHERE b.view_id=$1 AND h.state='active'";
        let bound: i64 = client.query_one(binding_sql, &[&view_id]).await?.get(0);
        ensure!(bound == 1, "the view has no active retained root binding");

        cluster.git.commit(&tree, "b.txt", "after reverse\n", "reverse fixture merge").await?;
        let proposal = proposal_bundle(&cluster, &tree).await?;
        let changeset = cluster.reverse(&view, &proposal, "refs/heads/main").await?;
        ensure!(changeset["state"].as_str() == Some("complete"), "reverse merge did not complete: {changeset}");

        let source = cluster.clone_source(&repo).await?;
        let merged = std::fs::read_to_string(source.join("dir/b.txt"))?;
        ensure!(merged == "after reverse\n", "the source subtree was not replaced: {merged:?}");
        ensure!(source.join("root.txt").is_file(), "reverse merge destroyed a sibling subtree");
        let subject = cluster.git.text(&source, &["log", "-1", "--format=%s"]).await?;
        ensure!(subject == "reverse fixture merge", "reverse merge did not preserve the message: {subject}");
        Ok(())
    }
    .await;
    cluster.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_sha256_pin_clone_and_reverse_round_trip() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let outcome = async {
        let repo = cluster.create_repository("sha256-repo", "sha256").await?;
        let base = cluster.push_initial(&repo, &[("note.txt", "sha256 before\n")]).await?;
        ensure!(base.len() == 64, "the fixture did not produce a SHA-256 object id");
        let job = Uuid::new_v4();
        cluster.pin(&repo, job, &base).await?;
        let token = cluster.checkout(&repo, job, &base).await?;
        ensure!(cluster.ci_clone(&repo, &base, &token).await? == base, "SHA-256 CI clone lost its pin");

        let namespace = cluster.namespace(&repo, &base, "src").await?;
        let view = cluster.view(&namespace, "src", "").await?;
        let bundle = cluster.get_bundle(&view).await?;
        let tree = clone_bundle(&cluster, &bundle, "sha256").await?;
        ensure!(tree.join("note.txt").is_file(), "the SHA-256 projected bundle is empty");
        let http_tree = cluster.clone_view(&view, "sha256").await?;
        ensure!(http_tree.join("note.txt").is_file(), "the SHA-256 Smart HTTP view is empty");
        let oid = cluster.git.text(&tree, &["rev-parse", "HEAD"]).await?;
        ensure!(oid.len() == 64, "the projected bundle is not SHA-256");

        cluster.git.commit(&tree, "note.txt", "sha256 after\n", "sha256 reverse").await?;
        let proposal = proposal_bundle(&cluster, &tree).await?;
        let changeset = cluster.reverse(&view, &proposal, "refs/heads/main").await?;
        ensure!(changeset["state"].as_str() == Some("complete"), "SHA-256 reverse merge incomplete: {changeset}");

        let source = cluster.clone_source(&repo).await?;
        ensure!(std::fs::read_to_string(source.join("note.txt"))? == "sha256 after\n", "SHA-256 source not merged");
        Ok(())
    }
    .await;
    cluster.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_terminal_job_rechecks_under_final_lock() -> Result<()> {
    hold_regressions::terminal_job_race().await
}
#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_git_children_are_bounded_and_reaped() -> Result<()> {
    hold_regressions::bounded_child_lifecycle().await
}
#[tokio::test]
#[ignore = "requires real PG17, an S3 endpoint and native Git"]
async fn s4_cluster_authority_fixture_restores_on_failure() -> Result<()> {
    hold_regressions::cluster_authority_restores_on_failure_and_panic().await
}
