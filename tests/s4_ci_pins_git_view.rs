//! S4 CI pin / Git view / reverse merge acceptance against real PG17, a
//! loopback S3 endpoint and native Git processes. Every case drives the public
//! HTTP routes; no SQL shortcut replaces an authorization or transport decision.
#[rustfmt::skip]
#[path = "s4_ci_pins_git_view_support/harness.rs"]
pub mod harness;

use anyhow::{Result, ensure};
use harness::{Cluster, Repository};
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
    let mut args = vec!["clone", "--no-local", "--no-hardlinks", "--no-tags"];
    if format == "sha256" {
        args.push("--object-format=sha256");
    }
    args.extend([path, "proj"]);
    cluster.git.ok(&work, &args).await?;
    Ok(work.join("proj"))
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

async fn revoke(cluster: &Cluster, repo: &Repository, job: Uuid) -> Result<()> {
    let url = format!("{}/api/repos/{}/{}/ci-checkouts/{job}/revoke", cluster.main, cluster.owner.username, repo.name);
    let response = reqwest::Client::new().post(url).bearer_auth(&cluster.owner.token).send().await?;
    ensure!(response.status().is_success(), "revoke returned {}", response.status());
    Ok(())
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
        let token = cluster.checkout(&repo, job, &first).await?;
        ensure!(token.starts_with("ryj_"), "checkout did not return a narrow job credential");
        ensure!(cluster.ci_clone(&repo, &first, &token).await? == first, "cold CI clone lost its pin");

        let second = cluster.force_push(&repo, "a.txt", "rewritten\n").await?;
        ensure!(second != first, "force push did not create a new commit");
        ensure!(
            cluster.ci_clone(&repo, &first, &token).await? == first,
            "the retained closure followed the live ref instead of the pin"
        );

        let wide = info_refs_status(&cluster, &repo, &first, Auth::Bearer("ryu_wide_credential")).await?;
        ensure!(wide == StatusCode::FORBIDDEN, "a wide user credential reached the CI transport: {wide}");
        let cross = info_refs_status(&cluster, &repo, &second, Auth::Basic {
            user: cluster.owner.username.as_str(),
            password: token.as_str(),
        })
        .await?;
        ensure!(cross == StatusCode::UNAUTHORIZED, "a job credential escaped its target closure: {cross}");

        revoke(&cluster, &repo, job).await?;
        let after = info_refs_status(&cluster, &repo, &first, Auth::Basic {
            user: cluster.owner.username.as_str(),
            password: token.as_str(),
        })
        .await?;
        ensure!(after == StatusCode::UNAUTHORIZED, "a revoked job credential still authorized a transfer");

        // A retained pack must stream in many bounded chunks. Releasing the pin
        // mid-stream has to end that stream instead of delivering every byte.
        let big = harness::incompressible(1_200_000);
        let big_oid = cluster.push_initial(&repo, &[("big.txt", big.as_str())]).await?;
        let stream_job = Uuid::new_v4();
        cluster.pin(&repo, stream_job, &big_oid).await?;
        let stream_token = cluster.checkout(&repo, stream_job, &big_oid).await?;
        let want = format!("want {big_oid}\n");
        let body = format!("{:04x}{want}00000009done\n", 4 + want.len());
        let url = format!(
            "{}/ci/{}/git/{}/{}/git-upload-pack",
            cluster.main, big_oid, cluster.owner.username, repo.name
        );
        let mut stream = reqwest::Client::new()
            .post(url)
            .basic_auth(&cluster.owner.username, Some(&stream_token))
            .header("Content-Type", "application/x-git-upload-pack-request")
            .body(body)
            .send()
            .await?;
        ensure!(stream.status().is_success(), "upload-pack returned {}", stream.status());
        let mut received = 0_usize;
        let Some(chunk) = stream.chunk().await?.filter(|chunk| !chunk.is_empty()) else {
            return Err(anyhow::anyhow!("the pack stream produced no first chunk"));
        };
        received += chunk.len();
        let released = reqwest::Client::new()
            .delete(format!(
                "{}/api/repos/{}/{}/ci-pins/{stream_job}",
                cluster.main, cluster.owner.username, repo.name
            ))
            .bearer_auth(&cluster.owner.token)
            .send()
            .await?;
        ensure!(released.status().is_success(), "mid-stream release returned {}", released.status());
        let mut stream_errored = false;
        loop {
            match stream.chunk().await {
                Ok(Some(chunk)) => received += chunk.len(),
                Ok(None) => break,
                Err(_) => {
                    stream_errored = true;
                    break;
                }
            }
        }
        ensure!(
            stream_errored || received < 550_000,
            "the revoked stream delivered the complete retained pack ({received} bytes)"
        );
        let dead = info_refs_status(&cluster, &repo, &big_oid, Auth::Basic {
            user: cluster.owner.username.as_str(),
            password: stream_token.as_str(),
        })
        .await?;
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

        // pg_refstore identity is guarded, so no product API can move a
        // repository between tenants. Re-seat the same repository under a new
        // owner in one replica-role fixture transaction, keeping the old URL
        // resolvable, so the old job credential must lose the repository.
        let transfer_job = Uuid::new_v4();
        cluster.pin(&repo, transfer_job, &big_oid).await?;
        let transfer_token = cluster.checkout(&repo, transfer_job, &big_oid).await?;
        let live = info_refs_status(&cluster, &repo, &big_oid, Auth::Basic {
            user: cluster.owner.username.as_str(),
            password: transfer_token.as_str(),
        })
        .await?;
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
        let gone = info_refs_status(&cluster, &repo, &big_oid, Auth::Basic {
            user: cluster.owner.username.as_str(),
            password: transfer_token.as_str(),
        })
        .await?;
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
        let job = Uuid::new_v4();
        cluster.pin(&repo, job, &base).await?;
        let token = cluster.checkout(&repo, job, &base).await?;
        cluster.ci_clone(&repo, &base, &token).await?;

        let namespace = cluster.namespace(&repo, &base, "/src").await?;
        let view = cluster.view(&namespace, "/src", "dir").await?;
        let bundle = cluster.get_bundle(&view).await?;
        let tree = clone_bundle(&cluster, &bundle, "sha1").await?;
        ensure!(tree.join("b.txt").is_file(), "the projected bundle lost the selected subtree");
        ensure!(!tree.join("root.txt").exists(), "the projected bundle leaked a path outside the mount");
        let branch = cluster.git.text(&tree, &["rev-parse", "--abbrev-ref", "HEAD"]).await?;
        ensure!(branch == "projected", "the bundle checked out {branch}, not the projected ref");
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

        let namespace = cluster.namespace(&repo, &base, "/src").await?;
        let view = cluster.view(&namespace, "/src", "").await?;
        let bundle = cluster.get_bundle(&view).await?;
        let tree = clone_bundle(&cluster, &bundle, "sha256").await?;
        ensure!(tree.join("note.txt").is_file(), "the SHA-256 projected bundle is empty");
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
