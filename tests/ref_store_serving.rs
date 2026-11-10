//! Real-PostgreSQL contract tests for the durable `pg_refstore` serving API.
//!
//! Run explicitly by the root runner:
//! `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_store_serving -- --ignored`.
//! Selecting this suite without a database panics instead of silently passing.
//! Every schema is random and task-owned; the Blob backend identities come from
//! the production profile factory (no provider IO is performed and no GitFS
//! directory is created). No Git/native command, Vault, Garage call or HTTP
//! route is exercised here: these are the internal trusted-caller APIs.
mod serving_support;

use anyhow::{Context, Result, bail, ensure};
use axum::http::StatusCode;
use rootyard::ref_store::{
    CommitMode, CommitRefsReceipt, CommitRefsRequest, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane,
    PgRefStoreCore, RefName, RefPrecondition, RefTarget, RefUpdate, VersionCheck,
    core::{DecisionFence, PgDecisionProtocol},
    serving::{ProvisionRequest, lookup, provision},
};
use serving_support::{Fixture, actor, backend_identity, deadline};
use uuid::Uuid;

const HEAD: &str = "refs/heads/main";

fn request(name: &str, owner: Option<&str>, format: GitObjectFormat) -> ProvisionRequest {
    ProvisionRequest { owner: owner.map(str::to_owned), name: name.to_owned(), object_format: format }
}

async fn one_i64(fixture: &Fixture, sql: &str, repo: &Uuid) -> Result<i64> {
    Ok(fixture.pool.get().await?.query_one(sql, &[repo]).await?.get(0))
}

async fn one_text(fixture: &Fixture, sql: &str, repo: &Uuid) -> Result<String> {
    Ok(fixture.pool.get().await?.query_one(sql, &[repo]).await?.get(0))
}

fn commit_request(
    repo: Uuid,
    tenant: Uuid,
    format: GitObjectFormat,
    history: Uuid,
    expected_revision: i64,
    oid: GitOid,
    operation: Uuid,
) -> Result<CommitRefsRequest> {
    Ok(CommitRefsRequest::new(
        repo,
        tenant,
        tenant,
        IssuerLane::new("serving-test")?,
        1,
        operation,
        format,
        history,
        1,
        1,
        expected_revision,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(RefName::branch(HEAD)?, RefPrecondition::Absent, RefTarget::Oid(oid))],
    )?)
}

async fn commit(fixture: &Fixture, request: &CommitRefsRequest) -> Result<CommitRefsReceipt> {
    let mut client = fixture.pool.get().await?;
    Ok(PgRefStoreCore.commit_refs(&mut client, request, deadline()).await?)
}

async fn gate_version(fixture: &Fixture, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = fixture.pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => bail!("the provisioned repository has no core gate"),
    }
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn provision_creates_durable_pg_refstore_authority_without_gitfs() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-primary")?;
        let other = backend_identity("serving-other")?;
        ensure!(backend.as_hex() != other.as_hex(), "two buckets must not share an identity");

        let receipt = provision(
            &fixture.pool,
            &alice.identity,
            request("durable", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await
        .context("provision")?;
        let repo = receipt.repository.id;
        ensure!(receipt.created, "a fresh provision must report created");
        ensure!(receipt.repository.state == "ready", "the provisioned repository is not ready");
        ensure!(receipt.repository.storage_backend == "pg_refstore", "the backend is not pg_refstore");
        ensure!(receipt.repository.owner == alice.username, "the repository owner namespace differs");
        // No GitFS storage was created for this repository.
        ensure!(
            !std::path::Path::new(&receipt.repository.clone_path).exists(),
            "provisioning must not create a local GitFS repository"
        );

        // Exactly one durable gate / protocol realm / serving binding, and the
        // history incarnation is the stored one (never a fresh roll).
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM ref_store_core_gates WHERE repository_id=$1", &repo).await? == 1
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM ref_store_core_protocol_repos WHERE repository_id=$1", &repo)
                .await?
                == 1
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM ref_store_serving_repositories WHERE repository_id=$1", &repo)
                .await?
                == 1
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM pando_repository_states WHERE repository_id=$1", &repo).await? == 0,
            "a pg_refstore authority must not create a Pando state row"
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM repository_ref_projection WHERE repository_id=$1", &repo).await?
                == 0,
            "a pg_refstore authority must not create legacy projection rows"
        );
        let state =
            one_text(&fixture, "SELECT state FROM ref_store_serving_repositories WHERE repository_id=$1", &repo)
                .await?;
        ensure!(state == "ready", "the durable serving binding is not ready");
        let stored_history = one_text(
            &fixture,
            "SELECT history_incarnation::text FROM ref_store_serving_repositories WHERE repository_id=$1",
            &repo,
        )
        .await?;
        let gate = gate_version(&fixture, repo, alice.user_id).await?;
        ensure!(gate.revision() == 1, "a fresh gate must be revision 1");
        ensure!(
            gate.history_incarnation().to_string() == stored_history,
            "gate history differs from the stored intent"
        );
        ensure!(gate.object_format() == GitObjectFormat::Sha1, "gate object format differs");
        ensure!(gate.head_ref().as_str() == HEAD, "gate HEAD differs");

        // The protocol realm is provisioned with the decision fence already required.
        let mut client = fixture.pool.get().await?;
        let protocol = PgDecisionProtocol::new()
            .read(&mut client, repo, deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("the provisioned repository has no protocol realm"))?;
        ensure!(protocol.decision_required(), "serving must require decisions before readiness");
        ensure!(protocol.tenant_id() == alice.user_id, "the protocol tenant is not the owner namespace");
        ensure!(
            protocol.history_incarnation().to_string() == stored_history,
            "the protocol history differs from the stored intent"
        );
        ensure!(
            PgDecisionProtocol::new().read_fence(&mut client, repo, deadline()).await? == DecisionFence::Required,
            "the serving decision fence must already be required"
        );

        // Ready serving is never permission to publish an unverified object.
        // Only the real authorized pack/native pipeline may create served refs.
        let first = commit_request(
            repo,
            alice.user_id,
            GitObjectFormat::Sha1,
            gate.history_incarnation(),
            1,
            GitOid::Sha1([7; 20]),
            Uuid::new_v4(),
        )?;
        ensure!(commit(&fixture, &first).await.is_err(), "metadata-only commit bypassed serving byte verification");
        let moved = gate_version(&fixture, repo, alice.user_id).await?;
        ensure!(moved.revision() == 1, "refused metadata-only write changed the gate");

        // Lookup returns the live gate after current authorization, and the
        // same repository is refused for a different opened backend.
        let served = lookup(&fixture.pool, &alice.identity, &alice.username, "durable", false, &backend, deadline())
            .await
            .context("lookup")?;
        ensure!(served.repository.id == repo, "lookup resolved another repository");
        ensure!(served.gate.revision() == 1, "lookup changed the refused gate");
        ensure!(served.gate.history_incarnation() == gate.history_incarnation(), "lookup gate history differs");
        let mismatch =
            lookup(&fixture.pool, &alice.identity, &alice.username, "durable", false, &other, deadline()).await;
        match mismatch {
            Err(error) if error.0 == StatusCode::CONFLICT => {}
            other => bail!("a different opened Blob backend must be refused, got {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn provisioning_retry_reuses_the_durable_intent_without_rerolling_history() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-retry")?;
        let first = provision(
            &fixture.pool,
            &alice.identity,
            request("retry", None, GitObjectFormat::Sha256),
            &backend,
            deadline(),
        )
        .await?;
        let repo = first.repository.id;
        let history = one_text(
            &fixture,
            "SELECT history_incarnation::text FROM ref_store_serving_repositories WHERE repository_id=$1",
            &repo,
        )
        .await?;

        for _ in 0..3 {
            let again = provision(
                &fixture.pool,
                &alice.identity,
                request("retry", None, GitObjectFormat::Sha256),
                &backend,
                deadline(),
            )
            .await
            .context("idempotent retry")?;
            ensure!(!again.created, "a retry must not report a new repository");
            ensure!(again.repository.id == repo, "a retry resolved another repository");
            ensure!(again.repository.object_format == "sha256", "the retry changed the object format");
            let stored = one_text(
                &fixture,
                "SELECT history_incarnation::text FROM ref_store_serving_repositories WHERE repository_id=$1",
                &repo,
            )
            .await?;
            ensure!(stored == history, "a retry re-rolled the history incarnation");
        }
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM ref_store_serving_repositories WHERE repository_id=$1", &repo)
                .await?
                == 1,
            "a retry created a second serving intent"
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM repositories WHERE owner_id=$1 AND name='retry'", &alice.user_id)
                .await?
                == 1,
            "a retry created a second repository row"
        );
        // The object format is immutable even through the intent.
        let conflict = provision(
            &fixture.pool,
            &alice.identity,
            request("retry", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await;
        match conflict {
            Err(error) if error.0 == StatusCode::CONFLICT => {}
            other => bail!("an object-format change must be a conflict, got {other:?}"),
        }
        // A different opened backend cannot take over the intent.
        let other = backend_identity("serving-retry-other")?;
        let conflict = provision(
            &fixture.pool,
            &alice.identity,
            request("retry", None, GitObjectFormat::Sha256),
            &other,
            deadline(),
        )
        .await;
        match conflict {
            Err(error) if error.0 == StatusCode::CONFLICT => {}
            other => bail!("a different Blob backend must be a conflict, got {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn concurrent_provisioning_converges_on_one_authority() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-concurrent")?;
        let mut handles = Vec::new();
        for _ in 0..6 {
            let pool = fixture.pool.clone();
            let identity = alice.identity.clone();
            let backend = backend.clone();
            handles.push(tokio::spawn(async move {
                provision(&pool, &identity, request("concurrent", None, GitObjectFormat::Sha1), &backend, deadline())
                    .await
            }));
        }
        let mut ids = Vec::new();
        let mut created = 0;
        for handle in handles {
            let receipt = handle.await.context("join")?.context("concurrent provision")?;
            if receipt.created {
                created += 1;
            }
            ensure!(receipt.repository.state == "ready", "a concurrent provision left the repository unready");
            ids.push(receipt.repository.id);
        }
        ensure!(created == 1, "exactly one concurrent provision may create the repository, got {created}");
        let first = ids[0];
        ensure!(ids.iter().all(|id| *id == first), "concurrent provisions resolved different repositories");
        ensure!(
            one_i64(
                &fixture,
                "SELECT count(*) FROM ref_store_serving_repositories WHERE owner_id=$1 AND name='concurrent'",
                &alice.user_id
            )
            .await?
                == 1,
            "concurrent provisioning created more than one intent"
        );
        ensure!(
            one_i64(&fixture, "SELECT count(*) FROM ref_store_core_gates WHERE repository_id=$1", &first).await? == 1,
            "concurrent provisioning created more than one gate"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn foreign_tenant_and_restricted_tokens_are_refused() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let mallory = actor(&fixture.pool, false).await?;
        let restricted = actor(&fixture.pool, true).await?;
        let backend = backend_identity("serving-auth")?;

        // A restricted token has no create scope: provisioning is refused
        // explicitly instead of inferring create from repo_admin.
        let refused = provision(
            &fixture.pool,
            &restricted.identity,
            request("restricted", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await;
        match refused {
            Err(error) if error.0 == StatusCode::FORBIDDEN => {}
            other => bail!("a restricted token must be refused, got {other:?}"),
        }
        // A foreign tenant cannot provision into another user's namespace.
        let refused = provision(
            &fixture.pool,
            &mallory.identity,
            request("stolen", Some(&alice.username), GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await;
        match refused {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            other => bail!("a foreign namespace create must be not-found, got {other:?}"),
        }
        // …nor read one.
        provision(
            &fixture.pool,
            &alice.identity,
            request("private", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await?;
        let refused =
            lookup(&fixture.pool, &mallory.identity, &alice.username, "private", false, &backend, deadline()).await;
        match refused {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            other => bail!("a foreign tenant lookup must be not-found, got {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn ordinary_ready_gitfs_and_pando_authority_are_never_adopted() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-legacy")?;
        let repo = Uuid::new_v4();
        {
            let client = fixture.pool.get().await?;
            client
                .execute(
                    "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                     VALUES($1,$2,'legacy','ready','gitfs','sha1')",
                    &[&repo, &alice.user_id],
                )
                .await?;
        }
        // A ready gitfs repository is not a pg_refstore authority.
        let refused =
            lookup(&fixture.pool, &alice.identity, &alice.username, "legacy", false, &backend, deadline()).await;
        match refused {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            other => bail!("a ready gitfs repository must not resolve as pg_refstore, got {other:?}"),
        }
        // Provisioning the same name cannot adopt or replace it.
        let refused = provision(
            &fixture.pool,
            &alice.identity,
            request("legacy", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await;
        match refused {
            Err(error) if error.0 == StatusCode::CONFLICT => {}
            other => bail!("provisioning must refuse an existing legacy authority, got {other:?}"),
        }
        // A forged backend string alone cannot mint authority: the backend
        // column of an existing repository is immutable and a ready pg_refstore
        // row without a ready binding is refused by migration 145.
        let forged = fixture
            .pool
            .get()
            .await?
            .execute("UPDATE repositories SET storage_backend='pg_refstore' WHERE id=$1", &[&repo])
            .await;
        ensure!(forged.is_err(), "a forged storage_backend transition must be refused");
        let bare = Uuid::new_v4();
        {
            let client = fixture.pool.get().await?;
            client
                .execute(
                    "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                     VALUES($1,$2,'bare','provisioning','pg_refstore','sha1')",
                    &[&bare, &alice.user_id],
                )
                .await?;
        }
        let promoted =
            fixture.pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&bare]).await;
        ensure!(promoted.is_err(), "a pg_refstore repository must not become ready without a ready binding");
        // And a Pando authority means no pg_refstore intent.
        let pando = Uuid::new_v4();
        {
            let client = fixture.pool.get().await?;
            client
                .execute(
                    "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                     VALUES($1,$2,'pando','provisioning','pando','sha1')",
                    &[&pando, &alice.user_id],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,object_format,state)
                     VALUES($1,$2,1,'sha1','copying')",
                    &[&pando, &alice.user_id],
                )
                .await?;
        }
        match provision(
            &fixture.pool,
            &alice.identity,
            request("pando", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await
        {
            Err(error) if error.0 == StatusCode::CONFLICT => {}
            other => bail!("a Pando repository must not be adopted, got {other:?}"),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn ambiguous_commit_is_resolved_by_the_same_idempotent_provision() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-ambiguous")?;
        let first = provision(
            &fixture.pool,
            &alice.identity,
            request("ambiguous", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await?;
        // A second call with an already expired deadline must not be reported as
        // a successful commit; the durable state from the first call is the
        // resolution and the retry converges on it.
        let expired = tokio::time::Instant::now();
        let timed = provision(
            &fixture.pool,
            &alice.identity,
            request("ambiguous", None, GitObjectFormat::Sha1),
            &backend,
            expired,
        )
        .await;
        match timed {
            Err(error) if error.0 == StatusCode::GATEWAY_TIMEOUT || error.0 == StatusCode::SERVICE_UNAVAILABLE => {}
            other => bail!("an expired deadline must not be a success, got {other:?}"),
        }
        let again = provision(
            &fixture.pool,
            &alice.identity,
            request("ambiguous", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await?;
        ensure!(!again.created, "the resolving retry created a second repository");
        ensure!(again.repository.id == first.repository.id, "the resolving retry changed the repository");
        ensure!(again.repository.state == "ready", "the resolving retry left the repository unready");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn single_connection_pool_provisions_retries_and_looks_up_without_deadlock() -> Result<()> {
    // `max_size = 1` is a supported deployment. Every factory step must release
    // its connection (in particular before the post-commit repository re-read).
    let fixture = Fixture::with_pool_size(1).await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-single-pool")?;
        let first = provision(
            &fixture.pool,
            &alice.identity,
            request("single", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await
        .context("single-connection provision")?;
        ensure!(first.created, "the single-connection provision did not create the repository");
        let again = provision(
            &fixture.pool,
            &alice.identity,
            request("single", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await
        .context("single-connection retry")?;
        ensure!(!again.created, "the single-connection retry created a second repository");
        ensure!(again.repository.id == first.repository.id, "the retry resolved another repository");
        let served = lookup(&fixture.pool, &alice.identity, &alice.username, "single", false, &backend, deadline())
            .await
            .context("single-connection lookup")?;
        ensure!(served.repository.id == first.repository.id, "lookup resolved another repository");
        ensure!(
            served.repository.state == "ready" && served.gate.revision() == 1,
            "lookup returned a non-serving proof"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL (real PostgreSQL)"]
async fn database_guards_refuse_forged_ready_and_bound_identity_drift() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        let alice = actor(&fixture.pool, false).await?;
        let backend = backend_identity("serving-guards")?;

        // 1. A direct INSERT of a ready `pg_refstore` repository has no durable
        //    binding and must be refused by the migration-145 trigger.
        let forged = fixture
            .pool
            .get()
            .await?
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                 VALUES($1,$2,'forged-ready','ready','pg_refstore','sha1')",
                &[&Uuid::new_v4(), &alice.user_id],
            )
            .await;
        ensure!(forged.is_err(), "a direct ready pg_refstore INSERT must be refused");

        // 2. A pending binding must already name the exact repository row.
        let unbound = Uuid::new_v4();
        fixture
            .pool
            .get()
            .await?
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                 VALUES($1,$2,'unbound','provisioning','pg_refstore','sha1')",
                &[&unbound, &alice.user_id],
            )
            .await?;
        let wrong_name = fixture
            .pool
            .get()
            .await?
            .execute(
                "INSERT INTO ref_store_serving_repositories
                     (repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,
                      backend_identity,state)
                 VALUES($1,$2,'other-name','sha1',$3,1,1,$4,'pending')",
                &[&unbound, &alice.user_id, &Uuid::new_v4(), &backend.as_hex()],
            )
            .await;
        ensure!(wrong_name.is_err(), "a binding with another repository name must be refused");
        let wrong_format = fixture
            .pool
            .get()
            .await?
            .execute(
                "INSERT INTO ref_store_serving_repositories
                     (repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,
                      backend_identity,state)
                 VALUES($1,$2,'unbound','sha256',$3,1,1,$4,'pending')",
                &[&unbound, &alice.user_id, &Uuid::new_v4(), &backend.as_hex()],
            )
            .await;
        ensure!(wrong_format.is_err(), "a binding with another object format must be refused");

        // Pending intents cannot disable an existing GitFS/Pando authority.
        for (backend_name, repo_state) in [("gitfs", "ready"), ("pando", "provisioning")] {
            let other = Uuid::new_v4();
            let name = format!("poison-{backend_name}");
            let client = fixture.pool.get().await?;
            client.execute(
                "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
                 VALUES($1,$2,$3,$4,$5,'sha1')",
                &[&other, &alice.user_id, &name, &repo_state, &backend_name],
            ).await?;
            let refused = client.execute(
                "INSERT INTO ref_store_serving_repositories
                 (repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,state)
                 VALUES($1,$2,$3,'sha1',$4,1,1,$5,'pending')",
                &[&other, &alice.user_id, &name, &Uuid::new_v4(), &backend.as_hex()],
            ).await;
            ensure!(refused.is_err(), "pending intent poisoned {backend_name} authority");
        }

        // 3. After a real provision the bound identity is immutable at both the
        //    repository and the binding layer.
        let receipt = provision(
            &fixture.pool,
            &alice.identity,
            request("guarded", None, GitObjectFormat::Sha1),
            &backend,
            deadline(),
        )
        .await?;
        let repo = receipt.repository.id;
        for sql in [
            "UPDATE repositories SET name='renamed' WHERE id=$1",
            "UPDATE repositories SET object_format='sha256' WHERE id=$1",
            "UPDATE ref_store_serving_repositories SET name='renamed' WHERE repository_id=$1",
            "UPDATE ref_store_serving_repositories SET object_format='sha256' WHERE repository_id=$1",
            "UPDATE ref_store_serving_repositories SET backend_identity=repeat('b',64) WHERE repository_id=$1",
        ] {
            let refused = fixture.pool.get().await?.execute(sql, &[&repo]).await;
            ensure!(refused.is_err(), "bound identity drift must be refused: {sql}");
        }

        // A matching protocol realm with decision_required=false cannot be
        // promoted to serving readiness, even through direct SQL.
        let client = fixture.pool.get().await?;
        client.execute(
            "INSERT INTO ref_store_core_gates
             (repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref)
             SELECT $1,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref
             FROM ref_store_core_gates WHERE repository_id=$2",
            &[&unbound, &repo],
        ).await?;
        client.execute(
            "INSERT INTO ref_store_core_protocol_repos
             (repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,decision_required)
             SELECT $1,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,false
             FROM ref_store_core_protocol_repos WHERE repository_id=$2",
            &[&unbound, &repo],
        ).await?;
        client.execute(
            "INSERT INTO ref_store_serving_repositories
             (repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,state)
             SELECT $1,owner_id,'unbound',object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,'pending'
             FROM ref_store_serving_repositories WHERE repository_id=$2",
            &[&unbound, &repo],
        ).await?;
        let unfenced = client.execute(
            "UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id=$1", &[&unbound],
        ).await;
        ensure!(unfenced.is_err(), "unfenced protocol became a ready serving authority");
        drop(client);

        // 4. The repository/gate/binding still agree and lookup keeps working.
        ensure!(one_text(&fixture, "SELECT name FROM repositories WHERE id=$1", &repo).await? == "guarded");
        ensure!(
            one_text(&fixture, "SELECT object_format FROM repositories WHERE id=$1", &repo).await? == "sha1"
        );
        ensure!(
            one_text(&fixture, "SELECT name FROM ref_store_serving_repositories WHERE repository_id=$1", &repo).await?
                == "guarded"
        );
        ensure!(
            one_text(&fixture, "SELECT object_format FROM ref_store_serving_repositories WHERE repository_id=$1", &repo)
                .await?
                == "sha1"
        );
        let served = lookup(&fixture.pool, &alice.identity, &alice.username, "guarded", false, &backend, deadline())
            .await
            .context("lookup after rejected identity drift")?;
        ensure!(served.repository.id == repo, "lookup resolved another repository");
        ensure!(served.repository.object_format == "sha1", "the repository object format drifted");
        ensure!(served.gate.object_format() == GitObjectFormat::Sha1, "the gate object format drifted");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}
