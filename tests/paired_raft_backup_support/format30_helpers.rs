//! Shared Smart-HTTP gateway, stock-Git, PG17 volume/config, and 3-voter mTLS fault helpers (#153).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use tokio::net::TcpListener;
use uuid::Uuid;

use rootyard::blob_git_gateway::{BlobGitConfig, BlobGitState, router};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::config::Config;
use rootyard::db::{self, Identity};
use rootyard::maintenance::paired_raft_backup::{
    DurableRaftBackend, MtlsLiveRaftBackend, MtlsRaftClusterConfig, PairedBackupError,
};
use rootyard::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireCommitRefsRequest,
    WireGateInit,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

use super::mtls_cluster::LiveMtlsRaftGroup;

pub struct IssuedActor {
    pub id: Uuid,
    pub username: String,
    pub token: String,
    pub identity: Identity,
}

pub async fn make_actor(pool: &Pool, prefix: &str, create_user: bool) -> Result<IssuedActor> {
    let uname =
        if create_user { format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10]) } else { prefix.to_owned() };
    let issued = db::issue_token(pool, &uname, create_user, false).await?;
    let id: Uuid = issued["user_id"].as_str().context("uid")?.parse()?;
    let token = issued["token"].as_str().context("tok")?.to_owned();
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{uname}:{token}"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::AUTHORIZATION, format!("Basic {b64}").parse()?);
    let identity = rootyard::auth::authenticate(pool, &headers).await.map_err(|e| anyhow!("{}", e.1))?;
    Ok(IssuedActor { id, username: uname, token, identity })
}

pub fn replace_db_in_url(base_url: &str, db_name: &str) -> Result<String> {
    let (prefix, _) = base_url.rsplit_once('/').context("invalid postgres URL")?;
    Ok(format!("{prefix}/{db_name}"))
}

pub fn find_git_bin() -> Result<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("git"))
        .find(|p| p.is_file())
        .context("git binary not found")?
        .canonicalize()
        .context("canonicalize git")
}

pub fn make_backup_config(database_url: String, data_dir: PathBuf, git: PathBuf) -> Config {
    Config {
        database_url,
        data_dir,
        bind: "127.0.0.1:0".parse().unwrap(),
        git,
        max_request_bytes: 64 * 1024 * 1024,
        max_output_bytes: 128 * 1024 * 1024,
        max_concurrent_git: 4,
        git_timeout: Duration::from_secs(60),
        git_memory_bytes: 512 * 1024 * 1024,
        max_repo_bytes: 512 * 1024 * 1024,
        max_pending_deliveries: 10_000,
        outbox_worker: false,
        metrics_bind: None,
    }
}

pub fn init_volume_dir(root: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        fs::DirBuilder::new().mode(0o700).create(root)?;
        let mut vf = OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join(".volume-id"))?;
        vf.write_all(Uuid::new_v4().to_string().as_bytes())?;
        vf.sync_all()?;
        let lf = OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join(".rootyard.lock"))?;
        lf.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(root)?;
        fs::write(root.join(".volume-id"), Uuid::new_v4().to_string())?;
        fs::write(root.join(".rootyard.lock"), b"")?;
    }
    Ok(())
}

pub fn run_git_cli(git: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(git)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "fmt30-it")
        .env("GIT_AUTHOR_EMAIL", "fmt30@example.invalid")
        .env("GIT_COMMITTER_NAME", "fmt30-it")
        .env("GIT_COMMITTER_EMAIL", "fmt30@example.invalid")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .output()
        .expect("spawn git")
}

pub async fn start_gateway(
    pool: Pool,
    store: BlobStore,
    git: PathBuf,
    scratch: PathBuf,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    fs::create_dir_all(&scratch)?;
    let state = Arc::new(
        BlobGitState::new(BlobGitConfig {
            pool,
            store,
            git_binary: git,
            scratch_root: scratch,
            max_concurrent_requests: 4,
            max_request_bytes: 16 * 1024 * 1024,
            max_response_bytes: 64 * 1024 * 1024,
            max_inflight_bytes: 64 * 1024 * 1024,
            operation_deadline: Duration::from_secs(60),
            native_limits: Default::default(),
        })
        .map_err(|e| anyhow!("BlobGitState::new: {e}"))?,
    );
    let lis = TcpListener::bind("127.0.0.1:0").await?;
    let addr = lis.local_addr()?;
    let app = router(state);
    let jh = tokio::spawn(async move {
        let _ = axum::serve(lis, app).await;
    });
    Ok((addr, jh))
}

pub fn seed_gate_and_commit(
    raft: &mut MtlsLiveRaftBackend,
    (repo, tenant, history, auth_e, grp_e): (Uuid, Uuid, Uuid, i64, i64),
    commits: &[String],
) -> Result<()> {
    let init = CoreGateInit::new(
        repo,
        tenant,
        GitObjectFormat::Sha256,
        history,
        auth_e,
        grp_e,
        RefName::branch("refs/heads/main")?,
    )?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 2,
    }))
    .map_err(|e| anyhow!("{e}"))?;
    let issuer = Uuid::new_v4();
    let lane = IssuerLane::new("live-sync")?;
    let mut prev: Option<GitOid> = None;
    for (idx, hex_oid) in commits.iter().enumerate() {
        let oid = GitOid::parse(GitObjectFormat::Sha256, hex_oid)?;
        let pre = prev.clone().map_or(RefPrecondition::Absent, RefPrecondition::Present);
        let upd = RefUpdate::new(RefName::new("refs/heads/main")?, pre, RefTarget::Oid(oid.clone()));
        let req = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane.clone(),
            (idx + 1) as i64,
            Uuid::new_v4(),
            GitObjectFormat::Sha256,
            history,
            auth_e,
            grp_e,
            (idx + 1) as i64,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![upd],
        )?;
        raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req),
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: (10 + idx) as u64,
        }))
        .map_err(|e| anyhow!("{e}"))?;
        prev = Some(oid);
    }
    Ok(())
}

/// Exercise live 3-voter mTLS peer certificate verification, `1/3` minority partition refusal,
/// and `2/3` remote quorum commit with lagging local replica on a disposable `raft-node` group.
pub fn verify_mtls_auth_and_quorum_faults() -> Result<()> {
    let gf = LiveMtlsRaftGroup::start_three(9)?;
    for (ca, crt, key) in [
        (&gf.pki.rogue_ca_cert, &gf.pki.rogue_client_cert, &gf.pki.rogue_client_key),
        (&gf.pki.ca_cert, &gf.pki.rogue_client_cert, &gf.pki.rogue_client_key),
        (&gf.pki.ca_cert, &gf.pki.wrong_san_cert, &gf.pki.wrong_san_key),
    ] {
        ensure!(
            MtlsLiveRaftBackend::connect(MtlsRaftClusterConfig {
                group_id: 9,
                local_node_id: 1,
                voter_endpoints: gf.endpoints(),
                ca_cert_pem: ca.clone(),
                client_cert_pem: crt.clone(),
                client_key_pem: key.clone(),
                rpc_timeout: Duration::from_secs(3),
            })
            .is_err(),
            "rogue CA, rogue client cert, and wrong SAN must fail mTLS authentication"
        );
    }

    let mut local1 = gf.connect_backend(1)?;
    let mut local2 = gf.connect_backend(2)?;

    // (a) 2/3 remote quorum commits on voters 2 & 3 while local replica 1 is partitioned!
    gf.isolate_nodes(&[1])?;
    seed_gate_and_commit(&mut local2, (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 1, 2), &["c".repeat(64)])?;
    assert!(matches!(local1.durable_state().unwrap_err(), PairedBackupError::FreezeNotHeld(_)));
    gf.heal_all()?;
    ensure!(local1.durable_state().map_err(|e| anyhow!("{e}"))?.0.body.last_applied.unwrap().index == 2);

    // (b) 1/3 minority partition refuses quorum writes!
    gf.isolate_nodes(&[2, 3])?;
    let init = CoreGateInit::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        GitObjectFormat::Sha256,
        Uuid::new_v4(),
        1,
        2,
        RefName::branch("refs/heads/main")?,
    )?;
    assert!(matches!(
        local1
            .commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&init),
                pack_mode: SmPackMode::MetadataOnly,
                lane: RepositoryLane::ServingRefStore,
                authz_floor: 1,
            }))
            .unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    Ok(())
}
