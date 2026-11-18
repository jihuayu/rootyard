//! End-to-end production `blob_git_gateway` + PostgreSQL 17 + OpenDAL S3 +
//! TLS `build_signed_packfile_router` + stock Git (`SHA-1` & `SHA-256`) tests.

#[path = "packfile_uri_support/gateway_env.rs"]
mod gateway_env;
#[path = "packfile_uri_support/harness.rs"]
mod harness;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use gateway_env::{IsolatedPgDb, LoopbackS3, create_and_provision_repo, issue_owner_actor, spawn_gateway};
use harness::{
    build_ephemeral_tls_cert, git_cmd, now_unix, reserve_loopback_listener, resolve_git_binary, shared_keyring,
    spawn_tls_axum_cdn_server,
};
use rootyard::{
    browse::packfile_uri::{
        AcquireLeaseParams, CdnHealthState, DownloadSubjectContext, FallbackReason, FetchAttemptResult,
        GatewayPackfileOffload, LivePackReadAuthorizer, MintUriRequest, OffloadPolicyConfig, PackDeliveryLeaseRegistry,
        PackDownloaderConfig, PackHttpServerState, PackObjectFormat, PackStreamMeta, PackfileUriError,
        SignedPackfileDescriptor, StaticMapDnsResolver, decode_packfile_uris_section,
        fetch_pack_with_integrity_and_retry, mint_signed_offload_uri, protocol_v2::push_pkt_line,
    },
    cache_wake::replica_cache::{DurablePinRegistry, lease_pin::AuthTask},
    ref_store::GitObjectFormat,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

fn incompressible_bytes(seed: u32, len: usize) -> Vec<u8> {
    let mut s = seed.max(1);
    (0..len)
        .map(|_| {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (s >> 24) as u8
        })
        .collect()
}

struct BoolAuth(Arc<AtomicBool>);

impl LivePackReadAuthorizer for BoolAuth {
    fn authorize_pack_download<'a>(
        &'a self,
        _tenant_id: Uuid,
        _repository_id: Uuid,
        subject: &'a DownloadSubjectContext,
        _pack_oid: &'a str,
        _pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        if let Err(e) = subject.validate() {
            return Box::pin(async move { Err(e) });
        }
        let ok = self.0.load(Ordering::SeqCst);
        Box::pin(async move { if ok { Ok(()) } else { Err(PackfileUriError::Unauthorized) } })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_blob_git_gateway_stock_git_dual_hash_offload_incremental_fallback_and_revocation() -> Result<()> {
    let Some(db) = IsolatedPgDb::try_setup().await? else {
        return Ok(());
    };
    let outcome = run_production_gateway_matrix(&db).await;
    db.finish(outcome).await
}

async fn run_production_gateway_matrix(db: &IsolatedPgDb) -> Result<()> {
    let store = LoopbackS3::shared().open_store()?;
    let git_bin = resolve_git_binary()?;
    let tmp = TempDir::new()?;
    let tls = build_ephemeral_tls_cert(tmp.path())?;
    let ca_pem = std::fs::read(&tls.cert_path)?;
    let reqwest_ca = reqwest::Certificate::from_pem(&ca_pem)?;
    let http_client = reqwest::Client::new();

    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let pack_fmt = match fmt {
            GitObjectFormat::Sha1 => PackObjectFormat::Sha1,
            GitObjectFormat::Sha256 => PackObjectFormat::Sha256,
        };
        let (tls_listener, tls_port) = reserve_loopback_listener()?;
        let policy = OffloadPolicyConfig::strict_production(vec!["cdn.localhost".to_owned()], "kid-v1")
            .with_loopback_localhost_for_test(tls_port)?;
        let resolver = Arc::new(StaticMapDnsResolver::new());
        resolver.set_host_addrs("cdn.localhost", vec![SocketAddr::from(([127, 0, 0, 1], tls_port))]);

        let offload =
            Arc::new(GatewayPackfileOffload::new(shared_keyring(), policy.clone(), "cdn.localhost", resolver.clone()));
        let cdn =
            spawn_tls_axum_cdn_server(tls_listener, Arc::clone(&tls.server_cfg), Arc::clone(offload.pack_server()))
                .await?;
        ensure!(cdn.port == tls_port && cdn.tls_requests.load(Ordering::SeqCst) == 0);

        let (def_addr, def_state, def_task) = spawn_gateway(
            db.pool.clone(),
            store.clone(),
            &git_bin,
            &tmp.path().join(format!("scratch_def_{}", fmt.as_str())),
            None,
        )
        .await?;
        let (off_addr, _off_state, off_task) = spawn_gateway(
            db.pool.clone(),
            store.clone(),
            &git_bin,
            &tmp.path().join(format!("scratch_off_{}", fmt.as_str())),
            Some(Arc::clone(&offload)),
        )
        .await?;

        let owner = issue_owner_actor(&db.pool).await?;
        let repo_name = format!("repo-{}", fmt.as_str());
        create_and_provision_repo(def_addr, &db.pool, &def_state, &owner, &repo_name, fmt).await?;

        let def_url =
            format!("http://{}:{}@{def_addr}/git/{}/{repo_name}.git", owner.username, owner.token, owner.username);
        let off_url =
            format!("http://{}:{}@{off_addr}/git/{}/{repo_name}.git", owner.username, owner.token, owner.username);
        let basic_hdr = format!("Basic {}", B64.encode(format!("{}:{}", owner.username, owner.token)));

        // Push Commit 1 (18 KiB incompressible base pack) + Commit 2 (small residual delta).
        let pusher = tmp.path().join(format!("pusher_{}", fmt.as_str()));
        std::fs::create_dir_all(&pusher)?;
        git_cmd(&["init", pack_fmt.git_init_flag(), "."], Some(&pusher), None)?;
        git_cmd(&["config", "user.name", "Pusher"], Some(&pusher), None)?;
        git_cmd(&["config", "user.email", "pusher@rootyard.test"], Some(&pusher), None)?;
        let base_payload = incompressible_bytes(0x1357_9bdf, 18_432);
        std::fs::write(pusher.join("base.bin"), &base_payload)?;
        git_cmd(&["add", "base.bin"], Some(&pusher), None)?;
        git_cmd(&["commit", "-m", "base pack"], Some(&pusher), None)?;
        git_cmd(&["push", &def_url, "HEAD:refs/heads/main"], Some(&pusher), None)?;

        std::fs::write(pusher.join("delta.txt"), b"small residual delta\n")?;
        git_cmd(&["add", "delta.txt"], Some(&pusher), None)?;
        git_cmd(&["commit", "-m", "small delta"], Some(&pusher), None)?;
        git_cmd(&["push", &def_url, "HEAD:refs/heads/main"], Some(&pusher), None)?;

        // 1. Default-off gateway: does NOT advertise `packfile-uris`; clones inline cleanly.
        let adv_def = http_client
            .get(format!("http://{def_addr}/git/{}/{repo_name}.git/info/refs?service=git-upload-pack", owner.username))
            .header("Authorization", &basic_hdr)
            .header("Git-Protocol", "version=2")
            .send()
            .await?
            .bytes()
            .await?;
        let adv_def_txt = String::from_utf8_lossy(&adv_def);
        ensure!(adv_def_txt.contains("version 2") && !adv_def_txt.contains("packfile-uris"));
        let clone_def = tmp.path().join(format!("clone_def_{}", fmt.as_str()));
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=https",
                "clone",
                &def_url,
                clone_def.to_str().unwrap(),
            ],
            Some(tmp.path()),
            None,
        )?;
        git_cmd(&["fsck", "--full", "--strict"], Some(&clone_def), None).context("fsck clone_def")?;
        ensure!(offload.pack_server().served_requests.load(Ordering::SeqCst) == 0);

        // 2. Enabled offload gateway: advertises `packfile-uris` and serves base pack over TLS Axum + inline residual.
        let adv_off = http_client
            .get(format!("http://{off_addr}/git/{}/{repo_name}.git/info/refs?service=git-upload-pack", owner.username))
            .header("Authorization", &basic_hdr)
            .header("Git-Protocol", "version=2")
            .send()
            .await?
            .bytes()
            .await?;
        ensure!(String::from_utf8_lossy(&adv_off).contains("packfile-uris"));

        let ca_cfg = format!("http.https://cdn.localhost:{tls_port}/.sslCAInfo={}", tls.cert_path.display());
        let proxy_cfg = format!("http.https://cdn.localhost:{tls_port}/.proxy=http://127.0.0.1:{tls_port}");
        let clone_off = tmp.path().join(format!("clone_off_{}", fmt.as_str()));
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=https",
                "-c",
                &ca_cfg,
                "-c",
                &proxy_cfg,
                "clone",
                &off_url,
                clone_off.to_str().unwrap(),
            ],
            Some(tmp.path()),
            None,
        )?;
        git_cmd(&["fsck", "--full", "--strict"], Some(&clone_off), None).context("fsck clone_off after clone")?;
        ensure!(std::fs::read(clone_off.join("base.bin"))? == base_payload);
        ensure!(clone_off.join("delta.txt").is_file());
        ensure!(offload.offload_responses.load(Ordering::SeqCst) == 1);
        ensure!(offload.pack_server().served_requests.load(Ordering::SeqCst) == 1);

        // 3. Incremental `have/want` fetch: push Commit 3 (18 KiB) and `git fetch` from `clone_off`.
        let inc_payload = incompressible_bytes(0x2468_ace0, 18_432);
        std::fs::write(pusher.join("inc.bin"), &inc_payload)?;
        git_cmd(&["add", "inc.bin"], Some(&pusher), None)?;
        git_cmd(&["commit", "-m", "incremental pack"], Some(&pusher), None)?;
        git_cmd(&["push", &off_url, "HEAD:refs/heads/main"], Some(&pusher), None)?;
        let tip_c3 = String::from_utf8(git_cmd(&["rev-parse", "HEAD"], Some(&pusher), None)?)?.trim().to_owned();

        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=https",
                "-c",
                &ca_cfg,
                "-c",
                &proxy_cfg,
                "fetch",
                "--no-auto-maintenance",
                "origin",
            ],
            Some(&clone_off),
            None,
        )?;
        git_cmd(&["merge", "--ff-only", "FETCH_HEAD"], Some(&clone_off), None)?;
        git_cmd(&["fsck", "--full", "--strict"], Some(&clone_off), None)
            .context("fsck clone_off after incremental fetch")?;
        ensure!(std::fs::read(clone_off.join("inc.bin"))? == inc_payload);
        ensure!(offload.offload_responses.load(Ordering::SeqCst) == 2);
        ensure!(offload.pack_server().served_requests.load(Ordering::SeqCst) == 2);

        // 4. Deterministic inline fallback when client omits `packfile-uris` or CDN is unhealthy.
        let clone_no_uri = tmp.path().join(format!("clone_nouri_{}", fmt.as_str()));
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=",
                "clone",
                &off_url,
                clone_no_uri.to_str().unwrap(),
            ],
            Some(tmp.path()),
            None,
        )?;
        git_cmd(&["fsck", "--full", "--strict"], Some(&clone_no_uri), None).context("fsck clone_nouri")?;
        ensure!(offload.last_fallback_reason() == Some(FallbackReason::ClientOmittedPackfileUris));
        ensure!(offload.pack_server().served_requests.load(Ordering::SeqCst) == 2);

        offload.set_cdn_health(CdnHealthState::Unavailable);
        let clone_deg = tmp.path().join(format!("clone_deg_{}", fmt.as_str()));
        git_cmd(
            &[
                "-c",
                "protocol.version=2",
                "-c",
                "fetch.uriprotocols=https",
                "clone",
                &off_url,
                clone_deg.to_str().unwrap(),
            ],
            Some(tmp.path()),
            None,
        )?;
        git_cmd(&["fsck", "--full", "--strict"], Some(&clone_deg), None).context("fsck clone_deg")?;
        ensure!(offload.last_fallback_reason() == Some(FallbackReason::CdnUnhealthy));
        offload.set_cdn_health(CdnHealthState::Healthy);

        // 5. Live PostgreSQL token revocation denies still-unexpired signed offload URL immediately.
        let mut v2_wire = Vec::new();
        push_pkt_line(&mut v2_wire, b"command=fetch")?;
        v2_wire.extend_from_slice(b"0001");
        push_pkt_line(&mut v2_wire, b"packfile-uris https")?;
        push_pkt_line(&mut v2_wire, format!("want {tip_c3}\n").as_bytes())?;
        push_pkt_line(&mut v2_wire, b"done\n")?;
        v2_wire.extend_from_slice(b"0000");
        let fetch_resp = http_client
            .post(format!("http://{off_addr}/git/{}/{repo_name}.git/git-upload-pack", owner.username))
            .header("Authorization", &basic_hdr)
            .header("Content-Type", "application/x-git-upload-pack-request")
            .header("Git-Protocol", "version=2")
            .body(v2_wire)
            .send()
            .await?
            .bytes()
            .await?;
        let uris = decode_packfile_uris_section(&fetch_resp, pack_fmt)?;
        ensure!(!uris.is_empty(), "expected signed packfile-uris in fetch response");
        let (signed_pack_hash, signed_url) = &uris[0];

        let pinned_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .add_root_certificate(reqwest_ca.clone())
            .resolve_to_addrs("cdn.localhost", &[SocketAddr::from(([127, 0, 0, 1], tls_port))])
            .build()?;
        let pre_rev = pinned_client.get(signed_url).send().await?;
        ensure!(pre_rev.status().is_success(), "signed url should succeed before PG token revocation");
        let pre_bytes = pre_rev.bytes().await?;
        ensure!(hex::encode(&pre_bytes[pre_bytes.len() - pack_fmt.oid_hex_len() / 2..]) == *signed_pack_hash);

        db.pool.get().await?.execute("DELETE FROM tokens WHERE id = $1", &[&owner.identity.token_id]).await?;
        let post_rev = pinned_client.get(signed_url).send().await?;
        ensure!(
            post_rev.status() == reqwest::StatusCode::FORBIDDEN,
            "revoked PG token must immediately deny signed offload URL with 403, got {}",
            post_rev.status()
        );

        def_task.abort();
        off_task.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloader_pinned_dns_chunked_cap_retry_and_pin_revocation_over_real_tls_axum() -> Result<()> {
    let tmp = TempDir::new()?;
    let tls = build_ephemeral_tls_cert(tmp.path())?;
    let (tls_listener, tls_port) = reserve_loopback_listener()?;
    let policy = OffloadPolicyConfig::strict_production(vec!["cdn.localhost".to_owned()], "kid-v1")
        .with_loopback_localhost_for_test(tls_port)?;
    let resolver = Arc::new(StaticMapDnsResolver::new());
    resolver.set_host_addrs("cdn.localhost", vec![SocketAddr::from(([127, 0, 0, 1], tls_port))]);

    let leases = PackDeliveryLeaseRegistry::new(DurablePinRegistry::new());
    let allow = Arc::new(AtomicBool::new(true));
    let auth: Arc<dyn LivePackReadAuthorizer> = Arc::new(BoolAuth(Arc::clone(&allow)));
    let pack_state = Arc::new(PackHttpServerState::new(
        shared_keyring(),
        leases.clone(),
        policy.clone(),
        resolver.clone(),
        auth,
        Arc::new(now_unix),
    ));
    let cdn = spawn_tls_axum_cdn_server(tls_listener, Arc::clone(&tls.server_cfg), Arc::clone(&pack_state)).await?;

    let mut raw = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
    raw.extend_from_slice(&incompressible_bytes(42, 8_192));
    let trailer = [0xcd; 20];
    raw.extend_from_slice(&trailer);
    let pack_hash = hex::encode(trailer);
    let sha256_hex = hex::encode(Sha256::digest(&raw));

    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = DownloadSubjectContext::new(Uuid::new_v4(), Uuid::new_v4(), 2)?;
    let now = now_unix();
    let pin = leases.acquire_offload_pin(&AcquireLeaseParams {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: &pack_hash,
        subject,
        gate_revision: 1,
        now_unix: now,
        expires_at_unix: now + 120,
        grace_secs: 60,
    })?;
    pack_state.insert_pack(PackStreamMeta {
        tenant_id: tenant,
        repository_id: repo,
        pack_oid: pack_hash.clone(),
        pack_hash_hex: pack_hash.clone(),
        object_format: PackObjectFormat::Sha1,
        sha256_hex: sha256_hex.clone(),
        payload: Bytes::from(raw.clone()),
    })?;
    let desc: SignedPackfileDescriptor = mint_signed_offload_uri(
        &shared_keyring(),
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            subject,
            pack_oid: &pack_hash,
            pack_hash_hex: &pack_hash,
            sha256_hex: &sha256_hex,
            byte_len: raw.len() as u64,
            object_format: PackObjectFormat::Sha1,
            allowed_host: "cdn.localhost",
            pin_id: pin.pin_id(),
            scope_nonce: "0123456789abcdef",
            now_unix: now,
            policy: &policy,
            resolver: resolver.as_ref(),
        },
    )?;

    let mut dl_cfg = PackDownloaderConfig::build(&policy)?;
    dl_cfg.resolver = resolver;
    dl_cfg.extra_root_certs = vec![reqwest::Certificate::from_pem(&std::fs::read(&tls.cert_path)?)?];

    // 1. Transient 503 recovers on attempt #2 using pinned `resolve_to_addrs`.
    cdn.fail_first_n.store(1, Ordering::SeqCst);
    let ok_res = fetch_pack_with_integrity_and_retry(&dl_cfg, &desc, PackObjectFormat::Sha1, &policy).await?;
    ensure!(matches!(ok_res, FetchAttemptResult::Verified { attempts: 2, .. }));

    // 2. Chunked Transfer-Encoding without Content-Length exceeding `desc.byte_len` fails closed immediately.
    cdn.emit_oversized_chunks.store(true, Ordering::SeqCst);
    let over_res = fetch_pack_with_integrity_and_retry(&dl_cfg, &desc, PackObjectFormat::Sha1, &policy).await;
    ensure!(matches!(over_res, Err(PackfileUriError::CapacityExceeded(_))));
    cdn.emit_oversized_chunks.store(false, Ordering::SeqCst);

    // 3. Pin revocation fails closed (`410 Gone` -> `RetentionPinMissing`).
    ensure!(leases.revoke_pin(desc.pin_id));
    let rev_res = fetch_pack_with_integrity_and_retry(&dl_cfg, &desc, PackObjectFormat::Sha1, &policy).await;
    ensure!(matches!(rev_res, Err(PackfileUriError::RetentionPinMissing(_))));
    Ok(())
}
