//! Live negative mTLS and Bearer-token probes against deployed `rootyard-safe-gc-voter` listeners (#122).

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use rootyard::{
    ref_store::core::{
        state_machine::{InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireGateInit},
        types::GitObjectFormat,
    },
    storage_lifecycle::safe_gc::{
        SafeGcError, VoterCutpointAttestation, verify_single_voter_cutpoint_attestation,
        voter_service::tls::request_voter_https,
    },
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::super::{
    PG_SAFE_GC_TEST_LOCK,
    raft_voter_cluster::{LiveRaftVoterCluster, resolve_raft_node_bin, resolve_voter_bin},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deployed_voter_listener_rejects_empty_wrong_plaintext_and_foreign_client_auth() -> Result<()> {
    let _serial = PG_SAFE_GC_TEST_LOCK.lock().await;
    let Some(node_bin) = resolve_raft_node_bin()? else { return Ok(()) };
    let Some(_voter_bin) = resolve_voter_bin()? else { return Ok(()) };
    let mut cluster = LiveRaftVoterCluster::start(node_bin).await?;
    let voter = cluster.trusted_voters().into_iter().next().context("first pinned voter")?;
    let auth = cluster.voter_client_auth();
    let timeout = Duration::from_secs(10);

    // Seed the Ref-CAS repository gate through the live Raft log before starting the listener.
    let (tenant_id, repo_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let _ = cluster
        .append(&RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit {
                repository_id: repo_id,
                tenant_id,
                object_format: GitObjectFormat::Sha1,
                history_incarnation: history_id,
                authority_epoch: 1,
                group_epoch: 1,
                head_ref: "refs/heads/main".into(),
            },
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        }))
        .await?;
    cluster.set_voter_enabled(1, true);
    assert_eq!(cluster.enabled_voter_ids(), vec![1], "voter 1 must be the only live listener for this probe");

    let cutpoint = format!("/v1/safe-gc/cutpoint/{repo_id}");

    // Case A: the pinned mTLS + `0600` Bearer credentials serve both the health and cutpoint probes.
    let (status, body) = request_voter_https(&voter.endpoint_url, "/healthz", &auth, None, timeout).await?;
    assert_eq!(status, 200, "the pinned mTLS + Bearer credentials must serve the health probe");
    let health: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(health["voter_id"], voter.voter_id);
    assert!(voter.endpoint_url.starts_with("https://"), "every deployed voter must publish an https endpoint");

    let (cut_status, cut_body) = request_voter_https(&voter.endpoint_url, &cutpoint, &auth, None, timeout).await?;
    assert_eq!(cut_status, 200, "the pinned mTLS + Bearer credentials must serve the cutpoint probe");
    let attestation: VoterCutpointAttestation = serde_json::from_slice(&cut_body)?;
    let _snapshot = verify_single_voter_cutpoint_attestation(&voter, repo_id, tenant_id, history_id, &attestation)?;

    // Case B: an empty `Authorization: Bearer` value must never be accepted.
    let (empty_status, _) = request_voter_https(&voter.endpoint_url, &cutpoint, &auth, Some(""), timeout).await?;
    assert_eq!(empty_status, 401, "an empty Bearer token must be rejected");

    // Case C: a well-formed but unpinned Bearer token must never be accepted.
    let wrong = "00".repeat(32);
    let (wrong_status, _) =
        request_voter_https(&voter.endpoint_url, &cutpoint, &auth, Some(wrong.as_str()), timeout).await?;
    assert_eq!(wrong_status, 401, "a wrong Bearer token must be rejected");

    // Case D: plaintext HTTP must be refused by the client and never reach the authenticated handler.
    let refused = request_voter_https("http://127.0.0.1:1/", &cutpoint, &auth, None, timeout).await;
    assert!(matches!(refused, Err(SafeGcError::ArmingRejected("voter endpoint_url must use https://"))));
    let addr = voter.endpoint_url.trim_start_matches("https://").trim_end_matches('/').to_owned();
    let mut plain = tokio::net::TcpStream::connect(&addr).await?;
    let request = format!("GET {cutpoint} HTTP/1.1\r\nHost: voter\r\nConnection: close\r\n\r\n");
    plain.write_all(request.as_bytes()).await?;
    let mut reply = Vec::new();
    let _ = plain.read_to_end(&mut reply).await;
    ensure!(
        !String::from_utf8_lossy(&reply).contains("200 OK"),
        "a plaintext HTTP request must never reach the authenticated voter handler"
    );

    // Case E: a TLS client without a client certificate must be rejected by the listener's verifier.
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(&auth.ca_cert_pem)?)) {
        roots.add(cert?)?;
    }
    let no_client = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(auth.server_name.clone())?;
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let connection = ClientConnection::new(Arc::new(no_client), server_name)?;
    let mut tls = StreamOwned::new(connection, tcp);
    let mut probe = [0_u8; 1];
    let rejected = match tls.write_all(request.as_bytes()) {
        Err(_) => true,
        Ok(()) => match tls.read(&mut probe) {
            Err(err) => !matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            Ok(_) => false,
        },
    };
    ensure!(rejected, "a TLS client without a client certificate must fail the mTLS handshake");

    // Case F: a client certificate from a foreign CA must fail the listener's client verifier.
    let foreign_dir = TempDir::new()?;
    let foreign = cluster.foreign_voter_client_auth(foreign_dir.path())?;
    let foreign_attempt = request_voter_https(&voter.endpoint_url, &cutpoint, &foreign, None, timeout).await;
    assert!(foreign_attempt.is_err(), "a client certificate from a foreign CA must fail the mTLS handshake");
    Ok(())
}
