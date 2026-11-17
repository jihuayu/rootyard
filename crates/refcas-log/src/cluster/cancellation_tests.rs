//! Real-mTLS regression coverage for cancellation of an in-flight cached peer stream.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::{
    CLIENT_RPC_TIMEOUT, MtlsPeerClient, PeerDirectory, RpcRequest, RpcResponse, read_frame_async, write_frame_async,
};
use crate::mtls::{MtlsClient, MtlsPaths, MtlsServer, node_dns_name};

#[derive(Clone, Copy)]
enum AckMode {
    Complete,
    Partial,
}

struct Control {
    mode: AckMode,
    a_received: Notify,
    release_a: Notify,
    a_sent: Notify,
}

impl Control {
    fn new(mode: AckMode) -> Self {
        Self { mode, a_received: Notify::new(), release_a: Notify::new(), a_sent: Notify::new() }
    }
}

struct TestPki {
    server_paths: MtlsPaths,
    client_paths: MtlsPaths,
    _dir: tempfile::TempDir,
}

impl TestPki {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create cancellation PKI tempdir");
        let (ca, ca_path) = write_ca(dir.path(), "refcas-cancellation-ca");
        let server_paths = write_leaf(dir.path(), "node1", &ca, &ca_path, &node_dns_name(1));
        let client_paths = write_leaf(dir.path(), "node2", &ca, &ca_path, &node_dns_name(2));
        Self { server_paths, client_paths, _dir: dir }
    }
}

fn write_ca(dir: &Path, name: &str) -> (CertifiedIssuer<'static, KeyPair>, PathBuf) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate cancellation CA key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    let issuer = CertifiedIssuer::self_signed(params, key).expect("self-sign cancellation CA");
    let ca_path = dir.join(format!("{name}.crt"));
    std::fs::write(&ca_path, issuer.pem()).expect("write cancellation CA");
    (issuer, ca_path)
}

fn write_leaf(dir: &Path, name: &str, ca: &CertifiedIssuer<'_, KeyPair>, ca_path: &Path, dns: &str) -> MtlsPaths {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate cancellation leaf key");
    let mut params = CertificateParams::new(vec![dns.to_owned()]).expect("build cancellation leaf SAN");
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, ca).expect("sign cancellation leaf");
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, cert.pem()).expect("write cancellation leaf cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write cancellation leaf key");
    MtlsPaths { ca_cert: ca_path.to_path_buf(), cert: cert_path, key: key_path }
}

struct PeerFixture {
    accepted: Arc<AtomicUsize>,
    control: Arc<Control>,
    task: JoinHandle<()>,
    _pki: TestPki,
}

impl Drop for PeerFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn setup(mode: AckMode) -> (MtlsPeerClient, PeerFixture) {
    let pki = TestPki::new();
    let server = MtlsServer::from_paths(&pki.server_paths).expect("build test mTLS server");
    let mtls_client = MtlsClient::from_paths(&pki.client_paths).expect("build test mTLS client");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test mTLS listener");
    let addr = listener.local_addr().expect("read test listener address").to_string();
    let mut peers = PeerDirectory::new();
    peers.insert(1, addr.clone());
    let client = MtlsPeerClient { target: 1, fallback_addr: addr, peers, client: mtls_client, stream: None };
    let control = Arc::new(Control::new(mode));
    let accepted = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(accept_loop(listener, server, control.clone(), accepted.clone()));
    (client, PeerFixture { accepted, control, task, _pki: pki })
}

async fn accept_loop(listener: TcpListener, server: MtlsServer, control: Arc<Control>, accepted: Arc<AtomicUsize>) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else { break };
        accepted.fetch_add(1, Ordering::SeqCst);
        let server = server.clone();
        let control = control.clone();
        tokio::spawn(async move {
            if let Ok((tls, _identity)) = server.accept(tcp).await {
                serve_connection(tls, control).await;
            }
        });
    }
}

async fn serve_connection<S>(mut tls: S, control: Arc<Control>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let req: Option<RpcRequest> = match read_frame_async(&mut tls).await {
            Ok(req) => req,
            Err(_) => return,
        };
        let Some(RpcRequest::KvGet { key }) = req else { return };
        if key == "A" {
            if matches!(control.mode, AckMode::Partial) {
                write_partial_a(&mut tls).await;
            }
            control.a_received.notify_one();
            control.release_a.notified().await;
            match control.mode {
                AckMode::Complete => {
                    let _ = write_frame_async(&mut tls, &a_response()).await;
                }
                AckMode::Partial => write_rest_a(&mut tls).await,
            }
            control.a_sent.notify_one();
        } else {
            let resp = RpcResponse::KvValue { value: Some(key), read_log_id: None };
            if write_frame_async(&mut tls, &resp).await.is_err() {
                return;
            }
        }
    }
}

fn a_response() -> RpcResponse {
    RpcResponse::KvValue { value: Some("A".to_owned()), read_log_id: None }
}

async fn write_partial_a<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(&a_response()).expect("encode partial withheld response");
    let len = (payload.len() as u32).to_be_bytes();
    if stream.write_all(&len).await.is_err() {
        return;
    }
    let prefix = payload.len().min(3);
    let _ = stream.write_all(&payload[..prefix]).await;
    let _ = stream.flush().await;
}

async fn write_rest_a<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(&a_response()).expect("encode withheld response remainder");
    let prefix = payload.len().min(3);
    let _ = stream.write_all(&payload[prefix..]).await;
    let _ = stream.flush().await;
}

async fn wait(notify: &Notify) {
    tokio::time::timeout(CLIENT_RPC_TIMEOUT, notify.notified())
        .await
        .expect("test barrier exceeded existing client budget");
}

async fn call(client: &mut MtlsPeerClient, key: &str) -> RpcResponse {
    let req = RpcRequest::KvGet { key: key.to_owned() };
    tokio::time::timeout(CLIENT_RPC_TIMEOUT, client.call_raft(req, CLIENT_RPC_TIMEOUT))
        .await
        .expect("peer RPC exceeded existing client budget")
        .unwrap_or_else(|e| panic!("peer RPC failed: {e}"))
}

fn kv_value(resp: RpcResponse) -> String {
    match resp {
        RpcResponse::KvValue { value: Some(value), .. } => value,
        other => panic!("unexpected RPC response: {other:?}"),
    }
}

async fn cancel_a(client: &mut MtlsPeerClient, control: &Control) {
    let mut in_flight = Box::pin(client.call_raft(RpcRequest::KvGet { key: "A".to_owned() }, CLIENT_RPC_TIMEOUT));
    tokio::select! {
        _ = control.a_received.notified() => {}
        result = in_flight.as_mut() => panic!("request A completed before outer cancellation: {result:?}"),
    }
    drop(in_flight);
}

#[tokio::test]
async fn cancelled_cached_request_drops_stream_and_next_request_reconnects() {
    let (mut client, fixture) = setup(AckMode::Complete).await;

    assert_eq!(kv_value(call(&mut client, "warm").await), "warm");
    assert!(client.stream.is_some(), "completed warm request must cache its stream");
    assert_eq!(fixture.accepted.load(Ordering::SeqCst), 1);

    cancel_a(&mut client, &fixture.control).await;
    assert!(client.stream.is_none(), "cancelled complete-response stream must not stay cached");

    fixture.control.release_a.notify_one();
    wait(&fixture.control.a_sent).await;

    assert_eq!(kv_value(call(&mut client, "B").await), "B");
    assert!(client.stream.is_some(), "completed B request must cache its fresh stream");
    assert_eq!(fixture.accepted.load(Ordering::SeqCst), 2, "request B must use a fresh connection");
}

#[tokio::test]
async fn cancelled_partial_response_frame_drops_stream_and_next_request_reconnects() {
    let (mut client, fixture) = setup(AckMode::Partial).await;

    assert_eq!(kv_value(call(&mut client, "warm").await), "warm");
    assert!(client.stream.is_some(), "completed warm request must cache its stream");

    cancel_a(&mut client, &fixture.control).await;
    assert!(client.stream.is_none(), "cancelled partial-frame stream must not stay cached");

    fixture.control.release_a.notify_one();
    wait(&fixture.control.a_sent).await;

    assert_eq!(kv_value(call(&mut client, "B").await), "B");
    assert_eq!(
        fixture.accepted.load(Ordering::SeqCst),
        2,
        "request B must use a fresh connection after a partial frame"
    );
}
