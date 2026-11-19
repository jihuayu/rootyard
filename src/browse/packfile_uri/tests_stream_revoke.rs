//! Deterministic paused live-authorization regressions for absolute-deadline
//! bounded streaming, post-await revocation rechecks, and exact guard release.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use uuid::Uuid;

use crate::cache_wake::replica_cache::{DurablePinRegistry, lease_pin::AuthTask};

use super::{
    tests::{sample_keyring, sample_pack_bytes, sample_policy, sample_resolver, sample_subject},
    tests_audit::raw_http_exchange,
    *,
};

struct PausedAuthorizer {
    calls: AtomicUsize,
    pause_on_call: usize,
    entered: mpsc::UnboundedSender<()>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<Result<(), PackfileUriError>>>>,
}

impl PausedAuthorizer {
    fn new(pause_on_call: usize) -> (Self, mpsc::UnboundedReceiver<()>, oneshot::Sender<Result<(), PackfileUriError>>) {
        let (entered_tx, entered_rx) = mpsc::unbounded_channel();
        let (release_tx, release_rx) = oneshot::channel();
        (
            Self {
                calls: AtomicUsize::new(0),
                pause_on_call,
                entered: entered_tx,
                release: tokio::sync::Mutex::new(Some(release_rx)),
            },
            entered_rx,
            release_tx,
        )
    }
}

impl LivePackReadAuthorizer for PausedAuthorizer {
    fn authorize_pack_download<'a>(
        &'a self,
        _tenant_id: Uuid,
        _repository_id: Uuid,
        _subject: &'a DownloadSubjectContext,
        _pack_oid: &'a str,
        _pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.pause_on_call {
            let _ = self.entered.send(());
            Box::pin(async move {
                match self.release.lock().await.take() {
                    Some(release) => release.await.unwrap_or(Err(PackfileUriError::Unauthorized)),
                    None => Err(PackfileUriError::Unauthorized),
                }
            })
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}

struct StreamFixture {
    state: Arc<PackHttpServerState>,
    leases: PackDeliveryLeaseRegistry,
    pin: Arc<OffloadPackPinGuard>,
    desc: SignedPackfileDescriptor,
    tenant: Uuid,
    repo: Uuid,
    pack_hash: String,
    raw_len: usize,
}

impl StreamFixture {
    fn request(&self) -> ServePackRequest<'_> {
        ServePackRequest {
            raw_uri: &self.desc.uri,
            inbound_host: "cdn.rootyard.test",
            tenant_id: self.tenant,
            repository_id: self.repo,
            pack_oid: &self.pack_hash,
            object_format: PackObjectFormat::Sha1,
            presented_subject: None,
        }
    }
}

fn build_stream_fixture(
    auth: Arc<dyn LivePackReadAuthorizer>,
    request_deadline_ms: u64,
    max_cached_packs: usize,
) -> StreamFixture {
    let mut policy = sample_policy();
    policy.request_deadline_ms = request_deadline_ms;
    let ring = Arc::new(sample_keyring());
    let resolver = sample_resolver();
    let leases = PackDeliveryLeaseRegistry::new(DurablePinRegistry::new());
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let subject = sample_subject();
    let (raw, pack_hash, sha256) = sample_pack_bytes(PackObjectFormat::Sha1, 96 * 1024);
    let pin = leases
        .acquire_offload_pin(&AcquireLeaseParams {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: &pack_hash,
            subject,
            gate_revision: 1,
            now_unix: 1_000,
            expires_at_unix: 1_120,
            grace_secs: 60,
        })
        .unwrap();
    let desc = mint_signed_offload_uri(
        &ring,
        &MintUriRequest {
            tenant_id: tenant,
            repository_id: repo,
            subject,
            pack_oid: &pack_hash,
            pack_hash_hex: &pack_hash,
            sha256_hex: &sha256,
            byte_len: raw.len() as u64,
            object_format: PackObjectFormat::Sha1,
            allowed_host: "cdn.rootyard.test",
            pin_id: pin.pin_id(),
            scope_nonce: "13579bdf2468ace0",
            now_unix: 1_000,
            policy: &policy,
            resolver: resolver.as_ref(),
        },
    )
    .unwrap();
    let mut srv = PackHttpServerState::new(ring, leases.clone(), policy, resolver, auth, Arc::new(|| 1_010));
    srv.max_cached_packs = max_cached_packs;
    let state = Arc::new(srv);
    state
        .insert_pack(PackStreamMeta {
            tenant_id: tenant,
            repository_id: repo,
            pack_oid: pack_hash.clone(),
            pack_hash_hex: pack_hash.clone(),
            object_format: PackObjectFormat::Sha1,
            sha256_hex: sha256,
            payload: Bytes::from(raw.clone()),
        })
        .unwrap();
    StreamFixture { state, leases, pin, desc, tenant, repo, pack_hash, raw_len: raw.len() }
}

#[tokio::test]
async fn stream_paused_live_auth_hits_absolute_deadline_without_yielding_and_releases_guards() {
    let (auth, mut entered, _release) = PausedAuthorizer::new(2);
    let fx = build_stream_fixture(Arc::new(auth), 100, 1);
    let permits_before = fx.state.inflight_limiter.available_permits();
    let body = serve_signed_packfile_stream(Arc::clone(&fx.state), &fx.request()).await.unwrap();
    assert_eq!(fx.leases.inflight_download_count(), 1);
    assert_eq!(fx.state.inflight_bytes.used_bytes(), fx.raw_len as u64);

    let mut stream = body.into_data_stream();
    let mut next = Box::pin(stream.next());
    tokio::select! {
        entered = tokio::time::timeout(Duration::from_secs(1), entered.recv()) => {
            assert!(entered.expect("entered signal timed out").is_some(), "live auth was not entered");
        }
        outcome = &mut next => panic!("stream yielded before paused live auth: {outcome:?}"),
    }
    let aborted = tokio::time::timeout(Duration::from_secs(2), &mut next)
        .await
        .expect("absolute stream deadline did not abort paused live auth")
        .expect("stream ended without surfacing the deadline abort");
    assert!(aborted.is_err());
    assert_eq!(fx.state.rejected_requests.load(Ordering::SeqCst), 1);

    drop(next);
    drop(stream);
    assert_eq!(fx.leases.inflight_download_count(), 0);
    assert_eq!(fx.state.inflight_bytes.used_bytes(), 0);
    assert_eq!(fx.state.inflight_limiter.available_permits(), permits_before);
}

#[tokio::test]
async fn stream_paused_live_auth_success_after_revocation_is_rechecked_before_next_chunk() {
    for disable_policy in [false, true] {
        let (auth, mut entered, release) = PausedAuthorizer::new(2);
        let fx = build_stream_fixture(Arc::new(auth), 30_000, 1);
        let permits_before = fx.state.inflight_limiter.available_permits();
        let body = serve_signed_packfile_stream(Arc::clone(&fx.state), &fx.request()).await.unwrap();
        let mut stream = body.into_data_stream();
        let mut next = Box::pin(stream.next());
        tokio::select! {
            entered = tokio::time::timeout(Duration::from_secs(1), entered.recv()) => {
                assert!(entered.expect("entered signal timed out").is_some(), "live auth was not entered");
            }
            outcome = &mut next => panic!("stream yielded before paused live auth: {outcome:?}"),
        }

        if disable_policy {
            let mut disabled = fx.state.current_policy();
            disabled.enabled = false;
            fx.state.set_policy(disabled);
        } else {
            assert!(fx.leases.revoke_pin(fx.pin.pin_id()));
        }
        release.send(Ok(())).expect("paused live auth receiver must still be live");

        let aborted = tokio::time::timeout(Duration::from_secs(2), &mut next)
            .await
            .expect("paused live auth did not abort after revocation")
            .expect("stream ended without surfacing the revocation abort");
        assert!(aborted.is_err(), "revocation during live auth must not yield another chunk");

        drop(next);
        drop(stream);
        assert_eq!(fx.leases.inflight_download_count(), 0);
        assert_eq!(fx.state.inflight_bytes.used_bytes(), 0);
        assert_eq!(fx.state.inflight_limiter.available_permits(), permits_before);
    }
}

#[tokio::test]
async fn prestream_live_auth_denial_preserves_403_and_unknown_errors_fail_closed() {
    for (auth_result, expected_status) in [
        (Err(PackfileUriError::Unauthorized), 403),
        (Err(PackfileUriError::Internal("unknown live auth failure".to_owned())), 400),
    ] {
        let (auth, mut entered, release) = PausedAuthorizer::new(1);
        let fx = build_stream_fixture(Arc::new(auth), 30_000, 1);
        let permits_before = fx.state.inflight_limiter.available_permits();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_signed_packfile_router(Arc::clone(&fx.state));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let parsed_uri: axum::http::Uri = fx.desc.uri.parse().unwrap();
        let pq = parsed_uri.path_and_query().unwrap().as_str().to_owned();
        let req_str = format!("GET {pq} HTTP/1.1\r\nHost: cdn.rootyard.test\r\nConnection: close\r\n\r\n");
        let exchange = tokio::spawn(async move { raw_http_exchange(addr, &req_str).await });
        let entered = tokio::time::timeout(Duration::from_secs(1), entered.recv())
            .await
            .expect("pre-stream live auth entered signal timed out");
        assert!(entered.is_some(), "pre-stream live auth was not entered");
        release.send(auth_result).expect("paused live auth receiver must still be live");

        let (status, body) = tokio::time::timeout(Duration::from_secs(2), exchange)
            .await
            .expect("pre-stream live auth denial did not terminate")
            .unwrap();
        assert_eq!(status, expected_status);
        assert!(!body.starts_with(b"PACK"), "denied response must never leak pack bytes");
        assert_eq!(fx.leases.inflight_download_count(), 0);
        assert_eq!(fx.state.inflight_bytes.used_bytes(), 0);
        assert_eq!(fx.state.inflight_limiter.available_permits(), permits_before);
        server.abort();
    }
}
