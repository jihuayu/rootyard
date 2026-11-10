//! Native transport and signature regressions for the webhook sender.
use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn rfc4231_hmac_sha256_test_vectors() {
    let key1 = [0x0bu8; 20];
    assert_eq!(
        hex::encode(hmac_sha256_bytes(&key1, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hmac_sha256_hex("Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let key3 = [0xaau8; 20];
    let data3 = [0xddu8; 50];
    assert_eq!(
        hex::encode(hmac_sha256_bytes(&key3, &data3)),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    );
    let key6 = [0xaau8; 131];
    let data6 = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(
        hex::encode(hmac_sha256_bytes(&key6, data6)),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
    let data7 = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    assert_eq!(
        hex::encode(hmac_sha256_bytes(&key6, data7)),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    );
}

#[test]
fn signature_header_and_constant_time_verification() {
    let secret = "whsec_rootyard_super_secret_key";
    let payload = br#"{"event":"pull_request","action":"opened","pull_number":1}"#;
    let sig = signature_header(secret, payload);
    assert!(sig.starts_with("sha256="));
    assert_eq!(sig.len(), 71);
    assert!(verify_signature_header(secret, payload, &sig));
    assert!(!verify_signature_header(secret, b"{}", &sig));
    assert!(!verify_signature_header("wrong_secret_value", payload, &sig));
    assert!(!verify_signature_header(secret, payload, &sig.to_uppercase()));
    assert!(!verify_signature_header(secret, payload, &sig[7..]));
    assert!(!verify_signature_header(secret, payload, "sha256=deadbeef"));
}

#[test]
fn delivery_headers_include_required_metadata() {
    let d_id = Uuid::new_v4();
    let h_id = Uuid::new_v4();
    let sig = "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    let hdrs = build_delivery_headers("push", d_id, h_id, 2, sig);
    assert_eq!(hdrs["X-Rootyard-Event"], "push");
    assert_eq!(hdrs["X-Rootyard-Delivery"], d_id.to_string());
    assert_eq!(hdrs["X-Rootyard-Hook-Id"], h_id.to_string());
    assert_eq!(hdrs["X-Rootyard-Signature-256"], sig);
    assert_eq!(hdrs["X-Rootyard-Attempt"], "2");
}

struct OwnedPeer {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

/// Owned loopback HTTP/1.1 peer. It counts accepted connections, reads one
/// request, then optionally delays before writing a canned response.
fn owned_peer(delay: Duration, response: Vec<u8>) -> OwnedPeer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind owned peer");
    listener.set_nonblocking(true).expect("nonblocking owned peer");
    let addr = listener.local_addr().expect("owned peer address");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    std::thread::spawn(move || {
        let until = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.set_nonblocking(false);
                    let mut request = [0u8; 8192];
                    let _ = std::io::Read::read(&mut stream, &mut request);
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let _ = std::io::Write::write_all(&mut stream, &response);
                    let _ = std::io::Write::flush(&mut stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= until {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    OwnedPeer { addr, accepts }
}

fn empty_ok_response(status: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

async fn transport_to_owned_peer(
    peer: &OwnedPeer,
    timeout_ms: i64,
    dns_delay: Duration,
) -> (Result<u16, String>, Duration) {
    let addr = peer.addr;
    let url = format!("http://127.0.0.1:{}/hook", addr.port());
    let started = std::time::Instant::now();
    let result = send_http11_webhook_with_resolver(
        &url,
        timeout_ms,
        "ping",
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        b"{\"event\":\"ping\"}",
        true,
        move |_host, _port| {
            Box::pin(async move {
                tokio::time::sleep(dns_delay).await;
                Ok(vec![addr])
            })
        },
    )
    .await;
    (result, started.elapsed())
}

#[tokio::test]
async fn one_absolute_deadline_covers_delayed_dns_and_slow_receiver() {
    let peer = owned_peer(Duration::from_millis(1400), empty_ok_response("204 No Content"));
    let (result, elapsed) = transport_to_owned_peer(&peer, 2000, Duration::from_millis(1000)).await;
    assert!(result.is_err(), "combined budget should stop before the slow response: {result:?}");
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 1, "HTTP phase should start with the remaining budget");
    // With separate full budgets the DNS phase (1.0 s) plus the HTTP phase
    // (2.0 s) would run about 3 s. The single deadline stops near 2 s.
    assert!(elapsed >= Duration::from_millis(1800), "budget was not spent meaningfully: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(2800), "per-stage budgets were not combined: {elapsed:?}");
}

#[tokio::test]
async fn delayed_dns_and_receiver_within_one_budget_still_deliver() {
    let peer = owned_peer(Duration::from_millis(300), empty_ok_response("204 No Content"));
    let (result, elapsed) = transport_to_owned_peer(&peer, 2500, Duration::from_millis(400)).await;
    assert_eq!(result, Ok(204), "a legitimate send must not be cancelled early");
    assert!(elapsed < Duration::from_millis(2500), "{elapsed:?}");
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mixed_dns_answers_fail_before_any_connection() {
    let peer = owned_peer(Duration::ZERO, empty_ok_response("204 No Content"));
    let addr = peer.addr;
    let url = format!("http://127.0.0.1:{}/hook", addr.port());
    let result = send_http11_webhook_with_resolver(
        &url,
        2000,
        "ping",
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        b"{}",
        true,
        move |_host, _port| Box::pin(async move { Ok(vec![addr, SocketAddr::from(([10, 0, 0, 1], 80))]) }),
    )
    .await;
    assert!(result.is_err(), "{result:?}");
    assert!(result.unwrap_err().contains("blocked"), "unexpected failure reason");
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 0, "a blocked answer must not reach the network");
}

#[tokio::test]
async fn redirect_response_is_not_followed_to_an_owned_peer() {
    let target = owned_peer(Duration::ZERO, empty_ok_response("204 No Content"));
    let redirect_body = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        target.addr.port()
    )
    .into_bytes();
    let redirect = owned_peer(Duration::ZERO, redirect_body);
    let addr = redirect.addr;
    let url = format!("http://127.0.0.1:{}/hook", addr.port());
    let result = send_http11_webhook_with_resolver(
        &url,
        2000,
        "ping",
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        b"{}",
        true,
        move |_host, _port| Box::pin(async move { Ok(vec![addr]) }),
    )
    .await;
    assert_eq!(result, Ok(302), "{result:?}");
    assert_eq!(redirect.accepts.load(Ordering::SeqCst), 1);
    // Give a wrongly-followed redirect a moment to connect.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(target.accepts.load(Ordering::SeqCst), 0, "redirect target must not be contacted");
}
