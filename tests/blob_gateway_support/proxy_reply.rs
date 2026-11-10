//! A forwarded backend answer reaches a stock Git client unchanged: the real
//! status, body and end-to-end headers (challenge, `Content-Type`, operation),
//! including when the request was held at the barrier first.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{Instant, sleep},
};

use super::{
    Limits, Rule, Rules, Shared, State, resolve_held, serve,
    wire::{self, Bounds},
};

fn test_shared(backend: SocketAddr) -> Arc<Shared> {
    Arc::new(Shared {
        backend,
        limits: Limits::default(),
        state: Mutex::new(State { records: Vec::new(), rules: Rules::default(), hold: None }),
        failure: StdMutex::new(None),
    })
}

/// Read one request head and bounded body from a backend connection.
async fn read_request(stream: &mut BufReader<TcpStream>) -> (String, Vec<(String, String)>, Vec<u8>) {
    let head = wire::read_head(stream, Duration::from_secs(5)).await.unwrap().unwrap();
    let (method, target, headers) = wire::parse_head(&head).unwrap();
    let bounds = Limits::default();
    let body = wire::read_body(stream, &headers, &Bounds { max_body: bounds.max_body, max_response: bounds.max_response, idle: &bounds.idle })
        .await
        .unwrap();
    (method, headers, body)
}

async fn answer(stream: &mut TcpStream, response: &[u8]) {
    stream.write_all(response).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// One client exchange through [`serve`]; returns what the client observes.
async fn through_proxy(shared: Arc<Shared>, target: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(serve(server, shared));
    let (read, mut write) = tokio::io::split(client);
    write
        .write_all(format!("POST {target} HTTP/1.1\r\nHost: proxy\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\n\r\n0000").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(read);
    let (_, status, headers) = wire::read_backend_head(&mut reader, Instant::now() + Duration::from_secs(5)).await.unwrap();
    let (body, truncated) =
        wire::read_backend(&mut reader, &headers, &Bounds { max_body: 1024, max_response: 1024, idle: &Duration::from_secs(5) })
            .await
            .unwrap();
    assert!(!truncated);
    serving.await.unwrap().unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn forwarded_backend_challenge_reaches_the_client_unchanged() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend = listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (method, headers, body) = read_request(&mut BufReader::new(stream.try_clone().await.unwrap())).await;
        assert_eq!(method, "POST");
        assert_eq!(wire::header(&headers, "x-rootyard-operation"), Some("op-42"));
        assert_eq!(body, b"0000");
        answer(
            &mut stream,
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: Basic realm=\"rootyard\"\r\n\
              Content-Type: application/x-git-receive-pack-result\r\n\
              X-Rootyard-Operation: op-42\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await;
    });
    let shared = test_shared(backend);
    let (status, headers, body) =
        through_proxy(shared.clone(), "/git/alice/demo.git/git-receive-pack?operation=op-42").await;
    backend_task.await.unwrap();
    assert_eq!(shared.failure(), None);
    assert_eq!(status, 401);
    assert!(body.is_empty());
    assert_eq!(wire::header(&headers, "www-authenticate"), Some("Basic realm=\"rootyard\""));
    assert_eq!(wire::header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
    assert_eq!(wire::header(&headers, "x-rootyard-operation"), Some("op-42"));
    let records = shared.state.lock().await.records.clone();
    assert_eq!(records.first().and_then(|record| record.status), Some(401));
}

#[tokio::test]
async fn held_backend_headers_are_saved_and_forwarded() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend = listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut BufReader::new(stream.try_clone().await.unwrap())).await;
        answer(
            &mut stream,
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/x-git-receive-pack-result\r\n\
              X-Rootyard-Operation: held-1\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: keep-alive\r\n\
              Keep-Alive: timeout=5\r\n\r\n\
              4\r\n0000\r\n0\r\n\r\n",
        )
        .await;
    });
    let shared = test_shared(backend);
    // Arm the barrier through its public path, replacing the joint slot so the
    // saved reply can be inspected after it reached the client.
    shared.hold_connection(1).await.unwrap();
    let outcome = Arc::new(tokio::sync::Mutex::new(None));
    shared.state.lock().await.rules.connection = vec![Rule::Hold { outcome: outcome.clone(), captured: None }];
    let client = through_proxy(shared.clone(), "/git/alice/demo.git/git-receive-pack");
    let held = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if shared.state.lock().await.hold.as_ref().is_some_and(|hold| hold.arrived.len() == 1) {
                return !client.is_finished();
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert_eq!(held, Ok(true), "the held request was answered before the barrier opened");
    resolve_held(&shared).await.unwrap();
    let (status, headers, body) = client.await.unwrap();
    backend_task.await.unwrap();
    assert_eq!(shared.failure(), None);
    assert_eq!(status, 200);
    assert_eq!(body, b"0000");
    assert_eq!(wire::header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
    assert_eq!(wire::header(&headers, "x-rootyard-operation"), Some("held-1"));
    assert_eq!(wire::header(&headers, "content-length"), Some("4"));
    assert_eq!(wire::header(&headers, "connection"), Some("close"));
    assert_eq!(wire::header(&headers, "transfer-encoding"), None);
    assert_eq!(wire::header(&headers, "keep-alive"), None);
    let saved = outcome.lock().await.clone().unwrap().unwrap();
    assert_eq!(saved.headers, vec![
        ("content-type".to_owned(), "application/x-git-receive-pack-result".to_owned()),
        ("x-rootyard-operation".to_owned(), "held-1".to_owned()),
        ("transfer-encoding".to_owned(), "chunked".to_owned()),
        ("connection".to_owned(), "keep-alive".to_owned()),
        ("keep-alive".to_owned(), "timeout=5".to_owned()),
    ]);
}
