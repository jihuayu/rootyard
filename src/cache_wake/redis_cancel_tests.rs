//! Real Redis through a byte-forwarding proxy: no RESP/TLS implementation.
//! Holding the cache alive after cancellation distinguishes dropped caller
//! futures from actual teardown of the SDK's connection driver.
use super::*;
use crate::cache_wake::{AdvisoryCache, CacheKeyParts, CacheKind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

struct LiveConnection(Arc<AtomicUsize>);
impl Drop for LiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ReplyBlackhole {
    port: u16,
    paused: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    read_event: Arc<Notify>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl ReplyBlackhole {
    async fn start(target_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let paused = Arc::new(AtomicBool::new(false));
        let live = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let read_event = Arc::new(Notify::new());
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let (paused, live, reads, read_event, stop) =
                (paused.clone(), live.clone(), reads.clone(), read_event.clone(), stop.clone());
            async move {
                let mut connections = JoinSet::new();
                loop {
                    let accepted = tokio::select! {
                        _ = stop.cancelled() => break,
                        completed = connections.join_next(), if !connections.is_empty() => {
                            completed.expect("connection task present").expect("proxy task panicked");
                            continue;
                        }
                        accepted = listener.accept() => accepted,
                    };
                    let (client, _) = accepted.expect("owned proxy accept failed");
                    live.fetch_add(1, Ordering::SeqCst);
                    let guard = LiveConnection(live.clone());
                    let (paused, reads, read_event) = (paused.clone(), reads.clone(), read_event.clone());
                    connections.spawn(async move {
                        let _guard = guard;
                        let Ok(server) = TcpStream::connect(("127.0.0.1", target_port)).await else { return };
                        let (mut client_read, mut client_write) = client.into_split();
                        let (mut server_read, mut server_write) = server.into_split();
                        let upload = async {
                            let mut bytes = [0u8; 16 * 1024];
                            loop {
                                let n = client_read.read(&mut bytes).await?;
                                if n == 0 {
                                    return Ok::<(), std::io::Error>(());
                                }
                                reads.fetch_add(1, Ordering::SeqCst);
                                read_event.notify_one();
                                server_write.write_all(&bytes[..n]).await?;
                            }
                        };
                        let download = async {
                            let mut bytes = [0u8; 16 * 1024];
                            loop {
                                let n = server_read.read(&mut bytes).await?;
                                if n == 0 {
                                    return Ok::<(), std::io::Error>(());
                                }
                                if !paused.load(Ordering::SeqCst) {
                                    client_write.write_all(&bytes[..n]).await?;
                                }
                            }
                        };
                        // Client EOF drops both directions and the backend TCP
                        // connection. Blackholed replies are discarded, never
                        // buffered, and no wire protocol is parsed.
                        tokio::select! { _ = upload => {}, _ = download => {} }
                    });
                }
                connections.abort_all();
                while let Some(result) = connections.join_next().await {
                    if let Err(error) = result {
                        assert!(error.is_cancelled(), "proxy task panicked")
                    }
                }
            }
        });
        Self { port, paused, live, reads, read_event, stop, task }
    }

    async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.live.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancelled Redis query retained an active SDK driver connection");
    }

    async fn wait_sent(&self, before: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.reads.load(Ordering::SeqCst) <= before {
                self.read_event.notified().await;
            }
        })
        .await
        .expect("test did not observe a request sent through the proxy");
    }
}

impl Drop for ReplyBlackhole {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

#[tokio::test]
#[ignore = "requires a dedicated loopback real Redis via ROOTYARD_TEST_REDIS_URL"]
async fn real_redis_cancelled_inflight_connections_are_closed() {
    let _serial = super::tests::live_redis_serial().lock().await;
    let raw = std::env::var("ROOTYARD_TEST_REDIS_URL").expect("dedicated real Redis URL required");
    let mut url = ::redis::parse_redis_url(&raw).expect("dedicated real Redis URL must parse");
    assert_eq!(url.host_str(), Some("127.0.0.1"), "driver teardown proof requires the owned IPv4 loopback fixture");
    let proxy = ReplyBlackhole::start(url.port().unwrap_or(6379)).await;
    url.set_port(Some(proxy.port)).unwrap();
    let limits = RedisCacheLimits {
        request_timeout: Duration::from_millis(250),
        max_inflight: 2,
        ..RedisCacheLimits::default()
    };
    let cache = Arc::new(RedisCache::connect(url.as_str(), limits).await.expect("owned proxy Redis must validate"));
    let key = CacheKey::new(CacheKeyParts {
        environment: "test",
        schema: 1,
        history_incarnation: Uuid::nil(),
        tenant: Uuid::from_u128(11),
        repo: Uuid::from_u128(22),
        kind: CacheKind::TreeListing,
        version: 5,
        discriminator: "driver-teardown",
    })
    .unwrap();
    assert_eq!(cache.get(&key).await.unwrap(), None);
    proxy.paused.store(true, Ordering::SeqCst);
    for _ in 0..4 {
        assert!(cache.get(&key).await.is_err(), "blackholed Redis reply unexpectedly completed");
        // cache remains alive: closing only when the entire cache is dropped
        // would leave the shared-manager abandonment bug undetected.
        proxy.wait_closed().await;
    }
    proxy.paused.store(false, Ordering::SeqCst);
    assert_eq!(cache.get(&key).await.unwrap(), None, "cache did not recover after connection disposal");
    proxy.paused.store(true, Ordering::SeqCst);
    let before = proxy.reads.load(Ordering::SeqCst);
    let caller = tokio::spawn({
        let cache = cache.clone();
        async move { cache.get(&key).await }
    });
    proxy.wait_sent(before).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    proxy.wait_closed().await;
}
