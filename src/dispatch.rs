//! Advisory wake transports. Only PostgreSQL owns delivery state and effects.
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Notify,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Implementations carry only a hint to rescan PG. They cannot supply a Claim,
/// mark a delivery complete, choose a repository, or execute a business effect.
pub trait WakeTransport: Send + Sync {
    fn publish(&self) -> Task<'_, Result<()>>;
    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()>;
}
#[derive(Default)]
pub struct Signals {
    pub local: Arc<Notify>,
    pub remote: Arc<Notify>,
}
impl Signals {
    /// Notify stores at most one permit: bursts coalesce and never queue events.
    pub fn committed(&self) {
        self.local.notify_one();
        self.remote.notify_one();
    }
}
#[derive(Clone)]
pub struct Settings {
    pub poll: Duration,
    pub batch: i64,
    pub lease_seconds: i64,
    pub consumers: Vec<String>,
    pub transport: Option<Arc<dyn WakeTransport>>,
}
impl Settings {
    pub fn from_env() -> Result<Self> {
        fn number(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
            let value = match std::env::var(name) {
                Ok(v) => v.parse().with_context(|| format!("invalid {name}"))?,
                Err(_) => default,
            };
            ensure!(
                (min..=max).contains(&value),
                "{name} outside supported range"
            );
            Ok(value)
        }
        let consumers = std::env::var("ROOTYARD_WORKER_CONSUMERS")
            .unwrap_or_else(|_| "audit-log,ref-index".into());
        let consumers: Vec<String> = consumers.split(',').map(str::to_owned).collect();
        ensure!(
            !consumers.is_empty()
                && consumers.len() <= 2
                && consumers
                    .iter()
                    .all(|s| matches!(s.as_str(), "audit-log" | "ref-index")),
            "invalid worker consumers"
        );
        ensure!(
            consumers.len() == 1 || consumers[0] != consumers[1],
            "duplicate worker consumer"
        );
        let transport: Option<Arc<dyn WakeTransport>> =
            match std::env::var("ROOTYARD_WAKE_TRANSPORT").as_deref() {
                Err(_) | Ok("poll") => None,
                Ok("redis") => {
                    let address = std::env::var("ROOTYARD_REDIS_ADDRESS")
                        .context("ROOTYARD_REDIS_ADDRESS is required")?
                        .parse()
                        .context("Redis address must be a loopback socket address")?;
                    let channel = std::env::var("ROOTYARD_WAKE_CHANNEL")
                        .unwrap_or_else(|_| "rootyard:outbox:v1".into());
                    Some(Arc::new(RedisWake::new(address, channel)?))
                }
                Ok("kafka") => Some(Arc::new(crate::kafka_wake::KafkaWake::new(
                    std::env::var("ROOTYARD_KAFKA_BOOTSTRAP_SERVERS")
                        .context("ROOTYARD_KAFKA_BOOTSTRAP_SERVERS is required")?,
                    std::env::var("ROOTYARD_KAFKA_TOPIC")
                        .context("ROOTYARD_KAFKA_TOPIC is required")?,
                    std::env::var("ROOTYARD_KAFKA_GROUP")
                        .context("ROOTYARD_KAFKA_GROUP is required")?,
                )?)),
                _ => bail!("wake transport must be poll, redis or kafka"),
            };
        Ok(Self {
            poll: Duration::from_millis(number("ROOTYARD_WORKER_POLL_MS", 5000, 50, 60_000)?),
            batch: number("ROOTYARD_WORKER_BATCH", 64, 1, 1000)? as i64,
            lease_seconds: number("ROOTYARD_WORKER_LEASE_SECONDS", 60, 1, 3600)? as i64,
            consumers,
            transport,
        })
    }
}
/// Runs independently of native Git, volume locks, and journal reconciliation.
/// A fixed interval remains active even when no transport exists or it fails.
pub async fn worker(pool: Pool, settings: Settings, signal: Arc<Notify>, stop: CancellationToken) {
    let listener = settings.transport.clone().map(|transport| {
        let signal = signal.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            tokio::select! {biased;
                _=stop.cancelled()=>{},
                _=transport.subscribe(signal,stop.clone())=>{},
            }
        })
    });
    let owner = Uuid::new_v4();
    let mut ticks = tokio::time::interval(settings.poll);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut unavailable = false;
    loop {
        tokio::select! {biased;
            _=stop.cancelled()=>break,
            _=ticks.tick()=>{},
            _=signal.notified()=>{},
        }
        let scan = async {
            // A poisoned consumer cannot suppress another consumer's scan.
            let results =
                futures_util::future::join_all(settings.consumers.iter().map(|consumer| {
                    tokio::time::timeout(
                        Duration::from_secs(15),
                        crate::events::worker_once_with_lease(
                            &pool,
                            consumer,
                            owner,
                            settings.batch,
                            settings.lease_seconds,
                        ),
                    )
                }))
                .await;
            let mut count = 0;
            let mut failed = false;
            for result in results {
                match result {
                    Ok(Ok(done)) => count += done,
                    _ => failed = true,
                }
            }
            (count, failed)
        };
        let result = tokio::select! {biased;
            _=stop.cancelled()=>break,
            result=tokio::time::timeout(Duration::from_secs(30),scan)=>result,
        };
        let (count, failed) = result.unwrap_or((0, true));
        if count > 0 {
            signal.notify_one();
        }
        if failed && !unavailable {
            eprintln!("rootyard: delivery worker unavailable; PostgreSQL retry remains scheduled");
        }
        unavailable = failed;
        // Also bounds wake floods, successful backlog draining, and DB retries.
        tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_millis(25))=>{} }
    }
    stop.cancel();
    if let Some(listener) = listener {
        let _ = listener.await;
    }
}
/// Called outside the Git/PG commit path. Any failure loses only a wake hint.
pub async fn publisher(
    transport: Option<Arc<dyn WakeTransport>>,
    signal: Arc<Notify>,
    stop: CancellationToken,
) {
    let Some(transport) = transport else {
        return;
    };
    let mut unavailable = false;
    loop {
        tokio::select! {biased; _=stop.cancelled()=>break, _=signal.notified()=>{} }
        let result = tokio::select! {biased;
            _=stop.cancelled()=>break,
            result=tokio::time::timeout(Duration::from_secs(1),transport.publish())=>result,
        };
        match result {
            Ok(Ok(())) => unavailable = false,
            _ => {
                if !unavailable {
                    eprintln!("rootyard: advisory wake unavailable; durable polling continues");
                    unavailable = true;
                }
            }
        }
        tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_millis(25))=>{} }
    }
}

/// Plain RESP2 over loopback only. Use a local authenticated TLS tunnel/proxy
/// for a remote Redis deployment. No URL credentials or event data are accepted.
pub struct RedisWake {
    address: SocketAddr,
    channel: String,
}
impl RedisWake {
    pub fn new(address: SocketAddr, channel: String) -> Result<Self> {
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Redis wake endpoint must be nonzero loopback address"
        );
        ensure!(
            (1..=128).contains(&channel.len())
                && channel
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b":_-".contains(&c)),
            "invalid wake channel"
        );
        Ok(Self { address, channel })
    }
    async fn connect(&self, command: &[&[u8]]) -> Result<BufReader<TcpStream>> {
        let mut stream = TcpStream::connect(self.address).await?;
        let bytes = encode(command);
        stream.write_all(&bytes).await?;
        Ok(BufReader::with_capacity(1024, stream))
    }
    async fn listen(&self, signal: Arc<Notify>, stop: CancellationToken) {
        let mut unavailable = false;
        loop {
            let connect = async {
                let mut stream = self
                    .connect(&[b"SUBSCRIBE", self.channel.as_bytes()])
                    .await?;
                let expected = Frame::Array(vec![
                    Frame::Bulk(b"subscribe".to_vec()),
                    Frame::Bulk(self.channel.as_bytes().to_vec()),
                    Frame::Integer(1),
                ]);
                ensure!(
                    read_frame(&mut stream).await? == expected,
                    "invalid subscription acknowledgment"
                );
                Ok::<_, anyhow::Error>(stream)
            };
            let connected = tokio::select! {biased;
                _=stop.cancelled()=>return,
                result=tokio::time::timeout(Duration::from_secs(1),connect)=>result,
            };
            if let Ok(Ok(mut stream)) = connected {
                unavailable = false;
                signal.notify_one(); // Subscribe/reconnect race is repaired by PG scan.
                loop {
                    let frame = tokio::select! {biased;
                        _=stop.cancelled()=>return,
                        value=tokio::time::timeout(Duration::from_secs(60),read_frame(&mut stream))=>value,
                    };
                    let Ok(Ok(frame)) = frame else {
                        break;
                    };
                    let expected = Frame::Array(vec![
                        Frame::Bulk(b"message".to_vec()),
                        Frame::Bulk(self.channel.as_bytes().to_vec()),
                        Frame::Bulk(b"v1".to_vec()),
                    ]);
                    if frame != expected {
                        break;
                    }
                    signal.notify_one();
                }
            }
            if !unavailable {
                eprintln!(
                    "rootyard: advisory subscription disconnected; PostgreSQL polling continues"
                );
                unavailable = true;
            }
            tokio::select! { _=stop.cancelled()=>return, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
        }
    }
}
impl WakeTransport for RedisWake {
    fn publish(&self) -> Task<'_, Result<()>> {
        Box::pin(async move {
            let call = async {
                let mut stream = self
                    .connect(&[b"PUBLISH", self.channel.as_bytes(), b"v1"])
                    .await?;
                ensure!(
                    matches!(read_frame(&mut stream).await?,Frame::Integer(n) if n>=0),
                    "invalid publish acknowledgment"
                );
                Ok(())
            };
            tokio::time::timeout(Duration::from_secs(1), call)
                .await
                .context("wake timeout")?
        })
    }
    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()> {
        Box::pin(self.listen(signal, stop))
    }
}
fn encode(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        output.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        output.extend_from_slice(part);
        output.extend_from_slice(b"\r\n");
    }
    output
}
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Bulk(Vec<u8>),
    Integer(i64),
    Array(Vec<Frame>),
}
async fn line<R: tokio::io::AsyncBufRead + Unpin>(
    stream: &mut R,
    budget: &mut usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        ensure!(*budget > 0 && out.len() < 256, "RESP line limit");
        let byte = stream.read_u8().await?;
        *budget -= 1;
        out.push(byte);
        if byte == b'\n' {
            ensure!(out.ends_with(b"\r\n"), "invalid RESP line");
            out.truncate(out.len() - 2);
            return Ok(out);
        }
    }
}
fn frame<'a, R: tokio::io::AsyncBufRead + Unpin + Send>(
    stream: &'a mut R,
    budget: &'a mut usize,
    depth: usize,
) -> Task<'a, Result<Frame>> {
    Box::pin(async move {
        ensure!(depth <= 1, "RESP nesting limit");
        let header = line(stream, budget).await?;
        ensure!(header.len() >= 2, "invalid RESP header");
        let number: i64 = std::str::from_utf8(&header[1..])?.parse()?;
        match header[0] {
            b':' => Ok(Frame::Integer(number)),
            b'$' => {
                ensure!((0..=256).contains(&number), "RESP bulk limit");
                let length = number as usize;
                ensure!(length + 2 <= *budget, "RESP aggregate limit");
                *budget -= length + 2;
                let mut data = vec![0; length + 2];
                stream.read_exact(&mut data).await?;
                ensure!(data.ends_with(b"\r\n"), "invalid RESP bulk");
                data.truncate(length);
                Ok(Frame::Bulk(data))
            }
            b'*' => {
                ensure!(depth == 0 && (0..=3).contains(&number), "RESP array limit");
                let mut items = Vec::new();
                for _ in 0..number {
                    items.push(frame(stream, budget, depth + 1).await?);
                }
                Ok(Frame::Array(items))
            }
            _ => bail!("unexpected RESP frame"),
        }
    })
}
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin + Send>(stream: &mut R) -> Result<Frame> {
    frame(stream, &mut 1024, 0).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_and_channel_bounds() {
        assert!(RedisWake::new("0.0.0.0:6379".parse().unwrap(), "valid".into()).is_err());
        for name in ["", "has space", "bad\r\n", &"x".repeat(129)] {
            assert!(RedisWake::new("127.0.0.1:6379".parse().unwrap(), name.into()).is_err());
        }
        assert!(RedisWake::new("[::1]:6379".parse().unwrap(), "rootyard:test_1-v1".into()).is_ok());
    }
    #[tokio::test]
    async fn bounded_resp() {
        let mut good = &b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$2\r\nv1\r\n"[..];
        assert_eq!(
            read_frame(&mut good).await.unwrap(),
            Frame::Array(vec![
                Frame::Bulk(b"message".to_vec()),
                Frame::Bulk(b"x".to_vec()),
                Frame::Bulk(b"v1".to_vec())
            ])
        );
        for raw in [
            b"$999999999\r\n".as_slice(),
            b"*4\r\n",
            b"*1\r\n*1\r\n:1\r\n",
            b"$-1\r\n",
            b"$1\r\nx!!",
            b":1\n",
            b"-ERR private-data\r\n",
            b"+OK\r\n",
        ] {
            assert!(read_frame(&mut &raw[..]).await.is_err());
        }
        assert!(read_frame(&mut &vec![b'9'; 300][..]).await.is_err());
    }
    #[tokio::test]
    async fn coalesced_memory_hints() {
        let signals = Signals::default();
        for _ in 0..100_000 {
            signals.committed();
        }
        signals.local.notified().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(5), signals.local.notified())
                .await
                .is_err()
        );
        signals.remote.notified().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(5), signals.remote.notified())
                .await
                .is_err()
        );
    }
    struct FailedTransport;
    impl WakeTransport for FailedTransport {
        fn publish(&self) -> Task<'_, Result<()>> {
            Box::pin(async { bail!("simulated lost wake") })
        }
        fn subscribe(&self, _: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()> {
            Box::pin(async move { stop.cancelled().await })
        }
    }
    #[tokio::test]
    async fn failed_adapter_is_cancellable() {
        let stop = CancellationToken::new();
        let signal = Arc::new(Notify::new());
        let task = tokio::spawn(publisher(
            Some(Arc::new(FailedTransport)),
            signal.clone(),
            stop.clone(),
        ));
        signal.notify_one();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}
