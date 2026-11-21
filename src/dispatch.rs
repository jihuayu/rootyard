//! Advisory wake transports. Only PostgreSQL owns delivery state and effects.
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
#[cfg(not(feature = "state-redis"))]
use std::net::SocketAddr;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Notify;
#[cfg(not(feature = "state-redis"))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::observability::{
    self,
    worker::{OperationContext, Phase, WorkerKind},
};

type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Explicit worker topology selectors. The generic scope preserves its existing
/// `audit-log,ref-index` and Ref-CAS projection scans. The A4 scope restricts
/// the scan to the dedicated target evidence kind, uses the A4 wake namespace,
/// and never enables legacy consumers or projection jobs.
pub const WORKER_SCOPE_ENV: &str = "ROOTYARD_WORKER_SCOPE";
pub const A4_WORKER_SCOPE: &str = "a4-target-audit";
/// A4 wake selection is deliberately separate from the generic outbox wake.
/// Setting the generic variables can never enroll this producer/subscriber.
pub const A4_WAKE_TRANSPORT_ENV: &str = "ROOTYARD_A4_WAKE_TRANSPORT";
pub const A4_WAKE_CHANNEL_ENV: &str = "ROOTYARD_A4_WAKE_CHANNEL";
/// Placement of the standalone A4 consumer. `embedded` is the default; the
/// explicit `external` value removes the in-process consumer so a separately
/// supervised `ROOTYARD_WORKER_SCOPE=a4-target-audit` process is the only one
/// that can claim the target audit rows.
pub const A4_WORKER_MODE_ENV: &str = "ROOTYARD_A4_WORKER_MODE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerScope {
    Generic,
    A4TargetAudit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A4WorkerMode {
    Embedded,
    External,
}

impl A4WorkerMode {
    /// True only for the default placement. External placement must not keep a
    /// dormant local consumer that could claim the healthy push or fallback.
    pub const fn runs_embedded_worker(self) -> bool {
        matches!(self, Self::Embedded)
    }
}

/// The fixed A4 advisory namespace. It contains the exact durable target-audit
/// kind and is never derived from a repository, operation, token or payload.
pub fn a4_wake_channel() -> String {
    format!("rootyard:a4:{}:v1", crate::events::TARGET_AUDIT_KIND)
}

/// Resolve the installation-selected A4 channel. Only a truly absent variable
/// selects the A4 default; a present empty, invalid or non-Unicode value fails
/// closed. The A4 namespace must also differ from the actual generic wake
/// channel, including the generic default, so one configured Generic worker can
/// never consume A4 hints or vice versa.
pub fn a4_wake_channel_from_env() -> Result<String> {
    let explicit = env_text(A4_WAKE_CHANNEL_ENV)?;
    let generic = crate::cache_wake::generic_wake_channel_from_env()?;
    a4_wake_channel_for(explicit.as_deref(), &generic)
}

fn a4_wake_channel_for(explicit: Option<&str>, generic: &str) -> Result<String> {
    let channel = match explicit {
        Some(value) => value.to_owned(),
        None => a4_wake_channel(),
    };
    crate::cache_wake::validate_wake_channel(&channel)?;
    ensure!(channel.as_str() != generic, "A4 wake channel must differ from the generic wake channel");
    Ok(channel)
}

pub fn worker_scope_from_env() -> Result<WorkerScope> {
    let raw = env_text(WORKER_SCOPE_ENV)?;
    worker_scope(raw.as_deref())
}

fn worker_scope(raw: Option<&str>) -> Result<WorkerScope> {
    match raw {
        None | Some("generic") => Ok(WorkerScope::Generic),
        Some(A4_WORKER_SCOPE) => Ok(WorkerScope::A4TargetAudit),
        Some(_) => bail!("{WORKER_SCOPE_ENV} must be generic or {A4_WORKER_SCOPE}"),
    }
}

pub fn a4_worker_mode_from_env() -> Result<A4WorkerMode> {
    let raw = env_text(A4_WORKER_MODE_ENV)?;
    a4_worker_mode(raw.as_deref())
}

fn a4_worker_mode(raw: Option<&str>) -> Result<A4WorkerMode> {
    match raw {
        None | Some("embedded") => Ok(A4WorkerMode::Embedded),
        Some("external") => Ok(A4WorkerMode::External),
        Some(_) => bail!("{A4_WORKER_MODE_ENV} must be embedded or external"),
    }
}

/// Read one new A4-specific variable with strict presence semantics. Only
/// `VarError::NotPresent` means "use the documented default"; present empty,
/// malformed and non-Unicode values are refusals. The error names the variable
/// but never includes its value.
fn env_text(name: &str) -> Result<Option<String>> {
    env_text_from(name, std::env::var(name))
}

fn env_text_from(name: &str, raw: std::result::Result<String, std::env::VarError>) -> Result<Option<String>> {
    match raw {
        Ok(value) if value.is_empty() => bail!("{name} must not be empty"),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid Unicode"),
    }
}

/// Implementations carry only a hint to rescan PG. They cannot supply a Claim,
/// mark a delivery complete, choose a repository, or execute a business effect.
pub trait WakeTransport: Send + Sync {
    fn publish(&self) -> Task<'_, Result<()>>;
    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()>;
}
#[derive(Clone, Default)]
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
    /// Restrict every consumer scan to the dedicated pg_refstore audit
    /// evidence kind. The shared legacy/default path keeps `false`.
    pub target_audit_only: bool,
    /// Enqueue/execute Ref-CAS projection jobs. The standalone target keeps
    /// this `false`; the shared legacy/default path keeps `true`.
    pub projection_jobs: bool,
}
impl Settings {
    /// Minimal serving never inspects or constructs external wake transports.
    /// Notify coalesces hints; periodic PostgreSQL scanning owns reliability.
    pub fn standalone() -> Self {
        Self {
            poll: Duration::from_secs(1),
            batch: 64,
            lease_seconds: 60,
            consumers: vec![crate::events::TARGET_AUDIT_CONSUMER.to_owned()],
            transport: None,
            target_audit_only: true,
            projection_jobs: false,
        }
    }

    /// Standalone serving keeps its bounded Memory cache and PG target-audit
    /// scan. The only production opt-in here is the explicitly selected A4
    /// advisory transport; generic wake variables are never read.
    pub fn standalone_from_env() -> Result<Self> {
        let mut settings = Self::standalone();
        settings.transport = a4_transport_from_env()?;
        Ok(settings)
    }

    /// Explicit external A4 worker. It scans only the target audit evidence
    /// kind and never enables Ref-CAS projection jobs or legacy consumers.
    pub fn a4_target_audit() -> Self {
        Self {
            poll: Duration::from_secs(1),
            batch: 64,
            lease_seconds: 60,
            consumers: vec![crate::events::TARGET_AUDIT_CONSUMER.to_owned()],
            transport: None,
            target_audit_only: true,
            projection_jobs: false,
        }
    }

    /// Read only the shared worker bounds and the A4-specific wake transport.
    /// `ROOTYARD_WORKER_CONSUMERS`, `ROOTYARD_WAKE_TRANSPORT` and
    /// `ROOTYARD_WAKE_CHANNEL` are deliberately ignored in this scope.
    pub fn a4_target_audit_from_env() -> Result<Self> {
        let mut settings = Self::a4_target_audit();
        settings.poll = Duration::from_millis(number_strict("ROOTYARD_WORKER_POLL_MS", 5000, 50, 60_000)?);
        settings.batch = number_strict("ROOTYARD_WORKER_BATCH", 64, 1, 1000)? as i64;
        settings.lease_seconds = number_strict("ROOTYARD_WORKER_LEASE_SECONDS", 60, 1, 3600)? as i64;
        settings.transport = a4_transport_from_env()?;
        Ok(settings)
    }

    pub fn from_env() -> Result<Self> {
        let consumers =
            std::env::var("ROOTYARD_WORKER_CONSUMERS").unwrap_or_else(|_| crate::events::CONSUMERS.join(","));
        let consumers: Vec<String> = consumers.split(',').map(str::to_owned).collect();
        ensure!(
            !consumers.is_empty()
                && consumers.len() <= crate::events::CONSUMERS.len()
                && consumers.iter().all(|s| crate::events::CONSUMERS.contains(&s.as_str())),
            "invalid worker consumers"
        );
        ensure!(consumers.len() == 1 || consumers[0] != consumers[1], "duplicate worker consumer");
        let transport: Option<Arc<dyn WakeTransport>> = match std::env::var("ROOTYARD_WAKE_TRANSPORT").as_deref() {
            Err(_) | Ok("poll") | Ok("memory") => None,
            Ok("redis") => {
                #[cfg(feature = "state-redis")]
                {
                    Some(Arc::new(crate::cache_wake::RedisWake::from_env()?))
                }
                #[cfg(not(feature = "state-redis"))]
                {
                    let address: std::net::SocketAddr = std::env::var("ROOTYARD_REDIS_ADDRESS")
                        .context("ROOTYARD_REDIS_ADDRESS is required")?
                        .parse()
                        .context("Redis address must be a loopback socket address")?;
                    let channel = crate::cache_wake::generic_wake_channel_from_env()?;
                    Some(Arc::new(RedisWake::new(address, channel)?))
                }
            }
            #[cfg(feature = "kafka-wake")]
            Ok("kafka") => Some(Arc::new(crate::kafka_wake::KafkaWake::new(
                std::env::var("ROOTYARD_KAFKA_BOOTSTRAP_SERVERS")
                    .context("ROOTYARD_KAFKA_BOOTSTRAP_SERVERS is required")?,
                std::env::var("ROOTYARD_KAFKA_TOPIC").context("ROOTYARD_KAFKA_TOPIC is required")?,
                std::env::var("ROOTYARD_KAFKA_GROUP").context("ROOTYARD_KAFKA_GROUP is required")?,
            )?)),
            #[cfg(not(feature = "kafka-wake"))]
            Ok("kafka") => bail!("Kafka wake support was not compiled; enable kafka-wake explicitly"),
            _ => bail!("wake transport must be poll, memory, redis or kafka"),
        };
        Ok(Self {
            poll: Duration::from_millis(number("ROOTYARD_WORKER_POLL_MS", 5000, 50, 60_000)?),
            batch: number("ROOTYARD_WORKER_BATCH", 64, 1, 1000)? as i64,
            lease_seconds: number("ROOTYARD_WORKER_LEASE_SECONDS", 60, 1, 3600)? as i64,
            consumers,
            transport,
            target_audit_only: false,
            projection_jobs: true,
        })
    }
}

/// Existing generic numeric read. It intentionally retains the legacy
/// non-Unicode fallback for the generic worker path; the A4 path uses the
/// strict variant below.
fn number(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let raw = std::env::var(name).ok();
    number_from_setting(name, raw.as_deref(), default, min, max)
}

fn number_strict(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let raw = env_text(name)?;
    number_from_setting(name, raw.as_deref(), default, min, max)
}

fn number_from_setting(name: &str, raw: Option<&str>, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match raw {
        Some(value) => value.parse().with_context(|| format!("invalid {name}"))?,
        None => default,
    };
    ensure!((min..=max).contains(&value), "{name} outside supported range");
    Ok(value)
}

fn a4_transport_from_env() -> Result<Option<Arc<dyn WakeTransport>>> {
    let raw = env_text(A4_WAKE_TRANSPORT_ENV)?;
    a4_transport_from_setting(raw.as_deref())
}

fn a4_transport_from_setting(raw: Option<&str>) -> Result<Option<Arc<dyn WakeTransport>>> {
    match raw {
        None | Some("poll") | Some("memory") => Ok(None),
        Some("redis") => {
            #[cfg(feature = "state-redis")]
            {
                let channel = a4_wake_channel_from_env()?;
                Ok(Some(Arc::new(crate::cache_wake::RedisWake::from_env_with_channel(channel)?)))
            }
            #[cfg(not(feature = "state-redis"))]
            {
                bail!("A4 Redis wake requires building with feature 'state-redis'")
            }
        }
        Some(_) => bail!("{A4_WAKE_TRANSPORT_ENV} must be poll, memory or redis"),
    }
}

/// Runs independently of native Git, volume locks, and journal reconciliation.
/// A fixed interval remains active even when no transport exists or it fails.
pub async fn worker(pool: Pool, settings: Settings, signal: Arc<Notify>, stop: CancellationToken) {
    let listener_operation = OperationContext::new(WorkerKind::DurableDispatch);
    let listener = settings.transport.clone().map(|transport| {
        let signal = signal.clone();
        let stop = stop.clone();
        observability::worker::spawn(&listener_operation, Phase::Subscribe, async move {
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
        let operation = OperationContext::new(WorkerKind::DurableDispatch);
        let target_kind = settings.target_audit_only.then_some(crate::events::TARGET_AUDIT_KIND);
        let scan = async {
            // A poisoned consumer cannot suppress another consumer's scan.
            let results = futures_util::future::join_all(settings.consumers.iter().map(|consumer| {
                tokio::time::timeout(
                    Duration::from_secs(15),
                    crate::events::worker_once_with_lease_scoped(
                        &pool,
                        consumer,
                        target_kind,
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
                    Ok(Err(error)) => {
                        observability::observe_internal(&error);
                        failed = true;
                    }
                    Err(_) => {
                        observability::observe_timeout();
                        failed = true;
                    }
                }
            }
            if settings.projection_jobs {
                match tokio::time::timeout(
                    Duration::from_secs(15),
                    crate::events::process_ref_cas_projection_jobs(
                        &pool,
                        owner,
                        settings.batch,
                        settings.lease_seconds,
                    ),
                )
                .await
                {
                    Ok(Ok(done)) => count += done,
                    Ok(Err(error)) => {
                        observability::observe_internal(&error);
                        failed = true;
                    }
                    Err(_) => {
                        observability::observe_timeout();
                        failed = true;
                    }
                }
            }
            (count, failed)
        };
        let result = tokio::select! {biased;
            _=stop.cancelled()=>break,
            result=tokio::time::timeout(Duration::from_secs(30), observability::worker::run(&operation, Phase::Dispatch, scan))=>result,
        };
        if result.is_err() {
            // Re-attribute the outer deadline to the same operation instead of
            // letting it fall through to a detached scope.
            observability::worker::run(&operation, Phase::Dispatch, async { observability::observe_timeout() }).await;
        }
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
pub async fn publisher(transport: Option<Arc<dyn WakeTransport>>, signal: Arc<Notify>, stop: CancellationToken) {
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

#[cfg(not(feature = "state-redis"))]
/// Plain RESP2 over loopback only. Use a local authenticated TLS tunnel/proxy
/// for a remote Redis deployment. No URL credentials or event data are accepted.
pub struct RedisWake {
    address: SocketAddr,
    channel: String,
}
#[cfg(not(feature = "state-redis"))]
impl RedisWake {
    pub fn new(address: SocketAddr, channel: String) -> Result<Self> {
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Redis wake endpoint must be nonzero loopback address"
        );
        ensure!(
            (1..=128).contains(&channel.len())
                && channel.bytes().all(|c| c.is_ascii_alphanumeric() || b":_-".contains(&c)),
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
                let mut stream = self.connect(&[b"SUBSCRIBE", self.channel.as_bytes()]).await?;
                let expected = Frame::Array(vec![
                    Frame::Bulk(b"subscribe".to_vec()),
                    Frame::Bulk(self.channel.as_bytes().to_vec()),
                    Frame::Integer(1),
                ]);
                ensure!(read_frame(&mut stream).await? == expected, "invalid subscription acknowledgment");
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
                eprintln!("rootyard: advisory subscription disconnected; PostgreSQL polling continues");
                unavailable = true;
            }
            tokio::select! { _=stop.cancelled()=>return, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
        }
    }
}
#[cfg(not(feature = "state-redis"))]
impl WakeTransport for RedisWake {
    fn publish(&self) -> Task<'_, Result<()>> {
        Box::pin(async move {
            let call = async {
                let mut stream = self.connect(&[b"PUBLISH", self.channel.as_bytes(), b"v1"]).await?;
                ensure!(
                    matches!(read_frame(&mut stream).await?,Frame::Integer(n) if n>=0),
                    "invalid publish acknowledgment"
                );
                Ok(())
            };
            tokio::time::timeout(Duration::from_secs(1), call).await.context("wake timeout")?
        })
    }
    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()> {
        Box::pin(self.listen(signal, stop))
    }
}
#[cfg(not(feature = "state-redis"))]
fn encode(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        output.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        output.extend_from_slice(part);
        output.extend_from_slice(b"\r\n");
    }
    output
}
#[cfg(not(feature = "state-redis"))]
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Bulk(Vec<u8>),
    Integer(i64),
    Array(Vec<Frame>),
}
#[cfg(not(feature = "state-redis"))]
async fn line<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R, budget: &mut usize) -> Result<Vec<u8>> {
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
#[cfg(not(feature = "state-redis"))]
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
#[cfg(not(feature = "state-redis"))]
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin + Send>(stream: &mut R) -> Result<Frame> {
    frame(stream, &mut 1024, 0).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "state-redis"))]
    #[test]
    fn endpoint_and_channel_bounds() {
        assert!(RedisWake::new("0.0.0.0:6379".parse().unwrap(), "valid".into()).is_err());
        for name in ["", "has space", "bad\r\n", &"x".repeat(129)] {
            assert!(RedisWake::new("127.0.0.1:6379".parse().unwrap(), name.into()).is_err());
        }
        assert!(RedisWake::new("[::1]:6379".parse().unwrap(), "rootyard:test_1-v1".into()).is_ok());
    }
    #[cfg(not(feature = "state-redis"))]
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
        assert!(tokio::time::timeout(Duration::from_millis(5), signals.local.notified()).await.is_err());
        signals.remote.notified().await;
        assert!(tokio::time::timeout(Duration::from_millis(5), signals.remote.notified()).await.is_err());
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
    #[test]
    fn standalone_scan_is_target_audit_only_and_skips_projection_jobs() {
        let settings = Settings::standalone();
        assert_eq!(settings.consumers, vec![crate::events::TARGET_AUDIT_CONSUMER.to_owned()]);
        assert!(settings.target_audit_only);
        assert!(!settings.projection_jobs);
        assert!(settings.transport.is_none());
    }
    #[test]
    fn a4_scope_excludes_legacy_consumers_and_projection_jobs() {
        let settings = Settings::a4_target_audit();
        assert_eq!(settings.consumers, vec![crate::events::TARGET_AUDIT_CONSUMER.to_owned()]);
        assert!(settings.target_audit_only);
        assert!(!settings.projection_jobs);
        assert!(settings.transport.is_none());
    }
    #[test]
    fn a4_channel_is_namespaced_valid_and_contains_the_target_kind() {
        let channel = a4_wake_channel();
        assert!(channel.starts_with("rootyard:a4:"));
        assert!(channel.contains(crate::events::TARGET_AUDIT_KIND));
        crate::cache_wake::validate_wake_channel(&channel).unwrap();
    }
    #[test]
    fn worker_scope_defaults_only_when_missing_and_rejects_empty_or_unknown() {
        assert_eq!(worker_scope(None).unwrap(), WorkerScope::Generic);
        assert_eq!(worker_scope(Some("generic")).unwrap(), WorkerScope::Generic);
        assert_eq!(worker_scope(Some(A4_WORKER_SCOPE)).unwrap(), WorkerScope::A4TargetAudit);
        assert!(worker_scope(Some("")).is_err());
        assert!(worker_scope(Some("a4")).is_err());
        assert!(worker_scope(Some("legacy")).is_err());
    }
    #[test]
    fn a4_worker_mode_defaults_only_when_missing_and_rejects_empty_or_unknown() {
        assert_eq!(a4_worker_mode(None).unwrap(), A4WorkerMode::Embedded);
        assert_eq!(a4_worker_mode(Some("embedded")).unwrap(), A4WorkerMode::Embedded);
        assert_eq!(a4_worker_mode(Some("external")).unwrap(), A4WorkerMode::External);
        assert!(a4_worker_mode(Some("")).is_err());
        assert!(a4_worker_mode(Some("disabled")).is_err());
        assert!(a4_worker_mode(Some("Redis")).is_err());
        assert!(A4WorkerMode::Embedded.runs_embedded_worker());
        assert!(!A4WorkerMode::External.runs_embedded_worker());
    }
    #[test]
    fn a4_transport_defaults_only_when_missing_and_rejects_empty_or_unrelated() {
        assert!(a4_transport_from_setting(None).unwrap().is_none());
        assert!(a4_transport_from_setting(Some("poll")).unwrap().is_none());
        assert!(a4_transport_from_setting(Some("memory")).unwrap().is_none());
        assert!(a4_transport_from_setting(Some("")).is_err());
        assert!(a4_transport_from_setting(Some("kafka")).is_err());
        assert!(a4_transport_from_setting(Some("redis ")).is_err());
    }
    #[test]
    fn a4_channel_cannot_alias_the_generic_channel_or_default() {
        let a4 = a4_wake_channel();
        let generic = crate::cache_wake::GENERIC_WAKE_CHANNEL_DEFAULT;
        assert_ne!(a4.as_str(), generic);
        assert_eq!(a4_wake_channel_for(None, generic).unwrap(), a4);
        assert!(a4_wake_channel_for(None, &a4).is_err());
        assert!(a4_wake_channel_for(Some(generic), generic).is_err());
        assert!(a4_wake_channel_for(Some(a4.as_str()), generic).is_ok());
        assert!(a4_wake_channel_for(Some(""), generic).is_err());
        assert!(a4_wake_channel_for(Some("has space"), generic).is_err());
    }
    #[test]
    fn strict_env_presence_rejects_empty_and_non_unicode_without_echoing() {
        assert_eq!(env_text_from("ROOTYARD_TEST_STRICT", Err(std::env::VarError::NotPresent)).unwrap(), None);
        assert!(env_text_from("ROOTYARD_TEST_STRICT", Ok(String::new())).is_err());
        let error = env_text_from(
            "ROOTYARD_TEST_STRICT",
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from("private-value"))),
        )
        .expect_err("non-Unicode must be refused");
        let text = format!("{error}");
        assert!(text.contains("ROOTYARD_TEST_STRICT"));
        assert!(!text.contains("private-value"));
    }
    #[test]
    fn strict_a4_numbers_default_only_when_missing_and_reject_bad_values() {
        assert_eq!(number_from_setting("ROOTYARD_TEST_NUMBER", None, 5, 1, 10).unwrap(), 5);
        assert_eq!(number_from_setting("ROOTYARD_TEST_NUMBER", Some("7"), 5, 1, 10).unwrap(), 7);
        assert!(number_from_setting("ROOTYARD_TEST_NUMBER", Some(""), 5, 1, 10).is_err());
        assert!(number_from_setting("ROOTYARD_TEST_NUMBER", Some("0"), 5, 1, 10).is_err());
        assert!(number_from_setting("ROOTYARD_TEST_NUMBER", Some("11"), 5, 1, 10).is_err());
        assert!(number_from_setting("ROOTYARD_TEST_NUMBER", Some("not-a-number"), 5, 1, 10).is_err());
    }
    #[cfg(not(feature = "state-redis"))]
    #[test]
    fn a4_redis_requires_the_explicit_state_redis_feature() {
        let error = a4_transport_from_setting(Some("redis")).err().expect("redis must be refused");
        assert!(format!("{error}").contains("state-redis"));
    }
    #[tokio::test]
    async fn failed_adapter_is_cancellable() {
        let stop = CancellationToken::new();
        let signal = Arc::new(Notify::new());
        let task = tokio::spawn(publisher(Some(Arc::new(FailedTransport)), signal.clone(), stop.clone()));
        signal.notify_one();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
    }
}
