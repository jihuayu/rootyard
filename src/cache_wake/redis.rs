//! Optional Redis adapters built on the mature `redis` async client.
//!
//! This module is compiled only with `--features state-redis`. It contains no
//! RESP parser, raw TCP client or TLS implementation. A standalone default
//! build exposes the Memory boundary and uses local `Notify` hints. Serving
//! cache consumers are not wired by this increment.
//!
//! `CacheLimits::max_entries`/`max_bytes` are Memory limits. Redis uses an
//! explicit, separate startup contract: a dedicated instance must set a finite
//! `maxmemory` and an eviction policy, validated before the cache is returned.
//! `RedisCache::connect` fails closed when CONFIG is unavailable or the server
//! cannot prove that bound. The Redis contract is memory eviction, not a hard
//! quota and never an authority.
use super::{AdvisoryCache, CacheKey, CacheTask, CacheValue, WAKE_PAYLOAD, validate_wake_channel};
use crate::dispatch::WakeTransport;
use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type MultiplexedConnection = ::redis::aio::MultiplexedConnection;
#[cfg(test)]
type ConnectionManager = ::redis::aio::ConnectionManager;

/// Reject obvious accidental weak deployment choices. TLS is never inferred or
/// downgraded: a remote endpoint must use `rediss://`, while plaintext
/// `redis://` is accepted only for an explicitly loopback authority.
fn validate_redis_url(raw: &str) -> Result<()> {
    ensure!(!raw.is_empty() && raw.len() <= 1024, "invalid Redis URL");
    // redis-rs treats a URL fragment named `insecure` as permission to disable
    // certificate and hostname verification. This adapter has no unsafe TLS
    // mode, so reject every fragment before the client can interpret it.
    ensure!(!raw.contains('#'), "Redis URL fragments, including #insecure, are not allowed");
    let rest = if let Some(rest) = raw.strip_prefix("rediss://") {
        ensure!(!authority_host(rest).is_empty(), "Redis TLS URL requires a host");
        rest
    } else if let Some(rest) = raw.strip_prefix("redis://") {
        ensure!(
            matches!(authority_host(rest), "127.0.0.1" | "::1" | "localhost"),
            "plaintext redis:// is only allowed for a loopback endpoint; use rediss:// for remote Redis"
        );
        rest
    } else {
        bail!("Redis URL must use rediss:// (or redis:// only for loopback)")
    };
    // The pinned redis-rs TCP parser recognizes only `protocol` in a query.
    // Reject every other parameter, including names other clients use to
    // disable TLS verification, instead of accepting and silently ignoring
    // them. Normal rediss:// certificate and hostname verification remains
    // delegated to redis-rs/rustls; this module contains no TLS code.
    if let Some((_, query)) = rest.split_once('?') {
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            ensure!(name == "protocol", "unsupported Redis URL query parameter");
            ensure!(matches!(value, "2" | "3" | "resp2" | "resp3"), "unsupported Redis protocol query value");
        }
    }
    Ok(())
}

/// Host extraction is used only for the plaintext-loopback policy check. Full
/// URL parsing, ACL credentials and TLS parameters are delegated to redis-rs.
fn authority_host(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if let Some(ipv6) = host_port.strip_prefix('[') {
        ipv6.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    }
}

/// The Redis-relevant subset of cache bounds. Memory's entry/byte caps are
/// deliberately absent: Redis capacity is proved from the dedicated server's
/// `maxmemory` + eviction policy instead of silently ignoring them.
#[derive(Clone, Copy, Debug)]
pub struct RedisCacheLimits {
    pub max_value_bytes: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub request_timeout: Duration,
    pub max_inflight: usize,
}

impl Default for RedisCacheLimits {
    fn default() -> Self {
        Self {
            max_value_bytes: 1024 * 1024,
            default_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            max_inflight: 32,
        }
    }
}

impl RedisCacheLimits {
    pub fn from_cache_limits(limits: super::CacheLimits) -> Self {
        Self {
            max_value_bytes: limits.max_value_bytes,
            default_ttl: limits.default_ttl,
            max_ttl: limits.max_ttl,
            request_timeout: limits.request_timeout,
            max_inflight: limits.max_inflight,
        }
    }

    pub fn from_env() -> Result<Self> {
        let limits = Self {
            max_value_bytes: super::number(
                "ROOTYARD_CACHE_MAX_VALUE_BYTES",
                Self::default().max_value_bytes as u64,
                1,
                64 * 1024 * 1024,
            )? as usize,
            default_ttl: Duration::from_secs(super::number("ROOTYARD_CACHE_TTL_SECONDS", 60, 1, 3600)?),
            max_ttl: Duration::from_secs(super::number("ROOTYARD_CACHE_MAX_TTL_SECONDS", 3600, 1, 86_400)?),
            request_timeout: Duration::from_millis(super::number(
                "ROOTYARD_CACHE_REQUEST_TIMEOUT_MS",
                1000,
                10,
                30_000,
            )?),
            max_inflight: super::number("ROOTYARD_CACHE_MAX_INFLIGHT", 32, 1, 1024)? as usize,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_value_bytes > 0, "Redis max_value_bytes must be positive");
        ensure!(self.max_value_bytes <= i64::MAX as usize, "Redis max_value_bytes exceeds GETRANGE bounds");
        ensure!(!self.default_ttl.is_zero(), "Redis default_ttl must be positive");
        ensure!(self.default_ttl <= self.max_ttl, "Redis default_ttl exceeds max_ttl");
        ensure!(!self.request_timeout.is_zero(), "Redis request_timeout must be positive");
        ensure!(self.max_inflight > 0, "Redis max_inflight must be positive");
        Ok(())
    }

    pub fn effective_ttl(&self, ttl: Option<Duration>) -> Result<Duration> {
        let ttl = ttl.unwrap_or(self.default_ttl);
        ensure!(!ttl.is_zero(), "cache ttl must be positive");
        ensure!(ttl <= self.max_ttl, "cache ttl exceeds max_ttl");
        Ok(ttl)
    }
}

/// Proof obtained from a dedicated Redis server before caching is enabled.
/// Stored policy is one of the fixed eviction names, safe to print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedisServerContract {
    pub maxmemory_bytes: u64,
    pub maxmemory_policy: &'static str,
}

fn eviction_policy(raw: &str) -> Result<&'static str> {
    match raw {
        "allkeys-lru" => Ok("allkeys-lru"),
        "allkeys-lfu" => Ok("allkeys-lfu"),
        "allkeys-random" => Ok("allkeys-random"),
        // Every value this cache writes has PX TTL, so volatile policies still
        // make all cache entries evictable.
        "volatile-lru" => Ok("volatile-lru"),
        "volatile-lfu" => Ok("volatile-lfu"),
        "volatile-random" => Ok("volatile-random"),
        "volatile-ttl" => Ok("volatile-ttl"),
        "noeviction" => bail!("Redis cache instance must not use noeviction"),
        _ => bail!("unsupported Redis maxmemory-policy for a cache instance"),
    }
}

/// Decode a bounded cache read. A TTL expiry, FLUSH, replacement or corrupt value
/// between STRLEN and GETRANGE is a miss, never an error or authority signal.
fn decode_bounded(key: &CacheKey, raw: &[u8], declared_length: u64) -> Option<CacheValue> {
    if raw.len() as u64 != declared_length {
        return None;
    }
    CacheValue::decode(key, raw).ok()
}

/// Check the cheap encoded-length bound before allocating the encoded value.
fn encode_bounded(value: &CacheValue, max_value_bytes: usize) -> Result<Vec<u8>> {
    ensure!(value.encoded_len() <= max_value_bytes, "cache value exceeds max_value_bytes");
    Ok(value.encode())
}

/// Capacity-bounded LIFO pool of canonical multiplexed connections. Every
/// entry is an owned `MultiplexedConnection`; no clone is shared between
/// borrowers, so a borrower that errors or times out drops the last handle for
/// its own canonical driver. redis-rs aborts that driver task on last drop,
/// which closes the socket and discards commands already written to it instead
/// of queueing them forever behind a manager that outlives the request.
struct IdlePool {
    capacity: usize,
    connections: Mutex<Vec<MultiplexedConnection>>,
}

impl IdlePool {
    fn new(capacity: usize) -> Self {
        Self { capacity, connections: Mutex::new(Vec::with_capacity(capacity)) }
    }

    /// Pop an idle connection. The pool mutex is never held across I/O.
    fn take(&self) -> Option<MultiplexedConnection> {
        self.connections.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop()
    }

    /// Return a connection only after its whole operation completed
    /// successfully. At capacity the caller's connection is dropped instead.
    fn put(&self, connection: MultiplexedConnection) {
        let mut connections = self.connections.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if connections.len() >= self.capacity {
            drop(connections);
            return;
        }
        connections.push(connection);
    }
}

/// One checked-out connection for exactly one bounded operation. `finish` is
/// called only after every command in the operation succeeded; all error,
/// timeout and cancellation paths drop the owned connection, which shuts the
/// canonical driver down instead of recycling an abandoned queue.
struct CheckedOutConnection<'a> {
    pool: &'a IdlePool,
    connection: Option<MultiplexedConnection>,
    completed: bool,
}

impl<'a> CheckedOutConnection<'a> {
    fn new(pool: &'a IdlePool, connection: MultiplexedConnection) -> Self {
        Self { pool, connection: Some(connection), completed: false }
    }

    fn connection(&mut self) -> &mut MultiplexedConnection {
        self.connection.as_mut().expect("checked-out Redis connection is present")
    }

    fn finish(mut self) {
        self.completed = true;
    }
}

impl Drop for CheckedOutConnection<'_> {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        if self.completed {
            self.pool.put(connection);
        }
    }
}

/// Bounded Redis cache. A capacity-bounded idle pool holds owned canonical
/// `MultiplexedConnection`s, at most `max_inflight` of them; an in-flight
/// semaphore bounds concurrent requests, and each `bounded` operation's
/// deadline covers permit wait, checkout and all commands. A connection is
/// checked out exclusively, recycled only after the whole operation succeeds,
/// and dropped on error/timeout so its canonical driver cannot accumulate
/// abandoned commands. Reads use STRLEN then a capped GETRANGE so an oversized
/// response is never fully fetched.
pub struct RedisCache {
    client: ::redis::Client,
    idle: IdlePool,
    limits: RedisCacheLimits,
    inflight: Semaphore,
    contract: Option<RedisServerContract>,
}

impl RedisCache {
    fn new(url: &str, limits: RedisCacheLimits) -> Result<Self> {
        limits.validate()?;
        validate_redis_url(url)?;
        let client = ::redis::Client::open(url).map_err(|_| anyhow::anyhow!("invalid Redis cache URL"))?;
        Ok(Self {
            client,
            idle: IdlePool::new(limits.max_inflight),
            inflight: Semaphore::new(limits.max_inflight),
            limits,
            contract: None,
        })
    }

    /// Startup entry point for production. Validates URL policy, then proves a
    /// finite server maxmemory and an eviction policy. Any CONFIG/permission/
    /// parsing failure is fatal to Redis cache enablement (fail closed).
    pub async fn connect(url: &str, limits: RedisCacheLimits) -> Result<Self> {
        let mut cache = Self::new(url, limits)?;
        let contract = cache.read_server_contract().await?;
        cache.contract = Some(contract);
        Ok(cache)
    }

    /// The URL is secret-bearing and is never logged or included in errors.
    pub async fn connect_from_env(limits: RedisCacheLimits) -> Result<Self> {
        let url = std::env::var("ROOTYARD_CACHE_REDIS_URL")
            .context("ROOTYARD_CACHE_REDIS_URL is required for Redis cache")?;
        Self::connect(&url, limits).await
    }

    async fn bounded<T, F, Fut>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        tokio::time::timeout(self.limits.request_timeout, operation())
            .await
            .map_err(|_| anyhow::anyhow!("Redis cache request timeout"))?
    }

    /// Exclusive checkout: reuse an idle owned connection or create a canonical
    /// one. No pool lock is held while connecting or running commands.
    async fn checkout(&self) -> Result<CheckedOutConnection<'_>> {
        let connection = match self.idle.take() {
            Some(connection) => connection,
            None => self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| anyhow::anyhow!("Redis cache connection unavailable"))?,
        };
        Ok(CheckedOutConnection::new(&self.idle, connection))
    }

    async fn inspect_server_contract(&self, connection: &mut MultiplexedConnection) -> Result<RedisServerContract> {
        let maxmemory: Vec<String> = ::redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory")
            .query_async(&mut *connection)
            .await
            .map_err(|_| anyhow::anyhow!("Redis cache maxmemory inspection failed"))?;
        ensure!(maxmemory.len() == 2, "invalid Redis maxmemory response");
        let maxmemory_bytes: u64 =
            maxmemory[1].parse().map_err(|_| anyhow::anyhow!("invalid Redis maxmemory value"))?;
        ensure!(maxmemory_bytes > 0, "Redis cache instance must set a finite maxmemory");
        ensure!(
            maxmemory_bytes >= self.limits.max_value_bytes as u64,
            "Redis maxmemory is smaller than max_value_bytes"
        );
        let policy: Vec<String> = ::redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query_async(&mut *connection)
            .await
            .map_err(|_| anyhow::anyhow!("Redis cache eviction inspection failed"))?;
        ensure!(policy.len() == 2, "invalid Redis maxmemory-policy response");
        Ok(RedisServerContract { maxmemory_bytes, maxmemory_policy: eviction_policy(&policy[1])? })
    }

    async fn read_server_contract(&self) -> Result<RedisServerContract> {
        self.bounded(|| async {
            let _permit = self.inflight.acquire().await.map_err(|_| anyhow::anyhow!("Redis cache unavailable"))?;
            let mut connection = self.checkout().await?;
            let contract = self.inspect_server_contract(connection.connection()).await?;
            connection.finish();
            Ok(contract)
        })
        .await
    }

    /// Re-check the cached proof before cache mutations. A changed maxmemory or
    /// eviction policy fails closed until an explicit reconnect revalidates it.
    async fn verify_contract_before_mutation(&self, connection: &mut MultiplexedConnection) -> Result<()> {
        let expected = self.contract()?;
        let observed = self.inspect_server_contract(connection).await?;
        ensure!(observed == expected, "Redis cache server resource contract changed; reconnect required");
        Ok(())
    }

    fn contract(&self) -> Result<RedisServerContract> {
        self.contract.context("Redis cache server contract was not validated")
    }

    async fn get_async(&self, key: &CacheKey) -> Result<Option<CacheValue>> {
        // Prove the server resource contract on every operation so a cache
        // constructed by mistake via a non-connecting path cannot be used.
        let _contract = self.contract()?;
        self.bounded(|| async {
            let _permit = self.inflight.acquire().await.map_err(|_| anyhow::anyhow!("Redis cache unavailable"))?;
            let mut connection = self.checkout().await?;
            let length: u64 = ::redis::cmd("STRLEN")
                .arg(key.as_str())
                .query_async(connection.connection())
                .await
                .map_err(|_| anyhow::anyhow!("Redis cache request failed"))?;
            if length == 0 {
                connection.finish();
                return Ok(None);
            }
            ensure!(
                length <= self.limits.max_value_bytes as u64,
                "Redis cache value exceeds max_value_bytes before fetch"
            );
            let raw: Vec<u8> = ::redis::cmd("GETRANGE")
                .arg(key.as_str())
                .arg(0)
                .arg((self.limits.max_value_bytes - 1) as i64)
                .query_async(connection.connection())
                .await
                .map_err(|_| anyhow::anyhow!("Redis cache request failed"))?;
            let value = decode_bounded(key, &raw, length);
            connection.finish();
            Ok(value)
        })
        .await
    }

    async fn put_async(&self, key: &CacheKey, value: CacheValue, ttl: Option<Duration>) -> Result<()> {
        self.contract()?;
        ensure!(
            value.kind() == key.kind() && value.version() == key.version(),
            "cache value does not match key kind/version"
        );
        let ttl = self.limits.effective_ttl(ttl)?;
        let encoded = encode_bounded(&value, self.limits.max_value_bytes)?;
        let milliseconds = ttl.as_millis().max(1);
        ensure!(milliseconds <= u64::MAX as u128, "cache ttl too large");
        self.bounded(|| async {
            let _permit = self.inflight.acquire().await.map_err(|_| anyhow::anyhow!("Redis cache unavailable"))?;
            let mut connection = self.checkout().await?;
            self.verify_contract_before_mutation(connection.connection()).await?;
            ::redis::cmd("SET")
                .arg(key.as_str())
                .arg(encoded)
                .arg("PX")
                .arg(milliseconds as u64)
                .query_async::<()>(connection.connection())
                .await
                .map_err(|_| anyhow::anyhow!("Redis cache request failed"))?;
            connection.finish();
            Ok(())
        })
        .await
    }

    async fn delete_async(&self, key: &CacheKey) -> Result<()> {
        self.contract()?;
        self.bounded(|| async {
            let _permit = self.inflight.acquire().await.map_err(|_| anyhow::anyhow!("Redis cache unavailable"))?;
            let mut connection = self.checkout().await?;
            self.verify_contract_before_mutation(connection.connection()).await?;
            ::redis::cmd("DEL")
                .arg(key.as_str())
                .query_async::<i64>(connection.connection())
                .await
                .map_err(|_| anyhow::anyhow!("Redis cache request failed"))?;
            connection.finish();
            Ok(())
        })
        .await
    }
}

impl AdvisoryCache for RedisCache {
    fn get<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<Option<CacheValue>>> {
        Box::pin(self.get_async(key))
    }

    fn put<'a>(&'a self, key: &'a CacheKey, value: CacheValue, ttl: Option<Duration>) -> CacheTask<'a, Result<()>> {
        Box::pin(self.put_async(key, value, ttl))
    }

    fn delete<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<()>> {
        Box::pin(self.delete_async(key))
    }
}

impl fmt::Debug for RedisCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the URL: it may contain ACL credentials useful to an
        // attacker. Fixed endpoint description plus validated server bounds.
        formatter
            .debug_struct("RedisCache")
            .field("endpoint", &"<configured-redis>")
            .field("limits", &self.limits)
            .field("contract", &self.contract)
            .finish()
    }
}

/// Advisory Redis Pub/Sub wake adapter. It publishes only the fixed `v1`
/// payload and treats every frame as a hint to rescan PostgreSQL. A wrong
/// payload/channel disconnects; no value from Redis is executed or trusted.
pub struct RedisWake {
    client: ::redis::Client,
    channel: String,
    inflight: Semaphore,
}

impl RedisWake {
    /// Read the existing legacy wake settings when present. `ROOTYARD_REDIS_URL`
    /// enables ACL/TLS URLs; the older `ROOTYARD_REDIS_ADDRESS` remains a
    /// loopback-only plaintext compatibility path. `ROOTYARD_WAKE_CHANNEL`
    /// retains its existing default and validation.
    pub fn from_env() -> Result<Self> {
        let channel = std::env::var("ROOTYARD_WAKE_CHANNEL").unwrap_or_else(|_| "rootyard:outbox:v1".into());
        let url = match std::env::var("ROOTYARD_REDIS_URL") {
            Ok(url) => url,
            Err(_) => {
                let address = std::env::var("ROOTYARD_REDIS_ADDRESS")
                    .context("ROOTYARD_REDIS_URL or ROOTYARD_REDIS_ADDRESS is required for Redis wake")?;
                let address: SocketAddr =
                    address.parse().context("ROOTYARD_REDIS_ADDRESS must be a loopback socket address")?;
                ensure!(
                    address.ip().is_loopback() && address.port() != 0,
                    "ROOTYARD_REDIS_ADDRESS must be a nonzero loopback address"
                );
                format!("redis://{address}")
            }
        };
        Self::from_url(&url, channel)
    }

    pub fn from_url(url: &str, channel: String) -> Result<Self> {
        validate_redis_url(url)?;
        validate_wake_channel(&channel)?;
        let client = ::redis::Client::open(url).map_err(|_| anyhow::anyhow!("invalid Redis wake URL"))?;
        Ok(Self { client, channel, inflight: Semaphore::new(1) })
    }

    /// Each hint uses its own owned canonical multiplexed connection behind a
    /// bounded permit. A shared `ConnectionManager` kept its driver alive after
    /// a cancelled publish, so commands already written to the socket stayed
    /// queued for the next hint. Here every completion, error or timeout drop
    /// closes that driver (redis-rs aborts the pipeline task on last drop).
    async fn publish_hint(&self) -> Result<()> {
        let _permit = self.inflight.acquire().await.map_err(|_| anyhow::anyhow!("Redis wake unavailable"))?;
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| anyhow::anyhow!("Redis wake connection unavailable"))?;
        let receivers: i64 = ::redis::cmd("PUBLISH")
            .arg(&self.channel)
            .arg(WAKE_PAYLOAD)
            .query_async(&mut connection)
            .await
            .map_err(|_| anyhow::anyhow!("Redis wake publication failed"))?;
        ensure!(receivers >= 0, "invalid Redis wake publication acknowledgment");
        Ok(())
    }

    async fn listen(&self, signal: Arc<Notify>, stop: CancellationToken) {
        let mut unavailable = false;
        loop {
            let connect = async {
                let mut pubsub = self
                    .client
                    .get_async_pubsub()
                    .await
                    .map_err(|_| anyhow::anyhow!("Redis wake subscription unavailable"))?;
                pubsub.subscribe(&self.channel).await.map_err(|_| anyhow::anyhow!("Redis wake subscribe failed"))?;
                Ok::<_, anyhow::Error>(pubsub)
            };
            let connected = tokio::select! {biased;
                _=stop.cancelled()=>return,
                result=tokio::time::timeout(Duration::from_secs(1),connect)=>result,
            };
            if let Ok(Ok(mut pubsub)) = connected {
                unavailable = false;
                signal.notify_one(); // Subscribe/reconnect race is repaired by PG scan.
                let messages = pubsub.on_message();
                tokio::pin!(messages);
                loop {
                    let next = tokio::select! {biased;
                        _=stop.cancelled()=>return,
                        value=tokio::time::timeout(Duration::from_secs(60),messages.next())=>value,
                    };
                    let Ok(Some(message)) = next else {
                        break;
                    };
                    if message.get_channel_name() != self.channel.as_str() {
                        break;
                    }
                    if message.get_payload_bytes() != WAKE_PAYLOAD {
                        break;
                    }
                    signal.notify_one();
                }
            }
            if !unavailable {
                eprintln!("rootyard: advisory Redis subscription disconnected; PostgreSQL polling continues");
                unavailable = true;
            }
            tokio::select! { _=stop.cancelled()=>return, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
        }
    }
}

impl WakeTransport for RedisWake {
    fn publish(&self) -> Task<'_, Result<()>> {
        Box::pin(async move {
            tokio::time::timeout(Duration::from_secs(1), self.publish_hint())
                .await
                .context("advisory Redis wake timeout")?
        })
    }

    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()> {
        Box::pin(self.listen(signal, stop))
    }
}

impl fmt::Debug for RedisWake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisWake")
            .field("endpoint", &"<configured-redis>")
            .field("channel", &self.channel)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_wake::{AdvisoryCache, CacheKeyParts, CacheKind};
    use std::time::Instant;
    use uuid::Uuid;

    fn live_url() -> String {
        // Explicitly panic rather than skip: a missing fixture must never be
        // reported as successful real-Redis coverage.
        std::env::var("ROOTYARD_TEST_REDIS_URL")
            .expect("ROOTYARD_TEST_REDIS_URL is required for real Redis contract tests")
    }

    fn owned_destructive_fixture() {
        // Destructive commands are allowed only when the operator explicitly
        // attests that this URL names a disposable, test-owned server.
        let guard = std::env::var("ROOTYARD_TEST_REDIS_DESTRUCTIVE")
            .expect("ROOTYARD_TEST_REDIS_DESTRUCTIVE=owned-fixture is required before a destructive Redis command");
        assert_eq!(
            guard, "owned-fixture",
            "destructive Redis tests require ROOTYARD_TEST_REDIS_DESTRUCTIVE=owned-fixture"
        );
    }

    pub(super) fn live_redis_serial() -> &'static tokio::sync::Mutex<()> {
        static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn raw_connection(url: &str) -> ConnectionManager {
        ::redis::Client::open(url)
            .expect("dedicated real Redis URL must parse")
            .get_connection_manager()
            .await
            .expect("dedicated real Redis connection failed")
    }

    async fn current_maxmemory_policy(url: &str) -> String {
        let mut connection = raw_connection(url).await;
        let response: Vec<String> = ::redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query_async(&mut connection)
            .await
            .expect("dedicated real Redis must permit CONFIG GET maxmemory-policy");
        assert_eq!(response.len(), 2, "invalid CONFIG GET maxmemory-policy response");
        response[1].clone()
    }

    async fn set_maxmemory_policy(url: &str, policy: &str) -> Result<()> {
        let mut connection = ::redis::Client::open(url)
            .map_err(|_| anyhow::anyhow!("test Redis URL failed to parse"))?
            .get_connection_manager()
            .await
            .map_err(|_| anyhow::anyhow!("test Redis connection unavailable"))?;
        ::redis::cmd("CONFIG")
            .arg("SET")
            .arg("maxmemory-policy")
            .arg(policy)
            .query_async::<()>(&mut connection)
            .await
            .map_err(|_| anyhow::anyhow!("test Redis CONFIG SET maxmemory-policy failed"))?;
        Ok(())
    }

    struct PolicyRestore {
        url: String,
        policy: String,
        restored: bool,
    }

    impl PolicyRestore {
        fn new(url: String, policy: String) -> Self {
            Self { url, policy, restored: false }
        }

        async fn restore(&mut self) -> Result<()> {
            set_maxmemory_policy(&self.url, &self.policy).await?;
            self.restored = true;
            Ok(())
        }
    }

    impl Drop for PolicyRestore {
        fn drop(&mut self) {
            if self.restored {
                return;
            }
            let url = self.url.clone();
            let policy = self.policy.clone();
            // Best-effort RAII fallback for panic/cancellation paths. A small
            // standalone runtime keeps this independent of the test runtime.
            drop(
                std::thread::spawn(move || {
                    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                        return;
                    };
                    runtime.block_on(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(2), set_maxmemory_policy(&url, &policy)).await;
                    });
                })
                .join(),
            );
        }
    }

    fn test_key(kind: CacheKind, version: u64, discriminator: &str) -> CacheKey {
        CacheKey::new(CacheKeyParts {
            environment: "standalone",
            schema: 1,
            history_incarnation: Uuid::nil(),
            tenant: Uuid::from_u128(11),
            repo: Uuid::from_u128(22),
            kind,
            version,
            discriminator,
        })
        .unwrap()
    }

    #[test]
    fn url_policy_rejects_plaintext_remote_and_bad_channels() {
        assert!(validate_redis_url("redis://127.0.0.1:6379").is_ok());
        assert!(validate_redis_url("redis://[::1]:6379").is_ok());
        assert!(validate_redis_url("redis://localhost:6379").is_ok());
        assert!(validate_redis_url("redis://redis.internal:6379").is_err());
        assert!(validate_redis_url("http://127.0.0.1:6379").is_err());
        assert!(validate_redis_url("rediss://cache.internal:6379").is_ok());
        for channel in ["", "has space", "bad\r\n", &"x".repeat(129)] {
            assert!(validate_wake_channel(channel).is_err());
        }
        let error = RedisCache::new("redis://redis.internal:6379", RedisCacheLimits::default()).unwrap_err();
        assert!(!format!("{error}").contains("redis.internal"));
        let error = RedisCache::new("rediss://user:private-password@", RedisCacheLimits::default()).unwrap_err();
        assert!(!format!("{error}").contains("private-password"));
    }

    #[test]
    fn redis_url_rejects_tls_weakening_and_accepts_supported_sdk_syntax() {
        for accepted in [
            "redis://127.0.0.1:6379",
            "redis://[::1]:6379",
            "redis://localhost:6379/0",
            "redis://user:password@localhost:6379/0",
            "redis://:password@localhost:6379/0?protocol=resp3",
            "rediss://cache.internal:6379",
            "rediss://user:secret@cache.internal:6380/0",
            "rediss://user:secret@cache.internal:6380/0?protocol=resp2",
            "rediss://cache.internal:6379/?protocol=3",
        ] {
            assert!(validate_redis_url(accepted).is_ok(), "supported Redis URL rejected: {accepted}");
        }
        for rejected in [
            "rediss://cache.internal:6379/#insecure",
            "rediss://cache.internal:6379/0#insecure",
            "rediss://cache.internal:6379#insecure",
            "rediss://cache.internal:6379/#INSECURE",
            "rediss://cache.internal:6379?tls_verify=false",
            "rediss://cache.internal:6379?ssl_cert_reqs=none",
            "rediss://cache.internal:6379?insecure=true",
            "rediss://cache.internal:6379?danger_accept_invalid_certs=true",
            "rediss://cache.internal:6379?danger_accept_invalid_hostnames=true",
            "rediss://cache.internal:6379?verify=false",
            "rediss://cache.internal:6379/0?protocol=resp3&tls_verify=false",
            "rediss://cache.internal:6379/0?protocol=resp4",
            "redis://127.0.0.1:6379/#insecure",
        ] {
            assert!(validate_redis_url(rejected).is_err(), "TLS-weakening Redis URL accepted: {rejected}");
        }
        let error = RedisCache::new(
            "rediss://user:private-password@cache.internal:6379/#insecure",
            RedisCacheLimits::default(),
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(!text.contains("private-password"));
        assert!(!text.contains("cache.internal"));
    }

    #[test]
    fn eviction_policy_is_an_allowlist_with_no_noeviction() {
        assert_eq!(eviction_policy("allkeys-lru").unwrap(), "allkeys-lru");
        assert_eq!(eviction_policy("volatile-ttl").unwrap(), "volatile-ttl");
        assert!(eviction_policy("noeviction").is_err());
        assert!(eviction_policy("allkeys-private-data").is_err());
    }

    #[test]
    fn debug_never_prints_redis_credentials() {
        let cache =
            RedisCache::new("rediss://user:private-password@cache.internal:6379", RedisCacheLimits::default()).unwrap();
        let text = format!("{cache:?}");
        assert!(!text.contains("private-password"));
        assert!(!text.contains("user"));
        let wake =
            RedisWake::from_url("rediss://user:private-password@cache.internal:6379", "rootyard:outbox:v1".into())
                .unwrap();
        let text = format!("{wake:?}");
        assert!(!text.contains("private-password"));
        assert!(!text.contains("user"));
    }

    #[test]
    fn bounded_read_mismatch_is_a_miss_and_oversize_is_rejected_before_encode() {
        let key = test_key(CacheKind::TreeListing, 5, "bounded-unit");
        let value = CacheValue::new(CacheKind::TreeListing, 5, b"ok".to_vec());
        let encoded = value.encode();
        assert_eq!(decode_bounded(&key, &encoded, encoded.len() as u64), Some(value));
        assert_eq!(decode_bounded(&key, &encoded[..encoded.len() - 1], encoded.len() as u64), None);
        let mut corrupt = encoded.clone();
        corrupt[0] = b'X';
        assert_eq!(decode_bounded(&key, &corrupt, encoded.len() as u64), None);
        assert_eq!(decode_bounded(&key, &encoded, encoded.len() as u64 + 1), None);

        let oversized = CacheValue::new(CacheKind::TreeListing, 5, vec![0; 1024]);
        assert!(encode_bounded(&oversized, 64).is_err());
    }

    #[tokio::test]
    async fn bounded_deadline_covers_permit_wait_and_contract_is_required() {
        let cache = RedisCache::new(
            "redis://127.0.0.1:1",
            RedisCacheLimits {
                max_inflight: 1,
                request_timeout: Duration::from_millis(15),
                ..RedisCacheLimits::default()
            },
        )
        .unwrap();
        let held = cache.inflight.try_acquire().unwrap();
        let result: Result<()> = cache
            .bounded(|| async {
                let _permit = cache.inflight.acquire().await.map_err(|_| anyhow::anyhow!("closed"))?;
                Ok(())
            })
            .await;
        assert!(result.is_err(), "whole-operation deadline did not cover permit wait");
        drop(held);

        let key = test_key(CacheKind::TreeListing, 5, "unvalidated");
        assert!(cache.get(&key).await.is_err(), "cache operated without a validated server contract");
    }

    #[tokio::test]
    async fn closed_loopback_port_outage_is_bounded_without_process_signals() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback bind failed");
        let address = listener.local_addr().expect("loopback address unavailable");
        drop(listener);
        let url = format!("redis://{address}");
        let limits = RedisCacheLimits { request_timeout: Duration::from_millis(250), ..RedisCacheLimits::default() };
        let started = Instant::now();
        assert!(RedisCache::connect(&url, limits).await.is_err(), "closed loopback port must fail cache connect");
        assert!(started.elapsed() <= Duration::from_secs(3), "closed-port cache connect was not bounded");
        let wake = RedisWake::from_url(&url, "rootyard:test:closed-port".into()).expect("loopback URL is valid");
        let started = Instant::now();
        assert!(wake.publish().await.is_err(), "closed loopback port publish must fail as an advisory hint");
        assert!(started.elapsed() <= Duration::from_secs(3), "closed-port wake publish was not bounded");
    }

    #[tokio::test]
    #[ignore = "requires a dedicated real Redis via ROOTYARD_TEST_REDIS_URL"]
    async fn real_redis_cache_contract_round_trip_and_bounded_read() {
        let _serial = live_redis_serial().lock().await;
        let url = live_url();
        let limits = RedisCacheLimits { request_timeout: Duration::from_secs(2), ..RedisCacheLimits::default() };
        let cache = RedisCache::connect(&url, limits).await.unwrap();
        let key = test_key(CacheKind::TreeListing, 5, "contract");
        let value = CacheValue::new(CacheKind::TreeListing, 5, b"bounded".to_vec());
        cache.put(&key, value.clone(), Some(Duration::from_secs(30))).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), Some(value));
        cache.delete(&key).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), None);
        let oversized = CacheValue::new(CacheKind::TreeListing, 5, vec![0; limits.max_value_bytes + 1]);
        assert!(cache.put(&key, oversized, None).await.is_err());

        // Plant an oversized raw value outside the cache boundary. STRLEN must
        // reject it before GETRANGE can fetch the full body.
        let oversized_key = test_key(CacheKind::TreeListing, 5, "oversized-raw");
        let mut raw = ::redis::Client::open(url.as_str()).unwrap().get_connection_manager().await.unwrap();
        ::redis::cmd("SET")
            .arg(oversized_key.as_str())
            .arg(vec![0u8; limits.max_value_bytes + 1])
            .arg("PX")
            .arg(30_000u64)
            .query_async::<()>(&mut raw)
            .await
            .unwrap();
        assert!(cache.get(&oversized_key).await.is_err());
        ::redis::cmd("DEL").arg(oversized_key.as_str()).query_async::<i64>(&mut raw).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a dedicated real Redis via ROOTYARD_TEST_REDIS_URL"]
    async fn real_redis_wake_publishes_only_a_hint() {
        let _serial = live_redis_serial().lock().await;
        let url = live_url();
        let channel = format!("rootyard:test:_{}", Uuid::new_v4().simple());
        let wake = Arc::new(RedisWake::from_url(&url, channel).unwrap());
        let signal = Arc::new(Notify::new());
        let stop = CancellationToken::new();
        let subscriber = tokio::spawn({
            let wake = wake.clone();
            let signal = signal.clone();
            let stop = stop.clone();
            async move { wake.subscribe(signal, stop).await }
        });
        // The adapter emits one scan hint after a successful subscription.
        tokio::time::timeout(Duration::from_secs(3), signal.notified())
            .await
            .expect("Redis subscription did not become ready");
        wake.publish().await.expect("real Redis publish failed");
        tokio::time::timeout(Duration::from_secs(3), signal.notified())
            .await
            .expect("Redis wake hint was not observed");
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), subscriber)
            .await
            .expect("Redis wake subscriber did not cancel")
            .expect("Redis wake subscriber panicked");
    }

    #[tokio::test]
    #[ignore = "requires a dedicated real Redis via ROOTYARD_TEST_REDIS_URL"]
    async fn real_redis_flushall_is_authoritative_cache_miss() {
        let _serial = live_redis_serial().lock().await;
        let url = live_url();
        let limits = RedisCacheLimits { request_timeout: Duration::from_secs(2), ..RedisCacheLimits::default() };
        let cache = RedisCache::connect(&url, limits).await.expect("dedicated real Redis contract must validate");
        let key = test_key(CacheKind::TreeListing, 5, "flushall");
        let value = CacheValue::new(CacheKind::TreeListing, 5, b"before-flushall".to_vec());
        cache.put(&key, value.clone(), Some(Duration::from_secs(30))).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), Some(value));
        let mut raw = raw_connection(&url).await;
        owned_destructive_fixture();
        ::redis::cmd("FLUSHALL")
            .query_async::<()>(&mut raw)
            .await
            .expect("dedicated owned real Redis must permit FLUSHALL");
        assert_eq!(cache.get(&key).await.unwrap(), None, "FLUSHALL must surface as a miss, not stale cache data");
    }

    #[tokio::test]
    #[ignore = "requires a dedicated real Redis via ROOTYARD_TEST_REDIS_URL"]
    async fn real_redis_bad_acl_credentials_are_rejected_bounded_and_redacted() {
        let _serial = live_redis_serial().lock().await;
        let url = live_url();
        const BAD_USER: &str = "rootyard-invalid-acl-user";
        const BAD_PASSWORD: &str = "rootyard-invalid-acl-secret";
        let mut parsed =
            ::redis::parse_redis_url(&url).expect("ROOTYARD_TEST_REDIS_URL must be a redis:// or rediss:// URL");
        parsed.set_username(BAD_USER).expect("test URL username can be replaced");
        parsed.set_password(Some(BAD_PASSWORD)).expect("test URL password can be replaced");
        let bad_url = parsed.to_string();
        let limits = RedisCacheLimits { request_timeout: Duration::from_millis(500), ..RedisCacheLimits::default() };
        let cache = RedisCache::new(&bad_url, limits).expect("bad-credential URL is syntactically valid");
        let cache_debug = format!("{cache:?}");
        assert!(!cache_debug.contains(BAD_USER));
        assert!(!cache_debug.contains(BAD_PASSWORD));
        let started = Instant::now();
        let error =
            RedisCache::connect(&bad_url, limits).await.expect_err("wrong ACL credentials must reject cache connect");
        assert!(started.elapsed() <= Duration::from_secs(3), "wrong ACL rejection was not bounded");
        let display = format!("{error}");
        let debug = format!("{error:?}");
        let chain = format!("{error:#}");
        for text in [&display, &debug, &chain] {
            assert!(!text.contains(BAD_USER), "error leaked ACL username: {text}");
            assert!(!text.contains(BAD_PASSWORD), "error leaked ACL password: {text}");
            assert!(!text.contains("redis://") && !text.contains("rediss://"), "error leaked the Redis URL: {text}");
        }
        let wake = RedisWake::from_url(&bad_url, "rootyard:test:bad-acl".into()).expect("bad-credential URL is valid");
        let wake_debug = format!("{wake:?}");
        assert!(!wake_debug.contains(BAD_USER));
        assert!(!wake_debug.contains(BAD_PASSWORD));
    }

    #[tokio::test]
    #[ignore = "requires a dedicated real Redis via ROOTYARD_TEST_REDIS_URL"]
    async fn real_redis_noeviction_policy_fails_connect_closed_and_restores() {
        let _serial = live_redis_serial().lock().await;
        let url = live_url();
        let limits = RedisCacheLimits { request_timeout: Duration::from_secs(2), ..RedisCacheLimits::default() };
        let original = current_maxmemory_policy(&url).await;
        assert!(eviction_policy(&original).is_ok(), "dedicated fixture must start with an accepted eviction policy");
        let mut restore = PolicyRestore::new(url.clone(), original.clone());
        owned_destructive_fixture();
        set_maxmemory_policy(&url, "noeviction")
            .await
            .expect("dedicated owned real Redis must permit CONFIG SET maxmemory-policy");
        let result = RedisCache::connect(&url, limits).await;
        let error = match &result {
            Ok(_) => None,
            Err(error) => Some(format!("{error:#}")),
        };
        restore.restore().await.expect("RAII maxmemory-policy restore failed");
        assert!(result.is_err(), "noeviction must fail cache connect closed");
        assert!(
            error.as_deref().is_some_and(|text| text.contains("noeviction")),
            "unexpected noeviction connect error: {error:?}"
        );
        assert_eq!(current_maxmemory_policy(&url).await, original, "original maxmemory-policy was not restored");
        RedisCache::connect(&url, limits).await.expect("cache must reconnect after policy restore");
    }
}

#[cfg(test)]
#[path = "redis_cancel_tests.rs"]
mod cancel_tests;
