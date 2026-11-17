//! Bounded, typed advisory cache/wake boundary.
//!
//! Nothing in this module is an authority. Cache misses, flushes, Redis
//! outages, evictions, duplicate warmups and lost wake hints may only change
//! latency or cause an origin read. They must never modify refs, tasks,
//! authentication/authorization, roots, holds, hard quotas or durable
//! PostgreSQL/RefStore state. Redis is independently enableable and does not
//! require Raft.
//!
//! This module pairs the bounded advisory backends (`memory`, optional `redis`),
//! origin protection (`origin`), and runtime fallback orchestration (`serving`).
//! Dispatch continues to use local `Notify` and an optional mature `RedisWake`.
//! Redis cache/wake compilation is gated by `state-redis` and uses the mature
//! `redis` async client without hand-written RESP, TCP or TLS.
pub mod breaker;
pub mod memory;
pub mod origin;
#[cfg(feature = "state-redis")]
pub mod redis;
pub mod replica_cache;
pub mod serving;
pub mod types;

pub use memory::{CacheStats, MemoryCache};
pub use origin::{OriginError, OriginGuard, SingleFlight, WarmupOutcome};
#[cfg(feature = "state-redis")]
pub use redis::{RedisCache, RedisWake};
pub use serving::{CacheBackendKind, CacheOutcome, ServingCache, ServingStats};
#[cfg(feature = "state-redis")]
pub(crate) use types::number;
pub use types::{
    AdvisoryCache, CacheKey, CacheKeyParts, CacheKind, CacheLimits, CacheTask, CacheValue, WAKE_PAYLOAD,
    validate_scope_token, validate_wake_channel,
};
