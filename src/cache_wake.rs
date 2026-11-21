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
use anyhow::Result;

pub const GENERIC_WAKE_CHANNEL_DEFAULT: &str = "rootyard:outbox:v1";

/// Resolve the generic outbox wake channel with the compatibility rule used by
/// the existing generic Redis adapters: a missing or legacy non-Unicode value
/// selects the historical default, while a present Unicode value must pass the
/// bounded channel validator. Centralizing it keeps the A4 alias check and the
/// generic adapters on exactly the same namespace.
pub fn generic_wake_channel_from_env() -> Result<String> {
    generic_wake_channel_from_result(std::env::var("ROOTYARD_WAKE_CHANNEL"))
}

fn generic_wake_channel_from_result(raw: std::result::Result<String, std::env::VarError>) -> Result<String> {
    match raw {
        Ok(channel) => {
            types::validate_wake_channel(&channel)?;
            Ok(channel)
        }
        Err(std::env::VarError::NotPresent | std::env::VarError::NotUnicode(_)) => {
            Ok(GENERIC_WAKE_CHANNEL_DEFAULT.to_owned())
        }
    }
}

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

#[cfg(test)]
mod wake_channel_tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn generic_channel_preserves_the_existing_missing_and_non_unicode_default() {
        assert_eq!(
            generic_wake_channel_from_result(Err(std::env::VarError::NotPresent)).unwrap(),
            GENERIC_WAKE_CHANNEL_DEFAULT
        );
        assert_eq!(
            generic_wake_channel_from_result(Err(std::env::VarError::NotUnicode(OsString::from("private")))).unwrap(),
            GENERIC_WAKE_CHANNEL_DEFAULT
        );
        assert_eq!(
            generic_wake_channel_from_result(Ok("rootyard:outbox_1-v1".to_owned())).unwrap(),
            "rootyard:outbox_1-v1"
        );
        assert!(generic_wake_channel_from_result(Ok(String::new())).is_err());
        assert!(generic_wake_channel_from_result(Ok("has space".to_owned())).is_err());
    }
}
