//! Standalone bounded Memory adapter. Eviction, expiry and flush are advisory
//! only; they never propagate a durable mutation.
use super::{AdvisoryCache, CacheKey, CacheLimits, CacheTask, CacheValue};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheStats {
    pub entries: usize,
    pub bytes: usize,
    pub order_records: usize,
}

struct Entry {
    value: CacheValue,
    expires: Instant,
    sequence: u64,
    size: usize,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    order: BTreeMap<u64, String>,
    bytes: usize,
    sequence: u64,
}

/// Bounded entry-count, byte-count and TTL cache. The lock is never held across
/// an await; every operation is a short in-process critical section.
pub struct MemoryCache {
    limits: CacheLimits,
    inner: Mutex<Inner>,
}

impl MemoryCache {
    pub fn new(limits: CacheLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self { limits, inner: Mutex::new(Inner::default()) })
    }

    /// Explicit startup-config helper. Production consumers are not wired yet;
    /// calling this does not enable caching or change authority.
    pub fn from_env() -> Result<Self> {
        Self::new(CacheLimits::from_env()?)
    }

    pub fn limits(&self) -> CacheLimits {
        self.limits
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        CacheStats { entries: inner.entries.len(), bytes: inner.bytes, order_records: inner.order.len() }
    }

    fn get_sync(&self, key: &CacheKey) -> Option<CacheValue> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        let expired = inner.entries.get(key.as_str()).is_some_and(|entry| entry.expires <= now);
        if expired {
            if let Some(entry) = inner.entries.remove(key.as_str()) {
                inner.bytes = inner.bytes.saturating_sub(entry.size);
                inner.order.remove(&entry.sequence);
            }
            return None;
        }
        inner.entries.get(key.as_str()).map(|entry| entry.value.clone())
    }

    fn put_sync(&self, key: &CacheKey, value: CacheValue, ttl: Option<Duration>) -> Result<()> {
        ensure!(
            value.kind() == key.kind() && value.version() == key.version(),
            "cache value does not match key kind/version"
        );
        let ttl = self.limits.effective_ttl(ttl)?;
        let encoded = value.encoded_len();
        ensure!(encoded <= self.limits.max_value_bytes, "cache value exceeds max_value_bytes");
        let size = key.len().saturating_add(encoded);
        ensure!(size <= self.limits.max_bytes, "cache entry exceeds max_bytes");
        let expires = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);
        let mut inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(old) = inner.entries.remove(key.as_str()) {
            inner.bytes = inner.bytes.saturating_sub(old.size);
            inner.order.remove(&old.sequence);
        }
        // Evict oldest inserted entries, skipping stale order records. Expired
        // entries are also naturally removed here when a later insert needs room.
        while inner.entries.len() >= self.limits.max_entries || inner.bytes.saturating_add(size) > self.limits.max_bytes
        {
            let Some((sequence, candidate)) = inner.order.pop_first() else {
                break;
            };
            if inner.entries.get(&candidate).is_some_and(|entry| entry.sequence == sequence)
                && let Some(removed) = inner.entries.remove(&candidate)
            {
                inner.bytes = inner.bytes.saturating_sub(removed.size);
            }
        }
        inner.sequence = inner.sequence.wrapping_add(1);
        let sequence = inner.sequence;
        inner.order.insert(sequence, key.as_str().to_owned());
        inner.bytes = inner.bytes.saturating_add(size);
        inner.entries.insert(key.as_str().to_owned(), Entry { value, expires, sequence, size });
        Ok(())
    }

    fn delete_sync(&self, key: &CacheKey) {
        let mut inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(entry) = inner.entries.remove(key.as_str()) {
            inner.bytes = inner.bytes.saturating_sub(entry.size);
            inner.order.remove(&entry.sequence);
        }
    }
}

impl AdvisoryCache for MemoryCache {
    fn get<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<Option<CacheValue>>> {
        Box::pin(async move { Ok(self.get_sync(key)) })
    }

    fn put<'a>(&'a self, key: &'a CacheKey, value: CacheValue, ttl: Option<Duration>) -> CacheTask<'a, Result<()>> {
        Box::pin(async move { self.put_sync(key, value, ttl) })
    }

    fn delete<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<()>> {
        Box::pin(async move {
            self.delete_sync(key);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache_wake::CacheKeyParts, cache_wake::CacheKind};
    use uuid::Uuid;

    fn key(kind: CacheKind, version: u64, name: &str) -> CacheKey {
        CacheKey::new(CacheKeyParts {
            environment: "standalone",
            schema: 1,
            history_incarnation: Uuid::nil(),
            tenant: Uuid::from_u128(1),
            repo: Uuid::from_u128(2),
            kind,
            version,
            discriminator: name,
        })
        .unwrap()
    }

    fn limits() -> CacheLimits {
        CacheLimits {
            max_entries: 4,
            max_bytes: 4096,
            max_value_bytes: 512,
            default_ttl: Duration::from_secs(5),
            max_ttl: Duration::from_secs(10),
            ..CacheLimits::default()
        }
    }

    #[tokio::test]
    async fn round_trip_and_typed_validation() {
        let cache = MemoryCache::new(limits()).unwrap();
        let key = key(CacheKind::DiffView, 3, "repo:oid");
        let value = CacheValue::new(CacheKind::DiffView, 3, b"diff".to_vec());
        cache.put(&key, value.clone(), None).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), Some(value));
        let wrong = CacheValue::new(CacheKind::TreeListing, 3, b"diff".to_vec());
        assert!(cache.put(&key, wrong, None).await.is_err());
        cache.delete(&key).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn entry_and_byte_budgets_are_enforced() {
        let cache =
            MemoryCache::new(CacheLimits { max_entries: 2, max_bytes: 512, max_value_bytes: 128, ..limits() }).unwrap();
        let first = key(CacheKind::IssueView, 1, "first");
        let second = key(CacheKind::IssueView, 1, "second");
        let third = key(CacheKind::IssueView, 1, "third");
        let value = || CacheValue::new(CacheKind::IssueView, 1, vec![b'x'; 32]);
        cache.put(&first, value(), None).await.unwrap();
        cache.put(&second, value(), None).await.unwrap();
        assert_eq!(cache.stats().entries, 2);
        cache.put(&third, value(), None).await.unwrap();
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.get(&first).await.unwrap(), None);
        assert!(cache.get(&second).await.unwrap().is_some());
        assert!(cache.get(&third).await.unwrap().is_some());
        assert!(cache.stats().bytes <= 512);
        assert!(cache.stats().order_records <= 2);

        let oversized = CacheValue::new(CacheKind::IssueView, 1, vec![b'x'; 200]);
        assert!(cache.put(&first, oversized, None).await.is_err());
        let over_ttl = Some(Duration::from_secs(11));
        assert!(cache.put(&first, value(), over_ttl).await.is_err());
    }

    #[tokio::test]
    async fn ttl_expiry_is_a_miss() {
        let cache = MemoryCache::new(CacheLimits {
            default_ttl: Duration::from_millis(10),
            max_ttl: Duration::from_millis(50),
            ..limits()
        })
        .unwrap();
        let key = key(CacheKind::QueryNegative, 1, "query");
        cache.put(&key, CacheValue::new(CacheKind::QueryNegative, 1, b"negative".to_vec()), None).await.unwrap();
        assert!(cache.get(&key).await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(cache.get(&key).await.unwrap().is_none());
        assert_eq!(cache.stats().bytes, 0);
        assert_eq!(cache.stats().order_records, 0);
    }

    #[tokio::test]
    async fn metadata_is_bounded_under_replace_delete_and_expiry() {
        let cache = MemoryCache::new(CacheLimits {
            max_entries: 4,
            max_bytes: 1024 * 1024,
            max_value_bytes: 256,
            default_ttl: Duration::from_millis(10),
            max_ttl: Duration::from_millis(20),
            ..limits()
        })
        .unwrap();
        let value = || CacheValue::new(CacheKind::RouteDirectory, 1, b"route".to_vec());
        let stable = key(CacheKind::RouteDirectory, 1, "stable");
        for _ in 0..5000 {
            cache.put(&stable, value(), None).await.unwrap();
        }
        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert!(stats.order_records <= 4, "order metadata grew to {}", stats.order_records);

        for _ in 0..1000 {
            cache.put(&stable, value(), None).await.unwrap();
            cache.delete(&stable).await.unwrap();
        }
        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.order_records, 0);

        for index in 0..100 {
            let key = key(CacheKind::RouteDirectory, 1, &format!("expire-{index}"));
            cache.put(&key, value(), None).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(35)).await;
        for index in 0..100 {
            let key = key(CacheKind::RouteDirectory, 1, &format!("expire-{index}"));
            assert!(cache.get(&key).await.unwrap().is_none());
        }
        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.order_records, 0);
    }
}
