//! Dedicated maintenance concurrency, scratch, and rewrite byte bulkhead (#162 / #176 / #177).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::CompactionError;

/// Bounded maintenance resource limits completely isolated from serving Git concurrency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionBudgetConfig {
    pub max_concurrent_jobs: usize,
    pub max_concurrent_git_processes: usize,
    pub max_scratch_bytes: u64,
    pub max_rewrite_bytes_per_run: u64,
    pub max_packs_per_batch: usize,
}

impl Default for CompactionBudgetConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 4,
            max_concurrent_git_processes: 2,
            max_scratch_bytes: 256 * 1024 * 1024,
            max_rewrite_bytes_per_run: 64 * 1024 * 1024,
            max_packs_per_batch: 8,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactionBudgetMetricsSnapshot {
    pub active_jobs: u64,
    pub active_git_processes: u64,
    pub reserved_scratch_bytes: u64,
    pub total_jobs_admitted: u64,
    pub total_rewrite_bytes_reserved: u64,
    pub budget_rejections: u64,
}

#[derive(Debug, Default)]
struct BudgetCounters {
    active_jobs: AtomicU64,
    active_git: AtomicU64,
    reserved_scratch: AtomicU64,
    total_admitted: AtomicU64,
    total_rewrite: AtomicU64,
    rejections: AtomicU64,
}

/// Dedicated maintenance bulkhead isolated from online serving Git semaphores.
#[derive(Clone, Debug)]
pub struct CompactionResourceBudget {
    cfg: CompactionBudgetConfig,
    job_sem: Arc<Semaphore>,
    git_sem: Arc<Semaphore>,
    counters: Arc<BudgetCounters>,
}

impl CompactionResourceBudget {
    pub fn new(cfg: CompactionBudgetConfig) -> Result<Self, CompactionError> {
        if cfg.max_concurrent_jobs == 0
            || cfg.max_concurrent_git_processes == 0
            || cfg.max_scratch_bytes == 0
            || cfg.max_rewrite_bytes_per_run == 0
            || cfg.max_packs_per_batch < 2
        {
            return Err(CompactionError::InvalidInput("compaction budget bounds must be positive".into()));
        }
        Ok(Self {
            job_sem: Arc::new(Semaphore::new(cfg.max_concurrent_jobs)),
            git_sem: Arc::new(Semaphore::new(cfg.max_concurrent_git_processes)),
            cfg,
            counters: Arc::new(BudgetCounters::default()),
        })
    }

    pub fn config(&self) -> &CompactionBudgetConfig {
        &self.cfg
    }

    pub async fn reserve_job(
        &self,
        pack_count: usize,
        rewrite_bytes: u64,
        scratch_bytes: u64,
        deadline: Instant,
    ) -> Result<CompactionJobPermit, CompactionError> {
        if pack_count > self.cfg.max_packs_per_batch || rewrite_bytes > self.cfg.max_rewrite_bytes_per_run {
            self.counters.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(CompactionError::BudgetExceeded(format!(
                "batch packs={pack_count} rewrite_bytes={rewrite_bytes} exceeds cap"
            )));
        }
        let scratch_need = scratch_bytes.max(1);
        if scratch_need > self.cfg.max_scratch_bytes {
            self.counters.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(CompactionError::BudgetExceeded(format!(
                "job scratch_bytes={scratch_need} exceeds max_scratch_bytes={}",
                self.cfg.max_scratch_bytes
            )));
        }
        let permit = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Arc::clone(&self.job_sem).acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(CompactionError::BudgetExceeded("compaction job semaphore closed".into())),
            Err(_) => {
                self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(CompactionError::DeadlineExceeded);
            }
        };
        let mut cur = self.counters.reserved_scratch.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_add(scratch_need);
            if next > self.cfg.max_scratch_bytes {
                self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(CompactionError::BudgetExceeded("compaction scratch byte ceiling reached".into()));
            }
            match self.counters.reserved_scratch.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        self.counters.active_jobs.fetch_add(1, Ordering::Relaxed);
        self.counters.total_admitted.fetch_add(1, Ordering::Relaxed);
        self.counters.total_rewrite.fetch_add(rewrite_bytes, Ordering::Relaxed);
        Ok(CompactionJobPermit { _job_permit: permit, reserved_scratch: scratch_need, budget: self.clone() })
    }

    pub async fn acquire_git_slot(&self, deadline: Instant) -> Result<CompactionGitPermit, CompactionError> {
        let permit = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Arc::clone(&self.git_sem).acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(CompactionError::BudgetExceeded("compaction git semaphore closed".into())),
            Err(_) => {
                self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(CompactionError::DeadlineExceeded);
            }
        };
        self.counters.active_git.fetch_add(1, Ordering::Relaxed);
        Ok(CompactionGitPermit { _permit: permit, counters: Arc::clone(&self.counters) })
    }

    pub fn metrics(&self) -> CompactionBudgetMetricsSnapshot {
        CompactionBudgetMetricsSnapshot {
            active_jobs: self.counters.active_jobs.load(Ordering::Relaxed),
            active_git_processes: self.counters.active_git.load(Ordering::Relaxed),
            reserved_scratch_bytes: self.counters.reserved_scratch.load(Ordering::Relaxed),
            total_jobs_admitted: self.counters.total_jobs_admitted_raw(),
            total_rewrite_bytes_reserved: self.counters.total_rewrite.load(Ordering::Relaxed),
            budget_rejections: self.counters.rejections.load(Ordering::Relaxed),
        }
    }
}

impl BudgetCounters {
    fn total_jobs_admitted_raw(&self) -> u64 {
        self.total_admitted.load(Ordering::Relaxed)
    }
}

pub struct CompactionJobPermit {
    _job_permit: OwnedSemaphorePermit,
    reserved_scratch: u64,
    budget: CompactionResourceBudget,
}

impl Drop for CompactionJobPermit {
    fn drop(&mut self) {
        self.budget.counters.active_jobs.fetch_sub(1, Ordering::Relaxed);
        self.budget.counters.reserved_scratch.fetch_sub(self.reserved_scratch, Ordering::Relaxed);
    }
}

pub struct CompactionGitPermit {
    _permit: OwnedSemaphorePermit,
    counters: Arc<BudgetCounters>,
}

impl Drop for CompactionGitPermit {
    fn drop(&mut self) {
        self.counters.active_git.fetch_sub(1, Ordering::Relaxed);
    }
}
