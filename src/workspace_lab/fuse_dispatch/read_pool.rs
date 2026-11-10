//! Global bounded pool for lazy lower-layer hydration/pread.
//!
//! The per-mount actor never performs a lazy read inline: one unreachable blob
//! must not stall a mount's freeze drain or its queue. Saturation is reported to
//! the caller, which replies `EAGAIN` instead of blocking.
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Condvar, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) const READ_WORKERS: usize = 4;
pub(super) const READ_JOBS: usize = 256;

pub(super) type ReadJob = Box<dyn FnOnce() + Send + 'static>;

pub(super) struct ReadPool {
    queue: Mutex<VecDeque<ReadJob>>,
    ready: Condvar,
    capacity: usize,
    closed: AtomicBool,
}

impl ReadPool {
    fn new(workers: usize, capacity: usize) -> io::Result<Arc<Self>> {
        let pool = Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            capacity,
            closed: AtomicBool::new(false),
        });
        for index in 0..workers {
            let worker = pool.clone();
            let result =
                std::thread::Builder::new().name(format!("rootyard-fuse-read-{index}")).spawn(move || worker.run());
            if let Err(error) = result {
                pool.close();
                return Err(error);
            }
        }
        Ok(pool)
    }

    pub(super) fn execute(&self, job: ReadJob) -> Result<(), ReadJob> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if self.closed.load(Ordering::Acquire) || queue.len() >= self.capacity {
            return Err(job);
        }
        queue.push_back(job);
        drop(queue);
        self.ready.notify_one();
        Ok(())
    }

    fn run(&self) {
        loop {
            let job = {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                while queue.is_empty() && !self.closed.load(Ordering::Acquire) {
                    queue = self.ready.wait(queue).unwrap_or_else(PoisonError::into_inner);
                }
                queue.pop_front()
            };
            match job {
                Some(job) => job(),
                None => return,
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

/// Process-wide pool used by every mount. Initialization is once per process;
/// a failed spawn is remembered so a broken helper cannot silently fall back to
/// inline reads on the actor.
pub(super) fn global() -> io::Result<&'static ReadPool> {
    static POOL: OnceLock<Result<Arc<ReadPool>, String>> = OnceLock::new();
    POOL.get_or_init(|| ReadPool::new(READ_WORKERS, READ_JOBS).map_err(|e| e.to_string()))
        .as_ref()
        .map(|pool| pool.as_ref())
        .map_err(|error| io::Error::other(error.clone()))
}
