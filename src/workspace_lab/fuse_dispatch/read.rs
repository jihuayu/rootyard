//! Lazy lower-layer reads handed from the per-mount actor to the global pool.
//!
//! A deferred read owns its reply and its queue [`Permit`], so it travels as one
//! unit into the read pool and sends exactly one reply. Shutdown drains every
//! read whose reply is still in its slot; a read already doing I/O re-checks
//! the shutdown flag and replies `EIO` instead of a late success.
use super::super::inner_ops::ReadPlan;
use super::*;

/// A lazy read whose reply and budget charge travel to the read pool together.
pub(super) struct DeferredRead {
    relative: PathBuf,
    source: Entry,
    lazy: Arc<dyn LazySource>,
    offset: i64,
    size: u32,
    reply: Option<ReplyData>,
    /// RAII queue budget for the read reply; dropped when the reply is sent.
    _permit: Permit,
    shared: Arc<Shared>,
}

impl DeferredRead {
    fn run(mut self) {
        let reply = self.reply.take().expect("deferred read replies exactly once");
        if self.shared.is_shutdown() {
            reply.error(libc::EIO);
            return;
        }
        let result = (|| {
            let file = open_lower(Some(self.lazy.as_ref()), &self.relative, &self.source)?;
            read_at(&file, self.offset, self.size)
        })();
        // The worker takes the reply out of the shared slot before I/O, so a
        // shutdown drain cannot answer this read. Re-check the flag instead of
        // returning a success after the mount has closed the queue.
        let shutdown = self.shared.is_shutdown();
        match result {
            Ok(_) if shutdown => reply.error(libc::EIO),
            Ok(data) => reply.data(&data),
            Err(_) if shutdown => reply.error(libc::EIO),
            Err(error) => reply.error(Overlay::err(error)),
        }
    }

    pub(super) fn reject(mut self, errno: i32) {
        if let Some(reply) = self.reply.take() {
            reply.error(errno);
        }
    }
}

impl Actor {
    pub(super) fn read(&mut self, ino: u64, offset: i64, size: u32, reply: ReplyData, permit: Permit) {
        match self.overlay.read_plan(ino) {
            Err(error) => reply.error(Overlay::err(error)),
            Ok(ReadPlan::Local(path)) => match self.overlay.read_local(&path, offset, size) {
                Ok(data) => reply.data(&data),
                Err(error) => reply.error(Overlay::err(error)),
            },
            Ok(ReadPlan::Lazy { relative, source, lazy }) => {
                self.submit_deferred(DeferredRead {
                    relative,
                    source,
                    lazy,
                    offset,
                    size,
                    reply: Some(reply),
                    _permit: permit,
                    shared: self.shared.clone(),
                });
            }
        }
    }
}

impl Actor {
    /// Hand a lazy read to the global pool. If the pool is saturated the reply is
    /// `EAGAIN`; the read is never executed inline on the actor.
    fn submit_deferred(&self, deferred: DeferredRead) {
        let slot = Arc::new(Mutex::new(Some(deferred)));
        let request_id = self.shared.register_deferred(slot.clone());
        let job_slot = slot.clone();
        let shared = self.shared.clone();
        let job: ReadJob = Box::new(move || {
            if let Some(deferred) = job_slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.run();
            }
            shared.complete_deferred(request_id);
        });
        if let Err(job) = self.pool.execute(job) {
            drop(job);
            self.shared.complete_deferred(request_id);
            if let Some(deferred) = slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                deferred.reject(libc::EAGAIN);
            }
        }
    }
}
