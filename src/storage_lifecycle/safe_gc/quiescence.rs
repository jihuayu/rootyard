//! Live active-reader & view-lease quiescence registry and watermark proof (#122).
//!
//! Reader quiescence is never a hardcoded constant flag: every retirement and
//! destructive deletion proof must observe zero active pre-cutover or pack-pinning
//! reader leases and a monotonic drain watermark at or above `retired_at_generation`
//! (plus an active PostgreSQL exclusive reader barrier epoch on `SingleNodePg`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    SafeGcError,
    model::{MAX_PACKS_PER_CLOSURE, validate_bounded_name},
};

pub const MAX_ACTIVE_READER_LEASES: usize = 8_192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveReaderLease {
    pub lease_id: Uuid,
    pub reader_label: String,
    pub pinned_generation: u64,
    pub pinned_pack_ids: Vec<Uuid>,
    pub acquired_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderQuiescenceObservation {
    pub observed_seq: u64,
    pub retired_at_generation: u64,
    pub min_active_reader_generation: u64,
    pub active_blocking_readers: usize,
    pub drain_watermark_generation: u64,
    pub pg_exclusive_reader_barrier_epoch: Option<u64>,
}

impl ReaderQuiescenceObservation {
    pub fn is_quiesced(&self, require_pg_barrier: bool) -> bool {
        self.verify_quiesced(require_pg_barrier).is_ok()
    }

    pub fn verify_quiesced(&self, require_pg_barrier: bool) -> Result<(), SafeGcError> {
        if self.observed_seq == 0 || self.retired_at_generation == 0 {
            return Err(SafeGcError::ReaderQuiescenceUnverified(
                "reader quiescence observation lacks sequence or retirement generation",
            ));
        }
        if self.active_blocking_readers > 0 {
            return Err(SafeGcError::ReaderQuiescenceUnverified(
                "active pre-cutover or pack-pinning reader leases still open",
            ));
        }
        if self.min_active_reader_generation < self.retired_at_generation {
            return Err(SafeGcError::ReaderQuiescenceUnverified(
                "active reader pinned to pre-retirement membership generation",
            ));
        }
        if self.drain_watermark_generation < self.retired_at_generation {
            return Err(SafeGcError::ReaderQuiescenceUnverified(
                "reader drain watermark has not reached retirement generation",
            ));
        }
        if require_pg_barrier && self.pg_exclusive_reader_barrier_epoch.unwrap_or(0) == 0 {
            return Err(SafeGcError::ReaderQuiescenceUnverified(
                "SingleNodePg requires a non-zero PostgreSQL exclusive reader barrier epoch",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(b"reader-quiescence-v1|");
        h.update(self.observed_seq.to_be_bytes());
        h.update(self.retired_at_generation.to_be_bytes());
        h.update(self.min_active_reader_generation.to_be_bytes());
        h.update((self.active_blocking_readers as u64).to_be_bytes());
        h.update(self.drain_watermark_generation.to_be_bytes());
        match self.pg_exclusive_reader_barrier_epoch {
            Some(epoch) => {
                h.update([1]);
                h.update(epoch.to_be_bytes());
            }
            None => h.update([0]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderLeaseRegistry {
    pub next_reader_seq: u64,
    pub completed_drain_generation: u64,
    pub pg_exclusive_barrier_epoch: Option<u64>,
    pub active_leases: BTreeMap<Uuid, ActiveReaderLease>,
}

impl Default for ReaderLeaseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderLeaseRegistry {
    pub fn new() -> Self {
        Self {
            next_reader_seq: 1,
            completed_drain_generation: 1,
            pg_exclusive_barrier_epoch: None,
            active_leases: BTreeMap::new(),
        }
    }

    pub fn set_pg_exclusive_barrier_epoch(&mut self, epoch: Option<u64>) {
        self.pg_exclusive_barrier_epoch = epoch;
    }

    pub fn acquire_lease(
        &mut self,
        reader_label: &str,
        pinned_generation: u64,
        pinned_pack_ids: Vec<Uuid>,
    ) -> Result<ActiveReaderLease, SafeGcError> {
        validate_bounded_name("reader_label", reader_label)?;
        if pinned_generation == 0 || pinned_pack_ids.len() > MAX_PACKS_PER_CLOSURE {
            return Err(SafeGcError::InvalidInput("invalid reader lease generation or pack count".into()));
        }
        if self.active_leases.len() >= MAX_ACTIVE_READER_LEASES {
            return Err(SafeGcError::InvalidInput("active reader lease table full".into()));
        }
        let seq = self.next_reader_seq.max(1);
        self.next_reader_seq =
            seq.checked_add(1).ok_or_else(|| SafeGcError::InvalidInput("reader seq overflow".into()))?;
        let lease_id = Uuid::new_v4();
        let lease = ActiveReaderLease {
            lease_id,
            reader_label: reader_label.to_owned(),
            pinned_generation,
            pinned_pack_ids,
            acquired_seq: seq,
        };
        self.active_leases.insert(lease_id, lease.clone());
        Ok(lease)
    }

    pub fn release_lease(&mut self, lease_id: Uuid, current_generation: u64) -> Result<bool, SafeGcError> {
        let existed = self.active_leases.remove(&lease_id).is_some();
        self.refresh_drain_watermark(current_generation);
        Ok(existed)
    }

    pub fn pinned_pack_ids(&self) -> BTreeSet<Uuid> {
        self.active_leases.values().flat_map(|l| l.pinned_pack_ids.iter().copied()).collect()
    }

    pub fn blocking_readers_for_packs(&self, pack_ids: &[Uuid], retired_at_generation: u64) -> usize {
        let target_set: BTreeSet<Uuid> = pack_ids.iter().copied().collect();
        self.active_leases
            .values()
            .filter(|l| {
                l.pinned_generation < retired_at_generation
                    || l.pinned_pack_ids.iter().any(|id| target_set.contains(id))
            })
            .count()
    }

    pub fn refresh_drain_watermark(&mut self, current_generation: u64) {
        let min_gen = self.active_leases.values().map(|l| l.pinned_generation).min().unwrap_or(current_generation);
        if min_gen > self.completed_drain_generation {
            self.completed_drain_generation = min_gen;
        }
    }

    pub fn observe_for_retirement(
        &mut self,
        retired_pack_ids: &[Uuid],
        retired_at_generation: u64,
        current_generation: u64,
    ) -> Result<ReaderQuiescenceObservation, SafeGcError> {
        self.refresh_drain_watermark(current_generation);
        let seq = self.next_reader_seq.max(1);
        self.next_reader_seq =
            seq.checked_add(1).ok_or_else(|| SafeGcError::InvalidInput("reader seq overflow".into()))?;
        let min_active = self.active_leases.values().map(|l| l.pinned_generation).min().unwrap_or(current_generation);
        let blocking = self.blocking_readers_for_packs(retired_pack_ids, retired_at_generation);
        Ok(ReaderQuiescenceObservation {
            observed_seq: seq,
            retired_at_generation,
            min_active_reader_generation: min_active,
            active_blocking_readers: blocking,
            drain_watermark_generation: self.completed_drain_generation,
            pg_exclusive_reader_barrier_epoch: self.pg_exclusive_barrier_epoch,
        })
    }
}
