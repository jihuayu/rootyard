//! Parent-side mount registry and the pending-mount reservation state machine.
//!
//! An admission is a two-phase operation: while the helper `Mount` RPC is in
//! flight the workspace is visible as `Pending`, so a concurrent `ensure` for
//! the same workspace must not start a second RPC. The "already mounted?" check
//! and the `Pending` insertion are linearized under the same registry mutex;
//! only the winner receives a [`ReservationGuard`] and therefore sends the RPC.
//!
//! A reservation carries a server-generated token plus the identity of the
//! helper generation that admitted it. The guard, promotion and helper-death
//! cleanup only touch an entry when that exact token/generation still matches,
//! so a failed old caller can never remove a newer reservation or mount.
//!
//! No RPC, filesystem operation or thread join is performed while the registry
//! mutex is held. The guard's `Drop` only removes its own pending entry.
use super::legacy_shutdown::LegacyShutdownTicket;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

/// Identity of one admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reservation {
    token: Uuid,
    helper_generation: u64,
}

impl Reservation {
    fn new(helper_generation: u64) -> Self {
        Self { token: Uuid::new_v4(), helper_generation }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperState {
    Pending(Reservation),
    Confirmed { helper_generation: u64 },
}

/// The parent-side registration for one workspace in the helper backend.
pub(crate) struct HelperSlot<C> {
    pub(crate) client: C,
    state: HelperState,
}

impl<C> HelperSlot<C> {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self.state, HelperState::Pending(_))
    }

    pub(crate) fn confirmed_generation(&self) -> Option<u64> {
        match self.state {
            HelperState::Confirmed { helper_generation } => Some(helper_generation),
            HelperState::Pending(_) => None,
        }
    }
}

/// A workspace is either served in-process or registered with the helper.
pub(crate) enum MountEntry<C, I> {
    InProcess(I),
    Helper(HelperSlot<C>),
}

/// All mount registrations. Generic over the client and in-process payload so
/// the reservation rules can be tested without FUSE or a helper process.
pub(crate) struct Registry<C, I> {
    entries: HashMap<Uuid, MountEntry<C, I>>,
    /// Terminal admission gate for the legacy in-process backend. This is the
    /// same registry authority as `entries`, never reset by `mem::take`.
    legacy_closing: bool,
    /// Exact pending legacy admission tokens. Close counts this set under the
    /// registry lock; a token is removed only by its own promotion/failure.
    legacy_pending: HashMap<Uuid, LegacyReservation>,
    /// The retained teardown owner, stored before its OS worker is spawned.
    legacy_ticket: Option<Arc<LegacyShutdownTicket<I>>>,
    /// A token-conflict owner that cannot be published or transferred. Keeping
    /// it here (rather than dropping it) makes it shutdown-visible.
    legacy_orphans: Vec<(Uuid, I)>,
    /// Post-spawn owners whose exact mount identity was not captured. They are
    /// never published as mounted; close seeds them into the retained ticket,
    /// where teardown is a permanent typed failure until real ownership is
    /// resolved.
    legacy_unproved: Vec<(Uuid, I)>,
}

impl<C, I> Default for Registry<C, I> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            legacy_closing: false,
            legacy_pending: HashMap::new(),
            legacy_ticket: None,
            legacy_orphans: Vec::new(),
            legacy_unproved: Vec::new(),
        }
    }
}

/// Identity of one legacy in-process admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyReservation {
    token: Uuid,
}

impl LegacyReservation {
    fn new() -> Self {
        Self { token: Uuid::new_v4() }
    }
}

/// Why a legacy admission could not reserve its short registry slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LegacyReserveError {
    Closing,
    Pending,
    Occupied,
    Unproved,
}

/// Result of publishing an owner after its IO/spawn work completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LegacyPromotion {
    /// The registry was still open and now owns the live mount.
    Mounted,
    /// Close won the linearization race. The owner was transferred to the same
    /// retained teardown ticket instead of being published as mounted.
    Transferred,
}

/// Deliberate extraction under the registry authority. Helper entries remain
/// alive until their own teardown; legacy owners are seeded into one retained
/// ticket, and pending admissions stay visible through that ticket.
pub(super) struct RegistryShutdown<C, I> {
    pub(super) helpers: Vec<(Uuid, HelperSlot<C>)>,
    pub(super) legacy: Option<Arc<LegacyShutdownTicket<I>>>,
}

/// Result of one admission attempt.
pub(crate) enum Admission<C, I> {
    /// A same-process mount owns the workspace; never overwrite it.
    InProcess,
    /// The helper already confirmed this workspace; the caller may hand off.
    Confirmed { client: C, helper_generation: u64 },
    /// Another caller is inside its mount RPC.
    Pending,
    /// This caller inserted the reservation and is the only one allowed to RPC.
    Reserved(ReservationGuard<C, I>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromoteConflict;

impl<C, I> Registry<C, I> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, id: &Uuid) -> Option<&MountEntry<C, I>> {
        self.entries.get(id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Uuid, &MountEntry<C, I>)> {
        self.entries.iter()
    }

    #[cfg(test)]
    pub(crate) fn insert_in_process(&mut self, id: Uuid, entry: I) {
        self.entries.insert(id, MountEntry::InProcess(entry));
    }

    pub(super) fn legacy_closing(&self) -> bool {
        self.legacy_closing
    }

    #[cfg(test)]
    pub(super) fn legacy_pending(&self, id: Uuid) -> bool {
        self.legacy_pending.contains_key(&id)
    }

    /// Reserve a legacy admission while holding the registry lock. The caller
    /// performs filesystem/lazy/spawn work only after the guard has handed the
    /// lock back. Promotion later rechecks this exact token under the same
    /// authority, so a stale failure can never remove a newer admission.
    pub(super) fn reserve_legacy(
        &mut self,
        id: Uuid,
        shared: &Arc<Mutex<Self>>,
    ) -> Result<LegacyReservationGuard<C, I>, LegacyReserveError> {
        if self.legacy_closing {
            return Err(LegacyReserveError::Closing);
        }
        if self.legacy_pending.contains_key(&id) {
            return Err(LegacyReserveError::Pending);
        }
        if self.entries.contains_key(&id) {
            return Err(LegacyReserveError::Occupied);
        }
        if self.legacy_unproved.iter().any(|(existing, _)| *existing == id) {
            return Err(LegacyReserveError::Unproved);
        }
        let reservation = LegacyReservation::new();
        self.legacy_pending.insert(id, reservation);
        Ok(LegacyReservationGuard { registry: shared.clone(), id, reservation, armed: true })
    }

    /// Keep an owner that could not be promoted because its exact token no
    /// longer matched. A closing registry adopts it into the retained ticket;
    /// otherwise it remains shutdown-visible in the orphan set.
    pub(super) fn retain_legacy_owner(&mut self, id: Uuid, owner: I) {
        if let Some(ticket) = self.legacy_ticket.as_ref() {
            ticket.adopt_owners(vec![(id, owner)]);
        } else {
            self.legacy_orphans.push((id, owner));
        }
    }

    /// Atomically close legacy admission, extract helper entries, and seed the
    /// legacy ticket with already-confirmed owners plus the pending count. No
    /// FUSE work, thread join or slow IO occurs here.
    pub(super) fn begin_shutdown(&mut self) -> RegistryShutdown<C, I> {
        let mut helpers = Vec::new();
        let mut in_process = Vec::new();
        for (id, entry) in self.entries.drain() {
            match entry {
                MountEntry::Helper(slot) => helpers.push((id, slot)),
                MountEntry::InProcess(owner) => in_process.push((id, owner)),
            }
        }
        in_process.append(&mut self.legacy_orphans);
        in_process.append(&mut self.legacy_unproved);

        if self.legacy_closing {
            if let Some(ticket) = self.legacy_ticket.as_ref() {
                ticket.adopt_owners(in_process);
            } else if !in_process.is_empty() {
                // The only path to this branch is a previously empty close
                // followed by an already-retained orphan. Create the same
                // retained owner rather than dropping it.
                let ticket = Arc::new(LegacyShutdownTicket::new());
                ticket.seed_owners(in_process);
                self.legacy_ticket = Some(ticket);
            }
        } else {
            self.legacy_closing = true;
            let pending = self.legacy_pending.len();
            if pending > 0 || !in_process.is_empty() {
                let ticket = Arc::new(LegacyShutdownTicket::new());
                ticket.add_pending(pending);
                ticket.seed_owners(in_process);
                self.legacy_ticket = Some(ticket);
            }
        }

        RegistryShutdown { helpers, legacy: self.legacy_ticket.clone() }
    }

    /// Check the workspace and reserve it in one critical section.
    ///
    /// Exactly one caller can receive `Reserved` for a workspace while no
    /// confirmed/in-process mount exists. Losers see `Pending` and must not
    /// send a mount RPC or cancel anything on the shared workspace.
    pub(crate) fn admit(shared: &Arc<Mutex<Self>>, id: Uuid, client: C, helper_generation: u64) -> Admission<C, I>
    where
        C: Clone,
    {
        let mut registry = lock(shared);
        match registry.entries.get(&id) {
            Some(MountEntry::InProcess(_)) => Admission::InProcess,
            Some(MountEntry::Helper(slot)) => match slot.state {
                HelperState::Pending(_) => Admission::Pending,
                HelperState::Confirmed { helper_generation } => {
                    Admission::Confirmed { client: slot.client.clone(), helper_generation }
                }
            },
            None => {
                let reservation = Reservation::new(helper_generation);
                registry
                    .entries
                    .insert(id, MountEntry::Helper(HelperSlot { client, state: HelperState::Pending(reservation) }));
                Admission::Reserved(ReservationGuard { registry: shared.clone(), id, reservation, armed: true })
            }
        }
    }

    /// Remove the pending entry only if `reservation` is still the exact one.
    pub(crate) fn release_pending(&mut self, id: Uuid, reservation: Reservation) -> bool {
        let ours = matches!(
            self.entries.get(&id),
            Some(MountEntry::Helper(slot)) if slot.state == HelperState::Pending(reservation)
        );
        if ours {
            self.entries.remove(&id);
        }
        ours
    }

    /// Remove a confirmed helper registration only for the generation that
    /// observed the death. An old caller must not delete a newer generation.
    pub(crate) fn remove_confirmed(&mut self, id: Uuid, helper_generation: u64) -> bool {
        let ours = matches!(
            self.entries.get(&id),
            Some(MountEntry::Helper(slot))
                if slot.confirmed_generation() == Some(helper_generation)
        );
        if ours {
            self.entries.remove(&id);
        }
        ours
    }

    #[cfg(test)]
    fn pending(&self, id: Uuid) -> Option<Reservation> {
        match self.entries.get(&id) {
            Some(MountEntry::Helper(slot)) => match slot.state {
                HelperState::Pending(reservation) => Some(reservation),
                HelperState::Confirmed { .. } => None,
            },
            _ => None,
        }
    }
}

/// Owns one pending reservation until it is promoted or dropped.
pub(crate) struct ReservationGuard<C, I> {
    registry: Arc<Mutex<Registry<C, I>>>,
    id: Uuid,
    reservation: Reservation,
    armed: bool,
}

impl<C, I> ReservationGuard<C, I> {
    #[cfg(test)]
    pub(crate) fn reservation(&self) -> Reservation {
        self.reservation
    }

    /// Publish the confirmed helper registration, but only if the pending entry
    /// is still exactly this token and helper generation. A mismatch is a
    /// conflict; the caller must not report success.
    pub(crate) fn promote(&mut self, client: C) -> Result<(), PromoteConflict> {
        let mut registry = lock(&self.registry);
        let matched = match registry.entries.get_mut(&self.id) {
            Some(MountEntry::Helper(slot)) if slot.state == HelperState::Pending(self.reservation) => {
                slot.client = client;
                slot.state = HelperState::Confirmed { helper_generation: self.reservation.helper_generation };
                true
            }
            _ => false,
        };
        if matched {
            self.armed = false;
            Ok(())
        } else {
            Err(PromoteConflict)
        }
    }
}

impl<C, I> Drop for ReservationGuard<C, I> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut registry = lock(&self.registry);
        registry.release_pending(self.id, self.reservation);
    }
}

/// Owns one pending legacy admission token until it is promoted or dropped.
pub(super) struct LegacyReservationGuard<C, I> {
    registry: Arc<Mutex<Registry<C, I>>>,
    id: Uuid,
    reservation: LegacyReservation,
    armed: bool,
}

impl<C, I> LegacyReservationGuard<C, I> {
    /// Publish the newly created owner only while the exact token is still
    /// pending. If close won the race, transfer the same owner to the retained
    /// teardown ticket instead; the caller must report the admission as not
    /// mounted.
    pub(super) fn promote(&mut self, owner: I) -> Result<LegacyPromotion, I> {
        let mut registry = lock(&self.registry);
        if registry.legacy_pending.get(&self.id) != Some(&self.reservation) {
            return Err(owner);
        }
        registry.legacy_pending.remove(&self.id);
        self.armed = false;
        if registry.legacy_closing {
            if let Some(ticket) = registry.legacy_ticket.clone() {
                ticket.resolve_with_owner(self.id, owner);
            } else {
                registry.legacy_orphans.push((self.id, owner));
            }
            Ok(LegacyPromotion::Transferred)
        } else {
            registry.entries.insert(self.id, MountEntry::InProcess(owner));
            Ok(LegacyPromotion::Mounted)
        }
    }

    /// Transfer an owner whose mount was created but whose exact identity was
    /// not captured. It is never published as mounted and never resolves the
    /// pending condition without an owner.
    pub(super) fn retain_unproved(&mut self, owner: I) {
        let mut registry = lock(&self.registry);
        if registry.legacy_pending.get(&self.id) != Some(&self.reservation) {
            // A stale token must not remove a newer reservation, but the owner
            // still has to stay shutdown-visible.
            registry.retain_legacy_owner(self.id, owner);
            return;
        }
        registry.legacy_pending.remove(&self.id);
        self.armed = false;
        if registry.legacy_closing {
            if let Some(ticket) = registry.legacy_ticket.clone() {
                ticket.resolve_with_owner(self.id, owner);
            } else {
                registry.legacy_orphans.push((self.id, owner));
            }
        } else {
            registry.legacy_unproved.push((self.id, owner));
        }
    }

    #[cfg(test)]
    fn reservation(&self) -> LegacyReservation {
        self.reservation
    }
}

impl<C, I> Drop for LegacyReservationGuard<C, I> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut registry = lock(&self.registry);
        if registry.legacy_pending.get(&self.id) != Some(&self.reservation) {
            return;
        }
        registry.legacy_pending.remove(&self.id);
        if registry.legacy_closing
            && let Some(ticket) = registry.legacy_ticket.clone()
        {
            // The admission failed before creating an owner. Resolve the
            // pending completion condition even though there is nothing to
            // retain.
            ticket.resolve_without_owner(self.id);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned registry is still a consistent map: every critical section is
    // a short insert/remove and does not leave half-updated state behind.
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::super::legacy_shutdown::LegacyOwner;
    use super::*;
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestClient(u64);

    type TestRegistry = Registry<TestClient, ()>;

    fn registry() -> Arc<Mutex<TestRegistry>> {
        Arc::new(Mutex::new(TestRegistry::new()))
    }

    fn reserve(
        registry: &Arc<Mutex<TestRegistry>>,
        id: Uuid,
        client: TestClient,
        generation: u64,
    ) -> ReservationGuard<TestClient, ()> {
        match TestRegistry::admit(registry, id, client, generation) {
            Admission::Reserved(guard) => guard,
            _ => panic!("expected this caller to win the reservation"),
        }
    }

    #[test]
    fn barrier_allows_only_one_rpc_winner_for_the_same_workspace() {
        let registry = registry();
        let id = Uuid::new_v4();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for n in 0..2 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                // Only `Reserved` is allowed to issue the mount RPC.
                let admission = TestRegistry::admit(&registry, id, TestClient(n), 7);
                let won = matches!(&admission, Admission::Reserved(_));
                // Keep the winner's reservation until both admissions finish.
                barrier.wait();
                drop(admission);
                won
            }));
        }
        let winners = handles.into_iter().map(|handle| handle.join().unwrap()).filter(|won| *won).count();
        assert_eq!(winners, 1, "two concurrent ensures must not both own the mount RPC");
    }

    #[test]
    fn failed_old_guard_cannot_remove_a_later_reservation() {
        let registry = registry();
        let id = Uuid::new_v4();
        let old = reserve(&registry, id, TestClient(1), 7);
        // Simulate the old failure path removing its own reservation while the
        // guard object is still alive (for example a promote error unwind).
        assert!(registry.lock().unwrap().release_pending(id, old.reservation()));
        let later = reserve(&registry, id, TestClient(2), 7);
        let later_reservation = later.reservation();

        drop(old);
        assert_eq!(
            registry.lock().unwrap().pending(id),
            Some(later_reservation),
            "the stale guard must not remove the later reservation"
        );
    }

    #[test]
    fn promote_mismatch_is_a_conflict_and_leaves_the_new_reservation() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut old = reserve(&registry, id, TestClient(1), 7);
        assert!(registry.lock().unwrap().release_pending(id, old.reservation()));
        let mut later = reserve(&registry, id, TestClient(2), 7);
        let later_reservation = later.reservation();

        assert_eq!(old.promote(TestClient(9)), Err(PromoteConflict));
        assert_eq!(registry.lock().unwrap().pending(id), Some(later_reservation));
        assert!(later.promote(TestClient(2)).is_ok());
        assert_eq!(registry.lock().unwrap().pending(id), None);
    }

    #[test]
    fn in_process_is_never_treated_as_missing_or_overwritten() {
        let registry = registry();
        let id = Uuid::new_v4();
        registry.lock().unwrap().insert_in_process(id, ());

        assert!(matches!(TestRegistry::admit(&registry, id, TestClient(1), 7), Admission::InProcess));
        assert!(matches!(registry.lock().unwrap().get(&id), Some(MountEntry::InProcess(()))));
    }

    #[test]
    fn confirmed_removal_is_scoped_to_the_observing_generation() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut guard = reserve(&registry, id, TestClient(1), 7);
        guard.promote(TestClient(1)).unwrap();

        assert!(!registry.lock().unwrap().remove_confirmed(id, 8));
        assert!(matches!(
            registry.lock().unwrap().get(&id),
            Some(MountEntry::Helper(slot))
                if slot.confirmed_generation() == Some(7)
        ));
        assert!(registry.lock().unwrap().remove_confirmed(id, 7));
        assert!(registry.lock().unwrap().get(&id).is_none());
    }

    #[derive(Debug)]
    struct LegacyTestOwner;

    impl LegacyOwner for LegacyTestOwner {
        fn fence_for_shutdown(&self) {}

        fn teardown_owned(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    type LegacyTestRegistry = Registry<TestClient, LegacyTestOwner>;

    fn legacy_registry() -> Arc<Mutex<LegacyTestRegistry>> {
        Arc::new(Mutex::new(LegacyTestRegistry::new()))
    }

    struct UnprovedTestOwner {
        drops: Arc<AtomicUsize>,
    }

    impl LegacyOwner for UnprovedTestOwner {
        fn fence_for_shutdown(&self) {}

        fn teardown_owned(&mut self) -> Result<(), String> {
            Err("mount identity unproved".into())
        }
    }

    impl Drop for UnprovedTestOwner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    type UnprovedTestRegistry = Registry<TestClient, UnprovedTestOwner>;

    fn unproved_registry() -> Arc<Mutex<UnprovedTestRegistry>> {
        Arc::new(Mutex::new(UnprovedTestRegistry::new()))
    }

    #[test]
    fn close_refuses_a_legacy_reservation_under_the_same_registry_authority() {
        let registry = legacy_registry();
        let id = Uuid::new_v4();
        let mut registry_lock = registry.lock().unwrap();
        let shutdown = registry_lock.begin_shutdown();
        assert!(shutdown.helpers.is_empty());
        assert!(shutdown.legacy.is_none());
        assert!(registry_lock.legacy_closing());
        assert!(matches!(registry_lock.reserve_legacy(id, &registry), Err(LegacyReserveError::Closing)));
    }

    #[test]
    fn pre_close_pending_owner_transfers_to_the_same_retained_ticket() {
        let registry = legacy_registry();
        let id = Uuid::new_v4();
        let mut guard = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        let ticket = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown().legacy.expect("pending admission must create a retained ticket")
        };
        assert_eq!(ticket.observe().pending, 1);
        ticket.spawn_worker().unwrap();

        assert_eq!(guard.promote(LegacyTestOwner).unwrap(), LegacyPromotion::Transferred);
        assert!(
            registry.lock().unwrap().get(&id).is_none(),
            "a pending admission that finishes after close must not be published as mounted"
        );
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(observation.success(), "{observation:?}");
    }

    #[test]
    fn failed_pre_close_admission_resolves_the_ticket_without_an_owner() {
        let registry = legacy_registry();
        let id = Uuid::new_v4();
        let guard = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        let ticket = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown().legacy.expect("pending admission must create a retained ticket")
        };
        ticket.spawn_worker().unwrap();
        assert_eq!(ticket.observe().pending, 1);
        drop(guard);
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(observation.success(), "{observation:?}");
        assert_eq!(observation.pending, 0);
        assert_eq!(observation.owned, 0);
    }

    #[test]
    fn helper_entries_are_extracted_without_resetting_the_legacy_close_flag() {
        let registry = legacy_registry();
        let id = Uuid::new_v4();
        let mut helper = match LegacyTestRegistry::admit(&registry, id, TestClient(1), 7) {
            Admission::Reserved(guard) => guard,
            _ => panic!("expected a helper reservation"),
        };
        helper.promote(TestClient(1)).unwrap();

        let first = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown()
        };
        assert_eq!(first.helpers.len(), 1);
        assert!(first.legacy.is_none());
        assert!(registry.lock().unwrap().legacy_closing());

        let second = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown()
        };
        assert!(second.helpers.is_empty());
        assert!(second.legacy.is_none());
        assert!(registry.lock().unwrap().legacy_closing(), "a repeated close must not reset the flag");
    }

    #[test]
    fn stale_legacy_guard_cannot_remove_a_later_reservation() {
        let registry = legacy_registry();
        let id = Uuid::new_v4();
        let old = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        let old_reservation = old.reservation();
        {
            let mut lock = registry.lock().unwrap();
            lock.legacy_pending.remove(&id);
        }
        let later = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        assert_ne!(old_reservation, later.reservation());
        drop(old);
        assert!(registry.lock().unwrap().legacy_pending(id), "the stale guard must leave the later token intact");
    }

    #[test]
    fn unproved_post_spawn_owner_is_retained_without_publishing_or_remount() {
        let registry = unproved_registry();
        let id = Uuid::new_v4();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut guard = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        guard.retain_unproved(UnprovedTestOwner { drops: drops.clone() });
        assert_eq!(drops.load(Ordering::SeqCst), 0, "the owner must not be dropped");

        {
            let mut lock = registry.lock().unwrap();
            assert!(!lock.legacy_pending(id), "an owner-bearing failure must remove the pending token");
            assert!(lock.get(&id).is_none(), "an unproved owner must never be published as mounted");
            assert_eq!(lock.legacy_unproved.len(), 1);
            assert!(matches!(lock.reserve_legacy(id, &registry), Err(LegacyReserveError::Unproved)));
        }
    }

    #[test]
    fn post_spawn_unproved_owner_after_close_resolves_pending_but_is_never_clean() {
        let registry = unproved_registry();
        let id = Uuid::new_v4();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut guard = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        let ticket = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown().legacy.expect("pending admission must create a retained ticket")
        };
        ticket.spawn_worker().unwrap();
        assert_eq!(ticket.observe().pending, 1);

        // This is the source stand-in for ensure() observing an owner-bearing
        // post-spawn failure. The owner and Reader transfer before guard Drop.
        guard.retain_unproved(UnprovedTestOwner { drops: drops.clone() });
        assert_eq!(drops.load(Ordering::SeqCst), 0, "retained unproved owner must not be dropped");
        assert_eq!(ticket.observe().pending, 0, "owner transfer must resolve the pending count");

        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(!observation.success(), "an unproved owner must never produce clean success");
        assert_eq!(observation.owned, 1, "the unproved owner stays ticket-owned");
        assert!(observation.failures.iter().any(|failure| failure.contains("mount identity unproved")));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn close_seeds_an_earlier_unproved_owner_into_the_ticket() {
        let registry = unproved_registry();
        let id = Uuid::new_v4();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut guard = {
            let mut lock = registry.lock().unwrap();
            lock.reserve_legacy(id, &registry).unwrap()
        };
        guard.retain_unproved(UnprovedTestOwner { drops: drops.clone() });
        let ticket = {
            let mut lock = registry.lock().unwrap();
            lock.begin_shutdown().legacy.expect("an unproved owner must create a retained ticket")
        };
        ticket.spawn_worker().unwrap();
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(!observation.success());
        assert_eq!(observation.owned, 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
}
