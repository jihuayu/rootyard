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
}

impl<C, I> Default for Registry<C, I> {
    fn default() -> Self {
        Self { entries: HashMap::new() }
    }
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

impl<C: Clone, I> Registry<C, I> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, id: &Uuid) -> Option<&MountEntry<C, I>> {
        self.entries.get(id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Uuid, &MountEntry<C, I>)> {
        self.entries.iter()
    }

    pub(crate) fn insert_in_process(&mut self, id: Uuid, entry: I) {
        self.entries.insert(id, MountEntry::InProcess(entry));
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Check the workspace and reserve it in one critical section.
    ///
    /// Exactly one caller can receive `Reserved` for a workspace while no
    /// confirmed/in-process mount exists. Losers see `Pending` and must not
    /// send a mount RPC or cancel anything on the shared workspace.
    pub(crate) fn admit(
        self: &Arc<Mutex<Self>>,
        id: Uuid,
        client: C,
        helper_generation: u64,
    ) -> Admission<C, I> {
        let mut registry = lock(self);
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
                registry.entries.insert(
                    id,
                    MountEntry::Helper(HelperSlot { client, state: HelperState::Pending(reservation) }),
                );
                Admission::Reserved(ReservationGuard {
                    registry: self.clone(),
                    id,
                    reservation,
                    armed: true,
                })
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
            Some(MountEntry::Helper(slot))
                if slot.state == HelperState::Pending(self.reservation) =>
            {
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned registry is still a consistent map: every critical section is
    // a short insert/remove and does not leave half-updated state behind.
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Barrier},
        thread,
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
        match registry.admit(id, client, generation) {
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
                matches!(registry.admit(id, TestClient(n), 7), Admission::Reserved(_))
            }));
        }
        let winners = handles
            .into_iter()
            .filter(|handle| handle.join().unwrap())
            .count();
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

        assert!(matches!(registry.admit(id, TestClient(1), 7), Admission::InProcess));
        assert!(matches!(
            registry.lock().unwrap().get(&id),
            Some(MountEntry::InProcess(()))
        ));
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
}
