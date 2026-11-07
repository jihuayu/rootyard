use super::*;

#[test]
fn budget_caps_ops_and_bytes_and_releases_exactly() {
    let budget = Budget::new(2, 100);
    assert!(budget.try_acquire(60));
    assert!(!budget.try_acquire(50), "byte cap must reject oversize operations");
    assert!(budget.try_acquire(40));
    assert!(!budget.try_acquire(1), "operation cap must reject a third operation");
    assert_eq!(budget.used(), (2, 100));
    budget.release(60);
    assert_eq!(budget.used(), (1, 40));
    budget.release(40);
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn permit_charges_both_budgets_and_releases_on_drop() {
    let mount = Arc::new(Budget::new(8, 1024));
    let global = Arc::new(Budget::new(8, 2048));
    let permit = Permit::acquire(&mount, &global, 128).expect("permit");
    assert_eq!(mount.used(), (1, 128));
    assert_eq!(global.used(), (1, 128));
    drop(permit);
    assert_eq!(mount.used(), (0, 0));
    assert_eq!(global.used(), (0, 0));
}

#[test]
fn queued_mutation_epoch_must_match_the_admitted_guard_epoch() {
    assert!(epoch_matches(Some(7), 7));
    assert!(!epoch_matches(Some(7), 8), "a parked old-epoch mutation must not run on the new epoch");
    assert!(!epoch_matches(None, 7), "an unstamped mutation fails closed");
}

#[test]
fn closed_work_queue_refuses_pops_but_drain_paths_still_clean_up() {
    let mut queue = WorkQueue::<u32>::new();
    assert_eq!(queue.push_ready(1), None);
    queue.push_frozen_back(2);
    queue.close();
    assert!(queue.is_shutdown());
    assert_eq!(queue.push_ready(3), Some(3), "a closed queue rejects new ready work");
    assert_eq!(queue.pop_ready(), None);
    assert_eq!(queue.pop_frozen(), None);
    assert_eq!(queue.lens(), (1, 1), "refusing a pop must not discard queued replies");
    assert_eq!(queue.pop_ready_for_drain(), Some(1));
    assert_eq!(queue.pop_frozen_for_drain(), Some(2));
    assert_eq!(queue.pop_ready_for_drain(), None);
    assert_eq!(queue.pop_frozen_for_drain(), None);
}
