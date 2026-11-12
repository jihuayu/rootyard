//! Retained-root capture and lifetime refusal tests.
//!
//! The shared fixture (`valid_source`, `root_capture`, `head`, `tombstone`,
//! `seal_root`) stays in the sibling `ledger_sets_tests` module; `use super::*`
//! imports it together with the constants and the parent checkers.
use super::*;

/// The capture disagrees with its stored head: exactly that, never missing.
fn assert_capture_mismatched(lines: &[String], state: &str) {
    assert_root_refused(lines, "root_capture_mismatch", state);
    assert!(!lines.iter().any(|line| line.starts_with("root_capture_missing")), "{lines:?}");
}

#[test]
fn a_retained_root_that_is_not_the_canonical_pair_is_refused() {
    let mut altered = valid_source();
    altered.roots[0].packs[0].idx.hold_id = Uuid::from_u128(0x1400);
    assert_refused(&altered.violations(), "root_set_mismatch");
    // A retained subset (no pack row) is not a complete pair either, and the
    // rest of the root (refs) is still validated first.
    let mut subset = valid_source();
    subset.roots[0].pack_count = 0;
    subset.roots[0].packs.clear();
    assert_refused(&subset.violations(), "root_pack_set_mismatch");
    // A root captured in another realm is refused even with identical digest.
    let mut realm = valid_source();
    realm.roots[0].realm.tenant_id = Uuid::from_u128(0x1500);
    assert_refused(&realm.violations(), "root_set_mismatch");
}

/// The selector, scatter and binding digests are the core's verdict, not a
/// second algorithm here: a capture the core refuses, or a stored column that
/// is not exactly what the core re-derived, is refused.
#[test]
fn a_root_must_carry_exactly_the_core_verified_capture() {
    let mut unproven = valid_source();
    unproven.roots[0].proof = None;
    assert_refused(&unproven.violations(), "root_capture_invalid");
    // Only the stored side changes: a stored selector that drops one of the
    // core's re-proven oids is refused. A stored snapshot equal to refs + HEAD is
    // the core's own verdict (`Snapshot == refs + HEAD` is proven by the real
    // core validator, never by a fixture-built `proof`).
    let mut snapshot = valid_source();
    snapshot.roots[0].oids.pop();
    snapshot.roots[0].oid_count = 1;
    assert!(
        snapshot.violations().contains(&format!("root_selector_mismatch:{REPO}:{ROOT}")),
        "{:?}",
        snapshot.violations()
    );
    let mut order = valid_source();
    order.roots[0].oids[0].0 = 3;
    assert_refused(&order.violations(), "root_selector_mismatch");
    let mut kind = valid_source();
    kind.roots[0].selector_kind = "oids".into();
    assert_refused(&kind.violations(), "root_selector_mismatch");
    let mut binding = valid_source();
    binding.roots[0].native_binding_digest = sha(0x38);
    assert_refused(&binding.violations(), "root_selector_mismatch");
    let mut head = valid_source();
    head.roots[0].head_ref = "refs/heads/other".into();
    assert_refused(&head.violations(), "root_selector_mismatch");
    // Counts are the rows': a binding digest proves them, so a stored count
    // that disagrees with its digest is refused by the core's own verdict.
    let mut count = valid_source();
    count.roots[0].oid_count = 7;
    count.roots[0].proof = None;
    assert_refused(&count.violations(), "root_capture_invalid");
}

#[test]
fn root_lifetime_covers_heads_captures_and_tombstones() {
    let valid = valid_source();
    assert!(valid.violations().is_empty(), "{:?}", valid.violations());
    // `register` writes only an active head and its capture: that must be valid.
    let mut active = valid_source();
    active.heads = vec![head("active", 1)];
    active.tombstones.clear();
    assert!(active.violations().is_empty(), "{:?}", active.violations());
    // Nothing registered: refused.
    // A missing capture is exactly its own missing verdict, never a mismatch.
    let mut nothing = active.clone();
    nothing.roots.clear();
    let lines = nothing.violations();
    assert!(lines.contains(&format!("root_capture_missing:{REPO}:{ROOT}:active")), "{lines:?}");
    assert!(!lines.iter().any(|line| line.starts_with("root_capture_mismatch")), "{lines:?}");
    // A capture without its head is refused.
    let mut headless = valid.clone();
    headless.heads.clear();
    assert!(headless.violations().contains(&format!("root_head_missing:{REPO}:{ROOT}")));
    // Release-before-register: a released head, its tombstone and no capture.
    let mut released_first = valid.clone();
    released_first.roots.clear();
    assert!(released_first.violations().is_empty(), "{:?}", released_first.violations());
    // Without its tombstone that head is not a legal release-before-register.
    let mut unregistered = released_first.clone();
    unregistered.tombstones.clear();
    assert_refused(&unregistered.violations(), "root_capture_missing");
    // A released root keeps its capture but must carry the release tombstone.
    let mut registered = valid_source();
    registered.heads = vec![head("released", 2)];
    registered.tombstones.clear();
    assert_root_refused(&registered.violations(), "root_head_mismatch", "unreleased");
    // The tombstone must fence exactly the capture scope and register digest.
    // A tombstone that does not fence leaves the released capture unreleased.
    let mut foreign = registered.clone();
    foreign.tombstones = vec![RootTombstone { owner_id: Uuid::from_u128(0x1600), ..tombstone() }];
    assert_root_refused(&foreign.violations(), "root_head_mismatch", "unreleased");
    let mut stale = registered.clone();
    stale.tombstones = vec![RootTombstone { expected_register_digest: sha(0x34), ..tombstone() }];
    assert_root_refused(&stale.violations(), "root_head_mismatch", "unreleased");
    // The capture exists under the head's key but under another scope.
    let mut tenant = registered.clone();
    tenant.heads[0].tenant_id = Uuid::from_u128(0x1700);
    assert_capture_mismatched(&tenant.violations(), "released");
    let mut intent = registered.clone();
    intent.heads[0].business_intent_digest = sha(0x36);
    assert_root_refused(&intent.violations(), "root_head_mismatch", "tombstone_mismatch");
    // The capture must itself carry the head's register digest, owner and tenant.
    let mut digest = registered.clone();
    digest.roots[0].register_digest = sha(0x35);
    assert_capture_mismatched(&digest.violations(), "released");
    let mut producer = active.clone();
    producer.roots[0].owner_id = Uuid::from_u128(0x1600);
    assert_root_refused(&producer.violations(), "root_capture_mismatch", "active");
    // A release-before-register head that the capture proves was registered is
    // not a release-before-register root.
    let mut contradiction = valid_source();
    contradiction.heads = vec![head("active", 1)];
    contradiction.roots.clear();
    assert_refused(&contradiction.violations(), "root_capture_missing");
    // A tombstone never follows an active capture.
    let mut early = active.clone();
    early.tombstones = vec![tombstone()];
    assert_root_refused(&early.violations(), "root_head_mismatch", "tombstone_without_release");
    // Any other lifetime shape is refused, and is a violation (never a panic)
    // whatever tombstones it carries: none, a legal-looking row or a corrupted one.
    let shapes =
        [("released", 1), ("released", 3), ("active", 2), ("active", 3), ("released", 0), ("", 1), ("Active", 1)];
    for (state, generation) in shapes {
        for tombstones in [Vec::new(), vec![tombstone()], vec![RootTombstone { generation: 3, ..tombstone() }]] {
            let mut shape = active.clone();
            shape.heads = vec![head(state, generation)];
            shape.tombstones = tombstones;
            assert_root_refused(&shape.violations(), "root_head_mismatch", "state");
        }
    }
    // A head whose owner moved away from the stored capture is a scope error, not
    // an unfenced release: the capture disagrees with its head, and the legal
    // tombstone no longer fences that head.
    let mut head_scope = registered.clone();
    head_scope.heads[0].owner_id = Uuid::from_u128(0x1800);
    assert_capture_mismatched(&head_scope.violations(), "released");
    assert_root_refused(&head_scope.violations(), "root_head_mismatch", "tombstone_mismatch");
    // A stale headless tombstone is refused.
    let mut orphan_tombstone = headless;
    orphan_tombstone.tombstones = vec![tombstone()];
    assert_refused(&orphan_tombstone.violations(), "root_tombstone_without_head");
}

/// A capture that exists under the head's key but carries another scope, owner
/// or register digest is a violation, never a release-before-register root,
/// even when a legal release tombstone fences the head.
#[test]
fn a_present_capture_that_disagrees_with_its_head_is_never_release_before_register() {
    let released = valid_source();
    assert!(released.violations().is_empty(), "{:?}", released.violations());
    let mut active = released.clone();
    active.heads = vec![head("active", 1)];
    active.tombstones.clear();
    assert!(active.violations().is_empty(), "{:?}", active.violations());
    // Each capture field alone must be a mismatch, never a missing capture.
    let fields: [(&str, fn(&mut RootCapture)); 6] = [
        ("generation", |root| root.generation = 2),
        ("tenant", |root| root.tenant_id = Uuid::from_u128(0x1700)),
        ("purpose", |root| root.purpose = "other".into()),
        ("intent", |root| root.business_intent_digest = sha(0x36)),
        ("owner", |root| root.owner_id = Uuid::from_u128(0x1600)),
        ("register_digest", |root| root.register_digest = sha(0x35)),
    ];
    // Only the head side moves away from the stored capture.
    let scopes: [(&str, fn(&mut RootHead)); 4] = [
        ("tenant", |head| head.tenant_id = Uuid::from_u128(0x1700)),
        ("purpose", |head| head.purpose = "other".into()),
        ("intent", |head| head.business_intent_digest = sha(0x36)),
        ("owner", |head| head.owner_id = Uuid::from_u128(0x1600)),
    ];
    for (field, change) in fields {
        for (state, generation, tombstones) in [("released", 2, vec![tombstone()]), ("active", 1, Vec::new())] {
            let mut sets = valid_source();
            sets.heads = vec![head(state, generation)];
            sets.tombstones = tombstones;
            change(&mut sets.roots[0]);
            let lines = sets.violations();
            let mismatch = format!("root_capture_mismatch:{REPO}:{ROOT}:{state}");
            assert!(lines.contains(&mismatch), "{field} on {state}: expected {mismatch} in {lines:?}");
            assert!(
                !lines.iter().any(|line| line.starts_with("root_capture_missing")),
                "{field} on {state}: a present capture is not missing: {lines:?}"
            );
        }
    }
    for (field, change) in scopes {
        for state in ["released", "active"] {
            // Only the head changes; the capture keeps its own rows.
            let mut sets = valid_source();
            sets.heads = vec![head(state, if state == "released" { 2 } else { 1 })];
            if state == "active" {
                sets.tombstones.clear();
            }
            change(&mut sets.heads[0]);
            let lines = sets.violations();
            assert_root_refused(&lines, "root_capture_mismatch", state);
            assert!(
                !lines.iter().any(|line| line.starts_with("root_capture_missing")),
                "{field} on {state}: a present capture is not missing: {lines:?}"
            );
            // A stored tombstone no longer fences a head whose scope changed.
            if state == "released" {
                assert_root_refused(&lines, "root_head_mismatch", "tombstone_mismatch");
            }
        }
    }
}

/// A third, distinct owner: the root head/capture/tombstone requester.
const REQUESTER: Uuid = Uuid::from_u128(0x1a00);

/// A producer owner distinct from the repository tenant is valid, and so is a
/// root requester that is a third identity: it is compared with its own head
/// and tombstone only, never with the publication owner.
#[test]
fn a_producer_and_a_root_requester_are_independent_identities() {
    let sets = valid_source();
    assert_eq!(sets.violations(), Vec::<String>::new());
    assert_eq!(sets.declared[0].publication.as_ref().unwrap().owner_id, PRODUCER);
    assert_eq!(sets.declared[0].publication.as_ref().unwrap().tenant_id, TENANT);
    assert_ne!(PRODUCER, TENANT);
    let mut requester = valid_source();
    requester.roots[0].owner_id = REQUESTER;
    requester.roots[0].proof.as_mut().unwrap().owner_id = REQUESTER;
    requester.heads[0].owner_id = REQUESTER;
    requester.tombstones[0].owner_id = REQUESTER;
    assert_ne!(REQUESTER, PRODUCER);
    assert_eq!(requester.violations(), Vec::<String>::new());
    // The requester must still be one identity across head, capture and
    // tombstone: only the head moves.
    let mut moved = requester;
    moved.heads[0].owner_id = PRODUCER;
    assert_refused(&moved.violations(), "root_capture_mismatch");
}
