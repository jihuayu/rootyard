//! Offline unit coverage for the sealed serving proof (#174).
//!
//! These cases isolate the pure binding step of the production builder
//! (`serving_materialization`) together with its only factory,
//! `VerifiedReadView::of_materialized`, over fixture snapshots. They prove that
//! only a complete transient read whose A5b materialization digest is the native
//! closure's own digest can become a sealed proof, that a retained A5a snapshot
//! never can, and that the narrower A5a read digest — the digest the previous
//! code compared — is never sealed and never equals the A5b binding. They also
//! prove that the proof's cluster authority incarnation is fixed to the view's
//! own T2-sealed anchor (which must equal the capture's), never one chosen at
//! the seal site, and that an unanchored view can never become a serving proof.
//!
//! They are NOT native evidence: no pack, Blob or Git binary is involved here.
//! The real-PostgreSQL + native-Git contract cases live in the `contract`
//! `#[path]` submodule below (`cfg(test)` + `#[ignore]`), because the production
//! builder is crate-private by design and an integration-test binary must never
//! widen it just to reach a test.

use super::super::serving_proof::{VerifiedReadView, probe_a5a};
use super::test_materialized_view;
use super::*;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, CapturedRef, ContentDigest, RegisteredArtifact, RegisteredPack,
};
use crate::ref_store::{GitObjectFormat, GitOid, MetadataPinPurpose, RefName};
use uuid::Uuid;

fn hex32(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn locator(byte: u8) -> ArtifactLocator {
    ArtifactLocator::new(
        Uuid::from_bytes([1; 16]),
        Uuid::from_bytes([2; 16]),
        1,
        Uuid::from_bytes([byte; 16]),
        format!("ns-{byte}"),
        ContentDigest::parse(hex32(byte)).expect("fixture digest"),
        u64::from(byte),
    )
    .expect("fixture locator")
}

fn artifact(role: PackArtifactRole, byte: u8) -> RegisteredArtifact {
    let locator = locator(byte);
    RegisteredArtifact::new(
        role,
        match role {
            PackArtifactRole::Pack => 0,
            PackArtifactRole::Idx => 1,
        },
        Uuid::from_bytes([byte; 16]),
        locator.clone(),
        "s3",
        hex32(byte),
        locator.sha256().clone(),
        locator.length(),
    )
    .expect("fixture artifact")
}

fn pack(byte: u8) -> RegisteredPack {
    let artifacts = vec![artifact(PackArtifactRole::Pack, byte), artifact(PackArtifactRole::Idx, byte + 1)];
    let digest = ArtifactSetDigest::of(&artifacts);
    RegisteredPack::new(Uuid::from_bytes([byte; 16]), Uuid::from_bytes([byte + 1; 16]), digest, artifacts, Some(3))
        .expect("fixture pack")
}

fn parts() -> super::super::read_snapshot::ReadSnapshotParts {
    let oid = "a".repeat(40);
    let reference = RefName::branch("refs/heads/main").expect("fixture ref name");
    super::super::read_snapshot::ReadSnapshotParts {
        snapshot_id: Uuid::from_bytes([3; 16]),
        pin_id: Uuid::from_bytes([4; 16]),
        pin_generation: 2,
        scope: MetadataSnapshotScope::new(
            Uuid::from_bytes([5; 16]),
            Uuid::from_bytes([6; 16]),
            Uuid::from_bytes([7; 16]),
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            Uuid::from_bytes([8; 16]),
            3,
            4,
        )
        .expect("fixture scope"),
        gate_revision: 11,
        gate_digest: hex32(9),
        head_ref: reference.as_str().to_owned(),
        head_oid: Some(oid.clone()),
        refs: vec![
            CapturedRef::new(reference, GitOid::parse(GitObjectFormat::Sha1, &oid).expect("fixture oid"))
                .expect("fixture ref"),
        ],
        packs: vec![pack(1)],
        membership_digest: hex32(10),
        snapshot_digest: hex32(11),
        logical_bytes: 4096,
        expires_at_unix_micros: 1_900_000_000_000_000,
    }
}

fn transient(parts: super::super::read_snapshot::ReadSnapshotParts) -> PackReadSnapshot {
    PackReadSnapshot::new_serving_transient(parts).expect("fixture transient snapshot")
}

/// The explicit fixed cluster authority incarnation every fixture capture and
/// serving view carries; production only ever takes it from the `FOR SHARE` T2
/// read. A different one models a restore rotation.
const FIXTURE_INCARNATION: Uuid = Uuid::from_u128(0x1740_0017_4000_1740_0017_4000_1740_0001);
const ROTATED_INCARNATION: Uuid = Uuid::from_u128(0x1740_0017_4000_1740_0017_4000_1740_0002);

/// A view over the fixture snapshot. `native_digest` is whatever digest the
/// stand-in native closure carries; `serving_incarnation` is the fixed anchor a
/// serving T2 would have set (production only ever builds this shape from a
/// closure whose digest T2 re-proved against the same snapshot).
fn view_bound_to(
    snapshot: PackReadSnapshot,
    native_digest: RequestDigest,
    serving_incarnation: Option<Uuid>,
) -> (MaterializedPackRead, PackReadSnapshot, RequestDigest) {
    let binding = snapshot.materialization_digest();
    (
        test_materialized_view(snapshot.clone(), NativeReadClosure::for_test(native_digest), serving_incarnation),
        snapshot,
        binding,
    )
}

fn view() -> (MaterializedPackRead, PackReadSnapshot, RequestDigest) {
    let snapshot = transient(parts());
    let binding = snapshot.materialization_digest();
    view_bound_to(snapshot, binding, Some(FIXTURE_INCARNATION))
}

/// A test-registered capture of the fixture snapshot with its A5b binding.
fn registered_capture() -> (ServingReadCapture, RequestDigest) {
    let snapshot = transient(parts());
    let binding = snapshot.materialization_digest();
    (ServingReadCapture::for_test(snapshot, binding, FIXTURE_INCARNATION), binding)
}

#[test]
fn the_fixture_distinguishes_the_a5a_read_digest_from_the_a5b_binding() {
    let snapshot = transient(parts());
    let a5b = snapshot.materialization_digest();
    let a5a = probe_a5a(&snapshot);
    assert_ne!(a5a, a5b, "the fixture must distinguish the two digests");
    // The view's public A5b binding is the native closure's digest, never A5a.
    let (view, _, binding) = view();
    assert_eq!(binding, a5b);
    assert_eq!(view.read_digest_hex(), a5b.as_hex());
    assert_ne!(view.read_digest_hex(), a5a.as_hex());
}

#[test]
fn the_production_step_keeps_the_view_and_its_proof_on_the_same_a5b_binding() {
    let (capture, binding) = registered_capture();
    let (view, snapshot, view_binding) = view();
    assert_eq!(view_binding, binding);
    let a5a = probe_a5a(&snapshot);
    assert_eq!(snapshot.read_digest_hex(), a5a.as_hex(), "A5a comes from the snapshot, A5b from the view");
    assert_ne!(a5a, binding);
    assert_eq!(capture.capture_incarnation(), FIXTURE_INCARNATION);
    let sealed = serving_materialization(view, &capture)
        .expect("the production step must seal its own capture on the A5b binding");
    // One value owns both halves: the verified view survives the call with the
    // proof that describes exactly it.
    assert_eq!(sealed.view().verified_pairs(), 1);
    let (revision, scope, proof_binding) = sealed.contract_parts();
    assert_eq!(revision, 11);
    assert_eq!(proof_binding, binding);
    assert_eq!(scope.repository_id(), Uuid::from_bytes([5; 16]));
    assert_eq!(scope.tenant_id(), Uuid::from_bytes([6; 16]));
    assert_eq!(scope.history_incarnation(), Uuid::from_bytes([8; 16]));
    // The proof carries the capture's fixed anchor, not anything chosen here.
    assert_eq!(sealed.proof().contract_cluster_incarnation(), FIXTURE_INCARNATION);
    // The seal site's own factory re-proves the sealed view on the same A5b
    // binding and incarnation; A5a is never an input to it.
    assert!(sealed.contract_refactory().is_ok());
    let view = sealed.view();
    assert!(view.verified_read_scope(&binding).is_some());
    assert!(view.verified_read_scope(&probe_a5a(view.snapshot())).is_none());
}

#[test]
fn a_view_from_another_capture_never_seals() {
    let (capture, binding) = registered_capture();
    let mut other = parts();
    other.snapshot_id = Uuid::from_bytes([9; 16]);
    // The other view is a valid materialization of a different snapshot: it
    // binds its own A5b digest, so only the cross-capture mismatch can refuse it.
    let other_snapshot = transient(other);
    let other_binding = other_snapshot.materialization_digest();
    assert_ne!(other_binding, binding);
    let (view, _, _) = view_bound_to(other_snapshot, other_binding, Some(FIXTURE_INCARNATION));
    assert!(serving_materialization(view, &capture).is_err());
}

#[test]
fn an_unanchored_view_can_never_become_a_serving_proof() {
    // A legacy/history view never took the cluster authority lock, so it has no
    // anchor: neither the factory nor the production step may mint it.
    let (capture, binding) = registered_capture();
    let (view, _, _) = view_bound_to(transient(parts()), binding, None);
    assert_eq!(view.serving_incarnation(), None);
    assert!(VerifiedReadView::of_materialized(&view).is_err());
    assert!(serving_materialization(view, &capture).is_err());
}

#[test]
fn a_proof_incarnation_is_fixed_to_the_view_its_t2_bound() {
    let (capture, binding) = registered_capture();
    // A view whose anchor was never T2-compared with this capture (e.g. an
    // anchor from after a restore rotation) is refused outright.
    let (rotated_view, _, _) = view_bound_to(transient(parts()), binding, Some(ROTATED_INCARNATION));
    assert!(serving_materialization(rotated_view, &capture).is_err());
    // A nil anchor is refused by the factory itself.
    let (nil_anchored, _, _) = view_bound_to(transient(parts()), binding, Some(Uuid::nil()));
    assert!(VerifiedReadView::of_materialized(&nil_anchored).is_err());
    // The proof seals exactly the view's own anchor, which is the capture's
    // T2-compared value; no seal-site argument can change it.
    let (view, _, _) = view();
    let sealed = serving_materialization(view, &capture).expect("seal the view-bound anchor");
    assert_eq!(sealed.contract_parts().0, 11);
    assert_eq!(sealed.proof().contract_cluster_incarnation(), FIXTURE_INCARNATION);
    assert_ne!(sealed.proof().contract_cluster_incarnation(), ROTATED_INCARNATION);
    // Re-running the only factory over the sealed view reproduces that anchor.
    assert!(sealed.contract_refactory().is_ok());
    assert_eq!(sealed.proof().contract_cluster_incarnation(), FIXTURE_INCARNATION);
}

#[test]
fn a_view_whose_binding_is_not_its_snapshot_never_proves() {
    // The one test seam refuses to build a view whose closure does not carry
    // its snapshot's A5b digest: a binding can never be chosen independently.
    let snapshot = transient(parts());
    let a5a = probe_a5a(&snapshot);
    assert_ne!(a5a, snapshot.materialization_digest());
    let refused = std::panic::catch_unwind(|| {
        test_materialized_view(snapshot, NativeReadClosure::for_test(a5a), Some(FIXTURE_INCARNATION))
    });
    assert!(refused.is_err(), "a view bound to A5a must never be built");
}

#[test]
fn a_retained_a5a_snapshot_never_seals() {
    let retained = PackReadSnapshot::new(parts()).expect("fixture retained snapshot");
    let retained_digest = retained.materialization_digest();
    let (view, snapshot, _) = view_bound_to(retained, retained_digest, Some(FIXTURE_INCARNATION));
    assert_eq!(view.proven_binding(), retained_digest, "even a correctly bound retained view");
    assert!(snapshot.complete_transient_pack_read().is_none());
    // Even a (fixture) serving anchor is refused: the shape is retained A5a.
    assert!(VerifiedReadView::of_materialized(&view).is_err());
    assert!(view.verified_read_scope(&retained_digest).is_none());
}

#[test]
fn a_shape_with_no_registered_pack_is_never_built() {
    let mut empty = parts();
    empty.packs.clear();
    assert!(PackReadSnapshot::new_serving_transient(empty).is_err());
}

// The real-PostgreSQL contract cases must run inside this crate (the sealed
// builder is crate-private by design), so they are `#[path]`-included here and
// reuse the existing `tests/serving_proof_support` fixtures rather than an
// integration binary.
#[path = "../../../../../tests/serving_proof_support/contract.rs"]
mod contract;
