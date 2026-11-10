//! Offline unit coverage for the sealed serving proof (#174).
//!
//! These cases isolate the pure binding step of the production builder
//! (`serving_materialization`) with test-revalidated snapshots. They prove that
//! only a T2-revalidated transient snapshot whose A5b materialization digest is
//! the native closure's digest can become a sealed proof, and that the narrower
//! A5a read digest — the digest the previous code compared — never can.
//!
//! They are NOT native evidence: no pack, Blob or Git binary is involved here.
//! The real-PostgreSQL + native-Git contract suite
//! (`tests/ref_store_serving_proof.rs`) drives the actual builder end to end.

use super::super::serving_proof::{
    contract_a5a_probe, contract_binding, contract_gate_revision, contract_history_incarnation, contract_repository_id,
    contract_scope, contract_tenant_id,
};
use super::*;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, CapturedRef, ContentDigest, RegisteredArtifact, RegisteredPack,
};
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
        crate::ref_store::core::pack_commit::role_slot(role),
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

#[test]
fn the_a5b_binding_is_the_native_digest_not_the_a5a_read_digest() {
    let snapshot = PackReadSnapshot::new_serving_transient(parts()).expect("fixture transient snapshot");
    let a5b = snapshot.materialization_digest();
    let a5a: RequestDigest = snapshot.read_digest_hex().parse().expect("fixture a5a hex");
    assert_ne!(a5a, a5b, "the fixture must distinguish the two digests");
    // The previous code compared A5a against the A5b binding, so every real
    // non-empty sealed read was refused. A5a must still be refused...
    assert!(VerifiedReadView::of_revalidated(&snapshot, a5a).is_err());
    // ...and only the A5b digest seals, with the proof stating that digest.
    let proof = VerifiedReadView::of_revalidated(&snapshot, a5b).expect("A5b must seal").seal();
    assert_eq!(contract_binding(&proof), a5b);
    assert_eq!(contract_a5a_probe(&proof), a5a);
    assert_eq!(contract_a5a_probe(&proof).as_hex(), snapshot.read_digest_hex());
}

#[test]
fn a_sealed_proof_copies_the_revalidated_gate_revision_and_realm() {
    let snapshot = PackReadSnapshot::new_serving_transient(parts()).expect("fixture transient snapshot");
    let proof =
        VerifiedReadView::of_revalidated(&snapshot, snapshot.materialization_digest()).expect("A5b must seal").seal();
    assert_eq!(contract_gate_revision(&proof), 11);
    let scope = contract_scope(&proof);
    assert_eq!(contract_repository_id(&scope), Uuid::from_bytes([5; 16]));
    assert_eq!(contract_tenant_id(&scope), Uuid::from_bytes([6; 16]));
    assert_eq!(contract_history_incarnation(&scope), Uuid::from_bytes([8; 16]));
}

#[test]
fn a_retained_a5a_snapshot_never_seals() {
    let retained = PackReadSnapshot::new(parts()).expect("fixture retained snapshot");
    let binding = retained.materialization_digest();
    assert!(VerifiedReadView::of_revalidated(&retained, binding).is_err());
}

#[test]
fn a_shape_with_no_registered_pack_is_never_built() {
    let mut empty = parts();
    empty.packs.clear();
    assert!(PackReadSnapshot::new_serving_transient(empty).is_err());
}
