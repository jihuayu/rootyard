//! Deterministic unit tests for Issue #145 (`Refs #145`).

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;

use crate::blob_store::BlobLocator;

use super::authz::{
    LfsBlobRuntimeGate, evaluate_repo_role_access, extract_credentials_header, verify_shared_hold_grant,
};
use super::locks_store::valid_lfs_lock_path;
use super::types::{
    AttestedLfsPointer, CommittedLfsBlobRecord, LfsAccessMode, LfsCollaboratorRole, LfsPointerAttestation,
    LfsProofRejectCode, LfsRefUpdateSpec, PointerInspection, PointerResolutionSource, SharedLfsHoldGrant,
    StoredBlobLocatorRef, compute_attestation_digest, compute_pointer_receipt_digest, compute_ref_updates_digest,
    inspect_candidate_lfs_pointer,
};

#[test]
fn unconfigured_runtime_gate_fails_closed_with_named_error() {
    let gate = LfsBlobRuntimeGate::unconfigured("ROOTYARD_BLOB_ENDPOINT missing");
    let Err(err) = gate.require_store() else {
        panic!("unconfigured gate must fail closed");
    };
    assert_eq!(err.code, LfsProofRejectCode::RemoteBlobUnconfigured);
    assert_eq!(err.code.http_status().as_u16(), 503);
}

#[test]
fn pointer_inspector_classifies_canonical_legacy_ordinary_and_malformed_blobs() {
    let oid = "a1".repeat(32);
    let canonical = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 4096\n");
    let hawser = format!("  version https://hawser.github.com/spec/v1\r\noid sha256:{oid}\r\nsize 4096\r\n");
    let media = format!("version http://git-media.io/v/2\noid sha256:{oid}\nsize 0\n");

    assert!(matches!(
        inspect_candidate_lfs_pointer(canonical.as_bytes()),
        PointerInspection::Valid(ref s) if s.oid == oid && s.size == 4096
    ));
    assert!(matches!(
        inspect_candidate_lfs_pointer(hawser.as_bytes()),
        PointerInspection::Valid(ref s) if s.oid == oid && s.size == 4096
    ));
    assert!(matches!(
        inspect_candidate_lfs_pointer(media.as_bytes()),
        PointerInspection::Valid(ref s) if s.oid == oid && s.size == 0
    ));

    assert_eq!(inspect_candidate_lfs_pointer(b"ordinary source code\nfn main() {}\n"), PointerInspection::NonPointer);
    assert_eq!(inspect_candidate_lfs_pointer(&vec![b'x'; 2048]), PointerInspection::NonPointer);

    let bad_oid = "version https://git-lfs.github.com/spec/v1\noid sha256:nothex\nsize 12\n";
    let missing_size = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\n");
    let bad_key = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 12\nbogus 1\n");
    for bad in [bad_oid.as_bytes(), missing_size.as_bytes(), bad_key.as_bytes()] {
        assert!(matches!(inspect_candidate_lfs_pointer(bad), PointerInspection::Malformed(_)));
    }
}

#[test]
fn cross_owner_collaborator_and_shared_hold_authorization_never_assume_caller_is_tenant() {
    let repo_id = Uuid::new_v4();
    let owner_tenant = Uuid::new_v4();
    let collab_writer = Uuid::new_v4();
    let collab_reader = Uuid::new_v4();
    let outsider = Uuid::new_v4();

    let owner_access =
        evaluate_repo_role_access(repo_id, owner_tenant, owner_tenant, "alice", None, true, true).unwrap();
    assert!(!owner_access.is_cross_owner());
    assert_eq!(owner_access.role, LfsCollaboratorRole::Admin);

    let writer_access = evaluate_repo_role_access(
        repo_id,
        owner_tenant,
        collab_writer,
        "bob",
        Some(LfsCollaboratorRole::Write),
        true,
        false,
    )
    .unwrap();
    assert!(writer_access.is_cross_owner());
    assert_eq!(writer_access.owner_tenant_id, owner_tenant);
    assert_eq!(writer_access.actor_id, collab_writer);

    let admin_denied = evaluate_repo_role_access(
        repo_id,
        owner_tenant,
        collab_writer,
        "bob",
        Some(LfsCollaboratorRole::Write),
        true,
        true,
    )
    .unwrap_err();
    assert_eq!(admin_denied.code, LfsProofRejectCode::UnauthorizedCollaborator);

    let read_write_denied = evaluate_repo_role_access(
        repo_id,
        owner_tenant,
        collab_reader,
        "carol",
        Some(LfsCollaboratorRole::Read),
        true,
        false,
    )
    .unwrap_err();
    assert_eq!(read_write_denied.code, LfsProofRejectCode::UnauthorizedCollaborator);

    let outsider_denied =
        evaluate_repo_role_access(repo_id, owner_tenant, outsider, "mallory", None, false, false).unwrap_err();
    assert_eq!(outsider_denied.code, LfsProofRejectCode::UnauthorizedCollaborator);

    let oid = "b2".repeat(32);
    let hold_id = Uuid::new_v4();
    let loc = BlobLocator::new(owner_tenant, repo_id, 1, Uuid::new_v4(), "lfs-objects", &oid, 512).unwrap();
    let src_rec = CommittedLfsBlobRecord {
        tenant_id: owner_tenant,
        repository_id: repo_id,
        oid_sha256: oid.clone(),
        size_bytes: 512,
        locator: StoredBlobLocatorRef::from_locator(&loc),
        hold_id,
        acquire_request_id: Uuid::new_v4(),
        consume_request_id: Uuid::new_v4(),
        backend_identity_hex: "c3".repeat(32),
        uploader_actor_id: collab_writer,
        retired: false,
    };
    let target_tenant = Uuid::new_v4();
    let target_repo = Uuid::new_v4();
    let mut grant = SharedLfsHoldGrant {
        grant_id: Uuid::new_v4(),
        source_tenant_id: owner_tenant,
        source_repository_id: repo_id,
        target_tenant_id: target_tenant,
        target_repository_id: target_repo,
        grantee_actor_id: Some(collab_writer),
        oid_sha256: oid.clone(),
        size_bytes: 512,
        source_hold_id: hold_id,
        active: true,
    };
    verify_shared_hold_grant(&grant, &src_rec, target_tenant, target_repo, collab_writer, &oid, 512).unwrap();

    let wrong_actor = verify_shared_hold_grant(&grant, &src_rec, target_tenant, target_repo, outsider, &oid, 512)
        .expect_err("wrong actor must fail shared hold check");
    assert_eq!(wrong_actor.code, LfsProofRejectCode::UnauthorizedSharedHold);

    grant.active = false;
    let revoked = verify_shared_hold_grant(&grant, &src_rec, target_tenant, target_repo, collab_writer, &oid, 512)
        .expect_err("revoked shared hold must fail closed");
    assert_eq!(revoked.code, LfsProofRejectCode::UnauthorizedSharedHold);
}

#[test]
fn attestation_digest_locator_roundtrip_and_auth_headers_are_deterministic() {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let op_id = Uuid::new_v4();
    let oid = "d4".repeat(32);
    let loc = BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "lfs-objects", &oid, 2048).unwrap();
    let stored = StoredBlobLocatorRef::from_locator(&loc);
    assert_eq!(stored.to_locator().unwrap(), loc);

    let u1 = LfsRefUpdateSpec {
        ref_name: "refs/heads/main".into(),
        old_oid: "0".repeat(40),
        new_oid: "1".repeat(40),
    };
    let u2 = LfsRefUpdateSpec {
        ref_name: "refs/heads/feature".into(),
        old_oid: "0".repeat(40),
        new_oid: "2".repeat(40),
    };
    assert_eq!(compute_ref_updates_digest(&[u1.clone(), u2.clone()]), compute_ref_updates_digest(&[u2, u1.clone()]));

    let ref_digest = compute_ref_updates_digest(&[u1]);
    let hold_id = Uuid::new_v4();
    let rcpt_digest = compute_pointer_receipt_digest(&oid, 2048, &stored, &"e5".repeat(32), hold_id);
    let ptr = AttestedLfsPointer {
        git_blob_oid: "f".repeat(40),
        oid_sha256: oid,
        size_bytes: 2048,
        locator: stored,
        backend_identity_hex: "e5".repeat(32),
        hold_id,
        resolution: PointerResolutionSource::RepositoryBlob,
        receipt_digest: rcpt_digest,
    };
    let proof_digest = compute_attestation_digest(
        op_id,
        tenant,
        repo,
        actor,
        "sha1",
        &ref_digest,
        std::slice::from_ref(&ptr),
    );
    let mut att = LfsPointerAttestation {
        attestation_id: Uuid::new_v4(),
        operation_id: op_id,
        tenant_id: tenant,
        repository_id: repo,
        actor_id: actor,
        access_mode: LfsAccessMode::Collaborator { role: LfsCollaboratorRole::Write },
        object_format: "sha1".into(),
        ref_updates_digest: ref_digest,
        pointers: vec![ptr],
        proof_digest,
    };
    att.verify_integrity().unwrap();
    att.pointers[0].size_bytes = 9999;
    assert_eq!(att.verify_integrity().unwrap_err().code, LfsProofRejectCode::AttestationEquivocation);

    let missing_auth = extract_credentials_header(&HeaderMap::new()).unwrap_err();
    assert_eq!(missing_auth.code, LfsProofRejectCode::Unauthenticated);
    assert_eq!(missing_auth.code.http_status().as_u16(), 401);
    let mut hdrs = HeaderMap::new();
    let encoded = BASE64.encode("bob:secret-token-123");
    hdrs.insert(header::AUTHORIZATION, format!("Basic {encoded}").parse().unwrap());
    assert_eq!(extract_credentials_header(&hdrs).unwrap(), ("bob".into(), "secret-token-123".into()));

    assert!(valid_lfs_lock_path("assets/model.bin"));
    assert!(!valid_lfs_lock_path("/abs/model.bin"));
    assert!(!valid_lfs_lock_path("assets/../escape.bin"));
}
