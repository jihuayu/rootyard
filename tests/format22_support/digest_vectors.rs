//! Offline parity vector: production `ArtifactSetDigest::of` over fixed rows.
//!
//! The drill rebuilds the digest from the stored `ref_store_core_pack_artifacts`
//! jsonb columns (`backup_blob_serving169_support.artifact_set_digest`). This
//! vector, printed by the same source-bound fixture binary, pins that rebuild
//! so the two cannot drift. No database or Blob is touched.

use rootyard::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// Rows in the exact shape the Python side reads from jsonb: role, slot,
/// hold/tenant/authority/attempt ids, generation, namespace, sha256, length,
/// provider and backend identity.
pub struct VectorRow {
    pub role: &'static str,
    pub slot: i32,
    pub hold_id: Uuid,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub attempt_id: Uuid,
    pub namespace: &'static str,
    pub sha256: String,
    pub content_length: u64,
    pub provider: &'static str,
    pub backend_identity: String,
}

impl VectorRow {
    fn artifact(&self) -> RegisteredArtifact {
        let role = match self.role {
            "pack" => PackArtifactRole::Pack,
            "idx" => PackArtifactRole::Idx,
            other => panic!("vector role is not pack/idx: {other}"),
        };
        let digest = ContentDigest::parse(self.sha256.clone()).expect("vector sha256");
        let locator = ArtifactLocator::new(
            self.tenant_id,
            self.authority_id,
            self.authority_generation,
            self.attempt_id,
            self.namespace,
            digest.clone(),
            self.content_length,
        )
        .expect("vector locator");
        RegisteredArtifact::new(
            role,
            self.slot,
            self.hold_id,
            locator,
            self.provider,
            self.backend_identity.clone(),
            digest,
            self.content_length,
        )
        .expect("vector artifact")
    }

    fn json(&self) -> Value {
        json!({
            "role": self.role,
            "slot": self.slot,
            "hold_id": self.hold_id.to_string(),
            "tenant_id": self.tenant_id.to_string(),
            "authority_id": self.authority_id.to_string(),
            "authority_generation": self.authority_generation,
            "attempt_id": self.attempt_id.to_string(),
            "namespace": self.namespace,
            "sha256": self.sha256,
            "content_length": self.content_length,
            "provider": self.provider,
            "backend_identity": self.backend_identity,
        })
    }
}

fn hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

pub fn rows() -> Vec<VectorRow> {
    let backend = hex(0xbb);
    vec![
        // The idx row sorts first in hold id, but the pack role still leads the
        // canonical order.
        VectorRow {
            role: "idx",
            slot: 1,
            hold_id: uuid(0x11),
            tenant_id: uuid(0x10),
            authority_id: uuid(0x12),
            authority_generation: 1,
            attempt_id: uuid(0x13),
            namespace: "core-pack",
            sha256: hex(0x21),
            content_length: 5,
            provider: "s3",
            backend_identity: backend.clone(),
        },
        VectorRow {
            role: "pack",
            slot: 0,
            hold_id: uuid(0x31),
            tenant_id: uuid(0x10),
            authority_id: uuid(0x12),
            authority_generation: 2,
            attempt_id: uuid(0x32),
            namespace: "core-pack",
            sha256: hex(0x41),
            content_length: 4096,
            provider: "s3",
            backend_identity: backend,
        },
    ]
}

pub fn vector() -> Value {
    let rows = rows();
    let artifacts = rows.iter().map(VectorRow::artifact).collect::<Vec<_>>();
    let reversed = artifacts.iter().rev().cloned().collect::<Vec<_>>();
    json!({
        "kind": "rootyard/format22-artifact-set-digest-vector",
        "domain": "core-pack-artifact-set-v2",
        "rows": rows.iter().map(VectorRow::json).collect::<Vec<_>>(),
        "digest": ArtifactSetDigest::of(&artifacts).as_hex(),
        "digest_reversed": ArtifactSetDigest::of(&reversed).as_hex(),
    })
}

pub fn run_if_requested(args: &[String]) -> Option<Value> {
    args.iter().any(|arg| arg == "--digest-vector").then(vector)
}
