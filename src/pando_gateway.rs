//! Production Pando storage boundary. Identity and publication policy remain
//! owned by the main authenticated gateway, never the synthetic Pando lab.
#[path = "pando_gateway/authority_cli.rs"]
pub mod authority_cli;
#[path = "pando_gateway/backup.rs"]
pub mod backup;
#[path = "pando_gateway/pack_store.rs"]
pub mod pack_store;
#[path = "pando_gateway/pitr_fence.rs"]
pub mod pitr_fence;
#[path = "pando_gateway/pitr_markers.rs"]
pub mod pitr_markers;
#[path = "pando_gateway/pitr_proof_model.rs"]
pub mod pitr_proof_model;
#[path = "pando_gateway/prepare.rs"]
pub mod prepare;
#[path = "pando_gateway/publish.rs"]
pub mod publish;
#[path = "pando_gateway/retention.rs"]
pub mod retention;
#[path = "pando_gateway/retention_roots.rs"]
pub mod retention_roots;
#[path = "pando_gateway/snapshot.rs"]
pub mod snapshot;
pub mod transition;
