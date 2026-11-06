//! Production Pando storage boundary. Identity and publication policy remain
//! owned by the main authenticated gateway, never the synthetic Pando lab.
#[path = "pando_gateway/backup.rs"]
pub mod backup;
#[path = "pando_gateway/pack_store.rs"]
pub mod pack_store;
#[path = "pando_gateway/prepare.rs"]
pub mod prepare;
#[path = "pando_gateway/publish.rs"]
pub mod publish;
#[path = "pando_gateway/snapshot.rs"]
pub mod snapshot;
pub mod transition;
