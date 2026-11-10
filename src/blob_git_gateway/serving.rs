//! The one shared serving authority surface used by the gateway.
//!
//! The gateway never calls legacy Pando/GitFS and never reads a data-directory
//! `config`/`objects` copy as authority. Repository aliases, actor scope, gate
//! and physical Blob backend binding come from the shared core worker.
pub(super) use crate::ref_store::serving::{ProvisionRequest, ServingRepository, lookup, provision};
