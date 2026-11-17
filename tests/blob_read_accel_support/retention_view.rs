//! Private view projection for the retention diagnostic.
//!
//! This moves the existing projection block intact so the parent retention
//! module stays below its line budget. Only finite classifier labels and
//! numeric metrics are stored.

use rootyard::blob_store::{
    BlobLocator,
    read_accel::{ReadAccelManifest, ReadAccelMaterializeMetrics, ReadAccelSidecarStatus},
};

use super::{
    DetailClass, KindClass, StageClass, StatusClass, cached_fallback_detail_class, cached_fallback_kind_label,
    cached_fallback_stage_label,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct ViewProjection {
    pub(super) status: StatusClass,
    pub(super) kind: KindClass,
    pub(super) stage: StageClass,
    pub(super) detail: DetailClass,
    pub(super) sidecars_applied: u64,
    pub(super) sidecar_get_attempts: u64,
    pub(super) sidecar_get_bytes: u64,
    pub(super) quarantined: u64,
    pub(super) artifacts: Option<u64>,
}

pub(super) fn project_view(
    status: &ReadAccelSidecarStatus,
    metrics: &ReadAccelMaterializeMetrics,
    manifest: &ReadAccelManifest,
    manifest_locator: &BlobLocator,
) -> ViewProjection {
    let stage = match status {
        ReadAccelSidecarStatus::Applied => StageClass::Applied,
        ReadAccelSidecarStatus::Disabled => StageClass::Disabled,
        ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(_) => {
            StageClass::from_label(cached_fallback_stage_label(status, metrics, manifest, manifest_locator, true))
        }
    };
    ViewProjection {
        status: StatusClass::from_status(status),
        kind: KindClass::from_label(cached_fallback_kind_label(status)),
        stage,
        detail: DetailClass::from_label(cached_fallback_detail_class(status)),
        sidecars_applied: metrics.sidecars_applied as u64,
        sidecar_get_attempts: metrics.sidecar_get_attempts,
        sidecar_get_bytes: metrics.sidecar_get_bytes,
        quarantined: metrics.quarantined_sidecar_paths.len() as u64,
        artifacts: Some(manifest.artifacts.len() as u64),
    }
}
