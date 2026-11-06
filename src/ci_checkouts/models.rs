//! Immutable checkout plan and mirror audience.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u32,
    pub job_id: Uuid,
    pub owner_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub object_format: String,
    pub target_oid: String,
    pub source_receipt_sha256: String,
    pub mirror_audience: Uuid,
    pub expires_unix: i64,
    #[serde(default)]
    pub dependencies: dependencies::Manifest,
}
pub(crate) fn audience() -> Result<Uuid, Error> {
    std::env::var("ROOTYARD_CI_MIRROR_AUDIENCE")
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CI mirror audience is not configured",
        ))
}
