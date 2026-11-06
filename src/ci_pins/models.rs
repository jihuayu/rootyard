//! CI pin models implementation.
use super::*;
pub(crate) const MAX_PINS: usize = 1024;
pub(super) const NAMESPACE: &str = "refs/rootyard-ci";

pub(crate) fn reserved(name: &str) -> bool {
    name == NAMESPACE || name.starts_with("refs/rootyard-ci/")
}
pub(crate) fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(),40|64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn zero_oid(oid:&str)->String {"0".repeat(oid.len())}
pub(super) fn nonzero_oid(oid:&str)->bool {valid_oid(oid) && oid.bytes().any(|b|b!=b'0')}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub version: u32,
    pub job_id: Uuid,
    pub owner_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub object_format: String,
    pub target_oid: String,
    pub retention_ref: String,
}
impl Intent {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.object_format == if self.target_oid.len()==40 {"sha1"} else {"sha256"}
                && self.storage_generation > 0
                && valid_oid(&self.target_oid)
                && nonzero_oid(&self.target_oid)
                && self.retention_ref == format!("{NAMESPACE}/jobs/{}", self.job_id),
            "invalid CI intent"
        );
        Ok(())
    }
    pub(crate) fn change(&self) -> journal::RefChange {
        journal::RefChange {
            ref_name: self.retention_ref.clone(),
            old_oid: zero_oid(&self.target_oid),
            new_oid: self.target_oid.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRequest {
    pub(super) job_id: Uuid,
    pub(super) target_oid: String,
    pub(super) storage_generation: i64,
}
