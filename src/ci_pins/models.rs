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
pub(crate) fn valid_format(format:&str)->bool {matches!(format,"sha1"|"sha256")}
pub(crate) fn valid_oid_for_format(oid:&str,format:&str)->bool {
    (match format {
        "sha1" => oid.len()==40,
        "sha256" => oid.len()==64,
        _ => return false,
    }) && valid_oid(oid)
}
pub(super) fn zero_oid(oid:&str)->String {"0".repeat(oid.len())}
pub(super) fn zero_oid_for_format(format:&str)->Option<String> {
    match format { "sha1" => Some("0".repeat(40)), "sha256" => Some("0".repeat(64)), _ => None }
}
pub(super) fn nonzero_oid(oid:&str)->bool {valid_oid(oid) && oid.bytes().any(|b|b!=b'0')}
pub(super) fn nonzero_oid_for_format(oid:&str,format:&str)->bool {
    valid_oid_for_format(oid,format) && oid.bytes().any(|b|b!=b'0')
}
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
                && valid_format(&self.object_format)
                && nonzero_oid_for_format(&self.target_oid,&self.object_format)
                && zero_oid_for_format(&self.object_format)
                    .is_some_and(|zero| self.target_oid != zero)
                && self.storage_generation > 0
                && self.retention_ref == format!("{NAMESPACE}/jobs/{}", self.job_id),
            "invalid CI intent"
        );
        Ok(())
    }
    pub(crate) fn change(&self) -> journal::RefChange {
        journal::RefChange {
            ref_name: self.retention_ref.clone(),
            old_oid: zero_oid_for_format(&self.object_format)
                .unwrap_or_else(|| zero_oid(&self.target_oid)),
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
