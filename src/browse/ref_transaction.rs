//! Native ref-transaction request models and wire-format construction.
use crate::Error;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use super::models::{is_zero_oid, valid_oid, valid_public_ref};

pub const MAX_REF_UPDATES: usize = 128;

fn default_atomic() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefTransactionRequest {
    pub storage_generation: Option<i64>,
    #[serde(default = "default_atomic")]
    pub atomic: bool,
    pub updates: Vec<RefUpdateInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefUpdateInput {
    #[serde(alias = "ref")]
    pub ref_name: String,
    #[serde(default, alias = "expectedOldOid")]
    pub old_oid: Option<String>,
    #[serde(default, alias = "newOid")]
    pub new_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppliedRefUpdate {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefTransactionResponse {
    pub operation_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub sequence: i64,
    pub atomic: bool,
    pub updates: Vec<AppliedRefUpdate>,
}

impl RefTransactionRequest {
    pub fn normalize(&self) -> Result<Vec<AppliedRefUpdate>, Error> {
        self.normalize_with_proposal_pin(None)
    }

    pub(crate) fn normalize_with_proposal_pin(
        &self,
        proposal_pin: Option<Uuid>,
    ) -> Result<Vec<AppliedRefUpdate>, Error> {
        if !self.atomic {
            return Err(Error(
                StatusCode::BAD_REQUEST,
                "only atomic ref transactions are supported",
            ));
        }
        if self.updates.is_empty() || self.updates.len() > MAX_REF_UPDATES {
            return Err(Error::bad_request());
        }
        if self.storage_generation.is_some_and(|g| g <= 0) {
            return Err(Error::bad_request());
        }
        let mut tx_format = None;
        for u in &self.updates {
            for candidate in [&u.old_oid, &u.new_oid].into_iter().flatten() {
                let fmt = crate::browse::object_format::detect_oid_format(candidate)
                    .ok_or_else(Error::bad_request)?;
                if let Some(prev) = tx_format {
                    if prev != fmt {
                        return Err(Error(
                            StatusCode::CONFLICT,
                            "mixed object formats in ref transaction are forbidden",
                        ));
                    }
                } else {
                    tx_format = Some(fmt);
                }
            }
        }
        let default_zero = tx_format
            .unwrap_or(crate::browse::object_format::ObjectFormat::Sha1)
            .zero_oid();
        let mut seen = HashSet::with_capacity(self.updates.len());
        let mut out = Vec::with_capacity(self.updates.len());
        for u in &self.updates {
            let trusted_pin = proposal_pin
                .is_some_and(|id| u.ref_name == crate::namespace_service::proposal_pin_ref(id));
            if !valid_public_ref(&u.ref_name) && !trusted_pin {
                return Err(Error::bad_request());
            }
            if !seen.insert(u.ref_name.clone()) {
                return Err(Error::bad_request());
            }
            let old_oid = u.old_oid.clone().unwrap_or_else(|| default_zero.to_owned());
            let new_oid = u.new_oid.clone().unwrap_or_else(|| default_zero.to_owned());
            if !valid_oid(&old_oid) || !valid_oid(&new_oid) || old_oid == new_oid {
                return Err(Error::bad_request());
            }
            if trusted_pin && (!is_zero_oid(&old_oid) || is_zero_oid(&new_oid)) {
                return Err(Error::bad_request());
            }
            out.push(AppliedRefUpdate {
                ref_name: u.ref_name.clone(),
                old_oid,
                new_oid,
            });
        }
        if let Some(id) = proposal_pin
            && (out.len() != 1 || out[0].ref_name != crate::namespace_service::proposal_pin_ref(id)) {
                return Err(Error::bad_request());
            }
        // Check directory/file prefix conflicts among target refs that will exist after the transaction.
        for (i, a) in out.iter().enumerate() {
            if is_zero_oid(&a.new_oid) {
                continue;
            }
            let prefix = format!("{}/", a.ref_name);
            for (j, b) in out.iter().enumerate() {
                if i != j && !is_zero_oid(&b.new_oid) && b.ref_name.starts_with(&prefix) {
                    return Err(Error(
                        StatusCode::CONFLICT,
                        "reference directory/file prefix conflict",
                    ));
                }
            }
        }
        Ok(out)
    }
}

pub fn build_update_ref_stdin_payload(updates: &[AppliedRefUpdate]) -> Vec<u8> {
    let mut sorted = updates.to_vec();
    sorted.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    let mut buf = Vec::with_capacity(64 + sorted.len() * 128);
    buf.extend_from_slice(b"start\0");
    for u in &sorted {
        buf.extend_from_slice(b"update ");
        buf.extend_from_slice(u.ref_name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(u.new_oid.as_bytes());
        buf.push(0);
        buf.extend_from_slice(u.old_oid.as_bytes());
        buf.push(0);
    }
    buf.extend_from_slice(b"prepare\0commit\0");
    buf
}
