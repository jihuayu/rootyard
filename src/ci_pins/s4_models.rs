//! `pg_refstore` (S4) CI retention models and their pure validation.
//!
//! Nothing in this module performs IO. Every value here is either a bounded
//! request body, a durable row projection or an opaque closure-grant value that
//! is re-validated against the live database before it authorizes one byte.
//!
//! A [`S4ClosureGrant`] is data, never a capability: the data plane re-reads the
//! `closure_grants`, `ci_pins`, `ci_checkout_jobs` and `ref_store_core_root_heads`
//! rows on every request and at every stream interval, so a persisted copy of
//! this value authorizes nothing on its own.
use crate::Error;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Dedicated coordination schema. S4 never adds a table to `public`, because the
/// migration-151 backup catalog pins the exact `public` table set.
pub(crate) const SCHEMA: &str = "s4_ci_retention";
/// Narrow, one-job checkout credential prefix.
pub(crate) const JOB_PREFIX: &str = "ryj_";
/// Maximum closure-grant lifetime accepted by the producer, in seconds.
pub(crate) const MAX_GRANT_TTL: i64 = 3_600;
/// Version of every canonical S4 JSON document.
pub(crate) const VERSION: u32 = 1;

/// One durable closure grant as stored in `s4_ci_retention.closure_grants`.
///
/// The JSON body is the only input the data plane deserializes, so it denies
/// unknown fields and re-proves every bound before use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S4ClosureGrant {
    pub version: u32,
    pub job_id: Uuid,
    pub repository_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub storage_generation: i64,
    pub authority_epoch: i64,
    pub object_format: String,
    pub target_oid: String,
    pub retention_root_id: Uuid,
    pub pack_set_digest: String,
    pub mirror_audience: Uuid,
    pub expires_unix: i64,
}

/// Producer request body for `POST /api/repos/{owner}/{name}/ci-pins`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S4PinBody {
    pub job_id: Uuid,
    pub target_oid: String,
    pub storage_generation: i64,
}

/// Empty-or-exact release body. Every field is optional so `DELETE` with no body
/// and an explicit idempotent replay share one type.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S4ReleaseBody {
    #[serde(default)]
    pub job_id: Option<Uuid>,
    #[serde(default)]
    pub target_oid: Option<String>,
    #[serde(default)]
    pub storage_generation: Option<i64>,
}

/// One `ci_pins` row projection returned to the caller.
#[derive(Clone, Debug, Serialize)]
pub struct S4PinView {
    pub job_id: Uuid,
    pub repository_id: Uuid,
    pub object_format: String,
    pub target_oid: String,
    pub storage_generation: i64,
    pub retention_root_id: Uuid,
    pub register_digest: String,
    pub pack_set_digest: String,
    pub state: &'static str,
}

/// Everything one data-plane request must prove about a stored grant.
#[derive(Clone, Copy, Debug)]
pub struct GrantExpectation<'a> {
    pub repository_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub storage_generation: i64,
    pub authority_epoch: i64,
    pub mirror_audience: Uuid,
    pub target_oid: &'a str,
    pub now_unix: i64,
}

/// A lowercase hex string of exactly `len` digits.
pub(crate) fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The exact object-id width of a supported `git` object format.
pub(crate) fn oid_width(format: &str) -> Option<usize> {
    match format {
        "sha1" => Some(40),
        "sha256" => Some(64),
        _ => None,
    }
}

/// Accept only a fixed, non-zero, lowercase object id of the repository's exact
/// width. Branch names, symbolic refs, `HEAD`, short ids and upper-case hex are
/// all refused here, before any durable read.
pub(crate) fn fixed_oid<'a>(oid: &'a str, format: &str) -> Result<&'a str, Error> {
    let width = oid_width(format).ok_or_else(Error::bad_request)?;
    if !is_lower_hex(oid, width) || oid.bytes().all(|byte| byte == b'0') {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "target must be a fixed non-zero object id of the repository object format",
        ));
    }
    Ok(oid)
}

/// A canonical opaque credential digest (lowercase sha256 hex).
pub(crate) fn is_digest_hex(value: &str) -> bool {
    is_lower_hex(value, 64)
}

/// Trusted, caller-fixed identities of one grant that is about to be issued.
/// Grouping them keeps the constructor within the seven-argument bound.
pub(crate) struct NewGrant<'a> {
    pub job_id: Uuid,
    pub repository_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub storage_generation: i64,
    pub authority_epoch: i64,
    pub object_format: &'a str,
    pub target_oid: &'a str,
    pub retention_root_id: Uuid,
    pub pack_set_digest: &'a str,
    pub mirror_audience: Uuid,
    pub expires_unix: i64,
}

impl S4ClosureGrant {
    /// Build the canonical body for one issued grant. All values are already
    /// trusted, caller-fixed identities; this only re-checks their shape.
    pub(crate) fn new(input: NewGrant<'_>) -> Result<Self, Error> {
        let grant = Self {
            version: VERSION,
            job_id: input.job_id,
            repository_id: input.repository_id,
            owner_tenant_id: input.owner_tenant_id,
            storage_generation: input.storage_generation,
            authority_epoch: input.authority_epoch,
            object_format: input.object_format.to_owned(),
            target_oid: input.target_oid.to_owned(),
            retention_root_id: input.retention_root_id,
            pack_set_digest: input.pack_set_digest.to_owned(),
            mirror_audience: input.mirror_audience,
            expires_unix: input.expires_unix,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Structural validation. This never reads the database, so it can only
    /// refuse malformed values; authority is always a separate live read.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION
            || self.job_id.is_nil()
            || self.repository_id.is_nil()
            || self.owner_tenant_id.is_nil()
            || self.retention_root_id.is_nil()
            || self.mirror_audience.is_nil()
            || self.storage_generation <= 0
            || self.authority_epoch <= 0
            || self.expires_unix <= 0
            || oid_width(&self.object_format).is_none()
            || !is_digest_hex(&self.pack_set_digest)
        {
            return Err(Error::internal("stored closure grant is malformed"));
        }
        fixed_oid(&self.target_oid, &self.object_format)?;
        Ok(())
    }

    /// Re-prove this stored grant against the live repository/gate facts and the
    /// exact requested object id. A mismatch is a non-disclosing refusal: the
    /// data plane must never reveal why an otherwise well-formed token failed.
    pub(crate) fn authorize(&self, expected: &GrantExpectation<'_>) -> Result<(), Error> {
        self.validate().map_err(|_| Error::unauthorized())?;
        if self.repository_id != expected.repository_id
            || self.owner_tenant_id != expected.owner_tenant_id
            || self.storage_generation != expected.storage_generation
            || self.authority_epoch != expected.authority_epoch
            || self.mirror_audience != expected.mirror_audience
            || self.target_oid != expected.target_oid
            || self.expires_unix <= expected.now_unix
        {
            return Err(Error::unauthorized());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> S4ClosureGrant {
        let target = "a".repeat(40);
        let packs = "b".repeat(64);
        S4ClosureGrant::new(NewGrant {
            job_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            owner_tenant_id: Uuid::new_v4(),
            storage_generation: 7,
            authority_epoch: 3,
            object_format: "sha1",
            target_oid: &target,
            retention_root_id: Uuid::new_v4(),
            pack_set_digest: &packs,
            mirror_audience: Uuid::new_v4(),
            expires_unix: 1_700_000_600,
        })
        .expect("valid grant")
    }

    fn expectation(grant: &S4ClosureGrant) -> GrantExpectation<'_> {
        GrantExpectation {
            repository_id: grant.repository_id,
            owner_tenant_id: grant.owner_tenant_id,
            storage_generation: grant.storage_generation,
            authority_epoch: grant.authority_epoch,
            mirror_audience: grant.mirror_audience,
            target_oid: &grant.target_oid,
            now_unix: 1_700_000_000,
        }
    }

    #[test]
    fn fixed_oid_rejects_branch_names_and_wrong_widths() {
        for refused in [
            "main",
            "refs/heads/main",
            "HEAD",
            &"A".repeat(40),
            &"0".repeat(40),
            &"a".repeat(39),
            &"a".repeat(64),
        ] {
            assert!(fixed_oid(refused, "sha1").is_err(), "accepted {refused}");
        }
        assert!(fixed_oid(&"a".repeat(40), "sha1").is_ok());
        assert!(fixed_oid(&"0".repeat(64), "sha256").is_err());
        assert!(fixed_oid(&"a".repeat(64), "sha256").is_ok());
        assert!(fixed_oid(&"a".repeat(40), "md5").is_err());
    }

    #[test]
    fn a_matching_grant_authorizes_one_exact_job() {
        let grant = grant();
        assert!(grant.authorize(&expectation(&grant)).is_ok());
    }

    #[test]
    fn tampered_target_audience_owner_or_expiry_is_refused() {
        let grant = grant();
        let tampered = "c".repeat(40);
        let mut expected = expectation(&grant);
        expected.target_oid = &tampered;
        assert!(grant.authorize(&expected).is_err());

        let mut expected = expectation(&grant);
        expected.mirror_audience = Uuid::new_v4();
        assert!(grant.authorize(&expected).is_err());

        let mut expected = expectation(&grant);
        expected.owner_tenant_id = Uuid::new_v4();
        assert!(grant.authorize(&expected).is_err());

        let mut expected = expectation(&grant);
        expected.now_unix = grant.expires_unix;
        assert!(grant.authorize(&expected).is_err());

        let mut expected = expectation(&grant);
        expected.storage_generation = grant.storage_generation + 1;
        assert!(grant.authorize(&expected).is_err());

        let mut expected = expectation(&grant);
        expected.authority_epoch = grant.authority_epoch + 1;
        assert!(grant.authorize(&expected).is_err());
    }

    #[test]
    fn grant_body_denies_unknown_fields_and_bad_shapes() {
        let mut value = serde_json::to_value(grant()).expect("grant serializes");
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<S4ClosureGrant>(value).is_err());

        let mut broken = grant();
        broken.target_oid = "refs/heads/main".into();
        assert!(broken.validate().is_err());

        let mut broken = grant();
        broken.pack_set_digest = "B".repeat(64);
        assert!(broken.validate().is_err());
    }
}
