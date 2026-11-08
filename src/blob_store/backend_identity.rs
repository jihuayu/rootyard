//! Deterministic, non-secret physical backend identity for the standalone Blob
//! profile.
//!
//! A locator names *what* content is expected at a logical path; it does not
//! name *where* that path is physically mapped. A ledger that captures only the
//! provider name plus the logical locator fields could otherwise accept an
//! upload intent minted against one store and hand it to a different store
//! (another provider, or the same S3 provider with another account, endpoint,
//! bucket or root prefix) while a hold still protects the wrong object.
//! [`BlobBackendIdentity`] closes that gap.
//!
//! The identity is a SHA-256 over one canonical, domain-separated descriptor
//! built from the **actually opened** profile (never from a caller-supplied
//! artifact scope, authority id or generation, which stay logical path scope):
//!
//! * domain/version tag;
//! * effective provider (`s3`/`azblob`);
//! * endpoint kind and origin, or `provider-default` plus the default scheme;
//! * bucket/container;
//! * root prefix exactly as handed to the operator;
//! * region when the provider profile carries one;
//! * a stable account identity: the S3 access key id hashed with its own
//!   SHA-256, or the Azure account name.
//!
//! It never contains the secret access key, the Azure account key, a session
//! token or any other credential material, and it is not produced by network
//! discovery, an ETag or a provider listing. Fields are length-prefixed so no
//! two different descriptors can serialize identically.
//!
//! Normalization is restricted to equivalences the URL parser itself
//! guarantees (scheme/host case and default ports in an explicit origin). Root
//! case, trailing segments and region spelling are preserved: this layer does
//! not claim equivalences the provider does not guarantee.
//!
//! Liveness and credential rotation: the account identity follows the S3 access
//! key id, not the secret. Rotating only the secret therefore keeps the same
//! physical identity (correct: the backend mapping did not change), while a
//! different access key id, account, endpoint, bucket or root yields a different
//! identity. An old grant whose identity no longer matches is conservatively
//! rejected as [`BlobError::ForeignBackend`](super::BlobError::ForeignBackend)
//! before any source or provider IO; the ledger must then treat that grant as
//! dead rather than retry it against the new mapping.
//!
//! The type is read-only data. Its only constructors are private to the
//! `blob_store` subtree, so parsing a stored hex string can never mint a proof:
//! a holder of stored bytes can compare them with
//! [`BlobBackendIdentity::as_hex`], but only `BlobStore::open`, `new_upload` and
//! receipt minting bind an identity to a real opened store. There is no
//! `Deserialize`, builder or public constructor.

use std::fmt;

use sha2::{Digest, Sha256};

use super::config::BlobProfile;

/// Domain/version tag mixed into every production backend identity digest.
const BACKEND_IDENTITY_DOMAIN: &str = "rootyard.blob.backend-identity.v1";
/// Domain tag for the `cfg(test)` in-process memory realm. A memory operator is
/// not an S3/Azure realm, so it gets its own unique identity instead of
/// pretending to be the synthetic profile it was built from.
#[cfg(test)]
const MEMORY_REALM_DOMAIN: &str = "rootyard.blob.backend-identity.memory-test.v1";

const IDENTITY_HEX_LEN: usize = 64;

/// Immutable physical backend identity. Equality is data equality over the
/// canonical digest; the digest is safe to persist, but a stored copy is only a
/// claim until it is compared with a live store's identity.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobBackendIdentity {
    hex: String,
}

impl BlobBackendIdentity {
    /// The canonical lowercase SHA-256 hex digest. This is the only value a
    /// ledger or checkpoint should persist; it is not a credential and cannot
    /// be turned back into write authority.
    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    /// Build the identity from the profile whose operator was actually opened.
    /// `pub(super)` keeps the mint inside the `blob_store` subtree.
    pub(super) fn from_profile(profile: &BlobProfile) -> Self {
        let mut canonical = String::new();
        push_field(&mut canonical, "domain", BACKEND_IDENTITY_DOMAIN);
        push_field(&mut canonical, "provider", profile.provider().as_str());
        match profile.endpoint() {
            Some(endpoint) => {
                push_field(&mut canonical, "endpoint_kind", "explicit-origin");
                push_field(&mut canonical, "endpoint_origin", &endpoint.origin().ascii_serialization());
            }
            None => {
                // The provider's own default mapping is used; record that fact
                // (and the fixed TLS default) instead of inventing an origin.
                push_field(&mut canonical, "endpoint_kind", "provider-default");
                push_field(&mut canonical, "endpoint_origin", "");
            }
        }
        // Provider defaults are HTTPS. A loopback HTTP fixture always carries an
        // explicit origin, whose scheme the origin string already includes.
        push_field(&mut canonical, "default_scheme", "https");
        push_field(&mut canonical, "bucket", profile.bucket());
        push_field(&mut canonical, "root", profile.root());
        push_field(&mut canonical, "region", profile.region().unwrap_or(""));
        push_field(&mut canonical, "account", &profile.credentials().account_identity());
        Self::from_canonical(&canonical)
    }

    /// Identity for one `cfg(test)` in-process memory operator. Each store gets
    /// a fresh realm id, so two unrelated memory stores are honestly distinct
    /// and can never be mistaken for the same physical backend.
    #[cfg(test)]
    pub(super) fn memory_test_realm() -> Self {
        let mut canonical = String::new();
        push_field(&mut canonical, "domain", MEMORY_REALM_DOMAIN);
        push_field(&mut canonical, "provider", "memory-test");
        push_field(&mut canonical, "realm", &uuid::Uuid::new_v4().to_string());
        Self::from_canonical(&canonical)
    }

    fn from_canonical(canonical: &str) -> Self {
        let hex = hex::encode(Sha256::digest(canonical.as_bytes()));
        debug_assert_eq!(hex.len(), IDENTITY_HEX_LEN);
        debug_assert!(hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        Self { hex }
    }
}

impl fmt::Debug for BlobBackendIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The digest is non-secret, but Debug stays fixed and opaque so no log
        // site can accidentally publish a stable cross-store correlator.
        f.debug_struct("BlobBackendIdentity").field("digest", &"<redacted>").finish()
    }
}

/// Length-prefixed field: `name=<len>:<value>\n`. This is unambiguous even for
/// values that contain field separators or newlines.
fn push_field(buffer: &mut String, name: &str, value: &str) {
    buffer.push_str(name);
    buffer.push('=');
    buffer.push_str(&value.len().to_string());
    buffer.push(':');
    buffer.push_str(value);
    buffer.push('\n');
}
