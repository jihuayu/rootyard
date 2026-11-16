//! Versioned cryptographically signed remote authorization grants (`#152`).
//!
//! Minted ONLY after confirming committed PostgreSQL `ref_store_publication_decisions`,
//! `ref_store_decision_refs`, `ref_store_decision_dependencies`, and `OPEN` rows in
//! `ref_store_decision_scopes`. Verifies domain-separated HMAC-SHA256, non-retired `key_id`,
//! service mTLS identity, realm fields, all 6+ decision digests, and monotonic `logical_tick`
//! without reading wall clocks inside Raft `apply`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::state_machine::{
    InstallDecisionCommand, InstallScopedDecisionCommand, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict,
    validate_scope_kind,
};

pub(crate) const GRANT_FORMAT_VERSION: u8 = 1;
const MAC_LEN: usize = 32;
const GRANT_TRANSCRIPT_DOMAIN: &[u8] = b"rootyard/ref-store/remote-decision-grant/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteAuthzGrantError {
    InvalidInput(String),
    PgDatabase(String),
    DecisionNotCommittedInPg(Uuid),
    DecisionNotOpenInPg { decision_id: Uuid, state: String },
    DecisionCancelledInPg(Uuid),
    ScopeClosingOrMissingInPg { scope_kind: String, scope_id: Uuid, observed_state: Option<String> },
    ForgedGrantSignature,
    RetiredSigningKey(u8),
    UnknownSigningKey(u8),
    ServiceIdentityMismatch { expected: String, actual: String },
    RealmMismatch(&'static str),
    GrantExpired { not_after_tick: u64, current_tick: u64 },
}

impl fmt::Display for RemoteAuthzGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid remote authz grant input: {msg}"),
            Self::PgDatabase(msg) => write!(f, "remote authz grant PG query failed: {msg}"),
            Self::DecisionNotCommittedInPg(id) => write!(f, "decision {id} is not committed in PG"),
            Self::DecisionNotOpenInPg { decision_id, state } => {
                write!(f, "decision {decision_id} in PG is {state}, not OPEN")
            }
            Self::DecisionCancelledInPg(id) => write!(f, "decision operation {id} has PG cancel tombstone"),
            Self::ScopeClosingOrMissingInPg { scope_kind, scope_id, observed_state } => {
                write!(f, "dependency scope ({scope_kind}, {scope_id}) state {observed_state:?} blocks grant mint")
            }
            Self::ForgedGrantSignature => f.write_str("signed decision grant MAC verification failed"),
            Self::RetiredSigningKey(id) => write!(f, "decision grant signing key_id {id} is retired"),
            Self::UnknownSigningKey(id) => write!(f, "unknown decision grant signing key_id {id}"),
            Self::ServiceIdentityMismatch { expected, actual } => {
                write!(f, "grant service mTLS identity {actual:?} does not match {expected:?}")
            }
            Self::RealmMismatch(why) => write!(f, "decision grant realm mismatch: {why}"),
            Self::GrantExpired { not_after_tick, current_tick } => {
                write!(f, "decision grant expired at logical_tick {not_after_tick} < {current_tick}")
            }
        }
    }
}

impl std::error::Error for RemoteAuthzGrantError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMtlsIdentity {
    pub san_identity: String,
    pub issuer_id: Uuid,
}

impl ServiceMtlsIdentity {
    pub fn validate(&self) -> Result<(), RemoteAuthzGrantError> {
        let s = self.san_identity.as_str();
        if self.issuer_id.is_nil()
            || s.is_empty()
            || s.len() > 128
            || s.contains('*')
            || s.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || !(s.starts_with("raft-bridge-") || s.starts_with("raft-client-tenant-"))
        {
            return Err(RemoteAuthzGrantError::InvalidInput(
                "service_mtls_identity must bind explicit non-wildcard bridge/tenant SAN and non-nil issuer_id".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantExpectedRealm {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub group_id: i64,
    pub group_epoch: i64,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
}

impl GrantExpectedRealm {
    pub fn validate(&self) -> Result<(), RemoteAuthzGrantError> {
        if self.tenant_id.is_nil()
            || self.repository_id.is_nil()
            || self.history_incarnation.is_nil()
            || self.group_id < 0
            || self.group_epoch <= 0
            || self.authority_epoch <= 0
        {
            return Err(RemoteAuthzGrantError::InvalidInput("invalid grant realm fields".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDecisionGrantPayload {
    pub format_version: u8,
    pub key_id: u8,
    pub issuer_id: Uuid,
    pub service_mtls_identity: String,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub group_id: i64,
    pub group_epoch: i64,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub authz_epoch: i64,
    pub base_revision: i64,
    pub kind: WireDecisionKind,
    pub not_after_tick: u64,
    pub command_digest: String,
    pub selection_digest: String,
    pub policy_digest: String,
    pub facts_digest: String,
    pub authz_digest: String,
    pub dependencies_digest: String,
    pub packs_digest: String,
    pub hold_receipts_digest: String,
    pub captured_oid_digest: String,
    pub base_gate_digest: String,
    pub required_holds: Vec<Uuid>,
    pub verdicts: Vec<WireDecisionVerdict>,
    pub scope_dependencies: Vec<WireDecisionScopeDep>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDecisionGrant {
    pub payload: SignedDecisionGrantPayload,
    pub mac_b64: String,
}

pub struct DecisionGrantKeyring {
    keys: BTreeMap<u8, Zeroizing<[u8; 32]>>,
    retired: BTreeSet<u8>,
    current_key_id: u8,
}

impl fmt::Debug for DecisionGrantKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionGrantKeyring")
            .field("active_keys", &self.keys.keys().collect::<Vec<_>>())
            .field("retired_keys", &self.retired)
            .field("current_key_id", &self.current_key_id)
            .finish()
    }
}

impl DecisionGrantKeyring {
    pub fn new(
        keys: impl IntoIterator<Item = (u8, Zeroizing<[u8; 32]>)>,
        current_key_id: u8,
        retired: BTreeSet<u8>,
    ) -> Result<Self, RemoteAuthzGrantError> {
        let mut map = BTreeMap::new();
        for (id, sec) in keys {
            if map.insert(id, sec).is_some() {
                return Err(RemoteAuthzGrantError::InvalidInput(format!("duplicate signing key_id {id}")));
            }
        }
        if !map.contains_key(&current_key_id) {
            return Err(RemoteAuthzGrantError::InvalidInput("missing current signing key_id in keyring".into()));
        }
        if retired.contains(&current_key_id) {
            return Err(RemoteAuthzGrantError::InvalidInput("current signing key_id cannot be retired".into()));
        }
        Ok(Self { keys: map, retired, current_key_id })
    }

    pub fn current_key_id(&self) -> u8 {
        self.current_key_id
    }

    pub fn rotate_key(
        &mut self,
        new_key_id: u8,
        secret: Zeroizing<[u8; 32]>,
        retire_previous: bool,
    ) -> Result<(), RemoteAuthzGrantError> {
        if self.retired.contains(&new_key_id) {
            return Err(RemoteAuthzGrantError::RetiredSigningKey(new_key_id));
        }
        let prev = self.current_key_id;
        self.keys.insert(new_key_id, secret);
        self.current_key_id = new_key_id;
        if retire_previous && prev != new_key_id {
            self.retired.insert(prev);
        }
        Ok(())
    }

    pub fn retire_key(&mut self, key_id: u8) -> Result<(), RemoteAuthzGrantError> {
        if key_id == self.current_key_id {
            return Err(RemoteAuthzGrantError::InvalidInput("cannot retire active current_key_id".into()));
        }
        self.retired.insert(key_id);
        Ok(())
    }

    pub fn sign(&self, mut payload: SignedDecisionGrantPayload) -> Result<SignedDecisionGrant, RemoteAuthzGrantError> {
        payload.format_version = GRANT_FORMAT_VERSION;
        payload.key_id = self.current_key_id;
        validate_payload_syntax(&payload)?;
        let secret =
            self.keys.get(&self.current_key_id).ok_or(RemoteAuthzGrantError::UnknownSigningKey(self.current_key_id))?;
        let transcript = canonical_grant_transcript(&payload)?;
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &secret[..]), &transcript);
        Ok(SignedDecisionGrant { payload, mac_b64: URL_SAFE_NO_PAD.encode(tag.as_ref()) })
    }
}

pub use super::remote_authz_pg::{PgGrantMintRequest, mint_signed_decision_grant_from_pg};

/// Verifies grant HMAC signature, non-retired key_id, service mTLS SAN binding, realm equality,
/// logical expiry, and converts cleanly into an ordered `InstallScopedDecisionCommand`.
pub fn verify_signed_decision_grant(
    verifier: &DecisionGrantKeyring,
    grant: &SignedDecisionGrant,
    expected_realm: &GrantExpectedRealm,
    expected_service_san: &str,
    current_logical_tick: u64,
) -> Result<InstallScopedDecisionCommand, RemoteAuthzGrantError> {
    expected_realm.validate()?;
    let p = &grant.payload;
    if p.format_version != GRANT_FORMAT_VERSION {
        return Err(RemoteAuthzGrantError::InvalidInput(format!("unsupported grant version {}", p.format_version)));
    }
    validate_payload_syntax(p)?;
    if verifier.retired.contains(&p.key_id) {
        return Err(RemoteAuthzGrantError::RetiredSigningKey(p.key_id));
    }
    let key = verifier.keys.get(&p.key_id).ok_or(RemoteAuthzGrantError::UnknownSigningKey(p.key_id))?;

    let mut mac = [0u8; MAC_LEN];
    if URL_SAFE_NO_PAD.decode_slice(&grant.mac_b64, &mut mac).ok() != Some(MAC_LEN) {
        return Err(RemoteAuthzGrantError::ForgedGrantSignature);
    }
    let transcript = canonical_grant_transcript(p)?;
    if hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &key[..]), &transcript, &mac).is_err() {
        return Err(RemoteAuthzGrantError::ForgedGrantSignature);
    }
    if p.service_mtls_identity != expected_service_san {
        return Err(RemoteAuthzGrantError::ServiceIdentityMismatch {
            expected: expected_service_san.to_owned(),
            actual: p.service_mtls_identity.clone(),
        });
    }
    if p.tenant_id != expected_realm.tenant_id
        || p.repository_id != expected_realm.repository_id
        || p.group_id != expected_realm.group_id
        || p.group_epoch != expected_realm.group_epoch
        || p.history_incarnation != expected_realm.history_incarnation
        || p.authority_epoch != expected_realm.authority_epoch
    {
        return Err(RemoteAuthzGrantError::RealmMismatch("signed grant target realm mismatch"));
    }
    if p.not_after_tick <= current_logical_tick {
        return Err(RemoteAuthzGrantError::GrantExpired {
            not_after_tick: p.not_after_tick,
            current_tick: current_logical_tick,
        });
    }

    Ok(InstallScopedDecisionCommand {
        decision: InstallDecisionCommand {
            decision_id: p.decision_id,
            repository_id: p.repository_id,
            tenant_id: p.tenant_id,
            actor_id: p.actor_id,
            operation_id: p.operation_id,
            kind: p.kind,
            base_revision: p.base_revision,
            command_digest: p.command_digest.clone(),
            selection_digest: p.selection_digest.clone(),
            policy_digest: p.policy_digest.clone(),
            facts_digest: p.facts_digest.clone(),
            authz_digest: p.authz_digest.clone(),
            dependencies_digest: p.dependencies_digest.clone(),
            verdicts: p.verdicts.clone(),
            authz_epoch: p.authz_epoch,
            not_after_tick: p.not_after_tick,
            logical_tick: current_logical_tick,
        },
        scope_dependencies: p.scope_dependencies.clone(),
    })
}

fn validate_payload_syntax(p: &SignedDecisionGrantPayload) -> Result<(), RemoteAuthzGrantError> {
    ServiceMtlsIdentity { san_identity: p.service_mtls_identity.clone(), issuer_id: p.issuer_id }.validate()?;
    if [p.decision_id, p.tenant_id, p.repository_id, p.actor_id, p.operation_id, p.history_incarnation]
        .iter()
        .any(Uuid::is_nil)
    {
        return Err(RemoteAuthzGrantError::InvalidInput("grant UUIDs must be non-nil".into()));
    }
    if p.group_id < 0 || p.group_epoch <= 0 || p.authority_epoch <= 0 || p.authz_epoch <= 0 || p.base_revision <= 0 {
        return Err(RemoteAuthzGrantError::InvalidInput("grant numeric epochs/revision out of bounds".into()));
    }
    if p.verdicts.is_empty() || p.scope_dependencies.is_empty() {
        return Err(RemoteAuthzGrantError::InvalidInput("grant requires verdicts and scope_dependencies".into()));
    }
    for hex in [
        &p.command_digest,
        &p.selection_digest,
        &p.policy_digest,
        &p.facts_digest,
        &p.authz_digest,
        &p.dependencies_digest,
        &p.packs_digest,
        &p.hold_receipts_digest,
        &p.captured_oid_digest,
        &p.base_gate_digest,
    ] {
        RequestDigest::from_str(hex).map_err(|e| RemoteAuthzGrantError::InvalidInput(e.to_string()))?;
    }
    for dep in &p.scope_dependencies {
        validate_scope_kind(&dep.scope_kind).map_err(|e| RemoteAuthzGrantError::InvalidInput(e.to_string()))?;
        if dep.scope_id.is_nil() || dep.observed_version < 0 {
            return Err(RemoteAuthzGrantError::InvalidInput("invalid dependency scope".into()));
        }
        RequestDigest::from_str(&dep.observed_digest)
            .map_err(|e| RemoteAuthzGrantError::InvalidInput(e.to_string()))?;
    }
    Ok(())
}

fn canonical_grant_transcript(p: &SignedDecisionGrantPayload) -> Result<Zeroizing<Vec<u8>>, RemoteAuthzGrantError> {
    let body =
        serde_json::to_vec(p).map_err(|e| RemoteAuthzGrantError::InvalidInput(format!("encode grant payload: {e}")))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(GRANT_TRANSCRIPT_DOMAIN.len() + 12 + body.len()));
    buf.extend_from_slice(GRANT_TRANSCRIPT_DOMAIN);
    buf.push(0);
    buf.extend_from_slice(&(body.len() as u64).to_be_bytes());
    buf.extend_from_slice(&body);
    Ok(buf)
}
