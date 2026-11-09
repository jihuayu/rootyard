//! Bounded root mutation receipts (canonical JSON, no raw payload, `<= 64 KiB`).
//!
//! A receipt is the durable idempotency record of one `register` or `release`. Its JSON body is derived from the
//! same semantic fields as the receipt row, so a replay can prove body/row agreement. The body never contains
//! captured ref names, object ids in bulk, Blob bytes, a locator, a token digest or any raw request payload: only
//! bounded identities, counts, digests and the one-way state.
use super::error::RootError;
use super::rows::ReceiptRow;
use super::usage::MAX_RECEIPT_BODY_BYTES;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use serde_json::{Map, Value, json};
use std::str::FromStr;
use uuid::Uuid;

/// The two receipted root actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootAction {
    Register,
    Release,
}

impl RootAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Release => "release",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RootError> {
        match value {
            "register" => Ok(Self::Register),
            "release" => Ok(Self::Release),
            _ => Err(RootError::Store(RefStoreError::Database(
                "stored root receipt action is not a bounded enum value".into(),
            ))),
        }
    }
}

/// Serialize once and enforce the fixed body bound; never truncate.
pub(super) fn ensure_body_budget(body: &Value) -> Result<usize, RootError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|_| RootError::Store(RefStoreError::Database("root receipt body cannot be serialized".into())))?;
    if bytes.len() > MAX_RECEIPT_BODY_BYTES {
        return Err(RootError::RootReceiptTooLarge { bytes: bytes.len(), max: MAX_RECEIPT_BODY_BYTES });
    }
    Ok(bytes.len())
}

/// Deterministic register receipt body.
#[allow(clippy::too_many_arguments)]
pub(super) fn register_body(
    scope: &super::scope::RootsScope,
    root_id: Uuid,
    operation_id: Uuid,
    operation_digest: &RequestDigest,
    source_snapshot_id: Uuid,
    source_pin_id: Uuid,
    source_pin_generation: i64,
    source_read_digest: &str,
    register_digest: &RequestDigest,
    binding_digest: &str,
    selector_kind: &str,
    refs_digest: &str,
    pack_set_digest: &str,
    gate_revision: i64,
    gate_digest: &str,
    ref_count: i64,
    oid_count: i64,
    pack_count: i64,
    roots_revision: i64,
) -> Result<Value, RootError> {
    let body = json!({
        "action": "register",
        "state": "active",
        "generation": 1,
        "repository_id": scope.repository_id().to_string(),
        "tenant_id": scope.tenant_id().to_string(),
        "owner_id": scope.owner_id().to_string(),
        "purpose": scope.purpose().as_str(),
        "business_intent_digest": scope.business_intent_hex(),
        "object_format": scope.object_format().as_str(),
        "history_incarnation": scope.history_incarnation().to_string(),
        "authority_epoch": scope.authority_epoch(),
        "group_epoch": scope.group_epoch(),
        "root_id": root_id.to_string(),
        "operation_id": operation_id.to_string(),
        "operation_digest": operation_digest.as_hex(),
        "source_snapshot_id": source_snapshot_id.to_string(),
        "source_pin_id": source_pin_id.to_string(),
        "source_pin_generation": source_pin_generation,
        "source_read_digest": source_read_digest,
        "register_digest": register_digest.as_hex(),
        "binding_digest": binding_digest,
        "selector_kind": selector_kind,
        "refs_digest": refs_digest,
        "pack_set_digest": pack_set_digest,
        "gate_revision": gate_revision,
        "gate_digest": gate_digest,
        "ref_count": ref_count,
        "oid_count": oid_count,
        "pack_count": pack_count,
        "roots_revision": roots_revision,
    });
    ensure_body_budget(&body)?;
    Ok(body)
}

/// Deterministic release receipt body.
#[allow(clippy::too_many_arguments)]
pub(super) fn release_body(
    scope: &super::scope::RootsScope,
    root_id: Uuid,
    expected_register_digest: &RequestDigest,
    release_digest: &RequestDigest,
    reason: &str,
    released_before_register: bool,
) -> Result<Value, RootError> {
    let body = json!({
        "action": "release",
        "state": "released",
        "generation": 2,
        "repository_id": scope.repository_id().to_string(),
        "tenant_id": scope.tenant_id().to_string(),
        "owner_id": scope.owner_id().to_string(),
        "purpose": scope.purpose().as_str(),
        "business_intent_digest": scope.business_intent_hex(),
        "object_format": scope.object_format().as_str(),
        "history_incarnation": scope.history_incarnation().to_string(),
        "authority_epoch": scope.authority_epoch(),
        "group_epoch": scope.group_epoch(),
        "root_id": root_id.to_string(),
        "expected_register_digest": expected_register_digest.as_hex(),
        "release_digest": release_digest.as_hex(),
        "reason": reason,
        "released_before_register": released_before_register,
        "retained": true,
        "released_holds": false,
        "deleted_blob_bytes": false,
    });
    ensure_body_budget(&body)?;
    Ok(body)
}

fn corrupt(message: &'static str) -> RootError {
    RootError::Store(RefStoreError::Database(message.into()))
}

fn body_field<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a Value, RootError> {
    object.get(field).ok_or_else(|| corrupt("stored root receipt body is missing a bounded field"))
}

fn body_text<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, RootError> {
    body_field(object, field)?.as_str().ok_or_else(|| corrupt("stored root receipt body field is not text"))
}

fn body_int(object: &Map<String, Value>, field: &'static str) -> Result<i64, RootError> {
    body_field(object, field)?.as_i64().ok_or_else(|| corrupt("stored root receipt body field is not an integer"))
}

fn body_uuid(object: &Map<String, Value>, field: &'static str) -> Result<Uuid, RootError> {
    Uuid::parse_str(body_text(object, field)?).map_err(|_| corrupt("stored root receipt body field is not a uuid"))
}

/// The complete trusted scope of one retained receipt, recovered from its immutable body.
///
/// The body is written once by the adapter, is covered by the receipt immutability trigger and has a fixed
/// `<= 64 KiB` bound, so it is the durable carrier of the receipt's *full* realm. A receipt query that names a
/// different object format, history incarnation, authority epoch or group epoch for the same repository and
/// otherwise identical owner/purpose/intent is therefore rejected instead of being misattributed.
struct ReceiptScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: String,
    business_intent_digest: String,
    object_format: String,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl ReceiptScope {
    fn from_body(row: &ReceiptRow) -> Result<Self, RootError> {
        let object = row.body.as_object().ok_or_else(|| corrupt("stored root receipt body is not a JSON object"))?;
        Ok(Self {
            repository_id: body_uuid(object, "repository_id")?,
            tenant_id: body_uuid(object, "tenant_id")?,
            owner_id: body_uuid(object, "owner_id")?,
            purpose: body_text(object, "purpose")?.to_owned(),
            business_intent_digest: body_text(object, "business_intent_digest")?.to_owned(),
            object_format: body_text(object, "object_format")?.to_owned(),
            history_incarnation: body_uuid(object, "history_incarnation")?,
            authority_epoch: body_int(object, "authority_epoch")?,
            group_epoch: body_int(object, "group_epoch")?,
        })
    }

    /// Require every field of the queried trusted scope, including the complete realm, to agree.
    fn require(&self, scope: &super::scope::RootsScope) -> Result<(), RootError> {
        if self.repository_id != scope.repository_id() {
            return Err(RootError::RootRealmMismatch("root receipt repository"));
        }
        if self.tenant_id != scope.tenant_id() {
            return Err(RootError::RootRealmMismatch("root receipt tenant"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(RootError::RootRealmMismatch("root receipt owner"));
        }
        if self.purpose != scope.purpose().as_str() {
            return Err(RootError::RootRealmMismatch("root receipt purpose"));
        }
        if self.business_intent_digest != scope.business_intent_hex() {
            return Err(RootError::RootRealmMismatch("root receipt business intent"));
        }
        if self.object_format != scope.object_format().as_str() {
            return Err(RootError::RootRealmMismatch("root receipt object format"));
        }
        if self.history_incarnation != scope.history_incarnation() {
            return Err(RootError::RootRealmMismatch("root receipt history incarnation"));
        }
        if self.authority_epoch != scope.authority_epoch() {
            return Err(RootError::RootRealmMismatch("root receipt authority epoch"));
        }
        if self.group_epoch != scope.group_epoch() {
            return Err(RootError::RootRealmMismatch("root receipt group epoch"));
        }
        Ok(())
    }
}

/// One durable root receipt.
///
/// Not `Clone` and not `Serialize`: a caller cannot forge, mutate or replay it as authority. The retained body is
/// the bounded canonical JSON that the adapter also verified against the receipt row.
#[derive(Debug)]
pub struct RootReceipt {
    action: RootAction,
    replayed: bool,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    root_id: Uuid,
    generation: i64,
    request_digest: RequestDigest,
    body: Value,
    created_at_unix_micros: i64,
}

impl RootReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        action: RootAction,
        replayed: bool,
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        root_id: Uuid,
        generation: i64,
        request_digest: RequestDigest,
        body: Value,
        created_at_unix_micros: i64,
    ) -> Self {
        Self {
            action,
            replayed,
            repository_id,
            tenant_id,
            owner_id,
            root_id,
            generation,
            request_digest,
            body,
            created_at_unix_micros,
        }
    }

    /// Rebuild a receipt from stored columns and prove the retained body agrees with them on every field the
    /// row carries (repository, complete trusted scope, root id, action and generation) as well as carrying the
    /// full realm the query must match.
    pub(super) fn from_row(row: ReceiptRow, replayed: bool) -> Result<Self, RootError> {
        let request_digest = RequestDigest::from_str(&row.request_digest)
            .map_err(|_| corrupt("stored root receipt digest is invalid"))?;
        let object = row.body.as_object().ok_or_else(|| corrupt("stored root receipt body is not a JSON object"))?;
        let stored = ReceiptScope::from_body(&row)?;
        if stored.repository_id != row.repository_id
            || stored.tenant_id != row.tenant_id
            || stored.owner_id != row.owner_id
            || stored.purpose != row.purpose.as_str()
            || stored.business_intent_digest != row.business_intent_digest
            || body_uuid(object, "root_id")? != row.root_id
            || body_text(object, "action")? != row.action.as_str()
            || body_int(object, "generation")? != row.generation
        {
            return Err(corrupt("stored root receipt body disagrees with its columns"));
        }
        Ok(Self {
            action: row.action,
            replayed,
            repository_id: row.repository_id,
            tenant_id: row.tenant_id,
            owner_id: row.owner_id,
            root_id: row.root_id,
            generation: row.generation,
            request_digest,
            body: row.body,
            created_at_unix_micros: row.created_at_unix_micros,
        })
    }

    pub fn action(&self) -> RootAction {
        self.action
    }
    /// `true` only when this receipt was returned by an exact request-id/digest replay (never charged again).
    pub fn replayed(&self) -> bool {
        self.replayed
    }
    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn request_digest(&self) -> RequestDigest {
        self.request_digest
    }
    pub fn created_at_unix_micros(&self) -> i64 {
        self.created_at_unix_micros
    }
    /// The bounded canonical body (no payload, no secret).
    pub fn body(&self) -> &Value {
        &self.body
    }
    /// One-way retained state implied by this receipt (`active` or `released`).
    pub fn state(&self) -> &str {
        self.body.get("state").and_then(Value::as_str).unwrap_or("released")
    }
}

/// Require a stored receipt to belong to the queried trusted scope **including the complete realm**.
///
/// The row columns carry tenant/owner/purpose/business intent; the immutable body carries the object format,
/// history incarnation, authority epoch and group epoch that the row does not. Both are checked, so a query
/// with the same repository and partial identity but a changed realm is refused instead of misattributed.
pub(super) fn verify_scope(row: &ReceiptRow, scope: &super::scope::RootsScope) -> Result<(), RootError> {
    super::handle::scope_matches(
        scope,
        row.tenant_id,
        row.owner_id,
        row.purpose.as_str(),
        &row.business_intent_digest,
    )?;
    ReceiptScope::from_body(row)?.require(scope)
}
