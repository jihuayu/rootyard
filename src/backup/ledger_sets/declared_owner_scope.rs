//! Owner and tenant scopes of one A4 registration.
//!
//! Two identities inside one publication are never conflated:
//!
//! * the **producer** (`owner_id`) is the A3 artifact-hold requester of the
//!   acquire request, both durable holds, both consume receipts and the typed
//!   ACK body. It may differ from the repository tenant;
//! * the **tenant** (`tenant_id`) is the actual repository tenant
//!   (`repositories.owner_id`) and the core gate tenant, and is repeated by the
//!   artifact locator, the request, both holds, both storage tenants and both
//!   receipts.
//!
//! The artifact row's own repository and pack are not part of the locator
//! digest, so they are checked directly against the declared publication key.
//! A root head/capture/tombstone requester is a separate lifetime scope (see
//! [`super::root_lifetime`]) and is never compared here. The typed ACK body is
//! judged by [`super::ledger::ack_scope_differs`].
use super::{DeclaredPair, PairArtifact, PublishedPack};

/// The publication tenant must be exactly the actual repository tenant of the
/// `repositories` row and of the core gate. The publication *owner* is the
/// producer and is deliberately not compared with the tenant here.
pub(super) fn declared_binding(pair: &DeclaredPair) -> bool {
    let publication = &pair.publication;
    publication.as_ref().is_some_and(|publication| {
        pair.actual.owner_id == Some(publication.tenant_id) && pair.actual.gate_tenant_id == Some(publication.tenant_id)
    })
}

/// Every scope violation line of one declared registration: `publication_key:{key}`
/// when the publication's own repository/pack leave the declared key, and one
/// `owner_scope_mismatch:{key}:{role}:{slot}` line per artifact row whose
/// request, hold, receipt, tenant or repository/pack disagrees. Sorted and
/// de-duplicated.
pub(super) fn declared_violations(pair: &DeclaredPair) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(publication) = &pair.publication else {
        return lines;
    };
    let key = super::tag(pair);
    if publication.repository_id != pair.repository_id || publication.pack_id != pair.pack_id {
        lines.push(format!("publication_key:{key}"));
    }
    for artifact in &pair.artifacts {
        if !declared_owner(publication, artifact).is_empty() {
            lines.push(format!("owner_scope_mismatch:{key}:{}:{}", artifact.role, artifact.slot));
        }
    }
    lines.sort();
    lines.dedup();
    lines
}

/// Every binding of one artifact row that can disagree, in a stable order. An
/// empty list accepts the row. The row's repository/pack identity is judged
/// against the declared key, every tenant against the publication (actual
/// repository) tenant, and every owner against the publication producer.
///
/// A missing hold, request or receipt is reported here instead of being hidden
/// by an inner join, so a corrupted row is always a refusal.
pub(super) fn declared_owner(publication: &PublishedPack, artifact: &PairArtifact) -> Vec<&'static str> {
    let owner = publication.owner_id;
    let tenant = publication.tenant_id;
    let mut lines = Vec::new();
    if artifact.repository_id != publication.repository_id || artifact.pack_id != publication.pack_id {
        lines.push("artifact_key");
    }
    if artifact.tenant_id != tenant {
        lines.push("artifact_tenant");
    }
    match &artifact.request {
        Some(request) => {
            if request.repository_id != artifact.repository_id {
                lines.push("request_repository");
            }
            if request.tenant_id != tenant {
                lines.push("request_tenant");
            }
            if request.owner_id != owner {
                lines.push("request_owner");
            }
        }
        None => lines.push("request"),
    }
    match &artifact.hold {
        Some(hold) => {
            if hold.owner_id != owner {
                lines.push("hold_owner");
            }
        }
        None => lines.push("hold"),
    }
    if artifact.hold_slot != Some(artifact.slot) {
        lines.push("hold_slot");
    }
    match &artifact.receipt_scope {
        Some(receipt) => {
            if receipt.repository_id != artifact.repository_id {
                lines.push("receipt_repository");
            }
            if receipt.tenant_id != tenant {
                lines.push("receipt_tenant");
            }
            if receipt.owner_id != owner {
                lines.push("receipt_owner");
            }
        }
        None => lines.push("receipt"),
    }
    lines
}
