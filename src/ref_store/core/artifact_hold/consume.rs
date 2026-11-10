//! Durable-consume and receipt-query verification helpers (A3).
//!
//! These functions are pure comparisons between the decoded immutable ACK, the
//! *complete* bounded hold set of one acquire request and the immutable consume
//! receipts. They never mint authority, never touch the Blob layer, never take
//! a lock of their own and never read the current core gate or a live parent
//! operation: a historical receipt must stay readable after the parent business
//! operation is gone. The adapter calls them inside its one owned transaction.
//!
//! The upload capability itself does not live here: [`ArtifactGrant`] and
//! [`ConsumedArtifacts`](crate::ref_store::core::artifact_hold::ConsumedArtifacts)
//! are defined in the private `pg::capability` module so only the PostgreSQL
//! adapter can construct them.
use super::contract::{ArtifactHoldError, HoldScope, MAX_BATCH_ARTIFACTS};
use super::receipt::{AcquireAck, ConsumeAck, HoldAck};
use super::sql::StoredAcquire;
use super::sql_rows::StoredHold;
use uuid::Uuid;

/// Verify that one locked durable hold row is exactly the granted, active,
/// generation-1 artifact and belongs to the same acquire request/scope. Any
/// difference is a hard refusal: the grant is burned (no IO) and the hold stays
/// retained.
pub(super) fn ensure_granted_hold(
    stored: &StoredHold,
    expected: &HoldAck,
    scope: &HoldScope,
    request_id: Uuid,
) -> Result<(), ArtifactHoldError> {
    if stored.hold_id != expected.hold_id {
        return Err(ArtifactHoldError::HoldNotFound { hold_id: expected.hold_id });
    }
    if stored.request_id != request_id {
        return Err(ArtifactHoldError::HoldIdentityMismatch { hold_id: stored.hold_id });
    }
    if stored.state != "active" || stored.generation != 1 {
        return Err(ArtifactHoldError::HoldNotActive { hold_id: stored.hold_id });
    }
    if stored.repository_id != scope.repository_id()
        || stored.tenant_id != scope.tenant_id()
        || stored.owner_id != scope.owner_id()
        || stored.purpose != scope.purpose().as_str()
    {
        return Err(ArtifactHoldError::ScopeMismatch("stored hold owner/purpose"));
    }
    if stored.slot != expected.slot
        || stored.artifact != expected.artifact
        || stored.declared_bytes != expected.declared_bytes
        || stored.logical_bytes != expected.logical_bytes
    {
        return Err(ArtifactHoldError::HoldIdentityMismatch { hold_id: stored.hold_id });
    }
    Ok(())
}

/// One immutable acquire receipt as a whole: the canonical body must agree
/// with every duplicated column of its own request row *and* the complete
/// bounded hold set must be exactly the ACK batch. This is the shared validator
/// used by both receipt-only queries before they may answer `Found` *and* by the
/// acquire replay path before it may answer `Replayed`; it never constructs a
/// grant and never revalidates current business/gate state.
pub(super) fn ensure_immutable_batch(
    request: &StoredAcquire,
    ack: &AcquireAck,
    stored: &[StoredHold],
) -> Result<(), ArtifactHoldError> {
    // Covers the canonical body, every duplicated request column (scope,
    // owner, purpose, object format, history incarnation, both epochs, parent
    // operation tuple, gate proof, shard, backend, byte totals) and the
    // bounded ACK shape.
    request.ensure_ack(ack)?;
    ensure_complete_batch(stored, ack)
}

/// The stored hold rows of one request must be *exactly* the ACK batch: same
/// count (bounded to the 16-slot maximum), every ACK slot present once, every
/// hold id, physical backend/locator, active generation-1 state, duplicated
/// scope column, parent operation tuple and per-hold declared/logical byte
/// count equal to its [`HoldAck`]. A partial (missing row), duplicated, extra
/// or rewritten set is a typed integrity error, never a smaller successful
/// batch and never `Unknown`.
pub(super) fn ensure_complete_batch(stored: &[StoredHold], ack: &AcquireAck) -> Result<(), ArtifactHoldError> {
    ack.ensure_batch_shape()?;
    if stored.len() != ack.artifacts.len() || stored.len() > MAX_BATCH_ARTIFACTS {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold row count differs from the ACK batch"));
    }
    let mut matched = vec![false; stored.len()];
    for expected in &ack.artifacts {
        let Some(index) = stored.iter().position(|row| row.slot == expected.slot) else {
            return Err(ArtifactHoldError::LedgerIntegrity("stored hold set is missing an ACK slot"));
        };
        if matched[index] {
            return Err(ArtifactHoldError::LedgerIntegrity("stored hold set repeats an ACK slot"));
        }
        matched[index] = true;
        ensure_hold_row_matches(&stored[index], expected, ack)?;
    }
    if matched.iter().any(|seen| !*seen) {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold set has a row outside the ACK batch"));
    }
    Ok(())
}

/// Compare one durable hold row with the immutable ACK slot it claims to be.
/// Every comparison is against immutable ledger columns: no current gate row,
/// pending operation or repository business row is consulted.
fn ensure_hold_row_matches(row: &StoredHold, expected: &HoldAck, ack: &AcquireAck) -> Result<(), ArtifactHoldError> {
    if row.request_id != ack.request_id {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold belongs to a different acquire request"));
    }
    if row.hold_id != expected.hold_id || row.slot != expected.slot {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold id/slot differs from its ACK slot"));
    }
    if row.state != "active" || row.generation != 1 {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold is not an active generation-1 row"));
    }
    if row.repository_id != ack.repository_id
        || row.tenant_id != ack.tenant_id
        || row.owner_id != ack.owner_id
        || row.purpose != ack.purpose.as_str()
    {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold scope differs from its acquire ACK"));
    }
    if row.operation_id != ack.operation_id || row.operation_digest != ack.operation_digest {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold parent operation differs from its acquire ACK"));
    }
    if row.artifact != expected.artifact || row.artifact.backend_identity != ack.backend_identity {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold backend/locator differs from its acquire ACK"));
    }
    if row.declared_bytes != expected.declared_bytes || row.logical_bytes != expected.logical_bytes {
        return Err(ArtifactHoldError::LedgerIntegrity(
            "stored hold declared/logical bytes differ from its acquire ACK",
        ));
    }
    Ok(())
}

/// A historical consume receipt must still describe the immutable hold row it
/// was written against. This reads no current gate and no live authority: a
/// later profile/gate change cannot invalidate an old receipt, but a rewritten
/// receipt body cannot borrow an old hold either.
pub(super) fn ensure_receipt_matches_hold(receipt: &ConsumeAck, stored: &StoredHold) -> Result<(), ArtifactHoldError> {
    if receipt.hold_id != stored.hold_id
        || receipt.request_id != stored.request_id
        || receipt.slot != stored.slot
        || receipt.repository_id != stored.repository_id
        || receipt.tenant_id != stored.tenant_id
        || receipt.owner_id != stored.owner_id
        || receipt.operation_id != stored.operation_id
        || receipt.operation_digest != stored.operation_digest
        || receipt.purpose.as_str() != stored.purpose
        || receipt.artifact != stored.artifact
    {
        return Err(ArtifactHoldError::LedgerIntegrity("stored consume receipt disagrees with its immutable hold row"));
    }
    if stored.state != "active" || stored.generation != 1 {
        return Err(ArtifactHoldError::LedgerIntegrity("stored hold is not an active generation-1 row"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::artifact_hold::contract::{ArtifactHoldPurpose, HoldScope, ShardId};
    use crate::ref_store::core::artifact_hold::receipt::{HoldAck, HoldArtifactIdentity};
    use crate::ref_store::core::types::GitObjectFormat;

    fn scope() -> HoldScope {
        HoldScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            ArtifactHoldPurpose::RefPublication,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
        )
        .unwrap()
    }

    fn artifact(scope: &HoldScope) -> HoldArtifactIdentity {
        HoldArtifactIdentity {
            provider: "s3".into(),
            backend_identity: "e".repeat(64),
            tenant_id: scope.tenant_id(),
            authority_id: Uuid::new_v4(),
            authority_generation: 1,
            attempt_id: Uuid::new_v4(),
            namespace: "packs".into(),
            sha256: "a".repeat(64),
            length: 10,
        }
    }

    fn hold(scope: &HoldScope, request_id: Uuid, hold_id: Uuid) -> StoredHold {
        StoredHold {
            hold_id,
            request_id,
            slot: 0,
            state: "active".into(),
            generation: 1,
            repository_id: scope.repository_id(),
            tenant_id: scope.tenant_id(),
            owner_id: scope.owner_id(),
            purpose: "ref_publication".into(),
            operation_id: Uuid::new_v4(),
            operation_digest: "b".repeat(64),
            artifact: artifact(scope),
            declared_bytes: 10,
            logical_bytes: 900,
        }
    }

    fn ack(scope: &HoldScope, request_id: Uuid, hold: &StoredHold) -> AcquireAck {
        AcquireAck {
            request_id,
            request_digest: "c".repeat(64),
            repository_id: scope.repository_id(),
            tenant_id: scope.tenant_id(),
            owner_id: scope.owner_id(),
            purpose: ArtifactHoldPurpose::RefPublication,
            object_format: GitObjectFormat::Sha1,
            history_incarnation: scope.history_incarnation(),
            authority_epoch: 1,
            group_epoch: 1,
            issuer_id: Uuid::new_v4(),
            lane: "pipeline:refs".into(),
            sequence: 1,
            operation_id: hold.operation_id,
            operation_digest: hold.operation_digest.clone(),
            gate_revision: 1,
            gate_digest: "d".repeat(64),
            shard: ShardId::of(request_id).as_i32(),
            backend_identity: hold.artifact.backend_identity.clone(),
            consume_request_id: Uuid::new_v4(),
            artifacts: vec![HoldAck::new(hold.hold_id, 0, hold.artifact.clone(), 10, 900)],
            declared_bytes: 10,
            logical_bytes: 900,
        }
    }

    fn stored_request(ack: &AcquireAck) -> StoredAcquire {
        StoredAcquire {
            request_id: ack.request_id,
            request_digest: ack.request_digest.clone(),
            repository_id: ack.repository_id,
            tenant_id: ack.tenant_id,
            owner_id: ack.owner_id,
            purpose: ack.purpose.as_str().to_owned(),
            object_format: ack.object_format.as_str().to_owned(),
            history_incarnation: ack.history_incarnation,
            authority_epoch: ack.authority_epoch,
            group_epoch: ack.group_epoch,
            operation_issuer_id: ack.issuer_id,
            operation_lane: ack.lane.clone(),
            operation_sequence: ack.sequence,
            operation_id: ack.operation_id,
            operation_digest: ack.operation_digest.clone(),
            gate_revision: ack.gate_revision,
            gate_digest: ack.gate_digest.clone(),
            shard: ack.shard,
            backend_identity: ack.backend_identity.clone(),
            consume_request_id: ack.consume_request_id,
            artifact_count: i32::try_from(ack.artifacts.len()).unwrap(),
            declared_bytes: ack.declared_bytes,
            logical_bytes: ack.logical_bytes,
            body: ack.encode().unwrap(),
        }
    }

    #[test]
    fn mismatch_is_a_hard_refusal() {
        let scope = scope();
        let request_id = Uuid::new_v4();
        let stored = hold(&scope, request_id, Uuid::new_v4());
        let ack = ack(&scope, request_id, &stored);
        assert!(ensure_granted_hold(&stored, &ack.artifacts[0], &scope, request_id).is_ok());
        assert!(ensure_complete_batch(std::slice::from_ref(&stored), &ack).is_ok());
        let mut released = self::hold(&scope, request_id, stored.hold_id);
        released.state = "released".into();
        assert!(matches!(
            ensure_granted_hold(&released, &ack.artifacts[0], &scope, request_id),
            Err(ArtifactHoldError::HoldNotActive { .. })
        ));
    }

    #[test]
    fn partial_and_extra_rows_are_integrity_errors() {
        let scope = scope();
        let request_id = Uuid::new_v4();
        let first = hold(&scope, request_id, Uuid::new_v4());
        let ack = ack(&scope, request_id, &first);
        assert!(matches!(ensure_complete_batch(&[], &ack), Err(ArtifactHoldError::LedgerIntegrity(_))));
        let mut two = ack.clone();
        two.artifacts.push(HoldAck::new(Uuid::new_v4(), 1, first.artifact.clone(), 10, 900));
        assert!(matches!(
            ensure_complete_batch(std::slice::from_ref(&first), &two),
            Err(ArtifactHoldError::LedgerIntegrity(_))
        ));
        let mut foreign = self::hold(&scope, request_id, Uuid::new_v4());
        foreign.artifact.sha256 = "f".repeat(64);
        assert!(matches!(
            ensure_complete_batch(std::slice::from_ref(&foreign), &ack),
            Err(ArtifactHoldError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn byte_scope_state_and_operation_mismatches_are_integrity_errors() {
        let scope = scope();
        let request_id = Uuid::new_v4();
        let base = hold(&scope, request_id, Uuid::new_v4());
        let ack = ack(&scope, request_id, &base);
        let mutations: [fn(&mut StoredHold); 7] = [
            |row| row.declared_bytes += 1,
            |row| row.logical_bytes += 1,
            |row| row.request_id = Uuid::new_v4(),
            |row| row.owner_id = Uuid::new_v4(),
            |row| row.purpose = "not-a-purpose".into(),
            |row| row.operation_digest = "0".repeat(64),
            |row| row.generation = 2,
        ];
        for mutate in mutations {
            let mut row = self::hold(&scope, request_id, base.hold_id);
            mutate(&mut row);
            assert!(
                matches!(
                    ensure_complete_batch(std::slice::from_ref(&row), &ack),
                    Err(ArtifactHoldError::LedgerIntegrity(_))
                ),
                "a rewritten hold row must be a typed integrity refusal"
            );
        }
    }

    #[test]
    fn immutable_batch_also_validates_outer_request_columns() {
        let scope = scope();
        let request_id = Uuid::new_v4();
        let base = hold(&scope, request_id, Uuid::new_v4());
        let ack = ack(&scope, request_id, &base);
        assert!(ensure_immutable_batch(&stored_request(&ack), &ack, std::slice::from_ref(&base)).is_ok());
        let mut moved_epoch = stored_request(&ack);
        moved_epoch.authority_epoch += 1;
        assert!(matches!(
            ensure_immutable_batch(&moved_epoch, &ack, std::slice::from_ref(&base)),
            Err(ArtifactHoldError::LedgerIntegrity(_))
        ));
        let mut moved_format = stored_request(&ack);
        moved_format.object_format = GitObjectFormat::Sha256.as_str().to_owned();
        assert!(matches!(
            ensure_immutable_batch(&moved_format, &ack, std::slice::from_ref(&base)),
            Err(ArtifactHoldError::LedgerIntegrity(_))
        ));
        // The physical primary key selected from the row must be the ACK's own
        // request id, not merely a body that happens to agree with itself.
        let mut moved_request = stored_request(&ack);
        moved_request.request_id = Uuid::new_v4();
        assert!(matches!(
            ensure_immutable_batch(&moved_request, &ack, std::slice::from_ref(&base)),
            Err(ArtifactHoldError::LedgerIntegrity(_))
        ));
    }
}
