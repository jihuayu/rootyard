//! Boot-time re-homing of restored `pg_refstore` A3/A4 and decision realm rows.
//!
//! A format 30 paired restore installs a brand-new history incarnation, authority epoch and
//! group epoch. Every restored A1/A2 row, A3 artifact-hold ACK, A4 pack registration ACK and
//! publication decision was captured under the *source* realm, and the bounded immutable ACK
//! bodies repeat that realm verbatim. The columns and the bodies must move together, or every
//! later replay cross-check fails closed on a stale foreign realm.
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::{AcquireAck, ConsumeAck};
use crate::ref_store::core::pack_commit::PackRegistrationAck;

use super::pg_cutpoint::pg_err;
use super::types::PairedBackupError;

const ARTIFACT_HOLD_BODIES: &str = "SELECT request_id, repository_id, tenant_id, shard_id, ack_body \
     FROM public.artifact_hold_requests ORDER BY request_id";
const PACK_REGISTRATION_BODIES: &str = "SELECT registration_id, repository_id, tenant_id, logical_bytes, ack_body \
     FROM public.ref_store_core_pack_publications ORDER BY registration_id";

const REALM_UPDATES: [&str; 8] = [
    "UPDATE public.ref_store_core_gates SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_core_protocol_repos SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_core_snapshots SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_core_roots SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_publication_decisions SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.artifact_hold_requests SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_core_pack_publications SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_serving_repositories SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
];

/// Re-home every restored realm row onto the freshly installed incarnation.
pub(super) async fn rehome_restored_repositories_realm(
    tx: &Transaction<'_>,
    new_history_inc: Uuid,
    new_authority_epoch: i64,
    new_group_epoch: i64,
) -> Result<(), PairedBackupError> {
    for statement in REALM_UPDATES {
        tx.execute(statement, &[&new_history_inc, &new_authority_epoch, &new_group_epoch]).await.map_err(pg_err)?;
    }
    rehome_artifact_hold_receipts(tx, new_history_inc, new_authority_epoch, new_group_epoch).await?;
    rehome_pack_registration_receipts(tx, new_history_inc, new_authority_epoch, new_group_epoch).await
}

async fn rehome_artifact_hold_receipts(
    tx: &Transaction<'_>,
    new_history_inc: Uuid,
    new_authority_epoch: i64,
    new_group_epoch: i64,
) -> Result<(), PairedBackupError> {
    let rows = tx.query(ARTIFACT_HOLD_BODIES, &[]).await.map_err(pg_err)?;
    for row in rows {
        let request_id: Uuid = row.get(0);
        let repository_id: Uuid = row.get(1);
        let tenant_id: Uuid = row.get(2);
        let shard_id: i32 = row.get(3);
        let raw: String = row.get(4);
        let mut ack = AcquireAck::decode(&raw).map_err(ledger_error)?;
        ack.history_incarnation = new_history_inc;
        ack.authority_epoch = new_authority_epoch;
        ack.group_epoch = new_group_epoch;
        let encoded = ack.encode().map_err(ledger_error)?;
        let consume_digest = ack.consume_digest().as_hex();
        tx.execute(
            "UPDATE public.artifact_hold_requests SET history_incarnation = $1, authority_epoch = $2, \
             group_epoch = $3, ack_body = $4 WHERE request_id = $5",
            &[&new_history_inc, &new_authority_epoch, &new_group_epoch, &encoded, &request_id],
        )
        .await
        .map_err(pg_err)?;
        let mut delta = encoded.len() as i64 - raw.len() as i64;
        delta += rehome_consume_receipts(tx, &ack, request_id, &consume_digest).await?;
        if delta != 0 {
            rehome_artifact_hold_usage(tx, delta, repository_id, tenant_id, shard_id).await?;
        }
    }
    Ok(())
}

/// Apply the exact body-length delta to the A3 shard/repository/tenant counters.
async fn rehome_artifact_hold_usage(
    tx: &Transaction<'_>,
    delta: i64,
    (repository_id, tenant_id, shard_id): (Uuid, Uuid, i32),
) -> Result<(), PairedBackupError> {
    tx.execute(
        "UPDATE public.artifact_hold_shards SET logical_bytes = GREATEST(0, logical_bytes + $1) \
         WHERE shard_id = $2",
        &[&delta, &shard_id],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE public.artifact_hold_repo_usage SET logical_bytes = GREATEST(0, logical_bytes + $1) \
         WHERE repository_id = $2",
        &[&delta, &repository_id],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE public.artifact_hold_tenant_usage SET logical_bytes = GREATEST(0, logical_bytes + $1) \
         WHERE tenant_id = $2",
        &[&delta, &tenant_id],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

/// Rewrite every one-shot consume receipt of one acquire ACK and return its body-length delta.
async fn rehome_consume_receipts(
    tx: &Transaction<'_>,
    ack: &AcquireAck,
    request_id: Uuid,
    consume_digest: &str,
) -> Result<i64, PairedBackupError> {
    let rows = tx
        .query(
            "SELECT hold_id, body FROM public.artifact_hold_consume_receipts WHERE request_id = $1 ORDER BY hold_id",
            &[&request_id],
        )
        .await
        .map_err(pg_err)?;
    let mut delta = 0i64;
    for row in rows {
        let hold_id: Uuid = row.get(0);
        let raw: String = row.get(1);
        let mut receipt = ConsumeAck::decode(&raw).map_err(ledger_error)?;
        receipt.history_incarnation = ack.history_incarnation;
        receipt.authority_epoch = ack.authority_epoch;
        receipt.group_epoch = ack.group_epoch;
        receipt.consume_digest = consume_digest.to_owned();
        receipt.ensure_acquire_ack(ack).map_err(ledger_error)?;
        let encoded = receipt.encode().map_err(ledger_error)?;
        delta += encoded.len() as i64 - raw.len() as i64;
        tx.execute(
            "UPDATE public.artifact_hold_consume_receipts SET consume_digest = $1, body = $2 WHERE hold_id = $3",
            &[&consume_digest, &encoded, &hold_id],
        )
        .await
        .map_err(pg_err)?;
    }
    Ok(delta)
}

/// Rewrite A4 ACK/history bodies, recompute the fixed point and move the exact signed delta.
async fn rehome_pack_registration_receipts(
    tx: &Transaction<'_>,
    new_history_inc: Uuid,
    new_authority_epoch: i64,
    new_group_epoch: i64,
) -> Result<(), PairedBackupError> {
    let rows = tx.query(PACK_REGISTRATION_BODIES, &[]).await.map_err(pg_err)?;
    for row in rows {
        let reg_id: Uuid = row.get(0);
        let repository_id: Uuid = row.get(1);
        let tenant_id: Uuid = row.get(2);
        let old_logical: i64 = row.get(3);
        let raw: String = row.get(4);
        let mut ack = PackRegistrationAck::decode(&raw).map_err(pack_error)?;
        ack.history_incarnation = new_history_inc;
        ack.authority_epoch = new_authority_epoch;
        ack.group_epoch = new_group_epoch;
        let mut logical = old_logical;
        let mut encoded = String::new();
        for _ in 0..8u8 {
            ack.logical_bytes = logical;
            encoded = ack.encode().map_err(pack_error)?;
            let target = 4 * 256 + 2 * (encoded.len() as i64);
            if target == logical {
                break;
            }
            logical = target;
        }
        tx.execute(
            "UPDATE public.ref_store_core_pack_publications SET history_incarnation = $1, authority_epoch = $2, \
             group_epoch = $3, logical_bytes = $4, ack_body = $5 WHERE registration_id = $6",
            &[&new_history_inc, &new_authority_epoch, &new_group_epoch, &ack.logical_bytes, &encoded, &reg_id],
        )
        .await
        .map_err(pg_err)?;
        tx.execute(
            "UPDATE public.ref_store_core_pack_history SET body = $1 \
             WHERE registration_id = $2 AND kind = 'registered'",
            &[&encoded, &reg_id],
        )
        .await
        .map_err(pg_err)?;
        if ack.logical_bytes != old_logical {
            let delta = ack.logical_bytes - old_logical;
            tx.execute(
                "UPDATE public.ref_store_core_pack_repo_usage SET logical_bytes = GREATEST(0, logical_bytes + $1) \
                 WHERE repository_id = $2",
                &[&delta, &repository_id],
            )
            .await
            .map_err(pg_err)?;
            tx.execute(
                "UPDATE public.ref_store_core_pack_tenant_usage SET logical_bytes = GREATEST(0, logical_bytes + $1) \
                 WHERE tenant_id = $2",
                &[&delta, &tenant_id],
            )
            .await
            .map_err(pg_err)?;
        }
    }
    Ok(())
}

fn ledger_error(error: crate::ref_store::core::artifact_hold::contract::ArtifactHoldError) -> PairedBackupError {
    PairedBackupError::StateMachine(format!("restored A3 realm re-home refused an ACK: {error}"))
}

fn pack_error(error: crate::ref_store::core::pack_commit::PackCommitError) -> PairedBackupError {
    PairedBackupError::StateMachine(format!("restored A4 realm re-home refused an ACK: {error}"))
}
