//! Restoring older durable state must not resurrect execution credentials.
use anyhow::{Result, ensure};
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;

mod restore_lineage;
pub(super) use restore_lineage::RestoreLineage;
use restore_lineage::rotate_cluster_incarnation;

const RESET_DELIVERIES: &str = "UPDATE public.event_deliveries SET state='pending', lease_owner=NULL, lease_until=NULL, next_attempt_at=clock_timestamp() WHERE state='leased'";
const FENCED_WORKSPACES: &str = "UPDATE public.workspaces SET lease_epoch=lease_epoch+1, lease_until=clock_timestamp()-interval '1 second' WHERE state='ready'";
const CANCELLED_DECISIONS: &str = "UPDATE public.ref_store_publication_decisions SET state='CANCELLED', cancelled_at=clock_timestamp(), closed_code='restored_incarnation', cancel_change_id=gen_random_uuid() WHERE state='OPEN'";
const RELEASED_PINS: &str = "UPDATE public.ref_store_core_pins SET state='released', released_at=GREATEST(clock_timestamp(), created_at), updated_at=GREATEST(clock_timestamp(), updated_at), release_request_id=gen_random_uuid(), release_reason='operator_request' WHERE state='active'";
const ABORTED_PULLS: &str = "UPDATE public.pull_remote_merge_attempts SET state='aborted_before_cas', reject_reason='aborted by paired restore incarnation rotation' WHERE state='pending_merge'";
const FENCED_AUTHORITY: &str = "UPDATE public.pando_storage_authorities SET authority_epoch = GREATEST(authority_epoch, $1) + 1, remote_delete_fenced = true, remote_delete_fence_reason = 'w8a-paired-restore-fenced', rotated_at = clock_timestamp() WHERE singleton = true RETURNING authority_id, restore_generation, authority_epoch, remote_delete_fenced";

/// Non-secret proof of the post-restore W8-A fencing transaction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct W8aFenceReceipt {
    pub new_cluster_incarnation: Uuid,
    pub new_storage_authority_id: Uuid,
    pub new_storage_restore_generation: i64,
    pub new_storage_authority_epoch: i64,
    pub remote_delete_fenced: bool,
    pub revoked_tokens: i64,
    pub revoked_sessions: i64,
    pub cancelled_ci_runs: i64,
    pub revoked_ci_checkouts: i64,
    pub expired_workspaces: i64,
    pub cancelled_decisions: i64,
    pub advanced_decision_scopes: i64,
    pub released_pins: i64,
    pub aborted_pull_merges: i64,
    pub reset_deliveries: i64,
}

pub(super) async fn fence(client: &mut Client, lineage: RestoreLineage) -> Result<()> {
    let tx = client.transaction().await?;
    rotate_cluster_incarnation(&tx, lineage).await?;
    tx.batch_execute(
        "DELETE FROM public.cluster_transport_nonces;
         UPDATE public.ci_runs SET state='cancelled',lease_generation=lease_generation+1,
             lease_expires_unix=0,runner_id=NULL,updated_at=clock_timestamp()
             WHERE state IN ('queued','leased');
         UPDATE public.ci_mirror_nodes SET active=false,ready_oids='[]'::jsonb,heartbeat_unix=0;
         UPDATE public.forge_webhook_deliveries SET state='pending',lease_generation=lease_generation+1,
             next_attempt_unix=0 WHERE state='leased';
         UPDATE public.ref_cas_projection_jobs SET state='queued',claim_generation=claim_generation+1,
             lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
             WHERE state='running';
         UPDATE public.workspaces SET lease_epoch=lease_epoch+1,
             lease_until=clock_timestamp()-interval '1 second' WHERE state='ready';
         UPDATE public.sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp()
             WHERE state IN ('queued','preparing','running');
         UPDATE public.tokens SET revoked=true WHERE kind='browser';
         UPDATE public.web_sessions SET revoked=true;",
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Post-restore W8-A incarnation/capability/deleter fencing.
pub async fn fence_w8a_fresh_incarnation(
    client: &mut Client,
    source_cluster_incarnation: Uuid,
    source_storage_authority_epoch: i64,
) -> Result<W8aFenceReceipt> {
    fence_w8a(client, source_cluster_incarnation, source_storage_authority_epoch, RestoreLineage::None).await
}

pub(super) async fn fence_w8a_fresh_incarnation_from_restore(
    client: &mut Client,
    source_cluster_incarnation: Uuid,
    source_storage_authority_epoch: i64,
    carry_lineage: bool,
) -> Result<W8aFenceReceipt> {
    let lineage = if carry_lineage {
        RestoreLineage::VerifiedW8aSource(source_cluster_incarnation)
    } else {
        RestoreLineage::None
    };
    fence_w8a(client, source_cluster_incarnation, source_storage_authority_epoch, lineage).await
}

async fn fence_w8a(
    client: &mut Client,
    source_cluster_incarnation: Uuid,
    source_storage_authority_epoch: i64,
    lineage: RestoreLineage,
) -> Result<W8aFenceReceipt> {
    ensure!(source_storage_authority_epoch >= 1, "source storage authority epoch is invalid");
    fence(client, lineage).await?;
    let tx = client.transaction().await?;
    tx.execute("UPDATE public.tokens SET revoked=true WHERE NOT revoked", &[]).await?;
    tx.execute("UPDATE public.web_sessions SET revoked=true WHERE NOT revoked", &[]).await?;
    tx.execute("UPDATE public.ci_checkout_jobs SET revoked=true WHERE plan IS NOT NULL AND NOT revoked", &[]).await?;
    tx.execute(RESET_DELIVERIES, &[]).await?;
    let counts = tx
        .query_one(
            "SELECT (SELECT count(*) FROM public.tokens WHERE revoked),
                    (SELECT count(*) FROM public.web_sessions WHERE revoked),
                    (SELECT count(*) FROM public.ci_runs WHERE state='cancelled'),
                    (SELECT count(*) FROM public.ci_checkout_jobs WHERE plan IS NOT NULL AND revoked),
                    (SELECT count(*) FROM public.event_deliveries WHERE state='pending')",
            &[],
        )
        .await?;
    let (revoked_tokens, revoked_sessions): (i64, i64) = (counts.get(0), counts.get(1));
    let cancelled_ci_runs: i64 = counts.get(2);
    let revoked_ci_checkouts: i64 = counts.get(3);
    let reset_deliveries: i64 = counts.get(4);
    let expired_workspaces = tx.execute(FENCED_WORKSPACES, &[]).await? as i64;
    let cancelled_decisions = tx.execute(CANCELLED_DECISIONS, &[]).await? as i64;
    let advanced_decision_scopes =
        tx.execute("UPDATE public.ref_store_decision_scopes SET version=version+1", &[]).await? as i64;
    let released_pins = tx.execute(RELEASED_PINS, &[]).await? as i64;
    let has_remote = tx
        .query_one("SELECT to_regclass('public.pull_remote_merge_attempts') IS NOT NULL", &[])
        .await?
        .get::<_, bool>(0);
    let aborted_pull_merges = if has_remote { tx.execute(ABORTED_PULLS, &[]).await? as i64 } else { 0 };
    let row = tx.query_one(FENCED_AUTHORITY, &[&source_storage_authority_epoch]).await?;
    let new_storage_authority_id: Uuid = row.get(0);
    let new_storage_restore_generation: i64 = row.get(1);
    let new_storage_authority_epoch: i64 = row.get(2);
    let remote_delete_fenced: bool = row.get(3);
    ensure!(remote_delete_fenced, "restored storage authority is not remote-delete fenced");
    ensure!(
        new_storage_authority_epoch > source_storage_authority_epoch,
        "restored storage authority epoch did not advance past the source"
    );
    let new_cluster_incarnation: Uuid =
        tx.query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton=true", &[]).await?.get(0);
    ensure!(
        new_cluster_incarnation != source_cluster_incarnation,
        "restored cluster incarnation equals the source incarnation"
    );
    tx.commit().await?;
    Ok(W8aFenceReceipt {
        new_cluster_incarnation,
        new_storage_authority_id,
        new_storage_restore_generation,
        new_storage_authority_epoch,
        remote_delete_fenced,
        revoked_tokens,
        revoked_sessions,
        cancelled_ci_runs,
        revoked_ci_checkouts,
        expired_workspaces,
        cancelled_decisions,
        advanced_decision_scopes,
        released_pins,
        aborted_pull_merges,
        reset_deliveries,
    })
}
