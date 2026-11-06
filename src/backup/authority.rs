//! Restoring older durable state must not resurrect execution credentials.
use anyhow::Result;
use tokio_postgres::Client;

pub(super) async fn fence(client: &Client) -> Result<()> {
    client.batch_execute(
        "BEGIN;
         UPDATE public.ci_runs SET state='cancelled',lease_generation=lease_generation+1,
             lease_expires_unix=0,runner_id=NULL,updated_at=clock_timestamp()
             WHERE state IN ('queued','leased');
         UPDATE public.ci_mirror_nodes SET active=false,ready_oids='[]'::jsonb,heartbeat_unix=0;
         UPDATE public.forge_webhook_deliveries SET state='pending',lease_generation=lease_generation+1,
             next_attempt_unix=0 WHERE state='leased';
         UPDATE public.workspaces SET lease_epoch=lease_epoch+1,
             lease_until=clock_timestamp()-interval '1 second' WHERE state='ready';
         UPDATE public.sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp()
             WHERE state IN ('queued','running');
         UPDATE public.tokens SET revoked=true WHERE kind='browser';
         UPDATE public.web_sessions SET revoked=true;
         COMMIT;"
    ).await?;
    Ok(())
}
