//! A fresh paired Raft history cannot replay an old public terminal.
use anyhow::{Result, ensure};
use deadpool_postgres::Client;
use uuid::Uuid;

use super::Realm;

pub(super) async fn verify_historical_wrapper_realm_refusal(
    client: &Client,
    repository_id: Uuid,
    old: Realm,
    live_incarnation: Uuid,
) -> Result<()> {
    let old_public = client
        .query(
            "SELECT public_id FROM public.ref_store_public_operations
          WHERE repository_id=$1 AND state='committed'
            AND (history_incarnation,authority_epoch,group_epoch)=($2,$3,$4)",
            &[&repository_id, &old.0, &old.1, &old.2],
        )
        .await?;
    ensure!(old_public.len() == 2, "expected both old committed public operations to be preserved");
    for row in old_public {
        let public_id: Uuid = row.get(0);
        let refusal = client
            .query_one(
                "SELECT rootyard_ref_store_attempt_current_scope(
                 jsonb_populate_record(w, jsonb_build_object('restore_incarnation', $3::uuid)))
             FROM public.ref_store_public_operations w WHERE (w.repository_id,w.public_id)=($1,$2)",
                &[&repository_id, &public_id, &live_incarnation],
            )
            .await
            .expect_err("old terminal must fail the current realm proof in a fresh #153 history");
        ensure!(
            refusal.code() == Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "old terminal received a non-scope refusal after the history rebind"
        );
    }
    Ok(())
}
