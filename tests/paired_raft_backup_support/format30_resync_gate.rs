//! Exercise source projection gaps before and during the live paired freeze.
use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use uuid::Uuid;

use rootyard::config::Config;
use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeRequest, DurableRaftBackend, ExpectedGroupCursorCut, Format30PairedBackupRequest, MtlsLiveRaftBackend,
    PairedBackupError, PeerGroupBackupInput, create_format30_paired_raft_backup, enter_durable_pg_raft_freeze,
    read_pg_database_freeze_marker, read_pg_database_read_only,
};
use rootyard::ref_store::projector::{
    ProjectionError, ProjectionRealm, RefCasEventPage, TruncationCutoff, compute_truncation_closure_digest,
    replay_page_to_pg,
};

use super::fixture::LoopbackS3;

const SOURCE_RESYNC_EVIDENCE: &str = "SELECT jsonb_build_object(
    'cursor', to_jsonb(c),
    'effects', ARRAY[(SELECT count(*) FROM public.ref_cas_projected_events),
          (SELECT count(*) FROM public.ref_cas_projected_operations),
          (SELECT count(*) FROM public.ref_cas_projected_refs),
          (SELECT count(*) FROM public.ref_cas_projection_jobs)],
    'scopes', (SELECT jsonb_agg(to_jsonb(s) ORDER BY s.scope_kind, s.scope_id)
               FROM public.ref_store_decision_scopes s),
    'deleter', (SELECT to_jsonb(p) FROM public.pando_storage_authorities p WHERE p.singleton))
    FROM public.ref_cas_projection_cursors c WHERE c.group_id=$1 AND c.history_incarnation=$2";

const DATABASE_SETTINGS: &str = "SELECT ARRAY(
    SELECT setting FROM pg_db_role_setting, unnest(setconfig) AS setting
    WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) AND setrole=0
    ORDER BY setting)";

async fn replay_gap_while_freeze_waits(
    holder: tokio_postgres::Transaction<'_>,
    freeze_pid: i32,
    pool: &deadpool_postgres::Pool,
    page: &RefCasEventPage,
) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let blocked: bool =
                holder.query_one("SELECT pg_backend_pid() = ANY(pg_blocking_pids($1))", &[&freeze_pid]).await?.get(0);
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, tokio_postgres::Error>(())
    })
    .await??;
    ensure!(
        matches!(replay_page_to_pg(pool, page).await, Err(ProjectionError::TruncatedBeforeCursor { .. })),
        "the projector did not record the truncation gap"
    );
    let evidence = holder
        .query_one(SOURCE_RESYNC_EVIDENCE, &[&page.realm.group_id, &page.realm.history_incarnation])
        .await?
        .get(0);
    holder.commit().await?;
    Ok(evidence)
}

pub(super) async fn verify(
    client: &mut tokio_postgres::Client,
    raft: &mut MtlsLiveRaftBackend,
    peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
    req: &DurableFreezeRequest<'_>,
    src_cfg: &Config,
    s3: &LoopbackS3,
) -> Result<()> {
    let staging_dir = src_cfg.data_dir.parent().ok_or_else(|| anyhow!("source volume has no parent"))?;
    let store = s3.open_store("paired-fmt30-s3")?;
    let pool = db::pool(req.fence_database_url)?;
    let database: String = client.query_one("SELECT current_database()", &[]).await?.get(0);
    let src_db = format!("\"{}\"", database.replace('"', "\"\""));
    let raft_before = raft.durable_state()?;
    ensure!(raft_before.0.body.next_event_seq > 0, "the source Raft group has no terminal events");
    let cut = ExpectedGroupCursorCut::from_verified_snapshot(raft.group_id(), &raft_before.0)?;
    let (group_id, history, group_epoch) = (cut.group_id, cut.history_incarnation, cut.group_epoch);
    let marker = "paired-resync-last-event-evidence";
    let closure_digest = "a".repeat(64);
    client
        .execute(
            "INSERT INTO public.ref_cas_projection_cursors(
            group_id,history_incarnation,group_epoch,last_event_id,stream_state,
            truncation_cutoff_log_index,truncation_cutoff_event_seq,truncation_cutoff_log_term,
            truncation_closure_digest,truncation_archive_uri)
         VALUES($1,$2,$3,$4,'resync_required',1,1,1,$5,'s3://projection-archive/known-cut')",
            &[&group_id, &history, &group_epoch, &marker, &closure_digest],
        )
        .await?;
    let source_before: serde_json::Value =
        client.query_one(SOURCE_RESYNC_EVIDENCE, &[&group_id, &history]).await?.get(0);
    ensure!(source_before["effects"] == json!([0, 0, 0, 0]), "the source unexpectedly has projected effects");
    let active_freeze_before = raft.read_freeze_record()?;
    let peer_freeze_before = peer_rafts[&2].read_freeze_record()?;
    let peer_before = peer_rafts[&2].durable_state()?;
    let refused_dir = staging_dir.join("resync-refused-archive");
    let refused = async {
        let freeze = enter_durable_pg_raft_freeze(client, raft, peer_rafts, req).await?;
        let peer_inputs = vec![PeerGroupBackupInput {
            group_id: 2,
            freeze_barrier: &freeze.peer_barriers[&2],
            raft: &peer_rafts[&2],
        }];
        let _s3_env = s3.apply_env("paired-fmt30-s3");
        create_format30_paired_raft_backup(Format30PairedBackupRequest {
            backup_id: Uuid::new_v4(),
            src_config: src_cfg,
            freeze_handle: &freeze,
            raft: &*raft,
            peer_groups: peer_inputs,
            store: &store,
            staging_dir,
            destination: &refused_dir,
        })
        .await
    }
    .await;
    let Err(PairedBackupError::CutpointSkew(detail)) = refused else {
        anyhow::bail!("an explicitly resync-required source cursor did not refuse paired backup");
    };
    ensure!(detail.contains("requires resync"), "unexpected refusal: {detail}");
    ensure!(!refused_dir.exists(), "resync refusal published an archive");
    let source_after: serde_json::Value =
        client.query_one(SOURCE_RESYNC_EVIDENCE, &[&group_id, &history]).await?.get(0);
    ensure!(source_after == source_before, "resync refusal changed the source ledger");
    ensure!(read_pg_database_freeze_marker(client).await?.is_none());
    ensure!(!read_pg_database_read_only(client).await?);
    ensure!(raft.read_freeze_record()? == active_freeze_before);
    ensure!(peer_rafts[&2].read_freeze_record()? == peer_freeze_before);
    ensure!(raft.durable_state()? == raft_before);
    ensure!(peer_rafts[&2].durable_state()? == peer_before);
    let deleted = client
        .execute(
            "DELETE FROM public.ref_cas_projection_cursors WHERE group_id=$1 AND history_incarnation=$2",
            &[&group_id, &history],
        )
        .await?;
    ensure!(deleted == 1, "resync fixture could not remove its own cursor after refusal");
    eprintln!("PAIRED_153_RESYNC_REFUSED: no archive or changed source ledger, no freeze left behind");

    client
        .batch_execute(&format!(
            "ALTER DATABASE {src_db} SET default_transaction_read_only = off;
         ALTER DATABASE {src_db} SET lock_timeout = '777ms'"
        ))
        .await?;
    let settings_before: Vec<String> = client.query_one(DATABASE_SETTINGS, &[]).await?.get(0);
    let freeze_pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
    let mut latch_conn = db::connect_url(req.fence_database_url).await?;
    let holder = latch_conn.transaction().await?;
    // Block the freeze's first ALTER DATABASE after preflight without
    // updating its settings tuple and causing a concurrent-update error.
    holder.batch_execute("SET LOCAL TIME ZONE 'UTC'; LOCK TABLE pg_catalog.pg_db_role_setting IN SHARE MODE").await?;
    let first = raft_before.0.body.events.first().ok_or_else(|| anyhow!("source event missing"))?;
    let realm = ProjectionRealm::new(history, group_id, group_epoch)?;
    let page = RefCasEventPage {
        realm,
        events: Vec::new(),
        earliest_available_event_seq: first.event_seq + 1,
        earliest_available_log_index: first.log_index + 1,
        truncation_cutoff: Some(TruncationCutoff {
            log_index: first.log_index,
            event_seq: first.event_seq,
            log_term: first.log_term,
            closure_digest: compute_truncation_closure_digest(
                &realm,
                first.log_index,
                first.event_seq,
                first.log_term,
                None,
            )?,
            archive_uri: Some("s3://projection-archive/late-cut".into()),
        }),
        has_more: false,
    };
    let (late_refused, late_source) = tokio::join!(
        enter_durable_pg_raft_freeze(client, raft, peer_rafts, req),
        replay_gap_while_freeze_waits(holder, freeze_pid, &pool, &page),
    );
    let late_source = late_source?;
    let Err(late_error) = late_refused else {
        anyhow::bail!("a projection gap recorded during freeze entry did not refuse the cut");
    };
    ensure!(
        matches!(&late_error, PairedBackupError::CutpointSkew(detail) if detail.contains("requires resync")),
        "unexpected refusal for a projection gap recorded during freeze entry: {late_error}"
    );
    ensure!(late_source["cursor"]["stream_state"] == "resync_required");
    ensure!(late_source["effects"] == source_before["effects"]);
    let late_after: serde_json::Value = client.query_one(SOURCE_RESYNC_EVIDENCE, &[&group_id, &history]).await?.get(0);
    ensure!(
        late_after == late_source,
        "late resync refusal changed the source ledger from {late_source} to {late_after}"
    );
    let settings_after: Vec<String> = client.query_one(DATABASE_SETTINGS, &[]).await?.get(0);
    ensure!(settings_after == settings_before, "late resync refusal stranded a PG freeze");
    ensure!(raft.read_freeze_record()? == active_freeze_before);
    ensure!(peer_rafts[&2].read_freeze_record()? == peer_freeze_before);
    ensure!(raft.durable_state()? == raft_before);
    ensure!(peer_rafts[&2].durable_state()? == peer_before);
    let deleted = client
        .execute(
            "DELETE FROM public.ref_cas_projection_cursors WHERE group_id=$1 AND history_incarnation=$2",
            &[&group_id, &history],
        )
        .await?;
    ensure!(deleted == 1, "late resync fixture could not remove its own cursor");
    client
        .batch_execute(&format!(
            "ALTER DATABASE {src_db} RESET default_transaction_read_only;
         ALTER DATABASE {src_db} RESET lock_timeout"
        ))
        .await?;
    eprintln!("PAIRED_153_LATE_RESYNC_REFUSED: persisted projector evidence, restored exact PG settings");
    Ok(())
}
