//! Authoritative PostgreSQL 17 & Ref-CAS state reconciliation for Safe GC (#122).

use std::collections::{BTreeMap, BTreeSet};

use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::{blob_store::opendal::BlobStore, ref_store::core::state_machine::RefCasStateMachine};

use super::{
    SafeGcError,
    model::{
        DecisionKind, DecisionState, GlobalHoldEntry, GlobalHoldState, InFlightDecisionRecord, LiveRefRoot,
        PairedCursorReconciliation, ProducerReconciliationEntry, RetentionProducer, SourceFreshness,
    },
    quiescence::ActiveReaderLease,
    refcas_cut::RefCasReconciledCut,
    store::DurableSafeGcAuthority,
};

pub struct PgRefstoreReconciledSummary {
    pub tenant_id: Uuid,
    pub history_id: Uuid,
    pub gate_revision: u64,
    pub gc_epoch: u64,
}

pub async fn reconcile_pg_refstore_authority<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    blob_store: &BlobStore,
    authority: &DurableSafeGcAuthority,
    pg_gc_fence_epoch: Option<u64>,
) -> Result<PgRefstoreReconciledSummary, SafeGcError> {
    let row = client
        .query_opt(
            "SELECT r.owner_id, r.gc_epoch, b.history_incarnation, b.authority_epoch, \
                    b.backend_identity, g.revision, p.roots_revision \
             FROM repositories r \
             JOIN ref_store_serving_repositories b ON b.repository_id = r.id \
             JOIN ref_store_core_gates g ON g.repository_id = r.id \
             JOIN ref_store_core_protocol_repos p ON p.repository_id = r.id \
             WHERE r.id = $1 AND r.state = 'ready' AND r.storage_backend = 'pg_refstore' AND b.state = 'ready'",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("query pg_refstore binding failed: {e}")))?
        .ok_or(SafeGcError::IncompleteProof("pg_refstore serving repository not ready"))?;

    let tenant_id: Uuid = row.get(0);
    let gc_epoch_i64: i64 = row.get(1);
    let history_id: Uuid = row.get(2);
    let authority_epoch_i64: i64 = row.get(3);
    let backend_identity: String = row.get(4);
    let gate_revision_i64: i64 = row.get(5);
    let roots_revision_i64: i64 = row.get(6);

    if backend_identity != blob_store.backend_identity().as_hex() {
        return Err(SafeGcError::IncompleteProof("pg_refstore backend_identity disagrees with opened BlobStore"));
    }

    let snap_before = authority.snapshot();
    if snap_before.authority.tenant_id != tenant_id
        || snap_before.authority.repo_id != repo_id
        || snap_before.authority.history_id != history_id
    {
        return Err(SafeGcError::IncompleteProof("safe_gc journal identity disagrees with pg_refstore binding"));
    }

    let gate_rev = (gate_revision_i64.max(1)) as u64;
    let roots_rev = (roots_revision_i64.max(0)) as u64;
    let live_refs = load_pg_live_refs(client, repo_id, gate_rev).await?;
    let max_ref_seq = live_refs.iter().map(|r| r.version_seq).max().unwrap_or(gate_rev).max(gate_rev);

    if authority_epoch_i64 <= 0 || snap_before.authority.incarnation_epoch < authority_epoch_i64 as u64 {
        return Err(SafeGcError::IncompleteProof("safe_gc incarnation_epoch lags pg_refstore authority_epoch"));
    }
    let producers = load_pg_producers(
        client,
        repo_id,
        tenant_id,
        max_ref_seq.max(roots_rev),
        snap_before.authority.incarnation_epoch,
    )
    .await?;
    let sql_holds = load_pg_artifact_holds(client, repo_id, tenant_id, snap_before.authority.incarnation_epoch).await?;
    let sql_decisions = load_pg_open_decisions(client, repo_id, max_ref_seq).await?;
    let transient_reads =
        load_pg_serving_read_leases(client, repo_id, snap_before.authority.membership_generation).await?;
    let (refcas_freshness, refcas_applied_index, refcas_required_index, refcas_cut) =
        load_pg_refcas_stream_state(client, repo_id, history_id, &snap_before.paired_cursors).await?;

    let cursors = PairedCursorReconciliation {
        pg_freshness: SourceFreshness::Reconciled,
        pg_applied_seq: max_ref_seq.max(roots_rev),
        pg_required_seq: max_ref_seq.max(roots_rev),
        refcas_freshness,
        refcas_applied_index,
        refcas_required_index,
        refcas_cut,
    };

    authority.apply_pg_reconciled_bundle(super::store_reconcile::PgReconciledBundle {
        live_refs,
        max_ref_seq,
        producers,
        cursors,
        sql_holds,
        sql_decisions,
        transient_reads,
        pg_gc_fence_epoch,
    })?;

    Ok(PgRefstoreReconciledSummary {
        tenant_id,
        history_id,
        gate_revision: gate_rev,
        gc_epoch: gc_epoch_i64.max(0) as u64,
    })
}

pub fn reconcile_refcas_quorum_into_authority(
    sm: &RefCasStateMachine,
    repo_id: Uuid,
    raft_commit_index: u64,
    authority: &DurableSafeGcAuthority,
) -> Result<(), SafeGcError> {
    let gate_ver = sm
        .read_gate_version(repo_id)
        .map_err(|_| SafeGcError::IncompleteProof("refcas repository gate version unreadable"))?;
    if gate_ver.is_none() {
        return Err(SafeGcError::IncompleteProof("refcas repository gate not initialized"));
    }
    let applied_idx = sm.last_applied().map(|id| id.index).unwrap_or(0);
    if applied_idx < raft_commit_index {
        return Err(SafeGcError::IncompleteProof("refcas state machine lags required raft_commit_index"));
    }
    let refs_map = sm.read_refs(repo_id);
    let mut live_refs = Vec::with_capacity(refs_map.len());
    for (ref_name, target_oid) in refs_map {
        live_refs.push(LiveRefRoot { ref_name, target_oid, version_seq: raft_commit_index.max(1) });
    }
    authority.apply_refcas_quorum_refs(live_refs, raft_commit_index.max(1))
}

async fn load_pg_live_refs<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    gate_rev: u64,
) -> Result<Vec<LiveRefRoot>, SafeGcError> {
    let rows = client
        .query(
            "SELECT ref_name, oid, revision FROM ref_store_core_refs WHERE repository_id = $1 ORDER BY ref_name",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_store_core_refs failed: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|r| LiveRefRoot {
            ref_name: r.get::<_, String>(0),
            target_oid: r.get::<_, String>(1),
            version_seq: (r.get::<_, i64>(2).max(1) as u64).max(gate_rev),
        })
        .collect())
}

async fn load_pg_producers<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    tenant_id: Uuid,
    cursor_seq: u64,
    epoch: u64,
) -> Result<Vec<ProducerReconciliationEntry>, SafeGcError> {
    let sql_pins = super::super::retention::collect_sql_roots(client, repo_id)
        .await
        .map_err(|e| SafeGcError::Io(format!("collect_sql_roots failed: {e}")))?;
    let mut oids_by_prod: BTreeMap<RetentionProducer, BTreeSet<String>> = BTreeMap::new();
    let mut packs_by_prod: BTreeMap<RetentionProducer, BTreeSet<Uuid>> = BTreeMap::new();
    for p in RetentionProducer::ALL {
        oids_by_prod.insert(p, BTreeSet::new());
        packs_by_prod.insert(p, BTreeSet::new());
    }
    for pin in sql_pins {
        let prod = match pin.kind.as_str() {
            "pull_head" | "pull_base" | "pull_merge" | "pull_review" | "check_run" => RetentionProducer::PullRequest,
            "ci_run_head" | "ci_run_base" | "ci_checkout_pin" | "ci_integration_pin" | "ci_pull_sync_head"
            | "ci_pull_sync_base" | "ci_sandbox_head" => RetentionProducer::CiPin,
            "namespace_mount" => RetentionProducer::Namespace,
            _ => RetentionProducer::Workspace,
        };
        if let Some(bucket) = oids_by_prod.get_mut(&prod) {
            bucket.insert(pin.oid);
        }
    }

    let root_oid_rows = client
        .query(
            "SELECT h.purpose, o.oid FROM ref_store_core_root_heads h \
             JOIN ref_store_core_root_oids o ON o.repository_id=h.repository_id AND o.root_id=h.root_id AND o.generation=1 \
             WHERE h.repository_id=$1 AND h.state='active' \
             UNION ALL \
             SELECT h.purpose, r.oid FROM ref_store_core_root_heads h \
             JOIN ref_store_core_root_refs r ON r.repository_id=h.repository_id AND r.root_id=h.root_id AND r.generation=1 \
             WHERE h.repository_id=$1 AND h.state='active'",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read protocol root oids failed: {e}")))?;
    for row in root_oid_rows {
        let prod = map_root_purpose(row.get::<_, &str>(0));
        if let Some(bucket) = oids_by_prod.get_mut(&prod) {
            bucket.insert(row.get(1));
        }
    }

    let root_pack_rows = client
        .query(
            "SELECT h.purpose, p.pack_id FROM ref_store_core_root_heads h \
             JOIN ref_store_core_root_packs p ON p.repository_id=h.repository_id AND p.root_id=h.root_id AND p.generation=1 \
             WHERE h.repository_id=$1 AND h.state='active'",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read protocol root packs failed: {e}")))?;
    for row in root_pack_rows {
        let prod = map_root_purpose(row.get::<_, &str>(0));
        if let Some(bucket) = packs_by_prod.get_mut(&prod) {
            bucket.insert(row.get(1));
        }
    }

    let pending_lfs: i64 = client
        .query_one(
            "SELECT count(*) FROM lfs_objects WHERE repository_id=$1 AND tenant_id=$2 AND state='pending'",
            &[&repo_id, &tenant_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read lfs_objects failed: {e}")))?
        .get(0);

    Ok(RetentionProducer::ALL
        .into_iter()
        .map(|prod| {
            let freshness = if prod == RetentionProducer::Lfs && pending_lfs > 0 {
                SourceFreshness::Lagging { behind_seq: pending_lfs as u64 }
            } else {
                SourceFreshness::Reconciled
            };
            ProducerReconciliationEntry {
                producer: prod,
                freshness,
                observed_cursor_seq: cursor_seq.max(1),
                required_cursor_seq: cursor_seq.max(1),
                authority_epoch: epoch,
                expected_authority_epoch: epoch,
                root_oids: oids_by_prod.remove(&prod).unwrap_or_default().into_iter().collect(),
                pinned_pack_ids: packs_by_prod.remove(&prod).unwrap_or_default().into_iter().collect(),
            }
        })
        .collect())
}

fn map_root_purpose(purpose: &str) -> RetentionProducer {
    match purpose {
        "pull_request" => RetentionProducer::PullRequest,
        "ci" => RetentionProducer::CiPin,
        "workspace" => RetentionProducer::Workspace,
        "namespace" => RetentionProducer::Namespace,
        _ => RetentionProducer::Backup,
    }
}

async fn load_pg_artifact_holds<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    tenant_id: Uuid,
    epoch: u64,
) -> Result<Vec<GlobalHoldEntry>, SafeGcError> {
    let rows = client
        .query(
            "SELECT h.hold_id, p.pack_id FROM artifact_holds h \
             LEFT JOIN ref_store_core_pack_artifacts p ON p.hold_id = h.hold_id \
             WHERE h.repository_id=$1 AND h.tenant_id=$2 AND h.state='active' \
               AND NOT EXISTS (SELECT 1 FROM artifact_hold_consume_receipts c WHERE c.hold_id = h.hold_id)",
            &[&repo_id, &tenant_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read unconsumed artifact_holds failed: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|r| GlobalHoldEntry {
            hold_id: r.get(0),
            tenant_id,
            repo_id,
            incarnation_epoch: epoch,
            registered_seq: 1,
            state: GlobalHoldState::Active,
            protected_pack_ids: r.get::<_, Option<Uuid>>(1).into_iter().collect(),
            protected_oids: Vec::new(),
            protected_physical_keys: Vec::new(),
        })
        .collect())
}

async fn load_pg_open_decisions<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    seq: u64,
) -> Result<Vec<InFlightDecisionRecord>, SafeGcError> {
    let rows = client
        .query(
            "SELECT d.decision_id, d.action, d.merge_head_oid, d.merge_base_oid, r.new_oid \
             FROM ref_store_publication_decisions d \
             LEFT JOIN ref_store_decision_refs r ON r.decision_id = d.decision_id AND r.verdict = 'accept' \
             WHERE d.repository_id = $1 AND d.state = 'OPEN'",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_store_publication_decisions failed: {e}")))?;
    let mut map: BTreeMap<Uuid, (DecisionKind, BTreeSet<String>)> = BTreeMap::new();
    for r in rows {
        let id: Uuid = r.get(0);
        let action: &str = r.get(1);
        let kind = if action == "merge" { DecisionKind::PullMerge } else { DecisionKind::Push };
        let entry = map.entry(id).or_insert_with(|| (kind, BTreeSet::new()));
        for col in [2, 3, 4] {
            if let Some(oid) = r.get::<_, Option<String>>(col) {
                entry.1.insert(oid);
            }
        }
    }
    Ok(map
        .into_iter()
        .map(|(decision_id, (kind, oids))| InFlightDecisionRecord {
            decision_id,
            kind,
            state: DecisionState::Pending,
            snapshot_seq: seq,
            protected_pack_ids: Vec::new(),
            protected_oids: oids.into_iter().collect(),
        })
        .collect())
}

async fn load_pg_serving_read_leases<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    fallback_gen: u64,
) -> Result<Vec<ActiveReaderLease>, SafeGcError> {
    let rows = client
        .query(
            "SELECT r.pin_id, r.gate_revision, p.pack_id \
             FROM ref_store_core_serving_reads r \
             LEFT JOIN ref_store_core_serving_read_packs p ON p.pin_id = r.pin_id \
             WHERE r.repository_id = $1 AND r.expires_at > clock_timestamp()",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_store_core_serving_reads failed: {e}")))?;
    let mut map: BTreeMap<Uuid, (u64, Vec<Uuid>)> = BTreeMap::new();
    for r in rows {
        let pin_id: Uuid = r.get(0);
        let gate_rev = (r.get::<_, i64>(1).max(1) as u64).min(fallback_gen);
        let entry = map.entry(pin_id).or_insert_with(|| (gate_rev, Vec::new()));
        if let Some(pack_id) = r.get::<_, Option<Uuid>>(2) {
            entry.1.push(pack_id);
        }
    }
    Ok(map
        .into_iter()
        .enumerate()
        .map(|(i, (lease_id, (pinned_generation, pinned_pack_ids)))| ActiveReaderLease {
            lease_id,
            reader_label: "pg_serving_read_pin".into(),
            pinned_generation,
            pinned_pack_ids,
            acquired_seq: (i + 1) as u64,
        })
        .collect())
}

async fn load_pg_refcas_stream_state<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    history_id: Uuid,
    prev: &PairedCursorReconciliation,
) -> Result<(SourceFreshness, u64, u64, Option<RefCasReconciledCut>), SafeGcError> {
    let unresolved_jobs: i64 = client
        .query_one(
            "SELECT count(*) FROM ref_cas_projection_jobs \
             WHERE repository_id = $1 AND state IN ('queued','running','unknown_hold','failed')",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_cas_projection_jobs failed: {e}")))?
        .get(0);
    if unresolved_jobs > 0 {
        return Ok((SourceFreshness::Lagging { behind_seq: unresolved_jobs as u64 }, 0, 1, None));
    }

    let rows = client
        .query(
            "SELECT group_id, group_epoch, applied_event_seq, applied_log_index, applied_log_term, stream_state \
             FROM ref_cas_projection_cursors WHERE history_incarnation = $1 ORDER BY group_id",
            &[&history_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_cas_projection_cursors failed: {e}")))?;

    if rows.is_empty() {
        if let Some(ref cut) = prev.refcas_cut {
            return Ok((
                SourceFreshness::Reconciled,
                cut.sm_applied_log_index,
                cut.sm_applied_log_index.max(1),
                Some(cut.clone()),
            ));
        }
        return Ok((SourceFreshness::Reconciled, 0, 0, None));
    }

    let mut max_proj_idx = 0_u64;
    for r in &rows {
        let state: &str = r.get(5);
        if state != "active" {
            return Ok((SourceFreshness::Unknown, 0, 1, None));
        }
        let g_id: i64 = r.get(0);
        let g_epoch = r.get::<_, i64>(1).max(0) as u64;
        let ev_seq = r.get::<_, i64>(2).max(0) as u64;
        let log_idx = r.get::<_, i64>(3).max(0) as u64;
        let log_term = r.get::<_, i64>(4).max(0) as u64;
        max_proj_idx = max_proj_idx.max(log_idx);
        let matched = prev.refcas_cut.as_ref().is_some_and(|cut| {
            cut.history_id == history_id
                && cut.group_id == g_id
                && cut.group_epoch == g_epoch
                && cut.pg_projected_event_seq == ev_seq
                && cut.pg_projected_log_index == log_idx
                && cut.pg_projected_log_term == log_term
                && cut.verify_reconciled(history_id, 1, g_epoch).is_ok()
        });
        if !matched {
            return Ok((SourceFreshness::Unknown, 0, max_proj_idx.max(1), None));
        }
    }

    let cut = prev.refcas_cut.clone().expect("verified matching refcas_cut");
    Ok((SourceFreshness::Reconciled, cut.sm_applied_log_index, cut.sm_applied_log_index.max(1), Some(cut)))
}
