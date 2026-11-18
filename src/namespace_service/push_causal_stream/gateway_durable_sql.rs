//! Read-only PostgreSQL loaders for durable `CausalPushProofReceipt` settlement & replay (#183).

use std::collections::BTreeMap;
use std::str::FromStr;

use deadpool_postgres::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{Instant as TokioInstant, timeout_at};
use uuid::Uuid;

use crate::blob_store::BlobLocator;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::PackCommitTerminal;
use crate::ref_store::core::terminal::RefCommitResult;
use crate::ref_store::core::types::GitObjectFormat;

use super::gateway_bridge::RawClosurePackDesc;
use super::receipt::CommittedPackPairProof;
use super::types::PushCausalError;

pub(super) struct DecisionMeta {
    pub(super) tenant_id: Uuid,
    pub(super) history_incarnation: Uuid,
    pub(super) authority_epoch: i64,
    pub(super) group_epoch: i64,
    pub(super) object_format: GitObjectFormat,
    pub(super) base_revision: i64,
    pub(super) base_gate_digest: RequestDigest,
}

pub(super) async fn load_decision_or_gate_meta(
    client: &Client,
    repository_id: Uuid,
    operation_id: Uuid,
    terminal: &PackCommitTerminal,
    deadline: TokioInstant,
) -> Result<DecisionMeta, PushCausalError> {
    let dec = timeout_at(
        deadline,
        client.query_opt(
            "SELECT tenant_id, history_incarnation, authority_epoch, group_epoch, object_format, base_revision, base_gate_digest
             FROM ref_store_publication_decisions
             WHERE repository_id = $1 AND operation_id = $2",
            &[&repository_id, &operation_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;

    if let Some(r) = dec {
        let fmt = parse_git_fmt(r.get::<_, &str>(4))?;
        let dig = RequestDigest::from_str(r.get::<_, &str>(6))?;
        return Ok(DecisionMeta {
            tenant_id: r.get(0),
            history_incarnation: r.get(1),
            authority_epoch: r.get::<_, i64>(2).max(1),
            group_epoch: r.get::<_, i64>(3).max(1),
            object_format: fmt,
            base_revision: r.get::<_, i64>(5).max(1),
            base_gate_digest: dig,
        });
    }

    let gate = timeout_at(
        deadline,
        client.query_one(
            "SELECT tenant_id, history_incarnation, authority_epoch, group_epoch, object_format
             FROM ref_store_core_gates WHERE repository_id = $1",
            &[&repository_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;
    let ev = timeout_at(
        deadline,
        client.query_opt(
            "SELECT revision FROM ref_store_core_events WHERE repository_id = $1 AND operation_id = $2",
            &[&repository_id, &operation_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;
    let base_rev = ev.map_or(terminal.revision, |r| r.get::<_, i64>(0)).max(1);
    let fmt = parse_git_fmt(gate.get::<_, &str>(4))?;
    Ok(DecisionMeta {
        tenant_id: gate.get(0),
        history_incarnation: gate.get(1),
        authority_epoch: gate.get::<_, i64>(2).max(1),
        group_epoch: gate.get::<_, i64>(3).max(1),
        object_format: fmt,
        base_revision: base_rev,
        base_gate_digest: RequestDigest::of("gw-gate-fallback", &[repository_id.as_bytes(), &base_rev.to_be_bytes()]),
    })
}

pub(super) async fn load_historical_refs_at_revision(
    client: &Client,
    repository_id: Uuid,
    base_revision: i64,
    deadline: TokioInstant,
) -> Result<BTreeMap<String, String>, PushCausalError> {
    let rows = timeout_at(
        deadline,
        client.query(
            "SELECT payload FROM ref_store_core_events
             WHERE repository_id = $1 AND outcome = 'committed' AND revision <= $2
             ORDER BY revision ASC",
            &[&repository_id, &base_revision],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;

    #[derive(Deserialize)]
    struct EventRefsOnly {
        refs: Vec<RefCommitResult>,
    }

    let mut refs = BTreeMap::new();
    for r in rows {
        let payload: Value = r.get(0);
        let ev_term: EventRefsOnly = serde_json::from_value(payload).map_err(|e| PushCausalError::Io(e.to_string()))?;
        for res in ev_term.refs {
            if let RefCommitResult::Applied { name, new_oid, .. } = res {
                match new_oid {
                    Some(oid) => {
                        refs.insert(name, oid);
                    }
                    None => {
                        refs.remove(&name);
                    }
                }
            }
        }
    }
    Ok(refs)
}

pub(super) async fn load_historical_pack_descs(
    client: &Client,
    repository_id: Uuid,
    base_revision: i64,
    deadline: TokioInstant,
) -> Result<Vec<RawClosurePackDesc>, PushCausalError> {
    let rows = timeout_at(
        deadline,
        client.query(
            "SELECT m.pack_id, m.registration_id, m.artifact_set_digest,
                    pa.provider, pa.backend_identity, pa.sha256, pa.content_length,
                    hp.storage_tenant_id, hp.authority_id, hp.authority_generation, hp.attempt_id, hp.namespace,
                    ia.sha256, ia.content_length,
                    hi.storage_tenant_id, hi.authority_id, hi.authority_generation, hi.attempt_id, hi.namespace
             FROM ref_store_core_pack_memberships m
             JOIN ref_store_core_pack_artifacts pa ON pa.registration_id = m.registration_id AND pa.role = 'pack'
             JOIN artifact_holds hp ON hp.hold_id = pa.hold_id
             JOIN ref_store_core_pack_artifacts ia ON ia.registration_id = m.registration_id AND ia.role = 'idx'
             JOIN artifact_holds hi ON hi.hold_id = ia.hold_id
             WHERE m.repository_id = $1 AND m.joined_revision <= $2
             ORDER BY m.pack_id ASC",
            &[&repository_id, &base_revision],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;

    let mut raw_packs = Vec::with_capacity(rows.len());
    for r in rows {
        let p_len = u64::try_from(r.get::<_, i64>(6)).unwrap_or(0);
        let i_len = u64::try_from(r.get::<_, i64>(13)).unwrap_or(0);
        let p_loc = BlobLocator::new(
            r.get(7),
            r.get(8),
            r.get(9),
            r.get(10),
            r.get::<_, &str>(11),
            r.get::<_, &str>(5),
            p_len,
        )?;
        let i_loc = BlobLocator::new(
            r.get(14),
            r.get(15),
            r.get(16),
            r.get(17),
            r.get::<_, &str>(18),
            r.get::<_, &str>(12),
            i_len,
        )?;
        raw_packs.push(RawClosurePackDesc {
            pack_id: r.get(0),
            registration_id: r.get(1),
            artifact_set_digest_hex: r.get(2),
            provider: r.get(3),
            backend_identity: r.get(4),
            pack_sha256: r.get(5),
            pack_length: p_len,
            idx_sha256: r.get(12),
            idx_length: i_len,
            pack_locator: p_loc,
            idx_locator: i_loc,
        });
    }
    Ok(raw_packs)
}

pub(super) async fn load_all_operation_pack_pairs(
    client: &Client,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: TokioInstant,
) -> Result<(Vec<CommittedPackPairProof>, Vec<String>), PushCausalError> {
    let rows = timeout_at(
        deadline,
        client.query(
            "SELECT request_id, slot, storage_tenant_id, authority_id, authority_generation, attempt_id, namespace, sha256, content_length
             FROM artifact_holds
             WHERE repository_id = $1 AND operation_id = $2
             ORDER BY request_id ASC, slot ASC",
            &[&repository_id, &operation_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;

    let mut by_req: BTreeMap<Uuid, (Option<BlobLocator>, Option<BlobLocator>)> = BTreeMap::new();
    let mut all_paths = Vec::with_capacity(rows.len());
    for r in rows {
        let req_id: Uuid = r.get(0);
        let slot: i32 = r.get(1);
        let len = u64::try_from(r.get::<_, i64>(8)).unwrap_or(0);
        let loc =
            BlobLocator::new(r.get(2), r.get(3), r.get(4), r.get(5), r.get::<_, &str>(6), r.get::<_, &str>(7), len)?;
        all_paths.push(loc.path());
        let entry = by_req.entry(req_id).or_insert((None, None));
        if slot == 0 {
            entry.0 = Some(loc);
        } else if slot == 1 {
            entry.1 = Some(loc);
        }
    }
    let mut pairs = Vec::new();
    for (_, (p_opt, i_opt)) in by_req {
        if let (Some(p), Some(i)) = (p_opt, i_opt) {
            pairs.push(CommittedPackPairProof {
                pack_sha256: p.sha256().to_owned(),
                pack_bytes: p.length(),
                idx_sha256: i.sha256().to_owned(),
                idx_bytes: i.length(),
                pack_locator: Some(p),
                idx_locator: Some(i),
            });
        }
    }
    pairs.sort_by(|a, b| (&a.pack_sha256, &a.idx_sha256).cmp(&(&b.pack_sha256, &b.idx_sha256)));
    Ok((pairs, all_paths))
}

fn parse_git_fmt(s: &str) -> Result<GitObjectFormat, PushCausalError> {
    match s {
        "sha1" => Ok(GitObjectFormat::Sha1),
        "sha256" => Ok(GitObjectFormat::Sha256),
        _ => Err(PushCausalError::MalformedProtocol(format!("invalid object_format `{s}`"))),
    }
}
