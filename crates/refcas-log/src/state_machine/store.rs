use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::{BasicNode, EntryPayload, LogId, StoredMembership};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fault::{FaultController, FaultPoint};
use crate::fixture::verify_same_device;
use crate::state_machine::snapshot;
use crate::{
    E, EntryOf, Res, checksum, configure, get_meta, idx_from_i64, idx_to_i64, jd, je, lock_named_dir, meta, set_meta,
};

pub(crate) const SM_FORMAT_VERSION: &str = "rootyard-refcas-sm/1";
const SM_DB_FILE: &str = "sm.sqlite3";
const SM_LOCK_FILE: &str = ".raftsm.lock";
pub(crate) const MAX_KV_KEY_BYTES: usize = 4096;
pub(crate) const MAX_KV_VAL_BYTES: usize = 256 * 1024;
pub(crate) const ZERO_DIGEST_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const K_LAST_APPLIED: &str = "last_applied";
pub(crate) const K_LAST_MEMBERSHIP: &str = "last_membership";
pub(crate) const K_STATE_DIGEST: &str = "state_digest";
pub(crate) const K_APPLIED_COUNT: &str = "applied_count";
pub(crate) const K_SNAP_BASE_LOG_ID: &str = "snap_base_log_id";
pub(crate) const K_SNAP_BASE_BOUNDARY_DIGEST: &str = "snap_base_boundary_digest";

const META_SCHEMA: &str = "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32)) WITHOUT ROWID;";
const SM_ENTRIES_SCHEMA: &str = "CREATE TABLE sm_entries(idx INTEGER PRIMARY KEY, log_id TEXT NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL, entry_digest BLOB NOT NULL CHECK(length(entry_digest)=32), checksum BLOB NOT NULL CHECK(length(checksum)=32));";
const SM_KV_SCHEMA: &str = "CREATE TABLE sm_kv(k TEXT PRIMARY KEY, v TEXT NOT NULL, last_idx INTEGER NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32)) WITHOUT ROWID;";

/// Structured deterministic state-machine mutation carried inside `EntryPayload::Normal`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SmCommand {
    Put { key: String, value: String },
    Delete { key: String },
}

impl SmCommand {
    /// Decodes strict `SmCommand` JSON, rejecting unknown fields.
    pub fn decode_strict(bytes: &[u8]) -> Res<Self> {
        serde_json::from_slice(bytes).map_err(|e| E::Codec(format!("decode sm command: {e}")))
    }

    /// Encodes this command as compact JSON bytes for Raft log submission.
    pub fn encode(&self) -> Res<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| E::Codec(format!("encode sm command: {e}")))
    }
}

pub(crate) type AppliedState = (Option<LogId<u64>>, StoredMembership<u64, BasicNode>);

struct DecodedPayload {
    kind: &'static str,
    payload_bytes: Vec<u8>,
    kv_cmd: Option<SmCommand>,
    membership: Option<openraft::Membership<u64, BasicNode>>,
}

/// Summary of persistent state-machine state for tests and cluster probes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateMachineSummary {
    pub node_id: u64,
    pub last_applied: Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, BasicNode>,
    pub state_digest_hex: String,
    pub applied_count: u64,
    pub kv_count: usize,
    pub active_snapshot_id: Option<String>,
    pub active_snapshot_file: Option<String>,
}

pub(crate) struct SmInner {
    pub(crate) _lock: File,
    pub(crate) dir: PathBuf,
    pub(crate) node_id: u64,
    pub(crate) conn: Connection,
    pub(crate) fault: Arc<FaultController>,
}

impl SmInner {
    pub(crate) fn open(dir: &Path, node_id: u64, check_on_open: bool, fault: Arc<FaultController>) -> Res<Self> {
        let lock = lock_named_dir(dir, SM_LOCK_FILE, "state machine directory")?;
        let canonical_dir = dir.canonicalize()?;
        let db_path = canonical_dir.join(SM_DB_FILE);
        let existed = db_path.exists();
        if existed {
            verify_same_device(&canonical_dir, &db_path)?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
        let mut conn = Connection::open_with_flags(&db_path, flags)?;
        configure(&conn)?;

        let has_meta: i64 =
            conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'", [], |r| r.get(0))?;
        if has_meta == 0 {
            if existed {
                return Err(E::Refused("existing state machine db lacks meta table; refusing to reset".into()));
            }
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(META_SCHEMA)?;
            tx.execute_batch(SM_ENTRIES_SCHEMA)?;
            tx.execute_batch(SM_KV_SCHEMA)?;
            set_meta(&tx, "format", Some(SM_FORMAT_VERSION))?;
            set_meta(&tx, "node", Some(&node_id.to_string()))?;
            let empty_mem: StoredMembership<u64, BasicNode> = StoredMembership::default();
            set_meta(&tx, K_LAST_MEMBERSHIP, Some(&je(&empty_mem)?))?;
            set_meta(&tx, K_STATE_DIGEST, Some(ZERO_DIGEST_HEX))?;
            set_meta(&tx, K_APPLIED_COUNT, Some("0"))?;
            tx.commit()?;
        } else {
            for table in ["sm_entries", "sm_kv"] {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )?;
                if count != 1 {
                    return Err(E::Refused(format!("state machine db missing {table}; refusing to reset")));
                }
            }
        }

        validate_identity(&conn, node_id)?;
        if check_on_open {
            let qc: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if qc != "ok" {
                return Err(E::Refused(format!("state machine quick_check failed: {qc}")));
            }
        }
        validate_persisted_state(&conn)?;
        snapshot::verify_on_open(&conn, &canonical_dir, node_id)?;

        Ok(SmInner { _lock: lock, dir: canonical_dir, node_id, conn, fault })
    }

    pub(crate) fn tx(&mut self) -> Res<rusqlite::Transaction<'_>> {
        Ok(self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?)
    }
}

fn validate_identity(conn: &Connection, node_id: u64) -> Res<()> {
    match get_meta(conn, "format")?.as_deref() {
        Some(SM_FORMAT_VERSION) => {}
        other => return Err(E::Refused(format!("unknown state machine format {other:?}; refusing to reset"))),
    }
    match get_meta(conn, "node")?.as_deref() {
        Some(s) if s == node_id.to_string() => {}
        Some(s) => return Err(E::Refused(format!("sm node identity mismatch: db {s}, requested {node_id}"))),
        None => return Err(E::Refused("state machine db lacks node identity".into())),
    }
    Ok(())
}

fn validate_persisted_state(conn: &Connection) -> Res<()> {
    let last_applied: Option<LogId<u64>> = meta(conn, K_LAST_APPLIED)?;
    let _: StoredMembership<u64, BasicNode> =
        meta(conn, K_LAST_MEMBERSHIP)?.ok_or_else(|| E::Refused("missing last_membership in state machine".into()))?;
    let digest = get_meta(conn, K_STATE_DIGEST)?.ok_or_else(|| E::Refused("missing state_digest".into()))?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(E::Codec("corrupt state_digest format".into()));
    }
    let _: u64 = meta(conn, K_APPLIED_COUNT)?.ok_or_else(|| E::Refused("missing applied_count".into()))?;
    let snap_base: Option<LogId<u64>> = meta(conn, K_SNAP_BASE_LOG_ID)?;
    let _ = get_meta(conn, K_SNAP_BASE_BOUNDARY_DIGEST)?;

    if snap_base.zip(last_applied).is_some_and(|(base, last)| last.index < base.index) {
        return Err(E::Refused(format!("last_applied {last_applied:?} precedes snapshot base {snap_base:?}")));
    }

    let mut st =
        conn.prepare("SELECT idx,log_id,kind,payload,entry_digest,checksum FROM sm_entries ORDER BY idx ASC")?;
    let mut rows = st.query([])?;
    let mut prev_idx: Option<u64> = snap_base.map(|b| b.index);
    while let Some(row) = rows.next()? {
        let idx_i64: i64 = row.get(0)?;
        let idx = idx_from_i64(idx_i64)?;
        let log_id_s: String = row.get(1)?;
        let kind: String = row.get(2)?;
        let payload: Vec<u8> = row.get(3)?;
        let entry_digest: Vec<u8> = row.get(4)?;
        let csum: Vec<u8> = row.get(5)?;
        if csum != sm_entry_checksum(idx_i64, &log_id_s, &kind, &payload, &entry_digest) {
            return Err(E::Codec(format!("corrupt sm_entries checksum at idx {idx}")));
        }
        let lid: LogId<u64> = jd(&log_id_s)?;
        if lid.index != idx {
            return Err(E::Refused(format!("sm_entries index mismatch: {idx} != {lid}")));
        }
        if prev_idx.is_some_and(|p| idx <= p) {
            return Err(E::Refused(format!("non-monotonic sm_entries index between {prev_idx:?} and {idx}")));
        }
        prev_idx = Some(idx);
    }
    if last_applied.is_some_and(|last| prev_idx != Some(last.index)) {
        return Err(E::Refused(format!(
            "sm last_applied {last_applied:?} inconsistent with persisted entries {prev_idx:?}"
        )));
    }

    let mut kv_st = conn.prepare("SELECT k,v,last_idx,checksum FROM sm_kv")?;
    let mut kv_rows = kv_st.query([])?;
    while let Some(row) = kv_rows.next()? {
        let k: String = row.get(0)?;
        let v: String = row.get(1)?;
        let last_idx: i64 = row.get(2)?;
        let csum: Vec<u8> = row.get(3)?;
        if csum != sm_kv_checksum(&k, &v, last_idx) {
            return Err(E::Codec(format!("corrupt sm_kv checksum for key {k:?}")));
        }
    }
    Ok(())
}

pub(crate) fn read_applied_state(conn: &Connection) -> Res<AppliedState> {
    let last_applied: Option<LogId<u64>> = meta(conn, K_LAST_APPLIED)?;
    let last_membership: StoredMembership<u64, BasicNode> =
        meta(conn, K_LAST_MEMBERSHIP)?.ok_or_else(|| E::Refused("missing last_membership in state machine".into()))?;
    Ok((last_applied, last_membership))
}

pub(crate) fn read_kv_map(conn: &Connection) -> Res<BTreeMap<String, String>> {
    let mut st = conn.prepare("SELECT k,v,last_idx,checksum FROM sm_kv ORDER BY k ASC")?;
    let mut rows = st.query([])?;
    let mut map = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let k: String = row.get(0)?;
        let v: String = row.get(1)?;
        let last_idx: i64 = row.get(2)?;
        let csum: Vec<u8> = row.get(3)?;
        if csum != sm_kv_checksum(&k, &v, last_idx) {
            return Err(E::Codec(format!("corrupt sm_kv checksum for key {k:?}")));
        }
        map.insert(k, v);
    }
    Ok(map)
}

pub(crate) fn read_boundary_entry_digest_hex(
    conn: &Connection,
    last_applied: Option<LogId<u64>>,
) -> Res<Option<String>> {
    let Some(last) = last_applied else {
        return Ok(None);
    };
    let idx = idx_to_i64(last.index)?;
    let mut st = conn.prepare("SELECT log_id,kind,payload,entry_digest,checksum FROM sm_entries WHERE idx=?1")?;
    let mut rows = st.query([idx])?;
    if let Some(row) = rows.next()? {
        let log_id_s: String = row.get(0)?;
        let kind: String = row.get(1)?;
        let payload: Vec<u8> = row.get(2)?;
        let digest: Vec<u8> = row.get(3)?;
        let csum: Vec<u8> = row.get(4)?;
        if csum != sm_entry_checksum(idx, &log_id_s, &kind, &payload, &digest) {
            return Err(E::Codec(format!("corrupt sm_entries checksum at boundary {last}")));
        }
        return Ok(Some(hex_encode(&digest)));
    }
    let snap_base: Option<LogId<u64>> = meta(conn, K_SNAP_BASE_LOG_ID)?;
    if snap_base == Some(last) {
        return get_meta(conn, K_SNAP_BASE_BOUNDARY_DIGEST);
    }
    Err(E::Refused(format!("missing boundary entry digest at {last}")))
}

pub(crate) fn read_summary(inner: &SmInner) -> Res<StateMachineSummary> {
    let (last_applied, last_membership) = read_applied_state(&inner.conn)?;
    let state_digest_hex = get_meta(&inner.conn, K_STATE_DIGEST)?.unwrap_or_else(|| ZERO_DIGEST_HEX.to_owned());
    let applied_count: u64 = meta(&inner.conn, K_APPLIED_COUNT)?.unwrap_or(0);
    let kv_count = read_kv_map(&inner.conn)?.len();
    let active_meta: Option<openraft::SnapshotMeta<u64, BasicNode>> = meta(&inner.conn, snapshot::K_ACTIVE_SNAP_META)?;
    let active_snapshot_file = get_meta(&inner.conn, snapshot::K_ACTIVE_SNAP_FILE)?;
    Ok(StateMachineSummary {
        node_id: inner.node_id,
        last_applied,
        last_membership,
        state_digest_hex,
        applied_count,
        kv_count,
        active_snapshot_id: active_meta.map(|m| m.snapshot_id),
        active_snapshot_file,
    })
}

pub(crate) fn apply_entries(inner: &mut SmInner, entries: Vec<EntryOf>) -> Res<Vec<()>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    for w in entries.windows(2) {
        if w[0].log_id.index >= w[1].log_id.index {
            return Err(E::Refused(format!(
                "non-monotonic sm apply batch between {} and {}",
                w[0].log_id, w[1].log_id
            )));
        }
    }

    let fault = inner.fault.clone();
    let tx = inner.tx()?;
    let (mut cur_last, mut last_membership) = read_applied_state(&tx)?;
    let mut state_digest = get_meta(&tx, K_STATE_DIGEST)?.ok_or_else(|| E::Refused("missing state_digest".into()))?;
    let mut applied_count: u64 = meta(&tx, K_APPLIED_COUNT)?.unwrap_or(0);
    let snap_base: Option<LogId<u64>> = meta(&tx, K_SNAP_BASE_LOG_ID)?;
    let snap_base_digest = get_meta(&tx, K_SNAP_BASE_BOUNDARY_DIGEST)?;

    let mut mutated = false;
    let mut responses = Vec::with_capacity(entries.len());

    for entry in entries {
        let lid = entry.log_id;
        let idx = idx_to_i64(lid.index)?;
        let lid_json = je(&lid)?;
        let decoded = decode_entry_payload(&entry.payload)?;
        let digest = compute_entry_digest(&lid, decoded.kind, &decoded.payload_bytes);

        if cur_last.is_some_and(|la| lid.index <= la.index) {
            check_idempotent_replay(&tx, idx, &lid, &digest, snap_base, snap_base_digest.as_deref())?;
            responses.push(());
            continue;
        }

        let row_csum = sm_entry_checksum(idx, &lid_json, decoded.kind, &decoded.payload_bytes, &digest);
        tx.execute(
            "INSERT INTO sm_entries(idx,log_id,kind,payload,entry_digest,checksum) VALUES(?1,?2,?3,?4,?5,?6)",
            (idx, &lid_json, decoded.kind, &decoded.payload_bytes, digest.as_slice(), row_csum),
        )?;
        if let Some(cmd) = decoded.kv_cmd {
            apply_kv_cmd(&tx, idx, &cmd)?;
        }
        if let Some(mem) = decoded.membership {
            last_membership = StoredMembership::new(Some(lid), mem);
        }
        state_digest = advance_state_digest(&state_digest, &lid, &digest);
        applied_count = applied_count.saturating_add(1);
        cur_last = Some(lid);
        mutated = true;
        responses.push(());
    }

    if mutated {
        set_meta(&tx, K_LAST_APPLIED, cur_last.as_ref().map(je).transpose()?.as_deref())?;
        set_meta(&tx, K_LAST_MEMBERSHIP, Some(&je(&last_membership)?))?;
        set_meta(&tx, K_STATE_DIGEST, Some(&state_digest))?;
        set_meta(&tx, K_APPLIED_COUNT, Some(&applied_count.to_string()))?;
        fault.check(FaultPoint::SmApplyEnospc)?;
        fault.check(FaultPoint::SmApplySync)?;
        tx.commit()?;
    }
    Ok(responses)
}

fn decode_entry_payload(payload: &EntryPayload<crate::LogTypeConfig>) -> Res<DecodedPayload> {
    match payload {
        EntryPayload::Blank => {
            Ok(DecodedPayload { kind: "blank", payload_bytes: Vec::new(), kv_cmd: None, membership: None })
        }
        EntryPayload::Normal(bytes) => {
            if let Ok(cmd) = serde_json::from_slice::<SmCommand>(bytes) {
                validate_kv_cmd(&cmd)?;
                Ok(DecodedPayload { kind: "kv", payload_bytes: cmd.encode()?, kv_cmd: Some(cmd), membership: None })
            } else {
                Ok(DecodedPayload { kind: "normal", payload_bytes: bytes.clone(), kv_cmd: None, membership: None })
            }
        }
        EntryPayload::Membership(mem) => Ok(DecodedPayload {
            kind: "membership",
            payload_bytes: je(mem)?.into_bytes(),
            kv_cmd: None,
            membership: Some(mem.clone()),
        }),
    }
}

fn validate_kv_cmd(cmd: &SmCommand) -> Res<()> {
    match cmd {
        SmCommand::Put { key, value } => {
            if key.len() > MAX_KV_KEY_BYTES || value.len() > MAX_KV_VAL_BYTES {
                return Err(E::Refused("kv put exceeds key/value byte limits".into()));
            }
        }
        SmCommand::Delete { key } => {
            if key.len() > MAX_KV_KEY_BYTES {
                return Err(E::Refused("kv delete exceeds key byte limit".into()));
            }
        }
    }
    Ok(())
}

fn apply_kv_cmd(conn: &Connection, idx: i64, cmd: &SmCommand) -> Res<()> {
    match cmd {
        SmCommand::Put { key, value } => {
            let csum = sm_kv_checksum(key, value, idx);
            conn.execute(
                "INSERT INTO sm_kv(k,v,last_idx,checksum) VALUES(?1,?2,?3,?4) \
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v,last_idx=excluded.last_idx,checksum=excluded.checksum",
                (key, value, idx, csum),
            )?;
        }
        SmCommand::Delete { key } => {
            conn.execute("DELETE FROM sm_kv WHERE k=?1", [key])?;
        }
    }
    Ok(())
}

fn check_idempotent_replay(
    conn: &Connection,
    idx: i64,
    lid: &LogId<u64>,
    digest: &[u8; 32],
    snap_base: Option<LogId<u64>>,
    snap_base_digest: Option<&str>,
) -> Res<()> {
    let mut st = conn.prepare("SELECT log_id,kind,payload,entry_digest,checksum FROM sm_entries WHERE idx=?1")?;
    let mut rows = st.query([idx])?;
    if let Some(row) = rows.next()? {
        let log_id_s: String = row.get(0)?;
        let kind: String = row.get(1)?;
        let payload: Vec<u8> = row.get(2)?;
        let stored_digest: Vec<u8> = row.get(3)?;
        let csum: Vec<u8> = row.get(4)?;
        if csum != sm_entry_checksum(idx, &log_id_s, &kind, &payload, &stored_digest) {
            return Err(E::Codec(format!("corrupt sm_entries checksum during replay at idx {idx}")));
        }
        let stored_lid: LogId<u64> = jd(&log_id_s)?;
        if stored_lid == *lid && stored_digest.as_slice() == digest.as_slice() {
            return Ok(());
        }
        return Err(E::Refused(format!("conflicting replay at applied idx {idx}: stored {stored_lid} != {lid}")));
    }
    if snap_base == Some(*lid) && snap_base_digest == Some(hex_encode(digest).as_str()) {
        return Ok(());
    }
    Err(E::Refused(format!("conflicting or unverifiable replay at {lid} against snapshot base {snap_base:?}")))
}

fn compute_entry_digest(lid: &LogId<u64>, kind: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(lid.leader_id.term.to_be_bytes());
    hasher.update(lid.leader_id.node_id.to_be_bytes());
    hasher.update(lid.index.to_be_bytes());
    hasher.update((kind.len() as u64).to_be_bytes());
    hasher.update(kind.as_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn advance_state_digest(prev_hex: &str, lid: &LogId<u64>, entry_digest: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hex.as_bytes());
    hasher.update(lid.leader_id.term.to_be_bytes());
    hasher.update(lid.leader_id.node_id.to_be_bytes());
    hasher.update(lid.index.to_be_bytes());
    hasher.update(entry_digest);
    let out: [u8; 32] = hasher.finalize().into();
    hex_encode(&out)
}

pub(crate) fn sm_entry_checksum(idx: i64, log_id: &str, kind: &str, payload: &[u8], digest: &[u8]) -> Vec<u8> {
    checksum(&[b"sm_entry", &idx.to_be_bytes(), log_id.as_bytes(), kind.as_bytes(), payload, digest])
}

pub(crate) fn sm_kv_checksum(k: &str, v: &str, last_idx: i64) -> Vec<u8> {
    checksum(&[b"sm_kv", k.as_bytes(), v.as_bytes(), &last_idx.to_be_bytes()])
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
