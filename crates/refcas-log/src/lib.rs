//! Experimental openraft 0.9.26 persistent `RaftLogStorage` + `RaftLogReader` on SQLite.
//!
//! Log slice only: one SQLite file (`log.sqlite3`) in an exclusively locked directory holding
//! the persistent vote, the optional committed log id, the durable last-purged log id and
//! JSON-encoded native `Entry`s. No state machine, snapshot, CAS, network or runtime code, and
//! no claim of whole-Raft / Ref-CAS / Git qualification.
//!
//! Durability: rollback journal, `synchronous=FULL`; every mutation (and its metadata) commits in
//! one `BEGIN IMMEDIATE` transaction via its own connection before returning.

use std::fmt::Debug;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Cursor;
use std::ops::Bound;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use fs2::FileExt;
use openraft::Entry;
use openraft::ErrorSubject;
use openraft::ErrorVerb;
use openraft::LogId;
use openraft::OptionalSend;
use openraft::StorageError;
use openraft::Vote;
use openraft::log_id::RaftLogId as _;
use openraft::storage::LogFlushed;
use openraft::storage::LogState;
use openraft::storage::RaftLogReader;
use openraft::storage::RaftLogStorage;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use rusqlite::TransactionBehavior;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// On-disk schema marker. Anything else fails closed.
pub const FORMAT_VERSION: &str = "rootyard-refcas-log/3";
const DB_FILE: &str = "log.sqlite3";
const LOCK_FILE: &str = ".raftlog.lock";
/// Max entries accepted by one `append` or returned by one range read.
pub const MAX_BATCH_ENTRIES: usize = 4096;
/// Max encoded bytes accepted by one `append` or returned by one range read.
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const BUSY_TIMEOUT_MS: u64 = 5_000;

// `Cursor` is required by the macro's default `SnapshotData`. Intentionally not documented.
openraft::declare_raft_types!(
    pub LogTypeConfig:
        D = Vec<u8>,
        R = (),
);

/// Native entry type of this store (`NodeId=u64`, `D=Vec<u8>`, node `BasicNode`).
pub type EntryOf = Entry<LogTypeConfig>;

/// Errors reported by this store (wrapped in `StorageError::IO` for openraft).
#[derive(Debug)]
pub enum E {
    Io(io::Error),
    Sql(rusqlite::Error),
    Codec(String),
    /// Refused operation / invariant violation.
    Refused(String),
}

impl std::fmt::Display for E {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E::Io(e) => write!(f, "io: {e}"),
            E::Sql(e) => write!(f, "sqlite: {e}"),
            E::Codec(m) => write!(f, "codec: {m}"),
            E::Refused(m) => write!(f, "refused: {m}"),
        }
    }
}
impl std::error::Error for E {}
impl From<io::Error> for E {
    fn from(e: io::Error) -> Self {
        E::Io(e)
    }
}
impl From<rusqlite::Error> for E {
    fn from(e: rusqlite::Error) -> Self {
        E::Sql(e)
    }
}

type Res<T> = Result<T, E>;

fn ioerr(subject: ErrorSubject<u64>, verb: ErrorVerb, e: &E) -> StorageError<u64> {
    StorageError::IO { source: openraft::StorageIOError::new(subject, verb, openraft::AnyError::error(e)) }
}

fn jd<T: DeserializeOwned>(s: &str) -> Res<T> {
    serde_json::from_str(s).map_err(|e| E::Codec(format!("decode: {e}")))
}
fn je<T: Serialize>(v: &T) -> Res<String> {
    struct Writer(Vec<u8>);
    impl io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_ENTRY_BYTES.saturating_sub(self.0.len()) {
                return Err(io::Error::other("encoded entry exceeds its byte ceiling"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(Vec::new());
    serde_json::to_writer(&mut writer, v).map_err(|e| E::Codec(format!("encode: {e}")))?;
    String::from_utf8(writer.0).map_err(|e| E::Codec(e.to_string()))
}

/// Durable last-purged log id (absent = nothing purged). Never derived from rows.
const K_PURGED: &str = "last_purged";
/// Optional persisted committed log id.
const K_COMMITTED: &str = "committed";
/// Persisted vote.
const K_VOTE: &str = "vote";

const META_SCHEMA: &str = "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32)) WITHOUT ROWID;";
const ENTRY_SCHEMA: &str = "CREATE TABLE log_entry(idx INTEGER PRIMARY KEY, log_id TEXT NOT NULL, data TEXT NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32));";

/// u64 index -> i64; refuses overflow (i64::MAX reserved as invalid).
fn idx_to_i64(idx: u64) -> Res<i64> {
    i64::try_from(idx)
        .ok()
        .filter(|v| *v >= 0 && *v < i64::MAX)
        .ok_or_else(|| E::Refused(format!("log index {idx} does not fit a valid SQLite key")))
}

/// i64 stored index -> u64; refuses negatives.
fn idx_from_i64(v: i64) -> Res<u64> {
    u64::try_from(v).map_err(|_| E::Codec(format!("negative stored log index {v}")))
}

/// Resolve range bounds to `(start, end)`; `None` end = unbounded. Explicit ends are preserved
/// exactly (an empty range stays `Some(end)` with `end <= start`); only `..=u64::MAX`, whose
/// exclusive end does not fit in `u64`, becomes unbounded.
fn normalize_range<R: RangeBounds<u64>>(range: &R) -> Res<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Included(&s) => s,
        Bound::Excluded(&s) => s.checked_add(1).ok_or_else(|| E::Refused("range start overflow".into()))?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&e) => e.checked_add(1),
        Bound::Excluded(&e) => Some(e),
        Bound::Unbounded => None,
    };
    Ok((start, end))
}

// ---- metadata / row helpers, generic over `&Connection` (a `Transaction` derefs to it) ----

fn checksum(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().to_vec()
}
fn entry_checksum(index: i64, log_id: &str, data: &str) -> Vec<u8> {
    checksum(&[b"entry", &index.to_be_bytes(), log_id.as_bytes(), data.as_bytes()])
}
fn get_meta(conn: &Connection, k: &str) -> Res<Option<String>> {
    let mut st = conn.prepare("SELECT v,checksum,length(v) FROM meta WHERE k=?1")?;
    let mut rows = st.query([k])?;
    let Some(row) = rows.next()? else { return Ok(None) };
    if row.get::<_, i64>(2)? > 4096 {
        return Err(E::Codec("metadata exceeds its byte ceiling".into()));
    }
    let value: String = row.get(0)?;
    let actual: Vec<u8> = row.get(1)?;
    if actual != checksum(&[b"meta", k.as_bytes(), value.as_bytes()]) {
        return Err(E::Codec(format!("metadata checksum mismatch for {k}")));
    }
    Ok(Some(value))
}
fn meta<T: DeserializeOwned>(conn: &Connection, k: &str) -> Res<Option<T>> {
    get_meta(conn, k)?.map(|value| jd(&value)).transpose()
}
fn set_meta(conn: &Connection, k: &str, v: Option<&str>) -> Res<()> {
    if let Some(value) = v {
        let hash = checksum(&[b"meta", k.as_bytes(), value.as_bytes()]);
        conn.execute("INSERT INTO meta(k,v,checksum) VALUES(?1,?2,?3) ON CONFLICT(k) DO UPDATE SET v=excluded.v,checksum=excluded.checksum", (k,value,hash))?;
    } else {
        conn.execute("DELETE FROM meta WHERE k=?1", [k])?;
    }
    Ok(())
}
fn read_meta_vote(conn: &Connection) -> Res<Option<Vote<u64>>> {
    meta(conn, K_VOTE)
}
fn write_meta_vote(conn: &Connection, v: &Vote<u64>) -> Res<()> {
    set_meta(conn, K_VOTE, Some(&je(v)?))
}

/// Durable last log id, computed from stored rows (never a cached pointer):
/// highest stored row, else the purge boundary.
///
/// `purge` is inclusive and deletes rows through the boundary. The only row it can leave at the
/// boundary is its own, because a purge writes `meta` in the same transaction that deletes rows: a
/// crash restores both, and a resume keeps a row only if nothing changed `meta`. An
/// [`is_invalid_residue`] row at or below the boundary therefore cannot come from this store and fails
/// closed, wherever it sits. That check is what [`read_last`] relies on, so a disallowed row hidden
/// beneath a valid live tail is never reported as part of the log.
fn read_last(conn: &Connection) -> Res<Option<LogId<u64>>> {
    let purged = purged_boundary(conn)?;
    invalid_residue(conn, purged.as_ref())?;
    match stored_max(conn)? {
        Some((_, lid)) => Ok(Some(lid)),
        None => Ok(purged),
    }
}

/// True for a row `purge` may legitimately leave behind: exactly the boundary row it addressed
/// (same index, same full `LogId`). Every other row at or below the boundary is [`is_invalid_residue`].
fn same_boundary_row(row: &LogId<u64>, purged: &LogId<u64>) -> bool {
    row == purged
}

/// The consistent fail-closed rule for rows the inclusive purge should have deleted: a row below
/// the boundary is invalid, and a row at it is valid only with the boundary's own `LogId`.
fn is_invalid_residue(row: &LogId<u64>, purged: &LogId<u64>) -> bool {
    row.index < purged.index || (row.index == purged.index && !same_boundary_row(row, purged))
}

/// Fail closed if any stored row at or below the boundary is invalid residue. With no boundary no
/// row exists, and without rows the index scan is empty.
///
/// Per level this is a jump to the greatest index `<= level` (the `INTEGER PRIMARY KEY` index, so
/// bounded by rows and never false on a sparse index), then one row: an invalid row is reported,
/// the boundary's own row lets the scan end, and any other row repeats one level lower. Only
/// residue costs iterations, at most one per distinct level.
fn residue_scan(conn: &Connection, boundary: LogId<u64>) -> Res<Option<(LogId<u64>, LogId<u64>)>> {
    let mut level = boundary.index;
    loop {
        let key = idx_to_i64(level)?;
        let Some(row) =
            read_indexed_row(conn, "SELECT {cols} FROM log_entry WHERE idx <= ?1 ORDER BY idx DESC LIMIT 1", [key])?
        else {
            return Ok(None);
        };
        let row_id = *row.get_log_id();
        if is_invalid_residue(&row_id, &boundary) {
            return Ok(Some((row_id, boundary)));
        }
        match row_id.index.checked_sub(1) {
            Some(next) => level = next,
            None => return Ok(None),
        }
    }
}

/// [`residue_scan`] with its refusal; the message names the invalid row and the boundary.
fn invalid_residue(conn: &Connection, purged: Option<&LogId<u64>>) -> Res<()> {
    let Some(boundary) = purged else { return Ok(()) };
    match residue_scan(conn, *boundary)? {
        Some((row, boundary)) => {
            Err(E::Refused(format!("stored {row} is invalid residue at or below purge boundary {boundary}")))
        }
        None => Ok(()),
    }
}

/// Decode the persistent purge boundary exactly as written (absent = nothing purged).
fn purged_boundary(conn: &Connection) -> Res<Option<LogId<u64>>> {
    match meta::<LogId<u64>>(conn, K_PURGED).map_err(|e| E::Codec(format!("purge boundary: {e}")))? {
        Some(p) => {
            idx_to_i64(p.index)?;
            Ok(Some(p))
        }
        None => Ok(None),
    }
}

/// Highest stored row as `(idx, log_id)`, validating the row's log id.
const ENTRY_COLUMNS: &str = "idx,log_id,data,checksum,length(log_id),length(data)";
fn decode_entry_row(row: &rusqlite::Row<'_>) -> Res<(LogId<u64>, EntryOf)> {
    let index: i64 = row.get(0)?;
    if row.get::<_, i64>(4)? > 4096 || row.get::<_, i64>(5)? > MAX_ENTRY_BYTES as i64 {
        return Err(E::Codec("stored entry exceeds its byte ceiling".into()));
    }
    let id: String = row.get(1)?;
    let data: String = row.get(2)?;
    let hash: Vec<u8> = row.get(3)?;
    if hash != entry_checksum(index, &id, &data) {
        return Err(E::Codec("entry checksum mismatch".into()));
    }
    let lid: LogId<u64> = jd(&id)?;
    let entry: EntryOf = jd(&data)?;
    if lid.index != idx_from_i64(index)? || entry.log_id != lid {
        return Err(E::Codec("entry identity mismatch".into()));
    }
    Ok((lid, entry))
}
fn stored_max(conn: &Connection) -> Res<Option<(i64, LogId<u64>)>> {
    Ok(read_indexed_row(conn, "SELECT {cols} FROM log_entry ORDER BY idx DESC LIMIT 1", [])?
        .map(|entry| (entry.get_log_id().index as i64, *entry.get_log_id())))
}

/// First row (with full checksum/identity validation) of an `{cols}`-templated index query, or
/// `None` when the query yields no row.
fn read_indexed_row<P: rusqlite::Params>(conn: &Connection, sql: &str, params: P) -> Res<Option<EntryOf>> {
    let mut st = conn.prepare(&sql.replace("{cols}", ENTRY_COLUMNS))?;
    let mut rows = st.query(params)?;
    rows.next()?.map(decode_entry_row).transpose().map(|row| row.map(|(_, entry)| entry))
}
fn read_row(conn: &Connection, idx: i64) -> Res<Option<(LogId<u64>, EntryOf)>> {
    let mut st = conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry WHERE idx=?1"))?;
    let mut rows = st.query([idx])?;
    rows.next()?.map(decode_entry_row).transpose()
}

/// Why [`read_rows`] stopped before `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// Every row in `[from, to)` was read.
    Complete,
    /// Limited read: the entry-count budget is full, later rows were not read.
    Count,
    /// Limited read: the next row would exceed the byte budget, it was not read.
    Bytes,
}

/// Read stored rows in `[from, to)` as `(index, entry)` pairs.
///
/// A full read refuses a range over the count or byte budget. A limited read returns as many
/// leading rows as fit and reports why it stopped; it never returns an empty result.
fn read_rows(conn: &Connection, from: i64, to: i64, limited: bool) -> Res<(Vec<(u64, EntryOf)>, Stop)> {
    let mut st =
        conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry WHERE idx >= ?1 AND idx < ?2 ORDER BY idx"))?;
    let mut rows = st.query([from, to])?;
    let mut out: Vec<(u64, EntryOf)> = Vec::new();
    let mut bytes = 0usize;
    while let Some(r) = rows.next()? {
        let (lid, entry) = decode_entry_row(r)?;
        let sid: String = r.get(1)?;
        let sdata: String = r.get(2)?;
        if !limited && out.len() >= MAX_BATCH_ENTRIES {
            return Err(E::Refused("requested log range exceeds its read budget".into()));
        }
        if !limited && bytes.saturating_add(sid.len() + sdata.len()) > MAX_BATCH_BYTES {
            return Err(E::Refused("requested log range exceeds its read budget".into()));
        }
        if out.len() >= MAX_BATCH_ENTRIES {
            return Ok((out, Stop::Count));
        }
        let next_bytes = bytes.saturating_add(sid.len() + sdata.len());
        if next_bytes > MAX_BATCH_BYTES {
            return Ok((out, Stop::Bytes));
        }
        bytes = next_bytes;
        out.push((lid.index, entry));
    }
    Ok((out, Stop::Complete))
}

/// Read rows in `[lo, hi)` (or `[lo, unbounded)`), bounded by count and encoded bytes.
/// Returns empty for an empty range; there is no "first row only" special case.
///
/// Fail closed on a genuine hole. `append`, `truncate` and `purge` each commit in one transaction
/// and never leave a hole, so the stored log is exactly the indices `(last_purged_log_id,
/// last_log_id]`; `RaftLogReader` states a missing entry is allowed.
///
/// `known = stored max + 1` is the end of any possible log, even after a row was deleted, and
/// `purged + 1` is the first index that can still be stored. So rows before
/// `first = max(lo, purged + 1)` can only be purged, and every index in `[first, known)` must be
/// stored. Whatever is returned must begin with `first` and have no internal gap, including a
/// limited read stopped by its count or byte budget. Only a complete read must also reach
/// `min(known, hi)`; past that end (and past `hi`) short reads and empty results stay valid.
fn read_range(conn: &Connection, lo: u64, hi: Option<u64>, limited: bool) -> Res<Vec<EntryOf>> {
    if hi.is_some_and(|h| h <= lo) {
        return Ok(Vec::new()); // empty range: never touches SQL
    }
    let purged = purged_boundary(conn)?;
    // Same rule as `read_last`; the scan is empty without a boundary.
    invalid_residue(conn, purged.as_ref())?;
    let first = purged.as_ref().map_or(lo, |p| lo.max(p.index.saturating_add(1)));
    let known = match stored_max(conn)? {
        Some((max, _)) => idx_from_i64(max)?.saturating_add(1),
        None => 0,
    };
    let end = known.min(hi.unwrap_or(u64::MAX));
    if end <= first {
        return Ok(Vec::new()); // nothing stored can be requested
    }
    let (rows, stop) = read_rows(conn, idx_to_i64(first)?, idx_to_i64(end)?, limited)?;
    // The head is required for every result, budget stops included.
    if rows.first().is_none_or(|(idx, _)| *idx != first) {
        return Err(E::Refused(format!("log entry {first} is missing although it is stored")));
    }
    // No gap may follow either: a later row cannot stand in for a lost one.
    if let Some(w) = rows.windows(2).find(|w| w[1].0 - w[0].0 != 1) {
        return Err(E::Refused(format!(
            "log entry {} is missing although it is stored; stored entry {} follows",
            w[0].0.saturating_add(1),
            w[1].0
        )));
    }
    // A budget stop is a contract-valid prefix; only a complete read must reach `end`.
    let reached = rows.last().map_or(first, |(idx, _)| idx.saturating_add(1));
    if stop == Stop::Complete && reached < end {
        return Err(E::Refused(format!("log entry {reached} is missing although it is stored")));
    }
    Ok(rows.into_iter().map(|(_, e)| e).collect())
}

/// Create the directory and take the process-exclusive directory lock.
fn lock_dir(dir: &Path) -> Res<File> {
    std::fs::create_dir_all(dir)?;
    let dir = std::fs::canonicalize(dir)?;
    let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(dir.join(LOCK_FILE))?;
    lock.try_lock_exclusive()
        .map_err(|e| E::Refused(format!("log directory is already locked by another process: {e}")))?;
    Ok(lock)
}

/// Set the required PRAGMAs and verify them.
fn configure(conn: &Connection) -> Res<()> {
    let mode = conn.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        let mode = conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get::<_, String>(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(E::Refused(format!("journal_mode is {mode}, expected DELETE")));
        }
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    let sf = conn.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))?;
    if sf != 2 {
        return Err(E::Refused(format!("synchronous={sf}, expected FULL(2)")));
    }
    conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
    Ok(())
}

struct Inner {
    _lock: File,
    conn: Connection,
}

impl Inner {
    fn open(dir: &Path, node_id: u64, check: bool) -> Res<Inner> {
        let lock = lock_dir(dir)?;
        let db_path = dir.join(DB_FILE);
        let existed = db_path.exists();
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
                return Err(E::Refused("existing database has no log schema; refusing to reset".into()));
            }
            // Fresh store: schema + atomic, NOT NULL format/node identity in one transaction.
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(META_SCHEMA)?;
            tx.execute_batch(ENTRY_SCHEMA)?;
            set_meta(&tx, "format", Some(FORMAT_VERSION))?;
            set_meta(&tx, "node", Some(&node_id.to_string()))?;
            tx.commit()?;
        } else {
            let has_entry: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='log_entry'",
                [],
                |r| r.get(0),
            )?;
            if has_entry != 1 {
                return Err(E::Refused("database has meta but no log_entry; refusing to reset".into()));
            }
        }

        // Format + identity validation, fail closed.
        match get_meta(&conn, "format")?.as_deref() {
            Some(FORMAT_VERSION) => {}
            other => return Err(E::Refused(format!("unknown db format {other:?}; refusing to reset"))),
        }
        match get_meta(&conn, "node")?.as_deref() {
            Some(s) if s == node_id.to_string() => {}
            Some(s) => return Err(E::Refused(format!("node identity mismatch: db node {s}, requested {node_id}"))),
            None => return Err(E::Refused("database has no node identity; refusing to adopt it".into())),
        }
        if check {
            let r: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if r != "ok" {
                return Err(E::Refused(format!("quick_check failed: {r}")));
            }
        }
        // Persistent vote / committed / purged are always decoded and validated (fail closed).
        read_meta_vote(&conn).map_err(|e| E::Refused(format!("stored vote: {e}")))?;
        let committed: Option<LogId<u64>> =
            meta(&conn, K_COMMITTED).map_err(|e| E::Refused(format!("stored committed: {e}")))?;
        purged_boundary(&conn).map_err(|e| E::Refused(format!("stored purge boundary: {e}")))?;
        let last = read_last(&conn)?;
        if let (Some(c), Some(l)) = (committed, last)
            && c.index > l.index
        {
            return Err(E::Refused(format!("committed {c} is ahead of last log {l}")));
        }
        Ok(Inner { _lock: lock, conn })
    }

    fn tx(&mut self) -> Res<rusqlite::Transaction<'_>> {
        Ok(self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?)
    }
}

/// Validate an append batch before any mutation: entry count and encoded size (with a cheap
/// payload-length precheck so oversized payloads are never serialized), then adjacency.
fn validate_batch(entries: &[EntryOf]) -> Res<()> {
    if entries.len() > MAX_BATCH_ENTRIES {
        return Err(E::Refused(format!("append batch exceeds {MAX_BATCH_ENTRIES} entries")));
    }
    let mut bytes = 0usize;
    for e in entries {
        if let openraft::EntryPayload::Normal(d) = &e.payload {
            // Payload bytes plus a small framing margin; never larger than the encoded entry.
            if d.len() > MAX_ENTRY_BYTES {
                return Err(E::Refused(format!("entry payload exceeds {MAX_ENTRY_BYTES} bytes")));
            }
        }
        bytes = bytes.saturating_add(je(e)?.len());
        if bytes > MAX_BATCH_BYTES {
            return Err(E::Refused(format!("append batch exceeds {MAX_BATCH_BYTES} encoded bytes")));
        }
    }
    for w in entries.windows(2) {
        if w[0].get_log_id().index.checked_add(1) != Some(w[1].get_log_id().index) {
            return Err(E::Refused(format!(
                "append batch has a hole between {} and {}",
                w[0].get_log_id(),
                w[1].get_log_id()
            )));
        }
    }
    Ok(())
}

/// Durable append core shared by the trait `append` and tests. Does not touch the vote.
/// Bounds and adjacency are validated here, before any transaction is opened.
fn append_entries(inner: &mut Inner, entries: Vec<EntryOf>) -> Res<()> {
    validate_batch(&entries)?;
    let tx = inner.tx()?;
    let last = read_last(&tx)?;
    let committed: Option<LogId<u64>> = meta(&tx, K_COMMITTED)?;
    if let (Some(first), Some(prev)) = (entries.first(), last) {
        let i = first.get_log_id().index;
        if i > prev.index.saturating_add(1) {
            return Err(E::Refused(format!("append starts at {i} but log ends at {prev} (hole)")));
        }
    }
    let purged = purged_boundary(&tx)?;
    if entries.first().is_some_and(|first| purged.is_some_and(|p| first.log_id.index <= p.index)) {
        return Err(E::Refused("append would revive a purged prefix".into()));
    }
    for e in &entries {
        let lid = *e.get_log_id();
        let idx = idx_to_i64(lid.index)?;
        let data = je(e)?;
        let id = je(&lid)?;
        let hash = entry_checksum(idx, &id, &data);
        match read_row(&tx, idx)? {
            Some((old, cur)) => {
                // Compare the full encoded entry: content can change under the same LogId.
                let same = old == lid && je(&cur)? == data;
                if committed.as_ref().is_some_and(|c| lid.index <= c.index) {
                    // Acknowledged entries are never rewritten: byte-identical replay only.
                    if same {
                        continue;
                    }
                    return Err(E::Refused(format!("refusing to rewrite committed entry {old}")));
                }
                if same {
                    continue;
                }
                if old == lid {
                    return Err(E::Refused(format!("replay of {lid} with different content")));
                }
                tx.execute("DELETE FROM log_entry WHERE idx >= ?1", [idx])?;
                tx.execute(
                    "INSERT INTO log_entry(idx, log_id, data, checksum) VALUES(?1, ?2, ?3, ?4)",
                    (idx, id, data, hash),
                )?;
            }
            None => {
                if committed.is_some_and(|c| lid.index <= c.index) {
                    return Err(E::Refused("a committed log entry is missing".into()));
                }
                tx.execute(
                    "INSERT INTO log_entry(idx, log_id, data, checksum) VALUES(?1, ?2, ?3, ?4)",
                    (idx, id, data, hash),
                )?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Truncate from `idx` (inclusive) to the stored tail. Only the index is compared.
fn truncate_to(inner: &mut Inner, idx: u64) -> Res<()> {
    let idx = idx_to_i64(idx)?;
    let committed: Option<LogId<u64>> = meta(&inner.conn, K_COMMITTED)?;
    let c = match committed {
        Some(c) => idx_to_i64(c.index)?,
        None => -1,
    };
    if idx <= c {
        return Err(E::Refused(format!("refusing to truncate through committed {committed:?}")));
    }
    let tx = inner.tx()?;
    tx.execute("DELETE FROM log_entry WHERE idx >= ?1", [idx])?;
    tx.commit()?;
    Ok(())
}

/// Purge through `log_id.index` (inclusive) and persist that exact native `LogId` as the
/// durable purge boundary. Compaction may remove committed logs and may advance past the local
/// tail (snapshot install). The boundary only moves forward, so an older purge is absorbed but
/// never makes a newer boundary older; when advancing, the caller's exact `LogId` is stored.
fn purge_to(inner: &mut Inner, log_id: LogId<u64>) -> Res<()> {
    let idx = idx_to_i64(log_id.index)?;
    let tx = inner.tx()?;
    let stored: Option<LogId<u64>> = meta(&tx, K_PURGED)?;
    if stored.as_ref().is_none_or(|p| p.index < log_id.index) {
        set_meta(&tx, K_PURGED, Some(&je(&log_id)?))?;
    }
    tx.execute("DELETE FROM log_entry WHERE idx <= ?1", [idx])?;
    tx.commit()?;
    Ok(())
}

/// Run `f` on the blocking pool with exclusive access to the store.
///
/// The mutex is `Arc`-owned and locked *inside* the blocking task, so nothing borrows the
/// store mutably across threads.
async fn with_inner<R: Send + 'static>(
    inner: Arc<Mutex<Inner>>,
    f: impl FnOnce(&mut Inner) -> Res<R> + Send + 'static,
) -> Res<R> {
    tokio::task::spawn_blocking(move || {
        let mut guard = inner.blocking_lock();
        f(&mut guard)
    })
    .await
    .map_err(|e| E::Io(io::Error::other(format!("blocking task failed: {e}"))))?
}

/// Persistent Raft log store (Id: `LogId<u64>`, Entry: [`EntryOf`], Vote: `Vote<u64>`).
pub struct PersistentLog {
    inner: Arc<Mutex<Inner>>,
}

impl PersistentLog {
    /// Open (or create) the store in `dir`; `node_id` is bound on creation and verified later.
    /// `check_on_open` enables `quick_check` and metadata decode.
    pub async fn open(path: impl AsRef<Path>, node_id: u64, check_on_open: bool) -> Res<Self> {
        let dir = path.as_ref().to_path_buf();
        let inner = tokio::task::spawn_blocking(move || Inner::open(&dir, node_id, check_on_open))
            .await
            .map_err(|e| E::Io(io::Error::other(format!("open task failed: {e}"))))??;
        Ok(PersistentLog { inner: Arc::new(Mutex::new(inner)) })
    }
}

impl RaftLogReader<LogTypeConfig> for PersistentLog {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf>, StorageError<u64>> {
        let (start, end) = normalize_range(&range).map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))?;
        with_inner(self.inner.clone(), move |i| read_range(&i.conn, start, end, false))
            .await
            .map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))
    }

    async fn limited_get_log_entries(&mut self, start: u64, end: u64) -> Result<Vec<EntryOf>, StorageError<u64>> {
        with_inner(self.inner.clone(), move |i| read_range(&i.conn, start, Some(end), true))
            .await
            .map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))
    }
}

impl RaftLogStorage<LogTypeConfig> for PersistentLog {
    type LogReader = LogReader;

    async fn get_log_state(&mut self) -> Result<LogState<LogTypeConfig>, StorageError<u64>> {
        with_inner(self.inner.clone(), |i| {
            Ok(LogState { last_purged_log_id: meta(&i.conn, K_PURGED)?, last_log_id: read_last(&i.conn)? })
        })
        .await
        .map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        LogReader { inner: self.inner.clone() }
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let vote = *vote;
        with_inner(self.inner.clone(), move |i| {
            let tx = i.tx()?;
            write_meta_vote(&tx, &vote)?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| ioerr(ErrorSubject::Vote, ErrorVerb::Write, &e))
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        with_inner(self.inner.clone(), |i| read_meta_vote(&i.conn))
            .await
            .map_err(|e| ioerr(ErrorSubject::Vote, ErrorVerb::Read, &e))
    }

    async fn save_committed(&mut self, committed: Option<LogId<u64>>) -> Result<(), StorageError<u64>> {
        with_inner(self.inner.clone(), move |i| {
            let tx = i.tx()?;
            set_meta(&tx, K_COMMITTED, committed.as_ref().map(je).transpose()?.as_deref())?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| ioerr(ErrorSubject::Store, ErrorVerb::Write, &e))
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        with_inner(self.inner.clone(), |i| meta(&i.conn, K_COMMITTED))
            .await
            .map_err(|e| ioerr(ErrorSubject::Store, ErrorVerb::Read, &e))
    }

    async fn append<I>(&mut self, entries: I, callback: LogFlushed<LogTypeConfig>) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = EntryOf> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        // Do not exhaust an untrusted/large iterator before checking admission.
        let mut batch = Vec::new();
        let mut raw_bytes = 0usize;
        let mut refused = false;
        for entry in entries {
            if let openraft::EntryPayload::Normal(data) = &entry.payload {
                raw_bytes = raw_bytes.saturating_add(data.len());
                refused |= data.len() > MAX_ENTRY_BYTES;
            }
            if refused || batch.len() >= MAX_BATCH_ENTRIES || raw_bytes > MAX_BATCH_BYTES {
                refused = true;
                break;
            }
            batch.push(entry);
        }
        let res = if refused {
            Err(E::Refused("append iterator exceeds admission bounds".into()))
        } else {
            with_inner(self.inner.clone(), move |i| append_entries(i, batch)).await
        };
        // `append_entries` returns only after COMMIT, so an Ok here is durable.
        match res {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(e) => {
                // Report the failure through the callback (never an ack), then return it.
                callback.log_io_completed(Err(io::Error::other(e.to_string())));
                Err(ioerr(ErrorSubject::Logs, ErrorVerb::Write, &e))
            }
        }
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        with_inner(self.inner.clone(), move |i| truncate_to(i, log_id.index))
            .await
            .map_err(|e| ioerr(ErrorSubject::Log(log_id), ErrorVerb::Delete, &e))
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        with_inner(self.inner.clone(), move |i| purge_to(i, log_id))
            .await
            .map_err(|e| ioerr(ErrorSubject::Log(log_id), ErrorVerb::Delete, &e))
    }
}

/// Read-only handle over the same serialized connection.
pub struct LogReader {
    inner: Arc<Mutex<Inner>>,
}

impl RaftLogReader<LogTypeConfig> for LogReader {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf>, StorageError<u64>> {
        let (start, end) = normalize_range(&range).map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))?;
        with_inner(self.inner.clone(), move |i| read_range(&i.conn, start, end, false))
            .await
            .map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))
    }

    async fn limited_get_log_entries(&mut self, start: u64, end: u64) -> Result<Vec<EntryOf>, StorageError<u64>> {
        with_inner(self.inner.clone(), move |i| read_range(&i.conn, start, Some(end), true))
            .await
            .map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::CommittedLeaderId;
    use openraft::EntryPayload;

    fn lid(term: u64, index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }
    fn blank(term: u64, index: u64) -> EntryOf {
        Entry { log_id: lid(term, index), payload: EntryPayload::Blank }
    }
    fn normal(term: u64, index: u64, d: &[u8]) -> EntryOf {
        Entry { log_id: lid(term, index), payload: EntryPayload::Normal(d.to_vec()) }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
    }
    fn open(rt: &tokio::runtime::Runtime, dir: &Path) -> PersistentLog {
        rt.block_on(PersistentLog::open(dir, 7, true)).unwrap_or_else(|e| panic!("open: {e}"))
    }
    /// Durable core the trait `append` calls (same bounds, no forged `LogFlushed`).
    fn append(rt: &tokio::runtime::Runtime, s: &PersistentLog, es: Vec<EntryOf>) -> Res<()> {
        rt.block_on(with_inner(s.inner.clone(), move |i| append_entries(i, es)))
    }
    fn append_ok(rt: &tokio::runtime::Runtime, s: &PersistentLog, es: Vec<EntryOf>) {
        append(rt, s, es).unwrap_or_else(|e| panic!("append: {e}"));
    }
    fn state(rt: &tokio::runtime::Runtime, s: &mut PersistentLog) -> LogState<LogTypeConfig> {
        rt.block_on(s.get_log_state()).unwrap()
    }
    fn logs(rt: &tokio::runtime::Runtime, s: &mut PersistentLog, r: std::ops::Range<u64>) -> Vec<EntryOf> {
        rt.block_on(s.try_get_log_entries(r)).unwrap()
    }

    #[test]
    fn index_and_range_bounds() {
        assert_eq!(idx_to_i64(0).ok(), Some(0)); // bootstrap index 0 valid
        assert!(idx_to_i64(u64::MAX).is_err());
        assert!(idx_to_i64(i64::MAX as u64).is_err());
        assert!(idx_from_i64(-1).is_err());
        // Empty ranges keep their explicit end; they are never widened to unbounded.
        assert_eq!(normalize_range(&(5u64..5)).ok(), Some((5, Some(5))));
        assert_eq!(normalize_range(&(Bound::Included(7_u64), Bound::Excluded(3_u64))).ok(), Some((7, Some(3))));
        assert_eq!(normalize_range(&(5u64..=7)).ok(), Some((5, Some(8))));
        assert_eq!(normalize_range(&(..)).ok(), Some((0, None)));
        assert_eq!(normalize_range(&(..=u64::MAX)).ok(), Some((0, None)));
        assert!(
            normalize_range(&(Bound::Excluded(u64::MAX), Bound::Unbounded)).is_err(),
            "exclusive u64::MAX start overflows"
        );
    }

    #[test]
    fn residue_rule_is_consistent() {
        // Below the boundary any row is invalid; at the boundary only its own full `LogId` is valid.
        let b = LogId::new(CommittedLeaderId::new(3, 1), 5);
        let at = |term: u64, node: u64| LogId::new(CommittedLeaderId::new(term, node), 5);
        assert!(!is_invalid_residue(&at(3, 1), &b), "the boundary's own row");
        assert!(is_invalid_residue(&at(2, 1), &b), "same index, older log id");
        assert!(is_invalid_residue(&at(3, 9), &b), "same index, other node");
        assert!(is_invalid_residue(&lid(3, 4), &b), "below the boundary, even the same leader");
        assert!(!is_invalid_residue(&lid(3, 6), &b), "above the boundary is live");
    }

    #[test]
    fn restart_preserves_vote_committed_purge_and_logs() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = open(&rt, dir.path());
            rt.block_on(s.save_vote(&Vote::new(3, 7))).unwrap();
            append_ok(&rt, &s, vec![blank(2, 0), normal(2, 1, b"a"), normal(2, 2, b"b")]);
            rt.block_on(s.save_committed(Some(lid(2, 1)))).unwrap();
            let purge_at = LogId::new(CommittedLeaderId::new(2, 5), 1);
            rt.block_on(s.purge(purge_at)).unwrap();
            assert_eq!(
                state(&rt, &mut s),
                LogState { last_purged_log_id: Some(purge_at), last_log_id: Some(lid(2, 2)) }
            );
        }
        let mut s = open(&rt, dir.path());
        assert_eq!(rt.block_on(s.read_vote()).unwrap(), Some(Vote::new(3, 7)));
        assert_eq!(rt.block_on(s.read_committed()).unwrap(), Some(lid(2, 1)));
        let st = state(&rt, &mut s);
        assert_eq!(st.last_purged_log_id, Some(LogId::new(CommittedLeaderId::new(2, 5), 1)), "exact native LogId");
        assert_eq!(st.last_log_id, Some(lid(2, 2)));
        assert_eq!(logs(&rt, &mut s, 0..10), vec![normal(2, 2, b"b")]);
    }

    #[test]
    fn fresh_db_has_valid_identity_and_empty_state() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        let st = state(&rt, &mut s);
        assert_eq!((st.last_purged_log_id, st.last_log_id), (None, None));
        assert_eq!(rt.block_on(s.read_vote()).unwrap(), None);
        assert!(rt.block_on(s.read_committed()).unwrap().is_none());
        drop(s);
        let mut s = rt.block_on(PersistentLog::open(dir.path(), 7, false)).unwrap();
        assert_eq!(state(&rt, &mut s).last_log_id, None);
    }

    #[test]
    fn append_rules_replay_conflict_commit_and_holes() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, vec![blank(1, 0), blank(1, 1)]);
        append_ok(&rt, &s, vec![blank(1, 1)]); // identical replay kept
        assert!(append(&rt, &s, vec![blank(2, 3), blank(2, 5)]).is_err(), "hole in batch");
        assert!(append(&rt, &s, vec![blank(2, 4)]).is_err(), "hole after tail");
        append_ok(&rt, &s, vec![normal(2, 2, b"x"), normal(2, 3, b"y")]); // conflict replace
        assert_eq!(logs(&rt, &mut s, 2..4), vec![normal(2, 2, b"x"), normal(2, 3, b"y")]);
        rt.block_on(s.save_committed(Some(lid(2, 2)))).unwrap();
        append_ok(&rt, &s, vec![normal(2, 2, b"x")]); // unchanged committed replay kept
        assert!(append(&rt, &s, vec![normal(2, 2, b"changed")]).is_err(), "payload change at committed id");
        assert!(append(&rt, &s, vec![normal(3, 2, b"z")]).is_err(), "rewrite committed");
        assert!(append(&rt, &s, vec![normal(3, 2, b"w")]).is_err(), "under committed");
        assert_eq!(logs(&rt, &mut s, 2..4), vec![normal(2, 2, b"x"), normal(2, 3, b"y")]);
    }

    #[test]
    fn truncate_purge_boundaries_and_snapshot_install() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..8).map(|i| blank(1, i)).collect());
        // Truncate uses the index only; a different leader id in the tuple is tolerated.
        rt.block_on(s.truncate(lid(9, 5))).unwrap();
        assert_eq!(state(&rt, &mut s).last_log_id, Some(lid(1, 4)));
        // Legit re-append at exactly the truncated index works (no permanent floor).
        append_ok(&rt, &s, vec![normal(2, 5, b"n"), normal(2, 6, b"m")]);
        assert_eq!(logs(&rt, &mut s, 0..10).len(), 7);
        // Acknowledged committed entries cannot be truncated.
        rt.block_on(s.save_committed(Some(lid(2, 6)))).unwrap();
        assert!(rt.block_on(s.truncate(lid(2, 6))).is_err());
        // Snapshot-style purge: may delete committed logs and advance past the local tail.
        let snap = LogId::new(CommittedLeaderId::new(15, 9), 20);
        rt.block_on(s.purge(snap)).unwrap();
        let st = state(&rt, &mut s);
        assert_eq!(st.last_purged_log_id, Some(snap), "exact caller LogId");
        assert_eq!(st.last_log_id, Some(snap), "empty log reports purged as last");
        assert_eq!(rt.block_on(s.read_committed()).unwrap(), Some(lid(2, 6)), "committed may lag purged");
        // An older purge is absorbed and never moves the boundary backwards.
        rt.block_on(s.purge(lid(2, 3))).unwrap();
        assert!(logs(&rt, &mut s, 0..10).is_empty());
        drop(s);
        let mut s = open(&rt, dir.path());
        assert_eq!(state(&rt, &mut s).last_purged_log_id, Some(snap), "exact LogId survives restart");
        append_ok(&rt, &s, vec![blank(3, 21)]);
        assert_eq!(state(&rt, &mut s).last_log_id, Some(lid(3, 21)));
    }

    #[test]
    fn batch_and_range_read_bounds() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        let too_many: Vec<_> = (0..=MAX_BATCH_ENTRIES as u64).map(|i| blank(1, i)).collect();
        assert!(append(&rt, &s, too_many).is_err(), "entry-count bound enforced in helper");
        let large = vec![0u8; MAX_BATCH_BYTES + 1];
        assert!(append(&rt, &s, vec![normal(1, 0, &large)]).is_err(), "payload precheck");
        assert!(append(&rt, &s, vec![normal(1, 0, &vec![0u8; 9 * 1024 * 1024])]).is_err());
        assert_eq!(state(&rt, &mut s).last_log_id, None, "refused batches mutated nothing");
        append_ok(&rt, &s, (0..MAX_BATCH_ENTRIES as u64).map(|i| blank(1, i)).collect());
        assert_eq!(rt.block_on(s.try_get_log_entries(0..u64::MAX)).unwrap().len(), MAX_BATCH_ENTRIES);
        assert_eq!(rt.block_on(s.try_get_log_entries(..)).unwrap().len(), MAX_BATCH_ENTRIES);
        assert!(
            rt.block_on(s.try_get_log_entries((Bound::Included(2000_u64), Bound::Excluded(1500_u64))))
                .unwrap()
                .is_empty()
        );
        assert!(rt.block_on(s.try_get_log_entries(5..5)).unwrap().is_empty());
        assert_eq!(rt.block_on(s.try_get_log_entries(10..12)).unwrap().len(), 2);
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(rt.block_on(r.limited_get_log_entries(0, 3)).unwrap().len(), 3);
        assert!(rt.block_on(r.limited_get_log_entries(4, 4)).unwrap().is_empty());
    }

    #[test]
    fn range_reads_fail_closed_on_internal_gap_and_keep_valid_short_reads() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..6).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 1))).unwrap();
        assert_eq!(logs(&rt, &mut s, 0..8), (2..6).map(|i| blank(1, i)).collect::<Vec<_>>());
        assert!(logs(&rt, &mut s, 6..9).is_empty());
        rt.block_on(s.truncate(lid(1, 5))).unwrap();
        assert_eq!(logs(&rt, &mut s, 2..9), (2..5).map(|i| blank(1, i)).collect::<Vec<_>>());
        drop(s);
        let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
        assert_eq!(conn.execute("DELETE FROM log_entry WHERE idx=3", []).unwrap(), 1);
        drop(conn);
        let mut s = open(&rt, dir.path());
        assert!(rt.block_on(s.try_get_log_entries(2..5)).is_err(), "full reader accepted an internal gap");
        let mut reader = rt.block_on(s.get_log_reader());
        assert!(rt.block_on(reader.limited_get_log_entries(2, 5)).is_err(), "limited reader accepted an internal gap");
        assert_eq!(logs(&rt, &mut s, 4..5), vec![blank(1, 4)]);
        assert!(logs(&rt, &mut s, 2..2).is_empty());
    }

    #[test]
    fn identity_format_and_lock_fail_closed() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        rt.block_on(s.save_vote(&Vote::new(1, 7))).unwrap();
        assert!(rt.block_on(PersistentLog::open(dir.path(), 7, false)).is_err(), "directory is locked");
        drop(s);
        assert!(rt.block_on(PersistentLog::open(dir.path(), 8, false)).is_err(), "node identity mismatch");
        let lock = OpenOptions::new().read(true).write(true).open(dir.path().join(LOCK_FILE)).unwrap();
        fs2::FileExt::unlock(&lock).unwrap();
        drop(lock);
        assert!(rt.block_on(PersistentLog::open(dir.path(), 7, true)).is_ok());
        {
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.execute("UPDATE meta SET v='other/9' WHERE k='format'", []).unwrap();
        }
        assert!(rt.block_on(PersistentLog::open(dir.path(), 7, true)).is_err(), "unknown format fails closed");
    }

    #[test]
    fn valid_json_corruption_is_detected() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, vec![normal(1, 0, b"original")]);
        rt.block_on(s.save_vote(&Vote::new(1, 7))).unwrap();
        drop(s);
        let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
        conn.execute("UPDATE log_entry SET data=?1 WHERE idx=0", [je(&normal(1, 0, b"changed")).unwrap()]).unwrap();
        drop(conn);
        assert!(rt.block_on(PersistentLog::open(dir.path(), 7, true)).is_err());
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        rt.block_on(s.save_vote(&Vote::new(1, 7))).unwrap();
        drop(s);
        let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
        conn.execute("UPDATE meta SET v=?1 WHERE k='vote'", [je(&Vote::new(2, 8_u64)).unwrap()]).unwrap();
        drop(conn);
        assert!(rt.block_on(PersistentLog::open(dir.path(), 7, true)).is_err());
    }

    #[test]
    fn corruption_fails_closed() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let s = open(&rt, dir.path());
        append_ok(&rt, &s, vec![blank(1, 0), blank(1, 1)]);
        drop(s);
        Connection::open(dir.path().join(DB_FILE))
            .unwrap()
            .execute("UPDATE log_entry SET data='not json' WHERE idx=0", [])
            .unwrap();
        let mut s = open(&rt, dir.path());
        assert!(rt.block_on(s.try_get_log_entries(0..2)).is_err());
        drop(s);
        for key in [K_VOTE, K_COMMITTED, K_PURGED] {
            let dir = tempfile::tempdir().unwrap();
            let mut s = open(&rt, dir.path());
            rt.block_on(s.save_vote(&Vote::new(3, 7))).unwrap();
            append_ok(&rt, &s, vec![blank(1, 0), blank(1, 1)]);
            rt.block_on(s.save_committed(Some(lid(1, 1)))).unwrap();
            rt.block_on(s.purge(lid(1, 1))).unwrap();
            drop(s);
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            assert_eq!(conn.execute("UPDATE meta SET v='not json' WHERE k=?1", [key]).unwrap(), 1);
            drop(conn);
            assert!(rt.block_on(PersistentLog::open(dir.path(), 7, false)).is_err(), "bad {key} accepted");
        }
    }

    /// Delete rows straight from SQLite, as silent file/runtime corruption would (`quick_check`
    /// still passes; callers reopen with it enabled).
    fn delete_rows(dir: &Path, sql: &str) {
        let conn = Connection::open(dir.join(DB_FILE)).unwrap();
        conn.execute(sql, []).unwrap();
        let ok: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0)).unwrap();
        assert_eq!(ok, "ok", "in-row deletion leaves SQLite itself consistent");
    }
    fn indices(es: &[EntryOf]) -> Vec<u64> {
        es.iter().map(|e| e.log_id.index).collect()
    }
    fn empty() -> Vec<EntryOf> {
        Vec::new()
    }
    /// True only for this store's explicit "required log index is missing" refusal.
    fn is_missing(r: &Result<Vec<EntryOf>, StorageError<u64>>) -> bool {
        let msg = match r {
            Ok(_) => return false,
            Err(StorageError::IO { source }) => source.to_string(),
            Err(other) => panic!("unexpected error kind: {other:?}"),
        };
        msg.contains("refused: log entry ") && msg.contains(" is missing although it is stored")
    }
    /// Adapter for the in-crate peers that return [`E`].
    fn missing_in_core(r: &Res<Vec<EntryOf>>) -> bool {
        is_missing(&r.as_ref().cloned().map_err(|e| ioerr(ErrorSubject::Logs, ErrorVerb::Read, e)))
    }

    #[test]
    fn read_fails_closed_on_deleted_internal_row() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..8).map(|i| blank(1, i)).collect());
        // Committed stays below the tail: a tail row must never be mistaken for a purge boundary.
        rt.block_on(s.save_committed(Some(lid(1, 5)))).unwrap();
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(1..5)).unwrap()), vec![1, 2, 3, 4]);
        drop(r);
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=3");

        let mut s = open(&rt, dir.path());
        let st = state(&rt, &mut s);
        assert_eq!((st.last_purged_log_id, st.last_log_id), (None, Some(lid(1, 7))), "state is unchanged");
        let mut r = rt.block_on(s.get_log_reader());
        // Previously: `Ok([1, 2, 4])`, `Ok([])` and `Ok(len 7)` — silent holes.
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(1..5))), "range spanning the hole");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(3..4))), "the hole alone");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(3..8))), "from the hole to the tail");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(0..8))), "whole log");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(..))), "unbounded read");
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(2, 5))), "limited read, gap mid-chunk");
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(3, 4))), "limited read of the hole");
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(3, 4))), "repeat stays failed");
        // The same hole through the store's own reader implementation.
        assert!(is_missing(&rt.block_on(s.try_get_log_entries(1..5))));
        assert!(is_missing(&rt.block_on(s.limited_get_log_entries(1, 5))));
        // Ranges with no index in the required prefix `(purged, last]` keep valid short reads.
        assert!(rt.block_on(r.try_get_log_entries(1..3)).map(|v| indices(&v)).unwrap() == vec![1, 2]);
        assert!(rt.block_on(r.try_get_log_entries(0..3)).map(|v| indices(&v)).unwrap() == vec![0, 1, 2]);
        assert!(rt.block_on(r.try_get_log_entries(8..20)).unwrap().is_empty(), "past the end");
        assert!(rt.block_on(r.try_get_log_entries(100..)).unwrap().is_empty(), "far past the end");
        assert!(rt.block_on(r.try_get_log_entries(5..5)).unwrap().is_empty(), "empty range");
        let exact: Vec<EntryOf> = (4..8).map(|i| blank(1, i)).collect();
        assert_eq!(rt.block_on(r.try_get_log_entries(4..8)).unwrap(), exact, "after the hole");
        drop(r);

        // Append still uses the stored last index; it cannot see the hole and must not repair it
        // silently: the next read still fails.
        append_ok(&rt, &s, vec![blank(1, 8)]);
        assert!(missing_in_core(&rt.block_on(with_inner(s.inner.clone(), |i| read_range(&i.conn, 2, Some(9), false)))));
        // Bootstrap entry and multiple holes are found too.
        drop(s);
        let dir = tempfile::tempdir().unwrap();
        let s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..10).map(|i| blank(1, i)).collect());
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx IN (0, 4, 7)");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(0..2))), "bootstrap entry lost");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(0..10))), "three holes");
        assert!(rt.block_on(r.try_get_log_entries(1..4)).unwrap().len() == 3, "hole-free range below the gap");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(5..7)).unwrap()), vec![5, 6], "between holes");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(6..8))), "second hole");
        drop(r);
    }

    #[test]
    fn read_fails_closed_on_missing_required_prefix_and_tail() {
        let rt = rt();
        // The stored last row (the tail) is gone: `get_log_state` still reports the purge boundary.
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..5).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 1))).unwrap();
        rt.block_on(s.save_committed(Some(lid(1, 4)))).unwrap();
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(2..10)).unwrap()), vec![2, 3, 4]);
        drop(r);
        drop(s);
        // Row 2 is required: it is the live row right after the boundary and the start of every
        // engine read of the committed log; losing it silently shifts the prefix's first row.
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=2");
        let mut s = open(&rt, dir.path());
        let st = state(&rt, &mut s);
        assert_eq!((st.last_purged_log_id, st.last_log_id), (Some(lid(1, 1)), Some(lid(1, 4))));
        let mut r = rt.block_on(s.get_log_reader());
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(2..10))), "prefix head lost");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(2..3))), "the lost row alone");
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(2, 10))), "limited prefix lost");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(3..5)).unwrap()), vec![3, 4], "after it");
        assert!(rt.block_on(r.try_get_log_entries(0..2)).unwrap().is_empty(), "wholly purged");
        assert!(rt.block_on(r.try_get_log_entries(1..2)).unwrap().is_empty(), "at the purge boundary");
        assert!(rt.block_on(r.try_get_log_entries(10..12)).unwrap().is_empty(), "past the stored last");

        // Deletes from a prefix back to the tail: the later deletes remove the very rows that would
        // otherwise reveal the hole, so the derived end itself shrinks.
        let dir = tempfile::tempdir().unwrap();
        let s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..5).map(|i| blank(1, i)).collect());
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx >= 2");
        let mut s = open(&rt, dir.path());
        let st = state(&rt, &mut s);
        assert_eq!((st.last_purged_log_id, st.last_log_id), (None, Some(lid(1, 1))), "tail moved");
        let mut r = rt.block_on(s.get_log_reader());
        // Without a persisted end there is no evidence of a hole here; these are valid short reads,
        // never an error, and the reader reports the reduced log exactly.
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(0..10)).unwrap()), vec![0, 1]);
        assert!(rt.block_on(r.try_get_log_entries(2..5)).unwrap().is_empty(), "past the new end");
        assert_eq!(indices(&rt.block_on(s.try_get_log_entries(1..)).unwrap()), vec![1], "unbounded");
    }

    #[test]
    fn read_short_results_stay_valid_at_boundaries() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(rt.block_on(r.try_get_log_entries(0..10)).unwrap().is_empty(), "fresh store: no log");
        assert!(rt.block_on(r.limited_get_log_entries(0, 10)).unwrap().is_empty());
        append_ok(&rt, &s, (0..4).map(|i| blank(1, i)).collect());
        let four = |a: u64, b: u64| -> Vec<EntryOf> { (a..b).map(|i| blank(1, i)).collect() };
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(0..10)).unwrap()), vec![0, 1, 2, 3]);
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(2..)).unwrap()), vec![2, 3]);
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(3..=3)).unwrap()), vec![3]);
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(..)).unwrap()), vec![0, 1, 2, 3]);
        assert_eq!(rt.block_on(r.try_get_log_entries(4..5)).unwrap(), empty(), "index == last + 1");
        assert_eq!(rt.block_on(r.try_get_log_entries(9..u64::MAX)).unwrap(), empty(), "huge end");
        assert_eq!(rt.block_on(r.try_get_log_entries(u64::MAX..)).unwrap(), empty(), "at u64::MAX");
        assert_eq!(rt.block_on(r.try_get_log_entries(i64::MAX as u64 - 2..)).unwrap(), empty(), "budget cap");
        assert_eq!(rt.block_on(r.try_get_log_entries(4..4)).unwrap(), empty(), "empty at last + 1");
        assert_eq!(
            rt.block_on(r.try_get_log_entries((Bound::Included(9_u64), Bound::Excluded(4_u64)))).unwrap(),
            empty(),
            "inverted range"
        );
        assert_eq!(rt.block_on(r.limited_get_log_entries(2, 2)).unwrap(), empty(), "limited empty");
        assert_eq!(rt.block_on(r.limited_get_log_entries(0, u64::MAX)).unwrap(), four(0, 4), "limited huge end");
        drop(r);

        // A limited read may stop at its budget: a contract-valid nonempty prefix, never a hole.
        // (The budget test also fetches the stored last row, so it is detected at once; a row that
        // is truncated right after the last budgeted entry is caught by the next engine read.)
        append_ok(&rt, &s, (4..MAX_BATCH_ENTRIES as u64 + 1).map(|i| blank(1, i)).collect());
        let mut r = rt.block_on(s.get_log_reader());
        let got = rt.block_on(r.limited_get_log_entries(10, u64::MAX)).unwrap();
        assert!(got.len() <= MAX_BATCH_ENTRIES && !got.is_empty(), "bounded, nonempty prefix");
        assert_eq!(indices(&got)[..2], [10, 11]);
        assert!(rt.block_on(r.limited_get_log_entries(0, 0)).unwrap().is_empty());
        drop(r);

        // Purge through 4: the boundary index is gone, the next index is required.
        rt.block_on(s.purge(lid(1, 4))).unwrap();
        drop(s);
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(4..8)).unwrap()), vec![5, 6, 7], "first stored");
        drop(r);
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=5");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(5..8))), "row after the boundary lost");
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(4..8))), "including the boundary index");
        assert!(rt.block_on(r.try_get_log_entries(0..5)).unwrap().is_empty(), "wholly purged");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(6..8)).unwrap()), vec![6, 7]);
        // Snapshot-style purge past the local tail: no stored log exists at all.
        rt.block_on(s.purge(LogId::new(CommittedLeaderId::new(9, 3), 5000))).unwrap();
        assert!(rt.block_on(r.try_get_log_entries(0..6000)).unwrap().is_empty());
        assert!(rt.block_on(r.limited_get_log_entries(0, 6000)).unwrap().is_empty());
        assert!(rt.block_on(r.try_get_log_entries(5001..)).unwrap().is_empty());
    }

    /// Pins the purge boundary with a matching meta checksum (upsert).
    fn set_purged(dir: &Path, boundary: LogId<u64>) {
        let value = je(&boundary).unwrap();
        let hash = checksum(&[b"meta", K_PURGED.as_bytes(), value.as_bytes()]);
        Connection::open(dir.join(DB_FILE))
            .unwrap()
            .execute(
                "INSERT INTO meta(k, v, checksum) VALUES(?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET v=excluded.v, checksum=excluded.checksum",
                (K_PURGED, &value, hash),
            )
            .unwrap();
    }
    /// Replaces a row's whole `LogId` (leader id included) with valid, checksum-consistent data.
    fn rewrite_row(dir: &Path, idx: u64, new_id: LogId<u64>) {
        let entry: EntryOf = Entry { log_id: new_id, payload: EntryPayload::Blank };
        let id = je(&new_id).unwrap();
        let data = je(&entry).unwrap();
        let hash = entry_checksum(idx as i64, &id, &data);
        let changed = Connection::open(dir.join(DB_FILE))
            .unwrap()
            .execute("UPDATE log_entry SET log_id=?2, data=?3, checksum=?4 WHERE idx=?1", (idx as i64, id, data, hash))
            .unwrap();
        assert_eq!(changed, 1, "row {idx} was rewritten");
    }
    /// A real stored row for `idx` from a throwaway store, so leftovers carry valid data and checksums.
    fn seeded_row(rt: &tokio::runtime::Runtime, idx: u64) -> (String, String, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let s = open(rt, dir.path());
        append_ok(rt, &s, (0..=idx).map(|i| blank(1, i)).collect());
        drop(s);
        Connection::open(dir.path().join(DB_FILE))
            .unwrap()
            .query_row("SELECT log_id, data, checksum FROM log_entry WHERE idx=?1", [idx as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }
    fn insert_row(dir: &Path, idx: u64, row: &(String, String, Vec<u8>)) {
        let changed = Connection::open(dir.join(DB_FILE))
            .unwrap()
            .execute(
                "INSERT INTO log_entry(idx, log_id, data, checksum) VALUES(?1, ?2, ?3, ?4)",
                (idx as i64, &row.0, &row.1, &row.2),
            )
            .unwrap();
        assert_eq!(changed, 1);
    }

    #[test]
    fn equal_purge_row_with_other_log_id_is_not_live() {
        let rt = rt();
        // `purge(.., lid(1, 1))` is inclusive: the only row it may leave at index 1 is its own log id.
        // A row there with another full `LogId` (`T9-N9-1`) cannot come from this store, yet fcb only
        // rejected rows *below* the boundary, so it read this one as the live tail.
        let row = seeded_row(&rt, 1);
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..3).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 1))).unwrap();
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx > 1"); // the leftover is the tail
        insert_row(dir.path(), 1, &row); // the purge's own row back on disk
        rewrite_row(dir.path(), 1, LogId::new(CommittedLeaderId::new(9, 9), 1));
        let stored = stored_max(&Connection::open(dir.path().join(DB_FILE)).unwrap()).unwrap().unwrap().1;
        assert_eq!(stored, LogId::new(CommittedLeaderId::new(9, 9), 1), "the fcb input state");
        // Grading: fcb's `index < boundary` comparison accepted exactly this state as the live tail,
        // while this store refuses to open it.
        let via_fcb = with_copy(dir.path(), fcb_read_last);
        assert_eq!(format!("{via_fcb:?}"), format!("Ok(Some({:?}))", LogId::new(CommittedLeaderId::new(9, 9), 1)));
        assert!(
            rt.block_on(PersistentLog::open(dir.path(), 7, false)).is_err(),
            "a leftover row with another LogId at the boundary must fail closed"
        );
        let err = match rt.block_on(PersistentLog::open(dir.path(), 7, false)) {
            Ok(_) => panic!("a leftover row with another LogId at the boundary must fail closed"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("at or below purge boundary"), "{err}");
    }

    #[test]
    fn hidden_residue_beneath_valid_live_tail_fails_closed() {
        let rt = rt();
        // Disallowed leftovers hidden below a valid live tail: the max row is valid, so 8a8ceb9's
        // max-only check accepted it. Each is caught by the bounded index scan on open, on state and
        // on reads; the boundary's own row stays supported.
        let rows: Vec<_> = (0..=4).map(|i| seeded_row(&rt, i)).collect();
        let leftovers: [(u64, LogId<u64>, &str); 3] = [
            (1, lid(2, 1), "below the boundary, same leader, older term"),
            (2, LogId::new(CommittedLeaderId::new(9, 9), 2), "below the boundary, other node"),
            (3, LogId::new(CommittedLeaderId::new(9, 9), 3), "at the boundary, another LogId"),
        ];
        for (idx, other, what) in leftovers {
            let dir = tempfile::tempdir().unwrap();
            let mut s = open(&rt, dir.path());
            append_ok(&rt, &s, (0..5).map(|i| blank(1, i)).collect());
            rt.block_on(s.purge(lid(1, 3))).unwrap();
            rt.block_on(s.save_committed(Some(lid(1, 4)))).unwrap();
            drop(s);
            insert_row(dir.path(), idx, &rows[idx as usize]);
            rewrite_row(dir.path(), idx, other);
            // Grading: 8a8ceb9 saw only the live tail (4) and accepted the residue beneath it, and
            // its range read never looked below the boundary.
            let prior = with_copy(dir.path(), prior_read_last);
            assert_eq!(format!("{prior:?}"), format!("Ok(Some({:?}))", lid(1, 4)), "{what}: 8a8ceb9 input");
            // This store refuses before it can report anything: open, state and every read path.
            let err = match rt.block_on(PersistentLog::open(dir.path(), 7, true)) {
                Ok(_) => panic!("{what}: residue accepted on open"),
                Err(e) => e,
            };
            assert!(format!("{err}").contains("invalid residue at or below purge boundary"), "{what}: {err}");
            // To observe state and reads on their own, a handle is opened with the rule's input
            // momentarily absent (no boundary pinned), then the boundary is restored, as a purge
            // would, through another connection; the handle's state and read paths must still refuse.
            let probe_dir = tempfile::tempdir().unwrap();
            std::fs::copy(dir.path().join(DB_FILE), probe_dir.path().join(DB_FILE)).unwrap();
            Connection::open(probe_dir.path().join(DB_FILE))
                .unwrap()
                .execute("DELETE FROM meta WHERE k=?1", [K_PURGED])
                .unwrap();
            let mut s = open(&rt, probe_dir.path());
            set_purged(probe_dir.path(), lid(1, 3));
            let state_err = rt.block_on(s.get_log_state()).expect_err("residue on state");
            assert!(format!("{state_err}").contains("invalid residue"), "{what}: {state_err}");
            let mut r = rt.block_on(s.get_log_reader());
            for err in [
                rt.block_on(r.try_get_log_entries(4..5)).expect_err("full read"),
                rt.block_on(r.try_get_log_entries(0..10)).expect_err("whole-log read"),
                rt.block_on(r.limited_get_log_entries(0, 10)).expect_err("limited read"),
            ] {
                assert!(format!("{err}").contains("invalid residue"), "{what}: {err}");
            }
            drop(r);
            drop(s);
        }

        // The matching boundary row (what `purge` may leave) stays supported, hidden or not.
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..5).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 3))).unwrap();
        drop(s);
        insert_row(dir.path(), 3, &rows[3]);
        let mut s = open(&rt, dir.path());
        assert_eq!(state(&rt, &mut s).last_log_id, Some(lid(1, 4)), "live tail");
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(0..10)).unwrap()), vec![4], "boundary not live");
        assert_eq!(indices(&rt.block_on(r.limited_get_log_entries(3, 10)).unwrap()), vec![4]);
        drop(r);
        drop(s);
    }

    #[test]
    fn leftover_purge_row_survives_reads_and_keeps_boundary_semantics() {
        let rt = rt();
        // Crash-style leftover of the purge's own row (same full `LogId` at the boundary index): the
        // purge contract admits it, so the store neither invents a failure nor treats it as live.
        // Reads start at the first live index; fcb returned the boundary row itself.
        let row = seeded_row(&rt, 1);
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..4).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 1))).unwrap();
        drop(s);
        insert_row(dir.path(), 1, &row);
        let mut s = open(&rt, dir.path());
        // Grading: fcb had no boundary-row filter. Its purge pin moved whole-range starts to the
        // boundary, but an unpinned read that starts exactly at the boundary row (a single-index
        // lookup) returned it as live; this store filters it and reports the row missing.
        let row_one = with_copy(dir.path(), |conn| {
            conn.execute("DELETE FROM meta WHERE k=?1", [K_PURGED]).unwrap();
            fcb_read_range(conn, 1, Some(2), false)
        });
        assert_eq!(format!("{:?}", row_one.map(|v| indices(&v))), "Ok([1])", "fcb returned the boundary row");
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(rt.block_on(r.try_get_log_entries(0..10)).unwrap(), vec![blank(1, 2), blank(1, 3)]);
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(1..10)).unwrap()), vec![2, 3], "from boundary");
        assert!(rt.block_on(r.try_get_log_entries(0..2)).unwrap().is_empty(), "through the boundary only");
        let limited = rt.block_on(r.limited_get_log_entries(0, 10)).unwrap();
        assert_eq!(indices(&limited), vec![2, 3], "limited read too");
        drop(r);
        drop(s);
    }

    #[test]
    fn row_at_purge_boundary_with_other_log_id_fails_closed() {
        let rt = rt();
        // The same leftover above an empty log: `purge(.., 3)` removed every row, so anything left
        // at or below 3 is residue; another `LogId` must not become the reported tail.
        let row = seeded_row(&rt, 2);
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..3).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 3))).unwrap();
        drop(s);
        insert_row(dir.path(), 2, &row);
        rewrite_row(dir.path(), 2, LogId::new(CommittedLeaderId::new(9, 9), 2));
        // This store refuses the leftover outright.
        let err = match rt.block_on(PersistentLog::open(dir.path(), 7, false)) {
            Ok(_) => panic!("a leftover row with another LogId at the boundary must fail closed"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("at or below purge boundary"), "{err}");
        // Grading: fcb's comparison rejects rows *below* the boundary, so a row one index *above* it
        // becomes the tail it reports (here `T9-N9-2` above `T1-N1-1`).
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..3).map(|i| blank(1, i)).collect());
        rt.block_on(s.purge(lid(1, 1))).unwrap();
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx <> 2");
        rewrite_row(dir.path(), 2, LogId::new(CommittedLeaderId::new(9, 9), 2));
        let via_fcb = with_copy(dir.path(), fcb_read_last);
        assert_eq!(format!("{via_fcb:?}"), format!("Ok(Some({:?}))", LogId::new(CommittedLeaderId::new(9, 9), 2)));
        let mut s = open(&rt, dir.path());
        assert_eq!(
            state(&rt, &mut s).last_log_id,
            Some(LogId::new(CommittedLeaderId::new(9, 9), 2)),
            "same answer today"
        );
    }

    /// fcb22c5's byte handling, kept only as a probe of that defect.
    fn fcb_read_rows(conn: &Connection, from: i64, to: i64, limited: bool) -> Res<Vec<(u64, EntryOf)>> {
        let mut st = conn
            .prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry WHERE idx >= ?1 AND idx < ?2 ORDER BY idx"))
            .unwrap();
        let mut rows = st.query([from, to]).unwrap();
        let mut out: Vec<(u64, EntryOf)> = Vec::new();
        let mut bytes = 0usize;
        while let Some(r) = rows.next().unwrap() {
            let (lid, entry) = decode_entry_row(r).unwrap();
            let sid: String = r.get(1).unwrap();
            let sdata: String = r.get(2).unwrap();
            let next_bytes = bytes.saturating_add(sid.len() + sdata.len());
            if out.len() >= MAX_BATCH_ENTRIES || next_bytes > MAX_BATCH_BYTES {
                if limited && !out.is_empty() {
                    break;
                }
                return Err(E::Refused("requested log range exceeds its read budget".into()));
            }
            bytes = next_bytes;
            out.push((lid.index, entry));
        }
        Ok(out)
    }
    /// Runs `f` against a byte-for-byte copy of the database (no lock, no WAL), for grading code
    /// that cannot be reached through a refused `open`.
    fn with_copy<R>(dir: &Path, f: impl FnOnce(&Connection) -> R) -> R {
        let copy = tempfile::tempdir().unwrap();
        std::fs::copy(dir.join(DB_FILE), copy.path().join("copy.sqlite3")).unwrap();
        let conn = Connection::open(copy.path().join("copy.sqlite3")).unwrap();
        f(&conn)
    }
    /// 8a8ceb9's `read_last`, kept only to grade the hidden-residue regression against it: it judged
    /// only the highest row, so invalid residue beneath a valid live tail was accepted.
    fn prior_read_last(conn: &Connection) -> Res<Option<LogId<u64>>> {
        let purged = purged_boundary(conn)?;
        match stored_max(conn)? {
            Some((_, lid)) => match &purged {
                Some(p) if lid.index <= p.index && !same_boundary_row(&lid, p) => {
                    Err(E::Refused(format!("last stored {lid} is at or below purge boundary {p}")))
                }
                _ => Ok(Some(lid)),
            },
            None => Ok(purged),
        }
    }
    /// fcb22c5's `read_last`, kept only to grade the purge-residue regression against it.
    fn fcb_read_last(conn: &Connection) -> Res<Option<LogId<u64>>> {
        let purged = purged_boundary(conn)?;
        match stored_max(conn)? {
            Some((_, lid)) => {
                if let Some(p) = &purged
                    && lid.index < p.index
                {
                    return Err(E::Refused(format!("last stored {lid} is below purge boundary {p}")));
                }
                Ok(Some(lid))
            }
            None => Ok(purged),
        }
    }
    /// fcb22c5's `read_range`, kept only as a probe of its count-stop early return.
    fn fcb_read_range(conn: &Connection, lo: u64, hi: Option<u64>, limited: bool) -> Res<Vec<EntryOf>> {
        if hi.is_some_and(|h| h <= lo) {
            return Ok(Vec::new());
        }
        let purged = purged_boundary(conn)?;
        let first = purged.as_ref().map_or(lo, |p| lo.max(p.index.saturating_add(1)));
        let known = match stored_max(conn)? {
            Some((max, _)) => idx_from_i64(max)?.saturating_add(1),
            None => 0,
        };
        let end = known.min(hi.unwrap_or(u64::MAX));
        if end <= first {
            return Ok(Vec::new());
        }
        let rows = fcb_read_rows(conn, idx_to_i64(first)?, idx_to_i64(end)?, limited)?;
        if limited && rows.len() >= MAX_BATCH_ENTRIES {
            return Ok(rows.into_iter().map(|(_, e)| e).collect());
        }
        if let Some(w) = rows.windows(2).find(|w| w[1].0 - w[0].0 != 1) {
            return Err(E::Refused(format!("gap after {}", w[0].0)));
        }
        if rows.first().is_none_or(|(idx, _)| *idx != first)
            || rows.last().is_none_or(|(idx, _)| idx.saturating_add(1) < end)
        {
            return Err(E::Refused(format!("log entry {first} is missing although it is stored")));
        }
        Ok(rows.into_iter().map(|(_, e)| e).collect())
    }
    fn rows_of(r: &Result<Vec<EntryOf>, StorageError<u64>>) -> Vec<u64> {
        indices(r.as_ref().unwrap())
    }

    #[test]
    fn limited_read_checks_head_and_gap_at_count_budget() {
        let rt = rt();
        // The head is missing but later rows fill the count budget: fcb returned them unchecked.
        let dir = tempfile::tempdir().unwrap();
        let s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..MAX_BATCH_ENTRIES as u64).map(|i| blank(1, i)).collect());
        append_ok(&rt, &s, vec![blank(1, MAX_BATCH_ENTRIES as u64)]);
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=0");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        // fcb's count-budget early return skipped the head check; the regression sees it returning.
        assert!(
            rt.block_on(with_inner(s.inner.clone(), |i| { fcb_read_range(&i.conn, 0, Some(u64::MAX), true) })).is_ok(),
            "probe: fcb no longer skips the head check at the count budget"
        );
        let got = rt.block_on(r.limited_get_log_entries(0, u64::MAX));
        assert!(is_missing(&got), "lost head, later rows fill the budget: {got:?}");
        drop(r);
        drop(s);

        // A middle index is missing and the later rows still fill the count budget.
        let dir = tempfile::tempdir().unwrap();
        let s = open(&rt, dir.path());
        append_ok(&rt, &s, (0..MAX_BATCH_ENTRIES as u64).map(|i| blank(1, i)).collect());
        append_ok(&rt, &s, vec![blank(1, MAX_BATCH_ENTRIES as u64)]);
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=1");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(
            rt.block_on(with_inner(s.inner.clone(), |i| { fcb_read_range(&i.conn, 0, Some(u64::MAX), true) })).is_ok(),
            "probe: fcb no longer skips the gap check at the count budget"
        );
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(0, u64::MAX))), "lost middle at budget");
        // A full read of the same range reports the middle index, not the head.
        let msg = format!("{}", rt.block_on(r.try_get_log_entries(0..)).unwrap_err());
        assert!(msg.contains("log entry 1 is missing"), "{msg}");
        // A hole-free part of the log still reads normally.
        assert_eq!(indices(&rt.block_on(r.limited_get_log_entries(2, u64::MAX)).unwrap()).len(), MAX_BATCH_ENTRIES - 1);
    }

    #[test]
    fn limited_read_accepts_byte_budget_prefix() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        // Change-log style batches: each 110 KiB ASCII payload stores at ~330 KB (3x), so rows 0..24
        // fit the 8 MiB byte budget, read 24 rows, and the 25th cannot be read.
        let big = vec![b'A'; 110 * 1024];
        for chunk in (0..25u64).collect::<Vec<_>>().chunks(12) {
            append_ok(&rt, &s, chunk.iter().map(|i| normal(1, *i, &big)).collect());
        }
        let mut r = rt.block_on(s.get_log_reader());
        let got = rt.block_on(r.limited_get_log_entries(0, 30));
        assert_eq!(rows_of(&got), (0..24).collect::<Vec<_>>(), "byte budget stops below the count budget");
        assert!(rows_of(&got).len() < MAX_BATCH_ENTRIES);
        // The stored budget is checked with the same stop reason a limited read sees.
        let (rows, stop) = rt.block_on(with_inner(s.inner.clone(), |i| read_rows(&i.conn, 0, 25, true))).unwrap();
        assert_eq!(stop, Stop::Bytes);
        assert_eq!(rows.len(), 24);
        // fcb's tail check called exactly this valid prefix a hole; the regression asserts that it
        // does, and the store's own result above is the correct one.
        let via_fcb = rt.block_on(with_inner(s.inner.clone(), |i| fcb_read_range(&i.conn, 0, Some(30), true)));
        assert!(missing_in_core(&via_fcb), "fcb's tail check no longer misreads the byte prefix: {via_fcb:?}");
        // A full read of the same range still refuses to exceed the budget.
        let msg = format!("{}", rt.block_on(r.try_get_log_entries(0..30)).unwrap_err());
        assert!(msg.contains("exceeds its read budget"), "{msg}");
        // A hole inside a byte-limited prefix still fails closed.
        drop(r);
        drop(s);
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=1");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(is_missing(&rt.block_on(r.limited_get_log_entries(0, 30))), "gap inside a byte prefix");
        // An empty or wholly-purged request keeps returning an empty result, never an error.
        rt.block_on(s.purge(lid(1, 40))).unwrap();
        assert!(rt.block_on(r.limited_get_log_entries(0, 30)).unwrap().is_empty());
    }

    #[test]
    fn read_range_boundaries_remain_valid() {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        // Empty store: empty results, never errors.
        assert!(rt.block_on(r.try_get_log_entries(0..10)).unwrap().is_empty());
        assert!(rt.block_on(r.limited_get_log_entries(0, 10)).unwrap().is_empty());
        assert!(rt.block_on(r.try_get_log_entries(5..5)).unwrap().is_empty());
        assert!(rt.block_on(r.limited_get_log_entries(5, 5)).unwrap().is_empty());
        append_ok(&rt, &s, (0..5).map(|i| blank(1, i)).collect());
        // Complete reads return the whole stored range, whatever the requested end.
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(0..u64::MAX)).unwrap()), (0..5).collect::<Vec<_>>());
        assert_eq!(indices(&rt.block_on(r.limited_get_log_entries(0, 100)).unwrap()), (0..5).collect::<Vec<_>>());
        // Short reads past the end, past the budget cap, and beyond u64 stay valid.
        assert!(rt.block_on(r.try_get_log_entries(5..10)).unwrap().is_empty());
        assert!(rt.block_on(r.try_get_log_entries(u64::MAX..)).unwrap().is_empty());
        assert!(rt.block_on(r.try_get_log_entries(i64::MAX as u64 - 2..)).unwrap().is_empty());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(3..)).unwrap()), vec![3, 4], "short inside the log");
        drop(r);
        // Purged boundaries: the boundary index is deleted (inclusive purge), its predecessor is
        // purged, and a request starting at the boundary is served by the first live index.
        rt.block_on(s.purge(lid(1, 2))).unwrap();
        let mut r = rt.block_on(s.get_log_reader());
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(3..10)).unwrap()), vec![3, 4], "first live");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(2..10)).unwrap()), vec![3, 4], "from the boundary");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(1..10)).unwrap()), vec![3, 4], "below it");
        assert!(rt.block_on(r.try_get_log_entries(0..3)).unwrap().is_empty(), "wholly purged");
        drop(r);
        drop(s);
        // With the first live row deleted, a request spanning it fails closed.
        delete_rows(dir.path(), "DELETE FROM log_entry WHERE idx=3");
        let mut s = open(&rt, dir.path());
        let mut r = rt.block_on(s.get_log_reader());
        assert!(is_missing(&rt.block_on(r.try_get_log_entries(3..10))), "first live row lost");
        assert_eq!(indices(&rt.block_on(r.try_get_log_entries(4..10)).unwrap()), vec![4], "after the hole");
        assert!(rt.block_on(r.try_get_log_entries(0..3)).unwrap().is_empty(), "purged reads unchanged");
    }
}
