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
fn read_last(conn: &Connection) -> Res<Option<LogId<u64>>> {
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
    let mut st = conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry ORDER BY idx DESC LIMIT 1"))?;
    let mut rows = st.query([])?;
    rows.next()?.map(|row| decode_entry_row(row).map(|(lid, _)| (lid.index as i64, lid))).transpose()
}
fn read_row(conn: &Connection, idx: i64) -> Res<Option<(LogId<u64>, EntryOf)>> {
    let mut st = conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry WHERE idx=?1"))?;
    let mut rows = st.query([idx])?;
    rows.next()?.map(decode_entry_row).transpose()
}

/// Read rows in `[lo, hi)` (or `[lo, unbounded)`), bounded by count and encoded bytes.
/// Returns empty for an empty range; there is no "first row only" special case.
fn read_range(conn: &Connection, lo: u64, hi: Option<u64>, limited: bool) -> Res<Vec<EntryOf>> {
    if hi.is_some_and(|h| h <= lo) {
        return Ok(Vec::new()); // empty range: never touches SQL
    }
    if lo >= i64::MAX as u64 {
        return Ok(Vec::new());
    }
    let lo = idx_to_i64(lo)?;
    let hi = hi.unwrap_or(u64::MAX).min(i64::MAX as u64) as i64;
    let mut st =
        conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM log_entry WHERE idx >= ?1 AND idx < ?2 ORDER BY idx"))?;
    let mut rows = st.query([lo, hi])?;
    let mut out: Vec<EntryOf> = Vec::new();
    let mut bytes = 0usize;
    let mut previous_index: Option<u64> = None;
    while let Some(r) = rows.next()? {
        let (log_id, entry) = decode_entry_row(r)?;
        let sid: String = r.get(1)?;
        let sdata: String = r.get(2)?;
        let next_bytes = bytes.saturating_add(sid.len() + sdata.len());
        if out.len() >= MAX_BATCH_ENTRIES || next_bytes > MAX_BATCH_BYTES {
            if limited && !out.is_empty() {
                break;
            }
            return Err(E::Refused("requested log range exceeds its read budget".into()));
        }
        if let Some(previous) = previous_index
            && previous.checked_add(1) != Some(log_id.index)
        {
            return Err(E::Refused(format!("log range has a gap after index {previous}, next is {}", log_id.index)));
        }
        previous_index = Some(log_id.index);
        bytes = next_bytes;
        out.push(entry);
    }
    Ok(out)
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
    fn range_read_rejects_internal_gap_without_rejecting_purged_prefix_or_tail() {
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
}
