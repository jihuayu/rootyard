//! Process kill/reopen of an acknowledged log append; no quorum, state-machine or power-loss claim.
//!
//! The Linux fixture check rejects known network mount types. That negative list does not prove
//! the backing device is local, and non-Linux hosts perform no filesystem qualification.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use openraft::CommittedLeaderId;
use openraft::Entry;
use openraft::EntryPayload;
use openraft::LogId;
use rootyard_refcas_log::EntryOf;
use serde::Deserialize;

const NODE_ID: u64 = 7;
const STARTUP: Duration = Duration::from_secs(10);
const EXIT: Duration = Duration::from_secs(10);
const REAP: Duration = Duration::from_secs(5);
/// `std::process::Child::kill` is SIGKILL on Unix.
const SIGKILL: i32 = 9;

#[cfg(target_os = "linux")]
type MountInfo = (String, String, String);
type StoredRow = (i64, String, String, Vec<u8>);

#[derive(Deserialize)]
struct Report {
    entries: Vec<EntryOf>,
    committed: Option<LogId<u64>>,
    last_purged_log_id: Option<LogId<u64>>,
    last_log_id: Option<LogId<u64>>,
}

fn log_id(term: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, NODE_ID), index)
}

/// Independently expected native entries; the probe builds the same batch.
fn expected_entries() -> Vec<EntryOf> {
    vec![
        Entry { log_id: log_id(2, 0), payload: EntryPayload::Blank },
        Entry { log_id: log_id(2, 1), payload: EntryPayload::Normal(b"alpha\0\xff".to_vec()) },
        Entry { log_id: log_id(2, 2), payload: EntryPayload::Normal(b"bravo".to_vec()) },
        Entry { log_id: log_id(3, 3), payload: EntryPayload::Blank },
        Entry { log_id: log_id(3, 4), payload: EntryPayload::Normal(b"charlie\0".to_vec()) },
    ]
}

fn committed() -> LogId<u64> {
    log_id(3, 3)
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn spawn(command: &mut Command) -> Self {
        Self(Some(command.spawn().expect("spawn log probe")))
    }

    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("child is still owned")
    }

    /// Consumes the owned handle. On return the child has been reaped; otherwise this panics.
    fn finish(mut self, kill: bool, timeout: Duration) -> ExitStatus {
        let child = self.0.as_mut().expect("child is still owned");
        if kill {
            let _ = child.kill();
        }
        let status = wait_with_deadline(child, timeout);
        self.0 = None;
        status
    }
}

impl Drop for OwnedChild {
    /// Last-resort bounded cleanup, normally while unwinding. Reaping is claimed only when
    /// `try_wait` returns the status; an expired deadline is reported as unconfirmed, not as
    /// success.
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else { return };
        let _ = child.kill();
        let message = match wait_bounded(&mut child, REAP) {
            Ok(Some(_)) => return,
            Ok(None) => {
                format!("owned child did not quiesce within {REAP:?} after kill; reaping remains unconfirmed")
            }
            Err(error) => format!("owned child cleanup wait failed: {error}; reaping remains unconfirmed"),
        };
        if std::thread::panicking() {
            eprintln!("{message}");
        } else {
            panic!("{message}");
        }
    }
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> ExitStatus {
    match wait_bounded(child, timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            match wait_bounded(child, REAP) {
                Ok(Some(_)) => panic!("child did not exit within {timeout:?}"),
                Ok(None) => panic!("child did not exit within {timeout:?} or quiesce within {REAP:?} after kill"),
                Err(error) => panic!("child wait failed after timeout: {error}"),
            }
        }
        Err(error) => panic!("child wait failed: {error}"),
    }
}

fn line(child: &mut Child, timeout: Duration) -> String {
    let stdout = child.stdout.take().expect("probe stdout");
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    let result = receiver.recv_timeout(timeout).expect("probe output deadline").expect("probe output read");
    reader.join().expect("probe output reader");
    result.trim().to_owned()
}

#[test]
fn acknowledged_log_append_survives_sigkill_and_a_fresh_process() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let fixture = qualify_fixture(directory.path());
    let executable = env!("CARGO_BIN_EXE_log-probe");
    let expected = expected_entries();

    let mut writer = OwnedChild::spawn(
        Command::new(executable).arg("write").arg(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()),
    );
    let ack_line = line(writer.child(), STARTUP);
    let ack_json = ack_line
        .strip_prefix("ACK ")
        .unwrap_or_else(|| panic!("writer did not acknowledge after LogFlushed: {ack_line}"));
    let ack: Report =
        serde_json::from_str(ack_json).unwrap_or_else(|error| panic!("invalid ACK JSON: {error}: {ack_json}"));
    assert_eq!(ack.entries, expected, "ACK entries differ from the exact native batch");
    assert_eq!(ack.committed, Some(committed()), "ACK committed metadata");
    assert_eq!(ack.last_purged_log_id, None, "ACK purge boundary");
    assert_eq!(ack.last_log_id, Some(log_id(3, 4)), "ACK last log id");

    // On the success path this is the first signal: the ACK exists only after blocking_append
    // awaited the public LogFlushed callback. Cleanup paths also kill a stuck owned child.
    let status = writer.finish(true, REAP);
    assert_eq!(status.signal(), Some(SIGKILL), "writer was not killed by SIGKILL: {status}");

    let mut reader = OwnedChild::spawn(
        Command::new(executable).arg("read").arg(directory.path()).stdin(Stdio::null()).stdout(Stdio::piped()),
    );
    let read_line = line(reader.child(), STARTUP);
    let read_json =
        read_line.strip_prefix("READ ").unwrap_or_else(|| panic!("fresh process did not read the log: {read_line}"));
    let read: Report =
        serde_json::from_str(read_json).unwrap_or_else(|error| panic!("invalid READ JSON: {error}: {read_json}"));
    assert_eq!(read.entries, expected, "fresh process entries differ from the exact native batch");
    assert_eq!(read.committed, Some(committed()), "fresh process committed metadata");
    assert_eq!(read.last_purged_log_id, None, "fresh process purge boundary");
    assert_eq!(read.last_log_id, Some(log_id(3, 4)), "fresh process last log id");
    let status = reader.finish(false, EXIT);
    assert!(status.success(), "fresh read process failed: {status}");

    assert_stored_rows(&fixture, &expected, committed());
}

/// Applies the available fixture checks. Passing them is not proof that the backing device is
/// local, and only Linux performs any filesystem-type check.
#[cfg(target_os = "linux")]
fn qualify_fixture(dir: &Path) -> PathBuf {
    let canonical = canonical_fixture(dir);
    let (device, fstype, mount_point) = fixture_mount(&canonical).expect("Linux fixture mount info");
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb",
        "smb3",
        "smbfs",
        "9p",
        "ceph",
        "glusterfs",
        "afs",
        "davfs",
        "davfs2",
        "lustre",
        "gpfs",
        "fuse.sshfs",
        "fuse.rclone",
        "fuse.glusterfs",
        "fuse.ceph",
        "fuse.smbnetfs",
        "fuse.davfs",
        "fuse.davfs2",
        "fuse.s3fs",
        "fuse.gcsfuse",
        "fuse.goofys",
        "fuse.juicefs",
    ];
    let lowered = fstype.to_ascii_lowercase();
    assert!(
        !NETWORK.iter().any(|kind| lowered.as_str() == *kind || lowered.starts_with(&format!("{kind}."))),
        "fixture filesystem {fstype} at {mount_point} is a known network filesystem"
    );
    // A FUSE name does not identify its backing store. Refuse every FUSE mount, not only the
    // named remote types above, because this test has no positive locality qualification.
    let is_fuse = matches!(lowered.as_str(), "fuse" | "fuseblk") || lowered.starts_with("fuse.");
    assert!(!is_fuse, "fixture filesystem {fstype} at {mount_point} is an unqualified FUSE mount");
    let metadata_device = std::fs::metadata(&canonical).expect("fixture metadata").dev();
    eprintln!(
        "fixture mount observation device={device} fstype={fstype} mount={mount_point} metadata_dev={metadata_device}; known-network denylist passed, not proof of a local backing device"
    );
    canonical
}

/// Only binds the canonical fixture to the temp directory; this platform has no filesystem
/// qualification.
#[cfg(not(target_os = "linux"))]
fn qualify_fixture(dir: &Path) -> PathBuf {
    let canonical = canonical_fixture(dir);
    eprintln!("fixture mount check unavailable on this platform; no filesystem qualification, path bound only");
    canonical
}

fn canonical_fixture(dir: &Path) -> PathBuf {
    let canonical = dir.canonicalize().expect("canonical fixture path");
    let temp = std::env::temp_dir().canonicalize().expect("canonical temp directory");
    let canonical_text = canonical.display();
    let temp_text = temp.display();
    assert!(canonical.starts_with(&temp), "fixture {canonical_text} is outside the temp directory {temp_text}");
    canonical
}

#[cfg(target_os = "linux")]
fn fixture_mount(path: &Path) -> Option<MountInfo> {
    let data = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, MountInfo)> = None;
    for line in data.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let left: Vec<&str> = left.split_whitespace().collect();
        let right: Vec<&str> = right.split_whitespace().collect();
        if left.len() < 5 || right.is_empty() {
            continue;
        }
        let mount_point = decode_mount_escape(left[4]);
        if !path.starts_with(Path::new(&mount_point)) {
            continue;
        }
        let len = mount_point.len();
        if best.as_ref().is_none_or(|(best_len, _)| len > *best_len) {
            best = Some((len, (left[2].to_owned(), right[0].to_owned(), mount_point)));
        }
    }
    best.map(|(_, mount)| mount)
}

#[cfg(target_os = "linux")]
fn decode_mount_escape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4].iter().all(|byte| byte.is_ascii_digit())
        {
            let value = u16::from(bytes[index + 1] - b'0') * 64
                + u16::from(bytes[index + 2] - b'0') * 8
                + u16::from(bytes[index + 3] - b'0');
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn assert_stored_rows(dir: &Path, expected: &[EntryOf], committed: LogId<u64>) {
    #[cfg(target_os = "linux")]
    {
        // Equal `st_dev` only shows the database did not cross a device boundary; it does not
        // prove that device is local or directly attached.
        let fixture_device = std::fs::metadata(dir).expect("fixture metadata").dev();
        let database_device = std::fs::metadata(dir.join("log.sqlite3")).expect("database metadata").dev();
        assert_eq!(database_device, fixture_device, "database is on a different device than the fixture");
    }

    let connection =
        rusqlite::Connection::open_with_flags(dir.join("log.sqlite3"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open stored log read-only");
    let mut statement =
        connection.prepare("SELECT idx,log_id,data,checksum FROM log_entry ORDER BY idx").expect("prepare stored rows");
    let rows: Vec<StoredRow> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .expect("query stored rows")
        .collect::<Result<_, _>>()
        .expect("decode stored rows");
    assert_eq!(rows.len(), expected.len(), "stored row count");
    for (row, entry) in rows.iter().zip(expected) {
        let (index, stored_log_id, stored_data, stored_checksum) = row;
        let entry_index = entry.log_id.index;
        let expected_log_id = serde_json::to_string(&entry.log_id).expect("encode expected log id");
        let expected_data = serde_json::to_string(entry).expect("encode expected entry");
        assert_eq!(*index, i64::try_from(entry_index).expect("index fits i64"));
        assert_eq!(stored_log_id, &expected_log_id, "stored log id at {entry_index}");
        assert_eq!(stored_data, &expected_data, "stored entry at {entry_index}");
        assert_eq!(stored_checksum.len(), 32, "stored checksum length at {entry_index}");
        assert_eq!(
            stored_checksum,
            &entry_checksum(*index, stored_log_id, stored_data),
            "stored checksum at {entry_index}"
        );
    }
    let (stored_value, stored_checksum): (String, Vec<u8>) = connection
        .query_row("SELECT v,checksum FROM meta WHERE k='committed'", [], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("stored committed metadata");
    assert_eq!(
        stored_value,
        serde_json::to_string(&Some(committed)).expect("encode committed metadata"),
        "stored committed value"
    );
    assert_eq!(
        stored_checksum,
        sha256_fields(&[b"meta", b"committed", stored_value.as_bytes()]),
        "stored committed checksum"
    );
}

fn sha256_fields(parts: &[&[u8]]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn entry_checksum(index: i64, log_id: &str, data: &str) -> Vec<u8> {
    sha256_fields(&[b"entry", &index.to_be_bytes(), log_id.as_bytes(), data.as_bytes()])
}
