//! Test-only original-process identity for the Linux final-wait witness.
//!
//! A bare PID is not an identity: Linux can reuse it, and a truncated stat
//! entry can end in `Z`. The witness captures `(pid, starttime)` only while the
//! fixture is demonstrably live and re-reads that identity after the timeout.

use std::{path::Path, time::Duration};
use tokio::time::Instant;

const FIELDS_THROUGH_STARTTIME: usize = 20;
const READINESS_POLL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OriginalProcess {
    pid: i32,
    starttime: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcState {
    Gone,
    Exited,
    Live,
}

#[derive(Clone, Copy)]
struct ProcEntry {
    state: ProcState,
    pgrp: i32,
    starttime: u64,
}

enum ProcLookup {
    Gone,
    Present(ProcEntry),
}

impl OriginalProcess {
    pub(super) fn state(self) -> ProcState {
        assert_procfs_live();
        match lookup(self.pid) {
            ProcLookup::Gone => ProcState::Gone,
            ProcLookup::Present(entry) if entry.starttime != self.starttime => ProcState::Gone,
            ProcLookup::Present(entry) => entry.state,
        }
    }
}

pub(super) async fn wait_for_original_pair(path: &Path, ready_deadline: Instant) -> (OriginalProcess, OriginalProcess) {
    assert_procfs_live();
    let mut diagnostic = String::from("pid file has not been observed");
    loop {
        assert_procfs_live();
        if Instant::now() >= ready_deadline {
            panic!("fixture did not expose a live original process pair before the readiness deadline: {diagnostic}");
        }
        match tokio::fs::read_to_string(path).await {
            Ok(text) => match parse_pids(&text) {
                Some((leader, descendant)) => match capture_pair(leader, descendant) {
                    Ok(pair) => {
                        assert!(
                            Instant::now() < ready_deadline,
                            "fixture pair was captured after the readiness deadline"
                        );
                        return pair;
                    }
                    Err(reason) => diagnostic = reason,
                },
                None => diagnostic = format!("pid file is not complete: {:?}", bounded(&text)),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                diagnostic = format!("{} is not present yet", path.display());
            }
            Err(error) => panic!("cannot read {}: {error}", path.display()),
        }
        tokio::time::sleep(READINESS_POLL).await;
    }
}

fn parse_pids(text: &str) -> Option<(i32, i32)> {
    let mut values = text.split_whitespace();
    let leader = values.next()?.parse::<i32>().ok()?;
    let descendant = values.next()?.parse::<i32>().ok()?;
    if values.next().is_some() || leader < 2 || descendant < 2 || leader == descendant {
        return None;
    }
    Some((leader, descendant))
}

fn capture_pair(leader: i32, descendant: i32) -> Result<(OriginalProcess, OriginalProcess), String> {
    let leader_entry = match lookup(leader) {
        ProcLookup::Gone => return Err(format!("leader {leader} is not visible in procfs")),
        ProcLookup::Present(entry) => entry,
    };
    let descendant_entry = match lookup(descendant) {
        ProcLookup::Gone => return Err(format!("descendant {descendant} is not visible in procfs")),
        ProcLookup::Present(entry) => entry,
    };
    if leader_entry.state != ProcState::Live {
        return Err(format!("leader {leader} is {:?}, not live", leader_entry.state));
    }
    if descendant_entry.state != ProcState::Live {
        return Err(format!("descendant {descendant} is {:?}, not live", descendant_entry.state));
    }
    if leader_entry.pgrp != leader {
        return Err(format!("leader {leader} is in process group {}, not its own", leader_entry.pgrp));
    }
    if descendant_entry.pgrp != leader {
        return Err(format!(
            "descendant {descendant} is in process group {}, not leader {leader}",
            descendant_entry.pgrp
        ));
    }
    assert_stdout_closed(leader);
    assert_stdout_closed(descendant);
    Ok((
        OriginalProcess { pid: leader, starttime: leader_entry.starttime },
        OriginalProcess { pid: descendant, starttime: descendant_entry.starttime },
    ))
}

fn assert_stdout_closed(pid: i32) {
    let fd = format!("/proc/{pid}/fd/1");
    let target = std::fs::read_link(&fd).unwrap_or_else(|error| panic!("cannot inspect {fd}: {error}"));
    assert_eq!(
        target.as_path(),
        Path::new("/dev/null"),
        "fixture {pid} still holds stdout {target:?}; the original stdout pipe is not closed"
    );
}

fn assert_procfs_live() {
    let pid = i32::try_from(std::process::id()).expect("test pid fits i32");
    match lookup(pid) {
        ProcLookup::Present(entry) if entry.state == ProcState::Live => {}
        ProcLookup::Present(entry) => panic!("procfs is present but test process {pid} is {:?}", entry.state),
        ProcLookup::Gone => panic!("procfs is not live: /proc/{pid}/stat is absent"),
    }
}

fn lookup(pid: i32) -> ProcLookup {
    let path = format!("/proc/{pid}/stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {
            return ProcLookup::Gone;
        }
        Err(error) => panic!("cannot read {path}: {error}"),
    };
    let (prefix, rest) =
        stat.rsplit_once(") ").unwrap_or_else(|| panic!("truncated {path}: missing command terminator"));
    let (stat_pid, _) = prefix.split_once(" (").unwrap_or_else(|| panic!("malformed {path}: missing `pid (` prefix"));
    let stat_pid = stat_pid.parse::<i32>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric pid"));
    if stat_pid != pid {
        panic!("{path} describes pid {stat_pid}, not {pid}");
    }
    let fields: Vec<_> = rest.split_whitespace().collect();
    if fields.len() < FIELDS_THROUGH_STARTTIME {
        panic!("truncated {path}: {} fields after comm, need at least {FIELDS_THROUGH_STARTTIME}", fields.len());
    }
    let state = match fields[0] {
        "R" | "S" | "D" | "T" | "t" | "W" | "P" | "I" | "K" => ProcState::Live,
        "Z" | "X" | "x" => ProcState::Exited,
        other => panic!("unsupported {path} state {other:?}"),
    };
    for (index, field) in fields.iter().enumerate().take(19).skip(1) {
        field.parse::<i64>().unwrap_or_else(|_| panic!("malformed {path}: field {index} {field:?} is not numeric"));
    }
    let pgrp = fields[2].parse::<i32>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric process group"));
    let starttime = fields[19].parse::<u64>().unwrap_or_else(|_| panic!("malformed {path}: non-numeric starttime"));
    ProcLookup::Present(ProcEntry { state, pgrp, starttime })
}

fn bounded(text: &str) -> String {
    text.chars().take(120).collect()
}
