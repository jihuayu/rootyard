//! Test-only Linux process identity for the cancelled S4 Git runner witness.
//!
//! A bare PID is not an identity: Linux can reuse it, and a zombie remains
//! visible until reaped. Capture `(pid, starttime)` only while the fixture is
//! demonstrably live, then re-read that identity at scratch release.

use std::io;

const FIELDS_THROUGH_STARTTIME: usize = 20;

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
        classify(self, lookup(self.pid))
    }
}

pub(super) fn capture_pair(leader: i32, descendant: i32) -> (OriginalProcess, OriginalProcess) {
    assert_procfs_live();
    let leader_entry = live_entry(leader, "leader");
    let descendant_entry = live_entry(descendant, "descendant");
    assert_eq!(
        leader_entry.pgrp, leader,
        "leader {leader} is in process group {}, not its own",
        leader_entry.pgrp
    );
    assert_eq!(
        descendant_entry.pgrp, leader,
        "descendant {descendant} is in process group {}, not leader {leader}",
        descendant_entry.pgrp
    );
    (
        OriginalProcess { pid: leader, starttime: leader_entry.starttime },
        OriginalProcess { pid: descendant, starttime: descendant_entry.starttime },
    )
}

fn live_entry(pid: i32, role: &str) -> ProcEntry {
    match lookup(pid) {
        ProcLookup::Gone => panic!("{role} {pid} is not visible in procfs"),
        ProcLookup::Present(entry) => {
            assert_eq!(entry.state, ProcState::Live, "{role} {pid} is {:?}, not live", entry.state);
            entry
        }
    }
}

fn classify(original: OriginalProcess, observed: ProcLookup) -> ProcState {
    match observed {
        ProcLookup::Gone => ProcState::Gone,
        ProcLookup::Present(entry) if entry.starttime != original.starttime => ProcState::Gone,
        ProcLookup::Present(entry) => entry.state,
    }
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
        Err(error) if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {
            return ProcLookup::Gone;
        }
        Err(error) => panic!("cannot read {path}: {error}"),
    };
    ProcLookup::Present(parse_stat(pid, &path, &stat))
}

fn parse_stat(pid: i32, path: &str, stat: &str) -> ProcEntry {
    let (prefix, rest) = stat
        .rsplit_once(") ")
        .unwrap_or_else(|| panic!("truncated {path}: missing command terminator"));
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
    ProcEntry { state, pgrp, starttime }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pid: i32, state: &str, pgrp: i32, starttime: u64) -> String {
        format!("{pid} (git ) child) {state} 1 {pgrp} 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 {starttime}")
    }

    #[test]
    fn parses_final_parenthesis_command_field_and_starttime() {
        let entry = parse_stat(4242, "/proc/4242/stat", &stat(4242, "S", 77, 9000));
        assert_eq!(entry.state, ProcState::Live);
        assert_eq!(entry.pgrp, 77);
        assert_eq!(entry.starttime, 9000);
    }

    #[test]
    #[should_panic(expected = "truncated")]
    fn rejects_short_stat() {
        parse_stat(4242, "/proc/4242/stat", "4242 (sh) S 0 77");
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn rejects_unknown_state() {
        parse_stat(4242, "/proc/4242/stat", &stat(4242, "?", 77, 9000));
    }

    #[test]
    fn pid_reuse_is_gone_and_zombie_is_exited() {
        let original = OriginalProcess { pid: 4242, starttime: 9000 };
        let reused = ProcLookup::Present(ProcEntry { state: ProcState::Live, pgrp: 77, starttime: 9001 });
        assert_eq!(classify(original, reused), ProcState::Gone);
        let zombie = ProcLookup::Present(ProcEntry { state: ProcState::Exited, pgrp: 77, starttime: 9000 });
        assert_eq!(classify(original, zombie), ProcState::Exited);
        let live = ProcLookup::Present(ProcEntry { state: ProcState::Live, pgrp: 77, starttime: 9000 });
        assert_eq!(classify(original, live), ProcState::Live);
    }
}
