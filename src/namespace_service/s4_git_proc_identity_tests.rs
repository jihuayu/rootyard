//! Test-only Linux process identity for the cancelled S4 Git runner witness.
//!
//! A bare PID is not an identity: Linux can reuse it, and a zombie remains
//! visible until reaped. Capture `(pid, starttime)` only while the fixture is
//! demonstrably live, then re-read that identity at scratch release.

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
impl OriginalProcess {
    pub(super) fn state(self) -> ProcState {
        assert_procfs_live();
        classify(self, lookup(self.pid))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn capture_pair(leader: i32, descendant: i32) -> (OriginalProcess, OriginalProcess) {
    assert!(leader > 1, "leader pid marker {leader} is not a valid positive process id");
    assert!(descendant > 1, "descendant pid marker {descendant} is not a valid positive process id");
    assert_ne!(leader, descendant, "leader and descendant pid markers must be distinct");
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn assert_procfs_live() {
    assert_procfs_mount();
    // Read the self entry with the kernel's actual PID. A numeric PID path
    // existing is not enough, and self must be positively parsed as live
    // before another PID's ENOENT/ESRCH can mean the original is gone.
    let pid = unsafe { libc::getpid() };
    assert!(pid > 1, "test process has invalid pid {pid}");
    let path = "/proc/self/stat";
    let stat = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    let entry = parse_stat(pid, path, &stat);
    assert_eq!(entry.state, ProcState::Live, "procfs is present but test process {pid} is {:?}", entry.state);
}

#[cfg(target_os = "linux")]
fn assert_procfs_mount() {
    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the path is a NUL-terminated literal and statfs writes the buffer
    // on success; it is only assumed initialized after a zero return.
    let result = unsafe { libc::statfs(b"/proc\0".as_ptr().cast(), statfs.as_mut_ptr()) };
    assert_eq!(result, 0, "cannot statfs /proc");
    // SAFETY: the successful statfs call initialized the buffer.
    let statfs = unsafe { statfs.assume_init() };
    assert_eq!(
        statfs.f_type as u64,
        libc::PROC_SUPER_MAGIC as u64,
        "/proc is not a procfs mount"
    );
}

/// Callers prove the `/proc` mount and parse `/proc/self/stat` first; only then
/// may ENOENT/ESRCH for another PID mean that original process is gone.
#[cfg(target_os = "linux")]
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
        "Z" | "X" => ProcState::Exited,
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

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(expected = "must be distinct")]
    fn rejects_equal_pid_markers_before_lookup() {
        capture_pair(4242, 4242);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(expected = "valid positive")]
    fn rejects_invalid_pid_markers_before_lookup() {
        capture_pair(0, 4242);
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
    fn parses_positive_zombie_and_dead_states_exited() {
        for state in ["Z", "X"] {
            assert_eq!(parse_stat(4242, "/proc/4242/stat", &stat(4242, state, 77, 9000)).state, ProcState::Exited);
        }
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn rejects_lowercase_x_state() {
        parse_stat(4242, "/proc/4242/stat", &stat(4242, "x", 77, 9000));
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
