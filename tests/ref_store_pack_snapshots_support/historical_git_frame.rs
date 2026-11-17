//! Test-only bounded numeric frame for historical `cat-file` failures.
//!
//! The frame is independent of the existing metadata-replay line grammar. It
//! carries only closed numeric outcome/class values and never formats stderr,
//! arguments, paths, object ids, or provider payloads.
#![allow(dead_code)]

use std::fmt;
use std::fmt::Write as _;
use std::io::Write as _;

pub const PREFIX: &str = "ROOTYARD_I107_HISTORICAL_GIT_V1";
const PHASE: u8 = 17;
const SITE: u8 = 9;
const MAX_LINE_BYTES: usize = 512;
const MAX_STDERR_BYTES: usize = 4096;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Exited = 1,
    Signaled = 2,
    Timeout = 3,
    SpawnIo = 4,
    WaitIo = 5,
    Other = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalGitError {
    outcome: Outcome,
    exit_code: Option<i32>,
    signal: Option<i32>,
    message_class: u8,
}

fn normalize_message_class(value: u8) -> u8 {
    if value <= 4 { value } else { 0 }
}

impl HistoricalGitError {
    pub fn exited(code: i32, message_class: u8) -> Self {
        if code < 0 {
            return Self::other();
        }
        Self {
            outcome: Outcome::Exited,
            exit_code: Some(code),
            signal: None,
            message_class: normalize_message_class(message_class),
        }
    }

    pub fn signaled(signal: i32, message_class: u8) -> Self {
        if !(1..=127).contains(&signal) {
            return Self::other();
        }
        Self {
            outcome: Outcome::Signaled,
            exit_code: None,
            signal: Some(signal),
            message_class: normalize_message_class(message_class),
        }
    }

    pub fn timeout() -> Self {
        Self { outcome: Outcome::Timeout, exit_code: None, signal: None, message_class: 0 }
    }

    pub fn spawn_io() -> Self {
        Self { outcome: Outcome::SpawnIo, exit_code: None, signal: None, message_class: 0 }
    }

    pub fn wait_io() -> Self {
        Self { outcome: Outcome::WaitIo, exit_code: None, signal: None, message_class: 0 }
    }

    pub fn other() -> Self {
        Self { outcome: Outcome::Other, exit_code: None, signal: None, message_class: 0 }
    }

    pub fn outcome(self) -> Outcome {
        self.outcome
    }

    pub fn exit_code(self) -> Option<i32> {
        self.exit_code
    }

    pub fn signal(self) -> Option<i32> {
        self.signal
    }

    pub fn message_class(self) -> u8 {
        self.message_class
    }

    /// Emit exactly one frame only when tracing is enabled for this call.
    pub fn trace_if(self, enabled: bool) -> Self {
        if enabled {
            self.emit_frame();
        }
        self
    }

    pub fn frame_line(self) -> String {
        let mut line = String::with_capacity(96);
        let _ = write!(&mut line, "{}|{}|{}|{}|", PREFIX, PHASE, SITE, self.outcome as u8);
        if let Some(code) = self.exit_code {
            let _ = write!(&mut line, "{code}");
        }
        line.push('|');
        if let Some(signal) = self.signal {
            let _ = write!(&mut line, "{signal}");
        }
        line.push('|');
        let _ = writeln!(&mut line, "{}", self.message_class);
        line
    }

    fn emit_frame(self) {
        let line = self.frame_line();
        if line.len() <= MAX_LINE_BYTES {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            let _ = handle.write_all(line.as_bytes());
            let _ = handle.flush();
        }
    }
}

impl fmt::Display for HistoricalGitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exit = match self.exit_code {
            Some(code) => code.to_string(),
            None => "-".to_owned(),
        };
        let signal = match self.signal {
            Some(signal) => signal.to_string(),
            None => "-".to_owned(),
        };
        write!(
            f,
            "historical git cat-file failed (outcome={} exit={exit} signal={signal} message={})",
            self.outcome as u8, self.message_class
        )
    }
}

impl std::error::Error for HistoricalGitError {}

fn single_ascii_line(stderr: &[u8]) -> Option<&str> {
    if stderr.is_empty() || stderr.len() > MAX_STDERR_BYTES {
        return None;
    }
    let bytes = stderr.strip_suffix(b"\n").unwrap_or(stderr);
    if bytes.is_empty() || bytes.iter().any(|byte| *byte == b'\n' || *byte == b'\r' || !(0x20..=0x7e).contains(byte)) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// Classify one exact official Git stderr template, without retaining it.
///
/// 0 unknown, 1 invalid object name, 2 bad file, 3 stream stdout, 4 path
/// absent. Malformed, multiline, non-ASCII, ambiguous, or oversized input is
/// unknown. This is observed static text only; it is not a cause claim.
pub fn classify_stderr(stderr: &[u8]) -> u8 {
    let line = match single_ascii_line(stderr) {
        Some(line) => line,
        None => return 0,
    };
    if let Some(rest) = line.strip_prefix("fatal: Not a valid object name ") {
        return if rest.is_empty() { 0 } else { 1 };
    }
    if let Some(rest) = line.strip_prefix("fatal: git cat-file ")
        && let Some(rest) = rest.strip_suffix(": bad file")
    {
        return if rest.is_empty() { 0 } else { 2 };
    }
    if let Some(rest) = line.strip_prefix("fatal: unable to stream ")
        && let Some(rest) = rest.strip_suffix(" to stdout")
    {
        return if rest.is_empty() { 0 } else { 3 };
    }
    if let Some(rest) = line.strip_prefix("fatal: path '")
        && let Some(rest) = rest.strip_suffix("'")
    {
        let mut parts = rest.split("' does not exist in '");
        let path = parts.next();
        let repo = parts.next();
        if let (Some(path), Some(repo), None) = (path, repo, parts.next()) {
            return if path.is_empty() || repo.is_empty() { 0 } else { 4 };
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_four_exact_templates() {
        assert_eq!(classify_stderr(b"fatal: Not a valid object name deadbeef\n"), 1);
        assert_eq!(classify_stderr(b"fatal: git cat-file 'HEAD:file': bad file\n"), 2);
        assert_eq!(classify_stderr(b"fatal: unable to stream 'HEAD:file' to stdout\n"), 3);
        assert_eq!(classify_stderr(b"fatal: path 'dir/file' does not exist in 'HEAD'\n"), 4);
    }

    #[test]
    fn classifies_one_complete_line_with_or_without_newline() {
        for line in [
            b"fatal: Not a valid object name deadbeef".as_slice(),
            b"fatal: Not a valid object name deadbeef\n".as_slice(),
        ] {
            assert_eq!(classify_stderr(line), 1);
        }
        assert_eq!(classify_stderr(b"fatal: git cat-file x: bad file"), 2);
        assert_eq!(classify_stderr(b"fatal: unable to stream x to stdout"), 3);
        assert_eq!(classify_stderr(b"fatal: path 'x' does not exist in 'y'"), 4);
    }

    #[test]
    fn rejects_empty_dynamic_values_and_ambiguous_shapes() {
        assert_eq!(classify_stderr(b"fatal: Not a valid object name \n"), 0);
        assert_eq!(classify_stderr(b"fatal: git cat-file : bad file\n"), 0);
        assert_eq!(classify_stderr(b"fatal: unable to stream  to stdout\n"), 0);
        assert_eq!(classify_stderr(b"fatal: path '' does not exist in 'HEAD'\n"), 0);
        assert_eq!(classify_stderr(b"fatal: path 'a' does not exist in ''\n"), 0);
        assert_eq!(classify_stderr(b"fatal: path 'a' does not exist in 'b' does not exist in 'c'\n"), 0);
        assert_eq!(classify_stderr(b"fatal: path 'a' does not exist in 'b' extra\n"), 0);
    }

    #[test]
    fn rejects_malformed_multiline_non_ascii_ambiguous_and_oversize() {
        assert_eq!(classify_stderr(b""), 0);
        assert_eq!(classify_stderr(b"fatal: unknown\n"), 0);
        assert_eq!(classify_stderr(b"fatal: Not a valid object name x\nsecond\n"), 0);
        assert_eq!(classify_stderr(b"fatal: Not a valid object name \xff\n"), 0);
        assert_eq!(classify_stderr(b"fatal: Not a valid object name x\r\n"), 0);
        assert_eq!(classify_stderr(b"fatal: Not a valid object name x\n\n"), 0);
        assert_eq!(classify_stderr(b"fatal: Not a valid object name x\t\n"), 0);
        assert_eq!(classify_stderr(&vec![b'a'; MAX_STDERR_BYTES + 1]), 0);
    }

    #[test]
    fn numeric_outcomes_are_closed_and_invalid_values_become_other() {
        for error in [
            HistoricalGitError::exited(-1, 2),
            HistoricalGitError::signaled(0, 3),
            HistoricalGitError::signaled(128, 3),
        ] {
            assert_eq!(error.outcome(), Outcome::Other);
            assert_eq!(error.exit_code(), None);
            assert_eq!(error.signal(), None);
            assert_eq!(error.message_class(), 0);
        }
        assert_eq!(HistoricalGitError::exited(7, 9).message_class(), 0);
        assert_eq!(HistoricalGitError::signaled(9, 9).message_class(), 0);
        assert_eq!(HistoricalGitError::exited(7, 4).outcome(), Outcome::Exited);
        assert_eq!(HistoricalGitError::signaled(9, 4).outcome(), Outcome::Signaled);
    }

    #[test]
    fn frames_are_numeric_and_bounded() {
        let exited = HistoricalGitError::exited(128, 2).frame_line();
        assert_eq!(exited, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|1|128||2\n");
        assert!(exited.len() <= MAX_LINE_BYTES);
        let signaled = HistoricalGitError::signaled(9, 0).frame_line();
        assert_eq!(signaled, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|2||9|0\n");
        let timeout = HistoricalGitError::timeout().frame_line();
        assert_eq!(timeout, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|3|||0\n");
        let spawn = HistoricalGitError::spawn_io().frame_line();
        assert_eq!(spawn, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|4|||0\n");
        let wait = HistoricalGitError::wait_io().frame_line();
        assert_eq!(wait, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|5|||0\n");
        let other = HistoricalGitError::other().frame_line();
        assert_eq!(other, "ROOTYARD_I107_HISTORICAL_GIT_V1|17|9|6|||0\n");
        let widest = HistoricalGitError::exited(i32::MAX, 4).frame_line();
        assert!(widest.len() <= MAX_LINE_BYTES);
        for line in [&exited, &signaled, &timeout, &spawn, &wait, &other, &widest] {
            let parts: Vec<&str> = line.trim_end_matches('\n').split('|').collect();
            assert_eq!(parts.len(), 7);
            assert_eq!(parts[0], PREFIX);
            assert_eq!(parts[1], "17");
            assert_eq!(parts[2], "9");
            assert!(parts[3..].iter().all(|part| part.is_empty() || part.bytes().all(|byte| byte.is_ascii_digit())));
        }
        assert!(!timeout.contains("stderr"));
    }

    #[test]
    fn display_is_fixed_label_and_numeric_only() {
        assert_eq!(
            HistoricalGitError::exited(128, 4).to_string(),
            "historical git cat-file failed (outcome=1 exit=128 signal=- message=4)"
        );
        assert_eq!(
            HistoricalGitError::signaled(9, 0).to_string(),
            "historical git cat-file failed (outcome=2 exit=- signal=9 message=0)"
        );
        assert_eq!(
            HistoricalGitError::timeout().to_string(),
            "historical git cat-file failed (outcome=3 exit=- signal=- message=0)"
        );
    }
}
