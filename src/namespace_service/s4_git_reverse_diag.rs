//! Closed, bounded advisory diagnostics for reverse-import Git child failures.
//!
//! A diagnostic carries only finite stages, failure classes, probe objects and
//! probe results. It never accepts argv, refs, object ids, paths, URIs,
//! credentials, status codes or child stdout/stderr.
use std::process::ExitStatus;

/// Closed stages for the reverse-import Git child diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseGitStage {
    SourceProjection,
    ProposalVerifyFetch,
    AncestryIntegrity,
    SubtreeExportRefUpdate,
    SubtreeSourceFetch,
    SubtreeSourceTreeResolve,
    SubtreeRootListing,
    SubtreeRootRebuild,
    CommitSynthesize,
    PackWriteIndex,
}

impl ReverseGitStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SourceProjection => "source_projection",
            Self::ProposalVerifyFetch => "proposal_verify_fetch",
            Self::AncestryIntegrity => "ancestry_integrity",
            Self::SubtreeExportRefUpdate => "subtree_export_ref_update",
            Self::SubtreeSourceFetch => "subtree_source_fetch",
            Self::SubtreeSourceTreeResolve => "subtree_source_tree_resolve",
            Self::SubtreeRootListing => "subtree_root_listing",
            Self::SubtreeRootRebuild => "subtree_root_rebuild",
            Self::CommitSynthesize => "commit_synthesize",
            Self::PackWriteIndex => "pack_write_index",
        }
    }
}

/// Bounded classification of an unsuccessful Git child status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseGitChildOutcome {
    NonzeroExit,
    Signaled,
    Unknown,
}

impl ReverseGitChildOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NonzeroExit => "nonzero_exit",
            Self::Signaled => "signaled",
            Self::Unknown => "unknown",
        }
    }
}

pub(crate) fn classify(status: ExitStatus) -> ReverseGitChildOutcome {
    match status.code() {
        Some(0) => ReverseGitChildOutcome::Unknown,
        Some(_) => ReverseGitChildOutcome::NonzeroExit,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if status.signal().is_some() {
                    return ReverseGitChildOutcome::Signaled;
                }
            }
            ReverseGitChildOutcome::Unknown
        }
    }
}

/// Closed object identities for the post-failure root-tree probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseGitProbeObject {
    ReplacementSubtree,
    RetainedRootSibling,
}

impl ReverseGitProbeObject {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReplacementSubtree => "replacement_subtree",
            Self::RetainedRootSibling => "retained_root_sibling",
        }
    }
}

/// Closed projected outcomes for one local object lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseGitProbeResult {
    PresentAndTyped,
    Missing,
    ProbeError,
    Unavailable,
}

impl ReverseGitProbeResult {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PresentAndTyped => "present_and_typed",
            Self::Missing => "missing",
            Self::ProbeError => "probe_error",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Closed Git object types accepted from a local `cat-file` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseGitObjectType {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ReverseGitObjectType {
    pub(crate) fn parse(label: &str) -> Option<Self> {
        match label {
            "blob" => Some(Self::Blob),
            "tree" => Some(Self::Tree),
            "commit" => Some(Self::Commit),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

/// Classify one `cat-file --batch-check` line without exposing its raw fields.
pub(crate) fn classify_batch_check_line(
    line: &str,
    expected_oid: &str,
    expected_type: ReverseGitObjectType,
) -> (ReverseGitProbeResult, Option<ReverseGitObjectType>) {
    let mut fields = line.split_whitespace();
    if fields.next() != Some(expected_oid) {
        return (ReverseGitProbeResult::ProbeError, None);
    }
    match (fields.next(), fields.next(), fields.next()) {
        (Some("missing"), None, None) => (ReverseGitProbeResult::Missing, None),
        (Some(kind), Some(size), None) => match (ReverseGitObjectType::parse(kind), size.parse::<u64>()) {
            (Some(actual), Ok(_)) if actual == expected_type => {
                (ReverseGitProbeResult::PresentAndTyped, Some(actual))
            }
            _ => (ReverseGitProbeResult::ProbeError, None),
        },
        _ => (ReverseGitProbeResult::ProbeError, None),
    }
}

pub(crate) fn write_failure_line<W: std::io::Write>(
    writer: &mut W,
    stage: ReverseGitStage,
    outcome: ReverseGitChildOutcome,
) -> std::io::Result<()> {
    writer.write_all(b"rootyard: S4 reverse Git child failed stage=")?;
    writer.write_all(stage.as_str().as_bytes())?;
    writer.write_all(b" outcome=")?;
    writer.write_all(outcome.as_str().as_bytes())?;
    writer.write_all(b"\n")
}

pub(crate) fn write_probe_line<W: std::io::Write>(
    writer: &mut W,
    object: ReverseGitProbeObject,
    result: ReverseGitProbeResult,
    object_type: Option<ReverseGitObjectType>,
) -> std::io::Result<()> {
    writer.write_all(b"rootyard: S4 reverse Git child probe object=")?;
    writer.write_all(object.as_str().as_bytes())?;
    writer.write_all(b" result=")?;
    writer.write_all(result.as_str().as_bytes())?;
    if let Some(object_type) = object_type {
        writer.write_all(b" type=")?;
        writer.write_all(object_type.as_str().as_bytes())?;
    }
    writer.write_all(b"\n")
}

pub(crate) fn emit_probe(
    object: ReverseGitProbeObject,
    result: ReverseGitProbeResult,
    object_type: Option<ReverseGitObjectType>,
) {
    // Probe output is advisory and best-effort: the original public error and
    // the already-emitted nonzero/signal classification remain authoritative.
    let _ = write_probe_line(&mut std::io::stderr().lock(), object, result, object_type);
}

#[cfg(test)]
type ReverseGitChildDiagnostics = Vec<(ReverseGitStage, ReverseGitChildOutcome)>;

#[cfg(test)]
thread_local! {
    static REVERSE_GIT_CHILD_DIAGNOSTICS: std::cell::RefCell<ReverseGitChildDiagnostics> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn take_for_test() -> Vec<(ReverseGitStage, ReverseGitChildOutcome)> {
    REVERSE_GIT_CHILD_DIAGNOSTICS.with(|records| std::mem::take(&mut *records.borrow_mut()))
}

pub(crate) fn emit(stage: ReverseGitStage, outcome: ReverseGitChildOutcome) {
    #[cfg(test)]
    REVERSE_GIT_CHILD_DIAGNOSTICS.with(|records| records.borrow_mut().push((stage, outcome)));
    // The S4 acceptance harness installs no tracing subscriber. This is a
    // best-effort write to process stderr; a failed write is deliberately
    // discarded so the caller still returns the original public error.
    let _ = write_failure_line(&mut std::io::stderr().lock(), stage, outcome);
}
