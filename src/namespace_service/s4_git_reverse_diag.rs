//! Closed, bounded advisory diagnostics for reverse-import Git child failures.
//!
//! A diagnostic carries only a finite stage and a finite failure class. It never
//! accepts argv, refs, object ids, paths, URIs, credentials, status codes or
//! child stdout/stderr.
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
