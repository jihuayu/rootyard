//! Typed Git command runner for native browse reads.
//!
//! This module owns the process contract of a native read: the bounded child
//! environment ([`git_cmd`]), the compiled step label ([`GitStep`]) whose typed
//! exit class decides 404 versus 500, the secret-free diagnostics, and the
//! outcome/runner pair ([`GitOutcome`], [`run_git`]) that maps a Git verdict to
//! an HTTP error without ever reading untrusted Git text.
use crate::{AppState, Error};
use axum::http::StatusCode;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::process::Command;
use uuid::Uuid;

pub(crate) fn git_cmd(state: &AppState, repo_id: Uuid) -> Result<Command, Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    let memory = state.config.git_memory_bytes;
    let file = state.config.max_repo_bytes;
    let cpu = state.config.git_timeout.as_secs().max(1);
    unsafe {
        cmd.pre_exec(move || {
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, file),
                (libc::RLIMIT_NOFILE, 256),
            ] {
                let value = libc::rlimit { rlim_cur: limit, rlim_max: limit };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "--git-dir"]).arg(repo_path);
    Ok(cmd)
}

/// Fixed label for one native read step.
///
/// A label is a compiled literal. It is never derived from argv, a ref name, an
/// object id, Git stdout or Git stderr, so a step diagnostic cannot leak a
/// credential or repository content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitStep {
    ObjectType,
    HeadVerify,
    HeadRefs,
    RefsPage,
    RevParse,
    CommitRead,
    CommitBatch,
    CommitDiff,
    CommitList,
    TreeList,
    BlobSize,
    BlobContent,
    MergeBase,
    CompareCount,
    CompareCommits,
    CompareDiff,
    ObjectFormat,
    RefVerify,
}

impl GitStep {
    pub(crate) fn label(self) -> &'static str {
        match self {
            GitStep::ObjectType => "object-type",
            GitStep::HeadVerify => "head-verify",
            GitStep::HeadRefs => "head-refs",
            GitStep::RefsPage => "refs-page",
            GitStep::RevParse => "rev-parse",
            GitStep::CommitRead => "commit-read",
            GitStep::CommitBatch => "commit-batch",
            GitStep::CommitDiff => "commit-diff",
            GitStep::CommitList => "commit-list",
            GitStep::TreeList => "tree-list",
            GitStep::BlobSize => "blob-size",
            GitStep::BlobContent => "blob-content",
            GitStep::MergeBase => "merge-base",
            GitStep::CompareCount => "compare-count",
            GitStep::CompareCommits => "compare-commits",
            GitStep::CompareDiff => "compare-diff",
            GitStep::ObjectFormat => "object-format",
            GitStep::RefVerify => "ref-verify",
        }
    }

    /// Only these steps run Git's precise quiet probes, whose exit 1 means "no
    /// such name". Any other step runs on a repository that already passed
    /// authorization and readiness checks, so a failure is a broken native read
    /// and must never be reported as "not found". In particular `object-type`
    /// is not here: it reads a type only after a probe proved the object exists.
    pub(crate) fn absence_is_expected(self) -> bool {
        matches!(self, GitStep::HeadVerify | GitStep::RevParse | GitStep::MergeBase | GitStep::RefVerify)
    }

    /// A probe may answer 404 only when Git itself answered "no such name" with
    /// its quiet verdict, which is exactly exit 1 for `rev-parse --verify
    /// --quiet`, `merge-base` and the ref probe. Exit 128 is Git's generic fatal
    /// class (damaged object database, missing repository path, a race on an
    /// otherwise healthy repository) and cannot prove that a name is absent; a
    /// usage error (129) or a signal likewise means the native read broke. All
    /// of those stay internal failures, so corruption is never disguised as a
    /// 404 and a real absence is never disguised as a 500.
    pub(crate) fn maps_to_not_found(self, exit: Option<i32>) -> bool {
        self.absence_is_expected() && matches!(exit, Some(1))
    }

    /// Fixed exit-class label. Git reserves 129 for usage errors (for example an
    /// option the configured Git does not implement) and 128 for fatal
    /// repository errors; anything else is an unclassified non-zero exit.
    pub(crate) fn failure_class(self, exit: Option<i32>) -> &'static str {
        match exit {
            Some(129) => "usage",
            Some(128) => "fatal",
            Some(_) => "nonzero",
            None => "signal",
        }
    }
}

/// Record once per process that the configured Git lacks the paging option.
pub(in crate::browse::git_read) fn report_seek_fallback() {
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    if REPORTED.fetch_add(1, Ordering::Relaxed) != 0 {
        return;
    }
    eprintln!(
        "rootyard: browse git read step={} class=usage fallback=bounded-scan",
        GitStep::RefsPage.label()
    );
}

/// Emit one bounded, secret-free record for a failed required native read step.
pub(in crate::browse::git_read) fn report_step_failure(step: GitStep, exit: Option<i32>) {
    // A broken storage volume must not be able to flood stderr per request.
    const BUDGET: u32 = 64;
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    if REPORTED.fetch_add(1, Ordering::Relaxed) >= BUDGET {
        return;
    }
    let code = match exit {
        Some(code) => code.to_string(),
        None => "signal".to_owned(),
    };
    eprintln!(
        "rootyard: browse git read step={} class={} exit={}",
        step.label(),
        step.failure_class(exit),
        code
    );
}

/// Raw outcome of one native read step before HTTP mapping.
///
/// The typed exit code exists so a capability fallback is selected from Git's
/// exit status, never by matching untrusted Git error text.
pub(in crate::browse::git_read) enum GitOutcome {
    Output(Vec<u8>),
    CommandFailed { exit: Option<i32> },
}

fn exit_of(err: &anyhow::Error) -> Option<Option<i32>> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<crate::git_http::GitCommandFailed>())
        .map(|failure| failure.exit)
}

/// Map a failed native read to the truthful HTTP result for its step.
pub(in crate::browse::git_read) fn map_git_failure(err: anyhow::Error, step: GitStep) -> Error {
    let msg = err.to_string();
    if msg.contains("timed out") {
        return Error::timeout();
    }
    if msg.contains("exceeds limit") {
        return Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit");
    }
    let failure = exit_of(&err);
    let Some(exit) = failure else {
        // Spawn, pipe or reaping failure: not a Git verdict, never a 404.
        return Error::internal(err);
    };
    if step.maps_to_not_found(exit) {
        return Error::not_found();
    }
    report_step_failure(step, exit);
    Error::internal(crate::git_http::GitCommandFailed { exit })
}

pub(in crate::browse::git_read) async fn run_git_step(
    state: &AppState,
    repo_id: Uuid,
    step: GitStep,
    args: &[&str],
    limit: usize,
) -> Result<GitOutcome, Error> {
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(args);
    match crate::git_http::collect_git_output(cmd, limit, state.config.git_timeout).await {
        Ok(bytes) => Ok(GitOutcome::Output(bytes)),
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("timed out") {
                return Err(Error::timeout());
            }
            if msg.contains("exceeds limit") {
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit"));
            }
            let failure = exit_of(&err);
            match failure {
                Some(exit) => Ok(GitOutcome::CommandFailed { exit }),
                None => Err(Error::internal(err)),
            }
        }
    }
}

pub(crate) async fn run_git(
    state: &AppState,
    repo_id: Uuid,
    step: GitStep,
    args: &[&str],
    limit: usize,
) -> Result<Vec<u8>, Error> {
    match run_git_step(state, repo_id, step, args, limit).await? {
        GitOutcome::Output(bytes) => Ok(bytes),
        GitOutcome::CommandFailed { exit } => {
            if step.maps_to_not_found(exit) {
                // The probe asked Git whether a named ref/object exists and Git
                // answered "no"; that answer is a genuine 404.
                return Err(Error::not_found());
            }
            report_step_failure(step, exit);
            Err(Error::internal(crate::git_http::GitCommandFailed { exit }))
        }
    }
}
