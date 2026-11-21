//! Reverse Git diagnostic coverage split out of `s4_git_proc_tests.rs`.
use super::*;

#[cfg(unix)]
const REVERSE_STAGES: [ReverseGitStage; 10] = [
    ReverseGitStage::SourceProjection,
    ReverseGitStage::ProposalVerifyFetch,
    ReverseGitStage::AncestryIntegrity,
    ReverseGitStage::SubtreeExportRefUpdate,
    ReverseGitStage::SubtreeSourceFetch,
    ReverseGitStage::SubtreeSourceTreeResolve,
    ReverseGitStage::SubtreeRootListing,
    ReverseGitStage::SubtreeRootRebuild,
    ReverseGitStage::CommitSynthesize,
    ReverseGitStage::PackWriteIndex,
];

#[test]
fn reverse_git_diagnostic_labels_are_closed_and_bounded() {
    let stages = [
        (ReverseGitStage::SourceProjection, "source_projection"),
        (ReverseGitStage::ProposalVerifyFetch, "proposal_verify_fetch"),
        (ReverseGitStage::AncestryIntegrity, "ancestry_integrity"),
        (ReverseGitStage::SubtreeExportRefUpdate, "subtree_export_ref_update"),
        (ReverseGitStage::SubtreeSourceFetch, "subtree_source_fetch"),
        (ReverseGitStage::SubtreeSourceTreeResolve, "subtree_source_tree_resolve"),
        (ReverseGitStage::SubtreeRootListing, "subtree_root_listing"),
        (ReverseGitStage::SubtreeRootRebuild, "subtree_root_rebuild"),
        (ReverseGitStage::CommitSynthesize, "commit_synthesize"),
        (ReverseGitStage::PackWriteIndex, "pack_write_index"),
    ];
    for (stage, label) in stages {
        assert_eq!(stage.as_str(), label);
    }
    let outcomes = [
        (reverse_diag::ReverseGitChildOutcome::NonzeroExit, "nonzero_exit"),
        (reverse_diag::ReverseGitChildOutcome::Signaled, "signaled"),
        (reverse_diag::ReverseGitChildOutcome::Unknown, "unknown"),
    ];
    for (outcome, label) in outcomes {
        assert_eq!(outcome.as_str(), label);
    }
    let mut line = Vec::new();
    reverse_diag::write_failure_line(
        &mut line,
        ReverseGitStage::CommitSynthesize,
        reverse_diag::ReverseGitChildOutcome::Signaled,
    )
    .unwrap();
    assert_eq!(line, b"rootyard: S4 reverse Git child failed stage=commit_synthesize outcome=signaled\n");
}

#[test]
fn reverse_git_diagnostic_write_failure_is_best_effort() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let result = reverse_diag::write_failure_line(
        &mut Failing,
        ReverseGitStage::CommitSynthesize,
        reverse_diag::ReverseGitChildOutcome::NonzeroExit,
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
}

#[cfg(unix)]
#[test]
fn reverse_git_child_outcome_distinguishes_nonzero_signal_and_unknown() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        reverse_diag::classify(ExitStatus::from_raw(7 << 8)),
        reverse_diag::ReverseGitChildOutcome::NonzeroExit
    );
    assert_eq!(reverse_diag::classify(ExitStatus::from_raw(9)), reverse_diag::ReverseGitChildOutcome::Signaled);
    assert_eq!(reverse_diag::classify(ExitStatus::from_raw(0x7f)), reverse_diag::ReverseGitChildOutcome::Unknown);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn every_reverse_stage_reaches_closed_runner_diagnostic_and_keeps_public_conflict() {
    for stage in REVERSE_STAGES {
        let _ = reverse_diag::take_for_test();
        let mut cmd = base_command(FsPath::new("/bin/sh"));
        cmd.args(["-c", "exit 7"]);
        let error = run_git_bounded(
            cmd,
            GitStdin::Null,
            1024,
            Instant::now() + Duration::from_secs(10),
            Error(StatusCode::CONFLICT, "Git View reverse mapping conflict"),
            Some(stage),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert_eq!(error.1, "Git View reverse mapping conflict");
        assert_eq!(
            reverse_diag::take_for_test(),
            vec![(stage, reverse_diag::ReverseGitChildOutcome::NonzeroExit)]
        );
    }
}
