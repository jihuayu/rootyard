//! Pure mock regressions for the Issue #182 empty/history diagnostic recorder.
//!
//! These tests use only typed values and local state.  They never invoke Git, a process, a
//! thread, the network, PostgreSQL/Garage, or a service, and they are not part of the
//! `ci_clonekit` three-case integration inventory.

#[path = "ci_clonekit_diag_support/mod.rs"]
mod ck_diag;

use std::{cell::Cell, rc::Rc};

use ck_diag::{Class, Frame, Phase, Recorder};
use rootyard::ci_checkouts::clonekit::CloneKitError;

const SUPPORT: &str = include_str!("ci_clonekit_diag_support/mod.rs");

fn ensure_blocks(source: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("anyhow::ensure!(") {
        let candidate = &rest[start..];
        let end = candidate.find(");").map(|i| i + 2).unwrap_or(candidate.len());
        blocks.push(&candidate[..end]);
        rest = &candidate[end..];
    }
    blocks
}

#[test]
fn original_ensure_conditions_have_no_diagnostic_wrappers() {
    let blocks = ensure_blocks(SUPPORT);
    assert_eq!(blocks.len(), 3, "the moved body must still contain the three original ensures");
    assert!(blocks.iter().all(|block| !block.contains("diag.")));
    assert!(blocks.iter().all(|block| !block.contains("ck_diag")));

    assert!(blocks[0].contains("build_kit(ids, Sha1, 1, &empty, &td, None, None)?"));
    assert!(blocks[0].contains("== CloneKitStatus::EmptyRepository"));
    assert!(blocks[1].contains("publish_clonekit_versioned(&store, &b2, &git_binary(), None, None).is_err()"));
    assert!(blocks[1].contains("store.load_latest(ids.1)?.expect(\"latest\").kit_generation"));
    assert!(blocks[1].contains("== 1"));
    assert!(blocks[2].contains("res.telemetry.strategy"));
    assert!(blocks[2].contains("CheckoutStrategy::StockGitFallback"));
    assert!(!SUPPORT.contains("expected_err"));
    assert!(!SUPPORT.contains("diag.typed_ck"));
    assert!(!SUPPORT.contains("diag.typed_anyhow"));
}

#[test]
fn pre_marks_precede_eager_empty_init_and_corrupt_build() {
    let empty_phase = SUPPORT.find("Phase::EmptyBuildOrStatus").expect("empty phase");
    let empty_init = SUPPORT.find("init_repo(td.path(), \"empty.git\"").expect("empty init");
    assert!(empty_phase < empty_init, "empty phase must be marked before the eager empty init");

    let corrupt_phase = SUPPORT.find("Phase::CorruptBuild").expect("corrupt phase");
    let corrupt_build = SUPPORT.find("build_kit(ids, Sha1, 2").expect("corrupt build");
    assert!(corrupt_phase < corrupt_build, "corrupt phase must be marked before the eager corrupt build");

    let publication_mark =
        SUPPORT.find("diag.mark(crate::ck_diag::Phase::CorruptPublicationPreservesLatest").expect("publication mark");
    let publish = SUPPORT.find("publish_clonekit_versioned(&store, &b2").expect("publish");
    let latest = SUPPORT.find("expect(\"latest\")").expect("latest expect");
    assert!(publication_mark < publish, "publication phase must be marked before publish");
    assert!(publication_mark < latest, "publication phase must be marked before latest expect");
}

#[test]
fn drop_io_is_best_effort_and_bounded() {
    assert!(SUPPORT.contains("let mut stderr = std::io::stderr().lock();"));
    assert!(SUPPORT.contains("let _ = writeln!("));
    assert!(!SUPPORT.contains("eprintln!("));
}

#[test]
fn observe_final_keeps_exact_ensure_error_text_and_classifies_assert() {
    fn original_shaped(lhs: bool, rhs: Option<u8>) -> anyhow::Result<()> {
        anyhow::ensure!(lhs && rhs.unwrap_or(0) == 1);
        Ok(())
    }

    let baseline = original_shaped(false, Some(1)).unwrap_err().to_string();
    let result = original_shaped(false, Some(1));
    let before = result.as_ref().unwrap_err().to_string();
    assert_eq!(before, baseline);

    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::EmptyBuildOrStatus, file!(), line!());
    recorder.observe_final(result.as_ref().unwrap_err());
    let frame = recorder.recorded().expect("untyped ensure Err must be ASSERT");
    assert_eq!(frame.phase, Phase::EmptyBuildOrStatus);
    assert_eq!(frame.class, Class::Assert);

    let after = result.unwrap_err().to_string();
    assert_eq!(after, baseline);
    recorder.disarm();
}

#[test]
fn observe_final_keeps_typed_clonekit_error_class() {
    let error: anyhow::Error = anyhow::anyhow!(CloneKitError::MissingKit);
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::HistoryCheckout, file!(), line!());
    recorder.observe_final(&error);
    let frame = recorder.recorded().expect("typed final Err must be classified");
    assert_eq!(frame.phase, Phase::HistoryCheckout);
    assert_eq!(frame.class, Class::MissingKit);
    recorder.disarm();
}

#[test]
fn observe_final_untyped_non_assert_phase_is_other() {
    let error = anyhow::anyhow!("synthetic setup failure not emitted");
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::Setup, file!(), line!());
    recorder.observe_final(&error);
    let frame = recorder.recorded().expect("untyped non-assert Err must be classified");
    assert_eq!(frame.phase, Phase::Setup);
    assert_eq!(frame.class, Class::Other);
    recorder.disarm();
}

#[test]
fn eager_anyhow_classifies_typed_and_other_and_preserves_error() {
    let mut typed = Recorder::new(file!(), line!());
    let observed = typed.eager_anyhow(Phase::ActiveBuild, file!(), line!(), || {
        Err::<(), _>(anyhow::anyhow!(CloneKitError::GitFailed("synthetic detail not emitted".into())))
    });
    assert!(matches!(observed, Err(ref err) if err.downcast_ref::<CloneKitError>().is_some()));
    let frame = typed.recorded().expect("typed eager error must be classified");
    assert_eq!(frame.phase, Phase::ActiveBuild);
    assert_eq!(frame.class, Class::GitFailed);
    typed.disarm();

    let mut plain = Recorder::new(file!(), line!());
    let observed = plain.eager_anyhow(Phase::ActiveBuild, file!(), line!(), || {
        Err::<(), _>(anyhow::anyhow!("synthetic plain error not emitted"))
    });
    assert!(observed.is_err());
    let frame = plain.recorded().expect("plain eager error must be classified");
    assert_eq!(frame.class, Class::Other);
    plain.disarm();
}

#[test]
fn eager_ck_classifies_variant_and_preserves_error() {
    let mut recorder = Recorder::new(file!(), line!());
    let observed = recorder.eager_ck(Phase::Setup, file!(), line!(), || Err::<(), _>(CloneKitError::MissingKit));
    assert!(matches!(observed, Err(CloneKitError::MissingKit)));
    let frame = recorder.recorded().expect("eager CloneKitError must be classified");
    assert_eq!(frame.phase, Phase::Setup);
    assert_eq!(frame.class, Class::MissingKit);
    recorder.disarm();
}

#[test]
fn eager_records_the_phase_passed_for_the_operation() {
    let mut recorder = Recorder::new(file!(), line!());
    let observed = recorder.eager_anyhow(Phase::CorruptBuild, file!(), line!(), || {
        Err::<(), _>(anyhow::anyhow!("synthetic corrupt build failure not emitted"))
    });
    assert!(observed.is_err());
    let frame = recorder.recorded().expect("eager failure must be classified");
    assert_eq!(frame.phase, Phase::CorruptBuild);
    assert_eq!(frame.class, Class::Other);
    recorder.disarm();
}

#[test]
fn panic_drop_uses_premarked_empty_init_phase() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(true, Rc::clone(&observed));
        recorder.mark(Phase::EmptyBuildOrStatus, file!(), 71);
    }
    let frame = observed.get().expect("Drop must emit one panic frame");
    assert_eq!(frame.phase, Phase::EmptyBuildOrStatus);
    assert_eq!(frame.class, Class::Panic);
    assert_eq!(frame.line, 71);
}

#[test]
fn panic_drop_uses_premarked_corrupt_build_phase() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(true, Rc::clone(&observed));
        recorder.mark(Phase::CorruptBuild, file!(), 72);
    }
    let frame = observed.get().expect("Drop must emit one panic frame");
    assert_eq!(frame.phase, Phase::CorruptBuild);
    assert_eq!(frame.class, Class::Panic);
    assert_eq!(frame.line, 72);
}

#[test]
fn expected_publish_err_is_success_input_and_not_recorded() {
    let publish: Result<(), CloneKitError> =
        Err(CloneKitError::CorruptArtifact("expected synthetic publish Err not emitted".into()));
    let rhs_calls = Cell::new(0);
    let evaluated = publish.is_err() && {
        rhs_calls.set(rhs_calls.get() + 1);
        true
    };
    assert!(evaluated);
    assert_eq!(rhs_calls.get(), 1);

    let final_result: anyhow::Result<()> = Ok(());
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), line!());
    match &final_result {
        Ok(()) => recorder.disarm(),
        Err(err) => recorder.observe_final(err),
    }
    assert!(recorder.recorded().is_none());
}

#[test]
fn unexpected_publish_ok_short_circuits_and_final_ensure_err_is_assert() {
    let publish: Result<(), CloneKitError> = Ok(());
    let rhs_calls = Cell::new(0);
    let evaluated = publish.is_err() && {
        rhs_calls.set(rhs_calls.get() + 1);
        true
    };
    assert!(!evaluated);
    assert_eq!(rhs_calls.get(), 0);

    let final_err = anyhow::anyhow!("synthetic failed ensure not emitted");
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), line!());
    recorder.observe_final(&final_err);
    let frame = recorder.recorded().expect("failed original condition must be ASSERT");
    assert_eq!(frame.phase, Phase::CorruptPublicationPreservesLatest);
    assert_eq!(frame.class, Class::Assert);
    recorder.disarm();
}

#[test]
fn all_success_is_silent() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(false, Rc::clone(&observed));
        recorder.mark(Phase::HistoryStrategy, file!(), 91);
        recorder.disarm();
    }
    assert!(observed.get().is_none());
}

#[test]
fn frames_are_first_wins_and_drop_emits_only_once() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(false, Rc::clone(&observed));
        recorder.mark(Phase::CorruptBuild, file!(), 101);
        let _ = recorder
            .eager_ck(Phase::CorruptBuild, file!(), 101, || Err::<(), _>(CloneKitError::GitFailed("first".into())));
        let _ = recorder
            .eager_ck(Phase::CorruptBuild, file!(), 102, || Err::<(), _>(CloneKitError::BlobFailed("second".into())));
    }
    let frame = observed.get().expect("one frame must be emitted");
    assert_eq!(frame.class, Class::GitFailed);
    assert_eq!(frame.line, 101);
}

#[test]
fn frame_is_copy_and_contains_no_owned_payload() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<Frame>();
}

#[test]
fn independent_recorders_do_not_cross_contaminate() {
    let mut first = Recorder::new(file!(), line!());
    let mut second = Recorder::new(file!(), line!());
    first.mark(Phase::EmptyBuildOrStatus, file!(), 111);
    second.mark(Phase::HistoryGrant, file!(), 112);
    let first_frame = first.finish(false).expect("assert phase must emit");
    let second_frame = second.finish(false).expect("non-assert phase must emit");
    assert_eq!(first_frame.phase, Phase::EmptyBuildOrStatus);
    assert_eq!(first_frame.class, Class::Assert);
    assert_eq!(second_frame.phase, Phase::HistoryGrant);
    assert_eq!(second_frame.class, Class::Other);
}
