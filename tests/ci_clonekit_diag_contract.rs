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

#[test]
fn expected_err_is_silent_and_preserves_error_identity() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(false, Rc::clone(&observed));
        recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), line!());
        let result = recorder.expected_err(
            Phase::CorruptPublicationPreservesLatest,
            file!(),
            line!(),
            Err::<(), _>(CloneKitError::CorruptArtifact("synthetic payload not emitted".into())),
        );
        assert!(matches!(result, Err(CloneKitError::CorruptArtifact(_))));
        assert!(recorder.recorded().is_none());
        recorder.disarm();
    }
    assert!(observed.get().is_none());
}

#[test]
fn expected_ok_records_exactly_one_assert_at_the_observer_line() {
    let mut recorder = Recorder::new(file!(), line!());
    let observer_line = line!() + 1;
    let observed = recorder.expected_err(
        Phase::CorruptPublicationPreservesLatest,
        file!(),
        observer_line,
        Ok::<(), CloneKitError>(()),
    );
    assert!(observed.is_ok());
    let frame = recorder.finish(false).expect("unexpected publish Ok must be classified");
    assert_eq!(frame.phase, Phase::CorruptPublicationPreservesLatest);
    assert_eq!(frame.class, Class::Assert);
    assert_eq!(frame.line, observer_line);
}

#[test]
fn typed_clonekit_error_preserves_error_and_classifies_variant() {
    let mut recorder = Recorder::new(file!(), line!());
    let error_line = line!() + 1;
    let observed = recorder.typed_ck(
        Phase::ActiveBuild,
        file!(),
        error_line,
        Err::<(), _>(CloneKitError::GitFailed("synthetic detail not emitted".into())),
    );
    assert!(matches!(observed, Err(CloneKitError::GitFailed(_))));
    let frame = recorder.finish(false).expect("typed Err must be classified");
    assert_eq!(frame.phase, Phase::ActiveBuild);
    assert_eq!(frame.class, Class::GitFailed);
    assert_eq!(frame.line, error_line);
}

#[test]
fn typed_anyhow_downcasts_clonekit_error_and_marks_plain_errors_other() {
    let mut typed = Recorder::new(file!(), line!());
    let typed_line = line!() + 1;
    let observed = typed.typed_anyhow(
        Phase::HistoryGrant,
        file!(),
        typed_line,
        Err::<(), _>(anyhow::anyhow!(CloneKitError::MissingKit)),
    );
    assert!(observed.is_err());
    let frame = typed.finish(false).expect("typed anyhow Err must be classified");
    assert_eq!(frame.class, Class::MissingKit);
    assert_eq!(frame.line, typed_line);

    let mut plain = Recorder::new(file!(), line!());
    let plain_line = line!() + 1;
    let observed = plain.typed_anyhow(
        Phase::HistoryGrant,
        file!(),
        plain_line,
        Err::<(), _>(anyhow::anyhow!("synthetic plain error not emitted")),
    );
    assert!(observed.is_err());
    let frame = plain.finish(false).expect("plain anyhow Err must be classified");
    assert_eq!(frame.class, Class::Other);
    assert_eq!(frame.line, plain_line);
}

#[test]
fn ensure_false_return_uses_assert_at_the_phase_line() {
    let ensure_result: anyhow::Result<()> = (|| {
        anyhow::ensure!(false, "synthetic ensure failure not emitted");
        Ok(())
    })();
    assert!(ensure_result.is_err());

    let mut recorder = Recorder::new(file!(), line!());
    let assertion_line = line!() + 1;
    recorder.mark(Phase::EmptyBuildOrStatus, file!(), assertion_line);
    let frame = recorder.finish(false).expect("armed assert phase must emit");
    assert_eq!(frame.phase, Phase::EmptyBuildOrStatus);
    assert_eq!(frame.class, Class::Assert);
    assert_eq!(frame.line, assertion_line);
}

#[test]
fn panic_via_drop_is_classified_panic_without_a_real_panic() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(true, Rc::clone(&observed));
        recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), 43);
    }
    let frame = observed.get().expect("Drop must emit one panic frame");
    assert_eq!(frame.phase, Phase::CorruptPublicationPreservesLatest);
    assert_eq!(frame.class, Class::Panic);
    assert_eq!(frame.line, 43);
}

#[test]
fn all_success_is_silent() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(false, Rc::clone(&observed));
        recorder.mark(Phase::HistoryStrategy, file!(), 51);
        recorder.disarm();
    }
    assert!(observed.get().is_none());
}

#[test]
fn frames_are_first_wins_and_drop_emits_only_once() {
    let observed = Rc::new(Cell::new(None));
    {
        let mut recorder = Recorder::test_with(false, Rc::clone(&observed));
        recorder.mark(Phase::CorruptBuild, file!(), 61);
        let _ = recorder.typed_ck(
            Phase::CorruptBuild,
            file!(),
            61,
            Err::<(), _>(CloneKitError::GitFailed("first synthetic error".into())),
        );
        let _ = recorder.typed_ck(
            Phase::CorruptBuild,
            file!(),
            62,
            Err::<(), _>(CloneKitError::BlobFailed("second synthetic error".into())),
        );
    }
    let frame = observed.get().expect("one frame must be emitted");
    assert_eq!(frame.class, Class::GitFailed);
    assert_eq!(frame.line, 61);
}

#[test]
fn compound_and_short_circuit_keeps_publish_single_and_skips_latest_when_ok() {
    let publish_calls = Cell::new(0);
    let rhs_calls = Cell::new(0);
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), line!());
    let publish = || {
        publish_calls.set(publish_calls.get() + 1);
        Ok::<(), CloneKitError>(())
    };
    let first = recorder.expected_err(Phase::CorruptPublicationPreservesLatest, file!(), 71, publish()).is_err();
    let evaluated = first && {
        rhs_calls.set(rhs_calls.get() + 1);
        true
    };
    assert!(!evaluated);
    assert_eq!(publish_calls.get(), 1);
    assert_eq!(rhs_calls.get(), 0);
    let frame = recorder.finish(false).expect("unexpected publish Ok must be classified");
    assert_eq!(frame.class, Class::Assert);
}

#[test]
fn compound_and_short_circuit_runs_latest_once_after_expected_err() {
    let publish_calls = Cell::new(0);
    let rhs_calls = Cell::new(0);
    let mut recorder = Recorder::new(file!(), line!());
    recorder.mark(Phase::CorruptPublicationPreservesLatest, file!(), line!());
    let publish = || {
        publish_calls.set(publish_calls.get() + 1);
        Err::<(), _>(CloneKitError::CorruptArtifact("expected synthetic error".into()))
    };
    let first = recorder.expected_err(Phase::CorruptPublicationPreservesLatest, file!(), 81, publish()).is_err();
    let evaluated = first && {
        rhs_calls.set(rhs_calls.get() + 1);
        true
    };
    assert!(evaluated);
    assert_eq!(publish_calls.get(), 1);
    assert_eq!(rhs_calls.get(), 1);
    assert!(recorder.recorded().is_none());
    recorder.disarm();
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
    first.mark(Phase::EmptyBuildOrStatus, file!(), 91);
    second.mark(Phase::HistoryGrant, file!(), 92);
    let first_frame = first.finish(false).expect("assert phase must emit");
    let second_frame = second.finish(false).expect("non-assert phase must emit");
    assert_eq!(first_frame.phase, Phase::EmptyBuildOrStatus);
    assert_eq!(first_frame.class, Class::Assert);
    assert_eq!(second_frame.phase, Phase::HistoryGrant);
    assert_eq!(second_frame.class, Class::Other);
}
