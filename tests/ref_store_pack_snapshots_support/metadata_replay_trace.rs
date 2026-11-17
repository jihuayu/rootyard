//! Test-only bounded diagnostic frames for
//! `serving_metadata_create_replays_after_ref_advance_and_old_a5a_rejects_it`.
//!
//! These frames are authored diagnostics, not proofs of an actual failure
//! cause. They are written directly to stderr so libtest capture does not hide
//! the last reached boundary. The fixed field vocabulary is deliberately
//! numeric/boolean only; no error text, SQL, DSN, argv or provider value is
//! ever formatted.
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use std::fmt::Write as _;
use std::io::Write as _;

pub const PREFIX: &str = "ROOTYARD_I107_METADATA_REPLAY_V1";
const MAX_LINE_BYTES: usize = 512;
const MAX_COUNTS: i64 = 1_000_000_000;
const MAX_ITERATION: usize = 100_000;
const MAX_CHECKS: usize = 8;

/// Fixed outer phases from the source-only persistent triage map.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Phase {
    Setup = 1,
    TenantCreate = 2,
    OldA5a = 3,
    FirstAdvance = 4,
    TenantReplay = 5,
    ChangedLease = 6,
    Collaborator = 7,
    CrossModeTenant = 8,
    CrossModeActor = 9,
    OwnedACreateRead = 10,
    OwnedARenew = 11,
    OwnedARelease = 12,
    OwnedBCreate = 13,
    SecondAdvanceReplay = 14,
    OwnedBRead = 15,
    OwnedBMaterialize = 16,
    HistoricalContent = 17,
    NonownerRead = 18,
    TenantReadRefusal = 19,
    NonownerMaterialize = 20,
    TenantMaterializeRefusal = 21,
    RoleRevokeRead = 22,
    RoleRevokeMaterialize = 23,
    Finish = 24,
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum Event {
    Enter = 0,
    Completed = 1,
    FailedPredicate = 2,
}

/// Closed source-owned error classes. Raw error text, paths, object ids and
/// provider payloads are never formatted into a frame.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum ErrorKind {
    Io = 1,
    RefStoreTimeout = 2,
    RefStoreUnsupported = 3,
    StorageDatabase = 4,
    RefStoreOther = 5,
    GitProcess = 6,
    Other = 7,
    BlobProvider = 8,
}

// Site identifiers are the per-phase ordinals from the same fixed map.

// Phase 1: setup.
pub const S1_DB_SETUP: u8 = 1;
pub const S1_OPEN_STORE: u8 = 2;
pub const S1_GIT_BINARY: u8 = 3;
pub const S1_SERVING_BUSINESS: u8 = 4;
pub const S1_SERVING_VERIFIED: u8 = 5;

// Phase 2: tenant_create.
pub const S2_CREATE: u8 = 1;
pub const S2_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S2_TENANT_ASSERT: u8 = 3;
pub const S2_COUNTS_READ: u8 = 4;

// Phase 3: old_a5a.
pub const S3_SCOPE_CONSTRUCT: u8 = 1;
pub const S3_EXPECTATION_CONSTRUCT: u8 = 2;
pub const S3_REQUEST_CONSTRUCT: u8 = 3;
pub const S3_POOL_ACQUIRE: u8 = 4;
pub const S3_CREATE_RESULT: u8 = 5;
pub const S3_REFUSED_ASSERT: u8 = 6;
pub const S3_COUNTS_READ: u8 = 7;
pub const S3_UNCHANGED_ASSERT: u8 = 8;

// Phase 4: first_advance.
pub const S4_SERVING_ADVANCE: u8 = 1;
pub const S4_GATE_READ: u8 = 2;
pub const S4_REVISION_ADVANCED_ASSERT: u8 = 3;

// Phase 5: tenant_replay.
pub const S5_CREATE: u8 = 1;
pub const S5_REPLAYED_ASSERT: u8 = 2;
pub const S5_SNAPSHOT_ID_ASSERT: u8 = 3;
pub const S5_PIN_ID_ASSERT: u8 = 4;
pub const S5_GATE_ASSERT: u8 = 5;
pub const S5_COUNTS_READ: u8 = 6;
pub const S5_UNCHANGED_ASSERT: u8 = 7;

// Phase 6: changed_lease.
pub const S6_CREATE_RESULT: u8 = 1;
pub const S6_REFUSED_ASSERT: u8 = 2;
pub const S6_COUNTS_READ: u8 = 3;
pub const S6_UNCHANGED_ASSERT: u8 = 4;

// Phase 7: collaborator.
pub const S7_CREATE_AUTHENTICATE_COLLABORATOR: u8 = 1;
pub const S7_DISTINCT_PRINCIPAL_ASSERT: u8 = 2;

// Phase 8: cross_mode_tenant.
pub const S8_CREATE: u8 = 1;
pub const S8_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S8_OWNER_ASSERT: u8 = 3;
pub const S8_COUNTS_READ: u8 = 4;

// Phase 9: cross_mode_actor.
pub const S9_CREATE_RESULT: u8 = 1;
pub const S9_EXACT_CONFLICT_MATCH: u8 = 2;
pub const S9_COUNTS_READ: u8 = 3;
pub const S9_UNCHANGED_ASSERT: u8 = 4;

// Phase 10: owned_a_create_read.
pub const S10_CREATE: u8 = 1;
pub const S10_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S10_OWNER_TENANT_ASSERT: u8 = 3;
pub const S10_READ: u8 = 4;
pub const S10_IMMUTABLE_CAPTURE_ASSERT: u8 = 5;

// Phase 11: owned_a_renew.
pub const S11_RENEW: u8 = 1;
pub const S11_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S11_GENERATION_TWO_ASSERT: u8 = 3;
pub const S11_RENEW_REPLAY: u8 = 4;
pub const S11_REPLAYED_ASSERT: u8 = 5;

// Phase 12: owned_a_release.
pub const S12_RELEASE: u8 = 1;
pub const S12_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S12_RELEASE_REPLAY: u8 = 3;
pub const S12_REPLAYED_ASSERT: u8 = 4;
pub const S12_RELEASED_READ_RESULT: u8 = 5;
pub const S12_REFUSED_ASSERT: u8 = 6;

// Phase 13: owned_b_create.
pub const S13_CREATE: u8 = 1;
pub const S13_NOT_REPLAYED_ASSERT: u8 = 2;
pub const S13_OWNER_TENANT_ASSERT: u8 = 3;
pub const S13_COUNTS_READ: u8 = 4;

// Phase 14: second_advance_replay.
pub const S14_SERVING_ADVANCE: u8 = 1;
pub const S14_CREATE_REPLAY: u8 = 2;
pub const S14_REPLAYED_ASSERT: u8 = 3;
pub const S14_SNAPSHOT_PIN_GATE_ASSERT: u8 = 4;
pub const S14_COUNTS_READ: u8 = 5;
pub const S14_UNCHANGED_ASSERT: u8 = 6;

// Phase 15: owned_b_read.
pub const S15_READ: u8 = 1;
pub const S15_IMMUTABLE_CAPTURE_ASSERT: u8 = 2;
pub const S15_NONEMPTY_PACKS_ASSERT: u8 = 3;
pub const S15_HEAD_OPTION: u8 = 4;
pub const S15_FIRST_ADVANCE_HEAD_ASSERT: u8 = 5;
pub const S15_DIFFERENT_SECOND_HEAD_ASSERT: u8 = 6;

// Phase 16: owned_b_materialize.
pub const S16_MATERIALIZER_CONSTRUCT: u8 = 1;
pub const S16_MATERIALIZE: u8 = 2;
pub const S16_VIEW_SHAPE_ASSERT: u8 = 3;
pub const S16_EACH_PACK_IDENTITY_ASSERT: u8 = 4;

// Phase 17: historical_content.
pub const S17_READ_MATERIALIZED_FILE: u8 = 1;
pub const S17_EXACT_FIRST_ADVANCE_CONTENT_ASSERT: u8 = 2;
pub const S17_GIT_REPO_NEW: u8 = 3;
pub const S17_PACK_DIR_CREATE: u8 = 4;
pub const S17_EXACT_PACK_BYTES: u8 = 5;
pub const S17_EXACT_IDX_BYTES: u8 = 6;
pub const S17_WRITE_PACK: u8 = 7;
pub const S17_WRITE_IDX: u8 = 8;
pub const S17_CAT_FILE: u8 = 9;

// Phase 18: nonowner_read.
pub const S18_LEDGER_BASELINE: u8 = 1;
pub const S18_READ_RESULT: u8 = 2;
pub const S18_EXACT_NOT_FOUND_MATCH: u8 = 3;
pub const S18_LEDGER_READ: u8 = 4;
pub const S18_UNCHANGED_ASSERT: u8 = 5;

// Phase 19: tenant_read_refusal.
pub const S19_READ_RESULT: u8 = 1;
pub const S19_REFUSED_ASSERT: u8 = 2;
pub const S19_LEDGER_READ: u8 = 3;
pub const S19_UNCHANGED_ASSERT: u8 = 4;

// Phase 20: nonowner_materialize.
pub const S20_MATERIALIZE_RESULT: u8 = 1;
pub const S20_EXACT_NOT_FOUND_MATCH: u8 = 2;
pub const S20_LEDGER_READ: u8 = 3;
pub const S20_UNCHANGED_ASSERT: u8 = 4;

// Phase 21: tenant_materialize_refusal.
pub const S21_MATERIALIZE_RESULT: u8 = 1;
pub const S21_REFUSED_ASSERT: u8 = 2;
pub const S21_LEDGER_READ: u8 = 3;
pub const S21_UNCHANGED_ASSERT: u8 = 4;

// Phase 22: role_revoke_read.
pub const S22_SET_ROLE: u8 = 1;
pub const S22_READ_RESULT: u8 = 2;
pub const S22_EXACT_COMMON_FORBIDDEN_ASSERT: u8 = 3;
pub const S22_LEDGER_READ: u8 = 4;
pub const S22_UNCHANGED_ASSERT: u8 = 5;

// Phase 23: role_revoke_materialize.
pub const S23_MATERIALIZE_RESULT: u8 = 1;
pub const S23_EXACT_COMMON_FORBIDDEN_ASSERT: u8 = 2;
pub const S23_LEDGER_READ: u8 = 3;
pub const S23_UNCHANGED_ASSERT: u8 = 4;

// Phase 24: finish.
pub const S24_FINISH_AND_TEARDOWN: u8 = 1;

pub fn enter(phase: Phase, site: u8) {
    emit(phase, site, Event::Enter, None, None, None, None, None, None);
}

pub fn enter_loop(phase: Phase, site: u8, iteration: usize) {
    emit(phase, site, Event::Enter, None, None, None, None, Some(iteration), None);
}

pub fn completed(phase: Phase, site: u8) {
    emit(phase, site, Event::Completed, Some(true), None, None, None, None, None);
}

/// A fallible propagating call returned an error. This is an operation result,
/// not a verified failure cause; the original error still propagates unchanged.
pub fn failed_operation(phase: Phase, site: u8) {
    emit(phase, site, Event::Completed, Some(false), None, None, None, None, None);
}

pub fn failed_error(phase: Phase, site: u8, error_kind: ErrorKind) {
    emit(phase, site, Event::Completed, Some(false), None, None, None, None, Some(error_kind));
}

pub fn failed_error_loop(phase: Phase, site: u8, iteration: usize, error_kind: ErrorKind) {
    emit(phase, site, Event::Completed, Some(false), None, None, None, Some(iteration), Some(error_kind));
}

pub fn completed_status(phase: Phase, site: u8, status: u16) {
    emit(phase, site, Event::Completed, Some(true), Some(status), None, None, None, None);
}

pub fn completed_counts(phase: Phase, site: u8, counts: (i64, i64, i64, i64, i64)) {
    emit(phase, site, Event::Completed, Some(true), None, Some(counts), None, None, None);
}

pub fn completed_loop(phase: Phase, site: u8, iteration: usize) {
    emit(phase, site, Event::Completed, Some(true), None, None, None, Some(iteration), None);
}

pub fn predicate(phase: Phase, site: u8, ok: bool) {
    emit(phase, site, Event::Enter, None, None, None, None, None, None);
    emit(
        phase,
        site,
        if ok { Event::Completed } else { Event::FailedPredicate },
        Some(ok),
        None,
        None,
        None,
        None,
        None,
    );
}

pub fn predicate_status(phase: Phase, site: u8, ok: bool, status: u16) {
    emit(phase, site, Event::Enter, None, None, None, None, None, None);
    emit(
        phase,
        site,
        if ok { Event::Completed } else { Event::FailedPredicate },
        Some(ok),
        Some(status),
        None,
        None,
        None,
        None,
    );
}

pub fn predicate_checks(phase: Phase, site: u8, ok: bool, checks: &[bool]) {
    emit(phase, site, Event::Enter, None, None, None, None, None, None);
    emit(
        phase,
        site,
        if ok { Event::Completed } else { Event::FailedPredicate },
        Some(ok),
        None,
        None,
        Some(checks),
        None,
        None,
    );
}

fn emit(
    phase: Phase,
    site: u8,
    event: Event,
    ok: Option<bool>,
    status: Option<u16>,
    counts: Option<(i64, i64, i64, i64, i64)>,
    checks: Option<&[bool]>,
    iteration: Option<usize>,
    error_kind: Option<ErrorKind>,
) {
    let mut line = String::with_capacity(192);
    let _ = write!(&mut line, "{}|{}|{}|{}|", PREFIX, phase as u8, site, event as u8);
    if let Some(ok) = ok {
        line.push(if ok { '1' } else { '0' });
    }
    line.push('|');
    if let Some(status) = status
        && (100..=599).contains(&status)
    {
        let _ = write!(&mut line, "{status}");
    }
    line.push('|');
    if let Some((a, b, c, d, e)) = counts {
        let _ = write!(
            &mut line,
            "{},{},{},{},{}",
            a.clamp(0, MAX_COUNTS),
            b.clamp(0, MAX_COUNTS),
            c.clamp(0, MAX_COUNTS),
            d.clamp(0, MAX_COUNTS),
            e.clamp(0, MAX_COUNTS)
        );
    }
    line.push('|');
    if let Some(checks) = checks {
        for (index, check) in checks.iter().take(MAX_CHECKS).enumerate() {
            if index > 0 {
                line.push(',');
            }
            line.push(if *check { '1' } else { '0' });
        }
    }
    line.push('|');
    if let Some(iteration) = iteration {
        let _ = write!(&mut line, "{}", iteration.min(MAX_ITERATION));
    }
    line.push('|');
    if let Some(error_kind) = error_kind {
        let _ = write!(&mut line, "{}", error_kind as u8);
    }
    line.push('\n');
    if line.len() <= MAX_LINE_BYTES {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let _ = handle.write_all(line.as_bytes());
        let _ = handle.flush();
    }
}
