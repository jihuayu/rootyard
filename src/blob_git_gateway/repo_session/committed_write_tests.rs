//! Synthetic committed-write proof fixtures: no PostgreSQL, no IO. Real core
//! gates and repository rows are assembled in memory from fixed ids.
use super::{
    SessionRealm, SessionTokenError, SessionTokens, VersionComparison, codec, header, key, presented_for_test,
};
use crate::{
    blob_git_gateway::repo_session::{CommittedWriteSessionProof, codec::Presented},
    db::Repository,
    ref_store::{
        CommitRejectCode, CoreGate, GitObjectFormat, RefCommitResult, RefName,
        core::pack_commit::{PackCommitTerminal, PackMode},
        serving::ServingRepository,
    },
};
use uuid::Uuid;

fn id(n: u8) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[15] = n;
    Uuid::from_bytes(bytes)
}

/// `revision` is the live gate; ids and cluster incarnation are fixed per
/// `realm` selector, and the row/gate repository id may be overridden.
fn serving(realm: u8, revision: i64, cluster: u8, gate_repository: u8, row_repository: u8) -> ServingRepository {
    let gate = CoreGate::new(
        id(gate_repository),
        id(11 + realm),
        GitObjectFormat::Sha1,
        id(13 + realm),
        1 + i64::from(realm),
        1 + i64::from(realm),
        RefName::new("refs/heads/main").expect("ref"),
        revision,
    )
    .expect("gate");
    ServingRepository {
        repository: Repository {
            id: id(row_repository),
            name: "demo".into(),
            owner: "alice".into(),
            state: "ready".into(),
            clone_path: "/git/alice/demo.git".into(),
            storage_backend: "pg_refstore".into(),
            storage_generation: 1,
            object_format: "sha1".into(),
        },
        gate,
        cluster_incarnation: id(cluster),
    }
}

fn committed(repository: u8, revision: i64) -> PackCommitTerminal {
    PackCommitTerminal::committed(
        id(repository),
        revision,
        "refs/heads/main".into(),
        PackMode::MetadataOnly,
        vec![RefCommitResult::Applied { name: "refs/heads/main".into(), old_oid: None, new_oid: Some("a".repeat(40)) }],
        Vec::new(),
    )
}

fn rejected(repository: u8, revision: i64) -> PackCommitTerminal {
    PackCommitTerminal::rejected(
        id(repository),
        revision,
        Some("refs/heads/main".into()),
        PackMode::MetadataOnly,
        vec![RefCommitResult::NotApplied { name: "refs/heads/main".into(), reason: CommitRejectCode::OldOidMismatch }],
        crate::ref_store::core::pack_commit::PackCommitRejection::new(
            crate::ref_store::core::pack_commit::PackCommitRejectCode::ClosureMismatch,
            "closure",
        ),
    )
}

fn admit(
    terminal: &PackCommitTerminal,
    first: &ServingRepository,
    last: &ServingRepository,
) -> Result<CommittedWriteSessionProof, SessionTokenError> {
    CommittedWriteSessionProof::new(terminal, first, last)
}

/// The exact durable terminal revision is signed and survives the exact/later
/// live-revision cases unchanged.
#[test]
fn committed_terminals_are_admitted_at_their_exact_revision() {
    let tokens = SessionTokens::new(codec(&[(0, key(3))], 0));
    let first = serving(0, 4, 40, 20, 20);
    let terminal = committed(20, 5);
    // The final lookup must be exactly at the terminal's gate revision: a
    // final gate behind it cannot admit the terminal, even though the
    // initial (authorizing) lookup at revision 4 is fine.
    assert_eq!(admit(&terminal, &first, &first).err(), Some(SessionTokenError::Invalid));
    let exact = serving(0, 5, 40, 20, 20);
    let proof = admit(&terminal, &first, &exact).expect("exact");
    assert_eq!(proof.revision, 5);
    let issued = tokens.issue_from_committed_write(&proof).expect("issue");
    assert_eq!(issued.revision(), 5);
    let live = SessionRealm::from_serving(&exact, exact.cluster_incarnation).expect("realm");
    let presented = header(issued.token());
    let presented: Presented<'_> = presented_for_test(&presented).expect("presented");
    assert_eq!(tokens.verify(&presented, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));

    // A concurrent higher revision in the same realm is acceptable, but the
    // bound stays the durable terminal revision, never the live one.
    let later = serving(0, 9, 40, 20, 20);
    let proof = admit(&terminal, &first, &later).expect("later");
    assert_eq!(proof.revision, 5);
    let issued = tokens.issue_from_committed_write(&proof).expect("issue");
    assert_eq!(issued.revision(), 5);
    let presented = header(issued.token());
    let presented: Presented<'_> = presented_for_test(&presented).expect("presented");
    let live = SessionRealm::from_serving(&later, later.cluster_incarnation).expect("realm");
    assert_eq!(tokens.verify(&presented, &live, 9), Ok(Some(VersionComparison::Satisfied { bound: 5 })));
}

#[test]
fn noncommitted_terminals_are_never_admitted() {
    let first = serving(0, 4, 40, 20, 20);
    let terminal = rejected(20, 5);
    assert!(!terminal.is_committed());
    assert_eq!(admit(&terminal, &first, &first).err(), Some(SessionTokenError::Invalid));
}

#[test]
fn the_terminal_repository_must_match_both_lookups() {
    let first = serving(0, 4, 40, 20, 20);
    let terminal = committed(20, 5);
    // Every final lookup is at or beyond the terminal revision 5, so the
    // admission fails on repository identity, not on the revision fence.
    let last = serving(0, 9, 40, 20, 20);
    // Terminal names another repository than either lookup.
    assert_eq!(admit(&committed(21, 5), &first, &last).err(), Some(SessionTokenError::Realm));
    // A first lookup whose row names another repository.
    assert_eq!(admit(&terminal, &serving(0, 4, 40, 20, 22), &last).err(), Some(SessionTokenError::Realm));
    // A first lookup whose gate names another repository.
    assert_eq!(admit(&terminal, &serving(0, 4, 40, 22, 20), &last).err(), Some(SessionTokenError::Realm));
    // A final lookup whose row names another repository.
    assert_eq!(admit(&terminal, &first, &serving(0, 9, 40, 20, 22)).err(), Some(SessionTokenError::Realm));
    // A final lookup whose gate names another repository.
    assert_eq!(admit(&terminal, &first, &serving(0, 9, 40, 22, 20)).err(), Some(SessionTokenError::Realm));
}

#[test]
fn any_realm_divergence_between_the_two_lookups_is_refused() {
    let first = serving(0, 4, 40, 20, 20);
    let terminal = committed(20, 5);
    // A restore between authorization and the final lookup rotates the
    // cluster authority incarnation even though the RefStore realm is the
    // same; the old terminal must not be relabeled into the new incarnation.
    assert_eq!(admit(&terminal, &first, &serving(0, 9, 41, 20, 20)).err(), Some(SessionTokenError::Realm));
    // Tenant/history/epochs divergence: same ids, another realm selector.
    assert_eq!(admit(&terminal, &first, &serving(1, 9, 40, 20, 20)).err(), Some(SessionTokenError::Realm));
    // A nil cluster incarnation never forms a realm.
    assert_eq!(admit(&terminal, &first, &serving(0, 9, 0, 20, 20)).err(), Some(SessionTokenError::Invalid));
}

#[test]
fn revision_bounds_are_enforced() {
    let first = serving(0, 4, 40, 20, 20);
    let last = serving(0, 9, 40, 20, 20);
    assert_eq!(admit(&committed(20, 0), &first, &last).err(), Some(SessionTokenError::Invalid));
    assert_eq!(admit(&committed(20, -1), &first, &last).err(), Some(SessionTokenError::Invalid));
    // Ahead of the final authoritative gate: never sign a future bound.
    assert_eq!(admit(&committed(20, 10), &first, &last).err(), Some(SessionTokenError::Invalid));
    assert_eq!(admit(&committed(20, 9), &first, &last).expect("bound").revision, 9);
}
