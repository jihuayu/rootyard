//! Deterministic original-order accepted-subset selection for the **trusted
//! in-process metadata-only** core commit path.
//!
//! `PgRefStoreCore::commit_refs` is the existing legacy metadata API: it takes
//! an already-authenticated, in-process [`CommitRefsRequest`] and has **no
//! actor parameter** and **no native facts/proof**. This module therefore does
//! exactly the work that API is allowed to do over the **actual locked old ref
//! map** of the real request:
//!
//! - per-ref exact old/new CAS (one bad ref never hides a good one),
//! - per-ref prefix/namespace semantics evaluated in the caller's **original
//!   ref order** over a simulated live map,
//! - the unchanged old core HEAD policy (a `Keep` batch may not delete the HEAD
//!   target), and whole-operation refusal of a retarget whose final target is
//!   absent,
//! - every planned ref's deterministic verdict persisted in one 138 terminal +
//!   event inside the caller's existing short transaction.
//!
//! It never fabricates a `PackCommitPlan`, native facts, a closure proof or a
//! decision grant, and it performs no Git/blob/byte IO. The decision-required
//! protocol fence and the `pack_verified` fence are enforced by
//! `core::pg::PgRefStoreCore::commit_refs_checked` **before** this module is
//! reached and after exact historical terminal replay, so this metadata path
//! can never bypass verified bytes. Policies that need unavailable native facts
//! (FF ancestry, changed paths, LFS object bytes) are simply not part of this
//! trusted metadata scope; the authorized decision path consumes a concrete
//! `publication_decision` selector instead (see
//! `docs/ref-store-roots-decisions.md`).

use super::super::contract::{RefStoreError, TerminalOutcome};
use super::super::pg::{self, PgRefStore};
use super::command::CommitRefsRequest;
use super::contract::CoreGate;
use super::sql::insert_event;
use super::terminal::{
    CommitRefsReceipt, CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult, ensure_exact_terminal_budget,
};
use super::types::{HeadUpdate, RefPrecondition, RefTarget, is_strict_prefix};
use std::collections::BTreeMap;
use tokio::time::Instant;
use tokio_postgres::Transaction;

/// Deterministic outcome of the in-memory original-order selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MetadataSelection {
    /// At least one planned ref survives. `results` keeps the **original**
    /// request order and covers every planned ref (applied or rejected);
    /// `accepted` is the original-order index list of refs to write.
    Commit { results: Vec<RefCommitResult>, accepted: Vec<usize>, head: String },
    /// The whole operation is rejected with all refs `NotApplied`: an absent
    /// retarget target (`HeadTargetMissing`) or an all-rejected subset
    /// (`NoRefApplied`). No ref, HEAD or revision write may follow.
    Reject { results: Vec<RefCommitResult>, rejection: CommitRejection },
}

fn not_applied(name: &str, reason: CommitRejectCode) -> RefCommitResult {
    RefCommitResult::NotApplied { name: name.to_owned(), reason }
}

/// Run the deterministic accepted-subset selection.
///
/// Semantics, frozen against the actual stock Git differential note:
///
/// 1. exact CAS against the *simulated live map* (which starts from the real
///    locked old ref map); a mismatch rejects only that ref;
/// 2. deleting the current HEAD with `HeadUpdate::Keep` rejects only that ref
///    (the stricter old core policy, retained);
/// 3. `Delete` of a ref whose simulated map still has strict descendants is a
///    per-ref `prefix_conflict`; `Oid` creation under or above another live
///    name is a per-ref `prefix_conflict`. Because the map is mutated in
///    original order, `delete a` then `create a/b` accepts both while
///    `create a/b` before `delete a` rejects the child and may accept the later
///    delete, matching normal non-atomic stock Git push;
/// 4. a `Retarget` whose final target is absent fails the whole operation
///    before any write; a valid retarget (existing or newly accepted branch)
///    commits with that HEAD.
///
/// `policy_rejects` is the trusted publication-decision projection for the
/// authorized path: a ref listed there is `NotApplied` with that code and is
/// **removed from the namespace simulation**, so a policy-rejected creation
/// cannot occupy a name for a later ref. It can only ever reject; it can never
/// turn a deterministic CAS/prefix/HEAD rejection into an acceptance. The
/// legacy trusted metadata path passes an empty map. This function is pure: it
/// performs no IO and grants nothing.
pub(crate) fn select(
    request: &CommitRefsRequest,
    current_head: &str,
    existing: &BTreeMap<String, String>,
    policy_rejects: &BTreeMap<String, CommitRejectCode>,
) -> MetadataSelection {
    let mut map = existing.clone();
    let mut results = Vec::with_capacity(request.refs().len());
    let mut accepted = Vec::new();
    for (index, update) in request.refs().iter().enumerate() {
        let name = update.name().as_str().to_owned();
        if let Some(code) = policy_rejects.get(&name) {
            results.push(not_applied(&name, *code));
            continue;
        }
        let current = map.get(&name).cloned();
        let expected = update.precondition().oid().map(|oid| oid.as_hex());
        let cas_ok = match update.precondition() {
            RefPrecondition::Absent => current.is_none(),
            RefPrecondition::Present(_) => match (&current, &expected) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            },
        };
        // A delete precondition must describe an existing value; deleting a
        // never-existing ref is not an exact old/new mutation of this core.
        let delete_without_old = matches!(update.target(), RefTarget::Delete) && expected.is_none();
        if !cas_ok || delete_without_old {
            results.push(not_applied(&name, CommitRejectCode::OldOidMismatch));
            continue;
        }
        if matches!(update.target(), RefTarget::Delete)
            && name.as_str() == current_head
            && matches!(request.head(), HeadUpdate::Keep)
        {
            results.push(not_applied(&name, CommitRejectCode::HeadDeletedWithoutRetarget));
            continue;
        }
        match update.target() {
            RefTarget::Delete => {
                let has_descendant =
                    map.keys().any(|other| other.as_str() != name.as_str() && is_strict_prefix(&name, other));
                if has_descendant {
                    results.push(not_applied(&name, CommitRejectCode::PrefixConflict));
                    continue;
                }
                let _ = map.remove(&name);
            }
            RefTarget::Oid(oid) => {
                let conflict = map.keys().any(|other| {
                    other.as_str() != name.as_str()
                        && (is_strict_prefix(&name, other) || is_strict_prefix(other, &name))
                });
                if conflict {
                    results.push(not_applied(&name, CommitRejectCode::PrefixConflict));
                    continue;
                }
                map.insert(name.clone(), oid.as_hex());
            }
        }
        accepted.push(index);
        results.push(RefCommitResult::Applied {
            name,
            old_oid: current,
            new_oid: update.target().oid().map(|oid| oid.as_hex()),
        });
    }

    let head = match request.head() {
        HeadUpdate::Keep => current_head.to_owned(),
        HeadUpdate::Retarget(target) => {
            if !map.contains_key(target.as_str()) {
                // Whole-operation failure before any write: a retarget may not
                // leave HEAD pointing at an absent ref, so no ref is applied.
                let results = request
                    .refs()
                    .iter()
                    .map(|update| not_applied(update.name().as_str(), CommitRejectCode::HeadTargetMissing))
                    .collect();
                return MetadataSelection::Reject {
                    results,
                    rejection: CommitRejection {
                        code: CommitRejectCode::HeadTargetMissing,
                        ref_name: Some(target.as_str().to_owned()),
                        expected: None,
                        actual: None,
                    },
                };
            }
            target.as_str().to_owned()
        }
    };
    if accepted.is_empty() {
        return MetadataSelection::Reject {
            results,
            rejection: CommitRejection {
                code: CommitRejectCode::NoRefApplied,
                ref_name: None,
                expected: None,
                actual: None,
            },
        };
    }
    MetadataSelection::Commit { results, accepted, head }
}

/// Apply an accepted-subset selection inside the caller's short transaction.
///
/// The caller (`core::pg::PgRefStoreCore::commit_refs_checked`) has already
/// replayed any historical terminal, validated the repository/gate/protocol
/// fences and locked the relevant refs. This function then persists either:
///
/// - one durable **rejected** terminal + event with every planned verdict and
///   no ref/HEAD/revision change, or
/// - the accepted refs in original order, the gate revision+HEAD, and one
///   durable **committed** terminal + event carrying *all* per-ref verdicts.
pub(super) async fn commit_accepted_subset(
    tx: &Transaction<'_>,
    request: &CommitRefsRequest,
    gate: &CoreGate,
    existing: &BTreeMap<String, String>,
    deadline: Instant,
) -> Result<CommitRefsReceipt, RefStoreError> {
    let selection = select(request, gate.head_ref().as_str(), existing, &BTreeMap::new());
    commit_selection(tx, request, gate, selection, deadline).await
}

pub(super) async fn commit_selection(
    tx: &Transaction<'_>,
    request: &CommitRefsRequest,
    gate: &CoreGate,
    selection: MetadataSelection,
    deadline: Instant,
) -> Result<CommitRefsReceipt, RefStoreError> {
    let revision = gate.revision();
    match selection {
        MetadataSelection::Reject { results, rejection } => {
            let terminal = CommitTerminal::rejected(
                request.repository_id(),
                revision,
                Some(gate.head_ref().as_str().to_owned()),
                results,
                rejection,
            );
            // Exact pre-write 64 KiB check of the real body (the pre-registry
            // worst case already covers this shape) before the 138 row.
            ensure_exact_terminal_budget(&terminal)?;
            let result = terminal.to_terminal_result()?;
            let receipt = PgRefStore
                .record_terminal(tx, request.identity(), TerminalOutcome::Rejected, &result, deadline)
                .await?;
            let operation_id = receipt.record.identity().operation_id();
            insert_event(tx, request.repository_id(), revision, operation_id, "rejected", &result).await?;
            Ok(CommitRefsReceipt { replayed: receipt.replayed, record: receipt.record, terminal })
        }
        MetadataSelection::Commit { results, accepted, head } => {
            let new_revision =
                revision.checked_add(1).ok_or_else(|| RefStoreError::InvalidIdentity("revision exhausted".into()))?;
            let terminal = CommitTerminal::committed(request.repository_id(), new_revision, head.clone(), results);
            ensure_exact_terminal_budget(&terminal)?;
            let result = terminal.to_terminal_result()?;

            for index in accepted {
                let update = &request.refs()[index];
                let name = update.name().as_str();
                match update.target() {
                    RefTarget::Delete => {
                        let changed = tx
                            .execute(
                                "DELETE FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2",
                                &[&request.repository_id(), &name],
                            )
                            .await
                            .map_err(pg::db_error)?;
                        if changed != 1 {
                            return Err(RefStoreError::Database(
                                "locked accepted-subset ref disappeared during delete".into(),
                            ));
                        }
                    }
                    RefTarget::Oid(oid) => {
                        tx.execute(
                            "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision)
                             VALUES($1,$2,$3,$4)
                             ON CONFLICT(repository_id,ref_name) DO UPDATE
                             SET oid=EXCLUDED.oid,revision=EXCLUDED.revision,updated_at=clock_timestamp()",
                            &[&request.repository_id(), &name, &oid.as_hex(), &new_revision],
                        )
                        .await
                        .map_err(pg::db_error)?;
                    }
                }
            }
            let updated = tx
                .query_opt(
                    "UPDATE ref_store_core_gates
                     SET revision=$2,head_ref=$3,updated_at=clock_timestamp()
                     WHERE repository_id=$1 AND revision=$4
                     RETURNING revision",
                    &[&request.repository_id(), &new_revision, &head, &revision],
                )
                .await
                .map_err(pg::db_error)?;
            if updated.is_none() {
                return Err(RefStoreError::Database("gate revision changed while its row was locked".into()));
            }
            let receipt = PgRefStore
                .record_terminal(tx, request.identity(), TerminalOutcome::Committed, &result, deadline)
                .await?;
            let operation_id = receipt.record.identity().operation_id();
            insert_event(tx, request.repository_id(), new_revision, operation_id, "committed", &result).await?;
            Ok(CommitRefsReceipt { replayed: receipt.replayed, record: receipt.record, terminal })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::contract::CommitMode;
    use super::super::types::{GitObjectFormat, GitOid, RefName, RefUpdate};
    use super::*;
    use crate::ref_store::IssuerLane;
    use uuid::Uuid;

    fn oid(byte: u8) -> GitOid {
        GitOid::Sha1([byte; 20])
    }

    fn update(name: &str, old: Option<u8>, new: Option<u8>) -> RefUpdate {
        let precondition = match old {
            Some(byte) => RefPrecondition::Present(oid(byte)),
            None => RefPrecondition::Absent,
        };
        let target = match new {
            Some(byte) => RefTarget::Oid(oid(byte)),
            None => RefTarget::Delete,
        };
        RefUpdate::new(RefName::new(name).unwrap(), precondition, target)
    }

    fn request(refs: Vec<RefUpdate>, head: HeadUpdate) -> CommitRefsRequest {
        CommitRefsRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            IssuerLane::new("lane").unwrap(),
            1,
            Uuid::new_v4(),
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            3,
            4,
            2,
            head,
            CommitMode::AcceptedSubset,
            refs,
        )
        .unwrap()
    }

    fn old(pairs: &[(&str, u8)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(name, byte)| ((*name).to_owned(), oid(*byte).as_hex())).collect()
    }

    #[test]
    fn one_bad_cas_does_not_hide_a_valid_ref() {
        let request = request(
            vec![update("refs/heads/bad", Some(9), Some(1)), update("refs/heads/good", Some(2), Some(3))],
            HeadUpdate::Keep,
        );
        let selection = select(
            &request,
            "refs/heads/main",
            &old(&[("refs/heads/bad", 8), ("refs/heads/good", 2)]),
            &BTreeMap::new(),
        );
        let MetadataSelection::Commit { results, accepted, head } = selection else {
            panic!("expected a partial commit");
        };
        assert_eq!(head, "refs/heads/main");
        assert_eq!(accepted, vec![1]);
        assert_eq!(
            results,
            vec![
                RefCommitResult::NotApplied { name: "refs/heads/bad".into(), reason: CommitRejectCode::OldOidMismatch },
                RefCommitResult::Applied {
                    name: "refs/heads/good".into(),
                    old_oid: Some(oid(2).as_hex()),
                    new_oid: Some(oid(3).as_hex())
                },
            ]
        );
    }

    #[test]
    fn delete_parent_then_create_child_in_original_order_accepts_both() {
        let request = request(
            vec![update("refs/heads/a", Some(1), None), update("refs/heads/a/b", None, Some(2))],
            HeadUpdate::Keep,
        );
        let selection = select(&request, "refs/heads/main", &old(&[("refs/heads/a", 1)]), &BTreeMap::new());
        let MetadataSelection::Commit { results, accepted, .. } = selection else {
            panic!("expected both refs accepted");
        };
        assert_eq!(accepted, vec![0, 1]);
        assert!(results.iter().all(|result| matches!(result, RefCommitResult::Applied { .. })));
    }

    #[test]
    fn create_child_before_delete_parent_rejects_the_child_only() {
        let request = request(
            vec![update("refs/heads/a/b", None, Some(2)), update("refs/heads/a", Some(1), None)],
            HeadUpdate::Keep,
        );
        let selection = select(&request, "refs/heads/main", &old(&[("refs/heads/a", 1)]), &BTreeMap::new());
        let MetadataSelection::Commit { results, accepted, .. } = selection else {
            panic!("expected the later delete accepted");
        };
        assert_eq!(accepted, vec![1]);
        assert_eq!(
            results[0],
            RefCommitResult::NotApplied { name: "refs/heads/a/b".into(), reason: CommitRejectCode::PrefixConflict }
        );
    }

    #[test]
    fn unaffected_parent_prefix_still_rejects_a_new_child() {
        let request = request(vec![update("refs/heads/a/b", None, Some(2))], HeadUpdate::Keep);
        let selection = select(&request, "refs/heads/main", &old(&[("refs/heads/a", 1)]), &BTreeMap::new());
        let MetadataSelection::Reject { results, rejection } = selection else {
            panic!("expected all-rejected");
        };
        assert_eq!(rejection.code, CommitRejectCode::NoRefApplied);
        assert_eq!(
            results,
            vec![RefCommitResult::NotApplied {
                name: "refs/heads/a/b".into(),
                reason: CommitRejectCode::PrefixConflict
            }]
        );
    }

    #[test]
    fn head_deletion_is_rejected_per_ref_while_other_refs_apply() {
        let request = request(
            vec![update("refs/heads/main", Some(1), None), update("refs/heads/topic", None, Some(2))],
            HeadUpdate::Keep,
        );
        let selection = select(&request, "refs/heads/main", &old(&[("refs/heads/main", 1)]), &BTreeMap::new());
        let MetadataSelection::Commit { results, accepted, head } = selection else {
            panic!("expected a partial commit");
        };
        assert_eq!(head, "refs/heads/main");
        assert_eq!(accepted, vec![1]);
        assert_eq!(
            results[0],
            RefCommitResult::NotApplied {
                name: "refs/heads/main".into(),
                reason: CommitRejectCode::HeadDeletedWithoutRetarget
            }
        );
    }

    #[test]
    fn retarget_to_absent_target_fails_the_whole_operation() {
        // `refs/heads/next` is neither existing nor created in this batch.
        let request =
            request(vec![update("refs/heads/topic", None, Some(2))], HeadUpdate::retarget("refs/heads/next").unwrap());
        let selection = select(&request, "refs/heads/main", &BTreeMap::new(), &BTreeMap::new());
        let MetadataSelection::Reject { results, rejection } = selection else {
            panic!("expected whole rejection");
        };
        assert_eq!(rejection.code, CommitRejectCode::HeadTargetMissing);
        assert_eq!(rejection.ref_name.as_deref(), Some("refs/heads/next"));
        assert_eq!(
            results,
            vec![RefCommitResult::NotApplied {
                name: "refs/heads/topic".into(),
                reason: CommitRejectCode::HeadTargetMissing
            }]
        );
    }

    #[test]
    fn retarget_to_newly_accepted_branch_commits_with_that_head() {
        let request =
            request(vec![update("refs/heads/next", None, Some(2))], HeadUpdate::retarget("refs/heads/next").unwrap());
        let selection = select(&request, "refs/heads/main", &BTreeMap::new(), &BTreeMap::new());
        let MetadataSelection::Commit { results, accepted, head } = selection else {
            panic!("expected a commit");
        };
        assert_eq!(head, "refs/heads/next");
        assert_eq!(accepted, vec![0]);
        assert!(matches!(results[0], RefCommitResult::Applied { .. }));
    }

    #[test]
    fn all_rejected_selection_carries_no_ref_applied() {
        let request = request(vec![update("refs/heads/a", Some(7), Some(1))], HeadUpdate::Keep);
        let selection = select(&request, "refs/heads/main", &old(&[("refs/heads/a", 8)]), &BTreeMap::new());
        let MetadataSelection::Reject { rejection, .. } = selection else {
            panic!("expected all-rejected");
        };
        assert_eq!(rejection.code, CommitRejectCode::NoRefApplied);
    }

    #[test]
    fn delete_of_a_missing_ref_with_absent_precondition_is_never_applied() {
        let request = request(vec![update("refs/heads/gone", None, None)], HeadUpdate::Keep);
        let selection = select(&request, "refs/heads/main", &BTreeMap::new(), &BTreeMap::new());
        let MetadataSelection::Reject { results, .. } = selection else {
            panic!("expected rejection");
        };
        assert_eq!(
            results[0],
            RefCommitResult::NotApplied { name: "refs/heads/gone".into(), reason: CommitRejectCode::OldOidMismatch }
        );
    }

    #[test]
    fn policy_rejected_creation_does_not_occupy_the_namespace() {
        let request = request(
            vec![update("refs/heads/a", None, Some(1)), update("refs/heads/a/b", None, Some(2))],
            HeadUpdate::Keep,
        );
        let rejects = BTreeMap::from([("refs/heads/a".to_owned(), CommitRejectCode::PolicyDenied)]);
        let selection = select(&request, "refs/heads/main", &BTreeMap::new(), &rejects);
        let MetadataSelection::Commit { results, accepted, .. } = selection else {
            panic!("expected the child to be accepted");
        };
        assert_eq!(accepted, vec![1]);
        assert_eq!(
            results[0],
            RefCommitResult::NotApplied { name: "refs/heads/a".into(), reason: CommitRejectCode::PolicyDenied }
        );
        assert!(matches!(results[1], RefCommitResult::Applied { .. }));
    }
}
