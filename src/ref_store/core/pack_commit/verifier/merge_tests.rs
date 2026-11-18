use super::*;
use crate::ref_store::core::pack_commit::facts::GitObjectKind;
use crate::ref_store::core::pack_commit::{MembershipDigest, PackCommitExpectation, PackCommitScope, PackMode};
use crate::ref_store::{IssuerLane, OperationIdentity, RefUpdate};
use uuid::Uuid;

fn fixture() -> (MergeClaim, Vec<CapturedRef>) {
    let claim = MergeClaim {
        pull_number: 3,
        expected_version: 7,
        head_ref: RefName::new("refs/heads/topic").unwrap(),
        head_oid: GitOid::Sha1([2; 20]),
        base_ref: RefName::new("refs/heads/main").unwrap(),
        base_oid: GitOid::Sha1([1; 20]),
        strategy: MergeStrategy::FastForward,
    };
    let captured = vec![
        CapturedRef::new(claim.base_ref.clone(), claim.base_oid).unwrap(),
        CapturedRef::new(claim.head_ref.clone(), claim.head_oid).unwrap(),
    ];
    (claim, captured)
}

fn plan(mode: CommitMode, head: HeadUpdate, refs: Vec<RefUpdate>, operation: u8) -> PackCommitPlan {
    let repository_id = Uuid::from_bytes([1; 16]);
    let tenant_id = Uuid::from_bytes([2; 16]);
    PackCommitPlan::new_with_mode(
        PackCommitScope::new(
            repository_id,
            tenant_id,
            tenant_id,
            GitObjectFormat::Sha1,
            Uuid::from_bytes([3; 16]),
            1,
            1,
        )
        .unwrap(),
        OperationIdentity::new(
            repository_id,
            Uuid::from_bytes([4; 16]),
            IssuerLane::new("native-merge").unwrap(),
            1,
            Uuid::from_bytes([operation; 16]),
            RequestDigest::from_bytes([0; 32]),
        )
        .unwrap(),
        PackCommitExpectation::new(12, RequestDigest::from_bytes([8; 32]), PackMode::PackVerified).unwrap(),
        head,
        refs,
        MembershipDigest::of(&[]),
        Vec::new(),
        Vec::new(),
        mode,
    )
    .unwrap()
}

fn base_update(claim: &MergeClaim, target: GitOid) -> RefUpdate {
    RefUpdate::new(claim.base_ref.clone(), RefPrecondition::Present(claim.base_oid), RefTarget::Oid(target))
}

#[test]
fn merge_shape_checks_atomic_base_only_keep_head_and_no_op() {
    let (claim, captured) = fixture();
    let base = base_update(&claim, claim.head_oid);
    let valid = plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base.clone()], 1);
    assert!(claim.check(&valid, &captured).is_ok());

    let extra = RefUpdate::new(claim.head_ref.clone(), RefPrecondition::Present(claim.head_oid), RefTarget::Delete);
    let invalid_plans = [
        plan(CommitMode::AcceptedSubset, HeadUpdate::Keep, vec![base.clone()], 1),
        plan(CommitMode::Atomic, HeadUpdate::Retarget(claim.head_ref.clone()), vec![base.clone()], 1),
        plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base.clone(), extra.clone()], 1),
        plan(CommitMode::Atomic, HeadUpdate::Keep, vec![extra], 1),
        plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base_update(&claim, claim.base_oid)], 1),
        plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base_update(&claim, GitOid::Sha1([3; 20]))], 1),
    ];
    for invalid in &invalid_plans {
        assert!(claim.check(invalid, &captured).is_err());
    }
    for (old, target) in [
        (RefPrecondition::Absent, RefTarget::Oid(claim.head_oid)),
        (RefPrecondition::Present(GitOid::Sha1([3; 20])), RefTarget::Oid(claim.head_oid)),
        (RefPrecondition::Present(claim.base_oid), RefTarget::Delete),
    ] {
        let wrong_update = RefUpdate::new(claim.base_ref.clone(), old, target);
        let invalid = plan(CommitMode::Atomic, HeadUpdate::Keep, vec![wrong_update], 1);
        assert!(claim.check(&invalid, &captured).is_err());
    }
}

#[test]
fn merge_shape_requires_both_pinned_refs_and_positive_claims() {
    let (mut claim, captured) = fixture();
    let valid = plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base_update(&claim, claim.head_oid)], 1);
    for index in 0..captured.len() {
        let mut moved = captured.clone();
        let name = RefName::new(moved[index].name()).unwrap();
        moved[index] = CapturedRef::new(name, GitOid::Sha1([4; 20])).unwrap();
        assert!(claim.check(&valid, &moved).is_err());
        moved.remove(index);
        assert!(claim.check(&valid, &moved).is_err());
    }

    claim.pull_number = 0;
    assert!(claim.check(&valid, &captured).is_err());
    claim.pull_number = 3;
    claim.expected_version = -1;
    assert!(claim.check(&valid, &captured).is_err());
    claim.expected_version = 7;
    claim.head_ref = claim.base_ref.clone();
    assert!(claim.check(&valid, &captured).is_err());
    claim.head_ref = RefName::new("refs/tags/topic").unwrap();
    assert!(claim.check(&valid, &captured).is_err());
    claim.head_ref = RefName::new("refs/heads/topic").unwrap();
    claim.head_oid = claim.base_oid;
    assert!(claim.check(&valid, &captured).is_err());
}

#[test]
fn merge_rules_require_ancestry_for_fast_forward_and_complete_native_evidence() {
    let (mut claim, captured) = fixture();
    let valid = plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base_update(&claim, claim.head_oid)], 1);
    let facts = |fast_forward, is_commit, complete, lfs_failure| {
        [RefFacts::new(
            RefName::new("refs/heads/main").unwrap(),
            Some(GitOid::Sha1([1; 20]).as_hex()),
            Some(GitOid::Sha1([2; 20]).as_hex()),
            Some(true),
            Some(GitObjectKind::Commit),
            is_commit,
            fast_forward,
            Vec::new(),
            complete,
            Vec::new(),
            lfs_failure,
        )]
    };
    let fast_forward = claim.check(&valid, &captured).unwrap();
    assert!(fast_forward.check_facts(&facts(Some(true), Some(true), true, None)).is_ok());
    for invalid in [
        facts(Some(false), Some(true), true, None),
        facts(None, Some(true), true, None),
        facts(Some(true), Some(false), true, None),
        facts(Some(true), Some(true), false, None),
        facts(Some(true), Some(true), true, Some("missing-durable-lfs")),
    ] {
        assert!(fast_forward.check_facts(&invalid).is_err());
    }
    assert!(fast_forward.check_facts(&[]).is_err());

    claim.strategy = MergeStrategy::MergeCommit;
    let non_ff = claim.check(&valid, &captured).unwrap();
    assert!(non_ff.check_facts(&facts(Some(false), Some(true), true, None)).is_ok());
}

#[test]
fn merge_commit_requires_two_ordered_parent_headers() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let base = "1".repeat(format.oid_hex_len());
        let head = "2".repeat(format.oid_hex_len());
        let tree = "3".repeat(format.oid_hex_len());
        let full = |parents: &str| format!("tree {tree}\n{parents}author A <a@b> 0 +0000\n\nparent {base}\n");
        let valid = full(&format!("parent {base}\nparent {head}\n"));
        let mut headers = commit_headers(valid.as_bytes()).unwrap();
        assert_eq!(parse_tree_oid(format, headers.next().unwrap().strip_prefix(b"tree ")).unwrap().as_hex(), tree);
        assert!(ordered_parents(&mut headers, &base, &head).is_ok());
        for parents in [
            format!("parent {head}\nparent {base}\n"),
            format!("parent {base}\n"),
            format!("parent {base}\nparent {head}\nparent {tree}\n"),
            format!("parent {base}\nauthor A <a@b> 0 +0000\nparent {head}\n"),
            format!("parent {base}\nparent {base}\n"),
        ] {
            let commit = full(&parents);
            let mut headers = commit_headers(commit.as_bytes()).unwrap().skip(1);
            assert!(ordered_parents(&mut headers, &base, &head).is_err());
        }
        assert!(commit_headers(format!("tree {tree}\nparent {base}\nparent {head}\n").as_bytes()).is_err());
    }
}

#[test]
fn merge_tree_output_must_be_one_canonical_matching_oid() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let hex = "a".repeat(format.oid_hex_len());
        let tree = GitOid::parse(format, &hex).unwrap();
        assert!(require_tree_match(format, tree, format!("{hex}\n").as_bytes()).is_ok());
        for invalid in [
            hex.clone(),
            format!("{hex}\n\n"),
            format!("{hex}\nCONFLICT\n"),
            format!("{}\n", hex.to_uppercase()),
            format!("{}\n", "0".repeat(format.oid_hex_len())),
            format!("{}\n", "b".repeat(format.oid_hex_len())),
        ] {
            assert!(require_tree_match(format, tree, invalid.as_bytes()).is_err());
        }
    }
}

#[test]
fn merge_requires_stable_git_2_43_or_later() {
    for version in ["git version 2.43.0\n", "git version 2.51.1 (Vendor build)\n", "git version 3.0.0\n"] {
        assert!(check_git_version(version.as_bytes()).is_ok());
    }
    for version in [
        "git version 2.42.99\n",
        "git version 2.43\n",
        "git version 2.43.0-rc0\n",
        "git version 2.+43.0\n",
        "git version 2.43.0.1\n",
        "git version 2.43.0\nextra\n",
        "version 2.43.0\n",
    ] {
        assert!(check_git_version(version.as_bytes()).is_err());
    }
}

#[test]
fn merge_digest_binds_the_operation_claim_facts_and_tree() {
    let (mut claim, _) = fixture();
    let plan_for = |operation| {
        let (claim, _) = fixture();
        plan(CommitMode::Atomic, HeadUpdate::Keep, vec![base_update(&claim, claim.head_oid)], operation)
    };
    let candidate = claim.head_oid;
    let tree = GitOid::Sha1([5; 20]);
    let facts = RequestDigest::from_bytes([7; 32]);
    let original = merge_digest(&plan_for(1), &claim, candidate, tree, &facts);
    assert_ne!(original, merge_digest(&plan_for(2), &claim, candidate, tree, &facts));
    assert_ne!(original, merge_digest(&plan_for(1), &claim, candidate, GitOid::Sha1([6; 20]), &facts));
    assert_ne!(original, merge_digest(&plan_for(1), &claim, candidate, tree, &RequestDigest::from_bytes([9; 32])));
    claim.expected_version += 1;
    assert_ne!(original, merge_digest(&plan_for(1), &claim, candidate, tree, &facts));
    claim.expected_version -= 1;
    claim.strategy = MergeStrategy::MergeCommit;
    assert_ne!(original, merge_digest(&plan_for(1), &claim, candidate, tree, &facts));
}
