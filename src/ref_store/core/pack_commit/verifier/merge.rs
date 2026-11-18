use super::PackVerifier;
use super::process::Stdin;
use super::publication::{PublicationFactsEngine, VerifiedPublicationFacts};
use super::refuse;
use super::view::NativeView;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::CommitMode;
use crate::ref_store::core::pack_commit::artifact::RegisteredPack;
use crate::ref_store::core::pack_commit::context::{CapturedRef, PackCommitBaseline};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::facts::{NoDurableLfsBytes, RefFacts};
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeStrategy {
    FastForward,
    MergeCommit,
}

#[derive(Debug)]
pub struct MergeClaim {
    pub pull_number: i64,
    pub expected_version: i64,
    pub head_ref: RefName,
    pub head_oid: GitOid,
    pub base_ref: RefName,
    pub base_oid: GitOid,
    pub strategy: MergeStrategy,
}

#[derive(Debug)]
pub struct VerifiedMergeAttestation {
    digest: RequestDigest,
    facts_digest: RequestDigest,
    candidate: GitOid,
    tree: GitOid,
}

impl VerifiedMergeAttestation {
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }

    pub fn publication_facts_digest(&self) -> &RequestDigest {
        &self.facts_digest
    }

    pub fn candidate_oid(&self) -> GitOid {
        self.candidate
    }

    pub fn tree_oid(&self) -> GitOid {
        self.tree
    }

    pub fn binds(&self, plan: &PackCommitPlan, claim: &MergeClaim) -> bool {
        self.digest == merge_digest(plan, claim, self.candidate, self.tree, &self.facts_digest)
    }
}

impl PackVerifier {
    pub async fn attest_merge(
        &self,
        plan: &PackCommitPlan,
        baseline: &PackCommitBaseline,
        new_packs: Vec<RegisteredPack>,
        claim: &MergeClaim,
        deadline: Instant,
    ) -> Result<VerifiedMergeAttestation, PackCommitError> {
        let engine = PublicationFactsEngine::new(self.store.clone(), self.git.clone())?;
        let (_, attestation) =
            engine.facts_with_merge(plan, baseline, new_packs, &NoDurableLfsBytes, Some(claim), deadline).await?;
        attestation.ok_or_else(|| refuse("publication facts did not attest the merge candidate"))
    }
}

pub(super) struct CheckedMerge<'a> {
    plan: &'a PackCommitPlan,
    claim: &'a MergeClaim,
    candidate: GitOid,
}

impl MergeClaim {
    pub(super) fn check<'a>(
        &'a self,
        plan: &'a PackCommitPlan,
        captured: &[CapturedRef],
    ) -> Result<CheckedMerge<'a>, PackCommitError> {
        if self.pull_number <= 0 || self.expected_version <= 0 {
            return Err(refuse("merge requires a positive pull number and expected version"));
        }
        if !self.head_ref.is_branch()
            || !self.base_ref.is_branch()
            || self.head_ref == self.base_ref
            || self.head_oid == self.base_oid
        {
            return Err(refuse("merge requires distinct captured branches and object ids"));
        }
        if !matches!(plan.commit_mode(), CommitMode::Atomic) || !matches!(plan.head(), HeadUpdate::Keep) {
            return Err(refuse("merge requires an atomic plan with unchanged symbolic HEAD"));
        }
        let [update] = plan.refs() else {
            return Err(refuse("merge requires exactly one base ref update"));
        };
        let (RefPrecondition::Present(old), RefTarget::Oid(candidate)) = (update.precondition(), update.target())
        else {
            return Err(refuse("merge requires an update to an existing branch"));
        };
        if update.name() != &self.base_ref || *old != self.base_oid || *candidate == self.base_oid {
            return Err(refuse("merge plan does not advance the claimed base from its expected object id"));
        }
        for (name, oid) in [(&self.base_ref, self.base_oid), (&self.head_ref, self.head_oid)] {
            if !captured.iter().any(|entry| entry.name() == name.as_str() && entry.oid_hex() == oid.as_hex()) {
                return Err(refuse("merge branch object id differs from the captured refs"));
            }
        }
        if matches!(self.strategy, MergeStrategy::FastForward) && *candidate != self.head_oid {
            return Err(refuse("fast-forward merge candidate differs from the captured head"));
        }
        Ok(CheckedMerge { plan, claim: self, candidate: *candidate })
    }
}

pub(super) struct VerifiedMergeCandidate<'a> {
    checked: CheckedMerge<'a>,
    tree: GitOid,
}

impl<'a> CheckedMerge<'a> {
    fn check_facts(&self, facts: &[RefFacts]) -> Result<(), PackCommitError> {
        let [facts] = facts else {
            return Err(refuse("merge requires facts for exactly one base ref"));
        };
        if facts.name() != &self.claim.base_ref || facts.branch_target_is_commit() != Some(true) {
            return Err(refuse("merge candidate is not a verified branch commit"));
        }
        if !facts.changed_paths_complete() || facts.lfs_failure().is_some() {
            return Err(refuse("merge changed paths or durable LFS evidence could not be verified"));
        }
        if matches!(self.claim.strategy, MergeStrategy::FastForward) && facts.fast_forward() != Some(true) {
            return Err(refuse("captured base is not an ancestor of the fast-forward candidate"));
        }
        Ok(())
    }

    pub(super) async fn verify(
        self,
        view: &NativeView,
        facts: &[RefFacts],
        deadline: Instant,
    ) -> Result<VerifiedMergeCandidate<'a>, PackCommitError> {
        self.check_facts(facts)?;
        let version = view.step("merge-version", &["--version"], Stdin::Null, deadline).await?;
        check_git_version(&version)?;

        let candidate = self.candidate.as_hex();
        let connectivity = view
            .step(
                "merge-connectivity",
                &["fsck", "--connectivity-only", "--no-dangling", "--no-progress", &candidate],
                Stdin::Null,
                deadline,
            )
            .await?;
        if !connectivity.iter().all(u8::is_ascii_whitespace) {
            return Err(refuse("merge candidate connectivity check reported a problem"));
        }
        let commit = view.step("merge-candidate", &["cat-file", "commit", &candidate], Stdin::Null, deadline).await?;
        let format = self.plan.object_format();
        let mut headers = commit_headers(&commit)?;
        let tree = parse_tree_oid(format, headers.next().and_then(|line| line.strip_prefix(b"tree ")))?;
        if matches!(self.claim.strategy, MergeStrategy::MergeCommit) {
            let base = self.claim.base_oid.as_hex();
            let head = self.claim.head_oid.as_hex();
            ordered_parents(&mut headers, &base, &head)?;
            let merged_tree =
                view.step("merge-tree", &["merge-tree", "--write-tree", &base, &head], Stdin::Null, deadline).await?;
            require_tree_match(format, tree, &merged_tree)?;
        }
        Ok(VerifiedMergeCandidate { checked: self, tree })
    }
}

impl VerifiedMergeCandidate<'_> {
    pub(super) fn attest(self, facts: &VerifiedPublicationFacts) -> VerifiedMergeAttestation {
        let facts_digest = *facts.facts_digest();
        let CheckedMerge { plan, claim, candidate } = self.checked;
        let tree = self.tree;
        let digest = merge_digest(plan, claim, candidate, tree, &facts_digest);
        VerifiedMergeAttestation { digest, facts_digest, candidate, tree }
    }
}

fn merge_digest(
    plan: &PackCommitPlan,
    claim: &MergeClaim,
    candidate: GitOid,
    tree: GitOid,
    facts: &RequestDigest,
) -> RequestDigest {
    let strategy: &[u8] = match claim.strategy {
        MergeStrategy::FastForward => b"fast_forward",
        MergeStrategy::MergeCommit => b"merge_commit",
    };
    RequestDigest::of(
        "core-native-merge-attestation-v1",
        &[
            plan.parent_digest().as_bytes(),
            facts.as_bytes(),
            &claim.pull_number.to_be_bytes(),
            &claim.expected_version.to_be_bytes(),
            claim.base_ref.as_str().as_bytes(),
            claim.base_oid.as_hex().as_bytes(),
            claim.head_ref.as_str().as_bytes(),
            claim.head_oid.as_hex().as_bytes(),
            strategy,
            candidate.as_hex().as_bytes(),
            tree.as_hex().as_bytes(),
        ],
    )
}

fn check_git_version(output: &[u8]) -> Result<(), PackCommitError> {
    let mut components = std::str::from_utf8(output)
        .ok()
        .and_then(|text| text.strip_prefix("git version "))
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|version| !version.contains(['\r', '\n']))
        .and_then(|version| version.split_ascii_whitespace().next())
        .ok_or_else(|| refuse("native merge requires stock Git 2.43 or later"))?
        .split('.');
    let mut number = || {
        components
            .next()
            .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|part| part.parse::<u32>().ok())
    };
    match (number(), number(), number()) {
        (Some(major), Some(minor), Some(_)) if (major, minor) >= (2, 43) && components.next().is_none() => Ok(()),
        _ => Err(refuse("native merge requires stock Git 2.43 or later")),
    }
}

fn commit_headers(commit: &[u8]) -> Result<impl Iterator<Item = &[u8]>, PackCommitError> {
    let end = commit
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(|| refuse("merge candidate commit headers are incomplete"))?;
    Ok(commit[..end].split(|byte| *byte == b'\n'))
}

fn parse_tree_oid(format: GitObjectFormat, bytes: Option<&[u8]>) -> Result<GitOid, PackCommitError> {
    bytes
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| GitOid::parse(format, value).ok())
        .ok_or_else(|| refuse("native merge tree object id is malformed"))
}

fn ordered_parents<'a>(
    headers: &mut impl Iterator<Item = &'a [u8]>,
    base: &str,
    head: &str,
) -> Result<(), PackCommitError> {
    for expected in [base, head] {
        if headers.next().and_then(|line| line.strip_prefix(b"parent ")) != Some(expected.as_bytes()) {
            return Err(refuse("merge candidate does not have the expected ordered parents"));
        }
    }
    if headers.any(|line| line.starts_with(b"parent ")) {
        return Err(refuse("merge candidate has more than two parents"));
    }
    Ok(())
}

fn require_tree_match(format: GitObjectFormat, tree: GitOid, merged_tree: &[u8]) -> Result<(), PackCommitError> {
    if parse_tree_oid(format, merged_tree.strip_suffix(b"\n"))? != tree {
        return Err(refuse("merge candidate tree differs from the native merge tree"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "merge_tests.rs"]
mod tests;
