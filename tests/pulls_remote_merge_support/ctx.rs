use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use rootyard::pulls::remote_merge_finalizer::{
    CheckRunSnapshot, LiveAuthzScopeState, MergeAttemptSpec, MergeBindingInputs, MergePullSnapshot, MergeStrategy,
    compute_merge_binding_digest,
};
use rootyard::ref_store::contract::IssuerLane;
use rootyard::ref_store::core::command::CommitRefsRequest;
use rootyard::ref_store::core::contract::CommitMode;
use rootyard::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, ScopeLifecycle, SmPackMode,
    WireCommitRefsRequest, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict, WireGateInit,
};
use rootyard::ref_store::core::types::{
    GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate,
};
use rootyard::ref_store::projector::{
    DecisionGrantKeyring, GrantExpectedRealm, ServiceMtlsIdentity, SignedDecisionGrantPayload,
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
const NULL_CFG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_CFG: &str = "NUL";

pub fn git_ok(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "--no-replace-objects", "-C"])
        .arg(dir)
        .args(args)
        .envs([
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_SYSTEM", NULL_CFG),
            ("GIT_CONFIG_GLOBAL", NULL_CFG),
            ("GIT_AUTHOR_NAME", "r"),
            ("GIT_AUTHOR_EMAIL", "r@e"),
            ("GIT_COMMITTER_NAME", "r"),
            ("GIT_COMMITTER_EMAIL", "r@e"),
        ])
        .output()?;
    ensure!(out.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

pub fn setup_git_repo(dir: &Path, fmt: GitObjectFormat) -> Result<(String, String, String)> {
    let flag = match fmt {
        GitObjectFormat::Sha1 => "--object-format=sha1",
        GitObjectFormat::Sha256 => "--object-format=sha256",
    };
    git_ok(dir, &["init", flag, "--initial-branch=main"])?;
    fs::write(dir.join("README.md"), "base\n")?;
    git_ok(dir, &["add", "."])?;
    git_ok(dir, &["commit", "-m", "base"])?;
    let base = git_ok(dir, &["rev-parse", "refs/heads/main"])?;
    git_ok(dir, &["checkout", "-b", "pr-1"])?;
    fs::write(dir.join("pr1.txt"), "ff feature\n")?;
    git_ok(dir, &["add", "."])?;
    git_ok(dir, &["commit", "-m", "pr-1"])?;
    let h1 = git_ok(dir, &["rev-parse", "HEAD"])?;
    git_ok(dir, &["checkout", "-b", "pr-2", "main"])?;
    fs::write(dir.join("pr2.txt"), "diverge feature\n")?;
    git_ok(dir, &["add", "."])?;
    git_ok(dir, &["commit", "-m", "pr-2"])?;
    let h2 = git_ok(dir, &["rev-parse", "HEAD"])?;
    git_ok(dir, &["checkout", "main"])?;
    Ok((base, h1, h2))
}

pub struct TestCtx {
    pub tenant: Uuid,
    pub repo: Uuid,
    pub actor: Uuid,
    pub scope_id: Uuid,
    pub fmt: GitObjectFormat,
    pub realm: GrantExpectedRealm,
    pub svc: ServiceMtlsIdentity,
    pub keyring: DecisionGrantKeyring,
}

pub struct BuildArgs<'a> {
    pub num: i64,
    pub seq: i64,
    pub base: &'a str,
    pub head: &'a str,
    pub target: &'a str,
    pub strat: MergeStrategy,
    pub rev: i64,
    pub gd: &'a str,
    pub psha: &'a str,
}

impl TestCtx {
    pub fn new(fmt: GitObjectFormat) -> Self {
        let (tenant, repo, actor, scope_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let realm = GrantExpectedRealm {
            tenant_id: tenant,
            repository_id: repo,
            group_id: 11,
            group_epoch: 1,
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 2,
        };
        let keyring = DecisionGrantKeyring::new([(1u8, Zeroizing::new([0x5au8; 32]))], 1, BTreeSet::new()).unwrap();
        let svc = ServiceMtlsIdentity { san_identity: "raft-bridge-pulls-it".into(), issuer_id: actor };
        Self { tenant, repo, actor, scope_id, fmt, realm, svc, keyring }
    }

    pub fn seed_cmds(&self, base_oid: &str) -> (RefCasCommand, RefCasCommand) {
        let init = RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit {
                repository_id: self.repo,
                tenant_id: self.tenant,
                object_format: self.fmt,
                history_incarnation: self.realm.history_incarnation,
                authority_epoch: self.realm.authority_epoch,
                group_epoch: self.realm.group_epoch,
                head_ref: "refs/heads/main".into(),
            },
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        });
        let upd = RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(self.fmt, base_oid).unwrap()),
        );
        let req = CommitRefsRequest::new(
            self.repo,
            self.tenant,
            self.actor,
            IssuerLane::new("seed").unwrap(),
            1,
            Uuid::new_v4(),
            self.fmt,
            self.realm.history_incarnation,
            self.realm.authority_epoch,
            self.realm.group_epoch,
            1,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![upd],
        )
        .unwrap();
        let seed = RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req),
            decision_id: None,
            required_holds: vec![],
            policy_rejects: BTreeMap::new(),
            logical_tick: 1,
        });
        (init, seed)
    }

    pub fn build(&self, a: BuildArgs<'_>) -> (MergeAttemptSpec, MergePullSnapshot) {
        let (num, seq, base, head, target, strat, rev, gd, psha) =
            (a.num, a.seq, a.base, a.head, a.target, a.strat, a.rev, a.gd, a.psha);
        let (op, dec, d) = (Uuid::new_v4(), Uuid::new_v4(), "11".repeat(32));
        let chks = vec!["ci/verify".to_owned()];
        let pull = MergePullSnapshot {
            tenant_id: self.tenant,
            repository_id: self.repo,
            pull_number: num,
            state: "open".into(),
            head_ref: format!("refs/heads/pr-{num}"),
            base_ref: "refs/heads/main".into(),
            head_oid: head.into(),
            base_oid: base.into(),
            merge_commit_oid: None,
            version: 1,
            storage_generation: 1,
            object_format: self.fmt,
            live_head_ref_oid: head.into(),
            live_base_ref_oid: base.into(),
            require_fast_forward: strat == MergeStrategy::FastForward,
            required_checks: chks.clone(),
            min_check_sequence: 1,
            observed_checks: vec![CheckRunSnapshot {
                context: "ci/verify".into(),
                commit_oid: head.into(),
                base_oid: Some(base.into()),
                status: "completed".into(),
                conclusion: Some("success".into()),
                sequence: 1,
                attempt: 1,
                trusted: true,
            }],
        };
        let upd = RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Present(GitOid::parse(self.fmt, base).unwrap()),
            RefTarget::Oid(GitOid::parse(self.fmt, target).unwrap()),
        );
        let creq = CommitRefsRequest::new(
            self.repo,
            self.tenant,
            self.actor,
            IssuerLane::new("pull-merge").unwrap(),
            seq,
            op,
            self.fmt,
            self.realm.history_incarnation,
            self.realm.authority_epoch,
            self.realm.group_epoch,
            rev,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![upd],
        )
        .unwrap();
        let facts = compute_merge_binding_digest(&MergeBindingInputs {
            tenant_id: self.tenant,
            repository_id: self.repo,
            pull_number: num,
            actor_id: self.actor,
            operation_id: op,
            decision_id: dec,
            base_ref: "refs/heads/main",
            expected_head_oid: head,
            expected_base_oid: base,
            candidate_target_oid: target,
            strategy: strat,
            expected_version: 1,
            expected_storage_generation: 1,
            required_checks: &chks,
            min_check_sequence: 1,
            authz_epoch: 3,
        });
        let grant = self
            .keyring
            .sign(SignedDecisionGrantPayload {
                format_version: 1,
                key_id: 1,
                issuer_id: self.actor,
                service_mtls_identity: self.svc.san_identity.clone(),
                decision_id: dec,
                tenant_id: self.tenant,
                repository_id: self.repo,
                actor_id: self.actor,
                operation_id: op,
                group_id: self.realm.group_id,
                group_epoch: self.realm.group_epoch,
                history_incarnation: self.realm.history_incarnation,
                authority_epoch: self.realm.authority_epoch,
                authz_epoch: 3,
                base_revision: rev,
                kind: WireDecisionKind::Atomic,
                not_after_tick: 1000,
                command_digest: creq.digest().as_hex(),
                selection_digest: d.clone(),
                policy_digest: d.clone(),
                facts_digest: facts,
                authz_digest: d.clone(),
                dependencies_digest: d.clone(),
                packs_digest: d.clone(),
                hold_receipts_digest: d.clone(),
                captured_oid_digest: d.clone(),
                base_gate_digest: gd.into(),
                required_holds: vec![],
                verdicts: vec![WireDecisionVerdict {
                    ref_name: "refs/heads/main".into(),
                    accepted: true,
                    reject_code: None,
                }],
                scope_dependencies: vec![WireDecisionScopeDep {
                    scope_kind: "token".into(),
                    scope_id: self.scope_id,
                    observed_version: 1,
                    observed_digest: d,
                }],
            })
            .unwrap();
        let scope = LiveAuthzScopeState {
            scope_kind: "token".into(),
            scope_id: self.scope_id,
            lifecycle: ScopeLifecycle::Open,
            authz_floor: 1,
        };
        let spec = MergeAttemptSpec {
            attempt_id: Uuid::new_v4(),
            operation_id: op,
            decision_id: dec,
            tenant_id: self.tenant,
            repository_id: self.repo,
            actor_id: self.actor,
            lane: "pull-merge".into(),
            sequence: seq,
            pull_number: num,
            base_ref: "refs/heads/main".into(),
            expected_head_oid: head.into(),
            expected_base_oid: base.into(),
            candidate_target_oid: target.into(),
            expected_version: 1,
            expected_storage_generation: 1,
            expected_base_revision: rev,
            strategy: strat,
            object_format: self.fmt,
            realm: self.realm.clone(),
            expected_service_san: self.svc.san_identity.clone(),
            grant,
            current_logical_tick: 10,
            live_scopes: vec![scope],
            cancelled_operations: BTreeSet::new(),
            pack_sha256: psha.into(),
        };
        (spec, pull)
    }
}
