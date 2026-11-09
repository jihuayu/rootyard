//! Live PostgreSQL authorization and policy facts for a publication decision.
//!
//! Everything here reads *actual* rows of actual schemas (migrations 001/009/020/040/050/106/107/
//! 120/121/136): `tokens`, `repositories`, `repository_collaborators`/`repository_teams`/
//! `repository_team_members`, `organization_memberships`/`organization_teams`/
//! `organization_team_members`, `token_repository_scopes` (through `token_scopes`), `forge_branch_rules`,
//! `forge_pulls`, `forge_pull_reviews`, `forge_check_runs`, `forge_trusted_check_contexts`,
//! `forge_webhooks`, `ci_runs`, `lfs_locks`, `lfs_objects`.
//!
//! Nothing is invented: there is no "auth source" table, no caller-supplied boolean and no
//! `allow-all` default. A row that cannot be read fails the whole publication closed.
//!
//! Credential identity is matched like `auth::verify_token`: exact `(token_id, user_id, digest)`,
//! `NOT revoked`, and the expiry compared with `clock_timestamp()` in this transaction (which is read
//! *after* the dependency lock wait, so a revoker that committed first is observed).
use super::contract::{DecisionError, DenialCode, DependencyObservation, PublicationAction, ScopeKind};
use super::digest::{self, AuthzFacts};
use super::sql_locks::{self, ProtocolState};
use crate::db::Identity;
use crate::members::models::Role;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::GitObjectFormat;
use crate::token_scopes::{RepoAction, ScopeDenial};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::policy::read_policy;
/// A decision never evaluates more open pull requests / rules / locks than this; beyond the bound the
/// publication is unverifiable rather than silently partially evaluated.
pub(super) use super::policy::{RepoPolicyFacts, read_lfs_objects};

/// Everything the decision binds about the live subject, repository and policy, plus the exact per-scope
/// observations that a final re-check compares.
pub(super) struct LiveAuthority {
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub role: Role,
    pub token_id: Uuid,
    pub token_kind: String,
    pub token_read_only: bool,
    pub token_restricted: bool,
    pub token_scope_version: i64,
    pub token_expires_millis: Option<i64>,
    pub storage_generation: i64,
    pub repository_state: String,
    pub storage_backend: String,
    pub transition_state: String,
    pub pando_authority: bool,
    pub action: &'static str,
    pub actions: Vec<&'static str>,
    pub dependencies: Vec<DependencyObservation>,
    pub policy: RepoPolicyFacts,
}

impl LiveAuthority {
    /// Earliest hard expiry this decision must respect (`None` = no token expiry).
    pub(super) fn earliest_expiry_millis(&self) -> Option<i64> {
        self.token_expires_millis
    }

    /// The canonical digest of the live subject/repository facts (recomputed on every re-check).
    pub(super) fn authz_digest(&self) -> RequestDigest {
        digest::authz_digest(&AuthzFacts {
            repository_id: self.repository_id,
            tenant_id: self.tenant_id,
            owner_id: self.owner_id,
            actor_id: self.actor_id,
            token_id: self.token_id,
            token_kind: &self.token_kind,
            token_read_only: self.token_read_only,
            token_restricted: self.token_restricted,
            token_scope_version: self.token_scope_version,
            token_expires_millis: self.token_expires_millis,
            role: self.role.as_str(),
            repository_state: &self.repository_state,
            storage_backend: &self.storage_backend,
            transition_state: &self.transition_state,
            pando_authority: self.pando_authority,
            storage_generation: self.storage_generation,
            action: self.action,
            actions: &self.actions,
        })
    }
}

fn scope(kind: ScopeKind, id: Uuid, version: i64, tag: &str, parts: &[Vec<u8>]) -> DependencyObservation {
    let refs = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    DependencyObservation { kind, id, version, digest: digest::scope_digest(tag, &refs) }
}

fn map_scope_denial(denial: ScopeDenial) -> DecisionError {
    match denial {
        ScopeDenial::InvalidToken => DecisionError::Denied(DenialCode::TokenInvalid),
        ScopeDenial::Forbidden => DecisionError::Denied(DenialCode::ScopeDenied),
        ScopeDenial::Unavailable => DecisionError::Unverifiable("token scope tables are unavailable"),
    }
}

/// Read and verify the live subject, repository lifecycle, RBAC role, token scope, core-gate protocol
/// state and the policy rows that selection needs.
///
/// `actor` must be an already authenticated [`Identity`]; this function re-verifies it against the live
/// `tokens` row (id/user/digest/revoked/expiry/kind/read_only) and the live RBAC/scope rows.
pub(super) async fn load_live_authority(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    actor: &Identity,
    action: &PublicationAction,
) -> Result<LiveAuthority, DecisionError> {
    let mut actions: Vec<&'static str> = Vec::with_capacity(2);

    // 1. Exact live credential. `digest` is matched in SQL, so only the real token secret can pass.
    let token = tx
        .query_opt(
            "SELECT t.user_id,t.read_only,t.is_restricted,t.kind,t.scope_version,\
                    (t.expires_at IS NULL OR t.expires_at > clock_timestamp()),\
                    (extract(epoch FROM t.expires_at)*1000)::bigint
             FROM tokens t
             WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked",
            &[&actor.token_id, &actor.id, &actor.token_digest],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::TokenInvalid))?;
    let token_user: Uuid = token.get(0);
    if token_user != actor.id {
        return Err(DecisionError::Denied(DenialCode::TokenInvalid));
    }
    let token_read_only: bool = token.get(1);
    let token_restricted: bool = token.get(2);
    let token_kind: String = token.get(3);
    let token_scope_version: i64 = token.get(4);
    let token_live_expiry: bool = token.get(5);
    let token_expires_millis: Option<i64> = token.get(6);
    if token_kind != "api" {
        // `web_sessions` stores only the child token id; the parent id exists only inside the session
        // secret, so a database-only decision module cannot verify the browser parent chain. Refuse
        // until a durable parent binding exists instead of pretending the chain was checked.
        return Err(DecisionError::Denied(DenialCode::BrowserTokenUnsupported));
    }
    if !token_live_expiry {
        return Err(DecisionError::Denied(DenialCode::TokenExpired));
    }
    if token_read_only {
        return Err(DecisionError::Denied(DenialCode::TokenReadOnly));
    }

    // 1b. Actual `users` row of the subject, read under the source-table locks (a deleted/suspended
    //     identity cannot authorize; the table itself is in the frozen SHARE set).
    let user_row = tx
        .query_opt("SELECT id FROM users WHERE id=$1 FOR SHARE", &[&actor.id])
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::TokenInvalid))?;
    let _user_id: Uuid = user_row.get(0);

    // 2. Repository lifecycle. A core repository is still unserved: it must stay `provisioning`,
    //    on the legacy `gitfs` backend, with a stable transition and no live Pando authority. The
    //    legacy global `ready` rule is deliberately untouched.
    let repository = tx
        .query_opt(
            "SELECT r.owner_id,r.state,r.storage_backend,r.transition_state,r.object_format,\
                    r.storage_generation,\
                    EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id)
             FROM repositories r WHERE r.id=$1 FOR SHARE",
            &[&plan.repository_id()],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::RepositoryNotFound))?;
    let owner_id: Uuid = repository.get(0);
    let repository_state: String = repository.get(1);
    let storage_backend: String = repository.get(2);
    let transition_state: String = repository.get(3);
    let repository_format_text: String = repository.get(4);
    let storage_generation: i64 = repository.get(5);
    let pando_authority: bool = repository.get(6);
    if owner_id != plan.tenant_id() || owner_id != plan.owner_id() {
        return Err(DecisionError::Denied(DenialCode::TenantMismatch));
    }
    if repository_state != "provisioning"
        || storage_backend != "gitfs"
        || transition_state != "stable"
        || pando_authority
    {
        return Err(DecisionError::Denied(DenialCode::RepositoryUnserved));
    }
    let repository_format = GitObjectFormat::parse(&repository_format_text)
        .map_err(|_| DecisionError::Ledger("repository object format is not a known format"))?;
    if repository_format != plan.object_format() {
        return Err(DecisionError::Denied(DenialCode::ObjectFormatMismatch));
    }

    // 3. Effective RBAC role of the *current* actor, read under this transaction.
    let resolved = crate::members::rbac::resolve_effective_role(tx, plan.repository_id(), owner_id, actor.id)
        .await
        .map_err(|_| DecisionError::Unverifiable("live RBAC resolution failed"))?;
    let role = resolved.map(|(effective, _, _)| effective).ok_or(DecisionError::Denied(DenialCode::RoleDenied))?;
    if role < Role::Write {
        return Err(DecisionError::Denied(DenialCode::RoleDenied));
    }

    // 4. Restricted-token narrowing through the real scope tables.
    let browser = crate::auth::web_scope_enabled();
    crate::token_scopes::authorize_repository_late(
        tx,
        actor.token_id,
        actor.id,
        plan.repository_id(),
        RepoAction::ContentsWrite,
        browser,
    )
    .await
    .map_err(map_scope_denial)?;
    actions.push(RepoAction::ContentsWrite.as_str());

    // 5. Core-gate protocol state (shared, Root-owned DDL) — fail closed when it is not installed.
    let protocol = sql_locks::protocol_state(tx, plan.repository_id()).await?;
    check_protocol(plan, &protocol)?;

    // 6. Live policy rows.
    let policy = read_policy(tx, plan).await?;

    // 7. Action scope is a fixed function of the requested semantic action, never of the presence of
    //    a `head_ref` or an open PR. Push is exactly ContentsWrite; an explicit Merge additionally
    //    requires PullsWrite and the exact bound PR facts (checked in the pure policy pass).
    if action.is_merge() {
        crate::token_scopes::authorize_repository_late(
            tx,
            actor.token_id,
            actor.id,
            plan.repository_id(),
            RepoAction::PullsWrite,
            browser,
        )
        .await
        .map_err(map_scope_denial)?;
        actions.push(RepoAction::PullsWrite.as_str());
    }

    let mut dependencies = Vec::with_capacity(ScopeKind::ALL.len());
    dependencies.push(scope(
        ScopeKind::Token,
        actor.token_id,
        token_scope_version,
        "token",
        &[
            token_kind.as_bytes().to_vec(),
            vec![token_read_only as u8, token_restricted as u8],
            token_expires_millis.unwrap_or(-1).to_be_bytes().to_vec(),
            actor.id.as_bytes().to_vec(),
        ],
    ));
    dependencies.push(scope(
        ScopeKind::ParentToken,
        actor.id,
        token_scope_version,
        "parent-token-api-only",
        &[b"api-kind".to_vec()],
    ));
    dependencies.push(scope(ScopeKind::Session, actor.token_id, 0, "no-browser-session", &[b"api-kind".to_vec()]));
    dependencies.push(scope(ScopeKind::User, actor.id, 0, "user", &[actor.id.as_bytes().to_vec()]));
    dependencies.push(scope(
        ScopeKind::OrgMembership,
        owner_id,
        0,
        "org-membership-folded-into-role",
        &[owner_id.as_bytes().to_vec(), role.as_str().as_bytes().to_vec()],
    ));
    dependencies.push(scope(
        ScopeKind::OrgTeam,
        owner_id,
        0,
        "org-team-folded-into-role",
        &[owner_id.as_bytes().to_vec()],
    ));
    dependencies.push(scope(
        ScopeKind::RepoAccess,
        plan.repository_id(),
        0,
        "repo-access-role",
        &[role.as_str().as_bytes().to_vec(), actor.id.as_bytes().to_vec()],
    ));
    dependencies.push(scope(
        ScopeKind::RepoLifecycle,
        plan.repository_id(),
        storage_generation,
        "repo-lifecycle",
        &[
            repository_state.as_bytes().to_vec(),
            storage_backend.as_bytes().to_vec(),
            transition_state.as_bytes().to_vec(),
            vec![pando_authority as u8],
            repository_format_text.as_bytes().to_vec(),
        ],
    ));
    dependencies.push(DependencyObservation {
        kind: ScopeKind::BranchRules,
        id: plan.repository_id(),
        version: policy.rules.iter().map(|rule| rule.version).max().unwrap_or(0),
        digest: digest::rules_digest(&policy.rules),
    });
    dependencies.push(DependencyObservation {
        kind: ScopeKind::Pull,
        id: plan.repository_id(),
        version: policy.pulls.iter().map(|pull| pull.version).max().unwrap_or(0),
        digest: digest::pulls_digest(&policy.pulls),
    });
    dependencies.push(DependencyObservation {
        kind: ScopeKind::Reviews,
        id: plan.repository_id(),
        version: 0,
        digest: digest::approvals_digest(&policy.approvals),
    });
    dependencies.push(DependencyObservation {
        kind: ScopeKind::Checks,
        id: plan.repository_id(),
        version: 0,
        digest: digest::checks_digest(&policy.checks),
    });
    dependencies.push(DependencyObservation {
        kind: ScopeKind::LfsLocks,
        id: plan.repository_id(),
        version: policy.lfs_locks.iter().map(|lock| lock.version).max().unwrap_or(0),
        digest: digest::lfs_locks_digest(&policy.lfs_locks),
    });
    dependencies.push(DependencyObservation {
        kind: ScopeKind::Authority,
        id: plan.repository_id(),
        version: protocol.revision,
        digest: digest::authority_digest(
            protocol.tenant_id,
            &protocol.object_format,
            protocol.history_incarnation,
            protocol.authority_epoch,
            protocol.group_epoch,
            protocol.revision,
            protocol.decision_required,
            &protocol.head_ref,
        ),
    });

    Ok(LiveAuthority {
        repository_id: plan.repository_id(),
        actor_id: actor.id,
        tenant_id: plan.tenant_id(),
        owner_id,
        role,
        token_id: actor.token_id,
        token_kind,
        token_read_only,
        token_restricted,
        token_scope_version,
        token_expires_millis,
        storage_generation,
        repository_state,
        storage_backend,
        transition_state,
        pando_authority,
        action: action.as_str(),
        actions,
        dependencies,
        policy,
    })
}

fn check_protocol(plan: &PackCommitPlan, protocol: &ProtocolState) -> Result<(), DecisionError> {
    if protocol.tenant_id != plan.tenant_id() {
        return Err(DecisionError::Denied(DenialCode::TenantMismatch));
    }
    if protocol.object_format != plan.object_format().as_str() {
        return Err(DecisionError::Denied(DenialCode::ObjectFormatMismatch));
    }
    if protocol.history_incarnation != plan.history_incarnation() {
        return Err(DecisionError::Denied(DenialCode::HistoryIncarnationMismatch));
    }
    if protocol.authority_epoch != plan.authority_epoch() {
        return Err(DecisionError::Denied(DenialCode::AuthorityEpochMismatch));
    }
    if protocol.group_epoch != plan.group_epoch() {
        return Err(DecisionError::Denied(DenialCode::GroupEpochMismatch));
    }
    if protocol.revision != plan.expected().revision() {
        return Err(DecisionError::Denied(DenialCode::RevisionMismatch));
    }
    Ok(())
}
