//! Shared contract parity tests verifying identical outputs between PostgreSQL
//! (`PgRefStoreCore`) and the deterministic Raft state machine (`RefCasStateMachine`)
//! across `CommitMode::Atomic`, `CommitMode::AcceptedSubset`, replay, digest conflict,
//! cancellation, and snapshot restart recovery (`#116`).

use super::*;
use rootyard::ref_store::core::pack_commit::PackMode;
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CancelCommand, CommitRefsCommand, InitializeGateCommand, RefCasCommand,
    RefCasLogEntry, RefCasStateMachine, RepositoryLane, StateMachineError, WireCommitRefsRequest, WireGateInit,
    WireOperationIdentity, encode_command,
};
use std::collections::BTreeMap;

struct DualHarness {
    pool: Pool,
    sm: RefCasStateMachine,
    entries: Vec<RefCasLogEntry>,
    next_index: u64,
    next_tick: u64,
}

impl DualHarness {
    fn new(pool: Pool) -> Self {
        Self { pool, sm: RefCasStateMachine::new(), entries: Vec::new(), next_index: 1, next_tick: 100 }
    }

    fn next_log(&mut self) -> (AppliedLogId, u64) {
        let log_id = AppliedLogId { term: 1, index: self.next_index };
        self.next_index += 1;
        let tick = self.next_tick;
        self.next_tick += 1;
        (log_id, tick)
    }

    async fn apply_both_init(&mut self, init: &CoreGateInit) -> Result<()> {
        let pg_gate = initialize(&self.pool, init).await?;
        let (log_id, _) = self.next_log();
        let cmd = RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(init),
            pack_mode: PackMode::MetadataOnly,
            lane: RepositoryLane::PgRefstore,
            authz_floor: 1,
        });
        let bytes = encode_command(&cmd)?;
        let res = self.sm.apply_bytes(log_id, &bytes)?;
        self.entries.push(RefCasLogEntry { log_id, payload: bytes });
        let sm_version = match res {
            ApplyResponse::GateInitialized { version, created } => {
                assert!(created);
                version
            }
            other => anyhow::bail!("unexpected init response {other:?}"),
        };
        assert_eq!(pg_gate.version(), sm_version, "init gate version must match exactly");
        Ok(())
    }

    async fn apply_both_commit(&mut self, req: &CommitRefsRequest) -> Result<Result<CommitRefsReceipt, RefStoreError>> {
        let pg_out = commit(&self.pool, req).await;
        let (log_id, tick) = self.next_log();
        let cmd = RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(req),
            decision_id: None,
            required_holds: vec![],
            policy_rejects: BTreeMap::new(),
            logical_tick: tick,
        });
        let bytes = encode_command(&cmd)?;
        let sm_out = match self.sm.apply_bytes(log_id, &bytes) {
            Ok(ApplyResponse::RefsCommitted(receipt)) => {
                self.entries.push(RefCasLogEntry { log_id, payload: bytes });
                Ok(receipt)
            }
            Ok(other) => anyhow::bail!("unexpected commit response {other:?}"),
            Err(StateMachineError::Store(err)) => {
                // Keep monotonic next_index only if accepted; rejected apply didn't bump last_applied.
                self.next_index -= 1;
                Err(err)
            }
            Err(err) => anyhow::bail!("unexpected SM error {err}"),
        };

        match (&pg_out, &sm_out) {
            (Ok(pg_r), Ok(sm_r)) => {
                assert_eq!(pg_r.replayed, sm_r.replayed, "replayed flag mismatch");
                assert_eq!(pg_r.terminal, sm_r.terminal, "CommitTerminal mismatch (per-ref & rejection)");
                assert_eq!(pg_r.record, sm_r.record, "OperationRecord mismatch");
            }
            (Err(RefStoreError::DigestConflict), Err(RefStoreError::DigestConflict)) => {}
            (Err(RefStoreError::Cancelled { operation_id: a }), Err(RefStoreError::Cancelled { operation_id: b })) => {
                assert_eq!(a, b);
            }
            (Err(RefStoreError::IdentityConflict), Err(RefStoreError::IdentityConflict)) => {}
            (pg_e, sm_e) => anyhow::bail!("commit parity mismatch: PG={pg_e:?} vs SM={sm_e:?}"),
        }
        Ok(pg_out)
    }

    async fn apply_both_cancel(&mut self, identity: &OperationIdentity) -> Result<()> {
        let pg_res = cancel(&self.pool, identity).await?;
        let (log_id, tick) = self.next_log();
        let cmd = RefCasCommand::Cancel(CancelCommand {
            identity: WireOperationIdentity::from(identity),
            reason: None,
            logical_tick: tick,
        });
        let bytes = encode_command(&cmd)?;
        let sm_receipt = match self.sm.apply_bytes(log_id, &bytes)? {
            ApplyResponse::OperationCancelled { receipt, .. } => {
                self.entries.push(RefCasLogEntry { log_id, payload: bytes });
                receipt
            }
            other => anyhow::bail!("unexpected cancel response {other:?}"),
        };
        assert_eq!(pg_res, sm_receipt, "CancelReceipt parity mismatch");
        Ok(())
    }

    async fn assert_version_and_lookup_parity(&self, repo: Uuid, tenant: Uuid, op_ids: &[Uuid]) -> Result<()> {
        let pg_ver = check_version(&self.pool, repo, tenant, None).await?;
        let sm_ver = self.sm.check_version(repo, tenant, None)?;
        assert_eq!(pg_ver, sm_ver, "check_version parity mismatch");
        if let VersionCheck::Changed(v) = pg_ver {
            assert_eq!(
                check_version(&self.pool, repo, tenant, Some(&v)).await?,
                self.sm.check_version(repo, tenant, Some(&v))?
            );
        }
        let mut client = self.pool.get().await?;
        for &op_id in op_ids {
            let pg_lookup = PgRefStoreCore.query_operation(&mut client, repo, op_id, deadline()).await?;
            let sm_lookup = self.sm.query_operation(repo, op_id)?;
            assert_eq!(pg_lookup, sm_lookup, "query_operation parity mismatch for {op_id}");
        }
        Ok(())
    }

    fn restart_sm_from_snapshot_and_log(&mut self) -> Result<()> {
        let snap = self.sm.snapshot_bytes()?;
        let mut restarted = RefCasStateMachine::restore_bytes(&snap)?;
        restarted.recover_entries(self.entries.clone())?;
        assert_eq!(restarted.state_digest()?, self.sm.state_digest()?);
        self.sm = restarted;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn atomic_pg_and_raft_sm_contract_parity() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut h = DualHarness::new(pool.clone());
        let issuer = Uuid::new_v4();
        let history = Uuid::new_v4();
        let init = gate(repo, tenant, GitObjectFormat::Sha1, history, "refs/heads/main");
        h.apply_both_init(&init).await?;

        let op1 = Uuid::new_v4();
        let req1 = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            1,
            op1,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            1,
            HeadUpdate::Retarget(ref_name("refs/heads/feature")),
            CommitMode::Atomic,
            vec![
                update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha1, 1))),
                update("refs/heads/feature", None, Some(oid(GitObjectFormat::Sha1, 2))),
                update("refs/tags/v1", None, Some(oid(GitObjectFormat::Sha1, 3))),
            ],
        )?;
        h.apply_both_commit(&req1).await?.expect("initial atomic commit succeeds");
        h.restart_sm_from_snapshot_and_log()?;

        // CAS mismatch, prefix conflict, wrong revision, wrong epochs, wrong tenant -> identical TerminalKind::Rejected.
        let op_cas = Uuid::new_v4();
        let req_cas = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            2,
            op_cas,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            2,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![
                update("refs/heads/other", None, Some(oid(GitObjectFormat::Sha1, 4))),
                update("refs/heads/main", Some(oid(GitObjectFormat::Sha1, 99)), Some(oid(GitObjectFormat::Sha1, 5))),
            ],
        )?;
        assert!(!h.apply_both_commit(&req_cas).await?.unwrap().is_committed());

        let op_prefix = Uuid::new_v4();
        let req_prefix = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            3,
            op_prefix,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            2,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![update("refs/heads/main/sub", None, Some(oid(GitObjectFormat::Sha1, 6)))],
        )?;
        assert!(!h.apply_both_commit(&req_prefix).await?.unwrap().is_committed());

        let op_rev = Uuid::new_v4();
        let req_rev = request(
            repo,
            tenant,
            issuer,
            4,
            op_rev,
            GitObjectFormat::Sha1,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/rev", None, Some(oid(GitObjectFormat::Sha1, 7)))],
        );
        assert!(!h.apply_both_commit(&req_rev).await?.unwrap().is_committed());

        let op_tenant = Uuid::new_v4();
        let req_tenant = request(
            repo,
            Uuid::new_v4(),
            issuer,
            5,
            op_tenant,
            GitObjectFormat::Sha1,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/tenant", None, Some(oid(GitObjectFormat::Sha1, 8)))],
        );
        assert!(!h.apply_both_commit(&req_tenant).await?.unwrap().is_committed());

        let op_format = Uuid::new_v4();
        let req_format = request(
            repo,
            tenant,
            issuer,
            6,
            op_format,
            GitObjectFormat::Sha256,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/fmt", None, Some(oid(GitObjectFormat::Sha256, 8)))],
        );
        assert!(!h.apply_both_commit(&req_format).await?.unwrap().is_committed());

        let op_hist = Uuid::new_v4();
        let req_hist = request(
            repo,
            tenant,
            issuer,
            7,
            op_hist,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/hist", None, Some(oid(GitObjectFormat::Sha1, 8)))],
        );
        assert!(!h.apply_both_commit(&req_hist).await?.unwrap().is_committed());

        // Deleting active head with HeadUpdate::Keep fails parity cleanly.
        let op_head = Uuid::new_v4();
        let req_head = request(
            repo,
            tenant,
            issuer,
            8,
            op_head,
            GitObjectFormat::Sha1,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/feature", Some(oid(GitObjectFormat::Sha1, 2)), None)],
        );
        assert!(!h.apply_both_commit(&req_head).await?.unwrap().is_committed());

        // Idempotent replay of op1 + op_cas, plus DigestConflict refusal.
        h.restart_sm_from_snapshot_and_log()?;
        h.apply_both_commit(&req1).await?.unwrap();
        h.apply_both_commit(&req_cas).await?.unwrap();
        let conflict = request(
            repo,
            tenant,
            issuer,
            1,
            op1,
            GitObjectFormat::Sha1,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha1, 42)))],
        );
        assert_eq!(h.apply_both_commit(&conflict).await?, Err(RefStoreError::DigestConflict));

        // Cancel committed op1 preserves Committed terminal; cancel unregistered seq9 blocks late commit.
        h.apply_both_cancel(req1.identity()).await?;
        let req_late = request(
            repo,
            tenant,
            issuer,
            9,
            Uuid::new_v4(),
            GitObjectFormat::Sha1,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/late", None, Some(oid(GitObjectFormat::Sha1, 9)))],
        );
        h.apply_both_cancel(req_late.identity()).await?;
        assert!(matches!(h.apply_both_commit(&req_late).await?, Err(RefStoreError::Cancelled { .. })));

        h.assert_version_and_lookup_parity(
            repo,
            tenant,
            &[op1, op_cas, op_prefix, op_rev, op_tenant, op_format, op_hist, op_head],
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("atomic parity test timed out")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn accepted_subset_pg_and_raft_sm_contract_parity() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut h = DualHarness::new(pool.clone());
        let issuer = Uuid::new_v4();
        let history = Uuid::new_v4();
        let init = gate(repo, tenant, GitObjectFormat::Sha1, history, "refs/heads/main");
        h.apply_both_init(&init).await?;

        // Mixed batch: valid alpha, bad CAS beta, colliding alpha/child, valid tag ok + Retarget.
        let op1 = Uuid::new_v4();
        let req1 = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            1,
            op1,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            1,
            HeadUpdate::Retarget(ref_name("refs/heads/alpha")),
            CommitMode::AcceptedSubset,
            vec![
                update("refs/heads/alpha", None, Some(oid(GitObjectFormat::Sha1, 1))),
                update("refs/heads/beta", Some(oid(GitObjectFormat::Sha1, 9)), Some(oid(GitObjectFormat::Sha1, 2))),
                update("refs/heads/alpha/child", None, Some(oid(GitObjectFormat::Sha1, 3))),
                update("refs/tags/ok", None, Some(oid(GitObjectFormat::Sha1, 4))),
            ],
        )?;
        let r1 = h.apply_both_commit(&req1).await?.unwrap();
        assert!(r1.is_committed());
        h.restart_sm_from_snapshot_and_log()?;

        // All-rejected subset batch must produce identical Rejected terminal + zero revision advance.
        let op2 = Uuid::new_v4();
        let req2 = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            2,
            op2,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            2,
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            vec![
                update("refs/heads/alpha/sub", None, Some(oid(GitObjectFormat::Sha1, 5))),
                update("refs/heads/missing", Some(oid(GitObjectFormat::Sha1, 7)), Some(oid(GitObjectFormat::Sha1, 6))),
            ],
        )?;
        let r2 = h.apply_both_commit(&req2).await?.unwrap();
        assert!(!r2.is_committed());

        // Replay both committed and all-rejected terminals after snapshot restart.
        h.restart_sm_from_snapshot_and_log()?;
        h.apply_both_commit(&req1).await?.unwrap();
        h.apply_both_commit(&req2).await?.unwrap();

        let conflict = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane(),
            1,
            op1,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
            1,
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            vec![update("refs/heads/alpha", None, Some(oid(GitObjectFormat::Sha1, 88)))],
        )?;
        assert_eq!(h.apply_both_commit(&conflict).await?, Err(RefStoreError::DigestConflict));
        h.assert_version_and_lookup_parity(repo, tenant, &[op1, op2]).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("accepted-subset parity test timed out")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}
