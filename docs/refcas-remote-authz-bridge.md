# Ref-CAS Remote Authorization Bridge, Signed Grants & Drain Barriers (Refs #152)

> **Status**: Control-plane state machine, signed decision grant verifier, PostgreSQL `OPEN -> CLOSING` bridge helpers, and linearizable Raft `ReadIndex` revocation drain barriers (`Refs #152`). **Issue `#152` remains `OPEN`** until live HTTP gateway/publication-service production cutover and downstream consumer wiring are completed.

## 1. Security & Determinism Guarantees

1. **PG `OPEN -> CLOSING` Projection & Monotonic `close_scope` / `authz_floor`**:
   - PostgreSQL `ref_store_decision_scopes` transitions (`state = 'CLOSING'`, supporting all 14 migration-144 `scope_kind` values) project through [`load_closing_scopes_from_pg`](../src/ref_store/projector/remote_authz_bridge.rs) and [`plan_close_scope_commands`](../src/ref_store/projector/remote_authz_bridge.rs) into [`CloseAuthScopeCommand`](../src/ref_store/core/state_machine/commands.rs) entries applied inside [`RefCasStateMachine`](../src/ref_store/core/state_machine/machine.rs).
   - Scope lifecycles (`Open -> Closing -> Closed`) and monotonic `authz_floor` are strictly non-decreasing: any downgrade (`LifecycleRegression` or `AuthzFloorRegression`) fails closed without mutating state.
   - Closed floors and `(decision_id -> scope_dependencies)` indexes are serialized cleanly inside [`RefCasSnapshot`](../src/ref_store/core/state_machine/snapshot.rs) and survive snapshots, WAL replay, and process crashes.

2. **Versioned Cryptographically Signed Decision Grants**:
   - [`mint_signed_decision_grant_from_pg`](../src/ref_store/projector/remote_authz_pg.rs) mints a [`SignedDecisionGrant`](../src/ref_store/projector/remote_authz_grant.rs) **only** after verifying a committed `OPEN` `ref_store_publication_decisions` row, absence of any matching `ref_store_decision_cancellations` tombstone, committed `ref_store_decision_refs` verdicts, and `OPEN` status across every row in `ref_store_decision_dependencies` joined against `ref_store_decision_scopes`.
   - Every grant binds domain-separated HMAC-SHA256 (`rootyard/ref-store/remote-decision-grant/v1`), explicit `key_id`, retired-key exclusion + key rotation (`DecisionGrantKeyring::rotate_key`), explicit non-wildcard service mTLS SAN (`raft-bridge-*` / `raft-client-tenant-*`), full realm (`tenant_id`, `repository_id`, `group_id`, `group_epoch`, `history_incarnation`, `authority_epoch`, `authz_epoch`), `base_revision`, all 10 committed decision digests, `required_holds`, and logical tick `not_after_tick`.
   - [`verify_signed_decision_grant`](../src/ref_store/projector/remote_authz_grant.rs) rejects forged MACs, retired keys, cross-domain/cross-incarnation/cross-service replay, and expired grants before producing [`InstallScopedDecisionCommand`](../src/ref_store/core/state_machine/commands.rs).
   - Once a dependency scope transitions to `CLOSING` / `Closed`, new late grants are rejected (`ScopeClosingOrClosed`) and pre-installed open decisions referencing that closed scope fail commit (`AuthzFloorViolation` / `ScopeClosingOrClosed`), while exact identical replays remain idempotent and unrelated `OPEN` scopes on the same repository proceed normally.

3. **Same-Log `Cancel` / `CommitRefs` Ordering & `ReadIndex` Drain Barriers**:
   - `Cancel`, `InstallScopedDecision`, `CloseAuthScope`, and `CommitRefs` serialize through the same ordered Raft log. PG cancellations project cleanly via [`load_decision_cancellations_from_pg`](../src/ref_store/projector/remote_authz_bridge.rs) and [`build_cancel_command_from_pg`](../src/ref_store/projector/remote_authz_bridge.rs).
   - [`evaluate_revocation_drain_barrier`](../src/ref_store/projector/remote_authz_bridge.rs) and [`await_drain_before_revocation_ack`](../src/ref_store/projector/remote_authz_bridge.rs) require [`AuthoritySourceKind::RaftReadIndexQuorum`](../src/ref_store/projector/session_fence.rs) (rejecting `PgRefsProjection`, `RedisCache`, and `UnverifiedLocalReplica` with `AuthorityViolation`), verify `applied_log_index >= read_log_index.max(close_log_index)`, and return [`RevocationDrainStatus::DrainedAndConfirmed`](../src/ref_store/projector/remote_authz_bridge.rs) **only** when zero open decisions and zero pending operations remain for that scope. Partitions or quorum loss stay explicit `UnknownQuorumLoss` (`can_ack_revocation() == false`).

4. **Clock Independence & Storage Boundaries**:
   - State-machine apply rules and grant expiry (`not_after_tick`) use monotonic logical ticks only; PostgreSQL `TIMESTAMPTZ` / session `TIME ZONE` shifts never affect Raft apply outputs or snapshot digests.
   - Zero large pack/object bytes are written to Raft or Redis, and zero cross-DB distributed transactions are assumed between PostgreSQL and Raft.

## 2. Verification & CI

- Offline unit + contract checks:
  - `cargo test --locked --lib ref_store::core::state_machine`
  - `cargo test --locked --lib ref_store::projector`
  - `cargo test --locked --test ref_store_remote_authz_bridge`
  - `python3 -m unittest tests.test_remote_authz_bridge_contracts`
- Multi-process 3-node mTLS `raft-node` + PostgreSQL 17 E2E qualification (`.github/workflows/refcas-remote-authz.yml`):
  - `cargo test --locked --test ref_store_remote_authz_bridge -- --ignored --test-threads=1`
