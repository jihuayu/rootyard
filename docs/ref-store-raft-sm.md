# RefStore 确定性 Raft 状态机与幂等 CAS 契约（`#116`）

**Status**: In Progress / Ref-CAS state-machine library slice (`#116`, PR under verification). Does not run multi-node `openraft` RPC/network runtime or asynchronous PostgreSQL event projection (`#117`).

## 实现位置

- 状态机入口与子模块：`src/ref_store/core/state_machine.rs` + `src/ref_store/core/state_machine/`（每子模块 `< 480` 行）
  - `wire.rs` / `commands.rs` / `response.rs`：带 `#[serde(deny_unknown_fields)]` 的确定性命令、响应与类型化错误。
  - `state.rs` / `snapshot.rs`：全 `BTreeMap` 有序内存表与带 SHA-256 校验和的 `RefCasSnapshot`（覆盖 gates、refs、`cancel_cutoff`、取消墓碑、终态与操作记录、publication decisions、snapshot/pin 租约、retention roots、artifact holds 与配额计数）。
  - `apply_refs.rs` / `apply_commit.rs`：`InitializeGate`、`SetRepositoryLane`、`BeginOperation`、`Cancel`、`AdvanceCancelCutoff` 与 `CommitRefs`（`CommitMode::Atomic` + `CommitMode::AcceptedSubset`）。
  - `apply_decisions.rs` / `apply_pins.rs` / `apply_roots.rs` / `apply_holds.rs`：单次授权决策、逻辑时钟驱动的 pin 租约、持久根与 hold 保护约束。
  - `machine.rs`：`RefCasStateMachine` 门面，`apply` / `apply_bytes` / `recover_entries` / `snapshot` / `restore` 与线性化查询接口。
- 单元测试（无 PG）：`tests/ref_store_raft_sm.rs`（含 `tests/raft_sm_support/`）。
- PG 与 Raft 状态机双端契约同测：`tests/ref_store_core_support/raft_sm_parity.rs`（接入 `tests/ref_store_core.rs`，使用真实 PostgreSQL schema 与 `RefCasStateMachine` 同序执行同一组契约用例并逐字段核验 `CommitTerminal`、`OperationRecord`、`CoreGateVersion` 与 `CancelReceipt`）。

## 确定性边界与不变量

1. **`apply` 内零外部副作用**：状态转移不启动 Git 子进程、不访问 Blob 存储、不连接 PostgreSQL，也不读取系统本机时钟（租约、decision `not_after_tick` 与过期比较仅使用日志条目携带的 `logical_tick` 与单调 `logical_clock_floor`）。
2. **失败无部分写入**：任何返回 `Err(StateMachineError)` 的 `apply` / `apply_bytes` 对状态完全回滚，不改变 `state_digest()` 或 `last_applied`。
3. **幂等与身份校验**：已终态操作重放优先于新闸门/生命周期校验返回原 `CommitTerminal`；同 `operation_id` 不同摘要拒绝并返回 `DigestConflict`；提交成功或拒绝后的终态均可通过 `query_operation` 与快照/日志恢复继续查询。
4. **`Cancel` 与 `cancel_cutoff`**：先到取消生成不可覆盖墓碑（含 `OperationState::Cancelled` 与关闭 `Open` 决策）；对已提交操作发 `Cancel` 只写取消墓碑并保持原 `Committed` 终态与事件流不变；`AdvanceCancelCutoff` 单调推进并可裁剪 `<= cancel_cutoff` 的旧取消墓碑，快照恢复后继续阻断低序号重试。
5. **非重叠配额与 hold 保护**：处于 `Active` 状态的 `RootRecordSm` 绑定的 `hold_id` 拒绝 `RetireHoldBatch`，直至 `ReleaseRoot` 执行后方可退休，且已释放的 `root_id` 永久保留 release tombstone，不可重用。
