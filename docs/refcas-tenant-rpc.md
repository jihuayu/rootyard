# 租户作用域 mTLS Raft RPC、ReadIndex 与有界流式协议（`#150`）

> **Status**: Experimental standalone crate library & test qualification slice (`crates/refcas-log/**`, `Refs #150`, `Refs #149`). Online Rootyard gateway wiring (`src/ref_store`, `src/sharding`, `src/git_http/process.rs`), PostgreSQL event projection (`#117`), and production service cutover (`#148`) are NOT yet wired in this increment; **Issue `#150` and Issue `#149` remain `OPEN`**.

## 1. 模块边界与严格隔离

本交付严格隔离于独立实验 crate `crates/refcas-log/**`（零根 `Cargo.lock` / `Cargo.toml` 变更、零 PostgreSQL migration、零 Redis/PG ref 回落、零 `mod.rs`、所有新增/修改 Rust 子模块均 `< 500` 行）：

- `crates/refcas-log/src/mtls/tenant_san.rs` + `crates/refcas-log/src/mtls.rs`：TLS 1.3 双向认证与 X.509 SAN 租户/组作用域解析。
- `crates/refcas-log/src/tenant_rpc.rs` + `crates/refcas-log/src/tenant_rpc/{types,server,client}.rs`：租户作用域 mTLS RPC 协议、`ReadIndex` 线性化屏障、结构化 `LeaderRedirect`、有限重连 deadline 与权威 epoch fail-closed 围栏。
- `crates/refcas-log/src/streaming.rs`：有界 Tokio `mpsc` 背压、信用窗口流控、逐帧与整条流字节上限、慢消费者超时取消及 RAII `TrackedChunk` 内存释放，并禁止大字节（`> 256 KiB` 或原始 Git `PACK` / LFS payload）写入 Raft WAL。
- `crates/refcas-log/tests/tenant_mtls_rpc.rs` + `crates/refcas-log/tests/helpers/tenant_cluster.rs`：三节点真 mTLS OpenRaft 集群与故障/背压集成验证。

## 2. 证书身份、Role 隔离与 Bearer Token 校验

1. **Disjoint SAN 身份**：
   - 集群节点间复制证书仅允许 `raft-node-<node_id>.refcas.internal` DNS SAN（`PeerIdentity::Node(node_id)`），禁止携带租户 URI SAN。
   - 租户 RPC 客户端证书必须同时携带 `raft-client-tenant-<tenant_uuid>.raft.internal` DNS SAN 与精确绑定租户/组/能力的 URI SAN：`urn:rootyard:refcas:tenant:<tenant_uuid>:group:<group_id>:scope:<cap1+cap2>`（能力仅限显式窄集合 `read | write | stream | admin`，禁止 `*`/`all`/`nil` UUID）。
   - `MtlsServer::accept_tenant` 仅接受 `TenantCertScope`，拒绝集群节点证书、旧版无作用域 `raft-client.refcas.internal` 证书、伪造 CA、DNS/URI 不一致或混淆角色的证书；`MtlsServer::accept` 反向拒绝租户证书连接内部节点端口。
2. **拒绝宽 Token**：
   - 每个 `TenantRpcRequest` 携带 `bearer_token`，必须匹配严格窄格式 `ryt1;tenant=<uuid>;group=<group>;auth=<authority_id>;cap=<cap>` 并与 X.509 证书作用域、`authority_id` 及操作所需最小能力一致。
   - 空字符串、通配符 `*`、多能力拼接、`all`、`global`、`unscoped` 等宽 token 返回 `TenantRpcErrorCode::WideTokenRejected`；跨租户复用或错误 group 分别返回 `CrossTenantDenied` / `WrongGroup`。

## 3. ReadIndex、`LeaderRedirect`、有界故障与 Epoch 隔离

- **跟随者线性化读与安全重定向**：对 follower 发起 `ReadIndex` / `LinearizableGet` / `ProposeKv` / `StreamCompute` 时，经校验身份与 realm epoch 后由 `raft.ensure_linearizable()` 返回结构化 `LeaderRedirect { leader_id, leader_addr, raft_term }`；`TenantRpcClient` 在调用方原始 `deadline` 剩余预算内（`max_redirects` 上限内）对 `node_dns_name(leader_id)` 校验证书并完成 `ReadIndex` 屏障，保证 `last_applied >= read_log_id`。
- **陈旧 Epoch Fail-Closed 与 Term 隔离**：每次请求核验 `RealmEpoch { tenant_id, group_id, authority_id, history_id, group_epoch, storage_generation }`。任何 `authority_id` / `history_id` 轮换、`group_epoch` 失配、错误 `group_id` 或已关闭租户均返回对应确定性错误码；Raft `raft_term` 仅用于连接/路由重定向提示，**永不改变或替代业务 `storage_generation`**（误把 `raft_term` 当作 `storage_generation` 将被 `StaleStorageGeneration` 拒绝）。
- **无 PG/Redis 回落**：隔离少数派或超时连接在 `quorum_timeout` / caller `deadline` 内有界返回 `QuorumUnavailable` / `DeadlineExceeded`，绝不读取陈旧投影或回落到 PostgreSQL / Redis。

## 4. 有界流式协议与大字节入日志围栏

- **严格上限**：`DEFAULT_CHANNEL_CAPACITY = 4`、`MAX_CHANNEL_CAPACITY = 16`、`MAX_STREAM_FRAME_BYTES = 64 KiB`、`MAX_STREAM_TOTAL_BYTES = 4 MiB`、`MAX_RAFT_PROPOSAL_BYTES = 256 KiB`。
- **背压与确定性释放**：服务端通过 `mpsc::channel(channel_capacity)` 与窗口信用 `StreamCredit` 限制在途帧数；慢消费者或中断触发 `write_deadline_ms` / `stream_deadline_ms` 取消，关闭 `mpsc::Receiver` 停止生产者并由 `TrackedChunk::drop` 将 `BufferedByteTracker::live_bytes` 清零。
- **`#149` 快照安装文档澄清**：`crates/refcas-log/README.md` 已同步补充区分 pre-commit 回滚（未提交文件由 `StagingCleanupGuard` 清理并恢复旧快照）与 commit/`SnapshotInstallPostCommitSync` 不确定错误（可能已写入新 active metadata，保留持久文件且不承诺回滚，需通过重读 metadata 确认）。

## 5. 验证入口

- Standalone crate checks: `cargo fmt --manifest-path crates/refcas-log/Cargo.toml --all -- --check`、`cargo clippy --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets -- -D warnings`、`cargo test --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets`（`.github/workflows/refcas-tenant-rpc.yml`）。
- Offline Python contracts: `python3 -m unittest tests.test_refcas_tenant_rpc_contracts`（由 `.github/workflows/ci.yml` 自动发现执行）及 `python3 scripts/check_design_docs.py`。
