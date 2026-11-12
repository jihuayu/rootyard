# Rootyard

Rootyard 是面向标准 Git 客户端、Forge 协作与 Agent 工作区的 Rust 项目。目前尚未发布，正在推进 **Blob-only 轻量单机与 Raft Ref-CAS 分布式架构**（总任务 [#105](https://github.com/jihuayu/rootyard/issues/105)）。

## 当前运维入口与支持契约矩阵（Current Operational Contract）

新部署与日常运维请以本表及对应手册为准；文末早期的分阶段记录仅供历史追溯，不代表当前代码边界：

| 维度 | 当前代码真实契约（`schema 147`） | 明确未交付 / 禁止误用边界 |
| --- | --- | --- |
| **运行入口与存储权威** | Linux 专用进程：默认 `rootyard serve` 使用本地私有卷 `ROOTYARD_DATA_DIR`（默认 `gitfs`，可选 `pando`；单目录单写进程、非 `noexec`、需容器 `init` 回收子进程与可读 `/proc/self/stat`，Git >= 2.43，PostgreSQL 17）。显式候选 `rootyard serve-blob` 基于 `schema 147` `pg_refstore` + OpenDAL v1 Blob（`s3`，`blob-azblob` 仅编译）+ 私有 `0700` `ROOTYARD_SCRATCH_DIR` 提供 Smart HTTP 与只读浏览（可选 `ROOTYARD_SESSION_KEYRING` `rs1` 会话读下界，[#174](https://github.com/jihuayu/rootyard/issues/174) 部分实现）。辅助进程含 PG-only `rootyard worker` / `worker-once` 与只读 `rootyard serve-mirror`。对外 Git 仅支持 Smart HTTP/HTTPS（支持 `sha1` 与 `sha256` 对象格式）。详见 [运行手册](docs/operations.md)。 | 默认 `serve` 尚未切换到 Blob-only 单机（[#148](https://github.com/jihuayu/rootyard/issues/148) / [#110](https://github.com/jihuayu/rootyard/issues/110) 未完成）；LFS/PR/Workspace/CI 尚未整体迁入 `serve-blob`（[#118](https://github.com/jihuayu/rootyard/issues/118)、[#119](https://github.com/jihuayu/rootyard/issues/119)、[#145](https://github.com/jihuayu/rootyard/issues/145)–[#147](https://github.com/jihuayu/rootyard/issues/147)）；不提供 Git SSH 传输；分布式 Raft Ref-CAS 运行时与远程授权桥未交付（`crates/refcas-log` 仅为隔离实验 crate）。 |
| **数据库 Schema 与离线备份恢复** | 当前迁移基线为 **`schema 147`**（`migrations/001_initial.sql`..`147_ref_store_serving_operations.sql`，内嵌 `schema/147_*`）。`rootyard backup <PATH> --offline` 按源库自动选择归档格式：无 `pg_refstore` 服务仓时生成 **`format 21`（`schema 147`）**（PG 快照 + 本地卷 + 已水化 LFS + Pando 加密闭包，**不含** OpenDAL Blob 字节）；存在 `pg_refstore` 服务仓时强制生成 **`format 22`（`schema 147`）**（经 [#169](https://github.com/jihuayu/rootyard/issues/169) 源账本逐项校验后打包 PG 快照 + 同物理后端 OpenDAL Blob `.pack`/`.idx` 闭包）。`rootyard restore <PATH> --isolated --trust-backup` 要求全新空 PostgreSQL 17 库、不存在的目标目录及**完全一致的生成二进制**（或显式单次升级参数：`--allow-legacy-schema007` 对应 `format 4`，`--allow-legacy-schema130`..`--allow-legacy-schema143` 对应 `formats 6..=19` 并会话内升级至 `schema 147`；`format 5`/`schema 060` 与 `format 20`/`schema 144` 保持冻结且无 `--allow-legacy-schema*` 参数）。恢复自动轮换 `cluster_authority` incarnation 并吊销已签发 CI checkout 凭证、浏览器会话与活跃租约。详见 [备份与恢复契约](docs/backup-restore.md)。 | 不是在线复制、自动故障切换、PITR 或零丢失保证。`format 22` 仅覆盖同物理 `BlobBackendIdentity` 上的纯 `pg_refstore` pack/idx 闭包（拒绝混合后端，不含 LFS/Workspace/事件全内容 Blob 闭包 [#120](https://github.com/jihuayu/rootyard/issues/120)，不支持改写到异构后端或中断续传）。 |
| **多用户共享、5 级 RBAC 与组织/团队** | 支持个人 owner、组织（`/api/orgs/*`、`/web/organizations/*`）、组织团队与仓库直接协作者/团队共享，统一执行 5 级角色层级（`read` < `triage` < `write` < `maintain` < `admin`）。私有仓库与组织对非成员一律返回 `404`（防探测），已认证成员角色或令牌权限不足返回 `403`；严格区分调用者 `actor.id` 与仓库归属 `tenant_id`。详见 [组织管理 Web 契约](docs/organization-web-ui.md)。 | 组织改名/删除、仓库跨主体安全 Ownership Transfer（[#85](https://github.com/jihuayu/rootyard/issues/85)）及用量/恢复管理后台 UI（[#87](https://github.com/jihuayu/rootyard/issues/87) 其余切片）尚未实现。 |
| **精细化 PAT、浏览器会话与认证限流** | API Token 支持仓库/命名空间动作收窄（`tokens.is_restricted`、`token_repository_scopes`、`token_namespace_scopes`）：Scope 只收窄不扩权，空授权集拒绝一切仓库读写并禁止创建仓库/组织；`token_scopes` 与 `authorize_publication_window` 在事务内对当前调用凭证行（`tokens` 行 `t`：`token_scopes` 中的 API Token，或 Git 引用发布中的 API / `browser` Token）加 `FOR SHARE` 锁并用 `clock_timestamp()` 校验过期，与并发吊销/收窄串行化。Web 登录（`POST /web/login`）仅接受**非受限** API Token 置换 `HttpOnly; SameSite=Strict` 的 `rootyard_session` + `rootyard_csrf`（受限父 Token 登录返回 `403`）；Web 写操作强制同源 `Origin` 与 `X-CSRF-Token` 并拒绝环境 `Basic` 认证，父 API Token 吊销或过期即刻使子会话失效。`/web/login` 与 `/api/auth/whoami` 在取库连接前按真实 TCP `ConnectInfo` 限流（`ROOTYARD_AUTH_ADMISSION_*`）。详见 [PAT Scope](docs/token-scopes.md) 与 [认证准入](docs/auth-admission.md)。 | CLI 仍签发传统非受限 Token；不支持受限浏览器子会话继承；未实现 OIDC/SSO、MFA/WebAuthn、账号锁定或跨副本/信任代理头（`X-Forwarded-For`）分布式限流（[#84](https://github.com/jihuayu/rootyard/issues/84) 仍开放）。 |
| **TLS、反向代理与数据库传输** | 应用进程不直接终止 HTTP TLS：非 `localhost` / `127.0.0.1` 暴露必须在受控反向代理终止 HTTPS，由代理覆盖并转发受信 `X-Forwarded-Proto: https`（非回环明文请求将被浏览器登录拒绝 `403` 且不下发 `Secure` Cookie），禁止记录 `Authorization` 头、Cookie 或含凭据 URL。PostgreSQL TLS 必须同时配置 `sslmode=require` 与 `ROOTYARD_PG_CA_PEM`（启用证书链与主机名校验，可选 `ROOTYARD_PG_CLIENT_CERT_PEM` / `ROOTYARD_PG_CLIENT_KEY_PEM` mTLS；单独 `sslmode=require` 缺 CA 或配 CA 却降级 `sslmode` 均启动拒绝）。详见 [运行手册](docs/operations.md)。 | 切勿将未清洗客户端转发头的服务直接暴露公网；代理超时或断连仍可能令进行中的 Git push 结果呈 `unknown`（需先 fetch/核对远端 refs 再决定重试）。 |
| **破坏性 GC、远端删除与配额** | **所有远端对象/后台物理删除默认关闭**：OpenDAL `BlobStore::delete` 固定返回 `DeleteDisabled`（拒绝 `ROOTYARD_BLOB_DELETE=exact-locator`）；后台存储维护 `ROOTYARD_STORAGE_MAINTENANCE` 默认 `false`；Pando 远端包删除需显式 `ROOTYARD_PANDO_REMOTE_DELETE=true`；Workspace 远端检查点物理清理需显式 `ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE=true`。详见 [OpenDAL Blob](docs/opendal-blob.md) 与 [Pando 远端保留](docs/pando-remote-retention.md)。 | **严禁**将单独复制的 PostgreSQL PITR/basebackup 元数据副本指向共享可删对象存储桶（缺外部删除代理与 epoch 隔离，[#77](https://github.com/jihuayu/rootyard/issues/77) 仍开放）；`ROOTYARD_MAX_REPO_BYTES` 仅为准入阈值而非原子硬磁盘配额（[#83](https://github.com/jihuayu/rootyard/issues/83) 仍开放）；[单主机外部 Patroni HA 参考](docs/operations-HA.md) 不提供跨物理机存储 fencing、硬件看门狗合格证或本地 Git 卷复制。 |

## 目标架构设计（Target Architecture — 进行中）

| 职责 | 轻量单机 | 分布式 |
| --- | --- | --- |
| 应用 | 一个 Rust 进程，内置可靠 worker | 多个计算/API 节点，可拆 worker |
| Git 元数据 | 进程内调用 PgRefStore，持久化在 PostgreSQL | 开源 Raft 支撑的 Ref-CAS 服务 |
| 用户、权限、Issue/PR、可靠业务任务 | PostgreSQL | PostgreSQL |
| 内容字节 | Apache OpenDAL Blob | 同一 OpenDAL Blob 契约 |
| 缓存与唤醒 | 有界内存 | Redis，可加本地缓存 |
| 本地 Git 视图 | 可删除、可重建的临时计算目录 | 同左 |

pack、idx、manifest、LFS、Workspace/checkpoint 和备份正文目标全部走 Blob。PG 与 Raft 的数据库/WAL 使用各自持久存储协议，普通 Blob API 不充当 WAL 设备。Redis 和内存不是 refs、权限、任务或保留根的唯一持久来源。

单机不强制 Redis、Raft、Kafka、Vault、FUSE 或集群控制器。分布式仍依赖业务 PG；Raft 不可用时禁止自动改写 PG refs。每仓只有一个元数据写入权威。

## 实现状态与路线导航

上述目标设计表**不是已发布功能表**。现有默认 `serve` 仍走持久 GitFS（可选 Pando），显式候选 `serve-blob`、RefStore 核心账本与 `format 22` 配对归档已有分项验收，但尚未替换默认入口；Raft 运行时、远程授权桥和全业务生产者接入仍待实现。

项目尚未发布，不承诺跨开发阶段自动就地升级或跨版本回滚；全新安装与当前 `schema 147` 契约下的崩溃恢复及隔离备份恢复见上方运维矩阵。

- [运行与恢复手册](docs/operations.md) · [离线备份与隔离恢复契约](docs/backup-restore.md) · [单主机 Patroni HA 参考与边界](docs/operations-HA.md)
- [当前架构与数据归属](docs/architecture.md) · [两种部署形态及协议图](docs/design/architecture-diagrams.md) · [状态服务详细契约](docs/design/12-state-services.md)
- [实施拆分、依赖和验收](docs/design/implementation-plan.md) · [实际实现与未完成边界](docs/design/implementation-status.md) · [新旧任务映射](docs/design/issue-map.md)
- [开发手册](docs/development.md) · [完整文档目录](docs/README.md) · [历史任务交付记录](docs/registered-task-delivery.md) · [GitHub 实施总任务 #105](https://github.com/jihuayu/rootyard/issues/105)

Licensed under Apache-2.0.

---

## Historical Incremental Milestones (Preserved Scope — Not Current Contract)

> **Historical Note:** The sections below preserve the original milestone notes and verification pointers from earlier increments (`schema 002`–`schema 060` and lab binaries). Where early slices originally lacked sharing, organizations, PRs, LFS, CI, Web UI, or `schema 147` (`format 21` / `format 22`) backups, refer to **Current Operational Contract** at the top of this file for the active codebase behavior.

### Historical increment: Phase-two reliability (`schema 002`–`003` baseline)

GitFS writes retain durable operation evidence and post-receive receipts, with explicit unknown/recovering states. PostgreSQL atomically stores audit evidence and durable events; fenced local consumers maintain audit and ref projections. This does not replace Git refs with PostgreSQL refs or enable HA. See [reliability contract and operations](docs/reliability.md) and [phase-two verification](docs/phase-two-verification.md).

Run the added tests against an isolated test database:

```sh
export ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test
cargo test --test outbox -- --ignored
python3 tests/reliability.py --binary target/debug/rootyard --report test-results/reliability.json
```

Offline backup and isolated restore originated in this phase-two slice; current binaries enforce `format 21` / `format 22` on `schema 147`. See [the backup/restore contract](docs/backup-restore.md) and [historical integrated verification evidence](docs/integration-verification.md) before using the maintenance commands. This is not online replication or a zero-loss guarantee.

### Historical increment: Explicit incident recovery, workers and metrics

The follow-on recovery increment supports offline inspection and explicit acknowledgment of an unknown-push audit gap without rewriting its outcome. It preserves immutable history, establishes an observed new-generation snapshot, and fences old ref-index effects. Read [the maintenance contract](docs/manual-recovery.md) before use. Optional [loopback-only metrics](docs/metrics.md) expose fixed-cardinality service health and durable backlog without repository or user labels. This is not distributed fencing or a substitute for verified backups.

PG-only `rootyard worker` processes can drain durable deliveries independently of Git storage. Optional Redis wake hints are advisory; periodic PostgreSQL scanning remains mandatory. The bounded advisory cache boundary is available with Memory bounds and an optional mature Redis cache/wake adapter; dispatch keeps local Notify/Redis hints and PostgreSQL scanning. Full production cache-consumer wiring (#110) is still pending, and PG/RefStore authority is unchanged. See the [bounded cache/wake contract](docs/state-cache-wake.md). See [cross-process workers](docs/cross-process-workers.md) for role separation, limits, and the separate Kafka profile and limits.

The [Kafka wake adapter](docs/kafka-wakes.md) adds optional hint transport for a controlled local broker. It does not replace PostgreSQL deliveries or provide storage-node takeover.

The backup/recovery and standalone-worker increments are integrated and tested together. See [fresh-restore worker verification](docs/workers-integration-verification.md), including the requirement to keep database-only workers stopped while a restore target is incomplete.

### Historical increment: Initial Issue API slice (`migrations/006`–`007` foundation)

The historical phase-six foundation introduced Issues and comments with bounded keyset pagination, transactional local numbering, explicit token authorization, optimistic `expected_version` CAS, optional bounded `Idempotency-Key` replay on creation, and open/closed state filters (`migrations/006_forge_issues.sql`–`007_forge_idempotency.sql`). At the time that initial slice was written, it covered personal-owner repositories only; later migrations (`009` PRs/reviews/checks/branch-rules, `020` LFS, `030` CI mirrors, `050` 5-role collaborators/teams, `120` organizations, `125` Web UI sessions, `136` scoped PATs, through current `schema 147`) expanded repository collaboration and backup coverage. See [the historical Issue slice contract](docs/forge-issues.md) and [historical populated Forge restore verification (`schema 007` / `format 4` era)](docs/forge-backup-verification.md).

### Historical increment: Exact-commit CI read mirrors

An opt-in `serve-mirror` process can serve CI clones from a separate private local
volume while the primary remains the only writer. Explicit sync uses native Git
transport, validates a complete snapshot, and publishes it atomically. Exact-OID
URLs clone a fixed commit and reject missing data instead of silently building an
old branch value. The mirror checks authoritative PostgreSQL permissions for every
Git request. See [the read-mirror contract](docs/ci-mirror.md) for configuration,
retained pins, verification and current limits. This is not automatic replication,
a CI scheduler, multi-writer support or high availability.

### Standalone lab binary: Workspace foundation experiment

An opt-in `rootyard-workspace-lab` binary tests independent Linux agent directories, fixed base OIDs and local full-copy checkpoints preserving HEAD/index/worktree. It does not change the hosting service or provide FUSE, live capture, remote durability or multi-tenant isolation. Read the [scope, caller-quiescence requirement and recovery limits](docs/workspace-foundation.md) before use.

### Standalone lab binary: Namespace, Git View and cross-repository ChangeSet experiment

An opt-in `rootyard-view-lab` binary tests company Namespace `BaseVector` mounts, deterministic subdirectory history projection with unreachable-object pruning, composite multi-repository task snapshot views, and two-phase cross-repository ChangeSet integration (candidate staging, ordered per-repository ref leases, zero partial updates on conflict, and crash roll-forward recovery). See [the Git View and ChangeSet contract](docs/git-view-foundation.md).


