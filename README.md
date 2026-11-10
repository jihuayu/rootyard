# Rootyard

Rootyard 是面向标准 Git 客户端、Forge 协作与 Agent 工作区的 Rust 项目。目前尚未发布，正在完成 **Blob-only 轻量单机与 Raft Ref-CAS 分布式架构**。

## 当前设计

| 职责 | 轻量单机 | 分布式 |
| --- | --- | --- |

pack、idx、manifest、LFS、Workspace/checkpoint 和备份正文全部走 Blob。PG 与 Raft 的数据库/WAL 使用各自持久存储协议，普通 Blob API 不充当 WAL 设备。Redis 和内存不是 refs、权限、任务或保留根的唯一持久来源。

单机不强制 Redis、Raft、Kafka、Vault、FUSE 或集群控制器。分布式仍依赖业务 PG；Raft 不可用时禁止自动改写 PG refs。每仓只有一个元数据写入权威。

## 实现状态

上述表格是当前实施目标，**不是已发布功能表**。现有默认服务仍走持久 GitFS，可选 Pando 路径也仍在源码中。新的 Blob/RefStore 组件和 roots、decisions、accepted-subset 已有分项验收，但尚未整体接入默认服务；Raft 运行时、远程授权桥和完整业务接入仍待实现。

本轮只整理设计和任务，不改变服务默认配置。项目没有已发布版本，不要求旧 GitFS 导入、旧数据库/备份格式升级或跨版本回滚；必须保留当前格式的崩溃恢复和全新环境备份恢复。

- [当前架构与数据归属](docs/architecture.md)
- [两种部署形态及协议图](docs/design/architecture-diagrams.md)
- [状态服务详细契约](docs/design/12-state-services.md)
- [实施拆分、依赖和验收](docs/design/implementation-plan.md)
- [实际实现与未完成边界](docs/design/implementation-status.md)
- [新旧任务映射](docs/design/issue-map.md)
- [GitHub 实施总任务 #105](https://github.com/jihuayu/rootyard/issues/105)

## 开发与证据

开发工具链、现有服务测试和组件验收见 [开发手册](docs/development.md) 和 [文档目录](docs/README.md)。在 Blob-only 默认部署任务完成前，现有 serve/Compose 入口仍属于旧实现；不能通过修改配置名把它当成新单机部署。

[历史验收记录](docs/registered-task-delivery.md) 继续保留其原有提交、环境和范围。旧架构资料与来源快照仅供追溯，不定义本轮交付目标。新代码的合并和实际验收完成后才关闭相应任务。

Licensed under Apache-2.0.

## Phase-two reliability increment

GitFS writes now retain durable operation evidence and post-receive receipts, with explicit unknown/recovering states. PostgreSQL atomically stores audit evidence and durable events; fenced local consumers maintain audit and ref projections. This does not replace Git refs with PostgreSQL refs or enable HA. See [reliability contract and operations](docs/reliability.md) and [phase-two verification](docs/phase-two-verification.md).

Run the added tests against an isolated test database:

```sh
export ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test
cargo test --test outbox -- --ignored
python3 tests/reliability.py --binary target/debug/rootyard --report test-results/reliability.json
```

Offline backup and isolated restore are available as a phase-two increment. See [the backup/restore contract](docs/backup-restore.md) and [integrated verification evidence](docs/integration-verification.md) before using the maintenance commands. This is not online replication or a zero-loss guarantee.

## Explicit incident recovery and metrics

The follow-on recovery increment supports offline inspection and explicit acknowledgment of an unknown-push audit gap without rewriting its outcome. It preserves immutable history, establishes an observed new-generation snapshot, and fences old ref-index effects. Read [the maintenance contract](docs/manual-recovery.md) before use. Optional [loopback-only metrics](docs/metrics.md) expose fixed-cardinality service health and durable backlog without repository or user labels. This is not distributed fencing or a substitute for verified backups.

PG-only `rootyard worker` processes can drain durable deliveries independently of Git storage. Optional Redis wake hints are advisory; periodic PostgreSQL scanning remains mandatory. The bounded advisory cache boundary is available with Memory bounds and an optional mature Redis cache/wake adapter; dispatch keeps local Notify/Redis hints and PostgreSQL scanning. Full production cache-consumer wiring (#110) is still pending, and PG/RefStore authority is unchanged. See the [bounded cache/wake contract](docs/state-cache-wake.md). See [cross-process workers](docs/cross-process-workers.md) for role separation, limits, and the separate Kafka profile and limits.

The [Kafka wake adapter](docs/kafka-wakes.md) adds optional hint transport for a controlled local broker. It does not replace PostgreSQL deliveries or provide storage-node takeover.

The backup/recovery and standalone-worker increments are integrated and tested together. See [fresh-restore worker verification](docs/workers-integration-verification.md), including the requirement to keep database-only workers stopped while a restore target is incomplete.

## Initial private-owner Issue API

The phase-six foundation adds owner-private Issues and comments with bounded
keyset pagination, transactional local numbering, explicit token authorization
and optimistic update versions. Optional bounded `Idempotency-Key` headers make
Issue/comment creation retries replay the original response. Issue lists support
optional open/closed state filters with number-keyset pagination. This does not add organization sharing, PRs,
LFS, CI or a Web UI. See [the API and integration contract](docs/forge-issues.md).

Private-owner Issues/comments are included in the exact schema008 backup contract, including durable creation retry records. See [populated Forge restore verification](docs/forge-backup-verification.md) for content, numbering, authorization and recovery-state checks after a fresh-cluster restore.

## Exact-commit CI read mirrors

An opt-in `serve-mirror` process can serve CI clones from a separate private local
volume while the primary remains the only writer. Explicit sync uses native Git
transport, validates a complete snapshot, and publishes it atomically. Exact-OID
URLs clone a fixed commit and reject missing data instead of silently building an
old branch value. The mirror checks authoritative PostgreSQL permissions for every
Git request. See [the read-mirror contract](docs/ci-mirror.md) for configuration,
retained pins, verification and current limits. This is not automatic replication,
a CI scheduler, multi-writer support or high availability.

## Workspace foundation experiment

An opt-in `rootyard-workspace-lab` binary tests independent Linux agent directories, fixed base OIDs and local full-copy checkpoints preserving HEAD/index/worktree. It does not change the hosting service or provide FUSE, live capture, remote durability or multi-tenant isolation. Read the [scope, caller-quiescence requirement and recovery limits](docs/workspace-foundation.md) before use.

## Namespace, Git View and cross-repository ChangeSet experiment

An opt-in `rootyard-view-lab` binary tests company Namespace `BaseVector` mounts, deterministic subdirectory history projection with unreachable-object pruning, composite multi-repository task snapshot views, and two-phase cross-repository ChangeSet integration (candidate staging, ordered per-repository ref leases, zero partial updates on conflict, and crash roll-forward recovery). See [the Git View and ChangeSet contract](docs/git-view-foundation.md).

