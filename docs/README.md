# Rootyard 文档

## 设计与架构

- [完整设计目录](design/README.md)
- [实现状态与计划边界](design/implementation-status.md)
- [`6d2f0b8` 主分支验收审计](acceptance/main-6d2f0b8-audit.md)
- [round-2 最终集成交付表（全部 native scope 已验收）](acceptance/round2-delivery.md)
- [架构图与 Mermaid 源文件](design/architecture-diagrams.md)
- [最新分期路线与验收闸门](design/08-roadmap.md)
- [状态服务设计提案（W0 快照/清单/契约/基线）](design/12-state-services.md)
- [原始设计快照](design/source-page.md)
- [ADR 001：当前 GitFS 权威边界](architecture.md)
- [ADR 002：操作证据与可靠事件](reliability.md)

## 运行与实现契约

- [运行与部署](operations.md)
- [HA 参考配置与物理 HA 未闭项（#26/#43/#44）](operations-HA.md)
- [开发与测试、MSRV 1.88 与 fmt/Clippy 门禁工具链](development.md)
- [仓库列表严格键集分页 API](repository-pagination.md)
- [并行开发与模块边界](parallel-development.md)
- [配对离线备份与恢复](backup-restore.md)
- [Schema 134：仓库/租户复合外键与 #90 关系完整性](storage-identity-fks.md)
- [显式事故恢复](manual-recovery.md)
- [指标](metrics.md)
- [跨进程 worker](cross-process-workers.md)
- [Kafka 唤醒适配器](kafka-wakes.md)
- [私有 owner Issue API](forge-issues.md)
- [Pull Request、Review、Check Run、分支保护与原子 Merge](../src/pulls.rs)
- [外部 CI Webhook 签名派发、重试与 PR 自动 CI 编排](../src/webhooks.rs)（含 [040_webhooks.sql](../src/webhooks/040_webhooks.sql)）
- [仓库协作者、团队 5 级 RBAC、禁止自审与分页审计日志 API](../src/members.rs)（含 [050_members_rbac.sql](../src/members/050_members_rbac.sql)）
- [仓库只读浏览、原子多引用 CAS 事务与 SHA-1/SHA-256 双对象格式协商 API](../src/browse.rs)（含 [object_format.rs](../src/browse/object_format.rs)）
- [Git LFS Batch 与流式对象传输网关](../src/lfs.rs)
- [CI source pin、只读镜像、水位 LRU 淘汰、单飞自动回源与跨集群 Runner 队列](ci-mirror.md)（含 [auto_origin.rs](../src/mirror/auto_origin.rs)）
- [服务端 HTML Web UI、Markdown XSS 净化与大文件 UTF-8 截断预览](../src/web.rs)
- [多节点仓库分片、一致哈希路由、Epoch 写屏障、自动故障切换、在线重平衡、RPO/RTO 灾备演练与 1/2/4 节点并发压测基准](../src/sharding.rs)（含 [rebalance.rs](../src/sharding/rebalance.rs)、[benchmark.rs](../src/sharding/benchmark.rs)、[060_sharding_fencing.sql](../src/sharding/060_sharding_fencing.sql)）
- [Workspace 本地、增量同步、远程 CAS 恢复、多仓虚拟 Namespace、按需稀疏 VFS、可写 Namespace 跨仓回写、CoW Overlay 沙箱与断电崩溃窗口恢复实验](workspace-foundation.md)（含 [remote.rs](../src/workspace_lab/remote.rs)、[namespace.rs](../src/workspace_lab/namespace.rs)、[vfs.rs](../src/workspace_lab/vfs.rs)、[writable_view.rs](../src/workspace_lab/writable_view.rs)、[crash_recovery.rs](../src/workspace_lab/crash_recovery.rs)）
- [Namespace、Git View 历史投影策略、签名溯源验签与跨仓 ChangeSet 实验](git-view-foundation.md)（含 [view_lab.rs](../src/view_lab.rs)、[models.rs](../src/view_lab/models.rs)、[namespace.rs](../src/view_lab/namespace.rs)、[projection.rs](../src/view_lab/projection.rs)、[changeset.rs](../src/view_lab/changeset.rs)）
- [Pando 存储、流式 Delta、图遍历、双算子导出、在线迁移/回滚、S3 对象存储、多 Pack 合并、生命周期 KMS 加密与 SHA-1/SHA-256 双对象格式实验](../experimental/pando/README.md)（含 [migration.rs](../src/pando_lab/migration.rs)、[rollback.rs](../src/pando_lab/rollback.rs)、[object_store.rs](../src/pando_lab/object_store.rs)、[repack.rs](../src/pando_lab/repack.rs)、[lifecycle.rs](../src/pando_lab/lifecycle.rs)、[object_format.rs](../src/pando_lab/object_format.rs)）
- [Schema 030 数据库迁移与配对备份基线](../schema/030_catalog.sql)（及 [Schema 050](../schema/050_catalog.sql)、[Schema 060](../schema/060_catalog.sql)）

## 已有验证记录

- [基础 Git](verification.md)
- [第二期可靠性增量](phase-two-verification.md)
- [备份](backup-verification.md)
- [备份与恢复整合](integration-verification.md)
- [事故恢复](recovery-verification.md)
- [恢复后跨进程 worker](workers-integration-verification.md)
- [Issue API](forge-verification.md)
- [Issue/comment 幂等](forge-idempotency-verification.md)
- [Issue 状态过滤](forge-state-filter-verification.md)
- [Forge 备份恢复](forge-backup-verification.md)
- [Workspace](workspace-verification.md)
- [PR、Review、Check Run、分支保护与配对备份测试](../tests/pulls.py)（含 [PR 备份恢复](../tests/backup_pulls.py)）
- [外部 CI Webhook、HMAC-SHA256 投递与自动 PR CI Pin 测试](../tests/webhooks.py)（含 [test_webhooks.py](../tests/test_webhooks.py)）
- [仓库协作者、团队 5 级 RBAC、禁止自审与审计查询测试](../tests/members.py)（含 [test_members.py](../tests/test_members.py)）
- [服务端 HTML Web UI、XSS 防护与浏览器工作流测试](../tests/web.py)（含 [test_web.py](../tests/test_web.py)）
- [多节点仓库分片、Epoch 写屏障、在线重平衡、RPO/RTO 灾备演练与 1/2/4 节点并发压测基准测试](../tests/sharding.py)（含 [test_sharding.py](../tests/test_sharding.py)、[benchmark_tiers.py](../tests/benchmark_tiers.py)、[test_benchmark_tiers.py](../tests/test_benchmark_tiers.py)）
- [仓库只读浏览、原子 Ref 事务与 SHA-1/SHA-256 双对象格式协商测试](../tests/browse.py)（含 [test_object_format.py](../tests/test_object_format.py)）
- [Git LFS 传输与备份完整性测试](../tests/lfs.py)
- [CI Mirror 水位 LRU 淘汰、Pin 释放、单飞自动回源与跨集群 Runner 调度测试](../tests/ci_mirror.py)（含 [test_ci_mirror.py](../tests/test_ci_mirror.py)）
- [Pando 流式 Delta、图遍历、双算子对拍、在线迁移/回滚、S3 Repack、生命周期 KMS 轮转与双对象格式兼容测试](../tests/pando_lab.py)（含 [test_pando_migration.py](../tests/test_pando_migration.py)、[test_pando_repack_object_store.py](../tests/test_pando_repack_object_store.py)、[test_object_format.py](../tests/test_object_format.py)）
- [Workspace 脏清单、忽略规则、增量同步、远程 CAS、多仓虚拟 Namespace、稀疏 VFS、可写 Namespace 跨仓回写、CoW Overlay 沙箱与断电崩溃恢复测试](../tests/workspace.py)（含 [test_workspace_remote_namespace.py](../tests/test_workspace_remote_namespace.py)、[test_workspace_vfs.py](../tests/test_workspace_vfs.py)、[test_workspace_crash_recovery.py](../tests/test_workspace_crash_recovery.py)）
- [Namespace、Git View 长周期历史投影、签名验签与跨仓 ChangeSet 二阶段集成测试](../tests/git_views.py)（含 [test_view_lab.py](../tests/test_view_lab.py)）
- [Schema 060 四级需求端到端验证套件](../tests/e2e_tiers.py)（含 [五级白盒对抗验证](../tests/test_tier5_adversarial.py)）

验证记录是带版本和环境边界的历史结果。设计目标、测试代码存在和某次测试通过是不同状态，请结合对应契约阅读。
