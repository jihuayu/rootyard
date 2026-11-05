# Rootyard 文档

## 设计与架构

- [完整设计目录](design/README.md)
- [实现状态与计划边界](design/implementation-status.md)
- [架构图与 Mermaid 源文件](design/architecture-diagrams.md)
- [最新分期路线与验收闸门](design/08-roadmap.md)
- [原始设计快照](design/source-page.md)
- [ADR 001：当前 GitFS 权威边界](architecture.md)
- [ADR 002：操作证据与可靠事件](reliability.md)

## 运行与实现契约

- [运行与部署](operations.md)
- [开发与测试](development.md)
- [并行开发与模块边界](parallel-development.md)
- [配对离线备份与恢复](backup-restore.md)
- [显式事故恢复](manual-recovery.md)
- [指标](metrics.md)
- [跨进程 worker](cross-process-workers.md)
- [Kafka 唤醒适配器](kafka-wakes.md)
- [私有 owner Issue API](forge-issues.md)
- [Pull Request、Review、Check Run、分支保护与原子 Merge](../src/pulls.rs)
- [外部 CI Webhook 签名派发、重试与 PR 自动 CI 编排](../src/webhooks.rs)（含 [040_webhooks.sql](../src/webhooks/040_webhooks.sql)）
- [仓库协作者、团队 5 级 RBAC、禁止自审与分页审计日志 API](../src/members.rs)（含 [050_members_rbac.sql](../src/members/050_members_rbac.sql)）
- [仓库只读浏览与原子多引用 CAS 事务 API](../src/browse.rs)
- [Git LFS Batch 与流式对象传输网关](../src/lfs.rs)
- [CI source pin、只读镜像与水位 LRU 淘汰](ci-mirror.md)
- [服务端 HTML Web UI、Markdown XSS 净化与大文件 UTF-8 截断预览](../src/web.rs)
- [多节点仓库分片、一致哈希路由、Epoch 写屏障与自动故障切换](../src/sharding.rs)（含 [060_sharding_fencing.sql](../src/sharding/060_sharding_fencing.sql)）
- [Workspace 本地、增量同步、远程 CAS 恢复、多仓虚拟 Namespace 与按需稀疏 VFS 实验](workspace-foundation.md)（含 [remote.rs](../src/workspace_lab/remote.rs)、[namespace.rs](../src/workspace_lab/namespace.rs)、[vfs.rs](../src/workspace_lab/vfs.rs)）
- [Pando 存储、流式 Delta、图遍历、双算子导出、在线迁移/回滚、S3 对象存储与多 Pack 合并实验](../experimental/pando/README.md)（含 [migration.rs](../src/pando_lab/migration.rs)、[rollback.rs](../src/pando_lab/rollback.rs)、[object_store.rs](../src/pando_lab/object_store.rs)、[repack.rs](../src/pando_lab/repack.rs)）
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
- [多节点仓库分片、Epoch 写屏障与自动故障切换测试](../tests/sharding.py)（含 [test_sharding.py](../tests/test_sharding.py)）
- [仓库只读浏览与原子 Ref 事务测试](../tests/browse.py)
- [Git LFS 传输与备份完整性测试](../tests/lfs.py)
- [CI Mirror 水位 LRU 淘汰、Pin 释放与限流测试](../tests/ci_mirror.py)
- [Pando 流式 Delta、图遍历、双算子对拍、在线迁移/回滚与 S3 Repack 测试](../tests/pando_lab.py)（含 [test_pando_migration.py](../tests/test_pando_migration.py)、[test_pando_repack_object_store.py](../tests/test_pando_repack_object_store.py)）
- [Workspace 脏清单、忽略规则、增量同步、远程 CAS、多仓虚拟 Namespace 与稀疏 VFS 测试](../tests/workspace.py)（含 [test_workspace_remote_namespace.py](../tests/test_workspace_remote_namespace.py)、[test_workspace_vfs.py](../tests/test_workspace_vfs.py)）
- [Schema 060 四级需求端到端验证套件](../tests/e2e_tiers.py)（含 [五级白盒对抗验证](../tests/test_tier5_adversarial.py)）

验证记录是带版本和环境边界的历史结果。设计目标、测试代码存在和某次测试通过是不同状态，请结合对应契约阅读。
