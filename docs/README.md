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
- [配对离线备份与恢复](backup-restore.md)
- [显式事故恢复](manual-recovery.md)
- [指标](metrics.md)
- [跨进程 worker](cross-process-workers.md)
- [Kafka 唤醒适配器](kafka-wakes.md)
- [私有 owner Issue API](forge-issues.md)
- [CI source pin 与只读镜像](ci-mirror.md)
- [Workspace 本地实验](workspace-foundation.md)
- [Namespace、Git View 与跨仓 ChangeSet 实验](git-view-foundation.md)
- [Pando 存储实验](../experimental/pando/README.md)

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

验证记录是带版本和环境边界的历史结果。设计目标、测试代码存在和某次测试通过是不同状态，请结合对应契约阅读。
