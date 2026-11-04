# Rootyard 实现状态

核对基线：2026-11-04，main [`1fd05a393fe24653687fa3e868f9dca2fb0c9a67`](https://github.com/jihuayu/rootyard/commit/1fd05a393fe24653687fa3e868f9dca2fb0c9a67)。本页说明这份代码具有什么边界，不承诺后续 main 或未合并分支的状态，也不把既有测试报告当作本次重新执行的结果。

## 当前默认实现

| 能力 | 已有边界 | 代码与契约 |
| --- | --- | --- |
| Git hosting | Rust HTTP 服务调用原生 Git；持久裸仓库是 refs/objects 权威，PG 保存身份、仓库元数据和投影；单卷单服务进程，不是多节点 HA | [ADR 001](../architecture.md)、[git_http.rs](../../src/git_http.rs)、[storage.rs](../../src/storage.rs) |
| 操作证据与可靠事件 | GitFS 操作 journal、成功子集 receipt、unknown/recovering 状态、PG 事务事件和投递；GitFS 与 PG 不共享原子事务 | [可靠性契约](../reliability.md)、[journal.rs](../../src/journal.rs)、[events.rs](../../src/events.rs) |
| 后台 worker | PG-only 独立 worker、有租约和 fence 的投递；周期扫描是恢复依据，Redis/Kafka 只是可丢失唤醒 | [跨进程 worker](../cross-process-workers.md)、[Kafka 边界](../kafka-wakes.md)、[dispatch.rs](../../src/dispatch.rs) |
| 运维恢复 | 配对离线 PG/卷备份、隔离恢复、显式 unknown-push 处理、固定维度指标 | [备份恢复](../backup-restore.md)、[手动恢复](../manual-recovery.md)、[指标](../metrics.md) |
| 基础 Forge | 私有 owner Issue/comment、版本条件、分页、创建幂等键、open/closed 过滤和备份 | [Issue 契约](../forge-issues.md)、[forge.rs](../../src/forge.rs) |
| CI 读取切片 | 主站精确 SHA-1 source pin、手动全量镜像同步、prepare receipt、精确 OID clone、限定作业凭证；镜像每请求重新授权，拒绝写入 | [镜像契约](../ci-mirror.md)、[ci_pins.rs](../../src/ci_pins.rs)、[ci_checkouts.rs](../../src/ci_checkouts.rs)、[mirror.rs](../../src/mirror.rs) |

默认仓库读权限是 owner/repository 范围。隐藏 refs、不可达对象或 sparse checkout 不建立细粒度保密边界。Kafka 的已有适配器用于受控本地 broker，不能当作生产远程 TLS/SASL 集群配置。服务的其余安全和部署前提见 [运行手册](../operations.md)。

CI 的 source-retention receipt 与 mirror-readiness receipt 是两种独立证据，由可信控制者核对。owner-wide token 不能交给不可信 runner；基线已增加绑定仓库、目标 OID、job、generation、镜像 audience 与绝对到期时间的作业凭证，一次性交付，最长一小时，并支持单调 cancel/revoke。作业读取使用只含目标可达闭包的独立视图，仍允许读取目标的完整祖先历史。每次请求及慢准备完成后再次授权；已准入的长传输不会被即时中止。没有自动调度、自动回源、增量复制或 pin 到期释放/GC；更完整的 source epoch/version 等字段仍是 [第 11 章](11-ci-read-mirrors.md) 的目标。schema 008 / backup format 5 恢复会撤销既有作业凭证，详见 [实现契约](../ci-mirror.md#bounded-job-checkout-credentials)。

## 独立实验

| 实验 | 已实现的实验内容 | 不能推导出的能力 |
| --- | --- | --- |
| [Pando lab](../../experimental/pando/README.md) | 单独 feature/binary/schema；PG refs、不可变本地 pack、事务 CAS、多 ref 发布、持久读取快照、真实 Smart HTTP 测试路径 | 不是默认存储，不执行 GitFS 迁移；使用可伪造测试身份，仅限合成数据；没有真实对象存储、生产认证、GC/压实或 HA；同仓最终发布仍串行 |
| [Workspace foundation](../workspace-foundation.md) | 独立完整 `.git` 与工作树副本；固定起点；本地 checkpoint/restore；保存部分暂存、冲突和 ignore 语义 | 不是 COW、FUSE、实时 watcher、远程持久或多租户沙箱；需可信单一 OS 用户及调用方保证静止；没有多仓 BaseVector 或 Namespace 挂载树 |

## 计划与待验证事项

- Pando 生产存储、真实对象存储适配、迁移/回滚、对象 pin、GC/repack 和多租户隔离。
- 仓库分片、路由、真正的存储 fencing、节点接管、多机部署、PG HA 与灾备 RPO/RTO。
- Workspace 全写者屏障、跨节点恢复、VFS 按需 hydrate、Namespace/Git View 与确定性历史投影。
- PR/Review 与准确提交检查、Git LFS、外部 CI 回调、Web UI，以及完整 CI 作业调度、续期/清理和受控镜像回源。
- 在指定硬件、真实对象存储和工作负载上的规模/成本测试；原文容量数字和性能目标须实测。

这些能力的依赖和发布出口见 [分期路线](08-roadmap.md)。已有切片可以并行推进，不能以“第几期已开始”代替整期验收完成。

## 执行证据入口

现有记录分别覆盖 [基础 Git](../verification.md)、[可靠性](../phase-two-verification.md)、[备份整合](../integration-verification.md)、[恢复](../recovery-verification.md)、[恢复后 worker](../workers-integration-verification.md)、[Forge](../forge-verification.md)、[幂等](../forge-idempotency-verification.md)、[状态筛选](../forge-state-filter-verification.md)、[Forge 备份](../forge-backup-verification.md) 与 [Workspace](../workspace-verification.md)。Pando 的报告在 [实验目录](../../experimental/pando/README.md)。每条报告的执行版本、日期与未测边界继续有效；不因文档迁移而扩大。

新增设计文档只做来源完整性、链接与图的检查。产品测试命令及隔离环境要求见 [开发手册](../development.md)。
