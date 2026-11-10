# Rootyard 设计文档

当前规范是 **Blob-only 轻量单机与 Raft Ref-CAS 分布式架构**，以尚未发布、全新部署为前提。以下入口取代历史 GitFS/Pando 分期路线；改变设计不表示服务已经切换。

## 当前规范与实施

- [架构决策与状态归属](../architecture.md)
- [单机、分布式与发布/恢复协议图](architecture-diagrams.md)
- [状态服务契约](12-state-services.md)
- [Pando 一致性与会话读取契约（提案）](pando-consistency.md)
- [实施计划、依赖和验收](implementation-plan.md)
- [实现状态](implementation-status.md)
- [旧任务删除与新任务覆盖](issue-map.md)
- [全部实现文档与证据](../README.md)

单机是一个应用进程 + PG + OpenDAL Blob；多机是计算节点 + 业务 PG + Raft Ref-CAS + Redis + 同一 Blob 契约。持久裸仓库退出目标架构，本地 Git 仅作临时计算视图。当前不安排旧 GitFS 导入、旧版本数据库/备份升级或跨版本回滚。

## 历史来源快照

以下材料保留原始内容与 SHA-256，用于解释早期决策及实验，**不再具有当前路线优先权**。其中“当前”“一期”“最新”等描述均只指原快照日期。

| 文件 | 历史内容 |
| --- | --- |
| [01 总体目标与技术架构](01-overview.md) | Namespace、Git View、Workspace、Git 语义、存储内核、安全与性能预算；早期目标建议 |
| [02 Git 存储事务与协议](02-git-storage.md) | 对象命名、发布状态机、CAS、fetch、故障、GC、API、Rust 模块与验收；SQL 是设计草案 |
| [03 Workspace 与 VFS](03-workspace-vfs.md) | HEAD/index/worktree、ignore 路由、捕获、checkpoint、恢复、安全与验收 |
| [04 Forge 与工程任务](04-forge.md) | Issue/PR/Review、API、CI、LFS 和依赖顺序 |
| [05 版本基线与服务规划](05-services.md) | 数据归属、部署单元、请求路径、后台任务、扩容、安全与 Git 兼容矩阵 |
| [06 后端与消息层](06-message-layer.md) | standalone/distributed 目标模式、可替换缓存和消息适配器、持久性与恢复 |
| [07 分布式与横向扩容](07-distributed-scaling.md) | 仓库分片、GitFS 与 PG refs 权威、迁移、fencing、热点和发布门槛 |
| [08 分期实施与预研闸门](08-roadmap.md) | 第零期至第六期的范围、依赖、研究和退出条件 |
| [09 Workspace 与 Git 预研记录](09-workspace-git-research.md) | 2026-11-03 的本地容器及 PostgreSQL/Smart HTTP 实验和限制 |
| [10 分布式存储故障预研](10-distributed-storage-research.md) | 2026-11-03 的多进程、本地对象模拟器、租约、晚到 PUT/DELETE、GC 和读取实验 |
| [11 CI 只读镜像](11-ci-read-mirrors.md) | 固定目标、复制屏障、等待/回源、权限撤销、对象保护与性能验收 |
| [12 状态服务设计（提案）](12-state-services.md) | PostgreSQL/Ref-CAS/Redis/OpenDAL Blob 目标；W0 为快照、生产者清单、部署契约与基线工具，**尚未实现** |

[原文归档](source-page.md) 和 [来源清单](source-manifest.json) 保持历史正文不变。2026-11-04 的 823 个来源正文块、11 章和原始摘要继续由 `python3 scripts/check_design_docs.py` 校验；当前架构图独立维护并验证源码与嵌入一致。历史图不再放在当前 diagrams 目录。
