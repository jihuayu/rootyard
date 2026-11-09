# Rootyard 设计文档

当前规范是 **Blob-only 轻量单机与 Raft Ref-CAS 分布式架构**，以尚未发布、全新部署为前提。以下入口取代历史 GitFS/Pando 分期路线；改变设计不表示服务已经切换。

## 当前规范与实施

- [架构决策与状态归属](../architecture.md)
- [单机、分布式与发布/恢复协议图](architecture-diagrams.md)
- [状态服务契约](12-state-services.md)
- [实施计划、依赖和验收](implementation-plan.md)
- [实现状态](implementation-status.md)
- [旧任务删除与新任务覆盖](issue-map.md)
- [全部实现文档与证据](../README.md)

单机是一个应用进程 + PG + OpenDAL Blob；多机是计算节点 + 业务 PG + Raft Ref-CAS + Redis + 同一 Blob 契约。持久裸仓库退出目标架构，本地 Git 仅作临时计算视图。当前不安排旧 GitFS 导入、旧版本数据库/备份升级或跨版本回滚。

## 历史来源快照

以下材料保留原始内容与 SHA-256，用于解释早期决策及实验，**不再具有当前路线优先权**。其中“当前”“一期”“最新”等描述均只指原快照日期。

| 文件 | 历史内容 |
| --- | --- |
| [01 总体目标](01-overview.md) | Namespace、Workspace、Git 语义与资源预算 |
| [02 Git 存储](02-git-storage.md) | 早期存储事务与协议草案 |
| [03 Workspace/VFS](03-workspace-vfs.md) | 工作区和 checkpoint 目标 |
| [04 Forge](04-forge.md) | Issue/PR/Review、CI、LFS |
| [05 服务规划](05-services.md) | 早期部署单元与数据归属 |
| [06 消息层](06-message-layer.md) | 早期 memory/Redis/Kafka 建议 |
| [07 横向扩容](07-distributed-scaling.md) | GitFS 分片与早期 Pando 演进 |
| [08 旧分期路线](08-roadmap.md) | 已被当前实施计划取代 |
| [09 Workspace 预研](09-workspace-git-research.md) | 本地实验与原有限制 |
| [10 分布式存储预研](10-distributed-storage-research.md) | 原故障模型与实验 |
| [11 CI 镜像](11-ci-read-mirrors.md) | 早期镜像设计 |

[原文归档](source-page.md) 和 [来源清单](source-manifest.json) 保持历史正文不变。2026-11-04 的 823 个来源正文块、11 章和原始摘要继续由 `python3 scripts/check_design_docs.py` 校验；当前架构图独立维护并验证源码与嵌入一致。历史图不再放在当前 diagrams 目录。
