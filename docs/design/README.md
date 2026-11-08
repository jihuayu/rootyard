# Rootyard 设计文档

Rootyard 面向标准 Git 客户端、多 Agent 工作区和大型仓库。核心目标是：Namespace 管理逻辑路径，Workspace 隔离编辑状态，Git 负责版本交换与发布。当前默认实现仍以原生 GitFS 为 refs/objects 权威，不能把完整目标架构理解为已经交付。

## 从哪里开始

- [实现状态与证据](implementation-status.md)：区分当前默认实现、有限增量、独立实验和计划。
- [架构图](architecture-diagrams.md)：当前服务、目标架构、两种发布路径、Workspace checkpoint、CI 镜像和分布式路由。
- [最新分期路线与验收闸门](08-roadmap.md)：本次来源快照中的路线优先级最高。
- [全部现有实现文档](../README.md)：运行、恢复、备份、测试和实验手册。

## 设计正文

| 文档 | 内容与阅读边界 |
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

## 状态与优先级

1. **当前能力**以所读代码提交、实现手册和对应执行记录为准。本次整理基线是 [`1fd05a39`](https://github.com/jihuayu/rootyard/commit/1fd05a393fe24653687fa3e868f9dca2fb0c9a67)。代码或测试存在，不等于生产验收通过。
2. **后续开发顺序**以第 08 章为准。该章明确优先于原文较早的泛化里程碑，先 GitFS，后验证 Pando；各阶段只能按自己的出口条件验收。
3. **详细契约**是实现目标，只有状态索引明确列出的部分才已落地。原文早期使用“首版”“一期”的描述可能早于后续路线修订，例如 PG refs/proc-receive 不是当前一期后端。
4. **预研实测**保留其日期、环境、故障模型和未覆盖项；不把原型数字推广成性能 SLA、真实对象存储能力或生产 HA 保证。

设计原文中的 SQL、JSON 和 API 示例留在 Markdown 内，不作为可执行 migration 或当前服务接口发布。原有 `docs/architecture.md`、运行手册、验证记录和源码保持不变。

## 来源与完整性

来源是 [Rootyard Git 平台技术设计与实施路线](https://chatgpt.com/space/page_81800ca4cf288191872091af9e0c97c3)，读取于 2026-11-04，Page 最后更新时间为 2026-11-04 01:28:10 UTC，来源版本为 9。该 Page 需要原有访问权限，仓库中的文档无需访问 Page 即可阅读。

[完整原文归档](source-page.md) 与 11 个专题文件来自同一快照，覆盖全部 823 个正文块并保持原顺序。仅将两条私有历史对话 URL 替换为原引用标题及隐私说明；公开技术来源链接保留。新增状态索引和架构图不属于原文，已单独标明。

[来源清单](source-manifest.json) 记录章节范围和正文 SHA-256。运行 `python3 scripts/check_design_docs.py` 可验证章节覆盖、归档重组、摘要、仓库内链接及 Mermaid 源文件与嵌入内容一致性。该检查不执行设计中的代码，也不代表产品功能测试。

后续修改设计时，应同时更新相关状态、图和验收条件。原始来源归档作为本次时间点记录保留；新的决策应明确说明其取代的旧建议。
