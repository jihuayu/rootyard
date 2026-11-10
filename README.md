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
