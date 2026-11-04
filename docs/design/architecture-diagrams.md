# Rootyard 架构图

这些图把当前实现和目标设计分开。除第二张为原 Page 图，其余是根据已链接的代码契约或设计整理的新图。图中的箭头表示依赖或调用，不表示所有步骤位于同一事务。

[设计目录](README.md) · [实现状态](implementation-status.md) · [分期路线](08-roadmap.md)

## 当前默认服务

按基线代码与实现契约整理。GitFS refs/objects 是默认服务权威；PG 持久事件不把这两种存储合成一个事务。参见 [ADR 001](../architecture.md)、[可靠性](../reliability.md)、[worker](../cross-process-workers.md) 与 [镜像](../ci-mirror.md)。

[Mermaid 源文件](diagrams/current-service.mmd)

```mermaid
flowchart TB
  Client["标准 Git 客户端"] --> Primary["Rootyard 主服务 / Smart HTTP"]
  API["仓库与 Issue API"] --> Primary
  Primary --> Git["原生 Git 子进程"]
  Git --> Volume[("主站私有持久卷<br/>权威裸仓库 refs / objects<br/>操作 journal 与 receipt")]
  Primary --> PG[("PostgreSQL<br/>身份 / 元数据 / Forge<br/>审计 / 事件 / 投递 / 投影")]
  Worker["独立 PG-only worker / 周期扫描"] <--> PG
  Embedded["进程内 worker / 周期扫描"] <--> PG
  Primary -. "进程内 Notify" .-> Embedded
  Primary -. "可丢失唤醒" .-> Hints["可选 Redis / Kafka"]
  Hints -. "跨进程提示" .-> Worker
  Trusted["CI 客户端 / 限定作业凭证"] --> Mirror["只读 serve-mirror"]
  Mirror --> PG
  Mirror --> MV[("独立镜像卷<br/>已验证快照与 OID pin")]
  Mirror -. "显式 full sync" .-> Primary
  Backup["离线配对备份工具"] --> PG
  Backup --> Volume
```

## 完整目标架构

这是设计 Page 原有 Mermaid 图，保持原文。它表示长期目标，不是当前已部署组件清单。图中的对象存储、Workspace、Namespace、PR/LFS 及独立协调能力仍有计划或实验部分；单机模式不要求 Redis。参见 [总体设计](01-overview.md) 与 [最新路线](08-roadmap.md)。

[Mermaid 源文件](diagrams/target-overview.mmd)

```mermaid
flowchart TB
  U[开发者与 Git 客户端] --> GW[Git 协议网关]
  A[Agent Sandbox] --> V[VFS 与本地缓存]
  V --> W[Workspace 服务]
  UI[Web UI 与 API] --> F[Forge Issue PR Review]
  W --> N[Namespace 与 Git View]
  W --> E[事件日志与 Checkpoint]
  GW --> O[对象读取与发布内核]
  N --> O
  F --> O
  O --> DB[(数据库 事务元数据)]
  O --> OBJ[(对象存储 pack 索引和 LFS)]
  W --> OBJ
  O --> REDIS[(Redis 缓存与协调)]
  W --> REDIS
  F --> CI[外部 CI]
  DB --> Q[Outbox 后台任务]
  Q --> GC[压实 索引 GC]
```

## 当前 GitFS push 与证据

按实现契约整理的成功路径与不确定结果边界。Git 的 ref 更新和后续 PG 导入不共享原子提交，receipt 只记录成功子集；不能从客户端断线推断未写入。参见 [操作证据契约](../reliability.md)。

[Mermaid 源文件](diagrams/gitfs-push.mmd)

```mermaid
sequenceDiagram
  participant C as Git 客户端
  participant S as Rootyard 主服务
  participant G as 原生 receive-pack
  participant V as GitFS 与持久 journal
  participant P as PostgreSQL
  C->>S: 认证后的 push
  S->>V: 先持久化操作意图与边界
  S->>G: 有限资源与期限内运行
  G->>G: quarantine / 校验 / ref 更新
  G->>V: 原生 refs 与成功子集 receipt
  G-->>C: 经服务返回 Git 协议结果
  S->>V: 扫描与对账证据
  alt 结果可证实
    S->>P: 事务写审计、事件与投递
  else 证据不足
    S->>P: 显式 unknown / recovering
  end
  Note over V,P: 不是 GitFS 与 PG 的分布式原子事务
  Note over C,V: 丢失响应后先查询 refs 与操作状态
```

## Pando 目标发布协议

从目标存储契约整理。独立 Pando lab 已验证其中一些本地 pack/PG 路径，但不等于真实对象存储、完整 GC/幂等和迁移已交付。参见 [存储契约](02-git-storage.md) 与 [Pando lab](../../experimental/pando/README.md)。

[Mermaid 源文件](diagrams/pando-publication.mmd)

```mermaid
sequenceDiagram
  participant C as Git 客户端
  participant G as Git Gateway / 校验
  participant O as 不可变对象存储
  participant P as PostgreSQL 权威 refs
  participant W as 后台 worker
  C->>G: push 与旧 OID
  G->>G: 权限、pack、delta base、对象闭包校验
  G->>O: 上传不可复用物理 key 的 pack / index
  O-->>G: 按后端契约确认可读与持久
  G->>P: 短事务校验 generation、权限、ref CAS
  alt 全部条件成立
    P->>P: 原子提交 locator、refs、操作结果、outbox
    P-->>G: COMMIT 确认
    G-->>C: 成功
    W->>P: 持久任务领取与幂等消费
  else 条件冲突或发布失败
    P-->>G: 拒绝发布
    G-->>C: 明确失败或结果待确认
  end
  Note over O,P: 对象先持久，元数据后发布；无跨系统原子事务
  Note over G,P: COMMIT 后丢 ACK，查询已持久结果再决定重试
```

## Workspace 目标 checkpoint

从 Workspace/VFS 设计整理。当前实验只有调用方静止下的本地完整副本，不能据此宣称本图的全写者 barrier、COW 或跨节点恢复已实现。参见 [Workspace 目标契约](03-workspace-vfs.md) 与 [实验边界](../workspace-foundation.md)。

[Mermaid 源文件](diagrams/workspace-checkpoint.mmd)

```mermaid
flowchart TB
  Base["固定 Namespace 版本与 BaseVector"] --> WS["隔离工作区<br/>HEAD / index / working tree"]
  Agent["单一有效写会话 / fencing"] --> WS
  WS --> Route{"tracked、显式纳入<br/>或 untracked 且未 ignored?"}
  Route -- "是" --> Managed["受管理文件 / overlay / 捕获日志"]
  Route -- "否且 ignored" --> Local["sandbox 原生文件<br/>默认不保证远端恢复"]
  Managed --> Barrier["全写者 barrier 或可靠快照<br/>固定版本与事件前沿"]
  Barrier --> Capture["捕获 index、Git 状态、文件字节与 manifest"]
  Capture --> Objects[("上传并验证所有依赖对象")]
  Objects --> Publish["事务发布 checkpoint 元数据"]
  Publish --> Restore["核验闭包、授权与版本后恢复新工作区"]
  Restore --> WS2["新的隔离工作区"]
```

## 当前 CI source pin 与只读镜像

按当前实现整理。两个 receipt 必须由可信控制者匹配，full sync 是显式动作。已有绑定目标、镜像 audience 与到期时间的 job token；仍无自动调度/回源、pin GC 或已准入长传输的即时撤销。参见 [CI 实现契约](../ci-mirror.md)；完整目标见 [第 11 章](11-ci-read-mirrors.md)。

[Mermaid 源文件](diagrams/ci-mirror-checkout.mmd)

```mermaid
sequenceDiagram
  participant T as 可信控制者
  participant P as 权威主站 / GitFS
  participant M as 只读镜像
  participant D as 权威 PostgreSQL
  participant R as CI runner
  T->>P: POST ci-pins(job UUID, exact OID, generation)
  P->>P: 持久意图、原生保留 ref、核验 receipt
  P-->>T: source-retention receipt
  T->>M: 显式 mirror-sync
  M->>D: 当前身份与仓库权限检查
  M->>P: 原生 Git 全量复制到 staging
  M->>M: fsck 后原子发布完整快照
  T->>M: mirror-prepare(同一 OID / generation)
  M->>M: 验证闭包并持久 pin
  M-->>T: readiness receipt / 精确 clone_path
  T->>T: 核对仓库、generation、格式和 OID
  T->>P: ci-checkouts(同一 job / OID / audience / expiry)
  P-->>T: 固定 plan 与一次性交付的 job token
  T->>R: 固定目标与受保护的 job token
  R->>M: clone / fetch 精确 OID URL
  M->>D: 每次请求重新授权
  M->>M: 只含目标闭包的独立 job view
  M->>D: 慢准备后重新检查作业授权
  M-->>R: 本地 pack 数据
  R->>R: 核对完整 HEAD OID 再构建
  Note over M,R: 写入拒绝；无目标替换或静默回源
```

## 分布式目标与权威边界

从横向扩容设计整理，尚不是当前默认服务部署。GitFS 接管必须隔离旧写者真实卷访问；PG 租约到期本身不足以保护卷。PG refs 是另一个后端阶段，不能和 GitFS 同时作为同仓 refs 权威。参见 [横向扩容](07-distributed-scaling.md)。

[Mermaid 源文件](diagrams/distributed-target.mmd)

```mermaid
flowchart TB
  Clients["Git / API / Agent 客户端"] --> Edge["无状态入口与鉴权"]
  Edge --> Router["仓库路由与 generation 校验"]
  Router --> ShardA["GitFS 分片 A<br/>每仓唯一实际写者"]
  Router --> ShardB["GitFS 分片 B<br/>每仓唯一实际写者"]
  ShardA --> VA[("A 持久卷<br/>原生 refs / objects 权威")]
  ShardB --> VB[("B 持久卷<br/>原生 refs / objects 权威")]
  Router --> Meta[("PG 身份 / placement / 迁移状态")]
  ShardA -. "固定版本复制" .-> Read["只读镜像 / 读取节点"]
  ShardB -. "固定版本复制" .-> Read
  Migration["单仓停写、排空、校验、fencing 与切换"] -. "后续可选阶段" .-> Pando["Pando 数据面"]
  Pando --> Refs[("PG 权威 refs / manifest")]
  Pando --> Packs[("不可变 pack / index 对象存储")]
  Meta -. "一个仓库只选一个权威后端" .-> Migration
```
