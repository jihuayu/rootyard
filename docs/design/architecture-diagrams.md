# Rootyard 当前目标架构图

五张图替换旧 GitFS/Pando/Patroni 演进图。它们定义尚未发布项目的新装目标，**不表示运行时已激活**。实际候选能力见 [实现状态](implementation-status.md)，协议见 [状态服务](12-state-services.md)，任务见 [实施计划](implementation-plan.md)。历史来源图只保留在摘要校验的原文归档中，不再作为当前 diagrams 源文件。

## 单机：目标形态，尚未激活

[Mermaid 源文件](diagrams/fresh-standalone.mmd)

```mermaid
flowchart TB
  C["Git / API / Web / Agent 客户端"] --> A["Rootyard standalone<br/>单 Rust 应用进程"]
  A --> H["Smart HTTP / API / 鉴权"]
  A --> P["发布协调器<br/>prepare / select / verify / commit"]
  A --> R["PgRefStore<br/>PG 内权威 refs / CAS / 操作终态"]
  A --> M["有界 MemoryCache / MemoryWake<br/>可删除，仅延迟优化"]
  A --> W["内置可靠 worker<br/>PG 任务 / outbox / 周期扫描"]
  H --> L["本地裸 Git 计算视图<br/>quarantine / upload-pack / receive-pack<br/>可删除并重建"]
  P --> L
  R --> PG[("业务 PostgreSQL<br/>身份 / 仓库 / 权限 / 策略<br/>refs / 决策 / roots / 配额 / 投影 / outbox")]
  P --> PG
  W --> PG
  P --> B[("Apache OpenDAL 远程 Blob<br/>pack / idx / manifest / LFS<br/>workspace / checkpoint / backup 不可变字节")]
  L --> B
  M -. "丢失只影响延迟" .-> W
  D["持久设备要求<br/>PG data/WAL 需正常持久盘<br/>Blob API 不是 WAL"] -.-> PG
  X["非必需：Redis / Raft / Kafka / Vault / FUSE / controller"] -.-> A
```

## 分布式：目标形态，尚未交付

[Mermaid 源文件](diagrams/fresh-distributed.mmd)

```mermaid
flowchart TB
  C["Git / API / Web / Agent 客户端"] --> E["应用 / 计算节点（可多个）<br/>Smart HTTP / API / 鉴权 / 发布协调"]
  E --> PG[("业务 PostgreSQL<br/>身份 / 仓库 / 权限 / 策略（权威）<br/>决策意图 / 全局 artifact hold / 配额 / 投影 / outbox")]
  E --> RC["Raft-backed Ref-CAS 服务<br/>每仓唯一 refs / CAS 权威<br/>refs / HEAD / membership / 终态 / 取消<br/>snapshot pin / durable root / repo retained quota"]
  RC --> R1[("Raft 节点 A<br/>日志 / 状态机 / 快照<br/>持久设备")]
  RC --> R2[("Raft 节点 B<br/>日志 / 状态机 / 快照<br/>持久设备")]
  RC --> R3[("Raft 节点 C<br/>日志 / 状态机 / 快照<br/>持久设备")]
  E --> RD[("Redis<br/>可删除 cache / wake")]
  E --> B[("同一 Apache OpenDAL 远程 Blob<br/>pack / idx / manifest / LFS<br/>workspace / checkpoint / backup")]
  E --> L["本地裸 Git 计算视图<br/>仅可删除物化"]
  W["独立可选 worker<br/>PG 任务 / outbox / 扫描"] --> PG
  W --> RD
  W --> B
  RC -. "durable cursor / 幂等投影" .-> PG
  B -. "大字节不进 Raft / Redis / PG 行" .-> RC
  F["Raft 不可用<br/>禁止 PG refs 回落"] -.-> E
  G["PG 权限不可用<br/>禁止未授权发布"] -.-> E
```

## 发布与撤销：待接入共同服务协议

[Mermaid 源文件](diagrams/publication-decision.mmd)

```mermaid
sequenceDiagram
  participant C as Git客户端
  participant A as 应用协调器
  participant B as OpenDAL Blob
  participant P as PG权限与决策
  participant R as RefStore权威
  C->>A: 真实鉴权的push与原operation身份
  A->>P: 当前权限与配额准入
  A->>B: 唯一attempt上传并独立回读校验
  A->>R: 原子capture refs和pin
  A->>A: 验证真实字节闭包及sealed selection
  A->>P: OPEN scope安装绑定proof与epoch的decision
  alt standalone
    P->>P: 同事务重检授权并写refs、终态、事件
  else distributed
    A->>R: 认证grant安装及Apply
    R->>R: 检查自有floor、CAS与保留绑定
    R-->>A: 同日志裁决commit或cancel的不可变终态
    A->>P: 幂等投影与业务finalizer
  end
  A-->>C: 确认结果，丢ACK则按原身份查询unknown
  opt 权限撤销
    P->>P: OPEN到CLOSING，停止新decision
    P->>R: 各相关group的幂等CloseScope
    R->>R: 单调floor，拒绝晚到旧grant，结算在途操作
    R-->>P: 关闭与终态回执
    P->>P: 对账投影及finalizer后才ACK撤销完成
  end
  Note over P,R: 无跨系统原子事务，无quorum时撤销保持pending
```

## 对象保留与GC：默认禁止物理删除

[Mermaid 源文件](diagrams/retention-gc.mmd)

```mermaid
flowchart TB
  B[("Blob 不可变对象<br/>pack / idx / manifest / LFS<br/>workspace / checkpoint / backup")] --> REG["pack 注册 + byte proof<br/>全局artifact hold + Blob回读核验"]
  REG --> SNAP["pack snapshot + durable pin"]
  SNAP --> ROOT["RefStore pin / root / live refs<br/>同权威捕获；release单向"]
  REF["权威 refs<br/>standalone：PgRefStore<br/>distributed：Ref-CAS"] --> ROOT
  ROOT --> E{"全部屏障满足？"}
  GLOBAL["PG全局artifact hold / 跨仓引用 / 删除权"] --> E
  REF --> E
  PIN["活动 snapshot / pin / decision"] --> E
  BK["备份保留 / 恢复点"] --> E
  PRJ["投影 cursor 已对账"] --> E
  E -- "否" --> KEEP["保留，不删除"]
  E -- "是" --> PLAN["GC 计划 + 引用闭包核验<br/>计划中的消费者"]
  PLAN -. "当前 BlobStore delete 禁用；尚无 GC 消费者" .-> DEL["物理删除（未实现）"]
  Q["配额：只拒绝新写入，不自动裁剪"] -.-> REG
  B -. "字节缺失或校验失败" .-> RO["仓库只读；从 Blob/备份恢复；不返回部分对象"]
  DEL -.-> RO
```

## 配对备份与全新同版本恢复：待实现

[Mermaid 源文件](diagrams/fresh-restore.mmd)

```mermaid
sequenceDiagram
  participant O as 备份恢复控制者
  participant A as 应用与独立worker
  participant P as 业务PostgreSQL
  participant R as RefStore权威
  participant B as Blob与维护删除器
  participant N as 隔离的全新同版本目标
  O->>A: 停止新写及独立worker
  O->>R: 冻结新apply，排空或闭合unknown
  O->>B: 冻结维护删除，建立备份hold
  O->>P: 捕获PG cut与决策、hold、cursor
  O->>R: 捕获权威快照、roots和终态
  Note over P,R: 单机权威在同一PG内，分布式另绑定Raft index
  O->>B: 校验完整对象闭包并写不可变配对manifest
  O->>N: 核验manifest，恢复PG、权威与Blob
  N->>N: 新history incarnation，拒绝旧decision与worker/deleter grant
  N->>P: 重放投影与finalizer，对账权限和保留
  N->>B: 空计算目录重建视图并验证clone/fsck与业务流
  N-->>O: 验收通过后开放
  Note over P,B: 不是跨存储原子事务，任一点不匹配拒绝开放
  Note over O,N: 无旧版本升级或GitFS导入；旧副本不得获删除权
```
