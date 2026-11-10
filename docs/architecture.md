# ADR 003：Blob-only 单机与 Raft Ref-CAS 分布式

状态：当前目标设计，尚未作为默认服务交付。项目未发布；本轮只规划全新部署，不要求旧 GitFS 导入、旧 schema/备份升级或跨版本回滚。当前源码默认仍是 GitFS，可选 Pando 仍在；PR #142 的 roots/decisions/accepted-subset 是已验收、未接服务的库能力。

本文取代旧 ADR 001、历史 01—11 章及 GitFS/Patroni 拓扑作为新安装规范。历史来源和验收记录保留原范围。[实施计划](design/implementation-plan.md) 定义任务与验收，[详细协议](design/12-state-services.md) 定义边界，[架构图](design/architecture-diagrams.md) 与正文同步。

## Git 传输范围

对外 Git 仅提供 Smart HTTP/HTTPS。HTTPS 在入口代理终止 TLS；不实现 SSH transport、SSH daemon、SSH 登录密钥管理或 SSH clone/push 验收。内部 Raft/服务 mTLS 不属于 Git SSH。签名提交中的 SSH 签名验证与传输协议是不同功能，不因本约束误删。

## 两种目标部署

| 职责 | Standalone | Distributed |
| --- | --- | --- |
| 应用 | 一个 Rust 应用，内置可靠 worker | 多个应用/计算节点，可独立 worker |
| refs、HEAD、pack membership、操作终态、取消、读取 pin/持久 root | PgRefStore，持久化在 PG | 同仓同 Raft Ref-CAS 权威 |
| 身份、权限、策略、发布决策、Forge、可靠业务任务 | PostgreSQL | PostgreSQL |
| 共享 artifact 登记/hold、全局删除权、租户配额 | PostgreSQL | PostgreSQL，与 Ref-CAS 使用显式保留桥 |
| 内容字节 | Apache OpenDAL 远程 Blob | 同一 Blob 契约 |
| 缓存/唤醒 | 有界 MemoryCache/MemoryWake | Redis，可加本地缓存 |
| 本地裸 Git | 可删除的隔离计算视图 | 同左 |

单机不强制 Redis、Raft、Kafka、Vault、FUSE 或集群控制器。PG 和 Blob 是必要持久依赖。分布式仍需要业务 PG；同一仓库只允许一个 ref 权威，Raft 故障时不向 PG 投影、本地目录或 Redis 回落写入。

## 发布与权限

字节先以不可复用 locator 上传 Blob 并回读验证，随后固定权威快照/pin、验证原生 Git 闭包、签发绑定 operation/digest/authority/history/selection/proof 的决策。单机在 PG 同一事务完成授权复核、decision 消费、refs/HEAD、终态和事件。分布式由 Ref-CAS 在复制日志中原子裁决 refs、commit/cancel 竞争、不可变终态和 Git 事件；PG 保存决策、历史终态投影及业务副作用，不拥有第二份可写 refs/取消权威。

跨 PG/Raft/Blob 没有原子事务。远程决策桥必须实现 OPEN→CLOSING：先在 PG 停止受影响范围的新决策，再向所有相关组提交单调关闭屏障，按日志顺序结算已提交或已取消操作。拒绝晚到旧决策；未知结果查询原 operation。所有关闭回执、投影和 finalizer 对账完成前，撤销保持 pending，不报告完成。状态机只比较自己持久化的 floor，不能相信请求自带 floor。时钟/deadline 不进入确定性 apply；有界有效期与关闭机制由桥的专门任务验收。

Atomic 全成全败；accepted-subset 固定原始请求顺序和每 ref verdict，最终验证不能静默缩小接受集合。共享字节损坏使整次发布失败。真实 API-token、浏览器、Merge 和策略 writer 都必须进入共同发布/撤销协议。

## 内容与保留

pack、idx、manifest、LFS、Workspace/checkpoint、事件归档和备份正文走 Blob。大字节不进 Raft/Redis。PG 与 Raft 的 data/WAL 使用各自持久设备和 fsync 协议，Blob API 不是 WAL 设备。KeyProvider 可替换，Vault 不作为单机必需依赖。

ref 快照与读取 pin/持久 root 必须同权威捕获；分布式不能把 refs 放 Raft 而把决定其回收安全的 pin/root 只放 PG 投影。PG 的共享 artifact hold 是另一层保护，必须覆盖跨仓去重与实际删除权；删任何物理字节前同时证明两层保护均已退役。live refs/membership 自身构成保留根，不要求每次 push 创建新的永久 root。

GC 独立验收、默认关闭；未知保留、未闭合决策、备份根、落后投影或旧 authority 都阻止删除。配额拒绝新写入，不自动裁剪 roots/回执；精确重放不重复计费。错误的新上传拒绝本次操作；已发布字节损坏则隔离受影响读取并进入恢复，不能用旧 refs 冒充最新结果。

## 恢复与运维

全新同版本恢复仍是必须交付的功能。先冻结入口、PG 独立 worker、Raft 新 apply 及 Blob 维护/删除器，排空在途操作或记录并闭合 unknown；保留备份根后取得 PG cut、Raft index/snapshot（单机无此项）和 Blob 完整闭包，写入同一个不可变 manifest。恢复到隔离目标，以新 deployment/history incarnation 撤销旧 worker/decision/deleter 凭证，再对账投影、权限和闭包，clone/fsck 通过后开放。单独复制 PG 并指向可删共享 bucket 不属于有效恢复。

Redis 故障仅降低速度；可靠任务由 PG 扫描、RefStore 事件重放和持久 cursor 恢复。分布式部署必须分别说明 PG、Raft quorum、Blob、入口及 Redis 的故障行为，并在独立故障域测量 RPO/RTO。旧单主机 Patroni 结果不等于本架构生产资格。

## 当前未完成

全内容网关和业务接入、fresh authority 创建、单机默认配置与依赖瘦身、开源 Raft 运行时/状态机/RPC、远程权限桥、PG 投影/finalizer、配对恢复、GC、容量成本与真实多故障域验收。Raft 库需要 ADR 和实测，不宣称 GitHub 内部采用相同算法。每项见 [实施计划](design/implementation-plan.md) 与 [任务映射](design/issue-map.md)。
