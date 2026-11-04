# 一期后端与可替换消息层

> 状态：范围与目标契约；当前 PG 持久投递及可选 Redis/Kafka 唤醒能力见实现文档。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# 十三 一期后端范围与可替换消息层

本节为最新实施优先级；如前文里程碑包含一期之外的功能，以本节为准。后端使用 Rust，数据库 PostgreSQL，对象存储保持可替换。先交付 Git 基础闭环；Issue、PR、LFS、外部 CI、Workspace/VFS 和 Web 界面放到后续阶段。

## 一期交付与边界

1. 初始化服务与数据库迁移，提供创建仓库的管理 API、仓库元数据、基本鉴权和持久化配置。

2. 标准 Git Smart HTTP：空仓库和已有仓库的 clone/fetch，以及 push、分支基本读写与明确的错误返回。commit 通常由客户端本地 Git 完成；一期不额外实现服务端提交 API。

3. 验证完整链路：创建仓库 → 原生 Git clone → 本地 commit → push → 独立客户端再次 clone/fetch 并核验 commit 和文件。

4. 保留多分支并行目标并建立基准，但如第一阶段使用成熟 Git 和持久卷，实际锁粒度、共享瓶颈必须实测；不能宣称已实现 Pando 存储或数据库权威 refs。对象存储作为目标架构及适配层的一部分，Git 对象何时从持久卷迁移至对象存储由独立原型验证决定。

5. 验收包含重启恢复、非法鉴权、非 fast-forward 拒绝、同分支竞争、不同分支并发、上传中断、clone 后 git fsck，以及当前稳定版 Git 客户端。明确单节点原型的可用性限制。

## 两种部署模式

单机 standalone：单进程 Rust 服务内置有界 memory cache 与 memory event transport，PostgreSQL 和对象存储仍为持久依赖；开发可选持久本地对象目录。此模式不要求单独运行 Redis 或 Kafka。多个独立进程不能把各自内存当共享总线；若拆 API 与 Worker，需 Kafka 或显式实现基于 PostgreSQL 领取及扫描的跨进程模式。

分布式 distributed：cache.driver=redis，events.transport=kafka 或其他实现同一契约的消息系统；Kafka 按 repository_id + ref 分区，支持多个逻辑消费组。队列不可用时保留 outbox 并重试，禁止静默回退为各节点独立内存队列。对象存储适配器及数据库连接不绑定厂商。

## 持久性、顺序与恢复

Cache 接口支持 memory / redis；EventTransport 支持 memory / kafka。两者都不是业务事实源。必须完成的任务和事件与业务变更同一 PostgreSQL 事务写入 outbox；内存队列只是唤醒或传输，入队不等于持久或完成。每个必需消费组独立记录 event_id 的完成状态，重启重扫未确认事件，至少一次投递，消费逻辑幂等。外部动作使用稳定幂等键，但不宣称跨系统 exactly-once。

同一 ref 的事件在对应事务内分配序号，以 ref 为键串行发布和处理，故障时不让后续事件越过未解决的事件；不同 ref 可并行。Kafka 分区本身不能修复生产者乱序、重试和重平衡，消费者必须验证序号并处理重复和缺口。不可用自增 outbox ID 的最大值代替事务提交顺序，避免晚提交事件被漏扫。

缓存和队列设字节、数量、并发和 TTL 上限；队列满时停止领取，持久任务留在数据库，达到安全水位后限流或拒绝，禁止静默丢失。Redis/内存锁仅是优化，ref CAS、租约 fencing 和 GC 安全由 PostgreSQL 权威状态保证。LISTEN/NOTIFY 只作唤醒，仍需周期扫描。

配置示例：deployment.mode=standalone|distributed；cache.driver=memory|redis；events.transport=memory|kafka；events.store=postgres；cache.max_bytes、events.max_bytes、events.max_inflight、outbox.max_pending_bytes。Kafka 设置可靠确认、生产端幂等以及业务完成后提交消费位点；副本、保留期按可用性目标确定。

## 分阶段任务

M1 Rust Git 后端：仓库创建、Git clone/fetch/push、客户端 commit、权限与持久化、测试和文档。先以成熟 Git 实现协议闭环；独立分支并发数据与失败恢复作为验收结果如实呈现。

M2 Pando 内核原型：对象包和 PostgreSQL ref CAS、依赖图、跨节点可读和故障注入；验证 Git 后端适配后决定是否替换 M1，不能假定现成 Git 能把 PG 直接当 refs。

M3 Workspace/VFS：隔离工作区、Git HEAD/index/working tree、实时变更、ignored 本地文件和 checkpoint 恢复。

M4 协作与集成：Issue/PR、LFS、外部 CI、Webhook、评审与 Web UI。各阶段仍可并行设计，但不扩大 M1 交付承诺。

## 必测消息故障

事务提交后投递前崩溃、入队后消费前崩溃、外部副作用后确认前崩溃、多个消费组部分成功、队列满、缓存清空、Kafka 中断、DB 短暂不可用、同 ref 事件乱序与 worker 租约过期。恢复后不得静默丢失；外部重复效果由消费者幂等或对账控制。PostgreSQL 和对象存储本身的 RPO/RTO 仍取决于实际部署与备份。
<!-- END SOURCE BODY -->
