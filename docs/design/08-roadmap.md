# 分期实施与预研闸门

> 历史来源快照：本文中的“最新/当前/优先级”仅指归档日期。现行规范见 [状态服务设计](12-state-services.md) 和 [实施计划](implementation-plan.md)，不再要求旧 GitFS 演进或旧版本升级。

> 状态：本来源快照中的最新实施路线，优先于早期泛化里程碑；阶段出口是验收要求，不是完成记录。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# Rootyard 分期实施与预研闸门

本节是最新实施路线，优先级高于前文泛化里程碑。以依赖和验收划分期数，不虚构工期；各阶段测试通过后才进入正式发布。部分工作可并行预研，但不把未经验证的能力当成已实现。

## 第零期 技术契约与预研

冻结 Rust 模块和接口、PostgreSQL 事务隔离与 schema、对象存储一致性、Git 兼容矩阵、鉴权、数据所有权和故障模型。Git 当前测试基线 2.56.0，每次部署固定已验收版本并持续跟进最新稳定版；客户端版本、Smart HTTP、refs、对象格式及可选能力逐项测试。

明确两种不同权威：一期 GitFS 的 refs/objects 以持久文件系统为准，PG 保存仓库元数据和可重建投影；后期 Pando 内核才由 PG 保存权威 refs，对象存储保存不可变 pack。每仓库预留 storage_backend、storage_generation 和迁移状态。预研官方 Git 子进程、gix、libgit2 的协议和存储扩展点；确认 SHA-1 与 SHA-256 的兼容边界，不把未测功能对外宣称支持。确定数据集、负载、硬件、RPO/RTO 和验收方法。

出口：每项状态仅一个权威源，每项协议承诺有测试，选型和未知项有记录。

## 第一期 Rust 基础 Git 后端

范围仅为创建仓库 → 标准 Git 客户端 clone → 本地 commit → push → 第二客户端 clone/fetch 和核对。commit 在客户端完成，不增加在线提交 API。优先官方 Git Smart HTTP 与持久卷；暂不接管 Git 对象到对象存储，不实现 Web、Issue、PR、LFS、VFS 或自研 Pando。

任务：建立 Rust workspace、PG migration、配置及健康检查；仓库创建幂等状态机和 bare repo 初始化；鉴权、仓库路径隔离、流式双向传输、Git 子进程资源限制、配额、超时与日志；保留 Git quarantine 和对象连通性校验；单机进程内有界缓存与消息调度。预研 HTTP 代理缓冲背压、空仓默认 HEAD、fsync 与持久卷、Git 多 ref 结果语义及文件系统锁范围。

验收：空仓及非空仓闭环，第二客户端相同 OID 与文件并通过 git fsck；无权限、损坏 pack、非法路径和过期 old OID 被拒；同 ref 并发不静默覆盖；重启后已确认提交可读，仓库创建崩溃后可恢复或明确失败。报告跨分支并行压测而非预设结果。

## 第二期 可靠性与部署模式

引入 PostgreSQL 持久任务/事件、outbox、审计、指标、备份恢复和仓库路由；standalone 使用单进程有界内存缓存与队列，distributed 可用 Redis + Kafka 类传输。事件至少一次且幂等，按 ref 定序；Redis 丢失不得改变正确性。

GitFS ref 写与 PG 事务不共用事务，设计持久操作记录、扫描与 reconciliation；仅靠 post-receive 写 PG 不保证没有遗漏。Git 节点接管必须隔离或 fencing 旧主的实际存储访问，不能只依赖过期租约。预研 Git hooks、崩溃窗口、卷语义、PG 与卷备份一致性和 Kafka 重平衡。

验收：kill、消息重复、队列积压、Redis 丢失、PG 暂断和故障切换演练；执行一次新环境备份恢复，记录实测 RPO/RTO。无法确认的事件必须显式进入对账状态。

## 第三期 Pando 单仓内核与迁移

PG refs 和对象存储 pack 成为目标后端：实现对象校验、pack/idx、不可变 manifest、CAS、多 ref 事务、写前持久、outbox、对象保护及恢复。Git gateway 与 upload/receive-pack 适配层单独原型验证，不能把 proc-receive 或临时仓库视为已验证可行方案。

迁移：复制对象与 refs → 校验 → 暂停源端写入、排空在途请求 → 复制最后增量 → 提升 generation 与 fencing → 切换 → 目标 clone/fsck 验证。切换后旧库只读；如目标已接收写入，回退须先同步新增对象与 refs，不能仅改路由。预研 thin pack、缺失 delta base、逻辑对象闭包、对象存储一致性及多 ref atomic。

验收：与 GitFS 相同 ref/OID、clone 内容和 fsck；各发布边界故障注入无已发布缺失对象；旧 generation 写入被拒；含切换后新提交的回退演练成功。未通过则继续使用 GitFS。

## 第四期 横向扩容与存储生命周期

扩展无状态入口与读取节点、按仓库分片、分层缓存和有界 pack worker；同 ref CAS，不同 ref 并行。引入 pack 索引、压实、对象保护与分阶段 GC。单个热分支必然串行；单仓跨 PG 分片、跨分片 atomic 与一致快照须专项设计，不能自动承诺。 CI 只读镜像作为读取扩容交付项，包含固定 OID、复制屏障、撤销授权和回源限流；MVP 可在第二期之后并行启动，完整门槛见第十五章。

预研负载热点、PG WAL/锁、对象存储请求放大、pack 依赖和跨租户隔离。验收 1/2/4 节点的吞吐、P95/P99、CPU、内存、临时盘、带宽和数据库等待；在并发 push/fetch/GC、缓存清空、节点失效下检查所有保留根可达对象。扩容效果以实测为准。

## 第五期 Workspace VFS 与 Namespace

先以独立 Agent 工作区、固定 BaseVector、HEAD/index/working tree 和 checkpoint 构建隔离恢复，再逐步引入按需 VFS；未跟踪且忽略文件留本地，tracked 优先。保留部分暂存、冲突状态；watcher 只是通知，不是事务日志；只有依赖对象完整持久化的 checkpoint 可承诺跨节点恢复。

Namespace 版本化挂载和 owner 路径；Git View 先只读、固定规则与源版本。历史策略分别为原仓库历史、确定性长期投影和任务快照；改变 tree/parent 会改变 OID 与签名含义。可写 view 需单独证明路径反向映射、权限和冲突无歧义。预研 mmap、锁、rename、非 UTF-8、构建扫描、故障屏障与权限边界；隐藏 refs 和 sparse checkout 不是数据保密隔离。

验收：多 Agent fork 隔离、部分暂存和冲突恢复、ignore/add-f/跨层 rename、断电恢复、授权隔离；标准 Git 客户端取到的投影可重复并通过 fsck。

## 第六期 Issue PR LFS CI 与 Web

Issue/PR/Review 持久模型和权限；PR 检查绑定准确 base/head、候选和可信 CI，合并使用目标 ref CAS。LFS Batch 上传校验 SHA-256 与大小、访问授权；外部 CI 使用签名事件、幂等回调及重试。Web 复用后端权限并处理不可信 Markdown、代码及大文件。

基础协作可在第二期后与 Pando/VFS 并行，不要求等待第五期；依赖虚拟视图的高级能力仍需对应闸门。验收：PR 更新后旧 CI 不再放行、并发合并不覆盖、标准 LFS 客户端往返、回调重复不重复副作用、UI/API 权限一致。

## 跨期交付清单

每期提交 ADR、接口契约、迁移脚本、测试、故障演练、监控、恢复手册、已知限制和实际性能报告。安全与正确性是发布闸门，性能不能抵消数据损坏风险；工期结合团队和试验结果估算。
<!-- END SOURCE BODY -->
