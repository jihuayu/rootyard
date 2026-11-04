# 版本基线与服务规划

> 状态：目标部署与接口规划；部署单元不表示已有独立服务。文中的版本记录属于原文时间点。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# 十二 PostgreSQL 与 Git 版本基线及服务规划

数据库选用 PostgreSQL，Redis 和对象存储保持可替换；下述各服务是部署及扩缩容的逻辑规划，不意味着首版必须全部部署为独立微服务。对象权限、事务和版本策略与前文保持一致。

Git 兼容目标为最新稳定版：截至 2026 年 11 月 3 日，Git 官方最新源码版为 [2.56.0](https://git-scm.com/)（2026 年 9 月 28 日发布）。以它作为当前测试基线，每次构建锁定验收通过的具体版本并跟进安全更新；新版本发布后通过协议、对象格式、VFS/index 与回归矩阵再升级。支持客户端新版本不代表所有可选能力已经实现：fetch v2、receive-pack、atomic、SHA-256、partial clone、LFS 分别声明与验收。

# Git 平台服务规划

## 1. 总体方案

基础设施采用 PostgreSQL 和通用对象存储，缓存与消息传输可选进程内实现或 Redis、Kafka 类组件。服务按三个平面组织：

- 控制面：用户、组织、权限、仓库设置、PR、Issue、检查结果、任务调度。

- Git 数据面：Git 协议、refs 事务、对象读写、pack 处理、历史查询和垃圾回收。

- 执行面：Agent workspace、VFS、终端和 CI sandbox。

首版部署 **5 类应用进程**：platform-api、git-data、workspace-service、background-worker、sandbox-runner。模块边界先明确，但不把每个模块都拆成独立微服务。重计算、不可信代码和在线控制接口从第一天隔离。

这一方案按“PostgreSQL 是 refs 的权威源、对象存储承载 Git 对象”的目标设计。**原生 Git 服务端不能仅靠连接字符串就使用 PostgreSQL refs 和远程对象存储。** 必须有明确的协议/存储适配层。调用原生 Git 工具时，可以生成隔离的临时 Git 目录作为计算视图；它不是另一份权威仓库。不能用“先更新本地 refs，再用 hook 写 PostgreSQL”假装完成跨系统原子事务。

## 2. 三种存储的职责

### PostgreSQL：持久状态与事务权威

保存以下数据：

- 用户、组织、仓库、权限、保护规则及规则版本。

- refs、符号引用、ref 版本和 ref 变更记录。

- 已发布 pack、索引分片和对象定位目录的元数据。

- workspace 的 base commit、持久快照、版本、执行租约及 fencing token。

- PR、Issue、review、check、CI run/job、LFS 关联和上传状态。

- 幂等请求、持久任务、outbox、GC 状态、保留策略和审计记录。

不把大量 blob、pack、日志正文或 CI artifact 塞入 PostgreSQL。Git 对象定位索引可使用不可变索引分片，PostgreSQL 保存发布关系和定位入口，不预先强制“每个 Git 对象一行”。

### 对象存储：不可变数据

保存 Git pack/索引、workspace 快照及增量内容、LFS 对象、CI artifact、日志分块和备份对象。对象使用不可变 key；新版本写新 key，再通过 PostgreSQL 事务发布。

定义厂商无关的存储接口：Put、Get、Head、Range Read、Delete，按能力选用 multipart。每种后端都要通过耐久性、写后读、校验和及失败重试测试。发布流程不依赖对象存储的原子 rename、目录语义或 List 立即一致性。若后端无法保证所需的写后读契约，就不能把该对象发布为可见状态。

### Redis：可丢失的加速层

用于热点缓存、限流计数、临时连接状态、进度广播和任务唤醒。不能成为 refs、workspace 最后版本、任务唯一副本或权限事实的唯一来源。

Redis 故障不应破坏仓库正确性。缓存可以绕过；任务从 PostgreSQL 恢复；限流按接口风险选择本地保守限流或拒绝，不允许故障时无限放行。Redis 租约不承担关键写入的最终互斥职责。

## 3. 首版部署单元

### 3.1 platform-api：控制面与 Forge

职责：

- 对外业务 API、Web UI 后端、用户和组织管理。

- 仓库生命周期、成员权限、保护规则、配额。

- PR、Issue、review、讨论、check 和 CI 调度元数据。

- 为 Git、workspace 和 runner 签发短时、限定范围的操作凭证。

- 对外 webhook 配置与审计查询。

边界：不代理大体积 pack，不运行构建，不直接修改 refs。创建分支、合并 PR、网页编辑提交等操作，统一调用 Git 数据面的发布接口。

部署：无状态副本，前接统一入口。按业务请求量扩容，不跟随 pack CPU 一起扩容。

### 3.2 git-data：Git 协议与仓库内核

首版在一个部署组中包含四个逻辑模块：

1. **Git Gateway**：Smart HTTP 和 SSH 入口、仓库解析、鉴权、协议能力协商、流式收发、超时和请求预算。

2. **Repository Core**：读取 refs、ref CAS、多 ref 事务、对象可达性检查、保护规则的最终校验、ref log 和 outbox。

3. **Object Store Adapter**：pack 与索引发布、对象定位、范围读取、本地 SSD 缓存、校验和校验。

4. **Git Compute**：pack 接收/校验/生成、diff、merge、history 和 archive。使用有资源上限的独立子进程或执行池，不在请求主线程做无限制计算。

边界：Git Gateway 不知道 PR 的完整业务模型，Repository Core 不负责发通知，Git Compute 不具有任意修改权威 refs 的权限。数据面内部也按读请求、push 和后台维护设置独立预算。

所有入口的 Git 写入都归 Repository Core：普通 push、网页提交、Agent commit、PR merge 和自动化账号不能各自维护一套 ref 更新逻辑。

### 3.3 workspace-service：Agent workspace 与 VFS

职责：

- 从确定的 commit 创建 workspace；管理生命周期、快照、恢复、分叉和差异。

- VFS 的路径解析、文件元数据、按需读取、写入 overlay 和持久 checkpoint。

- 为 sandbox 挂载工作区，管理会话所有权、心跳和 fencing token。

- 把工作区变化转换成 Git tree/commit，再请求 Repository Core 发布。

模型：workspace = 不可变 base commit + 可写 overlay + 持久 checkpoint。workspace_id 与 repo_id 分开；同仓库可以同时有大量独立 workspace。

首版让同一 workspace 只有一个有效写会话，采用 workspace 级 PostgreSQL 租约和递增 fencing token；不同 workspace 完全并行。租约接管后，旧会话不得再提交快照或发布结果。这个限制不等于锁住仓库。

VFS 是工作区抽象，不意味着首版必须把每次文件系统调用都转成网络 RPC。可先采用“按需物化 + 本地可写层 + 持久快照”，后续再按测量结果引入 FUSE 等挂载实现。若 sandbox 内要运行标准 Git 和构建工具，必须验证文件模式、符号链接、原子 rename、大小写、fsync 等语义，不能只支持 read/write/list。

Agent 的实时本地写入与持久保存要区分。只有内容和快照元数据已持久化才能报告 checkpoint 保存成功；节点丢失后只能恢复到最后确认的 checkpoint。若产品要求每次保存都持久化，就实现对应的 write-through/flush 契约，不能以定时快照冒充零数据丢失。

### 3.4 background-worker：可靠异步任务

职责：

- 消费 outbox，投递 webhook、刷新索引、触发 CI。

- 导入/导出、预热、pack 合并、GC、LFS 清理。

- workspace 到期回收、失败上传清理、审计归档。

任务状态保存在 PostgreSQL，Redis 只负责降低等待时间。首版可用 PostgreSQL 持久任务表和 SKIP LOCKED 领取任务；领取事务应短，任务执行不持有数据库行锁。领取后使用租约、attempt 和 fencing token 验证结果，崩溃任务可再次领取。SKIP LOCKED 适合此类队列消费者，不应拿它跳过 refs 冲突来“完成”用户事务。[PostgreSQL SELECT 文档](https://www.postgresql.org/docs/current/sql-select.html)

在线关键任务、通知、维护任务分队列和并发池，避免一次 GC 堵住 webhook 或 CI 调度。规模扩大后，worker 类型可独立部署，不必改变任务模型。

### 3.5 sandbox-runner：不可信代码执行

职责：启动、停止并回收 Agent/CI 执行环境，提供终端、进程管理和受控网络出口，上传日志与 artifact。

每个任务使用独立隔离环境。多租户执行优先采用 microVM 或等效强隔离，不能把普通容器本身视为充分的敌对租户边界。限制 CPU、内存、进程数、磁盘、执行时间和出口；不暴露宿主机 Docker socket，不挂载平台数据库凭证，不赋予整个对象存储桶的访问权。

Runner 只获得指定 workspace、repo/commit 和任务范围的短时凭证。Agent runner 与 CI runner 可共用管理接口，但生产资源池和凭证策略分开，防止交互任务与大构建互相挤压。

## 4. 三个暂不独立部署的模块

### LFS

LFS Batch API、仓库授权和对象关联属于控制面逻辑；大对象字节直接进入对象存储。上传完成必须验证大小和内容哈希，再标记可用。Git 指针提交与 LFS 上传是两个流程；需要明确“缺失 LFS 对象时是否拒绝 push”的产品策略。首版建议拒绝新增的缺失 LFS 引用，并在可承受范围内验证。

LFS 的文件锁是用户可见的协作功能，不是平台实现 ref 正确性的分布式锁。

### CI 控制器

首版位于 platform-api + background-worker。CI run 绑定准确的 commit OID、配置版本和触发事件，不在执行开始时重新解析一个可能已移动的分支。结果回传使用 job_id、attempt 和 fencing token，晚到的旧尝试不能覆盖新尝试结果。

### 搜索/索引

首版从 PostgreSQL 的基础查询和按 commit 查询开始。代码全文搜索量上来后再引入独立索引组件。搜索索引是可重建投影，不影响 Git push 是否成功。

## 5. 关键请求路径

### 5.1 clone / fetch

1. Gateway 鉴权，并解析仓库与允许读取的 refs。

2. Repository Core 读取一致的 refs/对象目录视图，建立有界的读取保护。

3. Git Compute 基于固定的对象集合协商并生成 pack，优先使用已验证缓存。

4. 数据流经 Gateway 返回客户端，结束后释放读取保护。

读取保护用于避免 fetch 尚在使用的 pack 被 GC 删除，不应在整个网络传输期间持有 PostgreSQL 事务。断线和超时需要取消计算及清理资源。

refs 隐藏不等于对象保密：客户端按 OID 请求对象时，也必须按授权仓库和允许的可达性范围检查。缓存命中不能绕过授权。

### 5.2 push

1. Gateway 完成初始授权和配额预检，接收 update commands 和 pack。

2. Pack 写入隔离的 staging/quarantine，校验哈希、格式、大小、delta 深度和对象连通性；必要时消除 thin-pack 的外部依赖。

3. 检查分支策略、fast-forward、对象格式和请求能力；重计算放在事务外。

4. 把验证通过的不可变 pack/索引持久化，并验证已满足后端读取契约。

5. 在短 PostgreSQL 事务中重新校验目标 refs 的 old OID/版本以及相关权限、策略版本，发布对象目录、更新 refs、追加 ref log 和 outbox。

6. 事务提交后向客户端返回成功，异步投递通知和触发 CI。

失败允许留下可清理的孤儿对象，不允许出现“ref 已成功但对应对象还没持久化”。Git 原生 receive-pack 同样区分 quarantine 与已发布对象；隔离区对象不可提前成为公共 refs 的目标。[Git receive-pack 文档](https://git-scm.com/docs/git-receive-pack)

请求 atomic push 时，所有 ref 更新在同一事务内成功或全部拒绝；普通 push 则按协商的状态语义返回逐 ref 结果。只宣告真正实现并测试过的能力。[Git 协议能力文档](https://git-scm.com/docs/gitprotocol-capabilities)

### 5.3 Agent 保存与发布

1. Agent 在自己的 workspace 修改文件，可保存多个 checkpoint，不立即更新分支。

2. 显式 commit 时，固定 workspace 版本并生成 Git objects。

3. 通过 Repository Core，携带期望 old OID 发布 commit。

4. 若分支已变化，返回冲突，让客户端选择更新/rebase/merge 或创建新分支，不能静默覆盖。

保存文件、形成 commit、更新分支是三个不同操作。产品 API 和权限也应区分它们。

### 5.4 PR merge

固定 PR head、base OID、保护策略与必要检查结果，先在事务外计算候选 merge commit，再在发布事务验证这些条件仍有效并执行 ref CAS。条件变化则重新计算或拒绝。PR 展示状态、通知、索引可以通过 outbox 收敛，但“已合并”的权威依据必须是提交成功的 merge 记录及 ref 事务，而不是任务曾经开始。

## 6. 不使用仓库级大锁

原则是“对象不可变，变更集中到小范围元数据”：

- 不同 refs 的 push 不使用同一个 repo mutex。

- 同一 ref 使用 old OID + 版本 CAS；冲突明确失败。

- 多 ref 更新只锁定涉及的 ref 行，并采用固定顺序减少死锁。

- 新建 refs 使用唯一约束等机制处理并发创建，还要处理 ref 名称的前缀冲突，不能只检查完整名称相同。

- workspace 的并发控制限定在 workspace，不扩大到仓库。

- pack 计算、上传、网络传输和 hook 不持有数据库事务。

- pack 发布尽量追加独立目录项，不让所有 push 都争抢同一个“仓库版本行”。

“No repo-wide locks”不等于数据库完全不加锁。PostgreSQL 行锁、唯一约束和事务正是保护被修改数据的手段；死锁与序列化冲突要进行有界重试，而不是把错误吞掉。[PostgreSQL 锁文档](https://www.postgresql.org/docs/current/explicit-locking.html)

## 7. outbox、幂等与结果不确定

refs、业务变更和对应 outbox 在同一 PostgreSQL 事务提交。投递保证至少一次，消费者按 event_id 去重；需要顺序的业务使用聚合对象的版本，不引入仓库全局事件序号热点。

内部 mutation、workspace commit、PR merge、CI 调度等接口使用持久幂等键，查询与重试返回同一次操作结果。标准 Git 客户端不一定提供平台幂等键，因此不能声称所有网络重试都“恰好一次”。push 已提交而响应丢失时，客户端应通过重新查询远端 refs 确认结果；服务端保留可追踪的 push session/transaction 记录。

hook/webhook/CI 失败不回滚已提交的 Git push；它们进入独立重试与失败状态。外部 webhook 投递须限制目标网络，防止访问内网和云元数据端点。

## 8. GC 与 pack 维护

GC 与 repack 是不同操作：repack 改变物理布局，GC 决定什么数据能删除。

- GC roots 除活动 refs 外，还包括保留中的 ref log、workspace、PR 需要保留的 head、CI 固定 commit、进行中的读写 pin 和备份保留范围。

- 采用 mark、候选标记、宽限期、删除前复核，而不是根据一次“当前不可达”立即删除。

- 新上传、并发 ref 更新和新 pin 必须与 GC 的删除决策协调；单靠等待固定时间不能证明安全。

- repack 先写新 pack 并验证，再用短事务发布替换关系，旧 pack 等读取保护及保留期结束后再删除。

- 维护任务的租约需要 fencing，但外部删除请求可能晚到；必须在数据库内先提交不可复活的删除决定，并使用永不复用的物理 key，不能只靠删除前检查 epoch。

- PostgreSQL PITR/备份的可恢复窗口必须与对象保留窗口匹配，否则恢复数据库后可能指向已删除对象。

首版可以保守回收、优先保证不误删，之后再优化存储放大。不需要为了 GC 给仓库加覆盖整个扫描过程的大锁。

## 9. 数据所有权与内部接口

初期共享一个 PostgreSQL 集群，但按域分 schema、数据库角色和访问接口：

- platform 域：身份、组织、仓库策略、Forge。

- git 域：refs、对象目录、push session、ref transaction。

- workspace 域：快照、会话、租约。

- jobs 域：任务、outbox 投递、执行尝试。

跨模块不能随意修改别人的表。需要原子发布的有限跨域条件，由受控的发布事务统一验证，不能把远程 RPC 包在长数据库事务里。

优先稳定以下内部接口：ReadRefs、ApplyRefTransaction、PrepareObjects、ReadObject/ReadTree、CreateWorkspace、SaveCheckpoint、CreateCommit、StartRun、ReportRunResult。所有写接口明确 expected version、幂等键、作用域和失败语义，内部通信协议可后定。

## 10. 部署与扩容路线

### 首版

- platform-api：多副本无状态部署。

- git-data：多副本，配独立 CPU/内存预算及本地 SSD 缓存。

- workspace-service：控制接口可多副本，活动工作区按 workspace_id 路由到当前会话节点。

- background-worker：按队列区分并发池。

- sandbox-runner：按任务弹性扩缩，执行节点与平台控制面分离。

- PostgreSQL：高可用主节点、备份/PITR、连接池；关键 refs 和策略检查读主库。

- Redis：独立部署；通用对象存储作为持久数据层。

不把本地缓存当持久仓库，也不要求同一个 repo 的所有请求永远落到同一台机器。会话可以有短时亲和性，正确性不能依赖亲和性。

### 增长后按瓶颈拆分

- 协议连接多而 pack 计算重：从 git-data 拆出 Git Gateway 和 Pack Compute 池。

- 对象定位/缓存/回源成为瓶颈：拆出 Object Storage Service。

- workspace 数量增长：拆 Workspace Controller 与节点侧 VFS/Session Agent。

- CI 抢占交互资源：分离 CI Scheduler 与不同 runner 资源池。

- webhook、索引、GC 积压互相干扰：将对应 worker 独立部署。

- PostgreSQL 达到实际容量瓶颈：先优化查询、索引、连接和分区，再按 tenant/repo 的事务边界分片。

分片后，同仓库 atomic push 涉及的 refs 应保持在同一事务分片。Kafka 可用于分布式事件传输，但不应为了微服务数量而提前引入跨库分布式事务或服务网格。

## 11. 故障隔离与降级

- Redis 不可用：缓存退化、实时进度可能延迟；持久写入不丢失。

- Runner 不可用：终端/CI 暂停或排队；Git clone、fetch、push 仍可用。

- 维护 worker 不可用：积压并告警；在线 Git 不因缺少索引刷新而失败。

- 对象存储不可用：未缓存内容读取失败，禁止发布依赖新对象的 refs；不能用“先记账后补对象”维持假成功。

- PostgreSQL 主库不可用：停止权威变更；仅在有可靠授权上下文和完整不可变快照时提供有限缓存读取，不能承诺全部 Git 读取照常。

- git-data 单节点丢失：由其他节点接管请求；客户端重试，临时 pack 和缓存可重建。

- 活动 workspace 节点丢失：恢复最后持久 checkpoint，明确尚未持久化的变化范围。

## 12. 安全与可观测性

安全最低要求：统一 tenant/repo 授权；短时最小权限凭证；Git 对象和 pack 作为不可信输入；沙箱禁止默认执行平台 hooks；路径遍历、符号链接逃逸、压缩炸弹、超深 delta、恶意 submodule URL 和 SSRF 防护；日志不记录密钥和完整授权头。

跨租户共享缓存和内容寻址去重要防止存在性泄露。首版优先租户内复用，不用跨租户全局去重增加授权和 GC 复杂度。

从第一天贯穿 request_id、push_id、ref_transaction_id、workspace_id、run_id 和 attempt。重点指标：

- Git 请求成功率、首字节时间、pack 计算耗时、传输量。

- ref CAS 冲突率、事务耗时、锁等待和死锁。

- 对象缓存命中、回源延迟、校验失败、缺失对象。

- workspace 启动和 checkpoint 延迟、租约失效和恢复次数。

- outbox/任务最老未处理时间、重试、死信和 runner 排队时间。

- GC 删除候选量、保留量、回收失败以及备份恢复演练结果。

租户和仓库级诊断优先放在日志/trace 或受控聚合中，避免把无界 repo_id 直接做成所有指标的标签。

## 13. “支持 Git 最新版本”的验收方式

把它定义为持续维护的兼容性契约，而非镜像里存在一个最新 Git 二进制：

- 发布时使用已验证的最新稳定 Git，固定版本与构建摘要，安全更新经回归后推广。

- 持续验证最新稳定客户端的 clone、fetch、push、atomic push、force-with-lease、tag、符号引用和错误处理。

- 验证 Smart HTTP/SSH、fetch protocol v2 及必要回退；push 的 receive-pack 能力单独验证，不能笼统写成“所有操作都是 v2”。protocol v2 通过能力协商选择命令和行为。[Git protocol v2 文档](https://git-scm.com/docs/gitprotocol-v2)

- 对 shallow、partial clone/filter、LFS、SHA-256 等列明“已实现/已测试/未开放”，只宣告确实支持的能力。兼容最新客户端不等于实现其所有可选功能。

- repo.object_format 必须显式建模，不在数据库或协议代码中把 OID 长度写死。是否首版开放 SHA-256 仓库，应由互操作测试与目标客户端决定。

- 多 ref 原子失败、连接断开后结果不确定、并发 push、GC 并发、恢复后不缺对象都进入必测集合。

## 14. 实施顺序

1. **先锁定正确性契约**：PG refs 权威、对象发布顺序、ref CAS、多 ref 事务、quarantine、对象可达性和幂等边界。

2. **打通最小 Git 链路**：建仓库、push、clone/fetch、并发 refs、进程崩溃恢复与最新客户端回归。

3. **加入 workspace/VFS**：独立工作区、checkpoint、恢复、commit 和冲突发布。

4. **加入 Forge 与执行能力**：PR merge、check、CI runner、LFS、webhook。

5. **补齐运营能力**：GC、repack、配额、备份恢复、审计和故障演练。

6. **按实际指标拆服务**，不先承担十几个分布式服务的运维成本。

首个技术里程碑应验证“最新 Git 客户端 → 协议适配 → 对象存储 → PostgreSQL ref 事务”的完整闭环，并覆盖并发和崩溃。这个闭环通过后，再扩展产品功能，能尽早暴露最昂贵的协议与存储风险。
<!-- END SOURCE BODY -->
