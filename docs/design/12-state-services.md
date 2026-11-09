# 第 12 章 状态服务、权威与发布协议

> 状态：**目标设计（Proposed），未激活**。本文定义全新安装的状态服务边界和接口，不改变当前默认运行时；当前默认仍是原生 GitFS refs/objects 权威，加可选 legacy Pando 过渡。
>
> 本分支基于未合并 PR142 final `49f09c2`。按 [roots/decisions 记录](../ref-store-roots-decisions.md) 与 [PR142 证据](../../evidence/state-services/roots-decisions144/README.md)，PR142 只交付**已测试、未服务**的库级 roots/decisions/accepted-subset；没有 HTTP 路由、服务激活、Raft/Redis、GC 消费者、加密或 Blob 字节备份资格。
>
> 软件从未发布。本文只覆盖 fresh install，不设计 legacy schema/backup 升级、GitFS/Pando 导入、旧版本兼容、双写或旧数据回退。规范性摘要见 [ADR](../architecture.md)，图见 [目标架构图](architecture-diagrams.md)，执行拆分见 Root 维护的 [实施计划](implementation-plan.md)。
>
> 本文与 [ADR](../architecture.md)、[目标架构图](architecture-diagrams.md) 一起取代 [01](01-overview.md)–[11](11-ci-read-mirrors.md) 的历史设计建议，以及旧 GitFS/Patroni 拓扑作为新装目标；历史正文、当前默认实现和已有证据继续保留。

## 1. 术语与不变量

**Git 传输仅 HTTP/HTTPS**：只交付标准 Smart HTTP，入口代理终止 HTTPS；没有 SSH 服务、SSH transport、SSH 登录密钥或 SSH 兼容矩阵。原生 Git 计算视图不接受由请求指定的外部 SSH remote/命令。内部 RPC 的 mTLS 与此无关。

- **repo authority**：每个仓库唯一的 refs/CAS 写权威。`pg_refstore` 或 `raft_refcas`，创建时固定，不按请求切换。
- **authority generation**：仓库 authority 的单调代；不匹配即 fail closed。
- **byte proof**：由实际 Blob 字节回读、SHA-256/长度、locator、native verifier 和 base snapshot 组成的发布前证明。
- **durable decision**：PG 中一次性、带 authority/policy epoch、期限和 proof 绑定的发布决策；复制或伪造不能获得权限。
- **retention root**：RefStore 权威中的非过期、自包含的保留记录，拥有自己的 refs/OID、pack locator 和配额；release 单向。
- **projection cursor**：distributed 中 PG 投影已应用到 Raft 的 `(group, term, index)` 或等价位置；只用于重建/对账，不是 ref 权威。
- **disposable view**：本地裸 Git、内存 cache、Redis cache/wake；删除或丢失不影响正确性。

必须成立：

1. 每个仓库只有一个 ref 权威；没有双写、PG fallback 或旧 GitFS 卷接管。
2. 已发布 ref 的完整 Git 闭包可从同一仓库的 Blob 对象集合读取；不允许已发布 ref 指向缺失对象。
3. 大字节只在 Blob；Raft/Redis/PG 行不保存 pack、LFS、workspace、checkpoint 或 backup 内容。
4. byte proof 先于 durable decision，decision 先于 ref CAS；不存在无证明或无授权的发布。
5. PG 权限/策略是权威；撤销/权限变更有 durable barrier，旧 epoch 的未消费 decision 被拒绝。
6. distributed 的 PG refs 投影是派生数据；Raft 不可用时不得用投影或本地视图继续服务 ref。
7. PG data/WAL 与 Raft log/state/snapshot 落在正常持久设备；Blob API 不是 WAL 设备。
8. unknown 不是 success，也不是 failure；按 operation id 查询同一身份。
9. retention root 不自动过期；配额只拒绝新写入，不自动裁剪；GC 删除必须满足全部屏障。
10. fresh install 之外的数据迁移、旧格式升级和旧版本兼容不在本设计内。

## 2. 部署与状态所有权

| 状态 | 单机权威 | 分布式权威 | 说明 |
| --- | --- | --- | --- |
| 身份/权限/策略/Forge/决策意图/可靠业务任务 | PG | PG | 缓存不授予新权限 |
| refs/HEAD/pack membership/operation identity与终态/取消 | PgRefStore/PG | Raft Ref-CAS | 同仓单权威，PG 投影不是第二写者 |
| snapshot + read pin / durable root / repo retained quota | PgRefStore/PG | 同一 Ref-CAS group | 与 ref 捕获/提交/退役原子协调 |
| 共享 artifact registry/跨仓 hold/全局删除权/租户配额 | PG | PG | 与 RefStore 显式保留桥，不能仅看某仓无引用就删 |
| authz epoch / CLOSING / decision 登记 | PG | PG | Raft 保存自己的单调关闭 floor 与已登记 grant |
| Git 操作结果和事件的 PG 投影 | PG | PG | 分布式从 Ref-CAS 不可变事件幂等重放 |
| pack/idx/manifest/LFS/workspace/checkpoint/backup 字节 | Blob | Blob | 不可变 locator，独立回读核验 |
| cache / wake | 有界内存 | Redis | 全部清空可恢复 |
| 本地裸 Git 视图 | 无持久权威 | 无持久权威 | 临时盘，可删除重建 |

`authority_kind`、`authority_generation` 和 Ref-CAS 组标识属于仓库元数据，必须与任何 ref 写入一起校验。distributed 的 PG 投影即使显示旧 ref，也不能覆盖 Ref-CAS；standalone 的 `PgRefStore` 行即使被缓存，也必须以 PG 事务中的当前行为准。

## 3. 持久设备与字节放置

- **Blob**：强制远程 Apache OpenDAL（当前实现支持 S3，Azure 为可选编译特性）。使用唯一 attempt locator，上传后回读校验 SHA-256 与长度；已发布对象不原地覆盖；写入未知可能留下 orphan，不能靠地址复用来“修复”。当前 `BlobStore::delete` 禁用，物理 GC 未实现。
- **PG**：业务 PostgreSQL 的 data/WAL 需要正常持久设备、fsync、备份和恢复。standalone 的 refs 就在 PG；distributed 的权限、decision 意图、全局 artifact hold、投影在 PG；同仓 pin/root 和 Git 终态在 Ref-CAS。
- **Raft**：日志、状态机快照和成员状态需要各自的持久设备；不能把 Raft log 放 Blob，也不能用 Blob 的 read-after-write 代替 Raft 的持久性。
- **本地盘**：只放可删除的裸 Git 计算视图、staging、cache 和临时传输文件；不得作为 LFS/workspace/checkpoint/backup 的权威副本。
- **Redis/内存**：只放 cache 和 wake；不放大字节，不作为锁/日志/决策的唯一记录。

## 4. 接口契约

以下签名是设计契约，不表示全部已有实现。已有库级接口的状态按 [PR142 证据](../../evidence/state-services/roots-decisions144/README.md)、[core CAS](../ref-store-core-cas.md)、[materialized reads](../ref-store-materialized-reads.md) 与 [OpenDAL Blob](../opendal-blob.md) 的记录理解；没有 serving 路由。

### 4.1 Ref 权威

```rust
trait RefAuthority {
    capture_and_pin(repo, selector, operation, rpc_deadline) -> PinnedView;
    apply(command, rpc_deadline) -> ImmutableTerminal;
    query_operation(identity, rpc_deadline) -> OperationState;
    cancel(identity, request_digest, cancel_grant, rpc_deadline) -> ImmutableTerminal;
    close_scope(scope, authz_epoch, close_id, rpc_deadline) -> CloseReceipt;
    register_root(candidate, operation, rpc_deadline) -> RootReceipt;
    release_root(root, expected_generation, operation, rpc_deadline) -> RootReceipt;
}
```

以上为待实现的跨驱动语义契约，并非当前 Rust trait 签名。RPC deadline 只在本地协调器和传输层控制等待，不能把 `Instant`、本机墙钟、随机数、PG/Blob 网络读取带入确定性 Raft apply。V1 强读使用权威 barrier/read-index；不默认开放陈旧 PG 投影读取。

分布式 V1 的 grant 由专用 PG bridge 在确认 decision 事务提交后签发：bridge 以服务 mTLS 身份调用 Ref-CAS，grant 使用版本化签名密钥，绑定 issuer/key version、tenant/repo/group/history/backend epoch、authz epoch、operation id/digest、base pin、sealed selection、byte proof 和保留 hold。Ref-CAS 校验受信签名及本地登记/关闭状态后才能安装，普通客户端或任意 mTLS 节点不能自行制造 grant。密钥分发/轮换、伪造与跨 scope 重放拒绝属于远程授权桥的前置验收，未通过不得开放远程发布。单机使用同 PG 事务与不可伪造的进程内 capability，无需独立签发服务。

复制命令只包含 tenant/repo、authority/history/group epoch、原 operation identity/digest、已认证安装的 grant/selection/proof 摘要、精确 CAS/HEAD 更新和有界元数据。Raft 状态机校验自己持久化的单调关闭 floor、grant 及保留状态；请求字段不能替代这些权威记录。事件 cursor 绑定 history/group/log index，leader term 不是业务 authority epoch。

当前 `PgRefStore`/`PgRefStoreCore` 与 PR142 facades 只覆盖未接服务的 PG 参考实现；其 `provisioning/gitfs` bootstrap 限制必须由全新仓库 provisioning 任务替换，不能直接对正常 `ready` 仓库启用测试 gate。当前没有 Raft 依赖，OpenRaft/raft-rs 需要选型验收。

### 4.2 发布协调器

已有库级接口（未服务）：

```rust
// 已存在的 staged API（PR142 记录为未服务）
PgAuthorizedCommit::prepare(pool, plan, deadline) -> PrepareOutcome
PgAuthorizedCommit::select(...) -> AuthorizedSelection
PgAuthorizedCommit::verify(...) -> VerifiedAuthorizedPublication
PgAuthorizedCommit::commit(...) -> AuthorizedCommitReceipt
PgAuthorizedCommit::cancel(...) -> AuthorizedCancelReceipt

enum AuthorizedCommitMode { Atomic, AcceptedSubset }
```

- `prepare` 捕获已有 pending operation、gate、refs 和 pack set；`select` 从实际 native facts 收集证据，锁住真实授权/策略源表，在短事务中安装 sealed selection 和 single-use decision；`verify` 校验完整 ref map 和 native closure；`commit` 复核 authority/policy/realm/capture/proof，消费 decision 并写 ref 效果、gate revision、终态、事件和配额。
- `PgAuthorizedMetadata` 对 `metadata_only` gate 执行对应 decision install/final commit；其 receipt 只证明元数据，不证明字节可用。
- 仅在当前 PG facade 中，`PgRefStore` 的 cancellation tombstone 与 decision tombstone 同一事务写入；commit 与 cancel 共享 operation 前缀，只有一个终态胜出。COMMIT 结果未知仍为 unknown，不退款、不授予新权限。
- distributed 的新增阶段（planned）：`stage_decision`、`install_grant/apply_refcas`、`query/cancel`、`project_terminal`。commit/cancel 和 Git 终态由 Ref-CAS 同一复制日志裁决；PG 仅持久化取消意图与历史回执投影。各阶段不共享事务，必须沿用同一 operation identity 和 durable cursor。

### 4.3 字节证明与 Blob

```rust
BlobStore::new_upload(intent) -> UploadIntent   // one-use, 不可克隆/反序列化/伪造
BlobStore::put_file(UploadIntent) -> BlobReceipt
BlobStore::get_to_file(BlobLocator, deadline) -> VerifiedFile
BlobStore::verify(BlobLocator, expected_digest, expected_len, deadline) -> BlobReceipt
```

- receipt 只在完整上传、provider 回读、独立 SHA-256/长度校验后签发；ETag/stat/list 不是内容证明。`BlobReceipt` 无公开构造器/serde，不能由 locator 伪造。
- byte proof 结构至少绑定 `repo_id`、`pack_id`、pack/idx locator、SHA-256、长度、对象数、base snapshot/pin、native verifier 版本和 Blob backend identity。
- 同一内容重复发布使用不同 attempt locator；不能覆盖或复用已发布物理 key。

### 4.4 保留与配额

以下 `PgRetentionRoots` 是已存在的 PG 实现；分布式必须在 Ref-CAS 提供同等捕获、pin、登记、释放及配额语义，不能只调用 PG 账本。跨仓物理 artifact hold 仍由全局 PG 账本保护。

已有库级接口（未服务）：

```rust
PgRetentionRoots::prepare(pin, selector, deadline) -> RootCandidate
PgRetentionRoots::register(candidate, deadline) -> RootReceipt
PgRetentionRoots::release(root, reason, deadline) -> RootReceipt
PgRetentionRoots::get(root, deadline) -> RootRecord
PgRetentionRoots::materialize(root, authority, deadline) -> RootReadView
```

- root 可固定整份 captured snapshot，或 `1..=256` 个精确 OID；候选由实际 Blob/native closure 验证，不能从元数据推断。
- release 是单向终态；root 不续期、不重开、不复用；release-before-register tombstone 绑定 register digest，阻止晚到注册。
- 配额按仓库/租户实际 canonical 行字节 + 有界开销计费；拒绝/取消/终态也计入；精确 replay 零计费；配额拒绝回滚，不裁剪旧 root/hold。

### 4.5 Cache、wake 与 worker

```rust
trait Cache { get/put/invalidate; max_bytes; max_entries; ttl; }
trait Wake { notify(repo, cursor); }          // 可丢失
trait DurableTaskStore { claim/lease/fence/complete; }  // PG outbox/扫描
```

- standalone 的 `MemoryCache`/`MemoryWake` 是 planned 名称；必须有界、可删除，丢失只影响延迟。
- distributed 的 Redis 实现同一语义；删除全部 key 后由 PG outbox/任务和投影 cursor 重扫恢复，不能漏任务。
- worker 的可靠性来自 PG 持久任务、租约/fence、幂等消费和周期扫描；内存队列/Redis/Kafka 都不能替代。

## 5. 发布协议

1. **全新 provisioning**：创建仓库时固定 backend authority/history incarnation、对象格式和 group。PG 目录和 RefStore gate 的创建有持久 intent 与幂等恢复；未完成则不开放。不存在 GitFS 导入或按请求选择另一个写权威。
2. **鉴权与准备**：真实 HTTP/API/浏览器上下文读取 PG 权限、策略及准入配额；临时 Git quarantine 接收并限制字节、delta 深度、CPU、内存、临时盘、并发与期限。不得使用 synthetic principal 代替真实授权。
3. **先字节**：唯一 attempt 上传 pack/idx 并独立回读 SHA-256/长度，登记全局 artifact hold。失败可留 orphan，但不能发布 ref 或复用 locator。
4. **快照与 proof**：从当前 RefStore 原子捕获 refs/membership 与 pin。分布式 pin 在 Ref-CAS，不在 PG 投影。用实际 Blob 字节校验完整闭包并绑定原 operation、base、selection、backend/history、locator 和 verifier。
5. **PG decision**：短事务锁真实授权/策略 writer，拒绝 CLOSING scope，持久登记一次性 grant 的全部绑定、受影响 scope 和操作身份。`authz_epoch` 与 backend/history epoch 分开；PG 不能依据陈旧 refs 投影推导可发布结果。
6. **单机提交**：同一 PG 事务复核权限/策略、消费决策，原子写 refs/HEAD/membership、操作终态、Git 事件/outbox 和已预留配额。
7. **分布式提交**：Ref-CAS 认证安装 grant，随后在确定性 apply 中校验自有 floor/grant、base CAS、完整 proof/retention bindings，原子记录 accepted 集合、commit/cancel 唯一终态与 Git 事件。大字节、Git 和 PG 查询均不进入 apply。
8. **结果与投影**：确认 RefStore 不可变终态后才可宣称 Git 结果。PG projector 同事务保存稳定 event identity、业务 effects/outbox 和 cursor；PG 不可用时历史投影排队重试，不重新授权已发生事实。需要同步业务状态的入口明确等待 finalizer；不能把 PG 投影滞后当成 refs 未提交。
9. **未知与取消**：丢 ACK/超时保留 unknown，按同一 identity 查询原权威；不能换 operation 重推。单机取消与 commit 在 PG 串行；分布式取消意图必须交 Ref-CAS，由同一日志决定 commit/cancel，PG 写 tombstone 本身不能宣布已取消。

### Accepted subset

atomic 全成全败；accepted-subset 按原请求顺序固定每 ref verdict 和 sealed 接受集合。单 ref CAS/type/policy 拒绝可以保留有效兄弟项；共享 pack/旧闭包损坏拒绝整次操作。最终 proof/消费不能静默缩小集合。all-rejected 持久记录结果但不改 refs。当前 PG 实现已验收，服务入口和 Raft 同等语义仍需共同契约验收。

### 撤销：OPEN → CLOSING → CLOSED

- 所有权限、token、浏览器父 token、成员/团队、分支策略和可信 check writer 在 PG 同事务更改有效状态、提升 `authz_epoch` 并写 CLOSING intent，停止对受影响 scope 签发新 decision。
- 持久登记的 decision/dependency 索引用于枚举所有受影响 repo/group。向各 Ref-CAS group 提交幂等 `close_scope`；状态机提升自己的单调 floor、拒绝晚到旧 grant/install/apply，并按同一日志给未消费操作生成取消/拒绝终态。已在屏障前提交的事实保留原结果，不能追溯改写。
- close 与 apply 竞争只有日志中的一个顺序；丢回包须查询原 close_id/operation，不能从 PG tombstone 或客户端 floor 推断结果。全部关闭回执、在途终态、PG 投影及需要的 finalizer 对账完成后才报告撤销完成。无 quorum/PG 中断时保持 pending/fail closed。
- 新 authz epoch 只在对应 scope 的关闭过程完成并按当前权限重新开启签发；旧 epoch 永不复活。该授权桥不宣称跨 PG/Raft 原子提交。
- decision 的 deadline 定义为准入窗口，不宣称物理提交时刻上限。复制状态机不读取墙钟；过期/有界关闭机制由协调器提交确定性的关闭命令实现，并验收时钟不确定性、停顿、选主和晚到消息。在机制通过前禁止远程发布。

## 6. 失败关闭鉴权

| 条件 | 行为 |
| --- | --- |
| token 缺失/过期/撤销、仓库不存在或非成员 | 拒绝；不区分“不可见”和“无权限”的探测细节按现有安全契约 |
| 权限/策略查询失败、锁冲突、epoch 不可确认 | 拒绝或按同一 operation 重试；不默认 allow |
| cache 命中旧 allow | 只能作提示；decision 必须重读 PG 权威 |
| decision 过期、proof 缺失、base 不匹配 | 拒绝；不应用 ref |
| Raft 不可用 | distributed 的 ref 读写失败；不回落 PG 投影/本地视图 |
| PG 不可用 | 不能授权/decision/投影；不发布；不以旧投影继续 |
| Blob 不可用/字节校验失败 | 不发布新 ref；读路径不返回未验证字节 |
| 结果未知 | 返回 unknown；按 operation id 查询；不盲目重放、不宣布失败 |

撤销后的语义必须明确：已提交 ref 不回滚；撤销阻止后续发布，并通过 floor 拒绝旧 decision。若产品需要“撤销即回滚已发布 ref”，那是另一个需要单独定义和验收的能力，本设计不承诺。

## 7. 保留、配额与 GC

- live refs/membership 自身构成保留根；PR/CI/Workspace 等额外保留用途登记 pin/root/hold，不要求每次 push 创建新的永久 root。roots 非过期，release 单向，root id 不复用。
- 全局 hold 桥必须先持久预留 PG hold，再允许 RefStore 发布引用；PG 不能在任意一个仓库 root 释放后立即退役共享 hold。只有所有涉及 group 的不可逆 retirement 回执与配对投影 cursor 已对账，且晚到登记被 fence，才可退役并授权物理删除。未知 group、回执、cursor 或关闭结果一律继续 hold；TTL 不能代替证明。该桥是分布式 GC 的独立前置任务。
- GC 候选必须同时满足：无 live ref（以 ref 权威为准）、无有效 root/hold、无活动 snapshot/pin/decision、无备份保留、PG 投影 cursor 已对账。任何一项不确定都保留。
- GC 需要引用闭包核验、quarantine、幂等删除和补偿；当前没有 GC 消费者，`BlobStore::delete` 仍禁用。不得用“对象年龄超过 N 天”直接删除正式对象。
- 配额按仓库/租户限制 root、snapshot、receipt、logical bytes 等；拒绝新写入而不是裁剪。拒绝/取消/终态记录也计入；精确 replay 不重复计费。
- 新上传/新 proof 校验失败拒绝本次操作；已发布字节缺失、receipt 不匹配或闭包损坏时隔离受影响读取，尝试从 Blob 副本/备份恢复；不得返回部分对象或旧 ref 冒充成功。

## 8. 故障与恢复矩阵

| 故障 | 行为 | 恢复依据 | 禁止 |
| --- | --- | --- | --- |
| PG 不可用 | 不能鉴权、decision、投影；发布失败 | 受支持的一致备份恢复 + outbox 重扫；单独 PG/PITR 副本不得取得删除权 | 用旧缓存 allow 或 PG 投影继续发布 |
| Raft 不可用 | distributed ref 读写失败 | Raft 重启/选主后按 operation 查询；不切 PG | PG refs fallback；本地视图充当权威 |
| Blob 不可用/损坏 | 新发布失败；读按已验证物化返回或失败 | 从 Blob 副本/备份恢复；隔离损坏对象 | 返回未验证字节；发布指向缺失对象 |
| Redis 清空/不可达 | cache/wake 丢失，任务延迟增加 | PG durable outbox/任务 + 投影 cursor 扫描 | 漏任务；把 Redis 当事实源 |
| worker 崩溃/租约过期 | 任务由新 worker 重领 | PG 租约/fence、幂等消费、周期扫描 | 旧 fence 写入；静默丢弃 |
| COMMIT/Apply 结果未知 | 返回 unknown，按 operation id 查询 | PG terminal/decision + Ref-CAS receipt | 盲目重试出第二个 terminal |
| decision 已安装但 apply 前崩溃 | operation 仍 pending/unknown；decision 可过期/撤销 | 重新查询/对账；不自动改 ref | 把 pending 当成功；跳过 proof |
| Raft 已应用但 PG 投影缺失 | ref 已生效；客户端可能看到 unknown | 从 durable cursor 幂等重放投影 | 用投影覆盖 Raft；重新 apply 产生新 ref 效果 |
| 本地裸 Git 视图丢失/损坏 | 删除并按 Blob + ref 权威重建 | 重新 materialize/fsck | 从本地视图反推发布状态 |
| 恢复三点不匹配 | 不开放服务 | 重新取得一致 PG/Raft/Blob 点；隔离目标 | 混用不同时间点；旧格式升级导入 |

## 9. 备份与全新恢复

1. 冻结入口、独立 PG worker、Raft 新 apply/管理命令及 Blob maintenance/deleter；建立持久备份保留根，排空在途操作或记录 unknown 并完成可验证关闭，不能在未闭合的后台写入间任意取三个快照。
2. 捕获 PG cut/决策/全局 hold/outbox/cursor、RefStore 一致 snapshot/log index/refs/pins/roots/terminals（单机在 PG 内，无 Raft 项）和 Blob 完整对象闭包，写同一不可变 manifest。manifest 包含当前 schema/格式、backend/history/group、配对 cut、对象摘要、必要密钥版本和可信来源证明。
3. 只恢复到隔离的全新同版本目标。验证 closure 与 manifest 后分配新 deployment/history incarnation，撤销旧 token/session/decision/worker/deleter grant 的执行资格；旧部署同时存在时也不能删除恢复点所需字节。原始 PG/PITR 复制不自动获得写入/删除资格。
4. 按 manifest 恢复权威和字节，幂等重放 PG 投影/finalizer，对账权限/撤销/hold/roots/cursor。清空本地计算目录后 fresh clone、fsck、真实 API/Web/LFS/CI 工作流通过，再开放写入。
5. 任何 cut/authority/摘要不匹配、缺对象或旧 grant 仍有效都拒绝开放。分别报告备份点损失和故障恢复 RPO/RTO，不承诺零损失；不要求旧版本格式升级、GitFS 导入或跨版本回滚。既有 [备份工具](../backup-restore.md) 不是新模式已完成的证明。

## 10. 支持范围

**支持的目标部署**：

1. **standalone**：一个 Rust 应用 + 业务 PostgreSQL + 进程内 `PgRefStore`（PG 持久化，不是内存 refs）+ 有界 `MemoryCache`/`MemoryWake` + 内置可靠 worker + 强制 Apache OpenDAL 远程 Blob；不要求 Redis/Raft/Kafka/Vault/FUSE/controller。
2. **distributed**：应用/计算节点 + 业务 PostgreSQL + 开源 Raft-backed Ref-CAS 服务 + Redis cache/wake + 同一 Blob 层 + 独立可选 worker；大字节不进 Raft/Redis；Raft 不可用不回落 PG。

**明确不支持**：旧 GitFS/Pando 数据导入、旧 schema/backup 升级、旧版本兼容、双权威/双写、PG fallback、把本地 FS 当持久 Blob、把 Blob 当 WAL、依赖 FUSE/controller 才能提供基础服务、无 proof/无 decision 发布。Git 客户端兼容矩阵仍需单独实测，不由本文宣称。

## 11. 验收拆分

| 阶段 | 内容 | 当前状态 |
| --- | --- | --- |
| A. 设计 | 本 ADR、图、第 12 章、fresh-install 边界 | 本 PR 的文档变更；无运行时变更 |
| B. 库级基础 | PR142 roots/decisions/accepted-subset；PG/S3/Git 库测试 | 已测试但**未服务**；无 HTTP 路由/激活 |
| C. standalone 激活 | PG `PgRefStore` 作为持久 ref 权威、PG decision、MemoryCache/Wake、内置 worker、OpenDAL Blob | 未实现；需 cutover/activation API、真实 provider 和故障注入 |
| D. distributed Ref-CAS | Raft 库选型、Ref-CAS、Redis、投影 cursor、独立 worker | 未实现；openraft vs raft-rs 是实测任务 |
| E. 保留/GC | root/hold/backup 屏障、GC planner、物理删除、quarantine | 未实现；当前 Blob delete 禁用 |
| F. fresh restore | PG+Raft+Blob 协调备份、隔离恢复、投影重建、fsck | 未实现；无 RPO/RTO 声明 |
| G. 运维/HA | 监控、限流、备份演练、业务 PG HA 选择 | 未实现；Patroni 等不改变 ref 权威 |

## 12. 未决问题

1. **Raft 库**：openraft vs raft-rs 的实测选择标准（安全/活性、snapshot、membership、线性读、故障注入、维护、许可证、异步运行时、集成成本）；不预先宣布胜者。
2. **Ref-CAS 分组**：每仓一组或按租户/分片共享；跨组原子多仓发布不支持；成员变更、快照传输和组迁移需设计。
3. **撤销 floor**：PG epoch 与 Raft floor 的推进顺序、时钟偏差、恢复时回退保护和观测。
4. **投影 cursor**：格式、读己写、滞后读取、UI 陈旧标记和对账 API；Git 读取不得使用投影。
5. **GC**：引用闭包算法、备份保留、root 释放、物理删除 idempotence/补偿和 provider 行为。
6. **fresh restore**：三存储协调、隔离目标、权限/撤销轮换、故障注入和实际 RPO/RTO。
7. **服务激活**：standalone/distributed 的 activation/cutover API、路由、默认运行时切换；由 [实施计划](implementation-plan.md) 拆分。
8. **业务 PG HA**：Patroni 等外部 HA 是部署选择，不是 ref 权威；不把旧 GitFS/Patroni 拓扑当作目标。
9. **KeyProvider/加密**：Vault 非必需；本地 envelope/远程 KMS 的选择、密钥轮换和 Blob 加密仍是后续设计，不影响本设计的明文字节契约。
