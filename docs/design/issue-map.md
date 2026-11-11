# 新旧任务映射

维护者明确要求改用全新 Blob-only 单机 / Raft Ref-CAS 分布式设计，项目尚未发布。本轮删除的是被取代的旧架构专属任务，不是将其标记“已完成”；不再安排旧 GitFS 导入或旧版本升级。原始 issues/评论已在维护工作区留存删除前快照，已完成历史验收及仍适用产品/缺陷没有删除。

## 旧架构任务替代

旧编号用纯文本显示，避免把已删除 issue 当可访问入口。技术和验收范围已经分配到真实替代任务；原 #48 的产品子项另外完整保留在下表。

| 旧编号 | 处理 | 替代任务 |
| --- | --- | --- |
| `20` | 已删除（按新范围取消，非验收完成） | [#108](https://github.com/jihuayu/rootyard/issues/108) |
| `22` | 已删除（按新范围取消，非验收完成） | [#109](https://github.com/jihuayu/rootyard/issues/109), [#110](https://github.com/jihuayu/rootyard/issues/110), [#144](https://github.com/jihuayu/rootyard/issues/144), [#148](https://github.com/jihuayu/rootyard/issues/148) |
| `24` | 已删除（按新范围取消，非验收完成） | [#150](https://github.com/jihuayu/rootyard/issues/150), [#143](https://github.com/jihuayu/rootyard/issues/143), [#144](https://github.com/jihuayu/rootyard/issues/144) |
| `26` | 已删除（按新范围取消，非验收完成） | [#115](https://github.com/jihuayu/rootyard/issues/115), [#116](https://github.com/jihuayu/rootyard/issues/116), [#152](https://github.com/jihuayu/rootyard/issues/152), [#155](https://github.com/jihuayu/rootyard/issues/155), [#157](https://github.com/jihuayu/rootyard/issues/157) |
| `43` | 已删除（按新范围取消，非验收完成） | [#155](https://github.com/jihuayu/rootyard/issues/155), [#157](https://github.com/jihuayu/rootyard/issues/157), [#153](https://github.com/jihuayu/rootyard/issues/153) |
| `44` | 已删除（按新范围取消，非验收完成） | [#157](https://github.com/jihuayu/rootyard/issues/157), [#154](https://github.com/jihuayu/rootyard/issues/154) |
| `48` | 已删除（按新范围取消，非验收完成） | [#105](https://github.com/jihuayu/rootyard/issues/105), [#123](https://github.com/jihuayu/rootyard/issues/123) |
| `121` | 已删除（按新范围取消，非验收完成） | 取消旧数据导入/迁移；没有替代迁移任务 |

旧 20 的 provider 能力归 OpenDAL；旧 22 的真实网关能力归单机/Gateway，不再做 Pando 迁移；旧 24 的安全流式路由归 RPC/Gateway；旧 26/43/44 的不双写、依赖 HA、物理故障域与 RPO/RTO 归新的分布式部署/资格；旧 121 的旧库导入与双向迁移不再安排，全新 provisioning 与同格式恢复有独立任务，但不替代旧数据迁移。

旧总路线 48 的正文及进度已逐字保存在 [退役历史记录](../acceptance/retired-roadmap48.md)，原 SHA-256 可核验；它不再定义当前任务。

## 保留编号并改写的架构任务

- [#105](https://github.com/jihuayu/rootyard/issues/105)：[Roadmap] Blob-only 单机与 Raft Ref-CAS 分布式状态服务。
- [#106](https://github.com/jihuayu/rootyard/issues/106)：[State/W0] 冻结全新安装 Blob-only 双部署契约与基线。
- [#107](https://github.com/jihuayu/rootyard/issues/107)：[State/W1] 完成 PG RefStore 服务权威与未决语义。
- [#108](https://github.com/jihuayu/rootyard/issues/108)：[State/W1-B] 完成 OpenDAL Blob 生产 provider 契约。
- [#109](https://github.com/jihuayu/rootyard/issues/109)：[State/W1-C] 全内容 Blob、可丢 Git 视图与 KeyProvider。
- [#110](https://github.com/jihuayu/rootyard/issues/110)：[State/W1-L] 交付单进程 PG+Blob 轻量单机。
- [#111](https://github.com/jihuayu/rootyard/issues/111)：[State/W2] Memory/Redis 缓存唤醒且 Redis 仅可丢。
- [#112](https://github.com/jihuayu/rootyard/issues/112)：[State/S3] PG 发布决策服务接入、真实权限 writer 与撤销屏障。
- [#113](https://github.com/jihuayu/rootyard/issues/113)：[State/W4-A] 全局 Blob artifact hold、配额与防 ABA。
- [#114](https://github.com/jihuayu/rootyard/issues/114)：[State/S2] 补齐 RefStore snapshot/pin/root 核心契约与同权威保留语义。
- [#115](https://github.com/jihuayu/rootyard/issues/115)：[State/W5-A] 交付真实持久 Raft Ref-CAS 运行时。
- [#116](https://github.com/jihuayu/rootyard/issues/116)：[State/W5-B] 确定性 Ref-CAS 状态机与幂等 CAS。
- [#117](https://github.com/jihuayu/rootyard/issues/117)：[State/D4] Ref-CAS Git 事件重放、PG 投影与可靠任务桥。
- [#118](https://github.com/jihuayu/rootyard/issues/118)：[State/W7-A] PG PR 合并与可恢复 finalizer 先行。
- [#119](https://github.com/jihuayu/rootyard/issues/119)：[State/W7-B] CI/Namespace/Workspace/LFS producer 先行接入。
- [#120](https://github.com/jihuayu/rootyard/issues/120)：[State/W8-A] 当前格式 PG+Blob 配对全新恢复。
- [#122](https://github.com/jihuayu/rootyard/issues/122)：[State/W9-A] Blob 压实与默认关闭的安全 GC。
- [#123](https://github.com/jihuayu/rootyard/issues/123)：[State/Release] 汇总单机与分布式新架构资格及发布闸门。
- [#42](https://github.com/jihuayu/rootyard/issues/42)：[Perf] 独立 ref 并发写入不引入整仓传输锁。

## 新增的实施子任务

- [#143](https://github.com/jihuayu/rootyard/issues/143)：[State/S1] 全新安装初始化、正常仓库创建与唯一 authority 的幂等 provisioning。
- [#144](https://github.com/jihuayu/rootyard/issues/144)：[State/S2] 公网 Git/Browse/ref 事务 API 统一走 RefStore 与 Blob 临时视图。
- [#145](https://github.com/jihuayu/rootyard/issues/145)：[State/S4] LFS Batch、传输与发布证明统一走 Blob 并用官方客户端验收。
- [#146](https://github.com/jihuayu/rootyard/issues/146)：[State/S4] workspace/checkpoint 字节单 barrier 入 Blob、不可变 manifest 与远端恢复。
- [#147](https://github.com/jihuayu/rootyard/issues/147)：[State/S4] CI checkout pin/revocation 与 Namespace GitView 的生产者与原子 retention。
- [#149](https://github.com/jihuayu/rootyard/issues/149)：[State/D] 成熟 Raft 存储适配：WAL/vote/hardstate、原子 apply 与真实故障注入。
- [#150](https://github.com/jihuayu/rootyard/issues/150)：[State/D] 租户作用域 mTLS Raft RPC、ReadIndex 与有界流式协议。
- [#152](https://github.com/jihuayu/rootyard/issues/152)：[State/D] PG OPEN→CLOSING 投影、signed decision 与吊销前 drain/terminal 屏障。
- [#155](https://github.com/jihuayu/rootyard/issues/155)：[State/D] 真实 3 选票独立主机分布式部署 profile 与 PG/ingress HA 策略。
- [#154](https://github.com/jihuayu/rootyard/issues/154)：[State/S6] 单进程 app+PG+Blob 安装、SIGKILL 全恢复与资源成本实测。
- [#157](https://github.com/jihuayu/rootyard/issues/157)：[State/D] 真实 3 主机故障矩阵、ACK 完整性、RPO/RTO 与容量成本。
- [#148](https://github.com/jihuayu/rootyard/issues/148)：[State/S5] 移除 GitFS legacy Pando 运行时与本地 durable 回退，保留产品安全行为与证据。
- [#156](https://github.com/jihuayu/rootyard/issues/156)：[State/D] PR 合并经 remote authz 的 Ref-CAS receipt 投影与可恢复 finalizer。
- [#153](https://github.com/jihuayu/rootyard/issues/153)：[State/D] PG 切点+Raft index+Blob closure 配对备份与全新 incarnation 恢复。
- [#151](https://github.com/jihuayu/rootyard/issues/151)：[State/D] 全局 PG artifact hold 与 Ref-CAS pin/root 的可恢复保留桥。

## 新发布的后继任务与修复 backlog（#166–#168 缺陷修复已并入 PR #170 集成；#169 候选实现待 PR CI/合并）

维护者另行发布了下列 issue。未实现的后继 backlog（#162–#165、#174）**尚未实现**、没有任何验收结果；#166–#168 已有绑定各自提交的组件修复与测试，最终集成 CI 与 issue 关闭以 PR #170 为准；#169 的候选实现已进入 `codex/backup169-candidate-20261110`，但尚未合并，不能据此称为已交付。两者都不改变上面任务的完成状态，不构成分布式/HA/GC 能力声明。标题取自 GitHub；合并与验收完成后才可据实更新。范围摘要与技术前置见[实施计划](implementation-plan.md)的“新增任务与修复 backlog”一节。

| issue | 标题 | 类型 |
| --- | --- | --- |
| [#162](https://github.com/jihuayu/rootyard/issues/162) | [Rubicon] 独立交付无删除 Blob 压实及可扩展维护吞吐 | #122 的 subtask；不是物理 GC |
| [#163](https://github.com/jihuayu/rootyard/issues/163) | [Rubicon] 接通版本感知的可丢计算副本缓存与有界路由调度 | 功能 backlog |
| [#164](https://github.com/jihuayu/rootyard/issues/164) | [Rubicon] 增加同仓 push/read/maintenance 稳态混合负载与扩容基线 | 测量 backlog；不是容量声明 |
| [#165](https://github.com/jihuayu/rootyard/issues/165) | [Rubicon] 将 MIDX、bitmap、commit-graph 作为可重建 Blob 读加速产物 | 非阻塞优化 |
| [#166](https://github.com/jihuayu/rootyard/issues/166) | [CI] 修复 genuine schema007 备份恢复回归，恢复完整合并门禁 | 缺陷修复 |
| [#167](https://github.com/jihuayu/rootyard/issues/167) | [Raft/P2] 持久日志范围读取检测内部缺口并失败关闭 | 实验 crate 缺陷（待复现） |
| [#168](https://github.com/jihuayu/rootyard/issues/168) | [P2] W0 baseline runner 落实运行因子、临时空间与全程绝对期限 | 工具缺陷 |
| [#169](https://github.com/jihuayu/rootyard/issues/169) | [Backup/P2] 配对归档逐项验证注册 pack 的完整 artifact 集合与摘要 | 备份缺陷；候选修复（待 PR CI 与合并） |
| [#170](https://github.com/jihuayu/rootyard/issues/170) | Integrate the pending Forge and Blob/RefStore PR stack with reviewed recovery fixes | 集成 PR |
| [#171](https://github.com/jihuayu/rootyard/issues/171) | [Integration] 分离历史 W0 冻结快照与当前架构，修复合并后的验证契约 | 合并契约修复 |
| [#172](https://github.com/jihuayu/rootyard/pull/172) / [#174](https://github.com/jihuayu/rootyard/issues/174) | Pando 一致性与会话读取契约（提案）/ 对应会话读取实施 | 文档提案；实施 backlog（未实现） |
| [#173](https://github.com/jihuayu/rootyard/pull/173) | 持久日志范围读取拒绝内部缺口 | 并入 #167 的修复，已随 PR #170 集成 |

原 #149 Raft 存储适配仍为 open：PR #160 的 `crates/refcas-log` 只是隔离的实验 crate，仅交付日志存储切片，不完成 #149/#115。

## 完整保留的产品、缺陷和已关闭历史

以下是重整前其余全部 71 个 issue 的状态快照；“open”不表示本轮新验收失败，“closed”也不推广为新架构资格。原 #48 的仍开放产品子项均在此，未随旧 umbrella 删除。当前运行路径的缺陷继续保留，直到相应修复合并验收或旧路径彻底移除后完成适用性复核。

| issue | 原状态 | 范围 |
| --- | --- | --- |
| [#2](https://github.com/jihuayu/rootyard/issues/2) | open | [P1] overlay-write follows parent symlinks and overwrites the read-only lower layer |
| [#3](https://github.com/jihuayu/rootyard/issues/3) | closed | [P1] Push webhook synchronization permanently skips events after the first 200 |
| [#4](https://github.com/jihuayu/rootyard/issues/4) | open | [P1] Owner-only gates reject authorized collaborators on Git transport and write endpoints |
| [#5](https://github.com/jihuayu/rootyard/issues/5) | closed | [P1] LFS uses the caller as tenant and fails for authorized collaborators |
| [#6](https://github.com/jihuayu/rootyard/issues/6) | closed | [P2] RBAC schema detection hard-codes public and breaks custom search_path deployments |
| [#7](https://github.com/jihuayu/rootyard/issues/7) | open | [P1] Concurrent audited writes fail because audit IDs are allocated with MAX(id) + 1 |
| [#8](https://github.com/jihuayu/rootyard/issues/8) | open | [P2] Browse pagination enumerates every ref and fails on large repositories even with limit=1 |
| [#9](https://github.com/jihuayu/rootyard/issues/9) | open | [P2] Commit browsing launches one Git subprocess per commit instead of batching object reads |
| [#10](https://github.com/jihuayu/rootyard/issues/10) | open | [P2] E2E validation can pass without executing the requested Rust binary |
| [#11](https://github.com/jihuayu/rootyard/issues/11) | closed | [P1] The members integration-test entrypoint cannot run the command configured in CI |
| [#12](https://github.com/jihuayu/rootyard/issues/12) | open | [P1] Any writable user token can modify global shard nodes and disrupt other tenants |
| [#13](https://github.com/jihuayu/rootyard/issues/13) | closed | [P1] A failed queued LFS upload can delete an object already committed by another upload |
| [#14](https://github.com/jihuayu/rootyard/issues/14) | open | [P1] Ref transactions update Git before recording durable intent, leaving untracked successful mutations |
| [#15](https://github.com/jihuayu/rootyard/issues/15) | open | [P1] Failed shard state transitions leave durable volume markers inconsistent with rolled-back PostgreSQL state |
| [#16](https://github.com/jihuayu/rootyard/issues/16) | closed | [P2] Concurrent webhook dispatches can overwrite a delivered result with dead_letter |
| [#17](https://github.com/jihuayu/rootyard/issues/17) | closed | [P2] A stalled LFS request body holds the repository write lock without a transfer deadline |
| [#18](https://github.com/jihuayu/rootyard/issues/18) | open | [P1] Direct Git writes and ref transactions bypass configured branch protection |
| [#19](https://github.com/jihuayu/rootyard/issues/19) | closed | [P2] Webhook HTTPS targets use plaintext on loopback and always fail for external hosts |
| [#21](https://github.com/jihuayu/rootyard/issues/21) | open | [Feature] Implement authenticated pack encryption and KMS-backed key rotation |
| [#23](https://github.com/jihuayu/rootyard/issues/23) | closed | [Feature] Run storage maintenance as durable background jobs |
| [#25](https://github.com/jihuayu/rootyard/issues/25) | closed | [Feature] Implement repository replication and resumable shard data migration |
| [#27](https://github.com/jihuayu/rootyard/issues/27) | open | [Feature] Add the persistent, authorized Workspace service API |
| [#28](https://github.com/jihuayu/rootyard/issues/28) | open | [Feature] Add live workspace capture, consistent checkpoints and replayable events |
| [#29](https://github.com/jihuayu/rootyard/issues/29) | open | [Feature] Persist workspace checkpoints over an authenticated remote CAS protocol |
| [#30](https://github.com/jihuayu/rootyard/issues/30) | closed | [Feature] Add transparent on-demand filesystem hydration for Workspace VFS |
| [#31](https://github.com/jihuayu/rootyard/issues/31) | open | [Feature] Serve authorized Namespace and Git View workflows online |
| [#32](https://github.com/jihuayu/rootyard/issues/32) | closed | [Feature] Implement the Agent and CI sandbox runner lifecycle |
| [#33](https://github.com/jihuayu/rootyard/issues/33) | closed | [Feature] Automatically synchronize PRs and deliver webhooks from durable background workers |
| [#34](https://github.com/jihuayu/rootyard/issues/34) | open | [Feature] Add durable CI run orchestration and multi-mirror checkout scheduling |
| [#35](https://github.com/jihuayu/rootyard/issues/35) | open | [Feature] Bind required CI checks to trusted integration identities |
| [#36](https://github.com/jihuayu/rootyard/issues/36) | open | [Feature] Include LFS and submodule dependencies in CI checkout readiness |
| [#37](https://github.com/jihuayu/rootyard/issues/37) | open | [Feature] Enforce bounded authorization revocation on active checkout transfers |
| [#38](https://github.com/jihuayu/rootyard/issues/38) | closed | [Feature] Complete SHA-256 repository support across hosting, Forge and CI checkout |
| [#39](https://github.com/jihuayu/rootyard/issues/39) | closed | [Feature] Store and recover LFS objects through the remote object-storage backend |
| [#40](https://github.com/jihuayu/rootyard/issues/40) | closed | [Feature] Validate newly introduced Git LFS pointers before publishing refs |
| [#41](https://github.com/jihuayu/rootyard/issues/41) | open | [Deferred feature] Implement the Git LFS file-locking protocol |
| [#45](https://github.com/jihuayu/rootyard/issues/45) | closed | [Validation] Add a real Git client and repository-state compatibility matrix |
| [#46](https://github.com/jihuayu/rootyard/issues/46) | open | [Feature] Add organization-owned repositories, teams and company namespace ownership |
| [#47](https://github.com/jihuayu/rootyard/issues/47) | closed | [Feature] Add browser sign-in, sign-out and revocable Web UI sessions |
| [#66](https://github.com/jihuayu/rootyard/issues/66) | open | [P1] Webhook 默认放行本机回环地址，削弱服务隔离 |
| [#67](https://github.com/jihuayu/rootyard/issues/67) | open | [P1] Webhook 将 actor.id 当 tenant_id，组织与协作者路径失效 |
| [#68](https://github.com/jihuayu/rootyard/issues/68) | open | [P1] Workspace 自动捕获永久停留在按UUID排序的前100个 |
| [#69](https://github.com/jihuayu/rootyard/issues/69) | open | [P2] 无活跃Webhook的PR不会随Git push自动更新 |
| [#70](https://github.com/jihuayu/rootyard/issues/70) | open | [P2] MAX(sequence)+1并发分配导致Webhook投递分页遗漏 |
| [#71](https://github.com/jihuayu/rootyard/issues/71) | open | [P2] LFS本地已验证字节仍依赖远端HEAD成功 |
| [#72](https://github.com/jihuayu/rootyard/issues/72) | open | [P2] Webhook全局串行扫描存在仓库间队头阻塞 |
| [#73](https://github.com/jihuayu/rootyard/issues/73) | open | [P2] Workspace全量双重fingerprint和同步Git调用占用async worker |
| [#74](https://github.com/jihuayu/rootyard/issues/74) | open | [P2] 列表能力有固定截断且缺可继续游标 |
| [#75](https://github.com/jihuayu/rootyard/issues/75) | open | [P2] 当前工具链下Clippy发布门禁失败 |
| [#76](https://github.com/jihuayu/rootyard/issues/76) | open | [P2] 近期关键native验收未作为常规CI回归 |
| [#77](https://github.com/jihuayu/rootyard/issues/77) | open | [P1] Pando元数据单独PITR副本不能安全共享可删bucket |
| [#78](https://github.com/jihuayu/rootyard/issues/78) | open | [P2] 当前运维入口混有过时能力声明 |
| [#79](https://github.com/jihuayu/rootyard/issues/79) | open | [Perf] 减少 LFS Batch 与下载的重复完整校验及远端请求 |
| [#80](https://github.com/jihuayu/rootyard/issues/80) | open | [P2] 增加脱敏结构化错误及任务积压观测 |
| [#81](https://github.com/jihuayu/rootyard/issues/81) | open | [P2] 为过期浏览器会话和子Token增加有界清理 |
| [#82](https://github.com/jihuayu/rootyard/issues/82) | open | [Feature] 为人用 API Token 增加仓库和动作Scope及自助管理 |
| [#83](https://github.com/jihuayu/rootyard/issues/83) | open | [Feature] 落实租户硬磁盘配额与聚合资源准入 |
| [#84](https://github.com/jihuayu/rootyard/issues/84) | open | [Feature] 补齐浏览器统一身份、MFA与认证接口限流 |
| [#85](https://github.com/jihuayu/rootyard/issues/85) | open | [Feature] 完善仓库归档、改名、删除恢复及安全Ownership Transfer |
| [#86](https://github.com/jihuayu/rootyard/issues/86) | open | [Feature] 补齐搜索、标签负责人、通知订阅与行级PR评审 |
| [#87](https://github.com/jihuayu/rootyard/issues/87) | open | [Feature] 增加组织、集成、用量及后台恢复状态管理界面 |
| [#88](https://github.com/jihuayu/rootyard/issues/88) | open | [Feature] 明确并扩展Workspace对Submodule、Linked Worktree和LFS等Git状态的支持 |
| [#90](https://github.com/jihuayu/rootyard/issues/90) | open | [P2] 为 Pando artifact 链接及维护任务补齐租户复合外键 |
| [#91](https://github.com/jihuayu/rootyard/issues/91) | open | [P2] 隔离 Workspace FUSE session 生命周期并补齐崩溃后的挂载回收 |
| [#95](https://github.com/jihuayu/rootyard/issues/95) | open | [P1] 原生 FUSE 工作区 live sandbox 挂起且服务在 SIGKILL 后未退出 |
| [#96](https://github.com/jihuayu/rootyard/issues/96) | open | [P1] 真实 post-receive 收据恢复被 recovering 状态的当前写鉴权阻断 |
| [#98](https://github.com/jihuayu/rootyard/issues/98) | open | [P2] Historical Git receipt projection is still blocked by current membership triggers after access removal |
| [#126](https://github.com/jihuayu/rootyard/issues/126) | open | Git receive-pack 同 ref 竞争返回 HTTP409，缺少可验证的 Git report-status 拒绝结果 |
| [#130](https://github.com/jihuayu/rootyard/issues/130) | open | [CI] schema138 Browse 原生验收在准备成功后首次 refs 请求返回 404 |
| [#134](https://github.com/jihuayu/rootyard/issues/134) | open | [CI] Sharding 原生夹具以普通 token 调全局管理 API，被正确的 operator gate 拒绝 |
| [#139](https://github.com/jihuayu/rootyard/issues/139) | open | [P2] Git 闭包验证的 loose refs 会放大目录与 inode 使用 |
