# Rootyard 实现状态

本页区分当前目标、候选代码与已验收范围。规范见 [架构](../architecture.md)、[最新实施计划](implementation-plan.md) 和 [任务映射](issue-map.md)。项目尚未发布，不安排旧版本升级或 GitFS 导入。

## 当前基线与剩余工作

本页状态以 [PR #170](https://github.com/jihuayu/rootyard/pull/170)（`codex/rubicon-all-pr-merge` → `main`）作为当前集成的权威记录；其最终合并状态、CI 结论与产出以该 PR 的最终检查和 artifacts 为准，本页不预先断言。该 PR 集成 32 个组件 PR（原 30 个及后来加入的 #172、#173），各组件 PR 的目标分支已统一为 `main`，实际合并状态以 PR #170 和原始 PR 记录为准；集成过程中的修复与合并结果见下节“集成状态”。集成状态不改变运行时边界：默认入口仍是既有 `serve`（legacy GitFS/Pando），Blob 单机仍是显式 `serve-blob` 候选，Raft 运行时未启用；分项组件验收不表示默认服务已替换，也不表示任何实施任务 epic 已全部完成。历史基线 PR #142 / `49f09c2` 的四组原生 8+11+12+20=51 场景（零失败、零忽略）及其证据见 [roots/decisions 证据](../../evidence/state-services/roots-decisions144/README.md)，保持原范围（其中的 CI 通过结论限于当时提交，不延伸到本分支）。

| 能力 | 当前状态 | 后续范围 |
| --- | --- | --- |
| OpenDAL Blob、KeyProvider、cache/wake | 有独立组件与限定验收；`state-redis` 为默认关闭的可选 feature，Redis 只作可丢缓存/唤醒 | 全内容/加密路径接入、provider 与部署边界验收 |
| PgRefStore 操作身份、CAS、pack 发布、快照和物化 | 库实现；显式 `serve-blob` 候选入口已使用 | 默认入口替换、全部业务 producer 与权限上下文等价 |
| artifact holds / durable roots | 有持久账本和真实 PG/Blob/native Git 验收 | PR/CI/Workspace/LFS producers、GC 与完整恢复闭包 |
| PG decisions / accepted-subset | PR #142 库增量验收通过 | HTTP/业务入口、浏览器与 Merge producer、远程 Raft 决策桥 |
| Blob-only standalone（显式 `serve-blob`） | 候选：clone/push、tree/blob 与 refs/历史/compare 浏览、format22 配对备份/恢复有真实验收 | 默认部署替换、LFS/PR/Workspace/CI 接入、默认服务验收 |
| Raft Ref-CAS distributed | 未交付；仅 PR #160 的独立实验 crate（见下） | 开源库选型、持久运行时、状态机、RPC、权限桥与 PG 投影 |
| 全新环境恢复与生产资格 | format22 同后端配对恢复有证据；组件恢复有旧证据 | 新架构 PG/Raft/Blob 一致恢复、独立故障域和容量成本验收 |
| 默认服务与对外 Git 传输 | 默认 `serve` 仍是既有 GitFS/Pando 实现；对外 Git 只承诺 Smart HTTP（HTTPS 由入口代理终止），不实现 SSH | 默认入口切换后补齐其特征接入 |

## Blob 单机服务候选：`serve-blob`

`rootyard serve-blob` 是显式的候选入口（`src/standalone.rs`），默认 `serve` 不受影响。它基于 schema147 的正常仓库创建、PG RefStore、OpenDAL Blob 和可丢弃 Git 计算视图运行；启动时检查未完成恢复标记、持有数据库级共享生命周期屏障，屏障丢失即关闭准入。

服务能力与验收（同机、真实 PostgreSQL/S3/原生 Git、当前源码绑定二进制）：

- HTTP/Git：`tests/blob_only_service.py` 11 项；tree/blob 浏览 `tests/blob_gateway_browse.py` 7 项（`f1889aa` 通过）；refs、提交列表/详情和 compare 历史 API 7 项（`7690758` 通过）。浏览复用捕获的 RefStore 快照、Blob 物化和真实 token/session 权限，支持 SHA-1/SHA-256、带注解标签、当前 refs 可达的历史对象、分页及二进制文件；消息、遍历、子进程输出和 JSON 编码都有明确上限。
- 并发提交收尾只在原 pending token、请求绑定与同一 realm 持久 gate 前进均核对后写入拒绝终态；真正结果未知的提交保持 UNKNOWN。A3 两个指定竞争窗口只有错误分类单元回归，HTTP 竞争验收不保证调度恰落在这两个窗口。
- 备份：format22/schema147 配对归档（见下节）7 项、旧 format21 备份/恢复 7 项，均在 `1d1ce62` 通过。
- 本地结构检查（非新增执行记录）：`src/standalone.rs` 只构造 Smart HTTP 路由，不提供 SSH 入口；`state-redis` 默认不在 feature 中，`serve-blob` 目前不使用 Redis；独立实验 crate 不在根依赖中。

Rust 与 Python 计数来自各候选提交当时记录的实跑：`7690758` 上 Rust 库测试 464 通过、9 项服务依赖测试显式忽略，最小依赖 all-targets Clippy 通过（候选 PR #159/#161 的 GitHub 主 CI `verify` 任务当时为失败，记录未追溯根因；独立的 CI 恢复与问题修复在其他分支进行，本页不重复）；`backup_blob_serving147.py` 记录 Python 336 项中 331 通过、5 跳过，外加 3 项 live S3 工作区用例通过。上述结果绑定各自源码提交；集成后的全量门禁（all-targets Clippy、Rust 测试与 native/remote 用例）以 PR #170 最终检查与 artifacts 为准，本页不另作汇总通过声明。

## 集成状态（PR #170）

- **范围与 ancestry**：集成 32 个组件 PR；每个组件 PR 的 head 保留在集成 history 中（经真实 merge 提交而非 squash/rebase）；各组件 PR 的目标分支已统一为 `main`，实际合并状态以 PR #170 和原始 PR 记录为准。集成后仅新增集成门禁修复（issue #171）及后并入的 #172、#173。
- **验收依据**：集成后的最终 CI 与 native/remote 结果见 PR #170 的最终检查和 artifacts；最终通过与否以该处为准，本页不在验证前给出全量通过结论。
- **缺陷修复组件**（结果绑定各自提交的证据；当时集成后的 CI 仍待完成，未把分项结果推广为整体通过）：
  - [issue #166](https://github.com/jihuayu/rootyard/issues/166)（本地集成修复提交 `bc0cff1`，LunaMax 已审）：备份 9 项；源码绑定二进制以当前 format21 恢复，并以真实的旧 format4 归档完成恢复与升级；此前失败的原始归档用例（Root 原样校验）恢复运行，完成约 6.3 秒。
  - [issue #167](https://github.com/jihuayu/rootyard/issues/167)（本地集成修复提交 `a323f87`）并入 [PR #173](https://github.com/jihuayu/rootyard/pull/173)（head `18e4884`）：集成后保留 #167 的日志读取实现，`crates/refcas-log` 21 项单元测试加 1 项真实 SIGKILL/新进程用例通过；仍是隔离实验 crate，不是运行时。
  - [issue #168](https://github.com/jihuayu/rootyard/issues/168)（本地集成修复提交 `a72cd4e`，LunaMax 已审）：41 项 W0 测试及真实 Git 的默认小规模运行通过。
  - [issue #171](https://github.com/jihuayu/rootyard/issues/171)（本地集成修复提交 `9f161c9`，LunaMax 已审）：21 项 overlay 负向检查及实际 `cargo check --locked --lib --tests`（0 错误、0 警告）通过；Root 在私有 `TMPDIR` 下重跑组合 overlay/W0 62 项通过。
  - [PR #172](https://github.com/jihuayu/rootyard/pull/172)（`fbe27cd`）：新增一致性/会话契约草案文档；其会话读取实施由 PR #209（Refs [#174](https://github.com/jihuayu/rootyard/issues/174)）交付**单机 PostgreSQL 基础**：`ROOTYARD_SESSION_KEYRING` v2 加载器、HMAC `rs1` 帧（绑定 tenant/repository/format/history/authority-kind/authority-epoch/group-id/group-epoch/cluster-incarnation/revision）、JSON 读强制、push 提交签发、sealed serving-read proof，以及真实 HTTP/PG 验收。`rs1` 显式携带 `authority_kind` 与 `group_id`，未知 authority-kind 字节按 malformed 失败关闭。
- **未包含**：issue #169（配对归档 corrupt-ledger 加固）不在 PR #170 中，仍 OPEN；其候选实现见下方“issue #169 候选实现”。#162–#165 仍是 backlog（见[实施计划](implementation-plan.md)）。#174 仍 **OPEN**：浏览器/UI 传播、完整损坏/保留矩阵与分布式 Raft Ref-CAS 矩阵尚未完成；当前范围是会话级 read-your-writes / monotonic reads，不是全局因果一致性。

## issue #169 边界

配对归档当前仅在受支持的 API 产生的静止配对流程上有资格。PR #161 本身没有完整的 ledger corruption guard；LunaMax 独立审查确认，由 API 创建并在静止状态固定的 root pack 能原子地从已登记的永久 artifact 派生，手工或特权直接改 DB 造成的损坏（root 到 A4 的等价性）未被 PR #161 语义验证。因此 #169 仍保持 OPEN，只有在候选实现合并并完成 PR CI/原生验收后才可关闭；本页不把候选分支的本地结果当作已合并能力。

### issue #169 候选实现（`codex/backup169-candidate-20261110`，未合并）

候选分支已实现并测试以下边界，但尚未合并到 `main`，也不改变 PR #170 的集成记录：

- **声明集合枚举**：`src/backup/ledger_validation.rs`（SQL 在 `ledger_validation/sql.rs`，摘要词表/typed refusal 在 `ledger_validation/refusal.rs`）在调用方已有的 `REPEATABLE READ` 导出快照事务（恢复时为恢复后的数据库）和**同一个绝对 deadline** 上读取；不新建连接、不 `BEGIN`、不取第二个快照。`membership`、A5 `snapshot_packs`、活动/已释放 `root_packs`、`serving_read_packs` 分别从各自的声明表枚举，artifact 侧使用 LEFT JOIN，所以缺失的 pack/idx 行变成 NULL 而不是让结果静默缩小。
- **逐项证明**：每个应归档 registration 必须恰好有 `pack`(slot 0) 与 `idx`(slot 1) 两个角色、合法 slot/locator、与同一 publication 的 acquire/consume request、durable hold 和 consume receipt 绑定，且 producer 与 tenant 两种身份分别核对；`artifact_set_digest` 从实际 artifact 行重算。A5 snapshot 与 retained root descriptor 逐项对照同一 canonical A4 集合；retained capture 还由 core 自己的 `retention_root` validator 在同一事务/期限上重新证明。任何缺件、额外/非法角色、错误摘要或身份/摘要不匹配都会形成有界、固定词表的 typed refusal，并在创建目标目录、`COMPLETE` 或 manifest 之前失败。
- **负向测试**：`tests/backup_blob_serving147.py` 的四个 corruption case（缺 `.pack`、缺 `.idx`、缺全部 artifact、错误 `artifact_set_digest`）在一次性 `pg_dump` clone 中构造，只在一个 `SET LOCAL session_replication_role = replica` 事务内改动目标行，先证明恰好该行/字段变化，再删除 clone；备份只允许以该 case 的精确 source-ledger validator violation 拒绝，且目标路径、`COMPLETE`、manifest 均不存在，干净归档随后在全新数据库恢复且摘要/locator 不变。
- **正向测试**：同一 drill 的第二份 API 产生源（`tests/ref_store_format22_backup_fixture.rs`，`pando-lab,format22-fixture`）带非空的活动与已释放 API-created roots，producer owner 与 repository tenant 不同；drill 验证 format22 manifest 的完整 artifact 集合、字节证明/摘要、root 生命周期和 serving-read 记录，并恢复到全新数据库。
- **CI 状态**：记录时该分支在 GitHub Actions 上没有运行记录（按 branch 与这两个候选 SHA 查询均为 0），因此没有可引用的失败日志；合并前必须由 PR 触发 `RefStore protocol native acceptance` 的 fixture 构建与 paired drill。候选分支的本地门禁结果记录在对应 delivery 记录/PR 中；未运行的 native 场景不得称为通过。

#171 的修复随 PR #170 整合，最终 CI 状态以 PR 为准；它只处理合并后的契约缺陷，未新增或声称任何分布式、HA、GC 或容量能力：

- 合并 PR #124 曾用旧 W0 正文覆盖 [第 12 章](12-state-services.md)，覆盖了 PR142 之后加入的 HTTP-only 段落，并带回旧 GitFS/Pando 导入与在线 transition。当前章节已从 canonical 分支 `codex/state-services-architecture-v2`（`23334bd`）逐字节恢复，W0 原始字节（SHA-256 `0187d9c0…`，80072 bytes）移到[显式历史归档](state-services/historical-w0/README.md)，`snapshot.json` 同时记录两者哈希。
- W0/phase-metrics 的 feature-only overlay 检查改为只针对其冻结的 parent fixture（`bcd3918` manifest/lock）；当前集成 manifest 单独做显式契约验证。历史 v1/v5/v6 原始测量报告未修改。
- `src/web.rs` 路由合成整理到原有 100 行结构上限内，全部 48 条路由与 session/Origin/CSRF 中间件保持不变；`src/token_management/mod.rs` 的过时发布声明注释已更正（父 token 发布锁已包含在当前代码）。

本页不以缺失前提条件代替回归证据；集成后的二进制/PG 原生门禁以 PR #170 最终检查为准。缺陷修复 #166–#168 已有绑定各自提交的结果（见“集成状态”），集成后是否闭合以 PR #170 最终证据为准；[#169](https://github.com/jihuayu/rootyard/issues/169) 仍 OPEN，其候选实现见本节，合并与 CI 通过前不改变该状态；#162–#165 仍是 backlog（见[实施计划](implementation-plan.md)）。[#174](https://github.com/jihuayu/rootyard/issues/174) 的单机 PostgreSQL 会话下界基础已由 PR #209 实现，但 issue 仍 OPEN（UI 传播、完整损坏/保留与分布式矩阵未完成）。详细构建、源码/二进制绑定和失败历史见 [后续验收证据](../../evidence/state-services/deepseek-followup/README.md) 与 [standalone147 证据](../../evidence/state-services/standalone147-followup/README.md)。

## format22 配对备份与恢复的真实边界

`format22/schema147` 是当前二进制自己的归档格式：归档既包含冻结 catalog 的 PostgreSQL 快照，也包含该快照引用的 **新鲜 PG RefStore pack/idx 闭包**（以校验和与流式行摘要绑定），并记录源物理 Blob 后端身份。备份与恢复使用与 `serve-blob` 相同的数据库级排他/共享生命周期屏障：备份固定单一 PG 快照并拒绝非终态写入切点，恢复在写入完成、发布与 fsync 前保持服务封锁，持久恢复标记同时阻止另一数据路径绕过。

已验收（`1d1ce62`，[证据](../../evidence/state-services/paired-blob-archive/README.md)）：删除原始 pack/idx 对象后，在全新数据库、原 Blob 后端同一坐标上重建字节并通过 clone/content/refs/fsck 与精确重放；屏障丢失、离线/快照屏障违规、损坏归档、已有目标、非终态切点均被拒绝；备份后 ACK 的写入被排除。损坏归档包含六种被拒绝的损伤样本，不是穷举的完整性证明。

明确限制：

- 仅覆盖新鲜 PG RefStore 仓库的 pack 闭包，**不是全内容闭包**；LFS、workspace/checkpoint、事件归档等字节尚未进入 format22。
- 只支持恢复到**同一物理 Blob 后端身份**；不支持改写到其他后端。
- 混合旧格式/PG 仓库被拒绝；不作旧 format/schema 升级。
- 中断的 format22 恢复没有专门恢复流程或演练（旧 format21 中断演练不覆盖 format22）；没有物理掉电、HA、多主机或生产 RPO/RTO 资格。
- 产品物理 GC 仍默认关闭。
- 本节取代此前“非空 Blob 仓库无法备份”“`backup::git_inventory` 仍要求持久 bare Git”的旧阻塞描述：该阻塞对 `pg_refstore` 仓库已由 format22 解除（旧描述保留在下方历史记录中，仅表示当时状态）。

## 独立实验：Ref-CAS 日志存储（PR #160）

PR #160 新增 `crates/refcas-log`：openraft 0.9.26 `RaftLogStorage`/`RaftLogReader` 的 SQLite 实现，带精确 purge 身份、校验和、有界 append/read、SQLite 提交后才确认日志 flush，以及 1 项真实 SIGKILL/新进程 vote 恢复测试；由独立 workflow 运行。它**只是隔离的实验 crate**：不在 `Cargo.toml` 根依赖、不参与根构建、不激活任何 Raft 运行时，状态机存储、快照、RPC/TLS/ReadIndex、完整 openraft 套件、Ref-CAS 集成和多主机资格均未实现。证据：[refcas-log 证据](../../evidence/state-services/refcas-log-slice/README.md)。

## 仍待完成

LFS、PR/Merge、Workspace、CI/Namespace 的新服务接入、默认入口替换；Raft 运行时、远程决策桥；GC 与容量成本；以及 format22 之外的全内容恢复与独立故障域验收。实施 issue 只有在相关实现合并并完成对应真实验收后关闭。

## 历史实现与验收索引

以下保留已发生的验收和原提交记录；其中旧“当前”指记录日期，不定义新的架构和 backlog。历史成功不因新设计而被抹除，也不作为新模式的验收结果。

# 历史实现记录

## 当前：状态服务 W0（提案，不是已实现能力）

issue #105/#106 W0 已提交[原始第 12 章设计快照](state-services/historical-w0/README.md)（后来被彻底取代，当前章节以其后 canonical 分支为准）、[可执行生产者清单](state-services/producers.json)、[部署契约/配置 schema](state-services/deployment-contract.json)、[provisional 预算](state-services/budgets.json)、[依赖冻结证据](state-services/dependencies.json)与[有限基线工具](state-services/README.md)。设计仍为**提案**：RefStore、BlobStore/OpenDAL、Scope CLOSING/CancelDecision、W1–W9 均未实现；现有 GitFS/PG 与 Pando remote+Vault 路径仍是 legacy/既有边界，不是 target 新部署。

历史 `d689bf8` 的 legacy Pando 基线回执记录于 [native-baseline](../../evidence/state-services/native-baseline.md)：可重跑脚本、原生二进制/源码/锁文件绑定、stock Git、真实 PG/Garage/Vault、冷暖 clone、竞争写入与 atomic 成功路径。该回执是**历史 pre-evolution 基线**，不回算到本次 rebase 的 security/token/membership parent，也不代表新后端或多主机资格。内部阶段等待、Blob bytes、精确 old-OID CAS 竞态、完整 producer coverage 与冻结预算仍待验收，**#106 保持 OPEN**。

历史 round-4 以下内容保持原样（保留原文与其标注的日期边界）。

## 当前：round-4 浏览器与 LFS（above 为历史快照）

集成源 `4c5bcfe56516434ea5b42985e9af90a8c1efe51f`（基线 main `a91c93f`，不可变二进制 `c0049c3a…`，生产输入 `8f399a06…`/331）通过全部 11 个 native coordinator job，独立终审 `APPROVED`（0 P1）：真实 Chromium 登录/发现/Issue+PR/合并/登出并拒绝旧 cookie；可撤销浏览器会话（CSRF/Origin/过期/父令牌撤销准入检查）；真实 stock `git-lfs` + 真实 Garage，删除源 `DATA_DIR` 后由第二进程/新 `DATA_DIR` 经共享 PostgreSQL 取回精确字节；pointer 规范化覆盖官方客户端 LF/CRLF、前导 Unicode 空白/NBSP 与两个 legacy 头，12 类坏 pointer 在 4 条发布路径上共 48 组合全部在 ref 移动前拒绝，18 个官方客户端探针全部匹配；4000 个真实 staging 清理在 native 数据 `ShareLock` 释放前无法删除；离线 format-8/schema-132 恢复撤销旧浏览器会话并在无目标 endpoint 下提供 LFS 字节。生产改动 4 个文件（浏览器与 LFS），**无 DDL**，schema 仍为 132。计数不混用：145 个 Rust 单元测试与 9 份 JSON 报告中的 25 个 case。水化 `0600` 属于加固——旧 `157748a` 适配器本已原子并通过 8 MiB 并发用例，本轮**不是**截断修复；旧二进制真实失败是 CRLF pointer 绕过（保留为标注的旧证据）。单物理主机、loopback 服务与一次性 PostgreSQL/Garage/Chromium，无生产 HA、厂商、云或跨主机声明；#26/#43/#44 与 umbrella #48 保持 OPEN。证据：[round-4 验收](../acceptance/round4-browser-lfs.md)、[evidence bundle](../../evidence/round4/browser-lfs-4c5bcfe/README.md)。

以下为历史快照，保持原样。

历史基线：2026-11-04，main [`1fd05a393fe24653687fa3e868f9dca2fb0c9a67`](https://github.com/jihuayu/rootyard/commit/1fd05a393fe24653687fa3e868f9dca2fb0c9a67)。本页历史快照说明该代码具有什么边界，不承诺后续 main，也不把既有测试报告当作本次重新执行的结果。

最终生产源：`f31910086acbaa87d9e98df440ca8c28c7bb7e08`（format-7 版本 `<=131` 冻结），certified input `fdfbbfc…`，immutable binary `35d01c5f…`，合并主线 `5fa4854`（PR #56 已合并）。除一个 physical-GC 组合 receipt 外，最终 NativeCore+Ops 结果已验证；逐条证据见 [round-2 交付表](../acceptance/round2-delivery.md) 与 [46 项任务台账](../registered-task-delivery.md)。

历史中间基线：`6d2f0b8`（PR #49–#55）与 `340e668` 的中间记录只作历史，不是最终验收结论；[6d2f0b8 审计](../acceptance/main-6d2f0b8-audit.md) 保持 historical。

## 最终源（f319100）能力与未验收边界

- #38：service 2/2（含 stock Git Forge pull/review/check/merge）、matrix 6/6（mirror/pin/checkout、64-hex plan/receipt、SHA-1 与 mixed/abbreviated/zero-OID negatives）、restore 2/2、真实 legacy format-6 3/3（旧 `6135` archive）、schema contract 8 checks（含 public/custom）、CI checkout 15/15（isolated DB；失败首试保留于 history）均在 `35d01` 通过。满足验收，PR 合并后关闭。
- #23：GitFS lifecycle 3/3 + API 7/7；automatic Pando 2/2（cache tamper、non-ref rollback）；同仓 format-7 paired backup/restore 通过。远端 Pando mark/delete/pruning 仍 DISABLED，需 foundational global-retention；GitFS physical GC **8/8 通过**（test-only `ed8d074`/`47a93ed` fixture fix，生产 input digest 未变）；issue 仅因远端 Pando GC foundation 保持 OPEN。
- #25/#26：draining reset、retired-source fencing before commit、online copy+delta、retained SQL roots、list/abort、migration/partition/full takeover 均通过。**#25** 仍缺 per-phase crash matrix 与 CI-sidecar intent/directory handoff；**#26** 同机 session fencing 已证明，physical cross-host fencing 未认证。
- #43/#44：真实 TLS/SCRAM、Kafka SASL_SSL、手工本地 PG promotion、PITR、ENOSPC 与本地 1/2/4 workload 通过；aggregate 为 #44 `passed_local_single_host`、#43 `blocked_external_ha_and_source_fence`、`production_scope=not_certified`。外部自动 PG HA/DCS、跨主机 source fence、全新部署 restore、物理跨主机/硬件资格仍缺失。
- #32：真实 dev/CI 6/6（own-DB retry）、tmpfs-only artifact pool、launch-failure cleanup 通过。正向 kernel cgroup 因无 delegated cgroup v2 subtree（rootless Docker cgroup driver `none`、cgroupfs EPERM）而 BLOCKED。
- #48：umbrella 保持 OPEN，roadmap 可勾选已关闭的 #30（PR #50）和待合并的 #38；#2–#19 不批量关闭（PR #49 历史代码不等于新验收）。

## 历史中间基线（6d2f0b8）已合并能力与未验收边界

- Pando 生产网关、双阶段 GitFS↔Pando 迁移/回滚、加密 pack CAS 与 transition 备份已合并（PR #53）；`tests/pando_transition_service.py` 需要真实 Garage/Vault，本次审计未重跑。
- 独立 ref 写入使用持久 `git_ref_admissions` 与 epoch fence（PR #51，迁移 126）；物理 GitFS GC 使用迁移 127 admission fence、完整 retention roots、quarantine 与幂等删除（PR #52）。
- SHA-256 已贯通仓库创建、Forge OID admission 与 service 测试（PR #54）；镜像/pin/checkout/restore 的端到端矩阵与 SHA-256 CI checkout 503 修复仍未完成。
- 本地集群真实 1/2/4-node workload、PG streaming/PITR、磁盘 ENOSPC、迁移和 controller/fence 报告已提交；当前 main 的 controller post-promotion push 409，以及同时具备 HA failover 与新部署恢复的验收仍未完成。
- Workspace 惰性 VFS 水化已合并（PR #50）；Agent/CI sandbox 已实现 bwrap dev 模式、PTY/artifact 和 cgroup 代码，但聚合 cgroup 资源耗尽、崩溃清理和 cgroup artifact 验收仍未完成。
- 未验收：跨主机物理 fencing、真实多主机 PostgreSQL/DCS HA、公有云 KMS/HSM、跨数据中心网络分区、生产规模长稳压测，以及 #48 中所有子项的关闭。

## 历史 main 基线实现

| 能力 | 已有边界 | 代码与契约 |
| --- | --- | --- |
| Git hosting | Rust HTTP 服务调用原生 Git；持久裸仓库是 refs/objects 权威，PG 保存身份、仓库元数据和投影；单卷单服务进程，不是多节点 HA | [ADR 001](../architecture.md)、[git_http.rs](../../src/git_http.rs)、[storage.rs](../../src/storage.rs) |
| 操作证据与可靠事件 | GitFS 操作 journal、成功子集 receipt、unknown/recovering 状态、PG 事务事件和投递；GitFS 与 PG 不共享原子事务 | [可靠性契约](../reliability.md)、[journal.rs](../../src/journal.rs)、[events.rs](../../src/events.rs) |
| 后台 worker | PG-only 独立 worker、有租约和 fence 的投递；周期扫描是恢复依据，Redis/Kafka 只是可丢失唤醒 | [跨进程 worker](../cross-process-workers.md)、[Kafka 边界](../kafka-wakes.md)、[dispatch.rs](../../src/dispatch.rs) |
| 运维恢复 | 配对离线 PG/卷备份（覆盖 Schema `030`/`050`/`060`、`SCHEMA_VERSIONS = [1, 2, 3, 6, 7, 8, 9, 20, 30, 40, 50, 60]`、23→30→34 张公共表、backup format 5 与遗留 format 4 兼容，含 `lfs/objects` 卷校验）、隔离恢复、显式 unknown-push 处理、固定维度指标 | [备份恢复](../backup-restore.md)、[手动恢复](../manual-recovery.md)、[指标](../metrics.md)、[030_catalog.sql](../../schema/030_catalog.sql)、[060_catalog.sql](../../schema/060_catalog.sql)、[db.rs](../../src/db.rs)、[backup.rs](../../src/backup.rs) |
| 基础 Forge | 私有 owner Issue/comment、版本条件、分页、创建幂等键、open/closed 过滤和备份 | [Issue 契约](../forge-issues.md)、[forge.rs](../../src/forge.rs) |
| PR、评审与分支保护 | Pull Request 状态机（`open`/`closed`/`merged`、乐观并发 `expected_version` CAS、限定 Diff 预览）、绑定 `head_oid` 的 Review 审批流（支持多人评审与 `prevent_self_approval` 禁止作者自审策略）、单调 `(attempt, sequence)` 的 Commit/PR Check Run 状态上报、分支保护规则（`branch-rules`：`required_approvals`、`required_checks`、`require_fast_forward`、`prevent_deletion`、`prevent_force_push`、`prevent_self_approval`）以及持写锁与同代校验的原子 `merge` API（发布 journal/outbox 事件并支持 `Idempotency-Key`）与配对备份（迁移 `009`） | [第 04 章](04-forge.md)、[pulls.rs](../../src/pulls.rs)、[handlers.rs](../../src/pulls/handlers.rs)、[checks.rs](../../src/pulls/checks.rs)、[rules.rs](../../src/pulls/rules.rs)、[merge.rs](../../src/pulls/merge.rs)、[009_forge_pulls.sql](../../migrations/009_forge_pulls.sql) |
| 外部 CI Webhook 与自动流水线 | 仓库级 Webhook 订阅 CRUD、SSRF 安全 URL 校验、RFC 2104 HMAC-SHA256 签名（`X-Rootyard-Signature-256: sha256=<hex>`）、消费 Outbox `push`/`pull_request` 事件投递、指数退避重试与死信队列（`pending`/`failed`/`dead_letter`/`delivered`）、HMAC 验签幂等 Check Run 回调（`forge_webhook_callbacks`），以及 PR 创建/更新（`on_pull_synchronized`）时自动创建确定性 CI Source Pin（`refs/rootyard-ci/jobs/*`）并登记待执行 `queued` Check Run | [webhooks.rs](../../src/webhooks.rs)、[models.rs](../../src/webhooks/models.rs)、[signing.rs](../../src/webhooks/signing.rs)、[delivery.rs](../../src/webhooks/delivery.rs)、[handlers.rs](../../src/webhooks/handlers.rs)、[040_webhooks.sql](../../src/webhooks/040_webhooks.sql) |
| 协作者、团队 5 级 RBAC 与审计查询 | 从单 owner 扩展至仓库协作者（`repository_collaborators`）与团队（`repository_teams` / `repository_team_members`）5 级角色体系（`read` < `triage` < `write` < `maintain` < `admin`），取直接角色与团队角色最高值并受只读 token 范围约束（非成员返回 `404` 防探测、权限不足返回 `403`）；支持 PR 禁止作者自审（`prevent_self_approval`）与不同 `write`+ 审批人计数，以及支持按 `actor`/`action`/`since`/`until` 游标分页查询的 `/api/repos/{owner}/{name}/audit` 审计日志 API | [members.rs](../../src/members.rs)、[models.rs](../../src/members/models.rs)、[rbac.rs](../../src/members/rbac.rs)、[audit.rs](../../src/members/audit.rs)、[auth.rs](../../src/auth.rs)、[050_members_rbac.sql](../../src/members/050_members_rbac.sql) |
| 仓库只读浏览与 Ref 事务 | `GET /refs`（自动过滤内部 `refs/rootyard-ci/*`）、`GET /commits`、`GET /tree`、`GET /blob`、`GET /compare` 只读 HTTP JSON 浏览 API 与游标分页；基于 `git update-ref --stdin -z --no-deref` 的原子多引用 CAS 事务接口（`POST /ref-transactions`），遵循分支保护、默认分支禁删与 journal/outbox 审计契约，暴露存储后端路由查询（`GET /storage-route`），并支持 `object-format=sha256` 仓库探测、双哈希（SHA-1 40 位 / SHA-256 64 位）校验、Smart HTTP v1/v2 `object-format` 能力协商与兼容矩阵演练（`GET/POST /object-format*`） | [browse.rs](../../src/browse.rs)、[handlers.rs](../../src/browse/handlers.rs)、[git_read.rs](../../src/browse/git_read.rs)、[transactions.rs](../../src/browse/transactions.rs)、[object_format.rs](../../src/browse/object_format.rs) |
| Git LFS 对象网关 | Git LFS Batch API（`upload`/`download` 动作协商）、流式 `PUT`/`GET` 对象传输、`verify` 校验端点、严格 SHA-256 `oid` 与 `size` 校验、基于 `.tmp-<uuid>` + `O_NOFOLLOW` + `fsync` 的内容寻址落盘（`lfs/objects/aa/bb/<oid>`），以及纳入 Schema `030`（迁移 `020`）的配对离线备份与恢复完整性核验 | [lfs.rs](../../src/lfs.rs)、[handlers.rs](../../src/lfs/handlers.rs)、[storage.rs](../../src/lfs/storage.rs)、[020_lfs_objects.sql](../../migrations/020_lfs_objects.sql) |
| CI 读取切片、镜像淘汰与自动回源调度 | 主站精确 SHA-1 source pin 列表/详情与租约协同安全释放（存在活跃 checkout 租约时返回 `409 Conflict` 拒绝释放）、手动全量镜像同步、prepare receipt、精确 OID 闭包 clone、限定作业凭证；镜像磁盘高低水位与 LRU 安全淘汰（`mirror-evict` / `mirror-prune`，严格保护 `current.json`、活跃 `ci_checkout_jobs` 租约与当前代 `refs/rootyard-ci/jobs/*` pin，并写入 `ci_mirror_evictions` 审计表，迁移 `030`）、并发同步/闭包构建限流（`429 Too Many Requests`）、按 `(repository_id, target_oid)` 单飞合并的缓存缺失自动回源拉取（`mirror-auto-fetch`）与跨集群 Runner 注册/心跳/过期重领作业队列（`mirror-runners`）以及 `mirror-status` 与固定维度 `/metrics` 暴露 | [镜像契约](../ci-mirror.md)、[ci_pins.rs](../../src/ci_pins.rs)、[ci_checkouts.rs](../../src/ci_checkouts.rs)、[mirror.rs](../../src/mirror.rs)、[auto_origin.rs](../../src/mirror/auto_origin.rs)、[eviction.rs](../../src/mirror/eviction.rs)、[limiter.rs](../../src/mirror/limiter.rs)、[observability.rs](../../src/mirror/observability.rs)、[030_ci_mirror.sql](../../migrations/030_ci_mirror.sql) |
| 服务端 HTML Web UI 与 XSS 防护 | 覆盖仓库概览、Tree/Blob（UTF-8 边界安全截断与二进制 Hex 预览）、Commits/Diff/Compare、Issues/PRs/Reviews/Checks/Merge 与 Audit 视图的服务端 HTML 渲染（`/web/repos/{owner}/{name}/*`），支持显式 `Authorization: Bearer` API 凭据，以及 `/web/login` 表单交换得到的短期 HttpOnly `rootyard_session` 浏览器会话（父 API token UUID 绑定、HTTP 准入检查父令牌撤销/过期、CSRF/Origin 保护；不再接受 `rootyard_token`/`token`/`X-Rootyard-Token` Web 凭据）、严格 CSP 响应头与零客户端脚本 XSS 净化器 | [web.rs](../../src/web.rs)、[models.rs](../../src/web/models.rs)、[sanitize.rs](../../src/web/sanitize.rs)、[templates.rs](../../src/web/templates.rs)、[handlers.rs](../../src/web/handlers.rs) |
| 多节点仓库分片、Epoch 写屏障、在线迁移与灾备演练 | 1024 虚拟分桶（`shard_virtual_buckets`）、节点租约目录（`shard_nodes`）、仓库级分片路由（`repository_shard_routes`）、与 `before_push` 联动的 `(route_epoch, storage_generation, lease_epoch)` 脑裂写屏障、自动主从故障切换（`shard_failover_operations`）、只读降级演练、四阶段在线分桶/仓库重平衡迁移（`drain` → `sync` → `fence` → `cutover`，`/api/shards/rebalance`）、实测 RPO/RTO SLA 灾备演练（`/api/repos/{owner}/{name}/shard-dr-drill`，迁移 `060`），以及 1/2/4 节点并发吞吐与 P50/P95/P99 延迟、`/proc/self` 资源遥测及保留根可达性核验基准套件（`/api/shards/benchmark`、`/api/repos/{owner}/{name}/shard-benchmark`） | [sharding.rs](../../src/sharding.rs)、[models.rs](../../src/sharding/models.rs)、[router.rs](../../src/sharding/router.rs)、[fencing.rs](../../src/sharding/fencing.rs)、[failover.rs](../../src/sharding/failover.rs)、[rebalance.rs](../../src/sharding/rebalance.rs)、[benchmark.rs](../../src/sharding/benchmark.rs)、[060_sharding_fencing.sql](../../src/sharding/060_sharding_fencing.sql) |

默认仓库读权限支持 owner 及已授权协作者/团队（`read` 及以上角色），非成员访问私有仓库统一返回 `404 Not Found`。隐藏 refs、不可达对象或 sparse checkout 不建立细粒度保密边界。Kafka 的已有适配器用于受控本地 broker，不能当作生产远程 TLS/SASL 集群配置。服务的其余安全和部署前提见 [运行手册](../operations.md)。

CI 的 source-retention receipt 与 mirror-readiness receipt 是两种独立证据，由可信控制者核对。owner-wide token 不能交给不可信 runner；基线已增加绑定仓库、目标 OID、job、generation、镜像 audience 与绝对到期时间的作业凭证，一次性交付，最长一小时，并支持单调 cancel/revoke。作业读取使用只含目标可达闭包的独立视图，仍允许读取目标的完整祖先历史。每次请求及慢准备完成后再次授权；已准入的长传输不会被即时中止。已实现租约协同的显式 source pin 释放、PR 同步自动创建 CI source pin（`on_pull_synchronized`）、磁盘高低水位与 LRU 安全淘汰（`mirror-evict` / `mirror-prune`）、单飞合并自动回源（`mirror-auto-fetch`）、跨集群 Runner 队列调度（`mirror-runners`）、并发同步限流与 `mirror-status` / `/metrics` 观测，闭环 [第 11 章](11-ci-read-mirrors.md) 核心控制面契约。Schema `030`（23 张公共表）/ Schema `060`（34 张公共表）/ backup format 5 恢复会撤销既有作业凭证，详见 [实现契约](../ci-mirror.md#bounded-job-checkout-credentials)。

## 独立实验

| 实验 | 已实现的实验内容 | 不能推导出的能力 |
| --- | --- | --- |
| [Pando lab](../../experimental/pando/README.md) | 单独 feature/binary/schema；PG refs、不可变本地 pack、事务 CAS、多 ref 发布、持久读取快照、真实 Smart HTTP 测试路径；纯 Rust 流式 pack/delta 解析校验（`verify-delta`，[delta.rs](../../src/pando_lab/delta.rs)）、Commit/Tree/Tag 可达图遍历（`walk-graph`，[graph.rs](../../src/pando_lab/graph.rs)）、与原生 `git` 双算子对拍导出校验（`diff-export`，[export.rs](../../src/pando_lab/export.rs)）、只读 refs/operations/migration/lifecycle HTTP 端点、孤儿 pack/过期快照 `gc`、GitFS ↔ Pando 五步在线迁移状态机（`migrate`、`migrate-step`：`copy` → `verify` → `drain` → `fence` → `switchover`、`migration-status`，[migration.rs](../../src/pando_lab/migration.rs)）、保留切流后新提交的安全回滚演练（`rollback`，[rollback.rs](../../src/pando_lab/rollback.rs)、[schema.sql](../../experimental/pando/schema.sql)）、S3 兼容对象存储 CAS 适配（`object-store-put`/`get`/`verify`，[object_store.rs](../../src/pando_lab/object_store.rs)）、多 Pack 合并压缩（`repack`，[repack.rs](../../src/pando_lab/repack.rs)）、碎片率驱动后台自动 Compaction 生命周期评估、冷数据本地驱逐与按需透明回源水化、KMS/SSE-C 信封加密与无停机密钥轮转（`lifecycle-evaluate` / `kms-rotate`，[lifecycle.rs](../../src/pando_lab/lifecycle.rs)），以及 SHA-1/SHA-256 双对象格式解析与兼容矩阵演练（`object-format-detect` / `verify-object-format` / `compat-matrix`，[object_format.rs](../../src/pando_lab/object_format.rs)） | 使用可伪造测试身份与受控 S3/KMS loopback 本地网关，仅限合成数据；未宣称跨区域公有云硬件 HSM 生产 SLA；同仓最终发布仍串行 |
| [Workspace foundation](../workspace-foundation.md) | 独立完整 `.git` 与工作树副本；固定起点；本地 checkpoint/restore；保存部分暂存、冲突和 ignore 语义；脏文件清单（`status`，[manifest.rs](../../src/workspace_lab/manifest.rs)）、层级 `.gitignore` 与 `.rootyardignore` 规则求值（[ignore.rs](../../src/workspace_lab/ignore.rs)）、有序 `changeset`/`apply` 与增量脏文件同步（`sync-dirty`，[sync.rs](../../src/workspace_lab/sync.rs)）、不可变只读（`0o555`）checkpoint 视图投影与校验（`verify-readonly-view`，[view.rs](../../src/workspace_lab/view.rs)）、对接内容寻址远程 CAS 的跨节点脏快照上传/恢复（`push-remote` / `pull-remote`，`remote_cas_committed`，[remote.rs](../../src/workspace_lab/remote.rs)）、多仓固定 `BaseVector` 的只读虚拟 Namespace 挂载校验及确定性 `task_snapshot` Git View 投影（`namespace-mount` / `verify-namespace` / `namespace-git-view`，[namespace.rs](../../src/workspace_lab/namespace.rs)）、惰性稀疏 VFS 挂载、按需 CAS 远程拉取水化、写时复制（CoW）脏追踪与干净缓存淘汰（`vfs-mount` / `vfs-hydrate` / `vfs-status` / `vfs-evict`，[vfs.rs](../../src/workspace_lab/vfs.rs)）、多 Agent 路径前缀排他租约锁、可写虚拟 Namespace 反向路径映射与跨仓两阶段原子回写（`agent-lease` / `namespace-write` / `namespace-commit-back`，[writable_view.rs](../../src/workspace_lab/writable_view.rs)），以及虚拟挂载写时复制（CoW）Overlay 沙箱（跨层目录 `rename`、`chmod`、`git add -f` 忽略覆盖、多 Agent 隔离）与断电崩溃窗口（`before_wal_fsync` / `after_wal_before_publish` / `after_publish_before_ack`）WAL 恢复对账演练（`overlay-mount` / `overlay-op` / `crash-drill` / `crash-recover`，[crash_recovery.rs](../../src/workspace_lab/crash_recovery.rs)） | 不是内核级 FUSE/projfs 驱动、实时 inotify watcher 或多租户容器沙箱；需可信单一 OS 用户及调用方保证 `--quiescent` 静止 |
| [Git View foundation](../git-view-foundation.md) | 多仓固定 `BaseVector` 的 Namespace、单子目录投影（`project-subdir`）、长周期历史投影策略（`deterministic_history` vs `task_snapshot`，增量 epoch 映射与 merge-parent 祖先保留，`project-history`）、源提交 GPG/SSH 签名识别与平台 HMAC-SHA256 溯源签名验签（`verify-view`）以及跨仓两阶段 `ChangeSet` 原子集成与恢复（[view_lab.rs](../../src/view_lab.rs)、[models.rs](../../src/view_lab/models.rs)、[namespace.rs](../../src/view_lab/namespace.rs)、[projection.rs](../../src/view_lab/projection.rs)、[changeset.rs](../../src/view_lab/changeset.rs)） | 独立本地 CLI 实验工具（`rootyard-view-lab`），不替代主站在线多租户分布式事务协调器 |

## 计划与待验证事项

- 跨公有云多区域真实云厂商 KMS 硬件 HSM 集成与超大规模生产集群长稳压测。
- 跨数据中心广域网真实物理网络分区下的多节点 Raft/Patroni 连续故障注入验证。
- Workspace 内核态 FUSE/overlayfs 透明挂载驱动。
- 在指定硬件、真实对象存储和工作负载上的规模/成本测试；原文容量数字和性能目标须实测。

这些能力的依赖和发布出口见 [分期路线](08-roadmap.md)。已有切片可以并行推进，不能以“第几期已开始”代替整期验收完成。

## 执行证据入口

现有记录分别覆盖 [基础 Git](../verification.md)、[可靠性](../phase-two-verification.md)、[备份整合](../integration-verification.md)、[恢复](../recovery-verification.md)、[恢复后 worker](../workers-integration-verification.md)、[Forge](../forge-verification.md)、[幂等](../forge-idempotency-verification.md)、[状态筛选](../forge-state-filter-verification.md)、[Forge 备份](../forge-backup-verification.md) 与 [Workspace](../workspace-verification.md)。Pando 的报告在 [实验目录](../../experimental/pando/README.md)。第一至第五梯队并行模块边界与契约见 [并行开发契约](../parallel-development.md)，配套自动化实测套件覆盖 [pulls.py](../../tests/pulls.py)、[backup_pulls.py](../../tests/backup_pulls.py)、[browse.py](../../tests/browse.py)（含 [test_object_format.py](../../tests/test_object_format.py)）、[lfs.py](../../tests/lfs.py)、[ci_mirror.py](../../tests/ci_mirror.py)（含 [test_ci_mirror.py](../../tests/test_ci_mirror.py)）、[webhooks.py](../../tests/webhooks.py)（含 [test_webhooks.py](../../tests/test_webhooks.py)）、[members.py](../../tests/members.py)（含 [test_members.py](../../tests/test_members.py)）、[web.py](../../tests/web.py)（含 [test_web.py](../../tests/test_web.py)）、[sharding.py](../../tests/sharding.py)（含 [test_sharding.py](../../tests/test_sharding.py)）、[benchmark_tiers.py](../../tests/benchmark_tiers.py)（含 [test_benchmark_tiers.py](../../tests/test_benchmark_tiers.py)）、[pando_lab.py](../../tests/pando_lab.py)（含 [test_pando_migration.py](../../tests/test_pando_migration.py)、[test_pando_repack_object_store.py](../../tests/test_pando_repack_object_store.py)）、[workspace.py](../../tests/workspace.py)（含 [test_workspace_remote_namespace.py](../../tests/test_workspace_remote_namespace.py)、[test_workspace_vfs.py](../../tests/test_workspace_vfs.py)、[test_workspace_crash_recovery.py](../../tests/test_workspace_crash_recovery.py)）、[git_views.py](../../tests/git_views.py)（含 [test_view_lab.py](../../tests/test_view_lab.py)）、[e2e_tiers.py](../../tests/e2e_tiers.py) 与 [test_tier5_adversarial.py](../../tests/test_tier5_adversarial.py)。每条报告的执行版本、日期与未测边界继续有效；不因文档迁移而扩大。

新增设计文档只做来源完整性、链接与图的检查。产品测试命令及隔离环境要求见 [开发手册](../development.md)。
