# 已退役总路线 48：历史进度快照

本页保存维护者授权删除旧 issue 前的历史记录，不是当前路线或新架构验收。现行任务见 [新实施计划](../design/implementation-plan.md) 与 [任务映射](../design/issue-map.md)。旧记录中的 open/close-eligible/当前等描述仅指记录日期，不能覆盖新任务状态。

原题：[Roadmap] Track remaining Rootyard capabilities and production acceptance。删除前 updated_at：`2026-11-08T12:57:03Z`。原 body SHA-256：`68bcc1855633b91e8501e7c7b7a5aa80e8decd60d636bd195c10dfc5d8638cde`。正文逐字保存于以下边界内；不在本轮更新历史断言。

<!-- BEGIN RETIRED ISSUE 48 BODY -->
<!-- rootyard-closure-audit-20261108:start -->
## 已合并事项收口（2026-11-08）

按维护者确认的规则：**仅关闭 PR 已合并且验收完成的 issue**。本次逐项核对 main `d689bf8`、具名源码/二进制的原生报告及 Luna Max 复核后，关闭 #5、#6、#11、#13、#17、#45；具体证据与边界已留在各 issue 的关闭说明。使用历史具名验收，不声称对当前 HEAD 新跑全部套件。

#41 继续打开：尚需原验收要求的跨仓库原生访问负例，以及一致的用户支持文档。#72、#79、#81、#90 等仍在草稿 PR 中，按上述规则保留；#105/#107 及其未完成子项继续推进。没有在此轮合并 PR 或关闭尚未完成的架构/HA资格。
<!-- rootyard-closure-audit-20261108:end -->

<!-- rootyard-round5-implementation:start -->
## Round-5 实施进展（2026-11-07）

已建立草稿 PR [#89](https://github.com/jihuayu/rootyard/pull/89)，尚未合并。实现使用 `auto/deepseek-v4.1-flash`，独立审查使用 Luna Max；没有仅凭代码存在批量关闭 issue。

- #72：真实后台 worker 的八项公平性/积压/重启/超时验收通过。
- #79/#71：真实 Garage、1/4/16 客户端测量中，热路径进程读取量/返回字节均为 1，远端请求为零；冷远端并发波次各为一次 HEAD 和一次 GET。真实池占用/等待指标与饱和恢复测试已加入；指标为近似采样值。
- #70：八项原生并发分配、历史 sequence ties、完整游标、提交/回滚、删除竞争测试通过。
- #66/#67/#69：11 项 Webhook 验收及四项无钩子/暂停/删除钩子 PR 同步测试通过。
- #73/#68：后台扫描/owned Git jobs 已实现。最新五项捕获验收通过四项，stale-revision 测试等待超时正在改为真实读门同步；保持未完成。
- #75：记录的集成版 fmt、all-target Clippy/pando-lab、206 项 Rust 测试通过；原始 main 同样存在的 Python 静态契约失败继续修复，未宣称完整 CI 全绿。
- #76：常规回归、候选版本验收、固定版本 Garage 冷启动及清理、证据重哈希已实现并经 Luna 复审；夹具/manifest/安装器共 44 项单元测试通过，真实 LFS 跨卷恢复通过。未宣称 GitHub Actions 已运行。
- #74 仓库列表分页、#80 脱敏错误、#81 会话 GC 正在分阶段实现/审查；组织/Web 列表、完整故障观测、schema133/format8 真恢复等仍需验收。

原始测量和构建凭据随 PR 的 `docs/acceptance/round5-priority-progress.md` 提交；各报告绑定具体二进制摘要，不把早期构建结果冒充最终提交结果。#26/#43/#44 仍缺独立物理主机和可控存储故障环境。其余功能单保持 open，按依赖继续实施。
<!-- rootyard-round5-implementation:end -->

<!-- rootyard-round5-status:start -->
## Round-5 审查待办（2026-11-07）

按仓库维护者要求，把本轮审查发现和功能建议全部建立为可验收 Issues。基线 `d689bf8062a73cfadbc0a72abf3f1546d992e09c`；新建 **23** 张。六类问题经本轮实际Rust服务/隔离PG复现；源代码性能风险、已知支持范围限制和新增产品规划在各单分别标明。三项性能专项独立建单。

实际验证：`cargo test --locked --lib` 为145 passed/0 failed；Rust1.99.1上的 `cargo clippy --locked --lib -- -D warnings` 退出101，14处诊断。并发delivery实验为72行、27个不同sequence、limit1仅遍历27条；记录未从DB删除。不存在新的生产规模吞吐或跨主机HA通过声明。

### 已复现的正确性与安全问题

- [ ] #66 — [P1] Webhook 默认放行本机回环地址，削弱服务隔离
- [ ] #67 — [P1] Webhook 将 actor.id 当 tenant_id，组织与协作者路径失效
- [ ] #68 — [P1] Workspace 自动捕获永久停留在按UUID排序的前100个
- [ ] #69 — [P2] 无活跃Webhook的PR不会随Git push自动更新
- [ ] #70 — [P2] MAX(sequence)+1并发分配导致Webhook投递分页遗漏
- [ ] #71 — [P2] LFS本地已验证字节仍依赖远端HEAD成功

### 三项独立性能专项

- [ ] #72 — [P2] Webhook全局串行扫描存在仓库间队头阻塞
- [ ] #73 — [P2] Workspace全量双重fingerprint和同步Git调用占用async worker
- [ ] #79 — [Perf] 减少 LFS Batch 与下载的重复完整校验及远端请求

### 恢复架构、验证与文档

- [ ] #77 — [P1] Pando元数据单独PITR副本不能安全共享可删bucket
- [ ] #75 — [P2] 当前工具链下Clippy发布门禁失败
- [ ] #76 — [P2] 近期关键native验收未作为常规CI回归
- [ ] #78 — [P2] 当前运维入口混有过时能力声明

### 权限、资源、可观测性及功能补齐

- [ ] #74 — [P2] 列表能力有固定截断且缺可继续游标
- [ ] #80 — [P2] 增加脱敏结构化错误及任务积压观测
- [ ] #81 — [P2] 为过期浏览器会话和子Token增加有界清理
- [ ] #82 — [Feature] 为人用 API Token 增加仓库和动作Scope及自助管理
- [ ] #83 — [Feature] 落实租户硬磁盘配额与聚合资源准入
- [ ] #84 — [Feature] 补齐浏览器统一身份、MFA与认证接口限流
- [ ] #85 — [Feature] 完善仓库归档、改名、删除恢复及安全Ownership Transfer
- [ ] #86 — [Feature] 补齐搜索、标签负责人、通知订阅与行级PR评审
- [ ] #87 — [Feature] 增加组织、集成、用量及后台恢复状态管理界面
- [ ] #88 — [Feature] 明确并扩展Workspace对Submodule、Linked Worktree和LFS等Git状态的支持

### 沿用现有架构遗留单，避免重复

- [ ] #26 — 物理跨主机存储fencing；已补充本轮剩余验收条件。
- [ ] #43 — 分布式生产HA实施与新部署恢复资格；已补充本轮剩余验收条件。
- [ ] #44 — 真实跨主机/硬件/故障域及性能证据；已补充本轮剩余验收条件。

Pando原始metadata-only PG/PITR副本共享可删bucket的authority防护此前未独立跟踪，已新建 #77；#23仍保持其已接受managed-authority模式的完成结论。其他既有已关闭模式保持原状，所有新单保持open。

建议先处理 #66/#67/#68 和门禁 #75，再处理 #69/#70/#71 及回归覆盖 #76；其余专项按依赖推进。原有历史记录和子项状态保留如下。
<!-- rootyard-round5-status:end -->

<!-- rootyard-round4-status:start -->
## Current round-4 progress (2026-11-07)

Merged [#64](https://github.com/jihuayu/rootyard/pull/64) and [#65](https://github.com/jihuayu/rootyard/pull/65); main `d689bf8062a73cfadbc0a72abf3f1546d992e09c`. **CLOSED this round: #3, #16, #19, #33, #39, #40 and #47.** DeepSeek workers handled most implementation, independent source/acceptance review and independent publication review.

Automatic PR synchronization/webhook recovery is delivered by #64. Browser sessions, LFS remote recovery and ref-publication validation are delivered by #65. All 11 final coordinated groups passed on compiled/harness source `4c5bcfe56516434ea5b42985e9af90a8c1efe51f`, immutable binary `c0049c3a4a97543cfe95a5deccc80b1404cc3b7f5a3eff2ad54acb9be0de1f45`, production inputs `8f399a064af9701de018bad5d527cd652767f03131a96affde8582fb6aac0034` / 331 files: real Chromium, stock Git LFS/real Garage recovery after removing the source DATA_DIR, 48 rejected pointer/path combinations plus 4 valid variants, real cleanup blocked by the native publication lease, paired format-8/schema-132 restore with actual schema comparison, both webhook groups, and 145 Rust unit tests (0 failed/ignored). [Acceptance](https://github.com/jihuayu/rootyard/blob/d689bf8062a73cfadbc0a72abf3f1546d992e09c/docs/acceptance/round4-browser-lfs.md) · [Raw reports and source/acceptance reviews](https://github.com/jihuayu/rootyard/tree/d689bf8062a73cfadbc0a72abf3f1546d992e09c/evidence/round4/browser-lfs-4c5bcfe).

This is single-host functional qualification with PostgreSQL 17, real Garage and a second process/data directory. Documented pointer inspection bounds, admission-only parent API revocation for browser requests, and source-only Pando gate coverage remain explicit. No physical distributed HA qualification is claimed. #26/#43/#44 and umbrella #48 remain OPEN; other unrelated backlog items and historical defects are not mass-closed. Prior closures #23/#25/#32/#38/#30 are preserved. Ordinary CI was not a merge gate per user instruction.
<!-- rootyard-round4-status:end -->

<!-- rootyard-round3-status:start -->
## Historical round-3 progress (2026-11-07)

Merged [#61](https://github.com/jihuayu/rootyard/pull/61), [#62](https://github.com/jihuayu/rootyard/pull/62) and [#63](https://github.com/jihuayu/rootyard/pull/63); main `53e77762a80a2fc28d4d3dcd8ca8c271eb687d47`. DeepSeek workers handled implementation, independent source review and separate acceptance/publication review.

**CLOSED:** #23 for the documented opt-in authority-scoped Pando deletion mode; #25 for the trusted single-host / disjoint-volume migration and CI handoff mode; #32 for the supported hosted-VM kernel profile; #38 was already closed via #57. #30 remains closed via #50. Historical #2–#19 are not mass-closed.

Current binary `157748add…` / production inputs `0f865a04…` passed four native migration/sidecar/takeover/partition groups, 145 Rust unit tests, real S3/Vault Pando maintenance, schema 132, five additional SIGKILL recovery cases and the final Patroni/etcd plus fresh-deployment restore/CI-checkout flow. [Migration proof](https://github.com/jihuayu/rootyard/tree/53e77762a80a2fc28d4d3dcd8ca8c271eb687d47/evidence/round3/migration25-ci-handoff-cb8d1b9) · [Final combination proof](https://github.com/jihuayu/rootyard/tree/53e77762a80a2fc28d4d3dcd8ca8c271eb687d47/evidence/round3/final-combination-157748add) · [Independent final approval](https://github.com/jihuayu/rootyard/blob/53e77762a80a2fc28d4d3dcd8ca8c271eb687d47/evidence/round3/final-combination-157748add-review.json). Final observed read/write recovery was 19.5227/20.7623 s, with zero lost among six acknowledged commits after automatic promotion. Restore intentionally lacks one post-backup ACK OID; no zero-RPO production DR claim.

The earlier Pando-combined source `1061a8e` also passed all ten acceptance groups and [VM run 42337108050](https://github.com/jihuayu/rootyard/actions/runs/42337108050) 17/17 kernel assertions; this is a different recorded build, not a claim that binary `157748add…` ran that VM matrix. Pando deletion remains opt-in; raw metadata-only PostgreSQL/PITR rollback against the shared bucket is unsupported, undetected and not fail-closed. Only paired Rootyard archives are supported restore authorities for that mode.

**OPEN:** #26 physical cross-host storage fencing; #43 distributed production HA/storage-fence qualification; #44 physical production hardware/cross-host validation; #48 umbrella. The new profile and measurements use one physical Linux host; hardware watchdog behavior, power loss, Kafka HA and HAProxy HA remain unqualified. Real local results and failed-attempt ledgers do not substitute for those gates. Three documented non-blocking migration operational residuals and both unclassified historical transients remain visible in the evidence.
<!-- rootyard-round3-status:end -->

<!-- rootyard-round2-status:start -->
## Historical round-2 status (`f319100`, before round-3 delivery)

Umbrella stays OPEN while child acceptance is unfinished. Final source `f319100` / input `fdfbbfc…` / binary `35d01…` passed all NativeCore and Ops matrices; physical GC 8/8 passed with test-only fixture fixes; integration commit `36d0545` commits the actual report set. [PR #56](https://github.com/jihuayu/rootyard/pull/56) is already merged at main `5fa4854`.

Roadmap markers: #30 already CLOSED via PR #50; #38 is CLOSED after PR #57 merged. #23/#25/#26/#32/#43/#44 remain open with the exact bounds above. Do not mass-close #2–#19: historical PR #49 code does not equal fresh acceptance. Overall production HA is NOT claimed.

Merged delivery: [#56](https://github.com/jihuayu/rootyard/pull/56) and [#57](https://github.com/jihuayu/rootyard/pull/57), main `d10627d60b2608bdffa37328a3cf514c82ce9184`. [Acceptance and remaining gates](https://github.com/jihuayu/rootyard/blob/d10627d60b2608bdffa37328a3cf514c82ce9184/docs/acceptance/round2-delivery.md) · [Native evidence](https://github.com/jihuayu/rootyard/tree/d10627d60b2608bdffa37328a3cf514c82ce9184/evidence/round2/integration-f319100) · [Independent DeepSeek review](https://github.com/jihuayu/rootyard/blob/d10627d60b2608bdffa37328a3cf514c82ce9184/evidence/round2/integration-f319100-review.json).
<!-- rootyard-round2-status:end -->

The repository has substantial implementation and lab coverage, but the remaining planned capabilities need explicit delivery and acceptance tracking. This umbrella issue links **26 functional capability tasks and 2 dedicated validation tasks** identified by a source/design review. Each linked issue states the current boundary, implementation scope, acceptance criteria and immutable source links.

The review baseline is `fdc9701964bdc9369a397780f5a6953a7972efd9`. The inspected newer main commit `85e5fa07` changes only the sharding JSON Cache-Control header and does not implement these capabilities. This review does not claim a fresh full-suite execution.

### Git backend and object storage

- [ ] #20 — Add a real streaming S3-compatible object storage backend
- [ ] #21 — Implement authenticated pack encryption and KMS-backed key rotation
- [ ] #22 — Integrate Pando into the authenticated Git gateway and backend migration lifecycle
- [x] #23 — Run storage maintenance as durable background jobs
- [x] #38 — Complete SHA-256 repository support across hosting, Forge and CI checkout
- [ ] #42 — Support concurrent independent-ref writes without a repository-wide transfer lock

### Distributed storage and deployment

- [ ] #24 — Route Git data requests to the owning shard node
- [x] #25 — Implement repository replication and resumable shard data migration
- [ ] #26 — Add a cluster controller with storage-enforced fencing and automatic takeover
- [ ] #43 — Provide a supported distributed deployment profile with secure dependencies and HA recovery

### Workspace, Namespace and execution

- [ ] #27 — Add the persistent, authorized Workspace service API
- [ ] #28 — Add live workspace capture, consistent checkpoints and replayable events
- [ ] #29 — Persist workspace checkpoints over an authenticated remote CAS protocol
- [x] #30 — Add transparent on-demand filesystem hydration for Workspace VFS
- [ ] #31 — Serve authorized Namespace and Git View workflows online
- [x] #32 — Implement the Agent and CI sandbox runner lifecycle

### CI, mirrors and authorization

- [x] #33 — Automatically synchronize PRs and deliver webhooks from durable background workers
- [ ] #34 — Add durable CI run orchestration and multi-mirror checkout scheduling
- [ ] #35 — Bind required CI checks to trusted integration identities
- [ ] #36 — Include LFS and submodule dependencies in CI checkout readiness
- [ ] #37 — Enforce bounded authorization revocation on active checkout transfers

### Git LFS

- [x] #39 — Store and recover LFS objects through the remote object-storage backend
- [x] #40 — Validate newly introduced Git LFS pointers before publishing refs
- [ ] #41 — Implement the Git LFS file-locking protocol

### Organization and browser workflows

- [ ] #46 — Add organization-owned repositories, teams and company namespace ownership
- [x] #47 — Add browser sign-in, sign-out and revocable Web UI sessions

### Production acceptance evidence

- [ ] #44 — Replace simulated cluster and DR receipts with real multi-node measurements
- [x] #45 — Add a real Git client and repository-state compatibility matrix

### Existing defects and delivery order

The existing correctness/security/integration-test defects #2–#19 remain tracked separately; they have not been duplicated as new feature requests. Some may have code changes awaiting verified closure. In particular, fix authorization, branch-policy, write-ahead journal, LFS concurrency and delivery fencing issues before extending the affected paths.

Suggested order:

1. Close known correctness/security defects with tests against actual Rust services; retain #10 as the test-integrity prerequisite.
2. Implement the remote storage/gateway and distributed data paths, including real data movement and storage fencing.
3. Deliver persistent Workspace/Namespace/CI workflows and their scoped identity and lifecycle controls.
4. Extend optional later-stage capabilities such as transparent filesystem hydration (#30) and LFS locks (#41); these are not retroactive requirements for the existing local lab/MVP.
5. Meet the real client, cluster and failure-recovery gates before claiming production support for those modes.

### Completion rule

A metadata flag, simulated receipt, reference-model test or synthetic principal is not completion evidence for a production data path. Close each capability only after its linked acceptance criteria are exercised against the relevant actual implementation. Update README, implementation-status, compatibility matrices and operations/recovery documentation to match the delivered boundary.

### Design sources

- [Implementation status](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/implementation-status.md)
- [Phased roadmap and acceptance gates](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/08-roadmap.md)
- [Service plan](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/05-services.md)
- [Workspace contract](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/03-workspace-vfs.md)
- [Distributed storage design](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/07-distributed-scaling.md)
- [CI mirror contract](https://github.com/jihuayu/rootyard/blob/fdc9701964bdc9369a397780f5a6953a7972efd9/docs/design/11-ci-read-mirrors.md)
<!-- END RETIRED ISSUE 48 BODY -->
