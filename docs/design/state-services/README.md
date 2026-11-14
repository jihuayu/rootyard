# 状态服务：当前模式、拒绝边界与历史 W0 归档

> 状态（2026-11-14）：本页区分**当前代码可运行模式**与**冻结的 W0 历史归档**。
> 当前默认仍是 legacy `rootyard serve`（GitFS/PG，既有可选 Pando 路径）；显式候选
> `rootyard serve-blob` 已使用 PostgreSQL 业务库、PG RefStore 和远程 OpenDAL Blob；
> 分布式 Raft Ref-CAS 仍是 **PROPOSED**，未在运行时可选择。`serve-blob` 不是默认入口；
> 默认入口切换由 [#148](https://github.com/jihuayu/rootyard/issues/148) 单独跟踪，不是
> #106 契约/基线的前置循环。**#106 保持 OPEN；本页不声称完整验收或生产资格。**

规范以 [第 12 章](../12-state-services.md) 和 [ADR](../../architecture.md) 为准；下面的
“当前模式/拒绝边界”以实际代码为准，历史 W0 JSON/config 只作为归档输入。

## 当前代码支持的模式与拒绝边界

| 模式 | 运行时选择 | 持久依赖与权威 | 当前状态 |
| --- | --- | --- | --- |
| 默认 legacy `rootyard serve` | 省略子命令或 `serve`；`src/main.rs`，配置来自 `src/config.rs` | 业务 PostgreSQL + 本地 `ROOTYARD_DATA_DIR` 裸 GitFS（默认 refs/objects 权威）；既有可选 Pando per-repo 路径仍在，不是 target | 当前默认，不是 fresh target。缺少 `DATABASE_URL`、Git 或卷锁时失败；本地卷是既有持久权威。 |
| Standalone target，候选 `rootyard serve-blob` | 精确子命令 `serve-blob`；`src/main.rs` → `src/standalone.rs` | 业务 PG + PgRefStore（`pg_refstore`）+ 远程 OpenDAL Blob；本地裸 Git/scratch 只是可删除计算视图，不是持久回退 | 候选入口，可运行但非默认；核心 HTTP/Git/browse/format22 已有候选验收，LFS/PR/Workspace/CI 与默认入口切换未完成。 |
| Distributed target **PROPOSED** | `src/main.rs` 没有 CLI/env selector；`crates/refcas-log` 只是隔离实验 crate，不是运行依赖 | 业务 PG + Raft Ref-CAS 元数据 + 同一 Blob；Raft/Redis/PG 行不保存大字节；目标契约禁止 PG refs/本地视图回退 | 未实现、不可运行时选择。不要声称存在已校验的分布式 selector，也不要把实验 crate 当作 Ref-CAS 运行时。 |

### `serve-blob` 的代码级启动拒绝

- 缺少 `DATABASE_URL`：`src/standalone.rs` 在打开池和生命周期屏障前返回
  `DATABASE_URL is required`；无效 PG 配置同样失败关闭。
- 缺少真实远程 Blob 配置：`src/blob_store/config.rs` 的 `BlobProfile::from_env`
  要求显式 `ROOTYARD_BLOB_ENDPOINT`；S3 还要求 service/bucket/region/access/secret，
  并拒绝 `fs`、`memory` 和未知 service。生产 profile 没有本地/内存 Blob 回退。
- 缺少或不合格的 `ROOTYARD_SCRATCH_DIR`：`src/standalone/config.rs` 要求绝对、
  私有、非符号链接目录；不满足即拒绝启动。
- PG schema/生命周期屏障不可用（包括 `public.cluster_authority` 缺失）：
  `src/standalone.rs` 返回固定的
  `Blob service schema or lifecycle barrier is unavailable`；屏障由
  `src/backup/authority.rs` 查询 `public.cluster_authority`，表由
  `migrations/085_cluster_authority.sql` 建立。隔离 random-schema fixture 必须先执行
  production CLI public migration，否则 Harness 的 schema 初始化不会创建
  `public.cluster_authority`；有界基线 README 记录了这一首次 503/preflight 和随后的
  CI 初始化重跑。
- 没有 canonical 的 64 个十六进制字符 Blob 物理后端身份：`src/blob_git_gateway/config.rs`
  的 `BlobGitConfig::validate` 拒绝；已验证 receipt/locator 绑定到另一后端时，
  `src/blob_store/backend_identity.rs` 的约束同样失败关闭。这只是 gateway/证据拒绝，
  不是分布式激活选择器。
- `ROOTYARD_SESSION_KEYRING` 可选；未配置时 session 路由明确 `501`，不生成或共享
  默认密钥（`src/blob_git_gateway/state.rs`）。这不改变 core `serve-blob` 的持久
  PG RefStore + Blob 边界。

两种 target 部署都要求业务 PG 和 Blob；Raft 只承载元数据，不承载 pack/LFS/
workspace/checkpoint/backup 字节。默认 legacy `serve` 不是这两种 target 之一。

### 有界 root 基线（不是容量/SLO 声明）

Root-run 的 credential-free 有界基线：
[README](../../../evidence/state-services/blob-baseline-20261114/README.md) 和
[报告](../../../evidence/state-services/blob-baseline-20261114/report.json)。
它绑定 root integration `ce1aaa3caccb6e9bca73cd960e4803aac8dfd862` 与 binary
`66fdfba3b7c55d9ceb659afc86d806a74b1336e0c1ee63904f6f17c82ee06cb3`，不是本 feature
branch 的运行结果。覆盖一个 256 KiB 仓库、两个并发只读 clone、restart 后
empty-scratch cold clone 和 250 ms PG session 采样；provider cache 未知，精确
lock-wait、OpenDAL GET bytes/phases、请求 wire bytes、容量和 SLO 均未测量。
报告明确 `issue_complete=false`、`budgets_frozen=false`。指标页对应段落：
[state-services-baseline-metrics.md](../../state-services-baseline-metrics.md#fresh-install-blob-only-baseline-evidence-2026-11-14)。

## 目标契约与 fresh-install 边界

- **standalone target**：一个 Rust 应用 + 业务 PostgreSQL + PgRefStore + 远程
  OpenDAL Blob + 可删除计算视图；不要求 Redis/Raft/Kafka/Vault/FUSE/controller。
  当前对应候选入口是 `serve-blob`，不是默认 `serve`。
- **distributed target**：业务 PostgreSQL + Raft Ref-CAS 元数据 + 同一 Blob；
  Raft 不可用时 ref 读写失败关闭，不回落 PG 投影或本地视图。当前没有运行时可选择的
  distributed 模式，也没有根依赖的 Raft 运行时。
- **fresh target only**：不设计 GitFS/Pando 导入、旧 schema/backup/archive 升级、
  PG↔Raft 在线迁移、双写或双权威回退。新仓库按 target provisioning 创建。
- 默认入口 cutover 与 target activation 由 [#148](https://github.com/jihuayu/rootyard/issues/148)
  单独跟踪；#106 只冻结 fresh-install 契约、配置/拒绝语义和有界基线，不把 #148
  当作前置循环。

### 现有 legacy CLI 与 target plan 的区别

`rootyard pando-transition ...`、`rootyard restore ... --allow-legacy-schema007/130..143`
和 `rootyard-pando-lab migrate`/`migrate-step` 是现有 legacy 过渡/恢复/实验 CLI
（`src/main.rs`、`src/pando_gateway/transition/operator.rs`、`src/pando_lab/mod.rs`），
不是 fresh target 的导入或升级方案，也不证明 distributed 可运行。不要用这些现有
flag 推断 target selector 已校验。

## 历史 W0 归档（冻结 d689bf8/bcd3918）

以下 W0 契约、配置、生产者和预算来自 `d689bf8`/rebase parent `bcd3918` 时点的冻结
输入，**不是当前 deployment profile**。它们仍由既有工具校验归档完整性和历史语义；
validator PASS 不等于当前 runtime 验收。JSON/config 字节和 validator 不在本次
checkpoint 中修改。

| 历史资产 | 用途 |
| --- | --- |
| [`snapshot.json`](snapshot.json) | W0 历史设计快照与当前第 12 章的 SHA-256/git blob、baseline commit、已复制/未修改边界 |
| [`historical-w0/`](historical-w0/README.md) | W0 原始设计正文归档（已被彻底取代；只用于可复现历史） |
| [`producers.json`](producers.json) | 历史可执行生产者清单：publish/auth mutation/root/hold/event/backup/durable ACK；未覆盖项显式列出 |
| [`deployment-contract.json`](deployment-contract.json) | 冻结 `d689bf8` profile 矩阵；只作历史/validator 输入，不是当前 selector |
| [`config.schema.json`](config.schema.json) | 冻结 W0 配置 schema；standalone/distributed 的当时拒绝规则不是当前 profile 表 |
| [`configs/`](configs/) | 2 个历史 accepted 示例 + 6 个历史 rejected 示例；不是当前部署示例 |
| [`budgets.json`](budgets.json) | 10 个历史 provisional 预算；全部 `not_frozen`/bound null；未测量不得 pass |
| [`dependencies.json`](dependencies.json) | 历史 baseline 1.85/计划 1.88 与 candidate 记录；W0 overlay 只是 provenance |
| [`workloads/w0-bounded.json`](workloads/w0-bounded.json) | 历史有限本地 Git workload；PG/API/Blob 明确 disabled |
| [`native-baseline.md`](../../../evidence/state-services/native-baseline.md) | 历史 `d689bf8` legacy Pando 原生基线回执、可重跑命令和未验收项；不 qualify rebased parent 或新后端 |
| [`w0-local-git-smoke.json`](../../../evidence/state-services/w0-local-git-smoke.json) | 历史有限本地 Git smoke；身份/provenance 证据，**不是** #106 runtime baseline |

### Cargo feature-only overlay（历史 provenance）

`current_stack_parent` 的 `Cargo.toml`/`Cargo.lock`/`LICENSE` 哈希仍是 frozen
parent `bcd3918` 的引用，不得用子分支 manifest 哈希重标。历史 W0 分支唯一允许的
偏差是 `implementation_overlay` 声明的空、默认 OFF `state-baseline-metrics`
feature：validator 用标准库 `tomllib` 解析当前 manifest，只删除这一个已声明的
空 feature 后与 parent 的 canonical（排序 JSON 化）语义 SHA-256 比较；
`Cargo.lock` 必须保持 parent 哈希。依赖、版本、额外 feature、默认启用或 MSRV
变更全部失败。没有 `implementation_overlay` 时恢复原始严格 parent-hash 检查。
该 overlay 只是 provenance 记录，不是 W0 修改 Cargo 的许可，也没有新增依赖。

历史 W0 文案中“RefStore、BlobStore/OpenDAL、W1–W9 未实现”等表述只描述该归档时点，
不描述当前代码；当前 `serve-blob` 已使用 PG RefStore 和 OpenDAL 路径，但仍是候选
入口，分布式 Raft 仍未实现。

历史 `d689bf8` 的 legacy Pando 基线回执记录于 [native-baseline](../../../evidence/state-services/native-baseline.md)：
可重跑脚本、原生二进制/源码/锁文件绑定、stock Git、真实 PG/Garage/Vault、冷暖 clone、
竞争写入与 atomic 成功路径。该回执是**历史 pre-evolution 基线**，不回算到 rebase
parent，也不代表新后端或多主机资格。历史 v1 因错误 PG selector 被拒绝；v5 使用
API 自有 socket 的 client port 匹配 PG 连接；零采样锁等待不能证明无争用；全阶段
waits、Blob bytes、精确 old-OID CAS 竞态和完整 producer coverage 仍为未验收。

## 验证

```bash
python3 scripts/check_state_services.py
python3 -m py_compile scripts/state_services_baseline.py scripts/state_services_checks.py scripts/check_state_services.py
python3 tests/test_state_services_w0.py
python3 -m unittest tests.test_state_services_overlay tests.test_state_services_native_cleanup
python3 scripts/check_design_docs.py
```

前四项验证冻结 W0 快照、生产者/契约/预算/依赖和 overlay provenance；它们通过只说明
历史归档输入完整，不说明当前 profile 已切换。`check_design_docs.py` 验证设计文档链接/
来源块，不运行 Rust、PG 或 Blob。本次 checkpoint 在 feature worktree 上运行这些
Python/doc/static 检查，**全部 PASS**（W0 41 项、overlay/native cleanup 24 项、设计文档
436 个仓库链接）；没有既有 baseline failure，也没有修改冻结 JSON/config 或 validator
来制造通过。本 checkpoint 未新增测试来镜像本页措辞。若未来冻结检查失败，应记录失败，
保留历史输入，不得为强制通过而改写它们。

历史本地 Git smoke（**不是** #106 runtime baseline）：

```bash
python3 scripts/state_services_baseline.py \
  --workload docs/design/state-services/workloads/w0-bounded.json \
  --budgets docs/design/state-services/budgets.json \
  --binary /path/to/rootyard \
  --out /tmp/rootyard-w0-smoke.json
```

`--binary` 只计算 SHA-256，不执行。PostgreSQL 仅在显式 `--pg-dsn-file` 且本机有
`psql` 时测量；否则明确 `unavailable`/`null`。此脚本的 HTTP API、OpenDAL Blob、
Raft、Redis 测量全部 `unavailable`。独立的有界 root baseline 见上文，不与本地 Git
smoke 混算。

## 明确未完成（#106 保持 OPEN）

- 默认入口仍是 legacy `serve`；standalone/Blob-only 入口切换由 #148 单独跟踪，
  不是 #106 的前置循环。
- `serve-blob` 已是候选入口，但默认入口替换、LFS/PR/Workspace/CI 接入、完整业务
  producer 等价和默认部署验收仍未完成。
- Distributed Raft Ref-CAS 运行时、Redis 投影/cursor、远程决策桥、撤销协调和
  PG 投影/finalizer 未交付；`crates/refcas-log` 只是隔离实验，不是运行时。
- Fresh restore、HA、多主机/多故障域、容量成本、GC 和完整 producer coverage
  仍未验收；物理 Blob 删除保持关闭。
- 历史 d689bf8/v5 legacy Pando 基线和历史 W0 deployment-contract/config 不等于
  target/new deployment；#106 不能因本页或基线证据而标为 complete/closed。
