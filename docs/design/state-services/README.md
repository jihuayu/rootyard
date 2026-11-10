# 状态服务 W0：设计、生产者清单、部署契约与基线

> 状态：W0 文档/契约/工具交付。本分支已 rebase 到 security/token/membership parent `bcd3918`；历史 `d689bf8` 原生回执未在该 parent 重跑，不构成新资格。**设计提案，尚未实现或生产验收。** issue #106 仍为 OPEN；本目录不得被读作 RefStore/OpenDAL Blob/Target 架构已完成，也不得把本地 Git smoke 结果当作 #106 runtime baseline。

## 先读

- 当前协议：[第 12 章 `docs/design/12-state-services.md`](../12-state-services.md)，从 canonical 分支
  `codex/state-services-architecture-v2`（`23334bd`）恢复；合并 PR #124 曾误用旧 W0 正文覆盖它。
  fresh-install-only、Blob-only 双部署、HTTP-only、无 PG fallback 与签名撤销屏障以该文为准。
- W0 原始 issue 设计快照：[`historical-w0/state-services-design.md`](historical-w0/state-services-design.md)
  （逐字节复制，SHA-256 `0187d9c0…`、80072 bytes，见 [`snapshot.json`](snapshot.json)；历史归档，**不是当前协议**）。
- 历史来源快照（01–11、source-page、source-manifest）未修改；第 12 章和 W0 历史快照不属于归档的 823-block 来源。
- 设计状态仍是“设计提案，尚未实现或生产验收”；路线仍以 [第 08 章](../08-roadmap.md) 的历史快照为来源，W0 只通过状态/索引页同步，不修改历史正文。

## W0 资产

| 资产 | 用途 |
| --- | --- |
| [`snapshot.json`](snapshot.json) | W0 历史设计快照与当前第 12 章的 SHA-256/git blob、baseline commit、已复制/未修改边界 |
| [`historical-w0/`](historical-w0/README.md) | W0 原始设计正文归档（已被彻底取代；只用于可复现历史） |
| [`producers.json`](producers.json) | 可执行生产者清单：publish/auth mutation/root/hold/event/backup/durable ACK；实际文件+符号+迁移对象；逻辑根、物理 hold、auth scope 分列；未覆盖项显式列出 |
| [`deployment-contract.json`](deployment-contract.json) | 已实现/部分/提案/实验 profile 矩阵；目标配置故意不可选；跨字段拒绝规则与 legacy 例外 |
| [`config.schema.json`](config.schema.json) | 仅接受已实现 profile 的配置 schema；standalone/distributed 被枚举和拒绝规则双重拒绝 |
| [`configs/`](configs/) | 2 个 accepted 示例 + 6 个 rejected 示例（目标 profile、memory Blob、bare Git target、WAL-on-Blob、Pando local-only） |
| [`budgets.json`](budgets.json) | 10 个 provisional 预算；全部 `not_frozen`/bound null；未测量不得 pass |
| [`dependencies.json`](dependencies.json) | baseline 1.85 与计划 1.88 分开记录；crates.io verified 版本/许可证与 candidate 未验证项分开；W0 未添加依赖；`implementation_overlay` 只记录一个空、默认 OFF 的 feature |
| [`workloads/w0-bounded.json`](workloads/w0-bounded.json) | 有限本地 Git workload；PG/API/Blob 明确 disabled |
| [`native-baseline.md`](../../../evidence/state-services/native-baseline.md) | 历史 `d689bf8` legacy Pando 原生基线回执、可重跑命令和未验收项；不qualify rebased parent 或新后端 |
| [`w0-local-git-smoke.json`](../../../evidence/state-services/w0-local-git-smoke.json) | 本仓库生成的有限本地 Git smoke；身份/provenance 证据，**不是** #106 runtime baseline |

### Cargo feature-only overlay

`current_stack_parent` 的 `Cargo.toml`/`Cargo.lock`/`LICENSE` 哈希仍是 frozen
parent `bcd3918` 的引用，不得用子分支 manifest 哈希重标。当前分支唯一允许的
偏差是 `implementation_overlay` 声明的空、默认 OFF `state-baseline-metrics`
feature：validator 用标准库 `tomllib` 解析当前 manifest，只删除这一个已声明的
空 feature 后与 parent 的 canonical（排序 JSON 化）语义 SHA-256 比较；
`Cargo.lock` 必须保持 parent 哈希。依赖、版本、额外 feature、默认启用或 MSRV
变更全部失败。没有 `implementation_overlay` 时恢复原始严格 parent-hash 检查。
该 overlay 只是 provenance 记录，不是 W0 修改 Cargo 的许可，也没有新增依赖。

## 验证

```bash
python3 scripts/check_state_services.py
python3 -m py_compile scripts/state_services_baseline.py scripts/state_services_checks.py scripts/check_state_services.py
python3 tests/test_state_services_w0.py
python3 -m unittest tests.test_state_services_overlay tests.test_state_services_native_cleanup
python3 scripts/check_design_docs.py
```

本地有限 Git smoke（**不是** #106 runtime baseline）：

```bash
python3 scripts/state_services_baseline.py \
  --workload docs/design/state-services/workloads/w0-bounded.json \
  --budgets docs/design/state-services/budgets.json \
  --binary /path/to/rootyard \
  --out /tmp/rootyard-w0-smoke.json
```

`--binary` 只计算 SHA-256，不执行。PostgreSQL 仅在显式 `--pg-dsn-file` 且本机有 `psql` 时测量；否则明确 `unavailable`/`null`。此脚本的 HTTP API、OpenDAL Blob、Raft、Redis 测量全部 `unavailable`。独立的 [原生服务基线](../../../evidence/state-services/native-baseline.md) 使用真实 legacy Pando/PG/Garage/Vault，不与本地 Git smoke 混算。

## 明确未完成（#106 保持 OPEN）

- 已记录可重跑原生 legacy Pando v5 基线；它不代表新后端、精确 CAS 竞态、多故障域或完整 #106 验收。
- v1 因错误 PG selector 被拒绝；v5 使用 API 自有 socket 的 client port 匹配 PG 连接，并替代 v2/v3 草稿测量。零采样锁等待不能证明无争用。
- 全阶段 waits、Blob bytes、真实多主机/多故障域和完整 producer coverage 仍为 null/unmeasured。
- 设计中的 Scope CLOSING/CancelDecision、RefStore、BlobStore/OpenDAL、W1–W9 均未实现。
- 现有生产路径继续是 **legacy** GitFS/PG 或已存在的 Pando remote+Vault 路径；不得把两者标成 target/new deployment。
