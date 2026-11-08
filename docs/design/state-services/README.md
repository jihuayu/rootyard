# 状态服务 W0：设计、生产者清单、部署契约与基线

> 状态：W0 文档/契约/工具交付。**设计提案，尚未实现或生产验收。** issue #106 仍为 OPEN；本目录不得被读作 RefStore/OpenDAL Blob/Target 架构已完成，也不得把本地 Git smoke 结果当作 #106 runtime baseline。

## 先读

- 原始 issue 设计快照：[`docs/design/12-state-services.md`](../12-state-services.md)（逐字节复制，SHA-256 见 [`snapshot.json`](snapshot.json)）
- 历史来源快照（01–11、source-page、source-manifest）未修改；第 12 章不属于归档的 823-block 来源。
- 设计状态仍是“设计提案，尚未实现或生产验收”；路线仍以 [第 08 章](../08-roadmap.md) 的历史快照为来源，W0 只通过状态/索引页同步，不修改历史正文。

## W0 资产

| 资产 | 用途 |
| --- | --- |
| [`snapshot.json`](snapshot.json) | 设计快照 SHA-256、baseline commit、已复制/未修改边界 |
| [`producers.json`](producers.json) | 可执行生产者清单：publish/auth mutation/root/hold/event/backup/durable ACK；实际文件+符号+迁移对象；逻辑根、物理 hold、auth scope 分列；未覆盖项显式列出 |
| [`deployment-contract.json`](deployment-contract.json) | 已实现/部分/提案/实验 profile 矩阵；目标配置故意不可选；跨字段拒绝规则与 legacy 例外 |
| [`config.schema.json`](config.schema.json) | 仅接受已实现 profile 的配置 schema；standalone/distributed 被枚举和拒绝规则双重拒绝 |
| [`configs/`](configs/) | 2 个 accepted 示例 + 6 个 rejected 示例（目标 profile、memory Blob、bare Git target、WAL-on-Blob、Pando local-only） |
| [`budgets.json`](budgets.json) | 10 个 provisional 预算；全部 `not_frozen`/bound null；未测量不得 pass |
| [`dependencies.json`](dependencies.json) | baseline 1.85 与计划 1.88 分开记录；crates.io verified 版本/许可证与 candidate 未验证项分开；W0 未添加依赖 |
| [`workloads/w0-bounded.json`](workloads/w0-bounded.json) | 有限本地 Git workload；PG/API/Blob 明确 disabled |
| [`native-baseline.md`](../../../evidence/state-services/native-baseline.md) | root 侧 native baseline 回执与未验收项；W0 不重跑 |
| [`w0-local-git-smoke.json`](../../../evidence/state-services/w0-local-git-smoke.json) | 本仓库生成的有限本地 Git smoke；身份/provenance 证据，**不是** #106 runtime baseline |

## 验证

```bash
python3 scripts/check_state_services.py
python3 -m py_compile scripts/state_services_baseline.py scripts/state_services_checks.py scripts/check_state_services.py
python3 tests/test_state_services_w0.py
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

`--binary` 只计算 SHA-256，不执行。PostgreSQL 仅在显式 `--pg-dsn-file` 且本机有 `psql` 时测量；否则明确 `unavailable`/`null`。HTTP API、OpenDAL Blob、Raft、Redis 在 W0 中没有可用的真实服务，全部 `unavailable`，不得补造数值。

## 明确未完成（#106 保持 OPEN）

- root 侧 native baseline runner 仍在审查；外部 harness 路径可移植性未确认，本目录只记录已给回执，不重跑、不声称通过。
- v1 因错误 PG selector 被拒绝并保留为 failed measurement；v2 的 109 samples、PG peak 15/16 conns、RSS 数据是 root 回执，不是本 W0 产生。
- 全阶段 waits、Blob bytes、真实多主机/多故障域和完整 producer coverage 仍为 null/unmeasured。
- 设计中的 Scope CLOSING/CancelDecision、RefStore、BlobStore/OpenDAL、W1–W9 均未实现。
- 现有生产路径继续是 **legacy** GitFS/PG 或已存在的 Pando remote+Vault 路径；不得把两者标成 target/new deployment。
