# Schema 134：仓库/租户复合外键（#90）

## 判定边界

`jobs::current`、transition fence 与 Pando serving 查询本来就会复核
owner/generation/backend，当前 runtime 未发现可利用的跨租户删除路径。这不是
P1 漏洞，本迁移**不删除也不弱化**任何运行时防护。缺的是关系完整性：数据库允许
`repository_id` 与另一个租户的 `tenant_id` 组成一行，运行时检查因此成了唯一
防线。Schema 134 让这种组合在约束层无法成立。

## 迁移内容

| 表 | 变更 |
| --- | --- |
| `pando_pack_manifests` | 新增 `UNIQUE (id, repository_id, tenant_id)`（`pando_pack_manifests_id_repository_tenant_key`）；保留原有 `UNIQUE (repository_id, id)` |
| `pando_manifest_artifacts` | 用 `(manifest_id, repository_id, tenant_id) -> pando_pack_manifests(id, repository_id, tenant_id)` 替换仅 `manifest_id` 的外键（实际旧名 `pando_manifest_artifacts_manifest_id_fkey`），保留 `ON DELETE CASCADE`；artifact 的 authority/tenant 外键不变 |
| `storage_maintenance_repo_state` | `(repository_id, tenant_id) -> repositories(id, owner_id)`（`storage_maintenance_repo_state_repository_owner_fkey`），保留 cascade 与 namespace 外键 |
| `storage_maintenance_jobs` | 同上（`storage_maintenance_jobs_repository_owner_fkey`） |
| `storage_maintenance_tombstones` | 同上（`storage_maintenance_tombstones_repository_owner_fkey`） |

仅 `manifest_id` 的外键必须删除而不是并存：两个外键会让同一批 manifest 行带两条
级联路径，产生冗余的级联触发。所有新约束显式命名。

## 索引

不新增 lookup 索引。级联与校验复用既有定义：`pando_manifest_artifacts_pkey`
以 `manifest_id` 开头；三张维护表分别以 `storage_maintenance_repo_state_pkey`、
`storage_maintenance_history`、`storage_maintenance_tombstones_pkey` 的
`repository_id` 前导列覆盖；被引用侧复用 `repositories_owner_identity`
（`(id, owner_id)` 唯一索引）。唯一新增的索引是复合外键所必需的
`pando_pack_manifests_id_repository_tenant_key`。

## 升级拒绝策略

迁移在加约束前先做只读预检：link 行的 repo/tenant 是否与 manifest 不一致、三张
维护表的 tenant 是否与当前 repo owner 不一致。只要有不一致，迁移以固定格式、
**只含行数**的诊断中止（不含任何 id、租户、对象或负载值），由运维人工检查。
迁移绝不静默删除或改写 job、tombstone、artifact 链接或 owner。失败时整个
migration transaction 回滚：`schema_migrations.version=134` 不会出现，四个新
外键和 `pando_pack_manifests_id_repository_tenant_key` 不会残留，旧的
单列 manifest 外键仍在，违规行原样保留。

## 两个 native 入口

| 入口 | 前置 schema | 证明的契约 |
| --- | --- | --- |
| `tests/storage_identity_fks.py --binary NEW --report` | candidate 已迁移到 134 | 134 的约束/索引形状；两个 owner 的真实 GitFS push + 真实 Pando cutover/publication；两个 owner 的真实 links、clone/fetch/fsck；精确 `23503` 负例；负例之后仍可真实 publication/fetch |
| `tests/storage_identity_upgrade.py --binary NEW --legacy-binary OLD --report` | 真实 legacy binary 写出的 schema133 | dirty schema133 上固定诊断拒绝、事务回滚与 bad row 原样保留；显式删除本测试自己的 bad row 后升级成功；四个新外键、ledger 134 与 clone/fetch/fsck |

两个入口都以真实 PostgreSQL 为准。第二个入口不需要真实 Pando：它只种一类
`storage_maintenance_jobs.tenant_id` 与 repo owner 不一致的脏行，用来证明升级
拒绝和显式修复路径；真实 Pando publication 由第一个入口证明。两者不能互相替代，
也不能用修改 manifest、dump 或手写 migration 子集伪造 legacy schema。这两个
Round-5 原生脚本显式固定断言 `schema_migrations = 134`（`tests/storage_identity_fks.py:294`
及 `schema 135` 之前的索引基线、`tests/storage_identity_upgrade.py:174`）；当前
`schema 134..=147` 演进后的每 PR 实时数据库与 worker 回归见下文最后一部分。

## 负例设计

`tests/storage_identity_fks.py` 先让 Alice 与 Bob 的两个仓库都完成真实 GitFS
push、真实 Pando cutover，并在 cutover 后再真实 push。每个 owner 的 link 必须
满足：`pando_manifest_artifacts` 的 `repository_id`/`tenant_id` 与 manifest 完全
一致、link 的 `tenant_id` 等于该仓库 owner、四个 artifact role 齐全、对应
`pando_remote_artifacts` tuple 真实存在。随后两个仓库各自 clone、`git fetch`、
`git fsck --full`。

负例只使用受控 SQL，但每个 insert 都先预验证：

1. 使用的 synthetic manifest 是真实 manifest 的副本，新 UUID、相同
   `(repository_id, tenant_id)` 三元组、零 artifact link，因此
   `(manifest_id, artifact_role)` 主键必然空闲；断言失败只可能来自目标外键。
2. 合法 manifest 三元组已存在；用于“缺失引用”的 artifact tuple 在目标 tenant
   下确实不存在，而在另一个真实 owner 下确实存在。
3. 只允许目标外键失败：断言 SQLSTATE 恰为 `23503` 且 constraint 名精确匹配；
   语法错误、check 约束、主键冲突或其他错误一律不算通过。

artifact-tenant 负例特意使用**合法 manifest 三元组**（Bob 的真实 manifest 副本
+ Bob repo + Bob tenant），只让 artifact 引用缺一个 tenant tuple：namespace 与
真实 remote row 的目标契约一致，sha256 真实属于 Alice，而 Bob 下不存在该 tuple。
因此该 insert 只违反
`pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey`，不会再同时
违反 manifest identity 外键。旧的两个 negative fixture（fresh manifest key）
仍然保留，且与两个 owner 的真实 manifest id 不冲突。

本脚本**不插入任何合成 remote-artifact metadata**：所有引用都来自两个真实
publication 注册的 remote tuple。真实 published objects 由环境提供的专用合成
Garage bucket 保留，脚本不删除任何有效 remote 对象。

## 运行环境与清理边界

- 必须使用专用合成 Garage bucket（例如 `scripts/owned_garage_fixture.sh`
  创建的 job-owned `rootyard-ci-*` bucket）和专用测试 PostgreSQL；不得指向生产或
  共享的有效数据。
- 测试不会自动删除真实 published remote 对象，也不得用“清理 bucket”的方式删除
  有效 remote 对象；那会绕过 GC/retention 语义并让证据失真。
- 受控 SQL 只删除本脚本自己写入的 synthetic manifest 行；若未来有测试确需合成
  remote metadata，只能写 `state='deleted'`、无远端字节的行，并在 `finally` 中按
  精确主键清理。当前脚本没有这类行。
- 运行结束只 drop 本进程随机创建的 PostgreSQL schema；真实对象存储内容保留。

## 集成与验收状态

- 冻结目录与当前契约：`schema/134_catalog.json`、`schema/134_restored_catalog.json`
  与 `schema/134_upgraded_catalog.json` 由真实 PostgreSQL 生成并在 `format 10`
  （`schema 134`）冻结；当前 `main` 已演进至 `schema 147`（`format 21` 元数据归档 /
  `format 22` 同物理 Blob 后端 `pg_refstore` `pack`/`idx` OpenDAL Blob 配对闭包归档），
  完整目录与 `pg_dump`/`pg_restore` 往返契约由 `tests/schema_contract.py` 在每 PR
  强制校验。
- Legacy 归档直接迁移恢复：`--allow-legacy-schema133`（仅限 `format 9 / schema 133`
  冻结归档）在导入 `schema 133` 转储后直接在数据库内按序执行内嵌 SQL 迁移 `134..=147`
  直达当前 `schema 147`（`src/backup/restore.rs:95, 243-250`），不经过中间 `format 10`
  归档步骤（`format 10 / schema 134` 为独立冻结归档格式，由 `--allow-legacy-schema134`
  单独校验恢复）；恢复时轮换新的 Pando storage authority 并重新导入远端对象闭包。
- Round-5 `schema 134 / format 10` 原生验收收据（候选二进制 `85c66397...`，非 `schema 147`
  二进制恢复运行）：
  - `docs/acceptance/round5-security-maintenance-evidence/schema134-legacy133-restore.json`：
    `format 9 / schema 133` 归档恢复至当期 `schema 134` 并轮换 Pando authority；
  - `docs/acceptance/round5-security-maintenance-evidence/security134-format10-backup-rerun.json`：
    `format 10 / schema 134` 离线屏障备份与新环境恢复；
  - `docs/acceptance/round5-security-maintenance-evidence/schema134-storage-identity-native-rerun.json`：
    真实 Garage + Vault Transit 双租户 Pando 发布及精确 `23503` 约束负例；
  - `docs/acceptance/round5-security-maintenance-evidence/schema134-dirty-upgrade-rerun2.json`：
    真实 `schema 133` 旧二进制脏库升级拒绝、回滚与显式修复后升级至 `schema 134`；
  - `docs/acceptance/round5-security-maintenance-evidence/security134-storage-lifecycle.json`
    （`tests/storage_lifecycle.py`）：仅覆盖定时 repack/staging 清理、租约过期重领
    （lease-expiry reclaim）与进程 `SIGKILL` 卷锁屏障（volume-lock barrier）。
- 每 PR 实时 PostgreSQL 与真实 Rust worker 门禁（`schema 134..=147`）：
  `tests/schema_contract.py` 校验冻结目录与转储往返；`tests/test_storage_identity_fks.py`
  在实时 PostgreSQL 上校验 `schema 134..=147` 复合外键/唯一约束、精确 `23503` 拒绝与
  `schema 133` 四类脏行单类及 `(1, 1, 1, 1)` 组合升级拒绝/零泄露/回滚；
  `tests/test_storage_identity_runtime.py` 启动启用 `storage_lifecycle` worker 的真实
  `rootyard` 二进制，在 GitFS 与 Pando 的 `mark`/`delete` 任务上验证跨租户 `23503` 拒绝、
  `stale-generation / wrong-backend / not-ready`（`recovering` 与 `provisioning`）运行期
  fail-closed（不写 tombstone、不退休远端 artifact、不删磁盘对象）及合法 `ready` 任务完整
  执行。仓库所有权变更期间的维护任务清理仍由 `#85` 独立跟踪。
