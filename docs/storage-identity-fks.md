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
迁移绝不静默删除或改写 job、tombstone、artifact 链接或 owner。

## 验证

`tests/storage_identity_fks.py`（`--binary ABS --report`）复用共享 Harness 与真实
PostgreSQL/Garage/Vault：两个不同 owner 的真实仓库、真实 Git push、真实 Pando
cutover 与 publication/fetch；负例用本 schema 内的受控 SQL 插入，断言 SQLSTATE
`23503` 与精确 constraint 名，并用全新未关联的 manifest 副本保证失败不可能来自
主键重复或 check 约束。合法 publication/fetch 在负例之后继续。

负例中的合成 remote artifact 行没有远端字节，只用于让独立 artifact 外键先被满足，
测试结束后删除；它不构成任何上传证明。

## 未闭项（协调者负责）

- 真实 PG 目录生成 / `schema/134_*_catalog.json` canonical JSON。
- backup format 10 与 legacy schema133 恢复支持：134 进入
  `SCHEMA_VERSIONS` 后，format 9（schema 133 目录）不再自洽。本分支不修改
  backup 格式，也**不宣称备份门禁通过**。
- dirty pre-upgrade 拒绝（schema133 上已存在不一致行）需要单独的真库用例，当前
  脚本明确未测。
- runtime stale-generation / wrong-backend / not-ready fail-closed 仍由
  `tests/storage_lifecycle.py` 与 `tests/storage_lifecycle_physical.py` 证明，本分支
  不重复实现，也不用 SQL 字符串检查替代。
