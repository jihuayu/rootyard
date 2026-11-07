# 并行开发与模块边界契约

本文档定义 Rootyard 多工作流并行开发的代码边界、共享底座接口、数据库迁移分段与合流检查清单，确保多条工作流在不同分支同时推进时不会在路由组装、鉴权辅助函数、迁移链与备份测试基线上产生合并冲突。

## 1. 为什么需要前置解耦

在历史提交（如 `007` 与 `008` 迁移演进）中，新增任意一张数据库表或一组 HTTP 路由都会同时修改：

1. `src/lib.rs` 的集中式路由表；
2. `src/db.rs` 的命令式迁移链；
3. `src/backup.rs` 的硬编码版本列表；
4. 7 个以上 Python 端到端测试文件（`tests/forge.py`、`tests/reliability.py`、`tests/backup_*.py`、`tests/schema_contract.py`）中硬编码的 `"1,2,3,6,7,8"`、`[1, 2, 3, 6, 7, 8]`、`16` 与 `'008_catalog.json'`。

完成前置拆分后，上述热点均已收敛为声明式单点定义或领域自包含子路由。

---

## 2. 并行开发轨道与文件归属

### 2.1 第一梯队并行轨道（Phase 1）

各并行轨道应当只修改各自归属的源码模块、二进制入口与独立测试套件：

| 轨道 | 负责范围 | 专属源码文件 / 目录 | 专属测试文件 |
| --- | --- | --- | --- |
| **Track 1：PR 与评审流** | Pull Request 状态机、Review、Check Run、Branch Rules 与同代原子 Merge | `src/pulls.rs`、`src/pulls/` | `tests/pulls.py`、`tests/backup_pulls.py`、`tests/test_pulls.py` |
| **Track 2A：仓库浏览与 Ref 事务 API** | Tree/Blob/Commit 只读 API、分页、原子多引用 CAS 事务 | `src/browse.rs`、`src/browse/` | `tests/browse.py`、`tests/test_browse_lfs.py` |
| **Track 2B：Git LFS 对象网关** | Git LFS Batch API、对象上传/下载、SHA-256 大小校验与配对备份校验 | `src/lfs.rs`、`src/lfs/` | `tests/lfs.py`、`tests/test_browse_lfs.py` |
| **Track 3：CI Mirror 淘汰与调度** | Mirror 磁盘水位 LRU 清理（避开活跃租约与 retention ref）、限流与指标 | `src/mirror.rs`、`src/mirror/`、`src/ci_pins.rs`、`src/ci_checkouts.rs` | `tests/ci_mirror.py`、`tests/ci_source_pins.py`、`tests/ci_job_checkouts.py`、`tests/test_ci_mirror.py` |
| **Track 4A：Pando 实验推进** | Streaming delta 解析、Tree/Commit 图遍历、Git 导出双算子对拍 | `src/pando_lab/`、`src/bin/rootyard-pando-lab.rs`、`experimental/pando/` | `tests/pando_lab.py`、`tests/test_track4_labs.py` |
| **Track 4B：Workspace 实验推进** | dirty-file manifest 增量同步、忽略规则、只读视图校验 | `src/workspace_lab.rs`、`src/workspace_lab/`、`src/bin/rootyard-workspace-lab.rs` | `tests/workspace.py`、`tests/test_track4_labs.py` |

### 2.2 第二梯队并行轨道（Phase 2）

| 轨道 | 负责范围 | 专属源码文件 / 目录 | 专属测试文件 |
| --- | --- | --- | --- |
| **Track A：外部 CI Webhook 与自动流水线** | Webhook 订阅、HMAC-SHA256 签名投递、退避重试/死信与 PR 同步自动创建 CI Source Pin / 待执行 Check Run | `src/webhooks.rs`、`src/webhooks/`（含 `040_webhooks.sql`） | `tests/webhooks.py`、`tests/test_webhooks.py` |
| **Track B：协作者、团队 5 级 RBAC 与审计日志** | 仓库协作者与团队 5 级角色鉴权、禁止 PR 作者自审、多人评审策略与游标分页 `/audit` API | `src/members.rs`、`src/members/`（含 `050_members_rbac.sql`）、`src/auth.rs` | `tests/members.py`、`tests/test_members.py` |
| **Track C：Pando 在线迁移与回滚状态机** | GitFS ↔ Pando 五步在线迁移状态机（`copy`/`verify`/`drain`/`fence`/`switchover`）与带新提交的安全回滚演练 | `src/pando_lab/migration.rs`、`src/pando_lab/rollback.rs`、`experimental/pando/schema.sql` | `tests/pando_lab.py`、`tests/test_pando_migration.py` |
| **Track D：Workspace 远程 CAS 与多仓虚拟 Namespace** | 远程 CAS 脏快照上传/恢复（`push-remote`/`pull-remote`）、多仓 `BaseVector` 虚拟 Namespace 与只读 Git View 投影 | `src/workspace_lab/remote.rs`、`src/workspace_lab/namespace.rs` | `tests/workspace.py`、`tests/test_workspace_remote_namespace.py` |

### 2.3 第三梯队并行轨道（Phase 3）

| 轨道 | 负责范围 | 专属源码文件 / 目录 | 专属测试文件 |
| --- | --- | --- | --- |
| **Track 1（M13）：服务端 HTML Web UI 与 XSS 防护** | 仓库概览、Tree/Blob 预览、Commits/Diff/Compare、Issues/PRs/Reviews/Checks/Merge 与 Audit 服务端 HTML 视图及 Markdown XSS 净化器 | `src/web.rs`、`src/web/`（`models.rs`、`sanitize.rs`、`templates.rs`、`handlers.rs`） | `tests/web.py`、`tests/test_web.py` |
| **Track 2（M14）：Pando S3 对象存储、多 Pack Repack 与网关路由** | S3 兼容远程对象存储 CAS 同步/校验、多 Pack 合并压缩（`repack`）及主站 `storage-route` 读写网关路由 | `src/pando_lab/object_store.rs`、`src/pando_lab/repack.rs`、`src/browse/handlers.rs` | `tests/pando_lab.py`、`tests/test_pando_repack_object_store.py` |
| **Track 3（M15）：Workspace 惰性稀疏 VFS 与按需水化** | 惰性稀疏 VFS 挂载（`vfs-mount`）、按需 CAS 水化（`vfs-hydrate`）、写时复制（CoW）脏追踪（`vfs-status`）与干净缓存淘汰（`vfs-evict`） | `src/workspace_lab/vfs.rs`、`src/workspace_lab.rs` | `tests/workspace.py`、`tests/test_workspace_vfs.py` |
| **Track 4（M16）：多节点仓库分片、Epoch 写屏障与故障切换** | 1024 虚拟分桶一致哈希路由、节点租约管理、`before_push` 跨节点脑裂写屏障、自动主从故障切换与只读降级演练 | `src/sharding.rs`、`src/sharding/`（`models.rs`、`router.rs`、`fencing.rs`、`failover.rs`、`060_sharding_fencing.sql`） | `tests/sharding.py`、`tests/test_sharding.py` |

### 2.4 第四梯队并行轨道（Phase 4）

| 轨道 | 负责范围 | 专属源码文件 / 目录 | 专属测试文件 |
| --- | --- | --- | --- |
| **Track 1（M18）：CI Mirror 单飞自动回源与跨集群 Runner 队列** | 缓存缺失时按 `(repository_id, target_oid)` 单飞合并自动回源拉取（`mirror-auto-fetch`）、跨集群 Runner 注册/心跳/租约过期重领作业队列（`mirror-runners`） | `src/mirror/auto_origin.rs`、`src/mirror.rs` | `tests/ci_mirror.py`、`tests/test_ci_mirror.py` |
| **Track 2（M19）：Pando 自动 Compaction 生命周期与 KMS 信封加密** | 碎片率驱动后台自动 Compaction 评估（`lifecycle-evaluate`）、冷数据本地驱逐与按需透明回源水化、KMS/SSE-C 信封加密与无停机密钥轮转（`kms-rotate`） | `src/pando_lab/lifecycle.rs`、`src/pando_lab/mod.rs`、`src/pando_lab/http.rs`、`experimental/pando/schema.sql` | `tests/test_pando_repack_object_store.py` |
| **Track 3（M20）：Workspace 可写虚拟 Namespace 与多 Agent 路径租约** | 多 Agent 路径前缀排他租约锁（`agent-lease`）、可写虚拟 Namespace 反向路径映射（`namespace-write`）与跨仓两阶段原子回写（`namespace-commit-back`） | `src/workspace_lab/writable_view.rs`、`src/workspace_lab.rs` | `tests/workspace.py`、`tests/test_workspace_remote_namespace.py` |
| **Track 4（M21）：多节点分片在线重平衡与 RPO/RTO 灾备演练** | 四阶段在线虚拟桶/仓库重平衡迁移（`drain` → `sync` → `fence` → `cutover`，`/api/shards/rebalance`）、实测 RPO/RTO 灾备切换演练与 SLA 门禁（`/api/repos/{owner}/{name}/shard-dr-drill`） | `src/sharding/rebalance.rs`、`src/sharding.rs` | `tests/sharding.py`、`tests/test_sharding.py` |

### 2.5 第五梯队并行轨道（Phase 5 / Tier 5）

| 轨道 | 负责范围 | 专属源码文件 / 目录 | 专属测试文件 |
| --- | --- | --- | --- |
| **Track 1（M23 / M24）：`view_lab` 模块化解耦、长周期历史投影策略与签名溯源验签** | `src/view_lab.rs`（`< 120` 行门面）与 4 个子模块拆分、`deterministic_history` vs `task_snapshot` 增量 Epoch DAG 投影（`project-history`）、源提交 GPG/SSH 签名识别与平台 HMAC-SHA256 溯源签名验签（`verify-view`） | `src/view_lab.rs`、`src/view_lab/`（`models.rs`、`namespace.rs`、`projection.rs`、`changeset.rs`）、`docs/git-view-foundation.md` | `tests/git_views.py`、`tests/test_view_lab.py` |
| **Track 2（M25）：Git SHA-256 双对象格式探测与 Smart HTTP v1/v2 协议能力协商** | `object-format=sha256` 仓库探测、SHA-1（40 位）/ SHA-256（64 位）双哈希与 Pack 尾部校验、Smart HTTP v1/v2 `object-format` 能力协商、跨格式推送/拉取拦截（`409 Conflict`）与兼容矩阵演练 | `src/browse/object_format.rs`、`src/browse.rs`、`src/pando_lab/object_format.rs`、`src/pando_lab/mod.rs`、`src/pando_lab/http.rs` | `tests/browse.py`、`tests/pando_lab.py`、`tests/test_browse_lfs.py`、`tests/test_object_format.py` |
| **Track 3（M26）：多节点 1/2/4 节点并发压测、保留根可达性核验与 P50/P95/P99 遥测基准** | 1/2/4 节点并发 `push`/`fetch`/`GC`/缓存淘汰/故障切换压测、CI 保留根（`refs/rootyard-ci/jobs/*`）可达性校验、P50/P95/P99 延迟与 `/proc/self` 资源遥测及 JSON + Markdown 基准报告 | `src/sharding/benchmark.rs`、`src/sharding.rs` | `tests/benchmark_tiers.py`、`tests/test_benchmark_tiers.py`、`tests/sharding.py`、`tests/test_sharding.py` |
| **Track 4（M27）：Workspace 虚拟挂载 CoW Overlay 沙箱与断电崩溃窗口 WAL 恢复演练** | 只读下层 + 可写上层 + Whiteout 墓碑 CoW Overlay 沙箱（跨层目录 `rename`、`chmod`、`git add -f` 忽略覆盖、多 Agent 隔离）与断电崩溃窗口（`before_wal_fsync` / `after_wal_before_publish` / `after_publish_before_ack`）WAL 恢复对账 | `src/workspace_lab/crash_recovery.rs`、`src/workspace_lab.rs`、`docs/workspace-foundation.md` | `tests/workspace.py`、`tests/test_workspace_crash_recovery.py`、`tests/test_workspace_vfs.py` |

---

## 3. 共享底座接口契约

### 3.1 领域自包含路由（`pub fn routes()`）

`src/lib.rs` 中的 `router()` 仅通过 `.merge(<domain>::routes())` 组装各领域路由：

- `browse::routes()`（`src/browse.rs`）
- `ci_pins::routes()`（`src/ci_pins.rs`）
- `ci_checkouts::routes()`（`src/ci_checkouts.rs`）
- `reliability::routes()`（`src/reliability.rs`）
- `forge::routes()`（`src/forge.rs`）
- `pulls::routes()`（`src/pulls.rs`）
- `lfs::routes()`（`src/lfs.rs`）
- `webhooks::routes()`（`src/webhooks.rs`）
- `members::routes()`（`src/members.rs`）
- `web::routes()`（`src/web.rs`）
- `sharding::routes()`（`src/sharding.rs`）

各轨道在自身模块内新增 HTTP 端点时，**直接挂载到本模块的 `pub fn routes() -> Router<Arc<AppState>>` 中，无需在 `src/lib.rs` 中内联业务路由**。

### 3.2 事务级仓库鉴权与幂等键辅助函数（`src/auth.rs`）

新增 HTTP JSON API（如 `src/pulls.rs`、`src/browse.rs`、`src/lfs.rs`、`src/webhooks.rs`、`src/members.rs`、`src/web.rs`、`src/sharding.rs`）应直接复用 `crate::auth` 导出的公共函数，避免重复编写 SQL 锁顺序：

- `auth::authorize_repo_with_role(&tx, &actor, &owner_name, &repo_name, min_role, action)`：在单个 `READ COMMITTED` 事务内校验仓库 5 级角色权限（`Role::Read`、`Role::Triage`、`Role::Write`、`Role::Maintain`、`Role::Admin`），再用显式 `token_scopes::RepoAction` 收窄 PAT 作用域，返回 `RepoAccess`。`action` 决定 `read_only` 判定（读取动作不被只读令牌误拒）。
- `auth::verify_active(&pool, &actor, repo_id, action, min_role)` / `auth::verify_repo_write_access(..., browser, action)`：事务外查询已解析仓库时使用，二者同样叠加 `RepoAction` 作用域检查。`verify_repo_write_access` 只接受裸 `GenericClient`，其 `FOR SHARE` 仅在本语句内有效，Git CAS 期间的父令牌锁仍未实现。
- `auth::verify_token(&mut tx, &headers, write)`：只校验令牌而不锁定特定仓库行。
- `auth::finish_tx(tx, &actor, write)`：显式提交事务后返回响应，保证读/写事务不会隐式回滚。
- `auth::idempotency_key(&headers)`：校验并提取 `Idempotency-Key` 请求头（拒绝空值、首尾空白、控制字符或超 128 字节的值）。

### 3.3 Outbox 消费者注册表（`src/events.rs`）

内部事务型消费者列表由 `crate::events::CONSUMERS` 单点定义，`src/dispatch.rs` 与 `src/events.rs` 均引用该常量。若某条轨道无需新增后台消费者，切勿触碰 `src/events.rs`。

---

## 4. 数据库迁移编号分段与 Schema 基线约定

### 4.1 预留迁移编号区间

为避免不同轨道使用相同的迁移版本号，按领域预留以下编号区间：

- `001` – `008`：已冻结的基线迁移（禁止修改历史 SQL 文件）。
- `009` – `019`：**Track 1（Forge / PR / Review / Check Run / Branch Rule）** 预留区间。
- `020` – `029`：**Track 2（Browse / Git LFS 元数据）** 预留区间。
- `030` – `039`：**Track 3（CI Mirror / Runner 调度扩展）** 预留区间。
- `040` – `049`：**Track A（外部 CI Webhook 订阅、投递与回调）** 预留区间（`src/webhooks/040_webhooks.sql`）。
- `050` – `059`：**Track B（仓库协作者、团队 5 级 RBAC 与审计日志）** 预留区间（`src/members/050_members_rbac.sql`）。
- `060` – `069`：**Tier 3 Track 4（多节点仓库分片、一致哈希路由与 Epoch 写屏障）** 预留区间（`src/sharding/060_sharding_fencing.sql`）。

> **建议**：日常并行开发期间，各轨道优先在自身提交历史末尾维护新迁移；需要合入主干并升级配对备份契约时，按以下步骤单点更新基线。

### 4.2 更新 Schema 基线的标准步骤

当某个分支新增 `migrations/NNN_<name>.sql` 并准备合入时：

1. 在 `src/db.rs` 的 `MIGRATIONS` 与 `SCHEMA_VERSIONS` 常量末尾追加新版本号（`src/backup.rs` 会自动读取 `crate::db::SCHEMA_VERSIONS`）。
2. 若新增了 `public` 表，在 `src/backup.rs` 的 `TABLES` 数组中登记表名及其外键父表锁定顺序。
3. 将 `schema/<prev>_catalog.sql` 复制为 `schema/NNN_catalog.sql`（若新增了自定义 SQL 函数，将其函数名加入 `proname` 列表），然后运行：
   ```bash
   python3 tests/schema_contract.py --sql-migrate --write
   ```
   生成 `schema/NNN_catalog.json`、`schema/NNN_restored_catalog.json` 与 `schema/NNN_upgraded_catalog.json`，并在 `src/backup.rs` 的 `SCHEMA_CONTRACT_CATALOGS` 中指向新文件名。
4. **无需手动修改其余 Python 测试脚本中的版本号或表数量**：`tests/schema_baseline.py` 会自动从 `migrations/` 和 `schema/` 推导 `SCHEMA_VERSIONS`、`SCHEMA_VERSION_CSV`、`EXPECTED_TABLES` 与 `TABLE_COUNT`。

---

## 5. 本地快速自检命令

在无需启动 PostgreSQL 的环境下，可随时运行以下静态契约检查，验证文档摘要、链接完整性以及模块/Schema 边界同步：

```bash
python3 scripts/check_design_docs.py
python3 -m unittest discover -s tests -p 'test_*.py'
```
