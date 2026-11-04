# Git 存储事务与协议契约

> 状态：目标设计；SQL 为设计草案，不是当前 migrations。proc-receive 已有独立实验，未切换默认后端。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# 十一 可开工详细设计

以下章节将前面的建议具体化为首版工程契约。数据库、Redis 和对象存储均不绑定供应商。存储内核的 proc-receive 路径是待验证原型，不保证成熟 Git 后端可无修改直接用于数据库权威 refs；第一阶段优先在持久卷使用成熟 Git，待兼容性和故障注入通过后再切换。

# Git 存储、事务与协议实现方案

## 1. 本章决策与前提

这是面向 Rust 模块化单体的首期实现设计，不绑定特定云数据库或对象存储厂商。三个基础设施角色严格分开：

- 事务数据库：仓库配置、权限、refs、对象 manifest、操作状态、审计与 outbox 的唯一权威来源。

- 对象存储：不可变 Git pack、idx 和可选辅助索引；不是 ref 数据库。

- Redis：缓存、限流、任务唤醒、减少重复工作；丢失全部数据或锁过期不能造成错误提交。

数据库必须提供原子事务、唯一约束、行锁或等价的可靠条件写。下文 SQL 是接近 PostgreSQL 语法的伪代码，不代表选择某个托管产品。对象存储适配器必须满足不可变对象写入、完成写后的持久性确认、按键读取及读后写一致性。仅一次 HEAD 成功不能替代供应商的一致性契约；不满足这些能力的存储不能直接接入发布路径。

首期选择标准 Git Smart HTTP，固定并维护服务端 Git 版本。fetch 使用 git-upload-pack；push 使用 git-receive-pack 的 proc-receive 接口把全部受管 refs 的更新交给 Rust 事务服务。Git 原生 quarantine、pack 解析和协议编码继续复用 Git。不用 post-receive 进行数据库补写，因为客户端看到成功以前必须完成权威事务。proc-receive 的接口允许外部程序负责引用更新并报告结果。[Git hooks 文档](https://git-scm.com/docs/githooks)

首期只创建 SHA-1 仓库以简化兼容矩阵，但 schema 和内部 ObjectId 枚举预留 SHA-256；仓库 object_format 创建后不可修改。不宣称 SHA-1 与 SHA-256 仓库可直接互推。标准对象格式支持与兼容限制以固定 Git 版本的集成测试为准。[Git index-pack 文档](https://git-scm.com/docs/git-index-pack)

## 2. 必须成立的系统不变量

I1. 每个已提交且可见的 ref，其目标对象及完整 Git 依赖闭包都能从同一仓库的已发布 manifest 读取。gitlink 指向的子模块提交属于另一仓库，不要求在本仓库对象库存在。

I2. 新 manifest 指针、refs 变化、ref 历史、操作最终结果和 outbox 在同一个数据库事务里提交。

I3. pack 和 idx 的完整上传、校验及存储持久性确认必须先于 I2。允许上传后未引用的孤儿包，不允许先提交 ref 再异步上传对象。

I4. 所有 ref 写入，包括 Git push、网页编辑、Agent 提交、合并、管理员修复，必须经过同一个 RefTransactionService；没有绕过 CAS 的快速通道。

I5. Redis、某个进程内存和某台机器的裸仓库都不是权威状态。缓存失效只影响延迟或可用性，不改变正确结果。

I6. 已发布 pack 不原地覆盖。任何读者使用的 pack 集合在其有效 pin 生命周期内不得被物理删除。

I7. 对象存在不等于有权读取。授权基于仓库与可见 ref；不能凭猜中的 OID 获取其他仓库内容。首期不把 monorepo 路径过滤当作读取权限边界。

I8. 对外报告 push 成功只能发生在数据库提交被确认之后。提交结果未知时先查询操作记录，不能自动宣布失败或回滚。

## 3. 数据模型

建议至少保留以下逻辑表。OID 使用二进制并由 object_format 决定长度，API 使用规范化小写十六进制。ref_name 使用大小写敏感、二进制排序规则；禁止数据库自动大小写折叠或 Unicode 归一化。

```sql
repositories (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  object_format TEXT NOT NULL,           -- sha1 / sha256
  default_branch_ref TEXT NOT NULL,      -- HEAD 的 symbolic target，可 unborn
  current_manifest_id UUID NOT NULL,
  manifest_generation BIGINT NOT NULL,
  object_epoch BIGINT NOT NULL,          -- 仅在对象集合可能减少时递增
  refs_epoch BIGINT NOT NULL,
  roots_epoch BIGINT NOT NULL,           -- GC retention roots 变化时递增
  policy_epoch BIGINT NOT NULL,
  lifecycle TEXT NOT NULL                -- active / read_only / deleting
);

-- 分布式 PG refs 模式新增的仓库所有权行；领取、续租、接管和发布遵守相同锁顺序。
repo_owners (
  repo_id UUID PRIMARY KEY,
  owner_id UUID NOT NULL,
  epoch BIGINT NOT NULL,
  lease_until TIMESTAMP NOT NULL
);

refs (
  repo_id UUID NOT NULL,
  ref_name TEXT NOT NULL,
  oid BYTES NULL,                        -- NULL = 已删除 tombstone
  version BIGINT NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY (repo_id, ref_name)
);

operations (
  id UUID PRIMARY KEY,
  repo_id UUID NOT NULL,
  actor_id UUID NOT NULL,
  idempotency_key TEXT NULL,
  request_digest BYTES NOT NULL,
  state TEXT NOT NULL,
  owner_fence BIGINT NOT NULL,
  lease_until TIMESTAMP NULL,
  validated_object_epoch BIGINT NULL,
  validated_policy_epoch BIGINT NULL,
  result_json JSON NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE (repo_id, actor_id, idempotency_key)
);

packs (
  repo_id UUID NOT NULL,
  id UUID NOT NULL,
  pack_key TEXT NOT NULL,
  idx_key TEXT NOT NULL,
  pack_sha256 BYTES NOT NULL,
  idx_sha256 BYTES NOT NULL,
  pack_bytes BIGINT NOT NULL,
  idx_bytes BIGINT NOT NULL,
  object_count BIGINT NOT NULL,
  state TEXT NOT NULL,                   -- uploading / ready / deleting / deleted
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (repo_id, id),
  UNIQUE (pack_key), UNIQUE (idx_key)
);

manifests (
  repo_id UUID NOT NULL,
  id UUID NOT NULL,
  generation BIGINT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (repo_id, id),
  UNIQUE (repo_id, generation)
);

manifest_packs (
  repo_id UUID NOT NULL,
  manifest_id UUID NOT NULL,
  pack_id UUID NOT NULL,
  PRIMARY KEY (repo_id, manifest_id, pack_id),
  FOREIGN KEY (repo_id, manifest_id) REFERENCES manifests(repo_id, id),
  FOREIGN KEY (repo_id, pack_id) REFERENCES packs(repo_id, id)
);

operation_packs (
  repo_id UUID NOT NULL,
  operation_id UUID NOT NULL,
  pack_id UUID NOT NULL,
  PRIMARY KEY (repo_id, operation_id, pack_id)
);

ref_events (
  repo_id UUID NOT NULL,
  seq BIGINT NOT NULL,
  operation_id UUID NOT NULL,
  ref_name TEXT NOT NULL,
  old_oid BYTES NULL,
  new_oid BYTES NULL,
  old_version BIGINT NOT NULL,
  new_version BIGINT NOT NULL,
  actor_id UUID NOT NULL,
  reason TEXT NOT NULL,
  retain_objects_until TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (repo_id, seq)
);

manifest_pins (
  id UUID PRIMARY KEY,
  repo_id UUID NOT NULL,
  manifest_id UUID NOT NULL,
  purpose TEXT NOT NULL,                 -- fetch / push_validation / gc / backup
  owner_id UUID NOT NULL,
  owner_fence BIGINT NOT NULL,
  expires_at TIMESTAMP NULL              -- backup pin 可由备份策略显式释放
);

outbox (
  id UUID PRIMARY KEY,
  repo_id UUID NOT NULL,
  operation_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  payload_json JSON NOT NULL,
  state TEXT NOT NULL,
  available_at TIMESTAMP NOT NULL,
  attempts INTEGER NOT NULL,
  UNIQUE (operation_id, event_type)
);
```

补充约束：所有关联写入都检查相同 repo_id；实际迁移应补齐 operation、repo 和 actor 的外键。ref_name 需通过 Git 规则校验，并额外限制产品支持的命名空间。首期公开写入 refs/heads/* 和 refs/tags/*；refs/platform/* 由内部服务管理。live refs 必须检查 `foo` 与 `foo/bar` 的目录/文件冲突，不能只靠完整名称唯一约束。持有仓库行锁时完成该检查，避免并发创建绕过。

refs 删除保留 tombstone，因此 API 的 ref version 可以发现删除再创建。原生 Git 只提供 old OID，不提供 version：A→B→A 后 old=A 的 push 可以成功，这是 Git 的 OID CAS 语义，不应宣称它具有额外的 ABA 防护。原生 old/new 的全零 OID 在服务内统一映射为“引用不存在/删除”。[Git update-ref 文档](https://git-scm.com/docs/git-update-ref)

不把每一个 blob 都写成数据库行。Git .idx 是 pack 内 OID 查找的基础；commit 元信息、目录树缓存、搜索索引均可重建，且不得成为对象持久性的唯一证明。首期 manifest_packs 保存完整集合，发布时复制旧集合再加入新包；随着 pack 数增长需测量写放大，再升级为分层清单或增量链，不提前宣称无限扩展。

## 4. 对象命名与存储适配器

对象键示例：

```
repos/<repo_uuid>/packs/<pack_uuid>/<content_sha256>.pack
repos/<repo_uuid>/packs/<pack_uuid>/<content_sha256>.idx
```

pack_uuid 保证被删除的物理键不被后来的上传复用，避免“旧 GC 删除请求删掉新复活对象”。业务 OID、Git pack checksum、存储传输 SHA-256 是不同概念，不混用。不能把对象存储 ETag 当作通用内容摘要。

接口至少包含 `put_immutable`、`complete_multipart`、`get`、`head_metadata`、`delete_idempotent`、`abort_multipart`。put 返回字节数、独立内容摘要、存储版本标识（若支持）及持久性确认。上传流计算 SHA-256；下载首次落盘校验；关键发布包通过完整回读或供应商支持的端到端校验验证。索引也独立校验，并确认它匹配 pack。

永久保存的 pack 必须解决包外 delta base 依赖；thin pack 可作为传输格式，但入库前必须补齐 delta base。这里的“pack 自包含”只针对 delta 重建，不代表 commit 的所有祖先都必须在同一个包内。[Git pack 格式](https://git-scm.com/docs/gitformat-pack)

## 5. Push 与对象发布状态机

操作状态：`receiving → validating → ready → committed`；失败进入 `rejected` 或 `aborted`。操作接管递增 operation owner_fence；仓库接管还需独立的 repo owner epoch。所有发布路径必须在权威事务中校验两者并遵守统一锁协议，具体保证边界见分布式预研。

1. 验证 HTTPS 身份、仓库存在和初始写权限；建立 operation，配额与请求上限检查先于大体积接收。

2. 在短数据库事务里锁 repository 行，读取 refs + current_manifest + object_epoch + policy_epoch，插入验证 pin，然后立即释放锁。

3. 构造只属于此请求的 bare repo 视图：固定 HEAD、固定 refs、只读 pack cache。Git 进程没有宿主 shell、任意 hook、外部网络或跨仓库 alternates 权限。

4. 流式接收并让 Git quarantine 验证；固定配置包括 receive.fsckObjects=true、receive.unpackLimit=0、receive.autogc=false 和覆盖所有受管 refs 的 receive.procReceiveRefs=refs/。限制请求字节、展开后资源、对象个数、处理时长和并行子进程。具体数值以测试和容量预算确定。

5. proc-receive 把已解析的命令集交给 Rust。不得返回 fall-through；未知或内部命名空间拒绝。按分支保护、权限、对象类型、fast-forward 与连通性验证。refs/heads/* 必须指向 commit；tag 按 Git 规则处理。

6. 将本次新增且已经规范化的 pack/idx 上传到不可变键。新对象可以引用同一仓库已发布的历史对象；必须验证新 tips 的闭包在“固定 base manifest + 新 pack”中完整。

7. 所有 pack READY 后执行第 6 节发布事务。事务中再次检查授权、策略版本、CAS 和 object_epoch。

8. 只有 COMMIT 被确认后，proc-receive 才对对应 ref 返回 ok；outbox 异步触发索引、webhook 和缓存失效。post-receive 不承担提交职责。

Quarantine 中的对象不应提前被可见 ref 引用，Git 自身也明确禁止 pre-receive 直接更新引用到这些对象。[Git receive-pack 文档](https://git-scm.com/docs/git-receive-pack)

必须先做 proc-receive 适配器工程验证：覆盖普通更新、创建、删除、仅删 ref、atomic push、非 atomic 部分失败、协议状态回传、网络断开，以及 Git 进程在数据库提交前后退出。此验证是发布门槛，不能只因 hook 存在就宣称数据库桥接已经实现。

## 6. Ref CAS 与数据库原子发布

首期以 repository 行锁串行化同一仓库的“最终提交窗口”；pack 接收、上传、对象检查均在锁外并行。不同仓库互不阻塞。这样先获得明确正确性，再依据锁等待数据决定是否细化，不预先承诺吞吐数字。

object_epoch 的作用：普通 push 只给 manifest 增加 pack，不递增它，因此多个并行验证可以在最终提交时把自己的 pack 加入最新 manifest。只有 GC/破坏性替换可能删对象时才递增。若验证期间 object_epoch 改变，退出事务，基于新 manifest 重新做连通性验证，不能直接复用旧结果。

```sql
BEGIN;

repo = SELECT * FROM repositories WHERE id = :repo_id FOR UPDATE;
owner = SELECT * FROM repo_owners WHERE repo_id = :repo_id FOR UPDATE;
op   = SELECT * FROM operations WHERE id = :operation_id FOR UPDATE;
checked_at = clock_timestamp(); -- 所有相关锁获取后取实际数据库时间

ASSERT op.repo_id = repo.id;
ASSERT op.request_digest = :request_digest;
IF op.state = 'committed' THEN RETURN op.result_json; END IF;
ASSERT op.state = 'ready';
ASSERT owner.epoch = :repo_owner_epoch AND owner.lease_until > checked_at;
ASSERT op.owner_fence = :operation_owner_fence AND op.lease_until > checked_at;
ASSERT repo.lifecycle = 'active';
ASSERT current_authorization_allows(:actor_id, :command_set);
ASSERT repo.policy_epoch = op.validated_policy_epoch;
ASSERT repo.object_epoch = op.validated_object_epoch;
ASSERT every_operation_pack_has_state('ready');

-- 全部 ref 命令排序处理；重复 ref 在进入事务前拒绝。
FOR cmd IN commands ORDER BY ref_name:
  current = SELECT * FROM refs
            WHERE repo_id = :repo_id AND ref_name = cmd.name;
  ASSERT normalized_oid(current.oid) = cmd.expected_old_oid;
  IF cmd.expected_version IS NOT NULL:
    ASSERT current.version = cmd.expected_version;
  END IF;
  ASSERT namespace_and_prefix_conflicts_absent(cmd);
END FOR;

new_manifest = create_manifest(repo.manifest_generation + 1);
INSERT INTO manifest_packs
  SELECT :repo_id, new_manifest.id, pack_id
  FROM manifest_packs
  WHERE repo_id = :repo_id AND manifest_id = repo.current_manifest_id;
INSERT INTO manifest_packs ... SELECT operation_pack_ids ...;
-- 若没有新 pack，可复用 current_manifest，不必制造空的新代。

FOR cmd IN accepted_commands:
  UPSERT refs (..., oid=cmd.new_oid, version=previous_version+1, ...);
  INSERT INTO ref_events (... old_oid, new_oid, actor_id, operation_id ...);
END FOR;

UPDATE repositories SET
  current_manifest_id = new_manifest.id,
  manifest_generation = new_manifest.generation,
  refs_epoch = refs_epoch + 1,
  roots_epoch = roots_epoch + 1
WHERE id = :repo_id;
UPDATE operations SET state='committed', result_json=:final_result
WHERE id=:operation_id AND owner_fence=:operation_owner_fence;
INSERT INTO outbox (..., event_type='refs.updated', ...);
COMMIT;
```

上例展示 atomic=true 路径。原生客户端协商 atomic 时任意 ref 错误都不提交；未请求 atomic 时应逐条保留失败原因，将通过检查的命令作为一个 accepted subset 原子提交，并准确返回逐 ref 状态。全局权限、非法 pack 或系统故障仍可拒绝整次 push。对 REST/Agent 的批量 ref API 默认且首期仅支持 atomic=true。[Git pack 协议](https://git-scm.com/docs/gitprotocol-pack)

保护规则依赖的测试结果必须绑定确切 commit OID（必要时包含目标分支版本），而不是“这个分支曾经绿过”。权限撤销和 policy 更新要与发布事务有可证明的顺序：采用共同的仓库写锁或一致锁顺序读取当前授权记录。只检查请求入口的缓存权限不足以防止长 push 期间撤权后仍发布。

死锁/序列化错误允许重试最终数据库事务，但每次重新读 refs、policy 与 operation。旧 OID 不匹配是业务冲突，不自动把新提交强推过去。CAS 返回当前值以便 Agent fetch/rebase/merge 后产生新的操作。

## 7. Fetch、一致性与缓存

一次 RPC 内创建读取快照：锁 repository 行 → 读取 current_manifest 和 refs → 插入 manifest pin → 提交。锁持有期间不下载对象、不运行 Git。随后按 manifest 组装只读裸仓库视图，由 git-upload-pack 协商并生成响应。Git 依赖普通文件 ODB，所以首期采用本地不可变 pack cache；不把对象存储 URL 冒充本地文件。

冷请求可能需要下载许多 pack；首期如选择完整物化必须明确承认冷 clone 成本，不承诺常数级访问。局部对象访问、MIDX/bitmap 优化、按需读取层在基线正确后另做设计与基准。

pin 有效期内不能删除其 manifest 的 pack。worker 定期续租，续租失败后在租约到期前停止新的远端读取并中止请求；不能继续依赖已失效 pin。若已完整物化并持有本地 cache 引用计数，可在释放远端 pin 后继续服务本地文件。临时网络失败可能使 fetch 失败，但不得导致静默返回错误对象。

HTTP 的发现 refs、ls-refs、协商与 pack 响应可能属于不同请求。逐请求重新物化最新快照存在竞态：已在实验中复现发现后 ref 删除导致 clone 失败。候选方案包括固定整个读取会话的授权快照或确保旧 want 在约定保留期内可读；短期只读快照 URL 已在 Git 2.56 原型中验证，生产权限、TTL、对象 pin、代理和多客户端兼容仍待验证。每次 RPC 必须重新授权，不依赖 cookie 或粘性会话。[Git HTTP 协议](https://git-scm.com/docs/gitprotocol-http)

缓存键至少包含 repo_id、manifest_id 或 refs_epoch、object_format，以及必要的权限视图标识。Redis refs cache 不能自行决定最新引用；从数据库读取版本后再命中版本化内容。POST Git RPC 设置禁止响应缓存。只向客户端声明实际通过兼容测试的 capabilities；fetch v2 的 ls-refs 与 fetch 可由固定 Git 版本处理，push 不应被笼统描述成“所有命令都是 protocol v2”。[Git protocol v2](https://git-scm.com/docs/gitprotocol-v2)

私有仓库不直接发物理 pack 的预签名下载链接，因为包内可能包含本次请求不应返回的对象。标准协商响应由授权网关输出。禁止客户端任意 OID 读取其他仓库，禁用允许任意对象 want 的宽松配置。隐藏 ref 不是独立秘密分区；需要强隔离的数据必须分仓库/分权限边界。

## 8. 并发情形的确定行为

- 两个 Agent 从同一 main=A 推到 B/C：一个 CAS 成功，另一个收到当前 OID 的冲突；对象上传可以均完成，失败者对象成为可回收候选。

- 两个 Agent 推到不同任务分支：接收与校验并行，最终提交短暂排队；第二个事务把自身 pack 加到第一个事务后的最新 manifest，不能覆盖丢失前者清单。

- push 与 GC 重叠：GC 替换对象集合会递增 object_epoch；旧验证结果必须重验。GC 自身也必须比较其起始 snapshot 版本。

- lock TTL 过期或 Redis 重启：允许重复 worker 被唤醒；数据库 fence、operation 状态和 CAS 保证仅一个结果生效。

- 主分支合并：读取 expected target OID、生成 merge/rebase 结果、检查后通过同一个 CAS；若 target 变化重新计算，不将过时测试结果套到新 merge commit。

- 客户端超时但 DB 已提交：保留 committed 结果；API 使用同一个幂等键读取原结果。原生 Git 无通用幂等键，客户端通过重新发现远端 refs 判断，不能宣称跨网络 exactly-once。

## 9. 故障恢复矩阵

1. 接收未完进程退出：没有可见 ref；operation 接管后可恢复完整输入，否则 aborted；删除临时目录并中止残留 multipart。

2. pack 上传完成、idx 未完成：不可 READY，不得发布；重试相同操作的未完成部分或终止，最终回收孤儿。

3. pack/idx READY、数据库事务未开始：可按 fence 重新接管并重验；未提交前用户不可见。

4. DB 回滚：refs 与 manifest 都保持旧值；新对象留作受控孤儿，不在错误路径里立即删除以免与重试竞态。

5. COMMIT 请求超时：使用新连接查询 operation；committed 则返回原结果；数据库不可读时报告结果未知。不要把“不知道”映射为“没有执行”。

6. 提交成功、响应丢失：状态仍 committed；API 重试按幂等键返回结果，Git 重新发现 ref。

7. 提交成功、Redis/outbox 消费失败：核心 Git 读写仍使用 DB 权威状态；outbox 按至少一次投递，消费者按 event_id 去重。不能以 webhook 已发送作为提交成功标准。

8. 已发布 pack 丢失/校验失败：立即隔离该副本，尝试副本或备份恢复；不能拿旧 ref 或空数据冒充成功。不具备恢复来源时将受影响仓库设只读并明确数据不可用，防止扩大损害。

operation、outbox 与 GC 任务都使用有上限退避与可观测的重试状态。有限重试失败进入待处理状态，不静默丢弃。系统性损坏需要告警与人工处置，不承诺任何故障都能自动恢复。

## 10. GC 与 pack 合并

把 GC 分成三个独立任务：未完成上传清理、未引用 pack 回收、可达对象重打包。

A. 上传清理：只有 operation 已终止或租约过期并被数据库正式 fencing、且 pack 不被任何受保护 manifest 引用，才能在短事务中置 packs.state=deleting。发布事务只接受 ready，所以从此不可再发布该包。事务提交后删除对象；404 视为幂等成功，最后置 deleted。

B. 重打包：取得并 pin 一组稳定根，包含当前所有 live refs、内部 PR/任务 refs、仍在保留期的 ref_events、未完成发布所依赖的 manifest，以及备份保留要求。审计历史的保留时长不自动等于 Git 对象保留时长，需分别定义。

C. 在锁外遍历这些根、构建新的 self-contained pack/idx、验证、上传。记录起始 current_manifest_id、refs_epoch、roots_epoch 和 object_epoch。

D. 获取 repository 行锁，确认上述版本仍一致、所有新包 READY、根闭包仍被完整覆盖，原子切换 current_manifest 到新集合并递增 object_epoch。若任意版本变化，保留旧状态，重新规划或重新构建；不得盲目替换。持续写入造成重试时先延后 GC，必要的维护写入窗口必须成为明确运维策略，而不是偷偷阻塞所有写入。

E. 旧 manifest 在不再是 current、没有有效 reader/push/backup pin 且过了配置的安全宽限期后才可退休。某 pack 只有不属于任何受保护 manifest 时才可置 deleting 并物理删。新 pin 只能在检查 manifest 可 pin 状态的同一事务内创建，不能事后复活已进入删除流程的旧 manifest。

F. 物理删除采用持久化 delete job；对象删除成功但 DB 更新失败时可重试。不得用“对象键年龄大于 N 天”直接删正式对象。对象存储 lifecycle 规则只用于独立临时前缀和未完成 multipart，不能扫正式 pack 前缀。

恢复备份需要同时具备数据库的一致恢复点及其引用对象。仅做数据库 PITR、却允许 GC 删除旧时间点需要的 pack，不构成可恢复备份。备份清单必须持有 object retention pin，定期在隔离环境真实恢复并 clone/fsck 验证。

## 11. 对外与内部 API 合约

标准 Git：

- GET /git/{owner}/{repo}.git/info/refs?service=git-upload-pack

- GET /git/{owner}/{repo}.git/info/refs?service=git-receive-pack

- POST /git/{owner}/{repo}.git/git-upload-pack

- POST /git/{owner}/{repo}.git/git-receive-pack

使用 Git 规定的 Content-Type 和 pkt-line/report-status，不能用 JSON 包装 Git 响应。认证失败等传输问题用 HTTP 状态；ref 冲突、保护规则失败等使用 Git 协议里的 ng 状态。只允许白名单 service，不能将 URL 参数直接拼接为 shell 命令。

应用 API：

- GET /api/v1/repos/{repo_id}/refs：返回 name、oid、version、refsEpoch；支持游标，要求一致分页时使用明确快照 token。

- GET /api/v1/repos/{repo_id}/operations/{operation_id}：返回 receiving/validating/ready/committed/rejected/aborted、逐 ref 结果和可安全公开的错误码。

- POST /api/v1/repos/{repo_id}/ref-transactions：必需 Idempotency-Key；原子更新已存在且授权对象的引用。新对象必须先经同一受控 ingestion 管线。

```json
{
  "atomic": true,
  "updates": [
    {
      "ref": "refs/heads/agent/task-123",
      "expectedOldOid": "<full-oid-or-null>",
      "expectedVersion": 7,
      "newOid": "<full-oid-or-null>"
    }
  ]
}
```

expectedOldOid 字段必须存在，JSON null 表示当前不存在；newOid=null 表示删除。省略期待值不代表允许无条件覆盖。创建从未存在的引用可使用 expectedVersion=0；删除后的 tombstone 版本由查询 API 返回。force 只表示放宽被授权的非 fast-forward 策略，不绕过 CAS。

- POST /api/v1/repos/{repo_id}/commits：网页/Agent 修改文件的便利入口，包含 expected branch OID/version、精确文件变化及提交元信息；生成标准 Git 对象后复用 ingestion + ref transaction，绝不独立维护另一套源码历史。

错误体建议包含 code、operationId、retryable、ref 和 currentOid/currentVersion（只有已授权用户可见）。409 REF_CONFLICT、409 IDEMPOTENCY_KEY_REUSED、403 POLICY_DENIED、413 PACK_TOO_LARGE、422 INVALID_OBJECT_GRAPH、503 STORAGE_UNAVAILABLE。未知提交结果用明确的 OPERATION_OUTCOME_UNKNOWN 和查询入口，避免诱导客户端换幂等键盲重发。

幂等键的 scope=(repo, actor, key)。同 key 同 canonical request_digest 返回原结果；同 key 不同内容返回 409；operation 最终结果及 digest 的保留窗口必须写进 API 契约，过期后不承诺永久幂等。

## 12. Rust 模块与适配器边界

建议 crate/module 边界：

- git_transport：Smart HTTP、认证上下文、Git 子进程与 proc-receive pkt-line。

- git_objects：ObjectId、pack 校验、对象闭包与类型检查、bare snapshot 物化。

- ref_service：CAS、分支保护、atomic/partial 策略、唯一发布入口。

- repository_store：SQL 事务、manifest、ref_events、operation、pins。

- object_store：通用不可变存储接口及供应商适配器。

- maintenance：GC、repack、恢复检查、outbox worker。

- application：Agent 提交、网页编辑和合并，通过上述领域接口调用。

关键内部类型为 VerifiedPack、ValidatedPush、PinnedManifest、RefUpdate、CommitOutcome。VerifiedPack 只能由成功的验证/持久上传流程创建；ValidatedPush 携带 base object_epoch 与 policy_epoch。类型能减少误用，不能替代数据库事务里的再验证。

进程调用使用参数数组，不执行拼接 shell。禁用外部 filter、textconv、任意用户 hooks、意外配置继承和跨仓库 alternates；Git 二进制纳入漏洞更新与兼容回归。stderr 日志不要泄露认证信息或未授权文件内容。

## 13. 必须自动化的验收测试

协议与兼容：空仓库 clone、首次 push、普通 fetch、tag/annotated tag、删除分支、force-with-lease、非 fast-forward、atomic 多 ref、非 atomic 部分失败、薄包补齐、gitlink、二进制 blob、无最终换行、合法非 ASCII ref、非法 ref 和 prefix 冲突。shallow/partial clone、filter、SHA-256、LFS、SSH 只在列入当期兼容矩阵并通过测试后宣布支持。

并发：同 ref 一百个并发候选只能出现符合 CAS 顺序的结果；不同分支并发提交不会丢 pack；ref 删除再创建的 API version 防 ABA；原生 Git OID CAS 保持 Git 语义；push 与 GC 随机交错；权限撤销和长上传交错；Redis 锁过期及重复 worker；读 pin 与删除任务竞争。

故障注入：在每个上传/READY/事务语句/COMMIT/响应/outbox/GC delete 边界 kill -9；丢失 COMMIT 响应；上传损坏、错误 idx、丢对象、存储超时、DB 断连、Redis 清空。每次恢复后检查 I1–I8、operation 结果与真实 refs 一致，并运行 clone + git fsck --full。

安全：跨仓库 OID 猜测、越权 want、隐藏 ref、路径穿越、shell 参数注入、恶意 pack、深 delta、超大展开对象、压缩炸弹、子进程资源耗尽、ACL 变化时旧缓存不能放行。

恢复：从真实备份恢复到隔离环境，用标准 Git clone、比较 refs 与对象集合、运行 fsck；验证备份窗口内旧 pack 未被 GC 破坏。

性能验证只报告实测值：冷/热 clone、fetch/push 时延分位数、pack 数与大小、Git CPU/内存、对象存储请求/字节、manifest 写放大、数据库锁等待、GC 额外空间、outbox 滞后。测试须注明硬件、网络、仓库数据集、并发、缓存状态和 Git 版本；没有数据前不写固定吞吐保证。
<!-- END SOURCE BODY -->
