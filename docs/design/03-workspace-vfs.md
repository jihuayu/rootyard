# Workspace 与 VFS 契约

> 历史来源快照：本文中的“最新/当前/优先级”仅指归档日期。现行规范见 [状态服务设计](12-state-services.md) 和 [实施计划](implementation-plan.md)，不再要求旧 GitFS 演进或旧版本升级。

> 状态：目标设计；当前只有本地独立副本与调用方静止条件下的 checkpoint 实验。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# Workspace / VFS 实施方案

## 1. 决策与边界

本模块提供公司级虚拟命名空间、每个 agent 的隔离工作空间、原生 Git 视图、实时变更追踪与可恢复 checkpoint。首版采用“逻辑 VFS + 原生工作目录投影”，不是自研 POSIX/FUSE 文件系统：工具仍使用标准文件路径与 Git CLI，服务层负责版本、捕获、隔离和恢复。此决策不妨碍以后替换底层物化器。

必须区分三个概念：

1. 实时追踪是发现和捕获 working tree 变化，绝不自动执行 git add、commit 或 push。

2. Git HEAD、index、working tree 是三个独立状态，checkpoint 必须一起保存，不能用 HEAD + 单份 diff 代替。

3. 只有 COMMITTED checkpoint 承诺跨节点恢复。watcher 通知、浏览器已显示、写入本机磁盘，都不等价于远端持久化完成。

V1 平台：Linux、大小写敏感路径、以最新稳定 Git 为兼容目标并固定每次部署的验收版本（当前 2.56.0）、普通文件/符号链接/执行位。子模块、LFS、稀疏检出须显式能力协商；不支持的仓库在导入时说明，不在恢复时悄悄丢失。长期开启的数据库文件、socket、FIFO、设备节点等不能冒充普通文件 checkpoint。

## 2. 命名空间和隔离

公司命名空间是版本化目录映射，例如：

    /company/acme/apps/payments -> repository R1, repo-root
    /company/acme/libs/common   -> repository R2, repo-root

它不是跨仓库的大 Git 仓库。进入 payments 才看到 R1 的 Git 根；上层目录不提供合成 .git。V1 拒绝重叠 mount、路径穿越及跨 repo 的原子 rename，跨 repo 移动是显式 copy + delete。每个 workspace 固定 namespace_revision 和每个 repo 的起始 commit；上游分支移动不能偷偷改变 agent 正在使用的文件。

每个 agent 对应一个独立 workspace。fork 以已完成 checkpoint 为父节点，复用不可变内容，不共享可写 inode。宿主支持 reflink 时用 reflink，否则复制；绝不能用普通 hardlink 假装工作文件 CoW。首次实现允许先物化完整工作树，之后再优化按需读取。

每个 repo view 具有独立 .git、HEAD、index、refs、reflog 和可写 object directory。只读 Git pack 缓存可以共享，但必须按租户授权、持有引用、禁止 agent 修改，并确保回收不会使活动 workspace 缺对象。不要直接把 git worktree 作为多 agent 安全边界，因为它默认共享 refs 和部分配置。[Git worktree 文档](https://git-scm.com/docs/git-worktree)

## 3. 精确状态模型

对 workspace 中的每个 repo 定义：

- B：fork 时不可变基线，含基线 manifest 和起始 commit。

- H：当前 HEAD，可为符号分支、detached HEAD 或尚无首个 commit 的 unborn HEAD。

- I：原生 Git index，保存 stage 0/1/2/3、文件模式、OID、intent-to-add 等语义。

- W：原生 working tree，独立于 H、I；原始字节不能和经 Git clean filter 处理后的 blob 混为一谈。

- N：仅原生磁盘保留的临时数据，默认包括 ignored 且不在 H/I 中的文件。

- C：捕获到远端的版本；C 可能落后于正在写入的 W，API 必须给出差距和状态。

Git 暂存读取 add 执行当时的内容，之后继续编辑不能反向修改 index；部分暂存也必须保留。[Git add 文档](https://git-scm.com/docs/git-add)

持久化资格规则：

    managed(path) = path in HEAD tree
                 OR path in any index stage
                 OR explicitly included by checkpoint policy
                 OR (untracked AND not ignored)

HEAD 并集用于保护“已从 index 删除、尚未提交”的文件。tracked 文件不受 ignore 规则影响。working tree 中新增、尚未 git add 的非忽略源码也进入 managed。已被忽略但仍 tracked 的 node_modules/foo 不能被整个目录剪枝漏掉。

ignored/native 是持久化分类，不是在规则变化时物理迁移目录。所有文件保持原路径，避免破坏打开的文件描述符和 rename 语义。

## 4. 组件与存储职责

- Workspace API：鉴权、版本条件、幂等键、生命周期和 checkpoint 请求。

- Workspace runtime：物化工作树，运行受控进程，维护独占写入租约、磁盘配额和写入屏障。

- Git adapter：调用固定版本 Git，读取机器格式状态，执行允许的 Git 操作，捕获 Git 元数据。

- Capture daemon：watcher、dirty set、扫描、内容哈希、本地恢复 journal、对象上传。

- Manifest service：管理不可变路径树、Git 元数据快照、checkpoint 根。

- Event relay：数据库 outbox 到 Redis/SSE/WebSocket，支持重放。

主数据库保存权威元数据、租约 fencing token、持久化 revision、操作状态和 outbox。Redis 只做缓存、唤醒和实时分发，不能成为唯一锁、唯一日志或唯一 checkpoint 清单。对象存储保存原始文件字节、Git 对象包、index、元数据包及不可变 manifest。数据面本机磁盘保存正在编辑的文件、本地 WAL 和不可变待上传快照。

文件内容用平台 SHA-256 CAS 标识，Git OID 单独存 object_format + oid，不把二者混用。对象 key 按 tenant 分区；跨租户不暴露去重存在性。大文件可后续分块，V1 可先整文件 CAS + 大小上限。Git pack 复用和平台文件 CAS 是两套可独立回收的引用图。

## 5. 最小数据库模型

所有表有 tenant_id，查询、外键和对象权限均带租户边界。

| 表 | 关键字段及约束 |
| --- | --- |
| repositories | id, provider, external_id, object_format, access_policy, imported_revision |
| namespace_versions | id, company_id, revision, manifest_digest；不可变 |
| namespace_mounts | namespace_version_id, mount_path_bytes, repository_id；不重叠 |
| workspaces | id, agent_id, namespace_version_id, parent_checkpoint_id, state, host_id, lease_epoch, lease_until, revision, last_checkpoint_id |
| workspace_repos | workspace_id, repo_id, mount_path, base_commit_oid, base_manifest, git_generation, git_snapshot_id |
| overlay_entries | workspace_id, repo_id, path_bytes, entry_version, kind, mode, content_digest, size, deleted, capture_class；仅存覆盖层变化 |
| blobs | tenant_id, digest, size, object_key, checksum, state；唯一(tenant_id,digest) |
| git_snapshots | id, git_version, head_descriptor, index_digest, refs_digest, metadata_digest, object_manifest_digest, config_policy_digest |
| checkpoints | id, workspace_id, lease_epoch, captured_revision, parent_id, root_manifest_digest, state, scope, excluded_summary, created_at, durable_at |
| workspace_events | workspace_id, revision, transaction_id, type, payload_digest；唯一(workspace_id,revision) |
| operations | id, workspace_id, type, idempotency_key, state, result；唯一(workspace_id,idempotency_key) |
| outbox | event_id, workspace_id, revision, payload, delivered_at |

baseline 的百万级路径表放在对象存储的分片有序 manifest/Merkle 树，不把每次 fork 变成百万行 INSERT。DB overlay 是 sparse delta。读取目录为 baseline + overlay - tombstone；压实得到新不可变根。tombstone 只遮蔽本层/基线，不修改其他 workspace。

## 6. API 合约

所有写 API 需 tenant/workspace 授权、Idempotency-Key；交互修改提供 expected_entry_version，跨文件事务提供 expected_workspace_revision。过期条件返回 409，不能自动覆盖新内容。

| 接口 | 输入 / 返回 |
| --- | --- |
| POST /workspaces | namespace_revision, repo base commits 或 checkpoint_id；返回 operation_id |
| POST /workspaces/{id}/fork | committed checkpoint_id, new_agent_id |
| GET /workspaces/{id}/tree | repo_id, path, view=head/index/working, revision；返回条目及 managed/native、captured/live 标记 |
| GET /workspaces/{id}/files | repo_id, path, revision；返回内容、ETag、durability |
| POST /workspaces/{id}/file-transactions | puts/deletes/renames[], expected versions；同一 repo 原子 API 事务 |
| POST /workspaces/{id}/repos/{repo}/git | action, args, expected_git_generation；返回原生命令结果和新 generation |
| POST /workspaces/{id}/checkpoints | mode=consistent, include_native allowlist；返回 operation_id，直到 COMMITTED 才算成功 |
| POST /checkpoints/{id}/restore | 默认 new_workspace；原地恢复必须显式要求并检查目标 revision |
| GET /workspaces/{id}/events | after_revision；SSE，缺口返回 RESYNC_REQUIRED + 最新 snapshot revision |
| POST /workspaces/{id}/changesets | base_checkpoint, source_checkpoint；形成可审核变更集 |
| POST /workspaces/{id}/apply | changeset_id, expected_revision；三方合并，冲突不覆盖 |

路径以 byte-safe 编码存储，JSON 可用 path_base64 + display_path。不得在无说明下把 Unicode 规范化或大小写折叠。文件名换行、tab、前导连字符必须能往返；Git 调用使用 NUL 分隔输入和 -- 结束选项，而非拼 shell 字符串。

file-transactions 的“原子”指本服务读取的发布版本原子切换。若底层是多文件原生写，不能宣称外部任意 POSIX 读取者同时看不到中间态；需要该保证时，所有读写都必须经过事务屏障，或切换不可变目录根并限制旧 FD 语义。普通工具看到的并发文件行为保持原生 OS 语义。

## 7. 变更捕获算法

1. inotify/等价 watcher 将路径加入 dirty set，目录新增先注册观察再扫描，删除和移动通知用于触发重新求值。watcher 不是事实日志。

2. close-write 或短 debounce 后读取当前文件；记录 inode、size、mtime、ctime，复制/哈希后再检查。发现变化则重试或保持 dirty。该流程只保证静止后的收敛，不承诺任意并发写下的线性化快照。

3. 使用当前 Git index/HEAD 和实际工作目录 ignore 规则判断 managed。新路径的 ignore 判断复用 Git check-ignore，缓存按目录及 ignore_generation 失效，不实现简化 glob 替代 Git 语义。

4. 对捕获内容写本地临时对象，fsync 文件，原子 rename，再 fsync 父目录；写带 checksum 的 WAL 记录。WAL 记录已捕获内容，不是盲重放 watcher 动作。

5. 上传不可变对象，验证长度/校验和，确认可读取后，在单个 DB 事务内检查 lease_epoch、推进 workspace revision、更新 overlay、插入 event/outbox。对象在 DB 引用前必须存在。

6. Redis 分发的是已发布事件。可另发 dirty hint 供 UI 提示，但必须标记非持久化。客户端按 revision 去重，丢通知后从 DB 补齐。

7. watcher overflow、断连或 daemon 重启时设 NEEDS_RESCAN，进行完整对账；后台周期性扫描及 checkpoint 扫描负责兜底。不能用“没收到事件”证明文件未变。

POSIX rename cookie 只作为优化提示；配对缺失时全量对账仍需得出正确状态。同 repo rename 在 manifest transaction 中产生旧路径 tombstone + 新路径 entry，可保留 correlation_id；Git 的 rename 检测仍由 Git 依据内容决定，平台不能强制把所有 rename 解释成 Git rename。

普通保存实时 SLO 建议在基准环境、单文件 ≤1 MiB 时，从 close 到状态出现 p95 <500 ms、远端捕获 p95 <2 s；这是待压测目标，不是已验证性能。大文件明确展示 uploading，不冻结整个 UI。

## 8. Git 和 ignore 的关键场景

- 编辑 A，git add A，再编辑 A：H 仍为旧版、I 为第一次编辑、W 为第二次编辑；恢复后两份差异都在。

- git add -f ignored.txt：命令成功后该路径已在 index，提升为 managed；必须在本次 Git 操作的同步 capture barrier 中保存 index blob 与 W，不能等旧 ignore 缓存刷新。

- .gitignore 修改：递增 ignore_generation，重扫受影响子树；tracked 文件照常捕获，未 tracked 文件只改变后续快照资格，不删除本机文件，不篡改过去 checkpoint。

- git rm --cached A：I 无 A，H 仍有 A，因此继续保存 W；提交删除后 H/I 均无 A，若当前被忽略才变 native。

- git add -N：保存 intent-to-add 语义和实际 W，不把空 blob 当成文件当前内容。

- 冲突：index stage 1/2/3 必须完整保留，不能仅存 write-tree 结果，因为未合并 index 无法用单一普通 tree 表示。[Git update-index 文档](https://git-scm.com/docs/git-update-index)

- clean/smudge、换行转换：W 保存原始字节，I 使用原生 Git 产生的对象；允许的 filter 在隔离运行环境执行，未知可执行配置需审批策略。

- native 的 ignored 文件不默认传入对象存储，也不默认随 fork 复制；本机 restart 仅在原卷仍在时可保留。UI 显示此类文件不会随 checkpoint 恢复。必要的文件可显式加入 checkpoint allowlist，凭证挂载目录禁止包含。

- Ignore 规则采用 Git 完整语义，包括层级优先级、否定规则及被忽略父目录的行为。禁止把 ignore 当成安全隔离策略。[Git ignore 文档](https://git-scm.com/docs/gitignore)

Git 状态使用 git status --porcelain=v2 -z，不解析给人阅读的输出。Git 管理操作串行化，每次操作结束重新捕获 HEAD/index/refs；任意 shell 内的 Git 也纳入受控进程边界。status 等读命令可用避免可选锁写入的方式运行，不能意外与 checkpoint 竞争。[Git status 文档](https://git-scm.com/docs/git-status)

## 9. 强一致 checkpoint

状态：REQUESTED → CAPTURING → UPLOADING → COMMITTED，失败为 FAILED；失败 checkpoint 不可作为 fork/recovery 根。

算法：

1. 写入幂等 operation，获取 workspace 的 DB 写入租约并校验 epoch，关闭新写入/exec admission。

2. 获得强静止屏障，确保全部写入者受控。V1 可在 job boundary，等待所有可写任务结束且没有遗留后台 writer 后捕获；持久服务场景必须使用经过验证的文件系统冻结/快照适配器。仅 SIGSTOP、等待一会儿或比较 mtime 不算完整屏障。

3. 如果存在活动 Git transaction/lock，等待其完成或超时返回 CHECKPOINT_BUSY；不自动删除锁。明确暂停于 merge/rebase 冲突、但没有活动写入事务的状态可以保存。

4. 在同一个屏障内取得所有 repo 的不可变本地快照，完整扫描 managed 文件并捕获 Git 元数据。跨 repo checkpoint 是同一时点的状态向量，不是跨仓库 Git commit。

5. 原始 index + 可验证语义摘要、HEAD/symref、refs/reflog、merge/rebase/cherry-pick/sequencer 状态、必要 Git 对象，以及非敏感配置进入 Git snapshot。存储路径使用 Git 提供的解析接口。禁止只备份工作文件和 HEAD。

6. 本地快照完成后可恢复运行，上传只读快照，不继续读取变化中的 live tree。root manifest 引用每个 repo 的 working manifest、git snapshot、namespace revision、捕获范围、exclude 摘要和版本。

7. 先上传所有引用对象并校验，再上传 root manifest。单个 DB 事务校验 epoch，登记 checkpoint COMMITTED、更新单调向前的 last_checkpoint、写 outbox。较旧 checkpoint 后上传完成时不能覆盖较新指针。

8. 返回 checkpoint_id、captured_revision、durable_at、excluded_summary。客户端只有此时显示“可恢复”。

V1 固定 Git 配置，禁用 split-index 等尚未验证的扩展，保存完整 index 与 Git 版本。恢复时使 stat/untracked/fsmonitor 缓存失效，但保留 index 的暂存、冲突和标志语义；未知扩展拒绝恢复或使用原版本，不擅自丢弃。之后再增加跨 Git 版本迁移。

## 10. 恢复、故障矩阵与回收

恢复默认创建新 workspace：读取 COMMITTED 根 → 验证租户及对象完整性 → 物化到临时目录 → 构造独立 Git 元数据/对象集合 → 校验 HEAD/index/working 的对比结果 → 原子发布 workspace ready。失败临时目录不对外暴露，也不覆盖用户当前目录。

| 故障点 | 处理 |
| --- | --- |
| 文件写到一半，尚未捕获 | 遵循 native OS 写入语义；不得声称远端已有该版本 |
| daemon 崩溃，本机卷尚在 | 校验 WAL 完整记录，忽略不完整尾部，扫描 live tree，再上传和发布 |
| blob 已上传，DB 尚未提交 | 孤儿对象；幂等重试，宽限期后 GC |
| DB 已提交，通知未发 | outbox 重发，客户端按 revision 去重 |
| COMMITTED 响应丢失 | 同一 Idempotency-Key 查回原结果，不重复建 checkpoint |
| Redis 丢失 | 从 DB/outbox 重建，正确性不受影响 |
| 节点完全丢失 | 从最新 COMMITTED checkpoint 恢复；未持久化 delta 和默认 native 数据可能丢失 |
| 网络分区/租约到期 | daemon 在租约失效前冻结/停止写入，旧 epoch 无权发布；不能继续对外确认成功 |
| 发现 Git lock | 结合进程/操作记录判断；结果不明先保留隔离副本，不盲删、不重跑非幂等 Git 命令 |
| 对象 checksum 错误/缺失 | 标为不可恢复并报警，尝试受信副本；不返回成功空文件 |

API 原子保存可承诺 fsync + 本地 WAL 后的 local-durable，要求远端成功时等待对象+DB 提交。任意 shell/POSIX 写不能在 native 模式下许诺“每次 write 都远端零丢失”。若业务要求该等级，需追加复制型写日志或同步远程文件系统，并单独定义 fsync/断网阻塞合约，不能靠 watcher 补上。

GC 使用 checkpoint、活跃 workspace、upload staging、fork parent、Git object pins 为根的可达性标记，先标记待删、宽限期后再扫；上传中的 manifest 必须有 pin。租约、保留策略和用户删除流程影响根，不以 Redis TTL 判定可删。[fsync 文件及目录持久化语义](https://man7.org/linux/man-pages/man2/fsync.2.html)

## 11. 并发与安全

- 一个 workspace 一个 writer host。主 DB CAS 获取递增 epoch，DB 时间判租约；Redis 锁只优化。每次发布检查 epoch；host watchdog 必须 fail closed，否则只能保证旧写入无法发布，不能宣称阻止旧节点本地继续写。

- 不同 agent 通过 fork 隔离，协作通过 change set + 三方合并；不让两个 agent 共写一个目录并期待自动解决逻辑冲突。

- 文件 API 乐观并发；Git mutation 和 checkpoint 使用相容锁顺序 workspace → repo → git。跨 repo 加锁按 repo_id 排序。

- 受控 API ref 更新使用 expected old OID 的 CAS；远端 push 是单独的授权操作，不随 checkpoint 自动触发。[Git update-ref 文档](https://git-scm.com/docs/git-update-ref)

- namespace 不是权限边界。每次打开文件、对象、event 和 Git 操作检查 repo 权限；权限撤销使 workspace 停止发起新操作，已持有敏感对象遵循回收策略。

- 容器/microVM 隔离、独立 UID、网络策略和 mount namespace 形成执行边界。限制对 .git 外部路径、替代对象库、配置 include、hooks、filters、credential helper 的访问与执行。

- 文件访问用目录 fd 及 beneath/no-follow 路径策略防止 symlink/TOCTOU 穿越；保存 symlink 的目标字节而不跟随它读取外部文件。普通 API 可显示外部 symlink，但不能据此读取 workspace 之外的内容。

- 密钥使用短期凭证 broker 或只读秘密挂载，不写入 repo config、日志、checkpoint。日志不记录文件正文；下载对象需授权，不把 CAS hash 当访问令牌。

- 对对象数、路径长度/深度、文件大小、磁盘/inode、上传带宽、CPU 和 watcher 数设配额。硬链接、特殊文件、挂载点须明确支持或报错，不能静默换语义。

## 12. 验收测试与里程碑

必须自动化的正确性场景：

1. 从同一 checkpoint fork A/B；A 修改、删除、chmod、rename 不改变 B，缓存 baseline 也不可写。

2. staged v1 + unstaged v2、add -p、add -N、冲突 stage 1/2/3、detached/unborn HEAD、暂停 rebase 经恢复后与原 Git 状态和 diff 等价。

3. ignored 未 tracked 的巨量目录不上传；其中已 tracked 文件仍捕获；add -f 立即提升；rm --cached + commit 正确降级。

4. 修改嵌套 .gitignore、否定模式、info/exclude、固定 global excludes 后分类与 Git 一致；过去 checkpoint 不变。

5. 原子保存 rename-overwrite、目录 rename、删除后重建同名文件、打开 FD 后 unlink、跨 repo rename、同路径并发 API 写；冲突符合合约。

6. binary、空文件、执行位、symlink、换行/Unicode/无效 UTF-8 文件名、CRLF/filter 都能按支持范围往返；不支持的类型显式失败。

7. 故障注入覆盖上传前/后、DB commit 前/后、outbox 发送前/后、租约切换、watcher overflow、磁盘满、对象损坏、强制重启；不能出现已确认 checkpoint 缺对象。

8. 两节点争抢同 workspace，旧 epoch 不能发布；分区时 write gate 到期关闭；Redis 全清空不丢持久化状态。

9. 跨租户 hash 猜测、路径穿越、symlink race、恶意 .git 配置/钩子、无权限 repo mount、事件流越权均被隔离。

10. 恢复到另一节点，直接运行 Git diff/status 与一次构建，证明并非仅 UI 看起来恢复。性能基准包含 100k 文件、1 GiB 源码、10 GiB ignored 依赖目录；报告冷热缓存分别的时间、磁盘和上传量。

阶段与完成门槛：

- M0，语义骨架：实现 namespace、状态模型、真实 Git adapter 和 golden fixture；先通过 staged/unstaged/conflict 测试，再建设 UI。

- M1，可打开最小闭环：单 repo、独立 .git、物化与 CoW、原生 shell 编辑、status/diff、workspace 文件树；浏览器可以创建并进入工作区。

- M2，可保存可恢复：CAS、manifest、幂等 checkpoint、job-boundary 写入屏障、同/异节点恢复，故障注入全部覆盖；UI 明确显示 durable 状态。

- M3，多 agent 与实时：fork、watcher+rescan、SSE、fencing、change set 三方合并、multi-repo namespace/checkpoint、ignored 边界。

- M4，生产强化：持久服务的强快照适配器、配额、GC、审计、规模基准；按真实需求增加 LFS/子模块/稀疏检出。

每阶段提交可运行代码、migration、API 示例和自动化测试，不把“方案写完”当作“可以打开”。如果暂时只有设计，交付状态必须写“待实现”，不能声称工作区已上线。

补充实现依据：[inotify 事件丢失与队列溢出](https://man7.org/linux/man-pages/man7/inotify.7.html)、[Git 仓库布局](https://git-scm.com/docs/gitrepository-layout)。
<!-- END SOURCE BODY -->
