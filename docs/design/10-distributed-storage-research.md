# 分布式存储故障预研记录

> 历史来源快照：本文中的“最新/当前/优先级”仅指归档日期。现行规范见 [状态服务设计](12-state-services.md) 和 [实施计划](implementation-plan.md)，不再要求旧 GitFS 演进或旧版本升级。

> 状态：2026-11-03 的历史实验记录；本地模拟器和多进程结果不是多机生产验证。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# 分布式存储与故障预研 2026 年 11 月 3 日

## 本轮实验范围与结果

本轮使用 Git 2.56.0、真实 PostgreSQL 17.11、单机多个独立应用进程以及本地 HTTP 对象存储模拟器。共 19 组实验、116 个应用进程通过预期断言；失败反例是被明确验证的预期结果。该实验不是多机或真实 S3 测试，也没有接入上一轮 Smart HTTP 网关。

- 同一 old OID：5 轮各 12 进程竞争，每轮 1 次提交、11 次 CAS 冲突；不同仓库的发布行锁可独立推进。

- 同一 operation ID：8 进程仅产生 1 次提交，其余重放结果；相同 ID 携带不同请求被拒绝。此 ID 是原型存储 API 的能力，并非原生 Git 自带的通用 push 幂等键。

- 上传前后、事务提交前后等六个故障窗口重试后均只有一条变更。PG immediate shutdown 后发生 WAL recovery，固定快照可再次物化。

- 若先发布 refs 再上传对象，读取会遇到对象 404。正确顺序是先完成上传并按后端契约校验，再在单个 PG 事务发布对象定位、refs、generation 和操作结果。PG 事务与对象存储之间不存在跨系统原子提交。

- 删除节点 A 的缓存和全部当前 refs 后，独立进程 B 从持久快照恢复 14 个 refs 和 42 个对象，严格 git fsck 通过。此实验没有实现已提交对象的可达性 GC，不能证明 pin 与 GC 的完整安全性。

## 所有权、租约与接管

PG refs 模式下，仓库 owner epoch、操作 owner_fence、存储迁移 generation 是不同概念。领取、续租、接管与发布须遵循统一锁顺序；最终发布事务取得仓库及 owner 权威行锁后，用数据库 clock_timestamp() 检查 lease，再校验 owner epoch、操作 fence、版本与 ref CAS。对象上传和 Git 计算放在锁外；短事务设置超时。PostgreSQL 的 now()/CURRENT_TIMESTAMP 是事务开始时间，等待锁后可能陈旧。[时间函数](https://www.postgresql.org/docs/current/functions-datetime.html)、[行锁](https://www.postgresql.org/docs/current/explicit-locking.html)

保证边界是：新 epoch 接管事务提交后，遵守协议的旧 epoch 不能再发布。旧事务如果在到期前通过检查并持锁，可能在到期后提交，新接管须等待；不能承诺墙钟到期瞬间终止已经持锁的事务。PG 自身需要单主与旧主隔离，应用层租约不能修复数据库 split brain。

GitFS 模式中原生 Git refs 和磁盘为权威，PG 标记或路由切换不能阻止旧进程直接写共享卷。必须由实际存储访问层隔离旧写者；无法确认隔离完成时不允许新主写入。该方案尚未实测 CSI、网络分区和旧主 fencing。

## GC、对象身份和恢复

实验复现 DELETE 超时后晚到，删除同名 key 的新上传。修正方案把 Git 内容 OID 与物理对象身份分开，物理 key 带不可复用的上传 generation；事务持久化退休决定后，禁止旧 operation 重新上传或发布。晚到 DELETE 只能作用于已永久退休的物理 key。生产 GC 应先在 PG 内检查 refs、读取及备份 pin、上传状态，并将对象转为不可复活的 deleting 状态，之后才执行外部删除；删前单次检查 epoch 仍有检查到删除之间的竞态。

还复现了晚到 PUT：旧上传在 GC 之后完成，可产生无记录的孤儿。它没有破坏实验中已发布的 refs，但要保留清理墓碑或做对象清单对账，才能保证最终回收。实验仅回收未被已提交 manifest 引用的对象；已提交对象的可达性 GC、repack 和读 pin 竞态仍需实现和验证。

对象存储接入需定义精确 key 的完整读取、耐久确认、multipart、range、条件写和独立校验语义，不以 LIST、一次 HEAD 或 CDN 缓存结果代替提交证明。PG 备份必须与对象保留窗口协同，覆盖 PITR 和灾备恢复；只恢复 PG 不能保证其引用的对象仍在。

## 读视图与验收闸门

有限 TTL 的 pin 不保证任意长暂停后的 fetch 必然完成：到期后尚未完整物化的读取应安全失败或重试。跨 HTTP 请求快照身份绑定、续期、逐次授权和 GC 保留要一起验证。

原生 Git 多 ref 事务也不承诺并发读取看到统一快照。[git-update-ref](https://git-scm.com/docs/git-update-ref)；辅助实验使用 Git 2.52.0 files 后端，2,500 refs 的并发枚举中观察到新旧混合，这不是 Git 2.56 或分布式环境的验证。

进入生产前按顺序完成：1）将存储原型接入 Smart HTTP，复测 push/fetch/clone 与应答丢失；2）在选定真实对象存储上验证上传、读取、延迟 DELETE/PUT 与版本语义；3）真实 PG 主从提升、旧主隔离及 RPO 演练；4）实现并验证 refs、reflog、快照、备份 pin 与 GC/repack 竞态；5）补齐不可信 Git 输入、认证授权和多租户隔离；6）在正确性达标后进行大仓和并发性能测试。当前结果支持继续开发原型，不构成分布式生产可用证明。
<!-- END SOURCE BODY -->
