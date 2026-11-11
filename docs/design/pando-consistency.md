# Pando 一致性契约与交付边界

状态：**部分实现（standalone PostgreSQL 会话下界基础已实现并验收；整体设计与分布式/UI 部分未完成）**。本文为 [全新安装实施计划](implementation-plan.md) 补充面向客户端的可观察保证；历史实现和单机测试不是分布式资格。Pando 在这里指目标 Blob-only Git 后端：单机使用 PostgreSQL RefStore，分布式使用 Raft Ref-CAS；两者使用 Blob 保存内容。本地 Git 仓库是可丢的计算视图。GitFS 及旧 Pando 不作为部署模式；本提案不新增旧数据导入、跨模式在线迁移或旧备份升级。

## 权威与提交

- 一个仓库、一个 history incarnation 的 refs/HEAD、commit terminal、pin/root 有且仅有一个 RefStore 权威。单机是 PG，分布式是该仓库的 Raft group；分布式业务 PG 投影、Redis、缓存或本地 Git 视图均不能自行裁决 refs，也不能在 Raft 不可用时顶替它。
- 发布前验证 Blob 对象及 Git 闭包，保留对象和原 operation identity；权威事务以精确 old OID 检查并提交 refs、membership 和终态。单机的成功提交点是 PG 事务提交，分布式是 Ref-CAS 确认提交并持久应用；业务 PG decision、授权屏障和保留桥按各模式的协议执行，不能假设跨系统原子提交。
- atomic push 的命令组全成全败。非 atomic push 保持 Git negotiated report-status 和逐 ref accepted-subset 语义；已封存的接受集合不得在发布时静默改变。成功仅在请求对应的权威结果可证明后返回。对象先持久、权威后发布；上传成功而发布失败可产生被保护的待回收对象。
- 权限/分支规则与提交必须遵守真实 writer 的同步校验和撤销屏障。旧令牌或陈旧投影不能赋予权限。无权威或无法验证的依赖时拒绝新的发布，不允许少数派独立确认另一个成功历史。
- COMMIT 已成功但响应或租约丢失可能导致结果未知；客户端按同一 operation identity 查询终态，不能把 unknown 当作失败后换身份重做。普通 stock Git 的未知结果按受支持流程重新获取 refs 并核对；不假定它能传递自定义 operation ID。

## 读的一致性

| 读取 | 契约 | 无法满足时 |
| --- | --- | --- |
| 默认 Git refs/HEAD | 向仓库权威读取一致快照；分布式强读需可证明的 ReadIndex 或同等屏障 | 权威不可达或闭包不可用时明确失败 |
| API/UI 的会话读 | 显式携带同仓已观察版本下界；结果不得早于依赖，返回实际服务版本 | 有界等待、回源权威或返回依赖未满足；不静默降级 |
| 固定 OID/快照 | 按已验证内容和完整闭包读取；实际字节必须有有效 pin/root/hold 和当前授权 | 缺字节、保留或授权时失败；不以残缺视图冒充空仓 |
| 搜索、通知、业务投影 | 异步最终一致；暴露连续已应用前沿，可选择等待明确支持的依赖 | 缺口、未完成事务或依赖未满足时不能报告已追上 |

默认 Git 请求不依赖客户端支持自定义令牌。Git advertisement 与随后 fetch 的跨请求固定快照是单独功能：需设计受控会话、pin、有效期、关闭和 GC、权限重查以及 stock Git 兼容；在交付前不宣称已有该保证。服务允许强读后被其他写入覆盖；客户端会话的“读到自己的写入”表示观察包含该写之后的历史，不意味着 ref 永远保持写入的 OID。

## 会话令牌

第一阶段目标是 **read-your-writes 与 monotonic reads**，不是完整跨服务因果一致性。令牌是服务端认证、有大小和有效期上限的不透明下界，至少绑定版本、部署/history incarnation、租户与仓库、authority 类型及 epoch、group/epoch（适用时）和仓库 revision；具体编码、签名轮换及上限由实现确定。当前 `rs1` 实现显式签名 authority kind（`1 = pg_refstore`，`2 = raft_refstore`）、`group_id`（standalone PostgreSQL 为 `0`）及 `group_epoch`，未知 authority-kind 字节按 malformed 失败关闭；密钥、轮换与部署契约见 [Repository session keyring](../development.md#repository-session-keyring-rootyard_session_keyring)。写入和读取返回服务端证明的实际版本；不能信任调用者自报的位点。令牌不是授权凭据，也不能固定 pack 布局或替代 pin/hold。

只有在相同 history 与可验证的同一权威序列中，revision 才能比较。Raft term 不是业务版本；不同 group 的裸日志 index 不可互相比较。恢复建立新 incarnation；旧令牌默认拒绝并要求重新同步，不能因新数字更大就承诺旧历史存在。全新安装路线不提供 PG↔Raft 在线切换；将来若另立迁移方案，必须先定义可验证的历史衔接，不能靠递增数字推断。

投影需要独立的连续处理位点，不能将 refs revision、pack membership 版本与事件投影 cursor 当成同一个值。需要等待投影时，令牌须绑定可证明的目标事件依赖；消费者在同一个 PG 事务内原子提交 effects、outbox/审计记录与 cursor 推进，使业务效果与投影位点一致可见；以幂等方式重放，不能跳过缺口。跨仓依赖要用有界的仓库令牌集合或服务器维护的依赖句柄；单仓标量不能表达跨仓因果关系。

只有后续写入、队列、投影、跨服务和跨仓调用都传播并检查依赖，且不先于依赖暴露结果，才能声称其覆盖范围内的完整因果一致性；第一阶段不作此声称。CI 使用固定 OID + 持久 pin/closure，而不是将令牌当作快照。

## 故障与恢复

- PG 单机提交使用与声明的持久性相符的配置；分布式 Ref-CAS 的 WAL、quorum、状态机和旧 leader fencing 都必须单独验证。同步复制、日志库或令牌本身不能证明跨主机零丢失。
- PG、Raft 或 Blob 不可用时，根据权威、授权和闭包分别失败；缓存命中不能绕开授权与保留。已有缓存是否能在依赖不可用时服务，必须作为独立受限能力明确设计，不能从对象不可变推导。
- 恢复必须对齐权威状态、业务 PG 决策及投影、pins/holds 和 Blob closure；新 history incarnation 拒绝旧执行凭据与旧读取令牌。仅 metadata 的 PG/PITR 副本不得自动获得共享 Blob 删除权。
- 保持同一仓库不同 ref 的上传、准备可并行；最终权威提交仍必须保证 CAS 与事务不变量。GC 不能删除活动视图、未决操作、备份或仍被保护的对象。

## 与现有工作的关系

- #107、#114、#143、#144、#163：实现权威快照、服务接入和版本感知视图；新增令牌与会话下界需要单独验收，不把现有 check-version 描述成因果一致性。
- #115、#116、#149、#150、#167：保留 Raft 持久性、状态机、ReadIndex 和日志完整性工作；单机不依赖 Raft。分布式不能回退 PG refs。
- #112、#117、#118、#151、#152、#156：授权屏障、事件和 PR finalizer 必须尊重各自权威与依赖；不要把不同系统的提交伪装成一个事务。
- #120、#122、#148、#153、#154、#157：恢复、GC、旧运行时移除和故障验收分别完成；不能因为设计宣布废弃就认定当前默认代码已移除。
- #126、#42、#164：分别验证真实 Git 回包、独立 ref 并发和混合负载；atomic 与 accepted-subset 分别验证。
- #171：#170 中历史 W0 冻结文档混入当前入口的问题已在集成分支修正，原 W0 正文归档于[历史归档](state-services/historical-w0/README.md)，当前 [12 状态服务设计](12-state-services.md) 保持 fresh-install、双部署协议；本文不更改冻结文件或覆盖该修复。

## 验收与分期

1. 固定 PG 和 Raft 的权威/提交/错误契约，先完成各模式真实 snapshot+pin 与对象闭包验收。以 stock Git 检查 atomic、subset、report-status、同 old OID 竞争及结果未知；不能将实验代码或库测试当服务资格。
2. 为 API/UI 实现有界服务端认证令牌、会话下界和主库回退；测试写后读、切换副本、延迟副本、缺对象、权限撤销及超时，保证不静默返回过旧成功结果。
3. 为具体投影实现连续 cursor 和等待接口；测试乱序、重复、缺口、崩溃、重放和原子效果；证明所宣称的范围后才扩大因果保证。
4. 单独评估 Git 跨请求 pin 和跨仓依赖；多主机测试覆盖 quorum loss、旧主复活、网络分区、PG/Blob 中断、恢复与 GC。按真实拓扑、持久配置及所测结果报告，不以单机证据宣称生产 HA、RPO=0 或全系统线性一致性。
