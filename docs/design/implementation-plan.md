# Blob-only 与 Ref-CAS 实施计划

本计划是当前路线，取代历史第 08 章及旧 GitFS/Pando 演进 backlog。项目尚未发布：只交付全新安装，不安排旧 GitFS 导入、旧 schema/备份格式升级、跨版本回滚或 PG↔Raft 在线转换。两种模式在安装时明确选择；相同当前格式的崩溃恢复与全新环境恢复仍是必须能力。

[架构 ADR](../architecture.md) · [五张架构图](architecture-diagrams.md) · [状态与协议](12-state-services.md) · [实际实现状态](implementation-status.md) · [任务映射](issue-map.md)

## 基线与交付顺序

候选基线 PR #142 / `49f09c2` 已验收未接服务的 Blob/RefStore 组件及 roots、PG decisions、accepted-subset；四组原生共 51 场景和最终远端 CI 通过，不意味着 HTTP/业务 producers 已接入或 Raft 已实现。复用已有代码与证据，避免重新实现同一套基础库。

1. **S0—S2：单机 Git 闭环。** 冻结契约，补齐 PG core、Blob/provider 和 hold/root 语义；完成全新 authority provisioning、真实 Smart HTTP/Browse/ref 事务、临时 Git 视图、PG 权限 writer。PG 与 Blob 是必要依赖，缓存/wake 用有界内存。
2. **S3—S6：完整单机与默认入口。** PG PR Merge/finalizer、LFS、Workspace/checkpoint、CI/Namespace、当前格式配对恢复；移除旧服务路径与 local durable fallback，再完成最小启动/依赖隔离和完整资格。单机链路不依赖 Raft、远程决策桥、Redis 或分布式资格。
3. **D0—D6：独立分布式路径。** 成熟 Raft 库选型与持久适配→运行时→确定性状态机→mTLS 客户端 RPC/ReadIndex→签名决策关闭桥→事件投影/全局保留桥→部署/远程 Merge/配对恢复→独立故障域资格。业务 PG 与同一 Blob 层仍保留。
4. **独立闸门：GC 与性能。** #122 的破坏性 GC 默认关闭，PG 与分布式分别验收；启用分布式删除前必须完成全局 hold 桥与远程备份根。#42 比较同 ref CAS、不同 ref 准备并发及短提交瓶颈；#139 的临时视图 inode/目录放大单独保留。安全的无删除模式可先发布。

## 任务与技术前置

“前置”只表示技术依赖，不把父 epic 当实施前置。完整图已检查无环，且单机发布链不含分布式节点。具体范围、代码触点和故障验收写在各 issue；本 PR 不改变运行时默认。

| 任务 | 范围 | 技术前置 |
| --- | --- | --- |
| [#105](https://github.com/jihuayu/rootyard/issues/105) | [Roadmap] Blob-only 单机与 Raft Ref-CAS 分布式状态服务 | 无 |
| [#106](https://github.com/jihuayu/rootyard/issues/106) | [State/W0] 冻结全新安装 Blob-only 双部署契约与基线 | 无 |
| [#107](https://github.com/jihuayu/rootyard/issues/107) | [State/W1] 完成 PG RefStore 服务权威与未决语义 | [#106](https://github.com/jihuayu/rootyard/issues/106) |
| [#108](https://github.com/jihuayu/rootyard/issues/108) | [State/W1-B] 完成 OpenDAL Blob 生产 provider 契约 | [#106](https://github.com/jihuayu/rootyard/issues/106) |
| [#109](https://github.com/jihuayu/rootyard/issues/109) | [State/W1-C] 全内容 Blob、可丢 Git 视图与 KeyProvider | [#107](https://github.com/jihuayu/rootyard/issues/107), [#108](https://github.com/jihuayu/rootyard/issues/108) |
| [#143](https://github.com/jihuayu/rootyard/issues/143) | [State/S1] 全新安装初始化、正常仓库创建与唯一 authority 的幂等 provisioning | [#107](https://github.com/jihuayu/rootyard/issues/107), [#106](https://github.com/jihuayu/rootyard/issues/106) |
| [#112](https://github.com/jihuayu/rootyard/issues/112) | [State/S3] PG 发布决策服务接入、真实权限 writer 与撤销屏障 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#106](https://github.com/jihuayu/rootyard/issues/106) |
| [#113](https://github.com/jihuayu/rootyard/issues/113) | [State/W4-A] 全局 Blob artifact hold、配额与防 ABA | [#107](https://github.com/jihuayu/rootyard/issues/107), [#108](https://github.com/jihuayu/rootyard/issues/108) |
| [#114](https://github.com/jihuayu/rootyard/issues/114) | [State/S2] 补齐 RefStore snapshot/pin/root 核心契约与同权威保留语义 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#113](https://github.com/jihuayu/rootyard/issues/113) |
| [#144](https://github.com/jihuayu/rootyard/issues/144) | [State/S2] 公网 Git/Browse/ref 事务 API 统一走 RefStore 与 Blob 临时视图 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#108](https://github.com/jihuayu/rootyard/issues/108), [#109](https://github.com/jihuayu/rootyard/issues/109), [#112](https://github.com/jihuayu/rootyard/issues/112), [#114](https://github.com/jihuayu/rootyard/issues/114), [#143](https://github.com/jihuayu/rootyard/issues/143) |
| [#145](https://github.com/jihuayu/rootyard/issues/145) | [State/S4] LFS Batch、传输与发布证明统一走 Blob 并用官方客户端验收 | [#108](https://github.com/jihuayu/rootyard/issues/108), [#109](https://github.com/jihuayu/rootyard/issues/109), [#112](https://github.com/jihuayu/rootyard/issues/112), [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#144](https://github.com/jihuayu/rootyard/issues/144) |
| [#146](https://github.com/jihuayu/rootyard/issues/146) | [State/S4] workspace/checkpoint 字节单 barrier 入 Blob、不可变 manifest 与远端恢复 | [#108](https://github.com/jihuayu/rootyard/issues/108), [#109](https://github.com/jihuayu/rootyard/issues/109), [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114) |
| [#147](https://github.com/jihuayu/rootyard/issues/147) | [State/S4] CI checkout pin/revocation 与 Namespace GitView 的生产者与原子 retention | [#107](https://github.com/jihuayu/rootyard/issues/107), [#109](https://github.com/jihuayu/rootyard/issues/109), [#112](https://github.com/jihuayu/rootyard/issues/112), [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#144](https://github.com/jihuayu/rootyard/issues/144) |
| [#118](https://github.com/jihuayu/rootyard/issues/118) | [State/W7-A] PG PR 合并与可恢复 finalizer 先行 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#109](https://github.com/jihuayu/rootyard/issues/109), [#112](https://github.com/jihuayu/rootyard/issues/112), [#114](https://github.com/jihuayu/rootyard/issues/114), [#144](https://github.com/jihuayu/rootyard/issues/144) |
| [#119](https://github.com/jihuayu/rootyard/issues/119) | [State/W7-B] CI/Namespace/Workspace/LFS producer 先行接入 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#109](https://github.com/jihuayu/rootyard/issues/109), [#112](https://github.com/jihuayu/rootyard/issues/112), [#114](https://github.com/jihuayu/rootyard/issues/114), [#145](https://github.com/jihuayu/rootyard/issues/145), [#146](https://github.com/jihuayu/rootyard/issues/146), [#147](https://github.com/jihuayu/rootyard/issues/147) |
| [#120](https://github.com/jihuayu/rootyard/issues/120) | [State/W8-A] 当前格式 PG+Blob 配对全新恢复 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#109](https://github.com/jihuayu/rootyard/issues/109), [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#118](https://github.com/jihuayu/rootyard/issues/118), [#119](https://github.com/jihuayu/rootyard/issues/119) |
| [#148](https://github.com/jihuayu/rootyard/issues/148) | [State/S5] 移除 GitFS legacy Pando 运行时与本地 durable 回退，保留产品安全行为与证据 | [#144](https://github.com/jihuayu/rootyard/issues/144), [#145](https://github.com/jihuayu/rootyard/issues/145), [#146](https://github.com/jihuayu/rootyard/issues/146), [#147](https://github.com/jihuayu/rootyard/issues/147), [#118](https://github.com/jihuayu/rootyard/issues/118), [#120](https://github.com/jihuayu/rootyard/issues/120) |
| [#110](https://github.com/jihuayu/rootyard/issues/110) | [State/W1-L] 交付单进程 PG+Blob 轻量单机 | [#107](https://github.com/jihuayu/rootyard/issues/107), [#108](https://github.com/jihuayu/rootyard/issues/108), [#109](https://github.com/jihuayu/rootyard/issues/109), [#143](https://github.com/jihuayu/rootyard/issues/143), [#144](https://github.com/jihuayu/rootyard/issues/144), [#148](https://github.com/jihuayu/rootyard/issues/148) |
| [#111](https://github.com/jihuayu/rootyard/issues/111) | [State/W2] Memory/Redis 缓存唤醒且 Redis 仅可丢 | [#106](https://github.com/jihuayu/rootyard/issues/106) |
| [#149](https://github.com/jihuayu/rootyard/issues/149) | [State/D] 成熟 Raft 存储适配：WAL/vote/hardstate、原子 apply 与真实故障注入 | [#106](https://github.com/jihuayu/rootyard/issues/106), [#107](https://github.com/jihuayu/rootyard/issues/107) |
| [#115](https://github.com/jihuayu/rootyard/issues/115) | [State/W5-A] 交付真实持久 Raft Ref-CAS 运行时 | [#106](https://github.com/jihuayu/rootyard/issues/106), [#107](https://github.com/jihuayu/rootyard/issues/107), [#149](https://github.com/jihuayu/rootyard/issues/149) |
| [#116](https://github.com/jihuayu/rootyard/issues/116) | [State/W5-B] 确定性 Ref-CAS 状态机与幂等 CAS | [#107](https://github.com/jihuayu/rootyard/issues/107), [#112](https://github.com/jihuayu/rootyard/issues/112), [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#115](https://github.com/jihuayu/rootyard/issues/115) |
| [#117](https://github.com/jihuayu/rootyard/issues/117) | [State/D4] Ref-CAS Git 事件重放、PG 投影与可靠任务桥 | [#116](https://github.com/jihuayu/rootyard/issues/116) |
| [#150](https://github.com/jihuayu/rootyard/issues/150) | [State/D] 租户作用域 mTLS Raft RPC、ReadIndex 与有界流式协议 | [#115](https://github.com/jihuayu/rootyard/issues/115), [#116](https://github.com/jihuayu/rootyard/issues/116), [#143](https://github.com/jihuayu/rootyard/issues/143) |
| [#151](https://github.com/jihuayu/rootyard/issues/151) | [State/D] 全局 PG artifact hold 与 Ref-CAS pin/root 的可恢复保留桥 | [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#116](https://github.com/jihuayu/rootyard/issues/116), [#117](https://github.com/jihuayu/rootyard/issues/117), [#150](https://github.com/jihuayu/rootyard/issues/150) |
| [#152](https://github.com/jihuayu/rootyard/issues/152) | [State/D] PG OPEN→CLOSING 投影、signed decision 与吊销前 drain/terminal 屏障 | [#112](https://github.com/jihuayu/rootyard/issues/112), [#115](https://github.com/jihuayu/rootyard/issues/115), [#116](https://github.com/jihuayu/rootyard/issues/116), [#150](https://github.com/jihuayu/rootyard/issues/150) |
| [#153](https://github.com/jihuayu/rootyard/issues/153) | [State/D] PG 切点+Raft index+Blob closure 配对备份与全新 incarnation 恢复 | [#120](https://github.com/jihuayu/rootyard/issues/120), [#116](https://github.com/jihuayu/rootyard/issues/116), [#117](https://github.com/jihuayu/rootyard/issues/117), [#152](https://github.com/jihuayu/rootyard/issues/152) |
| [#122](https://github.com/jihuayu/rootyard/issues/122) | [State/W9-A] Blob 压实与默认关闭的安全 GC | [#113](https://github.com/jihuayu/rootyard/issues/113), [#114](https://github.com/jihuayu/rootyard/issues/114), [#118](https://github.com/jihuayu/rootyard/issues/118), [#119](https://github.com/jihuayu/rootyard/issues/119), [#120](https://github.com/jihuayu/rootyard/issues/120), [#151](https://github.com/jihuayu/rootyard/issues/151), [#153](https://github.com/jihuayu/rootyard/issues/153) |
| [#154](https://github.com/jihuayu/rootyard/issues/154) | [State/S6] 单进程 app+PG+Blob 安装、SIGKILL 全恢复与资源成本实测 | [#110](https://github.com/jihuayu/rootyard/issues/110), [#118](https://github.com/jihuayu/rootyard/issues/118), [#119](https://github.com/jihuayu/rootyard/issues/119), [#120](https://github.com/jihuayu/rootyard/issues/120), [#145](https://github.com/jihuayu/rootyard/issues/145), [#146](https://github.com/jihuayu/rootyard/issues/146), [#147](https://github.com/jihuayu/rootyard/issues/147), [#148](https://github.com/jihuayu/rootyard/issues/148) |
| [#155](https://github.com/jihuayu/rootyard/issues/155) | [State/D] 真实 3 选票独立主机分布式部署 profile 与 PG/ingress HA 策略 | [#115](https://github.com/jihuayu/rootyard/issues/115), [#116](https://github.com/jihuayu/rootyard/issues/116), [#117](https://github.com/jihuayu/rootyard/issues/117), [#111](https://github.com/jihuayu/rootyard/issues/111), [#152](https://github.com/jihuayu/rootyard/issues/152), [#150](https://github.com/jihuayu/rootyard/issues/150), [#151](https://github.com/jihuayu/rootyard/issues/151) |
| [#156](https://github.com/jihuayu/rootyard/issues/156) | [State/D] PR 合并经 remote authz 的 Ref-CAS receipt 投影与可恢复 finalizer | [#118](https://github.com/jihuayu/rootyard/issues/118), [#117](https://github.com/jihuayu/rootyard/issues/117), [#152](https://github.com/jihuayu/rootyard/issues/152) |
| [#42](https://github.com/jihuayu/rootyard/issues/42) | [Perf] 独立 ref 并发写入不引入整仓传输锁 | [#107](https://github.com/jihuayu/rootyard/issues/107) |
| [#157](https://github.com/jihuayu/rootyard/issues/157) | [State/D] 真实 3 主机故障矩阵、ACK 完整性、RPO/RTO 与容量成本 | [#155](https://github.com/jihuayu/rootyard/issues/155), [#156](https://github.com/jihuayu/rootyard/issues/156), [#153](https://github.com/jihuayu/rootyard/issues/153), [#42](https://github.com/jihuayu/rootyard/issues/42), [#151](https://github.com/jihuayu/rootyard/issues/151) |
| [#123](https://github.com/jihuayu/rootyard/issues/123) | [State/Release] 汇总单机与分布式新架构资格及发布闸门 | [#154](https://github.com/jihuayu/rootyard/issues/154), [#157](https://github.com/jihuayu/rootyard/issues/157) |

## 必须守住的验收边界

- 真实入口和身份：标准 Git 双客户端、SHA-1/SHA-256、atomic/subset 与 report-status，API token/浏览器/协作者/组织/团队、分支规则、可信 check、LFS pointer；未支持组合在副作用前拒绝。新 LFS 文件锁协议 #41 属于独立产品功能，不作为保留既有功能的 Blob 接入门槛。
- 字节与元数据：Blob 唯一 locator、独立回读、pack/idx 闭包、base pin、grant 与选择集合全部绑定；本地计算目录清空不丢 ACK 内容。复制命令不含大字节/网络/本机时钟。
- 权威：同仓 refs、终态/取消、snapshot pin/root 由同一 RefStore 裁决；PG 全局 hold 桥先预留后引用，全部 group 退役回执与 cursor 闭合后才释放。Raft 不可用不写 PG refs。
- 撤销：PG OPEN→CLOSING 停止签发，服务 mTLS + 签名 grant，Ref-CAS 自有单调 floor；所有相关组、在途操作、投影及 finalizer 对账前不 ACK 撤销完成。丢 ACK 查询原 operation，不换身份重做。
- 恢复：冻结应用、独立 worker、Raft apply、维护/删除器；排空或闭合 unknown，以不可变 manifest 固定 PG cut/RefStore index/Blob closure；新 incarnation 拒绝旧执行 grant，隔离恢复验收后再开放。
- 证据：绑定确切源码、二进制、配置、真实依赖和原始失败记录。单主机/进程测试不替代物理故障域与厂商耐久资格；RPO/RTO、容量与成本必须实测。

## 产品 backlog 与完成规则

本轮没有删除仍适用的产品与缺陷任务。#72 Webhook 公平调度、#73 Workspace async/指纹性能、#79 LFS 请求放大及其已有候选实现继续按各自验收和合并状态处理；#14/#15/#77/#90/#96/#98 等当前数据/恢复边界也保留，不能因计划移除旧路径就称已修复。旧路径真正不可达后，才可按新模式重新验证适用范围。

已关闭的历史验收不重开也不删除；尚未合并的完成候选不提前关闭。任务只有实现合并、对应验收完成、文档/配置/CI 一致后才关闭。总任务 #105 与 #123 汇总两个可独立发布的模式，不阻塞已合格单机等待分布式。完整保留清单见 [任务映射](issue-map.md)。
