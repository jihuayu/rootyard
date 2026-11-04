# CI 只读镜像与 clone 加速

> 状态：目标契约；当前手动 full sync、精确 SHA-1 pin/prepare 已有有限实现，已有作业级凭证；调度、自动回源、GC 和完整生产验证仍未完成。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# 十五 CI 只读镜像与 clone 加速

状态：正在开发，未完成生产验证。目标是在保证 CI 构建输入可复现、权限不扩大的前提下，把重复 clone/fetch 的 pack 计算、对象读取和网络出口移到靠近 runner 的只读镜像。以下接口、流程与发布门槛是本轮目标契约。

## 架构与权威边界

权威端继续负责 refs 写入、权限、CI 目标解析和保留策略。GitFS 模式以原生仓库为 ref 权威，PG refs 模式以数据库为权威，镜像不改变两者边界。CI 控制器从权威端取得固定 checkout plan，再把读取路由至已经准备好的镜像。镜像负责本地 Git 协商、pack 生成与发送；只反向代理到主站无法卸载主站 pack CPU。

镜像部署在 CI 所在区域或 runner 集群附近，可按仓库放置多个副本。复制 worker 使用限定仓库和用途的服务身份获取已提交数据，按仓库合并重复同步请求；runner 的 clone 不逐个触发一次全量回源。单机部署可先运行一个独立只读镜像进程和本地持久目录，集群再增加节点、分片与本地 SSD 缓存。

所有 push 始终发到权威端。镜像入口拒绝 receive-pack 的发现请求、实际 RPC 及 SSH 写命令；CI 默认只有读取凭证。确需写回的作业取得独立、最小权限的权威端凭证和明确 push URL，不能靠镜像代理、重定向或临时升主完成写入。使用 git-http-backend 时显式关闭 http.receivepack，不能依赖“匿名默认不可 push”，因为已认证用户的默认行为不同；同时关闭不需要的 dumb HTTP 任意文件读取入口。[Git HTTP 服务配置](https://git-scm.com/docs/git-http-backend)

## 固定构建输入与 checkout 契约

checkout plan 至少包含 job_id、tenant_id、repo_id、object_format、完整 target_oid、CI ref 或 snapshot_id、source_epoch、source_version、授权策略版本及有效期。目标 OID 由权威端在接受作业时确认；PR 构建额外记录准确 base、head 与候选合并 OID。source_version 是该仓库的发布水位，不能与其他仓库、迁移代次或存储 generation 混用。

首版为作业保留不可变的 CI ref，例如 refs/ci/jobs/<job_id>，或提供等价的固定只读快照端点。CI ref 在有效期内只能指向计划中的目标提交，只有控制面可以创建和回收；访问仍须逐次授权。目标和所需对象先被 pin，再把计划标为可执行。分支随后前进、force push 或删除时，已获准任务仍读取原目标，不能悄悄改用新 tip；显式撤销任务或访问权则停止新的读取。

runner 使用标准 Git fetch 获取该固定 ref，确认取回的是 commit 且完整 OID 等于 target_oid，再执行 detached checkout；不匹配即失败，构建结果也绑定同一 OID。可以用 init 加 fetch 实现 CI checkout，不要求先 clone 全部 refs。历史深度、tags、submodule 和 LFS 是否必需由任务契约声明；不能用 depth=1 或 blob:none 自动替代任务需要的历史或内容。

Git fetch 的 refspec 接受完整十六进制对象名，但是否允许取回某个未广告 OID、对象是否存在及是否获授权，仍由服务端协议、配置与实现决定。首版用可 fetch 的不可变任务 ref 保证取数，不承诺任意 OID fetch，也不为兼容性直接开启 allowAnySHA1InWant。[Git fetch refspec](https://git-scm.com/docs/git-fetch)、[upload-pack OID 配置](https://git-scm.com/docs/git-config)

## 复制与就绪屏障

每个复制单元记录 repo_id、object_format、source_epoch、snapshot_id、目标 refs/OID、源端保留标识及依赖对象清单。源端先固定可重取的保留根，再发送同步通知；outbox 只负责唤醒，周期对账补齐遗漏。镜像按相同标识幂等处理，乱序消息不能把当前可服务版本回退。旧快照是否继续可用由 pin 和授权决定，不因新水位出现就立即删除。

复制流程为：领取任务 → 在 staging 获取对象 → 验证 Git 对象身份、pack/index、delta base 与请求范围所需的可达闭包 → 持久化对象 → 原子发布该镜像快照的 refs 和 manifest → 标记 ready。镜像水位推进到较新版本，不等于旧任务目标仍可用；路由还必须检查准确目标及其保留根。ready 必须能在镜像重启后恢复，否则重启先复验，不能仅相信内存标记。

GitFS 首版通过 Git 协议增量复制到 staging，并在有 pin 的固定输入上发布可服务视图，不复制一个正在变化的目录作为一致快照。git clone --mirror 会映射源端所有 refs，并配置后续更新覆盖这些 refs；它不是持续同步、权限隔离或对外只读策略。只在复制身份和目标服务边界允许全部这些 refs 时使用，否则显式限定复制范围。[Git mirror 语义](https://git-scm.com/docs/git-clone)

PG refs 加对象存储阶段可复制不可变 manifest、pack 和索引，复用既有发布顺序及物理对象 generation。按安全域复用已验证字节，按仓库和授权范围构造服务视图；共享底层存储不能让 upload-pack 直接遍历整个对象池。Git 对象、Git LFS 内容和 submodule 是不同数据依赖，不能只复制 Git pack 就宣布完整构建输入 ready。

## 滞后等待与回源

调度器只选择健康且能够服务计划目标的镜像。未就绪时返回可区分的 waiting 状态，触发一次合并同步并在有限预算内重试；镜像故障可切换到另一台满足相同目标的镜像。达到等待上限后，仅在任务允许且权威端仍有容量时回源获取同一目标；禁止改成“当前 main”或较旧提交来让构建继续。

回源路径也必须具备相同 CI ref 或快照及保留根，不能假定权威端会接受任意裸 OID 请求。设置每仓库和全局回源并发、带宽及 pack worker 上限，对同时启动的任务合并预热并加入抖动。没有可用镜像且回源预算耗尽时排队或可重试失败，避免镜像故障把 clone 风暴重新打到主站。

HTTP 发现和 fetch 跨多个请求，路由须固定到同一可服务快照，或保证参与节点都能服务该快照。快照 URL 绑定身份和期限，仍逐次鉴权；过期后重新申请同一目标的计划，无法续保则明确失败。protocol v2 的 ref-in-want 可作为复制滞后的兼容优化，但只有客户端和服务端支持时才可依赖，而且按 ref 取数仍须核对 target_oid。[Git protocol v2](https://git-scm.com/docs/gitprotocol-v2)、[ref-in-want 配置](https://git-scm.com/docs/git-config)

等待预算、重试上限、任务 pin 保留期及镜像同步时延 SLO 均可配置，由实测 CI 排队时间与源端容量决定。任务到期、对象缺失、权限拒绝、镜像损坏和源端过载必须返回不同原因；“过期”不能伪装为成功或无限续期。

## 权限撤销与对象隔离

首版镜像在每次发现、fetch 和续期时向权威权限服务验证当前访问权；权限服务不可用则拒绝新的敏感读取。短期作业凭证绑定租户、仓库、作业、目标范围、接收服务与过期时间，不放在 URL、Git remote、日志或缓存键里。只有 TTL 不能实现即时撤销；若后续缓存授权结果，必须先定义并验证最大撤销延迟和失效传播。

撤销后拒绝新请求和续期，并对长连接设置重新校验或中止机制，测试撤销到停止传输的上界。已经传给 runner 的字节无法追回。快照 pin 保证保留，不代表继续授权；仓库转私有、成员移除、任务取消和服务凭证失效都必须覆盖。权限拒绝不得自动降级到另一个使用更宽凭证的回源通道。

镜像按仓库和可读安全域隔离对象访问面；缓存键至少包含 tenant/repo、object_format、视图规则或授权版本、snapshot/目标及所需传输参数。OID 相同或 pack 已在磁盘上不能跳过授权。原生 Git namespace、hideRefs 和 sparse checkout 都不能作为对象保密边界；向 upload-pack 暴露的对象库只包含该服务视图获准的闭包，禁止通过 alternates、静态 pack URL、错误回显或 delta base 泄露其他范围。[Git namespace 安全边界](https://git-scm.com/docs/gitnamespaces)

复制身份只用于受控同步，不发给不可信 runner。LFS 下载逐对象验证权限、OID 和大小；submodule 按 gitlink 固定提交，并对每个来源重新授权，不将镜像主仓库凭证自动发送给任意 .gitmodules URL。预签名下载或 CDN 加速须另行解决到期、撤销与共享缓存风险，未通过前保持认证网关下载。

## 保护对象与控制负载

镜像保留根包括当前服务 refs、有效 CI plan、正在读取的快照和复制中的依赖。源端 pin 只有在镜像确认完整持久化、并满足回源与重试保留策略后才能释放；镜像侧 pin 由自身 GC 检查。引用删除先改变可服务状态，再按保留策略清理，不能随同步 prune 立即回收仍被任务使用的对象。

复用既有不可复用物理 key、删除墓碑与 GC 状态机。读 pin、续期、GC 和 repack 需要统一竞态测试；有限 TTL 不保证任意长暂停后的任务总能恢复。镜像可被重建，但有在途任务时不能把整个目录当成可随时清空的普通缓存。

镜像限制 pack 并发、CPU、内存、临时盘和单请求规模，按授权范围合并热点预热。默认先实现常规 Smart HTTP 全量或明确浅历史路径。后续再评估预生成 bundle、packfile URI、partial clone 和 runner 本地缓存；bundle 可先提供共同对象，再通过正常 fetch 补增量，但这些优化须独立验证客户端兼容、授权和回退，不能成为首版正确性的前提。[Git bundle URI 设计](https://git-scm.com/docs/gitprotocol-v2)

## 分期与发布门槛

- 第二期之后可并行启动镜像 MVP，不等待完整 Forge 或 Pando 内核：单个只读镜像、GitFS 复制、固定任务 ref、OID 校验、在线授权、有限等待和受控回源。先验证 clone 卸载链路，不宣称已具备多区域容灾。

- 第四期纳入正式读扩容：多镜像路由、复制对账、GC/pin、故障隔离、撤销传播、容量控制与 CI clone 风暴压测；若改用 PG refs 和 pack 存储，沿用同一 checkout 契约并重跑全部门槛。

- 基础正确性通过后再做预生成 bundle、共享 pack、LFS 就近缓存与区域优化；吞吐和成本收益以相同工作负载的前后对比决定，不预设加速倍数。

正确性门槛：标准 Git 客户端在支持矩阵内 clone/fetch 成功，最终 HEAD 严格等于计划 OID，目标树和所需历史与权威端一致；适用于完整仓库的 fsck 和对象连通性检查通过。覆盖 SHA-1/SHA-256、tag peel、合并候选、分支删除/force push、任务重复及源端保留过期；浅克隆和 partial clone 使用各自的完整性契约，不能把有意缺失对象误判为全量闭包。

复制与故障门槛：注入对象先缺失、pack 损坏、复制重复/乱序、发布前后崩溃、跨请求切换、镜像失联和磁盘耗尽。未完成复制的版本不得被路由；等待、切换和回源保持同一目标；满负载下回源仍受预算约束。源端或镜像发生 GC/repack、pin 到期和晚到 PUT/DELETE 时，读取只能正确完成或明确失败，不能成功返回错误提交。

安全门槛：验证镜像所有 push 路径均拒绝；跨租户已知 OID、隐藏 refs、孤立对象、delta base、alternates、静态下载、缓存命中、LFS 和 submodule 均不能越权。测试任务取消、成员移除、仓库可见性变化、令牌泄露/过期以及权限服务失联；记录撤销在新请求和长传输上的实际生效边界。

性能门槛：对比直接从权威端 clone 与经镜像的冷/热缓存、小仓/大仓、单仓热点及 CI 扇出。记录端到端 checkout P50/P95/P99、成功率、镜像就绪延迟、主站 pack CPU 秒与出口字节、镜像资源、复制流量、回源比例和总成本。卸载率分别按主站 CPU 与出口计算，并计入预热和复制成本；只有降低了权威端重复工作才算卸载，单纯把请求转发到镜像域名不算完成。
<!-- END SOURCE BODY -->
