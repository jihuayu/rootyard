# Forge 与工程任务

> 历史来源快照：本文中的“最新/当前/优先级”仅指归档日期。现行规范见 [状态服务设计](12-state-services.md) 和 [实施计划](implementation-plan.md)，不再要求旧 GitFS 演进或旧版本升级。

> 状态：目标设计；当前仅落地私有 owner Issue/comment 等有限切片。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# Forge 与首期工程任务

## 工程模块

Rust workspace 按 domain、store、git、workspace、vfs、auth、lfs、integrations、api、worker、admin 划分，先做后端；Web 后续实现。领域层不直接调用 HTTP 或 SQL；Git 写入、网页合并及 Agent 发布经过同一受保护写入口。PostgreSQL 保存权威数据，对象存储通过流式接口适配；单机缓存和消息通道使用有界内存实现，分布式可接 Redis 和 Kafka 类队列。

## 核心数据

users、sessions、tokens、namespaces、repositories、repository_members、issues、comments、pull_requests、branch_rules、integrations、check_runs、lfs_objects、repository_operations、outbox_events、audit_events。仓库、Issue、PR 编号分别有作用域内唯一约束；Issue/PR 修改携带版本条件。敏感凭证保存摘要或密钥引用，不进入日志。

## API 与状态

统一 /api/v1，错误返回 code、message、request_id；列表 cursor 分页，变更接口提供条件版本及适用的幂等键。

- POST /repositories 创建仓库；GET /repositories/{id}/refs、/tree、/blob、/commits、/compare 浏览固定 OID。

- GET/POST /repositories/{id}/issues，PATCH /issues/{number}，POST /comments。

- GET/POST /repositories/{id}/pulls，GET /pulls/{number}/diff，POST /pulls/{number}/merge。

- POST /integrations/{id}/check-runs，回传 integration 身份、固定 commit SHA、context、attempt、sequence、status 和 conclusion。

- Git Smart HTTP、LFS Batch 和上传下载端点单独遵守对应协议，不将自有 JSON API 当 Git 兼容协议。

PR 状态 open → merged 或 closed，closed 可重开；mergeable 是根据当前 head/base、策略和检查计算的瞬时结果。首版可只支持 fast-forward，合并请求携带 expected_head、expected_base 和版本，校验 trusted CI 对应精确 SHA 后 CAS 更新。若 Git 文件卷与数据库分属不同事务域，先写合并意图，再更新 ref，最后持久化 PR 状态与 outbox，崩溃后按意图与实际 ref 对账，禁止宣称跨域原子。Pando 数据库权威 refs 原型通过同一事务更新 refs、manifest、operation 与 outbox。

## CI 与 LFS

外部 CI 通过签名 webhook 和专用 integration 身份回传，事件含 event_id、仓库、固定 head/base 和检查定义；按 event_id 幂等，拒绝过期及乱序状态覆盖。只有可信来源对当前候选 SHA 的成功结果可放行，模拟回调不能冒充真实构建。出站 webhook 做 SSRF 防护、明确白名单、签名和重试。

LFS Batch API 校验仓库权限、OID 和 size；上传流式计算 SHA-256 与字节数，校验通过才标 ready，不能用对象存储 ETag 代替内容哈希。Git 引用的新增 LFS pointer 需要可访问的 ready 对象。LFS 锁、跨仓去重后置并显式说明。

## 按依赖开工

1. 架构决策记录：数据库使用 PostgreSQL，确定隔离等级和对象存储一致性契约；Git 以最新稳定版为目标，当前基线 2.56.0，明确 object format 和客户端兼容矩阵；确定仓库和开发环境。

2. 建立 Rust workspace、迁移、配置、日志、health、最小授权、容器及自动测试。验收：干净环境启动，重启数据存在。

3. 用持久文件卷上的成熟 Git 打通受控 HTTPS clone/push、权限、仓库浏览与可观测性；单节点锁是阶段性限制，不能当最终多分支无仓库锁方案。

4. 独立实现 Workspace 固定版本、各 Agent 私有 .git、checkpoint 和恢复，先本地物化验证，再逐步接真实 VFS；完成 ignore、部分暂存、崩溃恢复验收。

5. 并行原型化 Pando 风格内核，先验证对象闭包、原子发布、标准 Git 客户端、并发和故障注入；与成熟基线比较后决定替换，未验证的 proc-receive/对象访问集成不得宣称生产可用。

6. 逐步接入 Issue、PR、LFS、外部 CI，完成审计、安全和真实端到端测试。实现顺序可并行，但每阶段必须满足前置依赖和验收。

## 验收门槛

清晰区分目标、实验结果和生产承诺。至少覆盖同 ref 冲突和不同 ref 并发、断电及对象与事务间故障、跨节点 fetch、Git CLI/JGit/libgit2 版本兼容、真实 LFS、真实 CI、受保护分支、restore 与权限隔离。测量 P50/P95/P99、对象放大、数据库等待、Redis 故障降级、缓存命中和资源峰值。
<!-- END SOURCE BODY -->
