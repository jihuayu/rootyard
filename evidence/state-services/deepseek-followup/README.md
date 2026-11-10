# DeepSeek 开发与 review 后续验收

干净被测提交：`7690758fdb269c52baf4abb4b671ee4f11eb7977`。后续证据和文档提交不改变生产输入。实际执行使用同一个由 `scripts/build_native.py --no-default-features --package-debug 0 --strip-debuginfo` 构建的二进制，构建记录见 [build.json](build.json)。

- 生产输入 SHA-256：`4ebfc52c26ece85fffc9bbeebb5cca73f2fd7e72080160989090de1a20bd2ef0`
- 二进制 SHA-256：`a04bdb0b1afb34324fa55d75f83a9f2bd4205c325512d4f0ba4c6282dee1234e`
- 环境：同机 PostgreSQL 17.11、Garage 2.1.0、原生 Git 2.52.0；真实 S3 请求和 HTTP/stock Git 流程。

| 验收 | 结果 | 原始记录 |
| --- | --- | --- |
| Smart HTTP/Git | 11/11，零跳过 | [http.json](http.json) |
| tree/blob Browse | 7/7，零跳过 | [browse.json](browse.json) |
| refs/commits/detail/compare | 7/7，零跳过 | [history.json](history.json) |
| 最小依赖 all-targets Clippy | `-D warnings` 通过 | [clippy.log](clippy.log) |
| Rust 库测试 | 464 通过，9 项服务依赖测试显式忽略 | [rust-tests.log](rust-tests.log) |
| Python CI 修复后的完整套件 | 332 项：330 通过、2 跳过 | [python-tests.log](python-tests.log) |
| Garage RPC 启动回归 | 31/31 通过 | [garage-rpc-tests.log](garage-rpc-tests.log) |

Python 全套结果对应 CI 测试修复提交 `68e54f1`，Garage 回归对应后续启动修复；不将它们当成新 Rust 源码的独立功能验收。真实新建 Garage 实例也已成功启动并按所有权 sentinel 清理。远端 `4849d33` 的 RefStore 专项工作流 [run 42633431904](https://github.com/jihuayu/rootyard/actions/runs/42633431904) 通过，Pando 专项 [run 42633431829](https://github.com/jihuayu/rootyard/actions/runs/42633431829) 通过；新历史 API 的远端结果应以对应新 head 的工作流为准。

历史 API 的正向检查覆盖 SHA-1/SHA-256、带注解的 commit/blob/tree 标签与 tag-of-tag、refs 前缀和游标、提交元数据、祖先 full OID、分页、分歧分支的 ahead/behind/merge-base/patch，以及四个端点的真实匿名 401。期望值由 fixture 工作库中的原生 Git 独立计算。消息超过 256 KiB、历史超过 20,000 提交或响应超过当前内存预算时明确拒绝；compare 的前 100 个 ahead 提交有显式截断标记。生产和测试均未伪造 ready 状态或成功回执。

使用 [jihuayu/skills deepseek-subagent](https://github.com/jihuayu/skills/tree/main/deepseek-subagent) 的官方 `@deepseek-ai/dsh@0.2.2-rc.1` 执行实现和独立只读 review；Root 负责整合、实际构建、服务和原生验收。模型报告不替代测试记录。review 提出的非 commit 标签约束、截断和测试断言问题已经结合源码及真实 Git 对照修正。

失败历史保留：[第一轮字段断言失败](history/01-harness-field-failure.json)、[第二轮授权期望失败](history/02-harness-auth-failure.json)、[修正脚本后的 dirty 诊断通过](history/03-dirty-diagnostic-pass.json)。只有本目录顶层三个最终 JSON 属于上述干净提交的资格记录。

本次不关闭 #144 或其它实施 issue：ref 事务及完整业务入口等价性、LFS、PR/Merge、Workspace、CI/Namespace、当前 PG+Blob 独立恢复、默认入口替换和 Raft 仍有待办。备份、LFS 和 Raft 实验代码没有并入此候选。以上是同机功能与进程恢复验收，不声明物理掉电、厂商耐久、HA 或多主机故障域资格。
