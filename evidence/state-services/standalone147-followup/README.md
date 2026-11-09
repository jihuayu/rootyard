# Blob 单机服务后续验收（2026-11-09）

被测代码提交为 `f1889aac45911e8a58b991c63373376f55af8939`，包含并发失败终态、tree/blob 浏览，以及原生 LFS 指针路径扫描的 NUL 分隔修复。报告生成时工作区干净；本目录及文档随后单独提交，不改生产输入。PR #159 仍为 Draft。

| 检查 | 本次结果 | 证据 |
| --- | --- | --- |
| 完整 Smart HTTP/Git | 11/11 通过，零跳过 | [smart-http.json](smart-http.json) |
| tree/blob 浏览 | 7/7 通过，零跳过 | [browse.json](browse.json) |
| 最小配置 all-targets Clippy，`-D warnings` | 通过 | [clippy.log](clippy.log) |
| Rust 库测试 | 456 通过，0 失败，9 显式忽略 | [library-tests.log](library-tests.log) |
| 当前格式非空仓库备份 | 源创建/推送/重克隆通过，快照失败；后续 5 项未执行 | [backup-gap.json](backup-gap.json) |

[summary.json](summary.json) 包含生产输入、二进制和原始证据文件的 SHA-256；[build.json](build.json) 是 `scripts/build_native.py` 从实际 Cargo 构建事件生成的记录。HTTP 与浏览报告绑定同一个被执行二进制和生产输入。归档前核对未包含本次 Garage fixture 的 endpoint、bucket、access key、secret key 或数据库 URL；未上传私有环境文件或服务器日志。

真实服务为同机 PostgreSQL 17.11、Garage 2.1.0 和原生 Git 2.52.0；并非模拟对象存储，也不是多主机或物理掉电资格。生产输入 SHA-256 为 `65c9da2bb9d0234cf3b7ac8ba119886ec4ba4235fcff44bc1298d42de6266511`，二进制为 `23c2979aa492abb790ff7b6e7eb2efb8e5f1353d02498b16a6267f87029a1f9f`。

HTTP 验收覆盖两种对象格式、ACK 后 SIGKILL/删除 scratch/重启重克隆、权限与作用域、真实双客户端竞争、atomic/accepted-subset、Blob 不可用/缺失、130 次读取后的零 pin/history 残留、相同请求并发与 gzip 重放，以及首次推送后的默认分支创建重试。双 operation 协议竞争留下一个 committed、一个 rejected，两个报告均逐字重放且账本计数不变。错误分类回归覆盖 A3 两条 gate 前进路径；本次 HTTP 竞争没有强制调度到两个指定窗口。

浏览验收逐项对照原生 Git 的 OID、目录条目和文件字节，包含空文件、嵌套目录、二进制、UTF-8、空格、tab/newline 文件名分页游标往返、直接对象接口、带注解标签、ref 前进后的祖先读取，以及丢弃全部计算目录后的重启浏览与重克隆。按文件路径读取仍沿用既有路径校验；tab/newline 在本次 HTTP 验收中仅验证目录列举、分页和原生克隆。

备份 CLI 本次在快照阶段退出 1，只返回通用错误。源码核对确认 `backup::git_inventory` 无条件要求 ready 仓库有持久 bare Git，这是新 `pg_refstore` 仓库的确定阻塞；本次未进一步证明它是唯一拒绝原因。当前归档不导出 OpenDAL 内容闭包，`serve-blob` 也尚未持有旧 volume flock 或检查其 restore guard。不得据此声明 #120 通过；即使后续元数据恢复脚本通过，保留原 Blob 的恢复也不等于独立 PG+Blob 备份。

复跑时先配置一次性 PostgreSQL 管理员与严格 `ROOTYARD_BLOB_*` S3 profile，再执行：

```sh
python3 scripts/build_native.py --no-default-features --package-debug 0 --strip-debuginfo
python3 tests/blob_only_service.py --binary "$PWD/target/debug/rootyard" --git /absolute/trusted/git --report /tmp/smart-http.json
python3 tests/blob_gateway_browse.py --binary "$PWD/target/debug/rootyard" --git /absolute/trusted/git --report /tmp/browse.json
python3 tests/backup_blob_serving147.py --binary "$PWD/target/debug/rootyard" --git /absolute/trusted/git --report /tmp/backup-gap.json
```

最后一个命令当前预期失败，未接 CI。前两个已接 RefStore 原生工作流；新增工作流步骤的远端执行结果需另行查看，本文只记录本机实际执行。

历史失败保留在 [history/browse-newline-failure.json](history/browse-newline-failure.json)：`9e4163b` 的 Browse 源仓库推送被拒绝，既有指针扫描用换行分隔路径，无法承载合法换行文件名。修复使用 Git `cat-file -Z`，继续执行全部路径检查；没有删去失败夹具。[history/smart-http-before-pointer-fix.json](history/smart-http-before-pointer-fix.json) 记录修复前独立通过的 11 项 HTTP 验收，只作历史证据。

默认入口、LFS/PR/Merge/Workspace/CI/Namespace 的完整接入、独立 Blob 恢复、真实 Raft 和多主机资格仍未交付。没有关闭实施 issue。
