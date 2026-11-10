# 历史 W0 设计快照（archival，已被取代）

本目录只保存 W0（issue #105/#106，subtask #106）在 `9d8373f` 写入的原始第 12 章
`state-services-design.md` 字节，用于保持历史证据可复现，**不是当前协议**。

- 字节与 SHA-256：`0187d9c00472a3b794661c450cbf6dd78440268b2ef5ce66d3ff9de54a957abf`，
  80072 bytes，逐字节复制，见 [`../snapshot.json`](../snapshot.json) 的 `design_snapshot`。
- 来源：`9d8373f:docs/design/12-state-services.md`；该 commit 的父提交
  `9d8373f^` 中没有该文件（`d689bf8` 基线也不含该文件），因此只能以 `9d8373f`
  为写入点复现；正文中标注的代码核对基线 `d689bf8` 是测量基线，不是写入 commit。
- 它早于 canonical 架构分支 `codex/state-services-architecture-v2`（`23334bd`/
  `5ef72e3`），仍描述旧 GitFS/Pando 导入与在线 transition 等内容，与当前
  fresh-install-only 双部署契约冲突。
- 合并 PR #124 曾误用此正文覆盖 `docs/design/12-state-services.md`，并覆盖了
  PR142 之后加入的 “Git 传输仅 HTTP/HTTPS” 段落。当前章节已从 canonical 分支恢复
  （含该段落）；本目录只保留历史。

复现：

```bash
git hash-object -t blob docs/design/state-services/historical-w0/state-services-design.md
# 输出 92b22d0c1ff1827ac2da3720d14467b60f0e03f5，与 9d8373f:docs/design/12-state-services.md 相同
```

当前协议见 [第 12 章](../../12-state-services.md)。
