# Workspace 与 Git 预研记录

> 状态：2026-11-03 的历史实验记录；保留环境和未验证边界，不等同于当前产品保证。
> [设计目录](README.md) · [实现状态](implementation-status.md) · [来源与完整归档](source-page.md)

<!-- BEGIN SOURCE BODY -->
# Rootyard 预研实测记录 2026 年 11 月 3 日

## MacBook OrbStack Docker 工作区

环境是 macOS ARM64、OrbStack Docker；Git 实验在 amd64 模拟镜像中，文件发布实验另用原生 ARM64 容器。未提升容器权限，普通容器没有 /dev/fuse 和 CAP_SYS_ADMIN，未验证真实 FUSE 或 Docker Desktop；不据此比较性能。

第一轮：bind mount 与 Linux named volume 均能保持 HEAD/index/working tree 的部分暂存；tracked 文件即使匹配 ignore 仍跟踪，git add -f 生效。Mac bind mount 不区分大小写而 Linux volume 区分。Mac 侧快速写入经 bind mount 后内容最终可读，但容器内 watcher 事件不完整；容器内操作本次观察到事件。git status 可能刷新 index 字节，观察性调用使用 GIT_OPTIONAL_LOCKS=0 并验证具体行为。多文件扫描可读到混合版本；单文件原子替换不等于完整工作区快照。

第二轮：同 checkpoint 完整复制得到两个独立 .git 工作区，一方修改暂存提交后另一方及源状态不变；验证的是完整复制，不是 COW。跨容器恢复完整保留 HEAD、index 及工作树三种不同状态、被跟踪/强制添加文件和删除状态，未跟踪 ignored 文件未恢复。故意丢失 watcher 事件后扫描可修复最终路径、内容、mode 和 symlink 目标，rename 表现为删除加新增；空窗内创建后删除的文件历史无法恢复，未测空窗内 index 变化。

进程级 checkpoint 实验在所有写者遵守同一 mutex 时可暂停写入；外部 Git 或编辑器不受该 mutex 约束，不构成生产全写者屏障。临时目录未发布即退出时旧 LATEST 仍可恢复，原子切换后新 checkpoint 可读。原生 ARM64 文件级补测通过，但未验证 fsync、断电、VM 崩溃、跨主机持久性、增量 checkpoint、多写者和 COW。忽略规则不构成 Git 历史对象的保密边界。

## 云端 PostgreSQL 与 Git Smart HTTP

环境：Git 2.56.0 官方源码隔离编译，使用 NO_RUST 等构建选项；PostgreSQL 17.11 和 psycopg 3.3.7；HTTP 与数据库均限 loopback，PG trust 与测试角色头仅用于隔离虚构数据。不是生产认证实现。

proc-receive 只写外部 refs 并返回成功时，原生 push 可成功但 ls-remote 不见分支、fetch 失败；原生 Git 读取端也需适配。pre-receive 在 quarantine 中不能 update-ref；proc-receive 拒绝后已迁移对象可能仍保留；atomic 回滚外部事务必须自己实现。

以 PG 为原型权威、每请求临时物化 Git 对象/refs 并复用 git-http-backend，原生 Git Smart HTTP push、clone、fsck 通过；同 old OID 并发 CAS 一胜一败，多 ref atomic 成功及回滚、提交前进程崩溃回滚、提交后丢 ACK 恢复、分支删除和 tag peel 通过。PG immediate shutdown 后 WAL recovery，随后 clone/fsck 通过。匿名读取以及测试 reader 的 receive-pack GET/POST 均被拒绝；这不等于完成生产多租户安全验收。

HTTP 的发现与 fetch 会跨请求：逐请求取最新 refs 时，发现后分支删除会产生 not our ref。原型使用首次 302 到限期只读快照 URL，Git 2.56 跟随，后续删除仍可完成 clone，新的会话能看到删除，快照 URL 拒绝 push。只证明该实验，不证明所有 Git 客户端、代理、缓存、权限撤销或过期时序均可靠；生产方案需设计会话身份绑定、每次授权、快照和对象 pin、TTL/续期、泄露防护、终止与 GC，并测试客户端/代理兼容。历史保留和失败重试仍是备选，不能仅要求 cookie 或粘性会话。

对象访问实验显示，Git protocol v2 可按已知 OID 获取对象库中不被 refs 指向的对象；隐藏 refs/namespace 不是保密边界。原型只暴露授权 ref 的可达闭包时，孤立对象 fetch 被拒。完整多租户授权、侧信道、tag 和历史组合仍需测试。

## 剩余预研与验收

尚未覆盖：TLS/SSH、生产身份授权、多租户全面安全、实际对象存储、性能与大仓物化成本、PG HA/failover、完整 Git 兼容矩阵、真实 FUSE、强写屏障、断电恢复。数据库和 HTTP 测试服务已关闭；Mac 的实验使用任务专用目录和 volume，未更改现有项目或安全设置。
<!-- END SOURCE BODY -->
