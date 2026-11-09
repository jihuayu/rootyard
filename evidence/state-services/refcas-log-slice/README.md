# Isolated Raft log storage verification

Source commit: `7422754481715cca8bbcf28db08078b5e6460b22`. `inputs.json` binds the independent crate and workflow
by SHA-256. The evidence-only commit adds no production inputs.

The pinned Rust 1.99.1 format check, strict all-target Clippy, nine unit tests
and one real SIGKILL/fresh-process vote recovery test passed with zero skips.
See `checks.log`. No external PostgreSQL, S3 or network service is used by this
suite.

Development and independent source review used the official DeepSeek dsh CLI
through [jihuayu/skills deepseek-subagent](https://github.com/jihuayu/skills/tree/main/deepseek-subagent).
The reviewer approved the log-only contract, including native openraft callback
ordering, full versus limited reads, exact purged log IDs, checksums and owned
child cleanup. Root checked the findings and corrected an entry-limit error
message before the recorded gates. The reviewer did not execute tests; Root
ran the recorded commands. Model sessions and connection settings are private
and are not part of this evidence.

This does not establish state-machine/snapshot/RPC integration, a three-host
quorum, Git ACK durability or power-loss durability. It does not complete
#149 or #115. The production Rootyard workspace does not depend on this crate.
