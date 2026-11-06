# Independent local-host takeover and partition review

Reviewed `/workspace/rootyard-cluster` through `fdcfc8e` and `375153d`, native binary SHA-256 `e0f475a5b1d7b52d54bf8464abf28ef05de6ba61808842c98ed1978fea283956`.

- `cluster_takeover_native.py` — PASS: stale replica rejected; SIGSTOP/admitted Git writer prevented promotion until physically fenced; process group killed, durable restart barrier checked; prior ACKed tip remained fetchable; target `git fsck` passed; target accepted a new ACKed push. Measured 4.639s.
- `cluster_partition_native.py` — PASS: source-only PostgreSQL TCP proxy and active sockets cut; source failed closed, its process session was killed, target promoted with prior ACK preserved, then target accepted a new push. Measured 4.735s.
- Code review of `fdcfc8e`: promotion commits the route/marker transition while holding the repository lock, drops the lock, then reconciles the pending marker. This avoids re-entering the same lock and relies on the pending transition to block pushes until publication. The tests exercise a post-promotion push.
- `cluster_pg_streaming_native.py` — PASS against the same binary and PostgreSQL 17.11; it asserts `SHOW synchronous_commit=remote_apply`, sync standby state, prior acknowledged commit preservation, and post-promotion push/fetch. RTO 566ms read / 754ms write. Report `/workspace/shared/reviews/cluster-pg-streaming-abf7113-independent.json`.
- `cluster_kafka_tls_native.py` — PASS against official Apache Kafka 3.9.1 archive after verifying its published SHA-512. Wrong CA, hostname, and PLAIN password were rejected; live Rootyard emitted wake offsets 2 to 3, continued Git writes during broker outage, and emitted a new wake after restart. Report `/workspace/shared/reviews/cluster-kafka-abf7113-independent.json`. The harness proves reconnection/new-event delivery, not separate draining of the outage-period wake.

The absent-durable-route guard in 375153d is correct by inspection at both HTTP pre-push and native hook paths. These four integration tests exercise configured routes; no dedicated native test was present for deleting a route after registering multiple shard nodes and then proving push rejection. Add that regression before using this commit as acceptance evidence for the new guard.

All reported takeover results are limited to this single-host process/session fence. They do not establish cross-host storage fencing or PostgreSQL automatic failover.
