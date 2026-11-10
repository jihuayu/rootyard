# Bounded cache/wake component qualification

This advances #111 under #105; production serving-cache consumers and the complete
standalone/distributed profiles remain unwired. Redis stays advisory; refs,
authorization, durable tasks/results and retained roots never become Redis data.

The library receipt binds clean bb47221, source inputs, Cargo.lock, rustc1.99.1,
exact flags and executable70b9c912721e7762bc1730e5c239d908cbe0ad4752bce5e0cde22c0a644782aa.
Later merges/evidence changes do not change those compiled inputs. The source and
executable still matched after native execution. Root-package debug symbols and
dependency debug sections in the linked test executable were stripped; actual
Cargo flags are in the receipt.

274 library cases passed;14 service-dependent cases were explicitly ignored
in that ordinary run. The cache-specific run passed21 and explicitly ignored
six. All six selected real-Redis cases then passed with zero ignored cases over
plaintext loopback and again over verified private-CA TLS. They cover normal
bounded reads, oversize refusal, FLUSHALL miss, bad ACL credentials/redaction,
unsafe policy rejection/restoration, advisory wake and actual driver teardown
after blackholed replies/caller abort while keeping the cache alive. The proxy
records forwarding only after successful backend writes and parses no protocol.

An untrusted CA intentionally produced exactly one failed case, then restoring
only the child-process trust environment passed that same case. This is a
negative-control security check, not a successful Rust test disguised as a pass.

The fixture was an owned loopback Redis7.4.2 server built from official tag
a0a6f23d997b024689ba157916837f493a593a34, with finite32MiB maxmemory, eviction,
default ACL user disabled and ephemeral CA. The report records its binary SHA,
PID/starttime and scope. Its task user allows CONFIG and destructive test
commands; this is not least-privilege production ACL, HA/Sentinel/Cluster,
physical-failure or production performance qualification. No secrets are evidence.

Luna Max closed the shared-manager cancellation leak after the exclusive idle
pool/owned wake connection change. All-target Clippy with pando-lab,state-redis
and warnings denied passed on17cfb6f; the subsequent Rust change only moved the
test proxy notification after backend forwarding and was rebuilt/retested above.

The checked-in CI runner was also executed locally on clean b0eb1a1 with an
owned official redis:7.2.6-alpine container, immutable image digest
redis@sha256:311acd7daf1c5ed17a8d275a3e3711be8081dbb89765c3524829b62b91ce1868.
`docker-redis72-contract.json` binds its fresh library executable, source,
Cargo.lock, rustc and command. Six cases passed over plaintext, six over
private-CA TLS, one negative CA case failed as required, and restored trust
passed. Zero cases were ignored in all four runs, no failure remained, and the
runner removed only its owned container. Twenty focused runner unit tests also
passed, including ambiguous-create cleanup and secret redaction. Full GitHub
Actions results are still required; this is not the complete #111 profile.
