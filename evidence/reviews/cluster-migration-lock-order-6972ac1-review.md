# Cluster staged migration independent review

Reviewed commit `6972ac1aafa20dccd142442de2928562d3026489` in `/workspace/rootyard-cluster`.

The lock sequence is consistent: source takes a PostgreSQL shared data lease, local maintenance gate, then writer mutex; after durably setting `repository_shard_routes.draining=true`, it snapshots the source, releases those barriers before contacting the target, then reacquires the exclusive PG/local barriers before cutover. The target snapshot endpoint takes the same exclusive ordering before staging and installing. This avoids holding the source lease while waiting for the target exclusive install.

Independent native test run:

```
source /workspace/shared/rootyard-env.sh
python3 tests/cluster_migration_native.py --binary target-cluster/debug/rootyard --report /workspace/shared/reviews/cluster-migration-lock-order-6972ac1-independent.json
```

PASS against PostgreSQL 17.11. The report binds to binary SHA-256 `5031928229726503335b0b55209d1c02f4232abced58bc6532a915e8eb705543` and harness SHA-256 `1721ac662b175c2e25007d03d1a52ce91ec09dea03c52e7b65872b7ba0369984`. It exercised partial-copy rejection before cutover, same-operation resume after target restart, ahead-journal rejection without replacing the target sentinel, source drain after failed transfer, target-exclusive wait for a live reader, browse from retired ingress, and post-cutover push.

No blocking finding in this commit. A failed transfer deliberately leaves the source route drained until the same operation is resumed. Scope remains one PostgreSQL authority and two Rust processes on one Linux host; it does not prove physical cross-host fencing.

## Re-review: `d720bec`

`d720bec` fixes the cross-repository operation UUID issue by checking the prior row's `repository_id` before committing the drain. It also uses the full exclusive order `PG data lease -> local maintenance gate -> PG repository publication fence -> local writer mutex`, so the drain starts only after active ref-publication windows finish. I independently reran the expanded native harness against the matching binary SHA `678f815c461618eb3ae7ca51e7d957e04028d54e72509c5f1ac5b6cb5dcaa080`; PASS against PG 17.11. Report: `/workspace/shared/reviews/cluster-migration-publication-d720bec-independent.json`. The test covers a second repo reusing the UUID with matching placement values and asserts 409 plus `draining=false` and no operation row, alongside migration, transfer retry, reader wait, and post-cutover cases.

The operation-ID finding is closed. No further blocking issue found in `d720bec`. Scope remains a single-host two-process run; cross-host physical fencing remains external.
