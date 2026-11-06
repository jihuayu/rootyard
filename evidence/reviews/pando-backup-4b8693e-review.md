# Pando encrypted backup closure review

Reviewed committed storage commit `4b8693e8f4cf3600979275e26b0c883f7d05114a` in `/workspace/rootyard-storage`. The committed tree is clean (the current working tree was temporarily in a broad merge with conflict markers; storage reports those were resolved after the commit). No Pando native test was independently run in this review; storage reported a live Garage/Vault/PostgreSQL suite with exact test binary SHA `110a94aa6219f714c98aeade67fb1fe9ec7175bb3eba37d2c9425010b6d4b317`.

The new `insert_ready_manifest` transaction correctly takes `SELECT ... FOR SHARE` on the repository row before rechecking owner, storage generation, object format and ready state, then inserts the row before commit. PostgreSQL's row lock conflicts with a non-key storage-generation update's `NO KEY UPDATE` lock, closing the prior check/insert race. The included two-connection test holds a generation update, asserts publication blocks, commits the new generation, then asserts publication fails without a manifest. I found no pack/index pairing issue: independently running Git 2.52 `git --git-dir=<bare> index-pack --verify <pack>` against a valid pack with a deliberately corrupt sibling `.idx` failed with “index file ... is too small.”

## Remaining integration limit: backup snapshot consistency is caller-owned

`backup::inventory` reads repository/Pando state, then each pack row, then refs in separate statements. `export_closure` accepts any `GenericClient` and does not establish or verify repeatable-read isolation or the required shared table/global-GC barriers. Its documentation says the caller must pass a consistent `REPEATABLE READ`/`SHARE`-all-tables backup transaction. A normal `READ COMMITTED` transaction can observe a ref or pack-set change between those statements and produce a mixed manifest unless that caller contract is enforced. The new test starts a default transaction and has no concurrent writer, so it proves encrypted closure copy/delete/import/recover but not snapshot consistency under mutation.

There are no production call sites for `export_closure` or `import_closure` yet. Treat this as a backup primitive with live round-trip evidence, not completed production backup/restore wiring. The later integration must own/enforce the required consistency and GC barrier and add a concurrent ref/pack publication regression before #21 backup closure is accepted.

## Status

`FOR SHARE` generation race fix: reviewed as sound from source and its live PostgreSQL regression design. Backup closure: partial pending integrated snapshot/barrier ownership and concurrent mutation proof. No authenticated gateway cutover is claimed.

## Re-review of `968e745`

`968e745` closes the inventory snapshot concern. `inventory()` now accepts only `repeatable read` or `serializable`, forces an XID before reads, and checks it again after repository/state, pack, and ref queries. A bare `Client` in autocommit cannot pass even if the session's configured default is repeatable-read, because each statement gets a different XID. The native test proves default `READ COMMITTED` export fails before creating a destination and explicitly sets its caller transaction to `REPEATABLE READ` for the encrypted round-trip. Reviewed as sound from source.

The remaining scope is unchanged: no committed production caller for the export/import primitive yet, and its caller must still take the existing global/volume/table barriers that protect remote closure from GC during the network copy. The live suite report described by storage also includes 8 concurrent snapshots and an authorization query, but I have not independently rerun that suite.
