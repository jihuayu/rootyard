# ADR 003: acknowledge an audit gap without inventing push history

Status: phase-two recovery/observability increment. This is a single-node administrative procedure, not distributed failover or storage fencing.

## What resolution means

An unknown push remains unknown forever. Resolution records that an administrator inspected the stopped repository, accepts the missing historical attribution, and chooses the current native Git snapshot as a new baseline. It does not assert that the unknown push succeeded, failed or had no effect. It does not replay a command, create a commit, change a native ref, delete a Git lock, or create successful push events.

The original operation and its evidence become immutable. A separate immutable resolution records the reason, inspected fingerprint, old/new storage generations, volume identity, observed HEAD/refs and covered operation digests. The ref cache explicitly distinguishes `recovery_snapshot` rows from `push_receipt` rows. A snapshot row references a resolution and has no event ID.

## Supported procedure

Upgrade all service and worker binaries before using these commands. Stop the Git-serving process and every uncoordinated writer. The CLI requires the exclusive volume lock inherited by Git children; a surviving receiver prevents admission. Read-only inspection also needs this lock to obtain a stable local snapshot.

1. Run `rootyard reconcile` offline. This imports retained journals and completes any automatically provable receipts. It does not make ambiguous operations successful. Check the resulting repository states.
2. Run `rootyard inspect-recovery REPOSITORY_UUID`. It performs native fsck and returns the exact generation, inspected fingerprint, current refs/HEAD and unknown operation identifiers/digests. Save and review this output.
3. If accepting that specific audit gap is appropriate, run:

   ```sh
   rootyard resolve-unknown REPOSITORY_UUID \
     --expected-generation GENERATION \
     --fingerprint SHA256_FROM_INSPECTION \
     --acknowledge-audit-gap 'Reason for accepting the missing attribution'
   ```

4. Inspect the resolution, then restart the service. New pushes use the increased generation. Owner-authenticated `/api/repos/{owner}/{name}/operations` exposes resolution IDs, `/resolutions` lists bounded summaries, and `/events` identifies operation outcomes and delivery effects. PostgreSQL retains full evidence and snapshots.

Never put credentials or unrelated sensitive data in the reason. Possession of the administrative database credentials and private volume is the authority for this CLI; ordinary HTTP owner tokens cannot invoke it.

## Inspection and transaction barriers

The versioned fingerprint uses deterministic ordered serialization of repository/volume identity, root device/inode, generation, incident revision, recovery state/reason, complete native refs/OIDs, symbolic/detached/unborn HEAD, journal sequence, every unresolved operation's stored row digest and any retained journal evidence/digest. A journal missing at review time is explicit `NULL`, not invented evidence. Duplicate operation IDs, corrupt records, malformed names, mixed operation generations and a missing/rolled-back counter relative to PostgreSQL history are refused. Only `push_outcome_unknown` incidents can be acknowledged here.

Resolution repeats filesystem inspection while holding the volume lock, then acquires the PostgreSQL repository `FOR UPDATE` lock and re-reads every SQL operation and the filesystem before comparing the fingerprint. State changes increment an incident revision even if someone later restores the old state text. Any observed change requires another inspection.

The database transaction records the immutable resolution and covered operations, advances the generation, establishes the snapshot projection and clears only the accepted incident. Candidate events previously attached to unknown history are retained but their deliveries become `discarded_unknown`, with leases invalidated; they do not become successful audit or ref updates. This prevents discarded candidates from permanently blocking later same-ref events.

Consumers acquire repository `FOR SHARE`, then delivery/projection locks. Before acknowledgment they recheck both the claim owner/generation/expiry and unresolved predecessor barriers. Ref-index effects additionally require the event's storage generation to match the repository's current generation. Old events complete as `superseded_generation`, without inserting a ref missing from the snapshot. The database projection trigger independently rejects stale-generation writes. Confirmed historical audit events remain valid historical evidence.

The resolution commit precedes local journal retirement. A retry first looks up the committed `(repository, old generation, fingerprint)` resolution, checks the same reason and volume identity, and resumes only matching journal retirement. It does not apply a second generation change. Startup checks the recorded operation and journal digests before discarding any covered journal. Later receipt files cannot upgrade resolved unknown history to success. Newly discovered or changed evidence is preserved and creates a new blocking incident.

## Limits and incidents requiring another procedure

- This command refuses malformed/corrupt journals and native Git lock files. It never deletes locks or repairs arbitrary filesystem damage. Restore a verified matching backup or use a separately reviewed incident procedure.
- A missing journal can be acknowledged only after fresh inspection, with its absence recorded. If that journal later reappears, the earlier missing-evidence acknowledgment does not authorize its deletion.
- A local counter behind durable PostgreSQL history blocks both inspection and new push admission. Do not reset it to zero or silently allocate old operation sequences.
- Bounds: 64 unresolved operations, 100000 refs, 1024 UTF-8 bytes per ref, 16 MiB native command output and 64 MiB serialized inspection. Oversized or unsupported repositories fail closed.
- Logical journal retirement is durable. A crash after the `.retired-*` rename can leave physical remnants; automatic collection of those remnants is not implemented in this increment. Preserve them or use a reviewed offline maintenance process. Do not describe logical retirement as complete physical garbage collection.
- Private volume ownership and the single native-write entry point are assumptions. The flock does not fence a different machine, an administrator ignoring it, an old PostgreSQL primary or direct filesystem writes. A generation number is not physical storage fencing.
- The procedure establishes an observed current baseline, not a historical or power-loss recovery guarantee. Backups, real storage failover and production RPO/RTO require their own validation.
