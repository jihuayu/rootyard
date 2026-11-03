# ADR 001: native Git authority on one durable node

Status: phase-one storage authority decision, retained in phase two. See [ADR 002](reliability.md) for the implemented durable evidence/outbox increment.

## Decision

PostgreSQL stores identities, hashed credentials, owner/name uniqueness, repository location metadata and provisioning state. A native bare Git repository on the assigned durable local volume stores the authoritative refs and objects. Rootyard authenticates requests and runs the native Smart HTTP backend without translating packs or implementing commits on the server.

Names are logical identifiers, not filesystem paths. Storage is keyed by server-generated repository identity. The volume is private to the service, not writable by repository owners. Native Git performs ref compare-and-swap and quarantine handling. The service must not publish refs by editing ref files itself.

One serving process owns a volume lock, inherited by Git children so a surviving receiver retains the lock if the parent is killed. This prevents accidental duplicate local service instances; it is not a distributed lease, fencing protocol or network-filesystem HA design. There is one node and one storage authority. Placement metadata is not a live remote-backend implementation.

## Provisioning and recovery

A repository is first recorded durably as provisioning. Its bare repository is initialized in staging, then published into the durable namespace and marked ready. Startup and periodic recovery resume interrupted provisioning. The durable row includes `provision_attempts` and `next_retry_at`; each scan selects at most 64 due entries and applies a 30-second retry backoff. Under the exclusive volume lock, recovery may rebuild only an unpublished `.init` staging directory, including one left with `config.lock`. Published repositories are not silently rebuilt or stripped of lock files. A duplicate create request uses the existing owner/name identity rather than allocating another repository.

Git and PostgreSQL do not share a transaction. Phase two adds durable operation evidence, successful-subset receipts and explicit unknown outcomes, not an atomic transaction spanning both stores or an unconditional complete audit guarantee. See [ADR 002](reliability.md). An HTTP error or disconnect does not prove a push failed; never blindly replay it.

Process-kill restart recovery is not a proof of power-loss durability. Git fsync settings, mount behavior, device cache and persistent storage contracts matter independently. A filesystem rename does not by itself prove data is durable on physical media.

## Transport and isolation

REST creates and lists repository metadata. Smart HTTP uses native Git's upload-pack and receive-pack. The service streams bodies and process output under configured limits instead of buffering a whole pack. Children have resource limits and deadlines. A producer task drives the transfer independently of downstream response polling, so a stalled reader cannot suspend the deadline. Normal cancellation signals the process group with TERM, allows one second of grace, then uses KILL; process-group identity remains tracked until the leader is reaped. Streaming gzip/x-gzip decoding limits both encoded and expanded bytes; unsupported content encodings are rejected. Capacity limits can reject work, so clients must handle rejection and retry only after observing ambiguous push outcomes.

Tokens are random bearer secrets with digests stored in PostgreSQL. Basic authentication binds the supplied username to the token owner. Read-only and read/write tokens operate across that owner's repositories. This is repository-level authorization, not branch-level isolation. Historical, dangling and otherwise unreachable objects must be treated as readable by repository readers.

Non-fast-forward branch updates are disabled. The service does not implement branch protection policies, review gates, server-side commit creation, user-controlled hooks or shell commands.

## Deliberately absent

No UI, Git LFS, VFS, online object storage, PostgreSQL refs authority, multi-node routing, HA, disaster-recovery automation, external notifications or online backup scheduler. The implemented PG outbox and local projections are described separately; no memory-only durable queue exists. No cache or queue is introduced merely to satisfy an architectural checklist; a measured need should justify either. Future work must preserve one explicit authority per repository and make cross-store consistency limits visible.
