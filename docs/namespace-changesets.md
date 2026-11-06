# Namespace Git Views and ChangeSets

An authorized namespace pins each repository mount to a source commit. A View
projects one mount subdirectory into a stock Git repository and exposes a Git
bundle. The bundle's projected commit is reproducible from the pinned source.
Readers need repository read access to every mount; write access is required to
submit a source proposal.

To propose an edit, clone the View bundle, commit on its projected branch, and
create a bundle containing that branch. Submit it to
`POST /api/views/{view_id}/changesets` with `bundle_base64`,
`bundle_ref`, `source_ref`, and `message`. The service verifies that the
candidate descends from the pinned projected commit, checks Git objects, and
replaces only the mapped source subtree. Requests are limited to a 16 MiB
bundle, 100,000 new objects, 256 MiB summed new-object size, 16 MiB Git
command output, and 60 seconds per Git process group. Each process has memory,
CPU, and file-size limits; staged Git storage is checked at 512 MiB after
bundle import. These checks do not provide a strict aggregate temporary-disk
quota during import. The service records a
new source commit without advancing the source branch. A protected
`refs/heads/rootyard-proposals/*` branch pins the source commit for review.
If the source branch has advanced past the View's pinned source commit, the
proposal conflicts and does not update that branch.

A ChangeSet can contain up to 32 source repository ref updates. The creator
proposes it; a different user with maintain access to every source repository
reviews it. Integration requires current write access and passes each
`old_oid` and storage generation to the platform's protected ref-transaction
entrypoint. The order is recorded in `workspace_changeset_steps`.

**Reader visibility is per repository.** Rootyard does not claim a native Git
transaction across repositories. A reader may see the first updated ref while
the ChangeSet is `integrating` or `partial`; the ChangeSet becomes
`complete` only after every step is recorded as applied. Consumers that need
the complete BaseVector must check `GET /api/changesets/{id}` and wait for
`complete`. A service crash releases the database integration lock. An
authorized `POST /api/changesets/{id}/recover` checks each live Git ref: an
already updated ref is recorded as applied, an expected old ref is retried
through the protected entrypoint, and a different ref becomes `conflict`.
Concurrent integrators are serialized by a transaction-scoped advisory lock.

The current reverse importer needs the source bare repository and View storage
on the handling node. Remote routing of these Git objects and automatic
retention cleanup of proposal pin branches remain deployment work. The
namespace API currently creates an immutable revision 1; advancing a
namespace revision with history-preserving reprojection is not exposed.
