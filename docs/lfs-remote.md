# Remote Git LFS durability

When `ROOTYARD_OBJECT_STORE_ENDPOINT` is configured, a verified LFS upload is
streamed to the configured S3-compatible object store before its metadata is
marked `ready`. The immutable key is scoped to the repository owner's
namespace ID and the SHA-256 digest. A serving node verifies its local copy
before download; if that copy is missing, it fetches and verifies the remote
object. Verification and download use the same authenticated repository role
checks as the LFS Batch API. Clients receive service URLs, not object-store
credentials or pre-signed URLs. Removing a role or revoking a token blocks new
downloads, including on another node.

Without the endpoint, LFS remains on the local data volume and belongs in the
paired database/volume backup. With the endpoint, the remote store preserves
objects between backups. A format-6 paired backup inventories every ready LFS
object and hydrates any missing local copy from the remote store before it
publishes the backup. Restore verifies those bytes and can serve them without
an object-store endpoint. The remote store must remain available during backup
if any ready object's local copy is missing; retain completed paired backups
for recovery if the store is lost afterward.

The service currently exposes no LFS object-delete or garbage-collection API.
Aborted and duplicate uploads cannot delete bytes published by another
request. Ready remote objects must remain available while any Git ref may
reference them; operator cleanup requires reachability and backup-retention
checks before deleting a key.

`ROOTYARD_LFS_POINTER_VERIFY_BYTES` caps the aggregate ready-object bytes
verified for a ref update (512 MiB by default, 8 GiB maximum). Ref publication
fails closed when its verification budget or Git deadline is exhausted.
