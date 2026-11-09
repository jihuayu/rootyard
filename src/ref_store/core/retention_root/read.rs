//! `materialize`: the only byte-read path for a retained root.
//!
//! A root read is deliberately **not** the A5b snapshot read: the source pin may be expired, released or its
//! snapshot pruned, so this path re-reads only the root's own retained rows.
//!
//! 1. T1 (short bounded tx, pooled client released before any IO): read the complete retained capture and prove
//!    its binding digest; require an `active` head and that the caller's asserted realm equals the stored realm.
//! 2. Native (no PostgreSQL): the shared private `NativeReadEngine` (same global native 2 / view 2 permits and
//!    the same workspace bound) downloads every retained pack/idx with a verified Blob GET, writes the exact
//!    captured refs plus synthetic non-branch root refs, an exact HEAD (or unborn HEAD) and runs `fsck`.
//! 3. T2 (fresh short bounded tx): the live core gate row must still exist and match the root realm (current
//!    repository authority), the head must still be `active`/generation 1 with the same register digest, and the
//!    complete retained binding must be unchanged. Only then is the opaque view built, and it is returned only
//!    after a successful bounded rollback that also runs when sealing itself refuses.
//!
//! Both transactions take the local `statement_timeout`/`lock_timeout` bound from the same absolute deadline
//! *before* their first query, run every SQL stage under that deadline, and clean up under it as well.
use super::capture::RawCapture;
use super::error::RootError;
use super::handle::RootReadRequest;
use super::pg::{before_deadline, bound_tx, effective_deadline, pooled_client, rollback_reads};
use super::view::RootReadView;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{NativeReadRequest, PackCommitError};
use crate::ref_store::tx::begin_bounded;
use deadpool_postgres::Pool;
use tokio::time::Instant;

impl super::pg::PgRetentionRoots {
    /// Materialize one retained root as an opaque owned read view.
    pub async fn materialize(
        &self,
        pool: &Pool,
        request: RootReadRequest,
        deadline: Instant,
    ) -> Result<RootReadView, RootError> {
        let deadline = effective_deadline(deadline)?;
        let root = request.root();
        let authority = *request.authority();

        // (T1) Retained rows only; no source pin, no source snapshot, no gate liveness requirement yet.
        let (capture, binding) = self.read_retained(pool, root, deadline).await?;
        if capture.header.object_format != authority.object_format()
            || capture.header.history_incarnation != authority.history_incarnation()
            || capture.header.authority_epoch != authority.authority_epoch()
            || capture.header.group_epoch != authority.group_epoch()
            || capture.header.tenant_id != authority.tenant_id()
        {
            return Err(RootError::RootRealmMismatch("root byte read asserted realm"));
        }

        let native_set = capture.native_refs()?;
        let binding_hex = binding.as_hex();
        let native = self
            .engine()
            .materialize(
                &NativeReadRequest {
                    format: capture.header.object_format,
                    head_ref: &capture.header.head_ref,
                    head_oid: capture.header.head_oid.as_deref(),
                    refs: &native_set,
                    packs: &capture.packs,
                    read_digest: &binding_hex,
                },
                deadline.into_std(),
            )
            .await
            .map_err(map_native_error)?;
        if native.read_digest() != binding {
            return Err(RootError::RootClosureUnproven("native closure binding differs from the retained root"));
        }
        if native.verified_pairs() != capture.packs.len() {
            return Err(RootError::RootClosureUnproven("native closure did not cover every retained pack"));
        }
        if native.retained_bytes(deadline.into_std()).await.map_err(map_native_error)?
            > crate::ref_store::core::pack_commit::contract::VERIFIER_VIEW_MAX_LOGICAL_BYTES
        {
            return Err(RootError::RootClosureUnproven("materialized root view exceeds the workspace bound"));
        }

        // (T2) Fresh short transaction: current authority + active root + unchanged retained binding.
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let checked = before_deadline(deadline, async {
            let gate = super::sql::gate_realm(&tx, root.repository_id(), false)
                .await?
                .ok_or(RootError::RootAuthorityRequired("the repository is deleted or has no core gate"))?;
            super::sql::require_realm(
                &gate,
                &capture.scope()?,
                capture.header.object_format,
                capture.header.history_incarnation,
                capture.header.authority_epoch,
                capture.header.group_epoch,
                "root byte read gate realm",
            )?;
            let head = super::sql::head_for_share(&tx, root.repository_id(), root.root_id()).await?.ok_or(
                RootError::RootReleased { repository_id: root.repository_id(), root_id: root.root_id(), generation: 2 },
            )?;
            if !head.is_active() {
                return Err(RootError::RootReleased {
                    repository_id: root.repository_id(),
                    root_id: root.root_id(),
                    generation: head.last_generation,
                });
            }
            if head.register_digest != capture.header.register_digest {
                return Err(RootError::RootDigestConflict("root head register digest changed"));
            }
            let fresh = super::sql_read::read_capture(&tx, root)
                .await?
                .ok_or(RootError::RootNotFound { repository_id: root.repository_id(), root_id: root.root_id() })?;
            let fresh_binding = fresh.binding_digest()?;
            if fresh_binding != binding {
                return Err(RootError::RootDigestConflict("retained root binding changed during materialization"));
            }
            Ok::<_, RootError>(fresh)
        })
        .await;
        // Resolve the seal refusal here, then always take the bounded rollback before either value or error is
        // returned: an early `?` must never skip the cleanup.
        let sealed = checked.and_then(|fresh| RootReadView::seal(fresh, native, binding));
        let cleanup = rollback_reads(tx, deadline).await;
        drop(client);
        match (sealed, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(view), Ok(())) => Ok(view),
        }
    }

    /// T1 retained read: head state + complete capture + binding proof, in one short bounded transaction.
    async fn read_retained(
        &self,
        pool: &Pool,
        root: super::handle::RootRef,
        deadline: Instant,
    ) -> Result<(RawCapture, RequestDigest), RootError> {
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let read = before_deadline(deadline, async {
            let head = super::sql::head_state(&tx, root.repository_id(), root.root_id()).await?;
            let capture = super::sql_read::read_capture(&tx, root).await?;
            Ok::<_, RootError>((head, capture))
        })
        .await;
        let result = read.and_then(|(head, capture)| {
            let capture = capture
                .ok_or(RootError::RootNotFound { repository_id: root.repository_id(), root_id: root.root_id() })?;
            let head = head.ok_or(RootError::RootReleased {
                repository_id: root.repository_id(),
                root_id: root.root_id(),
                generation: 2,
            })?;
            if !head.is_active() {
                Err(RootError::RootReleased {
                    repository_id: root.repository_id(),
                    root_id: root.root_id(),
                    generation: head.last_generation,
                })
            } else if head.register_digest != capture.header.register_digest {
                Err(RootError::RootDigestConflict("retained root head/header disagree"))
            } else {
                let binding = capture.binding_digest()?;
                Ok((capture, binding))
            }
        });
        let cleanup = rollback_reads(tx, deadline).await;
        drop(client);
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

fn map_native_error(error: PackCommitError) -> RootError {
    RootError::from(error)
}
