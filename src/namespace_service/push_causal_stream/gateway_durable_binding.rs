use deadpool_postgres::Client;
use tokio::time::{Instant as TokioInstant, timeout_at};
use uuid::Uuid;

use super::types::PushCausalError;

/// Exact public-wrapper realm/backend binding proved at the receipt boundary.
pub(super) struct PublicPrivateBinding {
    pub(super) admission_owner_id: Uuid,
    pub(super) object_format: String,
    pub(super) history_incarnation: Uuid,
    pub(super) authority_epoch: i64,
    pub(super) group_epoch: i64,
}

/// Require the supplied private attempt to be the exact **current** attempt of
/// the public wrapper that names the stable public UUID, in the same repository
/// and currently valid realm/backend/restore scope, with its positive terminal
/// event equal to the wrapper event.
///
/// This is the receipt boundary's substitution guard. It reuses migration 152's
/// own current-scope and evidence verifiers, then compares the wrapper's current
/// private id/event with the requested private operation. A different committed
/// private operation, a retired slot-zero attempt, another repository, a
/// pending/cancelled wrapper or a different event cannot produce a receipt.
pub(super) async fn require_public_private_binding(
    client: &Client,
    repository_id: Uuid,
    public_id: Uuid,
    private_id: Uuid,
    backend_hex: &str,
    deadline: TokioInstant,
) -> Result<PublicPrivateBinding, PushCausalError> {
    let schema =
        timeout_at(deadline, client.query_one("SELECT to_regclass('ref_store_public_operations') IS NOT NULL", &[]))
            .await
            .map_err(|_| PushCausalError::DeadlineExceeded)?
            .map_err(|_| PushCausalError::StateMachine("private receipt schema probe failed".into()))?;
    if !schema.get::<_, bool>(0) {
        return Err(PushCausalError::StateMachine("private receipt requires migration 152".into()));
    }

    let wrapper = timeout_at(
        deadline,
        client.query_opt(
            "SELECT w.state, w.event_id, a.private_id,
                    w.admission_owner_id, w.object_format, w.history_incarnation,
                    w.authority_epoch, w.group_epoch, w.backend_identity
               FROM ref_store_public_operations w
               JOIN ref_store_private_attempts a
                 ON a.repository_id = w.repository_id
                AND a.public_id = w.public_id
                AND a.slot = w.current_slot
              WHERE w.repository_id = $1 AND w.public_id = $2",
            &[&repository_id, &public_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|_| PushCausalError::StateMachine("private receipt wrapper read failed".into()))?
    .ok_or_else(|| PushCausalError::StateMachine("private receipt has no current public attempt".into()))?;
    let state: String = wrapper.get(0);
    let wrapper_event: Option<Uuid> = wrapper.get(1);
    let current_private: Uuid = wrapper.get(2);
    let admission_owner_id: Uuid = wrapper.get(3);
    let object_format: String = wrapper.get(4);
    let history_incarnation: Uuid = wrapper.get(5);
    let authority_epoch: i64 = wrapper.get(6);
    let group_epoch: i64 = wrapper.get(7);
    let wrapper_backend: String = wrapper.get(8);
    if !matches!(state.as_str(), "committed" | "rejected") {
        return Err(PushCausalError::StateMachine("private receipt wrapper is not terminal".into()));
    }
    let wrapper_event = wrapper_event
        .ok_or_else(|| PushCausalError::StateMachine("private receipt terminal event is missing".into()))?;
    if current_private != private_id {
        return Err(PushCausalError::StateMachine("private receipt current attempt substitution".into()));
    }
    if wrapper_backend.as_str() != backend_hex {
        return Err(PushCausalError::StateMachine("private receipt backend substitution".into()));
    }

    let scope = timeout_at(
        deadline,
        client.query_one(
            "SELECT rootyard_ref_store_attempt_current_scope(w)
               FROM ref_store_public_operations w
              WHERE w.repository_id = $1 AND w.public_id = $2",
            &[&repository_id, &public_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|_| PushCausalError::StateMachine("private receipt current scope is invalid".into()))?
    .get::<_, i64>(0);
    if scope <= 0 {
        return Err(PushCausalError::StateMachine("private receipt current scope is invalid".into()));
    }

    timeout_at(
        deadline,
        client.query_one("SELECT rootyard_ref_store_verify_public_operation($1,$2)", &[&repository_id, &public_id]),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|_| PushCausalError::StateMachine("private receipt public wrapper verification failed".into()))?;

    let private_event = timeout_at(
        deadline,
        client.query_opt(
            "SELECT event_id FROM ref_store_core_events
              WHERE repository_id = $1 AND operation_id = $2",
            &[&repository_id, &private_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|_| PushCausalError::StateMachine("private receipt event read failed".into()))?
    .ok_or_else(|| PushCausalError::StateMachine("private receipt event is missing".into()))?
    .get::<_, Uuid>(0);
    if private_event != wrapper_event {
        return Err(PushCausalError::StateMachine("private receipt event substitution".into()));
    }
    Ok(PublicPrivateBinding { admission_owner_id, object_format, history_incarnation, authority_epoch, group_epoch })
}

/// Preserve the independently proven legacy-only receipt path on catalogs that
/// may predate migration 152, while refusing to label a public wrapper or a
/// private attempt id as that legacy flow.
pub(super) async fn reject_private_claim_for_legacy_receipt(
    client: &Client,
    repository_id: Uuid,
    public_id: Uuid,
    deadline: TokioInstant,
) -> Result<(), PushCausalError> {
    let schema =
        timeout_at(deadline, client.query_one("SELECT to_regclass('ref_store_public_operations') IS NOT NULL", &[]))
            .await
            .map_err(|_| PushCausalError::DeadlineExceeded)?
            .map_err(|_| PushCausalError::StateMachine("legacy receipt schema probe failed".into()))?;
    if !schema.get::<_, bool>(0) {
        return Ok(());
    }
    let claimed: bool = timeout_at(
        deadline,
        client.query_one(
            "SELECT EXISTS(
                 SELECT 1 FROM ref_store_public_operations
                  WHERE repository_id = $1 AND public_id = $2
             ) OR EXISTS(
                 SELECT 1 FROM ref_store_private_attempts
                  WHERE repository_id = $1 AND private_id = $2
             )",
            &[&repository_id, &public_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|_| PushCausalError::StateMachine("legacy receipt claim probe failed".into()))?
    .get(0);
    if claimed {
        return Err(PushCausalError::StateMachine(
            "legacy receipt cannot resolve a private/public wrapper identity".into(),
        ));
    }
    Ok(())
}
