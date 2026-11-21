//! Active GitView binding lookup for the reverse importer.
use crate::{AppState, Error, namespace_service::views::View};
use uuid::Uuid;

pub(super) struct Binding {
    pub(super) root_id: Uuid,
    pub(super) source_oid: String,
    pub(super) projected_oid: String,
    pub(super) subdir: String,
    pub(super) owner_tenant_id: Uuid,
    pub(super) storage_generation: i64,
}

pub(super) async fn load_binding(state: &AppState, view: &View) -> Result<Binding, Error> {
    crate::ci_pins::s4_schema::ensure_s4_schema(&state.pool).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let cluster_inc = crate::ci_pins::s4_authority::require_cluster_incarnation_nowait(&tx).await?;
    let row = tx
        .query_opt(
            "SELECT b.retention_root_id, b.source_oid, b.projected_oid, b.subdir, b.owner_tenant_id, \
                    r.owner_id, r.storage_generation, r.state \
             FROM s4_ci_retention.git_view_bindings b JOIN repositories r ON r.id=b.repository_id \
             JOIN ref_store_core_gates cg ON cg.repository_id=b.repository_id \
             WHERE b.view_id=$1 AND b.state='active' AND b.repository_id=$2 \
               AND cg.authority_epoch=b.authority_epoch \
               AND cg.history_incarnation=b.history_incarnation AND cg.group_epoch=b.group_epoch \
               AND b.cluster_incarnation=$3",
            &[&view.id, &view.repository_id, &cluster_inc],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let _ = tx.rollback().await;
    drop(client);
    if row.get::<_, String>(7) != "ready" || Some(row.get::<_, Uuid>(5)) != Some(row.get(4)) {
        return Err(Error::not_found());
    }
    Ok(Binding {
        root_id: row.get(0),
        source_oid: row.get(1),
        projected_oid: row.get(2),
        subdir: row.get(3),
        owner_tenant_id: row.get(4),
        storage_generation: row.get(6),
    })
}
