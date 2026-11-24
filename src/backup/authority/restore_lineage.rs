//! Record lineage only when a verified restore rotates authority.
use anyhow::{Result, ensure};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(in crate::backup) enum RestoreLineage {
    None,
    VerifiedArchive,
    VerifiedW8aSource(Uuid),
}

pub(super) async fn rotate_cluster_incarnation(tx: &Transaction<'_>, lineage: RestoreLineage) -> Result<()> {
    let record_lineage = match lineage {
        RestoreLineage::None => false,
        RestoreLineage::VerifiedArchive => true,
        RestoreLineage::VerifiedW8aSource(source) => {
            // The sealed W8-A sidecar is checked before the guarded inner restore.
            // Pin its intermediate incarnation and require an exact first edge.
            let has_first_edge: bool = tx
                .query_one(
                    "SELECT EXISTS (
                     SELECT FROM public.ref_store_restore_lineage l
                      WHERE l.target_incarnation=(SELECT incarnation FROM public.cluster_authority
                                                  WHERE singleton FOR UPDATE)
                        AND l.source_incarnation=$1
                 )",
                    &[&source],
                )
                .await?
                .get(0);
            ensure!(has_first_edge, "paired restore lineage does not connect to the verified source");
            true
        }
    };
    if record_lineage {
        let added = tx
            .execute(
                "WITH prior AS (
                 SELECT incarnation FROM public.cluster_authority WHERE singleton FOR UPDATE
             ), rotated AS (
                 UPDATE public.cluster_authority c
                    SET incarnation=gen_random_uuid(), rotated_at=clock_timestamp()
                   FROM prior WHERE c.singleton
                RETURNING c.incarnation AS target, prior.incarnation AS source
             )
             INSERT INTO public.ref_store_restore_lineage(target_incarnation, source_incarnation)
             SELECT target, source FROM rotated",
                &[],
            )
            .await?;
        ensure!(added == 1, "restored cluster authority must have one lineage edge");
    } else {
        tx.execute(
            "UPDATE public.cluster_authority SET incarnation=gen_random_uuid(),rotated_at=clock_timestamp() WHERE singleton=true",
            &[],
        ).await?;
    }
    Ok(())
}
