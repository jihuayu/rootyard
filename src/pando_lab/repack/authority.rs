//! Final-target and local-staging helpers for the repack producer.

use super::super::lifecycle;
use super::CompactedPackArtifact;
use anyhow::{Result, bail, ensure};
use std::path::Path;

pub(super) fn remove_staged_local_artifacts(repo_obj_dir: &Path, art: &CompactedPackArtifact) {
    let _ = std::fs::remove_file(repo_obj_dir.join(format!("{}.pack", art.pack_id)));
    let _ = std::fs::remove_file(repo_obj_dir.join(format!("{}.idx", art.pack_id)));
}

/// Bind the actual DB-winning receipt envelope to the target re-read in the
/// final transaction. Existing-pair recovery inside `publish_in` is not proof
/// of a new link to the current rotation pin.
pub(super) fn validate_final_publication_target(
    prepared: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    fresh: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    envelope: Option<&lifecycle::KmsEnvelopeRecord>,
) -> Result<()> {
    match (prepared, fresh) {
        (None, None) => Ok(()),
        (Some(prepared), Some(fresh)) => {
            ensure!(
                prepared.rotation_id == fresh.rotation_id
                    && prepared.state == fresh.state
                    && prepared.write_epoch == fresh.write_epoch,
                "Pando rotation checkpoint changed after repack publication preparation"
            );
            if let Some(envelope) = envelope {
                ensure!(
                    envelope.provider_kind == fresh.to_provider_kind
                        && envelope.key_id == fresh.to_key_id
                        && envelope.key_version == fresh.expected_version(),
                    "the actual published Pando envelope does not match the final rotation target"
                );
            }
            Ok(())
        }
        (None, Some(_)) => bail!("an active Pando rotation checkpoint appeared after repack publication preparation"),
        (Some(_), None) => {
            bail!("the active Pando rotation checkpoint disappeared after repack publication preparation")
        }
    }
}
