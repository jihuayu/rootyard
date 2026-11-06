//! Native-directory, full-copy and incremental-sync workspace experiment. All writers
//! must be stopped by the caller. The store lock cannot fence editors, Git or arbitrary processes.
#[path = "workspace_lab/core.rs"]
mod core_inner;
#[rustfmt::skip]
pub mod core { pub use super::core_inner::*; pub(crate) fn private_dir(p: &std::path::Path) -> anyhow::Result<()> { if let Some(d) = p.parent() && !d.as_os_str().is_empty() && !d.exists() { private_dir(d)?; } super::core_inner::private_dir(p) } }
#[path = "workspace_lab/crash_recovery.rs"]
pub mod crash_recovery;
#[path = "workspace_lab/fuse_mount.rs"]
pub mod fuse_mount;
#[path = "workspace_lab/ignore.rs"]
pub mod ignore;
#[path = "workspace_lab/manifest.rs"]
pub mod manifest;
#[path = "workspace_lab/namespace.rs"]
#[rustfmt::skip]
pub mod namespace;
#[path = "workspace_lab/remote.rs"]
pub mod remote;
#[path = "workspace_lab/security.rs"]
pub mod security;
#[path = "workspace_lab/sync.rs"]
pub mod sync;
#[path = "workspace_lab/vfs.rs"]
#[rustfmt::skip]
pub mod vfs;
#[path = "workspace_lab/view.rs"]
pub mod view;
#[path = "workspace_lab/writable_view.rs"]
#[rustfmt::skip]
pub mod writable_view;

use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsString, path::Path};

pub use self::core::{
    Entry, MAX_BYTES, MAX_ENTRIES, MAX_MANIFEST, Manifest, SCHEMA, Staging, Store, Workspace,
};
pub use crash_recovery::{
    CrashDrillReport, CrashJournal, CrashJournalEntry, CrashRecoveryReport, OverlayMountManifest,
    OverlayOpReport, OverlayStatusReport,
};
pub use ignore::{IgnoreMatcher, PathClass, WorkspaceClassification};
pub use manifest::{Changeset, ChangesetEntry, DirtyEntry, WorkspaceStatus};
pub use namespace::{
    BaseVectorEntry, NamespaceGitViewReport, NamespaceManifest, NamespaceViewReport,
};
pub use remote::{
    RemoteCheckpointManifest, RemoteDirtyManifest, RemotePullReport, RemotePushReport,
};
pub use sync::{ApplyReport, SyncDirtyReport};
pub use vfs::{
    VfsCatalogEntry, VfsDirtyEntry, VfsEvictReport, VfsHydrateReport, VfsMountManifest,
    VfsStatusReport,
};
pub use view::ReadonlyViewReport;
pub use writable_view::{AgentLeaseEntry, CrossRepoCommitReceipt, NamespaceWriteReport};

const USAGE: &str = "usage: rootyard-workspace-lab \
init STORE SOURCE AGENT BASE_OID --quiescent | \
checkpoint STORE WORKSPACE_ID --quiescent | \
restore STORE CHECKPOINT_ID AGENT | \
inspect STORE WORKSPACE_ID | \
status STORE WORKSPACE_ID | \
changeset STORE BASE_CHECKPOINT_ID SOURCE_CHECKPOINT_ID | \
apply STORE WORKSPACE_ID CHANGESET_ID --quiescent | \
sync-dirty STORE SOURCE_WORKSPACE_ID [TARGET_WORKSPACE_ID] --quiescent | \
verify-readonly-view STORE CHECKPOINT_ID [VIEW_PATH] | \
push-remote STORE WORKSPACE_OR_CHECKPOINT_ID REMOTE_CAS_DIR [--quiescent] | \
pull-remote STORE REMOTE_CAS_DIR CHECKPOINT_ID AGENT | \
namespace-mount STORE NAMESPACE_NAME MOUNT_PATH=CHECKPOINT_ID... | \
verify-namespace STORE NAMESPACE_ID [VIEW_PATH] | \
namespace-git-view STORE NAMESPACE_ID [VIEW_PATH] | \
vfs-mount STORE CHECKPOINT_ID AGENT [--remote-cas CAS_DIR] [--inline-threshold BYTES] [--hydrate-pattern GLOB...] | \
vfs-hydrate STORE VFS_ID [PATH_OR_GLOB...] [--cow-write CONTENT_OR_FILE] [--prewarm] | \
vfs-status STORE VFS_ID | \
vfs-evict STORE VFS_ID [PATH_OR_GLOB...] [--quiescent] [--skip-dirty] | \
agent-lease STORE NAMESPACE_OR_WS_ID AGENT_ID ACTION [--prefix REL_PATH] [--ttl-secs SECS] [--epoch EPOCH] | \
namespace-write STORE NAMESPACE_ID AGENT_ID REL_PATH CONTENT_OR_DELETE [--lease-epoch EPOCH] | \
namespace-commit-back STORE NAMESPACE_ID AGENT_ID [--quiescent] [--lease-epoch EPOCH] | \
overlay-mount STORE CHECKPOINT_ID AGENT_ID [--remote-cas CAS_DIR] | overlay-op STORE OVERLAY_ID OP_KIND [ARGS...] | \
overlay-write STORE OVERLAY_ID REL_PATH CONTENT_OR_FILE | overlay-delete STORE OVERLAY_ID REL_PATH | \
overlay-rename STORE OVERLAY_ID SRC_REL_PATH DST_REL_PATH | overlay-chmod STORE OVERLAY_ID REL_PATH MODE_OCTAL | \
overlay-git-add-f STORE OVERLAY_ID REL_PATH | overlay-status STORE OVERLAY_ID | \
crash-drill STORE TARGET_ID WINDOW [--quiescent] | crash-recover STORE TARGET_ID";

#[rustfmt::skip]
pub fn run(args: Vec<OsString>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "workspace lab requires Linux");
    let command = args.first().and_then(|x| x.to_str()).context(USAGE)?;
    match command {
        "init" => ensure!(args.len() == 6, "{USAGE}"),
        "checkpoint" | "restore" | "changeset" => ensure!(args.len() == 4, "{USAGE}"),
        "inspect" | "status" | "vfs-status" | "overlay-status" | "crash-recover" => ensure!(args.len() == 3, "{USAGE}"),
        "apply" | "pull-remote" => ensure!(args.len() == 5, "{USAGE}"),
        "sync-dirty" => ensure!(args.len() == 4 || args.len() == 5, "{USAGE}"),
        "verify-readonly-view" | "verify-namespace" | "namespace-git-view" => ensure!(args.len() == 3 || args.len() == 4, "{USAGE}"),
        "push-remote" => { ensure!(args.len() == 4 || (args.len() == 5 && args[4] == "--quiescent"), "{USAGE}"); }
        "namespace-mount" | "vfs-mount" | "vfs-hydrate" | "vfs-evict" | "namespace-commit-back" | "overlay-mount" | "overlay-op" | "overlay-delete" | "overlay-git-add-f" | "crash-drill" => ensure!(args.len() >= 4, "{USAGE}"),
        "agent-lease" | "overlay-write" | "overlay-rename" | "overlay-chmod" => ensure!(args.len() >= 5, "{USAGE}"),
        "namespace-write" => ensure!(args.len() >= 6, "{USAGE}"),
        _ => bail!(USAGE),
    }
    if matches!(command, "init" | "checkpoint" | "apply" | "sync-dirty") {
        ensure!(args.last().is_some_and(|x| x == "--quiescent"), "stop ALL writers and explicitly pass --quiescent; this is a caller assumption, not a write barrier");
    }
    if command == "init" { self::core::check_source_store_overlap(&args[1], &args[2])?; }
    let store = Store::open(Path::new(&args[1]))?;
    let result = match command {
        "init" => store.cmd_init(&args[2], &args[3], &args[4])?,
        "checkpoint" => store.cmd_checkpoint(&args[2])?,
        "restore" => store.cmd_restore(&args[2], &args[3])?,
        "inspect" => store.cmd_inspect(&args[2])?,
        "status" => manifest::cmd_status(&store, &args[2])?,
        "changeset" => manifest::cmd_changeset(&store, &args[2], &args[3])?,
        "apply" => sync::cmd_apply(&store, &args[2], &args[3])?,
        "sync-dirty" => sync::cmd_sync_dirty(&store, &args[2], (args.len() == 5).then(|| args[3].as_os_str()))?,
        "verify-readonly-view" => view::cmd_verify_readonly_view(&store, &args[2], args.get(3).map(OsString::as_os_str))?,
        "push-remote" => remote::cmd_push_remote(&store, &args[2], &args[3], args.len() == 5)?,
        "pull-remote" => remote::cmd_pull_remote(&store, &args[2], &args[3], &args[4])?,
        "namespace-mount" => namespace::cmd_namespace_mount(&store, &args[2], &args[3..])?,
        "verify-namespace" => crash_recovery::cmd_verify_namespace_any_rev(&store, &args[2], args.get(3).map(OsString::as_os_str))?,
        "namespace-git-view" => namespace::cmd_namespace_git_view(&store, &args[2], args.get(3).map(OsString::as_os_str))?,
        "vfs-mount" => vfs::cmd_vfs_mount(&store, &args[2], &args[3], &args[4..])?,
        "vfs-hydrate" => vfs::cmd_vfs_hydrate(&store, &args[2], &args[3..])?,
        "vfs-status" => vfs::cmd_vfs_status(&store, &args[2])?,
        "vfs-evict" => vfs::cmd_vfs_evict(&store, &args[2], &args[3..])?,
        "agent-lease" => writable_view::cmd_agent_lease(&store, &args[2], &args[3], &args[4], &args[5..])?,
        "namespace-write" => writable_view::cmd_namespace_write(&store, &args[2], &args[3], &args[4], &args[5], &args[6..])?,
        "namespace-commit-back" => writable_view::cmd_namespace_commit_back(&store, &args[2], &args[3], &args[4..])?,
        "overlay-mount" => crash_recovery::cmd_overlay_mount(&store, &args[2], &args[3], &args[4..])?,
        "overlay-op" => crash_recovery::cmd_overlay_op(&store, &args[2], &args[3], &args[4..])?,
        "overlay-write" | "overlay-delete" | "overlay-rename" | "overlay-chmod" | "overlay-git-add-f" | "overlay-status" => crash_recovery::cmd_overlay_alias(&store, command, &args[2], &args[3..])?,
        "crash-drill" => crash_recovery::cmd_crash_drill(&store, &args[2], &args[3], &args[4..])?,
        "crash-recover" => crash_recovery::cmd_crash_recover(&store, &args[2])?,
        _ => unreachable!(),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
