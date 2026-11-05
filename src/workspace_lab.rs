//! Native-directory, full-copy and incremental-sync workspace experiment. All writers
//! must be stopped by the caller. The store lock cannot fence editors, Git or arbitrary processes.
#[path = "workspace_lab/core.rs"]
pub mod core;
#[path = "workspace_lab/ignore.rs"]
pub mod ignore;
#[path = "workspace_lab/manifest.rs"]
pub mod manifest;
#[path = "workspace_lab/namespace.rs"]
pub mod namespace;
#[path = "workspace_lab/remote.rs"]
pub mod remote;
#[path = "workspace_lab/sync.rs"]
pub mod sync;
#[path = "workspace_lab/view.rs"]
pub mod view;
#[path = "workspace_lab/vfs.rs"]
pub mod vfs;

use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsString, path::Path};

pub use core::{
    Entry, MAX_BYTES, MAX_ENTRIES, MAX_MANIFEST, Manifest, SCHEMA, Staging, Store, Workspace,
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
vfs-evict STORE VFS_ID [PATH_OR_GLOB...] [--quiescent] [--skip-dirty]";

pub fn run(args: Vec<OsString>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "workspace lab requires Linux");
    let command = args.first().and_then(|x| x.to_str()).context(USAGE)?;
    match command {
        "init" => ensure!(args.len() == 6, "{USAGE}"),
        "checkpoint" | "restore" | "changeset" => ensure!(args.len() == 4, "{USAGE}"),
        "inspect" | "status" | "vfs-status" => ensure!(args.len() == 3, "{USAGE}"),
        "apply" | "pull-remote" => ensure!(args.len() == 5, "{USAGE}"),
        "sync-dirty" => ensure!(args.len() == 4 || args.len() == 5, "{USAGE}"),
        "verify-readonly-view" | "verify-namespace" | "namespace-git-view" => {
            ensure!(args.len() == 3 || args.len() == 4, "{USAGE}")
        }
        "push-remote" => {
            ensure!(args.len() == 4 || args.len() == 5, "{USAGE}");
            if args.len() == 5 {
                ensure!(args[4] == "--quiescent", "{USAGE}");
            }
        }
        "namespace-mount" | "vfs-mount" | "vfs-hydrate" | "vfs-evict" => {
            ensure!(args.len() >= 4, "{USAGE}")
        }
        _ => bail!(USAGE),
    }
    if matches!(command, "init" | "checkpoint" | "apply" | "sync-dirty") {
        ensure!(
            args.last().is_some_and(|x| x == "--quiescent"),
            "stop ALL writers and explicitly pass --quiescent; this is a caller assumption, not a write barrier"
        );
    }
    // Reject overlap before creating even a store lock or staging directory.
    if command == "init" {
        core::check_source_store_overlap(&args[1], &args[2])?;
    }
    let store = Store::open(Path::new(&args[1]))?;
    let result = match command {
        "init" => store.cmd_init(&args[2], &args[3], &args[4])?,
        "checkpoint" => store.cmd_checkpoint(&args[2])?,
        "restore" => store.cmd_restore(&args[2], &args[3])?,
        "inspect" => store.cmd_inspect(&args[2])?,
        "status" => manifest::cmd_status(&store, &args[2])?,
        "changeset" => manifest::cmd_changeset(&store, &args[2], &args[3])?,
        "apply" => sync::cmd_apply(&store, &args[2], &args[3])?,
        "sync-dirty" => {
            let target = (args.len() == 5).then(|| args[3].as_os_str());
            sync::cmd_sync_dirty(&store, &args[2], target)?
        }
        "verify-readonly-view" => {
            let view_path = args.get(3).map(OsString::as_os_str);
            view::cmd_verify_readonly_view(&store, &args[2], view_path)?
        }
        "push-remote" => remote::cmd_push_remote(&store, &args[2], &args[3], args.len() == 5)?,
        "pull-remote" => remote::cmd_pull_remote(&store, &args[2], &args[3], &args[4])?,
        "namespace-mount" => namespace::cmd_namespace_mount(&store, &args[2], &args[3..])?,
        "verify-namespace" => {
            let view_path = args.get(3).map(OsString::as_os_str);
            namespace::cmd_verify_namespace(&store, &args[2], view_path)?
        }
        "namespace-git-view" => {
            let view_path = args.get(3).map(OsString::as_os_str);
            namespace::cmd_namespace_git_view(&store, &args[2], view_path)?
        }
        "vfs-mount" => vfs::cmd_vfs_mount(&store, &args[2], &args[3], &args[4..])?,
        "vfs-hydrate" => vfs::cmd_vfs_hydrate(&store, &args[2], &args[3..])?,
        "vfs-status" => vfs::cmd_vfs_status(&store, &args[2])?,
        "vfs-evict" => vfs::cmd_vfs_evict(&store, &args[2], &args[3..])?,
        _ => unreachable!(),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
