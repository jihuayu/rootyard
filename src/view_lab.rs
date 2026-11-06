//! Opt-in local Namespace, Git View and two-phase cross-repository ChangeSet prototype.
//! Native bare Git repositories in the private store remain authoritative per repository.
#[path = "view_lab/changeset.rs"]
pub mod changeset;
#[path = "view_lab/models.rs"]
pub mod models;
#[path = "view_lab/namespace.rs"]
pub mod namespace;
#[path = "view_lab/projection.rs"]
pub mod projection;

use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsString, fs, path::Path};

pub use models::*;

pub fn run(args: Vec<OsString>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "view lab requires Linux");
    let usage = "usage: rootyard-view-lab register-repo | advance-repo | create-namespace | project-subdir | create-task-view | project-history | verify-view | integrate-changeset | recover-changeset";
    let command = args.first().and_then(|x| x.to_str()).context(usage)?;
    ensure!(args.len() >= 3, "{usage}");
    let store = Store::open(Path::new(&args[1]))?;
    let result = match command {
        "register-repo" => {
            ensure!(
                args.len() == 5 && args[4] == "--quiescent",
                "register-repo requires STORE REPO_NAME SOURCE_PATH --quiescent"
            );
            let name = text_arg(&args[2])?;
            let source = fs::canonicalize(&args[3]).context("source unavailable")?;
            store.register_repo(&name, &source)?
        }
        "advance-repo" => {
            ensure!(
                args.len() == 5 && args[4] == "--quiescent",
                "advance-repo requires STORE REPO_NAME SOURCE_PATH --quiescent"
            );
            let name = text_arg(&args[2])?;
            let source = fs::canonicalize(&args[3]).context("source unavailable")?;
            store.advance_repo(&name, &source)?
        }
        "create-namespace" => {
            ensure!(args.len() >= 4, "create-namespace requires STORE NAMESPACE_NAME and at least one mount");
            let namespace = text_arg(&args[2])?;
            let specs: Vec<String> = args[3..].iter().map(text_arg).collect::<Result<_>>()?;
            store.create_namespace(&namespace, &specs)?
        }
        "project-subdir" => {
            ensure!(args.len() == 5, "project-subdir requires STORE VIEW_NAME REPO_NAME SUBDIR_PATH");
            let view_name = text_arg(&args[2])?;
            let repo_name = text_arg(&args[3])?;
            let subdir = text_arg(&args[4])?;
            store.project_subdir(&view_name, &repo_name, &subdir)?
        }
        "create-task-view" => {
            ensure!(args.len() == 4, "create-task-view requires STORE VIEW_NAME REVISION_ID");
            let view_name = text_arg(&args[2])?;
            let revision_id = text_arg(&args[3])?;
            store.create_task_view(&view_name, &revision_id)?
        }
        "project-history" => store.project_history_cli(&args[2..])?,
        "verify-view" => {
            ensure!(args.len() == 3, "verify-view requires STORE VIEW_ID");
            store.verify_view(&text_arg(&args[2])?)?
        }
        "integrate-changeset" => {
            ensure!(args.len() == 4, "integrate-changeset requires STORE VIEW_ID TASK_REF");
            let view_id = text_arg(&args[2])?;
            let task_ref = text_arg(&args[3])?;
            store.integrate_changeset(&view_id, &task_ref)?
        }
        "recover-changeset" => {
            ensure!(args.len() == 3, "recover-changeset requires STORE CHANGESET_ID");
            let changeset_id = text_arg(&args[2])?;
            store.recover_changeset(&changeset_id)?
        }
        _ => bail!(usage),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
