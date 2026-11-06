use crate::{AppState, Error, workspace_lab::core, workspaces::service};
use std::{fs::{self,OpenOptions}, os::unix::fs::{OpenOptionsExt,PermissionsExt}, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::process::Command;
use uuid::Uuid;

pub fn job_root(state: &AppState, id: Uuid) -> PathBuf { state.storage.root.join("sandbox-jobs").join(id.to_string()) }

fn limit(resource: libc::__rlimit_resource_t, soft: u64) -> std::io::Result<()> {
    let lim=libc::rlimit{rlim_cur:soft,rlim_max:soft};
    if unsafe {libc::setrlimit(resource,&lim)}!=0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}

pub async fn launch(state: Arc<AppState>, job: Uuid, workspace: Uuid, argv: Vec<String>, timeout_seconds: u64) -> Result<(),Error> {
    let root=job_root(&state,job);
    fs::create_dir_all(&root).map_err(Error::internal)?;
    fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let workspace_dir=root.join("workspace");
    core::copy_all(&service::workspace_repo(&state,workspace),&workspace_dir).map_err(Error::internal)?;
    let stdout=OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join("stdout.log")).map_err(Error::internal)?;
    let stderr=OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join("stderr.log")).map_err(Error::internal)?;
    let mut command=Command::new("bwrap");
    command.args(["--unshare-all","--die-with-parent","--clearenv","--setenv","PATH","/usr/bin:/bin","--setenv","HOME","/home",
        "--ro-bind","/usr","/usr","--ro-bind","/bin","/bin","--ro-bind","/lib","/lib","--ro-bind","/lib64","/lib64",
        "--proc","/proc","--dev","/dev","--tmpfs","/tmp","--tmpfs","/run","--dir","/home","--bind"])
        .arg(&workspace_dir).args(["/workspace","--chdir","/workspace","--"])
        .args(argv.iter().map(String::as_str));
    command.stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).stdin(Stdio::null());
    unsafe { command.pre_exec(move || {
        if libc::setsid()<0 { return Err(std::io::Error::last_os_error()); }
        limit(libc::RLIMIT_CPU,timeout_seconds+2)?;
        limit(libc::RLIMIT_AS,512*1024*1024)?;
        limit(libc::RLIMIT_FSIZE,16*1024*1024)?;
        limit(libc::RLIMIT_NOFILE,128)?;
        limit(libc::RLIMIT_NPROC,1024)?;
        Ok(())
    }); }
    let mut child=command.spawn().map_err(Error::internal)?;
    let pid=child.id().ok_or_else(||Error::internal("sandbox process missing pid"))? as i32;
    let client=state.pool.get().await.map_err(Error::internal)?;
    client.execute("UPDATE sandbox_jobs SET state='running',pid=$2,started_at=clock_timestamp() WHERE id=$1 AND state='queued'", &[&job,&pid]).await.map_err(Error::internal)?;
    tokio::spawn(async move {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(timeout_seconds);
        let (state_name,code) = loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break ("succeeded",status.code()),
                Ok(Some(status)) => break ("failed",status.code()),
                Err(_) => break ("failed",None),
                Ok(None) => {}
            }
            if tokio::time::Instant::now()>=deadline {
                unsafe {libc::kill(-pid,libc::SIGKILL);}
                let _=child.wait().await;
                break ("timed_out",None);
            }
            if let Ok(client)=state.pool.get().await {
                if let Ok(Some(row))=client.query_opt("SELECT state FROM sandbox_jobs WHERE id=$1", &[&job]).await {
                    if row.get::<_,String>(0)=="cancelled" {
                        unsafe {libc::kill(-pid,libc::SIGKILL);}
                        let _=child.wait().await;
                        break ("cancelled",None);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        if let Ok(client)=state.pool.get().await {
            let _=client.execute("UPDATE sandbox_jobs SET state=$2,exit_code=$3,finished_at=clock_timestamp(),pid=NULL WHERE id=$1 AND state='running'", &[&job,&state_name,&code]).await;
        }
    });
    Ok(())
}

pub async fn reconcile_startup(state: &AppState) -> Result<(),Error> {
    let client=state.pool.get().await.map_err(Error::internal)?;
    let rows=client.query("SELECT id,pid FROM sandbox_jobs WHERE host_id=$1 AND state='running'", &[&state.storage.volume_id]).await.map_err(Error::internal)?;
    for row in rows {
        let id: Uuid=row.get(0);
        let pid: Option<i32>=row.get(1);
        let _=pid; // --die-with-parent kills the namespace on service crash.
        client.execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp(),pid=NULL WHERE id=$1 AND state='running'", &[&id]).await.map_err(Error::internal)?;
    }
    Ok(())
}
