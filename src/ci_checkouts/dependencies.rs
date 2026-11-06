//! Immutable CI dependency closure from Git trees, LFS pointers, and gitlink sources.
use crate::{AppState, Error, auth, ci_pins, db, git_http, lfs, members::{models::Role,rbac}, webhooks::delivery::ensure_pull_ci_pin};
use axum::http::StatusCode;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::collections::{HashMap,HashSet,VecDeque};
use uuid::Uuid;

#[derive(Clone,Debug,Default,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub history: String,
    pub tags: Vec<TagDependency>,
    pub lfs: Vec<LfsDependency>,
    pub submodules: Vec<SubmoduleDependency>,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct LfsDependency {
    pub repository_id: Uuid, pub path: String, pub oid: String, pub size: i64,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct TagDependency { pub name: String, pub object_oid: String }
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmoduleDependency {
    pub path: String, pub repository_id: Uuid, pub owner: String, pub name: String,
    pub target_oid: String, pub storage_generation: i64, pub job_id: Uuid,
}
impl Manifest {
    pub fn for_submodule(&self, sub:&SubmoduleDependency)->Self {
        let prefix=format!("{}/",sub.path);
        Self {version:1,history:self.history.clone(),tags:Vec::new(),
            lfs:self.lfs.iter().filter(|d|d.path.starts_with(&prefix)).cloned().collect(),
            submodules:self.submodules.iter().filter(|d|d.path.starts_with(&prefix)).cloned().collect()}
    }
}
struct Source { repo: db::Repository, oid: String, prefix: String, depth: usize }
#[derive(Clone,Copy)]
pub enum Principal<'a> { User(&'a db::Identity), Integration(Uuid) }

fn unsafe_dependency() -> Error { Error(StatusCode::CONFLICT,"CI dependency is missing or unsafe") }

async fn git(state: &AppState, repo_id: Uuid, args: &[&str], cap: usize) -> Result<Vec<u8>,Error> {
    let path=state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let mut cmd=state.storage.git(&state.config);
    cmd.args(["--no-replace-objects","--git-dir"]).arg(path).args(args);
    git_http::collect_git_output(cmd,cap,state.config.git_timeout).await.map_err(|_| unsafe_dependency())
}
async fn blob(state:&AppState,repo:Uuid,oid:&str,cap:usize)->Result<Vec<u8>,Error>{
    git(state,repo,&["cat-file","blob",oid],cap).await
}

fn parse_tree(raw:&[u8])->Result<Vec<(String,String,String,Option<usize>,String)>,Error>{
    let mut entries=Vec::new();
    for record in raw.split(|b|*b==0).filter(|r|!r.is_empty()) {
        let text=std::str::from_utf8(record).map_err(|_|unsafe_dependency())?;
        let (head,path)=text.split_once('\t').ok_or_else(unsafe_dependency)?;
        let mut parts=head.split_ascii_whitespace();
        let mode=parts.next().ok_or_else(unsafe_dependency)?;
        let kind=parts.next().ok_or_else(unsafe_dependency)?;
        let oid=parts.next().ok_or_else(unsafe_dependency)?;
        let size=parts.next().and_then(|n|n.parse::<usize>().ok());
        if !ci_pins::valid_oid(oid) || path.is_empty() || path.starts_with('/') ||
            path.split('/').any(|s|s.is_empty() || s=="." || s=="..") { return Err(unsafe_dependency()); }
        entries.push((mode.into(),kind.into(),oid.into(),size,path.into()));
        if entries.len()>10_000 { return Err(unsafe_dependency()); }
    }
    Ok(entries)
}

fn parse_gitmodules(raw:&[u8])->Result<HashMap<String,String>,Error>{
    let text=std::str::from_utf8(raw).map_err(|_|unsafe_dependency())?;
    let mut names:HashMap<String,(Option<String>,Option<String>)>=HashMap::new();
    let mut current=None;
    for line in text.lines() {
        let line=line.trim();
        if line.is_empty() || line.starts_with('#') {continue;}
        if line.starts_with('[') {
            let name=line.strip_prefix("[submodule \"").and_then(|s|s.strip_suffix("\"]"))
                .ok_or_else(unsafe_dependency)?;
            if name.is_empty() || names.contains_key(name) {return Err(unsafe_dependency());}
            names.insert(name.into(),(None,None));current=Some(name.to_owned());continue;
        }
        let (key,value)=line.split_once('=').ok_or_else(unsafe_dependency)?;
        let name=current.as_deref().ok_or_else(unsafe_dependency)?;
        let pair=names.get_mut(name).ok_or_else(unsafe_dependency)?;
        match key.trim() {
            "path" if pair.0.is_none()=>pair.0=Some(value.trim().into()),
            "url" if pair.1.is_none()=>pair.1=Some(value.trim().into()),
            _=>return Err(unsafe_dependency()),
        }
    }
    let mut paths=HashMap::new();
    for (_, (path,url)) in names {
        let path=path.ok_or_else(unsafe_dependency)?;
        let url=url.ok_or_else(unsafe_dependency)?;
        if path.is_empty() || paths.insert(path,url).is_some(){return Err(unsafe_dependency());}
    }
    Ok(paths)
}

fn relative_source(parent_owner:&str,url:&str)->Result<(String,String),Error>{
    if url.contains('?') || url.contains('#') || url.contains('@') || url.contains(':') || url.contains('\\') {
        return Err(unsafe_dependency());
    }
    let parts:Vec<_>=url.split('/').collect();
    let (owner,name)=match parts.as_slice(){
        ["..",name]=>(parent_owner.to_owned(),*name),
        ["..","..",owner,name] if db::valid_name(owner)=>(owner.to_string(),*name),
        _=>return Err(unsafe_dependency()),
    };
    let name=name.strip_suffix(".git").ok_or_else(unsafe_dependency)?;
    if !db::valid_name(name) {return Err(unsafe_dependency());}
    Ok((owner,name.to_owned()))
}

async fn permitted_repo(state:&AppState,principal:Principal<'_>,owner:&str,name:&str)
    ->Result<db::Repository,Error>{
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let repo_id=match principal {
        Principal::User(actor)=>auth::authorize_repo_with_role(&tx,actor,owner,name,Role::Read).await?.repo_id,
        Principal::Integration(hook_id)=>tx.query_opt(
            "SELECT r.id FROM repositories r JOIN namespaces u ON u.id=r.owner_id \
             JOIN ci_integration_source_grants g ON g.repository_id=r.id \
             WHERE u.slug=$1 AND r.name=$2 AND g.issuer_webhook_id=$3 AND g.active=true \
               AND r.state='ready'",
            &[&owner,&name,&hook_id],
        ).await.map_err(Error::internal)?.ok_or_else(unsafe_dependency)?.get(0),
    };
    let row=tx.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&repo_id])
        .await.map_err(Error::internal)?;
    let repo=db::Repository::from_row(&row);
    match principal {Principal::User(actor)=>auth::finish_tx(tx,actor,false).await?,
        Principal::Integration(_)=>tx.commit().await.map_err(Error::internal)?};
    Ok(repo)
}

async fn check_lfs(state:&AppState,repo:&db::Repository,oid:&str,size:i64)->Result<(),Error>{
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt(
        "SELECT 1 FROM lfs_objects WHERE repository_id=$1 AND oid=$2 AND size=$3 AND state='ready'",
        &[&repo.id,&oid,&size],
    ).await.map_err(Error::internal)?;
    if row.is_none(){return Err(unsafe_dependency());}
    let root=state.storage.root.clone();let repo_id=repo.id;let oid=oid.to_owned();
    let valid=tokio::task::spawn_blocking(move||
        lfs::storage::verify_object_integrity(&root,repo_id,&oid,size as u64))
        .await.map_err(Error::internal)?.map_err(Error::internal)?;
    if !valid {return Err(unsafe_dependency());}
    Ok(())
}

/// Fail closed on unknown Git modules and missing/corrupt LFS bytes. Every
/// submodule is resolved and authorized as a separate repository source.
pub async fn scan(state:&AppState,principal:Principal<'_>,root_repo:db::Repository,
    root_job_id:Uuid,target:&str,history:&str,tags:&[String])->Result<Manifest,Error>{
    if !matches!(history,"full"|"target") || tags.len()>32 {return Err(Error::bad_request());}
    let mut result=Manifest{version:1,history:history.into(),tags:Vec::new(),
        lfs:Vec::new(),submodules:Vec::new()};
    let tag_lease=if tags.is_empty(){None}else{Some(
        crate::storage::read_leases::shared(&state.pool,root_repo.id,
            tokio::time::Instant::now()+state.config.git_timeout).await?)};
    for tag in tags {
        if tag.is_empty() || tag.len()>128 || tag.starts_with('-') || tag.contains("..") ||
            tag.contains("@{") || tag.bytes().any(|b|!b.is_ascii_alphanumeric() && !b"/._-".contains(&b)) {
            return Err(Error::bad_request());
        }
        let name=format!("refs/tags/{tag}");
        let out=git(state,root_repo.id,&["rev-parse","--verify",&name],128).await?;
        let oid=std::str::from_utf8(&out).map_err(|_|unsafe_dependency())?.trim();
        if !ci_pins::valid_oid(oid) {return Err(unsafe_dependency());}
        result.tags.push(TagDependency{name:tag.clone(),object_oid:oid.into()});
    }
    if let Some(lease)=tag_lease {lease.ensure_active()?;}
    let mut queue=VecDeque::from([Source{repo:root_repo,oid:target.into(),prefix:String::new(),depth:0}]);
    let mut scanned=HashSet::new();
    while let Some(source)=queue.pop_front(){
        if source.depth>5 || !scanned.insert((source.repo.id,source.oid.clone(),source.prefix.clone())) {
            return Err(unsafe_dependency());
        }
        // Claim and user issuance run outside Git HTTP's transfer lease. Hold
        // the same durable source barrier while native tree/blob reads run;
        // release it before pinning another repository to avoid nested slots.
        let lease=crate::storage::read_leases::shared(&state.pool,source.repo.id,
            tokio::time::Instant::now()+state.config.git_timeout).await?;
        let entries=parse_tree(&git(state,source.repo.id,&["ls-tree","-rzl","--full-tree",&source.oid],4*1024*1024).await?)?;
        let module_oid=entries.iter().find(|e|e.4==".gitmodules" && e.1=="blob").map(|e|e.2.clone());
        let gitlinks:Vec<_>=entries.iter().filter(|e|e.0=="160000" && e.1=="commit").collect();
        let modules=if gitlinks.is_empty(){HashMap::new()}else{
            let oid=module_oid.ok_or_else(unsafe_dependency)?;
            parse_gitmodules(&blob(state,source.repo.id,&oid,64*1024).await?)?
        };
        for (_,kind,oid,size,path) in &entries {
            if kind!="blob" || size.is_none_or(|n|n>1024) {continue;}
            let bytes=blob(state,source.repo.id,oid,1024).await?;
            if let Some(pointer)=lfs::models::parse_pointer(&bytes){
                check_lfs(state,&source.repo,&pointer.oid,pointer.size).await?;
                result.lfs.push(LfsDependency{repository_id:source.repo.id,
                    path:format!("{}{}",source.prefix,path),oid:pointer.oid,size:pointer.size});
            }
        }
        let links=gitlinks.into_iter().map(|entry|Ok::<_,Error>((entry.4.clone(),
            entry.2.clone(),modules.get(&entry.4).ok_or_else(unsafe_dependency)?.clone())))
            .collect::<Result<Vec<_>,_>>()?;
        lease.ensure_active()?;
        drop(lease);
        for (relative,commit_oid,url) in links {
            let (owner,name)=relative_source(&source.repo.owner,&url)?;
            let nested=permitted_repo(state,principal,&owner,&name).await?;
            if nested.state!="ready" || nested.storage_backend!="gitfs" {return Err(unsafe_dependency());}
            let path=format!("{}{}",source.prefix,relative);
            let mut hash=Sha256::new();
            hash.update(b"rootyard-submodule-pin-v1\0");hash.update(root_job_id.as_bytes());
            hash.update(nested.id.as_bytes());hash.update(commit_oid.as_bytes());hash.update(path.as_bytes());
            let digest=hash.finalize();let mut id=[0u8;16];id.copy_from_slice(&digest[..16]);
            id[6]=(id[6]&0x0f)|0x40;id[8]=(id[8]&0x3f)|0x80;
            let job_id=Uuid::from_bytes(id);
            let client=state.pool.get().await.map_err(Error::internal)?;
            let owner_id:Uuid=client.query_one("SELECT owner_id FROM repositories WHERE id=$1",&[&nested.id])
                .await.map_err(Error::internal)?.get(0);
            drop(client);
            ensure_pull_ci_pin(state,&nested,owner_id,job_id,&commit_oid).await?;
            result.submodules.push(SubmoduleDependency{path:path.clone(),repository_id:nested.id,
                owner,name,target_oid:commit_oid.clone(),storage_generation:nested.storage_generation,job_id});
            queue.push_back(Source{repo:nested,oid:commit_oid,prefix:format!("{path}/"),depth:source.depth+1});
        }
        if result.lfs.len()+result.submodules.len()>128 {return Err(unsafe_dependency());}
    }
    if serde_json::to_vec(&result).map_err(Error::internal)?.len()>7000 {return Err(unsafe_dependency());}
    Ok(result)
}

/// A job is ready on a mirror only if every declared dependency is present and
/// the original issuer still has independent read authority on each source.
pub async fn verify_on_mirror(state:&AppState,plan:&super::Plan)->Result<(),Error>{
    verify_dependencies(state,plan,true).await
}

pub async fn verify_on_origin(state:&AppState,plan:&super::Plan)->Result<(),Error>{
    verify_dependencies(state,plan,false).await
}

async fn verify_dependencies(state:&AppState,plan:&super::Plan,mirror:bool)->Result<(),Error>{
    if state.mirror_primary.is_some()!=mirror || plan.dependencies.version!=1 {
        return Err(unsafe_dependency());
    }
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let issuer=tx.query_opt(
        "WITH grants AS (SELECT repository_id,job_id,issuer_token_id,expires_unix \
          FROM ci_checkout_jobs WHERE NOT cancelled AND NOT revoked \
          UNION ALL SELECT d.repository_id,d.job_id,d.issuer_token_id,d.expires_unix \
          FROM ci_checkout_delegations d JOIN ci_checkout_jobs p \
          ON p.repository_id=d.parent_repository_id AND p.job_id=d.parent_job_id \
          WHERE NOT p.cancelled AND NOT p.revoked) \
         SELECT t.user_id FROM grants j JOIN tokens t ON t.id=j.issuer_token_id \
         WHERE j.repository_id=$1 AND j.job_id=$2 \
           AND j.expires_unix>extract(epoch FROM clock_timestamp()) AND NOT t.revoked \
           AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp())",
        &[&plan.repository_id,&plan.job_id],
    ).await.map_err(Error::internal)?;
    let hook=if issuer.is_none(){super::authority::integration_hook_for_plan(state,plan).await?}
        else {None};
    if issuer.is_none() && hook.is_none(){return Err(Error::unauthorized());}
    for sub in &plan.dependencies.submodules {
        let row=tx.query_opt(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&sub.repository_id])
            .await.map_err(Error::internal)?.ok_or_else(unsafe_dependency)?;
        let repo=db::Repository::from_row(&row);
        let owner_id:Uuid=row.get("owner_id");
        let allowed=if let Some(issuer)=&issuer {
            let actor:Uuid=issuer.get(0);
            rbac::resolve_effective_role_by_id(&tx,repo.id,owner_id,actor).await?
                .is_some_and(|r|r>=Role::Read)
        } else {
            tx.query_opt("SELECT 1 FROM ci_integration_source_grants WHERE issuer_webhook_id=$1 \
                AND repository_id=$2 AND active=true",&[&hook.unwrap(),&repo.id])
                .await.map_err(Error::internal)?.is_some()
        };
        if repo.owner!=sub.owner || repo.name!=sub.name ||
            repo.storage_generation!=sub.storage_generation || repo.state!="ready" || !allowed {
            return Err(unsafe_dependency());
        }
    }
    for lfs in &plan.dependencies.lfs {
        let row=tx.query_opt(
            "SELECT 1 FROM lfs_objects WHERE repository_id=$1 AND oid=$2 AND size=$3 AND state='ready'",
            &[&lfs.repository_id,&lfs.oid,&lfs.size],
        ).await.map_err(Error::internal)?;
        if row.is_none(){return Err(unsafe_dependency());}
    }
    tx.commit().await.map_err(Error::internal)?;
    // Native pin views or source receipts verify the exact Gitlink commit,
    // never a moving branch.
    for sub in &plan.dependencies.submodules {
        let client=state.pool.get().await.map_err(Error::internal)?;
        let row=client.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&sub.repository_id])
            .await.map_err(Error::internal)?;
        let repo=db::Repository::from_row(&row);
        if mirror {
            crate::mirror::pinned_path(state,&repo,&sub.target_oid).await?;
        } else {
            let owner_id:Uuid=row.get("owner_id");
            let intent=ci_pins::Intent{version:1,job_id:sub.job_id,owner_id,
                repository_id:repo.id,storage_generation:repo.storage_generation,
                object_format:if sub.target_oid.len()==40 {"sha1"} else {"sha256"}.into(),
                target_oid:sub.target_oid.clone(),
                retention_ref:format!("refs/rootyard-ci/jobs/{}",sub.job_id)};
            let lock=state.storage.write_lock(repo.id).await;
            ci_pins::verify_receipt(state,&intent).await.map_err(|_|unsafe_dependency())?;
            drop(lock);
        }
    }
    for lfs in &plan.dependencies.lfs {
        let root=state.storage.root.clone();let repo=lfs.repository_id;
        let oid=lfs.oid.clone();let size=lfs.size as u64;
        let valid=tokio::task::spawn_blocking(move||
            lfs::storage::verify_object_integrity(&root,repo,&oid,size))
            .await.map_err(Error::internal)?.map_err(Error::internal)?;
        if !valid{return Err(unsafe_dependency());}
    }
    Ok(())
}
