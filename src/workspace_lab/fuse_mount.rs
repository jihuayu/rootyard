//! Transparent Linux FUSE overlay over an immutable snapshot and private CoW layer.
use fuser::{FileAttr,FileType,Filesystem,MountOption,ReplyAttr,ReplyCreate,ReplyData,ReplyDirectory,ReplyEmpty,ReplyEntry,ReplyOpen,ReplyWrite,Request,TimeOrNow};
use std::{collections::{BTreeMap,BTreeSet},ffi::{OsStr,OsString},fs::{self,File,OpenOptions},io,path::{Path,PathBuf},os::unix::{fs::{FileExt,MetadataExt,OpenOptionsExt,PermissionsExt,symlink},ffi::OsStrExt},time::{Duration,SystemTime}};

const TTL: Duration=Duration::ZERO;

pub struct Overlay {
    lower:PathBuf, upper:PathBuf,
    paths:BTreeMap<u64,PathBuf>, ids:BTreeMap<PathBuf,u64>, next:u64,
    whiteouts:BTreeSet<PathBuf>,
}
impl Overlay {
    pub fn new(lower:PathBuf,upper:PathBuf)->io::Result<Self>{
        if !lower.is_dir(){return Err(io::Error::from_raw_os_error(libc::ENOENT));}
        fs::create_dir_all(&upper)?;
        let lower=lower.canonicalize()?;
        let upper=upper.canonicalize()?;
        if upper.starts_with(&lower) || lower.starts_with(&upper){return Err(io::Error::from_raw_os_error(libc::EINVAL));}
        let mut paths=BTreeMap::new(); paths.insert(1,PathBuf::new());
        let mut ids=BTreeMap::new(); ids.insert(PathBuf::new(),1);
        let whiteouts=if upper.join(".rootyard-whiteouts.json").exists(){
            serde_json::from_slice::<Vec<String>>(&fs::read(upper.join(".rootyard-whiteouts.json"))?).map_err(io::Error::other)?
                .into_iter().map(PathBuf::from).collect()
        }else{BTreeSet::new()};
        Ok(Self{lower,upper,paths,ids,next:2,whiteouts})
    }
    fn ino(&mut self,p:&Path)->u64{
        if let Some(n)=self.ids.get(p){return *n;}
        let n=self.next;self.next+=1;self.ids.insert(p.to_path_buf(),n);self.paths.insert(n,p.to_path_buf());n
    }
    fn rel(&self,ino:u64)->io::Result<PathBuf>{self.paths.get(&ino).cloned().ok_or_else(||io::Error::from_raw_os_error(libc::ENOENT))}
    fn child(&self,parent:u64,name:&OsStr)->io::Result<PathBuf>{
        if name.as_bytes().is_empty() || name.as_bytes().contains(&b'/') || name=="." || name==".." || name==".rootyard-whiteouts.json"{return Err(io::Error::from_raw_os_error(libc::EINVAL));}
        Ok(self.rel(parent)?.join(name))
    }
    fn hidden(&self,p:&Path)->bool{self.whiteouts.iter().any(|w|p==w || p.starts_with(w))}
    fn selected(&self,p:&Path)->io::Result<PathBuf>{
        if self.hidden(p){return Err(io::Error::from_raw_os_error(libc::ENOENT));}
        let up=self.upper.join(p);
        if fs::symlink_metadata(&up).is_ok(){return Ok(up);}
        let low=self.lower.join(p);
        fs::symlink_metadata(&low)?;
        Ok(low)
    }
    fn attr(&self,p:&Path,ino:u64)->io::Result<FileAttr>{
        let path=self.selected(p)?;let m=fs::symlink_metadata(path)?;
        let kind=if m.file_type().is_dir(){FileType::Directory}else if m.file_type().is_symlink(){FileType::Symlink}else if m.file_type().is_file(){FileType::RegularFile}else{return Err(io::Error::from_raw_os_error(libc::EIO))};
        Ok(FileAttr{ino,size:m.len(),blocks:m.blocks(),atime:m.accessed().unwrap_or(SystemTime::UNIX_EPOCH),mtime:m.modified().unwrap_or(SystemTime::UNIX_EPOCH),ctime:m.created().unwrap_or(SystemTime::UNIX_EPOCH),crtime:SystemTime::UNIX_EPOCH,kind,perm:(m.permissions().mode()&0o777) as u16,nlink:m.nlink() as u32,uid:unsafe{libc::getuid()},gid:unsafe{libc::getgid()},rdev:0,blksize:4096,flags:0})
    }
    fn prepare(&mut self,p:&Path)->io::Result<PathBuf>{
        let to=self.upper.join(p);
        let parent=to.parent().ok_or_else(||io::Error::from_raw_os_error(libc::EINVAL))?;
        fs::create_dir_all(parent)?;
        if fs::symlink_metadata(&to).is_err(){
            if let Ok(from)=self.selected(p){
                let m=fs::symlink_metadata(&from)?;
                if m.is_file(){fs::copy(&from,&to)?;fs::set_permissions(&to,m.permissions())?;}
                else if m.file_type().is_symlink(){symlink(fs::read_link(&from)?,&to)?;}
                else if m.is_dir(){fs::create_dir(&to)?;}
            }
        }
        Ok(to)
    }
    fn save_whiteouts(&self)->io::Result<()> {
        let names:Vec<String>=self.whiteouts.iter().map(|p|p.to_string_lossy().into_owned()).collect();
        let tmp=self.upper.join(".rootyard-whiteouts.tmp");
        fs::write(&tmp,serde_json::to_vec(&names)?)?;
        File::open(&tmp)?.sync_all()?;
        fs::rename(tmp,self.upper.join(".rootyard-whiteouts.json"))?;
        File::open(&self.upper)?.sync_all()
    }
    fn err(e:io::Error)->i32{e.raw_os_error().unwrap_or(libc::EIO)}
}

impl Filesystem for Overlay {
    fn lookup(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,reply:ReplyEntry){
        let result=(||{let p=self.child(parent,name)?;let ino=self.ino(&p);self.attr(&p,ino)})();
        match result{Ok(attr)=>reply.entry(&TTL,&attr,0),Err(e)=>reply.error(Self::err(e))}
    }
    fn getattr(&mut self,_:&Request<'_>,ino:u64,_:Option<u64>,reply:ReplyAttr){
        let result=self.rel(ino).and_then(|p|self.attr(&p,ino));
        match result{Ok(attr)=>reply.attr(&TTL,&attr),Err(e)=>reply.error(Self::err(e))}
    }
    fn readdir(&mut self,_:&Request<'_>,ino:u64,_:u64,offset:i64,mut reply:ReplyDirectory){
        let result=(||->io::Result<Vec<(u64,FileType,OsString)>>{
            let p=self.rel(ino)?;if self.attr(&p,ino)?.kind!=FileType::Directory{return Err(io::Error::from_raw_os_error(libc::ENOTDIR));}
            let parent=p.parent().unwrap_or(&p).to_path_buf();
            let parent_ino=self.ino(&parent);
            let mut out=vec![(ino,FileType::Directory,OsString::from(".")),(parent_ino,FileType::Directory,OsString::from(".."))];
            let mut names=BTreeSet::new();
            for root in [&self.lower,&self.upper]{let dir=root.join(&p);if dir.is_dir(){for entry in fs::read_dir(dir)?{names.insert(entry?.file_name());}}}
            for name in names {if let Ok(child)=self.child(ino,&name){let child_ino=self.ino(&child);if let Ok(attr)=self.attr(&child,child_ino){out.push((attr.ino,attr.kind,name));}}}
            Ok(out)
        })();
        match result{Ok(rows)=>{for (idx,(child,kind,name)) in rows.into_iter().enumerate().skip(offset.max(0) as usize){if reply.add(child,(idx+1) as i64,kind,name){break;}}reply.ok();},Err(e)=>reply.error(Self::err(e))}
    }
    fn readlink(&mut self,_:&Request<'_>,ino:u64,reply:ReplyData){
        let result=self.rel(ino).and_then(|p|self.selected(&p)).and_then(fs::read_link);
        match result{Ok(p)=>reply.data(p.as_os_str().as_bytes()),Err(e)=>reply.error(Self::err(e))}
    }
    fn open(&mut self,_:&Request<'_>,ino:u64,flags:i32,reply:ReplyOpen){
        let result=(||{let p=self.rel(ino)?;if flags & (libc::O_WRONLY|libc::O_RDWR)!=0{self.prepare(&p)?;}else{self.selected(&p)?;}Ok::<_,io::Error>(())})();
        match result{Ok(())=>reply.opened(0,0),Err(e)=>reply.error(Self::err(e))}
    }
    fn read(&mut self,_:&Request<'_>,ino:u64,_:u64,offset:i64,size:u32,_:i32,_:Option<u64>,reply:ReplyData){
        let result=(||{let p=self.rel(ino)?;let file=File::open(self.selected(&p)?)?;let mut buf=vec![0;size.min(1024*1024) as usize];let count=file.read_at(&mut buf,offset.max(0) as u64)?;buf.truncate(count);Ok::<_,io::Error>(buf)})();
        match result{Ok(data)=>reply.data(&data),Err(e)=>reply.error(Self::err(e))}
    }
    fn write(&mut self,_:&Request<'_>,ino:u64,_:u64,offset:i64,data:&[u8],_:u32,_:i32,_:Option<u64>,reply:ReplyWrite){
        let result=(||{let p=self.rel(ino)?;let file=OpenOptions::new().write(true).open(self.prepare(&p)?)?;let count=file.write_at(data,offset.max(0) as u64)?;file.sync_data()?;Ok::<_,io::Error>(count)})();
        match result{Ok(n)=>reply.written(n as u32),Err(e)=>reply.error(Self::err(e))}
    }
    fn setattr(&mut self,_:&Request<'_>,ino:u64,mode:Option<u32>,_:Option<u32>,_:Option<u32>,size:Option<u64>,_:Option<TimeOrNow>,_:Option<TimeOrNow>,_:Option<SystemTime>,_:Option<u64>,_:Option<SystemTime>,_:Option<SystemTime>,_:Option<SystemTime>,_:Option<u32>,reply:ReplyAttr){
        let result=(||{let p=self.rel(ino)?;if mode.is_some()||size.is_some(){let path=self.prepare(&p)?;if let Some(mode)=mode{fs::set_permissions(&path,fs::Permissions::from_mode(mode&0o777))?;}if let Some(size)=size{OpenOptions::new().write(true).open(path)?.set_len(size)?;}}self.attr(&p,ino)})();
        match result{Ok(attr)=>reply.attr(&TTL,&attr),Err(e)=>reply.error(Self::err(e))}
    }
    fn create(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,mode:u32,_:u32,_:i32,reply:ReplyCreate){
        let result=(||{let p=self.child(parent,name)?;if self.selected(&p).is_ok(){return Err(io::Error::from_raw_os_error(libc::EEXIST));}let path=self.prepare(&p)?;OpenOptions::new().write(true).create_new(true).mode(mode&0o777).open(path)?;self.whiteouts.remove(&p);let ino=self.ino(&p);self.attr(&p,ino)})();
        match result{Ok(attr)=>reply.created(&TTL,&attr,0,0,0),Err(e)=>reply.error(Self::err(e))}
    }
    fn mkdir(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,mode:u32,_:u32,reply:ReplyEntry){
        let result=(||{let p=self.child(parent,name)?;if self.selected(&p).is_ok(){return Err(io::Error::from_raw_os_error(libc::EEXIST));}let path=self.upper.join(&p);fs::create_dir_all(path.parent().unwrap())?;fs::create_dir(&path)?;fs::set_permissions(&path,fs::Permissions::from_mode(mode&0o777))?;self.whiteouts.remove(&p);let ino=self.ino(&p);self.attr(&p,ino)})();
        match result{Ok(attr)=>reply.entry(&TTL,&attr,0),Err(e)=>reply.error(Self::err(e))}
    }
    fn unlink(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,reply:ReplyEmpty){
        let result=(||{let p=self.child(parent,name)?;let selected=self.selected(&p)?;if fs::symlink_metadata(&selected)?.is_dir(){return Err(io::Error::from_raw_os_error(libc::EISDIR));}if selected.starts_with(&self.upper){fs::remove_file(selected)?;}if fs::symlink_metadata(self.lower.join(&p)).is_ok(){self.whiteouts.insert(p);self.save_whiteouts()?;}Ok::<_,io::Error>(())})();
        match result{Ok(())=>reply.ok(),Err(e)=>reply.error(Self::err(e))}
    }
    fn rmdir(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,reply:ReplyEmpty){
        let result=(||{let p=self.child(parent,name)?;let selected=self.selected(&p)?;if !fs::symlink_metadata(&selected)?.is_dir(){return Err(io::Error::from_raw_os_error(libc::ENOTDIR));}if fs::read_dir(&selected)?.next().is_some(){return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));}if selected.starts_with(&self.upper){fs::remove_dir(selected)?;}if self.lower.join(&p).exists(){self.whiteouts.insert(p);self.save_whiteouts()?;}Ok::<_,io::Error>(())})();
        match result{Ok(())=>reply.ok(),Err(e)=>reply.error(Self::err(e))}
    }
    fn rename(&mut self,_:&Request<'_>,parent:u64,name:&OsStr,newparent:u64,newname:&OsStr,flags:u32,reply:ReplyEmpty){
        let result=(||{if flags!=0{return Err(io::Error::from_raw_os_error(libc::EINVAL));}let src=self.child(parent,name)?;let dst=self.child(newparent,newname)?;if src==dst{return Ok(());}let from=self.prepare(&src)?;let to=self.upper.join(&dst);fs::create_dir_all(to.parent().unwrap())?;fs::rename(&from,&to)?;for (ino,old) in self.paths.clone(){if old==src || old.starts_with(&src){let suffix=old.strip_prefix(&src).unwrap();let new=if suffix.as_os_str().is_empty(){dst.clone()}else{dst.join(suffix)};self.ids.remove(&old);self.ids.insert(new.clone(),ino);self.paths.insert(ino,new);}}if self.lower.join(&src).exists(){self.whiteouts.insert(src.clone());}self.whiteouts.remove(&dst);self.save_whiteouts()?;Ok::<_,io::Error>(())})();
        match result{Ok(())=>reply.ok(),Err(e)=>reply.error(Self::err(e))}
    }
}

pub fn mount(lower:PathBuf,upper:PathBuf,mountpoint:PathBuf)->io::Result<()> {
    let fs=Overlay::new(lower,upper)?;
    fuser::mount2(fs,mountpoint,&[MountOption::FSName("rootyard-vfs".into()),MountOption::DefaultPermissions])
}
