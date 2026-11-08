"""Root-only real same-crate compile rejection with a permissive control."""
import hashlib,json,re,subprocess,time
from pathlib import Path
root=Path('/workspace/scratch/state-holds-trust-check')
out=Path('/workspace/scratch/state-holds-trust-privacy-v3');out.mkdir(exist_ok=False)
paths=[root/'src/lib.rs',root/'src/blob_store/mod.rs',root/'src/blob_store/transfer.rs',root/'src/blob_store/transfer/receipt.rs',root/'src/blob_store/opendal.rs',root/'src/blob_store/config.rs']
original={p:p.read_text() for p in paths}
sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
before={str(p.relative_to(root)):sha(s) for p,s in original.items()}
command=['cargo','--config','profile.dev.package.rootyard.debug=0','--config','profile.test.package.rootyard.debug=0','--config','profile.dev.package.rootyard.strip="debuginfo"','--config','profile.test.package.rootyard.strip="debuginfo"','check','--locked','--lib','--features','pando-lab']
def run(name):
    start=time.monotonic()
    r=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    text=r.stdout.decode(errors='replace');(out/(name+'.log')).write_text(text)
    return dict(returncode=r.returncode,seconds=round(time.monotonic()-start,3)),text
try:
    paths[0].write_text(original[paths[0]]+"""
#[allow(dead_code)]
mod root_hold_privacy_probe {
    fn sealed_functions() {
        let _ = crate::blob_store::BlobReceipt::new;
        let _ = crate::blob_store::opendal::BlobStore::put_file;
        let _ = crate::blob_store::opendal::BlobStore::operator;
        let _ = crate::blob_store::opendal::BlobStore::object_path;
        let _ = crate::blob_store::opendal::BlobStore::profile;
        let _ = crate::blob_store::config::BlobProfile::credentials;
        let _ = crate::blob_store::config::BlobProfile::object_path;
    }
}
""")
    paths[1].write_text(original[paths[1]]+"""
#[allow(dead_code)]
mod root_blob_sibling_privacy_probe {
    fn sealed_receipt() { let _ = super::BlobReceipt::new; }
}
""")
    negative,text=run('sealed-negative')
    count=len(re.findall(r'error\[E0624\]',text))
    assert negative['returncode']!=0 and count==8 and '`new`' in text and '`put_file`' in text, 'expected eight exact privacy failures; inspect private logs'
    assert 'root_hold_privacy_probe' in paths[0].read_text()
    assert original[paths[2]].count('pub(super) async fn put_file(')==1
    assert original[paths[3]].count('pub(super) fn new(')==1
    paths[2].write_text(original[paths[2]].replace('pub(super) async fn put_file(', 'pub(crate) async fn put_file('))
    paths[3].write_text(original[paths[3]].replace('pub(super) fn new(', 'pub(crate) fn new('))
    paths[4].write_text(original[paths[4]].replace('pub(super) fn ', 'pub(crate) fn '))
    paths[5].write_text(original[paths[5]].replace('pub(super) fn ', 'pub(crate) fn '))
    positive,_=run('permissive-positive-control')
    assert positive['returncode']==0, 'permissive control must compile; inspect private logs'
finally:
    for p,s in original.items():p.write_text(s)
after={str(p.relative_to(root)):sha(p.read_text()) for p in paths}
assert before==after
report=dict(passed=True,base_commit='46b6e87f0c29dfc6b5440147bec9dd010baa8acf',command=command,negative=negative,negative_privacy_errors=count,positive=positive,exact_sources_restored=True,before=before,after=after,limits=['Isolated same-crate compile probes and permissive visibility mutation only; not a runtime hold/upload qualification.','All candidate production inputs were copied to the isolated checkout and their combined source digest verified before probes; no runtime/PG/byte success is qualified here.'])
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(passed=True,privacy_errors=count,permissive_control_passed=True,exact_sources_restored=True)))
