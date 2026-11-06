#!/usr/bin/env python3
"""Real nested Gitlink and Git LFS checkout from a prepared CI mirror."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

from ci_job_checkouts import JobCheckoutHarness


def make_repo(h, name):
    repo=json.loads(h.expect("/api/repos",201,token=h.alice,method="POST",body={"name":name}))
    work=h.root/name
    h.git("clone",h.base+repo["clone_path"],str(work),token=h.alice)
    h.git("config","user.name","CI Test",cwd=work)
    h.git("config","user.email","ci@example.invalid",cwd=work)
    return repo,work


def link(h,work,path,name,oid):
    (work/".gitmodules").write_text(
        f'[submodule "{name}"]\n\tpath = {path}\n\turl = ../{name}.git\n')
    h.git("add",".gitmodules",cwd=work)
    h.git("update-index","--add","--cacheinfo",f"160000,{oid},{path}",cwd=work)
    h.git("commit","-m",f"pin {name}",cwd=work)
    return h.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    h=JobCheckoutHarness(args)
    h.mirror_env["ROOTYARD_CI_MIRROR_PUBLIC_URL"]=h.mirror_base
    try:
        h.setup();h.api();h.roundtrip()
        h.mirror_env["ROOTYARD_CI_MIRROR_SOURCE_TOKEN"]=h.alice["token"]
        h.start_mirror()
        grand,grand_work=make_repo(h,"grand")
        h.git("lfs","install","--local",cwd=grand_work)
        h.git("lfs","track","big.bin",cwd=grand_work)
        payload=b"nested Git LFS fixture\n"*8192
        (grand_work/"big.bin").write_bytes(payload)
        h.git("add",".gitattributes","big.bin",cwd=grand_work)
        h.git("commit","-m","large immutable input",cwd=grand_work)
        grand_oid=h.git("rev-parse","HEAD",cwd=grand_work).stdout.decode().strip()
        h.git("push","origin","HEAD:main",cwd=grand_work,token=h.alice)
        lfs_oid=hashlib.sha256(payload).hexdigest()
        assert h.sql("SELECT state FROM lfs_objects WHERE repository_id='"+grand["id"]+
            "' AND oid='"+lfs_oid+"'")=="ready"
        child,child_work=make_repo(h,"child")
        child_oid=link(h,child_work,"deps/grand","grand",grand_oid)
        h.git("push","origin","HEAD:main",cwd=child_work,token=h.alice)
        root_oid=link(h,h.work,"deps/child","child",child_oid)
        h.git("push","origin","HEAD:main",cwd=h.work,token=h.alice)
        body=h.request_body(oid=root_oid,job=str(uuid.uuid4()))
        h.pin(h.pin_body(root_oid,body["job_id"],1))
        object_path=h.root/"data"/"lfs"/grand["id"]/lfs_oid
        missing=object_path.with_name(lfs_oid+".temporarily-missing")
        object_path.rename(missing)
        try:
            h.issue(body,codes=409)
        finally:
            missing.rename(object_path)
        grant=h.issue(body)
        deps=grant["plan"]["dependencies"]
        assert len(deps["submodules"])==2 and len(deps["lfs"])==1,deps
        assert deps["lfs"][0]["oid"]==lfs_oid
        credentials={x["name"]:x for x in grant["submodule_credentials"]}
        assert set(credentials)=={"child","grand"}
        root_token={"username":"alice","token":grant["token"]}
        prepare=f"/api/repos/alice/demo/ci-checkouts/{body['job_id']}/prepare-dependencies"
        status,raw,_=h.mirror_http(prepare,token=h.alice,method="POST",body=b"")
        assert status==200,(status,raw[:500])
        grand_token={"username":"alice","token":credentials["grand"]["token"]}
        grand_base=f"/ci/{grand_oid}/git/alice/grand.git/info/lfs/objects"
        batch_status,batch_raw,_=h.mirror_http(grand_base+"/batch",token=grand_token,
            method="POST",body={"operation":"download","objects":[{"oid":lfs_oid,
                "size":len(payload)}]})
        assert batch_status==200,(batch_status,batch_raw[:500])
        get_status,get_raw,_=h.mirror_http(grand_base+"/"+lfs_oid,token=grand_token)
        assert get_status==200 and get_raw==payload,(get_status,get_raw[:200])
        clone=h.root/"nested-build"
        h.git("clone",h.mirror_base+h.path(root_oid),str(clone),token=root_token)
        for name,parent,path in (("child",clone,"deps/child"),
                                 ("grand",clone/"deps/child","deps/grand")):
            item=credentials[name]
            url=f"{h.mirror_base}/ci/{item['target_oid']}/git/alice/{name}.git"
            h.git("config",f"submodule.{name}.url",url,cwd=parent)
            env=h.env.copy();env["GIT_LFS_SKIP_SMUDGE"]="1"
            h.git("submodule","update","--init",path,cwd=parent,
                  token={"username":"alice","token":item["token"]},env=env)
        grand_clone=clone/"deps/child/deps/grand"
        h.git("lfs","install","--local",cwd=grand_clone)
        h.git("config","credential.helper",'!f() { if test "$1" = get; then echo username=alice; echo password="$CI_JOB_TOKEN"; fi; }; f',
              cwd=grand_clone)
        env=h.env.copy();env["CI_JOB_TOKEN"]=grand_token["token"]
        h.git("lfs","pull",cwd=grand_clone,token=grand_token,env=env)
        h.git("lfs","checkout","big.bin",cwd=grand_clone,token=grand_token,env=env)
        observed=(grand_clone/"big.bin").read_bytes()
        assert observed==payload,(len(observed),len(payload))
        assert h.git("rev-parse","HEAD",cwd=grand_clone).stdout.decode().strip()==grand_oid
        h.transition(body["job_id"],"cancel")
        denied,_,_=h.mirror_http(grand_base+"/"+lfs_oid,token=grand_token)
        assert denied in (401,403),denied
        hook_secret="nested-integration-secret-123456"
        hook=json.loads(h.expect("/api/repos/alice/demo/webhooks",201,token=h.alice,
            method="POST",body={"url":"http://127.0.0.1:1/hook","secret":hook_secret,
                "events":["pull_request"],"ci_contexts":["ci/nested"],"auto_ci_pin":True}))
        hook_id=hook["id"]
        h.expect(f"/api/repos/alice/demo/integrations/{hook_id}/trusted-contexts",200,
            token=h.alice,method="PUT",body={"context":"ci/nested"})
        for source in ("child","grand"):
            h.expect(f"/api/repos/alice/{source}/ci-source-grants/{hook_id}",200,
                token=h.alice,method="PUT",body={})
        h.git("checkout","-b","feature",cwd=h.work)
        h.git("commit","--allow-empty","-m","CI feature",cwd=h.work)
        feature_oid=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
        h.git("push","origin","HEAD:feature",cwd=h.work,token=h.alice)
        pr=json.loads(h.expect("/api/repos/alice/demo/pulls",201,token=h.alice,
            method="POST",body={"title":"Nested CI","body":"real dependencies",
                "head_ref":"refs/heads/feature","base_ref":"refs/heads/main"}))
        assert pr["head_oid"]==feature_oid
        run_id=h.sql("SELECT id FROM ci_runs WHERE repository_id='"+h.repo["id"]+
            "' AND context='ci/nested' AND head_oid='"+feature_oid+"'")
        claim_path=f"/api/repos/alice/demo/integrations/{hook_id}/runs/{run_id}/claim"
        status,raw,_=h.http(claim_path,method="POST",body={"runner_id":"nested-runner"},
            extra_headers={"Authorization":"Bearer "+hook_secret})
        assert status==200,(status,raw[:300])
        claim=json.loads(raw)
        assert len(claim["checkout"]["submodule_credentials"])==2
        root_job=claim["checkout"]["plan"]["job_id"]
        service_token={"username":"alice","token":claim["checkout"]["token"]}
        service_prep=f"/api/repos/alice/demo/ci-checkouts/{root_job}/prepare-dependencies"
        status,raw,_=h.mirror_http(service_prep,token=service_token,method="POST",body=b"")
        assert status==200,(status,raw[:300])
        service_clone=h.root/"integration-build"
        h.git("clone",h.mirror_base+h.path(feature_oid),str(service_clone),token=service_token)
        assert h.git("rev-parse","HEAD",cwd=service_clone).stdout.decode().strip()==feature_oid
        print("fenced integration prepared and cloned nested manifest: passed",flush=True)
        (h.work/".gitmodules").write_text(
            '[submodule "child"]\n\tpath = deps/child\n\turl = https://outside.invalid/child.git\n')
        h.git("add",".gitmodules",cwd=h.work)
        h.git("commit","-m","unsafe URL fixture",cwd=h.work)
        unsafe_oid=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
        h.git("push","origin","HEAD:main",cwd=h.work,token=h.alice)
        unsafe_job=str(uuid.uuid4())
        h.pin(h.pin_body(unsafe_oid,unsafe_job,1))
        h.issue(h.request_body(oid=unsafe_oid,job=unsafe_job),codes=409)
        print("stock Git nested pinned submodules and Git LFS: passed",flush=True)
        return 0
    finally:
        h.cleanup()


if __name__=="__main__":sys.exit(main())
