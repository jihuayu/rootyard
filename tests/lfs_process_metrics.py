"""Coordinator-owned real process metrics; no product implementation or secret output."""
import argparse, concurrent.futures, hashlib, json, math, os, statistics, sys, threading, time, urllib.parse
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lfs import LfsHarness
from lfs_hydration_concurrency import S3ControlProxy
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--report',required=True);a=p.parse_args()
e=urllib.parse.urlsplit(os.environ['ROOTYARD_OBJECT_STORE_ENDPOINT'])
assert e.scheme == 'http' and e.hostname in ('127.0.0.1', 'localhost', '::1'), 'use an owned HTTP loopback object-store fixture'
proxy=S3ControlProxy(e.hostname,e.port);proxy.start()
h=LfsHarness(argparse.Namespace(binary=str(Path(a.binary).resolve()),keep=False))
h.env.update(ROOTYARD_OBJECT_STORE_ENDPOINT=f'http://127.0.0.1:{proxy.port}',ROOTYARD_OUTBOX_WORKER='false')
hz=os.sysconf('SC_CLK_TCK')
db_port=urllib.parse.urlsplit(h.base_db).port or 5432
def snap():
 io={k:int(v) for k,v in (line.split(':',1) for line in Path(f'/proc/{h.proc.pid}/io').read_text().splitlines())}
 fields=Path(f'/proc/{h.proc.pid}/stat').read_text().rsplit(')',1)[1].split()
 io.update(cpu_user_ticks=int(fields[11]),cpu_system_ticks=int(fields[12]),rss_bytes=int(fields[21])*os.sysconf('SC_PAGE_SIZE'))
 return io
def count():
 with proxy.lock:return Counter(x['method'] for x in proxy.events if x['kind']=='pass_through')
def ports():
 inodes=set()
 for fd in Path(f'/proc/{h.proc.pid}/fd').iterdir():
  try:
   target=os.readlink(fd)
   if target.startswith('socket:['):inodes.add(target[8:-1])
  except FileNotFoundError:pass
 found=[]
 for f in ('tcp','tcp6'):
  for line in Path(f'/proc/{h.proc.pid}/net/{f}').read_text().splitlines()[1:]:
   x=line.split()
   if x[9] in inodes and int(x[2].split(':')[1],16)==db_port:found.append(int(x[1].split(':')[1],16))
 return found
def summary(ts):
 ts=sorted(ts)
 return {**{f'p{q}_seconds':ts[max(0,math.ceil(q/100*len(ts))-1)] for q in (50,95,99)},'samples_seconds':ts,'sample_count':len(ts)}
def measure(label,n,waves):
 stopped=threading.Event();samples=[];errors=[]
 def sampler():
  while not stopped.is_set():
   try:
    ps=ports()
    if ps:
     value=h.sql("SELECT count(*) || '|' || count(*) FILTER(WHERE state='active') FROM pg_stat_activity WHERE application_name='rootyard' AND client_port IN ("+','.join(map(str,ps))+")")
     total,active=map(int,value.split('|')); samples.append({'monotonic':time.monotonic(),'connections':total,'active_sql':active})
   except Exception as exc:errors.append(type(exc).__name__)
   stopped.wait(.1)
 t=threading.Thread(target=sampler,daemon=True);t.start();before=snap();counts=count();started=time.monotonic();times=[]
 try:
  with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
   for _ in range(waves):
    barrier=threading.Barrier(n)
    def request(_):
     barrier.wait(timeout=10);st=time.monotonic()
     h.lfs_batch('download',[{'oid':oid,'size':size}],token=h.alice)
     status,body,_=h.http(path,token=h.alice)
     assert status==200 and body==payload
     return time.monotonic()-st
    times.extend(pool.map(request,range(n)))
 finally:
  after=snap();elapsed=time.monotonic()-started;stopped.set();t.join(5)
 assert not t.is_alive(),'sampler did not stop'
 delta={k:after[k]-before[k] for k in before if k!='rss_bytes'}
 return {'phase':label,'concurrent_clients':n,'waves':waves,'wall_seconds':elapsed,'served_bytes':size*len(times),'process_deltas':delta,'cpu_seconds':(delta['cpu_user_ticks']+delta['cpu_system_ticks'])/hz,'rss_before_bytes':before['rss_bytes'],'rss_after_bytes':after['rss_bytes'],'rchar_per_served_byte':delta['rchar']/(size*len(times)),'remote_requests':dict(count()-counts),'postgres_connection_samples':samples,'postgres_sampler_error_kinds':errors,**summary(times)}
try:
 h.setup();h.api();payload=os.urandom(8*1024*1024);size=len(payload);oid=hashlib.sha256(payload).hexdigest()
 b=h.lfs_batch('upload',[{'oid':oid,'size':size}],token=h.alice);h.lfs_put(b['objects'][0]['actions']['upload']['href'],payload,token=h.alice)
 path=f'/git/alice/demo.git/info/lfs/objects/{oid}/{size}';final=Path(h.env['ROOTYARD_DATA_DIR'])/'lfs'/h.repo['id']/oid
 results=[]
 for clients in (1,4,16):
  h.stop();h.start();results.append(measure('restart_existing_local_empty_cache',clients,1))
  results.append(measure('warm_batch_get',clients,max(2,32//clients)))
  final.unlink();results.append(measure('remote_cold_batch_get',clients,1))
 assert not proxy.errors,proxy.errors
 report={'binary_sha256':hashlib.sha256(Path(a.binary).read_bytes()).hexdigest(),'object_bytes':size,'results':results,'scope':'Actual native Rust service / configured PostgreSQL and owned S3-compatible fixture through counting proxy, one host, random8MiB object; endpoints and tokens excluded.','limitations':['Debug build; timings under shared host load, no production throughput/SLA inference. Small cold samples give empirical order statistics only.','rchar counts all process read syscalls; read_bytes/write_bytes kernel storage accounting can be zero due pagecache; no direct disk device busy measurement.','PostgreSQL samples match service-owned TCP client ports: active_sql counts executing/waiting SQL, total counts physical pooled connections. Checked-out idle clients/pool waiter counts are not directly instrumented; these are not exact busy pool occupancy.','CPU ticks are service process CPU including internal worker threads; excludes PostgreSQL/Garage CPU.']}
 Path(a.report).write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps({'binary_sha256':report['binary_sha256'],'phases':len(results),'report':a.report}),flush=True)
finally:h.cleanup();proxy.stop()
