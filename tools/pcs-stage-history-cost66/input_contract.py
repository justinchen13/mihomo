"""Static workspace-only identity contract; no process or network operations."""
import hashlib, os, re
from workload_contract import validate_selection
from pathlib import Path
HELPERS=('run.py','adjudicate.py','numeric_core.py','collector-wrapper.py',
         'runtime_security.py','runtime_protocol.py','client-v3.go','input_contract.py','launch.sh','build-client.sh','prepare.py','history_contract.py','cleanup_contract.py','workload_contract.py')
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def fixed_path(value,workspace,exists=True):
 p=Path(value)
 assert p.is_absolute() and p==p.resolve(strict=exists),'path must be canonical, no symlinks'
 assert p.is_relative_to(workspace) and p!=workspace,'outside explicit workspace'
 assert not any(p.is_relative_to(Path(x)) for x in ('/root/deploy','/opt','/var/lib','/etc','/proc','/sys','/run')),'production/system input refused'
 return p
def validate_manifest(m,root):
 validate_selection(m)
 w=Path(m['workspace']);assert w.is_absolute() and w==w.resolve(strict=True) and w!=Path('/')
 assert root.is_relative_to(w),'adapter not inside workspace'
 assert m['profiles']==[1,32,66] and m['order']==['A','B','B','A']
 assert m['gates']=={'goodput_median_min_ratio':.98,'p95_median_max_ratio':1.05,'proxy_cpu_max_ratio':1.20,'collector_cpu_max_ratio':1.20,'rss_max_extra_bytes':16777216}
 assert re.fullmatch(r'sha256:[0-9a-f]{64}',m['runtime_image_id'])
 for p,s in m['files'].items():
  f=fixed_path(p,w);assert f.is_file() and re.fullmatch('[0-9a-f]{64}',s)
  assert sha(f)==s,'frozen input digest mismatch'
 for name in HELPERS:assert str(root/name) in m['files'],'unbound helper'
 for label in ('A','B'):
  a=m['arms'][label];assert re.fullmatch('[0-9a-f]{40}',a['source_commit'])
  assert a['inner_schema'] in (1,2) and type(a['inner_schema']) is int
  assert a['enabled'] is True and a['producer_enabled'] is True and a['reader_enabled'] is True
  p=fixed_path(a['binary_path'],w);assert m['files'][str(p)]==a['server_binary_sha256'] and os.access(p,os.X_OK),'server non-executable or unbound'
  c=fixed_path(a['collector_dir'],w);assert c.is_dir()
  for n,k in (('stage.py','stage_module_sha256'),('monitor.py','monitor_sha256'),('proxy_rollup.py','rollup_sha256')):
   assert m['files'][str(c/n)]==a[k],'consumer unbound'
  for p in c.glob('*.py'):assert str(p) in m['files'],'unfrozen consumer dependency'
 client=fixed_path(m['client_binary'],w);assert str(client) in m['files'] and os.access(client,os.X_OK)
 assert m['client_source']==str(root/'client-v3.go')
 output=fixed_path(m['output_root'],w,False)
 assert not output.exists() and not output.is_relative_to(root),'new output must be outside immutable adapter'
 assert not any(Path(p).is_relative_to(output) for p in m['files'])
