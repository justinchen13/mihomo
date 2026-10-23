#!/usr/bin/env python3
"""Prepare frozen identities from explicit inputs after CI builds; never builds/runs proxies."""
import argparse,json,os,datetime
from pathlib import Path
from input_contract import HELPERS,sha,fixed_path,validate_manifest
from workload_contract import validate_selection

def main():
 p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();os.umask(0o077)
 root=Path(__file__).resolve().parent;raw=json.loads(a.inputs.read_text());w=Path(raw['workspace']).resolve(strict=True)
 m={'schema':'history-whole-proxy-cost66-v1','status':'FROZEN_FOR_EXECUTION','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'workspace':str(w),'runtime_image_id':raw['runtime_image_id'],'profiles':[1,32,66],'selected_profile':raw['selected_profile'],'execution_mode':raw['execution_mode'],'workload':raw['workload'],'order':['A','B','B','A'],'client_source':str(root/'client-v3.go'),'client_binary':str(fixed_path(raw['client_binary'],w)),'output_root':str(fixed_path(raw['output_root'],w,False)),'gates':{'goodput_median_min_ratio':.98,'p95_median_max_ratio':1.05,'proxy_cpu_max_ratio':1.20,'collector_cpu_max_ratio':1.20,'rss_max_extra_bytes':16777216},'files':{},'arms':{},'scope':'actual whole proxy + respective collector; capped66s load; one selected profile per invocation, no capacity claim','build_provenance':{}}
 validate_selection(m)
 for name in HELPERS:m['files'][str(root/name)]=sha(root/name)
 m['files'][m['client_binary']]=sha(m['client_binary'])
 for label,name in (('A','baseline'),('B','candidate')):
  x=raw[name];binary=fixed_path(x['binary'],w);consumer=fixed_path(x['consumer_dir'],w)
  assert sha(binary)==x['binary_sha256'],'supplied server binary mismatch'
  provenance=fixed_path(x['provenance'],w);pr=json.loads(provenance.read_text())
  assert pr['source_commit']==x['source_commit'] and pr['binary_sha256']==x['binary_sha256'],'reviewed build provenance mismatch'
  m['files'][str(provenance)]=sha(provenance);m['files'][str(binary)]=x['binary_sha256'];m['build_provenance'][label]=str(provenance)
  for f in consumer.glob('*.py'):m['files'][str(fixed_path(str(f),w))]=sha(f)
  arm={'arm':name+'_diagnostics_on','source_commit':x['source_commit'],'binary_path':str(binary),'server_binary_sha256':x['binary_sha256'],'collector_dir':str(consumer),'inner_schema':x['inner_schema'],'diagnostic_capability':x['diagnostic_capability'],'enabled':True,'producer_enabled':True,'reader_enabled':True,'stage_http_before':200,'stage_http_after':200}
  for file,key in (('stage.py','stage_module_sha256'),('monitor.py','monitor_sha256'),('proxy_rollup.py','rollup_sha256')):arm[key]=sha(consumer/file)
  m['arms'][label]=arm
 client_proof=fixed_path(raw['client_provenance'],w);cp=json.loads(client_proof.read_text())
 assert cp['binary_sha256']==m['files'][m['client_binary']] and cp['source_sha256']==sha(root/'client-v3.go') and cp['go_version']=='go1.25.6','client build provenance mismatch'
 m['files'][str(client_proof)]=sha(client_proof);m['build_provenance']['client']=str(client_proof)
 validate_manifest(m,root)
 target=fixed_path(str(a.output),w,False);data=(json.dumps(m,indent=2)+'\n').encode()
 with target.open('xb') as f:f.write(data)
 os.chmod(target,0o600);print(sha(target))
if __name__=='__main__':main()
