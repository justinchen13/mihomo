#!/usr/bin/env python3
"""CI-only functional/API-cost/build qualification; whole-proxy release gate separate."""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import statistics
import subprocess
import sys
import time

ROOT=Path(os.environ['GITHUB_WORKSPACE']).resolve()
CANDIDATE=ROOT/'src/mihomo'
BASELINE=ROOT/'src/mihomo-base'
PCS=ROOT/'src/pcs-consumer'
PCSBASE=ROOT/'src/pcs-base'
OUT=ROOT/'dist/stage-history'
SOURCE='7ab4483aa23007253800e1ddd576a7ef277be220'
CONSUMER='fa11a3aa2c4059f8298a962ab85e702e35fe6a41'
BASE='00e79a0a478d6cc340ca039bd4f6a021dc3f03de'
PCSBASE_SOURCE='8c1816e571b9c9dcadce158f799fef0812794c45'
VERSION='v1.19.17-pcsproxy5'
BUILD_TIME='2026-10-23T12:38:00Z'
ENV=dict(os.environ,GOTOOLCHAIN='local',GOMAXPROCS='2',GOMEMLIMIT='2GiB',GOFLAGS='-mod=readonly',GOOS='linux',GOARCH='amd64',GOAMD64='v1')
RECORD={'status':'FAIL','runtime_source':SOURCE,'consumer_source':CONSUMER,'baseline_source':BASE,'version':VERSION,'build_time':BUILD_TIME,'phases':[],'tests':{},'deployment':False,'whole_proxy_gate':'PENDING_SEPARATE_FROZEN_WORKLOAD'}

def utc(): return dt.datetime.now(dt.timezone.utc).isoformat()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def git(path,*args):
 return subprocess.check_output(['git',*args],cwd=path,text=True,timeout=20).strip()
def save(): (OUT/'result.json').write_text(json.dumps(RECORD,indent=2)+'\n')

def run(label,args,cwd=CANDIDATE,timeout=180,env=None):
 """Bound output and wall time, kill/reap the entire owned process group."""
 phase={'name':label,'args':args,'started_utc':utc(),'timeout_seconds':timeout}
 RECORD['phases'].append(phase); save()
 log=OUT/(label+'.log'); deadline=time.monotonic()+timeout; written=0; p=None
 try:
  p=subprocess.Popen(args,cwd=cwd,env=dict(ENV,**(env or {})),stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT,start_new_session=True)
  selector=selectors.DefaultSelector();selector.register(p.stdout,selectors.EVENT_READ)
  with log.open('wb') as dest:
   while selector.get_map():
    if time.monotonic()>=deadline: raise TimeoutError('phase wall-time limit')
    for key,_ in selector.select(.2):
     block=os.read(key.fd,65536)
     if not block: selector.unregister(key.fd);continue
     if written+len(block)>16*1024*1024: raise RuntimeError('phase log limit')
     dest.write(block);written+=len(block)
   phase['exit_code']=p.wait(timeout=max(.1,deadline-time.monotonic()))
  return phase['exit_code'],log
 except Exception as exc:
  phase['exception']=type(exc).__name__+': '+str(exc);raise
 finally:
  if p is not None:
   try: os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError: pass
   p.wait(timeout=10)
  phase['ended_utc']=utc();phase['log_bytes']=written
  if log.exists():phase['log_sha256']=sha(log)
  save()

def must(label,args,**kwargs):
 code,log=run(label,args,**kwargs)
 if code: raise RuntimeError(label+' nonzero exit')
 return log

def go_tests(label,packages,pattern='^Test',race=False,cwd=CANDIDATE,negative=False,fixtures=False):
 env={'CGO_ENABLED':'1' if race else '0','PCS_ANYTLS_REAL_DEADLINE':'1'}
 if fixtures:env['PCS_STAGE_HISTORY_FIXTURES']=str(OUT/'source-fixtures')
 args=['go','test','-json','-mod=readonly','-p=2']+(['-race'] if race else [])+packages+['-run',pattern,'-count=1','-timeout=240s']
 code,log=run(label,args,cwd=cwd,timeout=900,env=env)
 events=[]
 for line in log.read_text().splitlines():
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  if isinstance(item,dict):events.append(item)
 skipped=[e.get('Test') for e in events if e.get('Action')=='skip']
 failed=[e.get('Test') for e in events if e.get('Action')=='fail' and e.get('Test')]
 passed=[e.get('Test') for e in events if e.get('Action')=='pass' and e.get('Test')]
 if negative:
  expected='TestStageHistoryCursorRecoversIntermediatePublication'
  if code!=1 or failed!=[expected] or not any('cursor1 returned 3; latest-only cannot recover2' in e.get('Output','') for e in events):raise RuntimeError('baseline negative did not reproduce exact loss')
 else:
  if code or skipped or failed or not passed:raise RuntimeError(label+' failed/skipped/no test evidence')
  if './transport/anytls/session' in packages and 'TestRealTLSDeadPeerWriteBudget' not in passed:raise RuntimeError('required real60s deadline test not passed')
 RECORD['tests'][label]={'exit_code':code,'top_passes':sum('/' not in n for n in passed),'sub_passes':sum('/' in n for n in passed),'skipped':skipped,'failed':failed,'verdict':'EXPECTED_NEGATIVE' if negative else 'PASS'};save()

def publisher_cost(label,cwd):
 log=must(label,['go','test','-mod=readonly','-p=2','./transport/anytls/session','-run','^$',
   '-bench','^BenchmarkStageHistory(Publish32|LegacyRead)$','-benchtime=2000x','-count=3','-timeout=90s'],cwd=cwd,timeout=240,env={'CGO_ENABLED':'0'})
 rows=[]
 for line in log.read_text().splitlines():
  if not line.startswith('BenchmarkStageHistory'):continue
  parts=line.split()
  if parts[1]!='2000' or len(parts[2:])%2:raise RuntimeError('benchmark identity')
  metrics={parts[i+1]:float(parts[i]) for i in range(2,len(parts),2)}
  if not {'cpu-ns/op','B/op','allocs/op'}<=set(metrics) or not all(math.isfinite(x) and x>=0 for x in metrics.values()):raise RuntimeError('cost metrics')
  rows.append({'case':re.sub(r'-\d+$','',parts[0]),'metrics':metrics})
 if len(rows)!=6:raise RuntimeError('missing benchmark repetitions')
 return rows

def main():
 os.umask(0o077);OUT.mkdir(parents=True,exist_ok=False);RECORD['started_utc']=utc();save()
 try:
  if os.environ.get('GITHUB_REPOSITORY')!='justinchen13/mihomo' or os.environ.get('GITHUB_REF')!='refs/heads/pcs/stage-history-20261023':raise RuntimeError('repository/ref guard')
  head=git(CANDIDATE,'rev-parse','HEAD');RECORD['workflow_commit']=head
  if git(BASELINE,'rev-parse','HEAD')!=BASE or git(PCS,'rev-parse','HEAD')!=CONSUMER or git(PCSBASE,'rev-parse','HEAD')!=PCSBASE_SOURCE:raise RuntimeError('checkout identity')
  subprocess.run(['git','merge-base','--is-ancestor',SOURCE,head],cwd=CANDIDATE,check=True,timeout=20)
  after=git(CANDIDATE,'diff','--name-only',SOURCE,head).splitlines()
  if any((p.endswith('.go') and not p.endswith('_test.go')) or p in ('go.mod','go.sum') for p in after):raise RuntimeError('runtime changed after source pin')
  for name,expected in {'go.mod':'23e40f9e1197e44b1709063e5c44c3f8ef7ef38c534aaf8b8094e391d47409db','go.sum':'847577650191553e901df6cd82cfec82d3411351cf3e5d5721720f4519fee374'}.items():
   if sha(CANDIDATE/name)!=expected or sha(BASELINE/name)!=expected:raise RuntimeError('dependency lock drift')
  RECORD['production_go_delta']=sorted(p for p in git(CANDIDATE,'diff','--name-only',BASE,SOURCE).splitlines() if p.endswith('.go') and not p.endswith('_test.go'))
  if set(RECORD['production_go_delta'])!={'transport/anytls/session/stage_evidence.go','transport/anytls/session/stage_export.go','hub/route/anytls_stage.go'}:raise RuntimeError('unexpected production scope')
  must('toolchain',['go','version'],timeout=10)
  causal='transport/anytls/session/stage_history_causal_test.go'
  bench='transport/anytls/session/stage_history_bench_linux_test.go'
  for name in (causal,bench):shutil.copyfile(CANDIDATE/name,BASELINE/name)
  go_tests('baseline-history-negative',['./transport/anytls/session'],'^TestStageHistoryCursorRecoversIntermediatePublication$',cwd=BASELINE,negative=True)
  go_tests('session-listener-normal',['./transport/anytls/session','./listener/anytls'],fixtures=True)
  go_tests('session-listener-race',['./transport/anytls/session','./listener/anytls'],race=True)
  go_tests('unix-route-normal',['./hub/route'],'^TestAnyTLSStage')
  go_tests('unix-route-race',['./hub/route'],'^TestAnyTLSStage',race=True)
  monitor=PCS/'mihomo-anytls/monitor'
  must('consumer-tests',['python3','-m','unittest','discover','-p','test_*.py'],cwd=monitor,timeout=180)
  must('source-consumer-contract',['python3',str(monitor/'validate_history_fixtures.py'),str(OUT/'source-fixtures'),str(OUT/'source-consumer-contract.json')],cwd=monitor,timeout=30)
  rounds=[]
  for i,arm in enumerate('ABBA'):rounds.append({'arm':arm,'rows':publisher_cost('publisher-cost-'+str(i)+'-'+arm,BASELINE if arm=='A' else CANDIDATE)})
  RECORD['publisher_cost']={'order':'ABBA','rounds':rounds,'cases':{}}
  for case in ('BenchmarkStageHistoryPublish32','BenchmarkStageHistoryLegacyRead'):
   a=[r['metrics']['cpu-ns/op'] for v in rounds if v['arm']=='A' for r in v['rows'] if r['case']==case]
   b=[r['metrics']['cpu-ns/op'] for v in rounds if v['arm']=='B' for r in v['rows'] if r['case']==case]
   ratio=statistics.median(b)/statistics.median(a)
   RECORD['publisher_cost']['cases'][case]={'baseline':a,'candidate':b,'ratio':ratio,'gate':'PASS' if case.endswith('LegacyRead') or ratio<=1.10 else 'HOLD_CPU'}
  save()
  if RECORD['publisher_cost']['cases']['BenchmarkStageHistoryPublish32']['ratio']>1.10:raise RuntimeError('publisher CPU regression')
  must('consumer-CPU-cost',['python3',str(CANDIDATE/'tools/pcs-stage-history/consumer_cost.py'),str(PCSBASE/'mihomo-anytls/monitor/stage.py'),str(monitor/'stage.py'),str(OUT/'source-fixtures/cost32.body.json'),str(OUT/'consumer-cost.json')],timeout=180)
  ldflags='-X github.com/metacubex/mihomo/constant.Version='+VERSION+' -X github.com/metacubex/mihomo/constant.BuildTime='+BUILD_TIME+' -s -w -buildid='
  for name,cwd,version in [('baseline',BASELINE,'v1.19.17-pcsproxy4'),('candidate',CANDIDATE,VERSION)]:
   flags=ldflags.replace(VERSION,version)
   binary=OUT/('mihomo-'+name)
   must(name+'-tagged-build',['go','build','-mod=readonly','-p=2','-tags','with_gvisor','-trimpath','-buildvcs=false','-ldflags',flags,'-o',str(binary),'.'],cwd=cwd,timeout=1200,env={'CGO_ENABLED':'0'})
   text=must(name+'-version',[str(binary),'-v'],timeout=10).read_text()
   if version not in text or 'with_gvisor' not in text:raise RuntimeError('binary identity')
   RECORD[name+'_binary']={'sha256':sha(binary),'bytes':binary.stat().st_size,'runtime_source':BASE if name=='baseline' else SOURCE,'tags':['with_gvisor'],'CGO_ENABLED':0};save()
  RECORD['status']='PASS_FUNCTIONAL_API_COST_AND_BUILD_ONLY'
  RECORD['release_status']='HOLD_PENDING_FROZEN_WHOLE_PROXY_98PCT_GOODPUT_105PCT_P95_AND_RUNTIME_SAFETY'
 except Exception as exc:
  RECORD['failure']=type(exc).__name__+': '+str(exc);raise
 finally:RECORD['ended_utc']=utc();save()

if __name__=='__main__':main()
