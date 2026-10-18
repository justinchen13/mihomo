#!/usr/bin/env python3
"""Reviewable remote-only validation: no route fixture or network workload."""
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

BASE = '68b13ec2ba57bbb8aafaedae98255636b4fc1bf5'
SOURCE = '00e79a0a478d6cc340ca039bd4f6a021dc3f03de'
VERSION = 'v1.19.17-pcsproxy4'
BUILD_TIME = '2026-10-18T11:50:53Z'
ROOT = Path(os.environ['GITHUB_WORKSPACE']).resolve()
CANDIDATE, BASELINE = ROOT/'src/mihomo', ROOT/'src/mihomo-base'
OUT = ROOT/'dist/stage-admission'
PACKAGE = './transport/anytls/session'
PREFIX = 'transport/anytls/session/'
NEGATIVE = 'TestStageAdmissionPreservesSlowWriterDuringAuthChurn'
TARGET = [NEGATIVE, 'TestStageAdmissionPreferenceBoundaries',
          'TestStageAdmissionFreeFirstAndAllSlowRotation', 'TestStageAdmissionConcurrentLifecycle']
PURE = [
 'TestStageEvidenceCapacityRotationAndUnknown',
 'TestStageEvidenceSlowRingAndBlockedSinkAreBounded',
 'TestStageEvidenceDefaultOffAndClientRefusal',
 'TestStageEvidenceConcurrentSnapshotAndRotation',
 'TestStageEvidenceDelayedTickerUsesActualCapture',
 'TestStageEvidenceExportQueueAge',
 'TestStageEvidenceSlowEventContainsActualInterval',
 'TestStagePublicationAvailabilityAndImmutableCopy',
 'TestStagePublicationLimitAndFailedExportAreExplicit',
 'TestStagePublicationConcurrentReadersAndOverwrite',
 'TestStagePublicationBypassesBlockedSharedLogSubscriber',
 'TestStagePublicationConsumerFixture',
 'TestStagePublicationBypassesBlockedSharedLogSink',
 'TestStageSlowHeaderFloodCannotConsumeOtherClasses',
 'TestStageSlowClassesBoundedAndQuiescentAccounting',
 'TestStageSlowClassesPayloadOmissionsSeparateFromQueueDrops',
]
LOCKS = {'go.mod':'23e40f9e1197e44b1709063e5c44c3f8ef7ef38c534aaf8b8094e391d47409db',
         'go.sum':'847577650191553e901df6cd82cfec82d3411351cf3e5d5721720f4519fee374'}
ENV = dict(os.environ, GOTOOLCHAIN='local', GOMAXPROCS='2', GOMEMLIMIT='2GiB',
           GOFLAGS='-mod=readonly', GOOS='linux', GOARCH='amd64', GOAMD64='v1')
RECORD = {'status':'FAIL', 'scope':'pure observation-registry validation and tagged diagnostic release candidate; no deployment',
          'runtime_source':SOURCE, 'baseline_source':BASE, 'version':VERSION, 'build_time':BUILD_TIME,
          'network_workload':False, 'deployment':False, 'phases':[], 'tests':{}}

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

def tests(label,names,race=False,cwd=CANDIDATE,expected_negative=False):
 args=['go','test','-json','-mod=readonly','-p=2']
 if race:args+=['-race']
 args += [PACKAGE,'-run','^('+'|'.join(names)+')$','-count=1','-timeout=120s']
 code,log=run(label,args,cwd=cwd,timeout=480 if race else 300,env={'CGO_ENABLED':'1' if race else '0'})
 events=[]
 for line in log.read_text().splitlines():
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  if isinstance(item,dict):events.append(item)
 ran={e.get('Test') for e in events if e.get('Action')=='run' and '/' not in e.get('Test','')}
 passed={e.get('Test') for e in events if e.get('Action')=='pass' and e.get('Test')}
 failed={e.get('Test') for e in events if e.get('Action')=='fail' and e.get('Test')}
 if ran!=set(names):raise RuntimeError(label+' exact test execution mismatch')
 if expected_negative:
  message='slow writer evicted before completion: status=untracked completed=0 lost=1'
  observed=any(e.get('Test')==NEGATIVE and message in e.get('Output','') for e in events)
  if code!=1 or failed!={NEGATIVE} or not observed:raise RuntimeError('baseline failed for unexpected reason or passed')
  verdict='EXPECTED_ASSERTION_FAIL'
 else:
  if code!=0 or failed or not set(names)<=passed:raise RuntimeError(label+' tests failed or skipped')
  verdict='PASS'
 RECORD['tests'][label]={'status':verdict,'run':sorted(ran),'failed':sorted(failed)};save()

def benchmark(label,cwd):
 log=must(label,['go','test','-mod=readonly','-p=2',PACKAGE,'-run','^$',
                 '-bench','^BenchmarkStageAdmissionChurn$','-benchtime=10000x','-count=1','-timeout=60s'],
          cwd=cwd,timeout=180,env={'CGO_ENABLED':'0'})
 rows={}
 for line in log.read_text().splitlines():
  if not line.startswith('BenchmarkStageAdmissionChurn/'):continue
  parts=line.split();case=re.sub(r'-\d+$','',parts[0].split('/',1)[1])
  if case in rows or parts[1]!='10000' or len(parts[2:])%2:raise RuntimeError('benchmark identity/iterations')
  metrics={parts[i+1]:float(parts[i]) for i in range(2,len(parts),2)}
  if set(metrics)!={'ns/op','B/op','allocs/op','cpu-us/op'} or not all(math.isfinite(v) and v>=0 for v in metrics.values()):raise RuntimeError('benchmark metrics')
  rows[case]=metrics
 if set(rows)!={'idle','one_slow_writer','all_slow'}:raise RuntimeError('missing benchmark cases')
 return rows

def main():
 os.umask(0o077);OUT.mkdir(parents=True,exist_ok=False);RECORD['started_utc']=utc();save()
 try:
  if os.environ.get('GITHUB_REPOSITORY')!='justinchen13/mihomo' or os.environ.get('GITHUB_REF')!='refs/heads/pcs/stage-admission-20261018':raise RuntimeError('repository/ref guard')
  head=git(CANDIDATE,'rev-parse','HEAD');RECORD['checkout_commit']=head;RECORD['checkout_tree']=git(CANDIDATE,'rev-parse','HEAD^{tree}')
  if git(BASELINE,'rev-parse','HEAD')!=BASE:raise RuntimeError('baseline identity')
  subprocess.run(['git','merge-base','--is-ancestor',SOURCE,head],cwd=CANDIDATE,check=True,timeout=20)
  changed=git(CANDIDATE,'diff','--name-only',SOURCE,head).splitlines()
  allowed=('.github/workflows/pcs-stage-admission.yml','tools/pcs-stage-admission/','docs/experiments/')
  if any(not any(p==a or (a.endswith('/') and p.startswith(a)) for a in allowed) for p in changed):raise RuntimeError('runtime changed after frozen source')
  for path in (CANDIDATE,BASELINE):
   if git(path,'status','--porcelain'):raise RuntimeError('checkout not clean')
   for name,want in LOCKS.items():
    if sha(path/name)!=want:raise RuntimeError('dependency lock drift')
  version=must('toolchain',['go','version']).read_text().strip()
  if version!='go version go1.25.6 linux/amd64':raise RuntimeError('toolchain drift')
  RECORD['toolchain']=version;RECORD['dependency_sha256']=LOCKS
  RECORD['fixture_sha256']={n:sha(CANDIDATE/PREFIX/n) for n in ['stage_admission_causal_test.go','stage_admission_bench_linux_test.go']}
  for label,path in [('candidate',CANDIDATE),('baseline',BASELINE)]:
   must(label+'-download',['go','mod','download'],cwd=path,timeout=300)
   must(label+'-verify',['go','mod','verify'],cwd=path,timeout=120)
   for name,want in LOCKS.items():
    if sha(path/name)!=want:raise RuntimeError('download modified dependency lock')
  for name in RECORD['fixture_sha256']:
   shutil.copyfile(CANDIDATE/PREFIX/name,BASELINE/PREFIX/name)
  tests('baseline-causal-negative',[NEGATIVE],cwd=BASELINE,expected_negative=True)
  tests('candidate-target-normal',TARGET)
  tests('candidate-target-race',TARGET,race=True)
  tests('candidate-stage-pure',PURE)
  rows=[]
  for i,arm in enumerate('ABBA'):
   rows.append({'arm':arm,'metrics':benchmark('admission-bench-'+str(i)+'-'+arm,BASELINE if arm=='A' else CANDIDATE)})
  RECORD['admission_benchmark']={'order':'ABBA','iterations_per_case':10000,'rounds':rows,
    'performance_gate':'REPORT_ONLY_NOT_NETWORK_OR_RELEASE_COST_ACCEPTANCE','cases':{}}
  for case in rows[0]['metrics']:
   stats={}
   for metric in rows[0]['metrics'][case]:
    a=[r['metrics'][case][metric] for r in rows if r['arm']=='A'];b=[r['metrics'][case][metric] for r in rows if r['arm']=='B']
    am,bm=statistics.median(a),statistics.median(b)
    stats[metric]={'baseline_all':a,'candidate_all':b,'baseline_median':am,'candidate_median':bm,
                   'absolute_delta':bm-am,'ratio':bm/am if am>0 else None}
   RECORD['admission_benchmark']['cases'][case]=stats
  binary=OUT/'mihomo-s2-experimental'
  ldflags='-X github.com/metacubex/mihomo/constant.Version='+VERSION+' -X github.com/metacubex/mihomo/constant.BuildTime='+BUILD_TIME+' -w -s -buildid='
  build=['go','build','-mod=readonly','-p=2','-tags','with_gvisor','-trimpath','-buildvcs=false','-ldflags',ldflags,'-o',str(binary),'.']
  must('tagged-candidate-build',build,timeout=600,env={'CGO_ENABLED':'0'})
  RECORD['binary']={'sha256':sha(binary),'bytes':binary.stat().st_size,'goos':'linux','goarch':'amd64','goamd64':'v1','cgo_enabled':0,'tags':['with_gvisor'],'build_args':build}
  # Version only: never start a server, listener, route fixture, or client.
  text=must('binary-version',[str(binary),'-v'],timeout=10).read_text()
  if VERSION not in text or BUILD_TIME not in text or 'with_gvisor' not in text:raise RuntimeError('binary identity/tags readback')
  must('binary-buildinfo',['go','version','-m',str(binary)],timeout=10)
  for path in (CANDIDATE,BASELINE):
   for name,want in LOCKS.items():
    if sha(path/name)!=want:raise RuntimeError('final dependency lock drift')
  RECORD['status']='PASS_SCOPED_FUNCTIONAL_BUILD_ONLY';RECORD['release_status']='HOLD_PENDING_ARTIFACT_IMAGE_CONSUMER_AND_ROLLOUT_REVIEW'
 except Exception as exc:
  RECORD['failure']=type(exc).__name__+': '+str(exc);raise
 finally:
  RECORD['ended_utc']=utc();save()
if __name__=='__main__':main()
