#!/usr/bin/env python3
"""Two fixed baseline-only native AnyTLS trials in owned network namespaces."""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess as sp
import sys
import time

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parent
F3 = R.parent/'loop-20261018/anytls-concurrent-f3'
sys.path.insert(0, str(F3))
def module(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    obj = importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
old = module('owned_f3', F3/'run.py')
net = old.netlab
contract = module('r04_contract', R/'fixture/contract.py')
quiet = module('r04_quiet', R/'fixture/quiet.py')
SERVER = Path('/root/proxy-source-lab/loop-20261018/anytls-stage-s2/formal-artifact-import/run-1/verified/mihomo-s2-experimental')
CLIENT = R/'validation-2/build/causal-client'
SERVER_SHA = '09f63bde838eb9391b7dcf15e8568368b98510dd52662b050420f3c391cfe85c'
CLIENT_SHA = 'a352dec234add87184ed83fc5d658548c07cd255ecfdca754807ce1fdccc1a4b'
def save(path,obj): net.save(path,obj)
def append(path,obj): old.append_evidence(path,obj)
def require(ok,code): net.require(ok,code)
def sha(path): return net.digest(path)

class Lab(old.Lab):
    def start(self, role, argv, name, **kwargs):
        if name == 'origin':
            require(role == 'S' and argv[:3] == [str(CLIENT), '--mode', 'origin'], 'origin_adapter_identity')
            argv = [*argv, '--isolated-lab']
        return super().start(role, argv, name, **kwargs)

def profile():
    p=copy.deepcopy(json.loads((old.MODEL/'network-plan.json').read_text())['profiles']['main'])
    p['rate_bits_per_second']=1600000
    p['modeled_rate_decimal_MB_per_second']=.2
    p['forward_propagation_BDP_bytes_at_rate']=15000
    p.pop('propagation_capacity_basis',None)
    p.pop('payload_goodput_qualification_decimal_MB_per_second',None)
    p['purpose']='R04 new finite6MiB native workload; actual fresh qualification required, not old800kbit qualification'
    return p

def resource(before,after):
    wall=after['monotonic']-before['monotonic']
    a,b=before['cpu'],after['cpu']
    keys=('usage_usec','throttled_usec','nr_periods','nr_throttled')
    valid=wall>0 and all(type(a.get(k)) is int and type(b.get(k)) is int and b[k]>=a[k] for k in keys)
    memory={k:after['memory_events'][k]-before['memory_events'][k] for k in ('high','max','oom','oom_kill')}
    return {'wall_s':wall,'cpu_s':(b['usage_usec']-a['usage_usec'])/1e6,
            'throttled_s':(b['throttled_usec']-a['throttled_usec'])/1e6,
            'counter_barrier':valid,'memory_event_deltas':memory}

def tcp(lab,ports,bulk):
    rows=lab.sockets(ports)
    for x in rows:
        x['role']='loaded' if x['outer_ordinal']==bulk else 'independent'
        raw=x['raw_synthetic']
        for key,pattern in [('effective_sendbuffer_bytes',r'\btb(\d+)'),('skmem_queued_write_bytes',r'\bw(\d+)')]:
            m=re.search(pattern,raw);x['socket'][key]=int(m.group(1)) if m else None
    return rows

def inner(args):
    os.umask(0o077)
    out=Path(args.out)
    p=profile();lab=Lab(out,p,args.unit,'bbr')
    before_host=net.host_network();save(out/'host-before.private.json',before_host)
    result={'status':'RUNNING','started_utc':net.utc(),'bulk_outer':args.bulk}
    save(out/'result.json',result)
    watcher=None;cleanup=None
    try:
        require(shutil.disk_usage(R).free>=1073741824,'start_disk_below1GiB')
        require(sha(SERVER)==SERVER_SHA and sha(CLIENT)==CLIENT_SHA,'binary_identity')
        require((net.cg_path()/'cpu.max').read_text().strip()=='400000 1000000','CPU_exact_period')
        sock=old.OwnedSocket(out)
        watcher=old.ArtifactWatch(out,guard_diagnostics={},diagnostics={},owned_socket=sock)
        old._artifact_watch=watcher
        lab.setup_cc()
        env0=net.environment.collect(lab,'before')
        namespace_buffers={role:{k:lab.run(role,['sysctl','-n','net.ipv4.'+k]).stdout.strip()
                                for k in ('tcp_rmem','tcp_wmem','tcp_notsent_lowat','tcp_congestion_control')}
                           for role in ('S','C')}
        save(out/'namespace-buffers.json',namespace_buffers)
        origin,proxy,path=old.configure(lab,out,{'server_binary':str(SERVER),'fixture_binary':str(CLIENT)},sock)
        client=lab.start('C',[str(CLIENT),'--mode','client','--dir',str(out),'--ca',str(out/'cert.pem'),
                             '--users',str(out/'users.json'),'--bulk-outer',str(args.bulk),'--isolated-lab'],'client')
        ready=old.wait_json(out/'client-ready.json',time.monotonic()+36,[origin,proxy,client],out)
        require(ready['readers_armed']==ready['writers_armed']==ready['unique_streams']==33 and
                ready['tls_verified']==ready['padding_verified']==ready['outer_sessions']==2,'client_readiness')
        require(ready['measured_application_queue'] is False,'application_serialization')
        require(140<=contract.percentile(ready['idle_echo_ms'],.5)<=180,'new_model_idle_RTT')
        ports=ready['synthetic_local_ports'];pre=tcp(lab,ports,args.bulk)
        save(out/'TCP-before.private.json',pre)
        require(all(x['socket'].get('valid') and x['socket']['algorithm']=='bbr' and
                    type(x['socket'].get('effective_sendbuffer_bytes')) is int for x in pre),'server_socket_policy')
        raw=lab.run('S',['ss','-Htinmpeo','state','established','( sport = :19081 or dport = :19081 )']).stdout
        save(out/'upstream-context.private.json',{'raw':raw})
        blocks=[]
        for line in raw.splitlines():
            if line and not line[0].isspace():blocks.append([line])
            elif blocks:blocks[-1].append(line)
        upstream=[net.parse_tcp('\n'.join(b)+'\n') for b in blocks]
        require(len(upstream)==66 and all(x.get('valid') and x.get('algorithm')=='bbr' for x in upstream),'upstream_socket_policy')
        clocks={label:os.readlink(f'/proc/{pid}/ns/time') for label,pid in
                [('runner',os.getpid()),('origin',origin.pid),('proxy',proxy.pid),('client',client.pid)]}
        save(out/'clock-scope.json',clocks);require(len(set(clocks.values()))==1,'time_namespace')
        stage=module('r04_live_compatible_consumer',Path('/opt/pcs-anytls-monitor/stage.py'))
        diag=out/'diagnostic';diag.mkdir(mode=0o700)
        reader=stage.StageReader(path,os.urandom(32),diag/'cursor.json',enabled=True)
        writer=stage.StageLog(diag)
        scope=json.dumps([lab.holders['S'],net.pid_identity(proxy.pid)],sort_keys=True)
        save(out/'stage-outer-join.private.json',{'outer_sessions':[{'outer_ordinal':x['outer_ordinal'],'role':x['role'],
             'stage_socket_id':stage.identity(reader.key,json.dumps([scope,'cookie',format(int(x['socket']['cookie'],16),'x')]))} for x in pre]})
        q0=lab.qdiscs()
        silent=quiet.fixed_quiet_before_go(out,[proxy,origin,client],net)
        save(out/'quiet-after.private.json',silent)
        cg0=old.resources(out,'before_GO');go=time.monotonic();(out/'go').touch()
        first=None;next_tcp=go+1.15;next_stage=go+10;samples=[];acks=[]
        while time.monotonic()-go<49:
            now=time.monotonic()
            require(proxy.poll() is None and origin.poll() is None,'service_early_exit')
            if first is None and now>=go+1.020:first=old.resources(out,'first')
            if (out/'client-result.json').exists():break
            if now>=next_tcp:
                x={'time':net.utc(),'monotonic':now,'server':tcp(lab,ports,args.bulk),'qdisc':lab.qdiscs()}
                append(out/'samples.private.jsonl',x);samples.append(x);next_tcp=now+1
            if now>=next_stage:
                ack=stage.collect_regular_stage(reader,writer,scope,regular_tick=now,next_regular=now+10)
                append(out/'stage-acks.jsonl',{'time':net.utc(),'ack':ack});acks.append(ack);next_stage=now+10
            old.bounded(out);time.sleep(.01)
        else:raise RuntimeError('client_result_deadline')
        cg1=old.resources(out,'after_workload')
        work=json.loads((out/'client-result.json').read_text());q1=lab.qdiscs()
        save(out/'TCP-after.private.json',tcp(lab,ports,args.bulk))
        env1=net.environment.collect(lab,'after')
        # Source final ledger is collected only after client and proxy cleanup;
        # a legal Write-return/receipt ordering cannot invalidate a one-shot snapshot.
        (out/'finish').touch();client_rc=client.wait(timeout=10)
        proxy.terminate()
        try:proxy.wait(timeout=5)
        except sp.TimeoutExpired:proxy.kill();proxy.wait(timeout=2)
        (out/'stop').touch();origin_rc=origin.wait(timeout=5)
        final=json.loads((out/'origin-result.json').read_text())
        require(first is not None,'first_resource_missing')
        deltas={k:q1[k]['drops']-q0[k]['drops'] for k in ('rate','propagation','reverse')}
        require(all(type(v) is int and v>=0 for v in deltas.values()),'qdisc_counter_barrier')
        require(deltas['propagation']==deltas['reverse']==0,'external_propagation_drop')
        require(len(samples)>=10,'inside_TCP_population')
        expected=[(x['socket']['cookie'],x['socket']['inode']) for x in pre]
        require(all(len(x['server'])==2 and all(y['socket'].get('valid') and y['socket']['algorithm']=='bbr' and
                    (y['socket']['cookie'],y['socket']['inode'])==expected[i] for i,y in enumerate(x['server'])) for x in samples),'TCP_identity_barrier')
        base=work['start']['monotonic_ns']/1e9;ending=work['end']['monotonic_ns']/1e9
        timing={'controller_GO_monotonic':go,'client_base_monotonic':base,'before_cgroup_monotonic':cg0['monotonic'],
                'first_cgroup_monotonic':first['monotonic'],'client_end_monotonic':ending,'after_cgroup_monotonic':cg1['monotonic'],
                'first_since_client_base_seconds':first['monotonic']-base}
        save(out/'resource-boundaries.json',timing)
        require(0<=base-go<=.020 and 1<=first['monotonic']-base<=1.05 and 0<=cg1['monotonic']-ending<=.1,'resource_workload_alignment')
        # Reap the namespace holders before cleanup and host comparison qualify.
        cleanup=lab.stop();host_same=net.host_network()==before_host
        required_files=['client-result.json','origin-result.json','TCP-before.private.json','TCP-after.private.json',
            'resources.private.jsonl','samples.private.jsonl','namespace-identities.json','clock-scope.json',
            'namespace-buffers.json','network-readback.json','stage-acks.jsonl','stage-outer-join.private.json',
            'diagnostic/stage.jsonl','quiet-before.private.json','quiet-after.private.json']
        raw_proof=[]
        for name in required_files:
            file=out/name
            require(file.is_file() and not file.is_symlink() and 0<file.stat().st_size<=4194304,'required_raw_file_missing_or_limited')
            content=file.read_bytes()
            if name.endswith('.jsonl'):
                require(content.endswith(b'\n'),'partial_raw_line')
                parsed=[json.loads(line) for line in content.splitlines()]
                require(bool(parsed),'empty_raw_lines')
                if name=='samples.private.jsonl':require(len(parsed)==len(samples),'raw_TCP_count')
            else:json.loads(content)
            raw_proof.append({'path':name,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()})
        watcher.check()
        save(out/'raw-provenance.json',raw_proof)
        normalized={'same_time_namespace':len(set(clocks.values()))==1,'owned_cleanup':cleanup['owned_processes_absent'],
                    'host_unchanged':host_same,'all_workers_reaped':work['unjoined_workers']==0 and final['all_handlers_joined'],
                    'raw_evidence_complete':len(raw_proof)==len(required_files) and watcher.d['coverage_passes']>0 and not watcher.d.get('failure'),
                    'same_server_identity':sha(SERVER)==SERVER_SHA,'tls_padding_readback':ready['tls_verified']==ready['padding_verified']==2,
                    'cpu_max':[int(x) for x in (net.cg_path()/'cpu.max').read_text().split()],
                    'memory_max':int((net.cg_path()/'memory.max').read_text()),'swap_max':int((net.cg_path()/'memory.swap.max').read_text()),
                    'oom_delta':cg1['memory_events']['oom']-cg0['memory_events']['oom'],'origin_exit_code':origin_rc,
                    'quiet':{'elapsed_s':silent['actual_wait_seconds'],'process_identities_stable':silent['task_CPU_comparable']},
                    'first':resource(cg0,first),'whole':resource(cg0,cg1),
                    'raw_provenance':{'resources':'resources.private.jsonl','boundaries':'resource-boundaries.json',
                        'unit':args.unit,'client_exit':client_rc,'origin_exit':origin_rc}}
        require(client_rc==0,'client_exit')
        require(env0['sha256']==env1['sha256'],'namespace_environment_changed')
        save(out/'resources.normalized.json',normalized)
        qualification=contract.analyse(work,final,normalized)
        save(out/'qualification.safe.json',qualification)
        result.update(status=qualification['status'],qualification_failures=qualification['failures'],
                      pair_summary=qualification.get('pair_summary'),qdisc_drop_deltas=deltas,
                      client_exit=client_rc,origin_exit=origin_rc,mechanism='UNKNOWN_PENDING_INSIDEEVENT_TCP_STAGE_AUDIT',
                      owned_cleanup=cleanup,host_unchanged=host_same)
    except BaseException as exc:
        result.update(status='FAILED_OR_INCONCLUSIVE',error_type=type(exc).__name__,reason=str(exc)[:300])
    finally:
        cleanup=cleanup or lab.stop();result['owned_cleanup']=cleanup
        result['host_unchanged']=net.host_network()==before_host
        if watcher:
            try:watcher.finish();result['artifact_watch']=watcher.d
            except BaseException as exc:result['artifact_failure']=type(exc).__name__;result['status']='FAILED_OR_INCONCLUSIVE';watcher.close()
        result['finished_utc']=net.utc();save(out/'result.json',result)
    return 0 if result['status']=='QUALIFIED_PROTOCOL_LATENCY_ONLY' and result['host_unchanged'] and cleanup['owned_processes_absent'] else 1

def outer():
    expected=json.loads((R/'network-manifest.json').read_text())
    require(expected['status']=='FROZEN_BEFORE_NETWORK','network_not_frozen')
    require(all(sha(Path(p))==h for p,h in expected['inputs'].items()),'frozen_network_input_changed')
    require(sha(SERVER)==SERVER_SHA and sha(CLIENT)==CLIENT_SHA,'frozen_binary_changed')
    root=R/'network-results';root.mkdir(mode=0o700)
    matrix={'status':'RUNNING','started_utc':net.utc(),'rows':[]}
    with open('/run/lock/pcs-proxy-experiment.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            for ordinal in (0,1):
                out=root/f'{ordinal}-bulk{ordinal}';out.mkdir(mode=0o700)
                unit='pcs-causal-r04-'+secrets.token_hex(5)+'.service';desc='PCS R04 causal baseline '+unit
                args=['systemd-run','--quiet','--wait','--collect','--unit',unit,'-p','Description='+desc,
                      '-p','CPUQuota=40%','-p','CPUQuotaPeriodSec=1s','-p','MemoryMax=512M','-p','MemorySwapMax=0',
                      '-p','TasksMax=256','-p','RuntimeMaxSec=160','-p','TimeoutStopSec=10','-p','KillMode=control-group',
                      sys.executable,'-B',str(Path(__file__).resolve()),'--inside','--unit',unit,'--out',str(out),'--bulk',str(ordinal)]
                save(root/'current-handle.json',{'unit':unit,'description':desc,'out':str(out),'bulk_outer':ordinal,'argv':args})
                try:
                    with (out/'unit.stdout').open('w') as stdout,(out/'unit.stderr').open('w') as stderr:
                        completed=sp.run(args,stdout=stdout,stderr=stderr,timeout=185)
                finally:
                    unit_cleanup={'status':'FAILED_OR_UNKNOWN','utc':net.utc()}
                    try:
                        props=dict(x.split('=',1) for x in net.cmd(['systemctl','show',unit,'-p','Description','-p','ControlGroup','-p','ActiveState'],check=False).stdout.splitlines() if '=' in x)
                        if props.get('ActiveState') in ('active','activating','deactivating','reloading'):
                            require(props.get('Description')==desc and props.get('ControlGroup','').endswith('/'+unit),'unit_owner_unknown')
                            net.cmd(['systemctl','stop',unit],timeout=15)
                        final=dict(x.split('=',1) for x in net.cmd(['systemctl','show',unit,'-p','ActiveState','-p','LoadState','-p','MainPID'],check=False).stdout.splitlines() if '=' in x)
                        unit_cleanup['final_unit']=final
                        require(final.get('LoadState')=='not-found' or (final.get('ActiveState') in ('inactive','failed') and final.get('MainPID')=='0'),'unit_terminal_state_unknown')
                        cg=Path('/sys/fs/cgroup/system.slice')/unit
                        require(not cg.exists() or net.values(cg/'cgroup.events')['populated']==0,'owned_cgroup_populated')
                        holders=json.loads((out/'namespace-identities.json').read_text()) if (out/'namespace-identities.json').exists() else {}
                        for identity in holders.values():
                            try:require(net.pid_identity(identity['pid'])!=identity,'namespace_holder_survived')
                            except FileNotFoundError:pass
                        unit_cleanup.update(status='PASS',cgroup_absent_or_empty=True,holders_absent=True)
                    except BaseException as exc:
                        unit_cleanup.update(status='FAILED_OR_UNKNOWN',error_type=type(exc).__name__,reason=str(exc)[:300])
                    finally:
                        try:
                            for name in ('users.json','key.pem','config.json'):(out/name).unlink(missing_ok=True)
                            unit_cleanup['synthetic_secrets_absent']=all(not (out/name).exists() for name in ('users.json','key.pem','config.json'))
                        except BaseException as exc:
                            unit_cleanup.update(status='FAILED_OR_UNKNOWN',secret_cleanup_error=type(exc).__name__)
                        save(out/'unit-cleanup.safe.json',unit_cleanup)
                result=json.loads((out/'result.json').read_text());result['outer_cleanup']=unit_cleanup
                matrix['rows'].append(result);save(root/'matrix.json',matrix)
                require(completed.returncode==0 and result['status']=='QUALIFIED_PROTOCOL_LATENCY_ONLY' and unit_cleanup['status']=='PASS' and unit_cleanup.get('synthetic_secrets_absent') is True,'first_failure_stops')
            matrix['status']='BOTH_PLACEMENTS_PROTOCOL_QUALIFIED_MECHANISM_PENDING'
        except BaseException as exc:
            matrix.update(status='STOPPED_FIRST_FAILURE_RETAINED',reason=str(exc)[:300],error_type=type(exc).__name__)
        finally:
            matrix['finished_utc']=net.utc();save(root/'matrix.json',matrix)
    print(json.dumps({'status':matrix['status'],'completed_rows':len(matrix['rows'])}))
    return 0 if matrix['status']=='BOTH_PLACEMENTS_PROTOCOL_QUALIFIED_MECHANISM_PENDING' else 1

if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('--inside',action='store_true');p.add_argument('--unit');p.add_argument('--out');p.add_argument('--bulk',type=int,choices=(0,1));args=p.parse_args()
    sys.exit(inner(args) if args.inside else outer())
