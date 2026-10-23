"""F3 fixed quiet, copied with explicit injected controller dependency.
Not executed here. Caller must already own/validate the supplied controller's
cgroup and processes. No API, ss, qdisc or adaptive quiet behavior is added.
"""
import json
import os
import time


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def save(path, value):
    data = json.dumps(value, separators=(',', ':')).encode()+b'\n'
    require(len(data) <= 262144, 'quiet_evidence_limit')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def quiet_cpu_snapshot(netlab):
    # Bounded read of this already-owned cgroup only. All process CPU clocks
    # include their threads. Exited/new tasks make task delta unknown, not zero.
    began=time.monotonic();utc=netlab.utc();cg=netlab.cg_path()
    before=sorted(set(int(x) for x in (cg/'cgroup.procs').read_text().split()))
    require(len(before)<=256,'quiet_task_capture_limit')
    cpu=netlab.values(cg/'cpu.stat');tasks=[];complete=True
    for pid in before:
        try:
            identity=netlab.pid_identity(pid)
            stats=netlab.process_stats(pid)
            require(netlab.pid_identity(pid)==identity,'quiet_task_identity_changed')
            tasks.append({'pid':pid,'start_ticks':identity['start_ticks'],'CPU_ns':stats['cpu_ns']})
        except (FileNotFoundError,ProcessLookupError,OSError,RuntimeError):
            complete=False
    after=sorted(set(int(x) for x in (cg/'cgroup.procs').read_text().split()))
    complete=complete and before==after and len(tasks)==len(before)
    return {'capture_started_utc':utc,'capture_started_monotonic':began,
            'capture_finished_utc':netlab.utc(),'capture_finished_monotonic':time.monotonic(),
            'cpu_stat':cpu,'tasks':tasks,'task_capture_complete':complete,
            'total_task_CPU_ns':sum(x['CPU_ns'] for x in tasks) if complete else None,
            'scope':'ownedcgroup processCPUclock includes threads; exited tasks not reconstructed; cpu.stat remains wholecgroup'}


def fixed_quiet_before_go(out, processes, netlab):
    before=quiet_cpu_snapshot(netlab)
    # Preserve first boundary before waiting; no ss/API/qdisc/subprocess/probe.
    save(out/'quiet-before.private.json',before)
    began=time.monotonic();utc=netlab.utc();deadline=began+1.2
    while time.monotonic()<deadline:
        time.sleep(max(0,deadline-time.monotonic()))
    wait_end=time.monotonic();end_utc=netlab.utc()
    require(all(p.poll() is None for p in processes),'owned_process_during_fixed_quiet_exit')
    after=quiet_cpu_snapshot(netlab)
    identities=lambda x:[(t['pid'],t['start_ticks']) for t in x['tasks']]
    comparable=before['task_capture_complete'] and after['task_capture_complete'] and identities(before)==identities(after)
    delta=after['total_task_CPU_ns']-before['total_task_CPU_ns'] if comparable else None
    if delta is not None and delta<0:comparable=False;delta=None
    return {'fixed_wait_seconds':1.2,'wait_started_utc':utc,'wait_started_monotonic':began,
            'wait_finished_utc':end_utc,'wait_finished_monotonic':wait_end,
            'actual_wait_seconds':wait_end-began,'before':before,'after':after,
            'task_CPU_comparable':comparable,'total_task_CPU_delta_seconds':delta/1e9 if delta is not None else None,
            'policy':'fixedonce; residualactivityreported; noadaptivewait/retry/quotaorgatechange; snapshotsnon-atomic'}
