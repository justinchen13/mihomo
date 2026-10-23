#!/usr/bin/env python3
"""R03 cost66 both-enabled comparison; fixed workload and inode-bound owned cleanup.
All older runners/results retained. No implicit retry, deployment or probing.

Run only after manifest freeze and assigned shared-lock slot. Every process that
carries fixture traffic belongs to the same bounded transient parent slice.
"""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import statistics
import subprocess
import sys
import time
import types
from history_contract import row_metadata, row_gate, tick_gate, ticks_from_events
from cleanup_contract import helper_readback, classify_unit, parse_properties, cgroup_readback
from workload_contract import workload, validate_client, RUNNER_DEADLINE_SECONDS

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT
WRAPPER = ROOT/'collector-wrapper.py'
LOCK = '/run/lock/pcs-proxy-experiment.lock'
SCHEME = 'stop=3\n0=30-30\n1=300-300\n2=600-600'


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path, value):
    data = json.dumps(value, indent=2, allow_nan=False) + '\n'
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(data)
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def owns_container(info, cid, owner, image):
    return (isinstance(cid,str) and len(cid)==64 and all(c in '0123456789abcdef' for c in cid)
            and info.get('Id')==cid and info.get('Image')==image
            and (info.get('Config',{}).get('Labels') or {}).get('pcs.lab.owner')==owner)


def runtime_resources_match(info):
    h=info.get('HostConfig') or {}
    return (h.get('NetworkMode')=='none' and not h.get('PortBindings')
            and h.get('NanoCpus')==400000000 and h.get('Memory')==536870912
            and h.get('MemorySwap')==536870912 and h.get('PidsLimit')==512)


def exact_container_absent(outcome,name):
    return (outcome.returncode==1 and outcome.stdout.strip() in ('','[]')
            and outcome.stderr.strip() in ('Error: No such object: '+name,
              'Error response from daemon: No such container: '+name,
              'Error: No such container: '+name))


def implicit_volume_mounts(mounts, declared, previous_names):
    expected={path.rstrip('/') for path in declared}
    assert expected in (set(),{'/root/.config/mihomo'}),'unexpected image volume declaration'
    volumes=[]
    for mount in mounts:
        if mount.get('Type')=='bind':continue
        assert mount.get('Type')=='volume','unknown mount type'
        name=mount.get('Name')
        assert isinstance(name,str) and len(name)==64 and all(c in '0123456789abcdef' for c in name),'not an automatic anonymous-volume ID'
        assert name not in previous_names,'volume existed before owned container creation'
        assert mount.get('Driver')=='local' and mount.get('Destination','').rstrip('/') in expected,'unexpected implicit volume'
        volumes.append(mount)
    assert len(volumes)==len(expected),'missing or extra implicit volume'
    return volumes


def same_volume_identity(actual, expected):
    # Docker20.10 local CreatedAt is _data ctime, which changes on initialization.
    # Keep it in the evidence, but bind directory identity using dev+inode below.
    return all(actual.get(k)==expected.get(k) for k in ('Name','Driver','Labels','Options','Scope','Mountpoint'))


def volume_directory_identity(mountpoint):
    path=Path(mountpoint)
    assert path.is_absolute() and path.resolve(strict=True)==path,'volume directory symlink or noncanonical path'
    info=os.lstat(path)
    assert stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),'volume mountpoint is not a directory'
    return {'device':info.st_dev,'inode':info.st_ino,'file_type':stat.S_IFMT(info.st_mode),'symlink':False}


def same_volume_mounts(current, expected):
    keys=('Type','Name','Source','Destination','Driver')
    normalize=lambda rows:sorted([tuple(str(row.get(k)) for k in keys) for row in rows if row.get('Type')=='volume'])
    return normalize(current)==normalize(expected)


def cmd(argv, timeout=15, check=True):
    return subprocess.run([str(x) for x in argv], check=check, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def wait(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(.02)
    raise TimeoutError('fixture readiness')


def proc(pid):
    raw = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    return {'pid': pid, 'start_ticks': int(raw[19]),
            'cpu_seconds': (int(raw[11]) + int(raw[12])) / os.sysconf('SC_CLK_TCK'),
            'rss_bytes': int(status['VmRSS'].split()[0]) * 1024,
            'hwm_bytes': int(status['VmHWM'].split()[0]) * 1024}


def cgroup_for_pid(pid):
    value = Path(f'/proc/{pid}/cgroup').read_text().strip()
    assert value.startswith('0::/') and '\n' not in value, 'cgroup v2 required'
    return Path('/sys/fs/cgroup') / value[4:]


def cg(path):
    out = {'path': str(path)}
    for name in ('cpu.stat', 'memory.events'):
        out[name] = {k: int(v) for k, v in (line.split() for line in (path/name).read_text().splitlines())}
    for name in ('cpu.max', 'memory.max', 'memory.swap.max', 'memory.current', 'memory.peak'):
        out[name] = (path/name).read_text().strip()
    return out


def cgdelta(a, b):
    return {'cpu_seconds': (b['cpu.stat']['usage_usec']-a['cpu.stat']['usage_usec'])/1e6,
            'throttled_seconds': (b['cpu.stat']['throttled_usec']-a['cpu.stat']['throttled_usec'])/1e6,
            'memory_events':{k:b['memory.events'][k]-a['memory.events'][k] for k in ('high','max','oom','oom_kill')},
            'oom': b['memory.events']['oom']-a['memory.events']['oom'],
            'oom_kill': b['memory.events']['oom_kill']-a['memory.events']['oom_kill']}


def pdelta(a, b):
    assert a['pid'] == b['pid'] and a['start_ticks'] == b['start_ticks'], 'process epoch changed'
    return b['cpu_seconds'] - a['cpu_seconds']


def unix_get(path, endpoint='/diagnostics/anytls-stage'):
    # Qualification only; timed stage requests use the actual StageReader.
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(1)
        s.connect(str(path))
        s.sendall(f'GET {endpoint} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
        b = bytearray()
        while len(b) < 80*1024:
            part = s.recv(8192)
            if not part:
                break
            b.extend(part)
        header, body = bytes(b).split(b'\r\n\r\n', 1)
        assert header.split()[1] == b'200', 'fixture Unix status'
        return json.loads(body)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompleteAPIResponse(http.client.HTTPResponse):
    """Test-only completion check around the original monitor API helper.

    http.client read(amt) can accept premature EOF with a remaining declared
    Content-Length. Reject that case even when the prefix happens to be JSON.
    Actual request, 4MiB cap, JSON decoding and timeout stay in unix_snapshot.
    """
    def begin(self):
        super().begin()
        lengths=self.headers.get_all('Content-Length') or []
        encodings=self.headers.get_all('Transfer-Encoding') or []
        if len(lengths)>1 or (lengths and encodings):
            raise ValueError('ambiguous fixture API framing')
        if lengths and (not lengths[0].isdigit() or self.length is None):
            raise ValueError('invalid fixture API content length')
        if encodings and (len(encodings)!=1 or encodings[0].lower()!='chunked'):
            raise ValueError('unsupported fixture API transfer encoding')

    def read(self, amt=None):
        body=super().read(amt)
        if self.length not in (None,0):
            raise http.client.IncompleteRead(body,self.length)
        return body


def load_collector_monitor(collector_dir):
    # Qualification runs in this host process; the timed collector already has
    # its own explicit module path. Bind only the pinned sibling dependency,
    # then restore the prior import context even when loading fails.
    missing=object()
    previous=sys.modules.get('proxy_rollup',missing)
    try:
        sibling=load_module(collector_dir/'proxy_rollup.py','frozen_warmup_rollup')
        sys.modules['proxy_rollup']=sibling
        return load_module(collector_dir/'monitor.py','frozen_warmup_monitor')
    finally:
        if previous is missing:sys.modules.pop('proxy_rollup',None)
        else:sys.modules['proxy_rollup']=previous


def api_snapshot(collector_dir, socket_path):
    monitor=load_collector_monitor(collector_dir)
    class CompleteAPIConnection(http.client.HTTPConnection):
        response_class=CompleteAPIResponse
    # Replace only this freshly loaded module's http object; never mutate the
    # shared stdlib module or the actual running collector process.
    monitor.http=types.SimpleNamespace(client=types.SimpleNamespace(HTTPConnection=CompleteAPIConnection))
    return monitor.unix_snapshot(socket_path)


def stage_summary(folder, go_time, completed_time, n, enabled):
    path = folder/'monitor/stage.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    selected = []
    window_rows=[r for r in rows if go_time <= dt.datetime.fromisoformat(r['time'].replace('Z','+00:00')) <= completed_time]
    window_stages=[r.get('stage') or {} for r in window_rows]
    delivery_rows=[row_metadata(r) for r in window_rows]
    delivery_checks=[row_gate(r) for r in delivery_rows]
    all_delivery_rows_valid=bool(delivery_checks) and all(r['pass'] for r in delivery_checks)
    # All delivered rows are checked even when observations were cropped or
    # capture predates GO. Such rows cannot disappear through the selection below.
    current_rows=[r for r,m,c in zip(window_rows,delivery_rows,delivery_checks)
                  if c['pass'] and (m['history_delivery'] is None or m['current_gauges_eligible'] is True)]
    current_stage_rows=[r['stage'] for r in current_rows if isinstance(r['stage'].get('observations'),dict)]
    unexpected=sum(r.get('availability')!='ready' for r in window_stages)
    epochs={r.get('epoch_id') for r in window_stages if r.get('availability')=='ready'}
    sequences=[r.get('sequence') for r in window_stages if r.get('availability')=='ready']
    sequence_ok=bool(sequences) and all(type(x) is int for x in sequences) and all(b>=a for a,b in zip(sequences,sequences[1:]))
    sequence_steps=[b-a for a,b in zip(sequences,sequences[1:])] if sequence_ok else None
    sequence_gaps=sum(max(0,step-1) for step in sequence_steps) if sequence_steps is not None else None
    for row in rows:
        stage = row.get('stage') or {}
        obs = stage.get('observations')
        if stage.get('availability') != 'ready' or not obs:
            continue
        capture = dt.datetime.fromisoformat(obs['capture_started'].replace('Z', '+00:00'))
        if go_time <= capture <= completed_time:
            selected.append(stage)
    unique = {r['sequence']: r for r in selected}
    ordinary_path=folder/'monitor/samples.jsonl'
    ordinary=[json.loads(l) for l in ordinary_path.read_text().splitlines()] if ordinary_path.exists() else []
    socket_ids={s['socket_id'] for row in ordinary for s in (row.get('tcp') or {}).get('sockets',[]) if s.get('identity_certain') and s.get('role')=='client'}
    stage_ids={s['socket_id'] for r in current_stage_rows for s in r['observations']['sessions'] if s.get('socket_id') and s.get('status')=='active'}
    joined=len(socket_ids & stage_ids)
    valid = list(unique.values())
    expected_tracked = min(n, 32)
    population_ok = bool(current_stage_rows) and all(
        r['observations']['live_authenticated_sessions'] == n and
        r['observations']['tracked_live_sessions'] == expected_tracked and
        r['observations']['untracked_live_sessions'] == n-expected_tracked for r in current_stage_rows)
    # Compare same-epoch cumulative counters; retain first values as lifetime,
    # do not pretend startup terminal loss is measured-window loss.
    counters = ['evicted_sessions_total', 'lost_completion_total', 'lost_batch_total',
                'lost_slow_event_total', 'lost_terminal_record_total']
    losses = {k: {'first_lifetime': valid[0]['observations'][k],
                  'last_lifetime': valid[-1]['observations'][k],
                  'window_delta': valid[-1]['observations'][k]-valid[0]['observations'][k]}
              for k in counters} if valid else None
    out = {'enabled': enabled, 'rows_total': len(rows),'window_unexpected_availability':unexpected,'window_epoch_count':len(epochs),'window_sequence_monotonic':sequence_ok,
           'window_sequence_steps':sequence_steps,'window_missing_sequence_numbers':sequence_gaps,
           'window_duplicate_sequence_count':sum(step==0 for step in sequence_steps) if sequence_steps is not None else None,
           'window_noncontiguous_publications':sum(r.get('publication_contiguous') is not True for r in window_stages),
           'sequence_gap_scope':'Numbers skipped between ready records inside workload only; first record continuity to warmup is retained in raw rows, not invented.',
           'distinct_ready_publications_in_workload': len(valid),
           'population_correct': population_ok if enabled else None,
           'exact_cookie_identity_joins':joined if enabled else None,
           'expected_tracked': expected_tracked if enabled else 0,
           'expected_untracked': n-expected_tracked if enabled else None,
           'loss_counters': losses,
           'payload_limited_publications': sum(r['observations']['payload_limited'] for r in valid),
           'max_age_ms': max((r['capture_age_ms'] for r in delivery_checks if r['capture_age_ms'] is not None), default=None),
           'max_capture_age_ms': max((r['capture_age_ms'] for r in delivery_checks if r['capture_age_ms'] is not None), default=None),
           'max_latest_age_ms': max((r['latest_age_ms'] for r in delivery_checks if r['latest_age_ms'] is not None), default=None),
           'history_freshness_gate':all_delivery_rows_valid,
           'delivery_rows':delivery_rows,'delivery_checks':delivery_checks,
           'historical_deliveries':sum(r['historical'] for r in delivery_checks),
           'consumer_payload_limited_deliveries':sum(r['consumer_payload_limited'] is True for r in delivery_rows),
           'missing_observation_deliveries':sum(r['observations_present'] is False and r['duplicate'] is not True for r in delivery_rows),
           'current_population_samples':len(current_stage_rows),
           'population_scope':'Only valid latest/current-gauges-eligible rows; historical active records are never current population.',
           'all_diagnostic_not_failure': all((r.get('stage') or {}).get('fault_count_increment') == 0 for r in rows),
           'publication_gate': (all_delivery_rows_valid and len(valid) >= 3 and unexpected==0 and len(epochs)==1 and None not in epochs and sequence_ok and sequence_gaps==0 and population_ok and joined>=1 and all(not r['observations']['payload_limited'] and len([s for s in r['observations']['sessions'] if s['status']=='active' and s['inflight_known']])==expected_tracked and
                r['failed_exports_total'] == 0 for r in valid) and losses['lost_batch_total']['window_delta'] == 0)
                if enabled else not rows,
           'privacy_note': 'Only counts here; private monitor files retain scoped HMACs, never raw cookie/token.'}
    return out


def regular_summary(folder, go_time, completed_time):
    path = folder/'monitor/samples.jsonl'
    all_rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    rows = [r for r in all_rows if go_time <= dt.datetime.fromisoformat(r['time'].replace('Z', '+00:00')) <= completed_time]
    gaps = [(dt.datetime.fromisoformat(b['time'])-dt.datetime.fromisoformat(a['time'])).total_seconds()
            for a,b in zip(rows,rows[1:])]
    complete=bool(rows) and all(all(k in r for k in ('tcp','api','log','process','collection_ms','issues','rollup_previous_error')) and
         all(k in r['tcp'] for k in ('rows_truncated','parse_errors','sockets')) and 'rows_truncated' in r['api'] for r in rows)
    tls=[r['tls'] for r in all_rows if 'tls' in r]
    return {'rows':len(rows),'issues':sum(bool(r.get('issues')) for r in rows),
            'max_gap_seconds':max(gaps,default=None),'complete_tcp_api_log':complete,
            'max_collection_ms_excluding_output_rollup_stage':max(r['collection_ms'] for r in rows) if complete else None,
            'tcp_rows_truncated_max':max(r['tcp']['rows_truncated'] for r in rows) if complete else None,
            'tcp_parse_errors':sum(r['tcp']['parse_errors'] for r in rows) if complete else None,
            'api_rows_truncated_max':max(r['api']['rows_truncated'] for r in rows) if complete else None,
            'rollup_errors':sum(bool(r['rollup_previous_error']) for r in rows) if complete else None,
            'tls_rows_including_warmup':len(tls),'tls_ok':bool(tls) and all(r.get('ok') is True for r in tls),
            'tls_scope':'unchanged 300s cadence; the positive control is normally in warmup, not every 66s workload',
            'boundary':'66s workload qualification, not later >=5min natural acceptance; shared lab netns includes both socket ends, so regular512 truncation is explicit'}


def timing_summary(folder, start_mono, end_mono, enabled):
    path=folder/'collector-timing.jsonl'
    events=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    footers=[r for r in events if r.get('event')=='wrapper_end']
    cycles=[r for r in events if r.get('event')=='cycle_complete' and type(r.get('regular_start_monotonic')) in (int,float) and start_mono <= r['regular_start_monotonic'] <= end_mono]
    operations=[r for r in events if r.get('event')=='exit' and start_mono <= r['monotonic'] <= end_mono]
    stage_ops=[r for r in operations if r.get('operation')=='stage_collect']
    tick_audit=ticks_from_events(events,start_mono,end_mono)
    all_deliveries_acknowledged=bool(tick_audit) and all(tick_gate(t)['pass'] for t in tick_audit)
    ack_ok=lambda a:isinstance(a,dict) and a.get('output_status')=='written' and a.get('checkpoint_status')=='saved' and a.get('availability')=='ready' and a.get('output_failures_total')==0 and a.get('cursor_failures_total')==0
    offsets=[dt.datetime.fromisoformat(r['utc'].replace('Z','+00:00')).timestamp()-r['monotonic'] for r in events]
    footer=footers[-1] if footers else {}
    stderr=(folder/'collector.private.log').read_text() if (folder/'collector.private.log').exists() else ''
    max_cycle=max((r['full_cycle_seconds'] for r in cycles if r.get('timing_known')),default=None)
    full_known=bool(cycles) and all(r.get('timing_known') is True and r.get('full_cycle_seconds') is not None for r in cycles)
    rollup_known=bool(cycles) and all(type(r.get('last_rollup_error')) is bool for r in cycles)
    return {'cycles':len(cycles),'full_cycle_seconds_max':max_cycle,'all_cycle_timing_known':full_known,
            'utc_monotonic_offset_span_seconds':max(offsets)-min(offsets) if offsets else None,
            'rollup_error_known':rollup_known,'rollup_errors':sum(r['last_rollup_error'] for r in cycles) if rollup_known else None,
            'stage_calls_in_window':len(stage_ops),'all_stage_acks_ok':all_deliveries_acknowledged and all(ack_ok(r.get('ack')) for r in stage_ops) if enabled else not stage_ops,
            'per_tick_request_row_ack_validation':[{'stage_tick':t['stage_tick'],**t['validation']} for t in tick_audit],
            'last_ack':footer.get('last_ack'),'footer_seen':bool(footers),'footer_last_rollup_error':footer.get('last_rollup_error'),
            'gate':len(cycles)>=3 and full_known and max_cycle<=10 and rollup_known and not any(r['last_rollup_error'] for r in cycles)
              and bool(footers) and footer.get('collector_exit_code')==0 and footer.get('timing_output_failed') is False
              and footer.get('last_rollup_error') is False
              and footer.get('active_call') is None and not any('PCS_COLLECTOR_WRAPPER_' in l for l in stderr.splitlines())
              and bool(offsets) and max(offsets)-min(offsets)<=.1
              and ((all_deliveries_acknowledged and len(stage_ops)>=3 and all(ack_ok(r.get('ack')) for r in stage_ops) and ack_ok(footer.get('last_ack'))) if enabled else (not stage_ops and footer.get('last_ack') is None)),
            'note':'Exact original functions; wrapper marker overhead is included. Its shutdown-only trace fsync is outside proxy workload CPU; actual stage append/cursor fsync is inside each cycle.'}


def stage_route(socket_path, enabled):
    """Qualification-only exact status check; no invented old inactive state."""
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(1)
        sock.connect(str(socket_path))
        sock.sendall(b'GET /diagnostics/anytls-stage HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        response=CompleteAPIResponse(sock)
        response.begin()
        body=response.read(65537)
        assert len(body)<=65536, 'bounded stage qualification body'
        expected=200 if enabled else 404
        assert response.status==expected, 'wrong release arm diagnostic capability'
        if not enabled:
            return {'http_status':404,'availability':'unsupported_route_404'}
        result=json.loads(body)
        result['http_status']=200
        return result


class Trial:
    def __init__(self, args, folder, n, enabled):
        self.args,self.folder,self.n,self.enabled = copy.copy(args),folder,n,True
        self.comparison_arm = 'B' if enabled else 'A'
        binding=args.arms[self.comparison_arm]
        self.inner_schema = binding['inner_schema']
        if not enabled:self.args.proxy_binary=args.baseline_binary
        self.args.collector_dir = args.candidate_collector_dir if enabled else args.baseline_collector_dir
        self.source=binding['source_commit']
        self.arm=binding['arm']
        self.capability=binding['diagnostic_capability']
        self.create_attempted=False
        self.allow_container_cleanup=True
        self.previous_volumes=set()
        self.expected_binds={}
        self.ident = 'pcs-history-cost66-'+secrets.token_hex(4)
        self.slice = self.ident+'.slice'
        self.container = self.ident+'-proxy'
        self.container_owner = secrets.token_hex(16)
        self.container_id = None
        self.container_image = None
        self.anonymous_volumes = []
        self.anonymous_volumes_verified = False
        self.anonymous_directory_identities = {}
        self.owned_mounts = []
        self.units = []
        self.unit_proofs = {}
        self.controller = Path('/run')/self.ident
        self.phase = 'init'
        self.proxy_pid = None
        self.parent = None
        self.members = {}

    def unit(self, role, argv, limited=False):
        unit = self.ident+'-'+role+'.service'
        self.units.append(unit)
        description='pcs-history-cost-owned:'+self.container_owner
        self.unit_proofs[unit]={'unit':unit,'description':description,'pid':None,'start_ticks':None,'cgroup_path':None}
        save(self.folder/'owned-helper-units.private.json',self.unit_proofs)
        props = ['-p','Description='+description,'-p','UMask=0077','-p','Environment=GOMAXPROCS=1 GOMEMLIMIT=384MiB','-p',f'StandardOutput=append:{self.folder/(role+".private.log")}',
                 '-p',f'StandardError=append:{self.folder/(role+".private.log")}']
        if limited:
            props += ['-p','CPUQuota=10%','-p','MemoryMax=96M','-p','MemorySwapMax=0','-p','Nice=10']
        cmd(['systemd-run','--quiet','--collect','--service-type=exec','--unit',unit,'--slice',self.slice,*props,'--',*argv])
        pid = int(cmd(['systemctl','show',unit,'-p','MainPID','--value']).stdout.strip())
        assert pid > 0
        proof=self.unit_proofs[unit]
        proof.update(pid=pid,start_ticks=proc(pid)['start_ticks'],cgroup_path=str(cgroup_for_pid(pid)))
        save(self.folder/'owned-helper-units.private.json',self.unit_proofs)
        ownership=classify_unit(cmd(['systemctl','show',unit,'--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ControlGroup'],check=False),proof)
        assert ownership['known'] and ownership['owned'],'created helper ownership unknown'
        if self.parent:
            assert cgroup_for_pid(pid).is_relative_to(self.parent), 'helper escaped parent resource cap'
        self.members[role] = pid
        return pid


    def capture_owned_proof(self,cid):
        f=self.folder
        self.anonymous_volumes=[]
        self.anonymous_directory_identities={}
        info=json.loads(cmd(['docker','inspect',cid]).stdout)[0]
        assert owns_container(info,cid,self.container_owner,self.container_image),'created container ownership mismatch'
        assert info.get('Name')=='/'+self.container,'exact owner name changed'
        binds=[m for m in info['Mounts'] if m['Type']=='bind']
        assert len(binds)==len(self.expected_binds) and len({m['Destination'] for m in binds})==len(binds),'bind mount count/destinations'
        assert all(type(m.get('RW')) is bool and self.expected_binds.get(m['Destination'])==(m['Source'],m['RW']) for m in binds),'unexpected bind source/mode'
        mounts=implicit_volume_mounts(info['Mounts'],self.args.image_declared_volumes,self.previous_volumes)
        self.owned_mounts=info['Mounts']
        save(f/'owned-mounts.private.json',{'container_id':cid,'owner':self.container_owner,'image':self.container_image,
             'all_mounts':info['Mounts'],'declared_volumes':self.args.image_declared_volumes,'previous_volume_names_private':sorted(self.previous_volumes),
             'created_at':info['Created'],'captured_utc':utc()})
        for mount in mounts:
            name=mount['Name'];volume=json.loads(cmd(['docker','volume','inspect',name]).stdout)[0]
            assert volume['Name']==name and volume['Driver']=='local' and volume.get('Scope')=='local'
            assert not volume.get('Labels') and not volume.get('Options'),'named or externally configured volume refused'
            assert volume['Mountpoint']==mount['Source'],'volume mountpoint mismatch'
            refs=cmd(['docker','ps','-aq','--no-trunc','--filter','volume='+name]).stdout.splitlines()
            assert set(refs)=={cid},'implicit volume already shared'
            self.anonymous_directory_identities[name]=volume_directory_identity(volume['Mountpoint'])
            self.anonymous_volumes.append(volume)
        self.anonymous_volumes_verified=True
        save(f/'owned-anonymous-volumes.private.json',{'verified_utc':utc(),'volumes':self.anonymous_volumes,'directory_identities':self.anonymous_directory_identities,
             'proof':'image implicit VOLUME; name absent beforecreate; actual returned owner CID is sole reference; no named volume argument'})
        return info

    def setup(self, load=True, management=False):
        f=self.folder
        assert shutil.disk_usage(ROOT).free>=1024**3,'start disk below frozen1GiB floor'
        f.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.controller.mkdir(mode=0o700)
        fixture=f/'fixture';fixture.mkdir(mode=0o700)
        users={name:secrets.token_urlsafe(24) for name in ('fixture-one','fixture-two')}
        save(fixture/'users.json',users)
        (fixture/'alias.key').write_bytes(os.urandom(32));os.chmod(fixture/'alias.key',0o600)
        cmd(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1',
             '-subj','/CN=anytls-runtime.test','-addext','subjectAltName=DNS:anytls-runtime.test,DNS:localhost',
             '-keyout',fixture/'key.pem','-out',fixture/'cert.pem'])
        for p in fixture.iterdir():os.chmod(p,0o600)
        config={'log-level':'warning','external-controller-unix':'/controller/controller.sock',
                'rules':['MATCH,DIRECT'],'listeners':[{'name':'fixture-anytls','type':'anytls',
                'listen':'127.0.0.1','port':7443,'users':users,
                'certificate':'/root/.config/mihomo/pcs-fixture/cert.pem',
                'private-key':'/root/.config/mihomo/pcs-fixture/key.pem','padding-scheme':SCHEME,
                'stage-evidence':self.enabled}]}
        if not self.enabled:config['listeners'][0].pop('stage-evidence')
        if management:
            secret=secrets.token_urlsafe(24);save(fixture/'management.json',{'secret':secret})
            config.update({'secret':secret,'external-controller':'127.0.0.1:9090','external-controller-tls':'127.0.0.1:9091',
                           'tls':{'certificate':'/root/.config/mihomo/pcs-fixture/cert.pem','private-key':'/root/.config/mihomo/pcs-fixture/key.pem'}})
        save(fixture/'config.yaml',config)
        self.phase='resource_setup'
        self.unit('anchor',['/usr/bin/sleep','240'])
        cmd(['systemctl','set-property','--runtime',self.slice,'CPUQuota=40%','MemoryMax=512M','MemorySwapMax=0','TasksMax=1024'])
        self.parent=Path('/sys/fs/cgroup')/cmd(['systemctl','show',self.slice,'-p','ControlGroup','--value']).stdout.strip().lstrip('/')
        initial=cg(self.parent);q,p=map(int,initial['cpu.max'].split())
        assert q/p <= .4 and int(initial['memory.max']) == 512*1024*1024 and initial['memory.swap.max']=='0'
        common=['--network','none','--cgroup-parent',self.slice,'--cpus','.4','--memory','512m','--memory-swap','512m',
                '--pids-limit','512','-e','GOMAXPROCS=1','-e','GOMEMLIMIT=384MiB',
                '-v',f'{fixture}:/root/.config/mihomo/pcs-fixture:ro',
                '-v',f'{self.controller}:/controller',
                '-v',f'{self.args.proxy_binary}:/mihomo:ro','--entrypoint','/mihomo']
        # One owned lifecycle: same binary validates then execs the server.
        # Both config loads remain before authenticated priming and fixed13s warmup.
        common[common.index('--entrypoint')+1]='/bin/sh'
        self.phase='runtime_create'
        self.expected_binds={'/root/.config/mihomo/pcs-fixture':(str(fixture),False),
            '/controller':(str(self.controller),True),'/mihomo':(str(self.args.proxy_binary),False)}
        save(f/'fixture-lifecycle.json',{'config_validation':'same owned container, /mihomo -t then exec /mihomo',
             'entirely_before_GO':True,'warmup_seconds_unchanged':13,'additional_validation_container':False})
        # Capture existing names before create. No explicitly named volume is
        # supplied by this fixture; image VOLUME is Docker-generated per trial.
        self.previous_volumes=set(cmd(['docker','volume','ls','-q']).stdout.splitlines())
        assert len(self.previous_volumes)<=4096,'volume inventory exceeds bounded preflight'
        self.container_image=self.args.runtime_image
        self.create_attempted=True
        save(f/'create-attempt.private.json',{'name':self.container,'owner':self.container_owner,
            'image':self.container_image,'previous_volumes':sorted(self.previous_volumes),'expected_binds':self.expected_binds,'utc':utc()})
        startup='/mihomo -f /root/.config/mihomo/pcs-fixture/config.yaml -t && exec /mihomo -f /root/.config/mihomo/pcs-fixture/config.yaml'
        cid=cmd(['docker','create','--name',self.container,'--label','pcs.lab.owner='+self.container_owner,*common,self.args.runtime_image,'-c',startup],timeout=25).stdout.strip()
        assert len(cid)==64 and all(c in '0123456789abcdef' for c in cid),'invalid created container ID'
        self.container_id=cid
        self.container_image=self.args.runtime_image
        before_start=self.capture_owned_proof(cid)
        assert runtime_resources_match(before_start),'prestart runtime resource mismatch'
        cmd(['docker','start',cid],timeout=25)
        info=json.loads(cmd(['docker','inspect',cid]).stdout)[0]
        assert owns_container(info,cid,self.container_owner,self.container_image),'started container ownership mismatch'
        self.proxy_pid=info['State']['Pid'];self.members['proxy']=self.proxy_pid
        assert info['HostConfig']['NetworkMode']=='none' and not info['HostConfig']['PortBindings']
        h=info['HostConfig'];assert h['NanoCpus']==400000000 and h['Memory']==536870912 and h['MemorySwap']==536870912 and h['PidsLimit']==512,'actual runtime resource mismatch'
        assert cgroup_for_pid(self.proxy_pid).is_relative_to(self.parent)
        assert os.readlink(f'/proc/{self.proxy_pid}/ns/net') != os.readlink('/proc/1/ns/net')
        wait(self.controller/'controller.sock',12)
        original_mode=oct(stat.S_IMODE((self.controller/'controller.sock').stat().st_mode))
        os.chmod(self.controller/'controller.sock',0o600)
        version=cmd(['docker','exec',self.container,'/mihomo','-v']).stdout
        assert 'with_gvisor' in version,'missing production tag'
        scope=json.dumps([info['Id'],info['State']['StartedAt'],os.readlink(f'/proc/{self.proxy_pid}/ns/net')])
        save(f/'scope.json',{'scope':scope,'socket_path':str(self.controller/'controller.sock')})
        self.before_auth=stage_route(self.controller/'controller.sock',self.enabled)
        save(f/'runtime.json',{'source':self.source,'source_commit':self.source,'arm':self.arm,'comparison_arm':self.comparison_arm,'inner_schema':None,'diagnostic_capability':self.capability,
           'server_binary_sha256':sha(self.args.proxy_binary),'binary_sha256':sha(self.args.proxy_binary),
           'stage_http_before':self.before_auth['http_status'],'stage_http_after':None,
           'producer_enabled':self.enabled,'reader_enabled':self.enabled,
           'client_sha256':sha(self.args.client_binary),'stage_module_sha256':sha(self.args.collector_dir/'stage.py'),
           'monitor_sha256':sha(self.args.collector_dir/'monitor.py'),'rollup_sha256':sha(self.args.collector_dir/'proxy_rollup.py'),'image':info['Image'],
           'version':version.strip(),'enabled':self.enabled,'outer_sessions':self.n,
           'selected_profile':self.args.selected_profile,'workload_contract':workload(),
           'isolated_network':True,'no_published_ports':True,'controller_directory_mode':'0o700',
           'socket_created_mode':original_mode,'socket_applied_mode':'0o600','resource_limits':initial})
        if self.enabled:assert self.before_auth['availability']=='inactive' and self.before_auth['snapshot'] is None
        else:assert self.before_auth['availability']=='unsupported_route_404' and 'snapshot' not in self.before_auth
        self.phase='fixture_setup'
        ns=['/usr/bin/nsenter','-t',str(self.proxy_pid),'-n']
        listen_deadline=time.monotonic()+8
        while ':7443 ' not in cmd([*ns,'ss','-Hlnpt']).stdout:
            if time.monotonic()>listen_deadline:raise TimeoutError('proxy listener readiness')
            time.sleep(.05)
        inventory=cmd([*ns,'ss','-Hlnpt']).stdout
        ports=sorted({int(line.split()[3].rsplit(':',1)[1]) for line in inventory.splitlines()})
        assert ports==([7443,9090,9091] if management else [7443]), 'unexpected TCP listener'
        save(f/'listener-inventory.json',{'ports':ports,'management_fixture_only':management,'time':utc()})
        if not load:return
        self.unit('origin',[*ns,self.args.client_binary,'--mode','origin','--dir',f])
        wait(f/'origin-ready.json',8)
        self.unit('client',[*ns,self.args.client_binary,'--mode','client','--dir',f,'--sessions',str(self.n),
                           '--ca',fixture/'cert.pem','--users',fixture/'users.json'])
        wait(f/'client-ready.json',40)
        ready=json.loads((f/'client-ready.json').read_text())
        assert ready['outer_sessions']==self.n and ready['tls_verified']==self.n and ready['streams']==3*self.n
        assert ready['outer_source_bind_verified']==self.n,'client source bind not verified'
        monitor=f/'monitor';monitor.mkdir(mode=0o700)
        shutil.copyfile(fixture/'alias.key',monitor/'alias.key');os.chmod(monitor/'alias.key',0o600)
        monitor_args=[*ns,'/usr/bin/env',f'SSL_CERT_FILE={fixture/"cert.pem"}',
            '/usr/bin/python3',WRAPPER,'--collector-dir',self.args.collector_dir,'--timing-output',f/'collector-timing.jsonl','--','--output',monitor,'--socket',self.controller/'controller.sock',
            '--container',self.container,'--server-name','localhost','--port','7443','--interval','10']
        if self.enabled:monitor_args.append('--stage-evidence')
        self.unit('collector',monitor_args,limited=True)
        collector_limits=cg(cgroup_for_pid(self.members['collector']));quota,period=map(int,collector_limits['cpu.max'].split())
        assert quota/period<=.1 and int(collector_limits['memory.max'])==96*1024*1024 and collector_limits['memory.swap.max']=='0'
        save(f/'collector-limits.json',collector_limits)
        # Fixed quiet warmup, after all auth/prime and full collector first tick.
        time.sleep(13)
        self.phase='warmup_checks'
        api=api_snapshot(self.args.collector_dir,self.controller/'controller.sock')
        assert len(api.get('connections') or [])==3*self.n,'wrong actual authenticated stream count'
        raw=cmd([*ns,'ss','-Htn','state','established','(','sport','=',':7443',')']).stdout
        assert len(raw.splitlines())==self.n,'wrong actual outer TCP count'
        origin_raw=cmd([*ns,'ss','-Htn','state','established','(','dport','=',':19081',')']).stdout
        origin_rows=[line.split() for line in origin_raw.splitlines()]
        assert len(origin_rows)==3*self.n,'wrong proxy-to-origin socket count'
        assert all(len(row)>=4 and row[-2].rsplit(':',1)[0]=='127.0.0.1' for row in origin_rows),'proxy outbound source must remain original loopback'
        save(f/'actual-population.json',{'outer_established':len(raw.splitlines()),'api_streams':len(api.get('connections') or []),'ready':ready,'origin_direct_sockets':len(origin_rows),'origin_local_address_is_expected':True,'utc':utc()})
        for role,pid in self.members.items():
            assert cgroup_for_pid(pid).is_relative_to(self.parent)
            if role!='anchor':assert os.readlink(f'/proc/{pid}/ns/net')==os.readlink(f'/proc/{self.proxy_pid}/ns/net')
        before=stage_route(self.controller/'controller.sock',self.enabled)
        save(f/'warmup-stage.json',before)
        if self.enabled:
            assert before['availability']=='ready'
            b=before['snapshot'];assert b['live_authenticated_sessions']==self.n
            assert type(b.get('schema')) is int and b['schema']==self.inner_schema,'actual warmup producer schema mismatch'
            runtime=json.loads((f/'runtime.json').read_text());runtime['inner_schema']=b['schema'];save(f/'runtime.json',runtime)
            assert b['tracked_live_sessions']==min(self.n,32) and b['untracked_live_sessions']==max(0,self.n-32)
        else:
            assert before['availability']=='unsupported_route_404' and 'snapshot' not in before

    def run_security(self):
        self.setup(load=False,management=True)
        self.phase='runtime_security'
        self.unit('security',['/usr/bin/nsenter','-t',str(self.proxy_pid),'-n','/usr/bin/python3',
                  ASSETS/'runtime_security.py','--root',self.folder,'--enabled','1' if self.enabled else '0','--collector-dir',self.args.collector_dir])
        wait(self.folder/'security-result.json',55)
        outcome=json.loads((self.folder/'security-result.json').read_text())
        assert outcome['ok']
        result={'status':'PASS','enabled':self.enabled,'gates':{'full_runtime_security':True},
                'security':outcome,'scope':'functional isolation only; no performance inference'}
        save(self.folder/'result.json',result)
        return result

    def capture(self):
        free=shutil.disk_usage(ROOT).free
        assert free>=600*1024*1024,'disk below frozen600MiB floor'
        return {'utc':utc(),'mono':time.monotonic(),'disk_free_bytes':free,'parent':cg(self.parent),
                'members':{r:proc(p) for r,p in self.members.items() if r!='anchor'},
                'collector_cgroup':cg(cgroup_for_pid(self.members['collector'])),
                'proxy_cgroup':cg(cgroup_for_pid(self.proxy_pid))}

    def run(self):
        self.setup();f=self.folder;self.phase='workload'
        before=self.capture();save(f/'before.json',before)
        (f/'go').touch(mode=0o600)
        samples=[];first=None;next_tick=before['mono']+1
        deadline=before['mono']+RUNNER_DEADLINE_SECONDS
        while not (f/'client-result.json').exists():
            if time.monotonic()>deadline:raise TimeoutError('workload hard deadline')
            now=time.monotonic()
            if now>=next_tick:
                row=self.capture();samples.append(row)
                if first is None:first=row;save(f/'first-second.json',first)
                next_tick+=1
            time.sleep(.02)
        client=json.loads((f/'client-result.json').read_text())
        if not client.get('ok'):raise AssertionError('payload or TLS session integrity')
        assert client['outer_source_bind_verified']==self.n,'final client bind verification missing'
        after=self.capture();samples.append(after)
        validate_client(client,self.n)
        # The active workload gate never divides by the later idle settle.
        time.sleep(1)
        settle=self.capture();save(f/'settle-after.json',settle)
        save(f/'settle-window.json',{'start':after['utc'],'end':settle['utc'],'wall_seconds':settle['mono']-after['mono'],'parent_delta':cgdelta(after['parent'],settle['parent']),'proxy_cpu_seconds':pdelta(after['members']['proxy'],settle['members']['proxy'])})
        save(f/'after.json',after);save(f/'resource-samples.json',samples)
        assert first is not None
        assert .95 <= first['mono']-before['mono'] <= 1.10, 'first-second capture skew'
        progress=json.loads((f/'first-second-client.json').read_text())
        assert progress['downstream_body_bytes']>0,'first second had no workload'
        (f/'finish').touch(mode=0o600)
        # SIGTERM does not shorten an already running production sleep; keep
        # this bounded grace out of every performance denominator.
        shutdown_start=time.monotonic()
        cmd(['systemctl','kill','--kill-whom=main','--signal=SIGTERM',self.ident+'-collector'],check=False)
        footer_path=f/'collector-timing.jsonl'
        while time.monotonic()-shutdown_start<12:
            if footer_path.exists() and '"event":"wrapper_end"' in footer_path.read_text() and not Path(f'/proc/{self.members["collector"]}').exists():break
            time.sleep(.05)
        else:raise TimeoutError('collector graceful footer')
        save(f/'shutdown-grace.json',{'utc':utc(),'seconds':time.monotonic()-shutdown_start,'included_in_performance':False})
        timing=timing_summary(f,before['mono'],after['mono'],self.enabled)
        # Stage summary uses actual client completion, not one-second settle.
        go_time=dt.datetime.fromisoformat(client['started_utc'].replace('Z','+00:00'))
        completed=dt.datetime.fromisoformat(client['completed_utc'].replace('Z','+00:00'))
        stage=stage_summary(f,go_time,completed,self.n,self.enabled)
        payload=payload_summary(f,before['mono'],after['mono'],self.inner_schema)
        regular=regular_summary(f,go_time,completed)
        overall=cgdelta(before['parent'],after['parent'])
        initial=cgdelta(before['parent'],first['parent'])
        wall=after['mono']-before['mono'];first_wall=first['mono']-before['mono']
        cpus={r:pdelta(before['members'][r],after['members'][r]) for r in before['members']}
        peak=max(after['members']['proxy']['hwm_bytes'],max(s['members']['proxy']['rss_bytes'] for s in [before,*samples]))
        mb=client['received_body_bytes']/1e6
        collector_delta=cgdelta(before['collector_cgroup'],after['collector_cgroup'])
        first_collector_delta=cgdelta(before['collector_cgroup'],first['collector_cgroup'])
        proxy_delta=cgdelta(before['proxy_cgroup'],after['proxy_cgroup'])
        first_proxy_delta=cgdelta(before['proxy_cgroup'],first['proxy_cgroup'])
        after_stage=stage_route(self.controller/'controller.sock',self.enabled)
        runtime=json.loads((f/'runtime.json').read_text());runtime['stage_http_after']=after_stage['http_status'];save(f/'runtime.json',runtime)
        off_gate=True if self.enabled else (after_stage['availability']=='unsupported_route_404' and 'snapshot' not in after_stage
          and not (f/'monitor/stage.jsonl').exists() and not (f/'monitor/stage-cursor.json').exists())
        result={'arm':self.arm,'comparison_arm':self.comparison_arm,'inner_schema':self.inner_schema,'source_commit':self.source,'server_binary_sha256':sha(self.args.proxy_binary),
                'stage_module_sha256':sha(self.args.collector_dir/'stage.py'),'monitor_sha256':sha(self.args.collector_dir/'monitor.py'),'rollup_sha256':sha(self.args.collector_dir/'proxy_rollup.py'),'publication_payload':payload,
                'diagnostic_capability':self.capability,'stage_http_before':self.before_auth['http_status'],'stage_http_after':after_stage['http_status'],
                'producer_enabled':self.enabled,'reader_enabled':self.enabled,
                'status':'PENDING','started_utc':before['utc'],'ended_utc':after['utc'],'enabled':self.enabled,
                'outer_sessions':self.n,'selected_profile':self.args.selected_profile,'workload_contract':workload(),'workload_wall_seconds':wall,'first_interval_seconds':first_wall,
                'client':{k:v for k,v in client.items() if k!='small'},'process_cpu_seconds':cpus,
                'proxy_cpu_per_received_decimal_MB':cpus['proxy']/mb,'proxy_peak_rss_bytes':peak,'proxy_warmup_hwm_bytes':before['members']['proxy']['hwm_bytes'],
                'rss_scope':'process HWM includes warmup; 1Hz steady samples also retained',
                'parent_delta':overall,'first_second_parent_delta':initial,
                'parent_throttled_wall_ratio':overall['throttled_seconds']/wall,
                'first_second_throttled_wall_ratio':initial['throttled_seconds']/first_wall,
                'first_second_client_received_body_bytes':progress['downstream_body_bytes'],
                'collector_delta':collector_delta,'first_second_collector_delta':first_collector_delta,
                'collector_throttled_wall_ratio':collector_delta['throttled_seconds']/wall,
                'first_second_collector_throttled_wall_ratio':first_collector_delta['throttled_seconds']/first_wall,'stage':stage,'regular':regular,
                'default_off_gate':off_gate,
                'timing':timing,'proxy_cgroup_delta':proxy_delta,'first_second_proxy_cgroup_delta':first_proxy_delta,
                'proxy_cgroup_throttled_wall_ratio':proxy_delta['throttled_seconds']/wall,
                'first_second_proxy_cgroup_throttled_wall_ratio':first_proxy_delta['throttled_seconds']/first_wall,
                'client_end_to_capture_skew_ms':(dt.datetime.fromisoformat(after['utc'])-completed).total_seconds()*1000,
                'scope':'history baseline+readerON -> candidate+readerON deployment combination; paced offered load, not capacity or public speed'}
        gates={'integrity':client['ok'],'resource':result['parent_throttled_wall_ratio']<=.1 and result['first_second_throttled_wall_ratio']<=.1 and result['collector_throttled_wall_ratio']<=.1 and result['first_second_collector_throttled_wall_ratio']<=.1 and result['proxy_cgroup_throttled_wall_ratio']<=.1 and result['first_second_proxy_cgroup_throttled_wall_ratio']<=.1,
               'proxy_cpu_denominator':cpus['proxy']>=.2,'no_oom_or_memory_pressure':all(not any(delta['memory_events'].values()) for delta in (overall,collector_delta,proxy_delta)),
               'complete_cycle_timing':timing['gate'],
               'end_capture_skew':0 <= result['client_end_to_capture_skew_ms'] <= 150,
               'publication_or_off':stage['publication_gate'] and off_gate,
               'full_regular':regular['rows']>=3 and regular['issues']==0 and regular['complete_tcp_api_log'] and regular['rollup_errors']==0 and regular['tcp_parse_errors']==0 and regular['tls_ok'] and regular['max_gap_seconds'] is not None and regular['max_gap_seconds']<=11,
               'collector_output_errors':not any((r.get('stage_previous') or {}).get('output_status')=='failed' or (r.get('stage_previous') or {}).get('checkpoint_status')=='failed' for r in (json.loads(l) for l in (f/'monitor/samples.jsonl').read_text().splitlines()))}
        result['gates']=gates
        result['status']='PASS' if all(gates.values()) else ('RESOURCE_INCONCLUSIVE' if not gates['resource'] or not gates['proxy_cpu_denominator'] else 'HOLD')
        save(f/'result.json',result)
        return result

    def recover_create(self,cleanup):
        if not self.create_attempted or self.container_id is not None:return
        outcome=cmd(['docker','container','inspect',self.container],check=False)
        if outcome.returncode:
            if exact_container_absent(outcome,self.container):
                cleanup['create_recovery']='EXACT_NAME_ABSENT';return
            raise RuntimeError('created container recovery unknown')
        inspected=json.loads(outcome.stdout)
        assert len(inspected)==1,'create recovery shape'
        value=inspected[0];cid=value.get('Id')
        assert owns_container(value,cid,self.container_owner,self.container_image) and value.get('Name')=='/'+self.container,'create recovery ownership mismatch'
        self.container_id=cid
        self.capture_owned_proof(cid)
        cleanup['create_recovery']='EXACT_OWNED_NAME_RECOVERED'

    def helper_readbacks(self):
        rows=[]
        for unit in self.units:
            try:rows.append(helper_readback(self.unit_proofs[unit],cmd))
            except (OSError,ValueError,subprocess.TimeoutExpired,KeyError) as error:
                rows.append({'unit':unit,'pass':False,'error_class':type(error).__name__})
        return rows

    def stop_owned_helpers(self):
        attempts=[]
        for unit in reversed(self.units):
            proof=self.unit_proofs[unit]
            try:
                state=classify_unit(cmd(['systemctl','show',unit,'--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ControlGroup'],timeout=3,check=False),proof)
                if state['known'] and state.get('absent'):
                    attempts.append({'unit':unit,'action':'already_absent'});continue
                if not state['known'] or not state['owned']:
                    attempts.append({'unit':unit,'action':'REFUSED_UNKNOWN_OWNERSHIP'});continue
                r=cmd(['systemctl','stop','--no-block',unit],timeout=3,check=False)
                attempts.append({'unit':unit,'action':'stop','exit_code':r.returncode})
            except (OSError,subprocess.TimeoutExpired) as error:
                attempts.append({'unit':unit,'action':'stop_error','error_class':type(error).__name__})
        deadline=time.monotonic()+12
        rows=self.helper_readbacks()
        while rows and not all(r['pass'] for r in rows) and time.monotonic()<deadline:
            time.sleep(.1);rows=self.helper_readbacks()
        if not all(r['pass'] for r in rows):
            for unit in self.units:
                proof=self.unit_proofs[unit]
                try:
                    state=classify_unit(cmd(['systemctl','show',unit,'--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ControlGroup'],timeout=3,check=False),proof)
                    if state['known'] and state['owned'] and any(r['unit']==unit and not r['pass'] for r in rows):
                        r=cmd(['systemctl','kill','--kill-whom=all','--signal=SIGKILL',unit],timeout=3,check=False)
                        attempts.append({'unit':unit,'action':'kill','exit_code':r.returncode})
                except (OSError,subprocess.TimeoutExpired) as error:
                    attempts.append({'unit':unit,'action':'kill_error','error_class':type(error).__name__})
            deadline=time.monotonic()+3
            rows=self.helper_readbacks()
            while not all(r['pass'] for r in rows) and time.monotonic()<deadline:
                time.sleep(.1);rows=self.helper_readbacks()
        return {'attempts':attempts,'final':rows,'pass':len(rows)==len(self.units) and all(r['pass'] for r in rows)}

    def cleanup(self):
        cleanup={'container_created':self.container_id is not None,'container_removed':False,
                 'anonymous_volumes_verified':self.anonymous_volumes_verified,'anonymous_volume_results_private':[],
                 'volume_checks_private':[],'rejection_reasons':[]}
        try:
            try:
                self.recover_create(cleanup)
                cleanup['container_created']=self.container_id is not None
                cleanup['anonymous_volumes_verified']=self.anonymous_volumes_verified
            except Exception as error:
                self.allow_container_cleanup=False
                cleanup['rejection_reasons'].append('create_recovery_unknown:'+type(error).__name__)
                raise
            if self.folder.exists():
                (self.folder/'finish').touch(mode=0o600)
            cleanup['helper_shutdown']=self.stop_owned_helpers()
            if self.folder.exists() and self.proxy_pid:
                owned=json.loads(cmd(['docker','inspect',self.container_id]).stdout)[0]
                assert owns_container(owned,self.container_id,self.container_owner,self.container_image),'refuse logs from unowned container'
                log_result=cmd(['docker','logs',self.container_id],check=False)
                logs=log_result.stdout+log_result.stderr
                (self.folder/'runtime.private.log').write_text(logs)
                findings={'all_log_bytes':len(logs.encode()),'stage_specific_log_bytes':sum(len(l.encode()) for l in logs.splitlines(True) if 'AnyTLS EVIDENCE' in l or 'anytls_stage_snapshot' in l or 'diagnostic_not_failure' in l)}
                save(self.folder/'log-budget.json',findings)
        finally:
            if self.container_id is not None and self.allow_container_cleanup:
                checked=cmd(['docker','inspect',self.container_id],timeout=10,check=False)
                if checked.returncode==0:
                    owned=json.loads(checked.stdout)[0]
                    if owns_container(owned,self.container_id,self.container_owner,self.container_image):
                        mount_matches=same_volume_mounts(owned.get('Mounts',[]),self.owned_mounts)
                        remove_volumes=self.anonymous_volumes_verified and mount_matches
                        cleanup['actual_volume_mounts_match']=mount_matches
                        if not mount_matches:cleanup['rejection_reasons'].append('owned_actual_volume_mounts_changed')
                        for expected in self.anonymous_volumes:
                            check={'name':expected['Name'],'rejection_reasons':[],
                                   'created_at_before':expected.get('CreatedAt'),'created_at_after':None,
                                   'created_at_is_mutable_ctime':True,
                                   'directory_identity_before':self.anonymous_directory_identities.get(expected['Name'])}
                            current=cmd(['docker','volume','inspect',expected['Name']],check=False)
                            refs=cmd(['docker','ps','-aq','--no-trunc','--filter','volume='+expected['Name']]).stdout.splitlines()
                            check['current_references_private']=refs
                            if current.returncode:check['rejection_reasons'].append('volume_inspect_failed')
                            else:
                                actual=json.loads(current.stdout)[0];check['metadata_current']=actual
                                check['created_at_after']=actual.get('CreatedAt')
                                if not same_volume_identity(actual,expected):check['rejection_reasons'].append('stable_volume_metadata_changed')
                            if set(refs)!={self.container_id}:check['rejection_reasons'].append('volume_reference_not_only_owned_container')
                            try:
                                check['directory_identity_current']=volume_directory_identity(expected['Mountpoint'])
                                if check['directory_identity_current']!=check['directory_identity_before']:check['rejection_reasons'].append('volume_directory_identity_changed')
                            except (AssertionError,OSError,RuntimeError) as error:
                                check['rejection_reasons'].append('volume_directory_identity_unavailable_or_unsafe')
                                check['directory_error_class']=type(error).__name__
                            if check['rejection_reasons']:remove_volumes=False
                            cleanup['volume_checks_private'].append(check)
                        cleanup['remove_anonymous_volumes_requested']=remove_volumes
                        argv=['docker','rm','-f']+(['-v'] if remove_volumes else [])+[self.container_id]
                        removed=cmd(argv,timeout=10,check=False)
                        cleanup['remove_exit_code']=removed.returncode
                        absent_by_id=exact_container_absent(cmd(['docker','container','inspect',self.container_id],timeout=10,check=False),self.container_id)
                        absent_by_name=exact_container_absent(cmd(['docker','container','inspect',self.container],timeout=10,check=False),self.container)
                        cleanup['container_absent_by_id']=absent_by_id
                        cleanup['container_absent_by_name']=absent_by_name
                        cleanup['container_removed']=removed.returncode==0 and absent_by_id and absent_by_name
                        for expected in self.anonymous_volumes:
                            after=cmd(['docker','volume','inspect',expected['Name']],check=False)
                            api_absent=after.returncode!=0 and 'no such volume' in after.stderr.lower()
                            directory_absent=not os.path.lexists(expected['Mountpoint'])
                            cleanup['anonymous_volume_results_private'].append({'name':expected['Name'],'absent':api_absent and directory_absent,
                                'api_absent':api_absent,'directory_absent':directory_absent,'readback_exit':after.returncode})
                    else:cleanup['refused']='identity_owner_or_image_mismatch'
                else:cleanup['refused']='inspect_failed'
            else:cleanup['refused']='no_verified_owned_container_or_no_creation'
            if 'helper_shutdown' not in cleanup:
                cleanup['helper_shutdown']=self.stop_owned_helpers()
            cleanup['parent_commands']=[]
            for argv in ((['systemctl','stop',self.slice],['systemctl','reset-failed',self.slice],['systemctl','revert',self.slice]) if self.parent is not None else ()):
                try:
                    result=cmd(argv,timeout=5,check=False)
                    cleanup['parent_commands'].append({'action':argv[1],'exit_code':result.returncode})
                except (OSError,subprocess.TimeoutExpired) as error:
                    cleanup['parent_commands'].append({'action':argv[1],'error_class':type(error).__name__})
            cleanup['helpers_final']=self.helper_readbacks()
            cleanup['helpers_verified_exited']=len(cleanup['helpers_final'])==len(self.units) and all(r['pass'] for r in cleanup['helpers_final'])
            cleanup['parent_cgroup']=cgroup_readback(str(self.parent) if self.parent else None)
            cleanup['parent_empty_verified']=cleanup['parent_cgroup']['known'] and cleanup['parent_cgroup']['empty_or_absent']
            try:
                state=cmd(['systemctl','show',self.slice,'--property=Id,LoadState,ActiveState,ControlGroup'],timeout=3,check=False)
                props=parse_properties(state.stdout)
                cleanup['parent_unit_readback']={'exit_code':state.returncode,'properties':props}
                cleanup['parent_inactive_verified']=(state.returncode in (0,1,4) and props.get('Id')==self.slice and
                    props.get('ActiveState')=='inactive' and props.get('LoadState') in ('loaded','not-found'))
            except (OSError,ValueError,subprocess.TimeoutExpired) as error:
                cleanup['parent_unit_readback']={'error_class':type(error).__name__}
                cleanup['parent_inactive_verified']=False
            cleanup['anonymous_volumes_cleanup_verified']=(self.container_id is None or
                self.anonymous_volumes_verified and len(cleanup['anonymous_volume_results_private'])==len(self.anonymous_volumes)
                and all(v['absent'] for v in cleanup['anonymous_volume_results_private']))
            cleanup['cleanup_pass']=(cleanup['helpers_verified_exited'] and cleanup['parent_empty_verified'] and
                cleanup['parent_inactive_verified'] and cleanup['anonymous_volumes_cleanup_verified'] and
                (self.container_id is None or cleanup['container_removed']) and not cleanup['rejection_reasons'])
            if self.folder.exists():save(self.folder/'cleanup.json',cleanup)
            if self.controller.exists() and cleanup['helpers_verified_exited'] and (self.container_id is None or cleanup['container_removed']):shutil.rmtree(self.controller)
            assert cleanup['cleanup_pass'],'owned helper/unit/PID/cgroup/volume cleanup unknown or incomplete; HOLD'
            if self.container_id is not None:
                assert self.allow_container_cleanup and cleanup['container_removed'],'owned container cleanup failed; stop instead of starting next trial'
                assert self.anonymous_volumes_verified and len(cleanup['anonymous_volume_results_private'])==len(self.anonymous_volumes) and all(v['absent'] for v in cleanup['anonymous_volume_results_private']),'anonymous-volume cleanup unverified; stop instead of continuing'


def payload_summary(folder,start_mono,end_mono,schema):
    events=[json.loads(line) for line in (folder/'collector-timing.jsonl').read_text().splitlines()]
    ticks=ticks_from_events(events,start_mono,end_mono)
    return {'expected_inner_schema':schema,'ticks':ticks,
            'scope':'All real requests/probes, append attempts and durable cursor ACKs per original regular tick, each bounded at2. No extra polling.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha',required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--mode',choices=('matrix','security'),default=None)
    args=parser.parse_args();os.umask(0o077)
    def interrupted(signum, frame):
        raise RuntimeError('bounded runner interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGINT,interrupted)
    path=args.manifest.resolve(strict=True);raw=path.read_bytes()
    assert len(args.manifest_sha)==64 and hashlib.sha256(raw).hexdigest()==args.manifest_sha,'whole manifest SHA mismatch'
    manifest=json.loads(raw);assert manifest['status']=='FROZEN_FOR_EXECUTION'
    from input_contract import validate_manifest
    validate_manifest(manifest, ROOT)
    if args.mode is not None:assert args.mode==manifest['execution_mode'],'mode outside frozen manifest'
    args.mode=manifest['execution_mode']
    args.selected_profile=manifest['selected_profile']
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','dedicated root CI runner required'
    assert Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)==Path(manifest['workspace']),'CI workspace identity mismatch'
    args.arms=manifest['arms']
    for path,expected in manifest['files'].items():assert sha(path)==expected,'frozen input hash mismatch'
    assert shutil.disk_usage(ROOT).free>=1024**3,'start disk below1GiB'
    args.proxy_binary=Path(manifest['arms']['B']['binary_path'])
    args.baseline_binary=Path(manifest['arms']['A']['binary_path'])
    args.client_binary=Path(manifest['client_binary'])
    args.baseline_collector_dir=Path(manifest['arms']['A']['collector_dir'])
    args.candidate_collector_dir=Path(manifest['arms']['B']['collector_dir'])
    args.runtime_image=manifest['runtime_image_id']
    info=json.loads(cmd(['docker','image','inspect',args.runtime_image]).stdout)[0]
    assert info['Id']==args.runtime_image,'immutable runtime image mismatch'
    args.image_declared_volumes=info['Config'].get('Volumes') or {}
    output=Path(manifest['output_root']);assert output.is_relative_to(Path(manifest['workspace'])) and not output.is_symlink()
    if output.exists():raise FileExistsError('attempt directory exists; no retry/pooling')
    output.mkdir(mode=0o700,parents=True)
    os.chmod(output,0o700)
    judge=load_module(ROOT/'adjudicate.py','history_cost_adjudicator')
    all_groups=[]
    with open(LOCK,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        save(output/'lock-start.json',{'time':utc(),'manifest_sha256':args.manifest_sha})
        try:
            if args.mode=='security':
                outcomes=[]
                for label in ('A','B'):
                    trial=Trial(args,output/('security-'+label),1,label=='B')
                    try:
                        outcome=trial.run_security()
                        outcomes.append(outcome)
                    except Exception as error:
                        trial.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
                        save(trial.folder/'failure.json',{'status':'FAIL','phase':trial.phase,'error_class':type(error).__name__,'time':utc()})
                        raise
                    finally:trial.cleanup()
                save(output/'complete.json',{'status':'SECURITY_PASS','results':outcomes,'performance_measured':False})
                return
            for n in (args.selected_profile,):
                folder=output/('matrix'+str(n));results=[];runtimes=[]
                for index,label in enumerate(('A','B','B','A')):
                    for frozen_path,expected in manifest['files'].items():
                        assert sha(frozen_path)==expected,'input changed between trials'
                    trial=Trial(args,folder/(f'{index:02d}-'+label),n,label=='B')
                    try:
                        result=trial.run()
                    except Exception as error:
                        trial.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
                        save(trial.folder/'failure.json',{'status':'FAIL','phase':trial.phase,'error_class':type(error).__name__,'time':utc()})
                        raise
                    finally:trial.cleanup()
                    log=json.loads((trial.folder/'log-budget.json').read_text())
                    result['gates']['zero_stage_shared_log']=log['stage_specific_log_bytes']==0
                    if not result['gates']['zero_stage_shared_log']:result['status']='HOLD'
                    save(trial.folder/'result.json',result)
                    runtime=json.loads((trial.folder/'runtime.json').read_text())
                    qualification=judge.adjudicate_bound([result],[runtime],manifest['arms'],'qualification',args.selected_profile)
                    save(trial.folder/'qualification.json',qualification)
                    if qualification['status']!='QUALIFIED_COST_PENDING':raise RuntimeError('trial qualification failed; first failure stop')
                    results.append(result);runtimes.append(runtime)
                summary=judge.adjudicate_bound(results,runtimes,manifest['arms'],'matrix',args.selected_profile)
                save(folder/'summary.json',summary)
                all_groups.append({'profile':n,'status':summary['status'],'time':utc()})
                print(json.dumps(all_groups[-1]),flush=True)
                if summary['status']!='CAPPED_RUNTIME_COST_PASS':raise RuntimeError('profile cost failed; no next group')
            save(output/'complete.json',{'status':'PROFILE_PASS','profile':args.selected_profile,'workload_contract':workload(),'groups':all_groups,'production_mutations':False})
        finally:save(output/'lock-end.json',{'time':utc(),'groups_completed':all_groups})


if __name__=='__main__':main()
