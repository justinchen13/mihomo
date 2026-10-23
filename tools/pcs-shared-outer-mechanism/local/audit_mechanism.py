"""Audit retained, strictly internal observations without inventing stream IDs."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

R = Path(__file__).resolve().parent
def ns(value):
    m = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|\+00:00)', value)
    if not m: raise ValueError('UTC_shape')
    base = dt.datetime.strptime(m[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc)
    return int(base.timestamp())*1_000_000_000+int((m[2] or '').ljust(9,'0'))
def load(p): return json.loads(p.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
rows=[]
for ordinal in (0,1):
    b=R/f'network-results/{ordinal}-bulk{ordinal}'
    result=load(b/'result.json');q=load(b/'qualification.safe.json');resources=load(b/'resources.normalized.json')
    assert result['status']==q['status']=='QUALIFIED_PROTOCOL_LATENCY_ONLY' and not q['failures']
    assert load(b/'unit-cleanup.safe.json')['status']=='PASS'
    client=load(b/'client-result.json');origin=load(b/'origin-result.json')['proof']
    cr={x['id']:x for x in client['rows']};org={x['id']:x for x in origin['rows']}
    begin,end=ns(client['start']['utc']),ns(client['end']['utc'])
    join=load(b/'stage-outer-join.private.json')['outer_sessions']
    socket_id=next(x['stage_socket_id'] for x in join if x['outer_ordinal']==ordinal)
    pre=load(b/'TCP-before.private.json')[ordinal]['socket'];cookie,inode=pre['cookie'],pre['inode']
    stages=[json.loads(l)['stage'] for l in (b/'diagnostic/stage.jsonl').open()]
    samples=[json.loads(l) for l in (b/'samples.private.jsonl').open()]
    events={}
    for s in stages:
        for e in s['observations']['slow_events']:
            key=(e['session_id'],e['stage'],e['started_at'],e['completed_at'],e['bytes'])
            events[key]=e
    evidence=[]
    for s in stages:
        o=s['observations'];a,z=ns(o['capture_started']),ns(o['capture_ended'])
        sessions=[x for x in o['sessions'] if x['socket_id']==socket_id]
        assert len(sessions)==1
        session=sessions[0]
        assert session['waiter_overflow_total']==0 and session['writer_wait_coverage_complete'] is True
        active={x['stage']:x for x in session['active']}
        if not (session['pending_writers']>0 and active.get('tls_write',{}).get('bytes',0)>4103 and
                active.get('writer_owned',{}).get('bytes')==active['tls_write']['bytes']):continue
        eligible=[ident for ident,c in cr.items() if ident!=32 and c['outer']==ordinal and
                  ns(org[ident]['ready']['utc'])<=a and ns(c['reader']['verified']['utc'])>z]
        for e in events.values():
            lo,hi=ns(e['started_at']),ns(e['completed_at'])
            if not (e['session_id']==session['session_id'] and e['stage']=='tls_write' and
                    e['bytes']==active['tls_write']['bytes'] and not e['failed'] and begin<=lo<a<=z<hi<=end):continue
            owners=[x for x in events.values() if x['session_id']==e['session_id'] and x['stage']=='writer_owned' and
                    x['bytes']==e['bytes'] and not x['failed'] and ns(x['started_at'])<=lo and ns(x['completed_at'])>=hi]
            if len(owners)!=1:continue
            points=[]
            for sample in samples:
                t=sample['server'][ordinal];x=t['socket']
                if lo<ns(t['started_utc'])<=ns(t['completed_utc'])<hi:
                    assert x['valid'] and (x['cookie'],x['inode'])==(cookie,inode)
                    points.append({'started_utc':t['started_utc'],'completed_utc':t['completed_utc'],
                        **{k:x.get(k) for k in ('bytes_acked','snd_wnd','send_q_bytes','notsent',
                              'effective_sendbuffer_bytes','skmem_queued_write_bytes','bytes_retrans','pacing_rate_bps')}})
            if len(points)<2:continue
            ack=points[-1]['bytes_acked']-points[0]['bytes_acked']
            if not (ack>0 and all(type(x['snd_wnd']) in (int,float) and x['snd_wnd']>0 and
                                 type(x['notsent']) in (int,float) and x['notsent']>0 for x in points)):continue
            assert len(eligible)>=session['pending_writers']
            evidence.append({'capture_sequence':s['sequence'],'capture_started':o['capture_started'],
                'capture_ended':o['capture_ended'],'TLS_write_started':e['started_at'],
                'TLS_write_completed':e['completed_at'],'TLS_write_bytes':e['bytes'],'TLS_write_duration_ms':e['duration_ms'],
                'unique_containing_owned_interval':True,'snapshot_pending_writers':session['pending_writers'],
                'snapshot_tracked_waiters':session['tracked_waiters'],'snapshot_active_stages':session['active'],
                'source_ready_client_not_verified_eligible_small_IDs':eligible,
                'TCP_points_strictly_inside_write':points,'strict_inside_ACK_progress_bytes':ack,
                'socket_cookie_and_inode_consistent':True,'same_run_HMAC_join_matches_exact_cookie':True,
                'class_drop_counters_at_snapshot':[x['dropped'] for x in o['slow_queue_counters']],
                'claim_scope':'retained same-session writer blocking and ready-small cohort coexist; no individual waiter-to-request-ID link'})
    # A real completed wait interval is also time evidence. A10s publication
    # need not occur inside a2s Write. Do not substitute cumulative maxima.
    loaded_session=next(x for x in stages[0]['observations']['sessions'] if x['socket_id']==socket_id)['session_id']
    seen={(x['TLS_write_started'],x['TLS_write_completed']) for x in evidence}
    for e in events.values():
        lo,hi=ns(e['started_at']),ns(e['completed_at'])
        if not (e['session_id']==loaded_session and e['stage']=='tls_write' and e['bytes']>4103 and
                not e['failed'] and begin<=lo<hi<=end and (e['started_at'],e['completed_at']) not in seen):continue
        owners=[x for x in events.values() if x['session_id']==loaded_session and x['stage']=='writer_owned' and
                x['bytes']==e['bytes'] and not x['failed'] and ns(x['started_at'])<=lo and ns(x['completed_at'])>=hi]
        waits=[x for x in events.values() if x['session_id']==loaded_session and x['stage']=='writer_wait' and
               x['frame_class']=='data' and x['bytes']==4103 and not x['failed'] and
               ns(x['started_at'])<=lo and ns(x['completed_at'])>=hi]
        eligible=[ident for ident,c in cr.items() if ident!=32 and c['outer']==ordinal and
                  ns(org[ident]['ready']['utc'])<=lo and ns(c['reader']['verified']['utc'])>=hi]
        if len(owners)!=1 or not waits or not eligible:continue
        points=[]
        for sample in samples:
            t=sample['server'][ordinal];x=t['socket']
            if lo<ns(t['started_utc'])<=ns(t['completed_utc'])<hi:
                assert x['valid'] and (x['cookie'],x['inode'])==(cookie,inode)
                points.append({'started_utc':t['started_utc'],'completed_utc':t['completed_utc'],
                    **{k:x.get(k) for k in ('bytes_acked','snd_wnd','send_q_bytes','notsent',
                          'effective_sendbuffer_bytes','skmem_queued_write_bytes','bytes_retrans')}})
        if len(points)<2:continue
        ack=points[-1]['bytes_acked']-points[0]['bytes_acked']
        if not (ack>0 and all(type(x['snd_wnd']) in (int,float) and x['snd_wnd']>0 and
                             type(x['notsent']) in (int,float) and x['notsent']>0 for x in points)):continue
        evidence.append({'evidence_kind':'retained_completed_waits_and_owned_TLS_intervals_not_cumulative_max',
            'TLS_write_started':e['started_at'],'TLS_write_completed':e['completed_at'],
            'TLS_write_bytes':e['bytes'],'TLS_write_duration_ms':e['duration_ms'],
            'unique_containing_owned_interval':True,'completed_data_waiters_covering_entire_TLS_interval':waits,
            'eligible_ready_not_verified_small_IDs_covering_entire_TLS_interval':eligible,
            'TCP_points_strictly_inside_write':points,'strict_inside_ACK_progress_bytes':ack,
            'socket_cookie_and_inode_consistent':True,'same_run_HMAC_join_matches_exact_cookie':True,
            'claim_scope':'specific preserved writer wait/TLS/ready-cohort overlap only; source queue losses prohibit complete event attribution'})
    last=stages[-1]['observations']
    pair=q['pair_summary']['after_ready']
    rows.append({'bulk_outer':ordinal,'protocol_status':q['status'],'primary_after_ready_pair_summary':pair,
                 'all16pairs':q['all_fixed_pairs'],'bulk_workload_goodput_MB_s':q['bulk_MB_per_s'],
                 'resource_first':resources['first'],'resource_whole':resources['whole'],
                 'actual_sender_buffer_before_bytes':pre.get('effective_sendbuffer_bytes'),
                 'qualified_specific_retained_cases':evidence,'specific_case_count':len(evidence),
                 'stage_final_quality':{k:last[k] for k in ('untracked_live_sessions','omitted_sessions','omitted_slow_events',
                     'evicted_sessions_total','lost_completion_total','lost_batch_total','lost_slow_event_total','lost_terminal_record_total')},
                 'stage_final_per_class_drop_counters':[x['dropped'] for x in last['slow_queue_counters']],
                 'last_retained_capture_to_client_finish_ms':(end-ns(last['capture_ended']))/1e6,
                 'stage_sequence_range_observed':[stages[0]['sequence'],stages[-1]['sequence']],
                 'stage_window_tail':'Later source publications not collected; tail completeness and final source counters UNKNOWN',
                 'full_event_attribution':'INCOMPLETE_QUEUE_DROPS_RETAINED_NO_GLOBAL_CAUSAL_PASS',
                 'raw_input_sha256':{n:sha(b/n) for n in ('client-result.json','origin-result.json','samples.private.jsonl',
                     'diagnostic/stage.jsonl','stage-outer-join.private.json','resources.normalized.json','qualification.safe.json')}})
supported=all(x['primary_after_ready_pair_summary']['positive_count']==16 and x['specific_case_count']>0 for x in rows)
record={'round_id':'R-20261023-04','status':'RETAINED_SHARED_WRITER_BLOCKING_REPRODUCED_BOTH_PLACEMENTS' if supported else 'PARTIAL_EVIDENCE_MECHANISM_UNKNOWN',
        'utc':dt.datetime.now(dt.timezone.utc).isoformat(),'rows':rows,'production_root_cause':'NOT_ESTABLISHED',
        'full_predeclared_event_attribution':'INCOMPLETE_NOT_ACCEPTED_FOR_PRODUCTION_PROMOTION',
        'production_speed_improvement':'NOT_ESTABLISHED','new_candidate_deployed':False,
        'limits':['Both outers share the declared bottleneck, so independent outer is not an uncongested path.',
           'Bulk placement is reversed, not a no-bulk intervention; observed contrast contains kernel TCP queuing and native writer waiting.',
           'No exact requestID-to-session-waiterID mapping is exported; eligible cohort is not a specific waiter assignment.',
           'Observed queue drops remain: no complete-event population or all-delay attribution; no relaxed global mechanism gate.',
           'A reproduced model mechanism does not prove that every production stall has the same cause.',
           'TCP ss pacing fields retain native bits/s raw units; user-facing speed reports use decimalMB/s.',
           'First CPU cgroup interval begins preGO; exact client/controller/cgroup boundaries are retained.']}
(R/'mechanism-audit.safe.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'status':record['status'],'specific_cases':[x['specific_case_count'] for x in rows],
                  'pair_afterready_median_extra_ms':[x['primary_after_ready_pair_summary']['median_extra_ms'] for x in rows]}))
