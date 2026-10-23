"""Pure bounded history evidence validation. No I/O or process operations."""
import math

def number(v):return type(v) in (int,float) and math.isfinite(v) and v>=0

def history_metadata(value):
 if value is None:return None
 if not isinstance(value,dict):return {'invalid':True}
 ints=('oldest_sequence','latest_sequence');bools=('more','capture_is_historical')
 return {**{k:value.get(k) if type(value.get(k)) is int and value[k]>=0 else None for k in ints},
         **{k:value.get(k) if type(value.get(k)) is bool else None for k in bools},
         'latest_age_ms':value.get('latest_age_ms') if number(value.get('latest_age_ms')) else None,
         'gap':value.get('gap') if value.get('gap') in ('none','retention','publication','epoch_changed','cursor_ahead') else None}

def row_metadata(row):
 s=row.get('stage') if isinstance(row,dict) else None
 if not isinstance(s,dict):return {'unknown':True}
 h=row.get('history_delivery')
 # Legacy absence of the optional payload-limited flag is its documented false default.
 limited=s.get('consumer_payload_limited',False)
 return {'sequence':s.get('sequence') if type(s.get('sequence')) is int else None,
         'availability':s.get('availability') if s.get('availability') in ('ready','inactive','awaiting_sample','stale','transport_error','invalid_payload','deadline_exceeded','http_status','sequence_regression','schedule_skipped','body_too_large','invalid_http','header_too_large','missing_scope') else None,
         'duplicate':s.get('duplicate') if type(s.get('duplicate')) is bool else None,
         'consumer_payload_limited':limited if type(limited) is bool else None,
         'observations_present':isinstance(s.get('observations'),dict),
         'capture_age_ms':s.get('age_ms') if number(s.get('age_ms')) else None,
         'history_delivery':history_metadata(h),
         'observations_time_scope':row.get('observations_time_scope') if row.get('observations_time_scope') in ('retained_historical_capture','latest_capture') else None,
         'current_gauges_eligible':row.get('current_gauges_eligible') if type(row.get('current_gauges_eligible')) is bool else None,
         'history_keys_present':any(k in row for k in ('history_delivery','observations_time_scope','current_gauges_eligible'))}

def row_gate(m):
 """All rows, including cropped and duplicate rows, must pass their own contract."""
 reasons=[]
 if m.get('availability')!='ready':reasons.append('not_ready')
 if type(m.get('sequence')) is not int or m['sequence']<=0:reasons.append('sequence_unknown')
 if type(m.get('duplicate')) is not bool:reasons.append('duplicate_unknown')
 if m.get('consumer_payload_limited') is not False:reasons.append('consumer_payload_limited_or_unknown')
 if not m.get('duplicate') and m.get('observations_present') is not True:reasons.append('observations_missing')
 age=m.get('capture_age_ms');h=m.get('history_delivery');latest=None;historical=False
 if not number(age):reasons.append('capture_age_unknown')
 if h is None:
  if m.get('history_keys_present'):reasons.append('partial_history_metadata')
  latest=age
  if number(age) and age>25000:reasons.append('legacy_latest_stale')
 else:
  required=('oldest_sequence','latest_sequence','latest_age_ms','gap','more','capture_is_historical')
  if not isinstance(h,dict) or any(h.get(k) is None for k in required):reasons.append('history_unknown')
  else:
   seq=m.get('sequence');oldest=h['oldest_sequence'];newest=h['latest_sequence'];latest=h['latest_age_ms']
   if type(oldest) is not int or type(newest) is not int or oldest<1 or newest<oldest or type(seq) is not int or not oldest<=seq<=newest:reasons.append('history_sequence_bounds')
   historical=type(seq) is int and seq<newest
   if h['capture_is_historical'] is not historical or h['more'] is not historical:reasons.append('history_selection_flags')
   expected_scope='retained_historical_capture' if historical else 'latest_capture'
   if m.get('observations_time_scope')!=expected_scope:reasons.append('history_time_scope')
   expected_eligible=not historical and m.get('availability')=='ready' and m.get('duplicate') is False
   if m.get('current_gauges_eligible') is not expected_eligible:reasons.append('current_gauge_label')
   if h['gap']!='none':reasons.append('history_gap')
   if not number(latest):reasons.append('latest_age_unknown')
   elif latest>25000:reasons.append('latest_stale')
   elif number(age) and latest>age+.001:reasons.append('contradictory_age')
   if number(age) and age>45000:reasons.append('historical_capture_stale')
   if not historical and number(age) and age>25000:reasons.append('latest_capture_stale')
 return {'pass':not reasons,'reasons':reasons,'capture_age_ms':age,'latest_age_ms':latest,'historical':historical}

def tick_gate(tick):
 requests=tick.get('requests');rows=tick.get('deliveries');acks=tick.get('acknowledgements')
 reasons=[]
 for name,items in (('requests',requests),('deliveries',rows),('acknowledgements',acks)):
  if not isinstance(items,list) or not 1<=len(items)<=2:return {'pass':False,'reasons':[name+'_count_unknown_or_outside_bound']}
 if tick.get('trace_errors')!=[]:reasons.append('trace_errors_or_unknown')
 if tick.get('operation_failed') is not False:reasons.append('operation_failure_or_unknown')
 observed=tick.get('observed_counts') or {}
 if any(type(observed.get(k)) is not int or observed[k]!=len(v) for k,v in (('requests',requests),('deliveries',rows),('acknowledgements',acks))):reasons.append('observed_count_mismatch')
 if [r.get('request_index') for r in requests]!=list(range(1,len(requests)+1)):reasons.append('request_indices')
 if [r.get('delivery_index') for r in rows]!=list(range(1,len(rows)+1)):reasons.append('delivery_indices')
 if len(acks)!=len(rows):reasons.append('ack_count')
 for r in requests:
  if r.get('request_failed') is not False or r.get('http_status')!=200 or type(r.get('raw_body_bytes')) is not int or not 0<r['raw_body_bytes']<=65536:reasons.append('request_failure_or_unknown')
  if r.get('availability')!='ready':reasons.append('consumption_not_ready')
  if r.get('request_kind') not in ('latest','history'):reasons.append('request_kind_unknown')
 for i,row in enumerate(rows):
  reasons.extend(row_gate(row)['reasons'])
  idx=row.get('request_index')
  req=requests[idx-1] if type(idx) is int and 1<=idx<=len(requests) else None
  if req is None or req.get('sequence')!=row.get('sequence'):reasons.append('request_delivery_join')
  if req is not None and req.get('request_kind')=='history' and row.get('history_delivery') is None:reasons.append('history_response_metadata_missing')
  if row.get('append_succeeded') is not True or row.get('rotation') not in ('unchanged','rotated','unknown'):reasons.append('append_not_confirmed')
  if i>=len(acks):continue
  ack=acks[i]
  if ack.get('delivery_index')!=row.get('delivery_index') or ack.get('sequence')!=row.get('sequence') or ack.get('request_index')!=idx:reasons.append('ack_delivery_join')
  if ack.get('written') is not True or ack.get('checkpoint_status')!='saved' or ack.get('ack_failed') is not False or ack.get('rotation')!=row.get('rotation'):reasons.append('durable_ack_failure')
 report=tick.get('ack') or {}
 # Old collector has no per-tick totals. New collector totals must agree if supplied.
 for key,actual in (('records_written',sum(r.get('append_succeeded') is True for r in rows)),('network_requests',len(requests))):
  if report.get(key) is not None and (type(report[key]) is not int or report[key]!=actual):reasons.append(key+'_mismatch')
 history=any(r.get('history_delivery') is not None for r in rows)
 if history and (report.get('records_written') is None or report.get('network_requests') is None):reasons.append('history_tick_counts_unknown')
 if history:
  latest=max((r['history_delivery']['latest_sequence'] for r in rows if isinstance(r.get('history_delivery'),dict) and type(r['history_delivery'].get('latest_sequence')) is int),default=None)
  if report.get('history_known_latest_sequence')!=latest or type(report.get('history_backlog_remaining')) is not bool:reasons.append('history_tick_backlog_unknown')
  elif latest is not None and report['history_backlog_remaining']!=(rows[-1].get('sequence',0)<latest):reasons.append('history_tick_backlog_mismatch')
 return {'pass':not reasons,'reasons':sorted(set(reasons)),'network_requests':len(requests),'rows_written':sum(r.get('append_succeeded') is True for r in rows),'uncommitted_request_indices':[r['request_index'] for r in requests if r['request_index'] not in {x.get('request_index') for x in rows}]}


def ticks_from_events(events,start_mono,end_mono):
 exits=[r for r in events if r.get('event')=='exit' and r.get('operation')=='stage_collect'
        and type(r.get('regular_start_monotonic')) in (int,float)
        and start_mono<=r['regular_start_monotonic']<=end_mono]
 ticks=[]
 for r in exits:
  number=r.get('stage_tick')
  parts=[e for e in events if e.get('stage_tick')==number and e.get('cycle')==r.get('cycle')]
  tick={'stage_tick':number,'regular_start_monotonic':r['regular_start_monotonic'],
        'requests':[e['details'] for e in parts if e.get('event')=='stage_request'],
        'deliveries':[e['details'] for e in parts if e.get('event')=='stage_append'],
        'acknowledgements':[e['details'] for e in parts if e.get('event')=='stage_ack'],
        'trace_errors':r.get('trace_errors'),'ack':r.get('ack'),'operation_failed':r.get('failed'),
        'observed_counts':{'requests':r.get('network_requests_observed'),
                           'deliveries':r.get('append_attempts_observed'),
                           'acknowledgements':r.get('ack_attempts_observed')}}
  tick['validation']=tick_gate(tick)
  ticks.append(tick)
 return ticks
