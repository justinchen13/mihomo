#!/usr/bin/env python3
"""S1 both-enabled cost: original trial gates/math, explicit arm and input binding."""
import hashlib,importlib.util,pathlib,statistics
from history_contract import tick_gate, row_gate
CORE=pathlib.Path(__file__).resolve().with_name('numeric_core.py')
CORE_SHA='69e9da6239de50b7bb9c8cd3307dc4c5cc3f3c95d804d6e929e8f8c5af052554'
if hashlib.sha256(CORE.read_bytes()).hexdigest()!=CORE_SHA:raise RuntimeError('frozen numerical core changed')
spec=importlib.util.spec_from_file_location('s1_frozen_core',CORE);core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
Unknown=core.Unknown

def payload_gate(report, expected_schema):
 if not isinstance(report,dict) or type(report.get('expected_inner_schema')) is not int or report['expected_inner_schema']!=expected_schema:raise Unknown('payload_report_schema_unknown')
 ticks=report.get('ticks')
 if not isinstance(ticks,list) or len(ticks)<3:raise Unknown('payload_tick_count_unknown')
 good=all(tick_gate(t)['pass'] for t in ticks)
 rows=[r for t in ticks for r in t.get('requests',[])]
 for row in rows:
  if not isinstance(row,dict):raise Unknown('payload_row_missing')
  for name in ('http_status','raw_body_bytes','inner_schema','sequence','omitted_sessions','omitted_slow_events'):
   if type(row.get(name)) is not int or row[name]<0:raise Unknown('payload_numeric_unknown')
  for name in ('payload_limited','consumer_payload_limited','consumer_published','duplicate'):
   if type(row.get(name)) is not bool:raise Unknown('payload_flag_unknown')
  good=good and row['http_status']==200 and 0<row['raw_body_bytes']<=65536 and row['inner_schema']==expected_schema and row['sequence']>0 and row.get('availability')=='ready'
  good=good and not row['payload_limited'] and not row['consumer_payload_limited'] and row['omitted_sessions']==0 and row['omitted_slow_events']==0
  good=good and (row['consumer_published'] or row['duplicate'])
  counts,omitted=row.get('slow_queue_counters'),row.get('omitted_slow_events_by_class')
  if expected_schema==1:
   if counts is not None or omitted is not None:raise Unknown('schema1_class_capability_not_unknown')
  else:
   if not isinstance(counts,list) or len(counts)!=6 or not isinstance(omitted,list) or len(omitted)!=6:raise Unknown('schema2_class_coverage_unknown')
   for item,capacity in zip(counts,(8,4,8,2,6,4)):
    if not isinstance(item,dict) or set(item)!=set(('capacity','attempted','admitted','dropped','dequeued')):raise Unknown('class_counter_fields')
    if any(type(v) is not int or v<0 for v in item.values()) or item['capacity']!=capacity:raise Unknown('class_counter_value')
   if any(type(v) is not int or v<0 for v in omitted):raise Unknown('class_omissions_unknown')
   good=good and sum(omitted)==row['omitted_slow_events']
 return good

IDENTITY_FIELDS=('arm','source_commit','server_binary_sha256','stage_module_sha256','monitor_sha256','rollup_sha256','diagnostic_capability')
def bind_result(row,runtime,arms):
 label=row.get('comparison_arm')
 if type(label) is not str or label not in ('A','B') or runtime.get('comparison_arm')!=label:raise Unknown('comparison_arm_identity_mismatch')
 expected=arms[label]
 for field in IDENTITY_FIELDS:
  value=expected.get(field)
  if not isinstance(value,str) or not value or row.get(field)!=value or runtime.get(field)!=value:raise Unknown('source_binary_consumer_identity_mismatch')
 for name in ('enabled','producer_enabled','reader_enabled'):
  if row.get(name) is not True or runtime.get(name) is not True:raise Unknown('both_arms_must_really_enable_diagnostics')
 for name in ('stage_http_before','stage_http_after'):
  if type(row.get(name)) is not int or type(runtime.get(name)) is not int or row[name]!=200 or runtime[name]!=200:raise Unknown('both_routes_must_be200')
 schema=expected.get('inner_schema')
 if type(schema) is not int or schema not in (1,2) or type(row.get('inner_schema')) is not int or row['inner_schema']!=schema or type(runtime.get('inner_schema')) is not int or runtime['inner_schema']!=schema:raise Unknown('inner_schema_identity_mismatch')
 return row

def qualified_trial(row):
 if row.get('enabled') is not True:raise Unknown('both_arms_require_diagnostics_enabled')
 if type(row.get('comparison_arm')) is not str or row['comparison_arm'] not in ('A','B'):raise Unknown('comparison_arm_unknown')
 stage=row.get('stage') or {}
 metadata=stage.get('delivery_rows')
 if not isinstance(metadata,list) or not metadata:raise Unknown('per_delivery_history_metadata_unknown')
 checks=[row_gate(m) for m in metadata]
 freshness=all(c['pass'] for c in checks)
 retained=payload_gate(row.get('publication_payload'),row['inner_schema'])
 ticks=row['publication_payload']['ticks']
 # All appended rows in the timing window are independently checked; row timing
 # and callback timing use explicit separate clocks and may differ at an edge.
 for tick in ticks:
  checks.extend(row_gate(m) for m in tick.get('deliveries',[]))
 freshness=freshness and all(c['pass'] for c in checks)
 core_view=row
 projection=None
 if freshness and retained:
  latest=max(c['latest_age_ms'] for c in checks)
  capture=max(c['capture_age_ms'] for c in checks)
  if stage.get('history_freshness_gate') is not True:raise Unknown('unvalidated_history_freshness')
  # Only the old core's connection-freshness scalar is projected. Actual input
  # capture ages/rows remain intact. Never use this view for current gauges.
  core_view=dict(row,stage=dict(stage,max_age_ms=latest))
  projection={'purpose':'legacy_core_connection_freshness_only','max_actual_capture_age_ms':capture,
              'max_validated_latest_age_ms':latest,'every_delivery_validated':True,
              'history_capture_limit_ms':45000,'latest_limit_ms':25000,
              'current_gauges_projection':False,'input_result_modified':False}
 result=core.trial(core_view)
 result['comparison_arm']=row['comparison_arm']
 result['gates']['schema_and_consumer_retention']=retained
 result['gates']['per_delivery_history_freshness']=freshness
 result['freshness_projection']=projection
 result['history_ticks']=[{'stage_tick':t.get('stage_tick'),**tick_gate(t),
                        'reported_ack':t.get('ack')} for t in ticks]
 if not retained or not freshness:result['status']='HOLD'
 return result

def adjudicate(rows,mode):
 try:
  trials=[qualified_trial(r) for r in rows]
  if mode=='qualification':
   if len(trials)!=1:raise Unknown('qualification_requires_one_trial')
   return {'status':trials[0]['status'],'cost_status':'NOT_MEASURED','trials':trials,'release_eligible':False}
  if len(trials)!=4 or [r['comparison_arm'] for r in trials]!=['A','B','B','A'] or len({r['outer_sessions'] for r in trials})!=1:raise Unknown('requires_one_profile_ABBA')
  keys=('proxy_cpu_per_received_decimal_MB','collector_cpu_per_received_decimal_MB','bulk_decimal_MB_per_second','small_p95_ms','proxy_peak_rss_bytes')
  med={k:{'A':statistics.median(trials[i][k] for i in (0,3)),'B':statistics.median(trials[i][k] for i in (1,2))} for k in keys}
  enough=all(trials[i]['collector_cpu_seconds']>=.10 for i in (0,3))
  dispersion={k:{arm:{'values':[trials[i][k] for i in ids],'sample_variance':statistics.variance(trials[i][k] for i in ids)} for arm,ids in (('A',(0,3)),('B',(1,2)))} for k in keys}
  pair=[]
  for a,b in ((0,1),(3,2)):
   av=trials[a]['small_p95_ms'];bv=trials[b]['small_p95_ms']
   pair.append({'A':a,'B':b,'delta_ms':bv-av,'ratio':bv/av if av>0 else None,'strict_p95_diagnostic_pass':bv<=1.05*av,'bulk_B_over_A':trials[b]['bulk_decimal_MB_per_second']/trials[a]['bulk_decimal_MB_per_second'],'proxy_cpu_delta_seconds_per_MB':trials[b][keys[0]]-trials[a][keys[0]],'collector_cpu_delta_seconds_per_MB':trials[b][keys[1]]-trials[a][keys[1]],'collector_cpu_ratio':trials[b][keys[1]]/trials[a][keys[1]] if enough else None,'collector_CPU_delta_seconds':trials[b]['collector_cpu_seconds']-trials[a]['collector_cpu_seconds']})
  cpu=med[keys[0]];ccpu=med[keys[1]];speed=med[keys[2]];lat=med[keys[3]];rss=med[keys[4]]
  gates={'all_trial_qualification':all(t['status']=='QUALIFIED_COST_PENDING' for t in trials),'proxy_cpu':cpu['B']<=1.20*cpu['A'],'collector_cpu_baseline_sufficient':enough,'collector_cpu_increment':ccpu['B']<=1.20*ccpu['A'] if enough else None,'goodput':speed['B']>=.98*speed['A'],'median_p95':lat['B']<=1.05*lat['A'],'rss':rss['B']-rss['A']<=16*1024*1024}
  failed=any(v is False for k,v in gates.items() if k!='collector_cpu_baseline_sufficient')
  return {'status':'HOLD' if failed else ('UNKNOWN_COST_BASELINE' if not enough else 'CAPPED_RUNTIME_COST_PASS'),'trials':trials,'gates':gates,'medians':med,'within_arm_dispersion':dispersion,'paired':pair,'collector_cpu_absolute_delta_seconds_per_MB':ccpu['B']-ccpu['A'],'collector_cpu_ratio':ccpu['B']/ccpu['A'] if enough else None,'release_eligible':False,'remaining_release_gates':['full runtime image/security','parent review and production observation'],'scope':'frozen history baseline versus candidate, actual respective collectors ON; group medians, all oriented pairs retained; capped offered load, not capacity or public throughput'}
 except (Unknown,KeyError,TypeError,ValueError,OverflowError) as e:
  return {'status':'UNKNOWN_INPUT','reason':str(e) if isinstance(e,Unknown) else type(e).__name__,'release_eligible':False}


def adjudicate_bound(rows,runtimes,arms,mode):
 try:
  if len(rows)!=len(runtimes):raise Unknown('runtime_count_mismatch')
  records=[bind_result(r,t,arms) for r,t in zip(rows,runtimes)]
 except (Unknown,KeyError,TypeError,ValueError) as e:
  return {'status':'UNKNOWN_INPUT','reason':str(e),'release_eligible':False}
 return adjudicate(records,mode)
