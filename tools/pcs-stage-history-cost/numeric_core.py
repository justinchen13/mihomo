#!/usr/bin/env python3
"""Independent capped-runtime adjudication; never rewrites v2 inputs or verdicts."""
import argparse,hashlib,json,math,pathlib,statistics
ROOT=pathlib.Path(__file__).resolve().parent
REQUIRED_GATES={'integrity','resource','proxy_cpu_denominator','no_oom_or_memory_pressure','complete_cycle_timing','end_capture_skew','publication_or_off','full_regular','collector_output_errors','zero_stage_shared_log'}
class Unknown(ValueError):pass
def num(v,positive=False):
 if type(v) not in (int,float) or not math.isfinite(v) or v<0 or (positive and v<=0):raise Unknown('missing_or_invalid_numeric')
 return v
def get(d,*keys):
 for k in keys:
  if not isinstance(d,dict) or k not in d:raise Unknown('missing_required_field')
  d=d[k]
 return d
def finite_tree(v):
 if type(v) is float and not math.isfinite(v):raise Unknown('nonfinite_number')
 if isinstance(v,dict):
  for item in v.values():finite_tree(item)
 elif isinstance(v,list):
  for item in v:finite_tree(item)
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise Unknown('duplicate_json_key')
  d[k]=v
 return d
def load(p):
 if p.stat().st_size>4*1024*1024:raise Unknown('input_size_limit')
 d=json.loads(p.read_text(),object_pairs_hook=unique);finite_tree(d);return d
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def close(a,b):return math.isclose(a,b,rel_tol=1e-8,abs_tol=1e-9)
def trial(r):
 finite_tree(r)
 gates=get(r,'gates')
 if set(gates)!=REQUIRED_GATES or any(type(v) is not bool for v in gates.values()):raise Unknown('gate_schema_changed')
 if type(r.get('enabled')) is not bool or type(r.get('outer_sessions')) is not int or r.get('outer_sessions') not in (1,32,66):raise Unknown('arm_or_profile_unknown')
 if r.get('status') not in ('PASS','HOLD','RESOURCE_INCONCLUSIVE'):raise Unknown('v2_verdict_unknown')
 wall=num(get(r,'workload_wall_seconds'),True);first=num(get(r,'first_interval_seconds'),True)
 received=num(get(r,'client','received_body_bytes'),True);expected=num(get(r,'client','expected_received_body_bytes'),True)
 cpu=num(get(r,'process_cpu_seconds','proxy'));collector=num(get(r,'collector_delta','cpu_seconds'))
 supplied=num(get(r,'proxy_cpu_per_received_decimal_MB'))
 if not close(supplied,cpu/(received/1e6)):raise Unknown('cpu_denominator_inconsistent')
 business={};observer={}
 for scope,fullkey,firstkey in (('parent','parent_delta','first_second_parent_delta'),('proxy','proxy_cgroup_delta','first_second_proxy_cgroup_delta'),('collector','collector_delta','first_second_collector_delta')):
  for label,key,denom in (('full',fullkey,wall),('first',firstkey,first)):
   delta=get(r,key);usage=num(get(delta,'cpu_seconds'));throttle=num(get(delta,'throttled_seconds'))
   for f in ('high','max','oom','oom_kill'):num(get(delta,'memory_events',f))
   row={'cpu_seconds':usage,'throttled_seconds':throttle,'wall_seconds':denom,'throttled_wall_ratio':throttle/denom}
   if scope=='collector':observer[label]=row
   else:business[scope+'_'+label]=row
 regular=get(r,'regular');timing=get(r,'timing');stage=get(r,'stage')
 for k in ('rows','issues','max_gap_seconds','tcp_rows_truncated_max','api_rows_truncated_max','tcp_parse_errors','rollup_errors'):num(get(regular,k))
 for k in ('cycles','full_cycle_seconds_max','stage_calls_in_window','utc_monotonic_offset_span_seconds'):num(get(timing,k))
 common={k:v for k,v in gates.items() if k!='resource'}
 common.update(business_quota=all(x['throttled_wall_ratio']<=.1 for x in business.values()),
  known_full_cycle=timing['cycles']>=3 and timing['full_cycle_seconds_max']<=10 and timing.get('all_cycle_timing_known') is True and timing.get('footer_seen') is True and timing.get('footer_last_rollup_error') is False,
  known_regular=regular['rows']>=3 and regular['max_gap_seconds']<=11 and regular['issues']==0 and regular['rollup_errors']==0 and regular['tcp_parse_errors']==0,
  exact_received=received==expected and get(r,'client','ok') is True,
  memory_events=all(get(r,key,'memory_events',f)==0 for key in ('parent_delta','collector_delta','proxy_cgroup_delta','first_second_parent_delta','first_second_collector_delta','first_second_proxy_cgroup_delta') for f in ('high','max','oom','oom_kill')),
  proxy_cpu_sufficient=cpu>=.20)
 if r['enabled']:
  for k in ('distinct_ready_publications_in_workload','exact_cookie_identity_joins','max_age_ms','window_unexpected_availability','window_epoch_count','window_missing_sequence_numbers','payload_limited_publications'):num(get(stage,k))
  losses=get(stage,'loss_counters')
  for item in losses.values():
   for k in ('first_lifetime','last_lifetime','window_delta'):num(get(item,k))
  ack=get(timing,'last_ack')
  common['known_publication']=stage['distinct_ready_publications_in_workload']>=3 and stage['exact_cookie_identity_joins']>=1 and stage['max_age_ms']<=25000 and stage['window_unexpected_availability']==0 and stage['window_epoch_count']==1 and stage.get('window_sequence_monotonic') is True and stage['window_missing_sequence_numbers']==0 and stage['payload_limited_publications']==0 and stage.get('population_correct') is True and get(losses,'lost_batch_total','window_delta')==0 and stage.get('publication_gate') is True
  common['known_final_ack']=timing['stage_calls_in_window']>=3 and timing.get('all_stage_acks_ok') is True and ack.get('availability')=='ready' and ack.get('output_status')=='written' and ack.get('checkpoint_status')=='saved' and get(ack,'output_failures_total')==0 and get(ack,'cursor_failures_total')==0
 else:
  common['off_inactive']=get(stage,'rows_total')==0 and timing['stage_calls_in_window']==0 and timing.get('last_ack') is None and r.get('default_off_gate') is True
 return {'status':'QUALIFIED_COST_PENDING' if all(common.values()) else 'HOLD','v2_status_preserved':r['status'],'v2_resource_gate_preserved':gates['resource'],'enabled':r['enabled'],'outer_sessions':r['outer_sessions'],'gates':common,'business_resources':business,'observer_resources':observer,'proxy_cpu_seconds':cpu,'collector_cpu_seconds':collector,'received_decimal_MB':received/1e6,'proxy_cpu_per_received_decimal_MB':cpu/(received/1e6),'collector_cpu_per_received_decimal_MB':collector/(received/1e6),'bulk_decimal_MB_per_second':num(get(r,'client','bulk_decimal_MB_per_second'),True),'small_p95_ms':num(get(r,'client','small_p95_scheduled_to_verified_ms')),'proxy_peak_rss_bytes':num(get(r,'proxy_peak_rss_bytes'),True),'tcp_rows_truncated_max':regular['tcp_rows_truncated_max']}
def adjudicate(results,mode):
 try:
  trials=[trial(r) for r in results]
  if mode=='qualification':
   if len(trials)!=1:raise Unknown('qualification_requires_one_trial')
   return {'status':trials[0]['status'],'cost_status':'NOT_MEASURED','trials':trials,'release_eligible':False}
  if len(trials)!=4 or [r['enabled'] for r in trials]!=[False,True,True,False] or len({r['outer_sessions'] for r in trials})!=1:raise Unknown('requires_one_profile_ABBA')
  keys=('proxy_cpu_per_received_decimal_MB','collector_cpu_per_received_decimal_MB','bulk_decimal_MB_per_second','small_p95_ms','proxy_peak_rss_bytes')
  med={k:{'A':statistics.median(trials[i][k] for i in (0,3)),'B':statistics.median(trials[i][k] for i in (1,2))} for k in keys}
  enough=all(trials[i]['collector_cpu_seconds']>=.10 for i in (0,3))
  dispersion={k:{arm:{'values':[trials[i][k] for i in ids],'sample_variance':statistics.variance(trials[i][k] for i in ids)} for arm,ids in (('A',(0,3)),('B',(1,2)))} for k in keys}
  pair=[]
  for a,b in ((0,1),(3,2)):
   av=trials[a]['small_p95_ms'];bv=trials[b]['small_p95_ms']
   pair.append({'A':a,'B':b,'delta_ms':bv-av,'ratio':bv/av if av>0 else None,'pass':not(bv>1.5*av and bv-av>20),'proxy_cpu_delta_seconds_per_MB':trials[b][keys[0]]-trials[a][keys[0]],'collector_cpu_delta_seconds_per_MB':trials[b][keys[1]]-trials[a][keys[1]],'collector_cpu_ratio':trials[b][keys[1]]/trials[a][keys[1]] if enough else None,'collector_CPU_delta_seconds':trials[b]['collector_cpu_seconds']-trials[a]['collector_cpu_seconds']})
  cpu=med[keys[0]];ccpu=med[keys[1]];speed=med[keys[2]];lat=med[keys[3]];rss=med[keys[4]]
  gates={'all_trial_qualification':all(t['status']=='QUALIFIED_COST_PENDING' for t in trials),'proxy_cpu':cpu['B']<=1.20*cpu['A'],'collector_cpu_baseline_sufficient':enough,'collector_cpu_increment':ccpu['B']<=1.20*ccpu['A'] if enough else None,'goodput':speed['B']>=.95*speed['A'],'median_p95':not(lat['B']>1.20*lat['A'] and lat['B']-lat['A']>5),'paired_p95':all(p['pass'] for p in pair),'rss':rss['B']-rss['A']<=16*1024*1024}
  failed=any(v is False for k,v in gates.items() if k!='collector_cpu_baseline_sufficient')
  return {'status':'HOLD' if failed else ('UNKNOWN_COST_BASELINE' if not enough else 'CAPPED_RUNTIME_COST_PASS'),'trials':trials,'gates':gates,'medians':med,'within_arm_dispersion':dispersion,'paired':pair,'collector_cpu_absolute_delta_seconds_per_MB':ccpu['B']-ccpu['A'],'collector_cpu_ratio':ccpu['B']/ccpu['A'] if enough else None,'release_eligible':False,'remaining_release_gates':['full runtime security','production binary versus candidate default-off','parent review and production observation'],'scope':'same candidate binary under fixed quota; not unthrottled or maximum throughput'}
 except (Unknown,KeyError,TypeError,ValueError,OverflowError) as e:
  return {'status':'UNKNOWN_INPUT','reason':str(e) if isinstance(e,Unknown) else type(e).__name__,'release_eligible':False}
def matrix_paths_valid(paths):
 return len(paths)==4 and len(set(paths))==4 and len({x.parent.parent for x in paths})==1 and [x.parent.name for x in paths]==['00-A','01-B','02-B','03-A']
def main():
 p=argparse.ArgumentParser();p.add_argument('--plan',type=pathlib.Path,default=ROOT/'plan-v3.json');p.add_argument('--mode',choices=['qualification','matrix'],required=True);p.add_argument('results',nargs='+',type=pathlib.Path);a=p.parse_args()
 plan=load(a.plan)
 if plan.get('status')!='FROZEN_FOR_EXECUTION':raise SystemExit('plan not frozen; no adjudication')
 for file,expected in plan['inputs_sha256'].items():
  if digest(pathlib.Path(file))!=expected:raise SystemExit('frozen input hash mismatch')
 expected_profile=plan['allowed_profiles'];provenance=[];rows=[]
 paths=[x.resolve() for x in a.results]
 if a.mode=='matrix' and not matrix_paths_valid(paths):raise SystemExit('matrix requires one retained fresh ABBA group; preflight pooling refused')
 for path in paths:
  path=path.resolve()
  if not path.is_relative_to(ROOT/'results') or path.name!='result.json':raise SystemExit('result outside private fixture outputs')
  row=load(path)
  if row.get('outer_sessions') not in expected_profile:raise SystemExit('profile outside frozen plan')
  evidence={}
  for name in ('result.json','before.json','after.json','client-result.json','collector-timing.jsonl','monitor/samples.jsonl','log-budget.json'):
   f=path.parent/name
   if not f.is_file():raise SystemExit('required retained evidence missing')
   evidence[name]=digest(f)
  provenance.append({'result_path':str(path),'sha256':evidence});rows.append(row)
 out=adjudicate(rows,a.mode);out.update(schema=1,plan_sha256=digest(a.plan),input_provenance=provenance,original_v2_files_modified=False)
 print(json.dumps(out,indent=2,allow_nan=False))
if __name__=='__main__':main()
