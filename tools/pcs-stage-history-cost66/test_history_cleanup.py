"""Prepared pure regressions. Only mock calls and temporary local files; never launches a process."""
import copy,datetime,importlib.util,json,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
from history_contract import row_metadata,row_gate,tick_gate
from cleanup_contract import classify_unit,cleanup_gate,helper_readback
ROOT=Path(__file__).resolve().parent

def load(name,file=None):
 spec=importlib.util.spec_from_file_location(name,ROOT/(file or name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
W=load('wrapper_for_tests','collector-wrapper.py');R=load('runner_for_tests','run.py');J=load('judge_for_tests','adjudicate.py')

def delivery(seq=1,latest=1,age=1000,latest_age=1000,crop=False):
 return {'delivery_index':seq,'request_index':seq,'sequence':seq,'availability':'ready','duplicate':False,
         'consumer_payload_limited':crop,'observations_present':not crop,'capture_age_ms':age,
         'history_delivery':{'oldest_sequence':1,'latest_sequence':latest,'latest_age_ms':latest_age,'gap':'none','more':seq<latest,'capture_is_historical':seq<latest},
         'observations_time_scope':'retained_historical_capture' if seq<latest else 'latest_capture',
         'current_gauges_eligible':seq==latest,'history_keys_present':True,'append_succeeded':True,'rotation':'unchanged'}
def request(seq):
 return {'request_index':seq,'request_kind':'history','request_failed':False,'http_status':200,'raw_body_bytes':500,'sequence':seq,'availability':'ready',
         'inner_schema':2,'omitted_sessions':0,'omitted_slow_events':0,'payload_limited':False,'consumer_payload_limited':False,'consumer_published':True,'duplicate':False,
         'slow_queue_counters':[{'capacity':n,'attempted':0,'admitted':0,'dropped':0,'dequeued':0} for n in (8,4,8,2,6,4)],'omitted_slow_events_by_class':[0]*6}
def ack(seq):return {'delivery_index':seq,'request_index':seq,'sequence':seq,'written':True,'rotation':'unchanged','checkpoint_status':'saved','ack_failed':False}
def tick():
 return {'requests':[request(1),request(2)],'deliveries':[delivery(1,2),delivery(2,2)],'acknowledgements':[ack(1),ack(2)],'trace_errors':[],
         'operation_failed':False,'observed_counts':{'requests':2,'deliveries':2,'acknowledgements':2},
         'ack':{'records_written':2,'network_requests':2,'history_known_latest_sequence':2,'history_backlog_remaining':False}}

class HistoryContracts(unittest.TestCase):
 def test_first_crop_second_full_stays_hold(self):
  t=tick();t['deliveries'][0].update(consumer_payload_limited=True,observations_present=False);t['requests'][0].update(consumer_payload_limited=True,consumer_published=False)
  self.assertFalse(tick_gate(t)['pass']);self.assertFalse(J.payload_gate({'expected_inner_schema':2,'ticks':[t,tick(),tick()]},2))
 def test_first_ack_second_append_failed_preserves_backlog(self):
  t=tick();t['deliveries'][1]['append_succeeded']=False;t['acknowledgements'][1].update(written=False,checkpoint_status='not_advanced');t['ack'].update(records_written=1,history_backlog_remaining=True)
  result=tick_gate(t);self.assertFalse(result['pass']);self.assertEqual(t['acknowledgements'][0]['checkpoint_status'],'saved')
  self.assertTrue(t['ack']['history_backlog_remaining']);self.assertEqual(result['rows_written'],1)
 def test_first_checkpoint_failure_cannot_be_hidden(self):
  t=tick();t['acknowledgements'][0]['checkpoint_status']='failed';self.assertFalse(tick_gate(t)['pass'])
 def test_valid_history45_latest25(self):self.assertTrue(row_gate(delivery(1,2,45000,25000))['pass'])
 def test_history_over45(self):self.assertFalse(row_gate(delivery(1,2,45000.001,25000))['pass'])
 def test_history_latest_over25(self):self.assertFalse(row_gate(delivery(1,2,40000,25000.001))['pass'])
 def test_legacy_still25(self):
  r=delivery(age=25001);r.update(history_delivery=None,history_keys_present=False,current_gauges_eligible=None,observations_time_scope=None)
  self.assertFalse(row_gate(r)['pass'])
 def test_history_missing_eligibility(self):
  r=delivery(1,2);r['current_gauges_eligible']=None;self.assertFalse(row_gate(r)['pass'])
 def test_historical_not_current(self):
  r=delivery(1,2);r['current_gauges_eligible']=True;self.assertFalse(row_gate(r)['pass'])
 def test_no_metadata_on_history_response(self):
  t=tick();t['deliveries'][0].update(history_delivery=None,history_keys_present=False,current_gauges_eligible=None,observations_time_scope=None)
  self.assertFalse(tick_gate(t)['pass'])
 def test_restart_probe_not_counted_as_delivery(self):
  t=tick();t['requests'][0]=request(9);t['requests'][0].update(request_index=1,request_kind='latest')
  t['deliveries']=[t['deliveries'][1]];t['deliveries'][0]['delivery_index']=1
  t['acknowledgements']=[t['acknowledgements'][1]];t['acknowledgements'][0]['delivery_index']=1
  t['observed_counts'].update(deliveries=1,acknowledgements=1);t['ack']['records_written']=1
  result=tick_gate(t);self.assertTrue(result['pass']);self.assertEqual(result['uncommitted_request_indices'],[1])
 def test_third_request_not_silently_dropped(self):
  t=tick();t['trace_errors']=['request_bound_exceeded'];self.assertFalse(tick_gate(t)['pass'])
 def test_tick_count_unknown(self):
  t=tick();t['ack']['network_requests']=None;self.assertFalse(tick_gate(t)['pass'])
 def test_stage_summary_checks_crop_with_other_complete_captures(self):
  begin=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc);end=begin+datetime.timedelta(seconds=33)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'monitor').mkdir();rows=[]
   for i in range(1,6):
    ts=(begin+datetime.timedelta(seconds=i)).isoformat();obs={'capture_started':ts,'live_authenticated_sessions':1,'tracked_live_sessions':1,'untracked_live_sessions':0,
      'sessions':[{'socket_id':'synthetic','status':'active','inflight_known':True}],'payload_limited':False,
      **{k:0 for k in ('evicted_sessions_total','lost_completion_total','lost_batch_total','lost_slow_event_total','lost_terminal_record_total')}}
    stage={'availability':'ready','epoch_id':'synthetic','sequence':i,'age_ms':1000,'duplicate':False,'consumer_payload_limited':i==1,
      'observations':None if i==1 else obs,'publication_contiguous':True,'failed_exports_total':0,'fault_count_increment':0}
    rows.append({'time':ts,'stage':stage})
   (p/'monitor'/'stage.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
   (p/'monitor'/'samples.jsonl').write_text(json.dumps({'tcp':{'sockets':[{'identity_certain':True,'role':'client','socket_id':'synthetic'}]}})+'\n')
   summary=R.stage_summary(p,begin,end,1,True)
   self.assertGreaterEqual(summary['distinct_ready_publications_in_workload'],3)
   self.assertFalse(summary['history_freshness_gate']);self.assertFalse(summary['publication_gate'])

class FreshnessProjectionContracts(unittest.TestCase):
 def row(self,metadata):
  return {'enabled':True,'comparison_arm':'B','inner_schema':2,
          'stage':{'delivery_rows':metadata,'max_age_ms':max(x['capture_age_ms'] for x in metadata),'history_freshness_gate':True},
          'publication_payload':{'expected_inner_schema':2,'ticks':[tick(),tick(),tick()]}}
 def core(self,row):return {'status':'QUALIFIED_COST_PENDING','gates':{}}
 def test_projection_is_max_latest_and_does_not_mutate_raw_capture(self):
  r=self.row([delivery(1,2,45000,25000),delivery(2,2,1000,1000)])
  with patch.object(J.core,'trial',side_effect=self.core) as core:out=J.qualified_trial(r)
  self.assertEqual(core.call_args.args[0]['stage']['max_age_ms'],25000)
  self.assertEqual(r['stage']['max_age_ms'],45000)
  self.assertFalse(out['freshness_projection']['current_gauges_projection'])
 def test_one_stale_latest_cannot_be_hidden_by_fresh_second(self):
  r=self.row([delivery(1,2,45000,25001),delivery(2,2,1000,1000)])
  with patch.object(J.core,'trial',side_effect=self.core) as core:out=J.qualified_trial(r)
  self.assertEqual(out['status'],'HOLD');self.assertIsNone(out['freshness_projection'])
  self.assertEqual(core.call_args.args[0]['stage']['max_age_ms'],45000)
 def test_unknown_eligibility_prevents_projection(self):
  item=delivery(1,2,40000,1000);item['current_gauges_eligible']=None;r=self.row([item])
  with patch.object(J.core,'trial',side_effect=self.core):out=J.qualified_trial(r)
  self.assertEqual(out['status'],'HOLD');self.assertIsNone(out['freshness_projection'])

class WrapperContracts(unittest.TestCase):
 def test_actual_wrapper_retains_both_payloads_and_forwards_history_kwargs(self):
  calls=[];data=[{'sequence':1,'crop':True},{'sequence':2,'crop':False}]
  stage=types.SimpleNamespace()
  class HTTP:
   def request(self,path,request=b'latest'):
    calls.append(('request',path,request));return 200,json.dumps(data.pop(0)).encode()
  def sanitize(batch,*args,**kwargs):
   return dict(payload_limited=False,omitted_sessions=0,omitted_slow_events=0,
       omitted_slow_events_by_class=[0]*6,slow_queue_counters=request_row['slow_queue_counters'])
  request_row=request(1)
  class Consumer:
   def consume(self,raw,key,scope,*,history=None,require_history=False):
    calls.append(('consume',history,require_history));v=json.loads(raw)
    stage.sanitize_batch({'schema':2,'sequence':v['sequence']},key,scope)
    self.previous=('private-not-exported',v['sequence'],0)
    return {'availability':'ready','sequence':v['sequence'],'age_ms':1000,'duplicate':False,
            'consumer_payload_limited':v['crop'],'observations':None if v['crop'] else {}}
  class Reader:
   def after_write(self,written,*,rotation='unknown'):self.pending=None;return {'checkpoint_status':'saved'}
  class Log:
   def append(self,row):return 'unchanged'
  def collect(reader,output,scope,*,regular_tick,next_regular):
   for seq in (1,2):
    _,raw=stage.UnixHTTPReader().request('private.sock',b'GET /diagnostics/anytls-stage/history?synthetic')
    c=stage.StageConsumer();value=c.consume(raw,b'k','scope',history={'synthetic':True},require_history=True);reader.pending=c
    h=delivery(seq,2)['history_delivery'];row={'stage':value,'history_delivery':h,
       'observations_time_scope':'retained_historical_capture' if seq==1 else 'latest_capture','current_gauges_eligible':seq==2}
    output.append(row);reader.after_write(True,rotation='unchanged')
   return {'availability':'ready','output_status':'written','checkpoint_status':'saved','rotation':'unchanged',
           'records_written':2,'network_requests':2,'history_known_latest_sequence':2,'history_backlog_remaining':False}
  stage.UnixHTTPReader=HTTP;stage.StageConsumer=Consumer;stage.StageReader=Reader;stage.StageLog=Log;stage.sanitize_batch=sanitize;stage.collect_regular_stage=collect
  class Rollup:
   def record(self,*args,**kwargs):self.error=False
  monitor=types.SimpleNamespace(write_row=lambda *a,**k:None,Rollup=Rollup)
  def main():
   start=time.monotonic();monitor.write_row(None,None,'samples.jsonl');monitor.Rollup().record(None)
   stage.collect_regular_stage(Reader(),Log(),'scope',regular_tick=start,next_regular=start+10)
  monitor.main=main
  with tempfile.TemporaryDirectory() as d:
   trace=W.Trace(Path(d)/'trace.jsonl')
   try:self.assertEqual(W.execute(monitor,stage,trace,['--stage-evidence']),0)
   finally:trace.close()
   events=[json.loads(l) for l in (Path(d)/'trace.jsonl').read_text().splitlines()]
   req=[e['details'] for e in events if e['event']=='stage_request'];rows=[e for e in events if e['event']=='stage_append'];acks=[e for e in events if e['event']=='stage_ack']
   self.assertEqual([r['consumer_payload_limited'] for r in req],[True,False]);self.assertEqual(len(rows),2);self.assertEqual(len(acks),2)
   self.assertEqual([x[2] for x in calls if x[0]=='consume'],[True,True])
   self.assertTrue(all(x[1]=={'synthetic':True} for x in calls if x[0]=='consume'))
   self.assertFalse(trace.failed)

class CleanupContracts(unittest.TestCase):
 def setUp(self):
  self.proof={'unit':'owned.service','description':'owned-token','pid':123,'start_ticks':456,'cgroup_path':'/sys/fs/cgroup/owned.slice/owned.service'}
 def response(self,active='inactive',pid='0',description='owned-token'):
  return types.SimpleNamespace(returncode=0,stdout='Id=owned.service\nDescription='+description+'\nLoadState=loaded\nActiveState='+active+'\nSubState=dead\nMainPID='+pid+'\nControlGroup=\n',stderr='')
 def test_success_requires_all_three(self):
  unit=classify_unit(self.response(),self.proof)
  self.assertTrue(cleanup_gate(unit,{'known':True,'departed':True},{'known':True,'empty_or_absent':True}))
 def test_pid_still_exists_even_if_systemd_inactive(self):
  unit=classify_unit(self.response(),self.proof)
  self.assertFalse(cleanup_gate(unit,{'known':True,'departed':False},{'known':True,'empty_or_absent':True}))
 def test_cgroup_unknown_is_hold(self):
  self.assertFalse(cleanup_gate(classify_unit(self.response(),self.proof),{'known':True,'departed':True},{'known':False,'empty_or_absent':False}))
 def test_foreign_unit_never_owned(self):self.assertFalse(classify_unit(self.response(description='foreign'),self.proof)['owned'])
 def test_unit_active_blocks_cleanup(self):
  self.assertFalse(cleanup_gate(classify_unit(self.response('active','123'),self.proof),{'known':True,'departed':True},{'known':True,'empty_or_absent':True}))
 def test_unknown_pid_blocks_cleanup(self):
  self.assertFalse(cleanup_gate(classify_unit(self.response(),self.proof),{'known':False,'departed':False},{'known':True,'empty_or_absent':True}))
 def test_stop_and_kill_success_do_not_override_failed_readback(self):
  t=object.__new__(R.Trial);t.units=['owned.service'];t.unit_proofs={'owned.service':self.proof}
  t.helper_readbacks=lambda:[{'unit':'owned.service','pass':False}]
  def command(args,**kwargs):
   if args[1]=='show':return self.response('active','123')
   return types.SimpleNamespace(returncode=0,stdout='',stderr='')
  with patch.object(R,'cmd',side_effect=command) as cmd,patch.object(R.time,'monotonic',side_effect=[0,13,14,18]):
   r=t.stop_owned_helpers()
  self.assertFalse(r['pass']);self.assertTrue(any(x['action']=='kill' for x in r['attempts']))
if __name__=='__main__':unittest.main()
