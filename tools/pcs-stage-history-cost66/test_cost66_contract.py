"""R03 pure workload/profile regressions. No processes, Docker, sockets or cgroups."""
import unittest
from pathlib import Path
from workload_contract import (SCHEMA, workload, validate_selection, validate_client,
                               validate_result_binding, CLIENT_DEADLINE_SECONDS,
                               RUNNER_DEADLINE_SECONDS)


def selection(n=1, mode='matrix'):
    return {'schema': SCHEMA, 'selected_profile': n, 'execution_mode': mode, 'workload': workload()}


def client(n=1):
    w=workload();expected=w['bulk_bytes']+w['small_count']*w['small_bytes']+n*32
    rows=[{'index':i,'outer_ordinal':i%n,'received_body_bytes':w['small_bytes'],
           'ok':True,'sha256':'a'*64,'scheduled_to_verified_ms':float(i)} for i in range(w['small_count'])]
    return {'workload_contract':'cost66-payload-v1','active_seconds':66,'outer_sessions':n,
            'live_sessions_at_finish':n,'streams':3*n,'tls_verified':n,'padding_verified':n,
            'outer_source_bind_verified':n,'received_body_bytes':expected,
            'expected_received_body_bytes':expected,'upload_verified_bytes':w['upload_bytes'],
            'bulk_body_bytes':w['bulk_bytes'],'small_count':w['small_count'],
            'ok':True,'small_all_verified':True,'errors':[], 'small':rows,
            'small_p95_scheduled_to_verified_ms':501.0}


class Cost66Contracts(unittest.TestCase):
    def test_three_selected_profiles(self):
        for n in (1,32,66):validate_selection(selection(n));validate_client(client(n),n)
    def test_security_only_profile1(self):
        validate_selection(selection(1,'security'))
        for n in (32,66):
            with self.assertRaises(AssertionError):validate_selection(selection(n,'security'))
    def test_boolean_or_invalid_profile_rejected(self):
        for n in (True,1.0,0,2,67):
            with self.assertRaises(AssertionError):validate_selection(selection(n))
    def test_old_schema_rejected(self):
        m=selection();m['schema']='history-whole-proxy-cost-v1'
        with self.assertRaises(AssertionError):validate_selection(m)
    def test_old_or_partial_workload_rejected(self):
        for key,value in (('seconds',33),('bulk_bytes',67108864),('upload_bytes',8388608),('small_count',264),('small_bytes',8192),('seconds',66.0)):
            m=selection();m['workload'][key]=value
            with self.assertRaises(AssertionError):validate_selection(m)
        m=selection();del m['workload']['small_bytes']
        with self.assertRaises(AssertionError):validate_selection(m)
    def test_extra_workload_field_rejected(self):
        m=selection();m['workload']['override']=True
        with self.assertRaises(AssertionError):validate_selection(m)
    def test_raw_samples_must_be528(self):
        c=client();c['small']=c['small'][:264]
        with self.assertRaises(AssertionError):validate_client(c,1)
    def test_nearest_rank_and_payload_checked(self):
        for key,value in (('small_p95_scheduled_to_verified_ms',500.0),('received_body_bytes',0),('upload_verified_bytes',8388608),('active_seconds',33)):
            c=client();c[key]=value
            with self.assertRaises(AssertionError):validate_client(c,1)
    def test_sample_integrity_and_index_checked(self):
        for key,value in (('index',2),('outer_ordinal',1),('received_body_bytes',1),('sha256','unknown'),('ok',False)):
            c=client();c['small'][0][key]=value
            with self.assertRaises(AssertionError):validate_client(c,1)
    def test_result_cannot_cross_profiles_or_workloads(self):
        r={'selected_profile':32,'outer_sessions':32,'workload_contract':workload(),'client':client(32)}
        t={k:v for k,v in r.items() if k!='client'}
        validate_result_binding(r,t,32)
        with self.assertRaises(AssertionError):validate_result_binding(r,t,1)
        t['workload_contract']=dict(workload(),seconds=33)
        with self.assertRaises(AssertionError):validate_result_binding(r,t,32)
    def test_client_source_and_deadline_audit(self):
        s=Path(__file__).with_name('client-v3.go').read_text()
        for line in ('const bulkBytes = 128 * 1024 * 1024','const uploadBytes = 16 * 1024 * 1024',
                     'const smallCount = 528','const smallBytes = 4096','const active = 66 * time.Second',
                     'const workloadDeadline = active + 27*time.Second',
                     'duration > active+7*time.Second || phase > active'):
            self.assertIn(line,s)
        self.assertEqual(s.count('began.Add(workloadDeadline)'),2)
        self.assertEqual((CLIENT_DEADLINE_SECONDS,RUNNER_DEADLINE_SECONDS),(93,98))
    def test_numeric_gates_and_measurement_mechanisms_preserved(self):
        s=Path(__file__).with_name('client-v3.go').read_text()
        for value in ('make(chan struct{}, 8)','make([]byte, 32768)',
                      'values[(smallCount*95+99)/100-1]','n*32'):
            self.assertIn(value,s)
        run=Path(__file__).with_name('run.py').read_text()
        self.assertIn('for n in (args.selected_profile,):',run)
        self.assertIn("'PROFILE_PASS','profile':args.selected_profile",run)
        self.assertIn("wait(f/'client-ready.json',40)",run)
        self.assertIn('time.sleep(13)',run)
        self.assertIn("'--interval','10'",run)

if __name__=='__main__':unittest.main()
