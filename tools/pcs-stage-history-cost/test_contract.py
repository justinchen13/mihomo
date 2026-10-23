"""Prepared pure contracts. Not run during adapter preparation; no processes/network."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
C=load('input_contract');J=load('adjudicate')

def trial(label,p95=10,goodput=2):
 return {'status':'QUALIFIED_COST_PENDING','comparison_arm':label,'outer_sessions':1,
         'proxy_cpu_per_received_decimal_MB':.02,'collector_cpu_per_received_decimal_MB':.003,
         'bulk_decimal_MB_per_second':goodput,'small_p95_ms':p95,'proxy_peak_rss_bytes':32000000,
         'collector_cpu_seconds':.2}
class Contracts(unittest.TestCase):
 def adjudicate(self,p95=10,goodput=2):
  rows=[trial('A'),trial('B',p95,goodput),trial('B',p95,goodput),trial('A')]
  with patch.object(J,'qualified_trial',side_effect=lambda x:x):return J.adjudicate(rows,'matrix')
 def test_exact_new_boundaries(self):
  r=self.adjudicate(10.5,1.96);self.assertTrue(r['gates']['goodput']);self.assertTrue(r['gates']['median_p95'])
 def test_no_old_latency_exception(self):self.assertFalse(self.adjudicate(10.51)['gates']['median_p95'])
 def test_no_old_goodput_tolerance(self):self.assertFalse(self.adjudicate(goodput=1.959)['gates']['goodput'])
 def test_every_pair_preserved(self):
  r=self.adjudicate();self.assertEqual([(p['A'],p['B']) for p in r['paired']],[(0,1),(3,2)])
  self.assertTrue(all('bulk_B_over_A' in p and 'ratio' in p for p in r['paired']))
 def test_wrong_order_unknown(self):
  with patch.object(J,'qualified_trial',side_effect=lambda x:x):r=J.adjudicate([trial('A')]*4,'matrix')
  self.assertEqual(r['status'],'UNKNOWN_INPUT')
 def test_workspace_escape_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(AssertionError):C.fixed_path('/etc/passwd',Path(d))
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'data').write_text('x');(p/'link').symlink_to(p/'data')
   with self.assertRaises(AssertionError):C.fixed_path(str(p/'link'),p)
 def test_core_and_client_unchanged(self):
  import hashlib
  old=json.loads((ROOT/'UPSTREAM-REUSE.json').read_text())['sources']
  for f in ('numeric_core.py','client-v2.go'):
   self.assertEqual(hashlib.sha256((ROOT/f).read_bytes()).hexdigest(),old[f]['sha256'])
if __name__=='__main__':unittest.main()
