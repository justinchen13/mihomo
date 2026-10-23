"""Pure synthetic tests only. Nothing here starts a binary or opens a socket."""
import copy
import unittest
from contract import analyse, expected_sha, percentile, resource_reasons


def pt(ns):
    return {'monotonic_ns': ns, 'utc': 'synthetic'}


def fixture(bulk_outer=0):
    base = 10_000_000_000
    client = {'ok': True, 'timed_out': False, 'unjoined_workers': 0, 'bulk_outer': bulk_outer,
              'start': pt(base), 'deadline_seconds': 45, 'expected_application_bytes': 6422528, 'rows': []}
    origin = {'rows': [], 'duplicates': 0, 'invalid': 0, 'parsed_count': 33}
    for id in range(33):
        due = base+(0 if id == 32 else 1_000_000_000+(id//2)*500_000_000)
        outer = bulk_outer if id == 32 else id % 2
        role = 'bulk' if id == 32 else ('loaded' if outer == bulk_outer else 'independent')
        n = 6291456 if id == 32 else 4096
        sha = expected_sha(id)
        client['rows'].append({'id': id, 'outer': outer, 'role': role, 'due_monotonic_ns': due,
            'writer_joined': True, 'reader_joined': True,
            'writer': {'armed': pt(base-100), 'wake': pt(due+1000), 'begin': pt(due+2000), 'end': pt(due+10000), 'error_class': ''},
            'reader': {'read_begin': pt(base-50), 'first_byte': pt(due+90_000_000), 'verified': pt(due+100_000_000),
                       'bytes': n, 'sha256': sha, 'error_class': ''}})
        origin['rows'].append({'id': id, 'parsed': pt(due+75_000_000), 'ready': pt(due+75_001_000),
            'write_begin': pt(due+75_002_000), 'write_end': pt(due+76_000_000), 'accepted_bytes': n,
            'expected_sha256': sha, 'error_class': '', 'omitted_write_calls': 0})
    resources = {x: True for x in ('same_time_namespace', 'owned_cleanup', 'host_unchanged', 'all_workers_reaped',
                                  'raw_evidence_complete', 'same_server_identity', 'tls_padding_readback')}
    resources.update(cpu_max=[400000, 1000000], memory_max=536870912, swap_max=0, oom_delta=0, origin_exit_code=0,
                     quiet={'elapsed_s': 1.2, 'process_identities_stable': True},
                     first={'wall_s': 1.01, 'cpu_s': .1, 'throttled_s': 0},
                     whole={'wall_s': 10, 'cpu_s': 1, 'throttled_s': 0})
    for phase in ('first', 'whole'):
        resources[phase]['counter_barrier'] = True
        resources[phase]['memory_event_deltas'] = dict(high=0, max=0, oom=0, oom_kill=0)
    return client, {'proof': origin, 'all_handlers_joined': True, 'protocol_errors': 0, 'control_normal_stop': True, 'io_errors_including_cleanup': 33}, resources


class ContractTests(unittest.TestCase):
    def test_fixed_ids_both_bulk_placements(self):
        for ordinal in (0, 1):
            result = analyse(*fixture(ordinal))
            self.assertEqual(result['status'], 'QUALIFIED_PROTOCOL_LATENCY_ONLY')
            self.assertEqual(len(result['all_fixed_pairs']), 16)
            self.assertFalse(result['performance_claim'])
            self.assertTrue(result['mechanism'].startswith('UNKNOWN'))

    def test_response_before_local_write_return_is_valid(self):
        c, o, r = fixture()
        c['rows'][0]['writer']['end'] = pt(c['rows'][0]['reader']['verified']['monotonic_ns']+1000)
        o['proof']['rows'][0]['write_end'] = pt(c['rows'][0]['reader']['verified']['monotonic_ns']+2000)
        self.assertEqual(analyse(c, o, r)['failures'], [])

    def test_missing_and_duplicate_id_rejected(self):
        c, o, r = fixture(); c['rows'][31]['id'] = 30
        self.assertIn('duplicate_or_invalid_id', analyse(c, o, r)['failures'])
        c, o, r = fixture(); o['proof']['rows'].pop()
        self.assertIn('fixed_population_missing', analyse(c, o, r)['failures'])

    def test_late_reader_rejected(self):
        c, o, r = fixture(); c['rows'][0]['reader']['read_begin'] = pt(c['start']['monotonic_ns']+1)
        self.assertIn('clock_or_readiness_id_0', analyse(c, o, r)['failures'])

    def test_scheduler_batch_pause_rejected(self):
        c, o, r = fixture(); c['rows'][0]['writer']['wake'] = pt(c['rows'][0]['due_monotonic_ns']+874_000_000)
        self.assertIn('scheduler_loaded', analyse(c, o, r)['failures'])

    def test_missing_resources_unknown_not_zero(self):
        c, o, r = fixture(); del r['first']['throttled_s']
        self.assertIn('resource_first_missing', analyse(c, o, r)['failures'])
        self.assertIn('resource_owned_cleanup', resource_reasons({}))

    def test_quota_and_first_boundary(self):
        c, o, r = fixture(); r['first']['throttled_s'] = .132351
        self.assertIn('resource_first_throttle', analyse(c, o, r)['failures'])
        r['first']['wall_s'] = 1.06
        self.assertIn('resource_first_interval', analyse(c, o, r)['failures'])

    def test_wrong_sha_partial_and_timeout_preserved(self):
        c, o, r = fixture(); c['rows'][0]['reader']['bytes'] = 11; c['timed_out'] = True
        v = analyse(c, o, r)
        self.assertIn('integrity_id_0', v['failures'])
        self.assertIn('business_or_worker_failure', v['failures'])
        self.assertEqual(v['per_request'][0]['partial_bytes'], 11)

    def test_boolean_id_and_nan_rejected(self):
        c, o, r = fixture(); c['rows'][0]['id'] = False
        self.assertIn('duplicate_or_invalid_id', analyse(c, o, r)['failures'])
        c, o, r = fixture(); r['whole']['cpu_s'] = float('nan')
        self.assertIn('resource_whole_missing', analyse(c, o, r)['failures'])
        with self.assertRaises(ValueError): percentile([1, float('inf')], .95)

    def test_pair_population_not_bulk_overlap_selected(self):
        c, o, r = fixture(); before = copy.deepcopy(c)
        result = analyse(c, o, r)
        self.assertEqual([x['pair'] for x in result['all_fixed_pairs']], list(range(16)))
        self.assertEqual(c, before)
        self.assertEqual(result['pair_summary']['positive_count'], 0)

    def test_timely_wake_late_actual_begin_rejected_including_bulk(self):
        for ident, role in [(0, 'loaded'), (32, 'bulk')]:
            c, o, r = fixture()
            row, source = c['rows'][ident], o['proof']['rows'][ident]
            for key in ('begin', 'end'):
                row['writer'][key] = pt(row['writer'][key]['monotonic_ns']+500_000_000)
            for key in ('first_byte', 'verified'):
                row['reader'][key] = pt(row['reader'][key]['monotonic_ns']+500_000_000)
            for key in ('parsed', 'ready', 'write_begin', 'write_end'):
                source[key] = pt(source[key]['monotonic_ns']+500_000_000)
            self.assertIn('request_start_scheduler_'+role, analyse(c, o, r)['failures'])

    def test_final_origin_status_and_actual_exit_required(self):
        for key, value in [('protocol_errors', 1), ('all_handlers_joined', False), ('control_normal_stop', False)]:
            c, o, r = fixture(); o[key] = value
            self.assertIn('origin_final_shutdown_or_protocol', analyse(c, o, r)['failures'])
        c, o, r = fixture(); del r['origin_exit_code']
        self.assertIn('resource_origin_exit', analyse(c, o, r)['failures'])
        c, o, r = fixture(); r['origin_exit_code'] = False
        self.assertIn('resource_origin_exit', analyse(c, o, r)['failures'])

    def test_snapshot_without_final_origin_result_cannot_qualify(self):
        c, o, r = fixture()
        self.assertEqual(analyse(c, o['proof'], r)['status'], 'INCONCLUSIVE')

    def test_primary_contrast_is_after_origin_ready(self):
        c, o, r = fixture()
        c['rows'][0]['reader']['verified'] = pt(c['rows'][0]['reader']['verified']['monotonic_ns']+50_000_000)
        x = analyse(c, o, r)
        self.assertEqual(x['primary_pair_metric'], 'loaded_minus_independent_after_ready_ms')
        self.assertEqual(x['all_fixed_pairs'][0]['loaded_minus_independent_after_ready_ms'], 50)
        self.assertEqual(x['pair_summary']['after_ready']['count'], 16)
        self.assertTrue(x['mechanism'].startswith('UNKNOWN'))


if __name__ == '__main__':
    unittest.main()
