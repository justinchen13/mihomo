"""Offline fixed-population contract. No network, process or runtime imports.

Inputs are full raw client/origin records plus separately captured resources.
Qualified protocol/latency evidence is not a performance or causal PASS.
"""
import hashlib
import math
from functools import lru_cache

SMALL = 32
BULK_ID = 32
SMALL_BYTES = 4096
BULK_BYTES = 6291456


def integer(v):
    return type(v) is int


def finite(v):
    return type(v) in (int, float) and math.isfinite(v)


def point(v):
    if not isinstance(v, dict) or not integer(v.get('monotonic_ns')) or v['monotonic_ns'] <= 0:
        raise ValueError('missing_or_invalid_monotonic_point')
    return v['monotonic_ns']


def percentile(v, q):
    if not v or any(not finite(x) for x in v):
        raise ValueError('percentile_population')
    s = sorted(v)
    p = (len(s)-1)*q
    i = int(p)
    return s[i] if i == len(s)-1 else s[i]+(s[i+1]-s[i])*(p-i)


@lru_cache(maxsize=33, typed=True)
def expected_sha(id):
    if not integer(id) or id not in range(33):
        raise ValueError('expected_sha_fixed_id')
    n = BULK_BYTES if id == BULK_ID else SMALL_BYTES
    seed = 2000+id
    period = bytes((i*31+seed*17) % 256 for i in range(256))
    return hashlib.sha256((period*(n//256+1))[:n]).hexdigest()


def rows_by_id(rows):
    if not isinstance(rows, list) or len(rows) != 33:
        raise ValueError('fixed_population_missing')
    out = {}
    for row in rows:
        if not isinstance(row, dict) or not integer(row.get('id')) or row['id'] not in range(33) or row['id'] in out:
            raise ValueError('duplicate_or_invalid_id')
        out[row['id']] = row
    return out


def resource_reasons(e):
    reasons = []
    # Mandatory real readbacks. No unknown/missing value defaults to zero.
    for key in ('same_time_namespace', 'owned_cleanup', 'host_unchanged', 'all_workers_reaped',
                'raw_evidence_complete', 'same_server_identity', 'tls_padding_readback'):
        if e.get(key) is not True:
            reasons.append('resource_'+key)
    if e.get('cpu_max') != [400000, 1000000] or not all(integer(e.get(k)) for k in ('memory_max', 'swap_max')) or e.get('memory_max') != 536870912 or e.get('swap_max') != 0:
        reasons.append('resource_limits')
    if not integer(e.get('oom_delta')) or e['oom_delta'] != 0:
        reasons.append('resource_oom')
    if not integer(e.get('origin_exit_code')) or e['origin_exit_code'] != 0:
        reasons.append('resource_origin_exit')
    quiet = e.get('quiet', {})
    if not finite(quiet.get('elapsed_s')) or quiet['elapsed_s'] < 1.2 or quiet.get('process_identities_stable') is not True:
        reasons.append('fixed_quiet_or_identity')
    for phase in ('first', 'whole'):
        x = e.get(phase, {})
        if x.get('counter_barrier') is not True:
            reasons.append('resource_'+phase+'_counter_barrier')
        memory = x.get('memory_event_deltas', {})
        if any(not integer(memory.get(k)) or memory[k] != 0 for k in ('high', 'max', 'oom', 'oom_kill')):
            reasons.append('resource_'+phase+'_memory_events')
        wall, cpu, throttle = (x.get(k) for k in ('wall_s', 'cpu_s', 'throttled_s'))
        if not all(finite(v) and v >= 0 for v in (wall, cpu, throttle)) or not wall:
            reasons.append('resource_'+phase+'_missing')
        elif throttle/wall > 0.10:
            reasons.append('resource_'+phase+'_throttle')
        if phase == 'first' and (not finite(wall) or not 1.0 <= wall <= 1.05):
            reasons.append('resource_first_interval')
    return reasons


def analyse(client, origin_final, resources):
    failures = resource_reasons(resources)
    output = {'schema': 1, 'status': 'INCONCLUSIVE', 'failures': failures,
              'mechanism': 'UNKNOWN_REQUIRES_TIME_AND_IDENTITY_CERTAIN_TCP_STAGE_EVIDENCE',
              'performance_claim': False, 'all_fixed_pairs': [], 'per_request': [],
              'business_outcome': 'COMPLETE' if client.get('ok') is True else 'FAIL_OR_UNKNOWN',
              'raw_population_retained_required': True}
    try:
        if (origin_final.get('all_handlers_joined') is not True or
                origin_final.get('control_normal_stop') is not True or
                not integer(origin_final.get('protocol_errors')) or origin_final['protocol_errors'] != 0):
            failures.append('origin_final_shutdown_or_protocol')
        origin = origin_final['proof']
        if client.get('ok') is not True or client.get('timed_out') is not False or client.get('unjoined_workers') != 0:
            failures.append('business_or_worker_failure')
        bulk_outer = client['bulk_outer']
        if not integer(bulk_outer) or bulk_outer not in (0, 1): raise ValueError('bulk_outer')
        base = point(client['start'])
        cr, org = rows_by_id(client['rows']), rows_by_id(origin['rows'])
        if origin.get('duplicates') != 0 or origin.get('invalid') != 0 or origin.get('parsed_count') != 33:
            failures.append('origin_identity')
        if client.get('deadline_seconds') != 45 or client.get('expected_application_bytes') != 6422528:
            failures.append('workload_changed')
        role_jitter = {'loaded': [], 'independent': []}
        begin_jitter = {'loaded': [], 'independent': [], 'bulk': []}
        per = {}
        for id in range(33):
            c, o = cr[id], org[id]
            w, r = c['writer'], c['reader']
            outer = bulk_outer if id == BULK_ID else id % 2
            role = 'bulk' if id == BULK_ID else ('loaded' if outer == bulk_outer else 'independent')
            due = base+(0 if id == BULK_ID else 1000000000+(id//2)*500000000)
            if c.get('outer') != outer or c.get('role') != role or c.get('due_monotonic_ns') != due:
                raise ValueError('fixed_assignment')
            n = BULK_BYTES if id == BULK_ID else SMALL_BYTES
            if any(x is not True for x in (c.get('writer_joined'), c.get('reader_joined'))):
                raise ValueError('unjoined_result')
            if w.get('error_class') or r.get('error_class') or o.get('error_class'):
                failures.append('io_failure_id_'+str(id))
            if r.get('bytes') != n or o.get('accepted_bytes') != n or r.get('sha256') != expected_sha(id) or o.get('expected_sha256') != expected_sha(id):
                failures.append('integrity_id_'+str(id))
            read_begin, armed = point(r['read_begin']), point(w['armed'])
            wake, begin, end = point(w['wake']), point(w['begin']), point(w['end'])
            parsed, ready = point(o['parsed']), point(o['ready'])
            ob, oe = point(o['write_begin']), point(o['write_end'])
            first, verified = point(r['first_byte']), point(r['verified'])
            # Cross-process Write return is not ordered before remote parse or
            # receipt. In particular end>verified and oe>verified are legal.
            if not (read_begin <= base and armed <= base and due <= wake <= begin <= end and
                    begin <= parsed <= ready <= ob <= oe and ob <= first <= verified and verified-base <= 45e9):
                failures.append('clock_or_readiness_id_'+str(id))
            jitter = (wake-due)/1e6
            if role != 'bulk': role_jitter[role].append(jitter)
            begin_jitter[role].append((begin-due)/1e6)
            x = {'id': id, 'pair': None if id == BULK_ID else id//2, 'outer': outer, 'role': role,
                 'due_to_wake_ms': jitter, 'wake_to_write_begin_ms': (begin-wake)/1e6,
                 'request_write_ms': (end-begin)/1e6, 'write_begin_to_origin_parsed_ms': (parsed-begin)/1e6,
                 'parsed_to_ready_ms': (ready-parsed)/1e6, 'origin_write_ms': (oe-ob)/1e6,
                 'ready_to_first_byte_ms': (first-ready)/1e6, 'ready_to_verified_ms': (verified-ready)/1e6,
                 'due_to_verified_ms': (verified-due)/1e6, 'first_byte_to_verified_ms': (verified-first)/1e6,
                 'origin_trace_omitted': o.get('omitted_write_calls'), 'partial_bytes': r.get('bytes')}
            per[id] = x; output['per_request'].append(x)
        for role, v in role_jitter.items():
            if len(v) != 16 or percentile(v, .95) > 20 or max(v) > 100:
                failures.append('scheduler_'+role)
        for role, v in begin_jitter.items():
            expected_count = 1 if role == 'bulk' else 16
            if len(v) != expected_count or percentile(v, .95) > 20 or max(v) > 100:
                failures.append('request_start_scheduler_'+role)
        for pair in range(16):
            loaded = per[2*pair+bulk_outer]
            other = per[2*pair+1-bulk_outer]
            output['all_fixed_pairs'].append({'pair': pair,
                'loaded_minus_independent_due_ms': loaded['due_to_verified_ms']-other['due_to_verified_ms'],
                'loaded_minus_independent_after_ready_ms': loaded['ready_to_verified_ms']-other['ready_to_verified_ms']})
        values = [x['loaded_minus_independent_due_ms'] for x in output['all_fixed_pairs']]
        output['pair_summary'] = {'median_extra_ms': percentile(values, .5), 'p95_extra_ms': percentile(values, .95),
                                  'positive_count': sum(x > 0 for x in values), 'count': 16}
        after_ready = [x['loaded_minus_independent_after_ready_ms'] for x in output['all_fixed_pairs']]
        output['pair_summary']['after_ready'] = {'median_extra_ms': percentile(after_ready, .5),
            'p95_extra_ms': percentile(after_ready, .95), 'positive_count': sum(x > 0 for x in after_ready), 'count': 16}
        output['primary_pair_metric'] = 'loaded_minus_independent_after_ready_ms'
        output['request_start_delay_ms_by_role'] = begin_jitter
        output['bulk_MB_per_s'] = BULK_BYTES/1e6/((point(cr[BULK_ID]['reader']['verified'])-point(cr[BULK_ID]['writer']['begin']))/1e9)
        if not failures: output['status'] = 'QUALIFIED_PROTOCOL_LATENCY_ONLY'
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
        failures.append(str(exc) if isinstance(exc, ValueError) else 'incomplete_or_invalid_record')
    return output
