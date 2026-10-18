#!/usr/bin/env python3
"""Isolated consumer contract, not an installed collector.

Poll at the collector's existing 10-second cadence, never in TCP burst sampling.
Only one epoch/sequence is retained. Output contains scoped HMAC identities and
fixed fields, never raw cookies/tokens, endpoint text, or exception messages.
"""
import datetime
import http.client
import json
import math
import re
import socket

from anytls_stage_consumer import identity

LIMIT = 64 * 1024
STAGES = ['writer_wait', 'writer_owned', 'tls_write', 'read_header', 'read_body', 'pipe_write']
FRAMES = {'data', 'synack', 'fin', 'syn', 'settings', 'heartbeat', 'other', 'unknown'}
EPOCH = re.compile(r'^[0-9a-f]{16}$')
TOKEN = re.compile(r'^[0-9a-f]{16}-[0-9a-f]{1,16}$')
COOKIE = re.compile(r'^[0-9a-f]{1,16}$')
LOSSES = ('evicted_sessions_total', 'lost_completion_total', 'lost_batch_total',
          'lost_slow_event_total', 'lost_terminal_record_total')
COUNTS = ('live_authenticated_sessions', 'tracked_live_sessions', 'untracked_live_sessions',
          'omitted_sessions', 'omitted_slow_events') + LOSSES


def number(value, integer=False):
    if type(value) not in ((int,) if integer else (int, float)) or not math.isfinite(value) or not 0 <= value <= 2**64-1:
        raise ValueError('invalid numeric field')
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError('invalid boolean field')
    return value


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('invalid timestamp')
    dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.utcoffset() != datetime.timedelta(0):
        raise ValueError('timestamp must be UTC')
    return value


def enum(value, allowed):
    if not isinstance(value, str) or value not in allowed:
        raise ValueError('invalid enum')
    return value


def keys(value, allowed):
    if not isinstance(value, dict) or set(value) != set(allowed):
        raise ValueError('unexpected or missing fields')


def session_id(token, epoch, key, scope):
    if not isinstance(token, str) or not TOKEN.fullmatch(token) or token.split('-')[0] != epoch:
        raise ValueError('invalid scoped session token')
    return identity(key, scope + '|' + token)


def sanitize_batch(b, epoch, sequence, key, scope):
    if not isinstance(b, dict) or type(b.get('schema')) is not int or b['schema'] not in (1, 2):
        raise ValueError('unsupported batch schema')
    extra = {'slow_event_policy', 'slow_queue_counters', 'omitted_slow_events_by_class'} if b['schema'] == 2 else set()
    keys(b, {'schema', 'kind', 'evidence_epoch', 'sequence', 'capture_started', 'capture_ended', 'time',
             'export_age_ms', 'payload_limited', 'metric_stage_names', 'admission_policy', 'sessions',
             'slow_events', *COUNTS, *extra})
    if b['kind'] != 'diagnostic_not_failure' or b['evidence_epoch'] != epoch or b['sequence'] != sequence:
        raise ValueError('batch identity mismatch')
    number(b['sequence'], True)
    if b['metric_stage_names'] != STAGES or b['admission_policy'] != 'bounded_rotation_on_auth_not_population_sample':
        raise ValueError('unsupported policy')
    out = {name: number(b[name], True) for name in COUNTS}
    out.update(slow_event_policy=None, slow_queue_counters=None, omitted_slow_events_by_class=None)
    if b['schema'] == 2:
        if b['slow_event_policy'] != 'fixed_stage_budgets_v1':
            raise ValueError('unsupported slow event policy')
        classes, omitted = b['slow_queue_counters'], b['omitted_slow_events_by_class']
        if not isinstance(classes, list) or len(classes) != len(STAGES) or not isinstance(omitted, list) or len(omitted) != len(STAGES):
            raise ValueError('slow class budget')
        out['slow_event_policy'] = b['slow_event_policy']
        out['slow_queue_counters'] = []
        for item, capacity in zip(classes, (8, 4, 8, 2, 6, 4)):
            keys(item, {'capacity', 'attempted', 'admitted', 'dropped', 'dequeued'})
            clean = {name: number(value, True) for name, value in item.items()}
            if clean['capacity'] != capacity:
                raise ValueError('unexpected slow class capacity')
            # Producer counters are non-atomic snapshots, not instantaneous
            # conservation equations. Never reject a valid concurrent capture
            # merely because admitted/dequeued loads straddle an enqueue.
            out['slow_queue_counters'].append(clean)
        out['omitted_slow_events_by_class'] = [number(value, True) for value in omitted]
        if sum(out['omitted_slow_events_by_class']) != out['omitted_slow_events']:
            raise ValueError('payload omission accounting')
    if out['tracked_live_sessions'] > 32 or out['live_authenticated_sessions'] != out['tracked_live_sessions'] + out['untracked_live_sessions']:
        raise ValueError('inconsistent population counts')
    out.update({name: stamp(b[name]) for name in ('capture_started', 'capture_ended', 'time')})
    out['export_age_ms'] = number(b['export_age_ms'])
    out['payload_limited'] = boolean(b['payload_limited'])
    sessions, slow = b['sessions'], b['slow_events']
    if sessions is None:
        sessions = []
    if slow is None:
        slow = []
    if not isinstance(sessions, list) or len(sessions) > 64 or not isinstance(slow, list) or len(slow) > 32:
        raise ValueError('row budget')
    out['sessions'], out['slow_events'] = [], []
    for row in sessions:
        keys(row, {'session', 'socket_cookie', 'status', 'inflight_known', 'captured_at', 'session_age_ms',
                   'pending_writers', 'tracked_waiters', 'writer_wait_coverage_complete', 'waiter_overflow_total', 'active', 'metrics'})
        clean = {'session_id': session_id(row['session'], epoch, key, scope),
                 'socket_id': None, 'association': 'unavailable',
                 'status': enum(row['status'], {'active', 'closed', 'evicted'}),
                 'inflight_known': boolean(row['inflight_known']),
                 'captured_at': stamp(row['captured_at']),
                 'session_age_ms': number(row['session_age_ms']),
                 'writer_wait_coverage_complete': boolean(row['writer_wait_coverage_complete'])}
        for name in ('pending_writers', 'tracked_waiters', 'waiter_overflow_total'):
            clean[name] = number(row[name], True)
        cookie = row['socket_cookie']
        if isinstance(cookie, str) and COOKIE.fullmatch(cookie) and int(cookie, 16):
            clean['socket_id'] = identity(key, json.dumps([scope, 'cookie', format(int(cookie, 16), 'x')]))
            clean['association'] = 'cookie_candidate'
        active = row['active']
        if active is None:
            if clean['inflight_known']:
                raise ValueError('known inflight requires a list')
            clean['active'] = None
        else:
            if not isinstance(active, list) or len(active) > 4 or not clean['inflight_known']:
                raise ValueError('inflight budget or unknown state')
            clean['active'] = []
            for item in active:
                keys(item, {'stage', 'frame_class', 'bytes', 'age_ms'})
                clean['active'].append({'stage': enum(item['stage'], set(STAGES)),
                                        'frame_class': enum(item['frame_class'], FRAMES),
                                        'bytes': number(item['bytes'], True), 'age_ms': number(item['age_ms'])})
        if not isinstance(row['metrics'], list) or len(row['metrics']) != len(STAGES):
            raise ValueError('metric count')
        clean['metrics'] = []
        for item in row['metrics']:
            keys(item, {'count', 'total_ms', 'max_ms', 'errors', 'slow_count'})
            clean['metrics'].append({name: number(value, name in {'count', 'errors', 'slow_count'}) for name, value in item.items()})
        out['sessions'].append(clean)
    for item in slow:
        keys(item, {'started_at', 'completed_at', 'session', 'stage', 'frame_class', 'bytes', 'duration_ms', 'failed'})
        out['slow_events'].append({'session_id': session_id(item['session'], epoch, key, scope),
                                  'started_at': stamp(item['started_at']), 'completed_at': stamp(item['completed_at']),
                                  'stage': enum(item['stage'], set(STAGES)), 'frame_class': enum(item['frame_class'], FRAMES),
                                  'bytes': number(item['bytes'], True), 'duration_ms': number(item['duration_ms']),
                                  'failed': boolean(item['failed'])})
    return out


class StageConsumer:
    """One fixed cursor; a repeated pull never repeats slow events or metrics.

    Metrics remain cumulative; downstream must not sum them as interval counts.
    Missing/invalid/stale input clears continuity but retains the duplicate
    high-water cursor. No cumulative delta bridges it and no old event replays.
    """
    def __init__(self, checkpoint=None):
        self.previous = None
        self.continuity = False
        if checkpoint is not None:
            keys(checkpoint, {'epoch_id', 'sequence', 'failed_exports_total'})
            if not isinstance(checkpoint['epoch_id'], str) or not re.fullmatch('[0-9a-f]{24}', checkpoint['epoch_id']):
                raise ValueError('invalid checkpoint')
            self.previous = (checkpoint['epoch_id'], number(checkpoint['sequence'], True),
                             number(checkpoint['failed_exports_total'], True))

    def checkpoint(self):
        if self.previous is None:
            return None
        return dict(zip(('epoch_id', 'sequence', 'failed_exports_total'), self.previous))

    def unavailable(self, reason):
        enum(reason, {'transport_error', 'body_too_large', 'http_status', 'invalid_payload',
                      'missing_scope', 'inactive', 'awaiting_sample', 'stale', 'sequence_regression'})
        self.continuity = False
        return {'classification': 'diagnostic:anytls_stage', 'fault_count_increment': 0,
                'availability': reason, 'publication_contiguous': False, 'observations': None}

    def consume(self, raw, key, scope):
        if not scope or not isinstance(scope, str):
            return self.unavailable('missing_scope')
        try:
            if not isinstance(raw, bytes) or len(raw) > LIMIT:
                return self.unavailable('body_too_large')
            data = json.loads(raw)
            keys(data, {'schema', 'kind', 'availability', 'evidence_epoch', 'sequence', 'age_ms', 'failed_exports_total', 'snapshot'})
            if type(data['schema']) is not int or data['schema'] != 1 or data['kind'] != 'anytls_stage_snapshot':
                raise ValueError('unsupported envelope')
            availability = enum(data['availability'], {'inactive', 'awaiting_sample', 'ready'})
            failures = number(data['failed_exports_total'], True)
            if availability != 'ready':
                if data['snapshot'] is not None or data['sequence'] is not None or data['age_ms'] is not None:
                    raise ValueError('unavailable claims observations')
                out = self.unavailable(availability)
                out['failed_exports_total'] = failures
                return out
            epoch = data['evidence_epoch']
            if not isinstance(epoch, str) or not EPOCH.fullmatch(epoch):
                raise ValueError('invalid epoch')
            sequence = number(data['sequence'], True)
            if sequence == 0:
                raise ValueError('invalid sequence')
            age = number(data['age_ms'])
            observations = sanitize_batch(data['snapshot'], epoch, sequence, key, scope)
            if age > 25000:
                out = self.unavailable('stale')
                out.update(age_ms=age, failed_exports_total=failures)
                return out
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return self.unavailable('invalid_payload')
        epoch_id = identity(key, json.dumps([scope, 'stage-epoch', epoch]))
        previous = self.previous
        if previous and previous[0] == epoch_id and sequence < previous[1]:
            return self.unavailable('sequence_regression')
        duplicate = bool(previous and previous[:2] == (epoch_id, sequence))
        contiguous = bool(self.continuity and previous and previous[0] == epoch_id and sequence == previous[1]+1 and failures == previous[2])
        skipped = sequence - previous[1] - 1 if previous and previous[0] == epoch_id and sequence > previous[1] else None
        self.previous = (epoch_id, sequence, failures)
        if not duplicate:
            self.continuity = True
        out = {'classification': 'diagnostic:anytls_stage', 'fault_count_increment': 0,
               'availability': 'ready', 'epoch_id': epoch_id, 'sequence': sequence, 'age_ms': age,
               'failed_exports_total': failures, 'duplicate': duplicate, 'publication_contiguous': contiguous,
               'skipped_publications': skipped, 'population_sample_complete': False,
               'metrics_are_cumulative': True, 'observations': None if duplicate else observations}
        if len(json.dumps(out).encode()) > LIMIT:
            out['observations'] = None
            out['consumer_payload_limited'] = True
            out['publication_contiguous'] = False
            self.continuity = False
        return out


def poll_unix(path, key, scope, state, timeout=1.0):
    """Unix-only, byte-bounded read with a socket I/O timeout.

    This timeout is not a total request deadline. The collector integration must
    enforce its absolute scheduling budget; this fixture is not installed.
    """
    conn = http.client.HTTPConnection('localhost', timeout=timeout)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        conn.sock = sock
        conn.request('GET', '/diagnostics/anytls-stage')
        response = conn.getresponse()
        if response.status != 200:
            out = state.unavailable('http_status')
            out['http_status_code'] = response.status
            return out
        raw = response.read(LIMIT + 1)
        return state.consume(raw, key, scope)
    except (OSError, http.client.HTTPException):
        return state.unavailable('transport_error')
    finally:
        conn.close()
        sock.close()
