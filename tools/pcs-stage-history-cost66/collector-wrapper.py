#!/usr/bin/env python3
"""Private test-only timing around unchanged real collector calls in both arms.

S1 adds fixed publication-size/schema counters at existing calls only.
Never import this wrapper into production. The ordinary monitor/stage functions
are invoked unchanged. This wrapper's bounded output adds common measurement
work; child-cgroup CPU includes it. It does not enforce a filesystem deadline.
"""
import argparse
import datetime
import importlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time
from history_contract import row_metadata


def stamp():
    return {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'monotonic': time.monotonic()}


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


class Trace:
    LIMIT = 1024 * 1024
    RECORD_LIMIT = 4096

    def __init__(self, path):
        p = Path(path)
        info = p.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise OSError('unsafe timing directory')
        self.fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.bytes = 0
        self.failed = False
        self.failure_reason = None
        self.sequence = 0
        self.calls = {'normal_write': 0, 'burst_write': 0, 'rollup': 0, 'stage_collect': 0}
        self.completed_cycles = 0
        self.last_ack = None
        self.last_rollup_error = None
        self.stage_tick = 0
        self.requests = None
        self.deliveries = None
        self.acknowledgements = None
        self.consumed_values = {}
        self.current_request = None
        self.trace_errors = []

    def emit(self, event, **fields):
        if self.failed:
            return
        self.sequence += 1
        record = {'schema': 1, 'event': event, 'sequence': self.sequence, **stamp(), **fields}
        try:
            raw = (json.dumps(record, separators=(',', ':'), allow_nan=False) + '\n').encode()
            if len(raw) > self.RECORD_LIMIT or self.bytes + len(raw) > self.LIMIT:
                self.failed, self.failure_reason = True, 'timing_budget_exceeded'
                return
            offset = 0
            while offset < len(raw):
                count = os.write(self.fd, raw[offset:])
                if count <= 0:
                    raise OSError('timing short write')
                offset += count
                self.bytes += count
        except (OSError, ValueError):
            self.failed, self.failure_reason = True, 'timing_output_failed'

    def close(self):
        try:
            os.fsync(self.fd)
        except OSError:
            self.failed, self.failure_reason = True, 'timing_fsync_failed'
        finally:
            os.close(self.fd)


def safe_ack(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        return {'availability': 'unknown_ack'}
    allowed = {
        'availability': {'ready', 'missing_scope', 'transport_error', 'body_too_large', 'http_status',
                         'invalid_payload', 'inactive', 'awaiting_sample', 'stale', 'sequence_regression',
                         'deadline_exceeded', 'invalid_http', 'header_too_large', 'schedule_skipped'},
        'output_status': {'written', 'failed'},
        'rotation': {'unchanged', 'rotated', 'unknown'},
        'checkpoint_status': {'saved', 'failed', 'not_advanced', 'no_ready_publication', 'no_pending_record'},
    }
    out = {}
    for name, choices in allowed.items():
        out[name] = value[name] if isinstance(value.get(name), str) and value[name] in choices else None
    for name in ('collection_ms', 'output_failures_total', 'cursor_failures_total', 'records_written', 'network_requests', 'history_known_latest_sequence'):
        out[name] = value[name] if number(value.get(name)) and value[name] >= 0 else None
    out['history_backlog_remaining'] = value.get('history_backlog_remaining') if type(value.get('history_backlog_remaining')) is bool else None
    out['publication_contiguous'] = value.get('publication_contiguous') if type(value.get('publication_contiguous')) is bool else None
    out['fault_count_increment'] = 0 if value.get('fault_count_increment') == 0 else None
    out['classification'] = 'diagnostic:anytls_stage' if value.get('classification') == 'diagnostic:anytls_stage' else None
    out['filesystem_deadline_guaranteed'] = False if value.get('filesystem_deadline_guaranteed') is False else None
    return out


def execute(monitor, stage, trace, monitor_args):
    """Wrap only frozen call boundaries. No I/O mocks or protocol substitution."""
    old_argv = sys.argv
    original_write, original_rollup = monitor.write_row, monitor.Rollup.record
    original_stage = stage.collect_regular_stage
    original_request = stage.UnixHTTPReader.request
    original_sanitize = stage.sanitize_batch
    original_consume = stage.StageConsumer.consume
    original_append = stage.StageLog.append
    original_after_write = stage.StageReader.after_write
    enabled = '--stage-evidence' in monitor_args
    cycle = 0
    current_start = None
    last_operation_end = None
    active = None
    exit_code = 0

    def start_from_frame(frame):
        # Read only the fixed monotonic local from the actual frozen main loop.
        # No other local, argv, address, scope or credentials are exported.
        if frame.f_code is monitor.main.__code__:
            value = frame.f_locals.get('start')
            if number(value):
                return value
        return None

    def operation(kind, callback, args, kwargs, tick=None):
        nonlocal active, last_operation_end
        trace.calls[kind] += 1
        if kind == 'stage_collect':
            trace.stage_tick += 1
            trace.requests, trace.deliveries, trace.acknowledgements = [], [], []
            trace.consumed_values, trace.current_request, trace.trace_errors = {}, None, []
        began = stamp()
        active = {'operation': kind, 'cycle': cycle, 'started': began}
        trace.emit('enter', operation=kind, cycle=cycle, started=began,
                   regular_start_monotonic=tick)
        failed = True
        result = None
        try:
            result = callback(*args, **kwargs)
            failed = False
            return result
        finally:
            ended = stamp()
            extra = {}
            if kind == 'stage_collect':
                # Separate <=4096B records retain both payloads; nothing overwrites
                # an earlier crop/error or an uncommitted restart probe.
                for event, records in (('stage_request', trace.requests), ('stage_append', trace.deliveries), ('stage_ack', trace.acknowledgements)):
                    for record in records:
                        trace.emit(event, stage_tick=trace.stage_tick, cycle=cycle,
                                   regular_start_monotonic=tick, details=record)
                extra = {'ack': safe_ack(result), 'stage_tick': trace.stage_tick,
                         'network_requests_observed': len(trace.requests),
                         'append_attempts_observed': len(trace.deliveries),
                         'ack_attempts_observed': len(trace.acknowledgements),
                         'trace_errors': list(trace.trace_errors)}
            if kind == 'stage_collect':
                trace.last_ack = safe_ack(result)
            if kind == 'rollup':
                value = getattr(args[0], 'error', None)
                trace.last_rollup_error = value if type(value) is bool else None
                extra['rollup_error'] = trace.last_rollup_error
            trace.emit('exit', operation=kind, cycle=cycle, started=began, ended=ended,
                       duration_seconds=ended['monotonic']-began['monotonic'], failed=failed,
                       regular_start_monotonic=tick, **extra)
            last_operation_end = ended
            active = None

    def complete(tick):
        trace.completed_cycles += 1
        end = last_operation_end or stamp()
        elapsed = end['monotonic'] - tick if number(tick) else None
        trace.emit('cycle_complete', cycle=cycle, regular_start_monotonic=tick, ended=end,
                   full_cycle_seconds=elapsed, timing_known=elapsed is not None and elapsed >= 0,
                   stage_enabled=enabled, last_ack=trace.last_ack,
                   last_rollup_error=trace.last_rollup_error)

    def write(*args, **kwargs):
        nonlocal cycle, current_start
        filename = kwargs.get('filename', args[2] if len(args) > 2 else 'samples.jsonl')
        kind = 'normal_write' if filename == 'samples.jsonl' else 'burst_write'
        if kind == 'normal_write':
            cycle += 1
            current_start = start_from_frame(sys._getframe(1))
        return operation(kind, original_write, args, kwargs, current_start)

    def rollup(self, *args, **kwargs):
        result = operation('rollup', original_rollup, (self, *args), kwargs, current_start)
        if not enabled:
            complete(current_start)
        return result

    def collect(*args, **kwargs):
        tick = kwargs.get('regular_tick')
        tick = tick if number(tick) else None
        result = operation('stage_collect', original_stage, args, kwargs, tick)
        complete(tick)
        return result

    def error(reason):
        if reason not in trace.trace_errors and len(trace.trace_errors)<8:
            trace.trace_errors.append(reason)

    def request(self, *args, **kwargs):
        request_bytes=kwargs.get('request',args[1] if len(args)>1 else None)
        kind=('history' if isinstance(request_bytes,bytes) and request_bytes.startswith(b'GET /diagnostics/anytls-stage/history?')
              else 'latest' if request_bytes is None or isinstance(request_bytes,bytes) and request_bytes.startswith(b'GET /diagnostics/anytls-stage HTTP/') else 'unknown')
        record={'request_index':len(trace.requests)+1,'request_kind':kind,'request_failed':True,
                'http_status':None,'raw_body_bytes':None,'sequence':None}
        trace.current_request=record
        if len(trace.requests)>=2:error('request_bound_exceeded')
        else:trace.requests.append(record)
        try:
            status,body=original_request(self,*args,**kwargs)
            record.update(request_failed=False,http_status=status,
                          raw_body_bytes=len(body) if isinstance(body,bytes) else None)
            return status,body
        except BaseException:
            record['request_failed']=True
            raise

    def sanitize(batch, *args, **kwargs):
        out=original_sanitize(batch,*args,**kwargs)
        record=trace.current_request
        if record is None:error('sanitize_without_request')
        else:
            record.update(inner_schema=batch.get('schema'),sequence=batch.get('sequence'),
                payload_limited=out.get('payload_limited'),omitted_sessions=out.get('omitted_sessions'),
                omitted_slow_events=out.get('omitted_slow_events'),
                omitted_slow_events_by_class=out.get('omitted_slow_events_by_class'),
                slow_queue_counters=out.get('slow_queue_counters'))
        return out

    def consume(self, *args, **kwargs):
        out=original_consume(self,*args,**kwargs)
        record=trace.current_request
        if record is None:error('consume_without_request')
        else:
            record.update(availability=out.get('availability'),
                sequence=out.get('sequence'),capture_age_ms=out.get('age_ms'),
                consumer_payload_limited=out.get('consumer_payload_limited',False),
                consumer_published=isinstance(out.get('observations'),dict),duplicate=out.get('duplicate'))
            if len(trace.consumed_values)<2:trace.consumed_values[id(out)]=record['request_index']
            else:error('consumption_bound_exceeded')
        return out

    def append(self,row):
        record={'delivery_index':len(trace.deliveries)+1,
                'request_index':trace.consumed_values.get(id(row.get('stage'))),
                **row_metadata(row),'append_succeeded':False,'rotation':None}
        if len(trace.deliveries)>=2:error('append_bound_exceeded')
        else:trace.deliveries.append(record)
        try:
            rotation=original_append(self,row)
            record.update(row_metadata(row),append_succeeded=True,rotation=rotation)
            return rotation
        finally:
            # Capture failure and post-append metadata even if the real caller
            # catches an output error and later returns an otherwise ready row.
            record.update(row_metadata(row))

    def after_write(self,written,*,rotation='unknown'):
        pending=getattr(self,'pending',None)
        previous=getattr(pending,'previous',None)
        sequence=previous[1] if isinstance(previous,tuple) and len(previous)>=2 else None
        delivery=trace.deliveries[-1] if trace.deliveries else {}
        record={'delivery_index':delivery.get('delivery_index'),'request_index':delivery.get('request_index'),
                'sequence':sequence,'written':written,'rotation':rotation,'ack_failed':True,
                'checkpoint_status':None}
        if len(trace.acknowledgements)>=2:error('ack_bound_exceeded')
        else:trace.acknowledgements.append(record)
        try:
            outcome=original_after_write(self,written,rotation=rotation)
            record.update(ack_failed=False,checkpoint_status=outcome.get('checkpoint_status'))
            return outcome
        finally:
            if sequence!=delivery.get('sequence'):error('pending_delivery_sequence_mismatch')

    stage.UnixHTTPReader.request, stage.sanitize_batch, stage.StageConsumer.consume = request, sanitize, consume
    stage.StageLog.append, stage.StageReader.after_write = append, after_write
    monitor.write_row, monitor.Rollup.record, stage.collect_regular_stage = write, rollup, collect
    sys.argv = ['monitor.py', *monitor_args]
    trace.emit('wrapper_start', stage_enabled=enabled, collector_functions_unchanged=True,
               measurement_overhead_in_child_cgroup=True, filesystem_deadline_guaranteed=False)
    try:
        monitor.main()
    except SystemExit as error:
        exit_code = error.code if isinstance(error.code, int) else 1
    except BaseException:
        exit_code = 1
        # Real failures are marked without dumping arbitrary exception strings.
        print('PCS_COLLECTOR_WRAPPER_MAIN_FAILED', file=sys.stderr)
    finally:
        monitor.write_row, monitor.Rollup.record, stage.collect_regular_stage = original_write, original_rollup, original_stage
        stage.UnixHTTPReader.request, stage.sanitize_batch, stage.StageConsumer.consume = original_request, original_sanitize, original_consume
        stage.StageLog.append, stage.StageReader.after_write = original_append, original_after_write
        sys.argv = old_argv
        trace.emit('wrapper_end', collector_exit_code=exit_code, stage_enabled=enabled,
                   completed_cycles=trace.completed_cycles, calls=trace.calls,
                   last_ack=trace.last_ack, active_call=active,
                   last_rollup_error=trace.last_rollup_error,
                   timing_output_failed=trace.failed)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector-dir', required=True)
    parser.add_argument('--timing-output', required=True)
    parser.add_argument('monitor_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = args.monitor_args[1:] if args.monitor_args[:1] == ['--'] else args.monitor_args
    if any(x.startswith('--stage') and x != '--stage-evidence' for x in forwarded):
        parser.error('stage option must use its complete frozen spelling')
    os.umask(0o077)
    sys.path.insert(0, str(Path(args.collector_dir).resolve()))
    try:
        monitor = importlib.import_module('monitor')
        stage = importlib.import_module('stage')
        trace = Trace(args.timing_output)
    except Exception:
        print('PCS_COLLECTOR_WRAPPER_SETUP_FAILED', file=sys.stderr)
        return 1
    try:
        code = execute(monitor, stage, trace, forwarded)
    finally:
        trace.close()
    if trace.failed:
        print('PCS_COLLECTOR_WRAPPER_TRACE_FAILED', file=sys.stderr)
        return 1
    return code


if __name__ == '__main__':
    sys.exit(main())
