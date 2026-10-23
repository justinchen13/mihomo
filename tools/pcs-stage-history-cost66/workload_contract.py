"""Pure R03 workload/profile identity checks; no processes, network or numeric-gate changes."""
import math
import re

SCHEMA = 'history-whole-proxy-cost66-v1'
ACTIVE_SECONDS = 66
CLIENT_DEADLINE_SECONDS = ACTIVE_SECONDS + 27
RUNNER_DEADLINE_SECONDS = CLIENT_DEADLINE_SECONDS + 5
_WORKLOAD = {'seconds': ACTIVE_SECONDS, 'bulk_bytes': 128*1024*1024,
             'upload_bytes': 16*1024*1024, 'small_count': 528, 'small_bytes': 4096}


def workload():
    return dict(_WORKLOAD)


def exact_workload(value):
    return (isinstance(value, dict) and set(value) == set(_WORKLOAD)
            and all(type(value[k]) is int and value[k] == v for k, v in _WORKLOAD.items()))


def validate_selection(manifest):
    assert manifest['schema'] == SCHEMA, 'cost66_schema_mismatch'
    n = manifest['selected_profile']
    assert type(n) is int and n in (1, 32, 66), 'selected_profile_mismatch'
    assert manifest['execution_mode'] in ('security', 'matrix'), 'execution_mode_mismatch'
    assert manifest['execution_mode'] != 'security' or n == 1, 'security_requires_profile1'
    assert exact_workload(manifest['workload']), 'workload_mismatch'


def validate_result_binding(row, runtime, selected_profile):
    assert type(selected_profile) is int and selected_profile in (1, 32, 66), 'selected_profile_mismatch'
    for value in (row, runtime):
        assert type(value.get('selected_profile')) is int and value['selected_profile'] == selected_profile, 'result_selected_profile_mismatch'
        assert type(value.get('outer_sessions')) is int and value['outer_sessions'] == selected_profile, 'result_outer_profile_mismatch'
        assert exact_workload(value.get('workload_contract')), 'result_workload_mismatch'
    validate_client(row['client'], selected_profile, require_samples=False)


def validate_client(client, selected_profile, require_samples=True):
    """Require a real cost66 payload result; raw samples are checked once and retained unchanged."""
    assert type(selected_profile) is int and selected_profile in (1, 32, 66), 'selected_profile_mismatch'
    assert client.get('workload_contract') == 'cost66-payload-v1', 'client_workload_identity_mismatch'
    expected = _WORKLOAD['bulk_bytes'] + _WORKLOAD['small_count']*_WORKLOAD['small_bytes'] + selected_profile*32
    numeric = {'active_seconds': ACTIVE_SECONDS, 'outer_sessions': selected_profile,
               'live_sessions_at_finish': selected_profile, 'streams': 3*selected_profile,
               'tls_verified': selected_profile, 'padding_verified': selected_profile,
               'outer_source_bind_verified': selected_profile, 'received_body_bytes': expected,
               'expected_received_body_bytes': expected, 'upload_verified_bytes': _WORKLOAD['upload_bytes'],
               'bulk_body_bytes': _WORKLOAD['bulk_bytes'], 'small_count': _WORKLOAD['small_count']}
    assert all(type(client.get(k)) is int and client[k] == v for k, v in numeric.items()), 'client_payload_or_profile_mismatch'
    assert client.get('ok') is True and client.get('small_all_verified') is True and client.get('errors') == [], 'client_integrity_mismatch'
    if not require_samples:
        return
    samples = client.get('small')
    assert isinstance(samples, list) and len(samples) == _WORKLOAD['small_count'], 'raw_small_count_mismatch'
    values = []
    for index, sample in enumerate(samples):
        assert type(sample.get('index')) is int and sample['index'] == index, 'small_index_mismatch'
        assert type(sample.get('outer_ordinal')) is int and sample['outer_ordinal'] == index % selected_profile, 'small_outer_mismatch'
        assert type(sample.get('received_body_bytes')) is int and sample['received_body_bytes'] == _WORKLOAD['small_bytes'], 'small_body_mismatch'
        assert sample.get('ok') is True and sample.get('error_class', '') == '', 'small_integrity_mismatch'
        assert isinstance(sample.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', sample['sha256']), 'small_sha_missing'
        latency = sample.get('scheduled_to_verified_ms')
        assert type(latency) in (int, float) and math.isfinite(latency) and latency >= 0, 'small_latency_unknown'
        values.append(latency)
    p95 = sorted(values)[(_WORKLOAD['small_count']*95 + 99)//100 - 1]
    supplied = client.get('small_p95_scheduled_to_verified_ms')
    assert type(supplied) in (int, float) and math.isfinite(supplied) and math.isclose(supplied, p95, rel_tol=1e-12, abs_tol=1e-9), 'small_p95_mismatch'
