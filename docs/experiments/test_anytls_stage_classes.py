import copy
import json
import unittest

from anytls_stage_unix_consumer import StageConsumer
from test_anytls_stage_unix_consumer import fixture, raw, KEY, SCOPE


def classes_fixture():
    value = fixture()
    batch = value['snapshot']
    batch.update(schema=2, slow_event_policy='fixed_stage_budgets_v1',
                 slow_queue_counters=[{'capacity':c,'attempted':10,'admitted':4,'dropped':6,'dequeued':4}
                                      for c in (8,4,8,2,6,4)],
                 omitted_slow_events_by_class=[0]*6)
    return value


class ClassContract(unittest.TestCase):
    def test_old_schema_has_unknown_class_counters(self):
        result = StageConsumer().consume(raw(fixture()), KEY, SCOPE)
        self.assertEqual(result['availability'], 'ready')
        self.assertIsNone(result['observations']['slow_queue_counters'])

    def test_new_fixed_fields_survive_sanitizing(self):
        result = StageConsumer().consume(raw(classes_fixture()), KEY, SCOPE)
        self.assertEqual(result['availability'], 'ready')
        observed = result['observations']
        self.assertEqual(observed['slow_event_policy'], 'fixed_stage_budgets_v1')
        self.assertEqual(sum(x['capacity'] for x in observed['slow_queue_counters']), 32)
        self.assertEqual(observed['slow_queue_counters'][3]['capacity'], 2)
        self.assertEqual(result['fault_count_increment'], 0)

    def test_non_atomic_counter_loads_are_not_fake_conservation(self):
        value = classes_fixture()
        value['snapshot']['slow_queue_counters'][0].update(attempted=1, admitted=0, dropped=0, dequeued=1)
        self.assertEqual(StageConsumer().consume(raw(value), KEY, SCOPE)['availability'], 'ready')

    def test_bad_class_fields_are_rejected_without_echo(self):
        cases=[]
        value=classes_fixture();value['snapshot']['slow_queue_counters'][0]['dropped']=True;cases.append(value)
        value=classes_fixture();value['snapshot']['slow_queue_counters'][3]['capacity']=32;cases.append(value)
        value=classes_fixture();value['snapshot']['slow_queue_counters'][0]['target']='secret.invalid';cases.append(value)
        value=classes_fixture();value['snapshot']['omitted_slow_events_by_class'][0]=1;cases.append(value)
        value=classes_fixture();value['snapshot']['slow_queue_counters']*=2;cases.append(value)
        for value in cases:
            result=StageConsumer().consume(raw(value), KEY, SCOPE)
            self.assertEqual(result['availability'], 'invalid_payload')
            self.assertNotIn('secret.invalid', json.dumps(result))

    def test_payload_omissions_preserve_class_totals(self):
        value=classes_fixture()
        value['snapshot'].update(payload_limited=True, omitted_slow_events=2,
                                 omitted_slow_events_by_class=[1,0,0,1,0,0], slow_events=None)
        result=StageConsumer().consume(raw(value), KEY, SCOPE)
        self.assertEqual(result['availability'], 'ready')
        self.assertEqual(result['observations']['omitted_slow_events_by_class'], [1,0,0,1,0,0])


if __name__ == '__main__':
    unittest.main()
