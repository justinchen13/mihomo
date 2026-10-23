"""Pure mocks; do not read real procfs or wait real time."""
import unittest
from pathlib import Path
from unittest.mock import patch
import quiet


class Clock:
    def __init__(self): self.now = 100.; self.sleeps = []
    def monotonic(self): return self.now
    def sleep(self, value): self.sleeps.append(value); self.now += value


class Process:
    def __init__(self, code=None): self.code = code
    def poll(self): return self.code


class Controller:
    def utc(self): return 'synthetic'


def snap(ticks=5, cpu=100, complete=True):
    return {'task_capture_complete': complete,
            'tasks': [{'pid': 123, 'start_ticks': ticks, 'CPU_ns': cpu}],
            'total_task_CPU_ns': cpu if complete else None, 'cpu_stat': {'usage_usec': cpu}}


class QuietTests(unittest.TestCase):
    def call(self, samples, processes):
        c = Clock()
        with patch.object(quiet, 'quiet_cpu_snapshot', side_effect=samples), patch.object(quiet, 'save'), \
             patch.object(quiet.time, 'monotonic', c.monotonic), patch.object(quiet.time, 'sleep', c.sleep):
            result = quiet.fixed_quiet_before_go(Path('/synthetic'), processes, Controller())
        return c, result

    def test_fixed_wait_no_adaptive_repeat(self):
        c, r = self.call([snap(), snap(cpu=200)], [Process()])
        self.assertEqual(len(c.sleeps), 1)
        self.assertAlmostEqual(sum(c.sleeps), 1.2)
        self.assertTrue(r['task_CPU_comparable'])
        self.assertAlmostEqual(r['total_task_CPU_delta_seconds'], 1e-7)

    def test_exit_stops(self):
        with self.assertRaisesRegex(RuntimeError, 'owned_process_during_fixed_quiet_exit'):
            self.call([snap()], [Process(1)])

    def test_identity_change_or_missing_is_unknown(self):
        for after in (snap(ticks=6), snap(complete=False), snap(cpu=90)):
            _, r = self.call([snap(), after], [Process()])
            self.assertFalse(r['task_CPU_comparable'])
            self.assertIsNone(r['total_task_CPU_delta_seconds'])


if __name__ == '__main__': unittest.main()
