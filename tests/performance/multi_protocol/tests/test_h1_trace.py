"""Consumer regressions; the workflow separately exercises the real C producers."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from h1_trace_contract import (COUNTERS, LOSSES, decode_cpu, fd_lifetimes,
                               load_trace, syscall_coverage, validate_record)
from h1_trace_preflight import reconcile
from h1_internal_profile import validate_selection


def counter(**changes):
    row = {k: 0 for k in COUNTERS}
    row.update(id=1, attempts=2, exits=2, positive=1, errors=1,
               accepted_known=2, accepted_bytes=5, min_return=-11, max_return=5,
               offered_known=2, offered=24)
    row.update(changes)
    return row


def producer_records():
    return [dict(phase='ready', status='supported'),
            dict(phase='bound', pid=7, start_ticks=9),
            dict(phase='final', before_ns=100, after_ns=110, pending=0, map_read_failures=0,
                 losses=[0] * len(LOSSES), totals=[counter()], census={'1': 2},
                 rows=[counter(attempts=0, pid=7, process_ns=90_000_000, cgroup=42,
                               cookie=55, netns=1, role=1, outcome=1, direction=1)]),
            dict(phase='termination', requested_stop=True, lifecycle_omitted=0,
                 checkpoints_omitted=0, snapshot_failures=0)]


class H1TraceTests(unittest.TestCase):
    def assess(self, rows):
        return syscall_coverage(rows, dict(pid=7, start_ticks=9, cgroup_id=42),
                                dict(measurement={'valid': True}))

    def test_byte_returns_and_errors_stay_distinct(self):
        result = self.assess(producer_records())
        self.assertTrue(result['complete'])
        row = result['syscall_totals'][0]
        self.assertEqual((row['attempts'], row['positive'], row['errors'], row['accepted_bytes']), (2, 1, 1, 5))
        self.assertFalse(result['accepted_is_peer_delivery'])
        self.assertFalse(result['exact_lifetimes_complete'])

    def test_missing_loss_schema_and_signed_return_do_not_zero_fill(self):
        for field in ('losses', 'pending', 'map_read_failures'):
            rows = producer_records()
            del rows[2][field]
            self.assertFalse(self.assess(rows).get('complete'))
        rows = producer_records()
        rows[2]['totals'][0]['min_return'] = 2**64 - 11
        self.assertFalse(self.assess(rows).get('complete'))

    def test_abandoned_attempts_and_reset_remain_incomplete(self):
        rows = producer_records()
        rows[2]['totals'][0]['attempts'] = 3
        self.assertFalse(self.assess(rows)['complete'])
        rows = producer_records()
        earlier = copy.deepcopy(rows[2]); earlier['phase'] = 'snapshot'
        earlier['totals'][0]['accepted_bytes'] = 50
        rows.insert(2, earlier)
        self.assertTrue(self.assess(rows)['reset'])

    def test_witness_cap_not_conflated_with_aggregate_loss(self):
        rows = producer_records()
        rows[2]['losses'][LOSSES.index('witness_cap')] = 100
        result = self.assess(rows)
        self.assertTrue(result['complete'])
        self.assertFalse(result['witness_complete'])
        rows[2]['losses'][LOSSES.index('map_full')] = 1
        self.assertFalse(self.assess(rows)['complete'])

    def test_zero_cookie_and_foreign_generation_never_get_roles(self):
        rows = producer_records()
        rows[2]['rows'][0]['cookie'] = 0
        with self.assertRaises(ValueError):
            validate_record(rows[2])
        rows = producer_records()
        rows[2]['rows'][0]['process_ns'] += 10_000_000
        self.assertFalse(self.assess(rows)['complete'])

    def test_unavailable_does_not_certify_measurement(self):
        self.assertFalse(self.assess([dict(phase='ready', status='unsupported')])['complete'])
        rows = producer_records()
        rows[-1]['requested_stop'] = False
        self.assertFalse(self.assess(rows)['complete'])
        rows[2]['census']['425'] = 1
        self.assertFalse(self.assess(rows)['socket_roles_complete'])

    def test_reconcile_actual_fixture_contract_mmsg_returns_messages(self):
        call = dict(phase='call', label='batch', pid=1, tid=2, id=307, fd=8,
                    result=2, errno=0, offered=24)
        event = dict(call, phase='h1_event', kind=1, known=1, accepted_known=1, accepted=24)
        self.assertEqual(reconcile([call], [event])['errors'], [])
        event['accepted'] = 2
        self.assertIn('batch returned-prefix length mismatch', reconcile([call], [event])['errors'])
        call.update(result=-1, errno=14)
        event.update(result=-14, accepted=0, inner_bytes=12)
        self.assertEqual(reconcile([call], [event])['errors'], [])

    def test_fd_reuse_retains_intervals_without_guessing_cookie(self):
        base = dict(phase='h1_event', kind=2, pid=1, process_ns=20, tid=1,
                    entered_ns=10, exited_ns=11, arg1=0, arg2=0)
        events = [dict(base, id=41, fd=2, result=9), dict(base, id=3, fd=9, result=0),
                  dict(base, id=33, fd=8, result=9)]
        result = fd_lifetimes(events)
        self.assertEqual(result['intervals'][2]['alias_of'], 8)
        self.assertTrue(all(r['cookie'] is None for r in result['intervals']))
        self.assertFalse(result['exact_alias_join'])

    def test_cpu_names_without_actual_stack_samples_are_not_stacks(self):
        counts = decode_cpu('cpu-clock count 99999 fixture_outer fixture_leaf', '', {7})
        self.assertFalse(counts['stack_useful'])
        text = '''fixture 7/8 12.000000000: cpu-clock:u:
        1234 fixture_leaf (/fixture)
        2345 fixture_middle (/fixture)
        3456 fixture_outer (/fixture)

fixture 99/99 12.100000000: cpu-clock:u:
        7777 unrelated (/control)

'''
        result = decode_cpu(text, 'PERF_RECORD_SAMPLE\nPERF_RECORD_SAMPLE\nPERF_RECORD_LOST\nPERF_RECORD_THROTTLE', {7})
        self.assertEqual(result['samples'], 1)
        self.assertEqual(result['foreign_samples'], 1)
        self.assertEqual(result['multi_frame_samples'], 1)
        self.assertEqual(result['lost_records'], 1)
        self.assertFalse(result['complete'])

    def test_external_calibration_is_separate_and_exact(self):
        validate_selection('trace-calibration', 'http1-tls', '4', '15', '200', 'ferrum', '5242880', 'same-image', '')
        with self.assertRaises(ValueError):
            validate_selection('trace-calibration', 'http1-tls', '4', '15', '100', 'ferrum', '5242880', 'same-image', '')
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(load_trace(Path(folder) / 'missing.json')['complete'])


if __name__ == '__main__':
    unittest.main()
