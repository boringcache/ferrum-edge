"""Consumer regressions; the workflow separately exercises the real C producers."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from h1_trace_contract import (COUNTERS, LOSSES, decode_cpu, fd_lifetimes,
                               load_trace, syscall_coverage, validate_record, nested_fixture_proof)
from h1_trace_preflight import reconcile
from h1_internal_profile import validate_selection
import h1_trace as trace


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

    def test_fixture_nested_proof_rejects_three_flat_samples_and_wrong_order(self):
        def decoded(groups):
            text = ''.join(f'fixture 7/{8 + i} 12.000000000: cpu-clock:u:\n' +
                           ''.join(f'        1234 {name} (/fixture)\n' for name in names) + '\n'
                           for i, names in enumerate(groups))
            return decode_cpu(text, '', {7})
        expected = ['fixture_leaf', 'fixture_middle', 'fixture_outer']
        flats = decoded([[name] for name in expected])
        self.assertFalse(nested_fixture_proof(flats['callchains'])['proven'])
        wrong = decoded([list(reversed(expected))])
        self.assertFalse(nested_fixture_proof(wrong['callchains'])['proven'])
        names = ['fixture_leaf.constprop.0+0x12', '[unknown]', 'inline_helper',
                 'fixture_middle.isra.1', 'fixture_outer']
        nested = decoded([names])
        proof = nested_fixture_proof(nested['callchains'])
        self.assertTrue(proof['proven'])
        self.assertEqual(proof['witnesses'][0]['matched_frame_indices'], [0, 3, 4])
        self.assertEqual(proof['witnesses'][0]['pid'], 7)
        self.assertEqual(proof['witnesses'][0]['tid'], 8)
        self.assertEqual(proof['witnesses'][0]['frames'], nested['callchains'][0]['frames'])
        self.assertEqual(nested['unresolved_samples'], 1)
        self.assertFalse(proof['complete_unwinding'])
        self.assertFalse(nested_fixture_proof(decoded([['fixture_leaf_fake'] + expected[1:]])['callchains'])['proven'])
        foreign = decode_cpu('fixture 99/99 12.0: cpu-clock:u:\n' +
                            ''.join(f'        1234 {name} (/fixture)\n' for name in expected), '', {7})
        self.assertFalse(nested_fixture_proof(foreign['callchains'])['proven'])
        self.assertEqual(foreign['foreign_samples'], 1)

    def test_external_calibration_is_separate_and_exact(self):
        validate_selection('trace-calibration', 'http1-tls', '4', '15', '200', 'ferrum', '5242880', 'same-image', '')
        with self.assertRaises(ValueError):
            validate_selection('trace-calibration', 'http1-tls', '4', '15', '100', 'ferrum', '5242880', 'same-image', '')
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(load_trace(Path(folder) / 'missing.json')['complete'])


class H1TeardownTests(unittest.TestCase):
    """Use the real runner request and supervisor consumer with mocked processes."""
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.out = Path(self.folder.name)
        self.owner = dict(pid=7, start_ticks=9, cgroup_id=42, executable_sha256='elf',
                          boot_id='boot', namespaces={'time': 1, 'net': 2})
        self.binding = dict(sample=str(self.out / 'sample.json'), raw_sample=str(self.out / 'raw.json'),
                            client_exit=str(self.out / 'exit'), arm='ferrum', pair=1, payload=10240)
        phases = dict(timed_out=False, stalled_workers=[], transport_close_timed_out=False,
                      drain_secs=0.2, drain_start_monotonic_secs=30.0,
                      measurement_secs=1, measurement_elapsed_secs=1.001,
                      measurement_start_unix_secs=102,
                      measurement_start_host_clock=dict(clock='CLOCK_MONOTONIC', before_ns=2_000_000_000,
                                                        after_ns=2_000_000_001))
        self.raw = dict(phases=phases, protocol='HTTP/1.1+TLS', rps=123)
        self.sample = dict(self.raw, gateway='ferrum', pair=1, payload_size=10240)
        self.retain_client()
        trace.write(self.out / 'bind.json', self.binding)
        self.ready = dict(session='this-capture', binding_sha256=trace.digest(self.out / 'bind.json'),
                          at=self.at(1_000_000_000), owner=self.owner, deadline_monotonic=30)
        trace.write(self.out / 'ready.json', self.ready)
        self.cpu = Mock(ready={'status': 'supported'})
        self.cpu.process.pid = 101
        self.cpu.process.poll.return_value = None
        self.observer = Mock(ready={'status': 'supported'})
        self.observer.process.pid = 102
        self.observer.process.poll.return_value = None
        self.lifecycle = trace.CaptureLifecycle(self.out, self.owner, self.binding, self.ready,
                                                dict(cpu=self.cpu, observer=self.observer))
        self.now = 5_000_000_000
        self.clock = self.patch('clock', side_effect=self.tick)
        self.alive = self.patch('target_alive', return_value=True)
        self.identity = self.patch('identity', return_value=self.owner)
        self.monotonic = self.patch('time.monotonic', return_value=5)

    def patch(self, name, **kwargs):
        context = patch('h1_trace.' + name, **kwargs)
        value = context.start()
        self.addCleanup(context.stop)
        return value

    @staticmethod
    def at(ns):
        return dict(before_ns=ns, after_ns=ns + 1, unix_ns=100_000_000_000 + ns)

    def tick(self):
        self.now += 100
        return self.at(self.now)

    def retain_client(self):
        trace.write(self.out / 'raw.json', self.raw)
        trace.write(self.out / 'sample.json', self.sample)
        (self.out / 'exit').write_text('0\n')

    def request(self):
        request = dict(session=self.ready['session'], binding_sha256=self.ready['binding_sha256'],
                       owner=self.owner, evidence=trace.completion_evidence(self.binding), at=self.tick())
        trace.write(self.out / 'teardown-request.json', request)
        return request

    def test_real_runner_handshake_then_autoexit_before_stop(self):
        events = []
        def supervisor_tick(_):
            events.append('retained_client_request')
            self.lifecycle.authorize_teardown()
            events.append('live_supervisor_ack')
        self.patch('time.sleep', side_effect=supervisor_tick)
        # Read the receipt on the next loop; a broken ack reaches the deadline.
        self.monotonic.side_effect = [5, 5, 5, 30]
        trace.request_teardown(self.out)
        self.assertTrue((self.out / 'teardown-ready.json').exists())
        # Docker removal can take arbitrarily many supervisor polls. Its stop
        # marker has not been published when perf naturally exits.
        self.alive.return_value = False
        self.cpu.process.poll.return_value = 0
        events.append('target_removed_perf_autoexit')
        for _ in range(3):
            self.lifecycle.poll()
        self.assertFalse((self.out / 'stop').exists())
        end = self.lifecycle.observations['cpu']['exit']
        self.assertTrue(end['expected_target_teardown'])
        self.assertIsNone(end['exact_exit_ns'])
        self.assertLessEqual(end['bounds_ns'][0], end['bounds_ns'][1])
        self.assertEqual(events, ['retained_client_request', 'live_supervisor_ack', 'target_removed_perf_autoexit'])
        self.assertLess(self.lifecycle.coverage_end(self.now), end['bounds_ns'][1])
        self.lifecycle.verify_stop()

    def test_stop_marker_cannot_bypass_completion_removal_or_final_read(self):
        (self.out / 'stop').touch()
        with self.assertRaisesRegex(RuntimeError, 'stop without verified'):
            self.lifecycle.verify_stop()
        self.request(); self.lifecycle.authorize_teardown()
        with self.assertRaisesRegex(RuntimeError, 'before owned gateway removal'):
            self.lifecycle.verify_stop()
        self.alive.return_value = False
        self.lifecycle.poll()
        self.lifecycle.verify_stop()
        (self.out / 'raw.json').write_text('{')
        with self.assertRaises(ValueError):
            self.lifecycle.verify_stop()

    def test_target_exit_between_alive_read_and_collector_poll(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.side_effect = [True, False]
        self.cpu.process.poll.return_value = 0
        self.assertFalse(self.lifecycle.poll())
        self.assertIsNotNone(self.lifecycle.target_gone)

    def test_resource_read_exit_race_requires_verified_teardown(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.return_value = False
        def read_usage(pid, *_):
            if pid == self.cpu.process.pid:
                self.cpu.process.poll.return_value = 0
                return None
            return {'rss_bytes': 100}
        self.patch('capture', side_effect=read_usage)
        self.assertEqual(self.lifecycle.usage(), [{'rss_bytes': 100}])
        self.assertTrue(self.lifecycle.observations['cpu']['resource_read_exit_race']['usage_unknown'])

    def test_live_resource_read_failure_remains_an_error(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.patch('capture', return_value=None)
        with self.assertRaisesRegex(RuntimeError, 'resource capture missing'):
            self.lifecycle.usage()

    def test_acknowledgement_wait_is_capped_by_capture_deadline(self):
        self.monotonic.side_effect = [29.95, 30]
        with self.assertRaisesRegex(RuntimeError, 'acknowledgement deadline'):
            trace.request_teardown(self.out)
        self.assertIsNone(self.lifecycle.teardown)

    def test_active_client_and_queued_completion_cannot_forgive_collector_loss(self):
        self.cpu.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()
        self.request()
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.authorize_teardown()
        self.assertIsNone(self.lifecycle.teardown)
        self.assertFalse((self.out / 'teardown-ready.json').exists())

    def test_early_target_death_or_generation_change_cannot_authorize(self):
        self.request()
        self.alive.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'gateway exited'):
            self.lifecycle.authorize_teardown()
        self.alive.return_value = True
        self.identity.return_value = dict(self.owner, start_ticks=10)
        with self.assertRaisesRegex(RuntimeError, 'generation changed'):
            self.lifecycle.authorize_teardown()

    def test_missing_stale_and_changed_completion_rejected(self):
        self.lifecycle.authorize_teardown()
        self.assertIsNone(self.lifecycle.teardown)
        request = self.request()
        for key, value in [('session', 'prior-capture'), ('binding_sha256', 'old'),
                           ('owner', dict(self.owner, boot_id='prior-boot')), ('at', self.at(1))]:
            with self.subTest(key=key):
                trace.write(self.out / 'teardown-request.json', dict(request, **{key: value}))
                with self.assertRaisesRegex(ValueError, 'stale/mismatched'):
                    self.lifecycle.authorize_teardown()
        trace.write(self.out / 'teardown-request.json', request)
        self.raw['rps'] = 999
        self.retain_client()
        with self.assertRaisesRegex(ValueError, 'changed after retention'):
            self.lifecycle.authorize_teardown()

    def test_old_client_measurement_cannot_authorize_fresh_capture(self):
        self.raw['phases']['measurement_start_host_clock']['before_ns'] = 1
        self.raw['phases']['measurement_start_host_clock']['after_ns'] = 2
        self.retain_client(); self.request()
        with self.assertRaisesRegex(ValueError, 'does not bracket'):
            self.lifecycle.authorize_teardown()

    def test_nonzero_client_incomplete_drain_partial_json_and_failed_read(self):
        (self.out / 'exit').write_text('124\n')
        with self.assertRaisesRegex(ValueError, 'client exit'):
            trace.completion_evidence(self.binding)
        self.retain_client()
        for field, value in [('timed_out', True), ('stalled_workers', [2]),
                              ('transport_close_timed_out', True), ('drain_secs', None)]:
            with self.subTest(field=field):
                saved = self.raw['phases'][field]
                self.raw['phases'][field] = value
                self.retain_client()
                with self.assertRaises(ValueError):
                    trace.completion_evidence(self.binding)
                self.raw['phases'][field] = saved
        (self.out / 'raw.json').write_text('{"phases":')
        with self.assertRaises(ValueError):
            trace.completion_evidence(self.binding)
        (self.out / 'raw.json').unlink()
        with self.assertRaises(OSError):
            trace.completion_evidence(self.binding)

    def test_only_zero_perf_exit_after_target_removal_is_allowed(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.cpu.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()  # acknowledged, but the target is still alive
        self.alive.return_value = False
        self.cpu.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()
        self.cpu.process.poll.return_value = None
        self.observer.process.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'collector exited'):
            self.lifecycle.poll()  # syscall observer may not autoexit

    def test_failed_target_read_is_not_target_removal(self):
        self.request(); self.lifecycle.authorize_teardown()
        self.alive.side_effect = PermissionError('proc read denied')
        with self.assertRaises(OSError):
            self.lifecycle.poll()

    def test_runner_retains_and_acknowledges_before_removing_gateway(self):
        source = (HERE / 'run_gateway_protocol_bench.sh').read_text()
        run = source.split('run_bench() {', 1)[1].split('# ── Orchestration', 1)[0]
        self.assertLess(run.index('_client.raw.json'), run.index('request-teardown'))
        self.assertLess(run.index('benchmark_plan.py" stamp'), run.index('request-teardown'))
        main = source.split('for size in $PAYLOAD_SIZES; do', 1)[1]
        self.assertLess(main.index('run_bench'), main.index('stop_gateway'))
        stop = source.split('stop_gateway() {', 1)[1].split('# ── Bench runner', 1)[0]
        self.assertLess(stop.index('docker rm -f'), stop.index('h1_trace_stop'))


if __name__ == '__main__':
    unittest.main()
