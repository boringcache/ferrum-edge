"""Hosted regressions for clock correlation and fail-closed live admission."""
import copy
import socket
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import live
from evidence import LOSSES
from live_contract import (FAMILIES, calibration, measurement_window, measurement_position,
                           provenance_issues, observer_issues, smoke_issues,
                           sample_admission_issues, validate_observer_record, envoy_protocol_evidence)

NS = 1_000_000_000


def supported_results():
    return [dict(family=f, ready=dict(phase='ready', status='supported', family=f,
                 start_ns=1, netns=2, links=1), error=None, returncode=0, capture_complete=True,
                 final=dict(phase='final', start_ns=1, end_ns=50, rows=[], losses=[0] * len(LOSSES),
                            map_read_failures=0, pending_tx=0, pending_rx=0, pending_selector=0,
                            pending_detach=0, ring_drops=0),
                 termination=dict(phase='termination', requested_stop=True, signal=False,
                                  forced_or_parent_death=False, snapshot_failures=0,
                                  lifecycle_omitted=0, checkpoints_omitted=0)) for f in FAMILIES]


class LiveRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.phases = dict(measurement_start_monotonic_secs=3.0, measurement_secs=30,
                           measurement_start_unix_secs=1_800_000_000,
                           measurement_start_host_clock=dict(clock='CLOCK_MONOTONIC',
                               before_ns=1000 * NS, after_ns=1000 * NS + 100))
        self.timeline = [dict(monotonic_ns=at * NS, capture_end_ns=at * NS + 1000,
                             clock=dict(before_ns=at * NS, after_ns=at * NS + 100,
                                        unix_ns=(1_800_000_000 + at - 1000) * NS),
                             transport=dict(errors=[])) for at in (999, 1001, 1031)]
        self.usage = dict(timeline=self.timeline, errors=[], capture_complete=True,
                          owners=[dict(role='client', time_namespace=123)])

    def test_process_epoch_is_never_host_time(self):
        window = measurement_window(self.phases, self.timeline)
        self.assertTrue(window['valid'])
        self.assertEqual(measurement_position(1005 * NS, window), 'measurement')
        self.assertEqual(measurement_position(5 * NS, window), 'outside')
        del self.phases['measurement_start_host_clock']
        self.assertFalse(measurement_window(self.phases, self.timeline)['valid'])

    def test_boundary_uncertainty_is_not_positive_measurement_evidence(self):
        window = measurement_window(self.phases, self.timeline)
        for at, expected in [(1000 * NS - 1, 'outside'), (1000 * NS, 'boundary_uncertain'),
                             (1000 * NS + 100, 'measurement'),
                             (1030 * NS, 'boundary_uncertain'), (1030 * NS + 100, 'outside'),
                             (None, 'unknown')]:
            self.assertEqual(measurement_position(at, window), expected)

    def test_missing_wide_or_mismatched_clocks_fail_closed(self):
        for clock in (None, {}, dict(clock='process_local', before_ns=3 * NS, after_ns=3 * NS + 10),
                      dict(clock='CLOCK_MONOTONIC', before_ns=1000 * NS, after_ns=1000 * NS + 1_000_001),
                      dict(clock='CLOCK_MONOTONIC', before_ns=1000 * NS, after_ns=999 * NS)):
            with self.subTest(clock=clock):
                phases = dict(self.phases, measurement_start_host_clock=clock)
                self.assertFalse(measurement_window(phases, self.timeline)['valid'])
        self.assertFalse(measurement_window(self.phases, self.timeline[:-1])['valid'])
        for duration in (0, -1, None, float('nan'), float('inf'), True):
            self.assertFalse(measurement_window(dict(self.phases, measurement_secs=duration), self.timeline)['valid'])
        bad = dict(self.phases, measurement_start_unix_secs=1_800_000_030)
        self.assertFalse(measurement_window(bad, self.timeline)['valid'])

    def test_clock_jump_and_nonmonotonic_capture_fail_closed(self):
        for shift in (-NS, NS):
            timeline = copy.deepcopy(self.timeline)
            timeline[1]['clock']['unix_ns'] += shift
            self.assertEqual(measurement_window(self.phases, timeline)['reason'], 'realtime_clock_jump')
        timeline = copy.deepcopy(self.timeline)
        timeline[1]['clock'] = timeline[0]['clock']
        self.assertFalse(measurement_window(self.phases, timeline)['valid'])

    def test_error_intervals_and_untimed_errors_are_conservative(self):
        window = measurement_window(self.phases, self.timeline)
        self.assertEqual(provenance_issues(self.usage, window, 123), [])
        for error in ({'error': 'cap'}, dict(at_ns=1005 * NS, end_ns=1005 * NS),
                      dict(at_ns=999 * NS, end_ns=1000 * NS), dict(at_ns=1000 * NS + 50),
                      dict(at_ns=1005 * NS, end_ns=1004 * NS)):
            self.usage['errors'] = [error]
            self.assertIn('process_provenance_incomplete', provenance_issues(self.usage, window, 123))
        self.usage['errors'] = [dict(at_ns=998 * NS, end_ns=999 * NS)]
        self.assertEqual(provenance_issues(self.usage, window, 123), [])
        self.usage['timeline'][1]['transport']['errors'] = ['diagnostic dump failed']
        self.assertIn('process_provenance_incomplete', provenance_issues(self.usage, window, 123))
        self.assertIn('process_clock_namespace_unverified', provenance_issues(self.usage, window, 124))

    def test_real_proof_path_keeps_only_definite_measurement_witnesses(self):
        ip = struct.unpack('=I', socket.inet_aton('127.0.0.1'))[0]
        event = dict(phase='lifecycle', kind=21, cookie=7, pid=10, process_start_ns=NS,
                     cgroup=3, family=2, local_ipv4=ip, local_port=20000, peer_ipv4=ip,
                     peer_port=3445, at_ns=999 * NS, result=0)
        witness = dict(phase='witness', kind=1, cookie=7, pid=10, process_start_ns=NS,
                       at_ns=1005 * NS, result=4096, length=4096, segment=1024)
        observer = SimpleNamespace(family='tx', ready={'status': 'supported'}, error=None,
                                   rows=[event, witness, dict(witness, at_ns=1000 * NS),
                                         dict(witness, at_ns=5 * NS)])
        self.usage['owners'][0].update(pid=10, cgroup_id=3, start_ticks=100, ticks=100)
        args = ([observer], self.usage, [], dict(phases=self.phases),
                dict(boot_id='boot', time_namespace=123), {}, 'direct')
        proof = live.proof(*args)
        self.assertEqual([r['at_ns'] for r in proof['positive']], [1005 * NS])
        self.assertEqual(len(proof['uncorrelated_positive']), 1)
        self.assertFalse(proof['absence_claim_allowed'])
        self.phases['measurement_start_host_clock'] = None
        proof = live.proof(*args)
        self.assertEqual(proof['positive'], [])
        self.assertFalse(proof['measurement_clock']['valid'])
        self.assertFalse(proof['absence_claim_allowed'])

    def test_malformed_diagnostics_or_capture_errors_never_pass(self):
        results = supported_results()
        self.assertEqual(observer_issues(results), [])
        for field, value in [('ready', {}), ('final', {}), ('termination', None),
                             ('capture_complete', False), ('error', 'observer_artifact_cap'),
                             ('error', 'observer_resource_capture_failed'), ('returncode', 1)]:
            bad = copy.deepcopy(results)
            bad[0][field] = value
            self.assertTrue(observer_issues(bad), (field, value))
        self.assertTrue(observer_issues(results[:-1]))
        for field, value in [('losses', []), ('map_read_failures', 1), ('map_read_failures', None),
                             ('start_ns', 'bad'), ('pending_tx', False)]:
            bad = copy.deepcopy(results)
            bad[0]['final'][field] = value
            self.assertTrue(observer_issues(bad), (field, value))
        for row in ([], {}, {'phase': 'unknown'}, dict(phase='ready', status='bogus')):
            with self.assertRaises(ValueError): validate_observer_record(row, 'tx')

    def test_missing_observer_resource_capture_is_an_error(self):
        observer = live.Observer.__new__(live.Observer)
        observer.process = SimpleNamespace(pid=123)
        observer.ready, observer.cpu, observer.error = {'status': 'supported'}, [], None
        with patch('live.capture', return_value=None):
            observer.sample_cpu()
        self.assertEqual(observer.error, 'observer_resource_capture_failed')

    def test_only_detached_final_rows_require_stable_counts_and_times(self):
        snapshot = supported_results()[0]['final']
        for count, last in [(0, 0), (1, 51)]:
            snapshot['rows'] = [dict(cookie=7, peer_cookie=0, kind=2, count=count,
                                    first_ns=20, last_ns=last, length=0, segment=0, cpu=0, result=0)]
            with self.assertRaises(ValueError): validate_observer_record(snapshot, 'tx')
            validate_observer_record(dict(snapshot, phase='checkpoint'), 'tx')

    def test_smoke_requires_each_role_operations_and_lifecycle(self):
        roles = ['backend', 'client', 'gateway_frontend', 'gateway_upstream']
        evidence = dict(operation_coverage={r: [2, 6] for r in roles},
                        roles=[dict(cookie=i + 1, role=r) for i, r in enumerate(roles)],
                        socket_lifetimes=[dict(cookie=i + 1, birth_ns=10, retirement_ns=20) for i in range(4)])
        results = supported_results()
        results[-1]['ready'] = dict(phase='ready', status='unsupported', errno=2,
                                   verifier_log_truncated=False, reason='missing_run_bpf_filter_execution_site')
        results[-1].update(final=None, termination=None)
        self.assertEqual(observer_issues(results), [])
        self.assertEqual(smoke_issues(evidence, results, 'envoy'), [])
        for i, role in enumerate(roles):
            bad = copy.deepcopy(evidence)
            del bad['operation_coverage'][role]
            self.assertIn(f'smoke_missing_operation_role:{role}', smoke_issues(bad, results, 'envoy'))
            bad = copy.deepcopy(evidence)
            bad['socket_lifetimes'][i]['retirement_ns'] = None
            self.assertIn(f'smoke_missing_lifecycle_role:{role}', smoke_issues(bad, results, 'envoy'))
        results[0]['ready'] = results[-1]['ready']
        self.assertIn('smoke_required_family_unavailable:tx', smoke_issues(evidence, results, 'envoy'))

    def test_late_failures_reach_calibration_and_traffic_validity(self):
        off = dict(rps=100, p99_us=100, traffic_issues=[], observer_ok=True)
        for record in (dict(status='error', reason='observer_RSS_reservation_exceeded'),
                       dict(artifact_cap_exceeded=True), dict(observer_errors=['malformed_final']),
                       dict(smoke_issues=['smoke_missing_lifecycle_role:client'])):
            issues = sample_admission_issues(record, [])
            self.assertTrue(issues)
            on = dict(off, traffic_issues=issues)
            self.assertFalse(calibration([(off, on), (off, on)])['active_main'])

    def test_malformed_envoy_counters_cannot_confirm_protocol_or_no_retries(self):
        counters = dict(upstream_cx_http1_total=0, upstream_cx_http2_total=0,
                        upstream_rq_retry=0, upstream_rq_retry_success=0,
                        upstream_rq_timeout=0, upstream_cx_http3_total=4)
        document = dict(stats=[dict(name='cluster.backend_h3.' + k, value=v) for k, v in counters.items()])
        self.assertEqual(envoy_protocol_evidence(document), counters)
        for key in (0, 5):
            for value in (None, True, False, float('nan'), float('inf'), -1, '0'):
                bad = copy.deepcopy(document)
                bad['stats'][key]['value'] = value
                with self.assertRaises(ValueError): envoy_protocol_evidence(bad)
        for stats in (document['stats'][:-1], document['stats'] + [document['stats'][0]], [], [None]):
            with self.assertRaises(ValueError): envoy_protocol_evidence(dict(stats=stats))
        document['stats'][0]['value'] = 1
        with self.assertRaises(ValueError): envoy_protocol_evidence(document)


if __name__ == '__main__':
    unittest.main()
