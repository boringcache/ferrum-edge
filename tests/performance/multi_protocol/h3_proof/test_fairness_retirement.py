"""Semantic regression for the idle used/unused retirement join.

These doubles exercise only the correlation rules over recorded evidence. The
real hosted Envoy-4 fixture remains the live used/unused retirement gate.
"""
import json
from pathlib import Path
import tempfile
import unittest

import fairness

BASE_UNIX = 1_000_000.0
TEARDOWN_NS = 10_000_000_000
# 127.0.0.1 in host byte order, matching live_contract.ipv4.
LOCAL_IPV4 = 0x0100007F
OWNER = dict(pid=4242, cgroup_id=99, netns=4026531833, ticks=100, start_ticks=100)


def unix_of(at_ns):
    return BASE_UNIX + at_ns / 1e9


def socket_event(kind, cookie, at_ns, port):
    return dict(kind=kind, cookie=cookie, at_ns=at_ns, phase='lifecycle', local_ipv4=LOCAL_IPV4,
                local_port=port, drops=0, so_rcvbuf=4194304, so_sndbuf=4194304, pid=OWNER['pid'],
                cgroup=OWNER['cgroup_id'], netns=OWNER['netns'], process_start_ns=1_000_000_000)


class Evidence:
    """One synthetic sample directory of recorded backend and kernel evidence."""

    def __init__(self, directory):
        self.out = Path(directory)
        self.profile, self.births, self.destroys, self.sockets = [], [], [], []

    def connection(self, connection_id, port, *, completed, first_ns=2_000_000_000, samples=6):
        # Sample zero always reports no completed work, so a connection that
        # carried any has a recorded instant after which work still arrived.
        for index in range(samples):
            done = 0 if index == 0 else completed
            self.profile.append(dict(unix_secs=unix_of(first_ns) + index * 0.5,
                                     connection_id=connection_id, peer=f'127.0.0.1:{port}',
                                     accepted=done, completed=done, bytes=done * 10240,
                                     close_reason='closed' if index == samples - 1 else None))

    def socket(self, cookie, port, *, birth_ns, destroy_ns):
        self.births.append(socket_event(18, cookie, birth_ns, port))
        self.destroys.append(socket_event(20, cookie, destroy_ns, port))
        self.sockets.append(dict(cookie=[cookie & 0xFFFFFFFF, cookie >> 32], local_port=port,
                                 owners=[dict(OWNER)]))

    def join(self):
        (self.out / 'backend.log').write_text(
            ''.join('H3_PROFILE ' + json.dumps(row) + '\n' for row in self.profile))
        for name, rows in (('lifetime.jsonl', self.births), ('destroy.jsonl', self.destroys)):
            (self.out / name).write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (self.out / 'proof.json').write_text(json.dumps(dict(
            roles=[dict(cookie=row['cookie'], role='gateway_upstream') for row in self.births])))
        (self.out / 'process-transport.raw.json').write_text(json.dumps(dict(timeline=[dict(
            clock=dict(before_ns=0, after_ns=0, unix_ns=int(BASE_UNIX * 1e9)),
            transport=dict(sockets=self.sockets))])))
        return fairness.retirement_evidence(self.out, dict(sample_record=dict(
            workload_teardown_ns=TEARDOWN_NS, workload_teardown_unix_secs=unix_of(TEARDOWN_NS))))


class RetirementJoinTests(unittest.TestCase):
    def test_retirement_well_before_the_reported_close_still_joins_used_and_unused(self):
        # Backend samples run to 1000004.5 while both kernel destructions land at
        # 1000002.6. The hosted Envoy arms reproduce exactly that lead, which the
        # retired fixed one-second correlation allowance silently rejected.
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(directory)
            evidence.connection(1, 3001, completed=1)
            evidence.connection(2, 3002, completed=0)
            evidence.socket(11, 3001, birth_ns=1_000_000_000, destroy_ns=2_600_000_000)
            evidence.socket(12, 3002, birth_ns=1_000_000_000, destroy_ns=2_600_000_000)
            joined = evidence.join()
            retained = json.loads((Path(directory) / 'idle-retirements.json').read_text())
        self.assertEqual(sorted(row['work'] for row in joined), ['unused', 'used'])
        self.assertEqual(len(retained['socket_retirements']), 2)
        for row in joined:
            self.assertEqual(len(row['kernel_retirements']), 1)
            self.assertEqual(row['kernel_retirements'][0]['backend_sample_quantum_secs'], 0.5)
            self.assertEqual(row['kernel_retirements'][0]['backend_alive_secs'], unix_of(2_000_000_000))

    def test_retirement_before_the_last_observed_work_is_not_joined(self):
        # Sample 1000002.0 still reported no completed request, so work arrived
        # after it; a socket destroyed at 1000001.5 is a different lifetime.
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(directory)
            evidence.connection(1, 3001, completed=1)
            evidence.socket(11, 3001, birth_ns=1_000_000_000, destroy_ns=1_500_000_000)
            joined = evidence.join()
        self.assertEqual([row['kernel_retirements'] for row in joined], [[]])

    def test_retirement_beyond_the_close_sample_quantum_is_not_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(directory)
            evidence.connection(1, 3001, completed=1)
            evidence.socket(11, 3001, birth_ns=1_000_000_000, destroy_ns=5_500_000_000)
            joined = evidence.join()
        self.assertEqual([row['kernel_retirements'] for row in joined], [[]])

    def test_socket_born_after_the_first_backend_observation_is_not_joined(self):
        # A later socket reusing the endpoint cannot be this connection's peer.
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(directory)
            evidence.connection(1, 3001, completed=1)
            evidence.socket(11, 3001, birth_ns=2_200_000_000, destroy_ns=2_600_000_000)
            joined = evidence.join()
        self.assertEqual([row['kernel_retirements'] for row in joined], [[]])

    def test_two_admitted_sockets_on_one_endpoint_reject_the_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(directory)
            evidence.connection(1, 3001, completed=1)
            evidence.socket(11, 3001, birth_ns=1_000_000_000, destroy_ns=2_600_000_000)
            evidence.socket(12, 3001, birth_ns=1_000_000_000, destroy_ns=2_700_000_000)
            with self.assertRaises(ValueError) as raised:
                evidence.join()
        self.assertIn('ambiguous reused endpoint', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
