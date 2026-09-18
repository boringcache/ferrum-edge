import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from h3_experiment import envoy_config, load_experiment, topology
from benchmark_validity import sample_issues
from transport_diagnostics import (backend_distribution, counter_delta, parse_diag,
                                   parse_envoy_stats, parse_snmp, parse_udp,
                                   summarize_transport, udp_sockets)


class TransportDiagnosticsTests(unittest.TestCase):
    def test_admission_ceilings_with_identical_worker_assignment(self):
        for workers, connections, cap in ((200, 21, 84), (100, 11, 44), (50, 6, 24)):
            self.assertEqual(topology(workers, 4)["client_connections"], connections)
            self.assertEqual(topology(workers, 4)["downstream_admission_ceiling"], cap)
            self.assertEqual(topology(workers, 100)["downstream_admission_ceiling"], workers)

    def test_only_limits_and_socket_options_change_in_envoy_variant(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "configs/envoy/http3.yaml").read_text()
        plan = load_experiment(root / "h3_experiment.json")
        low = envoy_config(source, 4, plan["socket_buffer_bytes"])
        high = envoy_config(source, 100, plan["socket_buffer_bytes"])
        self.assertEqual(low.replace("max_concurrent_streams: { value: 4 }",
                                     "max_concurrent_streams: { value: 100 }"), high)
        self.assertEqual(low.count("name: 8, int_value: 2097152"), 2)
        self.assertEqual(low.count("name: 7, int_value: 2097152"), 2)
        self.assertIn("quic_options:\n          quic_protocol_options:\n"
                      "            max_concurrent_streams: { value: 4 }", low)
        self.assertIn("sni: localhost", low)
        self.assertIn("trusted_ca:", low)
        with self.assertRaises(ValueError):
            envoy_config("missing markers", 4, 4194304)

    def test_kernel_counters_and_resets_remain_distinct_from_envoy_stats(self):
        self.assertEqual(parse_snmp("Udp: InDatagrams RcvbufErrors\nUdp: 100 7\n"),
                         dict(InDatagrams=100, RcvbufErrors=7))
        rows = parse_udp("header\n1: 0100007F:20FB 00000000:0000 07 00000001:00000002 "
                         "00:00000000 00000000 1000 0 1234 2 00000000 9\n")
        self.assertEqual(rows[1234], dict(proc_drops=9, proc_tx_queue=1, proc_rx_queue=2))
        self.assertEqual(counter_delta(dict(drops=7, reset=10, missing=1), dict(drops=9, reset=0)),
                         dict(drops=2, reset=None, missing=None))

    def test_netlink_uses_actual_kernel_limits_not_queue_occupancy(self):
        payload = bytearray(72)
        payload[0] = socket.AF_INET
        struct.pack_into("!HH", payload, 4, 8443, 3445)
        struct.pack_into("=II", payload, 44, 10, 20)
        struct.pack_into("=II", payload, 64, 1000, 123)
        payload += struct.pack("=HH9I", 40, 7, 19, 4194304, 21, 4194304, 0, 0, 0, 0, 7)
        row = parse_diag(payload)
        self.assertEqual(row["so_rcvbuf"], 4194304)
        self.assertEqual(row["so_sndbuf"], 4194304)
        self.assertEqual(row["socket_drops"], 7)
        self.assertEqual(row["cookie"], [10, 20])
        with self.assertRaises(ValueError):
            parse_diag(payload[:-1])

    def test_transport_brackets_preserve_inflated_stats_and_missing_sockets(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        sock = dict(inode=42, cookie=[1, 2], socket_drops=3, proc_drops=3,
                    so_rcvbuf=4194304, so_sndbuf=4194304)
        left = dict(unix_secs=9.9, errors=[], sockets=[sock], udp_snmp=dict(RcvbufErrors=3),
                    envoy_stats=dict(downstream_rx_datagram_dropped=100000))
        right = dict(unix_secs=11.1, errors=[], sockets=[dict(sock, socket_drops=5, proc_drops=5)],
                     udp_snmp=dict(RcvbufErrors=5),
                     envoy_stats=dict(downstream_rx_datagram_dropped=900000))
        timeline = [dict(transport=row) for row in (left, right)]
        result = summarize_transport(timeline, phases)
        self.assertEqual(result["udp_snmp_delta"], dict(RcvbufErrors=2))
        self.assertEqual(result["envoy_delta"]["downstream_rx_datagram_dropped"], 800000)
        self.assertEqual(result["sockets"][0]["delta"], dict(socket_drops=2, proc_drops=2))
        self.assertAlmostEqual(result["boundary_slack_secs"], 0.2)
        right["sockets"][0]["cookie"] = [3, 4]  # reused inode
        result = summarize_transport(timeline, phases)
        self.assertFalse(result["sockets"][0]["complete_bracket"])
        self.assertIsNone(result["sockets"][0]["delta"]["socket_drops"])
        self.assertFalse(summarize_transport(timeline[:1], phases)["complete_bracket"])

    def test_backend_distribution_is_per_connection_and_bracketed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.log"
            rows = [dict(connection_id=1, peer="127.0.0.1:44444", unix_secs=t,
                         accepted=n, completed=n, bytes=n * 10240)
                    for t, n in ((9.9, 3), (11.1, 7))]
            path.write_text("banner\n" + "\n".join("H3_PROFILE " + json.dumps(row) for row in rows))
            result = backend_distribution(path, dict(measurement_start_unix_secs=10,
                                                     measurement_secs=1))
            self.assertEqual(result[0]["delta"]["completed"], 4)
            self.assertEqual(result[0]["peer"], "127.0.0.1:44444")
            self.assertTrue(result[0]["complete_bracket"])

    def test_experiment_does_not_accept_unverified_socket_parity(self):
        issues = sample_issues(dict(h3_experiment={"enabled": True}))
        self.assertIn("incomplete H3 transport observations", issues)
        self.assertIn("H3 socket budget parity unverified", issues)

    def test_envoy_histogram_wrapper_is_not_a_scalar_counter(self):
        self.assertEqual(parse_envoy_stats({"stats": [
            {"name": "watchdog_miss", "value": 2},
            {"histograms": {"supported_quantiles": [0, 50, 100], "computed_quantiles": []}},
        ]}), {"watchdog_miss": 2})
        with self.assertRaises(ValueError):
            parse_envoy_stats({"stats": [{"unrecognized": 2}]})

    @unittest.skipUnless(sys.platform == "linux", "Linux socket diagnostics")
    def test_passive_readback_matches_getsockopt_on_a_live_socket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            rows = [row for row in udp_sockets() if row["local_port"] == udp.getsockname()[1]
                    and row["family"] == socket.AF_INET]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["so_rcvbuf"], udp.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
            self.assertEqual(rows[0]["so_sndbuf"], udp.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))


if __name__ == "__main__":
    unittest.main()
