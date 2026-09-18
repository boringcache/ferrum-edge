import json
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from h3_experiment import envoy_config, load_experiment, topology
from transport_diagnostics import counter_delta, parse_diag, parse_snmp, parse_udp, udp_sockets


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
