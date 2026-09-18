import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_plan import gateway_order, paired_comparison, summarize, write_summaries
from benchmark_validity import sample_issues
from process_usage import measurement_usage, parse_stat


def sample(pair, rps=10):
    return dict(pair=pair, host_id="same-host", payload_size=64, duration_secs=1,
                effective_concurrency=2, total_requests=rps, total_errors=0,
                total_bytes=rps * 64, rps=rps, p99_us=500)


class PairedPlanTests(unittest.TestCase):
    def test_counterbalances_and_rotates_every_arm_including_direct(self):
        gateways = ["direct", "ferrum", "envoy", "ferrum-baseline"]
        orders = [gateway_order(gateways, pair) for pair in range(1, 9)]
        for i in range(0, 8, 2):
            self.assertEqual(orders[i], list(reversed(orders[i + 1])))
        for position in range(4):
            self.assertEqual(sorted(order[position] for order in orders), sorted(gateways * 2))
        self.assertEqual(gateway_order([], 1), [])
        with self.assertRaises(ValueError):
            gateway_order(["ferrum", "ferrum"], 1)

    def test_requires_three_matched_clean_pairs_without_cherry_picking(self):
        baseline = [sample(i) for i in range(1, 4)]
        candidate = [sample(i, 20) for i in range(1, 4)]
        result = paired_comparison(baseline, candidate, 3)
        self.assertTrue(result["accepted"])
        self.assertAlmostEqual(result["ratio"], 2)
        self.assertFalse(result["needs_more_measurement"])
        self.assertFalse(paired_comparison(baseline[:2], candidate[:2], 2)["accepted"])
        for field, value in (("host_id", "another-host"), ("pair", 4),
                             ("duration_secs", 2), ("effective_concurrency", 1),
                             ("total_errors", 1)):
            changed = [dict(row) for row in candidate]
            changed[1][field] = value
            self.assertFalse(paired_comparison(baseline, changed, 3)["accepted"])
        self.assertFalse(paired_comparison([sample(1)] * 3, [sample(1, 20)] * 3, 3)["accepted"])
        baseline[1]["host_id"] = candidate[1]["host_id"] = "another-host"
        self.assertFalse(paired_comparison(baseline, candidate, 3)["accepted"])

    def test_uncertainty_requests_more_measurement(self):
        result = paired_comparison([sample(i, 100) for i in range(1, 4)],
                                   [sample(i, rps) for i, rps in enumerate((98, 102, 104), 1)], 3)
        self.assertTrue(result["needs_more_measurement"])
        self.assertLess(result["ci95_low"], 1)
        self.assertGreater(result["ci95_high"], 1)

    def test_summary_retains_raw_records_and_legacy_byte_and_rate_contract(self):
        rows = [sample(i, 10 * i) for i in range(1, 4)]
        summary = summarize(rows, 3)
        self.assertEqual(summary["samples"], rows)
        self.assertEqual(summary["rps"], 20)
        self.assertEqual(summary["total_bytes"], summary["total_requests"] * 64)
        self.assertEqual(sample_issues(summary), [])
        rows[1]["total_errors"] = 1
        self.assertTrue(sample_issues(summarize(rows, 3)))
        self.assertTrue(sample_issues(summarize(rows[:2], 3)))
        rows[1] = sample(1)  # duplicate IDs are not a complete pair set
        self.assertTrue(sample_issues(summarize(rows, 3)))

    def test_missing_arm_remains_visible_in_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            write_summaries(directory, "http3", ["direct", "ferrum"], [64], 3)
            row = json.loads((Path(directory) / "ferrum_http3_64.json").read_text())
            self.assertEqual(len(row["samples"]), 3)
            self.assertTrue(sample_issues(row))

    def test_proc_parser_handles_parentheses_and_counts_process_cpu(self):
        fields = ["0"] * 22
        fields[0] = "S"
        fields[11], fields[12], fields[19], fields[21] = "120", "30", "999", "16"
        record = parse_stat("42 (worker (echo)) " + " ".join(fields), 100, 4096)
        self.assertEqual(record, dict(start_ticks=999, cpu_seconds=1.5, rss_bytes=65536))

    def test_measurement_cpu_brackets_and_pid_reuse_are_explicit(self):
        timeline = [dict(unix_secs=t, processes=[dict(
            pid=42, start_ticks=1, role="gateway", cpu_seconds=t * 2, rss_bytes=1024)])
            for t in (0.9, 1.1, 1.9, 2.1)]
        timeline.append(dict(unix_secs=2.2, processes=[dict(
            pid=42, start_ticks=2, role="gateway", cpu_seconds=0, rss_bytes=512)]))
        rows = measurement_usage(dict(timeline=timeline), dict(
            measurement_start_unix_secs=1, measurement_secs=1))
        self.assertEqual(len(rows), 2)
        self.assertAlmostEqual(rows[0]["cpu_seconds"], 2.4)
        self.assertAlmostEqual(rows[0]["boundary_slack_secs"], 0.2)
        self.assertTrue(rows[0]["complete_bracket"])
        self.assertFalse(rows[1]["complete_bracket"])
        self.assertNotIn("cpu_seconds", rows[1])

    def test_every_protocol_uses_shared_phases_and_timed_records(self):
        source = (Path(__file__).resolve().parents[1] / "proto_bench.rs").read_text()
        throughput = source.split("// ── Saturation (")[0]
        self.assertEqual(throughput.count("Phases::new("), 7)
        self.assertEqual(throughput.count("phases.finish(handles).await"), 7)
        self.assertNotIn("Instant::now() < deadline", throughput)
        self.assertIn("endpoint.wait_idle()", throughput)
        self.assertIn("connect_with_connector(connections.clone())", throughput)


if __name__ == "__main__":
    unittest.main()
