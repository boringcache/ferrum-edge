import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pool_internal_profile as profile


def values():
    result = dict.fromkeys(profile.FIELDS, 0)
    result.update(schema=1, sample_every=64, pid=1, allocator_installed=1, slot_capacity=128)
    return result


def capture():
    rows = []
    for index, timestamp in enumerate([9.9, 10.5, 11.1]):
        counters = values()
        counters["h2_request_poll_alloc"] = index
        counters["h2_request_sampled"] = index
        counters["h2_request_completed"] = index
        rows.append(dict(unix_secs=timestamp, processes=[dict(pid=31, start_ticks=100, role="gateway")],
                         pool_profile=dict(unix_secs=timestamp, monotonic_secs=timestamp,
                                           sample_id=index, capture_secs=0.01,
                                           sampler_cpu_secs=0.001, counters=counters)))
    return dict(capture_complete=True, timeline=rows)


class PoolInternalProfileTests(unittest.TestCase):
    def test_rust_schema_is_the_fixed_cartesian_product(self):
        source = (profile.ROOT.parents[2] / "src/pool_profile/schema.rs").read_text()
        arrays = {name: re.findall(r'"([a-z0-9_]+)"', re.search(
            r"pub const " + name + r": .*?= \[(.*?)\];", source, re.S)[1])
                  for name in ["FAMILIES", "PURPOSES", "EVENTS", "PHASES", "FIELDS", "PROBES"]}
        names = []
        for family in arrays["FAMILIES"]:
            for purpose in arrays["PURPOSES"]:
                prefix = family + "_" + purpose + "_"
                names += [prefix + event for event in arrays["EVENTS"]]
                names += [prefix + phase + "_" + field for phase in arrays["PHASES"]
                          for field in arrays["FIELDS"]]
                names += [prefix + bucket for bucket in arrays["PROBES"]]
        names.append("counter_overflow")
        self.assertEqual(names, profile.SCHEMA["counters"])
        self.assertEqual(len(names), len(set(names)))

    def test_metrics_reject_missing_unknown_duplicate_noninteger_and_bad_samplerate(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        self.assertEqual(profile.parse_metrics(text), values())
        for malformed in ["", text + "\n" + text, text.replace("schema 1", "schema NaN"),
                          text.replace("sample_every 64", "sample_every 1"),
                          text.replace("allocator_installed 1", "allocator_installed 0"),
                          text + "\nferrum_pool_profile_pool_key 1"]:
            with self.assertRaises(ValueError):
                profile.parse_metrics(malformed)

    def test_missing_reset_loss_overflow_tail_identity_and_observer_cost_fail_closed(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        self.assertTrue(profile.profile_bracket(capture(), phases)["complete"])
        mutations = [
            lambda c: c["timeline"][1].pop("pool_profile"),
            lambda c: c["timeline"][1]["processes"].clear(),
            lambda c: c["timeline"][1]["processes"][0].update(start_ticks=101),
            lambda c: c["timeline"][2]["pool_profile"]["counters"].update(h2_request_poll_alloc=0),
            lambda c: c["timeline"][1]["pool_profile"].pop("sampler_cpu_secs"),
            lambda c: c["timeline"][1]["pool_profile"].update(sample_id=0),
            lambda c: c["timeline"][1]["pool_profile"].update(monotonic_secs=1),
            lambda c: c["timeline"][1]["pool_profile"].update(capture_secs=float("nan")),
            lambda c: c["timeline"][2]["pool_profile"]["counters"].update(h2_request_completed=0),
            lambda c: c.update(capture_complete=False),
            lambda c: c.update(timeline=None),
            lambda c: c["timeline"][1].update(pool_profile=[]),
            lambda c: c["timeline"][1]["pool_profile"].update(counters=[]),
        ]
        for field in ("missing_slots", "lost_events", "counter_overflow", "unpublished_events",
                      "allocator_lost_events", "allocator_overflow"):
            mutations.append(lambda c, field=field: c["timeline"][1]["pool_profile"]["counters"].update(
                {field: 1}))
        for mutate in mutations:
            data = copy.deepcopy(capture())
            mutate(data)
            result = profile.profile_bracket(data, phases)
            self.assertFalse(result["complete"], result)
            self.assertTrue(result["issues"])

    def test_selector_and_materialization_hold_flow_control_policy_fixed(self):
        args = ["profile", "http2", "4", "15", "200", "ferrum", "10240 5242880", "same-image", ""]
        profile.validate_selection(*args)
        for index, replacement in [(0, "cutoff"), (1, "http1-tls"), (2, "2"), (3, "60"),
                                   (4, "100"), (5, "ferrum envoy"), (6, "1024"), (7, ""),
                                   (8, "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            for protocol, fixture in [("http2", "http2_perf.yaml"), ("grpcs", "grpcs_e2e_perf.yaml")]:
                outputs = []
                for arm in ("ferrum", "ferrum-baseline"):
                    output = root / (arm + ".yaml")
                    profile.materialize(protocol, arm, profile.ROOT / "configs" / fixture, output, manifest)
                    outputs.append(output.read_text())
                    self.assertIn("pool_http2_adaptive_window: false", outputs[-1])
                    self.assertNotIn("CA_PATH", outputs[-1])
                self.assertEqual(*outputs)

    def test_report_retains_all_failed_samples_and_malformed_partial_captures(self):
        for usage in ([], dict(timeline=[None]), capture()):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "manifest.json").write_text(json.dumps(dict(
                    pairs=4, gateways=["direct", "ferrum", "ferrum-baseline"],
                    payload_sizes=[5242880], host_id="host")))
                folder = root / "pairs/pair_001/diagnostics"
                folder.mkdir(parents=True)
                (folder / "ferrum_5242880_process_usage.json").write_text(json.dumps(usage))
                (folder.parent / "ferrum_http2_5242880.json").write_text(json.dumps(dict(
                    error="retained protocol failure", phases=dict(
                        measurement_start_unix_secs=10, measurement_secs=1))))
                result = profile.report(root, "profile", "http2")
                self.assertEqual(len(result["observations"]), 12)
                self.assertFalse(result["traffic_complete"])
                self.assertFalse(result["profiles_complete"])
                self.assertFalse(result["fully_measured_comparison_eligible"])
                row = result["observations"][1]
                self.assertEqual(row["capture"], usage)
                self.assertEqual(row["sample"]["error"], "retained protocol failure")

    def test_runtime_mismatch_is_written_before_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            config.write_text("fixture")
            container = dict(Config=dict(Env=[], Labels={}), Image="sha256:x", Id="x",
                             State=dict(Pid=31, StartedAt="now"))
            with self.assertRaises(ValueError):
                profile.retain_runtime(root / "runtime.json", container, config)
            result = json.loads((root / "runtime.json").read_text())
            self.assertTrue(result["issues"])
            self.assertIsNone(result["revision"])


if __name__ == "__main__":
    unittest.main()
