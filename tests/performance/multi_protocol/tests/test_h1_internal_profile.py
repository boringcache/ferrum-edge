import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import h1_internal_profile as profile


def values():
    result = dict.fromkeys(profile.FIELDS, 0)
    result.update(schema=1, pid=1, allocator_installed=1, slot_capacity=128)
    return result


def capture():
    rows = []
    for time in [9.9, 10.5, 11.1]:
        counters = values()
        counters["alloc_process_alloc_calls"] = int(time * 10)
        rows.append(dict(unix_secs=time, processes=[dict(pid=31, start_ticks=100, role="gateway")],
                         h1_profile=dict(unix_secs=time, counters=counters)))
    return dict(capture_complete=True, timeline=rows)


class H1InternalProfileTests(unittest.TestCase):
    def test_literal_rust_and_sampler_schema_match(self):
        root = Path(__file__).resolve().parents[4]
        source = (root / "src/h1_profile/schema.rs").read_text()
        names = re.findall(r'^    "([a-z0-9_]+)",$', source, re.M)
        self.assertEqual(names, profile.SCHEMA["counters"])
        self.assertEqual(len(set(names)), 206)

    def test_metrics_require_every_fixed_field_and_integer(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        self.assertEqual(profile.parse_metrics(text), values())
        for malformed in [text + "\n" + text, text.replace("schema 1", "schema NaN"),
                          text.replace("schema 1", "schema 2"), "", text + "\nferrum_h1_profile_secret 1"]:
            with self.assertRaises(ValueError):
                profile.parse_metrics(malformed)

    def test_missing_resets_identity_overflow_and_thread_tails_are_explicit(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        self.assertTrue(profile.profile_bracket(capture(), phases)["complete"])
        mutations = [
            lambda c: c["timeline"][1].pop("h1_profile"),
            lambda c: c["timeline"][1]["processes"].clear(),
            lambda c: c["timeline"][1]["processes"][0].update(start_ticks=101),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(alloc_process_alloc_calls=0),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(counter_overflow=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(missing_slots=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(lost_events=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(unpublished_events=1),
            lambda c: c.update(capture_complete=False),
            lambda c: c.update(timeline=None),
            lambda c: c["timeline"][1].update(h1_profile=[]),
            lambda c: c["timeline"][1]["h1_profile"].update(counters=[]),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(alloc_process_alloc_calls=True),
            lambda c: c["timeline"][1]["h1_profile"].update(capture_secs=float("nan")),
            lambda c: c["timeline"][1].update(unix_secs=1),
        ]
        for mutate in mutations:
            data = copy.deepcopy(capture())
            mutate(data)
            result = profile.profile_bracket(data, phases)
            self.assertFalse(result["complete"])
            self.assertTrue(result["issues"])
        for invalid in (None, [], dict(measurement_start_unix_secs=float("nan"), measurement_secs=1),
                        dict(measurement_start_unix_secs=10, measurement_secs=-1)):
            self.assertFalse(profile.profile_bracket(capture(), invalid)["complete"])

    def test_selection_preserves_declared_policy_and_h2_manifest(self):
        args = ["cutoff", "http1-tls", "4", "15", "200", "ferrum", "10240 5242880", "", ""]
        profile.validate_selection(*args)
        for index, replacement in [(1, "http2"), (2, "2"), (3, "60"), (4, "100"),
                                   (5, "ferrum envoy"), (6, "1024"), (7, "other-image"),
                                   (8, "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)

    def test_diagnostic_slice_cannot_change_bounds_or_enter_full_comparisons(self):
        args = ["diagnostic", "http1-tls", "1", "30", "200", "ferrum", "5242880", "", ""]
        profile.validate_selection(*args)
        for index, replacement in [(1, "http3"), (2, "2"), (3, "31"), (4, "100"),
                                   (5, "ferrum envoy"), (6, "1048576"), (7, "image"),
                                   (8, "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)
        with tempfile.TemporaryDirectory() as directory:
            result = profile.report_diagnostic(directory)
            self.assertEqual(len(result["observations"]), 3)
            self.assertFalse(result["complete"])
            self.assertFalse(result["comparison_eligible"])
            self.assertTrue(all(row["issues"] for row in result["observations"]))

    def test_h1_diagnostic_is_registered_without_changing_cadence_or_retry_policy(self):
        root = Path(__file__).resolve().parents[4]
        workflow = (root / ".github/workflows/h1-internal-profile.yml").read_text()
        self.assertIn("--test metrics_tests h1_diagnostic_tests", workflow)
        self.assertIn("--duration 30 --concurrency 200 --pairs 1 --payload-sizes 5242880", workflow)
        self.assertLess(workflow.index("id: diagnostic"), workflow.index("id: calibration"))
        self.assertIn("--test functional_tests h1_cadence_tests::", workflow)
        runner = (root / "tests/performance/multi_protocol/run_gateway_protocol_bench.sh").read_text()
        self.assertIn('extra_args+=(--h1-diagnostic)', runner)
        self.assertIn('cp "$out" "$diagnostics/${gateway}_${payload}_client.raw.json"', runner)
        self.assertIn("One pass only: never pair, extend, rerun", runner)

    def test_reports_retain_failed_and_missing_five_mib_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps(dict(
                pairs=4, gateways=["direct", "ferrum", "ferrum-exp-cutoff-one"], payload_sizes=[5242880])))
            malformed = root / "pairs/pair_001/direct_http1-tls_5242880.json"
            malformed.parent.mkdir(parents=True)
            malformed.write_text("[]")
            result = profile.report(root, "cutoff")
            self.assertEqual(len(result["observations"]), 12)
            self.assertFalse(result["traffic_complete"])
            self.assertFalse(result["profiles_complete"])
            self.assertFalse(result["fully_measured_comparison_eligible"])
            self.assertTrue(all(row["traffic_issues"] for row in result["observations"]))


if __name__ == "__main__":
    unittest.main()
