import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "h2_guard"))
from benchmark_validity import sample_issues
from experiment_arms import load_experiment
from h2_diagnostics import parse_gauges
from h2_guard_observation import FIELDS, annotate, parse_line
from prepare import SHA256, extract_source, patch_source
from verify import verify_campaign
from lint import compare


def row(**updates):
    values = dict.fromkeys(FIELDS, 0)
    values.update(seq=1, cid=1, role=1, initial_max=32767, initial_available=32767,
                  max=32767, available=32767)
    values.update(updates)
    return values


def line(values, timestamp="2026-09-18T00:00:04Z", marker="H2_GUARD_V1"):
    message = marker + " " + " ".join(f"{key}={value}" for key, value in values.items())
    return timestamp + " " + json.dumps(dict(timestamp=timestamp, target="ferrum_h2_guard",
                                             fields=dict(message=message)))


def usage():
    gauges = {f"log_dropped_{sink}_{reason}": 0 for sink in ("stdout", "stderr")
              for reason in ("saturation", "record_too_large", "closed")}
    return dict(timeline=[dict(h2_gauges=dict(unix_secs=1789689604, gauges=gauges))])


class GuardObservationTests(unittest.TestCase):
    def test_lint_gate_rejects_new_changed_duplicate_and_incomplete_diagnostics(self):
        warning = dict(reason="compiler-message", message=dict(
            level="warning", code=dict(code="clippy::question_mark"), message="use ?",
            spans=[dict(is_primary=True, file_name="src/upstream.rs", line_start=1,
                        text=[dict(text="match existing {}")])]))
        completed = dict(reason="build-finished", success=True)
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / "before", Path(directory) / "after"

            def write(path, records):
                path.write_text("".join(json.dumps(record) + "\n" for record in records))

            write(before, [warning, completed])
            shifted = copy.deepcopy(warning)
            shifted["message"]["spans"][0]["line_start"] = 99
            write(after, [shifted, completed])
            self.assertEqual(compare(before, after)["new_diagnostics"], 0)
            write(after, [completed])
            self.assertEqual(compare(before, after)["new_diagnostics"], 0)
            changed = copy.deepcopy(warning)
            changed["message"]["spans"][0]["text"][0]["text"] = "match observation {}"
            error = copy.deepcopy(warning)
            error["message"]["level"] = "error"
            unclassified = copy.deepcopy(warning)
            unclassified["message"]["code"] = None
            for records in ([changed, completed], [warning, warning, completed],
                            [error, completed], [unclassified, completed], [warning],
                            [dict(reason="build-finished", success=False)]):
                write(after, records)
                with self.assertRaises(ValueError):
                    compare(before, after)

    def sample(self):
        return dict(gateway="ferrum", total_errors=361, phases=dict(
            setup_start_unix_secs=1789689600, setup_start_monotonic_secs=0,
            warmup_start_monotonic_secs=1, measurement_start_monotonic_secs=3,
            measurement_secs=15))

    def test_fixed_schema_and_branch_identity_do_not_copy_arbitrary_fields(self):
        for branch in (1, 2, 3, 4, 5):
            record = parse_line(line(row(event=1, branch=branch, reason=11)))
            self.assertEqual(record["branch"], branch)
        malformed = row()
        malformed["secret"] = "do-not-retain"
        with self.assertRaises(ValueError):
            parse_line(line(malformed))
        with self.assertRaises(ValueError):
            parse_line(line(row(branch=6)))
        for malformed in [
            '["H2_GUARD_V1"]',
            json.dumps(dict(target="ferrum_h2_guard", fields=dict(message=["H2_GUARD_V1"]))),
            line(row(byte_available=-(2**63) - 1)),
        ]:
            with self.assertRaises(ValueError):
                parse_line(malformed)
        message = line(row()).replace('"fields": {', '"peer": "do-not-retain", "fields": {')
        self.assertNotIn("do-not-retain", str(parse_line(message)))
        self.assertIsNone(parse_line(line(row()).replace('"ferrum_h2_guard"', '"another_target"')))

    def test_failures_and_all_phases_retained_without_cross_hop_inference(self):
        sample = self.sample()
        rows = [line(row(seq=1), "2026-09-17T23:59:59Z"),
                line(row(seq=2, event=1, branch=2, reason=11, empty=101)),
                line(row(seq=3, event=2), "2026-09-18T00:00:20Z")]
        annotate(sample, usage(), rows)
        observation = sample["h2_guard_observation"]
        self.assertEqual([r["phase"] for r in observation["events"]],
                         ["before_sample", "measurement", "drain"])
        self.assertEqual(observation["measurement_failures"], [2])
        self.assertEqual(observation["capture_errors"], [])
        self.assertEqual(sample["total_errors"], 361)
        self.assertIn("instrumented H2 guard build: diagnostic only", sample_issues(sample))

    def test_missing_malformed_and_suppressed_logs_are_not_zero_failure_proof(self):
        sample = self.sample()
        limits = line(dict(seq=3, scope=3, suppressed=8), marker="H2_GUARD_LIMIT_V1")
        annotate(sample, {}, [line(row()), limits, "H2_GUARD_V1 malformed"])
        observation = sample["h2_guard_observation"]
        self.assertTrue(observation["suppression_observed"])
        self.assertTrue(observation["suppression_counts_are_lower_bounds"])
        self.assertEqual(observation["missing_sequence_count"], 1)
        self.assertIn("malformed_guard_record", observation["capture_errors"])
        self.assertIn("missing_log_sink_loss_counters", observation["capture_errors"])
        annotate(sample, usage(), [])
        self.assertIn("missing_client_role_observation", sample["h2_guard_observation"]["capture_errors"])
        annotate(dict(sample, gateway="direct"), {}, [])

    def test_sampled_logger_loss_and_duplicate_records_remain_visible(self):
        sample = self.sample()
        capture = usage()
        capture["timeline"][0]["h2_gauges"]["gauges"]["log_dropped_stdout_saturation"] = 3
        annotate(sample, capture, [line(row()), line(row())])
        self.assertTrue(sample["h2_guard_observation"]["sink_loss_observed"])
        self.assertIn("malformed_guard_record", sample["h2_guard_observation"]["capture_errors"])
        metrics = ('ferrum_connection_pool_entries{pool="http2"} 1\n'
                   'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                   'ferrum_overload_active_connections 21\n'
                   'ferrum_log_sink_dropped_records_total{sink="stdout",reason="saturation"} 3\n')
        self.assertEqual(parse_gauges(metrics)["log_dropped_stdout_saturation"], 3)

    def test_exported_loss_metric_family_is_retained_and_missing_counters_fail_closed(self):
        # These are the labels emitted by src/logging/mod.rs::render_prometheus.
        gauges = ('ferrum_connection_pool_entries{pool="http2"} 1\n'
                  'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                  'ferrum_overload_active_connections 21\n')
        losses = (
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="saturation"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="record_too_large"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="closed"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="saturation"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="record_too_large"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="closed"} 0\n'
        )

        def observe(metrics):
            capture = usage()
            capture["timeline"][0]["h2_gauges"]["gauges"] = parse_gauges(gauges + metrics)
            sample = self.sample()
            annotate(sample, capture, [line(row())])
            return sample["h2_guard_observation"]

        observation = observe(losses)
        self.assertEqual(observation["capture_errors"], [])
        self.assertFalse(observation["sink_loss_observed"])
        self.assertEqual(len(observation["sink_loss_samples"][0]), 7)  # timestamp + six counters
        for sink in ("stdout", "stderr"):
            with self.subTest(sink=sink):
                label = f'sink="{sink}",reason="record_too_large"'
                positive = losses.replace(label + '} 0', label + '} 2')
                observation = observe(positive)
                self.assertEqual(observation["capture_errors"], [])
                self.assertTrue(observation["sink_loss_observed"])
                self.assertEqual(observation["sink_loss_samples"][0][
                    f"log_dropped_{sink}_record_too_large"], 2)
        for missing in losses.splitlines(keepends=True):
            with self.subTest(missing=missing):
                observation = observe(losses.replace(missing, ""))
                self.assertIn("missing_log_sink_loss_counters", observation["capture_errors"])
                self.assertFalse(observation["sink_loss_observed"])

    def test_explicit_manifest_does_not_enable_original_campaign(self):
        old = json.loads((ROOT / "experiment.json").read_text())
        self.assertFalse(old["enabled"])
        plan = load_experiment(ROOT / "h2_guard/experiment.json", "http2")
        self.assertEqual(plan["h2_guard_observation"], 1)
        self.assertEqual(plan["h2_campaign"]["concurrency"], 200)
        self.assertEqual(plan["h2_campaign"]["duration"], 15)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for bad in ("warn,h2=trace", "warn,ferrum_h2_guard=debug"):
                changed = copy.deepcopy(plan)
                changed["arms"][0]["FERRUM_EXTRA_ENV"] = "FERRUM_LOG_LEVEL=" + bad
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    load_experiment(path, "http2")

    def test_archive_patch_and_asset_identities_fail_closed(self):
        assets = ROOT / "h2_guard"
        provenance = json.loads((assets / "source.json").read_text())
        self.assertEqual(provenance["sha256"], SHA256)
        self.assertEqual(hashlib.sha256((assets / "h2-0.4.19.patch").read_bytes()).hexdigest(),
                         provenance["patch_sha256"])
        for name, digest in provenance["assets"].items():
            self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest(), digest)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            with self.assertRaises(ValueError):
                extract_source(b"not the approved crate", source)
            bad = dict(provenance, patch_sha256="0" * 64)
            with self.assertRaises(ValueError):
                patch_source(source, bad)
            for name in provenance["files"]:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("drift")
            with self.assertRaises(ValueError):
                patch_source(source, provenance)

    def test_campaign_index_keeps_failed_repetitions_and_rejects_missing_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pair in range(1, 5):
                path = root / "pairs" / f"pair_{pair:03d}"
                path.mkdir(parents=True)
                for gateway in ("direct", "ferrum", "ferrum-exp-fixed"):
                    sample = dict(effective_concurrency=200, total_errors=361 if pair == 1 else 0,
                                  h2_guard_observation=dict(schema=1, capture_errors=[]))
                    (path / f"{gateway}_http2_71680.json").write_text(json.dumps(sample))
            verify_campaign(root, "http2")
            report = json.loads((root / "guard-evidence-index.json").read_text())
            self.assertEqual(len(report["samples"]), 12)
            self.assertEqual(report["samples"][0]["total_errors"], 361)
            (root / "pairs/pair_004/ferrum_http2_71680.json").unlink()
            with self.assertRaises(ValueError):
                verify_campaign(root, "http2")
            self.assertEqual(len(json.loads((root / "guard-evidence-index.json").read_text())["samples"]), 11)


if __name__ == "__main__":
    unittest.main()
