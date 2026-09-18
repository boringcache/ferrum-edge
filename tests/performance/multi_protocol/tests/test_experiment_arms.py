import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_arms import load_experiment
from benchmark_plan import write_summaries


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(enabled=True, name="h1-cutoff", protocol="http1-tls", arms=[
            dict(gateway="ferrum", FERRUM_EXTRA_ENV="FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0"),
            dict(gateway="ferrum-exp-one", FERRUM_EXTRA_ENV="FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1"),
        ])

    def load(self, plan, protocol="http1-tls"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.json"
            path.write_text(json.dumps(plan))
            return load_experiment(path, protocol)

    def test_scoping_and_disabled_manifest(self):
        self.assertEqual(self.load(self.plan), self.plan)
        self.assertIsNone(self.load(self.plan, "http3"))
        self.plan["enabled"] = False
        self.assertIsNone(self.load(self.plan))

    def test_rejects_command_syntax_identity_collisions_and_non_env_changes(self):
        for field, value in (("gateway", "ferrum"), ("gateway", "../escape"),
                             ("gateway", "ferrum-baseline"), ("image", "other:tag"),
                             ("FERRUM_EXTRA_ENV", "FERRUM_X=$(whoami)"),
                             ("FERRUM_EXTRA_ENV", "FERRUM_X=1\nFERRUM_Y=2"),
                             ("FERRUM_EXTRA_ENV", "FERRUM_X=1 FERRUM_X=2")):
            plan = copy.deepcopy(self.plan)
            plan["arms"][1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load(plan)

    def test_extra_arm_is_included_in_paired_intervals_and_missing_arm_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pair in (1, 2):
                path = root / "pairs" / f"pair_{pair:03d}"
                path.mkdir(parents=True)
                for arm, rps in (("ferrum", 10), ("ferrum-exp-one", 12)):
                    sample = dict(pair=pair, host_id="host", payload_size=64, duration_secs=1,
                                  effective_concurrency=2, total_requests=rps, total_errors=0,
                                  total_bytes=rps * 64, rps=rps)
                    (path / f"{arm}_http1-tls_64.json").write_text(json.dumps(sample))
            write_summaries(root, "http1-tls", ["ferrum", "ferrum-exp-one"], [64], 2)
            comparison = json.loads((root / "paired_comparisons.json").read_text())[0]
            self.assertTrue(comparison["accepted"])
            self.assertAlmostEqual(comparison["ratio"], 1.2)
            (root / "pairs/pair_002/ferrum-exp-one_http1-tls_64.json").unlink()
            write_summaries(root, "http1-tls", ["ferrum", "ferrum-exp-one"], [64], 2)
            comparison = json.loads((root / "paired_comparisons.json").read_text())[0]
            self.assertFalse(comparison["accepted"])


if __name__ == "__main__":
    unittest.main()
