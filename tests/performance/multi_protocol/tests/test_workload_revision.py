import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluate_protocol_perf_budgets import (build_trends_point, history_metric, merge_history)


class WorkloadRevisionTests(unittest.TestCase):
    def test_revision_restarts_history_without_mixing_legacy_or_other_workloads(self):
        def point(revision, rps):
            return dict(workload_revision=revision, runner_class="host", build_profile="release",
                        protocols={"TCP": dict(rps=rps)})

        legacy = point(None, 1000)
        del legacy["workload_revision"]
        history = dict(points=[legacy, point("old", 900), point("new", 100)])
        self.assertEqual(history_metric(history, "TCP", "rps", runner_class="host",
                                        build_profile="release", workload_revision="new"), [100])
        merged = merge_history(history, point("new", 110), 8)
        self.assertEqual(len(merged["points"]), 2)
        self.assertTrue(all(p["workload_revision"] == "new" for p in merged["points"]))
        self.assertEqual(build_trends_point({}, dict(workload_revision="new"))
                         ["workload_revision"], "new")


if __name__ == "__main__":
    unittest.main()
