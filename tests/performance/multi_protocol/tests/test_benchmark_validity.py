import sys
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_validity import bucket_issues, expected_rows, sample_issues, throughput_value


def clean():
    return dict(total_requests=10, total_errors=0, total_bytes=10240, payload_size=1024, rps=5)


class BenchmarkValidityTests(unittest.TestCase):
    def test_startup_failure_still_has_expected_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.assertEqual(expected_rows(path), [])
            (path / "manifest.json").write_text(json.dumps({
                "gateways": ["ferrum", "envoy"], "payload_sizes": [10240, 5242880]}))
            self.assertEqual(expected_rows(path), [
                ("ferrum", 10240), ("ferrum", 5242880),
                ("envoy", 10240), ("envoy", 5242880)])
            self.assertTrue(bucket_issues([], 3))

    def test_all_iterations_must_be_clean(self):
        self.assertEqual(bucket_issues([clean()] * 3, 3), [])
        bad = dict(clean(), total_errors=1)
        self.assertTrue(bucket_issues([clean(), bad, clean()], 3))
        self.assertTrue(bucket_issues([clean()], 3))
        self.assertTrue(bucket_issues([], 3))

    def test_zero_work_is_not_an_error_free_sample(self):
        self.assertTrue(sample_issues(dict(clean(), total_requests=0, total_bytes=0, rps=0)))

    def test_failure_placeholders_and_malformed_measurements(self):
        for sample in [{}, {"error": "bench wallclock timeout", "rps": 0},
                       dict(clean(), total_bytes=10239), dict(clean(), total_errors=None),
                       dict(clean(), rps=float("nan")), dict(clean(), rps=float("inf"))]:
            with self.subTest(sample=sample):
                self.assertTrue(sample_issues(sample))
        self.assertEqual(throughput_value(dict(rps=float("nan"))), 0)


if __name__ == "__main__":
    unittest.main()
