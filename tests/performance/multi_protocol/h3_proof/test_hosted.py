"""Hosted driver admission and fixed-command data boundary regressions."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import hosted


class HostedTests(unittest.TestCase):
    def test_classic_unavailability_cannot_hide_fixture_failure(self):
        ready = dict(phase='ready', status='unsupported', errno=2, verifier_log_truncated=False,
                     reason='missing_run_bpf_filter_execution_site')
        for fixture_status, code, expected in [('supported', 0, 'unsupported'),
                                                ('error', 1, 'error'), ('malformed', 0, 'error')]:
            with self.subTest(fixture_status=fixture_status), tempfile.TemporaryDirectory() as directory:
                process = Mock(returncode=0, args=['observer'])
                process.poll.return_value = 0
                fixture = dict(returncode=code, truncated=False,
                               stdout=json.dumps(dict(mode='classic-select', status=fixture_status,
                                   reason='fixture_assertion', start_ns=10, end_ns=20,
                                   operations=[{'op': 'selection'}], sockets=[{'cookie': 7}])))
                with (patch('hosted.subprocess.Popen', return_value=process),
                      patch('hosted.readiness', return_value=ready),
                      patch('hosted.command', return_value=fixture)):
                    case = hosted.observer_case(Path(directory), 'classic', 'classic-select')
                self.assertEqual(case['status'], expected)
                self.assertEqual(case['ready'], ready)
                self.assertEqual(case['fixture_process'], fixture)

    def test_fixture_exit_and_capture_must_match_diagnostics(self):
        for code, status, truncated in [(0, 'error', False), (1, 'supported', False),
                                        (0, 'supported', True), (0, 'unknown', False)]:
            process = dict(returncode=code, truncated=truncated,
                           stdout=json.dumps(dict(mode='offload', status=status)))
            with self.assertRaises(AssertionError): hosted.fixture_result(process, 'offload')
        empty = dict(mode='offload', status='supported', start_ns=10, end_ns=20, operations=[], sockets=[])
        with self.assertRaises(AssertionError):
            hosted.fixture_result(dict(returncode=0, truncated=False, stdout=json.dumps(empty)), 'offload')

    def test_actions_flag_does_not_admit_missing_or_self_hosted_environment(self):
        for environment in [None, "self-hosted"]:
            with self.subTest(environment=environment):
                env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
                if environment is not None:
                    env["RUNNER_ENVIRONMENT"] = environment
                with (patch.dict(os.environ, env, clear=True),
                      patch("sys.argv", ["hosted.py", "--output", "/unused-h3-proof-test"]),
                      patch("hosted.platform.system", return_value="Linux"),
                      patch("hosted.platform.machine", return_value="x86_64"),
                      patch("hosted.Path.mkdir") as mkdir,
                      patch("hosted.subprocess.run") as run,
                      contextlib.redirect_stderr(io.StringIO()) as error):
                    with self.assertRaises(SystemExit) as raised:
                        hosted.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertIn("GitHub-hosted", error.getvalue())
                    mkdir.assert_not_called()
                    run.assert_not_called()

    def test_shell_rejects_non_allowlisted_data_before_execution(self):
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true")
        self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
        self.assertEqual(os.environ.get("RUNNER_OS"), "Linux")
        self.assertEqual(os.environ.get("RUNNER_ARCH"), "X64")
        cases = [
            {"action": "unknown"},
            {"action": "fixture", "mode": "offload; exit 0"},
            {"action": "package-version", "package": "--help"},
            {"action": "package-record", "package": "python3", "version": "1; exit 0"},
            {"action": "observer", "family": "rx", "netns": "not-an-inode",
             "capacity": "512", "fault": "normal", "unprivileged": "false"},
            {"action": "isolate", "output": "relative-path"},
        ]
        for data in cases:
            with self.subTest(data=data):
                # This test is executed only by the hosted workflow, like the
                # rest of this directory. It never starts an observer/fixture.
                result = subprocess.run(
                    ["bash", "tests/performance/multi_protocol/h3_proof/commands.sh"],
                    cwd=hosted.ROOT, env=hosted.command_env(**data),
                    capture_output=True, timeout=3, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
