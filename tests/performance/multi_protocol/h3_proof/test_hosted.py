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
from evidence import LOSSES


class HostedTests(unittest.TestCase):
    def test_attachment_enospc_is_an_error_even_when_fixture_succeeds(self):
        for truncated in (False, True):
            with self.subTest(truncated=truncated), tempfile.TemporaryDirectory() as directory:
                ready = dict(phase='ready', status='error', reason='load', errno=28,
                             verifier_log_truncated=truncated)
                process = Mock(returncode=1, args=['observer'])
                process.poll.return_value = 1
                fixture = dict(returncode=0, truncated=False,
                               stdout=json.dumps(dict(mode='classic-select', status='supported',
                                   start_ns=10, end_ns=20, operations=[{'op': 'selection'}],
                                   sockets=[{'cookie': 7}])))
                with (patch('hosted.subprocess.Popen', return_value=process),
                      patch('hosted.readiness', return_value=ready),
                      patch('hosted.command', return_value=fixture),
                      patch('hosted.read_file', return_value=dict(text='load -28', truncated=truncated))):
                    case = hosted.observer_case(Path(directory), 'attach', 'classic-select')
                retained = json.loads((Path(directory) / 'attach-classic-select-512-normal.json').read_text())
                self.assertEqual(retained, case)
                self.assertEqual(case['status'], 'error')
                self.assertEqual(case['reason'], 'load')
                self.assertEqual(case['ready'], ready)
                self.assertEqual(case['fixture_process'], fixture)

    def test_final_log_truncation_cannot_pass_fixture_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = dict(phase='ready', status='supported', family='attach',
                         start_ns=1, netns=2, links=1)
            final = dict(phase='final', start_ns=1, end_ns=30, rows=[],
                         losses=[0] * len(LOSSES),
                         map_read_failures=0, pending_tx=0, pending_rx=0, pending_selector=0,
                         pending_detach=0, ring_drops=0, verifier_log_truncated=True)
            process = Mock(returncode=0, args=['observer'])
            process.poll.return_value = 0
            process.communicate.return_value = (json.dumps(final).encode() + b'\n', None)
            fixture = dict(returncode=0, truncated=False,
                           stdout=json.dumps(dict(mode='classic-select', status='supported',
                               start_ns=10, end_ns=20, operations=[{'op': 'selection'}],
                               sockets=[{'cookie': 7}])))
            with (patch('hosted.subprocess.Popen', return_value=process),
                  patch('hosted.readiness', return_value=ready),
                  patch('hosted.command', return_value=fixture)):
                case = hosted.observer_case(Path(directory), 'attach', 'classic-select')
            self.assertEqual(case['status'], 'error')
            self.assertEqual(case['detail'], 'observer diagnostics incomplete')
            self.assertEqual(case['snapshots'], [final])

    def test_classic_unavailability_cannot_hide_fixture_failure(self):
        ready = dict(phase='ready', status='unsupported', errno=2, verifier_log_truncated=False,
                     reason='missing_run_bpf_filter_execution_site')
        for fixture_status, code, truncated, expected in [('supported', 0, False, 'unsupported'),
                ('supported', 0, True, 'error'), ('error', 1, False, 'error'), ('malformed', 0, False, 'error')]:
            with self.subTest(fixture_status=fixture_status, truncated=truncated), tempfile.TemporaryDirectory() as directory:
                process = Mock(returncode=0, args=['observer'])
                process.poll.return_value = 0
                fixture = dict(returncode=code, truncated=False,
                               stdout=json.dumps(dict(mode='classic-select', status=fixture_status,
                                   reason='fixture_assertion', start_ns=10, end_ns=20,
                                   operations=[{'op': 'selection'}], sockets=[{'cookie': 7}])))
                with (patch('hosted.subprocess.Popen', return_value=process),
                      patch('hosted.readiness', return_value=ready),
                      patch('hosted.command', return_value=fixture),
                      patch('hosted.read_file', return_value=dict(text='', truncated=truncated))):
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
