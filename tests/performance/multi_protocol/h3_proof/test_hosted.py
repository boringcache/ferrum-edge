"""Hosted driver admission and fixed-command data boundary regressions."""

import contextlib
import io
import os
import subprocess
import unittest
from unittest.mock import patch

import hosted


class HostedTests(unittest.TestCase):
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
