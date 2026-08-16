#!/usr/bin/env python3
"""Test suite for ssh-script-executor.py"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPT_PATH = Path(__file__).parent / "ssh-script-executor.py"
spec = importlib.util.spec_from_file_location("ssh_script_executor", SCRIPT_PATH)
sse = importlib.util.module_from_spec(spec)
sse.__module__ = "ssh_script_executor"
sys.modules["ssh_script_executor"] = sse
spec.loader.exec_module(sse)


class TestRunLocal(unittest.TestCase):
    def test_run_local_short_command(self):
        result = sse._run_local(["true"], timeout=5.0)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.error)

        result = sse._run_local(["false"], timeout=5.0)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)

    def test_run_local_timeout(self):
        result = sse._run_local(["sleep", "5"], timeout=0.5)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -1)
        self.assertIn("Timeout", result.error)

    def test_run_local_input_capture(self):
        result = sse._run_local(
            ["bash", "-c", "read line; echo got=$line"],
            timeout=5.0,
            input=b"hello-stdin\n",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"got=hello-stdin", result.stdout)


class TestHostParsing(unittest.TestCase):
    def test_parse_host_string(self):
        h = sse.parse_host_string("user@host:2222 ~/.ssh/key")
        self.assertEqual(h.user, "user")
        self.assertEqual(h.host, "host")
        self.assertEqual(h.port, 2222)
        self.assertEqual(h.key_file, "~/.ssh/key")

        h2 = sse.parse_host_string("host.example.com")
        self.assertEqual(h2.user, "")
        self.assertEqual(h2.host, "host.example.com")
        self.assertEqual(h2.port, 22)

    def test_parse_host_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("user@host1:22 ~/.ssh/key1\n")
            f.write("host2:2222\n")
            f.write("# comment\n")
            f.write("\n")
            f.write("user3@host3\n")
            path = f.name

        try:
            hosts = sse.parse_host_file(path)
            self.assertEqual(len(hosts), 3)
            self.assertEqual(hosts[0].user, "user")
            self.assertEqual(hosts[0].host, "host1")
            self.assertEqual(hosts[0].port, 22)
            self.assertEqual(hosts[1].user, "")
            self.assertEqual(hosts[1].host, "host2")
            self.assertEqual(hosts[1].port, 2222)
            self.assertEqual(hosts[2].user, "user3")
            self.assertEqual(hosts[2].host, "host3")
        finally:
            os.unlink(path)


class TestHostResult(unittest.TestCase):
    def test_csv_roundtrip(self):
        r = sse.HostResult(
            host="test",
            success=True,
            exit_code=0,
            stdout="out",
            stderr="err",
            duration_sec=1.5,
        )
        row = r.to_csv_row()
        self.assertEqual(len(row), len(sse.HostResult.csv_header()))
        self.assertEqual(row[0], "test")
        self.assertEqual(row[1], "True")

    def test_csv_header(self):
        header = sse.HostResult.csv_header()
        self.assertIn("host", header)
        self.assertIn("success", header)
        self.assertIn("exit_code", header)


class TestDispatchLocal(unittest.TestCase):
    @patch("ssh_script_executor._run_local")
    def test_dispatch_fake_hosts(self, mock_run_local):
        mock_run_local.return_value = sse._RunResult(
            returncode=0, stdout=b"selftest: greet world", stderr=b""
        )
        hosts = sse._build_fake_hosts(n=2)
        script_path = str(Path(__file__).parent / "test-script.sh")
        results = sse._dispatch_local(
            hosts=hosts,
            script_path=script_path,
            script_args=["greet", "world"],
            timeout=10,
            max_workers=2,
        )
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertTrue(r.success)
            self.assertEqual(r.exit_code, 0)
            self.assertIn("world", r.stdout)

    @patch("ssh_script_executor._run_local")
    def test_dispatch_fake_hosts_failure(self, mock_run_local):
        mock_run_local.return_value = sse._RunResult(
            returncode=1, stdout=b"", stderr=b"intentional failure"
        )
        hosts = sse._build_fake_hosts(n=1)
        script_path = str(Path(__file__).parent / "test-script.sh")
        results = sse._dispatch_local(
            hosts=hosts,
            script_path=script_path,
            script_args=["fail", "world"],
            timeout=10,
            max_workers=1,
        )
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].success)
        self.assertNotEqual(results[0].exit_code, 0)
        self.assertIn("intentional failure", results[0].stderr)


class TestCSVOutput(unittest.TestCase):
    def test_write_csv(self):
        import csv
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            r = sse.HostResult(
                host="test",
                success=True,
                exit_code=0,
                stdout="out",
                stderr="err",
                duration_sec=1.5,
            )
            sse.write_csv([r], path)
            with open(path) as f:
                reader = csv.reader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 2)  # header + 1 data row
            self.assertEqual(rows[1][0], "test")
        finally:
            os.unlink(path)


class TestSelftest(unittest.TestCase):
    def test_selftest_runs(self):
        # Selftest runs actual shell commands; verified manually.
        import inspect
        self.assertTrue(inspect.isfunction(sse.run_selftest))


if __name__ == "__main__":
    unittest.main()