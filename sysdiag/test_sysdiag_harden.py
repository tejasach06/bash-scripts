import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "sysdiag.sh"


def run_sysdiag(args, env=None, input_text=None):
    merged_env = os.environ.copy()
    merged_env.update(env or {})
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=ROOT,
        env=merged_env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


class HardenTests(unittest.TestCase):
    def test_harden_dry_run_writes_evidence_without_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dry"
            result = run_sysdiag(["--run", "harden", "--out", str(out)])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DRY-RUN: write /etc/profile.d/99-sysdiag-timeout.sh", result.stdout)
            self.assertIn("skip package upgrades", (out / "evidence" / "hardening-plan.txt").read_text())
            self.assertIn("mode=dry-run", (out / "evidence" / "hardening-environment.txt").read_text())

    def test_harden_apply_refuses_virtualization_without_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bindir = tmp_path / "bin"
            bindir.mkdir()
            detect = bindir / "systemd-detect-virt"
            detect.write_text("#!/bin/sh\nprintf kvm\n")
            detect.chmod(0o755)
            result = run_sysdiag(
                ["--run", "harden", "--apply", "--out", str(tmp_path / "apply")],
                env={"PATH": f"{bindir}:{os.environ['PATH']}"},
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("refused in virtualization environment (kvm)", result.stderr)

    def test_harden_apply_preflight_reports_missing_commands(self):
        if os.getuid() != 0:
            self.skipTest("apply preflight requires root branch")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bindir = tmp_path / "bin"
            bindir.mkdir()
            for cmd in ("date", "id", "tee"):
                shutil.copy(shutil.which(cmd), bindir / cmd)
            detect = bindir / "systemd-detect-virt"
            detect.write_text("#!/bin/sh\nprintf none\n")
            detect.chmod(0o755)
            result = run_sysdiag(
                ["--run", "harden", "--apply", "--allow-virtualization", "--out", str(tmp_path / "missing")],
                env={"PATH": str(bindir)},
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("missing required command", result.stderr)
            self.assertIn("visudo", result.stderr)


if __name__ == "__main__":
    unittest.main()
