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
    merged_env.setdefault("SYSDIAG_SCAN_ROOTS", tempfile.gettempdir())
    merged_env.update(env or {})
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=ROOT,
        env=merged_env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


class HardenTests(unittest.TestCase):
    def test_harden_dry_run_writes_evidence_without_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dry"
            result = run_sysdiag(["--run", "harden", "--out", str(out)], env={"SYSDIAG_SCAN_ROOTS": tmp})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DRY-RUN: write /etc/profile.d/99-sysdiag-timeout.sh", result.stderr)
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
            self.assertIn("virtualization is kvm", result.stderr)

            bindir_empty = tmp_path / "bin_empty"
            bindir_empty.mkdir()
            for pdir in os.environ["PATH"].split(":"):
                if os.path.isdir(pdir):
                    for item in os.listdir(pdir):
                        if item not in ("systemd-detect-virt", "virt-what"):
                            src = os.path.join(pdir, item)
                            dst = bindir_empty / item
                            if not dst.exists() and os.path.isfile(src):
                                try:
                                    os.symlink(src, dst)
                                except OSError:
                                    pass
            result_unk = run_sysdiag(
                ["--run", "harden", "--apply", "--out", str(tmp_path / "apply_unk")],
                env={"PATH": str(bindir_empty)},
            )
            self.assertEqual(result_unk.returncode, 1)
            self.assertIn("virtualization is unknown", result_unk.stderr)

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
    def test_audit_mode_scores_every_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit"
            result = run_sysdiag(["--run", "harden", "--out", str(out)], env={"SYSDIAG_SCAN_ROOTS": tmp})
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            self.assertTrue(status_file.exists())
            ids = set()
            for line in status_file.read_text().splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                self.assertGreaterEqual(len(parts), 2)
                ctrl, status = parts[0], parts[1]
                ids.add(ctrl)
                self.assertIn(status, {"PASS", "FAIL", "NA", "INFO"})
            expected = {
                "tmout", "banner", "ipv6", "packages", "packages_extra", "pwquality",
                "user_sudo", "su_wheel", "kernel_sysctl", "coredump",
                "auditd", "timesync", "journald", "sshd", "file_scan"
            }
            self.assertEqual(ids, expected)

    def test_controls_flag_limits_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sel"
            result = run_sysdiag(["--run", "harden", "--controls", "kernel_sysctl", "--out", str(out)])
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            ids = {line.split("\t")[0] for line in status_file.read_text().splitlines() if line.strip()}
            self.assertEqual(ids, {"kernel_sysctl"})

    def test_unknown_control_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nope"
            result = run_sysdiag(["--run", "harden", "--controls", "nope", "--out", str(out)])
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown hardening control", result.stderr)
            self.assertFalse(out.exists())

    def test_audit_mode_never_writes_to_etc(self):
        dirs = ("/etc/ssh/sshd_config.d", "/etc/systemd/coredump.conf.d", "/etc/audit/rules.d")
        before = {d: os.path.isdir(d) for d in dirs}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "noetc"
            result = run_sysdiag(["--run", "harden", "--out", str(out)], env={"SYSDIAG_SCAN_ROOTS": tmp})
            self.assertEqual(result.returncode, 0, result.stderr)
        after = {d: os.path.isdir(d) for d in dirs}
        self.assertEqual(before, after)

    def test_audit_mode_findings_reach_summary(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "findings"
            result = run_sysdiag(["--run", "harden", "--out", str(out)], env={"SYSDIAG_SCAN_ROOTS": tmp})
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            fails = [
                line.split("\t")[0]
                for line in status_file.read_text().splitlines()
                if line.strip() and line.split("\t")[1] == "FAIL"
            ]
            summary_file = out / "summary.json"
            self.assertTrue(summary_file.exists())
            summary = json.loads(summary_file.read_text())
            titles = [f.get("title", "") for f in summary.get("findings", [])]
            for ctrl in fails:
                self.assertTrue(
                    any(ctrl in title for title in titles),
                    f"FAIL status for '{ctrl}' had no finding in summary.json"
                )

    def test_progress_lines_on_stderr_and_quiet_suppresses(self):
        import re
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "prog"
            result = run_sysdiag(["--run", "tools", "--out", str(out)])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(re.search(r"^==> tools", result.stderr, re.M))
            self.assertIn("Report:", result.stdout)

            out_q = Path(tmp) / "quiet"
            result_q = run_sysdiag(["--run", "tools", "--quiet", "--out", str(out_q)])
            self.assertEqual(result_q.returncode, 0, result_q.stderr)
            self.assertNotIn("==> tools", result_q.stderr)
            self.assertIn("Report:", result_q.stdout)

    def test_list_packages_and_unknown_install(self):
        result = run_sysdiag(["--list-packages"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for pkg in ("guest_agent", "fail2ban", "logging", "firewall"):
            self.assertIn(pkg, result.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bad_pkg"
            result_bad = run_sysdiag(["--install", "bogus", "--run", "harden", "--out", str(out)])
            self.assertEqual(result_bad.returncode, 2)
            self.assertIn("unknown package group", result_bad.stderr)
            self.assertFalse(out.exists())

    def test_packages_extra_audit_never_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pkg_audit"
            result = run_sysdiag(["--run", "harden", "--controls", "packages_extra", "--install", "fail2ban,logging", "--out", str(out)])
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            self.assertTrue(status_file.exists())
            for line in status_file.read_text().splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                self.assertEqual(parts[0], "packages_extra")
                self.assertIn(parts[1], {"INFO", "NA"})
            plan_file = out / "evidence" / "hardening-plan.txt"
            self.assertIn("install", plan_file.read_text())
            self.assertFalse(Path("/etc/fail2ban/jail.d/99-sysdiag.local").exists())
    def test_file_scan_reports_world_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scan_root = tmp_path / "scanroot"
            scan_root.mkdir()
            ww_file = scan_root / "ww-file.txt"
            ww_file.write_text("probe")
            ww_file.chmod(0o666)
            out = tmp_path / "out"
            result = run_sysdiag(
                ["--run", "harden", "--controls", "file_scan", "--out", str(out)],
                env={"SYSDIAG_SCAN_ROOTS": str(scan_root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            self.assertTrue(status_file.exists())
            status_content = status_file.read_text()
            self.assertIn("file_scan\tFAIL", status_content)
            self.assertIn("1 world-writable", status_content)
            scan_file = out / "evidence" / "hardening-file-scan.txt"
            self.assertTrue(scan_file.exists())
            self.assertIn(str(ww_file), scan_file.read_text())

    def test_file_scan_clean_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scan_root = tmp_path / "scanroot"
            scan_root.mkdir()
            clean_file = scan_root / "clean-file.txt"
            clean_file.write_text("clean")
            clean_file.chmod(0o644)
            out = tmp_path / "out"
            result = run_sysdiag(
                ["--run", "harden", "--controls", "file_scan", "--out", str(out)],
                env={"SYSDIAG_SCAN_ROOTS": str(scan_root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status_file = out / "evidence" / "hardening-status.tsv"
            self.assertTrue(status_file.exists())
            self.assertIn("file_scan\tPASS", status_file.read_text())

    @unittest.skipUnless(shutil.which("timeout"), "requires timeout binary")
    def test_file_scan_timeout_reports_info_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = run_sysdiag(
                ["--run", "harden", "--controls", "file_scan", "--out", str(out)],
                env={"SYSDIAG_SCAN_ROOTS": "/", "SYSDIAG_FIND_TIMEOUT": "1"},
            )
            status_file = out / "evidence" / "hardening-status.tsv"
            self.assertTrue(status_file.exists())
            status_content = status_file.read_text()
            self.assertIn("file_scan\tINFO", status_content)
            self.assertNotIn("file_scan\tPASS", status_content)
            self.assertIn("timed out", status_content)

    def test_harden_run_cmd_propagates_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd = (
                f"SYSDIAG_LIB=1 . '{SCRIPT}'; "
                f"HARDEN_APPLY=1; EVIDENCE_DIR='{tmp}'; "
                "harden_run_cmd probe false; echo rc=$?"
            )
            proc = subprocess.run(
                ["bash", "-c", cmd],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertIn("rc=1", proc.stdout)
            actions_file = Path(tmp) / "hardening-actions.tsv"
            self.assertTrue(actions_file.exists())
            self.assertIn("command_failed", actions_file.read_text())

class RebootVerdictTests(unittest.TestCase):
    def _run_verdict(self, fixtures):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            evidence_dir = tmp_path / "evidence"
            evidence_dir.mkdir(parents=True)
            for fname, content in fixtures.items():
                (evidence_dir / fname).write_text(content)

            script_cmd = (
                f"SYSDIAG_LIB=1 . '{SCRIPT}'; "
                f"OUT_DIR='{tmp_path}'; "
                f"EVIDENCE_DIR='{evidence_dir}'; "
                f"REPORT_FILE='{tmp_path}/report.md'; "
                f"FINDINGS_TSV='{tmp_path}/findings.tsv'; "
                f"reboot_verdict; "
                f"cat '{evidence_dir}/reboot-verdict.txt'"
            )
            proc = subprocess.run(
                ["bash", "-c", script_cmd],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            verdict_lines = {}
            for line in proc.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    verdict_lines[k] = v
            return verdict_lines, proc.stdout

    def test_kernel_panic_verdict(self):
        fixtures = {
            "reboot-journal-prev-kernel.txt": "Kernel panic - not syncing: Fatal exception in interrupt\n",
            "reboot-kdump-status.txt": "kdump active\n/var/crash/2026-08-20/vmcore-dmesg.txt\n",
        }
        verdict, _ = self._run_verdict(fixtures)
        self.assertEqual(verdict.get("verdict"), "kernel-panic")
        self.assertEqual(verdict.get("confidence"), "high")

    def test_abrupt_reset_verdict(self):
        fixtures = {
            "reboot-wtmp-timeline.txt": "reboot   system boot  6.1.0-20-amd64   Mon Aug 20 10:00\nreboot   system boot  6.1.0-20-amd64   Mon Aug 19 10:00\n",
            "reboot-journal-prev-tail.txt": "Aug 20 09:59:00 host kernel: Normal operation\n",
        }
        verdict, _ = self._run_verdict(fixtures)
        self.assertEqual(verdict.get("verdict"), "abrupt-reset-power-or-hypervisor")

    def test_unknown_insufficient_evidence_verdict(self):
        fixtures = {
            "reboot-journal-persistence.txt": "no /var/log/journal (volatile journal)\n",
        }
        verdict, _ = self._run_verdict(fixtures)
        self.assertEqual(verdict.get("verdict"), "unknown-insufficient-evidence")
        self.assertEqual(verdict.get("confidence"), "low")


class BundleTests(unittest.TestCase):
    def test_bundle_creation_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = run_sysdiag(["--run", "tools", "--bundle", "--out", str(out)])
            self.assertEqual(result.returncode, 0, result.stderr)
            bundle_file = out / "bundle.md"
            self.assertTrue(bundle_file.exists())
            content = bundle_file.read_text()
            self.assertIn("# sysdiag bundle", content)
            self.assertIn("Redaction: on", content)

    def test_bundle_redaction_secrets_and_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir(parents=True)
            evidence = out / "evidence"
            evidence.mkdir(parents=True)
            probe = evidence / "zz-redact-probe.txt"
            probe.write_text("ssh-rsa AAAAB3Nz test\nhost 8.8.8.8\nlocal 192.168.1.1\n")

            cmd_redact = (
                f"SYSDIAG_LIB=1 . '{SCRIPT}'; "
                f"OUT_DIR='{out}'; EVIDENCE_DIR='{evidence}'; "
                f"REPORT_FILE='{out}/report.md'; FINDINGS_TSV='{out}/findings.tsv'; "
                f"SUMMARY_FILE='{out}/summary.json'; COMMAND_LOG='{out}/commands.log'; "
                f"METADATA_FILE='{out}/metadata.env'; "
                f"touch '{out}/report.md' '{out}/findings.tsv' '{out}/summary.json' '{out}/commands.log' '{out}/metadata.env'; "
                f"BUNDLE_REDACT=1 build_bundle"
            )
            proc = subprocess.run(["bash", "-c", cmd_redact], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            bundle_content = (out / "bundle.md").read_text()
            self.assertIn("[REDACTED SECRET LINE]", bundle_content)
            self.assertIn("8.8.x.x", bundle_content)
            self.assertIn("192.168.1.1", bundle_content)
            self.assertNotIn("AAAAB3Nz", bundle_content)
            self.assertNotIn("8.8.8.8", bundle_content)
            self.assertEqual(probe.read_text(), "ssh-rsa AAAAB3Nz test\nhost 8.8.8.8\nlocal 192.168.1.1\n")

            cmd_unredact = (
                f"SYSDIAG_LIB=1 . '{SCRIPT}'; "
                f"OUT_DIR='{out}'; EVIDENCE_DIR='{evidence}'; "
                f"REPORT_FILE='{out}/report.md'; FINDINGS_TSV='{out}/findings.tsv'; "
                f"SUMMARY_FILE='{out}/summary.json'; COMMAND_LOG='{out}/commands.log'; "
                f"METADATA_FILE='{out}/metadata.env'; "
                f"BUNDLE_REDACT=0 build_bundle"
            )
            proc2 = subprocess.run(["bash", "-c", cmd_unredact], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(proc2.returncode, 0, proc2.stderr)
            bundle_unredacted = (out / "bundle.md").read_text()
            self.assertIn("8.8.8.8", bundle_unredacted)


if __name__ == "__main__":
    unittest.main()
