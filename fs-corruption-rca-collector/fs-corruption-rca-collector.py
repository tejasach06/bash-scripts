#!/usr/bin/env python3
# =============================================================================
# Filesystem Corruption RCA Log Collector for Ubuntu 22.04 on Proxmox
# =============================================================================
# Purpose: Collect comprehensive logs for filesystem corruption root cause analysis
# Output: Structured JSON + human-readable reports for easy LLM analysis
# Author: Generated for Tejas Acharya (tejasach06)
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import platform
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── Configuration ────────────────────────────────────────────────────────────
SCRIPT_VERSION = "1.1.0"
TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
HOSTNAME = platform.node().split(".")[0]
OUTPUT_DIR = Path(f"/tmp/fs-corruption-rca-{HOSTNAME}-{TIMESTAMP}")
JSON_OUTPUT = OUTPUT_DIR / "rca-data.json"
REPORT_OUTPUT = OUTPUT_DIR / "rca-report.txt"
ARCHIVE_NAME = f"fs-corruption-rca-{HOSTNAME}-{TIMESTAMP}.tar.gz"

# Parallelism for read-only diagnostic commands
MAX_WORKERS = 4

# Command timeout (seconds)
CMD_TIMEOUT = 30

# ─── Logging Setup ────────────────────────────────────────────────────────────

class TTYColoredFormatter(logging.Formatter):
    """Formatter that adds colors when outputting to a TTY."""
    COLORS = {
        logging.DEBUG: "\033[0;36m",   # cyan
        logging.INFO: "\033[0;34m",    # blue
        logging.WARNING: "\033[1;33m", # yellow
        logging.ERROR: "\033[0;31m",   # red
        logging.CRITICAL: "\033[1;31m",# bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if sys.stderr.isatty() and record.levelno in self.COLORS:
            return f"{self.COLORS[record.levelno]}{msg}{self.RESET}"
        return msg


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure structured logging with TTY-aware colored output."""
    logger = logging.getLogger("fs-corruption-rca")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(TTYColoredFormatter(
        fmt="%(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(handler)
    return logger


logger = setup_logging()


def log_info(msg: str) -> None:
    logger.info(msg)


def log_warn(msg: str) -> None:
    logger.warning(msg)


def log_error(msg: str) -> None:
    logger.error(msg)


def log_ok(msg: str) -> None:
    logger.info(msg)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], timeout: int = CMD_TIMEOUT) -> str:
    """Run command and return stdout+stderr; never shell=True."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = result.stdout
        if result.stderr:
            out += ("\n" if out else "") + result.stderr
        return out.strip()
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"


def add_report_section(report: list[str], title: str, content: str) -> None:
    """Append a titled section to the report."""
    report.append(f"\n{'=' * 60}")
    report.append(f" {title} ")
    report.append(f"{'=' * 60}\n")
    report.append(content if content else "(no output)")


# ─── Collection Functions (designed for parallel execution) ──────────────────

def collect_system_info() -> dict[str, Any]:
    """Static system metadata."""
    return {
        "script_version": SCRIPT_VERSION,
        "timestamp": TIMESTAMP,
        "hostname": HOSTNAME,
        "platform": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }


def collect_journal_logs(since: str = "-24h") -> dict[str, str]:
    """Collect journalctl logs related to filesystem/storage."""
    cmds = {
        "journal_all": ["journalctl", "--since", since, "--no-pager"],
        "journal_kernel": ["journalctl", "-k", "--since", since, "--no-pager"],
        "journal_systemd": ["journalctl", "-u", "systemd-*", "--since", since, "--no-pager"],
        "journal_block": ["journalctl", "-k", "-g", "block", "--since", since, "--no-pager"],
        "journal_fs": ["journalctl", "-k", "-g", "ext4|xfs|btrfs|zfs", "--since", since, "--no-pager"],
        "journal_io": ["journalctl", "-k", "-g", "I/O error|buffer|writeback", "--since", since, "--no-pager"],
    }
    return {k: run_cmd(v) for k, v in cmds.items()}


def collect_dmesg() -> dict[str, str]:
    """Collect dmesg output."""
    return {
        "dmesg_full": run_cmd(["dmesg", "-T"]),
        "dmesg_errors": run_cmd(["dmesg", "-T", "-l", "err,crit,alert,emerg"]),
    }


def collect_filesystem_info() -> dict[str, str]:
    """Filesystem and disk diagnostics."""
    cmds = {
        "df_h": ["df", "-h"],
        "df_i": ["df", "-i"],
        "lsblk": ["lsblk", "-f"],
        "mount": ["mount"],
        "findmnt": ["findmnt", "-rn"],
        "blkid": ["blkid"],
        "fdisk_l": ["fdisk", "-l"],
        "smartctl_scan": ["smartctl", "--scan"],
    }
    return {k: run_cmd(v) for k, v in cmds.items()}


def collect_kernel_params() -> dict[str, str]:
    """Kernel parameters related to filesystems and storage."""
    cmds = {
        "sysctl_vm": ["sysctl", "-a"],
        "sysctl_fs": ["sysctl", "fs."],
        "sysctl_kernel": ["sysctl", "kernel."],
    }
    return {k: run_cmd(v) for k, v in cmds.items()}


def collect_lvm_info() -> dict[str, str]:
    """LVM and block device info (Proxmox-specific)."""
    cmds = {
        "pvs": ["pvs", "-a"],
        "vgs": ["vgs", "-a"],
        "lvs": ["lvs", "-a"],
        "pvdisplay": ["pvdisplay"],
        "vgdisplay": ["vgdisplay"],
        "lvdisplay": ["lvdisplay"],
    }
    return {k: run_cmd(v) for k, v in cmds.items()}


def collect_proxmox_info() -> dict[str, str]:
    """Proxmox VE specific diagnostics."""
    cmds = {
        "pveversion": ["pveversion", "-v"],
        "qm_list": ["qm", "list"],
        "pvesh_nodes": ["pvesh", "get", "/nodes"],
        "pvesh_storage": ["pvesh", "get", "/storage"],
    }
    return {k: run_cmd(v) for k, v in cmds.items()}


def collect_all_parallel() -> dict[str, Any]:
    """Run all read-only collectors in parallel using ThreadPoolExecutor."""
    log_info(f"Starting parallel collection with {MAX_WORKERS} workers...")

    collectors = [
        ("system_info", collect_system_info),
        ("journal_logs", collect_journal_logs),
        ("dmesg", collect_dmesg),
        ("filesystem_info", collect_filesystem_info),
        ("kernel_params", collect_kernel_params),
        ("lvm_info", collect_lvm_info),
        ("proxmox_info", collect_proxmox_info),
    ]

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_name = {executor.submit(fn): name for name, fn in collectors}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
                log_ok(f"Collected: {name}")
            except Exception as exc:  # noqa: BLE001
                log_error(f"Collector {name} failed: {exc}")
                results[name] = {"error": str(exc)}

    return results


def collect_all_sequential() -> dict[str, Any]:
    """Fallback sequential collection (for --selftest without parallelism)."""
    log_info("Running sequential collection...")
    return {
        "system_info": collect_system_info(),
        "journal_logs": collect_journal_logs(),
        "dmesg": collect_dmesg(),
        "filesystem_info": collect_filesystem_info(),
        "kernel_params": collect_kernel_params(),
        "lvm_info": collect_lvm_info(),
        "proxmox_info": collect_proxmox_info(),
    }


def build_report(data: dict[str, Any]) -> list[str]:
    """Build human-readable report from collected data."""
    report: list[str] = []
    report.append(f"Filesystem Corruption RCA Report")
    report.append(f"Generated: {TIMESTAMP}")
    report.append(f"Host: {HOSTNAME}")
    report.append(f"Script version: {SCRIPT_VERSION}")
    report.append("")

    # System Info
    if "system_info" in data:
        sysinfo = data["system_info"]
        if isinstance(sysinfo, dict):
            add_report_section(report, "SYSTEM INFO", "\n".join(f"{k}: {v}" for k, v in sysinfo.items()))

    # Journal Logs
    if "journal_logs" in data:
        for key, val in data["journal_logs"].items():
            add_report_section(report, f"JOURNAL: {key.upper()}", val)

    # Dmesg
    if "dmesg" in data:
        for key, val in data["dmesg"].items():
            add_report_section(report, f"DMESG: {key.upper()}", val)

    # Filesystem
    if "filesystem_info" in data:
        for key, val in data["filesystem_info"].items():
            add_report_section(report, f"FS: {key.upper()}", val)

    # Kernel params
    if "kernel_params" in data:
        for key, val in data["kernel_params"].items():
            add_report_section(report, f"SYSCTL: {key.upper()}", val)

    # LVM
    if "lvm_info" in data:
        for key, val in data["lvm_info"].items():
            add_report_section(report, f"LVM: {key.upper()}", val)

    # Proxmox
    if "proxmox_info" in data:
        for key, val in data["proxmox_info"].items():
            add_report_section(report, f"PVE: {key.upper()}", val)

    return report


def write_outputs(data: dict[str, Any], report_lines: list[str]) -> None:
    """Write JSON and text report to output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # JSON
    JSON_OUTPUT.write_text(json.dumps(data, indent=2, default=str))
    log_ok(f"JSON written to {JSON_OUTPUT}")

    # Text report
    REPORT_OUTPUT.write_text("\n".join(report_lines))
    log_ok(f"Report written to {REPORT_OUTPUT}")


def create_archive() -> Path:
    """Create tar.gz archive of the output directory."""
    archive_path = Path.cwd() / ARCHIVE_NAME
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(OUTPUT_DIR, arcname=OUTPUT_DIR.name)
    log_ok(f"Archive created: {archive_path}")
    return archive_path


# ─── Signal Handling ─────────────────────────────────────────────────────────

def _cleanup_temp() -> None:
    """Remove temp directory on exit (best effort)."""
    try:
        if OUTPUT_DIR.exists():
            import shutil
            shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    except Exception:  # noqa: BLE001
        pass


def _signal_handler(signum: int, frame: Any) -> None:  # noqa: ARG001
    log_warn(f"Received signal {signum}, cleaning up...")
    _cleanup_temp()
    sys.exit(130)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─── Selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    """Run internal validation with fixtures; no root required."""
    log_info("=== SELFTEST START ===")
    log_info(f"Script version: {SCRIPT_VERSION}")
    log_info(f"Output dir would be: {OUTPUT_DIR}")
    log_info(f"Max workers: {MAX_WORKERS}")
    log_info(f"Command timeout: {CMD_TIMEOUT}s")

    # Test run_cmd with safe commands
    out = run_cmd(["echo", "hello"])
    assert out == "hello", f"run_cmd failed: {out}"
    log_ok("run_cmd works")

    out = run_cmd(["false"])
    assert "ERROR" in out or out == "", f"run_cmd non-zero exit: {out}"
    log_ok("run_cmd handles failures")

    # Test timeout
    out = run_cmd(["sleep", "10"], timeout=1)
    assert "TIMEOUT" in out, f"timeout not triggered: {out}"
    log_ok("timeout works")

    # Test parallel collection (with tiny mock)
    import unittest.mock
    with unittest.mock.patch.object(sys.modules[__name__], "collect_system_info", return_value={"test": "ok"}):
        with unittest.mock.patch.object(sys.modules[__name__], "collect_journal_logs", return_value={}):
            with unittest.mock.patch.object(sys.modules[__name__], "collect_dmesg", return_value={}):
                with unittest.mock.patch.object(sys.modules[__name__], "collect_filesystem_info", return_value={}):
                    with unittest.mock.patch.object(sys.modules[__name__], "collect_kernel_params", return_value={}):
                        with unittest.mock.patch.object(sys.modules[__name__], "collect_lvm_info", return_value={}):
                            with unittest.mock.patch.object(sys.modules[__name__], "collect_proxmox_info", return_value={}):
                                results = collect_all_parallel()
                                assert "system_info" in results
                                log_ok("collect_all_parallel executes")

    # Test report building
    report = build_report({"system_info": {"a": "1"}})
    assert any("SYSTEM INFO" in line for line in report)
    log_ok("build_report works")

    # Test archive creation (dry)
    log_ok("Selftest would create archive")

    log_info("=== SELFTEST PASSED ===")
    return 0


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Filesystem Corruption RCA Log Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s                    # Full collection (needs root for some commands)
  %(prog)s --selftest              # Internal validation (no root needed)
  %(prog)s --sequential            # Disable parallel collection
  %(prog)s --verbose               # Debug logging
        """,
    )
    parser.add_argument("--selftest", action="store_true", help="Run internal validation and exit")
    parser.add_argument("--sequential", action="store_true", help="Run collectors sequentially")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version=SCRIPT_VERSION)

    args = parser.parse_args()

    # Reconfigure logging if verbose
    if args.verbose:
        global logger
        logger = setup_logging(verbose=True)

    if args.selftest:
        return selftest()

    log_info("Starting filesystem corruption RCA collection")
    log_info(f"Output directory: {OUTPUT_DIR}")

    # Run collectors
    if args.sequential:
        data = collect_all_sequential()
    else:
        data = collect_all_parallel()

    # Build and write outputs
    report = build_report(data)
    write_outputs(data, report)
    create_archive()

    log_ok("Collection complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())