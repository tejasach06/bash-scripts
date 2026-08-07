#!/usr/bin/env python3
# =============================================================================
# Filesystem Corruption RCA Log Collector for Ubuntu 22.04 on Proxmox
# =============================================================================
# Purpose: Collect comprehensive logs for filesystem corruption root cause analysis
# Output: Structured JSON + human-readable reports for easy LLM analysis
# Author: Generated for Tejas Acharya (tejasach06)
# =============================================================================

import subprocess
import json
import os
import sys
import tarfile
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# ─── Configuration ──────────────────────────────────────────────────────────
SCRIPT_VERSION = "1.0.0"
TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
HOSTNAME = platform.node().split('.')[0]
OUTPUT_DIR = Path(f"/tmp/fs-corruption-rca-{HOSTNAME}-{TIMESTAMP}")
JSON_OUTPUT = OUTPUT_DIR / "rca-data.json"
REPORT_OUTPUT = OUTPUT_DIR / "rca-report.txt"
ARCHIVE_NAME = f"fs-corruption-rca-{HOSTNAME}-{TIMESTAMP}.tar.gz"

# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def log_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")

def log_warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")

def log_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")

def log_ok(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.NC} {msg}")

def run_cmd(cmd: str, shell: bool = True) -> str:
    """Run command and return stdout+stderr combined."""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after 60s] {cmd}"
    except Exception as e:
        return f"[ERROR: {e}] {cmd}"

def run_cmd_list(cmd: List[str]) -> str:
    """Run command as list and return stdout+stderr combined."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after 60s] {' '.join(cmd)}"
    except Exception as e:
        return f"[ERROR: {e}] {' '.join(cmd)}"

# ─── Initialize ─────────────────────────────────────────────────────────────
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
log_info(f"Starting filesystem corruption RCA log collection")
log_info(f"Output directory: {OUTPUT_DIR}")
log_info(f"Hostname: {HOSTNAME} | Timestamp: {TIMESTAMP}")

# ─── Data Collection ────────────────────────────────────────────────────────
data: Dict[str, Any] = {
    "metadata": {
        "script_version": SCRIPT_VERSION,
        "timestamp": TIMESTAMP,
        "hostname": HOSTNAME,
        "kernel": platform.release(),
        "distro": "",
        "proxmox_vm": False
    },
    "filesystems": {},
    "smart": {},
    "kernel_logs": {},
    "journal_logs": {},
    "system_state": {},
    "proxmox": {},
    "corruption_indicators": {}
}

report_lines: List[str] = []

def add_report_section(title: str, content: str) -> None:
    report_lines.append(f"=== {title} ===")
    report_lines.append("")
    report_lines.append(content)
    report_lines.append("")

# Get distro
distro = run_cmd("lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'").strip()
data["metadata"]["distro"] = distro

# Check Proxmox VM
is_proxmox = False
cpuinfo = run_cmd("cat /proc/cpuinfo")
if "QEMU" in cpuinfo or "KVM" in cpuinfo:
    is_proxmox = True
dmi_product = run_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null").lower()
if any(x in dmi_product for x in ["proxmox", "qemu", "kvm"]):
    is_proxmox = True
data["metadata"]["proxmox_vm"] = is_proxmox

# ─── Section 1: Filesystem Overview ─────────────────────────────────────────
log_info("[1/8] Collecting filesystem overview...")

df_human = run_cmd("df -hT")
df_inodes = run_cmd("df -i")
df_structured = run_cmd("df --output=source,fstype,size,used,avail,pcent,target")
lsblk_f = run_cmd("lsblk -f")
findmnt_root = run_cmd("findmnt -T /")
fstab = run_cmd("cat /etc/fstab")
mount_out = run_cmd("mount")

add_report_section("FILESYSTEM OVERVIEW", "\n".join([
    "--- df -hT ---", df_human,
    "--- df -i ---", df_inodes,
    "--- df --output=source,fstype,size,used,avail,pcent,target ---", df_structured,
    "--- lsblk -f ---", lsblk_f,
    "--- findmnt -T / ---", findmnt_root,
    "--- /etc/fstab ---", fstab,
    "--- mount ---", mount_out
]))

# Parse structured df for JSON
df_lines = df_structured.strip().split('\n')
if len(df_lines) > 1:
    df_data = []
    for line in df_lines[1:]:
        parts = line.split()
        if len(parts) >= 7:
            df_data.append({
                "device": parts[0],
                "fstype": parts[1],
                "size_kb": parts[2],
                "used_kb": parts[3],
                "avail_kb": parts[4],
                "use_pct": parts[5],
                "mountpoint": parts[6]
            })
    data["filesystems"]["df"] = df_data

# lsblk JSON
lsblk_json = run_cmd("lsblk -J -o NAME,FSTYPE,LABEL,MOUNTPOINT,SIZE,TYPE,MODEL,SERIAL 2>/dev/null")
try:
    data["filesystems"]["lsblk"] = json.loads(lsblk_json).get("blockdevices", [])
except:
    data["filesystems"]["lsblk"] = []

# ─── Section 2: SMART & Disk Health ─────────────────────────────────────────
log_info("[2/8] Collecting SMART data and disk health...")

smart_data = {}
smart_report_parts = []

disks = run_cmd("lsblk -dn -o NAME | grep -v loop").strip().split('\n')
for disk in disks:
    if not disk:
        continue
    dev = f"/dev/{disk}"
    smart_report_parts.append(f"--- SMART for {dev} ---")
    
    # Human readable
    smart_human = run_cmd(f"smartctl -a {dev} 2>&1")
    smart_report_parts.append(smart_human)
    
    # JSON for parsing
    smart_json = run_cmd(f"smartctl -a -j {dev} 2>&1")
    try:
        smart_data[dev] = json.loads(smart_json)
    except:
        smart_data[dev] = {"raw_output": smart_human}

# NVMe
nvme_devices = run_cmd("ls /dev/nvme*n1 2>/dev/null").strip().split('\n')
for nvme in nvme_devices:
    if nvme and os.path.exists(nvme):
        smart_report_parts.append(f"--- nvme smart-log {nvme} ---")
        smart_report_parts.append(run_cmd(f"nvme smart-log {nvme} 2>&1"))

# badblocks (sample)
smart_report_parts.append("--- badblocks quick scan (read-only, sample) ---")
for disk in disks:
    if not disk:
        continue
    dev = f"/dev/{disk}"
    smart_report_parts.append(run_cmd(f"badblocks -v -s -n {dev} 2>&1 | head -20"))

add_report_section("SMART & DISK HEALTH", "\n".join(smart_report_parts))
data["smart"] = smart_data

# ─── Section 3: Kernel Logs (dmesg) ─────────────────────────────────────────
log_info("[3/8] Collecting kernel logs (dmesg)...")

dmesg_full = run_cmd("dmesg -T 2>&1")
dmesg_errors = run_cmd("dmesg -T -l err,crit,alert,emerg 2>&1")
dmesg_fs = run_cmd("dmesg -T 2>&1 | grep -iE 'ext4|xfs|btrfs|fsck|corrupt|error|fail|i/o|read.only|remount|superblock|inode|journal'")
dmesg_disk = run_cmd("dmesg -T 2>&1 | grep -iE 'sd|nvme|scsi|ata|block' | head -100")

add_report_section("KERNEL LOGS (dmesg)", "\n".join([
    "--- dmesg -T (full, timestamped) ---", dmesg_full,
    "--- dmesg -T -l err,crit,alert,emerg (errors only) ---", dmesg_errors,
    "--- dmesg -T | grep -iE FS keywords ---", dmesg_fs or "No matches",
    "--- dmesg -T | grep -iE disk keywords | head -100 ---", dmesg_disk
]))

data["kernel_logs"] = {
    "dmesg_full": dmesg_full,
    "dmesg_errors": dmesg_errors,
    "dmesg_fs_related": dmesg_fs,
    "dmesg_disk_related": dmesg_disk
}

# ─── Section 4: Journal Logs (systemd) ──────────────────────────────────────
log_info("[4/8] Collecting journal logs...")

j_cur = run_cmd("journalctl -b -0 -p err..alert --no-pager 2>&1")
j_prev = run_cmd("journalctl -b -1 -p err..alert --no-pager 2>&1")
j_fsck = run_cmd("journalctl -b -0 -u systemd-fsck* --no-pager 2>&1")
j_fs = run_cmd("journalctl -b -0 -k -g 'ext4|xfs|btrfs|corrupt|i/o error|read.only|remount' --no-pager 2>&1")
j_fail = run_cmd("journalctl -b -0 -k -g 'FAIL|ERROR|CORRUPT' --no-pager 2>&1 | head -200")

add_report_section("JOURNAL LOGS (systemd)", "\n".join([
    "--- journalctl -b -0 -p err..alert (current boot) ---", j_cur,
    "--- journalctl -b -1 -p err..alert (previous boot) ---", j_prev,
    "--- journalctl -b -0 -u systemd-fsck* ---", j_fsck,
    "--- journalctl -b -0 -k -g FS keywords ---", j_fs,
    "--- journalctl -b -0 -k -g FAIL|ERROR|CORRUPT ---", j_fail
]))

data["journal_logs"] = {
    "current_boot_errors": j_cur,
    "previous_boot_errors": j_prev,
    "fsck_units": j_fsck,
    "kernel_fs_messages": j_fs,
    "fail_error_corrupt": j_fail
}

# ─── Section 5: Filesystem-Specific Diagnostics ─────────────────────────────
log_info("[5/8] Collecting filesystem-specific diagnostics...")

fs_diag_parts = []

# ext4
ext4_parts = run_cmd("lsblk -ln -o NAME,FSTYPE | awk '$2==\"ext4\"{print \"/dev/\"$1}'").strip().split('\n')
for part in ext4_parts:
    if not part:
        continue
    fs_diag_parts.append(f"--- ext4: dumpe2fs -h {part} ---")
    fs_diag_parts.append(run_cmd(f"dumpe2fs -h {part} 2>&1"))
    fs_diag_parts.append(f"--- ext4: tune2fs -l {part} ---")
    fs_diag_parts.append(run_cmd(f"tune2fs -l {part} 2>&1"))
    fs_diag_parts.append(f"--- ext4: fsck -n {part} (dry-run) ---")
    fs_diag_parts.append(run_cmd(f"fsck -n {part} 2>&1"))
    fs_diag_parts.append(f"--- ext4: debugfs -R 'stats' {part} ---")
    fs_diag_parts.append(run_cmd(f"debugfs -R 'stats' {part} 2>&1"))

# XFS
xfs_parts = run_cmd("lsblk -ln -o NAME,FSTYPE | awk '$2==\"xfs\"{print \"/dev/\"$1}'").strip().split('\n')
for part in xfs_parts:
    if not part:
        continue
    fs_diag_parts.append(f"--- XFS: xfs_info {part} ---")
    fs_diag_parts.append(run_cmd(f"xfs_info {part} 2>&1"))
    fs_diag_parts.append(f"--- XFS: xfs_repair -n {part} (dry-run) ---")
    fs_diag_parts.append(run_cmd(f"xfs_repair -n {part} 2>&1"))
    fs_diag_parts.append(f"--- XFS: xfs_db -r -c 'freesp' {part} ---")
    fs_diag_parts.append(run_cmd(f"xfs_db -r -c 'freesp' {part} 2>&1"))

# Btrfs
btrfs_parts = run_cmd("lsblk -ln -o NAME,FSTYPE | awk '$2==\"btrfs\"{print \"/dev/\"$1}'").strip().split('\n')
for part in btrfs_parts:
    if not part:
        continue
    fs_diag_parts.append(f"--- Btrfs: btrfs filesystem usage {part} ---")
    fs_diag_parts.append(run_cmd(f"btrfs filesystem usage {part} 2>&1"))
    fs_diag_parts.append(f"--- Btrfs: btrfs device stats {part} ---")
    fs_diag_parts.append(run_cmd(f"btrfs device stats {part} 2>&1"))
    fs_diag_parts.append(f"--- Btrfs: btrfs scrub status {part} ---")
    fs_diag_parts.append(run_cmd(f"btrfs scrub status {part} 2>&1"))

# ZFS
if run_cmd("command -v zpool").strip():
    fs_diag_parts.append("--- ZFS: zpool status -v ---")
    fs_diag_parts.append(run_cmd("zpool status -v 2>&1"))
    fs_diag_parts.append("--- ZFS: zpool list -v ---")
    fs_diag_parts.append(run_cmd("zpool list -v 2>&1"))

add_report_section("FILESYSTEM-SPECIFIC DIAGNOSTICS", "\n".join(fs_diag_parts))

# ─── Section 6: System State & Config ──────────────────────────────────────
log_info("[6/8] Collecting system state and configuration...")

sys_parts = []
sys_parts.append("--- uname -a ---")
sys_parts.append(run_cmd("uname -a"))
sys_parts.append("--- cat /proc/version ---")
sys_parts.append(run_cmd("cat /proc/version"))
sys_parts.append("--- cat /proc/mdstat ---")
sys_parts.append(run_cmd("cat /proc/mdstat"))
sys_parts.append("--- lscpu ---")
sys_parts.append(run_cmd("lscpu"))
sys_parts.append("--- free -h ---")
sys_parts.append(run_cmd("free -h"))
sys_parts.append("--- cat /proc/meminfo ---")
sys_parts.append(run_cmd("cat /proc/meminfo"))
sys_parts.append("--- sysctl -a | grep -iE 'vm.dirty|vm.swappiness|fs.inotify|kernel.panic' ---")
sys_parts.append(run_cmd("sysctl -a 2>/dev/null | grep -iE 'vm.dirty|vm.swappiness|fs.inotify|kernel.panic'"))
sys_parts.append("--- cat /etc/sysctl.d/* ---")
sys_parts.append(run_cmd("cat /etc/sysctl.d/* 2>/dev/null"))
sys_parts.append("--- systemctl list-units --state=failed ---")
sys_parts.append(run_cmd("systemctl list-units --state=failed --no-pager 2>&1"))
sys_parts.append("--- uptime ---")
sys_parts.append(run_cmd("uptime"))
sys_parts.append("--- last -x shutdown reboot | head -20 ---")
sys_parts.append(run_cmd("last -x shutdown reboot 2>&1 | head -20"))
sys_parts.append("--- /var/log/syslog (last 500 lines) ---")
sys_parts.append(run_cmd("tail -500 /var/log/syslog 2>/dev/null || tail -500 /var/log/messages 2>/dev/null"))
sys_parts.append("--- /var/log/kern.log (last 500 lines) ---")
sys_parts.append(run_cmd("tail -500 /var/log/kern.log 2>/dev/null"))

add_report_section("SYSTEM STATE & CONFIGURATION", "\n".join(sys_parts))

data["system_state"] = {
    "uname": run_cmd("uname -a"),
    "proc_version": run_cmd("cat /proc/version"),
    "proc_mdstat": run_cmd("cat /proc/mdstat"),
    "lscpu": run_cmd("lscpu"),
    "free_h": run_cmd("free -h"),
    "proc_meminfo": run_cmd("cat /proc/meminfo"),
    "sysctl_fs_vm": run_cmd("sysctl -a 2>/dev/null | grep -iE 'vm.dirty|vm.swappiness|fs.inotify|kernel.panic'"),
    "sysctl_d": run_cmd("cat /etc/sysctl.d/* 2>/dev/null"),
    "failed_units": run_cmd("systemctl list-units --state=failed --no-pager 2>&1"),
    "uptime": run_cmd("uptime"),
    "reboot_history": run_cmd("last -x shutdown reboot 2>&1 | head -20"),
    "syslog_tail": run_cmd("tail -500 /var/log/syslog 2>/dev/null || tail -500 /var/log/messages 2>/dev/null"),
    "kernlog_tail": run_cmd("tail -500 /var/log/kern.log 2>/dev/null")
}

# ─── Section 7: Proxmox-Specific Info ───────────────────────────────────────
log_info("[7/8] Collecting Proxmox-specific information...")

prox_parts = []
prox_parts.append("--- DMI Info (VM detection) ---")
prox_parts.append(run_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null"))
prox_parts.append(run_cmd("cat /sys/class/dmi/id/product_version 2>/dev/null"))
prox_parts.append(run_cmd("cat /sys/class/dmi/id/bios_vendor 2>/dev/null"))
prox_parts.append(run_cmd("cat /sys/class/dmi/id/sys_vendor 2>/dev/null"))
prox_parts.append("--- CPU Info (hypervisor detection) ---")
prox_parts.append(run_cmd("grep -i hypervisor /proc/cpuinfo | head -1"))
prox_parts.append(run_cmd("lscpu | grep -i hypervisor"))
prox_parts.append("--- Virt-what ---")
prox_parts.append(run_cmd("virt-what 2>/dev/null"))
prox_parts.append("--- /proc/scsi/scsi (SCSI devices) ---")
prox_parts.append(run_cmd("cat /proc/scsi/scsi 2>/dev/null"))
prox_parts.append("--- ls -la /dev/disk/by-id/ (disk identifiers) ---")
prox_parts.append(run_cmd("ls -la /dev/disk/by-id/ 2>/dev/null"))
prox_parts.append("--- Proxmox guest agent (if installed) ---")
prox_parts.append(run_cmd("systemctl status qemu-guest-agent 2>&1"))
prox_parts.append(run_cmd("qm-agent get-fsinfo 2>/dev/null"))

add_report_section("PROXMOX-SPECIFIC INFO", "\n".join(prox_parts))

data["proxmox"] = {
    "dmi_product_name": run_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null").strip(),
    "dmi_product_version": run_cmd("cat /sys/class/dmi/id/product_version 2>/dev/null").strip(),
    "dmi_bios_vendor": run_cmd("cat /sys/class/dmi/id/bios_vendor 2>/dev/null").strip(),
    "cpuinfo_hypervisor": run_cmd("grep -i hypervisor /proc/cpuinfo | head -1").strip(),
    "virt_what": run_cmd("virt-what 2>/dev/null").strip(),
    "proc_scsi": run_cmd("cat /proc/scsi/scsi 2>/dev/null").strip(),
    "disk_by_id": run_cmd("ls -la /dev/disk/by-id/ 2>/dev/null").strip(),
    "guest_agent_status": run_cmd("systemctl status qemu-guest-agent 2>&1").strip(),
    "guest_agent_fsinfo": run_cmd("qm-agent get-fsinfo 2>/dev/null").strip()
}

# ─── Section 8: Corruption Indicators Summary ───────────────────────────────
log_info("[8/8] Generating corruption indicators summary...")

ci_parts = []
ci_parts.append("--- Filesystem read-only remounts (from dmesg) ---")
ci_ro = run_cmd("dmesg -T | grep -i 'remount.*read.only'")
ci_parts.append(ci_ro if ci_ro.strip() else "None found")

ci_parts.append("--- I/O errors (from dmesg) ---")
ci_io = run_cmd("dmesg -T | grep -i 'i/o error'")
ci_parts.append(ci_io if ci_io.strip() else "None found")

ci_parts.append("--- Filesystem corruption messages ---")
ci_corrupt = run_cmd("dmesg -T | grep -iE 'corrupt|filesystem error|ext4_error|xfs_error|btrfs_error'")
ci_parts.append(ci_corrupt if ci_corrupt.strip() else "None found")

ci_parts.append("--- Superblock/inode errors ---")
ci_super = run_cmd("dmesg -T | grep -iE 'superblock|inode.*error|inode.*corrupt'")
ci_parts.append(ci_super if ci_super.strip() else "None found")

ci_parts.append("--- Journal/fsck related ---")
ci_journal = run_cmd("journalctl -b -0 -k -g 'fsck|recovery|replay|journal' --no-pager 2>&1 | head -50")
ci_parts.append(ci_journal if ci_journal.strip() else "None found")

ci_parts.append("--- Disk SMART critical attributes ---")
smart_critical = []
for disk in disks:
    if not disk:
        continue
    dev = f"/dev/{disk}"
    out = run_cmd(f"smartctl -A {dev} 2>/dev/null | awk '/Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|UDMA_CRC_Error_Count|End-to-End_Error|Command_Timeout|High_Fly_Writes/ {{print \"{dev}: \" $0}}'")
    if out.strip():
        smart_critical.append(out.strip())
ci_parts.append("\n".join(smart_critical) if smart_critical else "None found")

ci_parts.append("--- Lost+found contents (recovery artifacts) ---")
lostfound = []
mnt_output = run_cmd("findmnt -rn -o TARGET -t ext4,xfs,btrfs")
for mp in mnt_output.strip().split('\n'):
    if mp and os.path.exists(f"{mp}/lost+found"):
        lostfound.append(f"Mountpoint: {mp}")
        lostfound.append(run_cmd(f"ls -la {mp}/lost+found 2>/dev/null"))
ci_parts.append("\n".join(lostfound) if lostfound else "None found")

add_report_section("CORRUPTION INDICATORS SUMMARY", "\n".join(ci_parts))

data["corruption_indicators"] = {
    "read_only_remounts": ci_ro.strip() or "None found",
    "io_errors": ci_io.strip() or "None found",
    "corruption_messages": ci_corrupt.strip() or "None found",
    "superblock_inode_errors": ci_super.strip() or "None found",
    "journal_fsck_related": ci_journal.strip() or "None found",
    "smart_critical_attributes": "\n".join(smart_critical) if smart_critical else "None found",
    "lostfound_contents": "\n".join(lostfound) if lostfound else "None found"
}

# ─── Write Outputs ──────────────────────────────────────────────────────────
log_info("Writing JSON output...")
with open(JSON_OUTPUT, 'w') as f:
    json.dump(data, f, indent=2)

log_info("Writing human-readable report...")
with open(REPORT_OUTPUT, 'w') as f:
    f.write("\n".join(report_lines))

# ─── Create Archive ─────────────────────────────────────────────────────────
log_info("Creating archive...")
archive_path = Path("/tmp") / ARCHIVE_NAME
with tarfile.open(archive_path, "w:gz") as tar:
    tar.add(OUTPUT_DIR, arcname=OUTPUT_DIR.name)

log_ok(f"Archive created: {archive_path}")

# ─── Summary ────────────────────────────────────────────────────────────────
print()
print("┌─────────────────────────────────────────────────────────────────────┐")
print("│  FILESYSTEM CORRUPTION RCA COLLECTION SUMMARY                      │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│  Output directory: {OUTPUT_DIR}")
print(f"│  Archive:          {archive_path}")
print(f"│  Human report:     {REPORT_OUTPUT}")
print(f"│  JSON data:        {JSON_OUTPUT}")
print("├─────────────────────────────────────────────────────────────────────┤")
print("│  Contents:")
print("│  • Filesystem overview (df, lsblk, fstab, mount)")
print("│  • SMART data for all disks (JSON + raw)")
print("│  • Kernel logs (dmesg full, errors, FS-related)")
print("│  • Journal logs (current/prev boot errors, fsck, kernel FS msgs)")
print("│  • FS-specific diagnostics (ext4/xfs/btrfs/zfs tools)")
print("│  • System state (kernel, CPU, memory, sysctl, failed units)")
print("│  • Proxmox VM info (DMI, hypervisor, disk IDs, guest agent)")
print("│  • Corruption indicators summary (RO remounts, I/O errors, etc.)")
print("└─────────────────────────────────────────────────────────────────────┘")
print()
log_info("Next steps:")
print(f"  1. Copy archive from VM: scp user@vm:{archive_path} .")
print(f"  2. Share JSON file ({JSON_OUTPUT}) for structured analysis")
print(f"  3. Share human report ({REPORT_OUTPUT}) for quick reading")
print("  4. Run this script again after any remediation to compare")