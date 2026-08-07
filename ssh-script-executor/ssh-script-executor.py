#!/usr/bin/env python3
"""
ssh-script-executor.py - Execute local scripts on remote hosts via SSH

Features:
- Cross-platform (macOS + Linux)
- Execute local script files on remote hosts via SSH
- Support for script arguments and stdin
- Connection reuse (ControlMaster) for speed
- Parallel execution with configurable concurrency
- CSV/JSON output for automation
- Dry-run mode for safety
- Colored output with verbosity levels
- Self-test suite

Usage:
    ./ssh-script-executor.py --host user@host --script ./script.sh --args "arg1 arg2"
    ./ssh-script-executor.py --host-file hosts.txt --script ./deploy.sh --parallel 4
    ./ssh-script-executor.py --host user@host --script ./setup.sh --dry-run
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import shutil
import signal
import sys
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from typing import Optional, List


# ──────────────────────────────────────────────────────────────────────────────
# Constants & Types
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
SCRIPT_NAME = "ssh-script-executor"

# Colors (only on TTY)
COLORS = {
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "BLUE": "\033[34m",
    "MAGENTA": "\033[35m",
    "CYAN": "\033[36m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}


@dataclass
class HostResult:
    """Result of executing script on a single host."""
    host: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def to_csv_row(self) -> list[str]:
        return [
            self.host,
            str(self.success),
            str(self.exit_code),
            self.stdout[:500],  # truncate for CSV
            self.stderr[:500],
            f"{self.duration_sec:.3f}",
            self.error,
            self.timestamp,
        ]

    @staticmethod
    def csv_header() -> list[str]:
        return ["host", "success", "exit_code", "stdout", "stderr", "duration_sec", "error", "timestamp"]


@dataclass
class HostConfig:
    """Configuration for a single host."""
    host: str
    port: int = 22
    user: str = ""
    key_file: str = ""
    timeout: int = 30
    control_master: bool = True
    passwords: list[str] = field(default_factory=list)  # List of passwords to try (fallback)
    password_file: str = ""  # Path to file with passwords (one per line)


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

class Log:
    verbose = False
    quiet = False
    use_color = sys.stdout.isatty()

    @classmethod
    def _color(cls, color: str, msg: str) -> str:
        if cls.use_color:
            return f"{COLORS.get(color, '')}{msg}{COLORS['RESET']}"
        return msg

    @classmethod
    def debug(cls, msg: str) -> None:
        if cls.verbose:
            print(cls._color("CYAN", f"[DEBUG] {msg}"), file=sys.stderr)

    @classmethod
    def info(cls, msg: str) -> None:
        if not cls.quiet:
            print(cls._color("BLUE", f"[INFO] {msg}"), file=sys.stderr)

    @classmethod
    def ok(cls, msg: str) -> None:
        if not cls.quiet:
            print(cls._color("GREEN", f"[OK] {msg}"), file=sys.stderr)

    @classmethod
    def warn(cls, msg: str) -> None:
        if not cls.quiet:
            print(cls._color("YELLOW", f"[WARN] {msg}"), file=sys.stderr)

    @classmethod
    def error(cls, msg: str) -> None:
        print(cls._color("RED", f"[ERROR] {msg}"), file=sys.stderr)

    @classmethod
    def fatal(cls, msg: str, code: int = 1) -> None:
        cls.error(msg)
        sys.exit(code)


# ──────────────────────────────────────────────────────────────────────────────
# SSH Connection Management
# ──────────────────────────────────────────────────────────────────────────────

class SSHConnection:
    """Manages SSH connection with ControlMaster for connection reuse."""

    def __init__(self, config: HostConfig):
        self.config = config
        self.socket_path: Optional[str] = None
        self._socket_dir: Optional[tempfile.TemporaryDirectory] = None
        self._master_pid: Optional[int] = None

    def _get_socket_path(self) -> str:
        if self.socket_path:
            return self.socket_path

        if self._socket_dir is None:
            self._socket_dir = tempfile.TemporaryDirectory(prefix="ssh-cm-")

        host_key = f"{self.config.user}@{self.config.host}:{self.config.port}".replace("@", "_").replace(":", "_")
        self.socket_path = os.path.join(self._socket_dir.name, f"cm-{host_key}.sock")
        return self.socket_path

    def _build_ssh_base_cmd(self, for_password: bool = False) -> list[str]:
        """Build base SSH command with common options."""
        cmd = ["ssh"]
        if not for_password:
            cmd.extend(["-o", "BatchMode=yes"])
        cmd.extend(["-o", "StrictHostKeyChecking=no"])
        cmd.extend(["-o", "UserKnownHostsFile=/dev/null"])
        cmd.extend(["-o", "ConnectTimeout=10"])
        cmd.extend(["-o", "ServerAliveInterval=15"])
        cmd.extend(["-o", "ServerAliveCountMax=3"])

        if self.config.port != 22:
            cmd.extend(["-p", str(self.config.port)])

        if self.config.key_file and not for_password:
            cmd.extend(["-i", os.path.expanduser(self.config.key_file)])

        if self.config.user:
            target = f"{self.config.user}@{self.config.host}"
        else:
            target = self.config.host

        if self.config.control_master and not for_password:
            socket_path = self._get_socket_path()
            cmd.extend(["-o", f"ControlPath={socket_path}"])
            cmd.extend(["-o", "ControlMaster=auto"])
            cmd.extend(["-o", "ControlPersist=60"])

        cmd.append(target)
        return cmd

    def _try_key_auth(self) -> bool:
        """Try SSH key authentication (ControlMaster)."""
        if not self.config.control_master:
            return False

        cmd = self._build_ssh_base_cmd()
        cmd.extend(["-N", "-f"])  # Background, no command

        try:
            Log.debug(f"Starting SSH master (key auth): {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, timeout=self.config.timeout)
            if result.returncode == 0:
                time.sleep(0.3)
                if os.path.exists(self._get_socket_path()):
                    Log.debug(f"SSH master started for {self.config.host} (key auth)")
                    return True
            Log.debug(f"SSH key auth failed: {result.stderr.decode() if result.stderr else 'unknown'}")
            return False
        except subprocess.TimeoutExpired:
            Log.error(f"SSH key auth timeout for {self.config.host}")
            return False
        except Exception as e:
            Log.error(f"SSH key auth error for {self.config.host}: {e}")
            return False

    def _try_password_auth(self, password: str) -> tuple[bool, Optional[str]]:
        """Try password authentication using pexpect. Returns (success, error_message)."""
        try:
            import pexpect
        except ImportError:
            return False, "pexpect not installed (pip install pexpect)"

        cmd = self._build_ssh_base_cmd(for_password=True)
        cmd.extend(["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"])
        
        # Build the remote command - simple test
        remote_cmd = "echo 'SSH_PASSWORD_AUTH_OK'"
        cmd.append(remote_cmd)

        Log.debug(f"Trying password auth for {self.config.host}...")
        try:
            child = pexpect.spawn(cmd[0], cmd[1:], timeout=20, encoding='utf-8')
            child.logfile_read = None  # Don't log passwords
            
            # Wait for password prompt
            index = child.expect([
                r'password:',
                r'Password:',
                pexpect.TIMEOUT,
                pexpect.EOF,
            ], timeout=15)
            
            if index == 0 or index == 1:
                Log.debug(f"Password prompt received, sending password...")
                child.sendline(password)
                
                # Wait for either success or another password prompt (failure)
                index2 = child.expect([
                    r'SSH_PASSWORD_AUTH_OK',
                    r'password:',
                    r'Password:',
                    pexpect.TIMEOUT,
                    pexpect.EOF,
                ], timeout=15)
                
                if index2 == 0:
                    Log.debug(f"Password auth succeeded for {self.config.host}")
                    return True, None
                elif index2 == 1 or index2 == 2:
                    return False, "Authentication failed (wrong password)"
                elif index2 == 3:
                    return False, "Connection timeout after password"
                else:
                    return False, "Connection closed unexpectedly"
            elif index == 2:
                return False, "Connection timeout waiting for password prompt"
            else:
                return False, "Connection closed unexpectedly"
                
        except Exception as e:
            return False, str(e)

    def _find_working_password(self) -> Optional[str]:
        """Try all configured passwords, return the one that works."""
        passwords = list(self.config.passwords)
        
        # Add passwords from file if specified
        if self.config.password_file:
            try:
                with open(os.path.expanduser(self.config.password_file)) as f:
                    file_passwords = [line.strip() for line in f if line.strip()]
                    passwords.extend(file_passwords)
            except Exception as e:
                Log.error(f"Failed to read password file {self.config.password_file}: {e}")
        
        if not passwords:
            return None
            
        Log.info(f"Trying {len(passwords)} password(s) for {self.config.host}...")
        
        for i, pwd in enumerate(passwords, 1):
            Log.debug(f"Trying password #{i}...")
            success, error = self._try_password_auth(pwd)
            if success:
                Log.ok(f"Password #{i} worked for {self.config.host}")
                return pwd
            else:
                Log.debug(f"Password #{i} failed: {error}")
        
        Log.error(f"All {len(passwords)} passwords failed for {self.config.host}")
        return None

    def start_master(self) -> bool:
        """Start SSH master connection for reuse. Tries key auth first, then password."""
        if not self.config.control_master:
            return True

        # Try key-based auth first
        if self._try_key_auth():
            return True

        # Fall back to password auth if passwords configured
        if self.config.passwords or self.config.password_file:
            Log.info(f"Key auth failed for {self.config.host}, trying password auth...")
            working_pwd = self._find_working_password()
            if working_pwd:
                # For password auth, we can't use ControlMaster easily
                # Fall back to per-command password auth
                Log.warn(f"Password auth works but ControlMaster not supported with password; using per-command auth")
                self.config.control_master = False
                return True
        
        return False

    def execute(self, script_content: str, script_args: list[str], stdin_data: str = "",
                timeout: int = 300, dry_run: bool = False) -> HostResult:
        """Execute script on remote host."""
        host = self.config.host
        start_time = time.time()

        if dry_run:
            Log.info(f"[DRY-RUN] Would execute on {host}: script with args {script_args}")
            return HostResult(
                host=host,
                success=True,
                exit_code=0,
                stdout="[DRY-RUN] Script would be executed",
                stderr="",
                duration_sec=time.time() - start_time,
            )

        # Build remote command: cat script | bash -s -- args...
        remote_cmd = f"bash -s -- {' '.join(shlex.quote(a) for a in script_args)}"

        # Determine auth method
        if self.config.control_master and self.socket_path and os.path.exists(self.socket_path):
            # Use existing ControlMaster connection
            cmd = self._build_ssh_base_cmd()
            cmd.append(remote_cmd)
            return self._execute_with_cmd(cmd, script_content, stdin_data, timeout, start_time, host)
        
        # Try key auth without ControlMaster
        if self.config.key_file:
            cmd = self._build_ssh_base_cmd()
            cmd.append(remote_cmd)
            result = self._execute_with_cmd(cmd, script_content, stdin_data, timeout, start_time, host)
            if result.success:
                return result
            Log.debug(f"Key auth execution failed: {result.error or 'non-zero exit'}")

        # Fall back to password auth
        if self.config.passwords or self.config.password_file:
            working_pwd = self._find_working_password()
            if working_pwd:
                return self._execute_with_password(working_pwd, remote_cmd, script_content, stdin_data, timeout, start_time, host)
            else:
                return HostResult(
                    host=host,
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    duration_sec=time.time() - start_time,
                    error="All authentication methods failed (key + passwords)",
                )

        # Last resort: try without any explicit auth (agent, etc.)
        cmd = self._build_ssh_base_cmd()
        cmd.append(remote_cmd)
        return self._execute_with_cmd(cmd, script_content, stdin_data, timeout, start_time, host)

    def _execute_with_cmd(self, cmd: list[str], script_content: str, stdin_data: str, 
                          timeout: int, start_time: float, host: str) -> HostResult:
        """Execute command with given SSH command."""
        Log.debug(f"Executing on {host}: {' '.join(cmd[:3])}... (script + args)")
        
        try:
            proc = subprocess.run(
                cmd,
                input=script_content.encode() + (b"\n" + stdin_data.encode() if stdin_data else b""),
                capture_output=True,
                timeout=timeout,
            )
            duration = time.time() - start_time

            return HostResult(
                host=host,
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout.decode(errors="replace"),
                stderr=proc.stderr.decode(errors="replace"),
                duration_sec=duration,
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=duration,
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            duration = time.time() - start_time
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=duration,
                error=str(e),
            )

    def _execute_with_password(self, password: str, remote_cmd: str, script_content: str, 
                               stdin_data: str, timeout: int, start_time: float, host: str) -> HostResult:
        """Execute script using password authentication via sshpass (preferred) or pexpect."""
        
        # Build base SSH command for password auth
        cmd = self._build_ssh_base_cmd(for_password=True)
        cmd.append(remote_cmd)
        
        # Try sshpass first (handles TTY properly)
        if shutil.which("sshpass"):
            return self._execute_with_sshpass(password, cmd, script_content, stdin_data, timeout, start_time, host)
        
        # Fall back to pexpect with PTY
        return self._execute_with_pexpect_pty(password, cmd, script_content, stdin_data, timeout, start_time, host)

    def _execute_with_sshpass(self, password: str, cmd: list[str], script_content: str,
                              stdin_data: str, timeout: int, start_time: float, host: str) -> HostResult:
        """Execute using sshpass for password authentication."""
        Log.debug(f"Executing with sshpass on {host}...")
        
        # Prepare input data
        input_data = script_content.encode() + (b"\n" + stdin_data.encode() if stdin_data else b"")
        
        sshpass_cmd = ["sshpass", "-p", password] + cmd
        
        try:
            proc = subprocess.run(
                sshpass_cmd,
                input=input_data,
                capture_output=True,
                timeout=timeout,
            )
            duration = time.time() - start_time
            
            return HostResult(
                host=host,
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout.decode(errors="replace"),
                stderr=proc.stderr.decode(errors="replace"),
                duration_sec=duration,
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=duration,
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            duration = time.time() - start_time
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=duration,
                error=str(e),
            )

    def _execute_with_pexpect_pty(self, password: str, cmd: list[str], script_content: str,
                                  stdin_data: str, timeout: int, start_time: float, host: str) -> HostResult:
        """Execute using pexpect with PTY allocation."""
        try:
            import pexpect
        except ImportError:
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=time.time() - start_time,
                error="pexpect not installed",
            )
        
        Log.debug(f"Executing with pexpect PTY on {host}...")
        
        try:
            # Use pexpect.spawn which allocates a PTY by default
            child = pexpect.spawn(cmd[0], cmd[1:], timeout=timeout, encoding='utf-8')
            child.logfile_read = None
            
            # Wait for password prompt
            index = child.expect([
                r'password:',
                r'Password:',
                pexpect.TIMEOUT,
                pexpect.EOF,
            ], timeout=15)
            
            if index == 0 or index == 1:
                child.sendline(password)
                
                # Send script content via stdin
                child.send(script_content)
                if stdin_data:
                    child.send(stdin_data)
                child.sendeof()
                
                # Wait for completion
                child.expect(pexpect.EOF)
                output = child.before
                exit_code = child.wait()
                
                duration = time.time() - start_time
                return HostResult(
                    host=host,
                    success=exit_code == 0,
                    exit_code=exit_code if exit_code is not None else -1,
                    stdout=output,
                    stderr="",
                    duration_sec=duration,
                )
            else:
                duration = time.time() - start_time
                error = "Timeout waiting for password prompt" if index == 2 else "Connection closed"
                return HostResult(
                    host=host,
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    duration_sec=duration,
                    error=error,
                )
                
        except Exception as e:
            duration = time.time() - start_time
            return HostResult(
                host=host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=duration,
                error=str(e),
            )

    def close(self) -> None:
        """Close SSH master connection."""
        if not self.config.control_master or not self.socket_path:
            return

        socket_path = self._get_socket_path()
        if os.path.exists(socket_path):
            cmd = ["ssh", "-O", "exit", "-o", f"ControlPath={socket_path}", self.config.host]
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                Log.debug(f"Closed SSH master for {self.config.host}")
            except Exception as e:
                Log.debug(f"Error closing SSH master: {e}")

        if self._socket_dir:
            try:
                self._socket_dir.cleanup()
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────────
# Host File Parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_host_file(path: str) -> list[HostConfig]:
    """Parse host file (one per line: [user@]host[:port] [key_file])."""
    hosts = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            host_spec = parts[0]
            key_file = parts[1] if len(parts) > 1 else ""

            # Parse user@host:port
            user = ""
            port = 22
            host = host_spec

            if "@" in host_spec:
                user, host = host_spec.split("@", 1)

            if ":" in host:
                host, port_str = host.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    Log.fatal(f"Invalid port in host file line {line_num}: {host_spec}")

            hosts.append(HostConfig(host=host, port=port, user=user, key_file=key_file))

    return hosts


def parse_host_string(s: str) -> HostConfig:
    """Parse single host string: [user@]host[:port] [key_file]."""
    parts = s.split()
    host_spec = parts[0]
    key_file = parts[1] if len(parts) > 1 else ""

    user = ""
    port = 22
    host = host_spec

    if "@" in host_spec:
        user, host = host_spec.split("@", 1)

    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            Log.fatal(f"Invalid port in host string: {host_spec}")

    return HostConfig(host=host, port=port, user=user, key_file=key_file)


# ──────────────────────────────────────────────────────────────────────────────
# Script Execution
# ──────────────────────────────────────────────────────────────────────────────

def read_script(script_path: str) -> str:
    """Read script file content."""
    path = Path(script_path).expanduser()
    if not path.exists():
        Log.fatal(f"Script not found: {script_path}")
    if not path.is_file():
        Log.fatal(f"Not a file: {script_path}")

    content = path.read_text()
    if not content.strip():
        Log.fatal(f"Script is empty: {script_path}")

    # Ensure script has shebang or add bash
    if not content.startswith("#!"):
        content = "#!/usr/bin/env bash\n" + content

    return content


def execute_on_host(
    host_config: HostConfig,
    script_content: str,
    script_args: list[str],
    stdin_data: str,
    timeout: int,
    dry_run: bool,
    reuse_connection: bool,
) -> HostResult:
    """Execute script on a single host."""
    # Skip SSH connection entirely for dry-run
    if dry_run:
        start_time = time.time()
        return HostResult(
            host=host_config.host,
            success=True,
            exit_code=0,
            stdout="[DRY-RUN] Script would be executed",
            stderr="",
            duration_sec=time.time() - start_time,
        )

    conn = SSHConnection(host_config)

    if reuse_connection and host_config.control_master:
        if not conn.start_master():
            return HostResult(
                host=host_config.host,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_sec=0,
                error="Failed to establish SSH master connection",
            )

    try:
        return conn.execute(script_content, script_args, stdin_data, timeout, dry_run)
    finally:
        if reuse_connection and host_config.control_master:
            conn.close()


def run_parallel(
    hosts: list[HostConfig],
    script_content: str,
    script_args: list[str],
    stdin_data: str,
    timeout: int,
    dry_run: bool,
    max_workers: int,
    reuse_connections: bool,
    progress_queue: Optional[Queue] = None,
) -> list[HostResult]:
    """Execute script on multiple hosts in parallel."""
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(
                execute_on_host,
                host,
                script_content,
                script_args,
                stdin_data,
                timeout,
                dry_run,
                reuse_connections,
            ): host
            for host in hosts
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results.append(result)
                if progress_queue:
                    progress_queue.put(result)
            except Exception as e:
                Log.error(f"Unexpected error for {host.host}: {e}")
                results.append(HostResult(
                    host=host.host,
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    duration_sec=0,
                    error=f"Executor error: {e}",
                ))

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def print_results(results: list[HostResult], verbose: bool = False) -> None:
    """Print execution results to stderr."""
    for r in results:
        status = Log._color("GREEN", "OK") if r.success else Log._color("RED", "FAIL")
        Log.info(f"{status} {r.host} (exit={r.exit_code}, {r.duration_sec:.2f}s)")

        if verbose or not r.success:
            if r.stdout:
                for line in r.stdout.strip().split("\n"):
                    Log.info(f"  {r.host} | {line}")
            if r.stderr:
                for line in r.stderr.strip().split("\n"):
                    Log.warn(f"  {r.host} | {line}")
            if r.error:
                Log.error(f"  {r.host} | {r.error}")


def write_csv(results: list[HostResult], path: str) -> None:
    """Write results to CSV file."""
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HostResult.csv_header())
        for r in results:
            writer.writerow(r.to_csv_row())
    Log.ok(f"CSV report written to {path}")


def write_json(results: list[HostResult], path: str) -> None:
    """Write results to JSON file."""
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    Log.ok(f"JSON report written to {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Self-Test
# ──────────────────────────────────────────────────────────────────────────────

def run_selftest() -> int:
    """Run self-test suite."""
    print(f"Running {SCRIPT_NAME} self-test...")
    passed = 0
    failed = 0

    def test(name: str, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  ✓ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1

    # Test 1: HostConfig parsing
    def test_host_parsing():
        h = parse_host_string("user@host:2222 ~/.ssh/key")
        assert h.user == "user"
        assert h.host == "host"
        assert h.port == 2222
        assert h.key_file == "~/.ssh/key"

        h2 = parse_host_string("host.example.com")
        assert h2.user == ""
        assert h2.host == "host.example.com"
        assert h2.port == 22

    test("HostConfig parsing", test_host_parsing)

    # Test 2: Host file parsing
    def test_host_file():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("user@host1:22 ~/.ssh/key1\n")
            f.write("host2:2222\n")
            f.write("# comment\n")
            f.write("\n")
            f.write("user3@host3\n")
            path = f.name

        try:
            hosts = parse_host_file(path)
            assert len(hosts) == 3
            assert hosts[0].user == "user"
            assert hosts[0].host == "host1"
            assert hosts[0].port == 22
            assert hosts[1].user == ""
            assert hosts[1].host == "host2"
            assert hosts[1].port == 2222
            assert hosts[2].user == "user3"
            assert hosts[2].host == "host3"
        finally:
            os.unlink(path)

    test("Host file parsing", test_host_file)

    # Test 3: HostResult CSV
    def test_csv():
        r = HostResult(
            host="host1",
            success=True,
            exit_code=0,
            stdout="hello",
            stderr="",
            duration_sec=1.5,
        )
        row = r.to_csv_row()
        assert row[0] == "host1"
        assert row[1] == "True"
        assert row[2] == "0"
        assert "hello" in row[3]

        header = HostResult.csv_header()
        assert header[0] == "host"
        assert header[1] == "success"

    test("HostResult CSV", test_csv)

    # Test 4: SSH command building
    def test_ssh_cmd():
        config = HostConfig(host="host", port=2222, user="user", key_file="~/.ssh/id")
        conn = SSHConnection(config)
        cmd = conn._build_ssh_base_cmd()
        assert "ssh" == cmd[0]
        assert "-p" in cmd and "2222" in cmd
        assert "-i" in cmd
        # key_file gets expanded by os.path.expanduser
        assert "user@host" in cmd

    test("SSH command building", test_ssh_cmd)

    # Test 5: Script reading
    def test_read_script():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/bash\necho hello\n")
            path = f.name

        try:
            content = read_script(path)
            assert content.startswith("#!/bin/bash")
            assert "echo hello" in content
        finally:
            os.unlink(path)

    test("Script reading", test_read_script)

    # Test 6: Script reading adds shebang
    def test_read_script_adds_shebang():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write("echo hello\n")
            path = f.name

        try:
            content = read_script(path)
            assert content.startswith("#!/usr/bin/env bash")
            assert "echo hello" in content
        finally:
            os.unlink(path)

    test("Script reading adds shebang", test_read_script_adds_shebang)

    print(f"\nSelf-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

import shlex


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description="Execute local scripts on remote hosts via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Examples:
  # Single host, script with args (key auth)
  {SCRIPT_NAME} --host user@server --script ./deploy.sh --args "prod us-east"

  # Single host with password auth (tries key first, falls back to password)
  {SCRIPT_NAME} --host user@server --script ./deploy.sh --password "mypassword"

  # Multiple passwords as fallback (tries in order)
  {SCRIPT_NAME} --host user@server --script ./deploy.sh --password "pass1" --password "pass2"

  # Password from file (one per line)
  {SCRIPT_NAME} --host user@server --script ./deploy.sh --password-file passwords.txt

  # Multiple hosts from file, parallel execution
  {SCRIPT_NAME} --host-file hosts.txt --script ./setup.sh --parallel 4

  # Dry run to preview
  {SCRIPT_NAME} --host user@server --script ./setup.sh --dry-run

  # With CSV output
  {SCRIPT_NAME} --host-file hosts.txt --script ./check.sh --csv report.csv

  # With stdin input
  echo "config data" | {SCRIPT_NAME} --host user@server --script ./apply.sh

Host file format (one per line):
  user@host:port [key_file]
  host.example.com
  user@192.168.1.10 ~/.ssh/id_ed25519

Password file format (one per line):
  password1
  password2
  password3""",
    )
    host_group = p.add_mutually_exclusive_group(required=False)
    host_group.add_argument("--host", help="Single host: [user@]host[:port] [key_file]")
    host_group.add_argument("--host-file", help="File with hosts (one per line)")

    # Script
    p.add_argument("--script", help="Local script file to execute on remote hosts")
    p.add_argument("--args", default="", help="Arguments to pass to the script (quoted)")
    p.add_argument("--stdin", help="Read stdin data from file instead of stdin")

    # Execution options
    p.add_argument("--parallel", "-p", type=int, default=4, help="Max parallel connections (default: 4)")
    p.add_argument("--timeout", "-t", type=int, default=300, help="Command timeout in seconds (default: 300)")
    p.add_argument("--no-reuse", action="store_true", help="Disable SSH ControlMaster connection reuse")
    p.add_argument("--dry-run", action="store_true", help="Show what would be executed without running")

    # Password authentication (fallback if key auth fails)
    p.add_argument("--password", action="append", dest="passwords", default=[], 
                   help="SSH password to try (can specify multiple for fallback)")
    p.add_argument("--password-file", help="File with passwords (one per line) to try")

    # Output
    p.add_argument("--csv", help="Write CSV report to file")
    p.add_argument("--json", help="Write JSON report to file")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")

    # Meta
    p.add_argument("--selftest", action="store_true", help="Run self-test and exit")
    p.add_argument("--version", action="version", version=f"{SCRIPT_NAME} {VERSION}")

    return p


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    Log.verbose = args.verbose
    Log.quiet = args.quiet

    if args.selftest:
        return run_selftest()

    # Validate required arguments for normal execution
    if not args.host and not args.host_file:
        parser.error("one of --host or --host-file is required")
    if not args.script:
        parser.error("--script is required")

    # Read script
    script_content = read_script(args.script)

    # Parse script args
    script_args = shlex.split(args.args) if args.args else []

    # Read stdin data
    stdin_data = ""
    if args.stdin:
        stdin_data = Path(args.stdin).expanduser().read_text()
    elif not sys.stdin.isatty():
        stdin_data = sys.stdin.read()

    # Parse hosts
    if args.host_file:
        hosts = parse_host_file(args.host_file)
    else:
        hosts = [parse_host_string(args.host)]

    # Add password configuration to all hosts
    for host in hosts:
        host.passwords = args.passwords
        host.password_file = args.password_file

    if not hosts:
        Log.fatal("No valid hosts specified")

    Log.info(f"Executing {args.script} on {len(hosts)} host(s) with {args.parallel} parallel workers")

    # Execute
    reuse = not args.no_reuse
    results = run_parallel(
        hosts=hosts,
        script_content=script_content,
        script_args=script_args,
        stdin_data=stdin_data,
        timeout=args.timeout,
        dry_run=args.dry_run,
        max_workers=args.parallel,
        reuse_connections=reuse,
    )

    # Output
    print_results(results, verbose=args.verbose)

    if args.csv:
        write_csv(results, args.csv)
    if args.json:
        write_json(results, args.json)

    # Exit code: 0 if all succeeded, 1 if any failed
    failed = sum(1 for r in results if not r.success)
    if failed:
        Log.error(f"{failed} of {len(results)} host(s) failed")
        return 1

    Log.ok(f"All {len(results)} host(s) succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())