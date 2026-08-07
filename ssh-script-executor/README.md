# SSH Script Executor

Execute local scripts on remote hosts via SSH with parallel execution, connection reuse, and CSV/JSON reporting.

## Quick Start

```bash
# Single host
./ssh-script-executor.py --host user@server --script ./deploy.sh --args "prod us-east"

# Multiple hosts from file, parallel execution
./ssh-script-executor.py --host-file hosts.txt --script ./setup.sh --parallel 4

# Dry run to preview
./ssh-script-executor.py --host user@server --script ./setup.sh --dry-run

# With CSV output
./ssh-script-executor.py --host-file hosts.txt --script ./check.sh --csv report.csv

# With stdin input
echo "config data" | ./ssh-script-executor.py --host user@server --script ./apply.sh
```

## Host File Format

One host per line:
```
user@host:port [key_file]
host.example.com
user@192.168.1.10 ~/.ssh/id_ed25519
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--host HOST` | Single target (user@host[:port]) | — |
| `--host-file FILE` | File with hosts (one per line) | — |
| `--script PATH` | Local script to execute remotely | **required** |
| `--args ARGS` | Arguments passed to the remote script | `""` |
| `--parallel N` | Max concurrent SSH connections | `1` |
| `--timeout SEC` | SSH connection timeout | `10` |
| `--cmd-timeout SEC` | Remote command timeout | `300` |
| `--dry-run` | Print commands without executing | `false` |
| `--csv FILE` | Write CSV report | — |
| `--json FILE` | Write JSON report | — |
| `--verbose`, `-v` | Increase verbosity | `0` |
| `--quiet`, `-q` | Suppress non-error output | `false` |
| `--selftest` | Run internal test suite | `false` |
| `--version` | Show version and exit | — |
| `--help` | Show help and exit | — |

## Features

- **Cross-platform** — macOS + Linux
- **Parallel execution** — configurable concurrency with `--parallel`
- **SSH ControlMaster** — connection reuse for speed
- **Script arguments + stdin passthrough** — flexible input
- **Dry-run mode** — preview commands before execution
- **CSV/JSON output** — automation-friendly reporting
- **Colored output** — verbosity levels (`-v`, `-vv`, `-q`)
- **Self-test suite** — `--selftest` validates functionality

## Requirements

- Python 3.8+
- OpenSSH client (`ssh`, `ssh-agent`)
- Target hosts accessible via SSH key authentication

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All hosts succeeded |
| `1` | One or more hosts failed |
| `2` | Usage error / invalid arguments |
| `130` | Interrupted (Ctrl+C) |

## Examples

### Deploy to multiple environments
```bash
# Staging
./ssh-script-executor.py --host-file staging-hosts.txt --script ./deploy.sh --args "staging" --parallel 5 --csv staging-deploy.csv

# Production (with approval pause)
./ssh-script-executor.py --host-file prod-hosts.txt --script ./deploy.sh --args "production" --parallel 2 --dry-run
# Review output, then re-run without --dry-run
```

### Health checks with JSON output
```bash
./ssh-script-executor.py --host-file all-servers.txt --script ./health-check.sh --json health-$(date +%F).json --parallel 10
```

### Passing stdin to remote script
```bash
cat config.yaml | ./ssh-script-executor.py --host user@server --script ./apply-config.sh
```

## Troubleshooting

**Connection refused / timeout**
- Verify SSH key is loaded: `ssh-add -l`
- Check target host allows key auth: `ssh user@host`
- Increase `--timeout` for slow networks

**Script not found on remote**
- The script is transferred to a temp location on the remote host and executed there
- Ensure the script is executable locally: `chmod +x your-script.sh`

**Permission denied**
- Ensure SSH key has correct permissions: `chmod 600 ~/.ssh/id_ed25519`
- Target user must have execute permission on remote temp directory (usually `/tmp`)

## License

MIT License — see [LICENSE](../LICENSE) in repo root.