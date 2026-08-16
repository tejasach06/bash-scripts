#!/usr/bin/env bash
# ssh-script-executor test-script.sh — real bash test used by --selftest.
#
# The executor can invoke this locally to validate its dispatch + result-
# collection logic without opening any SSH connection.  It accepts the same
# arguments the real remote path would receive, prints them to stdout, and
# exits 0.  Exit code is non-zero when the first argument is "fail", so the
# negative-path tests can exercise the failure handling code as well.
set -euo pipefail

action="${1:-greet}"
name="${2:-world}"

case "$action" in
    fail)
        echo "intentional failure for $name" >&2
        exit 1
        ;;
    sleep)
        secs="${3:-1}"
        sleep "$secs"
        echo "slept ${secs}s for $name"
        ;;
    *)
        echo "selftest: $0 action=${action} name=${name} args=$*"
        ;;
esac
