#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: stop_event_log.sh [--pid-file <path>]

Stop the structured event follower started by start_event_log.sh.
EOF
}

pid_file="/tmp/poem_bpf_follow.pid"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid-file)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      pid_file="$1"
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ ! -f "$pid_file" ]]; then
  echo "no pid file found at $pid_file"
  exit 0
fi

pid="$(cat "$pid_file")"
if kill -0 "$pid" >/dev/null 2>&1; then
  kill -2 "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" >/dev/null 2>&1 || break
    sleep 0.1
  done
  kill "$pid" >/dev/null 2>&1 || true
fi

rm -f "$pid_file"
echo "event follower stopped"