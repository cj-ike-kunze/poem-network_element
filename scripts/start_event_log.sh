#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: start_event_log.sh <output_log_path> [--pid-file <path>] [--map-name <name>] [--poll-sleep-ms <n>]

Start the structured event follower in background and write a PID file.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

out_path="$1"
shift

pid_file="/tmp/poem_bpf_follow.pid"
map_name="poem_events"
poll_sleep_ms="20"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid-file)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      pid_file="$1"
      ;;
    --map-name)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      map_name="$1"
      ;;
    --poll-sleep-ms)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      poll_sleep_ms="$1"
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

mkdir -p "$(dirname "$out_path")"

if [[ -f "$pid_file" ]]; then
  old_pid="$(cat "$pid_file")"
  if kill -0 "$old_pid" >/dev/null 2>&1; then
    echo "event follower already running pid=$old_pid (pid file: $pid_file)" >&2
    exit 1
  fi
  rm -f "$pid_file"
fi

nohup python3 "$SCRIPT_DIR/bpf_trace_dispatch.py" \
  follow-events \
  --out "$out_path" \
  --map-name "$map_name" \
  --poll-sleep-ms "$poll_sleep_ms" \
  >/dev/null 2>&1 &

echo $! > "$pid_file"
echo "event follower started pid=$(cat "$pid_file") out=$out_path"