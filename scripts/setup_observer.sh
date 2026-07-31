#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: setup_observer.sh <iface> [--hook ingress|egress] [--no-build]

Attach the POEM tc observer to a local interface.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

iface="$1"
shift

hook="egress"
do_build=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hook)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      hook="$1"
      ;;
    --no-build)
      do_build=0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

cmd=(python3 "$SCRIPT_DIR/bpf_trace_dispatch.py" attach --iface "$iface" --hook "$hook")
if [[ "$do_build" -eq 1 ]]; then
  cmd+=(--build)
fi

"${cmd[@]}"

echo "observer setup complete on iface=$iface hook=$hook"