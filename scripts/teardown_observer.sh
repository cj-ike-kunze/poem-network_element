#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: teardown_observer.sh <iface> [--hook ingress|egress|both]

Detach the POEM tc observer from a local interface.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

iface="$1"
shift

hook="both"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hook)
      shift
      [[ $# -gt 0 ]] || { usage; exit 1; }
      hook="$1"
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

python3 "$SCRIPT_DIR/bpf_trace_dispatch.py" detach --iface "$iface" --hook "$hook"

echo "observer teardown complete on iface=$iface hook=$hook"