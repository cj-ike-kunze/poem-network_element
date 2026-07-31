#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <iface> [ingress|egress]" >&2
  exit 2
fi

IFACE="$1"
HOOK="${2:-egress}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OBJ="${ROOT_DIR}/ebpf/poem_observer_tc.o"
SEC="tc"

if [[ ! -f "${OBJ}" ]]; then
  echo "missing ${OBJ}; run scripts/build-ebpf.sh first" >&2
  exit 1
fi

if ! command -v tc >/dev/null 2>&1; then
  echo "tc not found" >&2
  exit 1
fi

if [[ "$HOOK" != "ingress" && "$HOOK" != "egress" ]]; then
  echo "invalid hook: $HOOK (expected ingress or egress)" >&2
  exit 2
fi

if ! tc qdisc show dev "${IFACE}" | grep -q "clsact"; then
  tc qdisc add dev "${IFACE}" clsact
fi

tc filter replace dev "${IFACE}" "$HOOK" bpf da obj "${OBJ}" sec "${SEC}"
echo "attached ${HOOK} tc observer on ${IFACE}"
