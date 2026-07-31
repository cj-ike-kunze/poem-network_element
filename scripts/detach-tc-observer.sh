#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <iface>" >&2
  exit 2
fi

IFACE="$1"

if ! command -v tc >/dev/null 2>&1; then
  echo "tc not found" >&2
  exit 1
fi

tc filter del dev "${IFACE}" ingress || true
tc filter del dev "${IFACE}" egress || true
if tc qdisc show dev "${IFACE}" | grep -q "clsact"; then
  tc qdisc del dev "${IFACE}" clsact || true
fi

echo "detached tc observer from ${IFACE}"
