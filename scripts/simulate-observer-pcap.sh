#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <input.pcap> [--verbose]" >&2
  exit 2
fi

PCAP_PATH="$1"
shift || true

cd "$ROOT_DIR"
go run ./agent --pcap "$PCAP_PATH" "$@"
