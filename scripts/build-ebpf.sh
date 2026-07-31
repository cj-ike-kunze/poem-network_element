#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SRC="${ROOT_DIR}/ebpf/poem_observer_tc.c"
OUT="${ROOT_DIR}/ebpf/poem_observer_tc.o"

if ! command -v clang >/dev/null 2>&1; then
  echo "clang not found" >&2
  exit 1
fi

if ! command -v llc >/dev/null 2>&1; then
  echo "llc not found (install llvm tools)" >&2
  exit 1
fi

arch="$(uname -m)"
target_arch_macro=""
case "$arch" in
  x86_64)
    target_arch_macro="__TARGET_ARCH_x86"
    ;;
  aarch64|arm64)
    target_arch_macro="__TARGET_ARCH_arm64"
    ;;
  *)
    echo "unsupported architecture for eBPF build: $arch" >&2
    exit 1
    ;;
esac

multiarch=""
if command -v dpkg-architecture >/dev/null 2>&1; then
  multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH || true)"
fi
if [[ -z "$multiarch" ]]; then
  case "$arch" in
    x86_64)
      multiarch="x86_64-linux-gnu"
      ;;
    aarch64|arm64)
      multiarch="aarch64-linux-gnu"
      ;;
  esac
fi

inc_flags=("-I/usr/include")
if [[ -n "$multiarch" && -d "/usr/include/$multiarch" ]]; then
  inc_flags+=("-I/usr/include/$multiarch")
fi

clang \
  -O2 -g -target bpf \
  "-D${target_arch_macro}" \
  "${inc_flags[@]}" \
  -c "${SRC}" -o "${OUT}"

echo "built ${OUT}"
