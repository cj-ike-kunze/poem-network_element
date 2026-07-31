# network-element

This folder contains the eBPF network observer and report rewriter.

Implemented behavior:

- Observe QUIC marker packets (long-header version `0xc2115e23`).
- Track per-flow marker intervals and infer upstream loss.
- Rewrite QUIC report packets (long-header version `0x2516f3b9`) by updating
	only the upstream ratio field (low 6 bits of the first byte).
- Never rewrite marker packets.
- Emit structured telemetry events from eBPF and consume them in userspace.

## Layout

- `ebpf/`: tc eBPF datapath (`poem_observer_tc.c`).
- `docs/`: design notes and contracts.
- `scripts/`: local setup, attach/detach, and userspace dispatch helpers.

## Local Minimal Setup

Build the eBPF object on Linux with clang/llvm and kernel BPF headers:

```bash
cd network-element
./scripts/build-ebpf.sh
```

Attach observer to a local interface:

```bash
cd network-element
sudo ./scripts/setup_observer.sh eth0 --hook egress
```

Start structured event logging in background:

```bash
cd network-element
./scripts/start_event_log.sh ./observer.log
```

Stop event logging:

```bash
cd network-element
./scripts/stop_event_log.sh
```

Detach observer:

```bash
cd network-element
sudo ./scripts/teardown_observer.sh eth0 --hook both
```