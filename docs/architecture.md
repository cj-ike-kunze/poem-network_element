# Observer Architecture

This folder implements the production path used by current POEM experiments:

- tc eBPF datapath for online packet processing.
- Python userspace dispatcher for attach/detach and structured event logging.

## Packet Contract

- Only the first QUIC packet in each UDP datagram is parsed.
- Marker packet version: `0xc2115e23`.
- Report packet version: `0x2516f3b9`.

## Behavioral Contract

- Marker packets are observed only and always forwarded unchanged.
- Report packets may be rewritten only in the low 6 bits of byte 0
  (upstream ratio field).
- Destination addresses/ports and all other packet fields remain unchanged.
- If there is not enough sender-loss baseline (`agg_sender_loss == 0`),
  upstream ratio stays `63` (unset semantics).

## eBPF Datapath

Program: `ebpf/poem_observer_tc.c`

- Hook type: `SEC("tc")` classifier.
- Attach model: clsact + tc filter on selected interface hooks
  (usually egress in current deployment).
- Flow key: IPv4 UDP 4-tuple (`src/dst ip`, `src/dst port`).

Maps:

- `flow_states` (`BPF_MAP_TYPE_LRU_HASH`, max 65536)
  - per-flow marker/report sequencing and aggregates.
  - fields: `packets_since_last_marker`, `last_counter_bit`,
    `agg_upstream_loss`, `agg_sender_loss`, `marker_seq`, `report_seq`.
- `stats` (`BPF_MAP_TYPE_PERCPU_ARRAY`, single entry)
  - counters: `udp_seen`, `marker_seen`, `report_seen`, `report_rewritten`.
- `poem_events` (`BPF_MAP_TYPE_QUEUE`, max 8192)
  - structured telemetry channel to userspace.
  - value type: packed `struct poem_event` with named fields
    (`ev_type`, `src_ip`, `dst_ip`, `seq`, `count`, `loss`, `upstream`,
    `prev_val`, `new_val`).

POEM logic:

- On marker packet:
  - derive sender Loss Count from low 5 bits of first byte.
  - infer expected packet count per interval (`64` or `128` when counter-bit
    implies a missed marker).
  - compute upstream interval loss = `expected - observed` when positive.
  - aggregate upstream and sender loss.
  - push marker event to `poem_events` queue.
- On report packet:
  - compute upstream ratio with rounding:
    `ratio = min(62, (upstream_loss * 62 + sender_loss / 2) / sender_loss)`.
  - push report event to `poem_events` queue, including pre/post field values.
  - rewrite low 6 bits only when `before != after`.

## Userspace Dispatcher

Script: `scripts/bpf_trace_dispatch.py`

- `attach`
  - optionally builds object via `scripts/build-ebpf.sh`.
  - ensures `clsact` qdisc exists.
  - attaches tc filter with object section `tc`.
- `detach`
  - removes tc filter(s) for `ingress`, `egress`, or `both`.
  - removes `clsact` qdisc if present.
- `follow-events`
  - discovers queue maps by name (`poem_events`) using `bpf(2)` syscalls.
  - pops records with `BPF_MAP_LOOKUP_AND_DELETE_ELEM`.
  - writes normalized single-line logs.

## Runtime Modes

- Local self-contained mode (generic interfaces):
  - `scripts/setup_observer.sh`
  - `scripts/start_event_log.sh`
  - `scripts/stop_event_log.sh`
  - `scripts/teardown_observer.sh`
- Framework-integrated mode:
  - framework scripts invoke the same dispatcher with explicit object/build
    paths and environment-specific interface selection.

## Non-Goals (Current)

- No XDP implementation.
- No in-kernel packet generation.
- No parsing beyond first QUIC packet in each UDP datagram.