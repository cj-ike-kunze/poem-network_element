#!/usr/bin/env python3
import argparse
import ctypes
import errno
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

running = True

BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21
BPF_MAP_GET_FD_BY_ID = 14
BPF_MAP_GET_NEXT_ID = 12
BPF_OBJ_GET_INFO_BY_FD = 15

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
DEFAULT_OBJ = ROOT_DIR / "ebpf" / "poem_observer_tc.o"
DEFAULT_BUILD_SCRIPT = SCRIPT_DIR / "build-ebpf.sh"


def _bpf_syscall_number() -> int:
    mach = subprocess.run(["uname", "-m"], check=False, capture_output=True, text=True).stdout.strip()
    if mach in ("aarch64", "arm64"):
        return 280
    if mach == "x86_64":
        return 321
    raise RuntimeError(f"unsupported architecture for bpf syscall: {mach}")


SYS_BPF = _bpf_syscall_number()
LIBC = ctypes.CDLL(None, use_errno=True)


class BpfAttrMapGetFdById(ctypes.Structure):
    _fields_ = [
        ("map_id", ctypes.c_uint),
        ("next_id", ctypes.c_uint),
        ("open_flags", ctypes.c_uint),
    ]


class BpfAttrGetNextId(ctypes.Structure):
    _fields_ = [
        ("start_id", ctypes.c_uint),
        ("next_id", ctypes.c_uint),
        ("open_flags", ctypes.c_uint),
    ]


class BpfAttrObjGetInfoByFd(ctypes.Structure):
    _fields_ = [
        ("bpf_fd", ctypes.c_uint),
        ("info_len", ctypes.c_uint),
        ("info", ctypes.c_uint64),
    ]


class BpfMapInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("id", ctypes.c_uint),
        ("key_size", ctypes.c_uint),
        ("value_size", ctypes.c_uint),
        ("max_entries", ctypes.c_uint),
        ("map_flags", ctypes.c_uint),
        ("name", ctypes.c_char * 16),
    ]


class BpfAttrMapElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint),
        ("pad", ctypes.c_uint),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class PoemEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ev_type", ctypes.c_uint8),
        ("reserved0", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint16),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("seq", ctypes.c_uint32),
        ("count", ctypes.c_uint16),
        ("loss", ctypes.c_uint8),
        ("upstream", ctypes.c_uint8),
        ("prev_val", ctypes.c_uint8),
        ("new_val", ctypes.c_uint8),
    ]

def handle_sigterm(_signo, _frame):
    global running
    running = False


def decode_ip(hex_str: str) -> str:
    v = int(hex_str, 16)
    b = v.to_bytes(4, byteorder="little", signed=False)
    return socket.inet_ntoa(b)


def decode_ip_u32(v: int) -> str:
    b = int(v).to_bytes(4, byteorder="little", signed=False)
    return socket.inet_ntoa(b)


def run_cmd(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        msg = (proc.stdout or "") + (proc.stderr or "")
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{msg}")


def bpf_map_get_next_id(start_id: int) -> int | None:
    attr = BpfAttrGetNextId()
    attr.start_id = start_id
    attr.next_id = 0
    attr.open_flags = 0
    ret = LIBC.syscall(SYS_BPF, BPF_MAP_GET_NEXT_ID, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret == 0:
        return int(attr.next_id)
    err = ctypes.get_errno()
    if err == errno.ENOENT:
        return None
    raise OSError(err, f"BPF_MAP_GET_NEXT_ID failed at start_id={start_id}")


def bpf_map_get_fd_by_id(map_id: int) -> int:
    attr = BpfAttrMapGetFdById()
    attr.map_id = map_id
    ret = LIBC.syscall(SYS_BPF, BPF_MAP_GET_FD_BY_ID, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"BPF_MAP_GET_FD_BY_ID failed for id={map_id}")
    return int(ret)


def bpf_map_name_from_fd(map_fd: int) -> str:
    info = BpfMapInfo()
    attr = BpfAttrObjGetInfoByFd()
    attr.bpf_fd = map_fd
    attr.info_len = ctypes.sizeof(info)
    attr.info = ctypes.addressof(info)

    ret = LIBC.syscall(SYS_BPF, BPF_OBJ_GET_INFO_BY_FD, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"BPF_OBJ_GET_INFO_BY_FD failed for fd={map_fd}")

    return info.name.split(b"\x00", 1)[0].decode("ascii", errors="ignore")


def get_map_ids_by_name(map_name: str) -> list[int]:
    out: list[int] = []
    cursor = 0
    while True:
        next_id = bpf_map_get_next_id(cursor)
        if next_id is None:
            break
        cursor = next_id
        fd = None
        try:
            fd = bpf_map_get_fd_by_id(next_id)
            name = bpf_map_name_from_fd(fd)
            if name == map_name:
                out.append(next_id)
        except OSError:
            continue
        finally:
            if fd is not None:
                try:
                    LIBC.close(fd)
                except Exception:
                    pass
    return out


def bpf_map_pop_event(map_fd: int) -> PoemEvent | None:
    ev = PoemEvent()
    attr = BpfAttrMapElem()
    attr.map_fd = map_fd
    attr.key = 0
    attr.value = ctypes.addressof(ev)
    attr.flags = 0

    ret = LIBC.syscall(SYS_BPF, BPF_MAP_LOOKUP_AND_DELETE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret == 0:
        return ev

    err = ctypes.get_errno()
    if err == errno.ENOENT:
        return None
    raise OSError(err, f"BPF_MAP_LOOKUP_AND_DELETE_ELEM failed for fd={map_fd}")


def render_event(ev: PoemEvent) -> str | None:
    src = decode_ip_u32(ev.src_ip)
    dst = decode_ip_u32(ev.dst_ip)

    if ev.ev_type == 1:
        return (
            f"poem src={src} dst={dst} type=marker seq={ev.seq} "
            f"count={ev.count} loss={ev.loss} upstream={ev.upstream}"
        )

    if ev.ev_type == 2:
        return (
            f"poem src={src} dst={dst} type=report seq={ev.seq} "
            f"upstream={ev.upstream} prev_val={ev.prev_val} new_val={ev.new_val}"
        )

    return None


def tc_attach(iface: str, hook: str, obj_path: Path, sec: str = "tc") -> None:
    if hook not in ("ingress", "egress"):
        raise ValueError(f"invalid hook: {hook}")

    proc = subprocess.run(["tc", "qdisc", "show", "dev", iface], check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"failed to query qdisc for {iface}: {(proc.stderr or '').strip()}")
    if "clsact" not in (proc.stdout or ""):
        run_cmd(["tc", "qdisc", "add", "dev", iface, "clsact"])

    run_cmd(["tc", "filter", "replace", "dev", iface, hook, "bpf", "da", "obj", str(obj_path), "sec", sec])


def tc_detach(iface: str, hook: str) -> None:
    hooks: list[str]
    if hook == "both":
        hooks = ["ingress", "egress"]
    elif hook in ("ingress", "egress"):
        hooks = [hook]
    else:
        raise ValueError(f"invalid hook: {hook}")

    for h in hooks:
        subprocess.run(["tc", "filter", "del", "dev", iface, h], check=False)

    proc = subprocess.run(["tc", "qdisc", "show", "dev", iface], check=False, capture_output=True, text=True)
    if proc.returncode == 0 and "clsact" in (proc.stdout or ""):
        subprocess.run(["tc", "qdisc", "del", "dev", iface, "clsact"], check=False)


def follow_events(out_path: Path, map_name: str, poll_sleep_s: float) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    map_ids = get_map_ids_by_name(map_name)
    if not map_ids:
        raise RuntimeError(f"no BPF map found with name={map_name}")

    map_fds: list[int] = []
    try:
        for map_id in map_ids:
            map_fds.append(bpf_map_get_fd_by_id(map_id))

        with out_path.open("a", encoding="utf-8") as fout:
            while running:
                emitted = False
                for map_fd in map_fds:
                    while running:
                        ev = bpf_map_pop_event(map_fd)
                        if ev is None:
                            break
                        line = render_event(ev)
                        if line is None:
                            continue
                        fout.write(line + "\n")
                        emitted = True
                if emitted:
                    fout.flush()
                else:
                    time.sleep(poll_sleep_s)
    finally:
        for map_fd in map_fds:
            try:
                LIBC.close(map_fd)
            except Exception:
                pass

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="eBPF dispatcher and single-line event logger")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_attach = sub.add_parser("attach", help="build and attach observer program")
    p_attach.add_argument("--iface", required=True)
    p_attach.add_argument("--hook", default="egress", choices=["ingress", "egress"])
    p_attach.add_argument("--obj", default=str(DEFAULT_OBJ))
    p_attach.add_argument("--build", action="store_true")
    p_attach.add_argument("--build-script", default=str(DEFAULT_BUILD_SCRIPT))

    p_detach = sub.add_parser("detach", help="detach observer program")
    p_detach.add_argument("--iface", required=True)
    p_detach.add_argument("--hook", default="both", choices=["ingress", "egress", "both"])

    p_follow_events = sub.add_parser("follow-events", help="consume structured eBPF events from queue map")
    p_follow_events.add_argument("--out", required=True)
    p_follow_events.add_argument("--map-name", default="poem_events")
    p_follow_events.add_argument("--poll-sleep-ms", type=int, default=20)

    args = parser.parse_args()

    if args.cmd == "attach":
        if args.build:
            run_cmd([args.build_script])
        tc_attach(args.iface, args.hook, Path(args.obj))
        print(f"attached {args.hook} tc observer on {args.iface}")
        return 0

    if args.cmd == "detach":
        tc_detach(args.iface, args.hook)
        print(f"detached tc observer from {args.iface}")
        return 0

    if args.cmd == "follow-events":
        sleep_s = max(1, args.poll_sleep_ms) / 1000.0
        return follow_events(Path(args.out), args.map_name, sleep_s)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
