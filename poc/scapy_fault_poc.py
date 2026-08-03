#!/usr/bin/env python3
"""Scapy PoC for malformed IP/TCP/UDP fields, truncation, and VXLAN parsing."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from scapy.all import (  # type: ignore
        Ether,
        IP,
        TCP,
        UDP,
        Raw,
        conf,
        hexdump,
        rdpcap,
        sniff,
        wrpcap,
    )
    from scapy.layers.vxlan import VXLAN  # type: ignore
except ImportError as exc:  # pragma: no cover - validated on target host.
    print("Scapy is required: python3 -m pip install scapy", file=sys.stderr)
    raise SystemExit(2) from exc


DEFAULT_OUTER_SPORT = 49152
DEFAULT_VXLAN_PORT = 4789
DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"
DEFAULT_INNER_SRC_MAC = "02:00:00:00:10:01"
DEFAULT_INNER_DST_MAC = "02:00:00:00:10:02"


@dataclass(frozen=True)
class Flow:
    proto: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]


def emit(event: str, **fields: Any) -> None:
    record = {"event": event, **fields}
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def parse_mac(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC must use aa:bb:cc:dd:ee:ff format")
    return value


def run_command(argv: List[str], dry_run: bool = False) -> Tuple[int, str, str]:
    if dry_run:
        emit("dry_run", command=" ".join(argv))
        return 0, "", ""
    proc = subprocess.run(argv, check=False, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def require_root(action: str) -> None:
    if hasattr(sys, "platform") and sys.platform.startswith("linux"):
        try:
            import os

            if os.geteuid() != 0:
                emit("warning", message=f"{action} normally requires root or CAP_NET_RAW")
        except AttributeError:
            pass


def check_offloads(iface: str) -> Dict[str, str]:
    if not shutil.which("ethtool"):
        emit("warning", message="ethtool not found; cannot inspect offload state")
        return {}

    rc, stdout, stderr = run_command(["ethtool", "-k", iface])
    if rc != 0:
        emit("warning", message="ethtool -k failed", stderr=stderr.strip())
        return {}

    states: Dict[str, str] = {}
    interesting = (
        "tx-checksumming",
        "tx-checksum-ip-generic",
        "tx-checksum-ipv4",
        "tcp-segmentation-offload",
        "generic-segmentation-offload",
        "generic-receive-offload",
        "large-receive-offload",
        "rx-checksumming",
    )
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name in interesting:
            states[name] = value.strip()
    emit("offload_state", iface=iface, states=states)
    return states


def disable_offloads(iface: str, dry_run: bool = False) -> None:
    if not shutil.which("ethtool"):
        emit("warning", message="ethtool not found; skip disabling offloads")
        return

    candidates = [
        "tx",
        "tso",
        "gso",
        "gro",
        "lro",
        "rx",
        "sg",
        "ufo",
    ]
    for feature in candidates:
        rc, _stdout, stderr = run_command(["ethtool", "-K", iface, feature, "off"], dry_run=dry_run)
        if rc != 0:
            emit(
                "offload_disable_warning",
                iface=iface,
                feature=feature,
                stderr=stderr.strip(),
            )


def build_base_packet(args: argparse.Namespace) -> Ether:
    ether_kwargs: Dict[str, str] = {}
    if args.src_mac:
        ether_kwargs["src"] = args.src_mac
    if args.dst_mac:
        ether_kwargs["dst"] = args.dst_mac

    payload = Raw(args.payload.encode("utf-8"))
    if args.l4 == "tcp":
        l4 = TCP(
            sport=args.sport,
            dport=args.dport,
            flags=args.tcp_flags,
            seq=args.seq,
            ack=args.ack,
            window=args.window,
        )
    else:
        l4 = UDP(sport=args.sport, dport=args.dport)

    ip = IP(src=args.src_ip, dst=args.dst_ip, ttl=args.ttl, id=args.ip_id)
    pkt = Ether(**ether_kwargs) / ip / l4 / payload

    if args.ip_len is not None:
        pkt[IP].len = args.ip_len
    if args.ip_chksum is not None:
        pkt[IP].chksum = args.ip_chksum
    if args.l4 == "tcp" and args.tcp_chksum is not None:
        pkt[TCP].chksum = args.tcp_chksum
    if args.l4 == "udp" and args.udp_chksum is not None:
        pkt[UDP].chksum = args.udp_chksum
    if args.udp_len is not None:
        pkt[UDP].len = args.udp_len

    return pkt


def build_vxlan_packet(args: argparse.Namespace) -> Ether:
    outer_ether_kwargs: Dict[str, str] = {}
    if args.src_mac:
        outer_ether_kwargs["src"] = args.src_mac
    if args.dst_mac:
        outer_ether_kwargs["dst"] = args.dst_mac

    inner_ether_kwargs: Dict[str, str] = {}
    if args.inner_src_mac:
        inner_ether_kwargs["src"] = args.inner_src_mac
    if args.inner_dst_mac:
        inner_ether_kwargs["dst"] = args.inner_dst_mac

    inner_payload = Raw(args.payload.encode("utf-8"))
    if args.inner_l4 == "tcp":
        inner_l4 = TCP(
            sport=args.inner_sport,
            dport=args.inner_dport,
            flags=args.tcp_flags,
            seq=args.seq,
            ack=args.ack,
            window=args.window,
        )
    else:
        inner_l4 = UDP(sport=args.inner_sport, dport=args.inner_dport)

    inner = (
        Ether(**inner_ether_kwargs)
        / IP(src=args.inner_src_ip, dst=args.inner_dst_ip, ttl=args.ttl, id=args.ip_id)
        / inner_l4
        / inner_payload
    )

    outer = (
        Ether(**outer_ether_kwargs)
        / IP(src=args.src_ip, dst=args.dst_ip, ttl=args.outer_ttl)
        / UDP(sport=args.outer_sport, dport=args.outer_dport)
        / VXLAN(vni=args.vni)
        / inner
    )

    if args.ip_len is not None:
        outer[IP].len = args.ip_len
    if args.ip_chksum is not None:
        outer[IP].chksum = args.ip_chksum
    if args.udp_chksum is not None:
        outer[UDP].chksum = args.udp_chksum
    if args.udp_len is not None:
        outer[UDP].len = args.udp_len

    inner_ip = outer[VXLAN].payload[IP]
    if args.inner_ip_len is not None:
        inner_ip.len = args.inner_ip_len
    if args.inner_ip_chksum is not None:
        inner_ip.chksum = args.inner_ip_chksum
    if args.inner_l4 == "tcp" and args.tcp_chksum is not None:
        outer[VXLAN].payload[TCP].chksum = args.tcp_chksum
    if args.inner_l4 == "udp" and args.inner_udp_chksum is not None:
        outer[VXLAN].payload[UDP].chksum = args.inner_udp_chksum

    return outer


def packet_bytes(pkt: Ether, truncate_to: Optional[int]) -> bytes:
    raw = bytes(pkt)
    if truncate_to is None:
        return raw
    if truncate_to <= 0:
        raise ValueError("--truncate-to must be greater than 0")
    return raw[:truncate_to]


def send_raw_frames(iface: str, frames: Iterable[bytes], interval_ms: int) -> int:
    require_root("Sending layer-2 packets")
    socket = conf.L2socket(iface=iface)
    sent = 0
    try:
        for frame in frames:
            socket.send(frame)
            sent += 1
            if interval_ms > 0:
                time.sleep(interval_ms / 1000.0)
    finally:
        socket.close()
    return sent


def summarize_packet(pkt: Any) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "wire_len": len(bytes(pkt)),
        "outer": None,
        "inner": None,
        "vxlan": None,
    }

    outer = extract_flow(pkt)
    if outer:
        summary["outer"] = flow_to_dict(outer)
    if IP in pkt:
        summary["outer_ip"] = {
            "len": int(pkt[IP].len) if pkt[IP].len is not None else None,
            "chksum": int(pkt[IP].chksum) if pkt[IP].chksum is not None else None,
            "ttl": int(pkt[IP].ttl) if pkt[IP].ttl is not None else None,
        }
    outer_l4 = direct_l4(pkt)
    if isinstance(outer_l4, TCP):
        summary["tcp"] = tcp_to_dict(outer_l4)
    if isinstance(outer_l4, UDP):
        summary["udp"] = {
            "len": int(outer_l4.len) if outer_l4.len is not None else None,
            "chksum": int(outer_l4.chksum) if outer_l4.chksum is not None else None,
        }

    vxlan_layer = first_vxlan(pkt)
    if vxlan_layer:
        summary["vxlan"] = {"vni": int(vxlan_layer.vni)}
        inner_pkt = vxlan_layer.payload
        inner = extract_flow(inner_pkt)
        if inner:
            summary["inner"] = flow_to_dict(inner)
        if IP in inner_pkt:
            summary["inner_ip"] = {
                "len": int(inner_pkt[IP].len) if inner_pkt[IP].len is not None else None,
                "chksum": int(inner_pkt[IP].chksum) if inner_pkt[IP].chksum is not None else None,
                "ttl": int(inner_pkt[IP].ttl) if inner_pkt[IP].ttl is not None else None,
            }
        inner_l4 = direct_l4(inner_pkt)
        if isinstance(inner_l4, TCP):
            summary["inner_tcp"] = tcp_to_dict(inner_l4)
        if isinstance(inner_l4, UDP):
            summary["inner_udp"] = {
                "len": int(inner_l4.len) if inner_l4.len is not None else None,
                "chksum": int(inner_l4.chksum) if inner_l4.chksum is not None else None,
            }

    return summary


def tcp_to_dict(tcp: TCP) -> Dict[str, Any]:
    return {
        "sport": int(tcp.sport),
        "dport": int(tcp.dport),
        "seq": int(tcp.seq),
        "ack": int(tcp.ack),
        "flags": str(tcp.flags),
        "window": int(tcp.window),
        "chksum": int(tcp.chksum) if tcp.chksum is not None else None,
    }


def flow_to_dict(flow: Flow) -> Dict[str, Any]:
    return {
        "proto": flow.proto,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
    }


def first_vxlan(pkt: Any) -> Optional[VXLAN]:
    if VXLAN in pkt:
        return pkt[VXLAN]
    return None


def direct_l4(pkt: Any) -> Optional[Any]:
    if IP not in pkt:
        return None
    payload = pkt[IP].payload
    if isinstance(payload, (TCP, UDP)):
        return payload
    return None


def extract_flow(pkt: Any) -> Optional[Flow]:
    if IP not in pkt:
        return None
    ip = pkt[IP]
    l4 = direct_l4(pkt)
    if isinstance(l4, TCP):
        return Flow("tcp", str(ip.src), str(ip.dst), int(l4.sport), int(l4.dport))
    if isinstance(l4, UDP):
        return Flow("udp", str(ip.src), str(ip.dst), int(l4.sport), int(l4.dport))
    return Flow(str(ip.proto), str(ip.src), str(ip.dst), None, None)


def match_packet(pkt: Any, args: argparse.Namespace) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    scope_pkt = pkt

    if args.match_scope == "inner":
        vxlan_layer = first_vxlan(pkt)
        if not vxlan_layer:
            return False, ["missing_vxlan"]
        if args.match_vni is not None and int(vxlan_layer.vni) != args.match_vni:
            return False, [f"vni:{int(vxlan_layer.vni)}"]
        scope_pkt = vxlan_layer.payload
        reasons.append("scope:inner")
    else:
        reasons.append("scope:outer")

    flow = extract_flow(scope_pkt)
    if not flow:
        return False, reasons + ["missing_flow"]

    checks = [
        (args.match_proto, flow.proto, "proto"),
        (args.match_src_ip, flow.src_ip, "src_ip"),
        (args.match_dst_ip, flow.dst_ip, "dst_ip"),
        (args.match_sport, flow.src_port, "src_port"),
        (args.match_dport, flow.dst_port, "dst_port"),
    ]
    for expected, actual, name in checks:
        if expected is not None and expected != actual:
            return False, reasons + [f"{name}:{actual}"]

    l4 = direct_l4(scope_pkt)
    tcp_layer = l4 if isinstance(l4, TCP) else None
    if args.match_tcp_flags and tcp_layer:
        actual_flags = set(str(tcp_layer.flags))
        expected_flags = set(args.match_tcp_flags)
        if not expected_flags.issubset(actual_flags):
            return False, reasons + [f"flags:{str(tcp_layer.flags)}"]
    elif args.match_tcp_flags:
        return False, reasons + ["missing_tcp_flags"]

    return True, reasons + ["matched"]


def cmd_send(args: argparse.Namespace) -> int:
    if args.offload_check:
        check_offloads(args.iface)
    if args.disable_offload:
        disable_offloads(args.iface, dry_run=args.dry_run)
        check_offloads(args.iface)

    pkt = build_vxlan_packet(args) if args.vxlan else build_base_packet(args)
    frame = packet_bytes(pkt, args.truncate_to)
    summary = summarize_packet(Ether(frame))
    emit(
        "prepared_packet",
        iface=args.iface,
        count=args.count,
        frame_len=len(frame),
        scapy_summary=summary,
    )
    if args.show_hex:
        hexdump(frame)
    if args.write_pcap:
        wrpcap(args.write_pcap, [Ether(frame)])
        emit("pcap_written", path=args.write_pcap)

    if args.dry_run:
        emit("send_skipped", reason="dry_run")
        return 0

    sent = send_raw_frames(args.iface, (frame for _ in range(args.count)), args.interval_ms)
    emit("send_done", iface=args.iface, sent=sent)
    return 0


def cmd_sniff(args: argparse.Namespace) -> int:
    require_root("Sniffing packets")
    matched = 0
    seen = 0

    def handle(pkt: Any) -> None:
        nonlocal matched, seen
        seen += 1
        ok, reasons = match_packet(pkt, args)
        summary = summarize_packet(pkt)
        emit("sniff_packet", seen=seen, matched=ok, reasons=reasons, summary=summary)
        if ok:
            matched += 1

    emit(
        "sniff_start",
        iface=args.iface,
        bpf=args.bpf,
        timeout=args.timeout,
        count=args.count,
        match_scope=args.match_scope,
    )
    sniff(iface=args.iface, filter=args.bpf, timeout=args.timeout, count=args.count, prn=handle, store=False)
    emit("sniff_done", seen=seen, matched=matched)
    return 0


def cmd_pcap(args: argparse.Namespace) -> int:
    packets = rdpcap(args.path)
    matched = 0
    for idx, pkt in enumerate(packets, start=1):
        ok, reasons = match_packet(pkt, args)
        if ok:
            matched += 1
        emit("pcap_packet", index=idx, matched=ok, reasons=reasons, summary=summarize_packet(pkt))
    emit("pcap_done", path=args.path, total=len(packets), matched=matched)
    return 0


def add_send_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--iface", required=True, help="Linux interface used for layer-2 send")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--show-hex", action="store_true")
    parser.add_argument("--write-pcap")
    parser.add_argument("--offload-check", action="store_true")
    parser.add_argument("--disable-offload", action="store_true")

    parser.add_argument("--src-mac", type=parse_mac, default=DEFAULT_SRC_MAC)
    parser.add_argument("--dst-mac", type=parse_mac, default=DEFAULT_DST_MAC)
    parser.add_argument("--src-ip", default="192.0.2.10")
    parser.add_argument("--dst-ip", default="192.0.2.20")
    parser.add_argument("--sport", type=int, default=12345)
    parser.add_argument("--dport", type=int, default=3260)
    parser.add_argument("--l4", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--tcp-flags", default="PA")
    parser.add_argument("--seq", type=int, default=1000)
    parser.add_argument("--ack", type=int, default=2000)
    parser.add_argument("--window", type=int, default=8192)
    parser.add_argument("--ttl", type=int, default=64)
    parser.add_argument("--ip-id", type=int, default=4660)
    parser.add_argument("--payload", default="pangea-packets-poc")

    parser.add_argument("--ip-len", type=lambda x: int(x, 0))
    parser.add_argument("--ip-chksum", type=lambda x: int(x, 0))
    parser.add_argument("--tcp-chksum", type=lambda x: int(x, 0))
    parser.add_argument("--udp-chksum", type=lambda x: int(x, 0))
    parser.add_argument("--udp-len", type=lambda x: int(x, 0))
    parser.add_argument("--truncate-to", type=int)

    parser.add_argument("--vxlan", action="store_true")
    parser.add_argument("--outer-sport", type=int, default=DEFAULT_OUTER_SPORT)
    parser.add_argument("--outer-dport", type=int, default=DEFAULT_VXLAN_PORT)
    parser.add_argument("--outer-ttl", type=int, default=64)
    parser.add_argument("--vni", type=int, default=100)
    parser.add_argument("--inner-src-mac", type=parse_mac, default=DEFAULT_INNER_SRC_MAC)
    parser.add_argument("--inner-dst-mac", type=parse_mac, default=DEFAULT_INNER_DST_MAC)
    parser.add_argument("--inner-src-ip", default="192.168.10.11")
    parser.add_argument("--inner-dst-ip", default="192.168.10.20")
    parser.add_argument("--inner-sport", type=int, default=111)
    parser.add_argument("--inner-dport", type=int, default=2049)
    parser.add_argument("--inner-l4", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--inner-ip-len", type=lambda x: int(x, 0))
    parser.add_argument("--inner-ip-chksum", type=lambda x: int(x, 0))
    parser.add_argument("--inner-udp-chksum", type=lambda x: int(x, 0))


def add_match_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--match-scope", choices=("outer", "inner"), default="outer")
    parser.add_argument("--match-vni", type=int)
    parser.add_argument("--match-proto", choices=("tcp", "udp"))
    parser.add_argument("--match-src-ip")
    parser.add_argument("--match-dst-ip")
    parser.add_argument("--match-sport", type=int)
    parser.add_argument("--match-dport", type=int)
    parser.add_argument("--match-tcp-flags")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Scapy malformed packets, offload behavior, seq/ack extraction, and VXLAN inner matching."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    send_parser = sub.add_parser("send", help="Construct and send one malformed packet template")
    add_send_args(send_parser)
    send_parser.set_defaults(func=cmd_send)

    sniff_parser = sub.add_parser("sniff", help="Sniff packets and print parsed JSON summaries")
    sniff_parser.add_argument("--iface", required=True)
    sniff_parser.add_argument("--bpf", default="ip")
    sniff_parser.add_argument("--timeout", type=int, default=30)
    sniff_parser.add_argument("--count", type=int, default=0)
    add_match_args(sniff_parser)
    sniff_parser.set_defaults(func=cmd_sniff)

    pcap_parser = sub.add_parser("pcap", help="Parse a pcap file with the same matching logic as sniff")
    pcap_parser.add_argument("path")
    add_match_args(pcap_parser)
    pcap_parser.set_defaults(func=cmd_pcap)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
