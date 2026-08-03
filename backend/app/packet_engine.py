from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ErrorDetail, FieldOffset, Mutation, Packet, PacketLayer, PacketPreview, Scenario


def _scapy():
    try:
        from scapy.all import Ether, IP, TCP, UDP, Raw, VXLAN, wrpcap  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Scapy 未安装；请在后端环境安装 scapy") from exc
    return Ether, IP, TCP, UDP, Raw, VXLAN, wrpcap


def _layer(packet: Packet, layer_type: str, role: str) -> PacketLayer | None:
    return next((item for item in packet.layers if item.type == layer_type and item.role == role), None)


def _value(layer: PacketLayer | None, name: str, default: Any) -> Any:
    if layer is None:
        return default
    value = layer.fields.get(name, default)
    return default if value is None else value


def _enabled(packet: Packet, mutation_type: str) -> list[Mutation]:
    return sorted([m for m in packet.mutations if m.enabled and m.type == mutation_type], key=lambda m: m.applyOrder)


def _matches(mutation: Mutation, role: str, layer_type: str, field: str) -> bool:
    target = mutation.target.fieldPath or ""
    return target.endswith(f".{field}") and f"{role}.{layer_type}" in target


def _mutate_layer_fields(packet: Packet) -> None:
    for mutation in _enabled(packet, "inner_outer_mismatch"):
        if mutation.strategy != "inner_src_equals_dst":
            continue
        inner_ip = _layer(packet, "ipv4", "inner")
        if inner_ip:
            inner_ip.fields["src"] = inner_ip.fields.get("dst", inner_ip.fields.get("src"))
    for mutation in _enabled(packet, "invalid_value") + _enabled(packet, "boundary_value") + _enabled(packet, "invalid_header"):
        path = mutation.target.fieldPath or ""
        for layer in packet.layers:
            if layer.id == mutation.target.layerId or f"{layer.role}.{layer.type}" in path:
                field = path.rsplit(".", 1)[-1]
                if field in layer.fields:
                    layer.fields[field] = mutation.value
                    layer.autoCalculate[field] = False


def build_scapy_packet(packet: Packet):
    Ether, IP, TCP, UDP, Raw, VXLAN, _ = _scapy()
    _mutate_layer_fields(packet)
    outer_eth = _layer(packet, "ethernet", "outer")
    outer_ip = _layer(packet, "ipv4", "outer")
    outer_tcp = _layer(packet, "tcp", "outer")
    outer_udp = _layer(packet, "udp", "outer")
    tunnel = _layer(packet, "vxlan", "tunnel")
    inner_eth = _layer(packet, "ethernet", "inner")
    inner_ip = _layer(packet, "ipv4", "inner")
    inner_tcp = _layer(packet, "tcp", "inner")
    inner_udp = _layer(packet, "udp", "inner")
    payload = _layer(packet, "raw_payload", "payload")

    frame = Ether(src=_value(outer_eth, "src", "02:00:00:00:00:01"), dst=_value(outer_eth, "dst", "02:00:00:00:00:02"))
    frame /= IP(src=_value(outer_ip, "src", "192.0.2.10"), dst=_value(outer_ip, "dst", "192.0.2.20"), ttl=int(_value(outer_ip, "ttl", 64)), id=int(_value(outer_ip, "id", 1)))
    if tunnel:
        frame /= UDP(sport=int(_value(outer_udp, "sport", 49152)), dport=int(_value(outer_udp, "dport", 4789)))
        frame /= VXLAN(flags=int(_value(tunnel, "flags", 8)), vni=int(_value(tunnel, "vni", 100)))
        frame /= Ether(src=_value(inner_eth, "src", "02:00:00:00:10:01"), dst=_value(inner_eth, "dst", "02:00:00:00:10:02"))
        frame /= IP(src=_value(inner_ip, "src", "192.168.10.11"), dst=_value(inner_ip, "dst", "192.168.10.20"), ttl=int(_value(inner_ip, "ttl", 64)))
        if inner_tcp:
            frame /= TCP(sport=int(_value(inner_tcp, "sport", 111)), dport=int(_value(inner_tcp, "dport", 2049)), seq=int(_value(inner_tcp, "seq", 0)), ack=int(_value(inner_tcp, "ack", 0)), flags=_value(inner_tcp, "flags", "PA"), window=int(_value(inner_tcp, "window", 8192)))
        else:
            frame /= UDP(sport=int(_value(inner_udp, "sport", 111)), dport=int(_value(inner_udp, "dport", 2049)))
    elif outer_tcp:
        frame /= TCP(sport=int(_value(outer_tcp, "sport", 12345)), dport=int(_value(outer_tcp, "dport", 3260)), seq=int(_value(outer_tcp, "seq", 0)), ack=int(_value(outer_tcp, "ack", 0)), flags=_value(outer_tcp, "flags", "A"), window=int(_value(outer_tcp, "window", 8192)))
    else:
        frame /= UDP(sport=int(_value(outer_udp, "sport", 49152)), dport=int(_value(outer_udp, "dport", 9)))
    raw = _value(payload, "bytes", "PANGEA")
    if isinstance(raw, str):
        raw = raw.encode()
    frame /= Raw(raw)

    for mutation in _enabled(packet, "invalid_length"):
        target = mutation.target.fieldPath or ""
        value = int(mutation.value if mutation.value is not None else 40)
        if "inner.ipv4" in target and tunnel:
            frame[VXLAN].payload[IP].len = value
        elif "outer.ipv4" in target:
            frame[IP].len = value
        elif "inner.udp" in target and tunnel:
            frame[VXLAN].payload[UDP].len = value
        elif "outer.udp" in target and outer_udp:
            frame[UDP].len = value
    for mutation in _enabled(packet, "invalid_checksum"):
        target = mutation.target.fieldPath or ""
        value = int(mutation.value if mutation.value is not None else 0x1234)
        if "inner.ipv4" in target and tunnel:
            frame[VXLAN].payload[IP].chksum = value
        elif "outer.ipv4" in target:
            frame[IP].chksum = value
        elif "inner.tcp" in target and tunnel:
            frame[VXLAN].payload[TCP].chksum = value
        elif "outer.tcp" in target and outer_tcp:
            frame[TCP].chksum = value
        elif "inner.udp" in target and tunnel:
            frame[VXLAN].payload[UDP].chksum = value
        elif "outer.udp" in target and outer_udp:
            frame[UDP].chksum = value
    return frame


def final_bytes(packet: Packet) -> bytes:
    raw = bytearray(bytes(build_scapy_packet(packet)))
    for mutation in _enabled(packet, "invalid_padding"):
        amount = int(mutation.value or 0)
        if amount:
            fill = b"\xff" * amount if mutation.strategy == "non_zero" else bytes((index % 251 for index in range(amount)))
            raw.extend(fill)
    for mutation in _enabled(packet, "truncate_packet"):
        amount = int(mutation.value or 0)
        if amount <= 0:
            continue
        raw = raw[:-amount] if mutation.strategy == "remove_tail_bytes" else raw[:amount]
    for mutation in _enabled(packet, "custom_patch"):
        offset = int(mutation.options.get("offset", 0))
        patch = bytes.fromhex(str(mutation.options.get("bytes", "")))
        if 0 <= offset <= len(raw) and offset + len(patch) <= len(raw):
            raw[offset:offset + len(patch)] = patch
    return bytes(raw)


def preview_packet(packet: Packet) -> PacketPreview:
    raw = final_bytes(packet)
    warnings: list[ErrorDetail] = []
    offsets: list[FieldOffset] = []
    # Fixed header fields are measured from the actual serialized packet, not placeholder text.
    if len(raw) >= 34:
        offsets.extend([
            FieldOffset(fieldPath="outer.ethernet[0].dst", startOffset=0, endOffset=6, valueHex=raw[0:6].hex()),
            FieldOffset(fieldPath="outer.ethernet[0].src", startOffset=6, endOffset=12, valueHex=raw[6:12].hex()),
            FieldOffset(fieldPath="outer.ipv4[0].len", startOffset=16, endOffset=18, valueHex=raw[16:18].hex()),
            FieldOffset(fieldPath="outer.ipv4[0].chksum", startOffset=24, endOffset=26, valueHex=raw[24:26].hex()),
        ])
    if _enabled(packet, "truncate_packet"):
        warnings.append(ErrorDetail(code="TRUNCATED_PREVIEW", message="预览 bytes 已按截断规则裁剪"))
    return PacketPreview(hex=raw.hex(" "), length=len(raw), fieldOffsets=offsets, warnings=warnings)


def _remote_runtime(scenario: Scenario) -> str:
    data = scenario.model_dump(mode="json")
    for packet in data["packets"]:
        model = next(item for item in scenario.packets if item.id == packet["id"])
        packet["_wireHex"] = final_bytes(model).hex()
    scenario_json = json.dumps(data, ensure_ascii=False)
    return f'''#!/usr/bin/env python3
# Generated by Pangea Packets. Execute only on an approved test host.
import json, sys, time
from scapy.all import Ether, IP, TCP, UDP, Raw, conf, wrpcap
from scapy.layers.vxlan import VXLAN
SCENARIO = json.loads({scenario_json!r})
# The full packet builder is intentionally kept in the controller; this exported script
# is a portable direct-mode baseline that preserves provided packet bytes when present.
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--pcap')
    args = parser.parse_args()
    frames = []
    sent = 0
    socket = None if args.dry_run else conf.L2socket(iface=args.iface)
    try:
        for _ in range(int(SCENARIO.get('sendOptions', {{}}).get('loopCount', 1))):
            for packet in SCENARIO['packets']:
                if not packet.get('enabled', True): continue
                # Controller-produced raw bytes are embedded per packet when execution is scheduled.
                raw = bytes.fromhex(packet.get('_wireHex', ''))
                if not raw: raise RuntimeError('missing controller-built wire bytes')
                frames.append(raw)
                for _ in range(int(packet.get('sendCount', 1))):
                    if socket is not None: socket.send(raw)
                    sent += 1
                    time.sleep(int(packet.get('intervalMs', 0)) / 1000)
    finally:
        if socket is not None: socket.close()
    if args.pcap: wrpcap(args.pcap, frames)
    print(json.dumps({{'event':'send_complete','reportedSendCount':sent}}))
if __name__ == '__main__': main()
'''


def export_scapy_script(scenario: Scenario, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_remote_runtime(scenario), encoding="utf-8")
    target.chmod(0o700)
    return target


def export_listener_script(scenario: Scenario, target: Path) -> Path:
    if scenario.listenConfig is None:
        raise ValueError("监听模式缺少 listenConfig")
    data = scenario.model_dump(mode="json")
    for packet in data["packets"]:
        model = next(item for item in scenario.packets if item.id == packet["id"])
        packet["_wireHex"] = final_bytes(model).hex()
    config = json.dumps(data, ensure_ascii=False)
    source = f'''#!/usr/bin/env python3
# Generated listener/injector for an approved isolated test network.
import argparse, json, time
from scapy.all import Ether, IP, TCP, UDP, conf, sniff
from scapy.layers.vxlan import VXLAN
SCENARIO = json.loads({config!r})
LISTEN = SCENARIO['listenConfig']
MATCH = LISTEN['match']

def l4(packet):
    if IP not in packet: return None
    value = packet[IP].payload
    return value if isinstance(value, (TCP, UDP)) else None

def flow_ok(packet):
    scope = packet
    if MATCH.get('mode') == 'vxlan_inner_five_tuple':
        if VXLAN not in packet: return False, None
        tunnel = MATCH.get('tunnel') or {{}}
        if tunnel.get('vni') is not None and int(packet[VXLAN].vni) != int(tunnel['vni']): return False, None
        scope = packet[VXLAN].payload
        expected = MATCH.get('inner') or {{}}
    else:
        expected = MATCH.get('outer') or {{}}
    if IP not in scope: return False, None
    ip, transport = scope[IP], l4(scope)
    if expected.get('srcIp') and expected['srcIp'] != ip.src: return False, None
    if expected.get('dstIp') and expected['dstIp'] != ip.dst: return False, None
    if expected.get('protocol') in ('tcp', 'udp') and (not transport or expected['protocol'] != ('tcp' if isinstance(transport, TCP) else 'udp')): return False, None
    if expected.get('srcPort') is not None and (not transport or int(expected['srcPort']) != int(transport.sport)): return False, None
    if expected.get('dstPort') is not None and (not transport or int(expected['dstPort']) != int(transport.dport)): return False, None
    flags = (LISTEN.get('trigger') or {{}}).get('tcpFlags') or []
    if flags and (not isinstance(transport, TCP) or not set(flags).issubset(set(str(transport.flags)))): return False, None
    return True, transport

def patch_seq_ack(raw, packet, transport):
    # This patches only the TCP seq/ack fields in final raw bytes, preserving deliberate
    # length/checksum/padding/truncation mutations already built by the controller.
    result = bytearray(raw)
    if MATCH.get('mode') == 'vxlan_inner_five_tuple':
        outer_ihl = (result[14] & 0x0f) * 4
        offset = 14 + outer_ihl + 8 + 8 + 14
        inner_ihl = (result[offset] & 0x0f) * 4
        tcp_offset = offset + inner_ihl
    else:
        tcp_offset = 14 + ((result[14] & 0x0f) * 4)
    payload_len = max(0, len(bytes(transport.payload)))
    seq, ack = int(transport.seq), int(transport.ack)
    direction = (LISTEN.get('direction') or {{}}).get('derive', 'same_direction')
    if direction == 'reverse_direction':
        seq, ack = ack, seq + payload_len + (1 if 'S' in str(transport.flags) or 'F' in str(transport.flags) else 0)
    result[tcp_offset+4:tcp_offset+8] = seq.to_bytes(4, 'big')
    result[tcp_offset+8:tcp_offset+12] = ack.to_bytes(4, 'big')
    return bytes(result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', required=True)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    bpf = MATCH.get('bpf') or ('udp and port 4789' if MATCH.get('mode') == 'vxlan_inner_five_tuple' else 'tcp or udp')
    target_index = int((LISTEN.get('trigger') or {{}}).get('packetIndex', 1))
    delay = int((LISTEN.get('trigger') or {{}}).get('delayMs', 0)) / 1000
    seen = matched = sent = 0
    socket = conf.L2socket(iface=args.iface)
    def handle(packet):
        nonlocal seen, matched, sent
        seen += 1
        ok, transport = flow_ok(packet)
        if not ok: return
        matched += 1
        print(json.dumps({{'event':'listen_match','seen':seen,'matched':matched,'seq':getattr(transport, 'seq', None),'ack':getattr(transport, 'ack', None)}}), flush=True)
        if matched != target_index: return
        if delay: time.sleep(delay)
        for item in SCENARIO['packets']:
            if not item.get('enabled', True): continue
            raw = bytes.fromhex(item['_wireHex'])
            if isinstance(transport, TCP): raw = patch_seq_ack(raw, packet, transport)
            for _ in range(int(item.get('sendCount', 1))):
                socket.send(raw); sent += 1; time.sleep(int(item.get('intervalMs', 0)) / 1000)
        raise KeyboardInterrupt
    try:
        print(json.dumps({{'event':'listen_start','bpf':bpf,'timeout':args.timeout}}), flush=True)
        sniff(iface=args.iface, filter=bpf, timeout=args.timeout, store=False, prn=handle)
    except KeyboardInterrupt:
        pass
    finally:
        socket.close()
    print(json.dumps({{'event':'listen_complete','seen':seen,'matched':matched,'reportedSendCount':sent}}), flush=True)
if __name__ == '__main__': main()
'''
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    target.chmod(0o700)
    return target


def export_pcap(scenario: Scenario, target: Path) -> Path:
    _, _, _, _, _, _, wrpcap = _scapy()
    frames = [final_bytes(packet) for packet in scenario.packets if packet.enabled]
    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), frames)
    return target
