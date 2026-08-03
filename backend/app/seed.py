from __future__ import annotations

from .models import Packet, PacketLayer, PacketTemplate, RemoteAuth, RemoteHost, PrivilegeConfig, Scenario
from .storage import HOSTS_FILE, SCENARIOS_DIR, TEMPLATES_DIR, ensure_dirs, read_json, write_json


def builtin_templates() -> list[PacketTemplate]:
    return [
        PacketTemplate(
            id="tmpl-ethernet-ipv4-tcp",
            name="Ethernet / IPv4 / TCP",
            description="普通 TCP 报文模板，适用于 iSCSI/NVMe-TCP 基础场景",
            layers=[
                PacketLayer(id="layer-eth0", type="ethernet", role="outer", fields={"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip0", type="ipv4", role="outer", fields={"src": "192.0.2.10", "dst": "192.0.2.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-tcp0", type="tcp", role="outer", fields={"sport": 12345, "dport": 3260, "seq": 0, "ack": 0, "flags": "A", "window": 8192, "chksum": None}, autoCalculate={"chksum": True, "dataofs": True}),
            ],
        ),
        PacketTemplate(
            id="tmpl-ethernet-ipv4-udp-vxlan",
            name="Ethernet / IPv4 / UDP / VXLAN / Inner IPv4 / TCP",
            description="VXLAN 内层 TCP 模板，支持 VNI 和内层五元组匹配",
            layers=[
                PacketLayer(id="layer-eth0", type="ethernet", role="outer", fields={"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip0", type="ipv4", role="outer", fields={"src": "10.1.1.10", "dst": "10.1.1.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-udp0", type="udp", role="outer", fields={"sport": 49152, "dport": 4789, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True}),
                PacketLayer(id="layer-vxlan0", type="vxlan", role="tunnel", fields={"flags": 8, "reserved1": "000000", "vni": 100, "reserved2": 0}),
                PacketLayer(id="layer-eth1", type="ethernet", role="inner", fields={"src": "02:00:00:00:10:01", "dst": "02:00:00:00:10:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip1", type="ipv4", role="inner", fields={"src": "192.168.10.11", "dst": "192.168.10.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-tcp1", type="tcp", role="inner", fields={"sport": 111, "dport": 2049, "seq": 1000, "ack": 2000, "flags": "PA", "window": 8192, "chksum": None}, autoCalculate={"chksum": True, "dataofs": True}),
            ],
        ),
        PacketTemplate(
            id="tmpl-iscsi-over-tcp",
            name="iSCSI over TCP",
            description="iSCSI PDU 基础模板，不包含完整状态机",
            layers=[
                PacketLayer(id="layer-eth0", type="ethernet", role="outer", fields={"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip0", type="ipv4", role="outer", fields={"src": "192.0.2.10", "dst": "192.0.2.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-tcp0", type="tcp", role="outer", fields={"sport": 12345, "dport": 3260, "seq": 0, "ack": 0, "flags": "PA", "window": 8192, "chksum": None}, autoCalculate={"chksum": True, "dataofs": True}),
                PacketLayer(id="layer-iscsi0", type="iscsi", role="payload", fields={"opcode": 1, "flags": 128, "dataSegmentLength": 0, "itt": 1, "cmdsn": 1, "expstatsn": 0}),
            ],
        ),
        PacketTemplate(
            id="tmpl-nvme-tcp",
            name="NVMe/TCP",
            description="NVMe/TCP PDU 基础模板，不包含完整队列状态机",
            layers=[
                PacketLayer(id="layer-eth0", type="ethernet", role="outer", fields={"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip0", type="ipv4", role="outer", fields={"src": "192.0.2.10", "dst": "192.0.2.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-tcp0", type="tcp", role="outer", fields={"sport": 12345, "dport": 4420, "seq": 0, "ack": 0, "flags": "PA", "window": 8192, "chksum": None}, autoCalculate={"chksum": True, "dataofs": True}),
                PacketLayer(id="layer-nvme0", type="nvme_tcp", role="payload", fields={"type": 4, "flags": 0, "hlen": None, "pdo": None, "plen": None, "commandCapsule": ""}, autoCalculate={"hlen": True, "pdo": True, "plen": True}),
            ],
        ),
        PacketTemplate(
            id="tmpl-rocev2-like",
            name="RoCEv2-like over UDP",
            description="RoCEv2-like UDP payload 模板，不承诺真实 RDMA QP 语义",
            layers=[
                PacketLayer(id="layer-eth0", type="ethernet", role="outer", fields={"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02", "type": 2048}, autoCalculate={"type": True}),
                PacketLayer(id="layer-ip0", type="ipv4", role="outer", fields={"src": "192.0.2.10", "dst": "192.0.2.20", "ttl": 64, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True, "proto": True}),
                PacketLayer(id="layer-udp0", type="udp", role="outer", fields={"sport": 49152, "dport": 4791, "len": None, "chksum": None}, autoCalculate={"len": True, "chksum": True}),
                PacketLayer(id="layer-roce0", type="rocev2_like", role="payload", fields={"opcode": 0, "pkey": 65535, "dqpn": 1, "psn": 1}),
            ],
        ),
    ]


def seed_data() -> None:
    ensure_dirs()
    for template in builtin_templates():
        write_json(TEMPLATES_DIR / "builtin" / f"{template.id}.json", template.model_dump(mode="json"))
    if not HOSTS_FILE.exists():
        host = RemoteHost(
            id="host-demo",
            name="demo-host",
            address="192.168.1.100",
            auth=RemoteAuth(username="tester", password=""),
            privilege=PrivilegeConfig(rootPassword=""),
            lastCheck={"os": "CentOS 8", "arch": "x86_64", "pythonVersion": "3.7.6", "scapyInstalled": True},
        )
        write_json(HOSTS_FILE, [host.model_dump(mode="json")])
    if not list(SCENARIOS_DIR.glob("*.json")):
        template = next(item for item in builtin_templates() if item.id == "tmpl-ethernet-ipv4-udp-vxlan")
        scenario = Scenario(
            id="scenario-demo",
            name="VXLAN 完整性回归",
            description="验证隧道内外层长度、校验和与截断异常的处理行为",
            target={"hostId": "host-demo", "interface": "ens5f0"},
            packets=[Packet(id="pkt-demo", name="vxlan_len_skew", templateId=template.id, layers=template.layers)],
        )
        write_json(SCENARIOS_DIR / f"{scenario.id}.json", scenario.model_dump(mode="json"))
