from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

ScenarioMode = Literal["direct", "listen"]
ExecutionStatus = Literal["pending", "running", "success", "failed", "cancelled"]
MatchMode = Literal["outer_five_tuple", "vxlan_inner_five_tuple", "custom"]
DirectionMode = Literal["host_to_array", "auto", "same_direction", "reverse_direction"]
MutationType = Literal[
    "invalid_value",
    "boundary_value",
    "invalid_length",
    "invalid_checksum",
    "invalid_header",
    "payload_mismatch",
    "truncate_packet",
    "invalid_padding",
    "inner_outer_mismatch",
    "custom_patch",
]


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class ErrorDetail(BaseModel):
    code: str
    message: str
    path: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    valid: bool
    errors: list[ErrorDetail] = Field(default_factory=list)
    warnings: list[ErrorDetail] = Field(default_factory=list)


class TargetRef(BaseModel):
    hostId: str | None = None
    interface: str | None = None


class SendOptions(BaseModel):
    loopCount: int = Field(default=1, ge=1)
    stopOnFailure: bool = True


class PacketLayer(BaseModel):
    id: str = Field(default_factory=lambda: new_id("layer"))
    type: str
    role: Literal["outer", "inner", "tunnel", "payload", "meta"] = "outer"
    fields: dict[str, Any] = Field(default_factory=dict)
    autoCalculate: dict[str, bool] = Field(default_factory=dict)


class MutationTarget(BaseModel):
    packetId: str | None = None
    layerId: str | None = None
    fieldPath: str | None = None


class Mutation(BaseModel):
    id: str = Field(default_factory=lambda: new_id("mut"))
    name: str
    enabled: bool = True
    target: MutationTarget = Field(default_factory=MutationTarget)
    type: MutationType
    strategy: str
    value: Any = None
    applyOrder: int = 100
    scope: Literal["field", "layer", "packet", "scenario"] = "field"
    options: dict[str, Any] = Field(default_factory=dict)


class Packet(BaseModel):
    id: str = Field(default_factory=lambda: new_id("pkt"))
    name: str
    enabled: bool = True
    templateId: str | None = None
    sendCount: int = Field(default=1, ge=1)
    intervalMs: int = Field(default=100, ge=0)
    layers: list[PacketLayer] = Field(default_factory=list)
    mutations: list[Mutation] = Field(default_factory=list)
    rawHex: str | None = None

    @field_validator('rawHex')
    @classmethod
    def valid_raw(cls, value):
        if value is not None:
            raw = bytes.fromhex(value)
            if not 14 <= len(raw) <= 65535:
                raise ValueError('原始 Ethernet 报文长度必须为 14–65535 字节')
            return raw.hex()
        return value


class FiveTuple(BaseModel):
    srcIp: str | None = None
    dstIp: str | None = None
    srcPort: int | None = None
    dstPort: int | None = None
    protocol: Literal["tcp", "udp", "icmp", "any"] = "tcp"


class TunnelMatch(BaseModel):
    type: Literal["vxlan"] = "vxlan"
    vni: int | None = None


class ListenMatch(BaseModel):
    mode: MatchMode = "outer_five_tuple"
    outer: FiveTuple | None = None
    tunnel: TunnelMatch | None = None
    inner: FiveTuple | None = None
    bpf: str = ""
    deepCondition: str = ""


class ListenTrigger(BaseModel):
    packetIndex: int = Field(default=1, ge=1, le=100000)
    tcpFlags: list[str] = Field(default_factory=list)
    delayMs: int = Field(default=0, ge=0, le=60000)


class ListenDirection(BaseModel):
    mode: DirectionMode = "host_to_array"
    derive: Literal["same_direction", "reverse_direction", "none"] = "same_direction"
    addresses: Literal['preserve', 'same_direction', 'reverse_direction'] = 'preserve'
    checksums: Literal['preserve', 'repair'] = 'preserve'


class CachePolicy(BaseModel):
    storePayload: bool = False
    persistToDisk: bool = False
    maxRecords: int = 1000


class ListenConfig(BaseModel):
    interface: str | None = None
    match: ListenMatch = Field(default_factory=ListenMatch)
    trigger: ListenTrigger = Field(default_factory=ListenTrigger)
    direction: ListenDirection = Field(default_factory=ListenDirection)
    cachePolicy: CachePolicy = Field(default_factory=CachePolicy)


class Scenario(BaseModel):
    id: str = Field(default_factory=lambda: new_id("scenario"))
    name: str
    description: str = ""
    version: str = "1.0"
    mode: ScenarioMode = "direct"
    target: TargetRef = Field(default_factory=TargetRef)
    sendOptions: SendOptions = Field(default_factory=SendOptions)
    listenConfig: ListenConfig | None = None
    packets: list[Packet] = Field(default_factory=list)
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)


class ScenarioCreate(BaseModel):
    name: str
    description: str = ""
    mode: ScenarioMode = "direct"


class PacketTemplate(BaseModel):
    id: str
    name: str
    builtin: bool = True
    description: str = ""
    layers: list[PacketLayer]
    packet: Packet | None = None


class FieldOffset(BaseModel):
    fieldPath: str
    startOffset: int
    endOffset: int
    valueHex: str = ""
    layerId: str | None = None
    fieldName: str | None = None
    truncated: bool = False


class PacketPreview(BaseModel):
    hex: str
    length: int
    fieldOffsets: list[FieldOffset] = Field(default_factory=list)
    warnings: list[ErrorDetail] = Field(default_factory=list)


class RemoteAuth(BaseModel):
    type: Literal["password"] = "password"
    username: str
    password: str | None = None


class PrivilegeConfig(BaseModel):
    mode: Literal["su_root"] = "su_root"
    rootPassword: str | None = None


class RemoteHost(BaseModel):
    id: str = Field(default_factory=lambda: new_id("host"))
    name: str
    address: str
    sshPort: int = 22
    auth: RemoteAuth
    privilege: PrivilegeConfig
    lastCheck: dict[str, Any] = Field(default_factory=dict)


class OffloadState(BaseModel):
    txChecksum: bool = True
    rxChecksum: bool = True
    tso: bool = True
    gso: bool = True
    gro: bool = True
    lro: bool = False
    scatterGather: bool = True
    raw: dict[str, Any] = Field(default_factory=dict)


class NicInfo(BaseModel):
    name: str
    mac: str = ""
    ips: list[str] = Field(default_factory=list)
    link: str = "unknown"
    speed: str = "unknown"
    driver: str = "unknown"
    pci: str = ""
    offload: OffloadState | None = None
    stats: dict[str, Any] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("exec"))
    scenarioId: str
    mode: ScenarioMode
    hostId: str | None = None
    interface: str | None = None
    status: ExecutionStatus = "pending"
    startedAt: datetime = Field(default_factory=datetime.utcnow)
    finishedAt: datetime | None = None
    level0: dict[str, Any] = Field(default_factory=dict)
    level1: dict[str, Any] = Field(default_factory=dict)
    logs: list[dict[str, Any]] = Field(default_factory=list)
