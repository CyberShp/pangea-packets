from __future__ import annotations

from datetime import datetime
from pathlib import Path
from random import sample
import struct
from typing import Any

from .models import (
    ErrorDetail,
    ExecutionResult,
    Mutation,
    Packet,
    PacketTemplate,
    RemoteHost,
    Scenario,
    ScenarioCreate,
    ValidationResult,
    new_id,
)
from .packet_engine import export_pcap, export_scapy_script, export_listener_script, preview_packet
from .storage import EXECUTIONS_DIR, EXPORTS_DIR, HOSTS_FILE, SCENARIOS_DIR, TEMPLATES_DIR, read_json, write_json


def list_scenarios() -> list[Scenario]:
    return [Scenario.model_validate(read_json(path, {})) for path in sorted(SCENARIOS_DIR.glob("*.json"))]


def get_scenario(scenario_id: str) -> Scenario:
    path = SCENARIOS_DIR / f"{scenario_id}.json"
    if not path.exists():
        raise KeyError("SCENARIO_NOT_FOUND")
    return Scenario.model_validate(read_json(path, {}))


def create_scenario(payload: ScenarioCreate) -> Scenario:
    scenario = Scenario(name=payload.name, description=payload.description, mode=payload.mode)
    write_json(SCENARIOS_DIR / f"{scenario.id}.json", scenario.model_dump(mode="json"))
    return scenario


def save_scenario(scenario_id: str, payload: dict[str, Any]) -> Scenario:
    current = get_scenario(scenario_id)
    merged = current.model_dump(mode="json") | payload | {"id": scenario_id, "updatedAt": datetime.utcnow().isoformat()}
    scenario = Scenario.model_validate(merged)
    for packet in scenario.packets:
        validation = validate_mutations(packet, packet.mutations)
        if not validation.valid:
            raise ValueError("；".join(error.message for error in validation.errors))
        try:
            preview_packet(packet)
        except (ValueError, TypeError, OSError, RuntimeError, OverflowError, struct.error) as exc:
            raise ValueError(f"报文 {packet.name} 无法构造：{exc}") from exc
    write_json(SCENARIOS_DIR / f"{scenario.id}.json", scenario.model_dump(mode="json"))
    return scenario


def delete_scenario(scenario_id: str) -> None:
    path = SCENARIOS_DIR / f"{scenario_id}.json"
    if path.exists():
        path.unlink()


def validate_scenario_obj(scenario: Scenario) -> ValidationResult:
    errors: list[ErrorDetail] = []
    warnings: list[ErrorDetail] = []
    if not scenario.packets:
        errors.append(ErrorDetail(code="SCENARIO_EMPTY_PACKETS", message="场景至少需要一个报文", path="packets"))
    if scenario.mode == "listen" and scenario.listenConfig is None:
        errors.append(ErrorDetail(code="LISTEN_CONFIG_REQUIRED", message="监听模式需要配置监听规则", path="listenConfig"))
    if scenario.mode == 'listen' and scenario.listenConfig:
        from .wire import layout, repair
        from .packet_engine import final_bytes
        direction = scenario.listenConfig.direction
        if scenario.sendOptions.loopCount != 1:
            errors.append(ErrorDetail(code='LISTEN_SINGLE_BATCH',message='监听模式一次触发一个批次，场景循环次数须为 1'))
        if scenario.listenConfig.match.deepCondition:
            errors.append(ErrorDetail(code='LISTEN_UNSUPPORTED_CONDITION',message='暂不支持 deepCondition，请使用 BPF 与五元组'))
        for packet in scenario.packets:
            if not packet.enabled: continue
            try:
                raw = final_bytes(packet)
                if direction.derive != 'none' or direction.addresses != 'preserve':
                    p = layout(raw,scenario.listenConfig.match.mode=='vxlan_inner_five_tuple')
                    if p['proto']!=6 or len(raw)<p['l4']+20:
                        raise ValueError('序号与地址推导仅支持完整 IPv4/TCP 首部')
                if direction.checksums=='repair': repair(raw)
                elif direction.derive!='none' or direction.addresses!='preserve':
                    warnings.append(ErrorDetail(code='INJECTION_CHECKSUM_PRESERVED',message='注入修改序号或地址但保留校验和，可能产生额外校验和异常'))
            except (ValueError,TypeError,OverflowError,IndexError) as exc:
                errors.append(ErrorDetail(code='INJECTION_INVALID_PACKET',message=f'{packet.name}: {exc}'))
    for packet_index, packet in enumerate(scenario.packets):
        try:
            preview_packet(packet)
        except (ValueError, TypeError, OSError, RuntimeError, OverflowError, struct.error) as exc:
            errors.append(ErrorDetail(code="PACKET_BUILD_FAILED", message=f"报文 {packet.name} 无法构造：{exc}", path=f"packets[{packet_index}]"))
        result = validate_mutations(packet, packet.mutations)
        for err in result.errors:
            err.path = err.path or f"packets[{packet_index}].mutations"
            errors.append(err)
        for warn in result.warnings:
            warn.path = warn.path or f"packets[{packet_index}].mutations"
            warnings.append(warn)
    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)


def list_templates() -> list[PacketTemplate]:
    templates: list[PacketTemplate] = []
    for folder in [TEMPLATES_DIR / "builtin", TEMPLATES_DIR / "user"]:
        for path in sorted(folder.glob("*.json")):
            templates.append(PacketTemplate.model_validate(read_json(path, {})))
    return templates


def get_template(template_id: str) -> PacketTemplate:
    for folder in [TEMPLATES_DIR / "builtin", TEMPLATES_DIR / "user"]:
        path = folder / f"{template_id}.json"
        if path.exists():
            return PacketTemplate.model_validate(read_json(path, {}))
    raise KeyError("TEMPLATE_NOT_FOUND")


def mutation_default_order(mutation: Mutation) -> int:
    return {
        "invalid_value": 100,
        "boundary_value": 100,
        "payload_mismatch": 200,
        "invalid_length": 300,
        "inner_outer_mismatch": 300,
        "invalid_header": 400,
        "invalid_checksum": 500,
        "invalid_padding": 600,
        "truncate_packet": 700,
        "custom_patch": 800,
    }.get(mutation.type, mutation.applyOrder)


def validate_mutations(packet: Packet, mutations: list[Mutation]) -> ValidationResult:
    errors: list[ErrorDetail] = []
    warnings: list[ErrorDetail] = []
    seen: set[tuple[str | None, int, str]] = set()
    auto_calc: dict[str, bool] = {}
    for layer in packet.layers:
        for field, enabled in layer.autoCalculate.items():
            auto_calc[f"{layer.role}.{layer.type}[0].{field}"] = enabled
            auto_calc[f"{layer.id}.{field}"] = enabled
    for mutation in [m for m in mutations if m.enabled]:
        order = mutation.applyOrder or mutation_default_order(mutation)
        key = (mutation.target.fieldPath, order, mutation.type)
        if key in seen:
            errors.append(ErrorDetail(code="MUTATION_DUPLICATE_ORDER", message="同一字段存在相同执行顺序的重复异常", path=mutation.id))
        seen.add(key)
        field_path = mutation.target.fieldPath or ""
        if mutation.type in {"invalid_length", "invalid_checksum"}:
            field = "len" if mutation.type == "invalid_length" else "chksum"
            types = {"ipv4", "udp"} if field == "len" else {"ipv4", "tcp", "udp"}
            targets = [layer for layer in packet.layers if layer.type in types and field_path == f"{layer.role}.{layer.type}[0].{field}"]
            if not targets or (mutation.target.layerId and all(layer.id != mutation.target.layerId for layer in targets)):
                errors.append(ErrorDetail(code="MUTATION_TARGET_INVALID", message=f"规则 {mutation.name} 的目标字段不匹配", path=mutation.id))
            if mutation.value is None:
                errors.append(ErrorDetail(code="MUTATION_VALUE_REQUIRED", message=f"请填写规则 {mutation.name} 的异常值", path=mutation.id))
        if mutation.type == "invalid_checksum":
            if auto_calc.get(field_path, False) and not mutation.options.get("disableAutoCalculate"):
                errors.append(ErrorDetail(code="CHECKSUM_AUTO_CALC_CONFLICT", message="checksum 自动计算与 checksum 异常冲突", path=mutation.id))
            warnings.append(ErrorDetail(code="OFFLOAD_RISK", message="checksum 异常可能被 TX checksum offload 修正", path=mutation.id))
        if mutation.type == "invalid_length" and auto_calc.get(field_path, False) and not mutation.options.get("disableAutoCalculate"):
            errors.append(ErrorDetail(code="LENGTH_AUTO_CALC_CONFLICT", message="length 自动计算与 length 异常冲突", path=mutation.id))
        if mutation.type == "truncate_packet":
            warnings.append(ErrorDetail(code="TRUNCATE_WIRE_RISK", message="普通网卡可能自动补齐或丢弃过短帧", path=mutation.id))
    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)


def random_mutations(packet: Packet, count: int, allowed_types: list[str] | None = None) -> list[Mutation]:
    allowed = allowed_types or ["invalid_length", "invalid_checksum", "inner_outer_mismatch"]
    candidates: list[Mutation] = []
    for layer in packet.layers:
        for field in layer.fields:
            field_path = f"{layer.role}.{layer.type}[0].{field}"
            if "invalid_length" in allowed and layer.type in {"ipv4", "udp"} and field == "len":
                candidates.append(Mutation(name=f"{field_path} 长度异常", target={"layerId": layer.id, "fieldPath": field_path}, type="invalid_length", strategy="custom", value=40, applyOrder=300, options={"disableAutoCalculate": True}))
            if "invalid_checksum" in allowed and layer.type in {"ipv4", "tcp", "udp"} and field == "chksum":
                candidates.append(Mutation(name=f"{field_path} invalid checksum", target={"layerId": layer.id, "fieldPath": field_path}, type="invalid_checksum", strategy="custom", value=0x1234, applyOrder=500, options={"disableAutoCalculate": True}))
    if "inner_outer_mismatch" in allowed and any(layer.type == "vxlan" for layer in packet.layers) and any(layer.type == "ipv4" and layer.role == "inner" for layer in packet.layers):
        candidates.append(Mutation(name="VXLAN inner src ip equals dst ip", type="inner_outer_mismatch", strategy="inner_src_equals_dst", applyOrder=300, scope="packet"))
    return sample(candidates, min(max(count, 0), len(candidates)))


def list_hosts() -> list[RemoteHost]:
    return [RemoteHost.model_validate(item) for item in read_json(HOSTS_FILE, [])]


def get_host(host_id: str) -> RemoteHost:
    for host in list_hosts():
        if host.id == host_id:
            return host
    raise KeyError("HOST_NOT_FOUND")


def save_host(payload: dict[str, Any]) -> RemoteHost:
    host = RemoteHost.model_validate(payload | {"id": payload.get("id") or new_id("host")})
    hosts = read_json(HOSTS_FILE, [])
    hosts = [item for item in hosts if item.get("id") != host.id]
    hosts.append(host.model_dump(mode="json"))
    write_json(HOSTS_FILE, hosts)
    return host


def list_executions() -> list[ExecutionResult]:
    return [ExecutionResult.model_validate(read_json(path, {})) for path in sorted(EXECUTIONS_DIR.glob("*/execution.json"))]


def get_execution(execution_id: str) -> ExecutionResult:
    path = EXECUTIONS_DIR / execution_id / "execution.json"
    if not path.exists():
        raise KeyError("EXECUTION_NOT_FOUND")
    return ExecutionResult.model_validate(read_json(path, {}))


def create_scapy_export(scenario_id: str) -> dict[str, str]:
    scenario = get_scenario(scenario_id)
    file_id = new_id("file")
    filename = 'listen_scenario.py' if scenario.mode == 'listen' else 'send_scenario.py'
    path = EXPORTS_DIR / "scapy" / file_id / filename
    (export_listener_script if scenario.mode == 'listen' else export_scapy_script)(scenario, path)
    return {"fileId": file_id, "fileName": filename, "downloadUrl": f"/api/v1/files/{file_id}"}


def create_pcap_export(scenario_id: str) -> dict[str, str]:
    scenario = get_scenario(scenario_id)
    file_id = new_id("file")
    path = EXPORTS_DIR / "pcap" / file_id / "scenario.pcap"
    export_pcap(scenario, path)
    return {"fileId": file_id, "fileName": "scenario.pcap", "downloadUrl": f"/api/v1/files/{file_id}"}


def find_export_file(file_id: str) -> Path:
    for path in EXPORTS_DIR.glob(f"*/{file_id}/*"):
        if path.is_file():
            return path
    raise KeyError("FILE_NOT_FOUND")
