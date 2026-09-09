from __future__ import annotations

import asyncio
import shlex
import struct
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import ValidationError

from .audit import record
from .execution_jobs import ACTIVE_STATUSES, recover_executions, start_execution
from .models import Mutation, Packet, RemoteHost, ScenarioCreate
from .remote_ops import offload_command, parse_ethtool_k
from .seed import seed_data
from .ssh_client import SSHClient, inspect_host
from .services import (
    create_pcap_export,
    create_scapy_export,
    create_scenario,
    get_host,
    delete_scenario,
    find_export_file,
    get_execution,
    get_scenario,
    get_template,
    list_executions,
    list_hosts,
    list_scenarios,
    list_templates,
    preview_packet,
    random_mutations,
    save_host,
    save_scenario,
    validate_mutations,
    validate_scenario_obj,
)

app = FastAPI(title="Pangea Packets API", version="0.1.0", openapi_url="/api/v1/openapi.json")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    seed_data()
    recover_executions()


def not_found(exc: KeyError) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": str(exc), "message": str(exc)})


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/scenarios")
def api_list_scenarios() -> dict[str, Any]:
    items = list_scenarios()
    return {"items": items, "total": len(items), "page": 1, "pageSize": len(items) or 20}


@app.post("/api/v1/scenarios")
def api_create_scenario(payload: ScenarioCreate):
    return create_scenario(payload)


@app.get("/api/v1/scenarios/{scenario_id}")
def api_get_scenario(scenario_id: str):
    try:
        return get_scenario(scenario_id)
    except KeyError as exc:
        raise not_found(exc)


@app.put("/api/v1/scenarios/{scenario_id}")
def api_update_scenario(scenario_id: str, payload: dict[str, Any]):
    try:
        return save_scenario(scenario_id, payload)
    except KeyError as exc:
        raise not_found(exc)
    except ValidationError as exc:
        labels = {
            "loopCount": "循环次数必须是至少为 1 的整数",
            "sendCount": "发送次数必须是至少为 1 的整数",
            "intervalMs": "发送间隔必须是至少为 0 的整数",
        }
        messages = [labels.get(str(error["loc"][-1]), f"配置字段 {'.'.join(map(str, error['loc']))} 无效") for error in exc.errors()]
        raise HTTPException(status_code=422, detail={"message": "；".join(messages)})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)})


@app.delete("/api/v1/scenarios/{scenario_id}")
def api_delete_scenario(scenario_id: str) -> dict[str, bool]:
    delete_scenario(scenario_id)
    return {"success": True}


@app.post("/api/v1/scenarios/{scenario_id}/validate")
def api_validate_scenario(scenario_id: str):
    try:
        return validate_scenario_obj(get_scenario(scenario_id))
    except KeyError as exc:
        raise not_found(exc)


@app.post("/api/v1/scenarios/{scenario_id}/duplicate")
def api_duplicate_scenario(scenario_id: str):
    try:
        scenario = get_scenario(scenario_id)
    except KeyError as exc:
        raise not_found(exc)
    clone = ScenarioCreate(name=f"{scenario.name} copy", description=scenario.description, mode=scenario.mode)
    created = create_scenario(clone)
    return save_scenario(created.id, scenario.model_dump(mode="json") | {"id": created.id, "name": clone.name})


@app.get("/api/v1/templates")
def api_list_templates() -> dict[str, Any]:
    items = list_templates()
    return {"items": items, "total": len(items)}


@app.get("/api/v1/templates/{template_id}")
def api_get_template(template_id: str):
    try:
        return get_template(template_id)
    except KeyError as exc:
        raise not_found(exc)


@app.post("/api/v1/templates/preview")
def api_preview_template(payload: dict[str, Any]):
    try:
        packet = Packet.model_validate(payload.get("packet", payload))
        validation = validate_mutations(packet, packet.mutations)
        if not validation.valid:
            raise ValueError("；".join(error.message for error in validation.errors))
        return preview_packet(packet)
    except (ValueError, TypeError, OSError, RuntimeError, OverflowError, struct.error) as exc:
        raise HTTPException(status_code=422, detail={"message": f"报文构造失败：{exc}"})


@app.get("/api/v1/mutation-types")
def api_mutation_types() -> dict[str, Any]:
    return {
        "items": [
            {"type": "invalid_value", "displayName": "字段非法值", "strategies": ["custom", "zero", "max", "random", "bit_flip"]},
            {"type": "invalid_length", "displayName": "长度异常", "strategies": ["less_than_actual", "greater_than_actual", "zero", "custom"]},
            {"type": "invalid_checksum", "displayName": "Checksum 异常", "strategies": ["zero", "max", "random", "bit_flip", "custom"]},
            {"type": "truncate_packet", "displayName": "报文截断", "strategies": ["fixed_length", "remove_tail_bytes", "truncate_at_layer", "random_length"]},
            {"type": "invalid_padding", "displayName": "非法 Padding", "strategies": ["non_zero", "random_bytes", "fake_header", "custom_bytes"]},
            {"type": "inner_outer_mismatch", "displayName": "隧道内外层异常", "strategies": ["inner_src_equals_dst", "vni_mismatch"]},
        ]
    }


@app.post("/api/v1/mutations/validate")
def api_validate_mutations(payload: dict[str, Any]):
    packet = Packet.model_validate(payload.get("packet", {}))
    mutations = [Mutation.model_validate(item) for item in payload.get("mutations", [])]
    return validate_mutations(packet, mutations)


@app.post("/api/v1/mutations/random-generate")
def api_random_mutations(payload: dict[str, Any]):
    packet = Packet.model_validate(payload.get("packet", {}))
    count = int(payload.get("count", 3))
    allowed = payload.get("allowedTypes")
    return {"mutations": random_mutations(packet, count, allowed), "warnings": []}


@app.post("/api/v1/exports/scapy")
def api_export_scapy(payload: dict[str, Any]) -> dict[str, str]:
    try:
        return create_scapy_export(payload["scenarioId"])
    except KeyError as exc:
        raise not_found(exc)


@app.post("/api/v1/exports/pcap")
def api_export_pcap(payload: dict[str, Any]) -> dict[str, str]:
    try:
        return create_pcap_export(payload["scenarioId"])
    except KeyError as exc:
        raise not_found(exc)


@app.get("/api/v1/files/{file_id}")
def api_download_file(file_id: str):
    try:
        path = find_export_file(file_id)
    except KeyError as exc:
        raise not_found(exc)
    return FileResponse(path)


@app.get("/api/v1/hosts")
def api_list_hosts() -> dict[str, Any]:
    items = list_hosts()
    return {"items": items, "total": len(items)}


@app.post("/api/v1/hosts")
def api_create_host(payload: RemoteHost):
    return save_host(payload.model_dump(mode="json"))


@app.post("/api/v1/hosts/{host_id}/connect-test")
def api_connect_test(host_id: str) -> dict[str, Any]:
    try:
        result = inspect_host(get_host(host_id))
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "HOST_CONNECT_FAILED", "message": str(exc)})
    record("host.connect_test", {"hostId": host_id, "success": True})
    return {"success": True, "sshConnected": True, "rootEntered": result["rootVerified"], "message": "ok"}


@app.post("/api/v1/hosts/{host_id}/env-check")
def api_env_check(host_id: str) -> dict[str, Any]:
    try:
        result = inspect_host(get_host(host_id))
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "HOST_ENV_CHECK_FAILED", "message": str(exc)})
    return result


@app.get("/api/v1/hosts/{host_id}/interfaces")
def api_interfaces(host_id: str) -> dict[str, Any]:
    try:
        host = get_host(host_id)
        client = SSHClient(host)
        client.connect()
        result = client.run_as_root("ip -j addr; ip -j link")
        client.close()
        if result.exitCode != 0:
            raise RuntimeError(result.stderr)
        chunks = result.stdout.strip().split("\n")
        addresses = __import__("json").loads(chunks[0])
        links = {item["ifname"]: item for item in __import__("json").loads(chunks[1])}
        items = []
        for item in addresses:
            name = item.get("ifname")
            if not name or name == "lo":
                continue
            ips = [entry.get("local") for entry in item.get("addr_info", []) if entry.get("local")]
            items.append({"name": name, "mac": item.get("address", ""), "ips": ips, "link": links.get(name, {}).get("operstate", "unknown").lower(), "speed": "unknown", "driver": "unknown", "pci": ""})
        return {"items": items, "total": len(items)}
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "NIC_QUERY_FAILED", "message": str(exc)})


@app.get("/api/v1/hosts/{host_id}/interfaces/{iface}/offload")
def api_get_offload(host_id: str, iface: str):
    try:
        client = SSHClient(get_host(host_id))
        client.connect()
        result = client.run_as_root(f"ethtool -k {shlex.quote(iface)}")
        client.close()
        if result.exitCode != 0:
            raise RuntimeError(result.stderr)
        return parse_ethtool_k(result.stdout)
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "OFFLOAD_QUERY_FAILED", "message": str(exc)})


@app.post("/api/v1/hosts/{host_id}/interfaces/{iface}/offload")
def api_set_offload(host_id: str, iface: str, payload: dict[str, Any]):
    try:
        client = SSHClient(get_host(host_id))
        client.connect()
        result = client.run_as_root(offload_command(iface, payload))
        client.close()
        if result.exitCode != 0:
            raise RuntimeError(result.stderr)
        record("nic.offload_set", {"hostId": host_id, "interface": iface, "fields": list(payload)})
        return api_get_offload(host_id, iface)
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "OFFLOAD_SET_FAILED", "message": str(exc)})


@app.get("/api/v1/hosts/{host_id}/interfaces/{iface}/stats")
def api_stats(host_id: str, iface: str):
    try:
        client = SSHClient(get_host(host_id))
        client.connect()
        result = client.run_as_root(f"ip -j -s link show dev {shlex.quote(iface)}")
        client.close()
        if result.exitCode != 0:
            raise RuntimeError(result.stderr)
        item = __import__("json").loads(result.stdout)[0]
        stats = item.get("stats64", {}).get("tx", {})
        return {"txPackets": stats.get("packets", 0), "txErrors": stats.get("errors", 0), "raw": stats}
    except (KeyError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=400, detail={"code": "NIC_STATS_FAILED", "message": str(exc)})


@app.post("/api/v1/executions", status_code=202)
def api_start_execution(payload: dict[str, Any]):
    try:
        scenario = get_scenario(payload["scenarioId"])
        validation = validate_scenario_obj(scenario)
        if not validation.valid:
            raise HTTPException(status_code=422, detail={"code": "SCENARIO_VALIDATION_FAILED", "errors": [item.model_dump() for item in validation.errors]})
        if not scenario.target.hostId:
            raise HTTPException(status_code=422, detail={"code": "TARGET_HOST_REQUIRED", "message": "场景未选择目标主机"})
        host = get_host(scenario.target.hostId)
        execution = start_execution(scenario, host)
    except KeyError as exc:
        raise not_found(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)})
    return {"executionId": execution.id, "status": execution.status}


@app.get("/api/v1/executions")
def api_list_executions() -> dict[str, Any]:
    items = list_executions()
    return {"items": items, "total": len(items)}


@app.get("/api/v1/executions/{execution_id}")
def api_get_execution(execution_id: str):
    try:
        return get_execution(execution_id)
    except KeyError as exc:
        raise not_found(exc)


@app.get("/api/v1/executions/{execution_id}/logs")
def api_get_logs(execution_id: str):
    try:
        return {"items": get_execution(execution_id).logs}
    except KeyError as exc:
        raise not_found(exc)


@app.websocket("/api/v1/executions/{execution_id}/stream")
async def execution_stream(websocket: WebSocket, execution_id: str):
    await websocket.accept()
    try:
        previous = None
        while True:
            execution = await asyncio.to_thread(get_execution, execution_id)
            snapshot = execution.model_dump(mode="json")
            if snapshot != previous:
                await websocket.send_json({"type": "execution_updated", "data": snapshot})
                previous = snapshot
            if execution.status not in ACTIVE_STATUSES:
                break
            await asyncio.sleep(0.3)
    except KeyError:
        await websocket.send_json({"type": "execution_failed", "data": {"code": "EXECUTION_NOT_FOUND"}})
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
