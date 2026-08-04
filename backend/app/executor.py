from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .audit import record
from .models import ExecutionResult, RemoteHost, Scenario
from .packet_engine import export_listener_script, export_scapy_script
from .ssh_client import SSHClient
from .storage import EXECUTIONS_DIR, write_json

EventSink = Callable[[dict[str, Any]], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(execution: ExecutionResult, sink: EventSink | None, event_type: str, data: Any = None) -> None:
    event = {"type": event_type, "timestamp": _now()}
    if data is not None:
        event["data"] = data
    execution.logs.append(event)
    if sink:
        sink(event)
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))


def _stats_command(iface: str) -> str:
    script = """import json, subprocess
iface = {iface!r}
text = subprocess.check_output(['ip', '-j', '-s', 'link', 'show', 'dev', iface], text=True)
data = json.loads(text)[0]
stats = data.get('stats64', {{}}).get('tx', {{}})
print(json.dumps({{'txPackets': stats.get('packets', 0), 'txErrors': stats.get('errors', 0)}}))""".format(iface=iface)
    return "python3 -c " + shlex.quote(script)


def _parse_json(result_text: str) -> dict[str, Any]:
    for line in reversed(result_text.splitlines()):
        try:
            value = json.loads(line)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            continue
    return {}


def _finish(execution: ExecutionResult, sink: EventSink | None) -> ExecutionResult:
    execution.finishedAt = datetime.now(timezone.utc)
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    if sink:
        sink({"type": "execution_finished", "timestamp": _now(), "data": {"executionId": execution.id, "status": execution.status, "level0": execution.level0, "level1": execution.level1}})
    return execution


def create_execution(scenario: Scenario, host: RemoteHost) -> ExecutionResult:
    interface = scenario.listenConfig.interface if scenario.mode == "listen" and scenario.listenConfig else scenario.target.interface
    execution = ExecutionResult(scenarioId=scenario.id, mode=scenario.mode, hostId=host.id, interface=interface, status="pending")
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    return execution


def run_listen(scenario: Scenario, host: RemoteHost, execution: ExecutionResult | None = None, sink: EventSink | None = None) -> ExecutionResult:
    if scenario.listenConfig is None or not scenario.listenConfig.interface:
        raise ValueError("监听模式未选择监听网口")
    execution = execution or create_execution(scenario, host)
    execution.status = "running"
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    _emit(execution, sink, "execution_started", {"mode": "listen", "interface": scenario.listenConfig.interface})

    local_script = EXECUTIONS_DIR / execution.id / "listen_scenario.py"
    export_listener_script(scenario, local_script)
    remote_dir = f"/tmp/pangea-packets/{execution.id}"
    remote_script = f"{remote_dir}/listen_scenario.py"
    client = SSHClient(host)
    try:
        _emit(execution, sink, "stage_changed", {"stage": "connect", "message": "连接远端主机"})
        client.connect()
        _emit(execution, sink, "stage_changed", {"stage": "upload", "message": "上传监听脚本"})
        client.upload(local_script, remote_script)
        timeout = max(1, int(scenario.listenConfig.trigger.delayMs / 1000) + 60)
        command = f"chmod 700 {shlex.quote(remote_script)} && python3 {shlex.quote(remote_script)} --iface {shlex.quote(scenario.listenConfig.interface)} --timeout {timeout}"
        _emit(execution, sink, "stage_changed", {"stage": "remote_run", "message": "监听匹配并触发注入"})
        result = client.run_as_root(command, timeout=timeout + 30)
        report = _parse_json(result.stdout)
        execution.level0 = {"exitCode": result.exitCode, "scriptSuccess": result.exitCode == 0, "reportedSendCount": report.get("reportedSendCount", 0), "stdout": result.stdout, "stderr": result.stderr}
        execution.status = "success" if result.exitCode == 0 else "failed"
        for line in result.stdout.splitlines():
            _emit(execution, sink, "remote_stdout", line)
        if result.stderr:
            _emit(execution, sink, "remote_stderr", result.stderr)
    except Exception as exc:
        execution.status = "failed"
        execution.level0 = {"scriptSuccess": False, "error": str(exc)}
        _emit(execution, sink, "execution_failed", str(exc))
    finally:
        client.close()
    record("execution.listen", {"executionId": execution.id, "scenarioId": scenario.id, "hostId": host.id, "interface": scenario.listenConfig.interface, "status": execution.status})
    return _finish(execution, sink)


def run_direct(scenario: Scenario, host: RemoteHost, execution: ExecutionResult | None = None, sink: EventSink | None = None) -> ExecutionResult:
    if not scenario.target.interface:
        raise ValueError("场景未选择发送网口")
    execution = execution or create_execution(scenario, host)
    execution.status = "running"
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    _emit(execution, sink, "execution_started", {"mode": "direct", "interface": scenario.target.interface})

    local_script = EXECUTIONS_DIR / execution.id / "send_scenario.py"
    export_scapy_script(scenario, local_script)
    remote_dir = f"/tmp/pangea-packets/{execution.id}"
    remote_script = f"{remote_dir}/send_scenario.py"
    client = SSHClient(host)
    try:
        _emit(execution, sink, "stage_changed", {"stage": "connect", "message": "连接远端主机"})
        client.connect()
        _emit(execution, sink, "stage_changed", {"stage": "stats_before", "message": "读取发送前 TX 统计"})
        before_result = client.run_as_root(_stats_command(scenario.target.interface), timeout=20)
        before = _parse_json(before_result.stdout)
        _emit(execution, sink, "stage_changed", {"stage": "upload", "message": "上传 Scapy 发包脚本"})
        client.upload(local_script, remote_script)
        command = f"chmod 700 {shlex.quote(remote_script)} && python3 {shlex.quote(remote_script)} --iface {shlex.quote(scenario.target.interface)}"
        timeout = max(60, sum(packet.intervalMs * packet.sendCount for packet in scenario.packets if packet.enabled) // 1000 + 30)
        _emit(execution, sink, "stage_changed", {"stage": "remote_run", "message": "执行远端发包"})
        sent = client.run_as_root(command, timeout=timeout)
        _emit(execution, sink, "stage_changed", {"stage": "stats_after", "message": "读取发送后 TX 统计"})
        after_result = client.run_as_root(_stats_command(scenario.target.interface), timeout=20)
        after = _parse_json(after_result.stdout)
        report = _parse_json(sent.stdout)
        execution.level0 = {"exitCode": sent.exitCode, "scriptSuccess": sent.exitCode == 0, "reportedSendCount": report.get("reportedSendCount", 0), "stdout": sent.stdout, "stderr": sent.stderr}
        execution.level1 = {"txPacketsBefore": before.get("txPackets"), "txPacketsAfter": after.get("txPackets"), "txErrorsBefore": before.get("txErrors"), "txErrorsAfter": after.get("txErrors"), "txPacketsDelta": (after.get("txPackets", 0) - before.get("txPackets", 0))}
        execution.status = "success" if sent.exitCode == 0 else "failed"
        if sent.stdout:
            for line in sent.stdout.splitlines():
                _emit(execution, sink, "remote_stdout", line)
        if sent.stderr:
            _emit(execution, sink, "remote_stderr", sent.stderr)
    except Exception as exc:
        execution.status = "failed"
        execution.level0 = {"scriptSuccess": False, "error": str(exc)}
        _emit(execution, sink, "execution_failed", str(exc))
    finally:
        client.close()
    record("execution.direct", {"executionId": execution.id, "scenarioId": scenario.id, "hostId": host.id, "interface": scenario.target.interface, "status": execution.status})
    return _finish(execution, sink)
