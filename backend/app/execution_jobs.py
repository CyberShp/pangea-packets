from __future__ import annotations

import shlex
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .audit import record
from .executor import _parse_json, _stats_command
from .models import ExecutionResult, RemoteHost, Scenario
from .packet_engine import export_listener_script, export_scapy_script
from .ssh_client import SSHClient, redact_output
from .storage import EXECUTIONS_DIR, read_json

_workers = ThreadPoolExecutor(max_workers=4, thread_name_prefix="packet-execution")
ACTIVE_STATUSES = {"pending", "running"}


def save_execution(execution: ExecutionResult) -> None:
    path = EXECUTIONS_DIR / execution.id / "execution.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(execution.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(path)


def _log(execution: ExecutionResult, event: str, message: str) -> None:
    execution.logs.append({"type": event, "data": message, "timestamp": datetime.now(timezone.utc).isoformat()})
    save_execution(execution)


def recover_executions() -> None:
    for path in EXECUTIONS_DIR.glob("*/execution.json"):
        execution = ExecutionResult.model_validate(read_json(path, {}))
        if execution.status in ACTIVE_STATUSES:
            execution.status = "failed"
            execution.finishedAt = datetime.now(timezone.utc)
            execution.level0["error"] = "服务已重启，上次执行结果未能确认；请核对远端状态后再执行"
            _log(execution, "execution_failed", execution.level0["error"])


def start_execution(scenario: Scenario, host: RemoteHost) -> ExecutionResult:
    iface = scenario.listenConfig.interface if scenario.mode == "listen" and scenario.listenConfig else scenario.target.interface
    if not iface or (scenario.mode == "listen" and not scenario.listenConfig):
        raise ValueError("请配置监听网口" if scenario.mode == "listen" else "请配置发送网口")
    execution = ExecutionResult(scenarioId=scenario.id, mode=scenario.mode, hostId=host.id, interface=iface, startedAt=datetime.now(timezone.utc))
    _log(execution, "execution_queued", "任务已创建，等待执行")
    response = execution.model_copy(deep=True)
    try:
        _workers.submit(run_execution, scenario.model_copy(deep=True), host.model_copy(deep=True), execution)
    except RuntimeError:
        execution.status = "failed"
        execution.finishedAt = datetime.now(timezone.utc)
        execution.level0["error"] = "执行服务正在关闭，请稍后重试"
        _log(execution, "execution_failed", execution.level0["error"])
    return response


def run_execution(scenario: Scenario, host: RemoteHost, execution: ExecutionResult) -> ExecutionResult:
    client = None
    secrets = [value for value in [host.auth.password, host.privilege.rootPassword] if value]

    def clean(text: str) -> str:
        return redact_output(text,secrets)

    def output(kind: str, line: str) -> None:
        _log(execution, kind, clean(line))

    try:
        execution.status = "running"
        _log(execution, "execution_started", "开始构造报文与执行脚本")
        listen = scenario.mode == "listen"
        filename = "listen_scenario.py" if listen else "send_scenario.py"
        local_script = EXECUTIONS_DIR / execution.id / filename
        (export_listener_script if listen else export_scapy_script)(scenario, local_script)
        remote_script = f"/tmp/pangea-packets/{execution.id}/{filename}"
        _log(execution, "progress", "正在连接目标主机")
        client = SSHClient(host)
        client.connect()
        before = {}
        if not listen:
            _log(execution, "progress", "正在读取发送前网卡统计")
            before = _parse_json(client.run_as_root(_stats_command(execution.interface)).stdout)
        _log(execution, "progress", "正在上传执行脚本")
        client.upload(local_script, remote_script)
        command = f"chmod 700 {shlex.quote(remote_script)} && python3 -u {shlex.quote(remote_script)} --iface {shlex.quote(execution.interface)}"
        if listen:
            timeout = max(1, int(scenario.listenConfig.trigger.delayMs / 1000) + 60)
            command += f" --timeout {timeout}"
            timeout += 30
        else:
            duration_ms = sum(packet.intervalMs * packet.sendCount for packet in scenario.packets if packet.enabled) * scenario.sendOptions.loopCount
            timeout = max(60, duration_ms // 1000 + 30)
        _log(execution, "progress", "正在监听匹配流量" if listen else "正在发送报文")
        sent = client.run_as_root(command, timeout=timeout, on_output=output)
        report = _parse_json(sent.stdout)
        execution.level0 = {"exitCode": sent.exitCode, "scriptSuccess": sent.exitCode == 0, "reportedSendCount": report.get("reportedSendCount", 0), "stdout": clean(sent.stdout), "stderr": clean(sent.stderr)}
        if sent.exitCode != 0:
            execution.level0["error"] = clean(sent.stderr.strip() or sent.stdout.strip() or f"远端命令退出码为 {sent.exitCode}")
        if not listen:
            _log(execution, "progress", "正在读取发送后网卡统计")
            after = _parse_json(client.run_as_root(_stats_command(execution.interface)).stdout)
            execution.level1 = {"txPacketsBefore": before.get("txPackets"), "txPacketsAfter": after.get("txPackets"), "txErrorsBefore": before.get("txErrors"), "txErrorsAfter": after.get("txErrors"), "txPacketsDelta": after.get("txPackets", 0) - before.get("txPackets", 0)}
        execution.status = "success" if sent.exitCode == 0 else "failed"
    except Exception as exc:
        execution.status = "failed"
        execution.level0.update({"scriptSuccess": False, "error": clean(str(exc))})
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        execution.finishedAt = datetime.now(timezone.utc)
        _log(execution, "execution_finished" if execution.status == "success" else "execution_failed", "执行完成" if execution.status == "success" else str(execution.level0.get("error", "执行失败")))
    record(f"execution.{scenario.mode}", {"executionId": execution.id, "scenarioId": scenario.id, "hostId": host.id, "interface": execution.interface, "status": execution.status})
    return execution
