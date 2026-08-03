from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from .audit import record
from .models import ExecutionResult, RemoteHost, Scenario
from .packet_engine import export_listener_script, export_scapy_script
from .ssh_client import SSHClient
from .storage import EXECUTIONS_DIR, write_json


def _stats_command(iface: str) -> str:
    script = """import json, subprocess
iface = {iface!r}
text = subprocess.check_output(['ip', '-j', '-s', 'link', 'show', 'dev', iface], text=True)
data = json.loads(text)[0]
stats = data.get('stats64', {{}}).get('tx', {{}})
print(json.dumps({{'txPackets': stats.get('packets', 0), 'txErrors': stats.get('errors', 0)}}))""".format(iface=iface)
    return "python3 -c " + shlex.quote(script)


def _parse_json(result_text: str) -> dict:
    for line in reversed(result_text.splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {}


def run_listen(scenario: Scenario, host: RemoteHost) -> ExecutionResult:
    if scenario.listenConfig is None or not scenario.listenConfig.interface:
        raise ValueError("监听模式未选择监听网口")
    execution = ExecutionResult(scenarioId=scenario.id, mode="listen", hostId=host.id, interface=scenario.listenConfig.interface, status="running")
    execution.logs.append({"type": "execution_started", "timestamp": datetime.now(timezone.utc).isoformat()})
    local_script = EXECUTIONS_DIR / execution.id / "listen_scenario.py"
    export_listener_script(scenario, local_script)
    remote_dir = f"/tmp/pangea-packets/{execution.id}"
    remote_script = f"{remote_dir}/listen_scenario.py"
    client = SSHClient(host)
    try:
        client.connect()
        client.upload(local_script, remote_script)
        timeout = max(1, int(scenario.listenConfig.trigger.delayMs / 1000) + 60)
        command = f"chmod 700 {shlex.quote(remote_script)} && python3 {shlex.quote(remote_script)} --iface {shlex.quote(scenario.listenConfig.interface)} --timeout {timeout}"
        result = client.run_as_root(command, timeout=timeout + 30)
        report = _parse_json(result.stdout)
        execution.level0 = {"exitCode": result.exitCode, "scriptSuccess": result.exitCode == 0, "reportedSendCount": report.get("reportedSendCount", 0), "stdout": result.stdout, "stderr": result.stderr}
        execution.status = "success" if result.exitCode == 0 else "failed"
        for line in result.stdout.splitlines():
            execution.logs.append({"type": "remote_stdout", "data": line})
        if result.stderr:
            execution.logs.append({"type": "remote_stderr", "data": result.stderr})
    except Exception as exc:
        execution.status = "failed"
        execution.level0 = {"scriptSuccess": False, "error": str(exc)}
        execution.logs.append({"type": "execution_failed", "data": str(exc)})
    finally:
        try:
            client.close()
        except Exception:
            pass
    execution.finishedAt = datetime.now(timezone.utc)
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    record("execution.listen", {"executionId": execution.id, "scenarioId": scenario.id, "hostId": host.id, "interface": scenario.listenConfig.interface, "status": execution.status})
    return execution


def run_direct(scenario: Scenario, host: RemoteHost) -> ExecutionResult:
    if not scenario.target.interface:
        raise ValueError("场景未选择发送网口")
    execution = ExecutionResult(scenarioId=scenario.id, mode="direct", hostId=host.id, interface=scenario.target.interface, status="running")
    execution.logs.append({"type": "execution_started", "timestamp": datetime.now(timezone.utc).isoformat()})
    local_script = EXECUTIONS_DIR / execution.id / "send_scenario.py"
    export_scapy_script(scenario, local_script)
    remote_dir = f"/tmp/pangea-packets/{execution.id}"
    remote_script = f"{remote_dir}/send_scenario.py"
    client = SSHClient(host)
    try:
        client.connect()
        before_result = client.run_as_root(_stats_command(scenario.target.interface))
        before = _parse_json(before_result.stdout)
        client.upload(local_script, remote_script)
        command = f"chmod 700 {shlex.quote(remote_script)} && python3 {shlex.quote(remote_script)} --iface {shlex.quote(scenario.target.interface)}"
        sent = client.run_as_root(command, timeout=max(60, sum(packet.intervalMs * packet.sendCount for packet in scenario.packets) // 1000 + 30))
        after_result = client.run_as_root(_stats_command(scenario.target.interface))
        after = _parse_json(after_result.stdout)
        report = _parse_json(sent.stdout)
        execution.level0 = {"exitCode": sent.exitCode, "scriptSuccess": sent.exitCode == 0, "reportedSendCount": report.get("reportedSendCount", 0), "stdout": sent.stdout, "stderr": sent.stderr}
        execution.level1 = {"txPacketsBefore": before.get("txPackets"), "txPacketsAfter": after.get("txPackets"), "txErrorsBefore": before.get("txErrors"), "txErrorsAfter": after.get("txErrors"), "txPacketsDelta": (after.get("txPackets", 0) - before.get("txPackets", 0))}
        execution.status = "success" if sent.exitCode == 0 else "failed"
        execution.logs.append({"type": "remote_stdout", "data": sent.stdout})
        if sent.stderr:
            execution.logs.append({"type": "remote_stderr", "data": sent.stderr})
    except Exception as exc:
        execution.status = "failed"
        execution.level0 = {"scriptSuccess": False, "error": str(exc)}
        execution.logs.append({"type": "execution_failed", "data": str(exc)})
    finally:
        try:
            client.close()
        except Exception:
            pass
    execution.finishedAt = datetime.now(timezone.utc)
    write_json(EXECUTIONS_DIR / execution.id / "execution.json", execution.model_dump(mode="json"))
    record("execution.direct", {"executionId": execution.id, "scenarioId": scenario.id, "hostId": host.id, "interface": scenario.target.interface, "status": execution.status})
    return execution
