from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .models import OffloadState


@dataclass
class CommandResult:
    exitCode: int
    stdout: str
    stderr: str


def run_local_command(argv: list[str], timeout: int = 20) -> CommandResult:
    proc = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def build_ssh_command(host: str, port: int, username: str, command: str) -> list[str]:
    return ["ssh", "-p", str(port), f"{username}@{host}", command]


def parse_ethtool_k(output: str) -> OffloadState:
    mapping = {
        "tx-checksumming": "txChecksum",
        "rx-checksumming": "rxChecksum",
        "tcp-segmentation-offload": "tso",
        "generic-segmentation-offload": "gso",
        "generic-receive-offload": "gro",
        "large-receive-offload": "lro",
        "scatter-gather": "scatterGather",
    }
    values: dict[str, Any] = {"raw": {}}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        state = value.strip().split()[0]
        values["raw"][key] = value.strip()
        if key in mapping:
            values[mapping[key]] = state == "on"
    return OffloadState.model_validate(values)


def parse_ip_j_addr(output: str) -> list[dict[str, Any]]:
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return []


def offload_command(iface: str, payload: dict[str, Any]) -> str:
    flags = {
        "txChecksum": "tx",
        "rxChecksum": "rx",
        "tso": "tso",
        "gso": "gso",
        "gro": "gro",
        "lro": "lro",
        "scatterGather": "sg",
    }
    args = ["ethtool", "-K", shlex.quote(iface)]
    for key, flag in flags.items():
        if key in payload:
            args.extend([flag, "on" if payload[key] else "off"])
    return " ".join(args)


def local_env_check() -> dict[str, Any]:
    python = shutil.which("python3") or shutil.which("python")
    ethtool = shutil.which("ethtool")
    ip = shutil.which("ip")
    return {
        "python": {"path": python, "valid": bool(python)},
        "ethtool": {"path": ethtool, "installed": bool(ethtool)},
        "iproute2": {"path": ip, "installed": bool(ip)},
    }
