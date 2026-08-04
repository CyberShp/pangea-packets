from __future__ import annotations

import asyncio
import json
import posixpath
import shlex
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko

from .models import RemoteHost

_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="pangea-ssh")


@dataclass
class RemoteResult:
    exitCode: int
    stdout: str
    stderr: str


def tcp_probe(host: str, port: int = 22, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


class SSHClient:
    """Small SSH wrapper tuned for one-shot packet execution hosts.

    The implementation follows the already-validated observation_web approach:
    fail fast with a TCP probe, keep the Paramiko transport alive, read command
    output before recv_exit_status() to avoid Paramiko buffer deadlocks, and
    expose async helpers so FastAPI can run SSH work without blocking the event
    loop.
    """

    CONNECT_TIMEOUT = 15
    KEEPALIVE_INTERVAL = 30

    def __init__(self, host: RemoteHost) -> None:
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._lock = threading.RLock()
        self._connected_at: float | None = None
        self.last_error = ""

    def is_connected(self) -> bool:
        try:
            transport = self.client.get_transport()
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def connect(self) -> None:
        password = self.host.auth.password
        if not password:
            raise RuntimeError("未配置 SSH 密码")
        if not tcp_probe(self.host.address, self.host.sshPort, timeout=2.0):
            raise RuntimeError(f"Host {self.host.address}:{self.host.sshPort} unreachable (TCP probe failed)")

        with self._lock:
            try:
                self.client.connect(
                    hostname=self.host.address,
                    port=self.host.sshPort,
                    username=self.host.auth.username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=self.CONNECT_TIMEOUT,
                    auth_timeout=self.CONNECT_TIMEOUT,
                    banner_timeout=self.CONNECT_TIMEOUT,
                )
                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(self.KEEPALIVE_INTERVAL)
                self._connected_at = time.time()
                self.last_error = ""
            except Exception as exc:
                self.last_error = str(exc)
                self.close()
                raise

    async def connect_async(self) -> None:
        await asyncio.get_running_loop().run_in_executor(_executor, self.connect)

    def close(self) -> None:
        with self._lock:
            try:
                self.client.close()
            except Exception:
                pass

    def _ensure_connected(self) -> None:
        if not self.is_connected():
            self.connect()

    def run(self, command: str, timeout: int = 60, get_pty: bool = False) -> RemoteResult:
        self._ensure_connected()
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout, get_pty=get_pty)
            channel = stdout.channel
            channel.settimeout(timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = channel.recv_exit_status()
            return RemoteResult(exit_code, out, err)
        except Exception as exc:
            self.last_error = str(exc)
            return RemoteResult(-1, "", str(exc))

    async def run_async(self, command: str, timeout: int = 60, get_pty: bool = False) -> RemoteResult:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, self.run, command, timeout, get_pty),
            timeout=max(timeout + 10, timeout * 2),
        )

    def run_as_root(self, command: str, timeout: int = 60) -> RemoteResult:
        root_password = self.host.privilege.rootPassword
        if not root_password:
            raise RuntimeError("未配置 su root 密码")
        self._ensure_connected()
        wrapped = f"su -c {shlex.quote(command)}"
        try:
            stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=True)
            stdin.write(root_password + "\n")
            stdin.flush()
            channel = stdout.channel
            channel.settimeout(timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = channel.recv_exit_status()
            return RemoteResult(exit_code, out, err)
        except Exception as exc:
            self.last_error = str(exc)
            return RemoteResult(-1, "", str(exc))

    async def run_as_root_async(self, command: str, timeout: int = 60) -> RemoteResult:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, self.run_as_root, command, timeout),
            timeout=max(timeout + 10, timeout * 2),
        )

    def upload(self, local_path: Path, remote_path: str) -> None:
        self._ensure_connected()
        parent = posixpath.dirname(remote_path)
        mkdir_result = self.run(f"mkdir -p {shlex.quote(parent)}", timeout=15)
        if mkdir_result.exitCode != 0:
            raise RuntimeError(mkdir_result.stderr or mkdir_result.stdout or "创建远端目录失败")
        sftp = self.client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()

    async def upload_async(self, local_path: Path, remote_path: str) -> None:
        await asyncio.get_running_loop().run_in_executor(_executor, self.upload, local_path, remote_path)


def _python_valid(version: str | None) -> bool:
    if not version:
        return False
    return any(token in version for token in ["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13"])


def inspect_host(host: RemoteHost) -> dict[str, Any]:
    client = SSHClient(host)
    try:
        client.connect()
        basic = client.run("uname -s; uname -m; command -v python3 || true; python3 --version 2>&1 || true; command -v ethtool || true; command -v ip || true; python3 - <<'PY'\ntry:\n import scapy.all\n print('scapy:yes')\nexcept Exception as exc:\n print('scapy:no:' + str(exc))\nPY", timeout=20)
        root = client.run_as_root("id -u", timeout=20)
        if basic.exitCode != 0 or root.exitCode != 0 or root.stdout.strip().splitlines()[-1:] != ["0"]:
            raise RuntimeError(f"远端检查失败: {basic.stderr or root.stderr or root.stdout}")
        lines = basic.stdout.splitlines()
        python_version = lines[3] if len(lines) > 3 else None
        scapy_line = next((line for line in lines if line.startswith("scapy:")), "scapy:no")
        return {
            "os": lines[0] if len(lines) > 0 else "unknown",
            "arch": lines[1] if len(lines) > 1 else "unknown",
            "python": {"path": lines[2] if len(lines) > 2 else None, "version": python_version, "valid": _python_valid(python_version)},
            "scapy": {"installed": scapy_line == "scapy:yes", "raw": scapy_line},
            "ethtool": {"path": lines[4] if len(lines) > 4 else None, "installed": bool(len(lines) > 4 and lines[4])},
            "iproute2": {"path": lines[5] if len(lines) > 5 else None, "installed": bool(len(lines) > 5 and lines[5])},
            "rootVerified": True,
            "tcpProbe": True,
        }
    finally:
        client.close()


def remote_json(client: SSHClient, command: str, root: bool = False) -> Any:
    result = client.run_as_root(command) if root else client.run(command)
    if result.exitCode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "远端命令执行失败")
    return json.loads(result.stdout)
