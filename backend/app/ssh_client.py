from __future__ import annotations

import json
import posixpath
import shlex
import codecs
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import paramiko

from .models import RemoteHost


def redact_output(text: str, secrets: list[str]) -> str:
    """Redact diagnostics while preserving explicitly captured binary evidence."""
    def redact(value):
        for secret in secrets:
            if secret: value = value.replace(secret, '[已隐藏]')
        return value
    lines = []
    for line in text.splitlines(keepends=True):
        try:
            event = json.loads(line)
            if isinstance(event,dict) and event.get('event') in ('trigger_evidence','injection_evidence') and re.fullmatch(r'[0-9a-f]{28,131070}',event.get('wireHex','')):
                for key in list(event):
                    if key not in ('event','wireHex') and isinstance(event[key],str):
                        event[key] = redact(event[key])
                lines.append(json.dumps(event,ensure_ascii=False)+'\n')
                continue
        except (ValueError,TypeError):
            pass
        if line.startswith('PANGEA_CAPTURE='):
            try:
                import base64
                values=json.loads(line.split('=',1)[1])
                if isinstance(values,list) and len(values)<=100 and all(isinstance(v,str) and 14<=len(base64.b64decode(v,validate=True))<=65535 for v in values):
                    lines.append(line); continue
            except (ValueError,TypeError):
                pass
        lines.append(redact(line))
    return ''.join(lines)


@dataclass
class RemoteResult:
    exitCode: int
    stdout: str
    stderr: str


class SSHClient:
    def __init__(self, host: RemoteHost) -> None:
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self) -> None:
        password = self.host.auth.password
        if not password:
            raise RuntimeError("未配置 SSH 密码")
        self.client.connect(
            hostname=self.host.address,
            port=self.host.sshPort,
            username=self.host.auth.username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            auth_timeout=15,
            banner_timeout=15,
        )

    def close(self) -> None:
        self.client.close()

    def run(self, command: str, timeout: int = 60) -> RemoteResult:
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        return self._collect(stdout.channel, timeout)

    def run_as_root(self, command: str, timeout: int = 60, on_output: Callable[[str, str], None] | None = None) -> RemoteResult:
        root_password = self.host.privilege.rootPassword
        if not root_password:
            raise RuntimeError("未配置 su root 密码")
        wrapped = f"su -c {shlex.quote(command)}"
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=True)
        stdin.write(root_password + "\n")
        stdin.flush()
        return self._collect(stdout.channel, timeout, on_output)

    def _collect(self, channel, timeout: int, on_output: Callable[[str, str], None] | None = None) -> RemoteResult:
        deadline = time.monotonic() + timeout
        decoders = {kind: codecs.getincrementaldecoder("utf-8")("replace") for kind in ("remote_stdout", "remote_stderr")}
        output = {kind: [] for kind in decoders}
        pending = {kind: "" for kind in decoders}
        secrets = [value for value in (self.host.auth.password, self.host.privilege.rootPassword) if value]

        def clean(text: str) -> str:
            return redact_output(text,secrets)

        def consume(kind: str, text: str, final: bool = False) -> None:
            output[kind].append(text)
            pending[kind] += text
            while "\n" in pending[kind]:
                line, pending[kind] = pending[kind].split("\n", 1)
                if on_output and line.strip():
                    on_output(kind, clean(line.rstrip("\r")))
            if final and pending[kind] and on_output:
                on_output(kind, clean(pending[kind]))

        try:
            while True:
                received = False
                for kind, ready, read in (("remote_stdout", channel.recv_ready, channel.recv), ("remote_stderr", channel.recv_stderr_ready, channel.recv_stderr)):
                    if ready():
                        consume(kind, decoders[kind].decode(read(32768)))
                        received = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"远端命令超过 {timeout} 秒仍未结束，请核对远端执行状态")
                if not received:
                    time.sleep(0.03)
            for kind, decoder in decoders.items():
                consume(kind, decoder.decode(b"", final=True), final=True)
            return RemoteResult(channel.recv_exit_status(), clean("".join(output["remote_stdout"])), clean("".join(output["remote_stderr"])))
        finally:
            channel.close()

    def upload(self, local_path: Path, remote_path: str) -> None:
        sftp = self.client.open_sftp()
        try:
            parent = posixpath.dirname(remote_path)
            self.run(f"mkdir -p {shlex.quote(parent)}")
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()


def inspect_host(host: RemoteHost) -> dict[str, Any]:
    client = SSHClient(host)
    try:
        client.connect()
        basic = client.run("uname -s; uname -m; command -v python3 || true; python3 --version 2>&1 || true; command -v ethtool || true; command -v ip || true")
        root = client.run_as_root("id -u")
        if basic.exitCode != 0 or root.exitCode != 0 or root.stdout.strip() != "0":
            raise RuntimeError(f"远端检查失败: {basic.stderr or root.stderr}")
        lines = basic.stdout.splitlines()
        return {
            "os": lines[0] if len(lines) > 0 else "unknown",
            "arch": lines[1] if len(lines) > 1 else "unknown",
            "python": {"path": lines[2] if len(lines) > 2 else None, "version": lines[3] if len(lines) > 3 else None, "valid": bool(len(lines) > 3 and "3.7" in lines[3] or "3.8" in lines[3] or "3.9" in lines[3] or "3.10" in lines[3] or "3.11" in lines[3] or "3.12" in lines[3])},
            "ethtool": {"installed": bool(len(lines) > 4 and lines[4])},
            "iproute2": {"installed": bool(len(lines) > 5 and lines[5])},
            "rootVerified": True,
        }
    finally:
        client.close()


def remote_json(client: SSHClient, command: str, root: bool = False) -> Any:
    result = client.run_as_root(command) if root else client.run(command)
    if result.exitCode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "远端命令执行失败")
    return json.loads(result.stdout)
