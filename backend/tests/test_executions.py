from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from threading import Event
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.main import app
from app import execution_jobs as jobs
from app.models import ExecutionResult, Packet, RemoteHost, Scenario
from app.seed import builtin_templates
from app.ssh_client import RemoteResult, SSHClient


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(jobs, "EXECUTIONS_DIR", self.directory))
        self.stack.enter_context(patch("app.services.EXECUTIONS_DIR", self.directory))
        self.stack.enter_context(patch.object(jobs, "record"))
        pool = self.stack.enter_context(ThreadPoolExecutor(max_workers=1))
        self.stack.enter_context(patch.object(jobs, "_workers", pool))
        self.release = Event()
        self.progress = Event()
        self.scenario = Scenario(id="scenario-test", name="test", target={"hostId": "host-test", "interface": "test0"}, packets=[Packet(name="test", layers=builtin_templates()[0].layers)])
        self.host = RemoteHost(id="host-test", name="test", address="192.0.2.1", auth={"username": "test", "password": "example-secret"}, privilege={"rootPassword": "root-secret"})
        self.stack.enter_context(patch("app.main.get_scenario", return_value=self.scenario))
        self.stack.enter_context(patch("app.main.get_host", return_value=self.host))
        self.remote = Mock()
        self.remote.run_as_root.side_effect = self.command
        self.stack.enter_context(patch.object(jobs, "SSHClient", return_value=self.remote))
        self.client = TestClient(app)
        self.exit_code = 0

    def tearDown(self):
        self.release.set()
        self.stack.close()

    def command(self, command, timeout=60, on_output=None):
        if on_output is None:
            return RemoteResult(0, '{"txPackets": 10, "txErrors": 0}', "")
        on_output("remote_stdout", "first progress")
        self.progress.set()
        if not self.release.wait(3):
            raise TimeoutError("test release missing")
        on_output("remote_stdout", "second progress")
        return RemoteResult(self.exit_code, '{"reportedSendCount":1}', "remote failure" if self.exit_code else "")

    def test_start_returns_before_remote_finishes_and_stream_survives_reconnect(self):
        response = self.client.post("/api/v1/executions", json={"scenarioId": self.scenario.id})
        self.assertEqual(response.status_code, 202, response.text)
        execution_id = response.json()["executionId"]
        self.assertFalse(self.release.is_set())
        self.assertTrue(self.progress.wait(1))
        url = f"/api/v1/executions/{execution_id}"
        snapshot = self.client.get(url).json()
        self.assertEqual(snapshot["status"], "running")
        self.assertIn("first progress", [log["data"] for log in snapshot["logs"]])
        with self.client.websocket_connect(url + "/stream") as socket:
            self.assertEqual(socket.receive_json()["data"]["status"], "running")
        with self.client.websocket_connect(url + "/stream") as socket:
            self.assertEqual(socket.receive_json()["data"]["id"], execution_id)
            self.release.set()
            while True:
                final = socket.receive_json()["data"]
                if final["status"] != "running":
                    break
        self.assertEqual(final["status"], "success")
        self.assertEqual(final["level0"]["reportedSendCount"], 1)
        self.assertEqual(self.client.get(url).json(), final)
        self.assertEqual(len([log for log in final["logs"] if log["data"] == "first progress"]), 1)

    def test_listen_failure_is_persisted_with_reason(self):
        self.scenario.mode = "listen"
        from app.models import ListenConfig
        self.scenario.listenConfig = ListenConfig(interface="test0")
        self.exit_code = 2
        self.release.set()
        execution = ExecutionResult(scenarioId=self.scenario.id, mode="listen", interface="test0")
        result = jobs.run_execution(self.scenario, self.host, execution)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.level0["error"], "remote failure")
        self.assertIsNotNone(result.finishedAt)
        self.assertEqual(self.client.get(f"/api/v1/executions/{result.id}").json()["status"], "failed")

    def test_connect_failure_redacts_credentials(self):
        self.remote.connect.side_effect = RuntimeError("connection failed example-secret root-secret")
        result = jobs.run_execution(self.scenario, self.host, ExecutionResult(scenarioId=self.scenario.id, mode="direct", interface="test0"))
        self.assertEqual(result.status, "failed")
        self.assertNotIn("example-secret", result.model_dump_json())
        self.assertNotIn("root-secret", result.model_dump_json())
        self.remote.close.assert_called_once()

    def test_build_failure_finishes_and_missing_interface_is_rejected(self):
        with patch.object(jobs, "export_scapy_script", side_effect=ValueError("build failed")):
            result = jobs.run_execution(self.scenario, self.host, ExecutionResult(scenarioId=self.scenario.id, mode="direct", interface="test0"))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.level0["error"], "build failed")
        self.remote.connect.assert_not_called()
        self.scenario.target.interface = None
        self.assertEqual(self.client.post("/api/v1/executions", json={"scenarioId": self.scenario.id}).status_code, 422)

    def test_restart_recovery_keeps_completed_history(self):
        active = ExecutionResult(scenarioId=self.scenario.id, mode="direct", status="running")
        complete = ExecutionResult(scenarioId=self.scenario.id, mode="direct", status="success")
        jobs.save_execution(active)
        jobs.save_execution(complete)
        jobs.recover_executions()
        recovered = self.client.get(f"/api/v1/executions/{active.id}").json()
        self.assertEqual(recovered["status"], "failed")
        self.assertIn("未能确认", recovered["level0"]["error"])
        self.assertEqual(self.client.get(f"/api/v1/executions/{complete.id}").json()["status"], "success")


class OutputTests(unittest.TestCase):
    def setUp(self):
        host = RemoteHost(name="test", address="192.0.2.1", auth={"username": "test", "password": "unused"}, privilege={"rootPassword": "secret-pass"})
        self.client = SSHClient(host)

    def test_output_is_delivered_before_exit_and_handles_split_utf8_and_secret(self):
        chunks = [b"first\nsecret-", b"pass\n" + "输出".encode()[:2], "输出".encode()[2:] + b"\n"]
        channel = Mock()
        channel.recv_ready.side_effect = lambda: bool(chunks)
        channel.recv_stderr_ready.return_value = False
        channel.recv.side_effect = lambda size: chunks.pop(0)
        channel.exit_status_ready.side_effect = lambda: not chunks
        channel.recv_exit_status.return_value = 0
        lines = []
        def output(kind, line):
            channel.recv_exit_status.assert_not_called()
            lines.append(line)
        result = self.client._collect(channel, 30, output)
        self.assertEqual(lines, ["first", "[已隐藏]", "输出"])
        self.assertNotIn("secret-pass", result.stdout)
        channel.close.assert_called_once()

    def test_command_timeout_closes_channel(self):
        channel = Mock()
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = False
        with patch("app.ssh_client.time.monotonic", side_effect=[0, 31]):
            with self.assertRaises(TimeoutError):
                self.client._collect(channel, 30)
        channel.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
