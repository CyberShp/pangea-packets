import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from scapy.utils import RawPcapReader

from app.main import app
from app.models import Mutation, Packet, Scenario
from app.packet_engine import export_pcap, export_scapy_script, final_bytes
from app.seed import builtin_templates
from app.services import preview_packet, random_mutations, validate_mutations


class EditingTests(unittest.TestCase):
    def setUp(self):
        self.packet = Packet(id="test-packet", name="VXLAN test", layers=builtin_templates()[1].layers)
        self.client = TestClient(app)

    def test_preview_tracks_fields_and_manual_checksum(self):
        initial = bytes.fromhex(preview_packet(self.packet).hex)
        self.packet.layers[1].fields["ttl"] = 37
        self.packet.layers[3].fields["vni"] = 321
        self.packet.layers[6].fields.update({"dport": 8080, "chksum": 0})
        self.packet.layers[6].autoCalculate["chksum"] = False
        raw = bytes.fromhex(preview_packet(self.packet).hex)
        self.assertNotEqual(initial, raw)
        self.assertEqual(raw[22], 37)
        self.assertEqual(int.from_bytes(raw[46:49], "big"), 321)
        self.assertEqual(int.from_bytes(raw[86:88], "big"), 8080)
        self.assertEqual(raw[100:102], b"\x00\x00")
        self.packet.layers[6].autoCalculate["chksum"] = True
        self.assertNotEqual(bytes.fromhex(preview_packet(self.packet).hex)[100:102], b"\x00\x00")

    def test_preview_pcap_and_script_have_identical_bytes(self):
        self.packet.mutations = [Mutation(name="checksum", type="invalid_checksum", strategy="custom", value=0x1234,
            target={"layerId": "layer-ip0", "fieldPath": "outer.ipv4[0].chksum"}, options={"disableAutoCalculate": True})]
        scenario = Scenario(name="test", packets=[self.packet])
        original = scenario.model_dump()
        expected = bytes.fromhex(preview_packet(self.packet).hex)
        with tempfile.TemporaryDirectory() as directory:
            pcap = export_pcap(scenario, Path(directory) / "test.pcap")
            with RawPcapReader(str(pcap)) as reader:
                self.assertEqual(next(reader)[0], expected)
            script = export_scapy_script(scenario, Path(directory) / "send.py")
            tree = ast.parse(script.read_text())
            assignment = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "SCENARIO" for target in node.targets))
            embedded = json.loads(ast.literal_eval(assignment.value.args[0]))
            self.assertEqual(bytes.fromhex(embedded["packets"][0]["_wireHex"]), expected)
        self.assertEqual(final_bytes(self.packet), expected)
        self.assertEqual(scenario.model_dump(), original)

    def test_preview_does_not_change_source_fields(self):
        self.packet.mutations = [Mutation(name="inner equal", type="inner_outer_mismatch", strategy="inner_src_equals_dst")]
        before = self.packet.model_dump()
        first = preview_packet(self.packet)
        self.assertEqual(preview_packet(self.packet), first)
        self.assertEqual(self.packet.model_dump(), before)

    def test_generated_rules_apply_and_toggle(self):
        self.packet.mutations = random_mutations(self.packet, 3)
        self.assertEqual(len(self.packet.mutations), 3)
        self.assertTrue(validate_mutations(self.packet, self.packet.mutations).valid)
        mutated = preview_packet(self.packet).hex
        for mutation in self.packet.mutations:
            mutation.enabled = False
        self.assertNotEqual(preview_packet(self.packet).hex, mutated)
        self.packet.mutations = []
        self.assertEqual(preview_packet(self.packet).length, 110)

    def test_rule_conflict_requires_explicit_override(self):
        mutation = Mutation(name="checksum", type="invalid_checksum", strategy="custom", value=0,
            target={"layerId": "layer-ip0", "fieldPath": "outer.ipv4[0].chksum"})
        self.assertFalse(validate_mutations(self.packet, [mutation]).valid)
        mutation.options["disableAutoCalculate"] = True
        self.assertTrue(validate_mutations(self.packet, [mutation]).valid)

    def test_save_readback_and_reject_invalid_edits(self):
        with tempfile.TemporaryDirectory() as directory, patch("app.services.SCENARIOS_DIR", Path(directory)):
            created = self.client.post("/api/v1/scenarios", json={"name": "editing test"}).json()
            url = f'/api/v1/scenarios/{created["id"]}'
            payload = {"packets": [self.packet.model_dump()], "mode": "listen",
                "target": {"hostId": "test-host", "interface": "test0"},
                "sendOptions": {"loopCount": 3, "stopOnFailure": False},
                "listenConfig": {"interface": "test0", "match": {"bpf": "tcp"}}}
            result = self.client.put(url, json=payload)
            self.assertEqual(result.status_code, 200, result.text)
            saved = self.client.get(url).json()
            self.assertEqual(saved["target"], payload["target"])
            self.assertEqual(saved["sendOptions"], payload["sendOptions"])
            self.assertEqual(saved["mode"], "listen")
            self.assertEqual(saved["packets"][0]["layers"], payload["packets"][0]["layers"])
            invalid_count = self.client.put(url, json={"sendOptions": {"loopCount": 0}})
            self.assertEqual(invalid_count.status_code, 422)
            self.assertIn("循环次数必须", invalid_count.json()["detail"]["message"])
            invalid = self.packet.model_copy(deep=True)
            invalid.layers[1].fields["ttl"] = "invalid"
            self.assertEqual(self.client.put(url, json={"packets": [invalid.model_dump()]}).status_code, 422)
            self.assertEqual(self.client.get(url).json(), saved)

    def test_bad_preview_returns_actionable_error(self):
        self.packet.layers[6].fields["dport"] = "invalid"
        result = self.client.post("/api/v1/templates/preview", json={"packet": self.packet.model_dump()})
        self.assertEqual(result.status_code, 422)
        self.assertIn("报文构造失败", result.json()["detail"]["message"])


if __name__ == "__main__":
    unittest.main()
