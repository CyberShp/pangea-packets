import base64
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.vxlan import VXLAN

from app.main import app
from app.models import Packet, Scenario
from app.packet_engine import final_bytes, export_listener_script, export_pcap
from app.samples import parse_pcap
from app.wire import fields, inject, repair


def frame():
    return bytes(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=1234,dport=3260,seq=4294967294,ack=77,flags='FA')/Raw(b'abc'))


def pcap(raw, endian='<'):
    return struct.pack(endian+'IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack(endian+'IIII',1,0,len(raw),len(raw))+raw


class SampleTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack(); self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for module, attr, value in [('samples','APP_DATA',self.root),('samples','TEMPLATES_DIR',self.root/'templates'),('services','TEMPLATES_DIR',self.root/'templates'),('services','SCENARIOS_DIR',self.root/'scenarios')]:
            self.stack.enter_context(patch(f'app.{module}.{attr}',value))
        self.client=TestClient(app)
        self.packet=Packet(name='captured',rawHex=frame().hex()).model_dump(mode='json')

    def edit(self, **kwargs):
        return self.client.post('/api/v1/samples/edit',json={'packet':self.packet,**kwargs})

    def test_import_roundtrip_both_endianness_and_persistence(self):
        for endian in ('<','>'):
            response=self.client.post('/api/v1/samples/import',files={'file':('sample.pcap',pcap(frame(),endian))})
            self.assertEqual(response.status_code,200,response.text)
            packet=Packet.model_validate(response.json()['items'][0]['packet'])
            self.assertEqual(final_bytes(packet),frame())
            path=export_pcap(Scenario(name='export',packets=[packet]),self.root/'out.pcap')
            self.assertEqual(bytes.fromhex(parse_pcap(path.read_bytes())[0]['packet']['rawHex']),frame())
        self.assertEqual(len(self.client.get('/api/v1/samples').json()['items']),2)

    def test_invalid_pcap_empty_link_and_truncation(self):
        for data in (b'bad',pcap(frame())[:-1],pcap(frame())[:24],pcap(frame())[:20]+struct.pack('<I',101)+pcap(frame())[24:]):
            self.assertEqual(self.client.post('/api/v1/samples/import',files={'file':('bad.pcap',data)}).status_code,422)

    def test_field_change_preserves_every_other_byte(self):
        response=self.edit(operation='field',field='outer.ttl',value='37')
        self.assertEqual(response.status_code,200,response.text)
        raw=bytes.fromhex(response.json()['packet']['rawHex'])
        self.assertEqual(raw[:22],frame()[:22]); self.assertEqual(raw[22],37); self.assertEqual(raw[23:],frame()[23:])

    def test_insert_delete_padding_overwrite_and_bounds(self):
        for operation, kwargs, expected in [
            ('insert',{'offset':54,'hex':'dead'},frame()[:54]+b'\xde\xad'+frame()[54:]),
            ('delete',{'offset':54,'count':2},frame()[:54]+frame()[56:]),
            ('padding',{'hex':'abcd','count':3},frame()+b'\xab\xcd\xab'),
            ('overwrite',{'offset':54,'hex':'fe'},frame()[:54]+b'\xfe'+frame()[55:])]:
            response=self.edit(operation=operation,**kwargs)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(bytes.fromhex(response.json()['packet']['rawHex']),expected)
        for args in ({'offset':1000},{'operation':'delete','count':65535},{'hex':'bad'},{'operation':'field','field':'outer.ttl','value':'999'}):
            self.assertEqual(self.edit(**args).status_code,422)

    def test_calculation_policy(self):
        response=self.edit(operation='padding',hex='ff',count=5,calculation='lengths_checksums')
        raw=bytes.fromhex(response.json()['packet']['rawHex'])
        self.assertEqual(Ether(raw)[IP].len,len(raw)-14)
        parsed=Ether(raw); del parsed[IP].chksum; del parsed[TCP].chksum
        self.assertEqual(bytes(parsed),raw)

    def test_template_crud_snapshot_and_invalid_id(self):
        created=self.client.post('/api/v1/templates',json={'name':'原始样本','packet':self.packet})
        self.assertEqual(created.status_code,200,created.text)
        identifier=created.json()['id']; frozen=created.json()['packet']['rawHex']
        self.packet['rawHex']=frame().hex()+'ffff'
        updated=self.client.put('/api/v1/templates/'+identifier,json={'name':'已修改','packet':self.packet})
        self.assertEqual(updated.status_code,200)
        self.assertEqual(created.json()['packet']['rawHex'],frozen)
        self.assertEqual(self.client.get('/api/v1/templates/'+identifier).json()['name'],'已修改')
        self.assertEqual(self.client.delete('/api/v1/templates/tmpl-ethernet-ipv4-tcp').status_code,422)
        self.assertEqual(self.client.delete('/api/v1/templates/'+identifier).status_code,200)
        self.assertEqual(self.client.get('/api/v1/templates/'+identifier).status_code,404)

    @patch('app.samples.get_host')
    @patch('app.samples.SSHClient')
    def test_capture_requires_approval_and_stores_mock_result(self, ssh, host):
        payload={'hostId':'test','interface':'eth0','seconds':1,'count':1}
        self.assertEqual(self.client.post('/api/v1/samples/capture',json=payload).status_code,422)
        ssh.assert_not_called()
        ssh.return_value.run_as_root.return_value.exitCode=0
        ssh.return_value.run_as_root.return_value.stdout='PANGEA_CAPTURE='+json.dumps([base64.b64encode(frame()).decode()])
        response=self.client.post('/api/v1/samples/capture',json={**payload,'approved':True})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['items'][0]['packet']['rawHex'],frame().hex())
        ssh.return_value.close.assert_called_once()


class InjectionTests(unittest.TestCase):
    def test_binary_evidence_is_exact_and_diagnostics_are_redacted(self):
        from app.ssh_client import redact_output
        event={'event':'trigger_evidence','wireHex':frame().hex(),'note':'abc'}
        result=json.loads(redact_output(json.dumps(event),['00','abc']))
        self.assertEqual(result['wireHex'],frame().hex())
        self.assertEqual(result['note'],'[已隐藏]')
        self.assertEqual(redact_output('diagnostic abc\n',['abc']),'diagnostic [已隐藏]\n')

    def test_reverse_wraparound_addresses_and_checksum(self):
        raw=inject(frame(),frame(),derive='reverse_direction',addresses='reverse_direction',checksums='repair')
        p=Ether(raw)
        self.assertEqual((p[TCP].seq,p[TCP].ack),(77,2))
        self.assertEqual((p[IP].src,p[TCP].sport,p.src),('192.0.2.2',3260,'02:00:00:00:00:02'))
        del p[IP].chksum; del p[TCP].chksum
        self.assertEqual(bytes(p),raw)

    def test_padding_not_counted_as_payload_and_none_preserves(self):
        observed=frame()+b'\xff'*20
        raw=inject(frame(),observed,derive='reverse_direction')
        self.assertEqual(Ether(raw)[TCP].ack,2)
        self.assertEqual(inject(frame(),b'',derive='none'),frame())

    def test_vxlan_inner_and_outer_repair(self):
        source=bytes(Ether(src='02:00:00:00:01:01',dst='02:00:00:00:01:02')/IP(src='198.51.100.1',dst='198.51.100.2')/UDP(sport=60000,dport=4789)/VXLAN(vni=10)/Ether(frame()))
        raw=inject(source,source,inner=True,derive='reverse_direction',addresses='reverse_direction',checksums='repair')
        p=Ether(raw)
        self.assertEqual(p[VXLAN][TCP].seq,77)
        for layer in (p[IP],p[UDP],p[VXLAN][IP],p[VXLAN][TCP]): del layer.chksum
        self.assertEqual(bytes(p),raw)

    def test_short_fragment_and_invalid_length_blocked(self):
        for target,source in ((frame()[:35],frame()),(frame(),frame()[:35]),(bytes(Ether()/IP(flags='MF')/TCP()),frame())):
            with self.assertRaises(ValueError): inject(target,source)
        with self.assertRaises(ValueError): repair(frame()[:40])

    def test_generated_listener_mock_send_evidence_and_timeout(self):
        scenario=Scenario(name='listener',mode='listen',packets=[Packet(name='test',rawHex=frame().hex())],listenConfig={'direction':{'derive':'reverse_direction','addresses':'reverse_direction','checksums':'repair'},'trigger':{'packetIndex':1}})
        with tempfile.TemporaryDirectory() as directory:
            path=export_listener_script(scenario,Path(directory)/'listen.py')
            scope={'__name__':'test_listener'}; exec(compile(path.read_text(),str(path),'exec'),scope)
            with patch.object(scope['conf'],'L2socket') as socket, patch('sys.argv',['listen','--iface','test0']), redirect_stdout(io.StringIO()) as output:
                scope['sniff']=lambda **kw: kw['prn'](Ether(frame()))
                scope['main']()
                self.assertEqual(socket.return_value.send.call_count,1)
                events=[json.loads(line) for line in output.getvalue().splitlines()]
                evidence=next(e for e in events if e['event']=='injection_evidence')
                self.assertEqual(evidence['wireHex'],socket.return_value.send.call_args.args[0].hex())
            with patch.object(scope['conf'],'L2socket'), patch('sys.argv',['listen','--iface','test0']), redirect_stdout(io.StringIO()):
                scope['sniff']=lambda **kw: None
                with self.assertRaises(SystemExit): scope['main']()
            with patch.object(scope['conf'],'L2socket') as socket, patch('sys.argv',['listen','--iface','test0']), redirect_stdout(io.StringIO()):
                socket.return_value.send.side_effect=OSError('test send failure')
                scope['sniff']=lambda **kw: kw['prn'](Ether(frame()))
                with self.assertRaises(SystemExit): scope['main']()
