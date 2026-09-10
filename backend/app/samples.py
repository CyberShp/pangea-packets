from __future__ import annotations

import base64
import json
import re
import shlex
import struct
from typing import Literal

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .models import Packet, PacketTemplate, new_id
from .services import get_host
from .ssh_client import SSHClient
from .storage import APP_DATA, TEMPLATES_DIR, read_json, write_json
from .wire import fields, repair

router = APIRouter(prefix='/api/v1')
MAX_BYTES = 16 * 1024 * 1024


def sample(raw, name):
    packet = Packet(name=name, rawHex=raw.hex())
    return {'packet': packet.model_dump(mode='json'), 'fields': fields(raw), 'length': len(raw)}


def parse_pcap(data):
    if len(data)>MAX_BYTES or len(data)<24:
        raise ValueError('PCAP 文件须为 24 字节到 16 MiB')
    magic=data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'): endian='<'
    elif magic in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'): endian='>'
    else: raise ValueError('请导入经典 PCAP 格式；PCAPNG 请先转换为 PCAP')
    major,minor,_,_,snap,link=struct.unpack(endian+'HHIIII',data[4:24])
    if (major,minor)!=(2,4) or link!=1: raise ValueError('仅支持 PCAP 2.4 Ethernet 链路类型')
    pos=24; items=[]
    while pos<len(data):
        if len(items)>=1000: raise ValueError('一次最多导入 1000 个报文，请先筛选文件')
        if pos+16>len(data): raise ValueError('PCAP 记录首部不完整')
        sec,sub,size,original=struct.unpack(endian+'IIII',data[pos:pos+16]); pos+=16
        if size>snap or size!=original or pos+size>len(data):
            raise ValueError('PCAP 含截断或损坏记录，无法作为完整报文导入')
        row=sample(data[pos:pos+size],f'报文 {len(items)+1}')
        row['timestamp']=f'{sec}.{sub}'
        items.append(row); pos+=size
    if not items: raise ValueError('PCAP 没有报文')
    return items


def store_samples(items, source):
    batch={'id':new_id('sample'),'source':source,'items':items}
    write_json(APP_DATA/'samples'/f"{batch['id']}.json",batch)
    return batch


@router.get('/samples')
def batches():
    return {'items':[read_json(p,{}) for p in sorted((APP_DATA/'samples').glob('sample-*.json'))]}


@router.post('/samples/import')
async def import_pcap(file: UploadFile):
    try:
        data=await file.read(MAX_BYTES+1)
        return store_samples(parse_pcap(data), 'PCAP 导入')
    except ValueError as exc:
        raise HTTPException(422,detail=str(exc))
    finally:
        await file.close()


class Edit(BaseModel):
    packet: Packet
    operation: Literal['inspect','field','overwrite','insert','delete','padding'] = 'inspect'
    offset: int = Field(default=0,ge=0)
    count: int = Field(default=0,ge=0,le=65535)
    hex: str = Field(default='',max_length=200000)
    field: str = ''
    value: str = ''
    calculation: Literal['preserve','checksums','lengths_checksums'] = 'preserve'


@router.post('/samples/edit')
def edit(payload: Edit):
    from .packet_engine import final_bytes
    try:
        raw=bytearray(final_bytes(payload.packet)); offset=payload.offset
        if offset>len(raw): raise ValueError('偏移超出报文范围')
        value=bytes.fromhex(payload.hex)
        if payload.operation=='field':
            import ipaddress
            f=next((f for f in fields(raw) if f['name']==payload.field),None)
            if not f: raise ValueError('字段不可编辑，请使用字节编辑')
            value=ipaddress.IPv4Address(payload.value).packed if f['kind']=='ip' else bytes.fromhex(payload.value.replace(':','')) if f['kind']=='mac' else int(payload.value,0 if payload.value.startswith('0x') else 10).to_bytes(f['size'],'big')
            if len(value)!=f['size']: raise ValueError('字段字节长度不符')
            raw[f['offset']:f['offset']+f['size']]=value
        elif payload.operation=='overwrite':
            if offset+len(value)>len(raw): raise ValueError('覆盖范围越界')
            raw[offset:offset+len(value)]=value
        elif payload.operation=='insert': raw[offset:offset]=value
        elif payload.operation=='delete':
            if offset+payload.count>len(raw): raise ValueError('删除范围越界')
            del raw[offset:offset+payload.count]
        elif payload.operation=='padding':
            if not value or len(value)>32: raise ValueError('填充模式须为 1–32 字节的 Hex')
            raw.extend((value*((payload.count+len(value)-1)//len(value)))[:payload.count])
        if payload.calculation!='preserve': raw=repair(bytes(raw),payload.calculation=='lengths_checksums')
        result=sample(bytes(raw),payload.packet.name)
        result['packet'].update(id=payload.packet.id,sendCount=payload.packet.sendCount,intervalMs=payload.packet.intervalMs)
        return result
    except (ValueError,OverflowError) as exc: raise HTTPException(422,detail=str(exc))


class TemplateWrite(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    packet: Packet


def template_path(identifier):
    if not re.fullmatch(r'user-[a-f0-9]{12}',identifier): raise HTTPException(422,detail='仅允许修改用户模板')
    return TEMPLATES_DIR/'user'/f'{identifier}.json'


def persist_template(payload,identifier):
    if not payload.name.strip(): raise HTTPException(422,detail='模板名称不能为空')
    # Freeze exact edited bytes and keep template snapshots independent of scenarios.
    result=edit(Edit(packet=payload.packet))
    template=PacketTemplate(id=identifier,name=payload.name.strip(),builtin=False,layers=[],packet=Packet.model_validate(result['packet']))
    write_json(template_path(identifier),template.model_dump(mode='json'))
    return template


@router.post('/templates')
def create_template(payload: TemplateWrite): return persist_template(payload,new_id('user'))


@router.put('/templates/{identifier}')
def update_template(identifier: str,payload: TemplateWrite):
    if not template_path(identifier).exists(): raise HTTPException(404,detail='模板不存在')
    return persist_template(payload,identifier)


@router.delete('/templates/{identifier}')
def delete_template(identifier: str):
    path=template_path(identifier)
    if not path.exists(): raise HTTPException(404,detail='模板不存在')
    path.unlink()
    return {'success':True}


class Capture(BaseModel):
    hostId: str
    interface: str = Field(min_length=1,max_length=64)
    bpf: str = Field(default='tcp or udp',max_length=512)
    seconds: int = Field(default=10,ge=1,le=30)
    count: int = Field(default=20,ge=1,le=100)
    approved: bool = False


@router.post('/samples/capture')
def capture(payload: Capture):
    if not payload.approved: raise HTTPException(422,detail='请确认已授权抓取该网口流量')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+',payload.interface): raise HTTPException(422,detail='网口名称无效')
    client=None
    try:
        host=get_host(payload.hostId); client=SSHClient(host); client.connect()
        script="import base64,json\nfrom scapy.all import sniff,Ether\npackets=sniff(iface=%r,filter=%r,timeout=%r,count=%r,store=True)\nif any(not isinstance(p,Ether) for p in packets): raise ValueError('Ethernet capture required')\nprint('PANGEA_CAPTURE='+json.dumps([base64.b64encode(bytes(p)).decode() for p in packets]))" % (payload.interface,payload.bpf,payload.seconds,payload.count)
        result=client.run_as_root('python3 -c '+shlex.quote(script),timeout=payload.seconds+20)
        if result.exitCode: raise ValueError('抓包失败，请核对远端 Scapy、libpcap、网口及过滤表达式')
        line=next((s for s in result.stdout.splitlines() if s.startswith('PANGEA_CAPTURE=')),None)
        if line is None: raise ValueError('远端未返回有效抓包结果')
        values=json.loads(line.split('=',1)[1])
        if not isinstance(values,list) or len(values)>payload.count: raise ValueError('远端返回超出抓包限制')
        items=[sample(base64.b64decode(v,validate=True),f'抓包 {i+1}') for i,v in enumerate(values)]
        return store_samples(items,f'{payload.interface} · {payload.seconds}s')
    except KeyError: raise HTTPException(404,detail='主机不存在')
    except (ValueError,RuntimeError,OSError) as exc: raise HTTPException(422,detail=str(exc))
    except Exception: raise HTTPException(422,detail='远端抓包连接失败，请检查 SSH 配置和主机状态')
    finally:
        if client: client.close()
