"""Byte-preserving Ethernet/IPv4 editing and bounded TCP injection helpers.

This stdlib-only module is embedded in the remote listener as well.
"""
import ipaddress
import struct


def layout(raw, inner=False, strict=False):
    def ipv4(eth):
        if len(raw) < eth + 14 or raw[eth+12:eth+14] != b'\x08\x00':
            raise ValueError('需要无 VLAN 的 Ethernet / IPv4 报文')
        ip = eth + 14
        if len(raw) < ip + 20 or raw[ip] >> 4 != 4:
            raise ValueError('IPv4 首部不完整')
        ihl = (raw[ip] & 15) * 4
        if ihl < 20 or len(raw) < ip + ihl:
            raise ValueError('IPv4 首部长度无效')
        if int.from_bytes(raw[ip+6:ip+8], 'big') & 0x3fff:
            raise ValueError('分片报文只支持原始字节编辑，不支持自动修正或注入推导')
        end = ip + int.from_bytes(raw[ip+2:ip+4], 'big')
        if strict and (end > len(raw) or end < ip + ihl):
            raise ValueError('IP 长度与实际字节不一致，无法自动计算')
        return {'eth': eth, 'ip': ip, 'ihl': ihl, 'l4': ip+ihl, 'proto': raw[ip+9], 'end': end}
    outer = ipv4(0)
    if not inner:
        return outer
    udp = outer['l4']
    if outer['proto'] != 17 or len(raw) < udp+16 or b'\x12\xb5' not in (raw[udp:udp+2],raw[udp+2:udp+4]) or not raw[udp+8] & 8:
        raise ValueError('需要标准 UDP/4789 VXLAN 报文')
    return ipv4(udp+16)


def fields(raw):
    result = []
    def add(name, offset, size, kind='int'):
        value = bytes(raw[offset:offset+size])
        if len(value) != size:
            return
        rendered = str(ipaddress.IPv4Address(value)) if kind == 'ip' else ':'.join(f'{v:02x}' for v in value) if kind == 'mac' else str(int.from_bytes(value, 'big'))
        result.append(dict(name=name, offset=offset, size=size, kind=kind, value=rendered))
    for inner in (False, True):
        try:
            p = layout(raw, inner)
        except ValueError:
            break
        role = 'inner' if inner else 'outer'
        e, i, t = p['eth'], p['ip'], p['l4']
        add(role+'.dstMac', e, 6, 'mac'); add(role+'.srcMac', e+6, 6, 'mac')
        add(role+'.srcIp', i+12, 4, 'ip'); add(role+'.dstIp', i+16, 4, 'ip')
        for name, off, size in [('tos',1,1), ('length',2,2), ('id',4,2), ('ttl',8,1), ('protocol',9,1), ('ipChecksum',10,2)]:
            add(role+'.'+name, i+off, size)
        if p['proto'] in (6,17):
            add(role+'.srcPort',t,2); add(role+'.dstPort',t+2,2)
        if p['proto'] == 6:
            for name, off, size in [('seq',4,4),('ack',8,4),('flags',13,1),('window',14,2),('tcpChecksum',16,2)]:
                add(role+'.'+name,t+off,size)
        elif p['proto'] == 17:
            add(role+'.udpLength',t+4,2); add(role+'.udpChecksum',t+6,2)
            if not inner and len(raw)>=t+16 and b'\x12\xb5' in (raw[t:t+2],raw[t+2:t+4]):
                add('tunnel.vni',t+12,3)
    return result


def checksum(data):
    if len(data)%2: data += b'\0'
    n = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while n >> 16: n = (n & 65535)+(n >> 16)
    return (~n)&65535


def repair(raw, lengths=False):
    data = bytearray(raw)
    outer = layout(data)
    plans = [outer]
    if outer['proto']==17 and b'\x12\xb5' in (data[outer['l4']:outer['l4']+2],data[outer['l4']+2:outer['l4']+4]):
        plans.append(layout(data,True))
    for p in reversed(plans):
        ip,t = p['ip'],p['l4']
        end = len(data) if lengths else p['end']
        if end > len(data) or end < t or end-ip > 65535:
            raise ValueError('长度异常：请保留异常字节，或明确选择修正长度')
        proto = p['proto']
        if proto not in (6,17): raise ValueError('自动修正仅支持 IPv4 TCP/UDP')
        if end-t < (20 if proto==6 else 8): raise ValueError('传输层首部不完整')
        if proto==6 and not 20 <= (data[t+12]>>4)*4 <= end-t:
            raise ValueError('TCP 首部长度无效')
        if lengths:
            data[ip+2:ip+4]=(end-ip).to_bytes(2,'big')
            if proto==17: data[t+4:t+6]=(end-t).to_bytes(2,'big')
        if proto==17 and int.from_bytes(data[t+4:t+6],'big') != end-t:
            raise ValueError('UDP 长度不一致，无法自动修正校验和')
        data[ip+10:ip+12]=b'\0\0'
        data[ip+10:ip+12]=checksum(bytes(data[ip:ip+p['ihl']])).to_bytes(2,'big')
        c = t+(16 if proto==6 else 6)
        data[c:c+2]=b'\0\0'
        pseudo=bytes(data[ip+12:ip+20])+bytes([0,proto])+(end-t).to_bytes(2,'big')
        value=checksum(pseudo+bytes(data[t:end]))
        data[c:c+2]=(value or 65535).to_bytes(2,'big')
    return bytes(data)


def inject(raw, observed, inner=False, derive='same_direction', addresses='preserve', checksums='preserve'):
    if derive == 'none' and addresses == 'preserve':
        return repair(raw) if checksums == 'repair' else raw
    target=layout(raw,inner); source=layout(observed,inner,True)
    t,s=target['l4'],source['l4']
    if target['proto']!=6 or source['proto']!=6 or len(raw)<t+20 or source['end']<s+20:
        raise ValueError('序号与地址推导需要完整 IPv4/TCP 首部')
    size=(observed[s+12]>>4)*4
    if not 20<=size<=source['end']-s: raise ValueError('触发包 TCP 首部无效')
    if not 20<=(raw[t+12]>>4)*4<=len(raw)-t: raise ValueError('注入包 TCP 首部无效')
    result=bytearray(raw)
    seq=int.from_bytes(observed[s+4:s+8],'big'); ack=int.from_bytes(observed[s+8:s+12],'big')
    if derive == 'reverse_direction':
        if not observed[s+13]&16: raise ValueError('反向推导要求触发包 ACK 有效')
        seq,ack=ack,(seq+source['end']-s-size+bool(observed[s+13]&2)+bool(observed[s+13]&1))%2**32
    if derive!='none':
        result[t+4:t+8]=seq.to_bytes(4,'big'); result[t+8:t+12]=ack.to_bytes(4,'big')
    if addresses!='preserve':
        reverse=addresses=='reverse_direction'
        pairs=[(target,source)]
        if inner: pairs.append((layout(raw),layout(observed,strict=True)))
        for dest,src in pairs:
            de,se=dest['eth'],src['eth']; di,si=dest['ip'],src['ip']; dt,st=dest['l4'],src['l4']
            result[de:de+6]=observed[se+6:se+12] if reverse else observed[se:se+6]
            result[de+6:de+12]=observed[se:se+6] if reverse else observed[se+6:se+12]
            result[di+12:di+16]=observed[si+16:si+20] if reverse else observed[si+12:si+16]
            result[di+16:di+20]=observed[si+12:si+16] if reverse else observed[si+16:si+20]
            if dest['proto']!=src['proto']: raise ValueError('触发包与注入包协议不一致')
            result[dt:dt+2]=observed[st+2:st+4] if reverse else observed[st:st+2]
            result[dt+2:dt+4]=observed[st:st+2] if reverse else observed[st+2:st+4]
    return repair(bytes(result)) if checksums=='repair' else bytes(result)
