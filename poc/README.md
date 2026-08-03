# Scapy 发包 PoC

目标：优先验证最大风险项，而不是先搭完整产品骨架。

本 PoC 覆盖四件事：

- Scapy 能否构造并发送异常 `IP.len`、`IP.chksum`、`TCP/UDP checksum`、截断报文。
- 关闭网卡 offload 后，异常长度和 checksum 字段是否能在抓包侧保留。
- 监听模式能否正确提取外层或内层 TCP `seq` / `ack` / `flags` / `window`。
- VXLAN 内层五元组和 VNI 能否稳定解析和匹配。

## 文件

- `scapy_fault_poc.py`：单文件 PoC 工具，支持 `send`、`sniff`、`pcap` 三种模式。

## 环境要求

目标 Linux：

```bash
python3 -m pip install scapy
sudo ethtool -k <iface>
```

发包和抓包通常需要 `root` 或 `CAP_NET_RAW`。如果要验证真实 wire 值，建议使用第二台主机或交换机镜像口抓包；同一台机器本地抓 TX 包时，结果可能受抓包位置和 offload 影响。

## 验证 1：普通异常 IPv4/TCP 报文

先 dry-run 看构造结果：

```bash
sudo python3 poc/scapy_fault_poc.py send \
  --iface ens5f0 \
  --src-mac 00:11:22:33:44:55 \
  --dst-mac 66:77:88:99:aa:bb \
  --src-ip 192.0.2.10 \
  --dst-ip 192.0.2.20 \
  --sport 12345 \
  --dport 3260 \
  --ip-len 0x0030 \
  --ip-chksum 0x1234 \
  --tcp-chksum 0x5678 \
  --truncate-to 54 \
  --show-hex \
  --dry-run
```

关闭 offload 并发送：

```bash
sudo python3 poc/scapy_fault_poc.py send \
  --iface ens5f0 \
  --disable-offload \
  --offload-check \
  --src-mac 00:11:22:33:44:55 \
  --dst-mac 66:77:88:99:aa:bb \
  --src-ip 192.0.2.10 \
  --dst-ip 192.0.2.20 \
  --sport 12345 \
  --dport 3260 \
  --ip-len 0x0030 \
  --ip-chksum 0x1234 \
  --tcp-chksum 0x5678 \
  --truncate-to 54 \
  --count 3
```

旁路抓包：

```bash
sudo tcpdump -i <capture-iface> -nn -vvv -XX 'host 192.0.2.10 or host 192.0.2.20'
```

预期：

- 抓包侧能看到 `IP length` 为指定异常值。
- 抓包侧能看到 IP/TCP checksum 为指定错误值，或者标记为 bad。
- 帧长度等于 `--truncate-to` 对应的截断长度。

## 验证 2：监听模式提取 seq/ack

监听外层 TCP：

```bash
sudo python3 poc/scapy_fault_poc.py sniff \
  --iface ens5f0 \
  --bpf 'tcp and port 3260' \
  --match-scope outer \
  --match-proto tcp \
  --match-src-ip 192.0.2.10 \
  --match-dst-ip 192.0.2.20 \
  --match-dport 3260 \
  --match-tcp-flags PA \
  --timeout 30
```

输出是 JSON Lines。重点看：

- `summary.tcp.seq`
- `summary.tcp.ack`
- `summary.tcp.flags`
- `summary.outer`

## 验证 3：VXLAN 内层五元组匹配

发送 VXLAN 包：

```bash
sudo python3 poc/scapy_fault_poc.py send \
  --iface ens5f0 \
  --vxlan \
  --src-mac 00:11:22:33:44:55 \
  --dst-mac 66:77:88:99:aa:bb \
  --src-ip 10.1.1.10 \
  --dst-ip 10.1.1.20 \
  --outer-dport 4789 \
  --vni 100 \
  --inner-src-ip 192.168.10.11 \
  --inner-dst-ip 192.168.10.20 \
  --inner-sport 111 \
  --inner-dport 2049 \
  --seq 1000 \
  --ack 2000
```

监听 VXLAN 内层匹配：

```bash
sudo python3 poc/scapy_fault_poc.py sniff \
  --iface ens5f0 \
  --bpf 'udp and port 4789' \
  --match-scope inner \
  --match-vni 100 \
  --match-proto tcp \
  --match-src-ip 192.168.10.11 \
  --match-dst-ip 192.168.10.20 \
  --match-sport 111 \
  --match-dport 2049 \
  --timeout 30
```

预期：

- `matched: true`
- `summary.vxlan.vni == 100`
- `summary.inner` 为内层五元组。
- `summary.inner_tcp.seq` 和 `summary.inner_tcp.ack` 与发包参数一致。

## 验证 4：离线复核 pcap

如果抓包保存为 `capture.pcap`：

```bash
python3 poc/scapy_fault_poc.py pcap capture.pcap \
  --match-scope inner \
  --match-vni 100 \
  --match-proto tcp \
  --match-src-ip 192.168.10.11 \
  --match-dst-ip 192.168.10.20 \
  --match-dport 2049
```

这一步用于把监听解析逻辑从实时抓包中拆出来，方便在不同 Linux 发行版、不同网卡上对同一份 pcap 做回归。

## 判定标准

通过：

- 在关闭 offload 后，旁路抓包能看到异常 checksum/length/truncate 保留。
- `sniff`/`pcap` 对普通 TCP 可以稳定输出 seq/ack。
- `sniff`/`pcap` 对 VXLAN 可以稳定输出 VNI 和内层五元组。

需继续专项验证：

- 关闭 offload 后 checksum 仍被修正。
- 同机抓包和旁路抓包结果不一致。
- 截断包在驱动或交换设备处被丢弃，旁路无法观察。
- VXLAN 被网卡硬件卸载后，本机抓包解析结果和旁路抓包不一致。
