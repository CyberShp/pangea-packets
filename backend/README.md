# Pangea Packets Backend

FastAPI 后端服务，提供场景、模板、异常校验、主机、网卡、执行等 V1 API。

## 启动

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API

- Health: `GET /api/v1/health`
- OpenAPI: `GET /api/v1/openapi.json`
- Docs: `/docs`

当前能力：

- 场景、模板、异常、主机、网卡与执行 API 可用于前端联调。
- Scapy 导出会生成可独立运行的 `send_scenario.py`，以 Scapy L2 socket 发送控制端生成的最终 raw bytes。
- PCAP 导出直接生成真实 `.pcap` 文件。
- 直接模式支持 SSH 上传、`su root`、远端发包、stdout/stderr 回收与 TX 统计。
- 监听模式支持外层或 VXLAN 内层匹配、VNI、TCP flags、第 N 个命中和 seq/ack 继承注入。

## 内网实机测试准入

仅可在受限的单用户、隔离内网测试控制端使用。执行前逐项确认：

- 主机配置可直接保存 SSH 与 `su root` 密码；`app-data/` 已被 Git 忽略，不会进入仓库。
- 首次 SSH 连接会自动接受目标主机 host key；确认目标 IP/主机名属于指定测试环境。
- 目标主机、网卡和 VLAN 已获批准，测试网口不承载生产或共享业务。
- 远端检查通过：Linux、Python `>=3.7.6`、Scapy、`ethtool`、`iproute2` 和 `su root`。
- 修改 Offload 前记录原始状态；V1 只提供手动开关，结束后必须人工恢复。
- 首次执行先导出 Scapy 脚本并以 `--dry-run` 检查报文构造与发送次数。
- 首次 wire 验证必须使用旁路抓包或镜像口；同机抓包不能作为 checksum、截断或硬件卸载结果的唯一证据。
- 每个异常场景需核对脚本结果、`reportedSendCount`、TX packet delta 和旁路抓包证据。

### 已支持

- Ethernet / IPv4 / TCP / UDP / VXLAN + inner IPv4/TCP 的基础构造。
- IPv4 / TCP / UDP length、checksum、截断、padding 和 bytes patch；VXLAN 内层基础异常。
- 直接模式远端原始二层发送、监听模式外层/内层五元组匹配、VNI、TCP flags、触发序号、延迟和 `seq/ack` 继承。
- 真实 `.pcap` 导出、Scapy 脚本导出、SSH 密码登录及审计记录。

### 已知限制

- iSCSI、NVMe/TCP、RoCEv2-like 目前仅提供字段模型，未实现完整 PDU 或状态机序列化。
- 普通网卡通常不能构造真实错误 FCS/CRC，也可能补齐过短以太网帧。
- 监听模式不接管内核 TCP 状态机；RST/ACK 干扰须在目标环境专项评估。
- 未实现多用户认证、RBAC 或 TLS，不应暴露为共享内网控制面。
