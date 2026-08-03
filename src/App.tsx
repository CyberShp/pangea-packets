import { useEffect, useMemo, useState } from "react";
import { apiGet, apiPost, executionStreamUrl } from "./api-contract";

type Status = "可执行" | "有警告" | "未校验";
type Mode = "直接模式" | "监听模式";
type DrawerTab = "Hex" | "日志" | "校验问题" | "执行输出";

type Packet = {
  id: number;
  enabled: boolean;
  name: string;
  template: string;
  mutations: number;
  count: number;
  interval: string;
  status: Status;
};

const initialPackets: Packet[] = [
  {
    id: 1,
    enabled: true,
    name: "baseline_tcp_syn",
    template: "TCP / IPv4",
    mutations: 0,
    count: 1,
    interval: "100 ms",
    status: "可执行",
  },
  {
    id: 2,
    enabled: true,
    name: "vxlan_len_skew",
    template: "VXLAN / TCP",
    mutations: 3,
    count: 1,
    interval: "100 ms",
    status: "有警告",
  },
  {
    id: 3,
    enabled: false,
    name: "truncated_payload",
    template: "UDP / IPv4",
    mutations: 1,
    count: 5,
    interval: "50 ms",
    status: "未校验",
  },
];

const nav = ["场景工作台", "协议编辑器", "异常用例", "监听模式", "远端主机", "执行结果", "设置"];
const navGlyphs = ["▦", "⌘", "✦", "◉", "▣", "↗", "⚙"];
const drawerTabs: DrawerTab[] = ["Hex", "日志", "校验问题", "执行输出"];

export default function App() {
  const [activeNav, setActiveNav] = useState("场景工作台");
  const [mode, setMode] = useState<Mode>("直接模式");
  const [packets, setPackets] = useState(initialPackets);
  const [selected, setSelected] = useState(2);
  const [validated, setValidated] = useState(false);
  const [drawer, setDrawer] = useState<DrawerTab>("Hex");
  const [running, setRunning] = useState(false);
  const [scenarioId, setScenarioId] = useState<string | null>(null);
  const [remoteLogs, setRemoteLogs] = useState<string[]>([]);
  const [apiError, setApiError] = useState<string>("");

  useEffect(() => {
    apiGet<{ items: Array<{ id: string; mode: "direct" | "listen"; packets: Array<{ id: string; enabled: boolean; name: string; templateId?: string; mutations: unknown[]; sendCount: number; intervalMs: number }> }> }>("/scenarios")
      .then(({ items }) => {
        const scenario = items[0];
        if (!scenario) return;
        setScenarioId(scenario.id);
        setMode(scenario.mode === "listen" ? "监听模式" : "直接模式");
        if (scenario.packets.length) {
          setPackets(scenario.packets.map((packet, index) => ({
            id: index + 1,
            enabled: packet.enabled,
            name: packet.name,
            template: packet.templateId ?? "自定义模板",
            mutations: packet.mutations.length,
            count: packet.sendCount,
            interval: `${packet.intervalMs} ms`,
            status: "未校验",
          })));
          setSelected(1);
        }
      })
      .catch((error: Error) => setApiError(`后端未连接：${error.message}`));
  }, []);

  const selectedPacket = useMemo(
    () => packets.find((packet) => packet.id === selected) ?? packets[0],
    [packets, selected],
  );
  const enabled = packets.filter((packet) => packet.enabled).length;

  const togglePacket = (id: number) => {
    setPackets((list) =>
      list.map((packet) => (packet.id === id ? { ...packet, enabled: !packet.enabled } : packet)),
    );
  };

  const addPacket = () => {
    const id = Math.max(...packets.map((packet) => packet.id)) + 1;
    setPackets([
      ...packets,
      {
        id,
        enabled: true,
        name: `packet_${String(id).padStart(2, "0")}`,
        template: "TCP / IPv4",
        mutations: 0,
        count: 1,
        interval: "100 ms",
        status: "未校验",
      },
    ]);
    setSelected(id);
  };

  const validate = async () => {
    if (!scenarioId) return;
    setApiError("");
    try {
      const result = await apiPost<{ valid: boolean; errors: Array<{ message: string }>; warnings: Array<{ message: string }> }>(`/scenarios/${scenarioId}/validate`);
      setValidated(result.valid);
      setPackets((list) => list.map((packet) => ({ ...packet, status: result.valid ? (result.warnings.length ? "有警告" : "可执行") : "未校验" })));
      if (!result.valid) setApiError(result.errors.map((item) => item.message).join("；"));
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "场景校验失败");
    }
  };

  const execute = async () => {
    if (!scenarioId) return;
    setRunning(true);
    setDrawer("执行输出");
    setRemoteLogs([]);
    setApiError("");
    try {
      const result = await apiPost<{ executionId: string; status: string }>("/executions", { scenarioId });
      const socket = new WebSocket(executionStreamUrl(result.executionId));
      socket.onmessage = (event) => setRemoteLogs((logs) => [...logs, event.data]);
      socket.onerror = () => setApiError("执行日志连接失败");
      socket.onclose = () => setRunning(false);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "执行请求失败");
      setRunning(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">∿</span>
          <span>
            PACKET<span>LAB</span>
          </span>
          <small>异常报文生成器</small>
        </div>
        <div className="crumb">
          <span>项目</span>
          <b>edge-regression</b>
          <i>/</i>
          <span>场景</span>
          <b>vxlan-integrity-suite</b>
        </div>
        <div className="top-status">
          <span className="host-dot" />
          <span>{scenarioId ? "已加载场景" : "等待后端"}</span>
          <span className="divider" />
          <span>ens5f0</span>
          <span className="divider" />
          <button
            className="mode-badge"
            onClick={() => setMode(mode === "直接模式" ? "监听模式" : "直接模式")}
          >
            {mode}⌄
          </button>
        </div>
        <button className="run-button" disabled={!validated || running} onClick={execute}>
          {running ? "执行中..." : "▶ 执行场景"}
        </button>
      </header>

      <aside className="sidebar">
        <div className="nav-group-label">工作区</div>
        <nav>
          {nav.map((item, index) => (
            <button
              key={item}
              onClick={() => setActiveNav(item)}
              className={`nav-item ${activeNav === item ? "active" : ""}`}
            >
              <span className="nav-glyph">{navGlyphs[index]}</span>
              {item}
              {item === "异常用例" && <em>4</em>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="risk-card">
            <span className="risk-icon">!</span>
            <div>
              <b>Offload 风险</b>
              <p>TX checksum 已关闭</p>
            </div>
          </div>
          <button className="help">? 使用指南</button>
        </div>
      </aside>

      <section className="workspace">
        {apiError && <div className="api-error">{apiError}</div>}
        {activeNav === "场景工作台" ? (
          <>
            <div className="page-title">
              <div>
                <div className="eyebrow">SCENARIO / 014</div>
                <h1>VXLAN 完整性回归</h1>
                <p>验证隧道内外层长度、校验和与截断异常的处理行为</p>
              </div>
              <div className="head-actions">
                <button className="quiet-button">⌘S 保存</button>
                <button className="quiet-button" onClick={validate}>
                  {validated ? "✓ 已校验" : "◇ 校验场景"}
                </button>
              </div>
            </div>

            <div className="mode-switch">
              <button onClick={() => setMode("直接模式")} className={mode === "直接模式" ? "selected" : ""}>
                ◉ 直接模式<span>主动构造并发送报文</span>
              </button>
              <button onClick={() => setMode("监听模式")} className={mode === "监听模式" ? "selected" : ""}>
                ◌ 监听模式<span>匹配流量后触发注入</span>
              </button>
              <div className="mode-summary">
                目标 <b>lab-node-07 / ens5f0</b> · {enabled} 个报文已启用
              </div>
            </div>

            <div className="content-grid">
              <section className="panel packets-panel">
                <div className="panel-head">
                  <div>
                    <h2>报文序列</h2>
                    <span>按顺序执行 · 可拖动排序</span>
                  </div>
                  <button className="add-button" onClick={addPacket}>
                    ＋ 添加报文
                  </button>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>启用</th>
                        <th>#</th>
                        <th>报文名</th>
                        <th>模板</th>
                        <th>异常</th>
                        <th>次数</th>
                        <th>间隔</th>
                        <th>状态</th>
                        <th aria-label="操作" />
                      </tr>
                    </thead>
                    <tbody>
                      {packets.map((packet) => (
                        <tr
                          onClick={() => setSelected(packet.id)}
                          className={selected === packet.id ? "selected-row" : ""}
                          key={packet.id}
                        >
                          <td>
                            <button
                              aria-label="切换报文"
                              className={`check ${packet.enabled ? "checked" : ""}`}
                              onClick={(event) => {
                                event.stopPropagation();
                                togglePacket(packet.id);
                              }}
                            >
                              {packet.enabled && "✓"}
                            </button>
                          </td>
                          <td className="order">⠿ {packet.id}</td>
                          <td>
                            <b>{packet.name}</b>
                          </td>
                          <td>
                            <span className="template">{packet.template}</span>
                          </td>
                          <td>
                            <button
                              className={packet.mutations ? "mutation" : "zero"}
                              onClick={(event) => {
                                event.stopPropagation();
                                setActiveNav("异常用例");
                              }}
                            >
                              {packet.mutations}
                            </button>
                          </td>
                          <td>{packet.count}</td>
                          <td className="mono">{packet.interval}</td>
                          <td>
                            <StatusBadge status={packet.status} />
                          </td>
                          <td className="row-more">•••</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <footer className="table-footer">
                  <span>
                    {packets.length} 个报文 · {enabled} 个已启用
                  </span>
                  <span>
                    总计 <b>7 次</b> 发送 · 约 0.6 秒
                  </span>
                </footer>
              </section>

              <aside className="config-stack">
                <section className="panel config-panel">
                  <div className="panel-head">
                    <div>
                      <h2>场景配置</h2>
                      <span>运行环境与控制项</span>
                    </div>
                    <button className="icon-button">•••</button>
                  </div>
                  <Config label="目标主机" value="lab-node-07" />
                  <Config label="发送网口" value="ens5f0 / 10GbE" />
                  <Config label="循环次数" value="1" />
                  <Config label="包间默认间隔" value="100 ms" />
                  <div className="switch-row">
                    <span>失败后停止</span>
                    <button className="toggle on" aria-label="切换失败后停止">
                      <i />
                    </button>
                  </div>
                </section>
                <section className="offload-card">
                  <div>
                    <span className="eyebrow">NIC OFFLOAD</span>
                    <h3>校验和异常可控</h3>
                    <p>硬件卸载已禁用，报文将按原始 bytes 发出。</p>
                  </div>
                  <span className="offload-ok">✓</span>
                </section>
              </aside>
            </div>

            <section className="panel selection-strip">
              <div>
                <span className="eyebrow">当前选择</span>
                <h3>{selectedPacket.name}</h3>
                <p>{selectedPacket.template} · 3 条异常规则</p>
              </div>
              <div className="protocol-steps">
                <span>Ethernet</span>
                <i>›</i>
                <span>IPv4</span>
                <i>›</i>
                <span>UDP</span>
                <i>›</i>
                <span className="highlight">VXLAN</span>
                <i>›</i>
                <span>Inner TCP</span>
              </div>
              <button className="open-editor" onClick={() => setActiveNav("协议编辑器")}>
                编辑协议 →
              </button>
            </section>
          </>
        ) : (
          <OtherPage page={activeNav} onBack={() => setActiveNav("场景工作台")} />
        )}
      </section>

      <section className="drawer">
        <div className="drawer-tabs">
          {drawerTabs.map((tab) => (
            <button key={tab} onClick={() => setDrawer(tab)} className={drawer === tab ? "active" : ""}>
              {tab}
              {tab === "校验问题" && <em>1</em>}
            </button>
          ))}
          <span>⌃</span>
        </div>
        <div className="drawer-content">
          {drawer === "Hex" ? (
            <>
              <div className="hex-label">
                0000&nbsp; 0a 1b 2c 3d 4e 5f&nbsp; 02 42 ac 11 00 07&nbsp; 08 00&nbsp; 45 00
                <br />
                0010&nbsp; <mark>00 74</mark> 3f 2a 40 00&nbsp; 40 11 <mark>00 00</mark> c0 a8 01 14&nbsp; c0 a8
                <br />
                0020&nbsp; 01 19 12 b5 12 b5&nbsp; 00 60 f3 8c 08 00 00 00&nbsp; 00 00 2a 00
              </div>
              <div className="hex-legend">
                <span>
                  <i className="orange" />
                  字段异常：outer.ip.len
                </span>
                <span>
                  <i className="purple" />
                  自动计算已覆盖：udp.chksum
                </span>
              </div>
            </>
          ) : (
            <div className="output">
              <span className="prompt">$</span>{" "}
              {running
                ? (remoteLogs[remoteLogs.length - 1] ?? "执行请求已提交，等待远端事件...")
                : drawer === "执行输出"
                  ? (remoteLogs[remoteLogs.length - 1] ?? "等待执行。场景校验通过后可启动。")
                  : (apiError || "场景数据由后端 API 提供")}
            </div>
          )}
        </div>
      </section>
    </main>
  );
}

function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={`status ${status === "可执行" ? "ok" : status === "有警告" ? "warn" : "idle"}`}>
      <i />
      {status}
    </span>
  );
}

function Config({ label, value }: { label: string; value: string }) {
  return (
    <label className="config-row">
      <span>{label}</span>
      <button>
        {value}
        <b>⌄</b>
      </button>
    </label>
  );
}

type PageContent = {
  eyebrow: string;
  title: string;
  subtitle: string;
  primary: string;
  rows: [string, string, string][];
};

function OtherPage({ page, onBack }: { page: string; onBack: () => void }) {
  const content: Record<string, PageContent> = {
    协议编辑器: {
      eyebrow: "PACKET / vxlan_len_skew",
      title: "协议编辑器",
      subtitle: "分层编辑字段，异常策略与 Hex bytes 实时联动。",
      primary: "＋ 添加协议层",
      rows: [
        ["Ethernet", "src 02:42:ac:11:00:07", "14 bytes"],
        ["IPv4", "total length 0x0074", "异常 1"],
        ["UDP", "checksum auto", "8 bytes"],
        ["VXLAN", "VNI 42", "8 bytes"],
        ["Inner TCP", "flags SYN", "20 bytes"],
      ],
    },
    异常用例: {
      eyebrow: "MUTATIONS / vxlan_len_skew",
      title: "异常用例",
      subtitle: "组合字段级异常，并在执行前发现冲突。",
      primary: "＋ 添加异常",
      rows: [
        ["长度异常", "outer.ip.len → less than actual", "Warning"],
        ["Checksum 异常", "outer.ip.chksum → 0x0000", "Enabled"],
        ["字段值异常", "inner.tcp.flags → SYN|FIN", "Enabled"],
        ["截断异常", "payload → 32 bytes", "Disabled"],
      ],
    },
    监听模式: {
      eyebrow: "LISTEN / CONFIGURATION",
      title: "监听模式",
      subtitle: "匹配经过接口的流量，并按触发策略注入异常报文。",
      primary: "应用监听规则",
      rows: [
        ["监听接口", "ens5f0", "Ready"],
        ["BPF 粗过滤", "udp and port 4789", "Valid"],
        ["VXLAN VNI", "42", "Inner match"],
        ["触发条件", "匹配第 3 个包后发送", "Armed"],
      ],
    },
    远端主机: {
      eyebrow: "ENVIRONMENT / 2 HOSTS",
      title: "远端主机",
      subtitle: "管理执行节点、网口状态和硬件卸载配置。",
      primary: "＋ 添加主机",
      rows: [
        ["lab-node-07", "10.42.0.17 · ens5f0", "Online"],
        ["qa-injector-02", "10.42.0.22 · ens3f1", "Online"],
        ["Offload 检查", "TX checksum / TSO / GSO", "Passed"],
      ],
    },
    执行结果: {
      eyebrow: "RUN / 2026-08-03 14:32",
      title: "执行结果",
      subtitle: "查看发包结果、远端日志与目标阵列响应摘要。",
      primary: "导出报告",
      rows: [
        ["baseline_tcp_syn", "1 / 1 已发送", "Success"],
        ["vxlan_len_skew", "1 / 1 已发送", "Warning"],
        ["truncated_payload", "跳过：未启用", "Skipped"],
        ["目标阵列处理", "未采集回执", "Unknown"],
      ],
    },
    设置: {
      eyebrow: "PREFERENCES",
      title: "设置",
      subtitle: "调整默认行为、编辑器密度与本地运行偏好。",
      primary: "保存设置",
      rows: [
        ["界面密度", "标准（表格行高 36px）", "Active"],
        ["执行前校验", "始终要求", "Enabled"],
        ["保存 payload", "默认关闭", "Secure"],
        ["本地日志保留", "7 天", "Active"],
      ],
    },
  };
  const view = content[page] ?? content.协议编辑器;

  return (
    <div className="other-page">
      <div className="page-title">
        <div>
          <div className="eyebrow">{view.eyebrow}</div>
          <h1>{view.title}</h1>
          <p>{view.subtitle}</p>
        </div>
        <div className="head-actions">
          <button className="quiet-button" onClick={onBack}>
            ← 返回工作台
          </button>
          <button className="add-button">{view.primary}</button>
        </div>
      </div>
      <div className="other-grid">
        <section className="panel other-main">
          <div className="panel-head">
            <div>
              <h2>{page === "异常用例" ? "规则列表" : page === "远端主机" ? "可用资源" : "配置概览"}</h2>
              <span>最近更新于 14:32:09</span>
            </div>
            <button className="icon-button">筛选⌄</button>
          </div>
          <div className="detail-list">
            {view.rows.map(([name, value, state]) => (
              <button className="detail-row" key={name}>
                <span className="row-marker" />
                <span>
                  <b>{name}</b>
                  <small>{value}</small>
                </span>
                <em className={state === "Warning" || state === "Unknown" ? "warning" : ""}>{state}</em>
                <i>→</i>
              </button>
            ))}
          </div>
        </section>
        <aside className="panel inspector">
          <div className="panel-head">
            <div>
              <h2>检查器</h2>
              <span>当前环境</span>
            </div>
          </div>
          <div className="inspector-content">
            <span className="eyebrow">STATUS</span>
            <strong>配置就绪</strong>
            <p>修改将在保存后应用到当前场景。执行环境已连接，未发现阻断类问题。</p>
            <div className="mini-rule" />
            <div className="meta-line">
              <span>远端主机</span>
              <b>lab-node-07</b>
            </div>
            <div className="meta-line">
              <span>网口</span>
              <b>ens5f0</b>
            </div>
            <div className="meta-line">
              <span>校验状态</span>
              <b className="green">通过</b>
            </div>
          </div>
        </aside>
      </div>
      <section className="panel activity-panel">
        <div className="panel-head">
          <div>
            <h2>最近活动</h2>
            <span>此工作区的变更记录</span>
          </div>
        </div>
        <div className="activity">
          <span>14:32:09</span>
          <b>系统</b>
          <p>已载入场景配置与远端环境摘要。</p>
        </div>
      </section>
    </div>
  );
}
