import { useEffect, useMemo, useState } from "react";
import {
  apiGet,
  apiPost,
  apiPut,
  executionStreamUrl,
  ExecutionResult,
  NicInfo,
  PacketModel,
  PacketPreview,
  PacketTemplateSummary,
  RemoteHostSummary,
  ScenarioModel,
  ValidationResult,
} from "./api-contract";

type Page = "场景工作台" | "协议编辑器" | "异常用例" | "远端主机" | "执行结果";
type Drawer = "Hex" | "校验问题" | "执行输出";

const pages: Page[] = ["场景工作台", "协议编辑器", "异常用例", "远端主机", "执行结果"];

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function id(prefix: string): string {
  return `${prefix}-${Math.random().toString(16).slice(2, 10)}`;
}

function textOf(event: MessageEvent<string>): string {
  try {
    const data = JSON.parse(event.data) as { type?: string; data?: unknown };
    return `${data.type ?? "event"}: ${typeof data.data === "string" ? data.data : JSON.stringify(data.data ?? {})}`;
  } catch {
    return event.data;
  }
}

export default function App() {
  const [page, setPage] = useState<Page>("场景工作台");
  const [drawer, setDrawer] = useState<Drawer>("Hex");
  const [scenarios, setScenarios] = useState<ScenarioModel[]>([]);
  const [scenario, setScenario] = useState<ScenarioModel | null>(null);
  const [templates, setTemplates] = useState<PacketTemplateSummary[]>([]);
  const [hosts, setHosts] = useState<RemoteHostSummary[]>([]);
  const [interfaces, setInterfaces] = useState<NicInfo[]>([]);
  const [executions, setExecutions] = useState<ExecutionResult[]>([]);
  const [packetId, setPacketId] = useState("");
  const [templateId, setTemplateId] = useState("");
  const [preview, setPreview] = useState<PacketPreview | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(false);
  const [running, setRunning] = useState(false);
  const [hostDraft, setHostDraft] = useState({ name: "lab-node-07", address: "192.168.1.100", sshPort: 22, username: "tester", password: "", rootPassword: "" });

  const packet = useMemo(() => scenario?.packets.find((item) => item.id === packetId) ?? scenario?.packets[0] ?? null, [scenario, packetId]);
  const host = useMemo(() => hosts.find((item) => item.id === scenario?.target.hostId), [hosts, scenario?.target.hostId]);
  const enabled = scenario?.packets.filter((item) => item.enabled).length ?? 0;

  async function load() {
    setError("");
    try {
      const [scenarioRes, templateRes, hostRes, executionRes] = await Promise.all([
        apiGet<{ items: ScenarioModel[] }>("/scenarios"),
        apiGet<{ items: PacketTemplateSummary[] }>("/templates"),
        apiGet<{ items: RemoteHostSummary[] }>("/hosts"),
        apiGet<{ items: ExecutionResult[] }>("/executions"),
      ]);
      setScenarios(scenarioRes.items);
      setTemplates(templateRes.items);
      setHosts(hostRes.items);
      setExecutions(executionRes.items);
      const first = scenarioRes.items[0] ?? null;
      setScenario(first);
      setPacketId(first?.packets[0]?.id ?? "");
      setTemplateId(templateRes.items[0]?.id ?? "");
      setDirty(false);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "加载失败");
    }
  }

  useEffect(() => { void load(); }, []);

  useEffect(() => {
    if (!packet) { setPreview(null); return; }
    let cancelled = false;
    apiPost<PacketPreview>("/templates/preview", { packet })
      .then((result) => { if (!cancelled) setPreview(result); })
      .catch((exc: unknown) => { if (!cancelled) setError(exc instanceof Error ? exc.message : "预览失败"); });
    return () => { cancelled = true; };
  }, [packet]);

  function edit(mutator: (draft: ScenarioModel) => void) {
    setScenario((current) => {
      if (!current) return current;
      const draft = clone(current);
      mutator(draft);
      setDirty(true);
      setValidation(null);
      return draft;
    });
  }

  async function save(): Promise<ScenarioModel | null> {
    if (!scenario) return null;
    const saved = await apiPut<ScenarioModel>(`/scenarios/${scenario.id}`, scenario);
    setScenario(saved);
    setScenarios((items) => items.map((item) => item.id === saved.id ? saved : item));
    setDirty(false);
    return saved;
  }

  async function validate() {
    if (!scenario) return;
    try {
      const target = dirty ? await save() : scenario;
      if (!target) return;
      const result = await apiPost<ValidationResult>(`/scenarios/${target.id}/validate`);
      setValidation(result);
      setDrawer("校验问题");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "校验失败");
    }
  }

  function addPacket() {
    const template = templates.find((item) => item.id === templateId) ?? templates[0];
    if (!template) return;
    const next: PacketModel = {
      id: id("pkt"),
      name: `${template.name}-${(scenario?.packets.length ?? 0) + 1}`,
      enabled: true,
      templateId: template.id,
      sendCount: 1,
      intervalMs: 100,
      layers: clone(template.layers).map((layer, index) => ({ ...layer, id: `${layer.id}-${Date.now()}-${index}` })),
      mutations: [],
    };
    edit((draft) => { draft.packets.push(next); });
    setPacketId(next.id);
  }

  function addLengthMutation() {
    if (!packet) return;
    edit((draft) => {
      const target = draft.packets.find((item) => item.id === packet.id);
      const layer = target?.layers.find((item) => item.role === "outer" && item.type === "ipv4");
      if (!target || !layer) return;
      layer.autoCalculate = { ...(layer.autoCalculate ?? {}), len: false };
      target.mutations.push({ id: id("mut"), name: "outer.ip.len less than actual", enabled: true, target: { packetId: target.id, layerId: layer.id, fieldPath: "outer.ipv4[0].len" }, type: "invalid_length", strategy: "less_than_actual", value: 40, applyOrder: 300, scope: "field", options: { disableAutoCalculate: true } });
    });
  }

  function updateField(layerId: string, key: string, value: string) {
    if (!packet) return;
    edit((draft) => {
      const target = draft.packets.find((item) => item.id === packet.id);
      const layer = target?.layers.find((item) => item.id === layerId);
      if (!layer) return;
      const old = layer.fields[key];
      const parsed = typeof old === "number" ? Number(value) : value;
      layer.fields[key] = Number.isNaN(parsed) ? value : parsed;
    });
  }

  async function saveHost() {
    try {
      const saved = await apiPost<RemoteHostSummary>("/hosts", { name: hostDraft.name, address: hostDraft.address, sshPort: hostDraft.sshPort, auth: { type: "password", username: hostDraft.username, password: hostDraft.password }, privilege: { mode: "su_root", rootPassword: hostDraft.rootPassword } });
      setHosts((items) => [saved, ...items.filter((item) => item.id !== saved.id)]);
      edit((draft) => { draft.target.hostId = saved.id; });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "保存主机失败");
    }
  }

  async function queryInterfaces() {
    if (!scenario?.target.hostId) return;
    try {
      const result = await apiGet<{ items: NicInfo[] }>(`/hosts/${scenario.target.hostId}/interfaces`);
      setInterfaces(result.items);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "查询网口失败");
    }
  }

  async function disableOffload() {
    if (!scenario?.target.hostId || !scenario.target.interface) return;
    try {
      const result = await apiPost<Record<string, unknown>>(`/hosts/${scenario.target.hostId}/interfaces/${encodeURIComponent(scenario.target.interface)}/offload`, { txChecksum: false, tso: false, gso: false, gro: false, lro: false });
      setLogs((items) => [`offload: ${JSON.stringify(result)}`, ...items]);
      setDrawer("执行输出");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "关闭 Offload 失败");
    }
  }

  async function execute() {
    if (!scenario) return;
    setRunning(true);
    setLogs([]);
    setDrawer("执行输出");
    try {
      const target = dirty ? await save() : scenario;
      if (!target) return;
      const result = await apiPost<{ executionId: string }>("/executions", { scenarioId: target.id });
      const socket = new WebSocket(executionStreamUrl(result.executionId));
      socket.onmessage = (event) => setLogs((items) => [...items, textOf(event)]);
      socket.onerror = () => setError("执行日志连接失败");
      socket.onclose = () => { setRunning(false); void apiGet<{ items: ExecutionResult[] }>("/executions").then((res) => setExecutions(res.items)); };
    } catch (exc) {
      setRunning(false);
      setError(exc instanceof Error ? exc.message : "执行失败");
    }
  }

  const mode = scenario?.mode === "listen" ? "监听模式" : "直接模式";

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark">∿</span><span>PACKET<span>LAB</span></span><small>异常报文生成器</small></div>
        <div className="crumb"><span>场景</span><b>{scenario?.name ?? "未加载"}</b><i>/</i><span>{dirty ? "未保存" : "已保存"}</span></div>
        <div className="top-status"><span className="host-dot" /><span>{host ? `${host.name} / ${host.address}` : "未选择主机"}</span><span className="divider" /><span>{scenario?.target.interface ?? "未选择网口"}</span><span className="divider" /><button className="mode-badge">{mode}⌄</button></div>
        <button className="run-button" disabled={!scenario || running} onClick={execute}>{running ? "执行中..." : "▶ 执行场景"}</button>
      </header>

      <aside className="sidebar"><div className="nav-group-label">工作区</div><nav>{pages.map((item) => <button key={item} onClick={() => setPage(item)} className={`nav-item ${page === item ? "active" : ""}`}>{item}</button>)}</nav><div className="sidebar-bottom"><button className="help" onClick={load}>↻ 刷新数据</button></div></aside>

      <section className="workspace">
        {error && <div className="api-error">{error}</div>}
        {page === "场景工作台" && <Workbench scenario={scenario} scenarios={scenarios} templates={templates} packet={packet} packetId={packetId} templateId={templateId} validation={validation} enabled={enabled} setScenario={(idValue) => { const next = scenarios.find((item) => item.id === idValue) ?? null; setScenario(next); setPacketId(next?.packets[0]?.id ?? ""); setDirty(false); }} setTemplateId={setTemplateId} setPacketId={setPacketId} addPacket={addPacket} save={save} validate={validate} edit={edit} />}
        {page === "协议编辑器" && <Protocol packet={packet} preview={preview} updateField={updateField} />}
        {page === "异常用例" && <Mutations packet={packet} addLengthMutation={addLengthMutation} />}
        {page === "远端主机" && <Hosts scenario={scenario} hosts={hosts} interfaces={interfaces} draft={hostDraft} setDraft={setHostDraft} edit={edit} saveHost={saveHost} queryInterfaces={queryInterfaces} disableOffload={disableOffload} />}
        {page === "执行结果" && <ExecutionList executions={executions} />}
      </section>

      <section className="drawer"><div className="drawer-tabs">{(["Hex", "校验问题", "执行输出"] as Drawer[]).map((item) => <button key={item} onClick={() => setDrawer(item)} className={drawer === item ? "active" : ""}>{item}</button>)}<span>⌃</span></div><div className="drawer-content">{drawer === "Hex" && <Hex preview={preview} />}{drawer === "校验问题" && <Validation validation={validation} />}{drawer === "执行输出" && <Output logs={logs} />}</div></section>
    </main>
  );
}

function Workbench(props: { scenario: ScenarioModel | null; scenarios: ScenarioModel[]; templates: PacketTemplateSummary[]; packet: PacketModel | null; packetId: string; templateId: string; validation: ValidationResult | null; enabled: number; setScenario: (id: string) => void; setTemplateId: (id: string) => void; setPacketId: (id: string) => void; addPacket: () => void; save: () => Promise<ScenarioModel | null>; validate: () => void; edit: (mutator: (draft: ScenarioModel) => void) => void }) {
  return <><div className="page-title"><div><div className="eyebrow">SCENARIO / API CONNECTED</div><h1>{props.scenario?.name ?? "未加载场景"}</h1><p>场景、模板、保存、校验、执行都走后端 API。</p></div><div className="head-actions"><select value={props.scenario?.id ?? ""} onChange={(event: { target: { value: string } }) => props.setScenario(event.target.value)}>{props.scenarios.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select><button className="quiet-button" onClick={() => void props.save()}>⌘S 保存</button><button className="quiet-button" onClick={props.validate}>◇ 校验</button></div></div><div className="mode-switch"><button className={props.scenario?.mode === "direct" ? "selected" : ""} onClick={() => props.edit((draft) => { draft.mode = "direct"; })}>◉ 直接模式<span>主动发包</span></button><button className={props.scenario?.mode === "listen" ? "selected" : ""} onClick={() => props.edit((draft) => { draft.mode = "listen"; draft.listenConfig ??= { interface: draft.target.interface ?? null, match: { mode: "outer_five_tuple", bpf: "tcp or udp" }, trigger: { packetIndex: 1, tcpFlags: [], delayMs: 0 }, direction: { mode: "host_to_array", derive: "same_direction" }, cachePolicy: { storePayload: false, persistToDisk: false, maxRecords: 1000 } }; })}>◌ 监听模式<span>匹配后注入</span></button><div className="mode-summary">启用 <b>{props.enabled}</b> 个报文 · {props.validation?.valid ? "校验通过" : "待校验"}</div></div><section className="panel packets-panel"><div className="panel-head"><div><h2>报文序列</h2><span>保存后写入 app-data/scenarios</span></div><div className="head-actions"><select value={props.templateId} onChange={(event: { target: { value: string } }) => props.setTemplateId(event.target.value)}>{props.templates.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select><button className="add-button" onClick={props.addPacket}>＋ 添加报文</button></div></div><div className="table-wrap"><table><thead><tr><th>启用</th><th>#</th><th>报文名</th><th>模板</th><th>异常</th><th>次数</th><th>间隔</th><th>状态</th></tr></thead><tbody>{(props.scenario?.packets ?? []).map((item, index) => <tr key={item.id} className={props.packetId === item.id ? "selected-row" : ""} onClick={() => props.setPacketId(item.id)}><td><button className={`check ${item.enabled ? "checked" : ""}`} onClick={(event: { stopPropagation: () => void }) => { event.stopPropagation(); props.edit((draft) => { const packet = draft.packets.find((p) => p.id === item.id); if (packet) packet.enabled = !packet.enabled; }); }}>{item.enabled ? "✓" : ""}</button></td><td className="order">⠿ {index + 1}</td><td><b>{item.name}</b></td><td><span className="template">{item.templateId ?? "custom"}</span></td><td>{item.mutations.length}</td><td>{item.sendCount}</td><td className="mono">{item.intervalMs} ms</td><td><span className="status idle"><i />{props.validation?.valid ? "可执行" : "未校验"}</span></td></tr>)}</tbody></table></div><footer className="table-footer"><span>{props.scenario?.packets.length ?? 0} 个报文</span><span>当前选择 <b>{props.packet?.name ?? "无"}</b></span></footer></section></>;
}

function Protocol({ packet, preview, updateField }: { packet: PacketModel | null; preview: PacketPreview | null; updateField: (layerId: string, key: string, value: string) => void }) {
  if (!packet) return <div className="other-page"><h1>请选择报文</h1></div>;
  return <div className="other-page"><div className="page-title"><div><div className="eyebrow">PACKET / {packet.name}</div><h1>协议编辑器</h1><p>字段变更后实时调用后端 Scapy 预览。</p></div></div><div className="other-grid"><section className="panel other-main"><div className="detail-list">{packet.layers.map((layer) => <div className="detail-row" key={layer.id}><span className="row-marker" /><span><b>{layer.role} / {layer.type}</b><small>{Object.keys(layer.fields).join(", ")}</small></span><div className="field-grid">{Object.entries(layer.fields).map(([key, value]) => <label key={key}><small>{key}</small><input value={String(value ?? "")} onChange={(event: { target: { value: string } }) => updateField(layer.id, key, event.target.value)} /></label>)}</div></div>)}</div></section><aside className="panel inspector"><h2>Wire Preview</h2><p>{preview?.length ?? 0} bytes</p><pre>{preview?.hex ?? "等待预览"}</pre></aside></div></div>;
}

function Mutations({ packet, addLengthMutation }: { packet: PacketModel | null; addLengthMutation: () => void }) {
  if (!packet) return <div className="other-page"><h1>请选择报文</h1></div>;
  return <div className="other-page"><div className="page-title"><div><div className="eyebrow">MUTATIONS / {packet.name}</div><h1>异常用例</h1><p>规则保存后参与后端校验和 Scapy bytes 生成。</p></div><button className="add-button" onClick={addLengthMutation}>＋ 长度异常</button></div><section className="panel other-main"><div className="detail-list">{packet.mutations.map((item) => <div className="detail-row" key={item.id}><span className="row-marker" /><span><b>{item.name}</b><small>{item.target.fieldPath ?? item.scope} · {item.strategy}</small></span><em>{item.enabled ? "Enabled" : "Disabled"}</em></div>)}</div></section></div>;
}

function Hosts(props: { scenario: ScenarioModel | null; hosts: RemoteHostSummary[]; interfaces: NicInfo[]; draft: { name: string; address: string; sshPort: number; username: string; password: string; rootPassword: string }; setDraft: (value: { name: string; address: string; sshPort: number; username: string; password: string; rootPassword: string }) => void; edit: (mutator: (draft: ScenarioModel) => void) => void; saveHost: () => void; queryInterfaces: () => void; disableOffload: () => void }) {
  return <div className="other-page"><div className="page-title"><div><div className="eyebrow">ENVIRONMENT / HOSTS</div><h1>远端主机</h1><p>SSH 登录、su root、网口发现和 Offload 控制。</p></div><div className="head-actions"><button className="add-button" onClick={props.saveHost}>保存主机</button><button className="quiet-button" onClick={props.queryInterfaces}>查询网口</button><button className="quiet-button" onClick={props.disableOffload}>关闭 Offload</button></div></div><div className="other-grid"><section className="panel other-main"><div className="detail-list">{props.hosts.map((host) => <button className="detail-row" key={host.id} onClick={() => props.edit((draft) => { draft.target.hostId = host.id; })}><span className="row-marker" /><span><b>{host.name}</b><small>{host.address}:{host.sshPort}</small></span><em>{props.scenario?.target.hostId === host.id ? "Selected" : "Saved"}</em></button>)}</div><div className="field-grid"><label>名称<input value={props.draft.name} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, name: e.target.value })} /></label><label>地址<input value={props.draft.address} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, address: e.target.value })} /></label><label>端口<input type="number" value={props.draft.sshPort} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, sshPort: Number(e.target.value) })} /></label><label>用户<input value={props.draft.username} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, username: e.target.value })} /></label><label>SSH 密码<input type="password" value={props.draft.password} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, password: e.target.value })} /></label><label>root 密码<input type="password" value={props.draft.rootPassword} onChange={(e: { target: { value: string } }) => props.setDraft({ ...props.draft, rootPassword: e.target.value })} /></label></div></section><aside className="panel inspector">{props.interfaces.map((item) => <button className="detail-row" key={item.name} onClick={() => props.edit((draft) => { draft.target.interface = item.name; if (draft.listenConfig) draft.listenConfig.interface = item.name; })}><span><b>{item.name}</b><small>{item.ips.join(", ") || item.mac}</small></span><em>{item.link}</em></button>)}</aside></div></div>;
}

function ExecutionList({ executions }: { executions: ExecutionResult[] }) {
  return <div className="other-page"><div className="page-title"><div><div className="eyebrow">RUN HISTORY</div><h1>执行结果</h1><p>Level0 脚本结果、Level1 TX 统计；Level2 旁路抓包后续接入。</p></div></div><section className="panel other-main"><div className="detail-list">{executions.map((item) => <div className="detail-row" key={item.id}><span className="row-marker" /><span><b>{item.id}</b><small>{item.interface ?? "no-iface"} · sent={String(item.level0.reportedSendCount ?? "?")} · txΔ={String(item.level1.txPacketsDelta ?? "?")}</small></span><em className={item.status === "failed" ? "warning" : ""}>{item.status}</em></div>)}</div></section></div>;
}

function Hex({ preview }: { preview: PacketPreview | null }) { return <div className="hex-label">{preview ? `${preview.hex}\n\n${preview.length} bytes` : "等待后端 Scapy 预览"}</div>; }
function Validation({ validation }: { validation: ValidationResult | null }) { const rows = validation ? [...validation.errors, ...validation.warnings] : []; return <div className="output">{rows.length ? rows.map((item) => <p key={`${item.code}-${item.path ?? ""}`}>{item.code}: {item.message}</p>) : <p>{validation ? "校验通过" : "尚未校验"}</p>}</div>; }
function Output({ logs }: { logs: string[] }) { return <div className="output"><span className="prompt">$</span>{logs.length ? logs.map((item, index) => <p key={`${index}-${item}`}>{item}</p>) : "等待执行"}</div>; }
