import { useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiPost, apiPut, executionStreamUrl } from "./api-contract";
import SampleWorkbench from "./SampleWorkbench";
import { AppDialog, ConfirmDialog, LoadingState, Icon } from "./ui";

type ScenarioMode = "direct" | "listen";
type DrawerTab = "Hex" | "日志" | "校验问题" | "执行输出";
type NavItem =
  | "场景工作台"
  | "报文样本"
  | "协议编辑器"
  | "异常用例"
  | "监听模式"
  | "远端主机"
  | "执行结果"
  | "设置";

type Layer = {
  id: string;
  type: string;
  role: string;
  fields: Record<string, unknown>;
  autoCalculate?: Record<string, boolean>;
};

type Mutation = {
  id: string;
  name: string;
  enabled: boolean;
  type: string;
  strategy: string;
  value?: unknown;
  target?: { fieldPath?: string; layerId?: string };
  options?: Record<string, unknown>;
  applyOrder?: number;
};

export type Packet = {
  id: string;
  enabled: boolean;
  name: string;
  templateId?: string;
  sendCount: number;
  intervalMs: number;
  layers: Layer[];
  mutations: Mutation[];
  rawHex?: string | null;
};

type Scenario = {
  id: string;
  name: string;
  description: string;
  mode: ScenarioMode;
  target: { hostId?: string | null; interface?: string | null };
  sendOptions: { loopCount: number; stopOnFailure: boolean };
  listenConfig?: {
    interface?: string | null;
    match: {
      mode: string;
      outer?: Record<string, unknown> | null;
      inner?: Record<string, unknown> | null;
      tunnel?: { type: "vxlan"; vni: number | null } | null;
      bpf?: string;
      deepCondition?: string;
    };
    trigger: { packetIndex: number; tcpFlags: string[]; delayMs: number };
    direction: {
      mode: string;
      derive: string;
      addresses?: string;
      checksums?: string;
    };
    cachePolicy: {
      storePayload: boolean;
      persistToDisk: boolean;
      maxRecords: number;
    };
  } | null;
  packets: Packet[];
};

type Template = {
  id: string;
  name: string;
  builtin: boolean;
  description?: string;
  layers: Layer[];
  packet?: Packet;
};
type Host = {
  id: string;
  name: string;
  address: string;
  sshPort: number;
  auth?: { username?: string };
  lastCheck?: Record<string, unknown>;
};
type Nic = {
  name: string;
  mac: string;
  ips: string[];
  link: string;
  speed: string;
  driver: string;
  pci: string;
};
type Offload = Record<string, boolean | Record<string, unknown>>;
type Execution = {
  id: string;
  scenarioId: string;
  mode: string;
  status: string;
  startedAt?: string;
  finishedAt?: string;
  level0?: Record<string, unknown>;
  level1?: Record<string, unknown>;
  logs?: Array<Record<string, unknown>>;
};
type MutationType = { type: string; displayName: string; strategies: string[] };
type Preview = {
  hex: string;
  length: number;
  warnings: Array<{ code: string; message: string }>;
};

const nav: NavItem[] = [
  "场景工作台",
  "报文样本",
  "远端主机",
  "执行结果",
  "设置",
];

const drawerTabs: DrawerTab[] = ["Hex", "日志", "校验问题", "执行输出"];

const emptyHostForm = {
  name: "",
  address: "",
  username: "",
  password: "",
  rootPassword: "",
  sshPort: 22,
};
const isActiveExecution = (execution: Execution) =>
  ["pending", "running"].includes(execution.status);
const executionStatus = (status: string) =>
  ({
    pending: "等待执行",
    running: "执行中",
    success: "成功",
    failed: "失败",
    cancelled: "已取消",
  })[status] ?? status;

function listenInputError(scenario?: Scenario): string {
  if (scenario?.mode !== "listen") return "";
  const c = scenario.listenConfig;
  if (!c) return "监听模式缺少配置";
  if (!Number.isInteger(c.trigger.packetIndex) || c.trigger.packetIndex < 1)
    return "触发序号必须是大于等于 1 的整数";
  if (!Number.isInteger(c.trigger.delayMs) || c.trigger.delayMs < 0)
    return "注入延迟必须是非负整数";
  if (c.trigger.tcpFlags.some((f) => !/^[FSRPAUEC]$/.test(f)))
    return "TCP 标记只能包含 F、S、R、P、A、U、E、C";
  const match =
    c.match.mode === "vxlan_inner_five_tuple"
      ? c.match.inner
      : c.match.mode === "custom"
        ? null
        : c.match.outer;
  for (const key of ["srcPort", "dstPort"]) {
    const port = match?.[key];
    if (
      port != null &&
      (!Number.isInteger(port) || Number(port) < 0 || Number(port) > 65535)
    )
      return "匹配端口必须是 0–65535 的整数";
  }
  const vni =
    c.match.mode === "vxlan_inner_five_tuple" ? c.match.tunnel?.vni : null;
  if (vni != null && (!Number.isInteger(vni) || vni < 0 || vni > 16777215))
    return "VNI 必须是 0–16777215 的整数";
  return "";
}

export default function App() {
  const [activeNav, setActiveNav] = useState<NavItem>("场景工作台");
  const [sceneView, setSceneView] = useState<"packets" | "config" | "records">(
    "packets",
  );
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [newSceneOpen, setNewSceneOpen] = useState(false);
  const [hostOpen, setHostOpen] = useState(false);
  const [hostBusy, setHostBusy] = useState(false);
  const [offloadConfirm, setOffloadConfirm] = useState<{
    key: string;
    value: boolean;
  } | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [previewRetry, setPreviewRetry] = useState(0);
  const [templateId, setTemplateId] = useState("");
  const [managedHostId, setManagedHostId] = useState("");
  const [queryingInterfaces, setQueryingInterfaces] = useState(false);
  const interfaceRequest = useRef(0);
  const [drawer, setDrawer] = useState<DrawerTab>("Hex");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioId, setScenarioId] = useState<string>("");
  const [templates, setTemplates] = useState<Template[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [interfaces, setInterfaces] = useState<Nic[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>("");
  const [offload, setOffload] = useState<Offload | null>(null);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [mutationTypes, setMutationTypes] = useState<MutationType[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [selectedPacketId, setSelectedPacketId] = useState<string>("");
  const [validated, setValidated] = useState(false);
  const [validationMessages, setValidationMessages] = useState<string[]>([]);
  const [remoteLogs, setRemoteLogs] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [executionId, setExecutionId] = useState("");
  const [executionConnection, setExecutionConnection] = useState("");
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [hostForm, setHostForm] = useState(emptyHostForm);
  const [dirtyIds, setDirtyIds] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [previewKey, setPreviewKey] = useState("");
  const [previewError, setPreviewError] = useState("");
  const [confirmExecution, setConfirmExecution] = useState(false);
  const [executionApproved, setExecutionApproved] = useState(false);
  const [validationScenario, setValidationScenario] = useState("");

  const scenario =
    scenarios.find((item) => item.id === scenarioId) ?? scenarios[0];
  const selectedPacket =
    scenario?.packets.find((packet) => packet.id === selectedPacketId) ??
    scenario?.packets[0];
  const selectedHost = hosts.find(
    (host) =>
      host.id ===
      (activeNav === "远端主机" ? managedHostId : scenario?.target?.hostId),
  );
  const inScene = !["远端主机", "执行结果", "设置", "报文样本"].includes(
    activeNav,
  );
  const enabledPackets =
    scenario?.packets.filter((packet) => packet.enabled).length ?? 0;
  const dirty = !!scenario && dirtyIds.includes(scenario.id);
  const packetKey = JSON.stringify(selectedPacket ?? null);
  const currentPreview = previewKey === packetKey ? preview : null;
  const running = submitting || executions.some(isActiveExecution);
  const selectedExecution = executions.find((item) => item.id === executionId);
  const sceneExecutions = executions.filter(
    (item) => item.scenarioId === scenario?.id,
  );
  useEffect(() => {
    if (
      inScene &&
      sceneView === "records" &&
      sceneExecutions.length &&
      !sceneExecutions.some((e) => e.id === executionId)
    )
      setExecutionId(sceneExecutions[0].id);
  }, [inScene, sceneView, scenario?.id, sceneExecutions[0]?.id, executionId]);
  const totalSends =
    (scenario?.packets.reduce((n, p) => n + (p.enabled ? p.sendCount : 0), 0) ??
      0) * (scenario?.sendOptions.loopCount ?? 0);
  const executeBlocker = !scenario
    ? "请先创建或选择场景"
    : dirty
      ? "请先保存修改"
      : !enabledPackets
        ? "请至少启用一个报文"
        : !scenario.target.hostId || !scenario.target.interface
          ? "请在执行配置中选择主机和网口"
          : !validated || validationScenario !== scenario.id
            ? "请先校验当前场景"
            : running
              ? "已有场景正在执行"
              : "";

  const selectScenario = (id: string) => {
    setScenarioId(id);
    setSelectedPacketId(
      scenarios.find((item) => item.id === id)?.packets[0]?.id ?? "",
    );
    setValidated(false);
    setValidationMessages([]);
    setSaveMessage("");
    setActiveNav("场景工作台");
    setSceneView("packets");
  };
  const createScenario = async (duplicate = false) => {
    if (creating || (duplicate ? !scenario || dirty : !newName.trim())) return;
    setCreating(true);
    setApiError("");
    try {
      const created = await apiPost<Scenario>(
        duplicate ? `/scenarios/${scenario!.id}/duplicate` : "/scenarios",
        duplicate ? undefined : { name: newName.trim() },
      );
      setScenarios((items) => [...items, created]);
      selectScenario(created.id);
      setSelectedPacketId(created.packets[0]?.id ?? "");
      setNewName("");
      setNewSceneOpen(false);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "创建场景失败");
    } finally {
      setCreating(false);
    }
  };
  const addPacket = () => {
    const template = templates.find(
      (item) => item.id === (templateId || templates[0]?.id),
    );
    if (!scenario || !template) return;
    const packet: Packet = {
      ...(template.packet
        ? structuredClone(template.packet)
        : { layers: structuredClone(template.layers), mutations: [] }),
      id: crypto.randomUUID(),
      name: `${template.name} ${scenario.packets.length + 1}`,
      templateId: template.id,
      enabled: true,
      sendCount: 1,
      intervalMs: 0,
    };
    updateScenario({ packets: [...scenario.packets, packet] });
    setSelectedPacketId(packet.id);
  };

  const updateScenario = (patch: Partial<Scenario>) => {
    if (!scenario || saving || validating || running) return;
    setScenarios((items) =>
      items.map((item) =>
        item.id === scenario.id ? { ...item, ...patch } : item,
      ),
    );
    setDirtyIds((ids) =>
      ids.includes(scenario.id) ? ids : [...ids, scenario.id],
    );
    setValidated(false);
    setValidationMessages([]);
    setSaveMessage("");
    setApiError("");
  };

  const updatePacket = (packet: Packet) => {
    if (scenario)
      updateScenario({
        packets: scenario.packets.map((item) =>
          item.id === packet.id ? packet : item,
        ),
      });
  };

  const saveScenario = async () => {
    if (!scenario || saving) return;
    const inputError = listenInputError(scenario);
    if (inputError) {
      setApiError(inputError);
      return;
    }
    setSaving(true);
    setApiError("");
    setSaveMessage("");
    try {
      const saved = await apiPut<Scenario>(
        `/scenarios/${scenario.id}`,
        scenario,
      );
      setScenarios((items) =>
        items.map((item) => (item.id === saved.id ? saved : item)),
      );
      setDirtyIds((ids) => ids.filter((id) => id !== saved.id));
      setSaveMessage("已保存，刷新后可继续编辑");
      setValidated(false);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "保存失败，请重试");
    } finally {
      setSaving(false);
    }
  };

  const templateById = useMemo(
    () => new Map(templates.map((template) => [template.id, template])),
    [templates],
  );

  const loadAll = async () => {
    setLoading(true);
    setLoadFailed(false);
    setApiError("");
    try {
      const [scenarioRes, templateRes, hostRes, executionRes, mutationRes] =
        await Promise.all([
          apiGet<{ items: Scenario[] }>("/scenarios"),
          apiGet<{ items: Template[] }>("/templates"),
          apiGet<{ items: Host[] }>("/hosts"),
          apiGet<{ items: Execution[] }>("/executions"),
          apiGet<{ items: MutationType[] }>("/mutation-types"),
        ]);
      setScenarios(scenarioRes.items);
      setTemplates(templateRes.items);
      setHosts(hostRes.items);
      setManagedHostId((current) => current || hostRes.items[0]?.id || "");
      setExecutions(executionRes.items);
      let remembered = "";
      try {
        remembered = localStorage.getItem("pangea.executionId") ?? "";
      } catch {
        /* Storage may be unavailable. */
      }
      const recent = [...executionRes.items].sort((a, b) =>
        (b.startedAt ?? "").localeCompare(a.startedAt ?? ""),
      );
      setExecutionId(
        (current) =>
          current ||
          recent.find(isActiveExecution)?.id ||
          recent.find((item) => item.id === remembered)?.id ||
          recent[0]?.id ||
          "",
      );
      setMutationTypes(mutationRes.items);
      let rememberedScene = "";
      try {
        rememberedScene = localStorage.getItem("pangea.scenarioId") ?? "";
      } catch {
        /* Selection remains usable without storage. */
      }
      const firstScenario =
        scenarioRes.items.find((item) => item.id === rememberedScene) ??
        scenarioRes.items[0];
      if (firstScenario) {
        setScenarioId((current) => current || firstScenario.id);
        setSelectedPacketId(firstScenario.packets[0]?.id ?? "");
      }
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "后端 API 加载失败");
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (scenarioId) {
      try {
        localStorage.setItem("pangea.scenarioId", scenarioId);
      } catch {
        /* Selection remains usable without storage. */
      }
    }
  }, [scenarioId]);

  useEffect(() => {
    if (!executionId) return;
    try {
      localStorage.setItem("pangea.executionId", executionId);
    } catch {
      /* History remains available through the API. */
    }
    let disposed = false;
    let finished = false;
    setExecutionConnection("正在连接执行日志…");
    const socket = new WebSocket(executionStreamUrl(executionId));
    socket.onmessage = (event) => {
      if (disposed) return;
      try {
        const message = JSON.parse(event.data);
        if (
          message.type === "execution_updated" &&
          message.data.id === executionId
        ) {
          const next = message.data as Execution;
          finished = !isActiveExecution(next);
          setExecutions((items) => [
            next,
            ...items.filter((item) => item.id !== next.id),
          ]);
          setExecutionConnection(finished ? "执行记录已保存" : "实时更新中");
        } else if (message.type === "execution_failed") {
          finished = true;
          setExecutionConnection("执行记录不存在，请重新选择");
        }
      } catch {
        setExecutionConnection("日志解析失败，正在定时刷新");
      }
    };
    socket.onerror = () => {
      if (!disposed) setExecutionConnection("实时连接中断，正在定时刷新");
    };
    socket.onclose = () => {
      if (!disposed && !finished)
        setExecutionConnection("实时连接中断，正在定时刷新");
    };
    return () => {
      disposed = true;
      socket.close();
    };
  }, [executionId]);

  useEffect(() => {
    if (!executions.some(isActiveExecution)) return;
    let cancelled = false;
    let timer: number;
    const refresh = async () => {
      try {
        const result = await apiGet<{ items: Execution[] }>("/executions");
        if (!cancelled) {
          setExecutions(result.items);
          if (!result.items.some(isActiveExecution))
            setExecutionConnection("执行记录已保存");
        }
      } catch {
        if (!cancelled)
          setExecutionConnection("暂时无法连接服务，显示上次状态；正在重试");
      } finally {
        if (!cancelled) timer = window.setTimeout(refresh, 1000);
      }
    };
    timer = window.setTimeout(refresh, 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [executions.some(isActiveExecution)]);

  useEffect(() => {
    let cancelled = false;
    setPreview(null);
    setPreviewError("");
    const packet = JSON.parse(packetKey) as Packet | null;
    if (!packet) return;
    const timer = window.setTimeout(() => {
      apiPost<Preview>("/templates/preview", { packet })
        .then((result) => {
          if (!cancelled) {
            setPreview(result);
            setPreviewKey(packetKey);
          }
        })
        .catch((error: Error) => {
          if (!cancelled) setPreviewError(error.message);
        });
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [packetKey, previewRetry]);

  useEffect(() => {
    if (!dirtyIds.length) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirtyIds.length]);

  useEffect(() => {
    interfaceRequest.current += 1;
    setInterfaces([]);
    setRemoteLogs([]);
    setOffload(null);
    setSelectedIface("");
    setQueryingInterfaces(false);
  }, [selectedHost?.id]);

  const loadInterfaces = async (hostId = selectedHost?.id) => {
    if (!hostId) return;
    const request = ++interfaceRequest.current;
    setQueryingInterfaces(true);
    setApiError("");
    try {
      const result = await apiGet<{ items: Nic[] }>(
        `/hosts/${hostId}/interfaces`,
      );
      if (request !== interfaceRequest.current) return;
      setInterfaces(result.items);
      const iface =
        activeNav === "远端主机"
          ? (result.items[0]?.name ?? "")
          : (scenario?.target.interface ?? "");
      setSelectedIface(iface);
      if (iface) {
        const state = await apiGet<Offload>(
          `/hosts/${hostId}/interfaces/${iface}/offload`,
        );
        if (request === interfaceRequest.current) setOffload(state);
      }
    } catch (error) {
      if (request !== interfaceRequest.current) return;
      setInterfaces([]);
      setOffload(null);
      setApiError(error instanceof Error ? error.message : "网卡查询失败");
    } finally {
      if (request === interfaceRequest.current) setQueryingInterfaces(false);
    }
  };

  const validateScenario = async () => {
    if (!scenario || dirty || saving) return;
    const inputError = listenInputError(scenario);
    if (inputError) {
      setApiError(inputError);
      return;
    }
    setValidating(true);
    setInspectorOpen(true);
    setApiError("");
    try {
      const result = await apiPost<{
        valid: boolean;
        errors: Array<{ message: string }>;
        warnings: Array<{ message: string }>;
      }>(`/scenarios/${scenario.id}/validate`);
      setValidated(result.valid);
      setValidationScenario(scenario.id);
      setValidationMessages([
        ...result.errors.map((item) => item.message),
        ...result.warnings.map((item) => item.message),
      ]);
      setDrawer("校验问题");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "场景校验失败");
    } finally {
      setValidating(false);
    }
  };

  const executeScenario = async () => {
    if (!scenario || executeBlocker || saving || !executionApproved) return;
    setConfirmExecution(false);
    setExecutionApproved(false);
    setSubmitting(true);
    setDrawer("执行输出");
    setApiError("");
    try {
      const result = await apiPost<{ executionId: string; status: string }>(
        "/executions",
        { scenarioId: scenario.id },
      );
      setExecutions((items) => [
        {
          id: result.executionId,
          scenarioId: scenario.id,
          mode: scenario.mode,
          status: result.status,
          logs: [],
        },
        ...items.filter((item) => item.id !== result.executionId),
      ]);
      setExecutionId(result.executionId);
      setActiveNav("场景工作台");
      setSceneView("records");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "执行请求失败");
    } finally {
      setSubmitting(false);
    }
  };

  const createHost = async () => {
    if (hostBusy) return;
    setHostBusy(true);
    setApiError("");
    try {
      const created = await apiPost<Host>("/hosts", {
        name: hostForm.name,
        address: hostForm.address,
        sshPort: hostForm.sshPort,
        auth: {
          type: "password",
          username: hostForm.username,
          password: hostForm.password,
        },
        privilege: { mode: "su_root", rootPassword: hostForm.rootPassword },
      });
      setHostForm(emptyHostForm);
      setManagedHostId(created.id);
      const result = await apiGet<{ items: Host[] }>("/hosts");
      setHosts(result.items);
      setHostOpen(false);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "主机保存失败");
    } finally {
      setHostBusy(false);
    }
  };

  const runHostAction = async (action: "connect-test" | "env-check") => {
    if (!selectedHost || hostBusy) return;
    setHostBusy(true);
    setInspectorOpen(true);
    setDrawer("日志");
    setApiError("");
    try {
      const result = await apiPost<Record<string, unknown>>(
        `/hosts/${selectedHost.id}/${action}`,
      );
      setRemoteLogs((logs) => [
        ...logs,
        `${selectedHost.name} · ${action === "connect-test" ? "连接测试" : "环境检查"}\n${JSON.stringify(result, null, 2)}`,
      ]);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : `${action} 失败`);
    } finally {
      setHostBusy(false);
    }
  };

  const exportFile = async (kind: "scapy" | "pcap") => {
    if (!scenario || dirty || saving) return;
    try {
      const result = await apiPost<{ downloadUrl: string; fileName: string }>(
        `/exports/${kind}`,
        { scenarioId: scenario.id },
      );
      window.open(result.downloadUrl, "_blank");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "导出失败");
    }
  };

  const toggleOffload = async (key: string, value: boolean) => {
    if (!selectedHost || !selectedIface || hostBusy) return;
    setHostBusy(true);
    setApiError("");
    try {
      const state = await apiPost<Offload>(
        `/hosts/${selectedHost.id}/interfaces/${selectedIface}/offload`,
        { [key]: value },
      );
      setOffload(state);
      setOffloadConfirm(null);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "Offload 设置失败");
    } finally {
      setHostBusy(false);
    }
  };

  const isSample = activeNav === "报文样本";
  const pageName = isSample
    ? "报文样本"
    : activeNav === "远端主机"
      ? "远端主机"
      : activeNav === "执行结果"
        ? "执行历史"
        : activeNav === "设置"
          ? "设置"
          : sceneView === "config"
            ? "执行配置"
            : sceneView === "records"
              ? "场景执行记录"
              : activeNav === "协议编辑器"
                ? "协议字段"
                : activeNav === "异常用例"
                  ? "异常规则"
                  : "报文序列";
  return (
    <main className="app-shell packet-light">
      <aside className="sidebar">
        <a className="packet-back" href="#/">
          ← 应用首页
        </a>
        <div className="packet-project">
          <strong>异常报文测试</strong>
          <small>PACKET LAB · 测试工作空间</small>
        </div>
        <nav aria-label="报文应用导航">
          {nav.map((item, index) => (
            <button
              key={item}
              aria-current={
                (item === "场景工作台" ? inScene : activeNav === item)
                  ? "page"
                  : undefined
              }
              onClick={() => setActiveNav(item)}
              className={`nav-item ${(item === "场景工作台" ? inScene : activeNav === item) ? "active" : ""}`}
            >
              <Icon
                kind={["grid", "sample", "host", "history", "settings"][index]}
              />
              {item === "场景工作台"
                ? "场景工作台"
                : item === "执行结果"
                  ? "执行历史"
                  : item}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <a href="#/ibmc">⇄ 切换到 iBMC 安全测试 ↗</a>
          <small>向测试设备发送真实报文</small>
        </div>
      </aside>
      <section className="workspace">
        <div className="packet-breadcrumb">异常报文测试 / {pageName}</div>
        <div className="packet-heading">
          <div>
            <h1>{pageName}</h1>
            <p>
              {isSample
                ? "获取报文，精确编辑字节，保存为可复用的测试模板。"
                : activeNav === "远端主机"
                  ? "选择主机，核对连接、网卡及 Offload 配置。"
                  : activeNav === "执行结果"
                    ? "选择执行记录，核对任务进度、日志与证据。"
                    : activeNav === "设置"
                      ? "查看工作空间的运行方式与保存行为。"
                      : activeNav === "异常用例"
                        ? "选择目标字段和异常值，先应用规则，再保存场景。"
                        : activeNav === "协议编辑器"
                          ? "按协议层编辑字段，实时核对报文字节。"
                          : "组织报文、配置目标并校验，再确认执行范围。"}
            </p>
          </div>
          <span className="packet-label">真实设备执行</span>
        </div>
        {apiError && (
          <div className="api-error" role="alert">
            <div>
              <strong>操作未完成</strong>
              <p>{apiError}</p>
            </div>
            {loadFailed ? (
              <button onClick={() => void loadAll()}>重试加载</button>
            ) : (
              <button aria-label="关闭错误提示" onClick={() => setApiError("")}>
                ×
              </button>
            )}
          </div>
        )}
        {loading ? (
          <LoadingState label="正在加载测试工作空间" />
        ) : loadFailed ? (
          <EmptyState
            title="暂时无法加载数据"
            text="请检查后端服务连接，然后点击上方重试。已有服务端记录不会被覆盖。"
          />
        ) : (
          <>
            {(inScene || isSample) && (
              <div className="packet-scenario-bar">
                <label>
                  当前场景
                  <select
                    aria-label="当前场景"
                    value={scenario?.id ?? ""}
                    disabled={saving || creating || validating}
                    onChange={(e) => selectScenario(e.target.value)}
                  >
                    <option value="" disabled>
                      请选择场景
                    </option>
                    {scenarios.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                        {dirtyIds.includes(item.id) ? " · 未保存" : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <div>
                  <button
                    disabled={creating || saving}
                    onClick={() => {
                      setApiError("");
                      setNewSceneOpen(true);
                    }}
                  >
                    ＋ 新建场景
                  </button>
                  <button
                    disabled={!scenario || dirty || creating || saving}
                    onClick={() => void createScenario(true)}
                  >
                    复制场景
                  </button>
                </div>
              </div>
            )}
            {scenario && inScene && (
              <>
                <div className="packet-scene-summary">
                  <div>
                    <h2>{scenario.name}</h2>
                    <p>
                      {scenario.description ||
                        "从报文配置开始，逐步完成本轮测试。"}
                    </p>
                  </div>
                  <span className={`packet-label ${dirty ? "amber" : ""}`}>
                    {saving
                      ? "正在保存…"
                      : dirty
                        ? "未保存"
                        : saveMessage || "已保存"}
                  </span>
                </div>
                <div className="packet-action-bar">
                  <span>{executeBlocker || "校验通过，可核对执行范围"}</span>
                  <div>
                    <button
                      disabled={!dirty || saving || validating || running}
                      onClick={() => void saveScenario()}
                    >
                      {saving ? "保存中…" : "保存场景"}
                    </button>
                    <button
                      disabled={dirty || saving || validating || running}
                      onClick={() => void validateScenario()}
                    >
                      {validating
                        ? "校验中…"
                        : validated
                          ? "重新校验"
                          : "校验场景"}
                    </button>
                    <button
                      className="run-button"
                      disabled={!!executeBlocker || saving}
                      onClick={() => {
                        setExecutionApproved(false);
                        setConfirmExecution(true);
                      }}
                    >
                      {running ? "执行中…" : "执行前确认 →"}
                    </button>
                  </div>
                </div>
                <nav className="scene-tabs packet-stages" aria-label="场景步骤">
                  {(
                    [
                      ["packets", "报文配置"],
                      ["config", "执行配置"],
                      ["records", "执行记录"],
                    ] as const
                  ).map(([v, label], i) => (
                    <button
                      key={v}
                      aria-pressed={sceneView === v}
                      onClick={() => {
                        setSceneView(v);
                        setActiveNav("场景工作台");
                      }}
                    >
                      <span>{i + 1}</span>
                      {label}
                    </button>
                  ))}
                </nav>
                {sceneView === "packets" && (
                  <div className="scene-tabs">
                    <nav aria-label="报文编辑">
                      {(
                        ["场景工作台", "协议编辑器", "异常用例"] as NavItem[]
                      ).map((item, i) => (
                        <button
                          key={item}
                          aria-pressed={activeNav === item}
                          onClick={() => setActiveNav(item)}
                        >
                          {["报文序列", "协议字段", "异常规则"][i]}
                        </button>
                      ))}
                    </nav>
                    <label className="packet-current">
                      当前报文
                      <select
                        aria-label="当前报文"
                        value={selectedPacket?.id ?? ""}
                        onChange={(e) => setSelectedPacketId(e.target.value)}
                      >
                        <option value="" disabled>
                          请添加报文
                        </option>
                        {scenario.packets.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                )}
              </>
            )}
            {selectedExecution && isActiveExecution(selectedExecution) && (
              <div className="execution-banner" role="status">
                <span>
                  {selectedExecution.id} ·{" "}
                  {executionStatus(selectedExecution.status)}
                </span>
                <button
                  onClick={() => {
                    setActiveNav("执行结果");
                    setDrawer("执行输出");
                  }}
                >
                  查看执行详情 →
                </button>
              </div>
            )}
            <fieldset
              className="workspace-fields"
              disabled={
                saving ||
                creating ||
                validating ||
                (running && activeNav !== "执行结果" && sceneView !== "records")
              }
            >
              {activeNav === "场景工作台" && sceneView !== "records" && (
                <div
                  className={
                    sceneView === "config"
                      ? "scene-config-view"
                      : "scene-packets-view"
                  }
                >
                  {scenario && sceneView === "packets" && (
                    <div className="packet-tools">
                      <label>
                        报文模板
                        <select
                          aria-label="报文模板"
                          value={templateId || templates[0]?.id || ""}
                          onChange={(e) => setTemplateId(e.target.value)}
                        >
                          {templates.map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.name}
                            </option>
                          ))}
                        </select>
                      </label>
                      <button
                        className="add-button"
                        disabled={!templates.length}
                        onClick={addPacket}
                      >
                        从模板添加报文
                      </button>
                      <div className="packet-export">
                        <button
                          disabled={dirty}
                          onClick={() => void exportFile("scapy")}
                        >
                          导出 Scapy
                        </button>
                        <button
                          disabled={dirty}
                          onClick={() => void exportFile("pcap")}
                        >
                          导出 PCAP
                        </button>
                      </div>
                    </div>
                  )}
                  {sceneView === "config" && (
                    <div className="packet-tools">
                      <button onClick={() => setActiveNav("远端主机")}>
                        管理主机
                      </button>
                      <button
                        disabled={!selectedHost || hostBusy}
                        onClick={() => void runHostAction("connect-test")}
                      >
                        测试连接
                      </button>
                      <button
                        disabled={!selectedHost || hostBusy}
                        onClick={() => void runHostAction("env-check")}
                      >
                        环境检查
                      </button>
                      <button
                        disabled={!selectedHost || queryingInterfaces}
                        onClick={() => void loadInterfaces()}
                      >
                        {queryingInterfaces ? "正在查询…" : "查询网卡"}
                      </button>
                    </div>
                  )}
                  <ScenarioWorkbench
                    scenario={scenario}
                    selectedPacketId={selectedPacketId}
                    setSelectedPacketId={setSelectedPacketId}
                    templateById={templateById}
                    enabledPackets={enabledPackets}
                    validated={validated}
                    setActiveNav={setActiveNav}
                    onChange={updateScenario}
                    onPacketChange={updatePacket}
                    hosts={hosts}
                    interfaces={interfaces}
                    view={sceneView}
                  />
                  {sceneView === "config" && scenario?.mode === "listen" && (
                    <ListenEditor
                      scenario={scenario}
                      onChange={updateScenario}
                    />
                  )}
                </div>
              )}
              <div hidden={!isSample}>
                <SampleWorkbench
                  current={selectedPacket}
                  canAdd={!!scenario && !running && !saving && !validating}
                  hosts={hosts}
                  onTemplates={async () => {
                    const r = await apiGet<{ items: Template[] }>("/templates");
                    setTemplates(r.items);
                  }}
                  onAdd={(p) => {
                    if (!scenario || running || saving || validating) return;
                    const copy = {
                      ...structuredClone(p),
                      id: crypto.randomUUID(),
                    };
                    updateScenario({ packets: [...scenario.packets, copy] });
                    setSelectedPacketId(copy.id);
                  }}
                />
              </div>
              {activeNav === "协议编辑器" && (
                <ProtocolEditor
                  packet={selectedPacket}
                  preview={currentPreview}
                  onChange={updatePacket}
                />
              )}
              <div hidden={activeNav !== "异常用例"}>
                <MutationPage
                  key={`${scenario?.id}/${selectedPacket?.id}`}
                  packet={selectedPacket}
                  mutationTypes={mutationTypes}
                  onChange={updatePacket}
                />
              </div>
              {activeNav === "远端主机" && (
                <HostPage
                  hosts={hosts}
                  logs={remoteLogs}
                  selectedHost={selectedHost}
                  onSelect={setManagedHostId}
                  interfaces={interfaces}
                  selectedIface={selectedIface}
                  onSelectIface={async (name) => {
                    const request = ++interfaceRequest.current;
                    setSelectedIface(name);
                    setOffload(null);
                    setQueryingInterfaces(true);
                    setApiError("");
                    try {
                      const result = await apiGet<Offload>(
                        `/hosts/${selectedHost?.id}/interfaces/${name}/offload`,
                      );
                      if (request === interfaceRequest.current)
                        setOffload(result);
                    } catch (e) {
                      if (request === interfaceRequest.current)
                        setApiError(
                          e instanceof Error ? e.message : "读取 Offload 失败",
                        );
                    } finally {
                      if (request === interfaceRequest.current)
                        setQueryingInterfaces(false);
                    }
                  }}
                  offload={offload}
                  busy={hostBusy || queryingInterfaces}
                  onNewHost={() => setHostOpen(true)}
                  onLoadInterfaces={() => void loadInterfaces()}
                  onHostAction={runHostAction}
                  onToggleOffload={(key, value) =>
                    setOffloadConfirm({ key, value })
                  }
                />
              )}
              {inScene && sceneView === "records" && (
                <ExecutionPage
                  executions={sceneExecutions}
                  selected={
                    sceneExecutions.find((e) => e.id === executionId) ??
                    sceneExecutions[0]
                  }
                  onSelect={setExecutionId}
                  connection={executionConnection}
                />
              )}
              {activeNav === "执行结果" && (
                <ExecutionPage
                  executions={executions}
                  selected={selectedExecution}
                  onSelect={setExecutionId}
                  connection={executionConnection}
                />
              )}
              {activeNav === "设置" && <SettingsPage />}
            </fieldset>
            {inScene && (
              <section className="drawer packet-inspector">
                <div className="drawer-tabs">
                  {drawerTabs.map((t) => (
                    <button
                      key={t}
                      aria-pressed={drawer === t}
                      onClick={() => {
                        setDrawer(t);
                        setInspectorOpen(true);
                      }}
                      className={drawer === t ? "active" : ""}
                    >
                      {t}
                      {t === "校验问题" && validationMessages.length > 0 && (
                        <em>{validationMessages.length}</em>
                      )}
                    </button>
                  ))}
                  <button
                    className="inspector-collapse"
                    aria-expanded={inspectorOpen}
                    onClick={() => setInspectorOpen(!inspectorOpen)}
                  >
                    {inspectorOpen ? "收起" : "展开"}
                  </button>
                </div>
                {inspectorOpen && (
                  <div className="drawer-content">
                    {drawer === "Hex" &&
                      (!selectedPacket ? (
                        <Lines lines={["添加报文后显示字节预览"]} />
                      ) : previewError ? (
                        <div role="alert" className="api-error">
                          {previewError}
                          <button onClick={() => setPreviewRetry((x) => x + 1)}>
                            重试预览
                          </button>
                        </div>
                      ) : (
                        <HexDrawer preview={currentPreview} />
                      ))}
                    {drawer === "校验问题" && (
                      <Lines
                        lines={
                          validationMessages.length
                            ? validationMessages
                            : [
                                validated
                                  ? "场景校验通过"
                                  : "尚未校验，请先保存并校验场景",
                              ]
                        }
                      />
                    )}{" "}
                    {drawer === "日志" && (
                      <Lines
                        lines={
                          remoteLogs.length ? remoteLogs : ["暂无远端日志"]
                        }
                      />
                    )}{" "}
                    {drawer === "执行输出" &&
                      (selectedExecution ? (
                        <ExecutionDetails
                          execution={selectedExecution}
                          compact
                        />
                      ) : (
                        <Lines
                          lines={["尚未执行，确认目标并校验场景后可创建任务。"]}
                        />
                      ))}
                  </div>
                )}
              </section>
            )}
          </>
        )}
      </section>
      {newSceneOpen && (
        <AppDialog
          title="新建报文场景"
          onClose={() => setNewSceneOpen(false)}
          busy={creating}
        >
          <p>填写场景名称，创建后添加报文并配置测试目标。</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void createScenario();
            }}
          >
            <label className="ui-field">
              场景名称
              <input
                autoFocus
                required
                maxLength={120}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="例如 VXLAN 长度异常验证"
              />
            </label>
            {apiError && (
              <p role="alert" className="api-error">
                {apiError}
              </p>
            )}
            <footer>
              <button
                type="button"
                disabled={creating}
                onClick={() => setNewSceneOpen(false)}
              >
                取消
              </button>
              <button
                className="ui-primary"
                disabled={creating || !newName.trim()}
              >
                {creating ? "创建中…" : "创建场景"}
              </button>
            </footer>
          </form>
        </AppDialog>
      )}
      {hostOpen && (
        <AppDialog
          title="添加远端主机"
          onClose={() => setHostOpen(false)}
          busy={hostBusy}
        >
          <p>保存主机信息后，可测试连接并查询网卡。</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void createHost();
            }}
          >
            <div className="ui-form-grid">
              {(
                [
                  ["name", "主机名称"],
                  ["address", "IP / 主机地址"],
                  ["username", "SSH 用户"],
                  ["sshPort", "SSH 端口"],
                  ["password", "SSH 密码"],
                  ["rootPassword", "root 密码（可选）"],
                ] as const
              ).map(([key, label]) => (
                <label className="ui-field" key={key}>
                  {label}
                  <input
                    autoComplete={
                      key.endsWith("assword") ? "new-password" : "off"
                    }
                    type={
                      key === "sshPort"
                        ? "number"
                        : key.toLowerCase().includes("password")
                          ? "password"
                          : "text"
                    }
                    required={["name", "address", "username"].includes(key)}
                    min={key === "sshPort" ? 1 : undefined}
                    max={key === "sshPort" ? 65535 : undefined}
                    value={hostForm[key]}
                    onChange={(e) =>
                      setHostForm({
                        ...hostForm,
                        [key]:
                          key === "sshPort"
                            ? Number(e.target.value)
                            : e.target.value,
                      })
                    }
                  />
                </label>
              ))}
            </div>
            {apiError && (
              <p role="alert" className="api-error">
                {apiError}
              </p>
            )}
            <footer>
              <button
                type="button"
                disabled={hostBusy}
                onClick={() => setHostOpen(false)}
              >
                取消
              </button>
              <button className="ui-primary" disabled={hostBusy}>
                {hostBusy ? "保存中…" : "保存主机"}
              </button>
            </footer>
          </form>
        </AppDialog>
      )}
      {offloadConfirm && (
        <ConfirmDialog
          title="修改网卡 Offload"
          busy={hostBusy}
          action="确认修改"
          onClose={() => setOffloadConfirm(null)}
          onConfirm={() =>
            void toggleOffload(offloadConfirm.key, offloadConfirm.value)
          }
        >
          <p>
            {selectedHost?.name} / {selectedIface}
          </p>
          <p>
            将 {offloadConfirm.key} 设置为{" "}
            <strong>{offloadConfirm.value ? "开启" : "关闭"}</strong>
            。此操作会修改所选网卡配置。
          </p>
          {apiError && <p role="alert">{apiError}</p>}
        </ConfirmDialog>
      )}
      {confirmExecution && scenario && (
        <ExecutionConfirm
          scenario={scenario}
          host={hosts.find((h) => h.id === scenario.target.hostId)}
          total={totalSends}
          approved={executionApproved}
          onApprove={setExecutionApproved}
          onClose={() => setConfirmExecution(false)}
          onExecute={() => void executeScenario()}
          blocker={executeBlocker}
        />
      )}
    </main>
  );
}

function ScenarioWorkbench({
  scenario,
  selectedPacketId,
  setSelectedPacketId,
  templateById,
  enabledPackets,
  validated,
  setActiveNav,
  onChange,
  onPacketChange,
  hosts,
  interfaces,
  view,
}: {
  scenario?: Scenario;
  selectedPacketId: string;
  setSelectedPacketId: (id: string) => void;
  templateById: Map<string, Template>;
  enabledPackets: number;
  validated: boolean;
  setActiveNav: (item: NavItem) => void;
  onChange: (patch: Partial<Scenario>) => void;
  onPacketChange: (packet: Packet) => void;
  hosts: Host[];
  interfaces: Nic[];
  view: "packets" | "config";
}) {
  if (!scenario)
    return (
      <EmptyState
        title="创建第一个场景"
        text="点击「新建场景」，再从模板添加报文。"
      />
    );
  const selectedPacket =
    scenario.packets.find((packet) => packet.id === selectedPacketId) ??
    scenario.packets[0];
  const totalSends =
    scenario.packets.reduce(
      (sum, packet) => sum + (packet.enabled ? packet.sendCount : 0),
      0,
    ) * scenario.sendOptions.loopCount;
  return (
    <>
      {view === "config" && (
        <div className="mode-switch">
          <button
            aria-pressed={scenario.mode === "direct"}
            onClick={() => onChange({ mode: "direct" })}
            className={scenario.mode === "direct" ? "selected" : ""}
          >
            ◉ 直接模式<span>主动构造并发送报文</span>
          </button>
          <button
            aria-pressed={scenario.mode === "listen"}
            onClick={() =>
              onChange({
                mode: "listen",
                listenConfig: scenario.listenConfig ?? {
                  interface: scenario.target.interface,
                  match: {
                    mode: "outer_five_tuple",
                    bpf: "",
                    outer: { protocol: "tcp" },
                  },
                  trigger: { packetIndex: 1, tcpFlags: [], delayMs: 0 },
                  direction: {
                    mode: "same_direction",
                    derive: "same_direction",
                  },
                  cachePolicy: {
                    storePayload: false,
                    persistToDisk: false,
                    maxRecords: 1000,
                  },
                },
              })
            }
            className={scenario.mode === "listen" ? "selected" : ""}
          >
            ◌ 监听模式<span>匹配流量后触发注入</span>
          </button>
          <div className="mode-summary">
            目标{" "}
            <b>
              {scenario.target.hostId ?? "未配置"} /{" "}
              {scenario.target.interface ?? "未选网口"}
            </b>{" "}
            · {enabledPackets} 个报文已启用
          </div>
        </div>
      )}
      <div className="content-grid">
        {view === "packets" && (
          <section className="panel packets-panel">
            <div className="panel-head">
              <div>
                <h2>报文序列</h2>
                <span>选择报文后可编辑协议字段与异常规则</span>
              </div>
            </div>
            {!scenario.packets.length && (
              <p className="editor-hint">
                从上方模板添加第一个报文，然后编辑字段并保存场景。
              </p>
            )}
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
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {scenario.packets.map((packet, index) => (
                    <tr
                      key={packet.id}
                      onClick={() => setSelectedPacketId(packet.id)}
                      className={
                        selectedPacketId === packet.id ? "selected-row" : ""
                      }
                    >
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`启用 ${packet.name}`}
                          checked={packet.enabled}
                          onClick={(event) => event.stopPropagation()}
                          onChange={(event) =>
                            onPacketChange({
                              ...packet,
                              enabled: event.target.checked,
                            })
                          }
                        />
                      </td>
                      <td className="order">⠿ {index + 1}</td>
                      <td>
                        <b>{packet.name}</b>
                      </td>
                      <td>
                        <span className="template">
                          {templateById.get(packet.templateId ?? "")?.name ??
                            packet.templateId ??
                            "自定义"}
                        </span>
                      </td>
                      <td>
                        <button
                          className={
                            packet.mutations.length ? "mutation" : "zero"
                          }
                          onClick={(event) => {
                            event.stopPropagation();
                            setSelectedPacketId(packet.id);
                            setActiveNav("异常用例");
                          }}
                        >
                          {packet.mutations.length}
                        </button>
                      </td>
                      <td>
                        <input
                          className="table-number"
                          type="number"
                          min="1"
                          aria-label={`${packet.name} 发送次数`}
                          value={packet.sendCount}
                          onChange={(event) =>
                            onPacketChange({
                              ...packet,
                              sendCount: Number(event.target.value),
                            })
                          }
                        />
                      </td>
                      <td>
                        <input
                          className="table-number"
                          type="number"
                          min="0"
                          aria-label={`${packet.name} 间隔毫秒`}
                          value={packet.intervalMs}
                          onChange={(event) =>
                            onPacketChange({
                              ...packet,
                              intervalMs: Number(event.target.value),
                            })
                          }
                        />{" "}
                        ms
                      </td>
                      <td>
                        <StatusBadge status={validated ? "可执行" : "未校验"} />
                      </td>
                      <td>
                        <button
                          className="quiet-button"
                          onClick={() => {
                            setSelectedPacketId(packet.id);
                            setActiveNav("协议编辑器");
                          }}
                        >
                          编辑
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <footer className="table-footer">
              <span>
                {scenario.packets.length} 个报文 · {enabledPackets} 个已启用
              </span>
              <span>
                总计 <b>{totalSends}</b> 次发送
              </span>
            </footer>
          </section>
        )}
        {view === "config" && (
          <aside className="config-stack">
            <section className="panel config-panel">
              <div className="panel-head">
                <div>
                  <h2>场景配置</h2>
                  <span>修改后点击「保存场景」</span>
                </div>
              </div>
              <label className="config-row">
                <span>目标主机</span>
                <select
                  value={scenario.target.hostId ?? ""}
                  onChange={(event) =>
                    onChange({
                      target: {
                        ...scenario.target,
                        hostId: event.target.value || null,
                        interface: null,
                      },
                      ...(scenario.listenConfig
                        ? {
                            listenConfig: {
                              ...scenario.listenConfig,
                              interface: null,
                            },
                          }
                        : {}),
                    })
                  }
                >
                  <option value="">请选择主机</option>
                  {scenario.target.hostId &&
                    !hosts.some(
                      (host) => host.id === scenario.target.hostId,
                    ) && (
                      <option value={scenario.target.hostId}>
                        主机已不可用
                      </option>
                    )}
                  {hosts.map((host) => (
                    <option key={host.id} value={host.id}>
                      {host.name} · {host.address}
                    </option>
                  ))}
                </select>
              </label>
              <label className="config-row">
                <span>发送网口</span>
                <select
                  value={scenario.target.interface ?? ""}
                  onChange={(event) =>
                    onChange({
                      target: {
                        ...scenario.target,
                        interface: event.target.value || null,
                      },
                      ...(scenario.listenConfig
                        ? {
                            listenConfig: {
                              ...scenario.listenConfig,
                              interface: event.target.value || null,
                            },
                          }
                        : {}),
                    })
                  }
                >
                  <option value="">查询网卡后选择</option>
                  {scenario.target.interface &&
                    !interfaces.some(
                      (nic) => nic.name === scenario.target.interface,
                    ) && (
                      <option value={scenario.target.interface}>
                        {scenario.target.interface} · 已保存，待查询
                      </option>
                    )}
                  {interfaces.map((nic) => (
                    <option key={nic.name} value={nic.name}>
                      {nic.name} · {nic.link} · {nic.ips.join(", ")}
                    </option>
                  ))}
                </select>
              </label>
              <label className="config-row">
                <span>循环次数</span>
                <input
                  type="number"
                  min="1"
                  value={scenario.sendOptions.loopCount}
                  onChange={(event) =>
                    onChange({
                      sendOptions: {
                        ...scenario.sendOptions,
                        loopCount: Number(event.target.value),
                      },
                    })
                  }
                />
              </label>
              <label className="config-row">
                <span>失败后停止</span>
                <select
                  value={String(scenario.sendOptions.stopOnFailure)}
                  onChange={(event) =>
                    onChange({
                      sendOptions: {
                        ...scenario.sendOptions,
                        stopOnFailure: event.target.value === "true",
                      },
                    })
                  }
                >
                  <option value="true">是</option>
                  <option value="false">否</option>
                </select>
              </label>
            </section>
            <section className="offload-card">
              <div>
                <span className="eyebrow">当前报文</span>
                <h3>{selectedPacket?.name ?? "未选择"}</h3>
                <p>
                  {selectedPacket?.layers
                    .map((layer) => layer.type)
                    .join(" / ")}
                </p>
              </div>
              <span className="offload-ok">API</span>
            </section>
          </aside>
        )}
      </div>
    </>
  );
}

function ProtocolEditor({
  packet,
  preview,
  onChange,
}: {
  packet?: Packet;
  preview: Preview | null;
  onChange: (packet: Packet) => void;
}) {
  const [layerId, setLayerId] = useState("");
  if (!packet)
    return <EmptyState title="未选择报文" text="请先在场景工作台选择报文。" />;
  if (packet.rawHex != null)
    return (
      <section className="panel packet-raw">
        <h2>原始样本报文</h2>
        <p>
          从「报文样本」载入当前场景报文，可修改协议字段、插入或删除字节、追加
          Padding 并保存为模板。
        </p>
        <pre className="sample-hex">{chunkHex(packet.rawHex)}</pre>
      </section>
    );
  const changeLayer = (layer: Layer) =>
    onChange({
      ...packet,
      layers: packet.layers.map((item) =>
        item.id === layer.id ? layer : item,
      ),
    });
  return (
    <div className="other-page">
      <div className="page-title">
        <div>
          <div className="eyebrow">PACKET / {packet.id}</div>
          <h1>协议编辑器</h1>
          <p>修改字段后自动更新字节预览，保存场景后可导出。</p>
        </div>
      </div>
      <div className="other-grid">
        <section className="panel other-main">
          <div className="panel-head">
            <div>
              <h2>协议层与字段</h2>
              <span>
                {packet.layers.length} 层 ·{" "}
                {preview ? `${preview.length} bytes` : "正在更新预览"}
              </span>
            </div>
          </div>
          <nav className="packet-layer-tabs" aria-label="协议层">
            {packet.layers.map((l) => (
              <button
                key={l.id}
                aria-pressed={
                  (packet.layers.some((x) => x.id === layerId)
                    ? layerId
                    : packet.layers[0]?.id) === l.id
                }
                onClick={() => setLayerId(l.id)}
              >
                {l.role} · {l.type}
              </button>
            ))}
          </nav>
          {packet.layers
            .filter(
              (l) =>
                l.id ===
                (packet.layers.some((x) => x.id === layerId)
                  ? layerId
                  : packet.layers[0]?.id),
            )
            .map((layer) => (
              <section className="layer-editor" key={layer.id}>
                <h3>
                  {layer.role}.{layer.type}
                </h3>
                {![
                  "ethernet",
                  "ipv4",
                  "tcp",
                  "udp",
                  "vxlan",
                  "raw_payload",
                ].includes(layer.type) && (
                  <p className="editor-hint">
                    此协议尚未实现完整构造，字段仅保存在配置中。
                  </p>
                )}
                {Array.from(
                  new Set([
                    ...Object.keys(layer.fields),
                    ...Object.keys(layer.autoCalculate ?? {}),
                  ]),
                ).map((name) => {
                  const automatic = !!layer.autoCalculate?.[name];
                  const value = layer.fields[name];
                  const label = `${layer.role}.${layer.type}.${name}`;
                  return (
                    <div className="field-editor" key={name}>
                      <label>
                        <span>{name}</span>
                        <ValueInput
                          label={label}
                          field={name}
                          disabled={automatic}
                          value={value}
                          onChange={(next) =>
                            changeLayer({
                              ...layer,
                              fields: { ...layer.fields, [name]: next },
                            })
                          }
                        />
                      </label>
                      {name in (layer.autoCalculate ?? {}) && (
                        <label className="auto-calculate">
                          <input
                            type="checkbox"
                            aria-label={`${label} 自动计算`}
                            checked={automatic}
                            onChange={(event) =>
                              changeLayer({
                                ...layer,
                                autoCalculate: {
                                  ...layer.autoCalculate,
                                  [name]: event.target.checked,
                                },
                              })
                            }
                          />
                          自动计算
                        </label>
                      )}
                    </div>
                  );
                })}
              </section>
            ))}
        </section>
        <aside className="panel inspector">
          <div className="panel-head">
            <div>
              <h2>Hex 预览</h2>
              <span>当前报文的最终字节</span>
            </div>
          </div>
          <pre className="mini-hex">
            {preview ? chunkHex(preview.hex) : "等待有效的报文预览"}
          </pre>
          {preview?.warnings.map((warning) => (
            <p className="editor-hint" key={warning.code}>
              {warning.message}
            </p>
          ))}
        </aside>
      </div>
    </div>
  );
}

function MutationPage({
  packet,
  mutationTypes,
  onChange,
}: {
  packet?: Packet;
  mutationTypes: MutationType[];
  onChange: (packet: Packet) => void;
}) {
  const [candidates, setCandidates] = useState<Mutation[]>([]);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [manualType, setManualType] = useState("invalid_length");
  if (!packet) return <EmptyState title="未选择报文" text="请先选择报文。" />;
  const addManual = () => {
    const field = manualType === "invalid_length" ? "len" : "chksum";
    const needsField = ["invalid_length", "invalid_checksum"].includes(
      manualType,
    );
    const layer = packet.layers.find(
      (l) =>
        (field === "len" ? ["ipv4", "udp"] : ["ipv4", "tcp", "udp"]).includes(
          l.type,
        ) && field in l.fields,
    );
    if (needsField && !layer) {
      setError("当前报文没有适用目标字段，请先检查协议层。");
      return;
    }
    setError("");
    setMessage("");
    setCandidates((items) => [
      ...items,
      {
        id: crypto.randomUUID(),
        name:
          manualType === "invalid_length"
            ? "指定长度异常"
            : manualType === "invalid_checksum"
              ? "指定校验和异常"
              : manualType === "truncate_packet"
                ? "尾部截断"
                : "非零填充",
        enabled: true,
        type: manualType,
        strategy:
          manualType === "truncate_packet"
            ? "remove_tail_bytes"
            : manualType === "invalid_padding"
              ? "non_zero"
              : "custom",
        value: needsField ? 0 : 1,
        applyOrder:
          manualType === "invalid_length"
            ? 300
            : manualType === "invalid_checksum"
              ? 500
              : manualType === "invalid_padding"
                ? 600
                : 700,
        ...(needsField && layer
          ? {
              target: {
                layerId: layer.id,
                fieldPath: `${layer.role}.${layer.type}[0].${field}`,
              },
              options: { disableAutoCalculate: true },
            }
          : {}),
      },
    ]);
  };
  const generate = async () => {
    setGenerating(true);
    setError("");
    setMessage("");
    try {
      const result = await apiPost<{ mutations: Mutation[] }>(
        "/mutations/random-generate",
        { packet, count: 3 },
      );
      setCandidates(result.mutations);
      if (!result.mutations.length) setMessage("当前报文没有可生成的异常规则");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "生成失败，请重试");
    } finally {
      setGenerating(false);
    }
  };
  const apply = async () => {
    setGenerating(true);
    setError("");
    try {
      const mutations = [...packet.mutations, ...candidates];
      const result = await apiPost<{
        valid: boolean;
        errors: Array<{ message: string }>;
      }>("/mutations/validate", { packet, mutations });
      if (!result.valid)
        throw new Error(result.errors.map((item) => item.message).join("；"));
      await apiPost<Preview>("/templates/preview", {
        packet: { ...packet, mutations },
      });
      onChange({ ...packet, mutations });
      setCandidates([]);
      setMessage("规则已应用到报文，请保存场景");
    } catch (failure) {
      setError(
        failure instanceof Error ? failure.message : "应用失败，请检查规则",
      );
    } finally {
      setGenerating(false);
    }
  };
  return (
    <div className="other-page">
      <div className="page-title">
        <div>
          <div className="eyebrow">MUTATIONS / {packet.name}</div>
          <h1>异常规则</h1>
          <p>指定异常类型、目标字段和值，校验并应用后保存场景。</p>
        </div>
        <button
          className="quiet-button"
          disabled={generating}
          onClick={generate}
        >
          {generating ? "处理中…" : "随机建议 3 条"}
        </button>
      </div>
      <div className="manual-mutation">
        <label>
          指定异常类型
          <select
            aria-label="指定异常类型"
            value={manualType}
            onChange={(e) => setManualType(e.target.value)}
          >
            <option value="invalid_length">长度字段异常</option>
            <option value="invalid_checksum">校验和异常</option>
            <option value="truncate_packet">尾部截断（字节）</option>
            <option value="invalid_padding">非零填充（字节）</option>
          </select>
        </label>
        <button
          className="add-button"
          disabled={generating}
          onClick={addManual}
        >
          添加指定规则
        </button>
        <span>切换报文或场景前，请将待应用规则应用到报文。</span>
      </div>
      {error && (
        <div role="alert" className="api-error">
          {error}
        </div>
      )}
      {message && (
        <p role="status" className="editor-hint">
          {message}
        </p>
      )}
      <fieldset className="workspace-fields" disabled={generating}>
        {!!candidates.length && (
          <section className="panel mutation-candidates">
            <div className="panel-head">
              <div>
                <h2>待应用规则</h2>
                <span>{candidates.length} 条 · 编辑后应用</span>
              </div>
              <button className="add-button" onClick={apply}>
                应用到报文
              </button>
            </div>
            {candidates.map((mutation, index) => (
              <MutationEditor
                key={mutation.id}
                label={`待应用规则 ${index + 1}`}
                mutation={mutation}
                packet={packet}
                onChange={(next) =>
                  setCandidates((items) =>
                    items.map((item) => (item.id === next.id ? next : item)),
                  )
                }
                onRemove={() =>
                  setCandidates((items) =>
                    items.filter((item) => item.id !== mutation.id),
                  )
                }
              />
            ))}
          </section>
        )}
        <section className="panel other-main">
          <div className="panel-head">
            <div>
              <h2>当前报文异常</h2>
              <span>{packet.mutations.length} 条规则 · 修改后保存场景</span>
            </div>
          </div>
          {packet.mutations.length ? (
            packet.mutations.map((mutation, index) => (
              <MutationEditor
                key={mutation.id}
                label={`报文规则 ${index + 1}`}
                mutation={mutation}
                packet={packet}
                onChange={(next) =>
                  onChange({
                    ...packet,
                    mutations: packet.mutations.map((item) =>
                      item.id === next.id ? next : item,
                    ),
                  })
                }
                onRemove={() =>
                  onChange({
                    ...packet,
                    mutations: packet.mutations.filter(
                      (item) => item.id !== mutation.id,
                    ),
                  })
                }
              />
            ))
          ) : (
            <EmptyInline text="当前报文没有异常规则" />
          )}
        </section>
        <p className="editor-hint">
          服务端规则目录：
          {mutationTypes.map((item) => item.displayName).join("、")}
          。本页手动入口提供已接入构造的四类规则；硬件可能修正校验和或补齐短帧，须结合旁路抓包判定。
        </p>
      </fieldset>
    </div>
  );
}

function MutationEditor({
  mutation,
  packet,
  label,
  onChange,
  onRemove,
}: {
  mutation: Mutation;
  packet: Packet;
  label: string;
  onChange: (mutation: Mutation) => void;
  onRemove: () => void;
}) {
  const fieldName =
    mutation.type === "invalid_checksum"
      ? "chksum"
      : mutation.type === "invalid_length"
        ? "len"
        : null;
  const targets = packet.layers
    .filter(
      (layer) =>
        !fieldName ||
        (fieldName === "len"
          ? ["ipv4", "udp"]
          : ["ipv4", "tcp", "udp"]
        ).includes(layer.type),
    )
    .flatMap((layer) =>
      Object.keys(layer.fields)
        .filter((field) => !fieldName || field === fieldName)
        .map((field) => ({
          layerId: layer.id,
          path: `${layer.role}.${layer.type}[0].${field}`,
        })),
    );
  return (
    <section className="mutation-editor" aria-label={label}>
      <div className="mutation-heading">
        <label>
          <input
            type="checkbox"
            aria-label={`${label} 启用`}
            checked={mutation.enabled}
            onChange={(event) =>
              onChange({ ...mutation, enabled: event.target.checked })
            }
          />
          启用
        </label>
        <span>
          {mutation.type} / {mutation.strategy}
        </span>
        <button
          className="quiet-button"
          aria-label={`${label} 移除`}
          onClick={onRemove}
        >
          移除
        </button>
      </div>
      <label className="editor-label">
        名称
        <input
          aria-label={`${label} 名称`}
          value={mutation.name}
          onChange={(event) =>
            onChange({ ...mutation, name: event.target.value })
          }
        />
      </label>
      {mutation.target?.fieldPath && (
        <label className="editor-label">
          目标字段
          <select
            aria-label={`${label} 目标字段`}
            value={mutation.target.fieldPath}
            onChange={(event) =>
              onChange({
                ...mutation,
                target: {
                  ...mutation.target,
                  fieldPath: event.target.value,
                  layerId: targets.find(
                    (item) => item.path === event.target.value,
                  )?.layerId,
                },
              })
            }
          >
            {!targets.some(
              (target) => target.path === mutation.target?.fieldPath,
            ) && (
              <option value={mutation.target.fieldPath}>
                {mutation.target.fieldPath}
              </option>
            )}
            {targets.map((target) => (
              <option
                key={`${target.layerId}/${target.path}`}
                value={target.path}
              >
                {target.path}
              </option>
            ))}
          </select>
        </label>
      )}
      {mutation.type !== "inner_outer_mismatch" && (
        <label className="editor-label">
          异常值
          <ValueInput
            label={`${label} 异常值`}
            field="value"
            value={mutation.value}
            onChange={(value) => onChange({ ...mutation, value })}
          />
        </label>
      )}
      {fieldName && (
        <label className="auto-calculate">
          <input
            type="checkbox"
            aria-label={`${label} 覆盖自动计算`}
            checked={!!mutation.options?.disableAutoCalculate}
            onChange={(event) =>
              onChange({
                ...mutation,
                options: {
                  ...mutation.options,
                  disableAutoCalculate: event.target.checked,
                },
              })
            }
          />
          应用时覆盖目标字段的自动计算
        </label>
      )}
    </section>
  );
}

function formatValue(value: unknown): string {
  return value == null
    ? ""
    : typeof value === "object"
      ? JSON.stringify(value)
      : String(value);
}

function ValueInput({
  label,
  field,
  value,
  disabled,
  onChange,
}: {
  label: string;
  field: string;
  value: unknown;
  disabled?: boolean;
  onChange: (value: unknown) => void;
}) {
  const [text, setText] = useState(formatValue(value));
  useEffect(() => {
    setText((current) =>
      JSON.stringify(parseFieldValue(current, field)) === JSON.stringify(value)
        ? current
        : formatValue(value),
    );
  }, [value, field]);
  return (
    <input
      aria-label={label}
      disabled={disabled}
      placeholder={disabled ? "自动计算" : "字段值"}
      value={text}
      onChange={(event) => {
        setText(event.target.value);
        onChange(parseFieldValue(event.target.value, field));
      }}
    />
  );
}

function parseFieldValue(value: string, field: string): unknown {
  if (["src", "dst", "bytes", "reserved1"].includes(field)) return value;
  if (value === "") return null;
  if (/^(?:-?\d+|0x[\da-f]+)$/i.test(value)) return Number(value);
  if (value.startsWith("[") || value.startsWith("{")) {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function ListenEditor({
  scenario,
  onChange,
}: {
  scenario: Scenario;
  onChange: (patch: Partial<Scenario>) => void;
}) {
  const config = scenario.listenConfig;
  if (!config) return <EmptyInline text="请重新选择监听模式以初始化配置" />;
  const change = (patch: Partial<NonNullable<Scenario["listenConfig"]>>) =>
    onChange({ listenConfig: { ...config, ...patch } });
  const tuple =
    config.match.mode === "vxlan_inner_five_tuple" ? "inner" : "outer";
  return (
    <section className="panel listen-editor">
      <div className="panel-head">
        <div>
          <h2>监听条件与触发</h2>
          <span>先匹配，再按触发序号注入；修改后保存并重新校验。</span>
        </div>
      </div>
      <div className="listen-fields">
        <label>
          匹配位置
          <select
            value={config.match.mode}
            onChange={(e) =>
              change({
                match: {
                  ...config.match,
                  mode: e.target.value,
                  ...(e.target.value === "custom"
                    ? { outer: null, inner: null, tunnel: null }
                    : {}),
                },
              })
            }
          >
            <option value="outer_five_tuple">外层五元组</option>
            <option value="vxlan_inner_five_tuple">VXLAN 内层五元组</option>
            <option value="custom">自定义 BPF（清空五元组）</option>
          </select>
        </label>
        <label>
          BPF 抓包过滤
          <input
            value={config.match.bpf || ""}
            placeholder={
              config.match.mode === "vxlan_inner_five_tuple"
                ? "留空使用 udp and port 4789"
                : "留空使用 tcp or udp"
            }
            onChange={(e) =>
              change({ match: { ...config.match, bpf: e.target.value } })
            }
          />
        </label>
        {config.match.mode !== "custom" && (
          <>
            {(["srcIp", "dstIp", "srcPort", "dstPort"] as const).map(
              (key, i) => (
                <label key={`${tuple}-${key}`}>
                  {tuple === "inner" ? "内层" : "外层"}{" "}
                  {["源 IP", "目的 IP", "源端口", "目的端口"][i]}
                  <input
                    value={String(config.match[tuple]?.[key] ?? "")}
                    placeholder="留空表示任意"
                    type={key.endsWith("Port") ? "number" : "text"}
                    min={key.endsWith("Port") ? 0 : undefined}
                    max={key.endsWith("Port") ? 65535 : undefined}
                    onChange={(e) =>
                      change({
                        match: {
                          ...config.match,
                          [tuple]: {
                            ...config.match[tuple],
                            [key]:
                              e.target.value === ""
                                ? null
                                : key.endsWith("Port")
                                  ? Number(e.target.value)
                                  : e.target.value,
                          },
                        },
                      })
                    }
                  />
                </label>
              ),
            )}
            <label>
              匹配协议
              <select
                value={String(config.match[tuple]?.protocol ?? "any")}
                onChange={(e) =>
                  change({
                    match: {
                      ...config.match,
                      [tuple]: {
                        ...config.match[tuple],
                        protocol: e.target.value,
                      },
                    },
                  })
                }
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="any">不限制协议</option>
                {config.match[tuple]?.protocol === "icmp" && (
                  <option value="icmp">ICMP（已有配置，未支持严格匹配）</option>
                )}
              </select>
            </label>
          </>
        )}
        {config.match.mode === "vxlan_inner_five_tuple" && (
          <label>
            VNI
            <input
              type="number"
              min="0"
              max="16777215"
              value={config.match.tunnel?.vni ?? ""}
              placeholder="留空表示任意"
              onChange={(e) =>
                change({
                  match: {
                    ...config.match,
                    tunnel: {
                      type: "vxlan",
                      vni:
                        e.target.value === "" ? null : Number(e.target.value),
                    },
                  },
                })
              }
            />
          </label>
        )}
        <label>
          第 N 个匹配包触发
          <input
            type="number"
            min="1"
            value={config.trigger.packetIndex}
            onChange={(e) =>
              change({
                trigger: {
                  ...config.trigger,
                  packetIndex: Number(e.target.value),
                },
              })
            }
          />
        </label>
        <label>
          注入延迟（ms）
          <input
            type="number"
            min="0"
            value={config.trigger.delayMs}
            onChange={(e) =>
              change({
                trigger: { ...config.trigger, delayMs: Number(e.target.value) },
              })
            }
          />
        </label>
        <label>
          TCP 标记
          <input
            value={config.trigger.tcpFlags.join("")}
            placeholder="例如 SA；留空不限制"
            onChange={(e) =>
              change({
                trigger: {
                  ...config.trigger,
                  tcpFlags: e.target.value
                    .toUpperCase()
                    .replace(/\s/g, "")
                    .split(""),
                },
              })
            }
          />
        </label>
        <label>
          TCP 序号继承
          <select
            value={config.direction.derive}
            onChange={(e) =>
              change({
                direction: {
                  ...config.direction,
                  mode: e.target.value,
                  derive: e.target.value,
                },
              })
            }
          >
            <option value="same_direction">同向复制触发包 seq / ack</option>
            <option value="reverse_direction">
              反向响应（按有效负载推导）
            </option>
            <option value="none">保留报文原有 seq / ack</option>
          </select>
        </label>
        <label>
          注入地址映射
          <select
            value={config.direction.addresses ?? "preserve"}
            onChange={(e) =>
              change({
                direction: { ...config.direction, addresses: e.target.value },
              })
            }
          >
            <option value="preserve">保留模板 MAC / IP / 端口</option>
            <option value="same_direction">复制触发包地址与端口</option>
            <option value="reverse_direction">交换触发包地址与端口</option>
          </select>
        </label>
        <label>
          注入校验和
          <select
            value={config.direction.checksums ?? "preserve"}
            onChange={(e) =>
              change({
                direction: { ...config.direction, checksums: e.target.value },
              })
            }
          >
            <option value="preserve">保留原值（含指定异常）</option>
            <option value="repair">注入修改后重新计算</option>
          </select>
        </label>
      </div>
      <p className="editor-hint">
        推导支持无 VLAN 的 IPv4/TCP 和标准 VXLAN 内层 TCP，不跟踪完整 TCP
        会话。长度异常或短包需要保留校验和策略；修改 seq/ack
        或地址却保留校验和，可能引入额外校验和错误。一次命中执行一个批次，未命中会报告超时；触发包和发送字节记录在执行日志中。
      </p>
    </section>
  );
}

function HostPage({
  hosts,
  selectedHost,
  onSelect,
  interfaces,
  selectedIface,
  onSelectIface,
  offload,
  busy,
  onNewHost,
  onLoadInterfaces,
  onHostAction,
  onToggleOffload,
  logs,
}: {
  hosts: Host[];
  selectedHost?: Host;
  onSelect: (id: string) => void;
  interfaces: Nic[];
  selectedIface: string;
  onSelectIface: (name: string) => void;
  offload: Offload | null;
  busy: boolean;
  onNewHost: () => void;
  onLoadInterfaces: () => void;
  onHostAction: (action: "connect-test" | "env-check") => void;
  onToggleOffload: (key: string, value: boolean) => void;
  logs: string[];
}) {
  return (
    <>
      <div className="packet-tools">
        <span>{hosts.length} 台已保存主机</span>
        <button className="add-button" onClick={onNewHost}>
          ＋ 添加主机
        </button>
      </div>
      <div className="packet-master-detail">
        <section className="panel">
          <div className="panel-head">
            <h2>主机列表</h2>
          </div>
          {hosts.length ? (
            hosts.map((h) => (
              <button
                key={h.id}
                className="packet-list-row"
                aria-pressed={selectedHost?.id === h.id}
                disabled={busy}
                onClick={() => onSelect(h.id)}
              >
                <Icon kind="host" />
                <span>
                  <b>{h.name}</b>
                  <small>
                    {h.address}:{h.sshPort}
                  </small>
                  <small>{h.auth?.username || "未记录用户"}</small>
                </span>
              </button>
            ))
          ) : (
            <EmptyInline text="添加第一台测试主机" />
          )}
        </section>
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>{selectedHost?.name || "主机详情"}</h2>
              <span>
                {selectedHost
                  ? `${selectedHost.address} · SSH ${selectedHost.sshPort}`
                  : "从左侧选择一台主机"}
              </span>
            </div>
          </div>
          {selectedHost && (
            <>
              <div className="packet-tools padded">
                <button
                  disabled={busy}
                  onClick={() => onHostAction("connect-test")}
                >
                  测试连接
                </button>
                <button
                  disabled={busy}
                  onClick={() => onHostAction("env-check")}
                >
                  环境检查
                </button>
                <button disabled={busy} onClick={onLoadInterfaces}>
                  查询网卡
                </button>
                {busy && <span role="status">正在处理…</span>}
              </div>
              <div className="nic-list">
                {interfaces.length ? (
                  interfaces.map((n) => (
                    <button
                      key={n.name}
                      className="packet-list-row"
                      disabled={busy}
                      aria-pressed={selectedIface === n.name}
                      onClick={() => onSelectIface(n.name)}
                    >
                      <span>
                        <b>
                          {n.name}{" "}
                          <span className="packet-label">{n.link}</span>
                        </b>
                        <small>
                          {n.mac} · {n.ips.join(", ") || "未配置 IP"}
                        </small>
                        <small>
                          {n.speed} · {n.driver}
                        </small>
                      </span>
                    </button>
                  ))
                ) : (
                  <EmptyInline text="查询网卡后，选择接口查看 Offload" />
                )}
              </div>
              {offload && (
                <div className="packet-offload">
                  <h3>{selectedIface} · Offload</h3>
                  {Object.entries(offload)
                    .filter(([, v]) => typeof v === "boolean")
                    .map(([key, value]) => (
                      <div className="switch-row" key={key}>
                        <span>{key}</span>
                        <button
                          className="packet-switch"
                          role="switch"
                          aria-checked={!!value}
                          aria-label={key}
                          disabled={busy}
                          onClick={() => onToggleOffload(key, !value)}
                        >
                          {value ? "开启" : "关闭"}
                        </button>
                      </div>
                    ))}
                </div>
              )}
            </>
          )}
        </section>
      </div>
      <section className="panel packet-host-log">
        <div className="panel-head">
          <h2>连接与环境检查记录</h2>
        </div>
        <Lines
          lines={
            logs.length
              ? logs
              : ["选择主机后运行连接测试或环境检查，结果会显示在这里。"]
          }
        />
      </section>
    </>
  );
}

function ExecutionPage({
  executions,
  selected,
  onSelect,
  connection,
}: {
  executions: Execution[];
  selected?: Execution;
  onSelect: (id: string) => void;
  connection: string;
}) {
  const [query, setQuery] = useState(""),
    [status, setStatus] = useState("all");
  const sorted = [...executions]
    .filter(
      (e) =>
        (status === "all" || e.status === status) &&
        `${e.id} ${e.scenarioId}`.toLowerCase().includes(query.toLowerCase()),
    )
    .sort((a, b) => (b.startedAt ?? "").localeCompare(a.startedAt ?? ""));
  const visibleSelected = sorted.find((e) => e.id === selected?.id);
  return (
    <>
      <div className="packet-tools">
        <label>
          搜索记录
          <input
            placeholder="执行 ID 或场景 ID"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <label>
          执行状态
          <select
            aria-label="执行状态"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="all">全部状态</option>
            {["pending", "running", "success", "failed", "cancelled"].map(
              (v) => (
                <option key={v} value={v}>
                  {executionStatus(v)}
                </option>
              ),
            )}
          </select>
        </label>
        <span>{sorted.length} 条记录</span>
      </div>
      <div className="packet-master-detail">
        <section className="panel execution-history">
          {sorted.length ? (
            sorted.map((e) => (
              <button
                key={e.id}
                className="execution-row"
                aria-pressed={selected?.id === e.id}
                onClick={() => onSelect(e.id)}
              >
                <span>
                  <b>{e.id}</b>
                  <small>
                    {e.mode === "listen" ? "监听模式" : "直接模式"} ·{" "}
                    {e.scenarioId}
                  </small>
                  <small>
                    {e.startedAt
                      ? executionDate(e.startedAt).toLocaleString()
                      : "等待开始"}
                  </small>
                </span>
                <span
                  className={`packet-label ${e.status === "failed" ? "red" : e.status === "running" ? "amber" : ""}`}
                >
                  {executionStatus(e.status)}
                </span>
              </button>
            ))
          ) : (
            <EmptyInline
              text={
                executions.length
                  ? "没有符合条件的执行记录"
                  : "暂无执行记录，完成场景配置后可发起执行"
              }
            />
          )}
        </section>
        <section className="panel execution-detail">
          <div className="panel-head">
            <h2>执行详情</h2>
            <span role="status">{visibleSelected ? connection : ""}</span>
          </div>
          {visibleSelected ? (
            <ExecutionDetails execution={visibleSelected} />
          ) : (
            <EmptyInline text="选择一条记录查看日志与证据" />
          )}
        </section>
      </div>
    </>
  );
}

function executionLogText(log: Record<string, unknown>): string {
  const data = log.data;
  if (typeof data !== "string") return JSON.stringify(data ?? log);
  try {
    const event = JSON.parse(data);
    if (event.event === "send_progress" || event.event === "send_complete")
      return `已报告发送 ${event.reportedSendCount} 个报文${event.event === "send_complete" ? " · 发送结束" : ""}`;
    if (event.event === "listen_start") return `开始监听：${event.bpf}`;
    if (event.event === "listen_match") return `已匹配 ${event.matched} 个报文`;
    if (event.event === "listen_complete")
      return `监听结束：匹配 ${event.matched} 个，发送 ${event.reportedSendCount} 个`;
    if (event.event === "trigger_evidence")
      return "已保存触发报文字节（可导出执行证据）";
    if (event.event === "injection_evidence")
      return `已保存提交网卡的报文字节：${event.packetId}（线上字节须旁路确认）`;
  } catch {
    /* Plain text output is rendered directly. */
  }
  return data;
}

function ExecutionDetails({
  execution,
  compact = false,
}: {
  execution: Execution;
  compact?: boolean;
}) {
  const logElement = useRef<HTMLDivElement>(null);
  const followOutput = useRef(true);
  useEffect(() => {
    followOutput.current = true;
  }, [execution.id]);
  useEffect(() => {
    if (followOutput.current && logElement.current)
      logElement.current.scrollTop = logElement.current.scrollHeight;
  }, [execution.id, execution.logs?.length]);
  const error =
    execution.level0?.error ??
    (execution.status === "failed" ? execution.level0?.stderr : null);
  return (
    <div className={`execution-output ${compact ? "compact" : ""}`}>
      <button
        className="quiet-button"
        onClick={() => {
          const url = URL.createObjectURL(
            new Blob([JSON.stringify(execution, null, 2)], {
              type: "application/json",
            }),
          );
          const link = document.createElement("a");
          link.href = url;
          link.download = `${execution.id}-evidence.json`;
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }}
      >
        导出执行证据 JSON
      </button>
      <div className="execution-summary">
        <b>{execution.id}</b>
        <span
          className={execution.status === "failed" ? "execution-failed" : ""}
        >
          {executionStatus(execution.status)}
        </span>
        {execution.level0?.reportedSendCount != null && (
          <span>报告发送：{String(execution.level0.reportedSendCount)}</span>
        )}
      </div>
      {!!error && (
        <p className="execution-failed" role="alert">
          失败原因：{String(error)}
        </p>
      )}
      {!compact && (
        <p className="editor-hint">
          开始：
          {execution.startedAt
            ? executionDate(execution.startedAt).toLocaleString()
            : "等待开始"}
          {execution.finishedAt
            ? ` · 结束：${executionDate(execution.finishedAt).toLocaleString()}`
            : ""}
        </p>
      )}
      {!compact && (
        <p className="editor-hint">
          此状态描述发包任务。卡件异常处理、业务中断与恢复是否符合预期，仍需结合设备日志、业务监控和旁路抓包验证。
        </p>
      )}
      <div
        ref={logElement}
        onScroll={(event) => {
          const element = event.currentTarget;
          followOutput.current =
            element.scrollHeight - element.scrollTop - element.clientHeight <
            24;
        }}
        className="execution-log"
        role="log"
        aria-label={compact ? "执行输出摘要" : "执行日志"}
      >
        {execution.logs?.length ? (
          execution.logs.map((log, index) => (
            <div key={index}>
              <time>
                {log.timestamp
                  ? executionDate(String(log.timestamp)).toLocaleTimeString()
                  : ""}
              </time>
              <span>{executionLogText(log)}</span>
            </div>
          ))
        ) : (
          <p>
            {isActiveExecution(execution)
              ? "等待执行日志…"
              : "此记录没有执行日志"}
          </p>
        )}
      </div>
    </div>
  );
}

function ExecutionConfirm({
  scenario,
  host,
  total,
  approved,
  onApprove,
  onClose,
  onExecute,
  blocker,
}: {
  scenario: Scenario;
  host?: Host;
  total: number;
  approved: boolean;
  onApprove: (v: boolean) => void;
  onClose: () => void;
  onExecute: () => void;
  blocker: string;
}) {
  return (
    <AppDialog title="确认真实发包范围" onClose={onClose}>
      <div className="packet-confirm-content">
        <p>
          {scenario.name} ·{" "}
          {scenario.mode === "listen" ? "监听匹配后注入" : "直接发送"}
        </p>
        <dl>
          <dt>主机</dt>
          <dd>
            {host?.name ?? scenario.target.hostId} · {host?.address}
          </dd>
          <dt>网口</dt>
          <dd>{scenario.target.interface}</dd>
          <dt>配置发送次数</dt>
          <dd>{total}（监听模式以实际触发记录为准）</dd>
          <dt>失败后停止</dt>
          <dd>{scenario.sendOptions.stopOnFailure ? "是" : "否"}</dd>
        </dl>
        <p>
          请确认测试网口不承载生产或共享业务，已检查连接、环境与
          Offload，并安排旁路观测和恢复。场景校验不代表这些条件已满足。
        </p>
        <label>
          <input
            type="checkbox"
            checked={approved}
            onChange={(e) => onApprove(e.target.checked)}
          />
          我已确认目标、授权范围及恢复安排
        </label>
        {blocker && <p role="alert">{blocker}</p>}
        <footer>
          <button className="quiet-button" onClick={onClose}>
            返回检查
          </button>
          <button
            className="run-button"
            disabled={!approved || !!blocker}
            onClick={onExecute}
          >
            确认并执行
          </button>
        </footer>
      </div>
    </AppDialog>
  );
}

function executionDate(value: string): Date {
  return new Date(/(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`);
}

function SettingsPage() {
  return (
    <div className="packet-settings">
      {[
        [
          "场景与保存",
          "场景修改需要点击「保存场景」。离开应用或刷新前，请保存修改。切换场景会保留本次会话中的编辑。",
        ],
        [
          "样本与模板",
          "样本编辑需要另存或更新模板。模板复用到场景后形成独立副本，修改模板不会改动已有场景。",
        ],
        [
          "执行与证据",
          "场景保存并校验通过后，核对目标主机和网口再执行。执行历史中可导出 JSON 证据。",
        ],
        [
          "运行服务",
          "此应用连接当前部署的报文测试服务。主机连接和网络配置在「远端主机」中管理。",
        ],
      ].map(([title, body]) => (
        <section className="panel" key={title}>
          <h2>{title}</h2>
          <p>{body}</p>
        </section>
      ))}
    </div>
  );
}

function HexDrawer({ preview }: { preview: Preview | null }) {
  if (!preview)
    return (
      <div className="hex-label" role="status">
        正在更新报文预览…
      </div>
    );
  return (
    <>
      <div className="hex-label">
        {preview?.hex ? chunkHex(preview.hex) : "等待后端 Hex 预览"}
      </div>
      <div className="hex-legend">
        <span>
          <i className="orange" />
          真实长度：{preview?.length ?? 0} bytes
        </span>
        <span>
          <i className="purple" />
          {preview?.warnings?.[0]?.message ?? "无预览告警"}
        </span>
      </div>
    </>
  );
}

function Lines({ lines }: { lines: string[] }) {
  return (
    <div className="output">
      <span className="prompt">$</span>{" "}
      {lines.map((line, index) => (
        <div key={`${index}-${line}`} className="log-line">
          {line}
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: "可执行" | "有警告" | "未校验" }) {
  return (
    <span
      className={`status ${status === "可执行" ? "ok" : status === "有警告" ? "warn" : "idle"}`}
    >
      <i />
      {status}
    </span>
  );
}

function EmptyState({ title, text }: { title: string; text: string }) {
  return (
    <section className="panel other-main packet-empty">
      <h2>{title}</h2>
      <p>{text}</p>
    </section>
  );
}

function EmptyInline({ text }: { text: string }) {
  return (
    <div className="detail-row">
      <span>
        <b>{text}</b>
        <small>等待后端数据或用户配置</small>
      </span>
    </div>
  );
}

function chunkHex(hex: string) {
  const compact = hex.replace(/\s+/g, "");
  const pairs = compact.match(/.{1,2}/g) ?? [];
  const lines: string[] = [];
  for (let i = 0; i < pairs.length; i += 16) {
    lines.push(
      `${i.toString(16).padStart(4, "0")}  ${pairs.slice(i, i + 16).join(" ")}`,
    );
  }
  return lines.join("\n");
}
