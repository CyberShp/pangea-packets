import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import PacketApp from "./App";
import { useDiscardGuard } from "./ui";
import {
  DEMO_KEY,
  draftFor,
  isDemoStore,
  methods,
  seedStore,
  uid,
} from "./platform-model";
import type { Case, DemoStore, Path, Project, Run } from "./platform-model";
import "./platform.css";

const pages = [
  ["overview", "项目工作台"],
  ["intake", "信息收集"],
  ["risks", "风险与范围"],
  ["paths", "攻击路径"],
  ["design", "测试用例"],
  ["execute", "执行与挖掘"],
  ["results", "结果与复测"],
  ["skills", "方法与 Skills"],
] as const;
const descriptions: Record<string, string> = {
  overview: "从产品资料到测试证据，逐步推进本轮验证。",
  intake: "先建立产品事实，再确定测试范围。",
  risks: "明确本轮要验证什么，并记录纳入或排除的理由。",
  paths: "明确入口、身份与目标，为测试用例保留完整依据。",
  design: "一条用例验证一条路径，保留步骤、判据与资料依据。",
  execute: "按已审查用例创建批次，保留快照与探索线索。",
  results: "先核对证据，再决定结论与复测范围。",
  skills: "查看内置方法，理解适用范围与交付要求。",
};
const skillNames = [
  "产品信息收集",
  "攻击面梳理",
  "风险路径分析",
  "Web 测试设计",
  "固件测试设计",
  "证据复核",
];
const skillIds = [
  "ibmc-product-intake",
  "ibmc-attack-surface",
  "ibmc-risk-paths",
  "ibmc-web-test-design",
  "ibmc-firmware-test-design",
  "ibmc-evidence-review",
];
const skillFiles = import.meta.glob("../skills/ibmc/ibmc-*/SKILL.md", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;
const hash = () => window.location.hash.slice(1) || "/";
const go = (p: string) => {
  window.location.hash = p;
};
const date = (s: string) =>
  new Date(s).toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
const stage = (p: Project) =>
  !p.docs.length
    ? 0
    : !p.risks.some((r) => r.selected)
      ? 1
      : !p.cases.some((c) => c.reviewed)
        ? 2
        : !p.runs.some((r) => r.done)
          ? 3
          : 4;
const stages = ["资料准备", "范围确认", "路径与用例", "模拟执行", "结果复测"];
type Field = {
  key: string;
  label: string;
  value?: string;
  multiline?: boolean;
  optional?: boolean;
  options?: { value: string; label: string }[];
};
type Editor = {
  title: string;
  note?: string;
  fields: Field[];
  save: (v: Record<string, string>) => boolean;
  submit?: string;
};
type Drawer = { kind: "review" | "evidence" | "snapshot"; id: string };
function Icon({ name = "overview" }: { name?: string }) {
  const paths: Record<string, ReactNode> = {
    overview: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    intake: (
      <>
        <path d="M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h7" />
      </>
    ),
    risks: <path d="M12 3l8 4v5c0 5-8 9-8 9s-8-4-8-9V7z" />,
    paths: (
      <>
        <circle cx="12" cy="5" r="3" />
        <circle cx="5" cy="19" r="3" />
        <circle cx="19" cy="19" r="3" />
        <path d="M12 8v4H5v4m7-4h7v4" />
      </>
    ),
    design: (
      <>
        <rect x="5" y="3" width="14" height="18" rx="2" />
        <path d="M9 8h6M9 12h6M9 16h3" />
      </>
    ),
    execute: <path d="M6 3l15 9L6 21z" />,
    results: (
      <>
        <rect x="3" y="14" width="4" height="7" rx="1" />
        <rect x="10" y="8" width="4" height="13" rx="1" />
        <rect x="17" y="3" width="4" height="18" rx="1" />
      </>
    ),
    skills: (
      <path d="M12 6c-4-3-8-2-9-1v15c3-2 6-2 9 0 3-2 6-2 9 0V5c-3-2-6-2-9 1zm0 0v14" />
    ),
    search: (
      <>
        <circle cx="10" cy="10" r="6" />
        <path d="M15 15l6 6" />
      </>
    ),
    plus: <path d="M12 5v14M5 12h14" />,
    info: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 10v7M12 6v1" />
      </>
    ),
  };
  return (
    <svg
      className="s-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name] || paths.overview}
    </svg>
  );
}
function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`s-badge ${tone}`}>{children}</span>;
}
function Empty({
  children,
  action,
}: {
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="s-empty">
      <Icon name="intake" />
      <h3>{children}</h3>
      {action}
    </div>
  );
}
function Panel({
  title,
  children,
  action,
}: {
  title?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="s-panel">
      {title && (
        <div className="s-row">
          <h2>{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
function Search({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (s: string) => void;
  placeholder: string;
}) {
  return (
    <label className="s-search">
      <Icon name="search" />
      <input
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}
function Modal({
  children,
  title,
  close,
  drawer = false,
}: {
  children: ReactNode;
  title: string;
  close: () => void;
  drawer?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLElement | null>(null);
  useEffect(() => {
    trigger.current = document.activeElement as HTMLElement;
    ref.current?.showModal();
    return () => {
      trigger.current?.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={`s-modal ${drawer ? "s-drawer" : ""}`}
      aria-labelledby="dialog-title"
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
    >
      <div className="s-row s-modal-head">
        <h2 id="dialog-title">{title}</h2>
        <button className="s-icon-button" onClick={close} aria-label="关闭">
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}
function EditDialog({ editor, close }: { editor: Editor; close: () => void }) {
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(false);
  const discard = useDiscardGuard(dirty);
  const requestClose = () => discard.request(close);
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const values = Object.fromEntries(
      editor.fields.map((f) => [f.key, String(fd.get(f.key) || "").trim()]),
    );
    if (editor.fields.some((f) => !f.optional && !values[f.key])) {
      setError("请填写必填字段，内容不能只有空格。");
      return;
    }
    if (editor.save(values)) close();
    else setError("保存未完成，请检查页面中的存储错误提示。");
  };
  return (
    <>
      <Modal title={editor.title} close={requestClose}>
        <p className="s-muted">
          {editor.note || "保存后可继续完善，记录保存在当前浏览器。"}
        </p>
        <form
          onSubmit={submit}
          onChange={(e) => {
            const data = new FormData(e.currentTarget);
            setDirty(
              editor.fields.some(
                (f) =>
                  String(data.get(f.key) || "") !==
                  (f.value ?? f.options?.[0]?.value ?? ""),
              ),
            );
          }}
        >
          {error && (
            <p className="s-warning" role="alert">
              {error}
            </p>
          )}
          <div className="s-form">
            {editor.fields.map((f) => (
              <label key={f.key}>
                {f.label}
                {!f.optional && <span className="s-required"> *</span>}
                {f.options ? (
                  <select
                    name={f.key}
                    defaultValue={f.value || f.options[0]?.value}
                    required={!f.optional}
                  >
                    {f.options.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                ) : f.multiline ? (
                  <textarea
                    name={f.key}
                    defaultValue={f.value}
                    rows={4}
                    required={!f.optional}
                    maxLength={6000}
                  />
                ) : (
                  <input
                    name={f.key}
                    defaultValue={f.value}
                    required={!f.optional}
                    maxLength={160}
                  />
                )}
              </label>
            ))}
          </div>
          <footer className="s-modal-footer">
            <button type="button" onClick={requestClose}>
              取消
            </button>
            <button className="s-primary">{editor.submit || "保存修改"}</button>
          </footer>
        </form>
      </Modal>
      {discard.dialog}
    </>
  );
}

export default function Platform() {
  const [route, setRoute] = useState(hash),
    [packetMounted, setPacketMounted] = useState(hash().startsWith("/packets"));
  const [store, setStore] = useState<DemoStore>(() => {
    try {
      const raw = localStorage.getItem(DEMO_KEY);
      if (!raw) return seedStore();
      const v = JSON.parse(raw);
      return isDemoStore(v) ? v : { version: 1, projects: [] };
    } catch {
      return { version: 1, projects: [] };
    }
  });
  const persisted = useRef<string | null>(null);
  useEffect(() => {
    try {
      persisted.current = localStorage.getItem(DEMO_KEY);
    } catch {
      /* Read error is surfaced below. */
    }
  }, []);
  const [storageError, setStorageError] = useState(() => {
    try {
      const raw = localStorage.getItem(DEMO_KEY);
      return raw && !isDemoStore(JSON.parse(raw))
        ? "本地数据格式不兼容。原数据已保留，当前仅可查看。"
        : "";
    } catch {
      return "本地数据无法读取。原数据已保留，当前仅可查看。";
    }
  });
  const [notice, setNotice] = useState(""),
    [editor, setEditor] = useState<Editor | null>(null),
    [drawer, setDrawer] = useState<Drawer | null>(null),
    [query, setQuery] = useState(""),
    [selected, setSelected] = useState(""),
    [filter, setFilter] = useState("all"),
    [tab, setTab] = useState("content"),
    [skill, setSkill] = useState(0),
    [checks, setChecks] = useState<boolean[]>([false, false, false, false]),
    [reviewNote, setReviewNote] = useState("");
  useEffect(() => {
    const change = () => {
      setRoute(hash());
      setEditor(null);
      setDrawer(null);
      setQuery("");
      setSelected("");
      setFilter("all");
      setTab("content");
      if (hash().startsWith("/packets")) setPacketMounted(true);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(""), 5000);
    return () => clearTimeout(t);
  }, [notice]);
  const [app = "home", projectId, page = "overview"] = route
    .split("/")
    .filter(Boolean);
  const project = store.projects.find((p) => p.id === projectId);
  const title = pages.find((p) => p[0] === page)?.[1];
  useEffect(() => {
    document.title = `${app === "packets" ? "异常报文测试" : project ? title || "页面不存在" : "iBMC 安全测试"} · PANGEA`;
  }, [app, project?.id, title]);
  const commit = (next: DemoStore, message: string) => {
    if (storageError) {
      setNotice("保存未完成，请先解决本地存储问题。");
      return false;
    }
    try {
      if (localStorage.getItem(DEMO_KEY) !== persisted.current) {
        setStorageError(
          "另一个页面已修改本地记录。为避免覆盖，请刷新页面读取最新数据后再编辑。",
        );
        return false;
      }
      const serialized = JSON.stringify(next);
      localStorage.setItem(DEMO_KEY, serialized);
      persisted.current = serialized;
      setStore(next);
      setNotice(message);
      return true;
    } catch {
      setStorageError(
        "本地保存失败，未覆盖现有记录。请检查浏览器存储空间或权限后重试。",
      );
      return false;
    }
  };
  const change = (patch: Partial<Project>, message = "已保存到本机") =>
    project
      ? commit(
          {
            ...store,
            projects: store.projects.map((p) =>
              p.id === project.id
                ? { ...p, ...patch, updated: new Date().toISOString() }
                : p,
            ),
          },
          message,
        )
      : false;
  const link = (p: string) => `#/ibmc/${project!.id}/${p}`;
  const newProject = () =>
    setEditor({
      title: "新建测试项目",
      note: "先填写基本信息，进入项目后继续补充资料。",
      submit: "创建并进入项目 →",
      fields: [
        { key: "name", label: "项目名称" },
        { key: "model", label: "产品型号" },
        { key: "version", label: "固件版本" },
        { key: "goal", label: "测试目标", multiline: true, optional: true },
      ],
      save: (v) => {
        const id = uid();
        const ok = commit(
          {
            ...store,
            projects: [
              ...store.projects,
              {
                id,
                name: v.name,
                model: v.model,
                version: v.version,
                goal: v.goal,
                updated: new Date().toISOString(),
                docs: [],
                risks: [],
                paths: [],
                cases: [],
                runs: [],
              },
            ],
          },
          "项目已创建",
        );
        if (ok) go(`/ibmc/${id}/overview`);
        return ok;
      },
    });
  const editDoc = (id?: string) => {
    const d = project!.docs.find((d) => d.id === id);
    setEditor({
      title: d ? "编辑资料记录" : "添加资料记录",
      note: "记录资料来源与摘要；当前不自动解析文件。",
      fields: [
        { key: "name", label: "资料名称", value: d?.name },
        { key: "version", label: "适用版本", value: d?.version },
        { key: "source", label: "来源位置", value: d?.source, optional: true },
        {
          key: "note",
          label: "关键内容与待确认事项",
          value: d?.note,
          multiline: true,
        },
      ],
      save: (v) => {
        const doc = {
          id: d?.id || uid(),
          name: v.name,
          version: v.version,
          source: v.source,
          note: v.note,
          parsed: true,
        };
        return change({
          docs: d
            ? project!.docs.map((x) => (x.id === id ? doc : x))
            : [...project!.docs, doc],
        });
      },
    });
  };
  const editRisk = (id?: string) => {
    const r = project!.risks.find((r) => r.id === id);
    setEditor({
      title: r ? "编辑风险依据" : "新增风险模块",
      fields: [
        { key: "name", label: "风险模块", value: r?.name },
        {
          key: "reason",
          label: "纳入理由 / 待验证问题",
          value: r?.reason,
          multiline: true,
        },
      ],
      save: (v) => {
        const next = {
          id: r?.id || uid(),
          name: v.name,
          reason: v.reason,
          selected: r?.selected ?? true,
        };
        return change({
          risks: r
            ? project!.risks.map((x) => (x.id === id ? next : x))
            : [...project!.risks, next],
        });
      },
    });
  };
  const editPath = (id?: string) => {
    const p = project!.paths.find((p) => p.id === id);
    setEditor({
      title: p ? "编辑候选路径" : "新增候选路径",
      fields: [
        { key: "name", label: "路径名称", value: p?.name },
        {
          key: "riskId",
          label: "所属风险",
          value: p?.riskId,
          options: project!.risks
            .filter((r) => r.selected || r.id === p?.riskId)
            .map((r) => ({ value: r.id, label: r.name })),
        },
        {
          key: "steps",
          label: "测试身份 → 入口 → 权限边界 → 验证目标",
          value: p?.steps,
          multiline: true,
        },
        {
          key: "method",
          label: "关联方法",
          value: p?.method,
          options: methods.map((m) => ({ value: m, label: m })),
        },
        {
          key: "docId",
          label: "资料依据",
          value: p?.docId,
          optional: true,
          options: [
            { value: "", label: "暂未关联" },
            ...project!.docs.map((d) => ({ value: d.id, label: d.name })),
          ],
        },
      ],
      save: (v) => {
        const next: Path = {
          id: p?.id || uid(),
          name: v.name,
          riskId: v.riskId,
          steps: v.steps,
          method: v.method,
          docId: v.docId,
        };
        return change(
          {
            paths: p
              ? project!.paths.map((x) => (x.id === id ? next : x))
              : [...project!.paths, next],
            cases: p
              ? project!.cases.map((c) =>
                  c.pathId === p.id ? { ...c, reviewed: false } : c,
                )
              : project!.cases,
          },
          p
            ? "路径已更新，关联用例需重新审查；批次快照保持不变。"
            : "候选路径已保存",
        );
      },
    });
  };
  const editCase = (c: Case) =>
    setEditor({
      title: "编辑测试用例",
      fields: [
        { key: "name", label: "用例名称", value: c.name },
        {
          key: "steps",
          label: "前置条件与测试步骤",
          value: c.steps,
          multiline: true,
        },
        {
          key: "criterion",
          label: "通过 / 失败 / 证据不足判据",
          value: c.criterion,
          multiline: true,
        },
      ],
      save: (v) =>
        change(
          {
            cases: project!.cases.map((x) =>
              x.id === c.id ? { ...x, ...v, reviewed: false } : x,
            ),
          },
          "用例已保存，需重新审查；已创建批次的快照保持不变。",
        ),
    });
  const addRun = (parent = "") => {
    const old = project!.runs.find((r) => r.id === parent);
    const cases = project!.cases.filter(
      (c) =>
        c.reviewed &&
        (!old || old.caseIds.includes(c.id)) &&
        project!.risks.find(
          (r) => r.id === project!.paths.find((p) => p.id === c.pathId)?.riskId,
        )?.selected,
    );
    if (!cases.length) {
      setNotice("请先审查至少一条纳入本轮范围的相关用例。");
      return;
    }
    const run: Run = {
      id: uid(),
      caseIds: cases.map((c) => c.id),
      snapshot: structuredClone(cases),
      done: false,
      created: new Date().toISOString(),
      parent,
      note: "",
    };
    if (
      change({ runs: [...project!.runs, run] }, "模拟批次已创建，未连接设备。")
    ) {
      go(`/ibmc/${project!.id}/execute`);
      setSelected(run.id);
    }
  };
  const generate = (p: Path) => {
    const c = draftFor(p);
    if (
      change(
        { cases: [...project!.cases, c] },
        "用例草稿已生成，需人工完善与审查。",
      )
    )
      go(`/ibmc/${project!.id}/design`);
  };
  const review = (c: Case) => {
    setChecks([false, false, false, false]);
    setReviewNote("");
    setDrawer({ kind: "review", id: c.id });
  };
  const saveReview = (approved: boolean) => {
    const c = project!.cases.find((c) => c.id === drawer?.id);
    if (!c) return;
    if (!approved && !reviewNote.trim()) {
      setNotice("请填写退回完善的原因。");
      return;
    }
    if (
      change(
        {
          cases: project!.cases.map((x) =>
            x.id === c.id
              ? {
                  ...x,
                  reviewed: approved,
                  reviewNote: reviewNote.trim(),
                  reviewedAt: new Date().toISOString(),
                  reviews: [
                    ...(x.reviews ?? []),
                    {
                      at: new Date().toISOString(),
                      approved,
                      note: reviewNote.trim(),
                    },
                  ],
                }
              : x,
          ),
        },
        approved ? "设计已确认，尚未执行。" : "已退回完善。",
      )
    )
      setDrawer(null);
  };
  const contains = (...s: string[]) =>
    s.join(" ").toLowerCase().includes(query.toLowerCase());
  const paths = project?.paths.filter((p) => contains(p.name, p.method)) || [],
    cases =
      project?.cases.filter(
        (c) =>
          contains(c.name, c.method) &&
          (filter === "all" ||
            (filter === "reviewed" ? c.reviewed : !c.reviewed)),
      ) || [];
  const selectedPath = paths.find((p) => p.id === selected) || paths[0],
    selectedCase = cases.find((c) => c.id === selected) || cases[0];
  const risks = project?.risks.filter((r) => contains(r.name, r.reason)) || [],
    selectedRisk = risks.find((r) => r.id === selected) || risks[0];
  const docs = project?.docs.filter((d) => contains(d.name, d.version)) || [],
    selectedDoc = docs.find((d) => d.id === selected) || docs[0];
  const runs = project
      ? [...project.runs].reverse().filter((r) => page !== "results" || r.done)
      : [],
    selectedRun = runs.find((r) => r.id === selected) || runs[0];
  const batchName = (r: Run) =>
    `SIM-${String(project!.runs.findIndex((x) => x.id === r.id) + 1).padStart(3, "0")}${r.parent ? " · 复测" : ""}`;
  const runDrawer = project?.runs.find((r) => r.id === drawer?.id),
    caseDrawer = project?.cases.find((c) => c.id === drawer?.id);
  const methodsUsed =
    project?.paths.filter((p) =>
      skill === 4
        ? p.method.startsWith("FW-")
        : skill === 3
          ? p.method.startsWith("WEB-")
          : true,
    ) || [];
  return (
    <div className="platform-root">
      <div
        className={`security-shell ${app === "packets" ? "s-packet-mode" : ""}`}
      >
        <header className="s-header">
          <a href="#/" className="s-brand">
            <span className="s-logo">P</span>PANGEA
          </a>
          <select
            aria-label="切换测试应用"
            value={
              app === "ibmc" ? "ibmc" : app === "packets" ? "packets" : "home"
            }
            onChange={(e) =>
              go(e.target.value === "home" ? "/" : `/${e.target.value}`)
            }
          >
            <option value="home">应用首页</option>
            <option value="ibmc">iBMC 安全测试</option>
            <option value="packets">异常报文测试</option>
          </select>
          <span className="s-header-end">
            <Badge>
              {app === "packets" ? "真实设备执行" : "iBMC 交互原型"}
            </Badge>
            <a href="#/">返回平台</a>
          </span>
        </header>
        {storageError && app !== "packets" && (
          <div className="s-storage" role="alert">
            <span>{storageError}</span>
            <button
              onClick={() => {
                try {
                  const raw = localStorage.getItem(DEMO_KEY);
                  if (raw !== persisted.current) {
                    setStorageError("本地记录已改变，请刷新页面读取最新数据。");
                    return;
                  }
                  if (raw && !isDemoStore(JSON.parse(raw))) return;
                  setStorageError("");
                  setNotice("已重新检查，可再次尝试保存。");
                } catch {
                  setNotice("仍无法读取本地记录，请检查浏览器权限。");
                }
              }}
            >
              重新检查存储
            </button>
          </div>
        )}
        {notice && (
          <div className="s-toast" role="status">
            {notice}
            <button aria-label="关闭提示" onClick={() => setNotice("")}>
              ×
            </button>
          </div>
        )}
        {app === "home" && (
          <main className="s-home">
            <div className="s-heading">
              <h1>选择测试应用</h1>
              <p>从安全测试设计到异常报文验证，在同一工作空间继续。</p>
            </div>
            <div className="s-apps">
              {[
                [
                  "risks",
                  "01 / SECURITY",
                  "iBMC 安全测试",
                  "整理产品资料，规划风险路径，设计测试并复核证据。",
                  "产品资料 · 攻击路径 · 测试用例",
                  "本地交互演示",
                  "ibmc",
                ],
                [
                  "intake",
                  "02 / PACKET LAB",
                  "异常报文测试",
                  "构造异常报文，配置监听注入，核对执行结果。",
                  "报文构造 · 监听注入 · 执行记录",
                  "连接现有报文 API",
                  "packets",
                ],
              ].map(([icon, code, name, note, tags, state, target]) => (
                <article className="s-app-card" key={target}>
                  <div className="s-row">
                    <span className="s-app-icon">
                      <Icon name={icon} />
                    </span>
                    <Badge>{state}</Badge>
                  </div>
                  <small>{code}</small>
                  <h2>{name}</h2>
                  <p>{note}</p>
                  <p className="s-muted">{tags}</p>
                  <a
                    className={
                      target === "ibmc" ? "s-primary s-button" : "s-button"
                    }
                    href={`#/${target}`}
                  >
                    进入{target === "ibmc" ? "安全测试" : "异常报文"} →
                  </a>
                </article>
              ))}
            </div>
            <h2 className="s-section-title">继续最近工作</h2>
            <Panel>
              {[...store.projects]
                .sort((a, b) => b.updated.localeCompare(a.updated))
                .slice(0, 4)
                .map((p) => (
                  <a
                    className="s-recent"
                    key={p.id}
                    href={`#/ibmc/${p.id}/overview`}
                  >
                    <strong>
                      {p.name}
                      <small>
                        {p.model} · {p.version}
                      </small>
                    </strong>
                    <Badge tone="teal">{stages[stage(p)]}</Badge>
                    <span>{date(p.updated)}</span>
                    <b>继续 →</b>
                  </a>
                ))}
              {!store.projects.length && (
                <Empty action={<button onClick={newProject}>新建项目</button>}>
                  暂无项目
                </Empty>
              )}
              <a className="s-recent" href="#/packets">
                <strong>
                  继续异常报文工作<small>恢复最近选择的场景</small>
                </strong>
                <span>打开 →</span>
              </a>
            </Panel>
          </main>
        )}
        {app === "ibmc" && (
          <div className="s-workspace">
            <aside className="s-sidebar">
              <a className="s-back" href="#/ibmc">
                ← 全部项目
              </a>
              {project ? (
                <>
                  <div className="s-project">
                    <strong>{project.name}</strong>
                    <small>
                      {project.model} · {project.version}
                    </small>
                  </div>
                  <nav aria-label="项目导航">
                    {pages.slice(0, 7).map(([id, label]) => (
                      <a
                        key={id}
                        href={link(id)}
                        aria-current={page === id ? "page" : undefined}
                      >
                        <Icon name={id} />
                        {label}
                      </a>
                    ))}
                  </nav>
                </>
              ) : (
                <>
                  <div className="s-project">
                    <strong>iBMC 安全测试</strong>
                    <small>项目工作空间</small>
                  </div>
                  <nav>
                    <a href="#/ibmc" aria-current="page">
                      <Icon />
                      全部项目
                    </a>
                  </nav>
                </>
              )}
              <div className="s-sidebar-bottom">
                {project && (
                  <a
                    href={link("skills")}
                    aria-current={page === "skills" ? "page" : undefined}
                  >
                    <Icon name="skills" />
                    方法与 Skills
                  </a>
                )}
                <a href="#/packets">⇄ 切换到异常报文测试 ↗</a>
              </div>
            </aside>
            <main className="s-main">
              <div className="s-breadcrumb">
                <a href="#/ibmc">项目</a> /{" "}
                {project
                  ? `${project.name} / ${title || "页面不存在"}`
                  : "iBMC 安全测试 / 全部项目"}
              </div>
              {!projectId ? (
                <>
                  <div className="s-heading s-row">
                    <div>
                      <h1>全部项目</h1>
                      <p>按产品与版本管理测试范围和工作记录。</p>
                    </div>
                    <button className="s-primary" onClick={newProject}>
                      <Icon name="plus" />
                      新建项目
                    </button>
                  </div>
                  <Panel>
                    <div className="s-toolbar">
                      <Search
                        value={query}
                        onChange={setQuery}
                        placeholder="搜索项目名称、型号或版本"
                      />
                      <span className="s-muted">最近更新优先</span>
                    </div>
                    <div className="s-table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>项目名称</th>
                            <th>产品与版本</th>
                            <th>当前阶段</th>
                            <th>待处理</th>
                            <th>最近更新</th>
                            <th>操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {[...store.projects]
                            .filter((p) => contains(p.name, p.model, p.version))
                            .sort((a, b) => b.updated.localeCompare(a.updated))
                            .map((p) => (
                              <tr key={p.id}>
                                <td>
                                  <a href={`#/ibmc/${p.id}/overview`}>
                                    <strong>{p.name}</strong>
                                  </a>
                                </td>
                                <td>
                                  {p.model}
                                  <small>{p.version}</small>
                                </td>
                                <td>
                                  <Badge tone="teal">{stages[stage(p)]}</Badge>
                                </td>
                                <td>
                                  {p.cases.filter((c) => !c.reviewed).length}{" "}
                                  条用例待审查
                                </td>
                                <td>{date(p.updated)}</td>
                                <td>
                                  <a href={`#/ibmc/${p.id}/overview`}>继续 →</a>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                    {!store.projects.filter((p) =>
                      contains(p.name, p.model, p.version),
                    ).length && (
                      <Empty
                        action={<button onClick={newProject}>新建项目</button>}
                      >
                        {query ? "没有匹配的项目" : "创建你的第一个测试项目"}
                      </Empty>
                    )}
                    <p className="s-muted s-footnote">
                      共 {store.projects.length} 个项目 · 数据保存在当前浏览器
                    </p>
                  </Panel>
                </>
              ) : !project ? (
                <Empty action={<a href="#/ibmc">返回项目列表 →</a>}>
                  项目不存在或本地数据尚未恢复
                </Empty>
              ) : (
                <>
                  <div className="s-heading s-row">
                    <div>
                      <h1>{title || "页面不存在"}</h1>
                      <p>{descriptions[page]}</p>
                    </div>
                    <Badge>本地交互原型</Badge>
                  </div>
                  {page === "overview" && (
                    <>
                      <div className="s-steps">
                        {stages.map((name, i) => (
                          <a
                            href={link(
                              [
                                "intake",
                                "risks",
                                "paths",
                                "execute",
                                "results",
                              ][i],
                            )}
                            className={i <= stage(project) ? "active" : ""}
                            key={name}
                          >
                            <span>{i < stage(project) ? "✓" : i + 1}</span>
                            <strong>{name}</strong>
                            <small>
                              {i < stage(project)
                                ? "已推进"
                                : i === stage(project)
                                  ? "当前阶段"
                                  : "待推进"}
                            </small>
                          </a>
                        ))}
                      </div>
                      <div className="s-next">
                        <div>
                          <small>当前阶段 · {stages[stage(project)]}</small>
                          <h2>
                            {
                              [
                                "先补充产品资料",
                                "确定本轮测试范围",
                                "完善路径与测试用例",
                                "创建或继续模拟批次",
                                "核对证据与复测范围",
                              ][stage(project)]
                            }
                          </h2>
                          <p>
                            {project.goal ||
                              "保留资料、路径与用例之间的依据，逐步完成本轮验证。"}
                          </p>
                        </div>
                        <a
                          className="s-primary s-button"
                          href={link(
                            ["intake", "risks", "paths", "execute", "results"][
                              stage(project)
                            ],
                          )}
                        >
                          继续当前工作 →
                        </a>
                      </div>
                      <div className="s-columns">
                        <div>
                          <Panel
                            title="本轮测试范围"
                            action={<a href={link("risks")}>管理范围 ↗</a>}
                          >
                            <div className="s-table-wrap">
                              <table>
                                <thead>
                                  <tr>
                                    <th>风险模块</th>
                                    <th>候选路径</th>
                                    <th>用例</th>
                                    <th>范围</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {project.risks.map((r) => (
                                    <tr key={r.id}>
                                      <td>{r.name}</td>
                                      <td>
                                        {
                                          project.paths.filter(
                                            (p) => p.riskId === r.id,
                                          ).length
                                        }
                                      </td>
                                      <td>
                                        {
                                          project.cases.filter(
                                            (c) =>
                                              project.paths.find(
                                                (p) => p.id === c.pathId,
                                              )?.riskId === r.id,
                                          ).length
                                        }
                                      </td>
                                      <td>
                                        <Badge
                                          tone={r.selected ? "teal" : "neutral"}
                                        >
                                          {r.selected ? "已纳入" : "暂不纳入"}
                                        </Badge>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                            {!project.risks.length && (
                              <Empty
                                action={
                                  <a href={link("risks")}>规划风险范围 →</a>
                                }
                              >
                                尚未规划风险模块
                              </Empty>
                            )}
                          </Panel>
                          <Panel title="最近批次">
                            {project.runs
                              .slice(-3)
                              .reverse()
                              .map((r) => (
                                <a
                                  key={r.id}
                                  className="s-recent"
                                  href={link(r.done ? "results" : "execute")}
                                >
                                  <strong>
                                    {batchName(r)}
                                    <small>{date(r.created)}</small>
                                  </strong>
                                  <Badge>
                                    {r.done ? "模拟结束" : "等待模拟"}
                                  </Badge>
                                </a>
                              ))}
                            {!project.runs.length && (
                              <p className="s-muted">
                                尚未创建模拟批次。完成用例审查后即可创建。
                              </p>
                            )}
                          </Panel>
                        </div>
                        <div>
                          <Panel title="待处理">
                            {[
                              [
                                "intake",
                                "补充资料依据",
                                project.docs.filter((d) => !d.parsed).length,
                              ],
                              [
                                "paths",
                                "规划候选路径",
                                project.risks.filter(
                                  (r) =>
                                    r.selected &&
                                    !project.paths.some(
                                      (p) => p.riskId === r.id,
                                    ),
                                ).length,
                              ],
                              [
                                "design",
                                "审查测试用例",
                                project.cases.filter((c) => !c.reviewed).length,
                              ],
                            ].map(([id, name, n]) => (
                              <a
                                key={id}
                                className="s-task"
                                href={link(String(id))}
                              >
                                <Icon name={String(id)} />
                                <strong>{name}</strong>
                                <Badge tone={n ? "amber" : "neutral"}>
                                  {n}
                                </Badge>
                                <span>→</span>
                              </a>
                            ))}
                          </Panel>
                          <Panel title="资料与方法">
                            <div className="s-stat-pair">
                              <a href={link("intake")}>
                                产品资料
                                <strong>
                                  {project.docs.length} <small>份</small>
                                </strong>
                              </a>
                              <a href={link("skills")}>
                                内置方法
                                <strong>
                                  6 <small>项</small>
                                </strong>
                              </a>
                            </div>
                            <p className="s-muted">
                              当前不调用 AI，模拟执行不连接设备。
                            </p>
                          </Panel>
                        </div>
                      </div>
                    </>
                  )}
                  {page === "intake" && (
                    <div className="s-columns">
                      <Panel
                        title="资料清单"
                        action={
                          <button
                            className="s-primary"
                            onClick={() => editDoc()}
                          >
                            ＋ 添加资料
                          </button>
                        }
                      >
                        <Search
                          value={query}
                          onChange={setQuery}
                          placeholder="搜索资料名称或版本"
                        />
                        <div className="s-table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>资料名称</th>
                                <th>适用版本</th>
                                <th>记录状态</th>
                                <th>操作</th>
                              </tr>
                            </thead>
                            <tbody>
                              {docs.map((d) => (
                                <tr
                                  key={d.id}
                                  className={
                                    selectedDoc?.id === d.id ? "selected" : ""
                                  }
                                >
                                  <td>
                                    <button
                                      className="s-link"
                                      onClick={() => setSelected(d.id)}
                                    >
                                      {d.name}
                                    </button>
                                  </td>
                                  <td>{d.version}</td>
                                  <td>
                                    <Badge tone={d.parsed ? "teal" : "amber"}>
                                      {d.parsed ? "已记录" : "待补充"}
                                    </Badge>
                                  </td>
                                  <td>
                                    <button
                                      className="s-link"
                                      onClick={() => editDoc(d.id)}
                                    >
                                      编辑
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {selectedDoc ? (
                          <div className="s-detail-inline">
                            <h2>{selectedDoc.name}</h2>
                            <p className="s-muted">
                              版本：{selectedDoc.version} · 来源：
                              {selectedDoc.source || "人工记录"}
                            </p>
                            <h3>关键内容与待确认事项</h3>
                            <p className="s-pre">{selectedDoc.note}</p>
                          </div>
                        ) : (
                          <Empty>暂无匹配的资料记录</Empty>
                        )}
                      </Panel>
                      <div>
                        <Panel title="产品概况">
                          <dl>
                            <dt>产品型号</dt>
                            <dd>{project.model}</dd>
                            <dt>固件版本</dt>
                            <dd>{project.version}</dd>
                            <dt>测试目标</dt>
                            <dd>{project.goal || "尚未填写"}</dd>
                          </dl>
                          <button
                            onClick={() =>
                              setEditor({
                                title: "编辑产品信息",
                                fields: [
                                  {
                                    key: "model",
                                    label: "产品型号",
                                    value: project.model,
                                  },
                                  {
                                    key: "version",
                                    label: "固件版本",
                                    value: project.version,
                                  },
                                  {
                                    key: "goal",
                                    label: "测试目标",
                                    value: project.goal,
                                    multiline: true,
                                    optional: true,
                                  },
                                ],
                                save: (v) => change(v),
                              })
                            }
                          >
                            编辑产品信息
                          </button>
                        </Panel>
                        <Panel title="下一步">
                          <p>基于收集的产品信息，明确本轮风险与测试范围。</p>
                          <a className="s-button" href={link("risks")}>
                            查看风险与范围 →
                          </a>
                        </Panel>
                        <p className="s-muted">
                          <Icon name="info" /> 资料由人工记录，不自动解析文件。
                        </p>
                      </div>
                    </div>
                  )}
                  {page === "risks" && (
                    <>
                      <div className="s-toolbar">
                        <Search
                          value={query}
                          onChange={setQuery}
                          placeholder="搜索风险模块或依据"
                        />
                        <span>
                          已纳入{" "}
                          {project.risks.filter((r) => r.selected).length} 项
                        </span>
                        <button
                          className="s-primary"
                          onClick={() => editRisk()}
                        >
                          ＋ 新增风险
                        </button>
                      </div>
                      <div className="s-columns">
                        <Panel>
                          <div className="s-table-wrap">
                            <table>
                              <thead>
                                <tr>
                                  <th>纳入</th>
                                  <th>风险模块</th>
                                  <th>关联路径</th>
                                  <th>范围</th>
                                </tr>
                              </thead>
                              <tbody>
                                {risks.map((r) => (
                                  <tr
                                    key={r.id}
                                    className={
                                      selectedRisk?.id === r.id
                                        ? "selected"
                                        : ""
                                    }
                                  >
                                    <td>
                                      <input
                                        type="checkbox"
                                        aria-label={`纳入 ${r.name}`}
                                        checked={r.selected}
                                        onChange={() =>
                                          change(
                                            {
                                              risks: project.risks.map((x) =>
                                                x.id === r.id
                                                  ? {
                                                      ...x,
                                                      selected: !x.selected,
                                                    }
                                                  : x,
                                              ),
                                              cases: project.cases.map((c) =>
                                                project.paths.find(
                                                  (p) => p.id === c.pathId,
                                                )?.riskId === r.id
                                                  ? { ...c, reviewed: false }
                                                  : c,
                                              ),
                                            },
                                            "测试范围已更新，关联用例需重新审查。",
                                          )
                                        }
                                      />
                                    </td>
                                    <td>
                                      <button
                                        className="s-link"
                                        onClick={() => setSelected(r.id)}
                                      >
                                        {r.name}
                                      </button>
                                    </td>
                                    <td>
                                      {
                                        project.paths.filter(
                                          (p) => p.riskId === r.id,
                                        ).length
                                      }
                                    </td>
                                    <td>
                                      <Badge
                                        tone={r.selected ? "teal" : "neutral"}
                                      >
                                        {r.selected ? "已纳入" : "暂不纳入"}
                                      </Badge>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {!risks.length && <Empty>还没有匹配的风险模块</Empty>}
                        </Panel>
                        <Panel title={selectedRisk?.name || "风险依据"}>
                          {selectedRisk ? (
                            <>
                              <Badge
                                tone={
                                  selectedRisk.selected ? "teal" : "neutral"
                                }
                              >
                                {selectedRisk.selected ? "已纳入" : "暂不纳入"}
                              </Badge>
                              <h3>风险依据 / 待验证问题</h3>
                              <p className="s-pre">{selectedRisk.reason}</p>
                              <button onClick={() => editRisk(selectedRisk.id)}>
                                编辑依据
                              </button>
                              <hr />
                              <a href={link("paths")}>查看候选路径 →</a>
                              <p className="s-muted">
                                范围调整后，关联路径与用例需重新核对。
                              </p>
                            </>
                          ) : (
                            <p>选择一个风险模块查看依据。</p>
                          )}
                        </Panel>
                      </div>
                    </>
                  )}
                  {page === "paths" && (
                    <>
                      <div className="s-toolbar">
                        <span>
                          {project.paths.length} 条候选路径 · 尚未验证
                        </span>
                        <button
                          className="s-primary"
                          disabled={!project.risks.some((r) => r.selected)}
                          onClick={() => editPath()}
                        >
                          ＋ 新增路径
                        </button>
                      </div>
                      {!project.risks.some((r) => r.selected) && (
                        <p className="s-warning">
                          请先在<a href={link("risks")}>风险与范围</a>
                          中纳入至少一个模块。
                        </p>
                      )}
                      <div className="s-master">
                        <Panel>
                          <Search
                            value={query}
                            onChange={setQuery}
                            placeholder="搜索路径或方法"
                          />
                          {paths.map((p) => (
                            <button
                              className={`s-list-item ${selectedPath?.id === p.id ? "active" : ""}`}
                              key={p.id}
                              onClick={() => {
                                setSelected(p.id);
                                setTab("content");
                              }}
                            >
                              <strong>{p.name}</strong>
                              <small>
                                {
                                  project.risks.find((r) => r.id === p.riskId)
                                    ?.name
                                }
                              </small>
                              <Badge>候选 · 未验证</Badge>
                            </button>
                          ))}
                          {!paths.length && <Empty>暂无匹配的候选路径</Empty>}
                        </Panel>
                        <Panel>
                          {selectedPath ? (
                            <>
                              <div className="s-row">
                                <h2>{selectedPath.name}</h2>
                                <Badge tone="amber">候选 · 未验证</Badge>
                              </div>
                              <p className="s-muted">
                                所属风险：
                                {
                                  project.risks.find(
                                    (r) => r.id === selectedPath.riskId,
                                  )?.name
                                }
                              </p>
                              <div className="s-tabs">
                                {[
                                  ["content", "路径设计"],
                                  ["source", "资料依据"],
                                  [
                                    "cases",
                                    `关联用例 ${project.cases.filter((c) => c.pathId === selectedPath.id).length}`,
                                  ],
                                ].map(([id, name]) => (
                                  <button
                                    key={id}
                                    aria-pressed={tab === id}
                                    onClick={() => setTab(id)}
                                  >
                                    {name}
                                  </button>
                                ))}
                              </div>
                              {tab === "content" ? (
                                <>
                                  <h3>测试身份 → 入口 → 权限边界 → 目标资源</h3>
                                  <div className="s-read-field s-pre">
                                    {selectedPath.steps}
                                  </div>
                                  <h3>关联方法</h3>
                                  <a href={link("skills")}>
                                    {selectedPath.method} ↗
                                  </a>
                                  {!project.risks.find(
                                    (r) => r.id === selectedPath.riskId,
                                  )?.selected && (
                                    <p className="s-warning">
                                      所属风险未纳入本轮范围，暂不能生成用例。
                                    </p>
                                  )}
                                </>
                              ) : tab === "source" ? (
                                <>
                                  <h3>资料依据</h3>
                                  <p>
                                    {project.docs.find(
                                      (d) => d.id === selectedPath.docId,
                                    )?.name ||
                                      "尚未关联资料，请编辑路径补充依据。"}
                                  </p>
                                  <p className="s-pre">
                                    {
                                      project.docs.find(
                                        (d) => d.id === selectedPath.docId,
                                      )?.note
                                    }
                                  </p>
                                  <a href={link("intake")}>查看产品资料 →</a>
                                </>
                              ) : (
                                <>
                                  {project.cases
                                    .filter((c) => c.pathId === selectedPath.id)
                                    .map((c) => (
                                      <a
                                        className="s-recent"
                                        key={c.id}
                                        href={link("design")}
                                      >
                                        {c.name}
                                        <Badge>
                                          {c.reviewed ? "已审查" : "待审查"}
                                        </Badge>
                                      </a>
                                    ))}
                                  {!project.cases.some(
                                    (c) => c.pathId === selectedPath.id,
                                  ) && <Empty>暂无关联用例</Empty>}
                                </>
                              )}
                              <footer className="s-detail-footer">
                                <small>候选路径不代表已确认漏洞</small>
                                <button
                                  onClick={() => editPath(selectedPath.id)}
                                >
                                  编辑路径
                                </button>
                                <button
                                  className="s-primary"
                                  disabled={
                                    !project.risks.find(
                                      (r) => r.id === selectedPath.riskId,
                                    )?.selected ||
                                    project.cases.some(
                                      (c) => c.pathId === selectedPath.id,
                                    )
                                  }
                                  onClick={() => generate(selectedPath)}
                                >
                                  {project.cases.some(
                                    (c) => c.pathId === selectedPath.id,
                                  )
                                    ? "已有关联用例"
                                    : "生成用例草稿 →"}
                                </button>
                              </footer>
                            </>
                          ) : (
                            <Empty>选择或创建一条候选路径</Empty>
                          )}
                        </Panel>
                      </div>
                    </>
                  )}
                  {page === "design" && (
                    <>
                      <div className="s-toolbar">
                        <span>{project.cases.length} 条测试用例</span>
                        <a className="s-button" href={link("paths")}>
                          从路径生成 →
                        </a>
                      </div>
                      <div className="s-master">
                        <Panel>
                          <Search
                            value={query}
                            onChange={setQuery}
                            placeholder="搜索测试用例"
                          />
                          <div className="s-tabs">
                            {[
                              ["all", "全部"],
                              ["pending", "待审查"],
                              ["reviewed", "已审查"],
                            ].map(([id, label]) => (
                              <button
                                aria-pressed={filter === id}
                                key={id}
                                onClick={() => setFilter(id)}
                              >
                                {label}
                              </button>
                            ))}
                          </div>
                          {cases.map((c) => (
                            <button
                              className={`s-list-item ${selectedCase?.id === c.id ? "active" : ""}`}
                              key={c.id}
                              onClick={() => {
                                setSelected(c.id);
                                setTab("content");
                              }}
                            >
                              <strong>{c.name}</strong>
                              <small>{c.method}</small>
                              <Badge tone={c.reviewed ? "teal" : "amber"}>
                                {c.reviewed ? "已审查" : "待审查"}
                              </Badge>
                            </button>
                          ))}
                          {!cases.length && <Empty>暂无匹配用例</Empty>}
                        </Panel>
                        <Panel>
                          {selectedCase ? (
                            <>
                              <div className="s-row">
                                <h2>{selectedCase.name}</h2>
                                <Badge
                                  tone={
                                    selectedCase.reviewed ? "teal" : "amber"
                                  }
                                >
                                  {selectedCase.reviewed ? "已审查" : "待审查"}
                                </Badge>
                              </div>
                              <p>
                                来源路径：
                                <a href={link("paths")}>
                                  {project.paths.find(
                                    (p) => p.id === selectedCase.pathId,
                                  )?.name || "原路径不可用"}
                                </a>
                              </p>
                              <div className="s-tabs">
                                {[
                                  ["content", "用例内容"],
                                  ["review", "审查记录"],
                                ].map(([id, label]) => (
                                  <button
                                    key={id}
                                    aria-pressed={tab === id}
                                    onClick={() => setTab(id)}
                                  >
                                    {label}
                                  </button>
                                ))}
                              </div>
                              {tab === "content" ? (
                                <>
                                  <h3>前置条件与测试步骤</h3>
                                  <div className="s-read-field s-pre">
                                    {selectedCase.steps}
                                  </div>
                                  <h3>预期结果与证据判据</h3>
                                  <div className="s-read-field s-pre">
                                    {selectedCase.criterion}
                                  </div>
                                </>
                              ) : (
                                <>
                                  <h3>审查记录</h3>
                                  {selectedCase.reviews?.length ? (
                                    <ol className="s-review-history">
                                      {[...selectedCase.reviews]
                                        .reverse()
                                        .map((r, i) => (
                                          <li key={`${r.at}-${i}`}>
                                            <div className="s-row">
                                              <Badge
                                                tone={
                                                  r.approved ? "green" : "amber"
                                                }
                                              >
                                                {r.approved
                                                  ? "设计已确认"
                                                  : "退回完善"}
                                              </Badge>
                                              <time>{date(r.at)}</time>
                                            </div>
                                            <p className="s-pre">
                                              {r.note ||
                                                (r.approved
                                                  ? "已完成设计检查项"
                                                  : "未填写意见")}
                                            </p>
                                          </li>
                                        ))}
                                    </ol>
                                  ) : (
                                    <>
                                      <h3>最近审查意见</h3>
                                      <p className="s-pre">
                                        {selectedCase.reviewNote ||
                                          "暂无审查意见"}
                                      </p>
                                      <p className="s-muted">
                                        {selectedCase.reviewedAt
                                          ? date(selectedCase.reviewedAt)
                                          : "尚未记录审查时间"}
                                      </p>
                                    </>
                                  )}
                                </>
                              )}
                              <footer className="s-detail-footer">
                                <small>设计审查不代表实际执行</small>
                                <button onClick={() => editCase(selectedCase)}>
                                  编辑用例
                                </button>
                                <button
                                  className="s-primary"
                                  onClick={() => review(selectedCase)}
                                >
                                  审查用例 →
                                </button>
                              </footer>
                            </>
                          ) : (
                            <Empty
                              action={
                                <a href={link("paths")}>从候选路径生成 →</a>
                              }
                            >
                              选择或生成第一条用例
                            </Empty>
                          )}
                        </Panel>
                      </div>
                    </>
                  )}
                  {(page === "execute" || page === "results") && (
                    <>
                      <div className="s-toolbar">
                        <p className="s-info">
                          <Icon name="info" /> 模拟模式 ·
                          不连接设备，不产生实测结论
                        </p>
                        {page === "execute" && (
                          <button
                            className="s-primary"
                            disabled={!project.cases.some((c) => c.reviewed)}
                            onClick={() => addRun()}
                          >
                            ＋ 创建模拟批次
                          </button>
                        )}
                      </div>
                      <div className="s-columns">
                        <div>
                          <Panel
                            title={page === "execute" ? "执行批次" : "结果记录"}
                          >
                            <div className="s-table-wrap">
                              <table>
                                <thead>
                                  <tr>
                                    <th>批次</th>
                                    <th>用例</th>
                                    <th>状态</th>
                                    <th>创建时间</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {runs.map((r) => (
                                    <tr
                                      key={r.id}
                                      className={
                                        selectedRun?.id === r.id
                                          ? "selected"
                                          : ""
                                      }
                                    >
                                      <td>
                                        <button
                                          className="s-link"
                                          onClick={() => setSelected(r.id)}
                                        >
                                          {batchName(r)}
                                        </button>
                                      </td>
                                      <td>{r.snapshot.length} 条</td>
                                      <td>
                                        <Badge
                                          tone={r.done ? "neutral" : "amber"}
                                        >
                                          {page === "results"
                                            ? "待真实验证"
                                            : r.done
                                              ? "模拟结束"
                                              : "等待模拟"}
                                        </Badge>
                                      </td>
                                      <td>{date(r.created)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                            {!runs.length && (
                              <Empty
                                action={
                                  <a
                                    href={link(
                                      page === "execute" ? "design" : "execute",
                                    )}
                                  >
                                    前往
                                    {page === "execute"
                                      ? "用例审查"
                                      : "执行批次"}{" "}
                                    →
                                  </a>
                                }
                              >
                                {page === "execute"
                                  ? "尚未创建批次"
                                  : "暂无已结束的模拟记录"}
                              </Empty>
                            )}
                          </Panel>
                          {selectedRun && (
                            <Panel title={batchName(selectedRun)}>
                              <h3>
                                {page === "execute"
                                  ? "冻结用例快照"
                                  : "当前结论"}
                              </h3>
                              {page === "execute" ? (
                                selectedRun.snapshot.map((c) => (
                                  <div key={c.id} className="s-recent">
                                    <strong>{c.name}</strong>
                                    <Badge>已冻结</Badge>
                                  </div>
                                ))
                              ) : (
                                <>
                                  <Badge tone="amber">待真实验证</Badge>
                                  <p>已有记录：本地模拟状态与人工线索。</p>
                                  <h3>仍缺实测证据</h3>
                                  <ul className="s-evidence-list">
                                    <li>设备响应</li>
                                    <li>操作前后状态</li>
                                    <li>对应审计日志</li>
                                  </ul>
                                  <p>恢复情况：未执行设备操作。</p>
                                </>
                              )}
                              <footer className="s-detail-footer">
                                <button
                                  onClick={() =>
                                    setDrawer({
                                      kind:
                                        page === "execute"
                                          ? "snapshot"
                                          : "evidence",
                                      id: selectedRun.id,
                                    })
                                  }
                                >
                                  {page === "execute"
                                    ? "查看冻结快照"
                                    : "查看证据详情"}
                                </button>
                                {page === "execute" ? (
                                  <button
                                    className="s-primary"
                                    disabled={selectedRun.done}
                                    onClick={() =>
                                      change(
                                        {
                                          runs: project.runs.map((r) =>
                                            r.id === selectedRun.id
                                              ? { ...r, done: true }
                                              : r,
                                          ),
                                        },
                                        "模拟结束，没有向设备发送请求。",
                                      )
                                    }
                                  >
                                    {selectedRun.done
                                      ? "模拟已结束"
                                      : "完成模拟"}
                                  </button>
                                ) : (
                                  <button
                                    className="s-primary"
                                    onClick={() => addRun(selectedRun.id)}
                                  >
                                    创建模拟复测 →
                                  </button>
                                )}
                              </footer>
                            </Panel>
                          )}
                        </div>
                        <div>
                          <Panel title="批次信息">
                            {selectedRun ? (
                              <dl>
                                <dt>创建时间</dt>
                                <dd>{date(selectedRun.created)}</dd>
                                <dt>执行模式</dt>
                                <dd>本地模拟</dd>
                                <dt>真实执行</dt>
                                <dd>未进行</dd>
                              </dl>
                            ) : (
                              <p className="s-muted">选择批次查看详情</p>
                            )}
                          </Panel>
                          {selectedRun && (
                            <Panel title="探索线索">
                              <p className="s-pre">
                                {selectedRun.note || "尚未记录线索"}
                              </p>
                              <button
                                onClick={() =>
                                  setEditor({
                                    title: "记录探索线索",
                                    fields: [
                                      {
                                        key: "note",
                                        label: "线索 / 证据缺口",
                                        value: selectedRun.note,
                                        multiline: true,
                                        optional: true,
                                      },
                                    ],
                                    save: (v) =>
                                      change({
                                        runs: project.runs.map((r) =>
                                          r.id === selectedRun.id
                                            ? { ...r, note: v.note }
                                            : r,
                                        ),
                                      }),
                                  })
                                }
                              >
                                编辑线索
                              </button>
                              <p className="s-muted">线索尚未确认为漏洞。</p>
                            </Panel>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                  {page === "skills" && (
                    <>
                      <div className="s-toolbar">
                        <Badge>内置方法包 0.1.0 · 只读</Badge>
                        <span className="s-muted">尚未接入 AI 调用</span>
                      </div>
                      <div className="s-skills">
                        <Panel>
                          {skillNames.map((name, i) => (
                            <button
                              key={name}
                              className={`s-list-item ${skill === i ? "active" : ""}`}
                              onClick={() => setSkill(i)}
                            >
                              <Icon
                                name={
                                  [
                                    "intake",
                                    "paths",
                                    "risks",
                                    "design",
                                    "design",
                                    "results",
                                  ][i]
                                }
                              />
                              <strong>{name}</strong>
                            </button>
                          ))}
                        </Panel>
                        <Panel title={skillNames[skill]}>
                          <p className="s-muted">{skillIds[skill]}</p>
                          <div className="s-tabs">
                            <button
                              aria-pressed={tab !== "raw"}
                              onClick={() => setTab("content")}
                            >
                              方法说明
                            </button>
                            <button
                              aria-pressed={tab === "raw"}
                              onClick={() => setTab("raw")}
                            >
                              原始内容
                            </button>
                          </div>
                          {tab === "raw" ? (
                            <pre className="s-skill-text s-pre">
                              {
                                skillFiles[
                                  `../skills/ibmc/${skillIds[skill]}/SKILL.md`
                                ]
                              }
                            </pre>
                          ) : (
                            <div className="s-skill-text">
                              {skillFiles[
                                `../skills/ibmc/${skillIds[skill]}/SKILL.md`
                              ]
                                ?.replace(/^---[\s\S]*?---\s*/, "")
                                .split("\n")
                                .map((line, i) =>
                                  line.startsWith("# ") ? (
                                    <h2 key={i}>{line.slice(2)}</h2>
                                  ) : line.startsWith("## ") ? (
                                    <h3 key={i}>{line.slice(3)}</h3>
                                  ) : (
                                    <p key={i}>{line}</p>
                                  ),
                                )}
                            </div>
                          )}
                        </Panel>
                        <Panel title="项目中的使用">
                          <p>项目候选路径：{methodsUsed.length} 条</p>
                          {methodsUsed.map((p) => (
                            <a
                              className="s-recent"
                              href={link("paths")}
                              key={p.id}
                            >
                              {p.name} →
                            </a>
                          ))}
                          <a
                            className="s-button s-primary"
                            href={link("paths")}
                          >
                            前往路径规划 →
                          </a>
                        </Panel>
                      </div>
                    </>
                  )}
                  {!title && (
                    <Empty action={<a href={link("overview")}>返回工作台 →</a>}>
                      页面不存在
                    </Empty>
                  )}
                </>
              )}
            </main>
          </div>
        )}
        {!["home", "ibmc", "packets"].includes(app) && (
          <main className="s-home">
            <Empty action={<a href="#/">返回平台 →</a>}>页面不存在</Empty>
          </main>
        )}
        {editor && <EditDialog editor={editor} close={() => setEditor(null)} />}
        {drawer && project && (
          <Modal
            drawer
            title={
              drawer.kind === "review"
                ? "审查测试用例"
                : drawer.kind === "evidence"
                  ? "证据详情"
                  : "冻结用例快照"
            }
            close={() => setDrawer(null)}
          >
            {drawer.kind === "review" && caseDrawer ? (
              <>
                <p>{caseDrawer.name}</p>
                <p className="s-info">
                  审查确认设计完整性，不代表设备执行授权。
                </p>
                <h3>审查要点</h3>
                <div className="s-review-checks">
                  {[
                    "来源路径与资料依据明确",
                    "前置条件与操作步骤可执行",
                    "通过、失败与证据不足判据清楚",
                    "接口清单与权限说明已核对",
                  ].map((t, i) => (
                    <label key={t}>
                      <input
                        type="checkbox"
                        checked={checks[i]}
                        onChange={(e) =>
                          setChecks(
                            checks.map((x, j) =>
                              j === i ? e.target.checked : x,
                            ),
                          )
                        }
                      />
                      {t}
                    </label>
                  ))}
                </div>
                {!checks.every(Boolean) && (
                  <p className="s-warning">
                    仍有 {checks.filter((x) => !x).length}{" "}
                    项待核对，确认全部要点后可通过审查。
                  </p>
                )}
                <h3>测试步骤</h3>
                <p className="s-pre">{caseDrawer.steps}</p>
                <h3>判据</h3>
                <p className="s-pre">{caseDrawer.criterion}</p>
                <label className="s-form-label">
                  审查意见
                  <textarea
                    rows={4}
                    value={reviewNote}
                    onChange={(e) => setReviewNote(e.target.value)}
                    placeholder="退回完善时请填写具体原因…"
                  />
                </label>
                <footer className="s-modal-footer">
                  <button
                    onClick={() => saveReview(false)}
                    disabled={!reviewNote.trim()}
                  >
                    退回完善
                  </button>
                  <button
                    className="s-primary"
                    disabled={!checks.every(Boolean)}
                    onClick={() => saveReview(true)}
                  >
                    确认设计
                  </button>
                </footer>
              </>
            ) : runDrawer ? (
              <>
                <p>
                  {batchName(runDrawer)} · {date(runDrawer.created)}
                </p>
                {drawer.kind === "evidence" ? (
                  <>
                    <Badge tone="amber">待真实验证</Badge>
                    <h3>已保存记录</h3>
                    <div className="s-read-field">
                      本地模拟状态：{runDrawer.done ? "模拟结束" : "等待模拟"}
                    </div>
                    <h3>待补充的实测证据</h3>
                    <div className="s-table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>证据项</th>
                            <th>用途</th>
                            <th>状态</th>
                          </tr>
                        </thead>
                        <tbody>
                          {[
                            ["设备响应", "核对访问结果"],
                            ["操作前后状态", "核对状态变化"],
                            ["审计日志", "核对身份与操作记录"],
                          ].map(([a, b]) => (
                            <tr key={a}>
                              <td>{a}</td>
                              <td>{b}</td>
                              <td>
                                <Badge tone="amber">缺失</Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className="s-warning">
                      当前证据不足，无法判定通过、失败或确认漏洞。
                    </p>
                    <h3>探索线索</h3>
                    <p className="s-pre">{runDrawer.note || "尚未记录"}</p>
                    <h3>恢复记录</h3>
                    <p>未执行设备操作。</p>
                    <button
                      onClick={() =>
                        setDrawer({ kind: "snapshot", id: runDrawer.id })
                      }
                    >
                      查看用例快照
                    </button>
                  </>
                ) : (
                  runDrawer.snapshot.map((c) => (
                    <section className="s-snapshot" key={c.id}>
                      <h3>{c.name}</h3>
                      <p className="s-pre">{c.steps}</p>
                      <h4>预期判据</h4>
                      <p className="s-pre">{c.criterion}</p>
                    </section>
                  ))
                )}
                <footer className="s-modal-footer">
                  <button onClick={() => setDrawer(null)}>返回</button>
                  {runDrawer.done && (
                    <button
                      className="s-primary"
                      onClick={() => {
                        setDrawer(null);
                        addRun(runDrawer.id);
                      }}
                    >
                      创建模拟复测 →
                    </button>
                  )}
                </footer>
              </>
            ) : (
              <Empty>记录不存在</Empty>
            )}
          </Modal>
        )}
      </div>
      {packetMounted && (
        <div hidden={app !== "packets"} className="s-packet-container">
          <PacketApp />
        </div>
      )}
    </div>
  );
}
