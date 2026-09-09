import { useEffect, useRef, useState } from "react";
import type { ReactNode, FormEvent } from "react";
import PacketApp from "./App";
import {
  DEMO_KEY,
  draftFor,
  isDemoStore,
  methods,
  seedStore,
  uid,
} from "./platform-model";
import type { DemoStore, Project, Run } from "./platform-model";
import "./platform.css";

const pages = [
  ["overview", "项目概览"],
  ["intake", "信息收集"],
  ["risks", "风险模块"],
  ["paths", "攻击路径"],
  ["design", "测试设计"],
  ["execute", "执行与挖掘"],
  ["results", "结果与复测"],
  ["skills", "方法与 Skills"],
] as const;
type Field = {
  key: string;
  label: string;
  value?: string;
  options?: { value: string; label: string }[];
  multiline?: boolean;
};
type Editor = {
  title: string;
  fields: Field[];
  save: (values: Record<string, string>) => void;
};
const skillFiles = import.meta.glob("../skills/ibmc/ibmc-*/SKILL.md", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;
const skillNames = [
  "产品信息收集",
  "侦察与攻击面识别",
  "风险与攻击路径规划",
  "Web/API 测试设计",
  "固件安全测试设计",
  "证据分析与复测",
];
const skillIds = [
  "ibmc-product-intake",
  "ibmc-attack-surface",
  "ibmc-risk-paths",
  "ibmc-web-test-design",
  "ibmc-firmware-test-design",
  "ibmc-evidence-review",
];
const hash = () => window.location.hash.slice(1) || "/";
const go = (path: string) => {
  window.location.hash = path;
};

export default function Platform() {
  const [route, setRoute] = useState(hash);
  const [packetMounted, setPacketMounted] = useState(
    hash().startsWith("/packets"),
  );
  const [store, setStore] = useState<DemoStore>(() => {
    try {
      const raw = localStorage.getItem(DEMO_KEY);
      if (!raw) return seedStore();
      const parsed: unknown = JSON.parse(raw);
      return isDemoStore(parsed) ? parsed : { version: 1, projects: [] };
    } catch {
      return { version: 1, projects: [] };
    }
  });
  const [storageError, setStorageError] = useState(() => {
    try {
      const raw = localStorage.getItem(DEMO_KEY);
      return raw && !isDemoStore(JSON.parse(raw))
        ? "本地演示数据格式不兼容，已保留原数据；当前仅可查看。"
        : "";
    } catch {
      return "本地演示数据不可读取，已保留原数据；当前仅可查看。";
    }
  });
  const [notice, setNotice] = useState("");
  const [editor, setEditor] = useState<Editor | null>(null);
  const [skill, setSkill] = useState(0);
  const [query, setQuery] = useState("");
  useEffect(() => {
    const change = () => {
      setRoute(hash());
      setEditor(null);
      setNotice("");
      setQuery("");
      if (hash().startsWith("/packets")) setPacketMounted(true);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  const segments = route.split("/").filter(Boolean);
  const app = segments[0] || "home";
  const project = store.projects.find((p) => p.id === segments[1]);
  const page = segments[2] || "overview";
  const pageIndex = pages.findIndex((p) => p[0] === page);
  const title = pages[pageIndex]?.[1] || "页面不存在";
  useEffect(() => {
    document.title =
      app === "packets"
        ? "异常报文测试 · PANGEA"
        : app === "ibmc"
          ? `${project ? title : "iBMC 安全测试"} · PANGEA`
          : "测试平台 · PANGEA";
  }, [app, project?.id, title]);
  const link = (section: string) => `/ibmc/${project!.id}/${section}`;
  const commit = (next: DemoStore, message: string) => {
    if (storageError) {
      setNotice("未保存：请先处理本地存储问题。");
      return;
    }
    try {
      localStorage.setItem(DEMO_KEY, JSON.stringify(next));
      setStore(next);
      setNotice(message);
    } catch {
      setStorageError(
        "本地保存失败，未覆盖现有记录。请检查浏览器存储空间或权限后刷新重试。",
      );
    }
  };
  const changeProject = (patch: Partial<Project>, message: string) => {
    if (!project) return;
    commit(
      {
        ...store,
        projects: store.projects.map((p) =>
          p.id === project.id
            ? { ...p, ...patch, updated: new Date().toISOString() }
            : p,
        ),
      },
      message,
    );
  };
  const newProject = () =>
    setEditor({
      title: "创建安全测试项目",
      fields: [
        { key: "name", label: "项目名称" },
        { key: "model", label: "产品型号 / 样机" },
        { key: "version", label: "固件版本" },
      ],
      save: (v) => {
        const id = uid();
        const p: Project = {
          id,
          ...v,
          name: v.name,
          model: v.model,
          version: v.version,
          updated: new Date().toISOString(),
          docs: [],
          risks: [],
          paths: [],
          cases: [],
          runs: [],
        };
        commit(
          { ...store, projects: [...store.projects, p] },
          "项目已保存到本机",
        );
      },
    });
  const editRisk = (id?: string) => {
    const r = project?.risks.find((x) => x.id === id);
    setEditor({
      title: r ? "编辑风险模块" : "新增风险模块",
      fields: [
        { key: "name", label: "模块名称", value: r?.name },
        {
          key: "reason",
          label: "风险依据 / 待验证问题",
          value: r?.reason,
          multiline: true,
        },
      ],
      save: (v) => {
        const next = {
          id: r?.id || uid(),
          name: v.name,
          reason: v.reason,
          selected: r?.selected ?? false,
        };
        changeProject(
          {
            risks: r
              ? project!.risks.map((x) => (x.id === r.id ? next : x))
              : [...project!.risks, next],
          },
          "风险模块已保存",
        );
      },
    });
  };
  const editPath = (id?: string) => {
    const p = project?.paths.find((x) => x.id === id);
    setEditor({
      title: p ? "编辑候选攻击路径" : "规划候选攻击路径",
      fields: [
        { key: "name", label: "路径名称", value: p?.name },
        {
          key: "riskId",
          label: "风险模块",
          value: p?.riskId,
          options: project!.risks
            .filter((r) => r.selected || r.id === p?.riskId)
            .map((r) => ({ value: r.id, label: r.name })),
        },
        {
          key: "steps",
          label: "起始身份 → 入口 → 权限边界 → 目标资源",
          value: p?.steps,
          multiline: true,
        },
        {
          key: "method",
          label: "关联方法",
          value: p?.method,
          options: methods.map((m) => ({ value: m, label: m })),
        },
      ],
      save: (v) => {
        const next = {
          id: p?.id || uid(),
          name: v.name,
          riskId: v.riskId,
          steps: v.steps,
          method: v.method,
        };
        changeProject(
          {
            paths: p
              ? project!.paths.map((x) => (x.id === p.id ? next : x))
              : [...project!.paths, next],
          },
          "候选路径已保存；已有用例与执行快照保持不变",
        );
      },
    });
  };
  const addRun = (parent = "") => {
    const selected = project!.cases.filter((c) => c.reviewed);
    const old = project!.runs.find((r) => r.id === parent);
    const cases = old
      ? selected.filter((c) => old.caseIds.includes(c.id))
      : selected;
    if (!cases.length) {
      setNotice("请先审查至少一条相关用例。");
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
    changeProject(
      { runs: [...project!.runs, run] },
      "模拟批次已创建，未连接设备",
    );
    go(link("execute"));
  };
  const head = (
    <header className="pf-header">
      <a className="pf-brand" href="#/">
        P<span>PANGEA</span>
      </a>
      <span className="pf-separator" />
      <label className="pf-switch">
        应用
        <select
          aria-label="切换测试应用"
          value={
            app === "packets" ? "packets" : app === "ibmc" ? "ibmc" : "home"
          }
          onChange={(e) =>
            go(e.target.value === "home" ? "/" : `/${e.target.value}`)
          }
        >
          <option value="home">平台首页</option>
          <option value="ibmc">iBMC 安全测试</option>
          <option value="packets">异常报文测试</option>
        </select>
      </label>
      <span className="pf-header-end">
        研发测试工作空间 <a href="#/">返回平台</a>
      </span>
    </header>
  );

  return (
    <div className="platform-root">
      {head}
      {app !== "packets" && (
        <div className="pf-notices">
          {storageError && <p role="alert">{storageError}</p>}
          {notice && <p role="status">{notice}</p>}
        </div>
      )}
      {app === "home" && (
        <main className="pf-home">
          <div className="pf-heading">
            <div>
              <small>TESTING WORKSPACE</small>
              <h1>从测试任务开始</h1>
              <p>两个专业应用，各自完成设计、执行与结果闭环。</p>
            </div>
            <span className="pf-label">V1 工作空间</span>
          </div>
          <div className="pf-app-grid">
            <article className="pf-app-card">
              <span className="pf-app-code">01 / SECURITY</span>
              <h2>iBMC 安全测试</h2>
              <p>理解产品，规划风险与攻击路径，让每条用例都有依据。</p>
              <div className="pf-tags">
                <span>信息收集</span>
                <span>渗透方法</span>
                <span>证据与复测</span>
              </div>
              <footer>
                <small>本地交互演示 · 未接入 AI</small>
                <a className="pf-primary" href="#/ibmc">
                  进入应用 →
                </a>
              </footer>
            </article>
            <article className="pf-app-card pf-packet-card">
              <span className="pf-app-code">02 / PACKET LAB</span>
              <h2>异常报文测试</h2>
              <p>构造指定报文，验证卡件异常处理与业务恢复能力。</p>
              <div className="pf-tags">
                <span>协议字段</span>
                <span>异常规则</span>
                <span>受控执行</span>
              </div>
              <footer>
                <small>连接现有报文 API · 含真实执行</small>
                <a className="pf-primary" href="#/packets">
                  进入应用 →
                </a>
              </footer>
            </article>
          </div>
          <section className="pf-section">
            <h2>继续最近项目</h2>
            {[...store.projects]
              .sort((a, b) => b.updated.localeCompare(a.updated))
              .slice(0, 4)
              .map((p) => (
                <a
                  key={p.id}
                  href={`#/ibmc/${p.id}/overview`}
                  className="pf-recent"
                >
                  <span>
                    <strong>{p.name}</strong>
                    <small>
                      iBMC · {p.model} · {p.version}
                    </small>
                  </span>
                  <span>继续 →</span>
                </a>
              ))}
            {!store.projects.length && <p>暂无 iBMC 项目，可进入应用创建。</p>}
            <a href="#/packets" className="pf-recent">
              <span>
                <strong>继续异常报文工作</strong>
                <small>恢复最近选择的场景，以后端保存记录为准</small>
              </span>
              <span>打开 →</span>
            </a>
          </section>
        </main>
      )}
      {app === "ibmc" && (
        <div className="pf-workspace">
          <aside className="pf-sidebar">
            <h2>iBMC 安全测试</h2>
            <small>SECURITY VALIDATION</small>
            <a href="#/ibmc" aria-current={!project ? "page" : undefined}>
              全部项目
            </a>
            {project && (
              <>
                <div className="pf-project-name">
                  {project.name}
                  <small>
                    {project.model} · {project.version}
                  </small>
                </div>
                <nav aria-label="iBMC 项目导航">
                  {pages.map(([id, name], i) => (
                    <a
                      key={id}
                      href={`#${link(id)}`}
                      aria-current={page === id ? "page" : undefined}
                    >
                      <span>{String(i + 1).padStart(2, "0")}</span>
                      {name}
                    </a>
                  ))}
                </nav>
              </>
            )}
            <p className="pf-sidebar-foot">
              本地演示数据
              <br />
              不连接设备或外部模型
            </p>
          </aside>
          <main className="pf-main">
            <div className="pf-demo">
              交互演示{" "}
              <span>数据保存在本机浏览器；解析、生成与执行均为示例交互。</span>
            </div>
            {!segments[1] ? (
              <>
                <Heading
                  title="安全测试项目"
                  note="按产品、版本和样机组织测试；模块在项目内规划。"
                  action={
                    <button
                      className="pf-primary"
                      onClick={newProject}
                      disabled={!!storageError}
                    >
                      创建项目
                    </button>
                  }
                />
                <label className="pf-search">
                  查找项目
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="项目名称、型号或版本"
                  />
                </label>
                <div className="pf-project-list">
                  {store.projects
                    .filter((p) =>
                      `${p.name} ${p.model} ${p.version}`
                        .toLowerCase()
                        .includes(query.toLowerCase()),
                    )
                    .map((p) => (
                      <a
                        className="pf-project-row"
                        key={p.id}
                        href={`#/ibmc/${p.id}/overview`}
                      >
                        <span>
                          <strong>{p.name}</strong>
                          <small>
                            {p.model} · {p.version}
                          </small>
                        </span>
                        <span>{p.docs.length} 份资料</span>
                        <span>{p.cases.length} 条用例</span>
                        <span>打开 →</span>
                      </a>
                    ))}
                </div>
                {!store.projects.some((p) =>
                  `${p.name} ${p.model} ${p.version}`
                    .toLowerCase()
                    .includes(query.toLowerCase()),
                ) && <Empty text="没有匹配项目，调整搜索或创建项目。" />}
              </>
            ) : !project ? (
              <Empty
                text="项目不存在或本地数据尚未恢复。"
                action={<a href="#/ibmc">返回项目列表</a>}
              />
            ) : (
              <>
                <div className="pf-breadcrumb">
                  <a href="#/ibmc">项目</a> / {project.name} / {title}
                </div>
                <Heading
                  title={title}
                  note={`${project.model} · 固件 ${project.version}`}
                />
                {page === "overview" && (
                  <>
                    <section className="pf-section">
                      <h2>{project.name}</h2>
                      <p>从产品资料建立测试依据，逐步确定范围、路径与用例。</p>
                      <div className="pf-metrics">
                        {[
                          ["资料", project.docs.length],
                          [
                            "已选模块",
                            project.risks.filter((r) => r.selected).length,
                          ],
                          ["候选路径", project.paths.length],
                          ["用例草稿", project.cases.length],
                        ].map(([label, n]) => (
                          <div key={label}>
                            <strong>{n}</strong>
                            <span>{label}</span>
                          </div>
                        ))}
                      </div>
                    </section>
                    <div className="pf-stage-list">
                      {pages.slice(1, 7).map(([id, name], i) => (
                        <a key={id} href={`#${link(id)}`}>
                          <span>{String(i + 1).padStart(2, "0")}</span>
                          <strong>{name}</strong>
                          <span>进入 →</span>
                        </a>
                      ))}
                    </div>
                  </>
                )}
                {page === "intake" && (
                  <>
                    <Toolbar note="添加资料摘要与版本；示例解析不会读取文件或推断真实设备。">
                      <button
                        className="pf-primary"
                        disabled={!!storageError}
                        onClick={() =>
                          setEditor({
                            title: "添加资料记录",
                            fields: [
                              { key: "name", label: "资料名称" },
                              {
                                key: "version",
                                label: "适用版本",
                                value: project.version,
                              },
                              {
                                key: "note",
                                label: "资料摘要 / 来源章节",
                                multiline: true,
                              },
                            ],
                            save: (v) =>
                              changeProject(
                                {
                                  docs: [
                                    ...project.docs,
                                    {
                                      id: uid(),
                                      name: v.name,
                                      version: v.version,
                                      note: v.note,
                                      parsed: false,
                                    },
                                  ],
                                },
                                "资料记录已保存",
                              ),
                          })
                        }
                      >
                        添加资料
                      </button>
                    </Toolbar>
                    {project.docs.map((d) => (
                      <section className="pf-section" key={d.id}>
                        <div className="pf-row">
                          <h2>{d.name}</h2>
                          <span className="pf-label">
                            {d.version} ·{" "}
                            {d.parsed ? "已查看解析示例" : "待整理"}
                          </span>
                        </div>
                        <p>{d.note}</p>
                        <button
                          onClick={() =>
                            changeProject(
                              {
                                docs: project.docs.map((x) =>
                                  x.id === d.id ? { ...x, parsed: true } : x,
                                ),
                              },
                              "已展开解析示例；请人工核对内容",
                            )
                          }
                        >
                          查看解析示例
                        </button>
                        {d.parsed && (
                          <div className="pf-evidence">
                            <strong>整理结果示例</strong>
                            <p>
                              来源：{d.name} / {d.version}
                            </p>
                            <p>
                              待核对：模块清单、接口入口、角色权限、部署网络和恢复材料。
                            </p>
                            <p>当前摘要：{d.note}</p>
                            <a href={`#${link("risks")}`}>据此规划风险模块 →</a>
                          </div>
                        )}
                      </section>
                    ))}
                    {!project.docs.length && (
                      <Empty text="先添加产品说明、接口说明或权限表的资料记录。" />
                    )}
                  </>
                )}
                {page === "risks" && (
                  <>
                    <Toolbar note="记录风险理由后，勾选纳入本轮范围；选择并不代表确认漏洞。">
                      <button onClick={() => editRisk()}>新增模块</button>
                    </Toolbar>
                    {project.risks.map((r) => (
                      <section key={r.id} className="pf-section">
                        <div className="pf-row">
                          <label className="pf-check">
                            <input
                              type="checkbox"
                              checked={r.selected}
                              onChange={(e) =>
                                changeProject(
                                  {
                                    risks: project.risks.map((x) =>
                                      x.id === r.id
                                        ? { ...x, selected: e.target.checked }
                                        : x,
                                    ),
                                  },
                                  "测试范围已更新",
                                )
                              }
                            />
                            {r.name}
                          </label>
                          <button onClick={() => editRisk(r.id)}>
                            编辑依据
                          </button>
                        </div>
                        <p>{r.reason}</p>
                        <small>
                          {r.selected ? "已纳入本轮范围" : "未纳入本轮范围"}
                        </small>
                      </section>
                    ))}
                    {!project.risks.length && (
                      <Empty text="还没有风险模块，可根据资料手动规划。" />
                    )}
                    <a href={`#${link("paths")}`}>规划候选攻击路径 →</a>
                  </>
                )}
                {page === "paths" && (
                  <>
                    <Toolbar note="每条路径保留身份、入口和目标，尚未验证的步骤作为假设。">
                      <button
                        disabled={!project.risks.some((r) => r.selected)}
                        onClick={() => editPath()}
                      >
                        新增路径
                      </button>
                    </Toolbar>
                    {!project.risks.some((r) => r.selected) && (
                      <p>请先在风险模块中选择测试范围。</p>
                    )}
                    {project.paths.map((p) => (
                      <section key={p.id} className="pf-section">
                        <div className="pf-row">
                          <h2>{p.name}</h2>
                          <span className="pf-label">候选 · 未验证</span>
                        </div>
                        <p className="pf-path">{p.steps}</p>
                        <p>
                          {project.risks.find((r) => r.id === p.riskId)?.name} ·{" "}
                          {p.method}
                        </p>
                        <div className="pf-actions">
                          <button onClick={() => editPath(p.id)}>
                            编辑路径
                          </button>
                          <button
                            className="pf-primary"
                            disabled={
                              !project.risks.find((r) => r.id === p.riskId)
                                ?.selected ||
                              project.cases.some((c) => c.pathId === p.id)
                            }
                            onClick={() => {
                              changeProject(
                                { cases: [...project.cases, draftFor(p)] },
                                "示例用例已生成，待人工编辑与审查",
                              );
                              go(link("design"));
                            }}
                          >
                            {project.cases.some((c) => c.pathId === p.id)
                              ? "已有关联用例"
                              : "生成示例用例"}
                          </button>
                        </div>
                      </section>
                    ))}
                    {!project.paths.length && (
                      <Empty text="尚无候选攻击路径。" />
                    )}
                  </>
                )}
                {page === "design" && (
                  <>
                    <Toolbar note="草稿使用本地方法模板。审查只确认演示设计，不授予设备执行权限。">
                      <a href={`#${link("paths")}`}>从路径生成用例</a>
                    </Toolbar>
                    {project.cases.map((c) => (
                      <section className="pf-section" key={c.id}>
                        <div className="pf-row">
                          <h2>{c.name}</h2>
                          <span className="pf-label">
                            {c.reviewed ? "演示设计已审查" : "草稿 · 待审查"}
                          </span>
                        </div>
                        <p>
                          {c.method} · 来源路径：
                          {project.paths.find((p) => p.id === c.pathId)?.name}
                        </p>
                        <h3>步骤</h3>
                        <p className="pf-pre">{c.steps}</p>
                        <h3>判据</h3>
                        <p>{c.criterion}</p>
                        <div className="pf-actions">
                          <button
                            onClick={() =>
                              setEditor({
                                title: "编辑测试用例",
                                fields: [
                                  {
                                    key: "name",
                                    label: "用例名称",
                                    value: c.name,
                                  },
                                  {
                                    key: "steps",
                                    label: "前提与步骤",
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
                                  changeProject(
                                    {
                                      cases: project.cases.map((x) =>
                                        x.id === c.id
                                          ? { ...x, ...v, reviewed: false }
                                          : x,
                                      ),
                                    },
                                    "用例已保存，修改后需要重新审查",
                                  ),
                              })
                            }
                          >
                            编辑用例
                          </button>
                          <button
                            disabled={c.reviewed}
                            onClick={() =>
                              changeProject(
                                {
                                  cases: project.cases.map((x) =>
                                    x.id === c.id
                                      ? { ...x, reviewed: true }
                                      : x,
                                  ),
                                },
                                "演示设计已确认，仍未执行",
                              )
                            }
                          >
                            确认演示设计
                          </button>
                        </div>
                      </section>
                    ))}
                    {!project.cases.length && (
                      <Empty text="从候选攻击路径生成第一条用例。" />
                    )}
                  </>
                )}
                {page === "execute" && (
                  <>
                    <Toolbar note="批次保存创建时的用例快照，仅演示状态流转。">
                      <button
                        className="pf-primary"
                        disabled={!project.cases.some((c) => c.reviewed)}
                        onClick={() => addRun()}
                      >
                        创建模拟批次
                      </button>
                    </Toolbar>
                    {project.runs.map((r, i) => (
                      <section className="pf-section" key={r.id}>
                        <div className="pf-row">
                          <h2>
                            模拟批次 {i + 1}
                            {r.parent ? " · 复测" : ""}
                          </h2>
                          <span className="pf-label">
                            {r.done ? "模拟结束 · 无实测结论" : "等待模拟"}
                          </span>
                        </div>
                        <p>
                          {r.caseIds.length} 条用例 ·{" "}
                          {new Date(r.created).toLocaleString()}
                        </p>
                        <details>
                          <summary>查看冻结用例快照</summary>
                          {r.snapshot.map((c) => (
                            <div key={c.id}>
                              <h3>{c.name}</h3>
                              <p className="pf-pre">{c.steps}</p>
                              <p>{c.criterion}</p>
                            </div>
                          ))}
                        </details>
                        <div className="pf-actions">
                          <button
                            disabled={r.done}
                            onClick={() =>
                              changeProject(
                                {
                                  runs: project.runs.map((x) =>
                                    x.id === r.id ? { ...x, done: true } : x,
                                  ),
                                },
                                "模拟状态已更新；没有请求发送到设备",
                              )
                            }
                          >
                            完成模拟
                          </button>
                          <button
                            onClick={() =>
                              setEditor({
                                title: "记录探索线索",
                                fields: [
                                  {
                                    key: "note",
                                    label: "线索 / 证据缺口",
                                    value: r.note,
                                    multiline: true,
                                  },
                                ],
                                save: (v) =>
                                  changeProject(
                                    {
                                      runs: project.runs.map((x) =>
                                        x.id === r.id
                                          ? { ...x, note: v.note }
                                          : x,
                                      ),
                                    },
                                    "线索已保存，尚未确认为漏洞",
                                  ),
                              })
                            }
                          >
                            记录线索
                          </button>
                          <a href={`#${link("results")}`}>结果与复测 →</a>
                        </div>
                        {r.note && (
                          <p className="pf-evidence">待验证线索：{r.note}</p>
                        )}
                      </section>
                    ))}
                    {!project.runs.length && (
                      <Empty
                        text="先审查用例，再创建模拟执行批次。"
                        action={<a href={`#${link("design")}`}>前往测试设计</a>}
                      />
                    )}
                  </>
                )}
                {page === "results" && (
                  <>
                    <p className="pf-subtle">
                      模拟记录不计入真实测试覆盖，也不会产生已确认漏洞。
                    </p>
                    {project.runs
                      .filter((r) => r.done)
                      .map((r, i) => (
                        <section className="pf-section" key={r.id}>
                          <div className="pf-row">
                            <h2>模拟结果 {i + 1}</h2>
                            <span className="pf-label">待真实验证</span>
                          </div>
                          <p>
                            证据：仅本地状态流转记录，缺设备响应、任务状态和审计日志。
                          </p>
                          <p>线索：{r.note || "尚未记录"}</p>
                          <p>恢复状态：未执行设备操作。</p>
                          <div className="pf-actions">
                            <button onClick={() => addRun(r.id)}>
                              创建模拟复测
                            </button>
                            <a href={`#${link("execute")}`}>
                              查看批次证据与用例快照
                            </a>
                          </div>
                        </section>
                      ))}
                    {!project.runs.some((r) => r.done) && (
                      <Empty
                        text="暂无模拟结果。完成一个模拟批次后可查看与复测。"
                        action={
                          <a href={`#${link("execute")}`}>前往执行与挖掘</a>
                        }
                      />
                    )}
                  </>
                )}
                {page === "skills" && (
                  <>
                    <p className="pf-subtle">
                      项目内置方法包 0.1.0 · 只读查看 · 尚未接入 AI 调用
                    </p>
                    <div className="pf-skill-layout">
                      <nav aria-label="Skill 列表">
                        {skillNames.map((name, i) => (
                          <button
                            key={name}
                            aria-pressed={skill === i}
                            onClick={() => setSkill(i)}
                          >
                            {name}
                          </button>
                        ))}
                      </nav>
                      <section className="pf-section">
                        <h2>{skillNames[skill]}</h2>
                        <pre className="pf-skill-source">
                          {
                            skillFiles[
                              `../skills/ibmc/${skillIds[skill]}/SKILL.md`
                            ]
                          }
                        </pre>
                        <a href={`#${link("paths")}`}>在路径规划中关联方法 →</a>
                      </section>
                    </div>
                  </>
                )}
                {pageIndex < 0 && (
                  <Empty
                    text="页面不存在。"
                    action={<a href={`#${link("overview")}`}>返回项目概览</a>}
                  />
                )}
                {pageIndex >= 0 && (
                  <footer className="pf-page-footer">
                    {pageIndex > 0 ? (
                      <a href={`#${link(pages[pageIndex - 1][0])}`}>
                        ← {pages[pageIndex - 1][1]}
                      </a>
                    ) : (
                      <a href="#/ibmc">← 全部项目</a>
                    )}
                    {pageIndex < pages.length - 1 && (
                      <a href={`#${link(pages[pageIndex + 1][0])}`}>
                        {pages[pageIndex + 1][1]} →
                      </a>
                    )}
                  </footer>
                )}
              </>
            )}
          </main>
        </div>
      )}
      {packetMounted && (
        <div hidden={app !== "packets"}>
          <PacketApp />
        </div>
      )}
      {!["home", "ibmc", "packets"].includes(app) && (
        <main className="pf-home">
          <Empty text="页面不存在。" action={<a href="#/">返回平台</a>} />
        </main>
      )}
      {editor && <EditorDialog editor={editor} close={() => setEditor(null)} />}
    </div>
  );
}

function Heading({
  title,
  note,
  action,
}: {
  title: string;
  note: string;
  action?: ReactNode;
}) {
  return (
    <div className="pf-heading">
      <div>
        <h1>{title}</h1>
        <p>{note}</p>
      </div>
      {action}
    </div>
  );
}
function Toolbar({ note, children }: { note: string; children: ReactNode }) {
  return (
    <div className="pf-toolbar">
      <p>{note}</p>
      <div className="pf-actions">{children}</div>
    </div>
  );
}
function Empty({ text, action }: { text: string; action?: ReactNode }) {
  return (
    <section className="pf-empty">
      <p>{text}</p>
      {action}
    </section>
  );
}
function EditorDialog({
  editor,
  close,
}: {
  editor: Editor;
  close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const values = Object.fromEntries(
      editor.fields.map((f) => [f.key, String(data.get(f.key) || "").trim()]),
    );
    if (Object.values(values).some((v) => !v)) {
      setError("请填写所有字段，内容不能只有空格。");
      return;
    }
    editor.save(values);
    close();
  };
  return (
    <dialog className="pf-dialog" ref={dialog} onCancel={close}>
      <form onSubmit={submit}>
        <div className="pf-row">
          <h2>{editor.title}</h2>
          <button type="button" onClick={close} aria-label="关闭编辑窗口">
            ×
          </button>
        </div>
        {error && <p role="alert">{error}</p>}
        {editor.fields.map((f) => (
          <label key={f.key}>
            {f.label}
            {f.options ? (
              <select
                name={f.key}
                defaultValue={f.value || f.options[0]?.value}
                required
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
                required
                rows={5}
                maxLength={6000}
              />
            ) : (
              <input
                name={f.key}
                defaultValue={f.value}
                required
                maxLength={160}
              />
            )}
          </label>
        ))}
        <footer className="pf-actions">
          <button type="button" onClick={close}>
            取消
          </button>
          <button className="pf-primary">保存到本机</button>
        </footer>
      </form>
    </dialog>
  );
}
