export type Doc = {
  id: string;
  name: string;
  version: string;
  note: string;
  parsed: boolean;
};
export type Risk = {
  id: string;
  name: string;
  reason: string;
  selected: boolean;
};
export type Path = {
  id: string;
  name: string;
  riskId: string;
  steps: string;
  method: string;
};
export type Case = {
  id: string;
  name: string;
  pathId: string;
  method: string;
  steps: string;
  criterion: string;
  reviewed: boolean;
};
export type Run = {
  id: string;
  caseIds: string[];
  snapshot: Case[];
  done: boolean;
  created: string;
  parent: string;
  note: string;
};
export type Project = {
  id: string;
  name: string;
  model: string;
  version: string;
  updated: string;
  docs: Doc[];
  risks: Risk[];
  paths: Path[];
  cases: Case[];
  runs: Run[];
};
export type DemoStore = { version: 1; projects: Project[] };
export const DEMO_KEY = "pangea.ibmc.demo.v1";
export const methods = [
  "WEB-SSRF",
  "WEB-XSS",
  "WEB-UPLOAD",
  "WEB-DOWNLOAD",
  "WEB-AUTHZ",
  "WEB-SESSION",
  "WEB-INJECTION",
  "FW-UPDATE-AUTHZ",
  "FW-INTEGRITY",
  "FW-RECOVERY",
];
export const uid = () => crypto.randomUUID();
export const seedStore = (): DemoStore => ({
  version: 1,
  projects: [
    {
      id: "lab-r12",
      name: "BMC-Lab · R12 安全验证",
      model: "BMC-Lab / 样机 A",
      version: "R12",
      updated: "2026-09-10T09:00:00+08:00",
      docs: [
        {
          id: "doc-1",
          name: "产品与接口说明（示例）",
          version: "R12",
          note: "远程镜像支持服务端获取 URL；Reader 可查看状态，Admin 可提交。具体接口及权限表需要核实。",
          parsed: true,
        },
      ],
      risks: [
        {
          id: "risk-1",
          name: "远程镜像",
          reason:
            "输入 URL 影响 BMC 服务端访问目标，需要验证目标限制与角色权限。",
          selected: true,
        },
        {
          id: "risk-2",
          name: "固件更新",
          reason: "涉及固件写入、完整性与恢复能力。",
          selected: false,
        },
      ],
      paths: [
        {
          id: "path-1",
          name: "远程镜像目标限制",
          riskId: "risk-1",
          steps: "Admin → 镜像 URL → BMC 服务端获取 → 验证目标是否受限",
          method: "WEB-SSRF",
        },
      ],
      cases: [],
      runs: [],
    },
  ],
});

export function isDemoStore(value: unknown): value is DemoStore {
  const obj = (v: unknown): v is Record<string, unknown> =>
    !!v && typeof v === "object" && !Array.isArray(v);
  const strings = (v: unknown, keys: string[]) =>
    obj(v) && keys.every((k) => typeof v[k] === "string");
  const list = (v: unknown, test: (x: unknown) => boolean) =>
    Array.isArray(v) && v.every(test);
  const caseOK = (v: unknown) =>
    strings(v, ["id", "name", "pathId", "method", "steps", "criterion"]) &&
    obj(v) &&
    typeof v.reviewed === "boolean";
  return (
    obj(value) &&
    value.version === 1 &&
    list(
      value.projects,
      (p) =>
        obj(p) &&
        strings(p, ["id", "name", "model", "version", "updated"]) &&
        list(
          p.docs,
          (d) =>
            obj(d) &&
            strings(d, ["id", "name", "version", "note"]) &&
            typeof d.parsed === "boolean",
        ) &&
        list(
          p.risks,
          (r) =>
            obj(r) &&
            strings(r, ["id", "name", "reason"]) &&
            typeof r.selected === "boolean",
        ) &&
        list(p.paths, (a) =>
          strings(a, ["id", "name", "riskId", "steps", "method"]),
        ) &&
        list(p.cases, caseOK) &&
        list(
          p.runs,
          (r) =>
            obj(r) &&
            strings(r, ["id", "created", "parent", "note"]) &&
            typeof r.done === "boolean" &&
            list(r.caseIds, (id) => typeof id === "string") &&
            list(r.snapshot, caseOK),
        ),
    )
  );
}

export function draftFor(path: Path): Case {
  const ssrf = path.method === "WEB-SSRF";
  return {
    id: uid(),
    name: path.name,
    pathId: path.id,
    method: path.method,
    reviewed: false,
    steps: ssrf
      ? "1. 确认目标、账号、允许源和受控测试地址。\n2. 记录正常镜像获取的任务与出站基线。\n3. 在批准环境验证策略外受控目标是否被阻止。\n4. 关联请求、接收端日志和任务状态，清理测试任务。"
      : `1. 核对 ${path.method} 的适用入口与角色。\n2. 记录正常操作及受保护状态。\n3. 在授权隔离环境验证选定边界。\n4. 比对响应、实际状态和日志，恢复基线。`,
    criterion: ssrf
      ? "允许源正常；策略外受控目标被阻止。需服务端及接收端关联证据，证据不全记为待确认。"
      : "正常对照有效；禁止操作未改变受保护状态；证据不足不能判为通过。",
  };
}
