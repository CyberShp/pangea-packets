// UI contract tests: all network/SSH/send/capture operations are intercepted.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const base = process.env.UI_BASE_URL || "http://127.0.0.1:5173";
const clone = (x) => JSON.parse(JSON.stringify(x));
const packet = {
  id: "packet-a",
  name: "IPv4 / TCP 边界验证",
  enabled: true,
  templateId: "template-a",
  sendCount: 1,
  intervalMs: 0,
  mutations: [],
  layers: [
    {
      id: "eth",
      role: "outer",
      type: "ethernet",
      fields: {
        src: "02:00:00:00:00:01",
        dst: "02:00:00:00:00:02",
        type: 2048,
      },
      autoCalculate: { type: true },
    },
    {
      id: "ip",
      role: "outer",
      type: "ipv4",
      fields: {
        src: "192.0.2.10",
        dst: "192.0.2.20",
        ttl: 64,
        len: null,
        chksum: null,
      },
      autoCalculate: { len: true, chksum: true },
    },
    {
      id: "tcp",
      role: "outer",
      type: "tcp",
      fields: {
        sport: 12345,
        dport: 3260,
        seq: 0,
        ack: 0,
        flags: "A",
        window: 8192,
        chksum: null,
      },
      autoCalculate: { chksum: true },
    },
  ],
};
const initial = {
  id: "scenario-a",
  name: "TCP 完整性回归",
  description: "验证长度、校验和与截断异常的处理行为",
  mode: "direct",
  target: { hostId: "host-a", interface: "eth0" },
  sendOptions: { loopCount: 1, stopOnFailure: true },
  packets: [packet],
};
const sample = {
  packet: {
    ...clone(packet),
    id: "sample-a",
    rawHex: "00112233445566778899aabb080045000028",
  },
  length: 18,
  fields: [
    { name: "ipv4.ttl", value: "64", offset: 8, size: 1, kind: "number" },
  ],
};
(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {}),
    args: ["--no-sandbox"],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1050 },
  });
  page.setDefaultTimeout(10000);
  const errors = [],
    unexpected = [],
    calls = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let scenarios = [clone(initial)],
    templates = [
      {
        id: "template-a",
        name: "Ethernet / IPv4 / TCP",
        builtin: true,
        layers: clone(packet.layers),
      },
    ],
    hosts = [
      {
        id: "host-a",
        name: "Lab 01 · 发包主机",
        address: "192.0.2.100",
        sshPort: 22,
        auth: { username: "tester" },
      },
      {
        id: "host-b",
        name: "Lab 02 · 备用主机",
        address: "192.0.2.101",
        sshPort: 22,
        auth: { username: "tester" },
      },
    ];
  let executions = [
    {
      id: "exec-success",
      scenarioId: initial.id,
      mode: "direct",
      status: "success",
      startedAt: "2026-09-30T08:00:00Z",
      finishedAt: "2026-09-30T08:00:04Z",
      level0: { reportedSendCount: 3 },
      logs: [
        {
          timestamp: "2026-09-30T08:00:04Z",
          data: JSON.stringify({
            event: "send_complete",
            reportedSendCount: 3,
          }),
        },
      ],
    },
    {
      id: "exec-failed",
      scenarioId: initial.id,
      mode: "listen",
      status: "failed",
      startedAt: "2026-09-29T08:00:00Z",
      level0: { error: "监听超时：未匹配到报文" },
      logs: [],
    },
  ];
  let failLoad = false,
    failSave = false,
    failPreview = false,
    failHost = false,
    invalid = false,
    offload = { gro: true, tso: false },
    sendCount = 0;
  await page.routeWebSocket("**/api/v1/executions/*/stream", (ws) => {
    const id = ws.url().split("/").at(-2),
      e = executions.find((x) => x.id === id);
    if (e) ws.send(JSON.stringify({ type: "execution_updated", data: e }));
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request(),
      path = new URL(req.url()).pathname.replace("/api/v1", ""),
      method = req.method();
    let body = {};
    try {
      body = req.postDataJSON() || {};
    } catch {}
    calls.push({ path, method, body });
    const ok = (json) => route.fulfill({ json: clone(json) }),
      bad = (message) =>
        route.fulfill({ status: 503, json: { detail: message } });
    if (path === "/scenarios" && method === "GET")
      return failLoad ? bad("服务暂不可用") : ok({ items: scenarios });
    if (path === "/templates" && method === "GET")
      return ok({ items: templates });
    if (path === "/hosts" && method === "GET") return ok({ items: hosts });
    if (path === "/executions" && method === "GET")
      return ok({ items: executions });
    if (path === "/mutation-types")
      return ok({
        items: [
          {
            type: "invalid_length",
            displayName: "长度字段异常",
            strategies: ["custom"],
          },
        ],
      });
    if (path === "/samples")
      return ok({
        items: [{ id: "batch-a", source: "lab-capture.pcap", items: [sample] }],
      });
    if (path === "/samples/import") return ok({ items: [sample] });
    if (path === "/samples/capture")
      return ok({ id: "capture", source: "eth0", items: [] });
    if (path === "/templates/preview")
      return failPreview
        ? bad("无法生成预览，请核对字段")
        : ok({
            hex: "00112233445566778899aabb080045000028",
            length: 18,
            warnings: [],
          });
    if (path === "/scenarios" && method === "POST") {
      const s = {
        ...clone(initial),
        id: "scenario-new",
        name: body.name,
        packets: [],
      };
      scenarios.push(s);
      return ok(s);
    }
    if (path.endsWith("/duplicate")) {
      const s = {
        ...clone(scenarios.find((s) => path.includes(s.id))),
        id: "scenario-copy",
        name: "复制的场景",
      };
      scenarios.push(s);
      return ok(s);
    }
    if (path.startsWith("/scenarios/") && method === "PUT") {
      if (failSave) return bad("保存失败，草稿仍保留");
      scenarios = scenarios.map((s) => (s.id === body.id ? clone(body) : s));
      return ok(body);
    }
    if (path.endsWith("/validate"))
      return ok({
        valid: !invalid,
        errors: invalid ? [{ message: "目标网口未就绪" }] : [],
        warnings: [],
      });
    if (path === "/mutations/random-generate") return ok({ mutations: [] });
    if (path === "/hosts" && method === "POST") {
      const h = { id: "host-new", ...body };
      hosts.push(h);
      return ok(h);
    }
    if (path.endsWith("/connect-test") || path.endsWith("/env-check"))
      return failHost
        ? bad("连接失败：请核对主机信息")
        : ok({ connected: true, python: "3.11", scapy: true });
    if (path.endsWith("/interfaces"))
      return ok({
        items: ["eth0", "eth1"].map((name) => ({
          name,
          mac: "02:00:00:00:00:01",
          ips: ["192.0.2.100"],
          link: "UP",
          speed: "10Gbps",
          driver: "test",
          pci: "test",
        })),
      });
    if (path.endsWith("/offload")) {
      if (method === "POST") offload = { ...offload, ...body };
      return ok(offload);
    }
    if (path === "/executions" && method === "POST") {
      sendCount++;
      const e = {
        id: "exec-new",
        scenarioId: body.scenarioId,
        mode: scenarios.find((s) => s.id === body.scenarioId).mode,
        status: "running",
        startedAt: new Date().toISOString(),
        logs: [],
      };
      executions.unshift(e);
      return ok({ executionId: e.id, status: e.status });
    }
    if (path === "/samples/edit")
      return ok({
        ...clone(sample),
        packet: {
          ...body.packet,
          rawHex: body.operation
            ? "ff112233445566778899aabb080045000028"
            : body.packet.rawHex || sample.packet.rawHex,
        },
      });
    if (path === "/templates" && method === "POST") {
      const t = {
        id: "user-template",
        name: body.name,
        builtin: false,
        packet: body.packet,
        layers: body.packet.layers,
      };
      templates.push(t);
      return ok(t);
    }
    if (path.startsWith("/templates/") && method === "PUT") {
      templates = templates.map((t) =>
        t.id === path.split("/").at(-1) ? { ...t, ...body } : t,
      );
      return ok(body);
    }
    if (path.startsWith("/templates/") && method === "DELETE") {
      templates = templates.filter((t) => t.id !== path.split("/").at(-1));
      return ok({ ok: true });
    }
    if (path.startsWith("/exports/"))
      return ok({ downloadUrl: "about:blank", fileName: "fixture.pcap" });
    unexpected.push(`${method} ${path}`);
    return bad("未定义的测试请求");
  });
  const root = page.locator(".packet-light"),
    click = async (name) =>
      root.getByRole("button", { name, exact: true }).click();
  const screen = async (name) => {
    fs.mkdirSync("output/ui", { recursive: true });
    await page.screenshot({
      path: `output/ui/packet-${name}.png`,
      fullPage: true,
    });
  };
  const nav = async (name) =>
    root
      .getByRole("navigation", { name: "报文应用导航" })
      .getByRole("button", { name, exact: true })
      .click();
  try {
    // Reachable failure and retry state.
    failLoad = true;
    await page.goto(base + "/#/packets");
    await root.getByText("暂时无法加载数据", { exact: true }).waitFor();
    await screen("load-failure");
    failLoad = false;
    await click("重试加载");
    await root.getByRole("table").waitFor();
    await screen("sequence");
    await click("＋ 新建场景");
    await page.getByRole("dialog").getByLabel("场景名称").fill("新建空场景");
    await screen("new-scene");
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "创建场景", exact: true })
      .click();
    await root
      .getByText("从上方模板添加第一个报文，然后编辑字段并保存场景。")
      .waitFor();
    await screen("empty-scene");
    await root
      .getByLabel("当前场景", { exact: true })
      .selectOption("scenario-a");
    // Field editing, failure keeps draft, successful save sends exact changes.
    await click("协议字段");
    await click("outer · ipv4");
    await root.getByLabel("outer.ipv4.ttl", { exact: true }).fill("63");
    failSave = true;
    await click("保存场景");
    await root.getByText("保存失败，草稿仍保留", { exact: true }).waitFor();
    assert.equal(
      await root.getByLabel("outer.ipv4.ttl", { exact: true }).inputValue(),
      "63",
    );
    await screen("save-failure");
    failSave = false;
    await click("保存场景");
    await root.getByText("已保存，刷新后可继续编辑", { exact: true }).waitFor();
    assert.equal(scenarios[0].packets[0].layers[1].fields.ttl, 63);
    await screen("protocol");
    failPreview = true;
    await root.getByLabel("outer.ipv4.ttl", { exact: true }).fill("62");
    await root.getByRole("button", { name: "重试预览" }).waitFor();
    failPreview = false;
    await click("重试预览");
    await root.getByText("真实长度：18 bytes").waitFor();
    await click("保存场景");
    await root.getByText("已保存，刷新后可继续编辑", { exact: true }).waitFor();
    // Candidate rules persist across tabs, then are validated before applying.
    await click("异常规则");
    await click("添加指定规则");
    await click("协议字段");
    await click("异常规则");
    await root
      .getByRole("heading", { name: "待应用规则", exact: true })
      .waitFor();
    await screen("mutation-candidate");
    await click("应用到报文");
    await root.getByText("规则已应用到报文，请保存场景").waitFor();
    await click("保存场景");
    await root.getByText("已保存，刷新后可继续编辑", { exact: true }).waitFor();
    assert.equal(scenarios[0].packets[0].mutations.length, 1);
    await root
      .getByRole("navigation", { name: "场景步骤" })
      .getByRole("button", { name: /执行配置/ })
      .click();
    await screen("direct-config");
    await root.getByRole("button", { name: /监听模式/ }).click();
    await root.getByLabel("匹配位置").selectOption("vxlan_inner_five_tuple");
    await root.getByLabel("VNI", { exact: true }).fill("100");
    await root.getByLabel("内层 源 IP", { exact: true }).fill("192.0.2.10");
    await screen("listen-config");
    await click("保存场景");
    await root.getByText("已保存，刷新后可继续编辑", { exact: true }).waitFor();
    assert.equal(scenarios[0].listenConfig.match.tunnel.vni, 100);
    invalid = true;
    await click("校验场景");
    await root.getByText("目标网口未就绪", { exact: true }).waitFor();
    assert(
      await root
        .getByRole("button", { name: "执行前确认 →", exact: true })
        .isDisabled(),
    );
    invalid = false;
    await click("校验场景");
    await root.getByText("场景校验通过", { exact: true }).waitFor();
    await click("执行前确认 →");
    let dialog = page.getByRole("dialog");
    assert(
      await dialog.getByRole("button", { name: "确认并执行" }).isDisabled(),
    );
    await screen("execute-confirm");
    await dialog.getByRole("button", { name: "返回检查" }).click();
    assert.equal(sendCount, 0);
    await click("执行前确认 →");
    await dialog.getByRole("checkbox").check();
    await dialog.getByRole("button", { name: "确认并执行" }).click();
    await root
      .getByRole("heading", { name: "场景执行记录", exact: true })
      .waitFor();
    assert.equal(sendCount, 1);
    await screen("running");
    executions[0] = {
      ...executions[0],
      status: "success",
      finishedAt: new Date().toISOString(),
      level0: { reportedSendCount: 1 },
      logs: [{ data: "已完成测试发送" }],
    };
    await root.getByText("已完成测试发送").first().waitFor({ timeout: 10000 });
    // Host selection / interface / explicit offload write gate.
    await nav("远端主机");
    await screen("hosts");
    await click("查询网卡");
    await root.getByRole("switch", { name: "gro", exact: true }).waitFor();
    await root.locator(".nic-list button").filter({ hasText: "eth1" }).click();
    await root
      .getByRole("heading", { name: "eth1 · Offload", exact: true })
      .waitFor();
    await root.getByRole("switch", { name: "gro", exact: true }).click();
    await screen("offload-confirm");
    await dialog.getByRole("button", { name: "取消", exact: true }).click();
    assert.equal(
      calls.filter((c) => c.path.endsWith("/offload") && c.method === "POST")
        .length,
      0,
    );
    await root.getByRole("switch", { name: "gro", exact: true }).click();
    await dialog.getByRole("button", { name: "确认修改", exact: true }).click();
    await page.waitForFunction(() => !document.querySelector("dialog[open]"));
    assert.equal(
      calls.filter(
        (c) => c.path.endsWith("/eth1/offload") && c.method === "POST",
      ).length,
      1,
    );
    failHost = true;
    await click("测试连接");
    await root.getByText("连接失败：请核对主机信息", { exact: true }).waitFor();
    failHost = false;
    await click("测试连接");
    await root.getByText(/Lab 01 · 发包主机 · 连接测试/).waitFor();
    await screen("host-details");
    await click("＋ 添加主机");
    await screen("host-new");
    await dialog.getByLabel("主机名称", { exact: true }).fill("UI 新主机");
    await dialog
      .getByLabel("IP / 主机地址", { exact: true })
      .fill("192.0.2.200");
    await dialog.getByLabel("SSH 用户", { exact: true }).fill("tester");
    await dialog.getByRole("button", { name: "保存主机", exact: true }).click();
    await root
      .getByRole("heading", { name: "UI 新主机", exact: true })
      .waitFor();
    assert.equal(hosts.at(-1).address, "192.0.2.200");
    // Sample byte editing, discard guard, user template save / update / delete.
    await nav("报文样本");
    await root
      .getByLabel("导入 PCAP")
      .setInputFiles({
        name: "ui-fixture.pcap",
        mimeType: "application/octet-stream",
        buffer: Buffer.from("UI contract fixture"),
      });
    await root
      .getByText("已导入 1 个报文，请从列表选择", { exact: true })
      .waitFor();
    await root.getByText("从远端网口抓包", { exact: true }).click();
    await root.getByLabel("抓包主机").selectOption("host-a");
    await root.getByLabel("抓包网口").fill("eth0");
    assert(
      await root
        .getByRole("button", { name: "开始限量抓包", exact: true })
        .isDisabled(),
    );
    await screen("sample-capture");
    await root.getByLabel("已获授权抓取上述网口流量并保存在本机").check();
    await click("开始限量抓包");
    await root.getByText("抓包结束，未匹配到报文", { exact: true }).waitFor();
    assert.equal(calls.filter((c) => c.path === "/samples/capture").length, 1);
    await root.getByText("从远端网口抓包", { exact: true }).click();

    await root.getByRole("button", { name: /#1 · 18 bytes/ }).click();
    await screen("samples");
    await root.getByLabel("编辑操作").selectOption("overwrite");
    await click("应用编辑");
    await root.getByText("字节已更新，请保存为模板或添加到场景").waitFor();
    await click("恢复载入字节");
    await dialog.getByRole("heading", { name: "放弃未保存的修改？" }).waitFor();
    await screen("sample-discard");
    await dialog.getByRole("button", { name: "取消", exact: true }).click();
    assert((await root.getByLabel("样本 Hex").textContent()).startsWith("ff"));
    await root.getByLabel("模板名称").fill("UI 字节模板");
    await click("另存为用户模板");
    await root.getByText("用户模板已保存", { exact: true }).waitFor();
    await click("删除当前模板");
    await screen("template-delete");
    await dialog.getByRole("button", { name: "取消", exact: true }).click();
    assert(templates.some((t) => t.id === "user-template"));
    await click("删除当前模板");
    await dialog
      .getByRole("button", { name: "确认删除模板", exact: true })
      .click();
    await root
      .getByText("模板已删除；已有场景保留原有报文", { exact: true })
      .waitFor();
    assert(!templates.some((t) => t.id === "user-template"));
    await nav("执行历史");
    await root.getByRole("button", { name: /exec-failed/ }).click();
    await root
      .getByText("失败原因：监听超时：未匹配到报文", { exact: true })
      .waitFor();
    await screen("execution-failed");
    await root.getByLabel("执行状态", { exact: true }).selectOption("success");
    assert.equal(
      await root.getByRole("button", { name: /exec-failed/ }).count(),
      0,
    );
    await root.getByPlaceholder("执行 ID 或场景 ID").fill("does-not-exist");
    await root.getByText("没有符合条件的执行记录", { exact: true }).waitFor();
    await screen("execution-empty-filter");
    await nav("报文样本");
    await page.setViewportSize({ width: 390, height: 1050 });
    for (const operation of [
      "field",
      "overwrite",
      "insert",
      "delete",
      "padding",
      "inspect",
    ]) {
      await root.getByLabel("编辑操作").selectOption(operation);
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth > innerWidth + 1,
        ),
        false,
        `sample ${operation} overflows`,
      );
    }
    // All main views and dialogs fit viewport; horizontal table scrolling stays local.
    for (const width of [1440, 1024, 390]) {
      await page.setViewportSize({ width, height: 1050 });
      for (const name of [
        "场景工作台",
        "报文样本",
        "远端主机",
        "执行历史",
        "设置",
      ]) {
        await nav(name);
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth + 1,
          ),
          false,
          `${name} overflows ${width}`,
        );
        await screen(`${name}-${width}`);
      }
      await nav("场景工作台");
      await root
        .getByRole("navigation", { name: "场景步骤" })
        .getByRole("button", { name: /报文配置/ })
        .click();
      for (const name of ["报文序列", "协议字段", "异常规则"]) {
        await click(name);
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth + 1,
          ),
          false,
          `${name} overflows ${width}`,
        );
        await screen(`${name}-${width}`);
      }
      await root
        .getByRole("navigation", { name: "场景步骤" })
        .getByRole("button", { name: /执行配置/ })
        .click();
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth > innerWidth + 1,
        ),
        false,
        `listen overflows ${width}`,
      );
      await screen(`listen-${width}`);
      await click("＋ 新建场景");
      assert.equal(
        await dialog.evaluate((e) => e.scrollWidth > e.clientWidth + 1),
        false,
        `dialog overflows ${width}`,
      );
      await screen(`dialog-${width}`);
      await page.keyboard.press("Escape");
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(unexpected, []);
    console.log(
      "PASS: packet save/retry, protocol, mutation, direct/listen, validation, send gate, progress/history, hosts/NIC/offload gate, sample edit/discard/templates, 9 views × 3 widths and dialogs; no page errors; no real network operations.",
    );
  } catch (e) {
    await screen("failure");
    throw e;
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
