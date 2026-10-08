// Run with Playwright installed, or PLAYWRIGHT_MODULE pointing at its package.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {}),
    args: ["--no-sandbox"],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const base = process.env.UI_BASE_URL || "http://127.0.0.1:5173";
  const nav = async (p) => {
    await page.goto(base + "/#" + p);
    await page.locator("h1").first().waitFor();
  };
  const saved = () =>
    page.evaluate(() =>
      JSON.parse(localStorage.getItem("pangea.ibmc.demo.v1")),
    );
  const click = async (name) =>
    page.getByRole("button", { name, exact: true }).first().click();
  const screenshot = async (name) => {
    fs.mkdirSync("output/ui", { recursive: true });
    await page.screenshot({ path: `output/ui/${name}.png`, fullPage: true });
  };
  try {
    await nav("/ibmc");
    await click("新建项目");
    await page.getByRole("dialog").getByLabel("项目名称").fill("UI 验收项目");
    await page.getByRole("dialog").getByLabel("产品型号").fill("iBMC");
    await page.getByRole("dialog").getByLabel("固件版本").fill("V3.2");
    await page
      .getByRole("dialog")
      .getByLabel("测试目标")
      .fill("验证权限与会话");
    await click("创建并进入项目 →");
    await page
      .getByRole("heading", { name: "项目工作台", exact: true })
      .waitFor();
    let data = await saved();
    const id = data.projects.find((p) => p.name === "UI 验收项目").id;
    const path = (p) => `/ibmc/${id}/${p}`;
    await nav(path("intake"));
    await click("＋ 添加资料");
    await page.getByRole("dialog").getByLabel("资料名称").fill("权限设计说明");
    await page.getByRole("dialog").getByLabel("适用版本").fill("V3.2");
    await page
      .getByRole("dialog")
      .getByLabel("关键内容与待确认事项")
      .fill("只读用户不得修改配置");
    await click("保存修改");
    await nav(path("risks"));
    await click("＋ 新增风险");
    await page
      .getByRole("dialog")
      .getByLabel("风险模块")
      .fill("权限与接口访问");
    await page
      .getByRole("dialog")
      .getByLabel("纳入理由 / 待验证问题")
      .fill("验证只读角色权限边界");
    await click("保存修改");
    await nav(path("paths"));
    await click("＋ 新增路径");
    await page
      .getByRole("dialog")
      .getByLabel("路径名称")
      .fill("低权限访问管理接口");
    await page
      .getByRole("dialog")
      .getByLabel("测试身份 → 入口 → 权限边界 → 验证目标")
      .fill("只读用户 → 管理接口 → 管理员操作 → 禁止配置变更");
    await page
      .getByRole("dialog")
      .getByLabel("关联方法")
      .selectOption("WEB-AUTHZ");
    await page
      .getByRole("dialog")
      .getByLabel("资料依据")
      .selectOption({ label: "权限设计说明" });
    await click("保存修改");
    await screenshot("paths");
    await click("生成用例草稿 →");
    await page
      .getByRole("heading", { name: "测试用例", exact: true })
      .waitFor();
    await click("审查用例 →");
    const dialog = page.getByRole("dialog");
    assert(await dialog.getByRole("button", { name: "确认设计" }).isDisabled());
    await dialog.getByLabel("审查意见").fill("补充操作前后状态");
    await dialog.getByRole("button", { name: "退回完善" }).click();
    data = await saved();
    assert.equal(
      data.projects.find((p) => p.id === id).cases[0].reviewed,
      false,
    );
    await click("审查用例 →");
    for (const checkbox of await page
      .getByRole("dialog")
      .getByRole("checkbox")
      .all())
      await checkbox.check();
    await screenshot("review");
    await click("确认设计");
    assert.equal(
      (await saved()).projects.find((p) => p.id === id).cases[0].reviews.length,
      2,
    );
    await nav(path("execute"));
    await click("＋ 创建模拟批次");
    data = await saved();
    const before = data.projects.find((p) => p.id === id).runs[0].snapshot;
    await screenshot("execute");
    await click("完成模拟");
    await nav(path("results"));
    await click("查看证据详情");
    await screenshot("evidence");
    await page.keyboard.press("Escape");
    assert.equal(await page.getByRole("dialog").count(), 0);
    await nav(path("design"));
    await click("编辑用例");
    await page
      .getByRole("dialog")
      .getByLabel("前置条件与测试步骤")
      .fill("修改后的步骤");
    await click("保存修改");
    data = await saved();
    let p = data.projects.find((p) => p.id === id);
    assert.equal(p.cases[0].reviewed, false);
    assert.deepEqual(p.runs[0].snapshot, before);
    await nav(path("results"));
    await click("创建模拟复测 →");
    assert.equal(
      (await saved()).projects.find((p) => p.id === id).runs.length,
      1,
    );
    await nav(path("design"));
    await click("审查用例 →");
    for (const checkbox of await page
      .getByRole("dialog")
      .getByRole("checkbox")
      .all())
      await checkbox.check();
    await click("确认设计");
    await nav(path("results"));
    await click("创建模拟复测 →");
    await page
      .getByRole("heading", { name: "执行与挖掘", exact: true })
      .waitFor();
    assert.equal(
      (await saved()).projects.find((p) => p.id === id).runs.length,
      2,
    );
    await page.reload();
    await page
      .getByRole("heading", { name: "执行与挖掘", exact: true })
      .waitFor();
    assert.equal(
      (await saved()).projects.find((p) => p.id === id).runs.length,
      2,
    );
    await nav(path("risks"));
    await page.getByRole("checkbox", { name: "纳入 权限与接口访问" }).uncheck();
    assert.equal(
      (await saved()).projects.find((p) => p.id === id).cases[0].reviewed,
      false,
    );
    for (const width of [1440, 1024, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const section of [
        "overview",
        "intake",
        "risks",
        "paths",
        "design",
        "execute",
        "results",
        "skills",
      ]) {
        await nav(path(section));
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth > window.innerWidth + 1,
        );
        assert.equal(overflow, false, `${section} overflows at ${width}`);
      }
      await nav(path("overview"));
      await screenshot("overview-" + width);
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await nav("/ibmc");
    assert.equal(
      await page.getByRole("navigation", { name: "项目导航" }).count(),
      0,
    );
    await screenshot("projects");
    await nav("/");
    await screenshot("home");
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ json: { items: [] } }),
    );
    await page.getByLabel("切换测试应用").selectOption("packets");
    await page.locator(".app-shell").waitFor();
    assert.equal(
      await page
        .locator(".app-shell")
        .evaluate((e) => getComputedStyle(e).backgroundColor),
      "rgb(245, 247, 249)",
    );
    await page.getByLabel("切换测试应用").selectOption("ibmc");
    await page
      .getByRole("heading", { name: "全部项目", exact: true })
      .waitFor();
    assert.equal(await page.locator(".s-packet-container").isVisible(), false);
    // Dirty dialog dismissals require an explicit discard; cancelled dismissal preserves input.
    await nav(path("intake"));
    await click("＋ 添加资料");
    await page.getByRole("dialog").getByLabel("资料名称").fill("未保存资料");
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "取消", exact: true })
      .click();
    const discard = page.getByRole("dialog", { name: "放弃未保存的修改？" });
    await discard.getByRole("button", { name: "取消", exact: true }).click();
    assert.equal(
      await page.getByRole("dialog").getByLabel("资料名称").inputValue(),
      "未保存资料",
    );
    await page.keyboard.press("Escape");
    await page
      .getByRole("dialog", { name: "放弃未保存的修改？" })
      .getByRole("button", { name: "放弃修改", exact: true })
      .click();
    assert.equal(await page.getByRole("dialog").count(), 0);
    // A concurrent tab update must not be overwritten by this tab's stale store.
    await nav(path("design"));
    await click("编辑用例");
    await page
      .getByRole("dialog")
      .getByLabel("用例名称")
      .fill("本窗口尚未保存的名称");
    await page.evaluate(() => {
      const key = "pangea.ibmc.demo.v1",
        v = JSON.parse(localStorage.getItem(key));
      v.projects[0].goal = "另一窗口的更新";
      localStorage.setItem(key, JSON.stringify(v));
    });
    const concurrent = await saved();
    await click("保存修改");
    await page
      .getByText(
        "另一个页面已修改本地记录。为避免覆盖，请刷新页面读取最新数据后再编辑。",
        { exact: true },
      )
      .waitFor();
    assert.deepEqual(await saved(), concurrent);
    await page.keyboard.press("Escape");
    await page
      .getByRole("dialog", { name: "放弃未保存的修改？" })
      .getByRole("button", { name: "放弃修改", exact: true })
      .click();
    // Preserve corrupt data instead of silently replacing it.
    await page.evaluate(() =>
      localStorage.setItem("pangea.ibmc.demo.v1", '{"broken":true}'),
    );
    await page.reload();
    await page.getByRole("alert").waitFor();
    await nav("/ibmc");
    await click("新建项目");
    await page.getByRole("dialog").getByLabel("项目名称").fill("不能保存");
    await page.getByRole("dialog").getByLabel("产品型号").fill("BMC");
    await page.getByRole("dialog").getByLabel("固件版本").fill("x");
    await click("创建并进入项目 →");
    assert.equal(await page.getByRole("dialog").count(), 1);
    assert.equal(
      await page.evaluate(() => localStorage.getItem("pangea.ibmc.demo.v1")),
      '{"broken":true}',
    );
    assert.deepEqual(errors, []);
    console.log(
      "PASS: create → intake → scope → path → draft → review → simulate → evidence → edit invalidation → retest → reload; corrupt-store protection; 8 routes × 3 viewport widths; no page errors.",
    );
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
