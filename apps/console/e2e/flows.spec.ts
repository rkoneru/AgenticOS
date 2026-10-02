import { expect, test } from "@playwright/test";
import {
  API,
  SEED_APPROVAL,
  SEED_RUN,
  SELF_APPROVAL,
  axeClean,
  login,
  resetMock,
  tamper,
} from "./helpers";

test.beforeEach(async () => {
  await resetMock();
});

test("unauthenticated visits are sent to sign-in and come back after SSO", async ({ page }) => {
  await page.goto("/approvals");
  await expect(page).toHaveURL(/\/login\?return_to=%2Fapprovals/);
  await page.getByLabel("Organization").fill("acme");
  await page.getByLabel(/sign in as role/i).selectOption("builder");
  await page.getByRole("button", { name: "Continue with SSO" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByRole("heading", { name: "Approvals", level: 1 })).toBeVisible();
});

test("a hostile return_to never leaves the site", async ({ page }) => {
  await page.goto("/login?return_to=//evil.example");
  await expect(page.locator('input[name="return_to"]')).toHaveValue("/");
});

test("navigation is role-aware (viewer has no Admin or Audit)", async ({ page }) => {
  await login(page, "viewer");
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("link", { name: "Runs" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Admin" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Audit" })).toHaveCount(0);
  await expect(page.getByRole("form", { name: "Start a run" })).toHaveCount(0);
});

test("blueprint editor: live diagnostics with line/column, then publish", async ({ page }) => {
  await login(page, "admin", "/blueprints/new");
  const editor = page.getByLabel("ABL (YAML)");
  await expect(page.getByTestId("abl-status")).toContainText("Valid");
  const original = await editor.inputValue();
  await editor.fill(
    original
      .replace("level: minimal", "level: tiny")
      .replace("name: hello-agent", "name: second-agent"),
  );
  const diag = page.getByRole("list", { name: "Diagnostics" });
  await expect(diag).toContainText(/\d+:\d+/);
  await expect(diag).toContainText("error");
  await expect(page.getByRole("button", { name: "Publish version" })).toBeDisabled();
  await editor.fill(original.replace("name: hello-agent", "name: second-agent"));
  await expect(page.getByTestId("abl-status")).toContainText("Valid");
  await page.getByRole("button", { name: "Publish version" }).click();
  await expect(page).toHaveURL(/\/blueprints\/second-agent\/1\.0\.0$/);
  await expect(page.getByRole("heading", { name: "second-agent @ 1.0.0" })).toBeVisible();
});

test("publishing an existing immutable version surfaces the server's conflict", async ({
  page,
}) => {
  await login(page, "admin", "/blueprints/new");
  await expect(page.getByTestId("abl-status")).toContainText("Valid");
  await page.getByRole("button", { name: "Publish version" }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("already published");
});

test("start a run, watch it stream live, then scrub the replay", async ({ page }) => {
  await login(page, "builder");
  await page.getByLabel("Blueprint").selectOption("hello-agent@1.0.0");
  await page.getByRole("button", { name: "Start run" }).click();
  await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  const timeline = page.getByRole("list", { name: "Run events" });
  await expect(timeline).toContainText("state_transition");
  // Events arrive over SSE; the run terminates by itself.
  await expect(page.getByTestId("replay-pos")).toHaveText("6 / 6", { timeout: 15_000 });
  await expect(page.getByTestId("gauge-tokens")).toContainText("1.3k".replace("1.3k", "1300"));
  // Scrub back to event 2: state is "running" and only one model call has happened.
  const slider = page.getByLabel("Event", { exact: true });
  await slider.fill("2");
  await expect(page.getByTestId("replay-pos")).toHaveText("2 / 6");
  const state = page.getByTestId("replay-state");
  await expect(state).toContainText("running");
  await expect(state.locator("div").filter({ hasText: "Model calls" })).toContainText("1");
  await expect(timeline.getByRole("listitem")).toHaveCount(2);
  await page.getByRole("button", { name: "Jump to live" }).click();
  await expect(page.getByTestId("replay-pos")).toHaveText("6 / 6");
  await expect(page.getByTestId("agil-panel")).toContainText("completed its work");
});

test("approvals: detail shows evidence, confirm dialog, approve", async ({ page }) => {
  await login(page, "builder", "/approvals");
  await page.getByRole("link", { name: SEED_APPROVAL.slice(0, 8) }).click();
  await expect(page.getByTestId("args-hash")).toHaveText("e".repeat(64));
  await expect(page.getByTestId("policy-reason")).toHaveText("external write needs approval");
  await expect(page.getByTestId("sla")).toContainText("left");
  await expect(page.getByTestId("agil-panel")).toContainText("human decision");
  await page.getByRole("button", { name: "Approve..." }).click();
  const dlg = page.getByRole("dialog", { name: "Approve this action?" });
  await expect(dlg).toBeVisible();
  await dlg.getByRole("button", { name: "Confirm approval" }).click();
  await expect(page.getByText("Decided:")).toBeVisible();
  await expect(page.getByText("Decided:")).toContainText("approved");
});

test("approvals: deny path", async ({ page }) => {
  await login(page, "builder", `/approvals/${SEED_APPROVAL}`);
  await page.getByLabel(/Comment/).fill("not this time");
  await page.getByRole("button", { name: "Deny..." }).click();
  await page.getByRole("button", { name: "Confirm denial" }).click();
  await expect(page.getByText("Decided:")).toContainText("rejected");
});

test("approvals: self-approval is disabled in the UI and refused by the server", async ({
  page,
}) => {
  await login(page, "admin", `/approvals/${SELF_APPROVAL}`);
  await expect(page.getByRole("button", { name: "Approve..." })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Deny..." })).toBeDisabled();
  await expect(page.getByRole("note")).toContainText(
    "cannot approve or deny a request made on your own behalf",
  );
  // Bypass the UI: the server must still refuse.
  const status = await page.evaluate(async (id) => {
    const csrf = document.cookie
      .split("; ")
      .find((c) => c.startsWith("__Host-axis_csrf="))!
      .split("=")[1]!;
    const r = await fetch(`/api/axis/v1/approvals/${id}/decision`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-axis-csrf": csrf },
      body: JSON.stringify({ decision: "approve" }),
    });
    return r.status;
  }, SELF_APPROVAL);
  expect(status).toBe(403);
});

test("viewer cannot decide approvals (hidden) and the server agrees", async ({ page }) => {
  await login(page, "viewer", `/approvals/${SEED_APPROVAL}`);
  await expect(page.getByText("Your role cannot decide approvals.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve..." })).toHaveCount(0);
});

test("policies: run test cases, then review diff and activate", async ({ page }) => {
  await login(page, "admin", "/policies");
  await page.getByRole("button", { name: "Run tests" }).click();
  await expect(page.getByTestId("policy-results")).toContainText("2 of 2 passed");
  // The sample policy lacks the expected apiVersion; make the case set fail to prove failures are shown.
  await page.getByLabel(/^Cases/).fill(
    JSON.stringify([
      {
        name: "write is denied",
        request: { enforcement_point: "tool_call", context: { tool: { side_effects: "write" } } },
        expect: "ALLOW",
      },
    ]),
  );
  await page.getByRole("button", { name: "Run tests" }).click();
  await expect(page.getByTestId("policy-results")).toContainText("0 of 1 passed");
  await expect(page.getByTestId("policy-results")).toContainText("fail");

  await page.getByRole("button", { name: "Review and activate" }).click();
  const dlg = page.getByRole("dialog");
  await expect(dlg.getByRole("figure", { name: "Policy changes" })).toContainText("allow-read");
  await expect(dlg.locator('[data-kind="add"]').first()).toBeVisible();
  await dlg.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByRole("row", { name: /baseline-deny 2 active/ })).toBeVisible();
});

test("policies: invalid documents are rejected with server detail and a builder cannot publish", async ({
  page,
}) => {
  await login(page, "admin", "/policies");
  await page.getByLabel(/^Policy \(JSON/).fill("{}");
  await page.getByRole("button", { name: "Run tests" }).click();
  await expect(page.getByTestId("policy-results")).toContainText("Policy failed validation");
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("**/login**");
  await login(page, "builder", "/policies");
  await expect(page.getByRole("button", { name: "Publish pack version" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Review and activate" })).toHaveCount(0);
});

test("audit: verify shows server and in-browser verdicts; tampering is detected by both", async ({
  page,
}) => {
  await login(page, "auditor", "/audit");
  await expect(page.getByRole("table", { name: "Audit events" })).toContainText("kb.search");
  await page.getByRole("button", { name: "Verify hash chain" }).click();
  const out = page.getByTestId("verify-result");
  await expect(out).toContainText("Server: verified 5 events");
  await expect(out).toContainText("This browser: consistent");
  await tamper();
  await page.getByRole("button", { name: "Verify hash chain" }).click();
  await expect(out).toContainText("BROKEN");
  await expect(out).toContainText("INCONSISTENT");
  await expect(out).toContainText("seq 3");
});

test("audit: trace filter, details and a denial explanation", async ({ page }) => {
  await login(page, "admin", "/audit");
  await page.getByLabel("Decision").selectOption("DENY");
  await expect(page.getByRole("table", { name: "Audit events" }).getByRole("row")).toHaveCount(2);
  await page.getByRole("button", { name: "Details for event 3" }).click();
  await expect(page.getByTestId("audit-detail")).toContainText("Previous hash");
  await expect(page.getByTestId("audit-detail").getByTestId("agil-panel")).toContainText(/deny/);
  await page.getByLabel("Trace ID").fill("nothex");
  await expect(page.getByText("32 lowercase hex")).toBeVisible();
});

test("admin: API key secret is shown exactly once", async ({ page }) => {
  await login(page, "admin", "/admin");
  await page.getByRole("tab", { name: "API keys" }).click();
  await page.getByLabel("Key name").fill("deploy-bot");
  await page.getByRole("button", { name: "Create key" }).click();
  const dlg = page.getByRole("dialog", { name: "Copy your API key now" });
  const secret = (await dlg.getByTestId("api-key-secret").textContent())!;
  expect(secret).toMatch(/^axk_[0-9a-f]{16}_[A-Za-z0-9_-]{40,}$/);
  await dlg.getByRole("button", { name: "I have stored it" }).click();
  await expect(dlg).toHaveCount(0);
  await expect(page.getByRole("row", { name: /deploy-bot/ })).toBeVisible();
  // The secret is gone from the page and from a fresh listing.
  await expect(page.locator("body")).not.toContainText(secret);
  await page.reload();
  await page.getByRole("tab", { name: "API keys" }).click();
  await expect(page.locator("body")).not.toContainText(secret);
  const listing = await page.evaluate(async () =>
    (await fetch("/api/axis/admin/v1/api-keys")).text(),
  );
  expect(listing).not.toContain(secret.split("_")[2]!);
});

test("admin: BYO model keys are write-only", async ({ page }) => {
  await login(page, "admin", "/admin");
  await page.getByRole("tab", { name: "Model keys" }).click();
  await page.getByLabel("Provider", { exact: true }).fill("openai");
  await page.getByLabel("Key value").fill("sk-live-super-secret-value-123456");
  await page.getByRole("button", { name: "Save key" }).click();
  await expect(page.getByRole("row", { name: /openai/ })).toBeVisible();
  await expect(page.getByLabel("Key value")).toHaveValue("");
  await expect(page.locator("body")).not.toContainText("super-secret-value");
});

test("admin: budgets validate soft <= hard and members are managed; builder sees no member tab", async ({
  page,
}) => {
  await login(page, "admin", "/admin");
  await page.getByRole("tab", { name: "Budgets" }).click();
  await page.getByLabel("Soft limit").fill("10");
  await page.getByLabel("Hard limit").fill("5");
  await page.getByRole("button", { name: "Add budget" }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("soft limit cannot exceed");
  await page.getByLabel("Hard limit").fill("20");
  await page.getByRole("button", { name: "Add budget" }).click();
  await expect(page.getByRole("row", { name: /tenant cost_usd month 10 20/ })).toBeVisible();
  await page.getByRole("tab", { name: "Members" }).click();
  await page.getByLabel("Email").fill("new@acme.test");
  await page.getByRole("button", { name: "Invite" }).click();
  await expect(page.getByRole("row", { name: /new@acme.test/ })).toBeVisible();
  await page.getByRole("tab", { name: "SSO, SCIM and region" }).click();
  await expect(page.getByText("us-east-1", { exact: true })).toBeVisible();
  await expect(page.getByText("Only the tenant owner can change SSO settings.")).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("**/login**");
  await login(page, "builder", "/admin");
  await expect(page.getByRole("tab", { name: "Members" })).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "API keys" })).toBeVisible();
});

test("marketplace: install requires consent to the permission diff", async ({ page }) => {
  await login(page, "admin", "/marketplace");
  await page.getByRole("link", { name: "CRM Agent" }).click();
  await page.getByRole("button", { name: "Install..." }).click();
  const dlg = page.getByRole("dialog", { name: "Install CRM Agent?" });
  const diff = dlg.getByTestId("permission-diff");
  await expect(diff).toContainText("crm.update");
  await expect(diff).toContainText("api.crm.example");
  await expect(diff).toContainText("pii");
  const go = dlg.getByRole("button", { name: "Grant and install" });
  await expect(go).toBeDisabled();
  await dlg.getByRole("checkbox").check();
  await go.click();
  await expect(page.getByText("installed, no new permissions")).toBeVisible();
});

test("marketplace: a builder cannot install", async ({ page }) => {
  await login(page, "builder", "/marketplace/crm-agent");
  await expect(page.getByText("Your role cannot install listings")).toBeVisible();
});

test("evals shows a graceful not-implemented state", async ({ page }) => {
  await login(page, "admin", "/evals");
  await expect(page.getByRole("heading", { name: "Evals are not available yet" })).toBeVisible();
});

test("usage: meters, chart and table view", async ({ page }) => {
  await login(page, "billing", "/usage");
  await expect(page.getByTestId("total-tokens")).toHaveText("52.3k".length ? "52.3k" : "");
  const chart = page.getByTestId("usage-chart");
  await expect(chart.getByRole("img", { name: /tokens per day: 14 periods/ })).toBeVisible();
  await chart.getByRole("button", { name: "Show table" }).click();
  await expect(chart.getByRole("table")).toContainText("Period");
});

test("security: CSP, headers, CSRF and the BFF allow-list", async ({ page, request }) => {
  const res = await page.goto("/login");
  const h = res!.headers();
  expect(h["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(h["content-security-policy"]).toContain("object-src 'none'");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBeTruthy();
  await login(page, "admin", "/runs");
  const r = await page.evaluate(async () => {
    const csrf = document.cookie
      .split("; ")
      .find((c) => c.startsWith("__Host-axis_csrf="))!
      .split("=")[1]!;
    const noToken = await fetch("/api/axis/v1/kill-switches", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scope: "tenant", engaged: true }),
    });
    const wrongToken = await fetch("/api/axis/v1/kill-switches", {
      method: "PUT",
      headers: { "content-type": "application/json", "x-axis-csrf": "wrong" },
      body: JSON.stringify({ scope: "tenant", engaged: true }),
    });
    const internal = await fetch("/api/axis/dev/session", {
      method: "POST",
      headers: { "x-axis-csrf": csrf },
    });
    const traversal = await fetch("/api/axis/v1/%2e%2e/dev/session");
    const ok = await fetch("/api/axis/v1/kill-switches", {
      method: "PUT",
      headers: { "content-type": "application/json", "x-axis-csrf": csrf },
      body: JSON.stringify({ scope: "tenant", engaged: false }),
    });
    return [noToken.status, wrongToken.status, internal.status, traversal.status, ok.status];
  });
  expect(r).toEqual([403, 403, 404, 404, 200]);
  // Cross-origin POST with the user's cookies (as a forged form would) is refused before reaching the API.
  const cross = await request.post("/api/axis/v1/kill-switches", {
    headers: { origin: "https://evil.example", "content-type": "application/json" },
    data: { scope: "tenant", engaged: true },
  });
  expect(cross.status()).toBe(403);
  const direct = await request.get(`${API}/v1/runs`);
  expect(direct.status()).toBe(401);
});

test("XSS: untrusted tool/model/policy text is rendered inert everywhere", async ({ page }) => {
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await login(page, "admin", `/runs/${SEED_RUN}`);
  await expect(page.getByRole("list", { name: "Run events" })).toContainText(
    '<img src=x onerror="window.__xss=1">',
  );
  await expect(page.getByTestId("agil-panel").first()).toContainText(
    "<script>window.__xss=2</script>",
  );
  await page.goto("/audit");
  await page.getByRole("button", { name: "Details for event 3" }).click();
  await expect(page.getByTestId("audit-detail")).toContainText("<img src=x");
  for (const url of [`/runs/${SEED_RUN}`, "/audit", "/approvals"]) {
    await page.goto(url);
    await page.waitForLoadState("networkidle");
    expect(await page.locator("main img[src='x'], main script:not([src])").count(), url).toBe(0);
    expect(
      await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss),
      url,
    ).toBeUndefined();
  }
  expect(dialogs).toEqual([]);
});

const PAGES: Array<[string, string, string]> = [
  ["login", "/login", "admin"],
  ["blueprints", "/blueprints", "admin"],
  ["blueprint editor", "/blueprints/new", "admin"],
  ["blueprint version", "/blueprints/hello-agent/1.0.0", "admin"],
  ["runs", "/runs", "admin"],
  ["run", `/runs/${SEED_RUN}`, "admin"],
  ["approvals", "/approvals", "admin"],
  ["approval", `/approvals/${SEED_APPROVAL}`, "builder"],
  ["policies", "/policies", "admin"],
  ["evals", "/evals", "admin"],
  ["audit", "/audit", "admin"],
  ["usage", "/usage", "admin"],
  ["admin", "/admin", "admin"],
  ["marketplace", "/marketplace", "admin"],
  ["listing", "/marketplace/crm-agent", "admin"],
];

for (const theme of ["light", "dark"] as const) {
  for (const [label, url, role] of PAGES) {
    test(`a11y (${theme}): ${label}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme });
      if (label !== "login") await login(page, role, "/runs");
      await page.goto(url);
      await page.waitForLoadState("networkidle");
      await expect(page.locator("main").first()).toBeVisible();
      await page.waitForTimeout(200);
      await axeClean(page, `${label} (${theme})`);
    });
  }
}

test("keyboard: skip link and tab order reach the main landmark", async ({ page }) => {
  await login(page, "admin", "/runs");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
});

test("responsive: phone width has a menu and no horizontal scroll", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await login(page, "admin", "/runs");
  await expect(page.getByRole("button", { name: "Menu" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeHidden();
  await page.getByRole("button", { name: "Menu" }).click();
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
});

test("dark mode toggle persists", async ({ page }) => {
  await login(page, "admin", "/runs");
  await page.getByRole("button", { name: /^Theme:/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});
