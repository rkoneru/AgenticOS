import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { parse } from "yaml";

/**
 * The console against the REAL stack: SSO through the control plane (fake IdP page), the real gateway, the real Risk Kernel, the run
 * service with a scripted model, AGIL, the registry and the marketplace. Nothing here is mocked. The registry publish is done with the
 * `axis` CLI because signing needs the publisher's private key, which never enters a browser.
 */
const S = JSON.parse(readFileSync(process.env["STACK_JSON"] ?? "stack.json", "utf8")) as {
  gateway: string;
  ops_url: string;
  ops_token: string;
  console_origin: string;
  byo_key: string;
};
const ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const CLI = join(ROOT, "apps/cli/dist/bin.js");
const doc = (p: string): unknown => parse(readFileSync(join(ROOT, p), "utf8"));
const PACK = doc("e2e/policies/phase7-interfaces/pack.yaml");
const HELPER = doc("e2e/agents/helper7.abl.yaml");

async function ops<T = Record<string, unknown>>(name: string, body: object = {}): Promise<T> {
  const r = await fetch(`${S.ops_url}/ops/${name}`, {
    method: "POST",
    headers: { authorization: `Bearer ${S.ops_token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`ops ${name}: ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

const rid = Math.random()
  .toString(36)
  .slice(2, 8)
  .replace(/[^a-z]/g, "k");
const A = { slug: `ca${rid}`, id: "", key: "", org: "", owner: "" };
const B = { slug: `cb${rid}`, id: "", key: "", org: "", owner: "" };
const NS = `pub-console-${rid}`;
const work = mkdtempSync(join(tmpdir(), "axis-console-e2e-"));
let ctxA: BrowserContext;
let ctxB: BrowserContext;
let page: Page;
let pageB: Page;
let runId = "";

function cli(key: string, ...argv: string[]): string {
  return execFileSync("node", [CLI, ...argv], {
    env: {
      ...process.env,
      AXIS_API_KEY: key,
      AXIS_BASE_URL: S.gateway,
      XDG_CONFIG_HOME: join(work, "cfg"),
      NO_COLOR: "1",
    },
    encoding: "utf8",
  });
}

async function sso(p: Page, org: string, returnTo = "/runs"): Promise<void> {
  await p.goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
  await p.getByLabel("Organization").fill(org);
  await p.getByRole("button", { name: "Continue with SSO" }).click();
  await p.waitForURL(`**${returnTo.split("?")[0]}**`);
}

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser }) => {
  for (const t of [A, B]) {
    const r = await ops<{ tenant_id: string; org: string; owner_member_id: string }>(
      "provision-tenant",
      { slug: t.slug, byo_key: S.byo_key },
    );
    t.id = r.tenant_id;
    t.org = r.org;
    t.owner = r.owner_member_id;
    t.key = (
      await ops<{ secret: string }>("api-key", {
        tenant_id: t.id,
        member_id: t.owner,
        scopes: ["*"],
      })
    ).secret;
  }
  ctxA = await browser.newContext();
  ctxB = await browser.newContext();
  page = await ctxA.newPage();
  pageB = await ctxB.newPage();
});
test.afterAll(async () => {
  await ctxA?.close();
  await ctxB?.close();
});

test("sign in through SSO (real control plane, fake IdP): the session shows the tenant and role from the server", async () => {
  await sso(page, A.org);
  await expect(page.getByRole("heading", { name: "Runs", level: 1 })).toBeVisible();
  await expect(page.getByText(`Tenant ${A.slug}`).first()).toBeVisible();
  await expect(page.getByText("owner").first()).toBeVisible();
  // the access token is HttpOnly: page scripts cannot read it
  const cookies = await ctxA.cookies();
  expect(cookies.find((c) => c.name === "__Host-axis_at")?.httpOnly).toBe(true);
  expect(await page.evaluate(() => document.cookie)).not.toContain("__Host-axis_at");
});

test("policy: publish with the CLI, review and activate in the console", async () => {
  const f = join(work, "pack.json");
  writeFileSync(f, JSON.stringify(PACK));
  cli(A.key, "policies", "publish", f);
  await page.goto("/policies");
  const row = page.getByRole("row", { name: /tenant-claims/ });
  await expect(row).toContainText("inactive");
  await row.getByRole("button", { name: "Review and activate" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Activate", exact: true }).click();
  await expect(page.getByRole("row", { name: /tenant-claims/ })).toContainText("active");
  await expect(page.getByRole("row", { name: /tenant-claims/ })).not.toContainText("inactive");
});

test("blueprint: live ABL validation, then publish and view the version", async () => {
  await page.goto("/blueprints/new");
  const editor = page.getByLabel("ABL (YAML)");
  const claims = readFileSync(join(ROOT, "e2e/agents/claims7.abl.yaml"), "utf8");
  await editor.fill(claims.replace("level: limited", "level: tiny"));
  await expect(page.getByRole("list", { name: "Diagnostics" })).toContainText("error");
  await expect(page.getByRole("button", { name: "Publish version" })).toBeDisabled();
  await editor.fill(claims);
  await expect(page.getByTestId("abl-status")).toContainText("Valid");
  await page.getByRole("button", { name: "Publish version" }).click();
  await expect(page).toHaveURL(/\/blueprints\/claims-agent\/1\.0\.0$/);
});

test("registry: a CLI-signed blueprint resolves in the console with the server's verification", async () => {
  const key = join(work, "publisher.pem");
  const kg = JSON.parse(cli(A.key, "--json", "registry", "keygen", "--out", key)) as {
    public_key: string;
  };
  cli(A.key, "registry", "claim", NS);
  cli(A.key, "registry", "add-key", NS, "--public-key", kg.public_key);
  await new Promise((r) => setTimeout(r, 1200)); // a signature is trusted from the moment its key is valid
  const abl = join(work, "helper.json");
  writeFileSync(abl, JSON.stringify(HELPER));
  cli(A.key, "registry", "publish", abl, "--namespace", NS, "--key", key);
  await page.goto("/registry");
  await expect(page.getByRole("list", { name: "Namespaces" })).toContainText(NS);
  await page.getByLabel(/Reference/).fill(`${NS}/helper-agent@^1`);
  await page.getByRole("button", { name: "Resolve" }).click();
  const out = page.getByTestId("resolved");
  await expect(out).toContainText("verified");
  await expect(out).toContainText("helper-agent@1.0.0");
  await expect(out).toContainText("k1-");
  // a reference nobody owns is a plain not-found, not a verification claim
  await page.getByLabel(/Reference/).fill(`nobody-here/helper-agent@^1`);
  await page.getByRole("button", { name: "Resolve" }).click();
  await expect(page.getByTestId("resolved")).toHaveCount(0);
});

test("marketplace: a second tenant sees the permission diff, must consent, and installs", async () => {
  await ops("mp/publisher-verify", { tenant_id: A.id });
  await ops("mp/review-and-list", {
    tenant_id: A.id,
    namespace: NS,
    name: "helper-agent",
    version: "1.0.0",
    title: "Helper Agent",
  });
  await sso(pageB, B.org, "/marketplace");
  await expect(pageB.getByRole("link", { name: "Helper Agent" })).toBeVisible();
  await pageB.getByRole("link", { name: "Helper Agent" }).click();
  await pageB.getByRole("button", { name: "Install..." }).click();
  const dlg = pageB.getByRole("dialog", { name: "Install Helper Agent?" });
  await expect(dlg.getByTestId("permission-diff")).toContainText("model:anthropic");
  const go = dlg.getByRole("button", { name: "Grant and install" });
  await expect(go).toBeDisabled(); // no consent, no install
  await dlg.getByRole("checkbox").check();
  await go.click();
  await expect(pageB.getByText("installed", { exact: true })).toBeVisible();
  // the publisher tenant has no install of its own listing
  await page.goto("/marketplace");
  await expect(page.getByText("installed", { exact: true })).toHaveCount(0);
});

async function startRun(p: Page, prompt: string): Promise<string> {
  await p.goto("/runs");
  await p.getByLabel("Blueprint").selectOption("claims-agent@1.0.0");
  await p.getByLabel("Input (JSON object)").fill(JSON.stringify({ prompt }));
  await p.getByRole("button", { name: "Start run" }).click();
  await expect(p).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  return p.url().split("/").pop() as string;
}

test("run: live events over SSE, a REQUIRE_APPROVAL appears, approve, the run completes, replay works", async () => {
  runId = await startRun(page, "review claim 42");
  const timeline = page.getByRole("list", { name: "Run events" });
  await expect(timeline).toContainText("process_spawned");
  await page.goto("/approvals");
  await page
    .getByRole("link", { name: /^[0-9a-f]{8}$/ })
    .first()
    .click();
  await expect(page.getByText("file-payout").first()).toBeVisible();
  await expect(page.getByTestId("agil-panel")).toBeVisible();
  await page.getByRole("button", { name: "Approve..." }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm approval" }).click();
  await expect(page.getByText("Decided:")).toContainText("approved");
  await page.goto(`/runs/${runId}`);
  await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
  await expect(timeline).toContainText("process_output");
  // replay: scrub back to an early event
  const slider = page.getByLabel("Event", { exact: true });
  await slider.fill("3");
  await expect(page.getByTestId("replay-pos")).toHaveText(/^3 \/ \d+$/);
  await expect(page.getByTestId("agil-panel").first()).toContainText(
    /payout|file-payout|approval|gated/i,
  );
});

test("run: deny means the action never runs", async () => {
  const id = await startRun(page, "review claim 43");
  await page.goto("/approvals?status=pending");
  await page
    .getByRole("link", { name: /^[0-9a-f]{8}$/ })
    .first()
    .click();
  await page.getByLabel(/Comment/).fill("not this one");
  await page.getByRole("button", { name: "Deny..." }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm denial" }).click();
  await expect(page.getByText("Decided:")).toContainText("rejected");
  await page.goto(`/runs/${id}`);
  await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
  await expect(page.getByRole("list", { name: "Run events" })).not.toContainText('"filed":true');
});

test("audit explorer: events, server and in-browser chain verification, AGIL on a denial", async () => {
  await startRun(page, "restricted 9").then(async (id) => {
    await page.goto(`/runs/${id}`);
    await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
    await expect(page.getByTestId("agil-panel").first()).toContainText(/lookup-restricted|denied/i);
  });
  await page.goto("/audit");
  await expect(page.getByRole("table").first()).toContainText("DENY");
  await page.getByRole("button", { name: "Verify hash chain" }).click();
  const res = page.getByTestId("verify-result");
  await expect(res).toContainText("Server:");
  await expect(res).toContainText("verified");
  await expect(res).not.toContainText("BROKEN");
});

test("usage shows metered tokens", async () => {
  await expect
    .poll(
      async () => {
        await page.goto("/usage");
        return (
          (await page.locator("main").innerText()).match(/tokens/i) !== null &&
          !/no usage/i.test(await page.locator("main").innerText())
        );
      },
      { timeout: 30_000 },
    )
    .toBe(true);
});

test("kill switch: engage stops the next action, release restores it", async () => {
  await page.goto("/kill-switch");
  await page.getByLabel(/Reason/).fill("console drill");
  await page.getByRole("button", { name: /Engage the tenant kill switch/ }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Engage", exact: true }).click();
  await expect(page.getByTestId("ks-state")).toHaveText("ENGAGED");
  const id = await startRun(page, "hello there");
  await page.goto(`/runs/${id}`);
  await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
  await expect(page.getByRole("list", { name: "Run events" })).toContainText(
    /DENY|denied|blocked|kill/i,
  );
  await page.goto("/kill-switch");
  await page.getByRole("button", { name: /Release the tenant kill switch/ }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Release", exact: true }).click();
  await expect(page.getByTestId("ks-state")).toHaveText("released");
  const ok = await startRun(page, "hello again");
  await page.goto(`/runs/${ok}`);
  await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
  await expect(page.getByRole("list", { name: "Run events" })).toContainText("echo: hello again");
});

test("XSS: hostile run output is rendered as inert text against the real backend", async () => {
  const id = await startRun(page, "xss please");
  await page.goto(`/runs/${id}`);
  await expect(page.getByTestId("replay-pos")).toHaveText(/(\d+) \/ \1/, { timeout: 60_000 });
  await expect(page.getByRole("list", { name: "Run events" })).toContainText("<img src=x");
  expect(
    await page.evaluate(() => (window as unknown as { __xss?: number }).__xss),
  ).toBeUndefined();
  expect(await page.locator("main img[src='x'], main script").count()).toBe(0);
});

test("CSRF: the BFF refuses state changes without the double-submit token or from another origin", async () => {
  const body = { blueprint: { name: "claims-agent", version: "1.0.0" }, input: { prompt: "csrf" } };
  const csrf = (await ctxA.cookies()).find((c) => c.name === "__Host-axis_csrf")?.value ?? "";
  const none = await ctxA.request.post("/api/axis/v1/runs", { data: body });
  expect(none.status()).toBe(403);
  const wrong = await ctxA.request.post("/api/axis/v1/runs", {
    data: body,
    headers: { "x-axis-csrf": "nope" },
  });
  expect(wrong.status()).toBe(403);
  const foreign = await ctxA.request.post("/api/axis/v1/runs", {
    data: body,
    headers: { "x-axis-csrf": csrf, origin: "http://evil.example" },
  });
  expect(foreign.status()).toBe(403);
});

test("the console does not trust a client-supplied tenant, and one tenant cannot reach another's data", async () => {
  const csrfB = (await ctxB.cookies()).find((c) => c.name === "__Host-axis_csrf")?.value ?? "";
  // B's session, with A's tenant id in a header and a query parameter: the credential decides
  const r = await ctxB.request.get(`/api/axis/v1/runs?tenant_id=${A.id}`, {
    headers: { "x-tenant-id": A.id },
  });
  expect(r.status()).toBe(422); // the gateway refuses a tenant in the query; the header never reaches it
  const own = await ctxB.request.get("/api/axis/v1/runs", { headers: { "x-tenant-id": A.id } });
  expect(own.status()).toBe(200);
  expect(JSON.stringify(await own.json())).not.toContain(runId);
  const a = await ctxB.request.get(`/api/axis/v1/runs/${runId}`);
  expect(a.status()).toBe(404);
  const ev = await ctxB.request.get(`/api/axis/v1/runs/${runId}/events`);
  expect(ev.status()).toBe(404);
  const me = await (await ctxB.request.get("/api/axis/v1/me")).json();
  expect(me.tenant.id).toBe(B.id);
  void csrfB;
  // the page for A's run, opened by B, shows an error and none of A's events
  await pageB.goto(`/runs/${runId}`);
  await expect(pageB.locator("main")).not.toContainText("process_spawned");
});

test("no secrets or server addresses in the client bundle served by the real stack", async ({
  request,
}) => {
  const sentinels = [new URL(S.gateway).host, S.byo_key, A.key, B.key, S.ops_token];
  const html = await (await request.get("/login")).text();
  const assets = [...html.matchAll(/(?:src|href)="(\/_next\/static\/[^"]+\.(?:js|css))"/g)].map(
    (m) => m[1] as string,
  );
  expect(assets.length).toBeGreaterThan(0);
  for (const a of assets) {
    const body = await (await request.get(a)).text();
    for (const x of sentinels) expect(body, `${a} contains a server-only value`).not.toContain(x);
  }
  for (const x of sentinels) expect(html).not.toContain(x);
});
