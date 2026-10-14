import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

/**
 * The data-governance pages on the REAL stack: requests, holds and a retention dry run written through the real gateway (governance kit on
 * Postgres with forced RLS and the tenant's audit chain), read in the console after SSO through the real control plane as the privacy
 * officer. Identifiers are never shown, hostile text is inert, another tenant sees nothing, and a builder is refused.
 */
const S = JSON.parse(readFileSync(process.env["STACK_JSON"] ?? "stack.json", "utf8")) as {
  gateway: string;
  ops_url: string;
  ops_token: string;
  byo_key: string;
};
const XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>';

async function ops<T = Record<string, unknown>>(name: string, body: object = {}): Promise<T> {
  const r = await fetch(`${S.ops_url}/ops/${name}`, {
    method: "POST",
    headers: { authorization: `Bearer ${S.ops_token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`ops ${name}: ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

async function api<T = Record<string, unknown>>(
  key: string,
  method: string,
  path: string,
  body?: object,
): Promise<T> {
  const r = await fetch(`${S.gateway}${path}`, {
    method,
    headers: { "x-axis-api-key": key, "content-type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

const rid = Math.random()
  .toString(36)
  .slice(2, 8)
  .replace(/[^a-z]/g, "k");
const A = { slug: `ga${rid}`, id: "", org: "", owner: "" };
const B = { slug: `gb${rid}`, id: "", org: "" };
const SUBJECT_EMAIL = `subject-${rid}@subject.example`;
let poEmail = "";
let builderEmail = "";
let bOwnerEmail = "";
let requestId = "";
let subjectRef = "";
let ctxPo: BrowserContext;
let ctxB: BrowserContext;
let ctxBuilder: BrowserContext;
let page: Page;

async function sso(p: Page, org: string, returnTo: string, email?: string): Promise<void> {
  if (email) await ops("idp/next", { org, email });
  await p.goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
  await p.getByLabel("Organization").fill(org);
  await p.getByRole("button", { name: "Continue with SSO" }).click();
  await p.waitForURL(`**${returnTo.split("?")[0]}**`);
}

async function axe(p: Page, label: string): Promise<void> {
  await p.waitForLoadState("networkidle");
  const r = await new AxeBuilder({ page: p })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`),
    `axe on ${label}`,
  ).toEqual([]);
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
    if (t === A) A.owner = r.owner_member_id;
  }
  const po = await ops<{ member_id: string; email: string }>("member", {
    tenant_id: A.id,
    role: "privacy_officer",
  });
  poEmail = po.email;
  builderEmail = (await ops<{ email: string }>("member", { tenant_id: A.id, role: "builder" }))
    .email;
  bOwnerEmail = (await ops<{ email: string }>("member", { tenant_id: B.id, role: "admin" })).email;
  await ops("member", { tenant_id: A.id, role: "viewer", email: SUBJECT_EMAIL });
  const key = (
    await ops<{ secret: string }>("api-key", { tenant_id: A.id, member_id: po.member_id })
  ).secret;
  const req = await api<{ id: string; subject_ref: string }>(
    key,
    "POST",
    "/governance/dsar-requests",
    { kind: "export", identifiers: [{ kind: "email", value: SUBJECT_EMAIL }] },
  );
  requestId = req.id;
  subjectRef = req.subject_ref;
  await api(key, "POST", "/governance/holds", {
    scope: "case",
    case_ref: "CASE-1",
    reason: `Litigation ${XSS}`,
    groups: [[{ kind: "email", value: SUBJECT_EMAIL }]],
  });
  await api(key, "POST", "/governance/retention-runs", { dry_run: true, classes: ["memory"] });
  ctxPo = await browser.newContext();
  ctxB = await browser.newContext();
  ctxBuilder = await browser.newContext();
  page = await ctxPo.newPage();
});
test.afterAll(async () => {
  await ctxPo?.close();
  await ctxB?.close();
  await ctxBuilder?.close();
});

test("the privacy officer sees the queue; identifiers never appear; hostile text is inert", async () => {
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await sso(page, A.org, "/governance", poEmail);
  await expect(
    page.getByRole("heading", { name: "Data-subject requests", level: 1 }),
  ).toBeVisible();
  await expect(page.getByTestId("governance-note")).toContainText("not a statement");
  const table = page.getByRole("table", { name: "Data-subject requests" });
  await expect(table).toContainText(subjectRef);
  await expect(table).toContainText("received");
  expect(await page.locator("body").innerText()).not.toContain(SUBJECT_EMAIL);
  await axe(page, "requests");
  await page.getByRole("link", { name: requestId.slice(0, 8) }).click();
  await expect(page.getByTestId("request-status")).toContainText("received");
  expect(await page.locator("body").innerText()).not.toContain(SUBJECT_EMAIL);
  await axe(page, "request");
  await page.goto("/governance/holds");
  const holds = page.getByRole("table", { name: "Legal holds" });
  await expect(holds).toContainText("<img src=x");
  await expect(holds).toContainText("CASE-1");
  expect(await page.locator("main img[src='x'], main script:not([src])").count()).toBe(0);
  await axe(page, "holds");
  await page.goto("/governance/retention");
  await expect(page.getByTestId("residency")).toContainText("us-east-1");
  await expect(page.getByRole("table", { name: "Retention periods" })).toContainText("memory");
  await expect(page.getByText("dry run").first()).toBeVisible();
  await axe(page, "retention");
  expect(
    await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss),
  ).toBeUndefined();
  expect(dialogs).toEqual([]);
});

test("another tenant sees none of it", async () => {
  const pageB = await ctxB.newPage();
  await sso(pageB, B.org, "/governance", bOwnerEmail);
  await expect(
    pageB.getByRole("heading", { name: "Data-subject requests", level: 1 }),
  ).toBeVisible();
  await expect(pageB.getByText("No requests yet")).toBeVisible();
  await pageB.goto(`/governance/requests/${requestId}`);
  await expect(pageB.locator("main").getByRole("alert")).toBeVisible();
  await pageB.goto("/governance/holds");
  await expect(pageB.getByText("No holds")).toBeVisible();
});

test("a builder has no navigation entry and the data is refused", async () => {
  const pageC = await ctxBuilder.newPage();
  await sso(pageC, A.org, "/runs", builderEmail);
  await expect(pageC.getByRole("link", { name: "Governance" })).toHaveCount(0);
  await pageC.goto("/governance");
  await expect(pageC.locator("main").getByRole("alert")).toBeVisible();
});
