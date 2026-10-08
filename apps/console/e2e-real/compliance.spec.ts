import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { parse } from "yaml";

/**
 * The compliance pages on the REAL stack: records written through the real gateway (compliance service on Postgres with forced RLS,
 * the registry, the audit chain), read in the console after SSO through the real control plane. An auditor (a different member) reviews
 * the owner's assessment. Hostile text in a record is rendered inert, another tenant sees nothing, and the generated document verifies.
 */
const S = JSON.parse(readFileSync(process.env["STACK_JSON"] ?? "stack.json", "utf8")) as {
  gateway: string;
  ops_url: string;
  ops_token: string;
  byo_key: string;
};
const ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const CLAIMS = parse(readFileSync(join(ROOT, "e2e/agents/claims7.abl.yaml"), "utf8")) as Record<
  string,
  unknown
>;
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
const A = { slug: `ka${rid}`, id: "", org: "", owner: "", key: "" };
const B = { slug: `kb${rid}`, id: "", org: "", owner: "", key: "" };
const SYSTEM = `claims-${rid}`;
let docId = "";
let ctxA: BrowserContext;
let ctxB: BrowserContext;
let page: Page;
let pageB: Page;

async function sso(p: Page, org: string, returnTo: string): Promise<void> {
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
    t.owner = r.owner_member_id;
    t.key = (
      await ops<{ secret: string }>("api-key", {
        tenant_id: t.id,
        member_id: t.owner,
        scopes: ["*"],
      })
    ).secret;
  }
  // the independent reviewer: an auditor of tenant A
  const aud = await ops<{ member_id: string }>("member", { tenant_id: A.id, role: "auditor" });
  const audKey = (
    await ops<{ secret: string }>("api-key", { tenant_id: A.id, member_id: aud.member_id })
  ).secret;
  await api(A.key, "POST", "/blueprints", { abl: CLAIMS });
  await api(A.key, "POST", "/compliance/systems", {
    system_id: SYSTEM,
    name: "Claims triage",
    purpose: `Routes inbound claims ${XSS}`,
    owner: "claims@example.test",
    risk_level: "limited",
    blueprints: [{ name: "claims-agent", version: "1.0.0" }],
  });
  const asm = await api<{ assessment_id: string }>(
    A.key,
    "POST",
    "/compliance/impact-assessments",
    {
      system_id: SYSTEM,
      title: `Claims triage impact ${XSS}`,
      risk_rating: "high",
      intended_use: "Recommend a queue",
      review_due: "2020-01-01",
    },
  );
  await api(A.key, "POST", `/compliance/impact-assessments/${asm.assessment_id}/submit`, {
    expected_version: 1,
  });
  await api(audKey, "POST", `/compliance/impact-assessments/${asm.assessment_id}/review`, {
    expected_version: 1,
    decision: "approve",
    comment: "independent",
  });
  const doc = await api<{ document: { meta: { document_id: string } } }>(
    A.key,
    "POST",
    "/compliance/documents",
    { blueprint: { name: "claims-agent", version: "1.0.0" } },
  );
  docId = doc.document.meta.document_id;
  ctxA = await browser.newContext();
  ctxB = await browser.newContext();
  page = await ctxA.newPage();
  pageB = await ctxB.newPage();
});
test.afterAll(async () => {
  await ctxA?.close();
  await ctxB?.close();
});

test("the inventory lists the system from the real gateway; hostile text is inert", async () => {
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await sso(page, A.org, "/compliance");
  await expect(page.getByRole("heading", { name: "AI system inventory", level: 1 })).toBeVisible();
  await expect(page.getByTestId("evidence-note")).toContainText("not a certification");
  const table = page.getByRole("table", { name: "AI systems" });
  await expect(table).toContainText("Claims triage");
  await expect(table).toContainText("<img src=x");
  expect(await page.locator("main img[src='x'], main script:not([src])").count()).toBe(0);
  expect(
    await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss),
  ).toBeUndefined();
  expect(dialogs).toEqual([]);
  await axe(page, "inventory");
});

test("assessments: approved by a different member, overdue is shown", async () => {
  await page.goto("/compliance/assessments");
  const table = page.getByRole("table", { name: "Impact assessments" });
  await expect(table).toContainText("approved");
  await expect(table).toContainText("review_due_passed");
  await expect(table).toContainText("<script>");
  const row = table.getByRole("row").filter({ hasText: "approved" });
  const cells = await row.getByRole("cell").allTextContents();
  const author = cells[6];
  const reviewer = cells[7];
  expect(author).toBeTruthy();
  expect(reviewer).toBeTruthy();
  expect(author).not.toBe(reviewer);
  await axe(page, "assessments");
});

test("the generated document verifies and lists its gaps", async () => {
  await page.goto("/compliance/documents");
  await expect(page.getByRole("table", { name: "Generated documents" })).toContainText(docId);
  await axe(page, "documents");
  await page.getByRole("link", { name: docId }).click();
  await expect(page.getByTestId("verification")).toContainText("verified");
  await expect(page.getByRole("table", { name: "Gaps" })).toContainText("registry_provenance");
  await expect(page.getByRole("table", { name: "Annex IV coverage" })).toContainText(
    "Harmonised standards",
  );
  await expect(page.getByTestId("document-markdown")).toContainText("Technical documentation");
  await axe(page, "document");
});

test("another tenant sees none of it", async () => {
  await sso(pageB, B.org, "/compliance");
  await expect(pageB.getByRole("heading", { name: "AI system inventory", level: 1 })).toBeVisible();
  await expect(pageB.getByRole("table", { name: "AI systems" })).toHaveCount(0);
  await expect(pageB.getByText("No AI systems yet")).toBeVisible();
  await pageB.goto(`/compliance/documents/${docId}`);
  await expect(pageB.locator("main").getByRole("alert")).toBeVisible();
  await pageB.goto("/compliance/assessments");
  await expect(pageB.getByText("No impact assessments yet")).toBeVisible();
});
