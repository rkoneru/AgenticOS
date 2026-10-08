import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

/**
 * Phase 8 on the REAL stack: the console's evals pages over the real gateway, the real Eval Hub, the real Risk Kernel and a REAL eval
 * runner process (scripted model). The data is seeded by `e2e/seed_console_evals.py` (blueprint v1 passes and is released, v2 regresses
 * and is blocked, one run waits for a human grade, one run has hostile output, online samples). Nothing is mocked.
 */
const STACK = process.env["STACK_JSON"] ?? "stack.json";
const S = JSON.parse(readFileSync(STACK, "utf8")) as { ops_url: string; ops_token: string };
const ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));

interface Seed {
  org: string;
  org_b: string;
  emails: { owner: string; reviewer: string };
  ns: string;
  v1: { content_hash: string };
  v2: { content_hash: string };
  run1: string;
  run2: string;
  run3: string;
  run4: string;
}
let seed: Seed;
let proc: ChildProcess;
let ctxOwner: BrowserContext;
let ctxReviewer: BrowserContext;
let ctxB: BrowserContext;
let owner: Page;
let reviewer: Page;
let other: Page;

async function ops(name: string, body: object): Promise<void> {
  const r = await fetch(`${S.ops_url}/ops/${name}`, {
    method: "POST",
    headers: { authorization: `Bearer ${S.ops_token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`ops ${name}: ${r.status}`);
}

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
  test.setTimeout(420_000);
  proc = spawn("uv", ["run", "python", "e2e/seed_console_evals.py", resolve(STACK)], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "inherit"],
  });
  seed = await new Promise<Seed>((ok, bad) => {
    let buf = "";
    proc.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      const line = buf.split("\n").find((l) => l.startsWith("{"));
      if (line) ok(JSON.parse(line) as Seed);
    });
    proc.on("exit", (c) => bad(new Error(`seed exited ${c}`)));
  });
  ctxOwner = await browser.newContext();
  ctxReviewer = await browser.newContext();
  ctxB = await browser.newContext();
  owner = await ctxOwner.newPage();
  reviewer = await ctxReviewer.newPage();
  other = await ctxB.newPage();
});
test.afterAll(async () => {
  proc?.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 3000));
  await Promise.all([ctxOwner?.close(), ctxReviewer?.close(), ctxB?.close()]);
});

test("runs: the seeded runs show their status, scores and the run waiting for a human", async () => {
  await sso(owner, seed.org, "/evals");
  const table = owner.getByRole("table", { name: "Eval runs" });
  await expect(table).toContainText("answer-agent@1.0.0");
  await expect(table).toContainText("answer-agent@1.1.0");
  await expect(table).toContainText("awaiting 4 human grade(s)");
  await axe(owner, "evals runs");
});

test("run detail: scores recomputed by the hub, per-case drill-down with grader details and kernel decisions, trace link", async () => {
  await owner.goto(`/evals/runs/${seed.run1}`);
  await expect(owner.getByTestId("run-status")).toContainText("passed");
  await expect(owner.getByTestId("run-score")).toContainText("0.96");
  await expect(owner.getByTestId("score-chart")).toBeVisible();
  await owner.getByTestId("case-q1").locator("summary").click();
  const c = owner.getByTestId("case-q1");
  await expect(c.getByTestId("case-output")).toContainText("Claim 1001 is open");
  await expect(c.getByRole("table", { name: "Grades of case q1" })).toContainText("human_review");
  await expect(c.getByRole("table", { name: "Kernel decisions of case q1" })).toContainText(
    "ALLOW",
  );
  await expect(c.getByRole("link", { name: /^[0-9a-f]{12}$/ })).toHaveAttribute(
    "href",
    /\/audit\?trace_id=/,
  );
  await axe(owner, "eval run");
});

test("regression: v2's run shows the baseline comparison; baselines page charts it", async () => {
  await owner.goto(`/evals/runs/${seed.run2}`);
  await expect(owner.getByTestId("baseline-compare")).toContainText("regression: blocks release");
  await owner.goto("/evals/baselines");
  await owner.getByLabel("Blueprint name").fill("answer-agent");
  await owner.getByLabel("Suite").fill("answers@1.0.0");
  await owner.getByRole("button", { name: "Show history" }).click();
  await expect(owner.getByRole("table", { name: "Baseline history" })).toContainText("release:");
  await owner
    .getByRole("button", { name: new RegExp(`Compare run ${seed.run2.slice(0, 6)}`) })
    .click();
  await expect(owner.getByTestId("compare-summary")).toContainText("blocks the release");
  await expect(owner.getByText("Per grader: this run against the baseline")).toBeVisible();
  await axe(owner, "eval baselines");
});

test("release gate panel: v2 BLOCKED with the reason; v1 is held while a newer run waits for a human", async () => {
  await owner.goto("/blueprints/answer-agent/1.1.0");
  const blocked = owner.getByTestId("gate-panel");
  await expect(blocked.getByTestId("gate-verdict")).toHaveText("BLOCKED");
  await expect(blocked.getByRole("list", { name: "Gate reasons" })).toContainText("regression");
  await expect(blocked.getByRole("table", { name: "Eval runs of this version" })).toContainText(
    "answers@1.0.0",
  );
  await owner.goto("/blueprints/answer-agent/1.0.0");
  const held = owner.getByTestId("gate-panel");
  await expect(held.getByTestId("gate-verdict")).toHaveText("BLOCKED");
  await expect(held.getByRole("list", { name: "Gate reasons" })).toContainText("run_in_progress");
  await axe(owner, "blueprint version with gate panel");
});

test("XSS: hostile agent output is inert in the run detail", async () => {
  const dialogs: string[] = [];
  owner.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await owner.goto(`/evals/runs/${seed.run4}`);
  await owner.getByTestId("case-x1").locator("summary").click();
  await expect(owner.getByTestId("case-output")).toContainText("<img src=x");
  expect(
    await owner.evaluate(() => (window as unknown as { __xss?: number }).__xss),
  ).toBeUndefined();
  expect(await owner.locator("main img[src='x'], main script").count()).toBe(0);
  expect(dialogs).toEqual([]);
});

test("review queue: the publisher sees nothing; a reviewer grades in the browser and the run finalises", async () => {
  await owner.goto("/evals/review");
  await expect(owner.getByText("Nothing to review")).toBeVisible();
  await sso(reviewer, seed.org, "/evals/review", seed.emails.reviewer);
  const list = reviewer.getByRole("list", { name: "Review tasks" });
  await expect(list.locator("li")).toHaveCount(4, { timeout: 30_000 });
  await axe(reviewer, "eval review queue");
  for (const id of ["q1", "q2", "q3", "q4"]) {
    const t = reviewer.getByTestId(`task-${id}`).first();
    await t.getByRole("button", { name: "Claim to grade" }).click();
    await t.getByLabel(`Score (0 to 1) for ${id}`).fill("0.9");
    await t.getByLabel(`Comment for ${id}`).fill("reads well");
    await t.getByRole("button", { name: "Submit grade" }).click();
    await expect(reviewer.getByTestId(`task-${id}`))
      .toHaveCount(0, { timeout: 30_000 })
      .catch(() => undefined);
  }
  await expect
    .poll(
      async () => {
        await owner.goto(`/evals/runs/${seed.run3}`);
        return (await owner.getByTestId("run-status").innerText()).includes("passed");
      },
      { timeout: 60_000 },
    )
    .toBe(true);
});

test("release gate panel: once the human grades are in, v1 is ALLOWED with its history and a verified attestation", async () => {
  await owner.goto("/blueprints/answer-agent/1.0.0");
  await expect(owner.getByTestId("gate-panel").getByTestId("gate-verdict")).toHaveText("ALLOWED");
  await owner.goto("/registry");
  await owner.getByLabel(/Reference/).fill(`${seed.ns}/answer-agent@1.0.0`);
  await owner.getByRole("button", { name: "Resolve" }).click();
  const panel = owner.getByTestId("gate-panel");
  await expect(panel.getByTestId("gate-verdict")).toHaveText("ALLOWED");
  await expect(
    panel.getByRole("table", { name: "Eval attestations of this version" }),
  ).toContainText("verified");
  await axe(owner, "registry with gate panel");
  await owner.getByLabel(/Reference/).fill(`${seed.ns}/answer-agent@1.1.0`);
  await owner.getByRole("button", { name: "Resolve" }).click();
  await expect(owner.getByTestId("gate-panel").getByTestId("gate-verdict")).toHaveText("BLOCKED");
});

test("online: sampled production runs appear as history, with a table view", async () => {
  await owner.goto("/evals/online");
  const s = owner.getByTestId("sampling-prod-health");
  await expect(s).toContainText("3 sample(s)");
  await s.getByRole("button", { name: "Show table" }).click();
  await expect(s.getByRole("table")).toBeVisible();
  await axe(owner, "eval online");
});

test("datasets and suites pages", async () => {
  await owner.goto("/evals/datasets");
  await expect(owner.getByRole("table", { name: "Dataset versions" })).toContainText(
    "answer-cases@1",
  );
  await owner.goto("/evals/suites");
  await expect(owner.getByRole("table", { name: "Suites" })).toContainText("answers@1.0.0");
  await axe(owner, "eval suites");
});

test("another tenant's console sees none of it", async () => {
  await sso(other, seed.org_b, "/evals");
  await expect(other.getByText("No eval runs")).toBeVisible();
  await other.goto(`/evals/runs/${seed.run1}`);
  await expect(other.getByRole("alert")).toBeVisible();
  await expect(other.getByTestId("run-score")).toHaveCount(0);
  await other.goto("/evals/datasets");
  await expect(other.getByText("answer-cases")).toHaveCount(0);
  const r = await ctxB.request.get(`/api/axis/v1/evals/runs/${seed.run1}`);
  expect(r.status()).toBe(404);
  void join;
});
