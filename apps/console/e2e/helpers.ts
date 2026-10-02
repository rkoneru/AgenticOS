import { expect, type Page, request } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

export const API = "http://127.0.0.1:4010";
export const SEED_RUN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const SEED_APPROVAL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const SELF_APPROVAL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

export async function resetMock(): Promise<void> {
  const ctx = await request.newContext();
  await ctx.post(`${API}/__reset`);
  await ctx.dispose();
}

export async function tamper(): Promise<void> {
  const ctx = await request.newContext();
  await ctx.post(`${API}/__tamper`);
  await ctx.dispose();
}

export async function login(page: Page, role = "admin", returnTo = "/runs"): Promise<void> {
  await page.goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
  await page.getByLabel("Organization").fill("acme");
  await page.getByLabel(/sign in as role/i).selectOption(role);
  await page.getByRole("button", { name: "Continue with SSO" }).click();
  await page.waitForURL(`**${returnTo.split("?")[0]}**`);
}

export async function axeClean(page: Page, label: string): Promise<void> {
  const r = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const msgs = r.violations.map(
    (v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
  );
  expect(msgs, `axe violations on ${label}`).toEqual([]);
}
