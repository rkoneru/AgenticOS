import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileKillSwitchStore } from "../src/index.js";
import { T1, T2 } from "./helpers.js";

const target = { tenantId: T1, agent: "a", tool: "t" };
const file = (): string => join(mkdtempSync(join(tmpdir(), "ks-")), "kill.json");

describe("FileKillSwitchStore (a kernel restart must not release a kill-switch: Phase 9 chaos finding)", () => {
  it("an engaged switch survives a restart (a new instance on the same file)", async () => {
    const f = file();
    const a = new FileKillSwitchStore(f);
    await a.set("tenant", { tenantId: T1 }, true);
    await a.set("tool", { tenantId: T1, target: "t" }, true);
    const b = new FileKillSwitchStore(f); // "restart"
    expect(await b.isEngaged("tenant", target)).toBe(true);
    expect(await b.isEngaged("tool", target)).toBe(true);
    expect(await b.isEngaged("tenant", { ...target, tenantId: T2 })).toBe(false);
  });

  it("a release survives a restart too", async () => {
    const f = file();
    const a = new FileKillSwitchStore(f);
    await a.set("tenant", { tenantId: T1 }, true);
    await a.set("tenant", { tenantId: T1 }, false);
    expect(await new FileKillSwitchStore(f).isEngaged("tenant", target)).toBe(false);
  });

  it("starts empty when the file does not exist yet", async () => {
    expect(await new FileKillSwitchStore(file()).isEngaged("global", target)).toBe(false);
  });

  it("REFUSES to start on a corrupt state file (it cannot know what was engaged: fail closed, not empty)", () => {
    const f = file();
    writeFileSync(f, "{not json");
    expect(() => new FileKillSwitchStore(f)).toThrow(/corrupt/);
    writeFileSync(f, JSON.stringify({ engaged: "nope" }));
    expect(() => new FileKillSwitchStore(f)).toThrow(/corrupt/);
  });

  it("a release that cannot be persisted fails and the switch STAYS engaged; an engage still takes effect", async () => {
    const f = file();
    const s = new FileKillSwitchStore(f);
    await s.set("tenant", { tenantId: T1 }, true);
    const broken = new FileKillSwitchStore(f, {
      write: () => {
        throw new Error("disk full");
      },
    });
    await expect(broken.set("tenant", { tenantId: T1 }, false)).rejects.toThrow("disk full");
    expect(await broken.isEngaged("tenant", target)).toBe(true);
    await expect(broken.set("agent", { tenantId: T1, target: "a" }, true)).resolves.toBeUndefined();
    expect(await broken.isEngaged("agent", target)).toBe(true);
  });

  it("writes atomically (valid JSON on disk after every change)", async () => {
    const f = file();
    const s = new FileKillSwitchStore(f);
    for (let i = 0; i < 20; i++)
      await s.set("agent", { tenantId: T1, target: `a${i}` }, i % 2 === 0);
    expect(() => JSON.parse(readFileSync(f, "utf8"))).not.toThrow();
    chmodSync(f, 0o600);
  });
});
