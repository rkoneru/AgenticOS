import { MemoryAuditLog } from "@axis/audit";
import { describe, expect, it } from "vitest";
import type { EraseResult, Identifier, ProviderContext } from "../src/index.js";
import { FakeProvider, email, officer, rig, setupTenant, verifiedErase } from "./helpers.js";

const DAY = 86_400_000;

/** Phase 9 adversarial review. */
describe("fail-closed ordering and hold races (review)", () => {
  it("a retention purge is not run when the audit sink is down", async () => {
    class Flaky extends MemoryAuditLog {
      down = false;
      override async append(...a: Parameters<MemoryAuditLog["append"]>) {
        if (this.down) throw new Error("sink down");
        return super.append(...a);
      }
    }
    const log = new Flaky();
    const mem = new FakeProvider("mem", { classes: ["memory"] });
    const r = rig([mem], { audit: log });
    const t = setupTenant(r);
    mem.put(t, "a", "x", { createdAt: new Date(r.clock.now.getTime() - 4000 * DAY) });
    log.down = true;
    await expect(r.retention.run(officer(t), { classes: ["memory"] })).rejects.toBeTruthy();
    expect(mem.all(t)).toHaveLength(1); // nothing purged without an audit record
  });

  it("a hold placed while an erase is running stops the providers not yet erased", async () => {
    class Placing extends FakeProvider {
      onErase: (() => Promise<void>) | undefined;
      override async erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
        const res = await super.erase(ctx, ids);
        await this.onErase?.();
        return res;
      }
    }
    const first = new Placing("first", { classes: ["memory"] });
    const second = new FakeProvider("second", { classes: ["conversation"] });
    const r = rig([first, second]);
    const t = setupTenant(r);
    const jane = email();
    first.put(t, "jane.doe@example.com");
    second.put(t, "jane.doe@example.com");
    const reqId = await verifiedErase(r, t, [jane]);
    first.onErase = async () => {
      await r.holds.placeHold(officer(t, "officer-2"), {
        scope: "tenant",
        reason: "litigation hold",
        dataClasses: ["conversation"],
      });
    };
    const out = await r.engine.erase(officer(t), reqId);
    expect(out.status).toBe("held");
    expect(second.all(t)).toHaveLength(1);
  });

  it("a hold placed while a retention purge is running stops the later classes", async () => {
    class Placing extends FakeProvider {
      onPurge: (() => Promise<void>) | undefined;
      override async purge(...a: Parameters<FakeProvider["purge"]>) {
        const res = await super.purge(...a);
        await this.onPurge?.();
        return res;
      }
    }
    const first = new Placing("first", { classes: ["memory"] });
    const second = new FakeProvider("second", { classes: ["conversation"] });
    const r = rig([first, second]);
    const t = setupTenant(r);
    const old = new Date(r.clock.now.getTime() - 4000 * DAY);
    first.put(t, "a", "x", { createdAt: old });
    second.put(t, "b", "x", { createdAt: old });
    first.onPurge = async () => {
      await r.holds.placeHold(officer(t, "officer-2"), {
        scope: "tenant",
        reason: "litigation hold",
        dataClasses: ["conversation"],
      });
    };
    await r.retention.run(officer(t), { classes: ["memory", "conversation"] });
    expect(second.all(t)).toHaveLength(1);
  });
});
