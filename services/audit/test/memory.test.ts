import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MemoryAuditLog } from "../src/index.js";
import { ev } from "./helpers.js";
import { storeContract } from "./store-contract.js";

class Tamperable extends MemoryAuditLog {
  chain(t: string) {
    return this.chains.get(t)!;
  }
}

storeContract("MemoryAuditLog", async () => ({
  log: new MemoryAuditLog(),
  tenant: async () => randomUUID(),
}));

describe("MemoryAuditLog specifics", () => {
  it("uses the injected clock for ts", async () => {
    const log = new MemoryAuditLog({ now: () => new Date("2030-05-06T07:08:09.123Z") });
    const a = await log.append(ev(randomUUID()));
    expect(a.ts).toBe("2030-05-06T07:08:09.123Z");
  });

  it("returns copies: callers cannot mutate the stored chain", async () => {
    const log = new MemoryAuditLog();
    const t = randomUUID();
    const a = await log.append(ev(t));
    a.action = "tampered";
    (await log.read(t, {}))[0]!.action = "tampered";
    (await log.head(t))!.action = "tampered";
    (await log.listEvents(t, { limit: 5 }))[0]!.action = "tampered";
    expect(await log.verify(t)).toEqual({ ok: true, length: 1 });
  });

  it("verify detects content tampering, a deleted middle event, and a foreign event", async () => {
    const log = new Tamperable();
    const t = randomUUID();
    for (let i = 0; i < 5; i++) await log.append(ev(t));
    log.chain(t)[2]!.action = "evil";
    expect(await log.verify(t)).toEqual({ ok: false, brokenAtSeq: 3, reason: "hash_mismatch" });
    log.chain(t)[2]!.action = "lookup";
    log.chain(t).splice(1, 1);
    expect(await log.verify(t)).toEqual({ ok: false, brokenAtSeq: 3, reason: "seq_gap" });
    log.chain(t)[1]!.tenant_id = randomUUID();
    expect(await log.verify(t)).toEqual({ ok: false, brokenAtSeq: 3, reason: "tenant_mismatch" });
  });
});
