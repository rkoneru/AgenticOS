import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  IdentityService,
  LINK_CODE_LENGTH,
  LINK_CODE_TTL_MS,
  MemoryConversationStore,
  MemoryRateLimiter,
  hashLinkCode,
  parseLinkCommand,
  type ConversationStore,
} from "../src/index.js";
import { AGENT, Clock, T1, T2 } from "./helpers.js";
import { storeContract } from "./store-contract.js";

storeContract("memory", async () => {
  const store = new MemoryConversationStore();
  let n = 0;
  return { store, tenant: async () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}` };
});

const mk = (store: ConversationStore = new MemoryConversationStore(), clock = new Clock()) => ({
  clock,
  store,
  svc: new IdentityService({ store, now: clock.now, limiter: new MemoryRateLimiter(clock.now) }),
});

describe("IdentityService", () => {
  it("issues a one-time code, stores only its hash, and links on redeem", async () => {
    const { svc, store, clock } = mk();
    await svc.resolve(T1, "slack", "UA");
    const { code, expires_at_ms } = await svc.issueLinkCode(T1, "slack", "UA");
    expect(code).toHaveLength(LINK_CODE_LENGTH);
    expect(expires_at_ms).toBe(clock.now() + LINK_CODE_TTL_MS);
    await svc.resolve(T1, "sms", "+1555");
    const r = await svc.redeem(T1, "sms", "+1555", code.toLowerCase());
    expect(r.ok).toBe(true);
    expect((await store.findIdentity(T1, "sms", "+1555"))!.verified_by).toBe("link");
    expect(hashLinkCode(T1, code)).toBe(
      hashLinkCode(T1, `${code.slice(0, 5)}-${code.slice(5)}`.toLowerCase()),
    );
    expect(hashLinkCode(T1, code)).not.toBe(hashLinkCode(T2, code));
  });
  it("codes expire after the TTL and cannot be issued for unknown identities", async () => {
    const { svc, clock } = mk();
    await svc.resolve(T1, "slack", "UA");
    const { code } = await svc.issueLinkCode(T1, "slack", "UA");
    clock.advance(LINK_CODE_TTL_MS + 1);
    expect(await svc.redeem(T1, "sms", "+1555", code)).toEqual({ ok: false, reason: "expired" });
    await expect(svc.issueLinkCode(T1, "slack", "ghost")).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(svc.issueLinkCode(T2, "slack", "UA")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
  it("throttles redemption attempts per identity (guessing is bounded)", async () => {
    const { svc } = mk();
    await svc.resolve(T1, "slack", "UA");
    const { code } = await svc.issueLinkCode(T1, "slack", "UA");
    const results = [];
    for (let i = 0; i < 6; i++) results.push(await svc.redeem(T1, "sms", "+1555", "ABCDEFGHJK"));
    expect(results.every((r) => !r.ok)).toBe(true);
    // even the right code is refused while throttled
    expect(await svc.redeem(T1, "sms", "+1555", code)).toEqual({ ok: false, reason: "invalid" });
  });
  it("parseLinkCommand only matches a message that is exactly the command", () => {
    expect(parseLinkCommand("link ABCDEFGHJK")).toBe("ABCDEFGHJK");
    expect(parseLinkCommand("  LINK abcde-fghjk ".replace("-", ""))).toBe("abcdefghjk");
    expect(parseLinkCommand("please link ABCDEFGHJK")).toBeUndefined();
    expect(parseLinkCommand("link ABCDEFGHJK and more")).toBeUndefined();
    expect(parseLinkCommand("link short")).toBeUndefined();
    expect(parseLinkCommand("")).toBeUndefined();
  });
  it("custom code alphabet source is honoured", async () => {
    const store = new MemoryConversationStore();
    const svc = new IdentityService({
      store,
      limiter: new MemoryRateLimiter(),
      randomChar: () => "A",
    });
    await svc.resolve(T1, "slack", "UA");
    expect((await svc.issueLinkCode(T1, "slack", "UA")).code).toBe("A".repeat(LINK_CODE_LENGTH));
  });
});

describe("identity linking never crosses tenants or links on a claim (property)", () => {
  type Op =
    | { k: "seen"; t: 0 | 1; ch: "slack" | "sms" | "email"; ext: number }
    | { k: "issue"; t: 0 | 1; ch: "slack" | "sms" | "email"; ext: number }
    | { k: "redeem"; t: 0 | 1; ch: "slack" | "sms" | "email"; ext: number; from: 0 | 1 };
  const ch = fc.constantFrom("slack", "sms", "email") as fc.Arbitrary<"slack" | "sms" | "email">;
  const tn = fc.constantFrom(0, 1) as fc.Arbitrary<0 | 1>;
  const op: fc.Arbitrary<Op> = fc.oneof(
    fc.record({ k: fc.constant("seen" as const), t: tn, ch, ext: fc.nat(3) }),
    fc.record({ k: fc.constant("issue" as const), t: tn, ch, ext: fc.nat(3) }),
    fc.record({ k: fc.constant("redeem" as const), t: tn, ch, ext: fc.nat(3), from: tn }),
  );

  it("any interleaving keeps every identity, end user and conversation inside its tenant", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(op, { maxLength: 40 }), async (ops) => {
        const { svc, store } = mk();
        const T = [T1, T2] as const;
        const codes: { t: 0 | 1; code: string }[] = [];
        const seen = new Set<string>();
        for (const o of ops) {
          const ext = `x${o.ext}`;
          if (o.k === "seen") {
            await svc.resolve(T[o.t], o.ch, ext);
            seen.add(`${o.t}:${o.ch}:${ext}`);
          } else if (o.k === "issue") {
            try {
              const c = await svc.issueLinkCode(T[o.t], o.ch, ext);
              codes.push({ t: o.t, code: c.code });
            } catch {
              /* unknown identity */
            }
          } else {
            const pick = codes[o.ext % Math.max(codes.length, 1)];
            if (pick) {
              await svc.resolve(T[o.t], o.ch, ext);
              seen.add(`${o.t}:${o.ch}:${ext}`);
              const r = await svc.redeem(T[o.from], o.ch, ext, pick.code);
              // a code only ever works in the tenant that issued it
              if (o.from !== pick.t) expect(r.ok).toBe(false);
            }
          }
        }
        const owners = new Map<string, 0 | 1>();
        for (const key of seen) {
          const [t, c, e] = key.split(":") as [string, "slack", string];
          const tid = T[Number(t) as 0 | 1];
          const ident = await store.findIdentity(tid, c, e);
          if (!ident) continue;
          expect(ident.tenant_id).toBe(tid);
          const prev = owners.get(ident.end_user_id);
          if (prev !== undefined) expect(prev).toBe(Number(t)); // one end user id never appears under both tenants
          owners.set(ident.end_user_id, Number(t) as 0 | 1);
          for (const i of await store.identitiesOf(tid, ident.end_user_id))
            expect(i.tenant_id).toBe(tid);
          const other = T[Number(t) === 0 ? 1 : 0];
          expect(await store.identitiesOf(other, ident.end_user_id)).toEqual([]);
        }
      }),
      { numRuns: 150 },
    );
  });

  it("a claim in text, or the same name on two channels, never links identities", async () => {
    const { svc, store } = mk();
    const a = await svc.resolve(T1, "email", "alice@example.org");
    const b = await svc.resolve(T1, "slack", "alice@example.org"); // same string, different channel
    const c = await svc.resolve(T1, "sms", "+15550001");
    expect(new Set([a.end_user_id, b.end_user_id, c.end_user_id]).size).toBe(3);
    expect(AGENT.name).toBe("support");
    expect((await store.identitiesOf(T1, a.end_user_id)).length).toBe(1);
  });
});
