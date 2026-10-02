import { randomUUID } from "node:crypto";
import fc from "fast-check";
import semver from "semver";
import { describe, expect, it } from "vitest";
import { Publisher, ablDoc, harness } from "./helpers.js";

const arbVer = fc
  .tuple(
    fc.integer({ min: 0, max: 3 }),
    fc.integer({ min: 0, max: 3 }),
    fc.integer({ min: 0, max: 3 }),
  )
  .map(([a, b, c]) => `${a}.${b}.${c}`);
const arbOp = fc.oneof(
  fc.record({ op: fc.constant("publish" as const), v: arbVer, tweak: fc.boolean() }),
  fc.record({ op: fc.constant("yank" as const), v: arbVer }),
  fc.record({ op: fc.constant("deprecate" as const), v: arbVer }),
);
const arbRange = fc.oneof(
  arbVer,
  arbVer.map((v) => `^${v}`),
  arbVer.map((v) => `~${v}`),
  fc.constant("*"),
);

describe("registry invariants under random operation sequences", () => {
  it("immutability, no resurrection of yanked versions, and resolve == reference semver over the live set", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(arbOp, { minLength: 1, maxLength: 14 }),
        arbRange,
        async (ops, range) => {
          const h = harness();
          const pub = await Publisher.create(h, randomUUID(), "acme");
          const view = { tenantId: pub.p.tenantId };
          const firstHash = new Map<string, string>();
          const yanked = new Set<string>();
          for (const o of ops) {
            if (o.op === "publish") {
              const doc = ablDoc(
                "prop-agent",
                o.v,
                o.tweak ? { instructions: { system: `variant ${Math.random()}` } } : {},
              );
              const res = await pub.publish(doc).then(
                (r) => r,
                (e: { code: string }) => e,
              );
              if ("code" in res) {
                expect(res.code).toBe("conflict"); // the only legal refusal here: it already exists
                expect(firstHash.has(o.v)).toBe(true);
              } else {
                expect(firstHash.has(o.v)).toBe(false);
                firstHash.set(o.v, res.contentHash);
              }
            } else {
              const f =
                o.op === "yank"
                  ? h.svc.yank(pub.p, "acme", "prop-agent", o.v, "reason")
                  : h.svc.deprecate(pub.p, "acme", "prop-agent", o.v, "reason");
              const r = await f.then(
                () => "ok",
                (e: { code: string }) => e.code,
              );
              if (!firstHash.has(o.v)) expect(r).toBe("not_found");
              else if (yanked.has(o.v)) expect(r).toBe("conflict");
              else {
                expect(r).toBe("ok");
                if (o.op === "yank") yanked.add(o.v);
              }
            }
          }
          // immutability: what is stored is what was first published, whatever else happened
          for (const [v, hash] of firstHash) {
            const got = await h.svc.getVersion(view, "acme", "prop-agent", v, {
              allowYanked: true,
            });
            expect(got.contentHash).toBe(hash);
            expect(got.state === "yanked").toBe(yanked.has(v));
          }
          // resolution picks exactly the reference's answer over live (non-yanked) versions, and never a yanked one
          const live = [...firstHash.keys()].filter((v) => !yanked.has(v));
          const want = semver.maxSatisfying(live, range);
          const got = await h.svc.resolve(view, `acme/prop-agent@${range}`).then(
            (r) => r.version,
            () => null,
          );
          expect(got).toBe(want);
        },
      ),
      { numRuns: 25 },
    );
  });
});
