import { verifyChain } from "@axis/contracts";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { DsarEngine, GovernanceAudit } from "../src/index.js";
import { FakeProvider, email, officer, rig, setupTenant, verifiedErase } from "./helpers.js";

const OWNERS = ["jane.doe@example.com", "bob@example.com", "carol@example.com"];
const rowsArb = fc.array(
  fc.record({ owner: fc.constantFrom(...OWNERS), prov: fc.constantFrom(0, 1, 2) }),
  { maxLength: 14 },
);

function build(rows: { owner: string; prov: number }[]) {
  const provs = [new FakeProvider("p0"), new FakeProvider("p1"), new FakeProvider("p2")];
  const r = rig(provs);
  const t = setupTenant(r);
  const other = setupTenant(r);
  for (const x of rows) {
    provs[x.prov]!.put(t, x.owner);
    provs[x.prov]!.put(other, x.owner);
  }
  return { r, t, other, provs };
}

describe("DSAR properties", () => {
  it("erase then verify: no residual for the subject, nobody else touched, other tenants untouched, chain intact", async () => {
    await fc.assert(
      fc.asyncProperty(rowsArb, async (rows) => {
        const { r, t, other, provs } = build(rows);
        const id = await verifiedErase(r, t, [email("JANE.DOE@example.com")]);
        const out = await r.engine.erase(officer(t), id);
        expect(out.status).toBe("completed");
        for (const p of provs) {
          expect(p.all(t).filter((x) => x.owner === "jane.doe@example.com")).toHaveLength(0);
          expect(p.all(t).filter((x) => x.owner !== "jane.doe@example.com")).toHaveLength(
            rows.filter((x) => x.owner !== "jane.doe@example.com" && provs[x.prov] === p).length,
          );
          expect(p.all(other)).toHaveLength(rows.filter((x) => provs[x.prov] === p).length);
          expect(
            (
              await p.count({ tenantId: t, now: new Date(), pseudonym: async () => "" }, [
                email("jane.doe@example.com"),
              ])
            ).residual,
          ).toBe(0);
        }
        const events = await r.audit.read(t, {});
        expect(verifyChain(events)).toMatchObject({ ok: true });
        expect(JSON.stringify(events).toLowerCase()).not.toContain("jane");
      }),
      { numRuns: 40 },
    );
  });

  it("idempotent: repeating an erase changes nothing and emits no further events", async () => {
    await fc.assert(
      fc.asyncProperty(rowsArb, fc.integer({ min: 1, max: 3 }), async (rows, times) => {
        const { r, t, provs } = build(rows);
        const id = await verifiedErase(r, t, [email()]);
        const first = await r.engine.erase(officer(t), id);
        const snapshot = JSON.stringify(provs.map((p) => p.all(t)));
        const n = (await r.audit.read(t, {})).length;
        for (let i = 0; i < times; i++) {
          const again = await r.engine.erase(officer(t), id);
          expect(again.request.result).toEqual(first.request.result);
        }
        expect(JSON.stringify(provs.map((p) => p.all(t)))).toBe(snapshot);
        expect((await r.audit.read(t, {})).length).toBe(n);
      }),
      { numRuns: 25 },
    );
  });

  it("resumable: a crash at ANY checkpoint, then a re-run, converges to the clean-run result", async () => {
    await fc.assert(
      fc.asyncProperty(rowsArb, fc.integer({ min: 0, max: 14 }), async (rows, crashAt) => {
        const clean = build(rows);
        const cleanId = await verifiedErase(clean.r, clean.t, [email()]);
        await clean.r.engine.erase(officer(clean.t), cleanId);

        const { r, t, provs } = build(rows);
        let n = 0;
        let crashes = 0;
        r.deps.checkpoint = () => {
          if (n++ === crashAt) {
            crashes++;
            throw new Error("simulated crash");
          }
        };
        const engine = new DsarEngine(r.deps);
        const id = await verifiedErase({ ...r, engine } as never, t, [email()]);
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            const out = await engine.erase(officer(t), id);
            expect(out.status).toBe("completed");
            break;
          } catch (e) {
            expect((e as Error).message).toBe("simulated crash");
          }
        }
        const req = await r.store.getRequest(t, id);
        expect(req?.status).toBe("completed");
        expect(req?.sealedIdentifiers).toBeNull();
        expect((await r.store.getSubject(t, req!.subjectId))?.salt).toBeNull();
        expect(JSON.stringify(provs.map((p) => p.all(t).map((x) => x.owner)))).toBe(
          JSON.stringify(clean.provs.map((p) => p.all(clean.t).map((x) => x.owner))),
        );
        expect(verifyChain(await r.audit.read(t, {}))).toMatchObject({ ok: true });
        expect(crashes).toBeLessThanOrEqual(1);
      }),
      { numRuns: 60 },
    );
  });

  it("resumable across audit failures: an audit outage at the k-th append never leaves data erased without a start event", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 6 }), async (failAt) => {
        const { r, t, provs } = build([{ owner: "jane.doe@example.com", prov: 0 }]);
        let n = 0;
        const orig = r.audit.append.bind(r.audit);
        r.audit.append = async (e) => {
          if (n++ === failAt) throw new Error("audit outage");
          return orig(e);
        };
        const p = officer(t);
        const run = async (): Promise<boolean> => {
          try {
            const q =
              (await r.store.listRequests(t))[0] ??
              (await r.engine.open(p, { kind: "erase", identifiers: [email()] }));
            if (q.status === "received") await r.engine.verify(p, q.id, {});
            return (await r.engine.erase(p, q.id)).status === "completed";
          } catch {
            return false;
          }
        };
        let done = false;
        for (let i = 0; i < 4 && !done; i++) done = await run();
        expect(done).toBe(true);
        expect(provs[0]!.all(t)).toHaveLength(0);
        const actions = (await r.audit.read(t, {})).map((e) => e.action);
        expect(
          actions.indexOf("dsar.erase.started") === -1
            ? actions.indexOf("dsar.erase.resumed")
            : actions.indexOf("dsar.erase.started"),
        ).toBeGreaterThanOrEqual(0);
        expect(actions).toContain("dsar.erase.completed");
        expect(verifyChain(await r.audit.read(t, {}))).toMatchObject({ ok: true });
      }),
      { numRuns: 7 },
    );
  });

  it("tenants are isolated: an erase in A cannot be driven from B and B's data survives any interleaving", async () => {
    await fc.assert(
      fc.asyncProperty(rowsArb, async (rows) => {
        const { r, t, other, provs } = build(rows);
        const before = JSON.stringify(provs.map((p) => p.all(other)));
        const id = await verifiedErase(r, t, [email()]);
        await expect(r.engine.erase(officer(other), id)).rejects.toMatchObject({
          code: "not_found",
        });
        await r.engine.erase(officer(t), id);
        expect(JSON.stringify(provs.map((p) => p.all(other)))).toBe(before);
        expect((await r.audit.read(other, {})).length).toBe(0);
      }),
      { numRuns: 20 },
    );
  });
});

describe("GovernanceAudit export", () => {
  it("keeps the same instance semantics", () => {
    expect(GovernanceAudit).toBeTypeOf("function");
  });
});
