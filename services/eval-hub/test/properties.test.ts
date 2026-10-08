import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { HubError } from "../src/index.js";
import {
  DAY,
  bp,
  caseResults,
  payloadFor,
  publishers,
  registerRunner,
  runnerOf,
  seedSuite,
  user,
  world,
  type World,
} from "./helpers.js";

const HA = "a".repeat(64);
const HB = "b".repeat(64);

interface Step {
  hash: "A" | "B";
  score: number; // tenths
  errored: boolean;
  revoke: boolean;
  days: number;
}
const stepArb: fc.Arbitrary<Step> = fc.record({
  hash: fc.constantFrom("A", "B"),
  score: fc.integer({ min: 0, max: 10 }),
  errored: fc.boolean(),
  revoke: fc.boolean(),
  days: fc.integer({ min: 0, max: 20 }),
});

describe("gate properties", () => {
  it("never allows without a fresh, passing, unrevoked-runner, latest run for the exact content hash (model-checked)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(stepArb, { maxLength: 8 }),
        fc.integer({ min: 0, max: 10 }),
        fc.integer({ min: 0, max: 45 }),
        async (steps, declaredTenths, waitDays) => {
          const w = world();
          await seedSuite(w, { pass_threshold: 0.5, suite: { max_age_days: 30 } });
          const model: {
            hash: string;
            score: number;
            errored: boolean;
            at: number;
            runner: string;
          }[] = [];
          const revoked = new Set<string>();
          for (const [i, s] of steps.entries()) {
            w.clock.advance(s.days * DAY + 1);
            const rid = `r${i}`;
            await registerRunner(w, rid);
            const runner = runnerOf(w.tenant, rid);
            const hash = s.hash === "A" ? HA : HB;
            const run = await w.hub.runs.startAsRunner(runner, {
              suite_ref: "smoke@1.0.0",
              blueprint: bp(hash),
            });
            if (s.errored) await w.hub.runs.fail(runner, run.id, "boom");
            else {
              const results = caseResults(
                ["c1", "c2", "c3", "c4"],
                ["exact", "contains"],
                s.score / 10,
              );
              await w.hub.runs.submitResults(
                runner,
                run.id,
                await payloadFor(w, run, results, { runnerId: rid }),
              );
            }
            model.push({
              hash,
              score: s.score / 10,
              errored: s.errored,
              at: w.clock.t.getTime(),
              runner: rid,
            });
            if (s.revoke) {
              await w.hub.runs.revokeRunner(w.admin, rid);
              revoked.add(rid);
            }
          }
          w.clock.advance(waitDays * DAY);
          const declared = declaredTenths / 10;
          const r = await w.hub.gate.check(w.builder, {
            blueprint: bp(HA),
            suites: [{ ref: "smoke@1.0.0", threshold: declared }],
          });
          const live = model.filter((m) => m.hash === HA && !revoked.has(m.runner));
          const latest = live[live.length - 1];
          const expected =
            latest !== undefined &&
            !latest.errored &&
            w.clock.t.getTime() - latest.at <= 30 * DAY &&
            latest.score >= Math.max(declared, 0.5);
          expect(r.allowed).toBe(expected);
          if (!r.allowed) expect(r.reasons.length).toBeGreaterThan(0);
          if (r.allowed) expect(r.reasons).toEqual([]);
          // a gate for a hash that no run was made for is never allowed
          const none = await w.hub.gate.check(w.builder, {
            blueprint: bp("c".repeat(64)),
            suites: [{ ref: "smoke@1.0.0" }],
          });
          expect(none.allowed).toBe(false);
        },
      ),
      { numRuns: 40 },
    );
  });

  it("tenants are isolated: another tenant never gets an allow from someone else's passing run", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 8, max: 10 }), async (tenths) => {
        const a = world();
        await seedSuite(a);
        await registerRunner(a);
        const run = await a.hub.runs.startAsRunner(a.runner, {
          suite_ref: "smoke@1.0.0",
          blueprint: bp(HA),
        });
        const results = caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], tenths / 10);
        await a.hub.runs.submitResults(a.runner, run.id, await payloadFor(a, run, results));
        expect(
          (
            await a.hub.gate.check(a.builder, {
              blueprint: bp(HA),
              suites: [{ ref: "smoke@1.0.0" }],
            })
          ).allowed,
        ).toBe(true);
        // tenant B shares the store, defines the same suite, and has no runs of its own
        const bTenant = "00000000-0000-4000-8000-0000000000b1";
        const b: World = {
          ...a,
          tenant: bTenant,
          admin: user(bTenant, "admin", "mallory"),
          builder: user(bTenant, "builder", "bob2"),
          runner: runnerOf(bTenant, "runner-1"),
        };
        await seedSuite(b);
        await registerRunner(b);
        const r = await b.hub.gate.check(b.builder, {
          blueprint: bp(HA),
          suites: [{ ref: "smoke@1.0.0" }],
        });
        expect(r.allowed).toBe(false);
        expect(r.reasons.map((x) => x.code)).toEqual(["missing_run"]);
        expect((await b.hub.runs.list(b.admin)).items).toEqual([]);
        await expect(b.hub.runs.get(b.admin, run.id)).rejects.toMatchObject({ code: "not_found" });
      }),
      { numRuns: 15 },
    );
  });
});

describe("review properties", () => {
  it("whoever started the run or published the blueprint can never claim or grade its tasks", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("viewer-publisher", "pat", "pub-1"),
        fc.array(fc.constantFrom("claim", "grade", "skip"), { minLength: 1, maxLength: 6 }),
        fc.constantFrom("operator", "admin", "builder", "owner", "reviewer"),
        async (publisher, attempts, role) => {
          const w = world({ publishers: publishers({ "support-agent@1.0.0": publisher }) });
          await seedSuite(w, {
            graders: [
              { id: "exact", kind: "deterministic", config: { type: "exact" } },
              { id: "h", kind: "human", config: { rubric: "ok?" } },
            ],
            cases: [{ id: "c1", input: "q" }],
          });
          await registerRunner(w);
          const queued = await w.hub.runs.request(w.builder, {
            suite_ref: "smoke@1.0.0",
            blueprint: bp(),
          });
          await w.hub.runs.claim(w.runner, queued.id);
          await w.hub.runs.submitResults(
            w.runner,
            queued.id,
            await payloadFor(
              w,
              queued,
              caseResults(["c1"], ["exact", "h"], (_i, g) => (g === "h" ? null : 1), {
                h: "human",
              }),
            ),
          );
          await w.hub.runs.createReviewTasks(w.runner, queued.id, {
            tasks: [
              {
                case_id: "c1",
                grader_id: "h",
                rubric: "ok?",
                input: "q",
                output: "a",
                expected: null,
              },
            ],
          });
          const task = (
            await w.hub.reviews.list(user(w.tenant, "operator", "someone-else"), {})
          )[0];
          expect(task).toBeDefined();
          for (const who of [publisher, "bob-builder"]) {
            const p = user(w.tenant, role as never, who);
            for (const a of attempts) {
              const op =
                a === "claim"
                  ? w.hub.reviews.claim(p, (task as { id: string }).id)
                  : a === "grade"
                    ? w.hub.reviews.grade(p, (task as { id: string }).id, {
                        score: 1,
                        comment: "mine",
                      })
                    : w.hub.reviews.skip(p, (task as { id: string }).id, "x");
              await expect(op).rejects.toBeInstanceOf(HubError);
            }
            expect(await w.hub.reviews.list(p, { all: true })).toEqual([]);
          }
          // nothing they tried changed the task or the run
          const after = await w.hub.reviews.get(
            user(w.tenant, "operator", "someone-else"),
            (task as { id: string }).id,
          );
          expect(after).toMatchObject({ state: "open", grades: [], claimed_by: null });
          expect((await w.hub.runs.get(w.admin, queued.id)).status).toBe("running");
        },
      ),
      { numRuns: 20 },
    );
  });
});

describe("integrity properties", () => {
  it("any perturbation of a submitted aggregate beyond the epsilon is rejected; the honest value is accepted", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.double({ min: 0, max: 1, noNaN: true }), { minLength: 4, maxLength: 4 }),
        fc.double({ min: 0.001, max: 0.5, noNaN: true }),
        async (scores, delta) => {
          const w = world();
          await seedSuite(w, {
            graders: [{ id: "exact", kind: "deterministic", config: { type: "exact" } }],
          });
          await registerRunner(w);
          const ids = ["c1", "c2", "c3", "c4"];
          const results = caseResults(ids, ["exact"], (id) => scores[ids.indexOf(id)] as number);
          const lie = await w.hub.runs.startAsRunner(w.runner, {
            suite_ref: "smoke@1.0.0",
            blueprint: bp(),
          });
          const honestPayload = await payloadFor(w, lie, results);
          const honest = (honestPayload["scores"] as { overall: number }).overall;
          const claimed = honest + delta <= 1 ? honest + delta : honest - delta;
          const forged = await payloadFor(w, lie, results, {
            patch: (p) => ((p["scores"] as { overall: number }).overall = claimed),
          });
          await expect(w.hub.runs.submitResults(w.runner, lie.id, forged)).rejects.toMatchObject({
            code: "integrity_failed",
          });
          const ok = await w.hub.runs.submitResults(w.runner, lie.id, honestPayload);
          expect(Math.abs((ok.scores?.overall ?? NaN) - honest)).toBeLessThan(1e-6);
          // the stored number is the hub's own, whatever the runner's float noise
          expect(ok.scores?.overall).toBe(Math.round((ok.scores?.overall as number) * 1e9) / 1e9);
        },
      ),
      { numRuns: 25 },
    );
  });
});
