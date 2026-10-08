import { describe, expect, it } from "vitest";
import { HubError } from "../src/index.js";
import {
  HASH_A,
  HOUR,
  events,
  bp,
  registerRunner,
  runnerOf,
  seedSuite,
  user,
  world,
  type World,
} from "./helpers.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : `error:${String(e)}`;
  }
};

async function ready(): Promise<World> {
  const w = world();
  await seedSuite(w);
  await registerRunner(w);
  return w;
}
const cfg = (o: Record<string, unknown> = {}) => ({
  blueprint_name: "support-agent",
  suite_ref: "smoke@1.0.0",
  rate: 0.1,
  max_per_hour: 5,
  alert_threshold: 0.7,
  ...o,
});
const ing = (
  w: World,
  scores: Record<string, number> = { exact: 1, contains: 1 },
  o: Record<string, unknown> = {},
) =>
  w.hub.online.ingest(w.runner, {
    sampling_id: "prod",
    blueprint: bp(HASH_A, "support-agent", "1.0.0"),
    scores,
    trace_id: "tr",
    source_run_id: "run-1",
    ...o,
  });

describe("sampling configs", () => {
  it("are created and updated by an admin, listed, and disabled", async () => {
    const w = await ready();
    const c1 = await w.hub.online.put(w.admin, "prod", cfg());
    expect(c1).toMatchObject({
      id: "prod",
      rate: 0.1,
      max_per_hour: 5,
      redaction: "redact",
      enabled: true,
      updated_by: "alice-admin",
    });
    const c2 = await w.hub.online.put(
      w.admin,
      "prod",
      cfg({ rate: 0.5, redaction: "hash_only", alert_threshold: null }),
    );
    expect(c2).toMatchObject({ rate: 0.5, redaction: "hash_only", alert_threshold: null });
    expect(await w.hub.online.list(w.builder)).toHaveLength(1);
    expect(await w.hub.online.list(w.runner)).toHaveLength(1);
    expect((await w.hub.online.disable(w.admin, "prod")).enabled).toBe(false);
    expect(await code(w.hub.online.disable(w.admin, "ghost"))).toBe("not_found:");
    expect(await code(w.hub.online.put(w.builder, "prod", cfg()))).toBe("forbidden:");
    expect(await code(w.hub.online.disable(w.builder, "prod"))).toBe("forbidden:");
    expect(await w.hub.online.list(user("00000000-0000-4000-8000-0000000000dd", "owner"))).toEqual(
      [],
    );
  });

  it("validates its fields", async () => {
    const w = await ready();
    const t = (o: Record<string, unknown>, id = "prod") =>
      code(w.hub.online.put(w.admin, id, cfg(o)));
    expect(await t({}, "bad id")).toMatch(/^invalid:id/);
    expect(await t({ blueprint_name: "Bad" })).toMatch(/blueprint_name/);
    expect(await t({ suite_ref: "x" })).toMatch(/suite_ref/);
    expect(await t({ suite_ref: "ghost@1.0.0" })).toMatch(/suite_ref/);
    expect(await t({ rate: 2 })).toMatch(/rate/);
    expect(await t({ max_per_hour: 0 })).toMatch(/max_per_hour/);
    expect(await t({ max_per_hour: 1.5 })).toMatch(/max_per_hour/);
    expect(await t({ redaction: "none" })).toMatch(/redaction/);
    expect(await t({ enabled: "yes" })).toMatch(/enabled/);
    expect(await t({ alert_threshold: 3 })).toMatch(/alert_threshold/);
  });
});

describe("ingestion", () => {
  it("stores scores and ids only, weighted over the graders sent", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg());
    const r = await ing(w, { exact: 1, contains: 0.5 });
    expect(r).toMatchObject({
      sampling_id: "prod",
      score: 0.75,
      runner_id: "runner-1",
      trace_id: "tr",
      source_run_id: "run-1",
    });
    expect(Object.keys(r).sort()).toEqual([
      "at",
      "blueprint",
      "id",
      "runner_id",
      "sampling_id",
      "score",
      "scores",
      "source_run_id",
      "suite_ref",
      "trace_id",
    ]);
    expect((await ing(w, { exact: 0.2 })).score).toBe(0.2);
  });

  it("is limited to registered runners, enabled configs, the configured blueprint and the suite's automated graders", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg());
    expect(await code(w.hub.online.ingest(w.builder, {}))).toBe("forbidden:");
    expect(
      await code(w.hub.online.ingest(runnerOf(w.tenant, "stranger"), { sampling_id: "prod" })),
    ).toBe("forbidden:");
    const bad = (o: Record<string, unknown>) =>
      code(
        w.hub.online.ingest(w.runner, {
          sampling_id: "prod",
          blueprint: bp(),
          scores: { exact: 1 },
          ...o,
        }),
      );
    expect(await bad({ sampling_id: 5 })).toMatch(/^invalid:sampling_id/);
    expect(await bad({ sampling_id: "ghost" })).toBe("not_found:");
    expect(await bad({ blueprint: bp(HASH_A, "other-agent") })).toMatch(/^invalid:blueprint/);
    expect(await bad({ blueprint: { ...bp(), content_hash: "x" } })).toMatch(/^invalid:blueprint/);
    expect(await bad({ scores: {} })).toMatch(/^invalid:scores/);
    expect(await bad({ scores: 1 })).toMatch(/^invalid:scores/);
    expect(await bad({ scores: { nope: 1 } })).toMatch(/scores.nope/);
    expect(await bad({ scores: { exact: 3 } })).toMatch(/scores.exact/);
    expect(await bad({ trace_id: 5 })).toMatch(/^invalid:trace_id/);
    expect(await bad({ source_run_id: "x".repeat(101) })).toMatch(/^invalid:source_run_id/);
    await w.hub.online.disable(w.admin, "prod");
    expect(await bad({})).toBe("conflict:");
    // human graders are not part of the online path
    const w2 = world();
    await seedSuite(w2, {
      graders: [
        { id: "exact", type: "deterministic", kind: "exact" },
        { id: "human", type: "human", rubric: "ok?" },
      ],
    });
    await registerRunner(w2);
    await w2.hub.online.put(w2.admin, "prod", cfg());
    expect(
      await code(
        w2.hub.online.ingest(w2.runner, {
          sampling_id: "prod",
          blueprint: bp(),
          scores: { human: 1 },
        }),
      ),
    ).toMatch(/scores.human/);
  });

  it("enforces the hourly cap and frees capacity as time passes", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg({ max_per_hour: 3, alert_threshold: null }));
    for (let i = 0; i < 3; i++) await ing(w);
    expect(await code(ing(w))).toBe("rate_limited:");
    w.clock.advance(HOUR + 1);
    expect(await code(ing(w))).toBe("ok");
  });
});

describe("history and alerts", () => {
  it("summarises and raises ONE alert per hour when the recent mean falls below the threshold; nothing else changes", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg({ max_per_hour: 50 }));
    for (let i = 0; i < 4; i++) await ing(w, { exact: 0.2, contains: 0.2 });
    const before = await w.hub.online.summary(w.admin, {});
    expect(before[0]).toMatchObject({ count: 4, alerting: false });
    await ing(w, { exact: 0.2, contains: 0.2 });
    await ing(w, { exact: 0.2, contains: 0.2 });
    const s = (
      await w.hub.online.summary(w.builder, {
        blueprint_name: "support-agent",
        suite_ref: "smoke@1.0.0",
      })
    )[0];
    expect(s).toMatchObject({
      sampling_id: "prod",
      count: 6,
      mean: 0.2,
      alerting: true,
      alert_threshold: 0.7,
    });
    expect(s?.recent).toHaveLength(6);
    expect(await events(w, "evals.online.alert")).toHaveLength(1); // five low results raised it, once for the hour
    w.clock.advance(HOUR);
    await ing(w, { exact: 0.2, contains: 0.2 });
    expect(await events(w, "evals.online.alert")).toHaveLength(2);
    expect(s?.recent[0]).toMatchObject({ score: 0.2, blueprint_version: "1.0.0" });
    expect(await w.hub.online.summary(w.admin, { blueprint_name: "other" })).toEqual([]);
    expect(await w.hub.online.summary(w.admin, { suite_ref: "other@1.0.0" })).toEqual([]);
    // good scores bring the window mean back up
    for (let i = 0; i < 20; i++) await ing(w, { exact: 1, contains: 1 });
    expect((await w.hub.online.summary(w.admin, {}))[0]?.alerting).toBe(false);
    // the gate is unaffected by any of it
    const g = await w.hub.gate.check(w.builder, {
      blueprint: bp(),
      suites: [{ ref: "smoke@1.0.0" }],
    });
    expect(g.allowed).toBe(false);
  });
});
