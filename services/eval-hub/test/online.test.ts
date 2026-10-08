import { describe, expect, it } from "vitest";
import { HubError } from "../src/index.js";
import {
  HOUR,
  events,
  onlineSample,
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
  grades: Record<string, number | null> = { exact: 1, contains: 1 },
  patch?: (p: Record<string, unknown>) => void,
) => w.hub.online.ingest(w.runner, onlineSample(grades, patch ? { patch } : {}));

describe("sampling configs", () => {
  it("are created and updated by an admin, listed, served to runners in the runner's shape, and disabled", async () => {
    const w = await ready();
    const c1 = await w.hub.online.put(w.admin, "prod", cfg());
    expect(c1).toMatchObject({
      id: "prod",
      rate: 0.1,
      max_per_hour: 5,
      redaction: "phi",
      enabled: true,
      updated_by: "alice-admin",
    });
    const c2 = await w.hub.online.put(
      w.admin,
      "prod",
      cfg({ rate: 0.5, redaction: "always", alert_threshold: null }),
    );
    expect(c2).toMatchObject({ rate: 0.5, redaction: "always", alert_threshold: null });
    expect(await w.hub.online.list(w.builder)).toHaveLength(1);
    expect(await w.hub.online.list(w.runner)).toHaveLength(1);
    expect(await w.hub.online.runnerConfigs(w.runner)).toEqual([
      {
        blueprint: "support-agent",
        suite_ref: "smoke@1.0.0",
        rate: 0.5,
        max_per_hour: 5,
        redaction: "always",
      },
    ]);
    expect(await code(w.hub.online.runnerConfigs(w.builder))).toBe("forbidden:");
    expect((await w.hub.online.disable(w.admin, "prod")).enabled).toBe(false);
    expect(await w.hub.online.runnerConfigs(w.runner)).toEqual([]);
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
    expect(await t({ redaction: "redact" })).toMatch(/redaction/);
    expect(await t({ enabled: "yes" })).toMatch(/enabled/);
    expect(await t({ alert_threshold: 3 })).toMatch(/alert_threshold/);
  });
});

describe("ingestion", () => {
  it("stores scores and ids only (never the sampled output, trace or review tasks), recomputing the score from the grades", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg());
    const r = await ing(w, { exact: 1, contains: 0.5 });
    expect(r).toMatchObject({
      sampling_id: "prod",
      score: 0.75,
      status: "complete",
      runner_id: "runner-1",
      trace_id: "tr-online-1",
      source_run_id: "run-prod-1",
      scores: { exact: 1, contains: 0.5 },
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
      "status",
      "suite_ref",
      "trace_id",
    ]);
    expect(JSON.stringify(await w.docs.find(w.tenant, "online"))).not.toContain("never stored");
    // a human grade parks the sample without a score
    const w2 = world();
    await seedSuite(w2, {
      graders: [
        { id: "exact", kind: "deterministic", weight: 1, config: { type: "exact" } },
        { id: "human", kind: "human", weight: 1, config: { rubric: "ok?" } },
      ],
    });
    await registerRunner(w2);
    await w2.hub.online.put(w2.admin, "prod", cfg());
    const p = await w2.hub.online.ingest(
      w2.runner,
      onlineSample({ exact: 1, human: null }, { kinds: { human: "human" } }),
    );
    expect(p).toMatchObject({ status: "pending_human", score: null, scores: { exact: 1 } });
    expect((await w2.hub.online.summary(w2.admin, {}))[0]).toMatchObject({ count: 0, mean: null });
  });

  it("REJECTS a score or status that does not match the grades", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg());
    expect(await code(ing(w, { exact: 1, contains: 0.5 }, (p) => (p["score"] = 1)))).toBe(
      "integrity_failed:mismatch.score",
    );
    expect(
      await code(ing(w, { exact: 1, contains: 0.5 }, (p) => (p["status"] = "pending_human"))),
    ).toBe("integrity_failed:mismatch.score");
    expect(await code(ing(w, { exact: 1, contains: 0.5 }, (p) => (p["score"] = null)))).toBe(
      "integrity_failed:mismatch.score",
    );
  });

  it("is limited to registered runners, enabled configs, the configured blueprint and the suite's own graders", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod", cfg());
    expect(await code(w.hub.online.ingest(w.builder, {}))).toBe("forbidden:");
    expect(
      await code(
        w.hub.online.ingest(
          runnerOf(w.tenant, "stranger"),
          onlineSample({ exact: 1 }, { patch: (p) => (p["runner_id"] = "stranger") }),
        ),
      ),
    ).toBe("forbidden:");
    const bad = (
      patch: (p: Record<string, unknown>) => void,
      grades: Record<string, number | null> = { exact: 1, contains: 1 },
    ) => code(ing(w, grades, patch));
    expect(await bad((p) => (p["mode"] = "ci"))).toMatch(/^invalid:mode/);
    expect(await bad((p) => (p["runner_id"] = "runner-9"))).toBe("integrity_failed:runner_id");
    expect(await bad((p) => (p["blueprint"] = 5))).toMatch(/^invalid:blueprint/);
    expect(
      await bad(
        (p) => (p["blueprint"] = { name: "support-agent", version: "", content_hash: "x" }),
      ),
    ).toMatch(/^invalid:blueprint/);
    expect(
      await bad(
        (p) =>
          (p["blueprint"] = { name: "other-agent", version: "1", content_hash: "a".repeat(64) }),
      ),
    ).toBe("not_found:");
    expect(await bad((p) => (p["suite_ref"] = "other@1.0.0"))).toBe("not_found:");
    expect(await bad((p) => (p["grades"] = []))).toMatch(/^invalid:grades/);
    expect(await bad((p) => (p["grades"] = 5))).toMatch(/^invalid:grades/);
    expect(
      await bad((p) => ((p["grades"] as { grader_id: string }[])[0]!.grader_id = "ghost")),
    ).toMatch(/^invalid:grades\[0\]/);
    expect(await bad((p) => ((p["grades"] as { kind: string }[])[0]!.kind = "human"))).toMatch(
      /^invalid:grades\[0\]/,
    );
    expect(await bad((p) => ((p["grades"] as { status: string }[])[0]!.status = "maybe"))).toMatch(
      /grades\[0\]\.status/,
    );
    expect(
      await bad((p) => ((p["grades"] as { status: string }[])[0]!.status = "pending")),
    ).toMatch(/grades\[0\]\.status/);
    expect(
      await bad(
        (p) => (p["grades"] = [...(p["grades"] as object[]), ...(p["grades"] as object[])]),
        { exact: 1 },
      ),
    ).toMatch(/^invalid:grades/);
    expect(
      await bad((p) => (p["grades"] as object[]).push((p["grades"] as object[])[0]!), {
        exact: 1,
        contains: 1,
      }),
    ).toMatch(/^invalid:grades/);
    expect(await bad((p) => (p["source_run_id"] = 5))).toMatch(/^invalid:source_run_id/);
    expect(await bad((p) => (p["trace"] = "x"))).toBe("ok"); // a malformed trace only loses the trace id
    await w.hub.online.disable(w.admin, "prod");
    expect(await bad(() => undefined)).toBe("not_found:");
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
    expect((await w.hub.online.summary(w.admin, {}))[0]).toMatchObject({
      count: 4,
      alerting: false,
    });
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
    expect(s?.recent[0]).toMatchObject({ score: 0.2, blueprint_version: "1.0.0" });
    expect(await events(w, "evals.online.alert")).toHaveLength(1);
    w.clock.advance(HOUR);
    await ing(w, { exact: 0.2, contains: 0.2 });
    expect(await events(w, "evals.online.alert")).toHaveLength(2);
    expect(await w.hub.online.summary(w.admin, { blueprint_name: "other" })).toEqual([]);
    expect(await w.hub.online.summary(w.admin, { suite_ref: "other@1.0.0" })).toEqual([]);
    for (let i = 0; i < 20; i++) await ing(w, { exact: 1, contains: 1 });
    expect((await w.hub.online.summary(w.admin, {}))[0]?.alerting).toBe(false);
    const g = await w.hub.gate.check(w.builder, {
      blueprint: { name: "support-agent", version: "1.0.0", content_hash: "a".repeat(64) },
      suites: [{ ref: "smoke@1.0.0" }],
    });
    expect(g.allowed).toBe(false);
  });
});
