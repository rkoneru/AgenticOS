import { describe, expect, it } from "vitest";
import { HubError } from "../src/index.js";
import {
  HOUR,
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

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : `error:${String(e)}`;
  }
};

const HUMAN_GRADERS = (extra: Record<string, unknown> = {}) => [
  { id: "exact", kind: "deterministic", weight: 1, config: { type: "exact" } },
  {
    id: "human",
    kind: "human",
    weight: 1,
    config: { rubric: "Is the answer helpful?", sla_hours: 24, ...extra },
  },
];

const taskInput = (ids: string[]) =>
  ids.map((id) => ({
    case_id: id,
    grader_id: "human",
    rubric: "Is the answer helpful?",
    input: `q ${id} [email]`,
    output: `answer ${id}`,
    expected: null,
  }));

async function awaiting(extra: Record<string, unknown> = {}, cases = 2) {
  const w = world({ publishers: publishers({ "support-agent@1.0.0": "pat-publisher" }) });
  const ids = Array.from({ length: cases }, (_, i) => `c${i + 1}`);
  await seedSuite(w, {
    graders: HUMAN_GRADERS(extra),
    cases: ids.map((id) => ({ id, input: `q ${id} jane@example.com`, expected: "a" })),
  });
  await registerRunner(w);
  const run = await w.hub.runs.startAsRunner(w.runner, {
    suite_ref: "smoke@1.0.0",
    blueprint: bp(),
  });
  const pending = await w.hub.runs.submitResults(
    w.runner,
    run.id,
    await payloadFor(
      w,
      run,
      caseResults(ids, ["exact", "human"], (_i, g) => (g === "human" ? null : 1)),
    ),
  );
  await w.hub.runs.createReviewTasks(w.runner, run.id, { tasks: taskInput(ids) });
  return { w, run, pending, ids };
}

const rev = (w: World, name: string) => user(w.tenant, "operator", name);

describe("task creation", () => {
  it("creates one task per case and human grader; the run waits and carries no human score", async () => {
    const { w, pending } = await awaiting({}, 3);
    expect(pending).toMatchObject({ status: "running", pending_human: 3, scores: null });
    const tasks = await w.hub.reviews.list(rev(w, "rita"), {});
    expect(tasks).toHaveLength(3);
    expect(tasks[0]).toMatchObject({
      state: "open",
      grader_id: "human",
      sla_breached: false,
      conflicts: ["runner:runner-1", "pat-publisher"],
    });
    expect(tasks[0]?.sla_deadline).toBe(new Date(w.clock.t.getTime() + 24 * HOUR).toISOString());
    expect(JSON.stringify(tasks[0]?.case_input)).toBeDefined();
  });

  it("a runner cannot supply a human score, and review tasks must name pending human cells of its own run", async () => {
    const w = world();
    await seedSuite(w, { graders: HUMAN_GRADERS() });
    await registerRunner(w);
    await registerRunner(w, "runner-2");
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    const ids = ["c1", "c2", "c3", "c4"];
    const scored = caseResults(ids, ["exact", "human"], 1); // human grade "scored" by the runner
    expect(
      await code(
        w.hub.runs.submitResults(
          w.runner,
          run.id,
          await payloadFor(w, run, scored, { status: "completed" }),
        ),
      ),
    ).toMatch(/^invalid:case_results\[0\]\.grades\[1\]\.status/);
    // nothing pending yet: no task can be created
    expect(
      await code(w.hub.runs.createReviewTasks(w.runner, run.id, { tasks: taskInput(ids) })),
    ).toMatch(/^invalid:tasks\[0\]/);
    await w.hub.runs.submitResults(
      w.runner,
      run.id,
      await payloadFor(
        w,
        run,
        caseResults(ids, ["exact", "human"], (_i, g) => (g === "human" ? null : 1)),
      ),
    );
    const t = (tasks: unknown, who = w.runner) =>
      code(w.hub.runs.createReviewTasks(who, run.id, { tasks }));
    expect(await t("x")).toMatch(/^invalid:tasks/);
    expect(await t([])).toMatch(/^invalid:tasks/);
    expect(await t([5])).toMatch(/^invalid:tasks\[0\]/);
    expect(await t([{ case_id: "zzz", grader_id: "human" }])).toMatch(/^invalid:tasks\[0\]/);
    expect(await t([{ case_id: "c1", grader_id: "exact" }])).toMatch(/^invalid:tasks\[0\]/); // not a human grader
    expect(await t([{ ...taskInput(["c1"])[0], rubric: "" }])).toMatch(/rubric/);
    expect(await t([{ ...taskInput(["c1"])[0], output: 5 }])).toMatch(/output/);
    expect(await t([{ ...taskInput(["c1"])[0], input: "x".repeat(70_000) }])).toMatch(
      /^invalid:tasks\[0\]/,
    );
    expect(await t(taskInput(["c1"]), runnerOf(w.tenant, "runner-2"))).toBe("forbidden:");
    expect(await t(taskInput(["c1"]), w.builder as never)).toBe("forbidden:");
    expect(
      await w.hub.runs.createReviewTasks(w.runner, run.id, { tasks: taskInput(["c1", "c2"]) }),
    ).toEqual({ created: 2, existing: 0 });
    // idempotent: re-posting creates nothing new, and the rest can follow later
    expect(await w.hub.runs.createReviewTasks(w.runner, run.id, { tasks: taskInput(ids) })).toEqual(
      { created: 2, existing: 2 },
    );
    expect(await w.hub.reviews.list(rev(w, "rita"), {})).toHaveLength(4);
    // the rubric defaults to the grader's own
    const w3 = await awaiting({}, 1);
    expect(await w3.w.hub.reviews.list(rev(w3.w, "rita"), {})).toHaveLength(1);
  });
});

describe("single grading", () => {
  it("claim -> grade resolves the task, and the last task finalizes the run with the hub's own aggregate", async () => {
    const { w, run, ids } = await awaiting();
    const r = rev(w, "rita");
    const [t1, t2] = await w.hub.reviews.list(r, {});
    await w.hub.reviews.claim(r, (t1 as { id: string }).id);
    const g1 = await w.hub.reviews.grade(r, (t1 as { id: string }).id, {
      score: 1,
      comment: "Great answer for jane@example.com",
    });
    expect(g1).toMatchObject({ state: "resolved", resolution: { score: 1, method: "single" } });
    expect(g1.grades[0]?.comment).toContain("[email]");
    expect(g1.grades[0]?.comment).not.toContain("jane@example.com");
    const mid = await w.hub.runs.get(w.admin, run.id);
    expect(mid).toMatchObject({ status: "running", pending_human: 1 });
    await w.hub.reviews.claim(r, (t2 as { id: string }).id);
    await w.hub.reviews.grade(r, (t2 as { id: string }).id, { score: 0.5, comment: "ok-ish" });
    const done = await w.hub.runs.get(w.admin, run.id);
    // exact = 1 for both cases; human = 1 and 0.5 -> case scores 1 and 0.75 -> overall 0.875
    expect(done).toMatchObject({ status: "passed", pending_human: 0 });
    expect(done.scores?.overall).toBe(0.875);
    expect(done.scores?.per_grader).toEqual({ exact: 1, human: 0.75 });
    expect(ids).toHaveLength(2);
  });

  it("a score below the suite threshold fails the run", async () => {
    const { w, run } = await awaiting();
    const r = rev(w, "rita");
    for (const t of await w.hub.reviews.list(r, {})) {
      await w.hub.reviews.claim(r, t.id);
      await w.hub.reviews.grade(r, t.id, { score: 0, comment: "unhelpful" });
    }
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("failed");
  });
});

describe("separation of duties", () => {
  it("the publisher and the starter can neither see, claim nor grade a task", async () => {
    const { w } = await awaiting();
    const pub = user(w.tenant, "admin", "pat-publisher");
    expect(await w.hub.reviews.list(pub, {})).toEqual([]);
    expect(await w.hub.reviews.list(pub, { all: true })).toEqual([]);
    const any = (await w.hub.reviews.list(rev(w, "rita"), {}))[0] as { id: string };
    expect(await code(w.hub.reviews.get(pub, any.id))).toBe("not_found:");
    expect(await code(w.hub.reviews.claim(pub, any.id))).toBe("forbidden:");
    expect(await code(w.hub.reviews.grade(pub, any.id, { score: 1, comment: "mine" }))).toBe(
      "forbidden:",
    );
    // a task whose run was started by a member excludes that member
    const w2 = world();
    await seedSuite(w2, { graders: HUMAN_GRADERS(), cases: [{ id: "c1", input: "q" }] });
    await registerRunner(w2);
    const q = await w2.hub.runs.request(w2.builder, { suite_ref: "smoke@1.0.0", blueprint: bp() });
    const claimed = await w2.hub.runs.claim(w2.runner, q.id);
    await w2.hub.runs.submitResults(
      w2.runner,
      claimed.id,
      await payloadFor(
        w2,
        claimed,
        caseResults(["c1"], ["exact", "human"], (_i, g) => (g === "human" ? null : 1)),
      ),
    );
    await w2.hub.runs.createReviewTasks(w2.runner, claimed.id, { tasks: taskInput(["c1"]) });
    const starter = user(w2.tenant, "builder", "bob-builder");
    const task = (await w2.hub.reviews.list(rev(w2, "rita"), {}))[0] as {
      id: string;
      conflicts: string[];
    };
    expect(task.conflicts).toContain("bob-builder");
    expect(await code(w2.hub.reviews.claim(starter, task.id))).toBe("forbidden:");
    expect(await code(w2.hub.reviews.claim(rev(w2, "rita"), task.id))).toBe("ok");
  });

  it("only reviewers/operators and up may review; viewers, runners and strangers cannot", async () => {
    const { w } = await awaiting();
    const t = (await w.hub.reviews.list(rev(w, "rita"), {}))[0] as { id: string };
    expect(await code(w.hub.reviews.claim(user(w.tenant, "viewer"), t.id))).toBe("forbidden:");
    expect(await code(w.hub.reviews.claim(w.runner, t.id))).toBe("forbidden:");
    expect(await code(w.hub.reviews.list(user(w.tenant, "viewer"), {}))).toBe("forbidden:");
    expect(
      await code(
        w.hub.reviews.claim(user("00000000-0000-4000-8000-0000000000cc", "operator"), t.id),
      ),
    ).toBe("not_found:");
    expect(await code(w.hub.reviews.claim(user(w.tenant, "reviewer", "rev-only"), t.id))).toBe(
      "ok",
    );
    expect(await code(w.hub.reviews.grade(w.runner, t.id, { score: 1, comment: "x" }))).toBe(
      "forbidden:",
    );
    expect(await code(w.hub.reviews.skip(w.runner, t.id, "x"))).toBe("forbidden:");
    expect(await code(w.hub.reviews.sweep(user(w.tenant, "reviewer")))).toBe("forbidden:");
  });
});

describe("claims, skipping and validation", () => {
  it("a task is held by one claimant until the claim expires; only the claimant grades or skips", async () => {
    const { w } = await awaiting();
    const a = rev(w, "ann");
    const b = rev(w, "ben");
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    expect(await code(w.hub.reviews.claim(b, t.id))).toBe("conflict:");
    expect(await code(w.hub.reviews.grade(b, t.id, { score: 1, comment: "x" }))).toMatch(
      /^conflict/,
    );
    expect(await code(w.hub.reviews.skip(b, t.id, "no"))).toBe("conflict:");
    expect(await code(w.hub.reviews.claim(a, t.id))).toBe("ok"); // re-claim by the holder extends
    w.clock.advance(31 * 60_000);
    expect(await code(w.hub.reviews.grade(a, t.id, { score: 1, comment: "late" }))).toMatch(
      /^conflict/,
    );
    expect(await code(w.hub.reviews.claim(b, t.id))).toBe("ok"); // expired claim is taken over
  });

  it("skipping releases the task and the skipper is not offered it again", async () => {
    const { w } = await awaiting();
    const a = rev(w, "ann");
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    expect(await code(w.hub.reviews.skip(a, t.id, ""))).toMatch(/^invalid/);
    const s = await w.hub.reviews.skip(a, t.id, "outside my expertise");
    expect(s).toMatchObject({ state: "open", claimed_by: null, skipped_by: ["ann"] });
    expect((await w.hub.reviews.list(a, {})).map((x) => x.id)).not.toContain(t.id);
    expect((await w.hub.reviews.list(a, { all: true })).map((x) => x.id)).toContain(t.id);
    expect(await code(w.hub.reviews.claim(a, t.id))).toBe("forbidden:");
  });

  it("validates grades and refuses a second grade after resolution", async () => {
    const { w } = await awaiting();
    const a = rev(w, "ann");
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    for (const g of [
      { score: 2, comment: "x" },
      { score: "1", comment: "x" },
      { score: 0.5, comment: "" },
      { score: 0.5, comment: 5 },
      { score: 0.5, comment: "x".repeat(2001) },
    ])
      expect(await code(w.hub.reviews.grade(a, t.id, g as never))).toMatch(/^invalid/);
    await w.hub.reviews.grade(a, t.id, { score: 1, comment: "fine" });
    expect(await code(w.hub.reviews.grade(a, t.id, { score: 1, comment: "again" }))).toBe(
      "forbidden:",
    );
    expect(await code(w.hub.reviews.claim(rev(w, "ben"), t.id))).toBe("conflict:");
    expect(await code(w.hub.reviews.skip(rev(w, "ben"), t.id, "x"))).toBe("conflict:");
    expect(await code(w.hub.reviews.get(a, "bad id"))).toBe("not_found:");
    expect(await code(w.hub.reviews.get(a, "ghost"))).toBe("not_found:");
    expect((await w.hub.reviews.list(a, { state: "resolved" })).length).toBe(0); // the grader already graded: hidden from their queue
    expect((await w.hub.reviews.list(a, { state: "resolved", all: true })).length).toBe(1);
    expect((await w.hub.reviews.list(rev(w, "ben"), { run_id: "nope" })).length).toBe(0);
  });
});

describe("double grading and adjudication", () => {
  it("two different reviewers whose grades agree resolve to their mean", async () => {
    const { w, run } = await awaiting({ double_grade: true, agreement_tolerance: 0.2 }, 1);
    const a = rev(w, "ann");
    const b = rev(w, "ben");
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    expect(await w.hub.reviews.grade(a, t.id, { score: 0.8, comment: "good" })).toMatchObject({
      state: "open",
      resolution: null,
    });
    // ann cannot grade it twice; ben can
    expect(await code(w.hub.reviews.claim(a, t.id))).toBe("forbidden:");
    expect((await w.hub.reviews.list(a, {})).map((x) => x.id)).not.toContain(t.id);
    await w.hub.reviews.claim(b, t.id);
    const done = await w.hub.reviews.grade(b, t.id, { score: 1, comment: "great" });
    expect(done).toMatchObject({ state: "resolved", resolution: { score: 0.9, method: "agreed" } });
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("passed");
  });

  it("grades that disagree need a THIRD, different reviewer whose grade decides", async () => {
    const { w, run } = await awaiting({ double_grade: true, agreement_tolerance: 0.1 }, 1);
    const [a, b, c] = ["ann", "ben", "cy"].map((n) => rev(w, n)) as [
      ReturnType<typeof rev>,
      ReturnType<typeof rev>,
      ReturnType<typeof rev>,
    ];
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    await w.hub.reviews.grade(a, t.id, { score: 0, comment: "bad" });
    await w.hub.reviews.claim(b, t.id);
    const disputed = await w.hub.reviews.grade(b, t.id, { score: 1, comment: "good" });
    expect(disputed).toMatchObject({ state: "needs_adjudication", resolution: null });
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("running");
    // the two graders are excluded from the adjudication
    expect(await code(w.hub.reviews.claim(a, t.id))).toBe("forbidden:");
    expect(await code(w.hub.reviews.claim(b, t.id))).toBe("forbidden:");
    expect((await w.hub.reviews.list(c, { state: "needs_adjudication" })).map((x) => x.id)).toEqual(
      [t.id],
    );
    await w.hub.reviews.claim(c, t.id);
    // skipping an adjudication keeps it waiting for an adjudicator
    expect(await w.hub.reviews.skip(c, t.id, "conflict of interest")).toMatchObject({
      state: "needs_adjudication",
    });
    const d = rev(w, "dee");
    await w.hub.reviews.claim(d, t.id);
    const fin = await w.hub.reviews.grade(d, t.id, { score: 0.9, comment: "decisive" });
    expect(fin).toMatchObject({
      state: "resolved",
      resolution: { score: 0.9, method: "adjudicated" },
    });
    expect(fin.grades.map((g) => g.adjudication)).toEqual([false, false, true]);
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("passed");
  });
});

describe("SLA", () => {
  it("shows breaches on every view and records each once on sweep", async () => {
    const { w } = await awaiting({ sla_hours: 2 }, 2);
    const a = rev(w, "ann");
    expect((await w.hub.reviews.list(a, {})).every((t) => !t.sla_breached)).toBe(true);
    expect(await w.hub.reviews.sweep(w.admin)).toEqual([]);
    w.clock.advance(3 * HOUR);
    expect((await w.hub.reviews.list(a, {})).every((t) => t.sla_breached)).toBe(true);
    const marked = await w.hub.reviews.sweep(w.admin);
    expect(marked).toHaveLength(2);
    expect(await w.hub.reviews.sweep(w.admin)).toEqual([]);
    // a breached task can still be graded, and a resolved one is not reported
    const t = (await w.hub.reviews.list(a, {}))[0] as { id: string };
    await w.hub.reviews.claim(a, t.id);
    await w.hub.reviews.grade(a, t.id, { score: 1, comment: "late but done" });
    expect((await w.hub.reviews.get(a, t.id)).sla_breached).toBe(false);
  });
});
