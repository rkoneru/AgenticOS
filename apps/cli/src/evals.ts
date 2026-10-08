import { readFileSync } from "node:fs";
import { AxisWaitTimeoutError, type Axis } from "@axis/sdk";
import { parse } from "yaml";
import type { Command, Ctx, FlagSpec } from "./cli.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import { inert, keyValues, structured, table } from "./render.js";

/**
 * `axis evals ...` (OpenAPI 1.3.0, ADR 0057): run suites, read results, ask the release gate, manage datasets, suites, baselines,
 * human review, online sampling and runners.
 *
 * Exit codes: `evals gate` exits 4 (the release is DENIED) when the gate does not allow; `evals run --wait` / `evals wait` exit 1 for a
 * run that failed or errored and 5 when the wait timed out. Text that came from the server (reasons, comments, rubrics) is printed inert.
 */

function emit(ctx: Ctx, data: unknown, human: () => string): void {
  ctx.out(ctx.format === "table" ? human() : structured(data, ctx.format));
}

function need(ctx: Ctx, n: number, usage: string): string[] {
  if (ctx.args.length < n) throw new UsageError(`missing argument; usage: axis ${usage}`);
  if (ctx.args.length > n)
    throw new UsageError(`unexpected argument "${ctx.args[n]}"; usage: axis ${usage}`);
  return ctx.args;
}

async function readDoc(ctx: Ctx, path: string): Promise<Record<string, unknown>> {
  let text: string;
  if (path === "-") {
    if (!ctx.deps.readStdin) throw new UsageError("reading from stdin is not available here");
    text = await ctx.deps.readStdin();
  } else {
    try {
      text = readFileSync(path, "utf8");
    } catch (e) {
      throw new CliError(`cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  }
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (e) {
    throw new CliError(`${path} is not valid YAML/JSON: ${(e as Error).message.split("\n")[0]}`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc))
    throw new CliError(`${path} must contain an object`);
  return doc as Record<string, unknown>;
}

const IDEM: FlagSpec = {
  name: "idempotency-key",
  type: "string",
  placeholder: "<key>",
  desc: "Idempotency key (default: generated)",
};
const WAIT_TIMEOUT: FlagSpec = {
  name: "wait-timeout",
  type: "number",
  placeholder: "<seconds>",
  desc: "Give up waiting after this long (default 300)",
};

const pct = (n: unknown): string => (typeof n === "number" ? n.toFixed(4) : "-");

async function waitFinal(ctx: Ctx, ax: Axis, id: string) {
  try {
    return await ax.evals.wait(id, {
      timeoutMs: (ctx.num("wait-timeout") ?? 300) * 1000,
      pollIntervalMs: 1000,
    });
  } catch (e) {
    if (e instanceof AxisWaitTimeoutError)
      throw new CliError(`eval run ${id} did not finish in time`, EXIT.APPROVAL_PENDING, [
        `check later with: axis evals get ${id}`,
      ]);
    throw e;
  }
}

type RunLike = {
  id: string;
  suite: string;
  status: string;
  score?: number | null | undefined;
  threshold?: number | null | undefined;
  blueprint?: { name: string; version: string; content_hash: string } | undefined;
  mode?: string | undefined;
  pending_human?: number | undefined;
  runner_id?: string | null | undefined;
  finished_at?: string | null | undefined;
  failure_reason?: string | null | undefined;
};

const runPairs = (r: RunLike): Array<[string, unknown]> => [
  ["eval run", r.id],
  ["suite", r.suite],
  ["blueprint", r.blueprint ? `${r.blueprint.name}@${r.blueprint.version}` : undefined],
  ["content hash", r.blueprint?.content_hash],
  ["mode", r.mode],
  ["status", r.status],
  ["score", r.score],
  ["threshold", r.threshold],
  ["waiting for human review", r.pending_human],
  ["runner", r.runner_id],
  ["finished", r.finished_at],
  [
    "failure",
    r.failure_reason === null || r.failure_reason === undefined
      ? undefined
      : inert(r.failure_reason),
  ],
];

function finalExit(r: RunLike): number {
  return r.status === "passed" ? EXIT.OK : EXIT.ERROR;
}

async function evalsRun(ctx: Ctx): Promise<number> {
  const [suite, ref] = need(ctx, 2, "evals run <suite> <[namespace/]name@version> [--wait]");
  const ax = ctx.client();
  const mode = ctx.str("mode") as "ci" | "manual" | undefined;
  const key = ctx.str("idempotency-key");
  let e: RunLike = await ax.evals.start({
    suite: suite as string,
    blueprint: ref as string,
    ...(mode ? { mode } : {}),
    ...(key ? { idempotencyKey: key } : {}),
  });
  if (ctx.bool("wait")) e = await waitFinal(ctx, ax, e.id);
  emit(ctx, e, () => keyValues(runPairs(e), ctx.style));
  return ctx.bool("wait") ? finalExit(e) : EXIT.OK;
}

async function evalsGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals get <eval-run-id>");
  const r = await ctx.client().evals.get(id as string);
  emit(ctx, r, () => {
    const head = keyValues(runPairs(r), ctx.style);
    const per = r.scores?.per_grader ?? {};
    const graders = Object.entries(per).map(
      ([g, v]) => [`grader ${g}`, pct(v)] as [string, unknown],
    );
    const failures = r.scores?.failures ?? [];
    return [
      head,
      graders.length ? keyValues(graders, ctx.style) : "",
      failures.length ? `failures: ${failures.map(inert).join("; ")}` : "",
    ]
      .filter(Boolean)
      .join("\n");
  });
  return EXIT.OK;
}

async function evalsWait(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals wait <eval-run-id>");
  const ax = ctx.client();
  const r = await waitFinal(ctx, ax, id as string);
  emit(ctx, r, () => keyValues(runPairs(r), ctx.style));
  return finalExit(r);
}

async function evalsList(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const limit = ctx.num("limit");
  const suite = ctx.str("suite");
  const blueprint = ctx.str("blueprint");
  const status = ctx.str("status") as "passed" | undefined;
  const q = {
    ...(suite ? { suite } : {}),
    ...(blueprint ? { blueprint } : {}),
    ...(status ? { status } : {}),
  };
  const items: RunLike[] = [];
  if (ctx.bool("all")) for await (const r of ax.evals.iterate(q)) items.push(r);
  else items.push(...(await ax.evals.list({ ...q, ...(limit ? { limit } : {}) })).items);
  emit(ctx, { items }, () =>
    table(
      items,
      [
        { header: "id", get: (r) => r.id },
        { header: "suite", get: (r) => r.suite },
        {
          header: "blueprint",
          get: (r) => (r.blueprint ? `${r.blueprint.name}@${r.blueprint.version}` : "-"),
        },
        { header: "status", get: (r) => r.status },
        {
          header: "score",
          get: (r) => (r.score === null || r.score === undefined ? "-" : pct(r.score)),
        },
        { header: "finished", get: (r) => r.finished_at },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function evalsCompare(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals compare <eval-run-id>");
  const c = await ctx.client().evals.comparison(id as string);
  emit(ctx, c ?? {}, () =>
    c
      ? keyValues(
          [
            ["baseline run", c.baseline_run_id],
            ["comparable", c.comparable],
            ["delta", c.delta],
            ["tolerance", c.tolerance],
            ["regression", c.regression],
            ["blocks release", c.blocking],
            [
              "paired test",
              c.significance ? `${c.significance.method} p=${c.significance.p_value}` : undefined,
            ],
          ],
          ctx.style,
        )
      : "no baseline for this blueprint and suite",
  );
  return c?.blocking ? EXIT.POLICY_DENIED : EXIT.OK;
}

/** `name@version` or `namespace/name@version` -> content hash and the suites its ABL declares. */
async function resolveBlueprint(ctx: Ctx, ref: string) {
  const ax = ctx.client();
  const slash = ref.indexOf("/");
  const at = ref.lastIndexOf("@");
  if (at <= 0 || at === ref.length - 1)
    throw new UsageError("expected [<namespace>/]<name>@<version>; usage: axis evals gate <ref>");
  if (slash > 0) {
    const r = await ax.registry.resolve(ref);
    const abl = r.abl as { spec?: { evals?: { suites?: { ref: string; threshold: number }[] } } };
    return {
      blueprint: {
        namespace: r.namespace,
        name: r.name,
        version: r.version,
        content_hash: r.content_hash,
      },
      suites: abl.spec?.evals?.suites ?? [],
    };
  }
  const v = await ax.blueprints.get(ref.slice(0, at), ref.slice(at + 1));
  const abl = v.abl as { spec?: { evals?: { suites?: { ref: string; threshold: number }[] } } };
  if (!v.content_hash) throw new CliError(`${ref} has no content hash; it cannot be gated`);
  return {
    blueprint: { name: v.name, version: v.version, content_hash: v.content_hash },
    suites: abl.spec?.evals?.suites ?? [],
  };
}

async function evalsGate(ctx: Ctx): Promise<number> {
  const [ref] = need(
    ctx,
    1,
    "evals gate <[namespace/]name@version> [--suite <ref[:threshold]>]...",
  );
  const { blueprint, suites } = await resolveBlueprint(ctx, ref as string);
  const given = ctx.list("suite").map((s) => {
    const i = s.lastIndexOf(":");
    const t = i > 0 ? Number(s.slice(i + 1)) : Number.NaN;
    return Number.isFinite(t) && t >= 0 && t <= 1 && !s.slice(i + 1).includes("@")
      ? { ref: s.slice(0, i), threshold: t }
      : { ref: s };
  });
  // The blueprint's own declared suites are always asked, in addition to any --suite given.
  const wanted = [...suites, ...given];
  const g = await ctx.client().evals.gate({ blueprint, suites: wanted });
  emit(ctx, g, () => {
    const head = g.allowed
      ? `ALLOWED: ${blueprint.name}@${blueprint.version} (${blueprint.content_hash.slice(0, 12)}) passes ${g.runs.length} suite(s)`
      : `BLOCKED: ${blueprint.name}@${blueprint.version} (${blueprint.content_hash.slice(0, 12)})`;
    const reasons = g.reasons.map(
      (r) => `  - ${r.code}${r.suite_ref ? ` [${r.suite_ref}]` : ""}: ${inert(r.message)}`,
    );
    const runs = g.runs.map(
      (r) =>
        `  ${r.suite_ref}: ${r.run_id ?? "no run"} score ${r.overall ?? "-"} (needs ${r.required_threshold})`,
    );
    return [head, ...reasons, ...runs].join("\n");
  });
  return g.allowed ? EXIT.OK : EXIT.POLICY_DENIED;
}

// ---- datasets, suites, baselines, review, sampling, runners ----------------------------------------------------------------------

async function datasetsList(ctx: Ctx): Promise<number> {
  const name = ctx.str("name");
  const r = await ctx.client().evals.datasets.list(name ? { name } : {});
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "ref", get: (d) => d.ref },
        { header: "cases", get: (d) => d.case_count },
        { header: "phi", get: (d) => d.phi },
        { header: "hash", get: (d) => d.content_hash.slice(0, 12) },
        { header: "created", get: (d) => d.created_at },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function datasetsGet(ctx: Ctx): Promise<number> {
  const [name, version] = ctx.args;
  if (!name || ctx.args.length > 2)
    throw new UsageError("usage: axis evals datasets get <name> [version|latest]");
  const v = version === undefined || version === "latest" ? "latest" : Number(version);
  if (v !== "latest" && !Number.isInteger(v))
    throw new UsageError("version must be an integer or latest");
  const d = await ctx.client().evals.datasets.get(name, v);
  emit(ctx, d, () =>
    keyValues(
      [
        ["ref", d.ref],
        ["cases", d.case_count],
        ["phi", d.phi],
        ["version hash", d.content_hash],
        ["created", d.created_at],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function datasetsCreate(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "evals datasets create <file.yaml|json|->");
  const doc = await readDoc(ctx, file as string);
  const key = ctx.str("idempotency-key");
  const d = await ctx
    .client()
    .evals.datasets.create(doc as never, key ? { idempotencyKey: key } : {});
  emit(
    ctx,
    d,
    () =>
      `created ${d.ref} (${d.case_count} cases${d.phi ? ", PHI redacted before storage" : ""}) hash ${d.content_hash.slice(0, 12)}`,
  );
  return EXIT.OK;
}

async function suitesList(ctx: Ctx): Promise<number> {
  const r = await ctx.client().evals.suites.list();
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "ref", get: (s) => s.ref },
        { header: "dataset", get: (s) => s.dataset_ref },
        { header: "graders", get: (s) => s.graders.map((g) => g.id).join(",") },
        { header: "pass", get: (s) => s.pass_threshold },
        { header: "tolerance", get: (s) => s.tolerance },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function suitesGet(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "evals suites get <name@version>");
  const s = await ctx.client().evals.suites.get(ref as string);
  emit(ctx, s, () =>
    keyValues(
      [
        ["ref", s.ref],
        ["dataset", s.dataset_ref],
        ["graders", s.graders.map((g) => `${g.id} (${g.kind})`).join(", ")],
        ["pass threshold", s.pass_threshold],
        ["tolerance", s.tolerance],
        ["min case score", s.min_case_score],
        ["max age (days)", s.max_age_days],
        ["suite hash", s.suite_hash],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function suitesCreate(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "evals suites create <file.yaml|json|->");
  const doc = await readDoc(ctx, file as string);
  const key = ctx.str("idempotency-key");
  const s = await ctx
    .client()
    .evals.suites.create(doc as never, key ? { idempotencyKey: key } : {});
  emit(
    ctx,
    s,
    () =>
      `created ${s.ref} over ${s.dataset_ref} (${s.graders.length} grader(s), pass at ${s.pass_threshold})`,
  );
  return EXIT.OK;
}

async function baselineList(ctx: Ctx): Promise<number> {
  const [bp, suite] = need(ctx, 2, "evals baseline list <blueprint-name> <suite>");
  const r = await ctx.client().evals.baselines.list(bp as string, suite as string);
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "seq", get: (b) => b.seq },
        { header: "run", get: (b) => b.run_id },
        { header: "score", get: (b) => b.overall },
        { header: "set by", get: (b) => b.set_by },
        { header: "at", get: (b) => b.at },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function baselineSet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals baseline set <eval-run-id>");
  const key = ctx.str("idempotency-key");
  const b = await ctx
    .client()
    .evals.baselines.set(id as string, key ? { idempotencyKey: key } : {});
  emit(
    ctx,
    b,
    () =>
      `baseline #${b.seq} of ${b.blueprint_name} for ${b.suite_ref} is run ${b.run_id} (score ${b.overall})`,
  );
  return EXIT.OK;
}

type TaskLike = {
  id: string;
  run_id: string;
  case_id: string;
  grader_id: string;
  rubric: string;
  state: string;
  sla_deadline: string;
  sla_breached: boolean;
  case_output?: string | null | undefined;
  claimed_by?: string | null | undefined;
};

const taskPairs = (t: TaskLike): Array<[string, unknown]> => [
  ["task", t.id],
  ["run", t.run_id],
  ["case", t.case_id],
  ["grader", t.grader_id],
  ["rubric", inert(t.rubric)],
  ["state", t.state],
  ["sla deadline", `${t.sla_deadline}${t.sla_breached ? " (BREACHED)" : ""}`],
];

async function reviewTasks(ctx: Ctx): Promise<number> {
  const state = ctx.str("state") as "open" | undefined;
  const run = ctx.str("run");
  const r = await ctx
    .client()
    .evals.review.tasks({ ...(state ? { state } : {}), ...(run ? { run_id: run } : {}) });
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "task", get: (t) => t.id },
        { header: "run", get: (t) => t.run_id },
        { header: "case", get: (t) => t.case_id },
        { header: "grader", get: (t) => t.grader_id },
        { header: "state", get: (t) => t.state },
        { header: "sla deadline", get: (t) => `${t.sla_deadline}${t.sla_breached ? " !" : ""}` },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function reviewClaim(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals review claim <task-id>");
  const t = await ctx.client().evals.review.claim(id as string);
  emit(ctx, t, () => keyValues(taskPairs(t as TaskLike), ctx.style));
  return EXIT.OK;
}

async function reviewGrade(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals review grade <task-id> --score <0-1> --comment <text>");
  const score = ctx.num("score");
  const comment = ctx.str("comment");
  if (score === undefined || comment === undefined)
    throw new UsageError("--score and --comment are required");
  const t = await ctx.client().evals.review.grade(id as string, { score, comment });
  emit(
    ctx,
    t,
    () =>
      `task ${t.id} is ${t.state}${t.resolution ? ` (score ${t.resolution.score}, ${t.resolution.method})` : ""}`,
  );
  return EXIT.OK;
}

async function reviewSkip(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals review skip <task-id> --reason <text>");
  const reason = ctx.str("reason");
  if (!reason) throw new UsageError("--reason is required");
  const t = await ctx.client().evals.review.skip(id as string, reason);
  emit(ctx, t, () => `task ${t.id} released (${t.state})`);
  return EXIT.OK;
}

async function samplingList(ctx: Ctx): Promise<number> {
  const r = await ctx.client().evals.sampling.list();
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "id", get: (c) => c.id },
        { header: "blueprint", get: (c) => c.blueprint_name },
        { header: "suite", get: (c) => c.suite_ref },
        { header: "rate", get: (c) => c.rate },
        { header: "max/hour", get: (c) => c.max_per_hour },
        { header: "redaction", get: (c) => c.redaction },
        { header: "enabled", get: (c) => c.enabled },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function samplingPut(ctx: Ctx): Promise<number> {
  const [id, file] = need(ctx, 2, "evals sampling put <sampling-id> <file.yaml|json|->");
  const doc = await readDoc(ctx, file as string);
  const c = await ctx.client().evals.sampling.put(id as string, doc as never);
  emit(
    ctx,
    c,
    () =>
      `sampling ${c.id}: ${c.blueprint_name} / ${c.suite_ref} at rate ${c.rate}, max ${c.max_per_hour}/hour (${c.enabled ? "enabled" : "disabled"})`,
  );
  return EXIT.OK;
}

async function samplingSummary(ctx: Ctx): Promise<number> {
  const blueprint = ctx.str("blueprint");
  const suite = ctx.str("suite");
  const r = await ctx
    .client()
    .evals.sampling.summary({ ...(blueprint ? { blueprint } : {}), ...(suite ? { suite } : {}) });
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "sampling", get: (s) => s.sampling_id },
        { header: "samples", get: (s) => s.count },
        { header: "mean", get: (s) => s.mean },
        { header: "recent mean", get: (s) => s.window.mean },
        { header: "alerting", get: (s) => s.alerting },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function runnersList(ctx: Ctx): Promise<number> {
  const r = await ctx.client().evals.runners.list();
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "runner", get: (x) => x.runner_id },
        { header: "registered", get: (x) => x.registered_at },
        { header: "revoked", get: (x) => x.revoked_at },
        { header: "description", get: (x) => (x.description ? inert(x.description) : "-") },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function runnersRegister(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals runners register <runner-id> [--description <text>]");
  const d = ctx.str("description");
  const r = await ctx.client().evals.runners.register(id as string, d);
  emit(ctx, r, () => `runner ${r.runner_id} registered`);
  return EXIT.OK;
}

async function runnersRevoke(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "evals runners revoke <runner-id>");
  const r = await ctx.client().evals.runners.revoke(id as string);
  emit(
    ctx,
    r,
    () =>
      `runner ${r.runner_id} revoked${r.revoked_at ? ` at ${r.revoked_at}` : ""}; its runs no longer count`,
  );
  return EXIT.OK;
}

const LIMIT_FLAGS: readonly FlagSpec[] = [
  { name: "limit", type: "number", placeholder: "<n>", desc: "Page size (1-200)" },
  { name: "all", type: "boolean", desc: "Follow every page" },
];
const WAIT_FLAGS: readonly FlagSpec[] = [
  {
    name: "wait",
    type: "boolean",
    desc: "Wait for the run to finish (exit 1 if it did not pass, 5 on timeout)",
  },
  WAIT_TIMEOUT,
];

export const EVALS_COMMANDS: Command[] = [
  { path: ["evals"], summary: "Eval Hub: suites, runs, release gate, human review" },
  {
    path: ["evals", "run"],
    summary: "Queue an eval run of a suite against a blueprint version",
    usage: "<suite> <[namespace/]name@version>",
    description:
      "The run is bound to the version's content hash and executed by a registered runner. With --wait the exit code is 0 only if the run passed.",
    flags: [
      {
        name: "mode",
        type: "string",
        placeholder: "<mode>",
        choices: ["ci", "manual"],
        desc: "Run mode (default ci)",
      },
      IDEM,
      ...WAIT_FLAGS,
    ],
    run: evalsRun,
  },
  {
    path: ["evals", "start"],
    summary: "Alias of `evals run`",
    usage: "<suite> <[namespace/]name@version>",
    flags: [
      {
        name: "mode",
        type: "string",
        placeholder: "<mode>",
        choices: ["ci", "manual"],
        desc: "Run mode (default ci)",
      },
      IDEM,
      ...WAIT_FLAGS,
    ],
    run: evalsRun,
  },
  {
    path: ["evals", "get"],
    summary: "Show one eval run with its scores",
    usage: "<eval-run-id>",
    run: evalsGet,
  },
  {
    path: ["evals", "wait"],
    summary: "Wait for an eval run to finish",
    usage: "<eval-run-id>",
    flags: [WAIT_TIMEOUT],
    run: evalsWait,
  },
  {
    path: ["evals", "list"],
    summary: "List eval runs, newest first",
    flags: [
      ...LIMIT_FLAGS,
      { name: "suite", type: "string", placeholder: "<ref>", desc: "Only this suite" },
      {
        name: "blueprint",
        type: "string",
        placeholder: "<name>",
        desc: "Only this blueprint name",
      },
      {
        name: "status",
        type: "string",
        placeholder: "<status>",
        choices: ["queued", "running", "passed", "failed", "errored"],
        desc: "Only this status",
      },
    ],
    run: evalsList,
  },
  {
    path: ["evals", "compare"],
    summary: "Compare a run with the baseline (delta, regression, paired significance)",
    usage: "<eval-run-id>",
    description: "Exits 4 when the run regressed beyond the suite's tolerance.",
    run: evalsCompare,
  },
  {
    path: ["evals", "gate"],
    summary: "Ask the release gate whether a blueprint version may be released",
    usage: "<[namespace/]name@version>",
    description:
      "Fail-closed: exits 0 only when every required suite has a fresh, intact, passing run of this exact content hash by a registered runner with no regression against the baseline. Exits 4 and lists every reason otherwise.",
    flags: [
      {
        name: "suite",
        type: "repeat",
        placeholder: "<ref[:threshold]>",
        desc: "An additional required suite (the blueprint's own spec.evals.suites are always asked)",
      },
    ],
    run: evalsGate,
  },
  { path: ["evals", "datasets"], summary: "Datasets (immutable numbered versions)" },
  {
    path: ["evals", "datasets", "list"],
    summary: "List dataset versions",
    flags: [{ name: "name", type: "string", placeholder: "<name>", desc: "Only this dataset" }],
    run: datasetsList,
  },
  {
    path: ["evals", "datasets", "get"],
    summary: "Show a dataset version",
    usage: "<name> [version|latest]",
    run: datasetsGet,
  },
  {
    path: ["evals", "datasets", "create"],
    summary: "Create the next version of a dataset from a YAML/JSON file",
    usage: "<file|->",
    description:
      "The file holds {name, cases: [{id, input, expected?, tags?, metadata?}], phi?, description?}. A phi dataset is redacted before it is stored.",
    flags: [IDEM],
    run: datasetsCreate,
  },
  { path: ["evals", "suites"], summary: "Suites (immutable definitions)" },
  { path: ["evals", "suites", "list"], summary: "List suites", run: suitesList },
  {
    path: ["evals", "suites", "get"],
    summary: "Show a suite",
    usage: "<name@version>",
    run: suitesGet,
  },
  {
    path: ["evals", "suites", "create"],
    summary: "Create a suite from a YAML/JSON file",
    usage: "<file|->",
    description:
      "The file holds {ref, dataset_ref, graders, pass_threshold, tolerance?, min_case_score?, settings?, ...}.",
    flags: [IDEM],
    run: suitesCreate,
  },
  { path: ["evals", "baseline"], summary: "Baselines (the run a release is judged against)" },
  {
    path: ["evals", "baseline", "list"],
    summary: "Baseline history",
    usage: "<blueprint-name> <suite>",
    run: baselineList,
  },
  {
    path: ["evals", "baseline", "set"],
    summary: "Make a passed run the baseline (admin)",
    usage: "<eval-run-id>",
    flags: [IDEM],
    run: baselineSet,
  },
  { path: ["evals", "review"], summary: "Human review of eval grades" },
  {
    path: ["evals", "review", "tasks"],
    summary: "Tasks you may work on",
    flags: [
      {
        name: "state",
        type: "string",
        placeholder: "<state>",
        choices: ["open", "claimed", "needs_adjudication", "resolved"],
        desc: "Only this state",
      },
      { name: "run", type: "string", placeholder: "<eval-run-id>", desc: "Only this run" },
    ],
    run: reviewTasks,
  },
  {
    path: ["evals", "review", "claim"],
    summary: "Claim a task",
    usage: "<task-id>",
    run: reviewClaim,
  },
  {
    path: ["evals", "review", "grade"],
    summary: "Grade a claimed task",
    usage: "<task-id> --score <0-1> --comment <text>",
    flags: [
      { name: "score", type: "number", placeholder: "<0-1>", desc: "Your score" },
      {
        name: "comment",
        type: "string",
        placeholder: "<text>",
        desc: "Why (redacted for personal data before it is stored)",
      },
    ],
    run: reviewGrade,
  },
  {
    path: ["evals", "review", "skip"],
    summary: "Give a claimed task back",
    usage: "<task-id> --reason <text>",
    flags: [{ name: "reason", type: "string", placeholder: "<text>", desc: "Why you skip it" }],
    run: reviewSkip,
  },
  {
    path: ["evals", "sampling"],
    summary: "Online sampling of production runs (alerts and history only)",
  },
  { path: ["evals", "sampling", "list"], summary: "Sampling configurations", run: samplingList },
  {
    path: ["evals", "sampling", "put"],
    summary: "Create or replace a sampling configuration (admin)",
    usage: "<sampling-id> <file|->",
    run: samplingPut,
  },
  {
    path: ["evals", "sampling", "summary"],
    summary: "History and alert state of the samples",
    flags: [
      { name: "blueprint", type: "string", placeholder: "<name>", desc: "Only this blueprint" },
      { name: "suite", type: "string", placeholder: "<ref>", desc: "Only this suite" },
    ],
    run: samplingSummary,
  },
  {
    path: ["evals", "runners"],
    summary: "Eval runners (only registered runners count toward a gate)",
  },
  { path: ["evals", "runners", "list"], summary: "Registered runners", run: runnersList },
  {
    path: ["evals", "runners", "register"],
    summary: "Register a runner id (admin)",
    usage: "<runner-id>",
    flags: [{ name: "description", type: "string", placeholder: "<text>", desc: "What it is" }],
    run: runnersRegister,
  },
  {
    path: ["evals", "runners", "revoke"],
    summary: "Revoke a runner (admin, one-way)",
    usage: "<runner-id>",
    run: runnersRevoke,
  },
];
