import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { writeFileSync } from "node:fs";
import { compileAbl, compileAblYaml, formatFindings, formatIssues } from "@axis/abl";
import {
  AxisWaitTimeoutError,
  collect,
  OPERATIONS,
  type Approval,
  type Axis,
  type OperationSpec,
  type Run,
  type RunEvent,
  type Signal,
} from "@axis/sdk";
import { parse } from "yaml";
import { completionScript, type Shell } from "./completion.js";
import { markdownReference, type Command, type Ctx, type FlagSpec } from "./cli.js";
import { configPath, loadConfig, resolveCredentials, saveConfig } from "./config.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import { keyValues, structured, table, asJson, type Column } from "./render.js";

// ------------------------------------------------------------------------------------------- helpers

const LIST_FLAGS: readonly FlagSpec[] = [
  { name: "limit", type: "number", placeholder: "<n>", desc: "Page size (1-200)" },
  { name: "all", type: "boolean", desc: "Follow every page" },
];

const fingerprint = (key: string): string =>
  createHash("sha256").update(key).digest("hex").slice(0, 8);

function need(ctx: Ctx, n: number, usage: string): string[] {
  if (ctx.args.length < n) throw new UsageError(`missing argument; usage: axis ${usage}`);
  if (ctx.args.length > n)
    throw new UsageError(`unexpected argument "${ctx.args[n]}"; usage: axis ${usage}`);
  return ctx.args;
}

function readText(path: string, deps: Ctx["deps"]): Promise<string> | string {
  if (path === "-") {
    if (!deps.readStdin) throw new UsageError("reading from stdin is not available here");
    return deps.readStdin();
  }
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    throw new CliError(`cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }
}

async function readDoc(ctx: Ctx, path: string): Promise<unknown> {
  const text = await readText(path, ctx.deps);
  try {
    return parse(text);
  } catch (e) {
    throw new CliError(`${path} is not valid YAML/JSON: ${(e as Error).message.split("\n")[0]}`);
  }
}

/** A JSON object given inline (`{...}`) or as a path ("-" is stdin). */
async function jsonArg(ctx: Ctx, value: string, what: string): Promise<Record<string, unknown>> {
  const text = value.trimStart().startsWith("{") ? value : await readText(value, ctx.deps);
  try {
    const v: unknown = JSON.parse(text);
    if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
  } catch {
    // fall through
  }
  throw new UsageError(`${what} must be a JSON object (inline or a file path)`);
}

function emit(ctx: Ctx, data: unknown, human: () => string): void {
  ctx.out(ctx.format === "table" ? human() : structured(data, ctx.format));
}

function parseBlueprintArg(
  args: readonly string[],
  usage: string,
): { name: string; version: string } {
  if (args.length === 2) return { name: args[0] as string, version: args[1] as string };
  const ref = args[0] ?? "";
  const at = ref.lastIndexOf("@");
  if (args.length !== 1 || at <= 0 || at === ref.length - 1)
    throw new UsageError(`expected <name>@<version>; usage: axis ${usage}`);
  return { name: ref.slice(0, at), version: ref.slice(at + 1) };
}

const runCols: Column<Run>[] = [
  { header: "id", get: (r) => r.id },
  { header: "blueprint", get: (r) => `${r.blueprint.name}@${r.blueprint.version}` },
  { header: "state", get: (r) => r.state },
  { header: "created", get: (r) => r.created_at },
  { header: "exit", get: (r) => r.exit_reason },
];

const runPairs = (r: Run): Array<[string, unknown]> => [
  ["id", r.id],
  ["blueprint", `${r.blueprint.name}@${r.blueprint.version}`],
  ["state", r.state],
  ["init pid", r.init_pid],
  ["trace id", r.trace_id],
  ["created", r.created_at],
  ["finished", r.finished_at],
  ["exit reason", r.exit_reason],
];

const approvalCols: Column<Approval>[] = [
  { header: "id", get: (a) => a.id },
  { header: "status", get: (a) => a.status },
  { header: "run", get: (a) => a.run_id },
  { header: "action", get: (a) => a.action },
  { header: "roles", get: (a) => a.roles?.join(",") },
  { header: "sla deadline", get: (a) => a.sla_deadline },
];

export function formatEvent(e: RunEvent): string {
  const data = e.data && Object.keys(e.data).length > 0 ? JSON.stringify(e.data) : "";
  const short = data.length > 120 ? `${data.slice(0, 117)}...` : data;
  return `${String(e.sequence).padStart(4)}  ${e.at}  ${e.type.padEnd(16)}  ${e.pid}${short ? `  ${short}` : ""}`.trimEnd();
}

/** One event per line: compact NDJSON for json/yaml consumers, a readable line for tables. */
function printEvent(ctx: Ctx, e: RunEvent): void {
  ctx.out(ctx.format === "table" ? formatEvent(e) : JSON.stringify(e));
}

async function page<T>(
  ctx: Ctx,
  fetchPage: (
    limit: number | undefined,
    cursor: string | undefined,
  ) => Promise<{ items: T[]; next_cursor?: string | null | undefined }>,
): Promise<T[]> {
  const limit = ctx.num("limit");
  if (ctx.bool("all")) {
    const items: T[] = [];
    let cursor: string | undefined;
    do {
      const p = await fetchPage(limit, cursor);
      items.push(...p.items);
      cursor = p.next_cursor ?? undefined;
    } while (cursor);
    return items;
  }
  return (await fetchPage(limit, undefined)).items;
}

const ablErrors = (r: ReturnType<typeof compileAblYaml>): string[] => [
  ...formatIssues(r.ok ? [] : r.issues).map((l) => `error ${l}`),
  ...formatFindings(r.findings),
];

// ------------------------------------------------------------------------------------------- auth

async function login(ctx: Ctx): Promise<number> {
  if (ctx.bool("device")) {
    throw new CliError(
      "device-flow login is not available yet: the API has no device authorization endpoint",
      EXIT.ERROR,
      [
        "create an API key in the console and run: axis login --with-key-stdin",
        "tracked in docs/NEEDS.md (SDK/CLI block, device flow)",
      ],
    );
  }
  let key: string;
  if (ctx.bool("with-key-stdin")) {
    if (!ctx.deps.readStdin) throw new UsageError("stdin is not available");
    key = (await ctx.deps.readStdin()).trim();
  } else if (ctx.deps.readSecret && ctx.deps.isTTY !== false) {
    key = (await ctx.deps.readSecret("API key (input hidden): ")).trim();
  } else {
    throw new UsageError("no API key supplied", [
      "pipe it in: echo $KEY | axis login --with-key-stdin",
    ]);
  }
  if (!key) throw new UsageError("the API key is empty");
  const baseUrl = ctx.str("base-url") ?? (ctx.deps.env["AXIS_BASE_URL"] || undefined);
  if (!ctx.bool("no-verify")) {
    const probe = await import("@axis/sdk").then(
      (m) =>
        new m.Axis({
          apiKey: key,
          ...(baseUrl ? { baseUrl } : {}),
          ...(ctx.deps.fetch ? { fetch: ctx.deps.fetch } : {}),
          maxRetries: 0,
        }),
    );
    await probe.runs.list({ limit: 1 });
  }
  const config = loadConfig(ctx.deps.env);
  const name = ctx.str("profile") ?? ctx.deps.env["AXIS_PROFILE"] ?? config.defaultProfile;
  config.profiles[name] = { apiKey: key, ...(baseUrl ? { baseUrl } : {}) };
  if (Object.keys(config.profiles).length === 1) config.defaultProfile = name;
  const path = saveConfig(ctx.deps.env, config);
  const data = {
    profile: name,
    config_path: path,
    key_fingerprint: fingerprint(key),
    base_url: baseUrl ?? null,
  };
  emit(
    ctx,
    data,
    () =>
      `Logged in. Profile "${name}" saved to ${path} (key fingerprint ${data.key_fingerprint}).`,
  );
  return EXIT.OK;
}

async function logout(ctx: Ctx): Promise<number> {
  const config = loadConfig(ctx.deps.env);
  const name = ctx.str("profile") ?? ctx.deps.env["AXIS_PROFILE"] ?? config.defaultProfile;
  if (!config.profiles[name]) throw new CliError(`no stored credentials for profile "${name}"`);
  delete config.profiles[name];
  saveConfig(ctx.deps.env, config);
  emit(
    ctx,
    { profile: name, removed: true },
    () => `Removed profile "${name}" (${configPath(ctx.deps.env)}).`,
  );
  return EXIT.OK;
}

async function whoami(ctx: Ctx): Promise<number> {
  const creds = resolveCredentials(ctx.deps.env, {
    profile: ctx.str("profile"),
    baseUrl: ctx.str("base-url"),
  });
  const ax = ctx.client(); // throws exit 3 when there are no credentials
  await ax.runs.list({ limit: 1 }); // the v1 API has no identity endpoint; a cheap authenticated read proves the key works
  const data = {
    profile: creds?.profile,
    credential_source: creds?.source === "env" ? "AXIS_API_KEY" : "profile",
    base_url: ax.baseUrl,
    key_fingerprint: fingerprint(creds?.apiKey ?? ""),
    authenticated: true,
    tenant: "derived from the credential by the server (the v1 API exposes no identity endpoint)",
  };
  emit(ctx, data, () =>
    keyValues(
      Object.entries(data).map(([k, v]) => [k.replace(/_/g, " "), v] as const),
      ctx.style,
    ),
  );
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- blueprints

async function blueprintsValidate(ctx: Ctx): Promise<number> {
  if (ctx.args.length === 0)
    throw new UsageError("missing file; usage: axis blueprints validate <file...>");
  const results: Array<{
    file: string;
    ok: boolean;
    issues: string[];
    content_hash?: string;
    risk_level?: string;
  }> = [];
  let failed = 0;
  for (const file of ctx.args) {
    const text = await readText(file, ctx.deps);
    const r = compileAblYaml(text);
    if (!r.ok) failed++;
    results.push({
      file,
      ok: r.ok,
      issues: ablErrors(r),
      ...(r.ok
        ? { content_hash: r.manifest.blueprint.content_hash, risk_level: r.manifest.risk.level }
        : {}),
    });
  }
  emit(ctx, results, () =>
    [
      ...results.flatMap((r) => [
        ...r.issues.map((l) => `${r.file}: ${l}`),
        ...(r.ok ? [`${r.file}: ok`] : []),
      ]),
      `${results.length} file(s), ${failed} failed`,
    ].join("\n"),
  );
  return failed > 0 ? EXIT.ERROR : EXIT.OK;
}

async function blueprintsPublish(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "blueprints publish <file>");
  const doc = await readDoc(ctx, file as string);
  if (!ctx.bool("no-validate")) {
    const r = compileAbl(doc);
    if (!r.ok) {
      for (const l of ablErrors(r)) ctx.err(`${file}: ${l}`);
      throw new CliError(`${file} does not validate; nothing was published`, EXIT.ERROR, [
        "fix the errors above, or check with: axis blueprints validate " + String(file),
      ]);
    }
  }
  const key = ctx.str("idempotency-key");
  const v = await ctx
    .client()
    .blueprints.publish(doc as Record<string, unknown>, key ? { idempotencyKey: key } : {});
  emit(ctx, v, () =>
    keyValues(
      [
        ["published", `${v.name}@${v.version}`],
        ["risk level", v.risk_level],
        ["content hash", v.content_hash],
        ["created", v.created_at],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function blueprintsList(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const items = await page(ctx, (limit, cursor) =>
    ax.blueprints.list({ ...(limit ? { limit } : {}), ...(cursor ? { cursor } : {}) }),
  );
  emit(ctx, { items }, () =>
    table(
      items,
      [
        { header: "name", get: (b) => b.name },
        { header: "version", get: (b) => b.version },
        { header: "risk", get: (b) => b.risk_level },
        { header: "created", get: (b) => b.created_at },
        { header: "hash", get: (b) => b.content_hash?.slice(0, 12) },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function blueprintsGet(ctx: Ctx): Promise<number> {
  const { name, version } = parseBlueprintArg(ctx.args, "blueprints get <name>@<version>");
  const b = await ctx.client().blueprints.get(name, version);
  emit(ctx, b, () =>
    [
      keyValues(
        [
          ["name", b.name],
          ["version", b.version],
          ["risk level", b.risk_level],
          ["content hash", b.content_hash],
          ["created", b.created_at],
        ],
        ctx.style,
      ),
      "",
      structured(b.abl, "yaml"),
    ].join("\n"),
  );
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- runs

const SIGNALS: readonly Signal[] = ["PAUSE", "RESUME", "TERM", "KILL", "INTERRUPT"];

async function pendingApprovalsFor(ax: Axis, runId: string): Promise<Approval[]> {
  try {
    const p = await ax.approvals.list({ status: "pending", limit: 200 });
    return p.items.filter((a) => a.run_id === runId);
  } catch {
    return [];
  }
}

async function tailRun(ctx: Ctx, ax: Axis, id: string, after?: number): Promise<void> {
  for await (const e of ax.runs.stream(id, after === undefined ? {} : { afterSequence: after }))
    printEvent(ctx, e);
}

async function runStart(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "run start <name>@<version>");
  const inline = ctx.str("input");
  const input = inline === undefined ? undefined : await jsonArg(ctx, inline, "--input");
  const ax = ctx.client();
  const key = ctx.str("idempotency-key");
  let run = await ax.runs.start({
    blueprint: ref as string,
    ...(input ? { input } : {}),
    ...(key ? { idempotencyKey: key } : {}),
  });
  if (ctx.bool("tail")) {
    ctx.err(`run ${run.id} started; streaming events`);
    await tailRun(ctx, ax, run.id);
    run = await ax.runs.get(run.id);
  } else if (ctx.bool("wait")) {
    try {
      run = await ax.runs.wait(run.id, {
        timeoutMs: (ctx.num("wait-timeout") ?? 300) * 1000,
        pollIntervalMs: 1000,
      });
    } catch (e) {
      if (e instanceof AxisWaitTimeoutError) {
        const pending = await pendingApprovalsFor(ax, run.id);
        if (pending.length > 0) {
          throw new CliError(
            `run ${run.id} is waiting for ${pending.length} approval(s): ${pending.map((a) => a.id).join(", ")}`,
            EXIT.APPROVAL_PENDING,
            [`approve with: axis approvals approve ${pending[0]?.id as string}`],
          );
        }
      }
      throw e;
    }
  }
  emit(ctx, run, () => keyValues(runPairs(run), ctx.style));
  return EXIT.OK;
}

async function runTail(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "run tail <run-id>");
  await tailRun(ctx, ctx.client(), id as string, ctx.num("after"));
  return EXIT.OK;
}

async function runGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "run get <run-id>");
  const run = await ctx.client().runs.get(id as string);
  emit(ctx, run, () => keyValues(runPairs(run), ctx.style));
  return EXIT.OK;
}

async function runList(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const state = ctx.str("state") as Run["state"] | undefined;
  const blueprint = ctx.str("blueprint");
  const items = await page(ctx, (limit, cursor) =>
    ax.runs.list({
      ...(limit ? { limit } : {}),
      ...(cursor ? { cursor } : {}),
      ...(state ? { state } : {}),
      ...(blueprint ? { blueprint } : {}),
    }),
  );
  emit(ctx, { items }, () => table(items, runCols, ctx.style));
  return EXIT.OK;
}

async function runSignal(ctx: Ctx): Promise<number> {
  const [id, sig] = need(ctx, 2, "run signal <run-id> <signal>");
  const signal = (sig as string).toUpperCase() as Signal;
  if (!SIGNALS.includes(signal))
    throw new UsageError(`signal must be one of ${SIGNALS.join(", ")}`);
  const pid = ctx.str("pid");
  const reason = ctx.str("reason");
  const r = await ctx
    .client()
    .runs.signal(id as string, { signal, ...(pid ? { pid } : {}), ...(reason ? { reason } : {}) });
  emit(ctx, r, () => `signal ${signal} delivered; pid ${r.pid} is now ${r.state}`);
  return EXIT.OK;
}

async function runCancel(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "run cancel <run-id>");
  const pid = ctx.str("pid");
  const reason = ctx.str("reason");
  const r = await ctx
    .client()
    .runs.cancel(id as string, {
      force: ctx.bool("force"),
      ...(pid ? { pid } : {}),
      ...(reason ? { reason } : {}),
    });
  emit(
    ctx,
    r,
    () => `${ctx.bool("force") ? "KILL" : "TERM"} delivered; pid ${r.pid} is now ${r.state}`,
  );
  return EXIT.OK;
}

async function runReplay(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "run replay <run-id>");
  const ax = ctx.client();
  const events = await collect(ax.runs.allEvents(id as string));
  if (ctx.format === "table") {
    const t0 = events[0] ? Date.parse(events[0].at) : 0;
    for (const e of events) {
      const dt = ((Date.parse(e.at) - t0) / 1000).toFixed(3);
      ctx.out(`+${dt.padStart(8)}s  ${formatEvent(e)}`);
    }
    ctx.out(`${events.length} event(s) replayed from the append-only log`);
  } else ctx.out(structured({ run_id: id, events }, ctx.format));
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- approvals

async function approvalsList(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const status = ctx.str("status") as Approval["status"] | undefined;
  const items = await page(ctx, (limit, cursor) =>
    ax.approvals.list({
      ...(limit ? { limit } : {}),
      ...(cursor ? { cursor } : {}),
      ...(status ? { status } : {}),
    }),
  );
  emit(ctx, { items }, () => table(items, approvalCols, ctx.style));
  return EXIT.OK;
}

function decide(decision: "approve" | "reject"): (ctx: Ctx) => Promise<number> {
  return async (ctx) => {
    const [id] = need(
      ctx,
      1,
      `approvals ${decision === "approve" ? "approve" : "deny"} <approval-id>`,
    );
    const comment = ctx.str("comment");
    const key = ctx.str("idempotency-key");
    const a = await ctx
      .client()
      .approvals.decide(id as string, decision, {
        ...(comment ? { comment } : {}),
        ...(key ? { idempotencyKey: key } : {}),
      });
    emit(
      ctx,
      a,
      () =>
        `approval ${a.id} is now ${a.status}${a.decided_by ? ` (decided by ${a.decided_by})` : ""}`,
    );
    return EXIT.OK;
  };
}

// ------------------------------------------------------------------------------------------- policies

async function policiesList(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const items = await page(ctx, (limit, cursor) =>
    ax.policies.list({ ...(limit ? { limit } : {}), ...(cursor ? { cursor } : {}) }),
  );
  emit(ctx, { items }, () =>
    table(
      items,
      [
        { header: "name", get: (p) => p.name },
        { header: "version", get: (p) => p.version },
        { header: "created", get: (p) => p.created_at },
        { header: "hash", get: (p) => p.content_hash?.slice(0, 12) },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function policiesTest(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "policies test <policy-file> --request <json|file>");
  const reqArg = ctx.str("request");
  if (!reqArg)
    throw new UsageError("--request is required", [
      `example: --request '{"enforcement_point":"tool_call","action":"tool.refund","context":{}}'`,
    ]);
  const policy = (await readDoc(ctx, file as string)) as Record<string, unknown>;
  const request = await jsonArg(ctx, reqArg, "--request");
  const d = await ctx
    .client()
    .policies.test(
      policy,
      request as { enforcement_point: string; context: Record<string, unknown> },
    );
  emit(ctx, d, () =>
    keyValues(
      [
        ["decision", d.decision],
        ["policy version", d.policy_version],
        ["reason", d.reason],
        ["matched rules", d.matched_rule_ids?.join(", ")],
        ["redact fields", d.redact_fields?.join(", ")],
      ],
      ctx.style,
    ),
  );
  return d.decision === "DENY"
    ? EXIT.POLICY_DENIED
    : d.decision === "REQUIRE_APPROVAL"
      ? EXIT.APPROVAL_PENDING
      : EXIT.OK;
}

async function policiesPublish(ctx: Ctx): Promise<number> {
  const [file] = need(ctx, 1, "policies publish <policy-file>");
  const policy = (await readDoc(ctx, file as string)) as Record<string, unknown>;
  const p = await ctx.client().policies.publish(policy);
  emit(ctx, p, () =>
    keyValues(
      [
        ["published", `${p.name}@${p.version}`],
        ["content hash", p.content_hash],
        ["created", p.created_at],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- audit

async function auditEvents(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  const f = auditFilter(ctx);
  const items = await page(ctx, (limit, cursor) =>
    ax.audit.events({ ...f, ...(limit ? { limit } : {}), ...(cursor ? { cursor } : {}) }),
  );
  emit(ctx, { items }, () =>
    table(
      items,
      [
        { header: "seq", get: (e) => e.seq },
        { header: "ts", get: (e) => e.ts },
        { header: "decision", get: (e) => e.decision },
        { header: "point", get: (e) => e.enforcement_point },
        { header: "action", get: (e) => e.action },
        { header: "trace", get: (e) => e.trace_id },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

function auditFilter(ctx: Ctx) {
  const trace = ctx.str("trace-id");
  const decision = ctx.str("decision") as
    "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION" | undefined;
  const from = ctx.num("from-seq");
  return {
    ...(trace ? { trace_id: trace } : {}),
    ...(decision ? { decision } : {}),
    ...(from ? { from_seq: from } : {}),
  };
}

async function auditVerify(ctx: Ctx): Promise<number> {
  const from = ctx.num("from-seq");
  const to = ctx.num("to-seq");
  const r = await ctx
    .client()
    .audit.verify({ ...(from ? { from_seq: from } : {}), ...(to ? { to_seq: to } : {}) });
  emit(ctx, r, () =>
    r.ok
      ? `audit chain OK: ${r.verified} event(s) verified`
      : `audit chain BROKEN at seq ${r.broken_at_seq ?? "?"}: ${r.reason ?? "hash mismatch"} (${r.verified} verified before the break)`,
  );
  return r.ok ? EXIT.OK : EXIT.ERROR;
}

async function auditExport(ctx: Ctx): Promise<number> {
  const ax = ctx.client();
  if (ctx.bool("verify")) {
    const v = await ax.audit.verify({});
    if (!v.ok)
      throw new CliError(
        `refusing to export: the audit chain is broken at seq ${v.broken_at_seq ?? "?"}`,
        EXIT.ERROR,
        ["run: axis audit verify"],
      );
  }
  const lines: string[] = [];
  for await (const e of ax.audit.iterate({ ...auditFilter(ctx) })) lines.push(JSON.stringify(e));
  const outPath = ctx.str("out");
  if (outPath) {
    writeFileSync(outPath, lines.length ? `${lines.join("\n")}\n` : "", { mode: 0o600 });
    ctx.err(`exported ${lines.length} event(s) to ${outPath}`);
  } else {
    for (const l of lines) ctx.out(l);
    ctx.err(`exported ${lines.length} event(s)`);
  }
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- kill switch, usage, evals

function killSwitch(engaged: boolean): (ctx: Ctx) => Promise<number> {
  return async (ctx) => {
    const [scope, target] = ctx.args;
    if (!scope || ctx.args.length > 2)
      throw new UsageError(
        `usage: axis kill-switch ${engaged ? "on" : "off"} <tenant|agent|tool> [target]`,
      );
    if (scope !== "tenant" && scope !== "agent" && scope !== "tool")
      throw new UsageError(`scope must be tenant, agent or tool (got "${scope}")`);
    const reason = ctx.str("reason");
    const ks = await ctx
      .client()
      .killSwitches.set({
        scope,
        engaged,
        ...(target ? { target } : {}),
        ...(reason ? { reason } : {}),
      });
    emit(
      ctx,
      ks,
      () =>
        `kill-switch ${ks.scope}${ks.target ? ` ${ks.target}` : ""} is ${ks.engaged ? "ENGAGED" : "released"}`,
    );
    return EXIT.OK;
  };
}

async function killSwitchList(ctx: Ctx): Promise<number> {
  const r = await ctx.client().killSwitches.list();
  emit(ctx, r, () =>
    r.items.length === 0
      ? "no kill-switches engaged"
      : table(
          r.items,
          [
            { header: "scope", get: (k) => k.scope },
            { header: "target", get: (k) => k.target },
            { header: "engaged", get: (k) => k.engaged },
            { header: "reason", get: (k) => k.reason },
            { header: "updated", get: (k) => k.updated_at },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function usage(ctx: Ctx): Promise<number> {
  const now = (ctx.deps.now ?? (() => new Date()))();
  const from =
    ctx.str("from") ?? new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
  const to = ctx.str("to") ?? now.toISOString();
  const groupBy = ctx.str("group-by") as "meter" | "model" | "blueprint" | "day" | undefined;
  const r = await ctx.client().usage.get({ from, to, ...(groupBy ? { groupBy } : {}) });
  emit(ctx, r, () =>
    r.items.length === 0
      ? `no usage between ${from} and ${to}`
      : table(
          r.items,
          [
            { header: "meter", get: (u) => u.meter },
            { header: "group", get: (u) => u.group },
            { header: "quantity", get: (u) => u.quantity },
            { header: "unit", get: (u) => u.unit },
          ],
          ctx.style,
        ),
  );
  return EXIT.OK;
}

async function evalsStart(ctx: Ctx): Promise<number> {
  const [suite, ref] = need(ctx, 2, "evals start <suite> <name>@<version>");
  const e = await ctx.client().evals.start({ suite: suite as string, blueprint: ref as string });
  emit(ctx, e, () =>
    keyValues(
      [
        ["eval run", e.id],
        ["suite", e.suite],
        ["status", e.status],
        ["score", e.score],
        ["threshold", e.threshold],
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- raw api, placeholders

/** Find an operation for a placeholder command: id starts with the verb and mentions the domain (id, tag or path). */
export function findOperation(
  ops: Record<string, OperationSpec>,
  domain: string,
  verb: RegExp,
): OperationSpec | undefined {
  const d = domain.toLowerCase();
  return Object.values(ops).find(
    (o) =>
      verb.test(o.id) &&
      (o.id.toLowerCase().includes(d) ||
        o.tag.toLowerCase().includes(d) ||
        o.path.toLowerCase().includes(`/${d}`)),
  );
}

async function callOperation(
  ctx: Ctx,
  ax: Axis,
  op: OperationSpec,
  positionals: readonly string[],
): Promise<number> {
  const params: Record<string, unknown> = {};
  op.pathParams.forEach((name, i) => {
    const v = positionals[i];
    if (v === undefined)
      throw new UsageError(
        `${op.id} needs path parameter "${name}" as positional argument ${i + 1}`,
      );
    params[name] = v;
  });
  for (const kv of ctx.list("param")) {
    const eq = kv.indexOf("=");
    if (eq <= 0) throw new UsageError(`--param expects name=value (got "${kv}")`);
    params[kv.slice(0, eq)] = kv.slice(eq + 1);
  }
  const body = ctx.str("body");
  if (body !== undefined) params["body"] = await jsonArg(ctx, body, "--body");
  const result = await ax.transport.call<unknown>(op, params);
  ctx.out(ctx.format === "yaml" ? structured(result, "yaml") : asJson(result ?? null));
  return EXIT.OK;
}

async function api(ctx: Ctx): Promise<number> {
  const [id, ...rest] = ctx.args;
  if (!id)
    throw new UsageError(
      "usage: axis api <operationId> [path args...] [--param name=value] [--body <json|file>]",
      [`operations: ${Object.keys(OPERATIONS).join(", ")}`],
    );
  const op = (OPERATIONS as Record<string, OperationSpec>)[id];
  if (!op)
    throw new UsageError(`unknown operationId "${id}"`, [
      `operations: ${Object.keys(OPERATIONS).join(", ")}`,
    ]);
  return callOperation(ctx, ctx.client(), op, rest);
}

const API_FLAGS: readonly FlagSpec[] = [
  {
    name: "param",
    type: "repeat",
    placeholder: "<name=value>",
    desc: "Query parameter (repeatable)",
  },
  {
    name: "body",
    type: "string",
    placeholder: "<json|file>",
    desc: "Request body (inline JSON, a file path, or - for stdin)",
  },
];

function placeholder(
  domain: string,
  verb: RegExp,
  name: string,
  hint: string,
): (ctx: Ctx) => Promise<number> {
  return async (ctx) => {
    const op = findOperation(OPERATIONS as Record<string, OperationSpec>, domain, verb);
    if (op) return callOperation(ctx, ctx.client(), op, ctx.args);
    throw new CliError(
      `\`axis ${name}\` is not available yet: the control-plane API v1 has no ${domain} endpoint`,
      EXIT.ERROR,
      [
        hint,
        "when the endpoint ships, regenerate the SDKs (node scripts/generate-sdks.mjs); this command will then call it",
      ],
    );
  };
}

async function completion(ctx: Ctx): Promise<number> {
  const [shell] = need(ctx, 1, "completion <bash|zsh|fish>");
  if (shell !== "bash" && shell !== "zsh" && shell !== "fish")
    throw new UsageError("shell must be bash, zsh or fish");
  ctx.deps.stdout(completionScript(shell as Shell, COMMANDS, "axis"));
  return EXIT.OK;
}

async function docs(ctx: Ctx): Promise<number> {
  ctx.out(markdownReference(COMMANDS));
  return EXIT.OK;
}

// ------------------------------------------------------------------------------------------- the table

const WAIT_FLAGS: readonly FlagSpec[] = [
  { name: "wait", type: "boolean", desc: "Wait for the run to terminate (exit 5 on timeout)" },
  { name: "tail", type: "boolean", desc: "Stream the run's events until it terminates" },
  {
    name: "wait-timeout",
    type: "number",
    placeholder: "<seconds>",
    desc: "Give up waiting after this long (default 300)",
  },
];

const NYI = "the registry and marketplace are being built (docs/NEEDS.md)";

export const COMMANDS: Command[] = [
  {
    path: ["login"],
    summary: "Store an API key for this machine",
    description:
      "The key is verified against the API, then saved under $XDG_CONFIG_HOME/axis/config.json with mode 0600. Alternatively set AXIS_API_KEY. The key is never accepted as a command-line argument (it would leak through shell history and process listings).",
    flags: [
      { name: "with-key-stdin", type: "boolean", desc: "Read the API key from stdin" },
      { name: "device", type: "boolean", desc: "Device-flow sign-in (not available yet)" },
      { name: "no-verify", type: "boolean", desc: "Save without calling the API" },
    ],
    examples: [
      "echo $AXIS_KEY | axis login --with-key-stdin --base-url https://api.us-east-1.axis.example/v1",
    ],
    run: login,
  },
  { path: ["logout"], summary: "Remove the stored API key of a profile", run: logout },
  { path: ["whoami"], summary: "Show the active profile and check the credential", run: whoami },

  { path: ["blueprints"], summary: "Author and publish agent blueprints (ABL)" },
  {
    path: ["blueprints", "validate"],
    summary: "Validate and lint ABL files locally (offline)",
    usage: "<file...>",
    description:
      "Uses the same compiler and linter as the platform; needs no credentials or network.",
    run: blueprintsValidate,
  },
  {
    path: ["blueprints", "publish"],
    summary: "Validate locally, then publish a blueprint version",
    usage: "<file>",
    flags: [
      {
        name: "no-validate",
        type: "boolean",
        desc: "Skip the local check (the server still validates)",
      },
      {
        name: "idempotency-key",
        type: "string",
        placeholder: "<key>",
        desc: "Idempotency key (default: generated)",
      },
    ],
    run: blueprintsPublish,
  },
  {
    path: ["blueprints", "list"],
    summary: "List blueprint versions",
    flags: LIST_FLAGS,
    run: blueprintsList,
  },
  {
    path: ["blueprints", "get"],
    summary: "Show one blueprint version",
    usage: "<name>@<version>",
    run: blueprintsGet,
  },

  { path: ["run"], summary: "Start and observe agent runs" },
  {
    path: ["run", "start"],
    summary: "Start a run of a published blueprint",
    usage: "<name>@<version>",
    flags: [
      {
        name: "input",
        type: "string",
        placeholder: "<json|file>",
        desc: "Run input: inline JSON object, a file path, or - for stdin",
      },
      {
        name: "idempotency-key",
        type: "string",
        placeholder: "<key>",
        desc: "Idempotency key (default: generated)",
      },
      ...WAIT_FLAGS,
    ],
    run: runStart,
  },
  {
    path: ["run", "tail"],
    summary: "Stream a run's events live",
    usage: "<run-id>",
    flags: [
      {
        name: "after",
        type: "number",
        placeholder: "<sequence>",
        desc: "Resume after this event sequence",
      },
    ],
    description:
      "Reconnects automatically with Last-Event-ID. With --json prints one JSON event per line.",
    run: runTail,
  },
  { path: ["run", "get"], summary: "Show a run", usage: "<run-id>", run: runGet },
  {
    path: ["run", "list"],
    summary: "List runs",
    flags: [
      ...LIST_FLAGS,
      {
        name: "state",
        type: "string",
        placeholder: "<state>",
        choices: ["spawn", "ready", "running", "waiting", "suspended", "terminated"],
        desc: "Filter by process state",
      },
      {
        name: "blueprint",
        type: "string",
        placeholder: "<name>",
        desc: "Filter by blueprint name",
      },
    ],
    run: runList,
  },
  {
    path: ["run", "signal"],
    summary: "Send a signal to a process in a run",
    usage: "<run-id> <PAUSE|RESUME|TERM|KILL|INTERRUPT>",
    flags: [
      {
        name: "pid",
        type: "string",
        placeholder: "<pid>",
        desc: "Target process (default: the run's init process)",
      },
      {
        name: "reason",
        type: "string",
        placeholder: "<text>",
        desc: "Reason recorded in the audit log",
      },
    ],
    run: runSignal,
  },
  {
    path: ["run", "cancel"],
    summary: "Stop a run (TERM; --force sends KILL)",
    usage: "<run-id>",
    flags: [
      { name: "force", type: "boolean", desc: "Send KILL instead of TERM" },
      { name: "pid", type: "string", placeholder: "<pid>", desc: "Target process" },
      {
        name: "reason",
        type: "string",
        placeholder: "<text>",
        desc: "Reason recorded in the audit log",
      },
    ],
    run: runCancel,
  },
  {
    path: ["run", "replay"],
    summary: "Replay a finished run from its append-only event log",
    usage: "<run-id>",
    description:
      "Prints the full event log in order with relative timestamps; nothing is executed.",
    run: runReplay,
  },

  { path: ["approvals"], summary: "Human-in-the-loop approvals" },
  {
    path: ["approvals", "list"],
    summary: "List approvals",
    flags: [
      ...LIST_FLAGS,
      {
        name: "status",
        type: "string",
        placeholder: "<status>",
        choices: ["pending", "approved", "rejected", "expired", "escalated"],
        desc: "Filter by status",
      },
    ],
    run: approvalsList,
  },
  {
    path: ["approvals", "approve"],
    summary: "Approve a pending approval",
    usage: "<approval-id>",
    flags: [
      {
        name: "comment",
        type: "string",
        placeholder: "<text>",
        desc: "Comment recorded with the decision",
      },
      {
        name: "idempotency-key",
        type: "string",
        placeholder: "<key>",
        desc: "Idempotency key (default: generated)",
      },
    ],
    run: decide("approve"),
  },
  {
    path: ["approvals", "deny"],
    summary: "Deny (reject) a pending approval",
    usage: "<approval-id>",
    flags: [
      {
        name: "comment",
        type: "string",
        placeholder: "<text>",
        desc: "Comment recorded with the decision",
      },
      {
        name: "idempotency-key",
        type: "string",
        placeholder: "<key>",
        desc: "Idempotency key (default: generated)",
      },
    ],
    run: decide("reject"),
  },

  { path: ["policies"], summary: "Policy packs" },
  {
    path: ["policies", "list"],
    summary: "List policy packs",
    flags: LIST_FLAGS,
    run: policiesList,
  },
  {
    path: ["policies", "test"],
    summary: "Evaluate a hypothetical request against a policy file",
    usage: "<policy-file> --request <json|file>",
    flags: [
      {
        name: "request",
        type: "string",
        placeholder: "<json|file>",
        desc: "The request: {enforcement_point, action?, context}",
      },
    ],
    description:
      "Nothing is executed. Exit 4 when the decision is DENY, 5 when it is REQUIRE_APPROVAL.",
    run: policiesTest,
  },
  {
    path: ["policies", "publish"],
    summary: "Validate, compile and publish a policy pack version",
    usage: "<policy-file>",
    run: policiesPublish,
  },
  {
    path: ["policies", "activate"],
    summary: "Activate a published policy pack version",
    usage: "<name>@<version>",
    placeholder: true,
    run: placeholder(
      "policy",
      /^activate/i,
      "policies activate",
      "published packs are not selectable per tenant through the API yet",
    ),
  },

  { path: ["audit"], summary: "The tamper-evident audit log" },
  {
    path: ["audit", "events"],
    summary: "Query audit events",
    flags: [
      ...LIST_FLAGS,
      {
        name: "trace-id",
        type: "string",
        placeholder: "<32 hex>",
        desc: "Only events of this trace",
      },
      {
        name: "decision",
        type: "string",
        placeholder: "<decision>",
        choices: ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"],
        desc: "Only this decision",
      },
      {
        name: "from-seq",
        type: "number",
        placeholder: "<seq>",
        desc: "Start at this sequence number",
      },
    ],
    run: auditEvents,
  },
  {
    path: ["audit", "verify"],
    summary: "Verify the hash chain (exit 1 if it is broken)",
    flags: [
      { name: "from-seq", type: "number", placeholder: "<seq>", desc: "First sequence to verify" },
      { name: "to-seq", type: "number", placeholder: "<seq>", desc: "Last sequence to verify" },
    ],
    run: auditVerify,
  },
  {
    path: ["audit", "export"],
    summary: "Export audit events as NDJSON",
    flags: [
      {
        name: "out",
        type: "string",
        placeholder: "<file>",
        desc: "Write to a file (mode 0600) instead of stdout",
      },
      {
        name: "verify",
        type: "boolean",
        desc: "Verify the chain first and refuse to export if it is broken",
      },
      {
        name: "trace-id",
        type: "string",
        placeholder: "<32 hex>",
        desc: "Only events of this trace",
      },
      {
        name: "decision",
        type: "string",
        placeholder: "<decision>",
        choices: ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"],
        desc: "Only this decision",
      },
      {
        name: "from-seq",
        type: "number",
        placeholder: "<seq>",
        desc: "Start at this sequence number",
      },
    ],
    run: auditExport,
  },

  { path: ["kill-switch"], summary: "Emergency stops" },
  {
    path: ["kill-switch", "on"],
    summary: "Engage a kill-switch",
    usage: "<tenant|agent|tool> [target]",
    flags: [
      {
        name: "reason",
        type: "string",
        placeholder: "<text>",
        desc: "Reason recorded in the audit log",
      },
    ],
    run: killSwitch(true),
  },
  {
    path: ["kill-switch", "off"],
    summary: "Release a kill-switch",
    usage: "<tenant|agent|tool> [target]",
    flags: [
      {
        name: "reason",
        type: "string",
        placeholder: "<text>",
        desc: "Reason recorded in the audit log",
      },
    ],
    run: killSwitch(false),
  },
  { path: ["kill-switch", "list"], summary: "List engaged kill-switches", run: killSwitchList },

  {
    path: ["usage"],
    summary: "Metered usage",
    flags: [
      {
        name: "from",
        type: "string",
        placeholder: "<iso-time>",
        desc: "Period start (default: first of this month, UTC)",
      },
      { name: "to", type: "string", placeholder: "<iso-time>", desc: "Period end (default: now)" },
      {
        name: "group-by",
        type: "string",
        placeholder: "<key>",
        choices: ["meter", "model", "blueprint", "day"],
        desc: "Group rows",
      },
    ],
    run: usage,
  },
  { path: ["evals"], summary: "Eval Hub" },
  {
    path: ["evals", "start"],
    summary: "Run an eval suite against a blueprint version",
    usage: "<suite> <name>@<version>",
    run: evalsStart,
  },

  { path: ["registry"], summary: "Blueprint registry (not yet available)" },
  {
    path: ["registry", "publish"],
    summary: "Publish a blueprint to the registry",
    usage: "<name>@<version>",
    placeholder: true,
    flags: API_FLAGS,
    run: placeholder("registry", /^(publish|create|put)/i, "registry publish", NYI),
  },
  {
    path: ["registry", "list"],
    summary: "List registry blueprints",
    placeholder: true,
    flags: API_FLAGS,
    run: placeholder("registry", /^list/i, "registry list", NYI),
  },
  {
    path: ["registry", "get"],
    summary: "Show a registry blueprint",
    usage: "<name>",
    placeholder: true,
    flags: API_FLAGS,
    run: placeholder("registry", /^get/i, "registry get", NYI),
  },
  { path: ["marketplace"], summary: "Marketplace (not yet available)" },
  {
    path: ["marketplace", "search"],
    summary: "Search marketplace listings",
    usage: "[query]",
    placeholder: true,
    flags: API_FLAGS,
    run: placeholder("marketplace", /^(search|list)/i, "marketplace search", NYI),
  },
  {
    path: ["marketplace", "install"],
    summary: "Install a marketplace listing",
    usage: "<listing-id>",
    placeholder: true,
    flags: API_FLAGS,
    run: placeholder("marketplace", /^install/i, "marketplace install", NYI),
  },

  {
    path: ["api"],
    summary: "Call any API operation by operationId",
    usage: "<operationId> [path args...]",
    description:
      "Escape hatch for endpoints without a dedicated command. Path parameters are positional, in order.",
    flags: API_FLAGS,
    run: api,
  },
  {
    path: ["completion"],
    summary: "Print a shell completion script",
    usage: "<bash|zsh|fish>",
    run: completion,
  },
  { path: ["docs"], summary: "Print the command reference as Markdown", run: docs },
];

export { collect };
