import { readFileSync, writeFileSync } from "node:fs";
import { parse } from "yaml";
import type { Command, Ctx, FlagSpec } from "./cli.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import { inert, structured, table } from "./render.js";

/**
 * `axis compliance ...` (OpenAPI 1.5.0, ADR 0071): the AI system inventory, AI impact assessments with an independent review, and
 * sealed technical documentation (EU AI Act Annex IV structure).
 *
 * The wording is deliberate: these records are evidence for a management system, not a certification. `compliance documents get` exits 1
 * when the document's hash, Markdown or seal does not verify. Text that came from the server is printed inert.
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

function fileArg(ctx: Ctx, usage: string): string {
  const f = ctx.str("file");
  if (!f) throw new UsageError(`--file is required; usage: axis ${usage}`);
  return f;
}

function expected(ctx: Ctx, usage: string): number {
  const v = ctx.num("expected-version");
  if (v === undefined || !Number.isInteger(v) || v < 1)
    throw new UsageError(`--expected-version <n> is required; usage: axis ${usage}`);
  return v;
}

function version(ctx: Ctx): number | undefined {
  const v = ctx.num("revision");
  if (v !== undefined && (!Number.isInteger(v) || v < 1))
    throw new UsageError("--revision must be a positive integer");
  return v;
}

const IDEM: FlagSpec = {
  name: "idempotency-key",
  type: "string",
  placeholder: "<key>",
  desc: "Idempotency key (default: generated)",
};
const FILE: FlagSpec = {
  name: "file",
  short: "f",
  type: "string",
  placeholder: "<path|->",
  desc: "YAML or JSON document ('-' reads stdin)",
};
const EXPECTED: FlagSpec = {
  name: "expected-version",
  type: "number",
  placeholder: "<n>",
  desc: "The version you read; a stale one is a conflict (exit 1)",
};
const VERSION: FlagSpec = {
  name: "revision",
  type: "number",
  placeholder: "<n>",
  desc: "An earlier version (default: the latest)",
};

// ---- systems -------------------------------------------------------------------------------------------------------------------

async function systemsList(ctx: Ctx): Promise<number> {
  const risk = ctx.str("risk-level");
  const stage = ctx.str("stage");
  const r = await ctx.client().compliance.systems.list({
    ...(risk ? { risk_level: risk as "high" } : {}),
    ...(stage ? { lifecycle_stage: stage as "design" } : {}),
  });
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "system", get: (x) => x.system_id },
        { header: "version", get: (x) => x.version },
        { header: "name", get: (x) => inert(x.name) },
        { header: "risk", get: (x) => x.risk_level },
        { header: "stage", get: (x) => x.lifecycle_stage },
        { header: "owner", get: (x) => inert(x.owner) },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function systemsGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "compliance systems get <system-id> [--revision <n>]");
  const r = await ctx.client().compliance.systems.get(id as string, version(ctx));
  emit(ctx, r, () =>
    [
      `${r.system_id} v${r.version}: ${inert(r.name)}`,
      `  purpose:   ${inert(r.purpose)}`,
      `  owner:     ${inert(r.owner)}`,
      `  risk:      ${r.risk_level}   stage: ${r.lifecycle_stage}`,
      `  blueprints: ${r.blueprints.map((b) => `${b.name}@${b.version}`).join(", ") || "-"}`,
      `  data:      ${r.data_categories.map(inert).join(", ") || "-"}`,
      `  updated:   ${r.updated_at} by ${inert(r.updated_by)}`,
    ].join("\n"),
  );
  return EXIT.OK;
}

async function systemsCreate(ctx: Ctx): Promise<number> {
  const usage = "compliance systems create --file <path|->";
  const body = await readDoc(ctx, fileArg(ctx, usage));
  const key = ctx.str("idempotency-key");
  const r = await ctx
    .client()
    .compliance.systems.create(body as never, key ? { idempotencyKey: key } : {});
  emit(ctx, r, () => `system ${r.system_id} registered (version ${r.version})`);
  return EXIT.OK;
}

async function systemsUpdate(ctx: Ctx): Promise<number> {
  const usage =
    "compliance systems update <system-id> --expected-version <n> --file <path|-> (the file holds the fields to change)";
  const [id] = need(ctx, 1, usage);
  const patch = await readDoc(ctx, fileArg(ctx, usage));
  const r = await ctx
    .client()
    .compliance.systems.update(id as string, expected(ctx, usage), patch as never);
  emit(ctx, r, () => `system ${r.system_id} is now version ${r.version}`);
  return EXIT.OK;
}

// ---- assessments ---------------------------------------------------------------------------------------------------------------

const assessmentLine = (x: {
  assessment_id: string;
  version: number;
  system_id: string;
  title: string;
  state: string;
  risk_rating: string;
  review_due: string;
  overdue: boolean;
}): string =>
  `${x.assessment_id} v${x.version} [${x.state}] ${inert(x.title)} (system ${x.system_id}, risk ${x.risk_rating}, review due ${x.review_due}${x.overdue ? ", OVERDUE" : ""})`;

async function assessmentsList(ctx: Ctx): Promise<number> {
  const system = ctx.str("system");
  const state = ctx.str("state");
  const r = await ctx.client().compliance.assessments.list({
    ...(system ? { system_id: system } : {}),
    ...(state ? { state: state as "draft" } : {}),
    ...(ctx.bool("overdue") ? { overdue: true } : {}),
  });
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "assessment", get: (x) => x.assessment_id },
        { header: "v", get: (x) => x.version },
        { header: "system", get: (x) => x.system_id },
        { header: "title", get: (x) => inert(x.title) },
        { header: "state", get: (x) => x.state },
        { header: "risk", get: (x) => x.risk_rating },
        { header: "review due", get: (x) => x.review_due },
        { header: "overdue", get: (x) => (x.overdue ? (x.overdue_reason ?? "yes") : "no") },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function assessmentsGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "compliance assessments get <assessment-id> [--revision <n>]");
  const r = await ctx.client().compliance.assessments.get(id as string, version(ctx));
  emit(ctx, r, () =>
    [
      assessmentLine(r),
      `  author: ${inert(r.author)}   contributors: ${r.contributors.map(inert).join(", ")}`,
      `  submitted: ${r.submitted_by ? `${inert(r.submitted_by)} at ${r.submitted_at}` : "-"}`,
      `  reviewed:  ${r.reviewed_by ? `${inert(r.reviewed_by)} at ${r.reviewed_at}` : "-"}${r.review_comment ? ` (${inert(r.review_comment)})` : ""}`,
      `  risks: ${r.risks.length}   affected groups: ${r.affected_groups.length}${r.superseded ? "   (a later version exists)" : ""}`,
    ].join("\n"),
  );
  return EXIT.OK;
}

async function assessmentsCreate(ctx: Ctx): Promise<number> {
  const usage = "compliance assessments create --file <path|->";
  const body = await readDoc(ctx, fileArg(ctx, usage));
  const key = ctx.str("idempotency-key");
  const r = await ctx
    .client()
    .compliance.assessments.create(body as never, key ? { idempotencyKey: key } : {});
  emit(ctx, r, () => `assessment ${r.assessment_id} created as a draft (version ${r.version})`);
  return EXIT.OK;
}

async function assessmentsRevise(ctx: Ctx): Promise<number> {
  const usage =
    "compliance assessments revise <assessment-id> --expected-version <n> --file <path|->";
  const [id] = need(ctx, 1, usage);
  const patch = await readDoc(ctx, fileArg(ctx, usage));
  const r = await ctx
    .client()
    .compliance.assessments.revise(id as string, expected(ctx, usage), patch as never);
  emit(ctx, r, () => `assessment ${r.assessment_id} is a draft at version ${r.version}`);
  return EXIT.OK;
}

async function assessmentsSubmit(ctx: Ctx): Promise<number> {
  const usage = "compliance assessments submit <assessment-id> --expected-version <n>";
  const [id] = need(ctx, 1, usage);
  const r = await ctx.client().compliance.assessments.submit(id as string, expected(ctx, usage));
  emit(ctx, r, () => `assessment ${r.assessment_id} v${r.version} is waiting for review`);
  return EXIT.OK;
}

async function assessmentsWithdraw(ctx: Ctx): Promise<number> {
  const usage = "compliance assessments withdraw <assessment-id> --expected-version <n>";
  const [id] = need(ctx, 1, usage);
  const r = await ctx.client().compliance.assessments.withdraw(id as string, expected(ctx, usage));
  emit(ctx, r, () => `assessment ${r.assessment_id} v${r.version} is a draft again`);
  return EXIT.OK;
}

async function assessmentsReview(ctx: Ctx): Promise<number> {
  const usage =
    "compliance assessments review <assessment-id> --expected-version <n> --decision <approve|reject> [--comment <text>]";
  const [id] = need(ctx, 1, usage);
  const decision = ctx.str("decision");
  if (decision !== "approve" && decision !== "reject")
    throw new UsageError(`--decision approve|reject is required; usage: axis ${usage}`);
  const r = await ctx
    .client()
    .compliance.assessments.review(
      id as string,
      expected(ctx, usage),
      decision,
      ctx.str("comment"),
    );
  emit(ctx, r, () => `assessment ${r.assessment_id} v${r.version} is ${r.state}`);
  return EXIT.OK;
}

// ---- documents -----------------------------------------------------------------------------------------------------------------

async function docsGenerate(ctx: Ctx): Promise<number> {
  const [ref] = need(ctx, 1, "compliance documents generate <name@version>");
  const key = ctx.str("idempotency-key");
  const r = await ctx
    .client()
    .compliance.documents.generate(ref as string, key ? { idempotencyKey: key } : {});
  const gaps = (r.document.body["gaps"] as unknown[] | undefined)?.length ?? 0;
  emit(
    ctx,
    r,
    () =>
      `${r.created ? "generated" : "unchanged"}: ${String(r.document.meta["document_id"])} (version ${String(r.document.meta["doc_version"])}, ${gaps} gap${gaps === 1 ? "" : "s"}, hash ${r.document.content_hash.slice(0, 16)})`,
  );
  return EXIT.OK;
}

async function docsList(ctx: Ctx): Promise<number> {
  const bp = ctx.str("blueprint");
  let name: string | undefined;
  let ver: string | undefined;
  if (bp) {
    const at = bp.lastIndexOf("@");
    name = at > 0 ? bp.slice(0, at) : bp;
    ver = at > 0 ? bp.slice(at + 1) : undefined;
  }
  const r = await ctx.client().compliance.documents.list({
    ...(name ? { blueprint_name: name } : {}),
    ...(ver ? { blueprint_version: ver } : {}),
  });
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "document", get: (x) => x.document_id },
        { header: "blueprint", get: (x) => `${x.blueprint.name}@${x.blueprint.version}` },
        { header: "v", get: (x) => x.doc_version },
        { header: "gaps", get: (x) => x.gap_count },
        { header: "generated", get: (x) => x.generated_at },
        { header: "hash", get: (x) => x.content_hash.slice(0, 12) },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function docsGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "compliance documents get <document-id> [--markdown] [--out <path>]");
  const r = await ctx.client().compliance.documents.get(id as string);
  const out = ctx.str("out");
  if (out) {
    try {
      writeFileSync(
        out,
        ctx.bool("markdown") ? r.document.markdown : `${JSON.stringify(r.document, null, 2)}\n`,
      );
    } catch (e) {
      throw new CliError(`cannot write ${out} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  } else if (ctx.bool("markdown")) ctx.out(inert(r.document.markdown));
  else
    emit(ctx, r, () =>
      [
        `${String(r.document.meta["document_id"])} v${String(r.document.meta["doc_version"])} (${String((r.document.meta["blueprint"] as { name: string; version: string }).name)})`,
        `  content hash: ${r.document.content_hash}`,
        `  seal: ${r.document.seal.alg} ${r.document.seal.key_id}`,
        `  verification: ${r.verification.ok ? "OK" : `FAILED (${r.verification.failed.join(", ")})`}`,
      ].join("\n"),
    );
  if (!r.verification.ok) {
    ctx.err(`document does not verify: ${r.verification.failed.join(", ")}`);
    return EXIT.ERROR;
  }
  return EXIT.OK;
}

export const COMPLIANCE_COMMANDS: Command[] = [
  {
    path: ["compliance"],
    summary: "AI system inventory, impact assessments and sealed technical documentation",
    description:
      "Designed for and evidence-ready toward ISO/IEC 42001 and the EU AI Act. These are records and evidence, not a certification.",
  },
  { path: ["compliance", "systems"], summary: "The AI system inventory" },
  {
    path: ["compliance", "systems", "list"],
    summary: "List AI systems (latest version of each)",
    flags: [
      {
        name: "risk-level",
        type: "string",
        placeholder: "<level>",
        choices: ["minimal", "limited", "high"],
        desc: "Only this risk level",
      },
      {
        name: "stage",
        type: "string",
        placeholder: "<stage>",
        choices: ["design", "development", "deployed", "retired"],
        desc: "Only this lifecycle stage",
      },
    ],
    run: systemsList,
  },
  {
    path: ["compliance", "systems", "get"],
    summary: "Show one AI system record",
    usage: "<system-id>",
    flags: [VERSION],
    run: systemsGet,
  },
  {
    path: ["compliance", "systems", "create"],
    summary: "Register an AI system",
    description:
      "The file holds name, purpose, owner, risk_level and optionally system_id, lifecycle_stage, blueprints, data_categories, stakeholders.",
    flags: [FILE, IDEM],
    run: systemsCreate,
  },
  {
    path: ["compliance", "systems", "update"],
    summary: "Change an AI system (a new version; nothing is deleted)",
    usage: "<system-id>",
    flags: [FILE, EXPECTED],
    run: systemsUpdate,
  },
  { path: ["compliance", "assessments"], summary: "AI impact assessments with independent review" },
  {
    path: ["compliance", "assessments", "list"],
    summary: "List impact assessments (latest version of each)",
    flags: [
      { name: "system", type: "string", placeholder: "<system-id>", desc: "Only this system" },
      {
        name: "state",
        type: "string",
        placeholder: "<state>",
        choices: ["draft", "in_review", "approved", "rejected"],
        desc: "Only this state",
      },
      { name: "overdue", type: "boolean", desc: "Only assessments that are overdue" },
    ],
    run: assessmentsList,
  },
  {
    path: ["compliance", "assessments", "get"],
    summary: "Show one impact assessment",
    usage: "<assessment-id>",
    flags: [VERSION],
    run: assessmentsGet,
  },
  {
    path: ["compliance", "assessments", "create"],
    summary: "Start an impact assessment (a draft)",
    description:
      "The file holds system_id, title, risk_rating, intended_use, review_due (YYYY-MM-DD) and optionally blueprints, affected_groups, risks, stakeholders.",
    flags: [FILE, IDEM],
    run: assessmentsCreate,
  },
  {
    path: ["compliance", "assessments", "revise"],
    summary: "Edit the draft, or start the next version of a reviewed assessment",
    usage: "<assessment-id>",
    flags: [FILE, EXPECTED],
    run: assessmentsRevise,
  },
  {
    path: ["compliance", "assessments", "submit"],
    summary: "Submit a draft for review",
    usage: "<assessment-id>",
    flags: [EXPECTED],
    run: assessmentsSubmit,
  },
  {
    path: ["compliance", "assessments", "withdraw"],
    summary: "Take a submitted assessment back to draft",
    usage: "<assessment-id>",
    flags: [EXPECTED],
    run: assessmentsWithdraw,
  },
  {
    path: ["compliance", "assessments", "review"],
    summary: "Approve or reject a submitted assessment (never your own work)",
    usage: "<assessment-id>",
    description:
      "The reviewer is never the author, a contributor or the member who submitted the version. A rejection needs a comment.",
    flags: [
      EXPECTED,
      {
        name: "decision",
        type: "string",
        placeholder: "<decision>",
        choices: ["approve", "reject"],
        desc: "approve or reject",
      },
      { name: "comment", type: "string", placeholder: "<text>", desc: "Review comment" },
    ],
    run: assessmentsReview,
  },
  {
    path: ["compliance", "documents"],
    summary: "Sealed technical documentation (Annex IV structure)",
  },
  {
    path: ["compliance", "documents", "generate"],
    summary: "Assemble and seal the technical documentation of a blueprint version",
    usage: "<name@version>",
    description:
      "Reads this tenant's records only. What cannot be read is listed in the document as a gap. Unchanged sources return the latest version.",
    flags: [IDEM],
    run: docsGenerate,
  },
  {
    path: ["compliance", "documents", "list"],
    summary: "List generated documents",
    flags: [
      {
        name: "blueprint",
        type: "string",
        placeholder: "<name[@version]>",
        desc: "Only this blueprint",
      },
    ],
    run: docsList,
  },
  {
    path: ["compliance", "documents", "get"],
    summary:
      "Show a document and verify its hash, Markdown and seal (exit 1 if they do not verify)",
    usage: "<document-id>",
    flags: [
      { name: "markdown", type: "boolean", desc: "Print (or write) the Markdown rendering" },
      { name: "out", type: "string", placeholder: "<path>", desc: "Write the document to a file" },
    ],
    run: docsGet,
  },
];
