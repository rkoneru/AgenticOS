import { readFileSync, writeFileSync } from "node:fs";
import { parse } from "yaml";
import type { Command, Ctx, FlagSpec } from "./cli.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import { inert, structured, table } from "./render.js";

/**
 * `axis governance ...` (OpenAPI 1.6.0, ADR 0111): data-subject requests (export, erasure, restriction), legal holds, retention and
 * residency. Writes need the tenant's `privacy_officer` role; reads also `owner`, `admin` and `auditor`.
 *
 * Identifiers are personal data: they are accepted from a file (or stdin) as well as from `--identifier kind:value` (which lands in shell
 * history, so prefer the file for real requests) and are never printed back; the server shows an opaque `subject_ref` only.
 * Text that came from the server is printed inert. These commands are evidence-ready engineering, not a compliance certification.
 */

type Kind =
  | "email"
  | "phone"
  | "user_ref"
  | "end_user_id"
  | "channel_identity"
  | "subject_key"
  | "billing_customer";
const KINDS: readonly Kind[] = [
  "email",
  "phone",
  "user_ref",
  "end_user_id",
  "channel_identity",
  "subject_key",
  "billing_customer",
];
const CLASSES = [
  "conversation",
  "memory",
  "run_logs",
  "transcripts",
  "eval_data",
  "telemetry",
  "billing",
  "audit",
] as const;
type DataClass = (typeof CLASSES)[number];

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
const FILE: FlagSpec = {
  name: "file",
  short: "f",
  type: "string",
  placeholder: "<path|->",
  desc: "YAML or JSON document ('-' reads stdin)",
};
const idem = (ctx: Ctx): { idempotencyKey: string } | Record<string, never> => {
  const k = ctx.str("idempotency-key");
  return k ? { idempotencyKey: k } : {};
};

function parseIdentifier(raw: string): { kind: Kind; value: string } {
  const at = raw.indexOf(":");
  const kind = at > 0 ? raw.slice(0, at) : "";
  const value = at > 0 ? raw.slice(at + 1) : "";
  if (!(KINDS as readonly string[]).includes(kind) || value === "")
    throw new UsageError(
      `--identifier must be <kind>:<value> with kind one of ${KINDS.join(", ")}`,
    );
  return { kind: kind as Kind, value };
}

function dataClass(v: string): DataClass {
  if (!(CLASSES as readonly string[]).includes(v))
    throw new UsageError(`unknown data class "${v}"; one of ${CLASSES.join(", ")}`);
  return v as DataClass;
}

const requestLine = (r: {
  id: string;
  kind: string;
  status: string;
  subject_ref: string;
  due_at: string;
  extended: boolean;
}): string =>
  `${r.id} [${r.kind}/${r.status}] subject ${r.subject_ref}, due ${r.due_at}${r.extended ? " (extended)" : ""}`;

// ---- requests ------------------------------------------------------------------------------------------------------------------

async function requestsList(ctx: Ctx): Promise<number> {
  const status = ctx.str("status");
  const r = await ctx
    .client()
    .governance.requests.list(status ? { status: status as "received" } : {});
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "request", get: (x) => x.id },
        { header: "kind", get: (x) => x.kind },
        { header: "status", get: (x) => x.status },
        { header: "subject", get: (x) => x.subject_ref },
        { header: "received", get: (x) => x.received_at },
        { header: "due", get: (x) => x.due_at },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function requestsGet(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "governance requests get <request-id>");
  const r = await ctx.client().governance.requests.get(id as string);
  emit(ctx, r, () =>
    [
      requestLine(r),
      `  received: ${r.received_at}`,
      `  verified: ${r.verified_at ? `${r.verified_at} (${inert(r.verified_method ?? "")})` : "no"}`,
      `  destination region: ${r.destination_region ?? "-"}`,
    ].join("\n"),
  );
  return EXIT.OK;
}

async function requestsCreate(ctx: Ctx): Promise<number> {
  const usage =
    "governance requests create --kind <export|erase|restrict> (--identifier <kind:value> ... | --file <path|->) [--destination-region <r>]";
  const kind = ctx.str("kind");
  if (kind !== "export" && kind !== "erase" && kind !== "restrict")
    throw new UsageError(`--kind export|erase|restrict is required; usage: axis ${usage}`);
  const fromFlags = ctx.list("identifier").map(parseIdentifier);
  const file = ctx.str("file");
  let identifiers = fromFlags;
  if (file) {
    const doc = await readDoc(ctx, file);
    const ids = doc["identifiers"];
    if (!Array.isArray(ids)) throw new CliError(`${file} must hold an "identifiers" list`);
    identifiers = [...fromFlags, ...(ids as { kind: Kind; value: string }[])];
  }
  if (identifiers.length === 0)
    throw new UsageError(`at least one identifier is required; usage: axis ${usage}`);
  const region = ctx.str("destination-region");
  const r = await ctx
    .client()
    .governance.requests.create(
      { kind, identifiers, ...(region ? { destination_region: region } : {}) } as never,
      idem(ctx),
    );
  emit(ctx, r, () => `request opened: ${requestLine(r)}`);
  return EXIT.OK;
}

async function requestsVerify(ctx: Ctx): Promise<number> {
  const usage = "governance requests verify <request-id> --file <path|-> (the evidence object)";
  const [id] = need(ctx, 1, usage);
  const f = ctx.str("file");
  if (!f) throw new UsageError(`--file is required; usage: axis ${usage}`);
  const evidence = await readDoc(ctx, f);
  const r = await ctx.client().governance.requests.verify(id as string, evidence, idem(ctx));
  emit(ctx, r, () =>
    r.status === "received"
      ? `NOT verified: the evidence was refused (${inert(r.verified_method ?? "unknown")}); nothing was exported or erased`
      : `request ${r.id} verified (${inert(r.verified_method ?? "")})`,
  );
  return r.status === "received" ? EXIT.ERROR : EXIT.OK;
}

async function requestsExport(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "governance requests export <request-id> [--out <path>]");
  const r = await ctx.client().governance.requests.export(id as string, idem(ctx));
  const out = ctx.str("out");
  if (out) {
    try {
      writeFileSync(out, `${JSON.stringify(r, null, 2)}\n`, { mode: 0o600 });
    } catch (e) {
      throw new CliError(`cannot write ${out} (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
    emit(ctx, { written: out }, () => `signed export bundle written to ${out} (mode 0600)`);
  } else {
    emit(
      ctx,
      r,
      () =>
        `signed export bundle (${r.signature.alg} ${r.signature.key_id}); use --out <path> to save it, or --json to print it`,
    );
  }
  return EXIT.OK;
}

async function requestsErase(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "governance requests erase <request-id>");
  const r = await ctx.client().governance.requests.erase(id as string, idem(ctx));
  emit(ctx, r, () =>
    r.status === "completed"
      ? `erased and verified: request ${r.request.id}`
      : `${r.status.toUpperCase()}: request ${r.request.id} is not complete (${r.providers.length} stores reported)`,
  );
  return r.status === "completed" ? EXIT.OK : EXIT.ERROR;
}

async function requestsRestrict(ctx: Ctx): Promise<number> {
  const usage = "governance requests restrict <request-id> --reason <text>";
  const [id] = need(ctx, 1, usage);
  const reason = ctx.str("reason");
  if (!reason) throw new UsageError(`--reason is required; usage: axis ${usage}`);
  const r = await ctx.client().governance.requests.restrict(id as string, reason, idem(ctx));
  emit(ctx, r, () => `restriction applied: ${requestLine(r)}`);
  return EXIT.OK;
}

// ---- holds ---------------------------------------------------------------------------------------------------------------------

async function holdsList(ctx: Ctx): Promise<number> {
  const r = await ctx.client().governance.holds.list(ctx.bool("all") ? { all: true } : {});
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "hold", get: (x) => x.id },
        { header: "kind", get: (x) => x.kind },
        { header: "scope", get: (x) => x.scope },
        { header: "case", get: (x) => inert(x.case_ref ?? "-") },
        { header: "reason", get: (x) => inert(x.reason) },
        { header: "placed", get: (x) => x.placed_at },
        { header: "released", get: (x) => x.released_at ?? "-" },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function holdsPlace(ctx: Ctx): Promise<number> {
  const usage =
    "governance holds place --scope <tenant|subject|case> --reason <text> [--case-ref <ref>] [--class <class> ...] [--file <path|->]";
  const scope = ctx.str("scope");
  if (scope !== "tenant" && scope !== "subject" && scope !== "case")
    throw new UsageError(`--scope tenant|subject|case is required; usage: axis ${usage}`);
  const reason = ctx.str("reason");
  if (!reason) throw new UsageError(`--reason is required; usage: axis ${usage}`);
  const classes = ctx.list("class").map(dataClass);
  const file = ctx.str("file");
  const groups = file ? (await readDoc(ctx, file))["groups"] : undefined;
  if (file && !Array.isArray(groups)) throw new CliError(`${file} must hold a "groups" list`);
  const caseRef = ctx.str("case-ref");
  const r = await ctx.client().governance.holds.place(
    {
      scope,
      reason,
      ...(caseRef ? { case_ref: caseRef } : {}),
      ...(classes.length ? { classes } : {}),
      ...(groups ? { groups } : {}),
    } as never,
    idem(ctx),
  );
  emit(
    ctx,
    r,
    () => `hold ${r.id} placed (${r.scope}); purge and erasure of matching data are suspended`,
  );
  return EXIT.OK;
}

async function holdsRelease(ctx: Ctx): Promise<number> {
  const [id] = need(ctx, 1, "governance holds release <hold-id>");
  const r = await ctx.client().governance.holds.release(id as string, idem(ctx));
  emit(ctx, r, () => `hold ${r.id} released at ${r.released_at ?? "-"}`);
  return EXIT.OK;
}

// ---- retention and residency ---------------------------------------------------------------------------------------------------

async function retentionGet(ctx: Ctx): Promise<number> {
  const r = await ctx.client().governance.retention.get();
  emit(ctx, r, () =>
    table(
      r.items,
      [
        { header: "class", get: (x) => x.data_class },
        { header: "requested days", get: (x) => x.requested_days },
        { header: "effective days", get: (x) => x.effective_days },
        { header: "clamped", get: (x) => x.clamped ?? "-" },
        { header: "source", get: (x) => x.source },
      ],
      ctx.style,
    ),
  );
  return EXIT.OK;
}

async function retentionSet(ctx: Ctx): Promise<number> {
  const [cls, days] = need(ctx, 2, "governance retention set <data-class> <days>");
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1) throw new UsageError("<days> must be a positive whole number");
  const r = await ctx.client().governance.retention.set(dataClass(cls as string), n);
  emit(
    ctx,
    r,
    () =>
      `retention for ${String((r as { data_class?: string }).data_class ?? cls)} set to ${n} days (bounds apply)`,
  );
  return EXIT.OK;
}

const reportTable = (
  ctx: Ctx,
  r: {
    run_id: string;
    dry_run: boolean;
    started_at: string;
    classes: {
      data_class: string;
      status: string;
      effective_days: number;
      matched: number;
      purged: number;
      protected_by_hold: number;
    }[];
  },
): string =>
  [
    `run ${r.run_id} (${r.dry_run ? "DRY RUN, nothing purged" : "purge"}) started ${r.started_at}`,
    table(
      r.classes,
      [
        { header: "class", get: (x) => x.data_class },
        { header: "status", get: (x) => x.status },
        { header: "days", get: (x) => x.effective_days },
        { header: "matched", get: (x) => x.matched },
        { header: "purged", get: (x) => x.purged },
        { header: "held", get: (x) => x.protected_by_hold },
      ],
      ctx.style,
    ),
  ].join("\n");

async function retentionRuns(ctx: Ctx): Promise<number> {
  const r = await ctx.client().governance.retention.runs();
  emit(ctx, r, () =>
    r.items.length === 0
      ? "no retention runs yet"
      : r.items.map((x) => reportTable(ctx, x)).join("\n\n"),
  );
  return EXIT.OK;
}

async function retentionRun(ctx: Ctx): Promise<number> {
  const classes = ctx.list("class").map(dataClass);
  const execute = ctx.bool("execute");
  const r = await ctx
    .client()
    .governance.retention.run(
      { dry_run: !execute, ...(classes.length ? { classes } : {}) },
      idem(ctx),
    );
  emit(ctx, r, () => reportTable(ctx, r));
  return r.classes.some((c) => c.status === "error" || c.status === "settings_unavailable")
    ? EXIT.ERROR
    : EXIT.OK;
}

async function residencyGet(ctx: Ctx): Promise<number> {
  const r = await ctx.client().governance.residency();
  emit(
    ctx,
    r,
    () => `home region: ${r.home_region}\nallowed regions: ${r.allowed_regions.join(", ")}`,
  );
  return EXIT.OK;
}

const CLASS_FLAG: FlagSpec = {
  name: "class",
  type: "repeat",
  placeholder: "<class>",
  desc: `Data class (repeatable): ${CLASSES.join(", ")}`,
};
const IDENT_FLAG: FlagSpec = {
  name: "identifier",
  type: "repeat",
  placeholder: "<kind:value>",
  desc: `Subject identifier (repeatable; lands in shell history, prefer --file). Kinds: ${KINDS.join(", ")}`,
};

export const GOVERNANCE_COMMANDS: Command[] = [
  {
    path: ["governance"],
    summary: "Data-subject requests, legal holds, retention and residency",
    description:
      "Writes need the privacy_officer role; reads also owner, admin and auditor. Evidence-ready engineering, not a compliance certification.",
  },
  {
    path: ["governance", "requests"],
    summary: "Data-subject requests (export, erasure, restriction)",
  },
  {
    path: ["governance", "requests", "list"],
    summary: "List data-subject requests",
    flags: [
      {
        name: "status",
        type: "string",
        placeholder: "<status>",
        choices: ["received", "verified", "processing", "completed", "rejected", "cancelled"],
        desc: "Only this status",
      },
    ],
    run: requestsList,
  },
  {
    path: ["governance", "requests", "get"],
    summary: "Show one request",
    usage: "<request-id>",
    run: requestsGet,
  },
  {
    path: ["governance", "requests", "create"],
    summary: "Open a request (the 30-day clock starts now)",
    description:
      "Identifiers are sealed at rest and never printed back; the request shows an opaque subject reference.",
    flags: [
      {
        name: "kind",
        type: "string",
        placeholder: "<kind>",
        choices: ["export", "erase", "restrict"],
        desc: "export, erase or restrict",
      },
      IDENT_FLAG,
      FILE,
      {
        name: "destination-region",
        type: "string",
        placeholder: "<region>",
        desc: "Export destination (must be allowed for the tenant)",
      },
      IDEM,
    ],
    run: requestsCreate,
  },
  {
    path: ["governance", "requests", "verify"],
    summary:
      "Verify the requester (nothing is exported or erased before this succeeds; exit 1 if refused)",
    usage: "<request-id>",
    description:
      "The file holds the evidence object: requester_token and admin_attestation. An independent tenant admin must attest (dual control).",
    flags: [FILE, IDEM],
    run: requestsVerify,
  },
  {
    path: ["governance", "requests", "export"],
    summary: "Produce the signed export bundle of a verified request",
    usage: "<request-id>",
    flags: [
      {
        name: "out",
        type: "string",
        placeholder: "<path>",
        desc: "Write the bundle to a file (mode 0600)",
      },
      IDEM,
    ],
    run: requestsExport,
  },
  {
    path: ["governance", "requests", "erase"],
    summary:
      "Erase a verified subject from every store (exit 1 unless completed; held data is not touched)",
    usage: "<request-id>",
    flags: [IDEM],
    run: requestsErase,
  },
  {
    path: ["governance", "requests", "restrict"],
    summary: "Apply a restriction of processing for a verified subject",
    usage: "<request-id>",
    flags: [{ name: "reason", type: "string", placeholder: "<text>", desc: "Why" }, IDEM],
    run: requestsRestrict,
  },
  {
    path: ["governance", "holds"],
    summary: "Legal holds (suspend purge and erasure of matching data)",
  },
  {
    path: ["governance", "holds", "list"],
    summary: "List active holds",
    flags: [{ name: "all", type: "boolean", desc: "Include released holds" }],
    run: holdsList,
  },
  {
    path: ["governance", "holds", "place"],
    summary: "Place a legal hold",
    description:
      "Subject and case scope read the people covered from the file's groups list (identifiers per person).",
    flags: [
      {
        name: "scope",
        type: "string",
        placeholder: "<scope>",
        choices: ["tenant", "subject", "case"],
        desc: "tenant, subject or case",
      },
      { name: "reason", type: "string", placeholder: "<text>", desc: "Why" },
      { name: "case-ref", type: "string", placeholder: "<ref>", desc: "Case reference" },
      CLASS_FLAG,
      FILE,
      IDEM,
    ],
    run: holdsPlace,
  },
  {
    path: ["governance", "holds", "release"],
    summary: "Release a hold",
    usage: "<hold-id>",
    flags: [IDEM],
    run: holdsRelease,
  },
  { path: ["governance", "retention"], summary: "Retention periods and purge runs" },
  {
    path: ["governance", "retention", "get"],
    summary: "Requested and effective retention per data class",
    run: retentionGet,
  },
  {
    path: ["governance", "retention", "set"],
    summary: "Set the retention period of one data class (clamped to its legal bounds)",
    usage: "<data-class> <days>",
    run: retentionSet,
  },
  {
    path: ["governance", "retention", "runs"],
    summary: "Stored retention reports, newest first",
    run: retentionRuns,
  },
  {
    path: ["governance", "retention", "run"],
    summary: "Run retention (a dry run unless --execute; exit 1 if a class errored)",
    flags: [
      CLASS_FLAG,
      { name: "execute", type: "boolean", desc: "Actually purge (default is a dry run)" },
      IDEM,
    ],
    run: retentionRun,
  },
  {
    path: ["governance", "residency"],
    summary: "The tenant's home region and the regions its data may be written to",
    run: residencyGet,
  },
];
