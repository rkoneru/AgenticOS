import { randomUUID } from "node:crypto";
import { compileAbl, type AblIssue } from "@axis/abl";
import type { AuditEvent } from "@axis/contracts";
import type { Ctx, HandlerResult, Route } from "./context.js";
import { PortConflict, PortNotFound, type BlueprintVersionDto, type RunEventDto } from "./ports.js";
import { internal, notFound, validation, type ValidationIssue } from "./problem.js";

const NAME = /^[a-z][a-z0-9-]{1,62}$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const AGENT_TARGET = /^[a-z][a-z0-9-]{1,62}$/;
const TOOL_TARGET = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/;
const MAX_USAGE_RANGE_MS = 366 * 86_400_000;

const str = (v: unknown): string => String(v);

/** Signed cursor round trip. A cursor that does not verify for THIS tenant and resource is a 422. */
function position(c: Ctx, resource: string): string | undefined {
  const raw = c.query["cursor"];
  if (raw === undefined) return undefined;
  const p = c.cursors.decode(c.tenantId, resource, str(raw));
  if (p === undefined)
    throw validation("invalid cursor", [
      { path: "/cursor", message: "malformed, forged or from another resource" },
    ]);
  return p;
}
const wrap = (c: Ctx, resource: string, next: string | undefined): string | null =>
  next === undefined ? null : c.cursors.encode(c.tenantId, resource, next);
const limit = (c: Ctx): number => Number(c.query["limit"] ?? 50);

const ok = (body: unknown, status = 200, headers?: Record<string, string>): HandlerResult => ({
  status,
  body,
  ...(headers ? { headers } : {}),
});

// ---- blueprints --------------------------------------------------------------------------------------------------------------

const issuesFromAbl = (issues: AblIssue[]): ValidationIssue[] =>
  issues.slice(0, 50).map((i) => ({ path: i.path, keyword: i.keyword, message: i.message }));

async function listBlueprints(c: Ctx): Promise<HandlerResult> {
  const after = position(c, "blueprints");
  const r = await c.deps.blueprints.list(c.tenantId, {
    limit: limit(c),
    ...(after ? { after } : {}),
  });
  return ok({ items: r.items, next_cursor: wrap(c, "blueprints", r.next) });
}

async function publishBlueprintVersion(c: Ctx): Promise<HandlerResult> {
  const abl = (c.body as { abl: unknown }).abl;
  const r = compileAbl(abl);
  if (!r.ok) {
    const errors: ValidationIssue[] = [
      ...issuesFromAbl(r.issues),
      ...r.findings
        .filter((f) => f.severity === "error")
        .map((f) => ({ path: f.path, keyword: f.code, message: f.message })),
    ];
    throw validation("the blueprint does not validate", errors);
  }
  const m = r.manifest;
  const dto: BlueprintVersionDto = {
    name: m.blueprint.name,
    version: m.blueprint.version,
    risk_level: m.risk.level as BlueprintVersionDto["risk_level"],
    content_hash: m.blueprint.content_hash,
    signature: null,
    created_at: new Date().toISOString(),
    abl,
  };
  const saved = await c.deps.blueprints.publish(c.tenantId, dto);
  return ok(saved, 201);
}

async function getBlueprintVersion(c: Ctx): Promise<HandlerResult> {
  const name = str(c.params["name"]);
  const version = str(c.params["version"]);
  if (!NAME.test(name) || !SEMVER.test(version)) throw notFound("blueprint version not found");
  const v = await c.deps.blueprints.get(c.tenantId, name, version);
  if (!v) throw notFound("blueprint version not found");
  return ok(v);
}

// ---- runs ------------------------------------------------------------------------------------------------------------------------

/** A run belongs to the tenant of the credential; a run service that answers for another tenant is a bug we refuse to relay. */
function ownRun<T extends { id: string }>(c: Ctx, r: T & { tenant_id?: string }): T {
  if (r.tenant_id !== undefined && r.tenant_id !== c.tenantId) {
    c.opts.log?.("error", "run service returned another tenant's run", { request_id: c.requestId });
    throw notFound("run not found");
  }
  const { tenant_id: _t, ...rest } = r as T & { tenant_id?: string };
  void _t;
  return rest as unknown as T;
}

async function listRuns(c: Ctx): Promise<HandlerResult> {
  const after = position(c, "runs");
  const r = await c.deps.runs.list(c.tenantId, {
    limit: limit(c),
    ...(after ? { after } : {}),
    ...(c.query["state"] ? { state: str(c.query["state"]) } : {}),
    ...(c.query["blueprint"] ? { blueprint: str(c.query["blueprint"]) } : {}),
  });
  return ok({ items: r.items.map((x) => ownRun(c, x)), next_cursor: wrap(c, "runs", r.next) });
}

async function startRun(c: Ctx): Promise<HandlerResult> {
  const b = c.body as {
    blueprint: { name: string; version: string };
    input?: Record<string, unknown>;
  };
  const bp = await c.deps.blueprints.get(c.tenantId, b.blueprint.name, b.blueprint.version);
  if (!bp) throw notFound("blueprint version not found");
  const compiled = compileAbl(bp.abl);
  if (!compiled.ok) {
    c.opts.log?.("error", "a stored blueprint no longer compiles", { request_id: c.requestId });
    throw internal();
  }
  const run = await c.deps.runs.start({
    tenantId: c.tenantId,
    runId: randomUUID(),
    traceId: c.traceId,
    blueprint: b.blueprint,
    manifest: compiled.manifest,
    input: b.input ?? {},
    principal: { memberId: c.principal.memberId, role: c.principal.role },
  });
  return ok(ownRun(c, run), 202, { location: `/v1/runs/${run.id}` });
}

async function getRun(c: Ctx): Promise<HandlerResult> {
  const r = await c.deps.runs.get(c.tenantId, str(c.params["runId"]));
  if (!r) throw notFound("run not found");
  return ok(ownRun(c, r));
}

async function signalRun(c: Ctx): Promise<HandlerResult> {
  const b = c.body as { pid?: string; signal: string; reason?: string };
  try {
    const r = await c.deps.runs.signal(c.tenantId, str(c.params["runId"]), {
      signal: b.signal,
      ...(b.pid ? { pid: b.pid } : {}),
      ...(b.reason ? { reason: b.reason } : {}),
    });
    return ok(r);
  } catch (e) {
    if (e instanceof PortNotFound) throw notFound("run or process not found");
    throw e;
  }
}

async function listRunEvents(c: Ctx): Promise<HandlerResult> {
  const runId = str(c.params["runId"]);
  const after = Number(c.query["after_sequence"] ?? 0);
  if (c.wantsStream) {
    // Existence and tenancy are checked BEFORE the stream opens (a 404 is a normal problem response, not an SSE error event).
    if (!(await c.deps.runs.get(c.tenantId, runId))) throw notFound("run not found");
    return {
      stream: c.deps.runs.stream(c.tenantId, runId, Math.max(after, c.lastEventId ?? 0), c.signal),
    };
  }
  const lim = limit(c);
  const items = await c.deps.runs.events(c.tenantId, runId, { afterSequence: after, limit: lim });
  if (!items) throw notFound("run not found");
  const last: RunEventDto | undefined = items[items.length - 1];
  return ok({ items, next_cursor: items.length === lim && last ? String(last.sequence) : null });
}

// ---- approvals -----------------------------------------------------------------------------------------------------------------------

async function listApprovals(c: Ctx): Promise<HandlerResult> {
  const after = position(c, "approvals");
  const r = await c.deps.approvals.list(c.principal, {
    limit: limit(c),
    ...(after ? { after } : {}),
    ...(c.query["status"] ? { status: str(c.query["status"]) as "pending" } : {}),
  });
  return ok({ items: r.items, next_cursor: wrap(c, "approvals", r.next) });
}

async function decideApproval(c: Ctx): Promise<HandlerResult> {
  const b = c.body as { decision: "approve" | "reject"; comment?: string };
  const r = await c.deps.approvals.decide(c.principal, str(c.params["approvalId"]), {
    decision: b.decision,
    ...(b.comment !== undefined ? { comment: b.comment } : {}),
  });
  return ok(r);
}

async function getApproval(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.approvals.get(c.principal, str(c.params["approvalId"])));
}

async function getMe(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.identity.me(c.principal));
}

// ---- policies ---------------------------------------------------------------------------------------------------------------------------

async function listPolicyPacks(c: Ctx): Promise<HandlerResult> {
  const after = position(c, "policies");
  const r = await c.deps.policies.list(c.principal, {
    limit: limit(c),
    ...(after ? { after } : {}),
  });
  return ok({ items: r.items, next_cursor: wrap(c, "policies", r.next) });
}

async function publishPolicyPack(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.policies.publish(c.principal, (c.body as { policy: unknown }).policy),
    201,
  );
}

async function activatePolicyPack(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.policies.activate(c.principal, str(c.params["versionId"])));
}

async function testPolicy(c: Ctx): Promise<HandlerResult> {
  const b = c.body as {
    policy: unknown;
    request: { enforcement_point: string; action?: string; context: Record<string, unknown> };
  };
  return ok(await c.deps.policies.test(c.principal, b));
}

// ---- audit ---------------------------------------------------------------------------------------------------------------------------------

const BATCH = 500;
const MAX_SCAN = 5000;

async function listAuditEvents(c: Ctx): Promise<HandlerResult> {
  const lim = limit(c);
  const cursor = position(c, "audit");
  let from = Math.max(cursor !== undefined ? Number(cursor) : 1, Number(c.query["from_seq"] ?? 1));
  if (!Number.isSafeInteger(from) || from < 1)
    throw validation("invalid cursor", [{ path: "/cursor", message: "malformed" }]);
  const decision = c.query["decision"] as string | undefined;
  const traceId = c.query["trace_id"] as string | undefined;
  const items: AuditEvent[] = [];
  let scanned = 0;
  let more = false;
  while (items.length < lim && scanned < MAX_SCAN) {
    const batch = await c.deps.auditLog.list(c.tenantId, {
      fromSeq: from,
      limit: BATCH,
      ...(traceId ? { traceId } : {}),
    });
    // Defence in depth: a store that returned another tenant's row would be a bug; never relay it.
    const mine = batch.filter((e) => e.tenant_id === c.tenantId);
    for (const [i, e] of mine.entries()) {
      scanned++;
      if (decision !== undefined && e.decision !== decision) continue;
      items.push(e);
      if (items.length === lim) {
        more = i < mine.length - 1 || batch.length === BATCH;
        from = e.seq + 1;
        break;
      }
    }
    if (items.length === lim) break;
    if (batch.length < BATCH) break;
    from = (batch[batch.length - 1] as AuditEvent).seq + 1;
    more = true; // scan budget may end mid-chain: tell the caller where to resume
  }
  const exhaustedBudget = items.length < lim && scanned >= MAX_SCAN;
  return ok({
    items,
    next_cursor:
      more && (items.length === lim || exhaustedBudget)
        ? c.cursors.encode(c.tenantId, "audit", String(from))
        : null,
  });
}

async function verifyAuditChain(c: Ctx): Promise<HandlerResult> {
  const b = (c.body ?? {}) as { from_seq?: number; to_seq?: number };
  const head = await c.deps.auditLog.head(c.tenantId);
  const from = b.from_seq ?? 1;
  const to = Math.min(b.to_seq ?? head, head);
  if (head === 0) return ok({ ok: true, verified: 0 });
  if (from > to)
    throw validation("from_seq is after the end of the range", [
      { path: "/from_seq", message: "must be <= to_seq and <= the chain head" },
    ]);
  if (to - from + 1 > c.opts.maxVerifyEvents)
    throw validation(
      `range too large: verify at most ${c.opts.maxVerifyEvents} events per call (narrow with from_seq/to_seq)`,
      [{ path: "/to_seq", message: "range too large" }],
    );
  const v = await c.deps.auditLog.verify(c.tenantId, { fromSeq: from, toSeq: to });
  return ok(
    v.ok
      ? { ok: true, verified: v.length }
      : {
          ok: false,
          verified: Math.max(0, v.brokenAtSeq - from),
          broken_at_seq: v.brokenAtSeq,
          reason: v.reason,
        },
  );
}

// ---- kill switches, usage, evals, explanations -------------------------------------------------------------------------------------------

async function listKillSwitches(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.killSwitches.list(c.tenantId) });
}

async function setKillSwitch(c: Ctx): Promise<HandlerResult> {
  const b = c.body as {
    scope: "tenant" | "agent" | "tool";
    target?: string;
    engaged: boolean;
    reason?: string;
  };
  if (b.scope === "tenant" && b.target !== undefined && b.target !== "")
    throw validation("a tenant kill-switch has no target", [
      { path: "/target", message: "must be absent for scope tenant" },
    ]);
  if (b.scope === "agent" && !(typeof b.target === "string" && AGENT_TARGET.test(b.target)))
    throw validation("an agent kill-switch needs the agent's name as target", [
      { path: "/target", message: "agent name required" },
    ]);
  if (b.scope === "tool" && !(typeof b.target === "string" && TOOL_TARGET.test(b.target)))
    throw validation("a tool kill-switch needs the tool's name as target", [
      { path: "/target", message: "tool name required" },
    ]);
  const r = await c.deps.killSwitches.set(c.principal, {
    scope: b.scope,
    engaged: b.engaged,
    ...(b.scope !== "tenant" && b.target ? { target: b.target } : {}),
    ...(b.reason ? { reason: b.reason } : {}),
  });
  return ok(r);
}

async function getUsage(c: Ctx): Promise<HandlerResult> {
  const from = new Date(str(c.query["from"]));
  const to = new Date(str(c.query["to"]));
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()))
    throw validation("from and to must be date-times", [
      { path: "/from", message: "invalid date-time" },
    ]);
  if (to <= from)
    throw validation("to must be after from", [{ path: "/to", message: "must be after from" }]);
  if (to.getTime() - from.getTime() > MAX_USAGE_RANGE_MS)
    throw validation("the range may span at most 366 days", [
      { path: "/to", message: "range too large" },
    ]);
  const groupBy = c.query["group_by"] as "meter" | "model" | "blueprint" | "day" | undefined;
  return ok({
    items: await c.deps.usage.query(c.tenantId, { from, to, ...(groupBy ? { groupBy } : {}) }),
  });
}

async function explainRun(c: Ctx): Promise<HandlerResult> {
  const runId = str(c.params["runId"]);
  const run = await c.deps.runs.get(c.tenantId, runId);
  if (!run) throw notFound("run not found");
  // The run service serves at most 200 events per call: page through the log (bounded) instead of asking for more.
  const events: RunEventDto[] = [];
  for (let after = 0, pages = 0; pages < 25; pages++) {
    const batch =
      (await c.deps.runs.events(c.tenantId, runId, { afterSequence: after, limit: 200 })) ?? [];
    events.push(...batch);
    if (batch.length < 200) break;
    after = (batch[batch.length - 1] as RunEventDto).sequence;
  }
  const x = await c.deps.explain.explainRun(c.tenantId, {
    traceId: run.trace_id ?? "",
    runEvents: events,
  });
  return ok(x);
}

async function explainAuditEvent(c: Ctx): Promise<HandlerResult> {
  const x = await c.deps.explain.explainEvent(c.tenantId, Number(c.params["seq"]));
  if (x === undefined) throw notFound("audit event not found");
  return ok(x);
}

// ---- evals ------------------------------------------------------------------------------------------------------------------------

async function startEvalRun(c: Ctx): Promise<HandlerResult> {
  const b = c.body as {
    suite: string;
    mode?: "ci" | "manual";
    blueprint: { name: string; version: string; namespace?: string };
  };
  // The run is bound to the CONTENT of exactly this version: the gateway resolves the hash, the caller never supplies it.
  let contentHash: string;
  if (b.blueprint.namespace !== undefined) {
    const r = await c.deps.registry.resolve(
      c.principal,
      `${b.blueprint.namespace}/${b.blueprint.name}@${b.blueprint.version}`,
    );
    contentHash = r.content_hash;
  } else {
    const bp = await c.deps.blueprints.get(c.tenantId, b.blueprint.name, b.blueprint.version);
    if (!bp) throw notFound("blueprint version not found");
    contentHash = bp.content_hash;
  }
  const run = await c.deps.evals.start(c.principal, {
    suite: b.suite,
    ...(b.mode ? { mode: b.mode } : {}),
    blueprint: {
      ...(b.blueprint.namespace !== undefined ? { namespace: b.blueprint.namespace } : {}),
      name: b.blueprint.name,
      version: b.blueprint.version,
      content_hash: contentHash,
    },
  });
  return ok(run, 202, { location: `/v1/evals/runs/${run.id}` });
}

async function listEvalRuns(c: Ctx): Promise<HandlerResult> {
  const after = position(c, "evalruns");
  const q = (k: string): string | undefined =>
    c.query[k] === undefined ? undefined : str(c.query[k]);
  const r = await c.deps.evals.listRuns(c.principal, {
    limit: limit(c),
    ...(after ? { cursor: after } : {}),
    ...(q("suite") ? { suite: q("suite") as string } : {}),
    ...(q("blueprint") ? { blueprint: q("blueprint") as string } : {}),
    ...(q("content_hash") ? { content_hash: q("content_hash") as string } : {}),
    ...(q("status") ? { status: q("status") as string } : {}),
  });
  return ok({ items: r.items, next_cursor: wrap(c, "evalruns", r.next) });
}

async function getEvalRun(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.getRun(c.principal, str(c.params["evalRunId"])));
}

async function getEvalRunComparison(c: Ctx): Promise<HandlerResult> {
  const cmp = await c.deps.evals.comparison(c.principal, str(c.params["evalRunId"]));
  return ok(cmp === undefined ? {} : { comparison: cmp });
}

type DeclaredSuites = { spec?: { evals?: { suites?: { ref: string; threshold: number }[] } } };

/**
 * The gate answers for a STORED version: the suites its ABL declares are always asked (a caller that leaves `suites` out cannot get a
 * green light by forgetting them), the tenant-required ones are added by the hub, and the caller may add more or raise a threshold.
 * A content hash that is not the stored version's is a 422: the answer would be about content that was never stored.
 * A version that is not stored (a hypothetical question) is answered for the suites given alone.
 */
async function gateEvalRelease(c: Ctx): Promise<HandlerResult> {
  const body = c.body as {
    blueprint: { namespace?: string; name: string; version: string; content_hash: string };
    suites?: { ref: string; threshold?: number }[];
  };
  const b = body.blueprint;
  let stored: { content_hash: string; abl: unknown } | undefined;
  try {
    stored =
      b.namespace !== undefined
        ? await c.deps.registry.resolve(c.principal, `${b.namespace}/${b.name}@${b.version}`)
        : await c.deps.blueprints.get(c.tenantId, b.name, b.version);
  } catch (e) {
    if (!(e instanceof PortNotFound)) throw e;
  }
  let suites = body.suites;
  if (stored !== undefined) {
    if (stored.content_hash !== b.content_hash)
      throw validation("blueprint.content_hash is not the content hash of the stored version", [
        { path: "/blueprint/content_hash", message: "does not match the stored version" },
      ]);
    const declared = (stored.abl as DeclaredSuites).spec?.evals?.suites ?? [];
    suites = [
      ...declared.map((d) => ({ ref: d.ref, threshold: d.threshold })),
      ...(body.suites ?? []),
    ];
  }
  return ok(
    await c.deps.evals.gate(c.principal, {
      blueprint: body.blueprint,
      ...(suites !== undefined ? { suites } : {}),
    }),
  );
}

async function listEvalDatasets(c: Ctx): Promise<HandlerResult> {
  const name = c.query["name"] === undefined ? undefined : str(c.query["name"]);
  return ok({ items: await c.deps.evals.listDatasets(c.principal, name) });
}
async function createEvalDataset(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.createDataset(c.principal, c.body as Record<string, unknown>), 201);
}
async function getEvalDatasetVersion(c: Ctx): Promise<HandlerResult> {
  const name = regName(c);
  const version = str(c.params["version"]);
  if (!/^(latest|[1-9][0-9]{0,8})$/.test(version)) throw notFound("not found");
  return ok(await c.deps.evals.getDataset(c.principal, name, version));
}
async function listEvalSuites(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.evals.listSuites(c.principal) });
}
async function createEvalSuite(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.createSuite(c.principal, c.body as Record<string, unknown>), 201);
}
async function getEvalSuite(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.getSuite(c.principal, str(c.params["suite"])));
}
async function listEvalBaselines(c: Ctx): Promise<HandlerResult> {
  return ok({
    items: await c.deps.evals.listBaselines(
      c.principal,
      str(c.query["blueprint"]),
      str(c.query["suite"]),
    ),
  });
}
async function setEvalBaseline(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.evals.setBaseline(c.principal, (c.body as { run_id: string }).run_id),
    201,
  );
}
async function listEvalReviewTasks(c: Ctx): Promise<HandlerResult> {
  return ok({
    items: await c.deps.evals.listTasks(c.principal, {
      ...(c.query["state"] ? { state: str(c.query["state"]) } : {}),
      ...(c.query["run_id"] ? { run_id: str(c.query["run_id"]) } : {}),
    }),
  });
}
async function claimEvalReviewTask(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.claimTask(c.principal, str(c.params["taskId"])));
}
async function gradeEvalReviewTask(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.evals.gradeTask(
      c.principal,
      str(c.params["taskId"]),
      c.body as { score: number; comment: string },
    ),
  );
}
async function skipEvalReviewTask(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.evals.skipTask(
      c.principal,
      str(c.params["taskId"]),
      (c.body as { reason: string }).reason,
    ),
  );
}
async function listEvalSamplingConfigs(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.evals.listSampling(c.principal) });
}
async function putEvalSamplingConfig(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.evals.putSampling(
      c.principal,
      str(c.params["samplingId"]),
      c.body as Record<string, unknown>,
    ),
  );
}
async function getEvalOnlineSummary(c: Ctx): Promise<HandlerResult> {
  return ok({
    items: await c.deps.evals.onlineSummary(c.principal, {
      ...(c.query["blueprint"] ? { blueprint: str(c.query["blueprint"]) } : {}),
      ...(c.query["suite"] ? { suite: str(c.query["suite"]) } : {}),
    }),
  });
}
async function listEvalRunners(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.evals.listRunners(c.principal) });
}
async function registerEvalRunner(c: Ctx): Promise<HandlerResult> {
  const d = (c.body as { description?: string } | undefined)?.description;
  return ok(await c.deps.evals.registerRunner(c.principal, str(c.params["runnerId"]), d));
}
async function revokeEvalRunner(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.evals.revokeRunner(c.principal, str(c.params["runnerId"])));
}

// ---- registry -----------------------------------------------------------------------------------------------------------------------

/** A registry name segment that cannot be a name is a 404 before any lookup (like a blueprint name). */
const regName = (c: Ctx, key = "name"): string => {
  const v = str(c.params[key]);
  if (!NAME.test(v)) throw notFound("not found");
  return v;
};

async function listRegistryNamespaces(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.registry.listNamespaces(c.principal) });
}
async function claimRegistryNamespace(c: Ctx): Promise<HandlerResult> {
  const ns = (c.body as { namespace: string }).namespace;
  return ok(await c.deps.registry.claim(c.principal, ns), 201);
}
async function listRegistryKeys(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.registry.listKeys(c.principal, str(c.params["namespace"])) });
}
async function addRegistryKey(c: Ctx): Promise<HandlerResult> {
  const k = await c.deps.registry.addKey(
    c.principal,
    str(c.params["namespace"]),
    (c.body as { public_key: string }).public_key,
  );
  return ok(k, 201);
}
async function publishRegistryBlueprint(c: Ctx): Promise<HandlerResult> {
  const b = c.body as Parameters<Ctx["deps"]["registry"]["publish"]>[2];
  return ok(await c.deps.registry.publish(c.principal, str(c.params["namespace"]), b), 201);
}
async function listRegistryVersions(c: Ctx): Promise<HandlerResult> {
  return ok({
    items: await c.deps.registry.listVersions(c.principal, str(c.params["namespace"]), regName(c)),
  });
}
async function yankRegistryVersion(c: Ctx): Promise<HandlerResult> {
  const version = str(c.params["version"]);
  if (!SEMVER.test(version)) throw notFound("not found");
  await c.deps.registry.yank(
    c.principal,
    str(c.params["namespace"]),
    regName(c),
    version,
    (c.body as { reason: string }).reason,
  );
  return ok({ ok: true });
}
async function listRegistryEvalAttestations(c: Ctx): Promise<HandlerResult> {
  const version = str(c.params["version"]);
  if (!SEMVER.test(version)) throw notFound("not found");
  return ok({
    items: await c.deps.registry.evalAttestations(
      c.principal,
      str(c.params["namespace"]),
      regName(c),
      version,
    ),
  });
}
async function resolveRegistryBlueprint(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.registry.resolve(c.principal, str(c.query["ref"])));
}

// ---- marketplace -----------------------------------------------------------------------------------------------------------------------

async function listMarketplaceListings(c: Ctx): Promise<HandlerResult> {
  const text = c.query["q"] === undefined ? undefined : str(c.query["q"]);
  const category = c.query["category"] === undefined ? undefined : str(c.query["category"]);
  return ok({
    items: await c.deps.marketplace.listings({
      ...(text ? { text } : {}),
      ...(category ? { category } : {}),
    }),
  });
}
async function getMarketplaceListing(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.marketplace.listing(str(c.params["namespace"]), regName(c)));
}
async function previewMarketplaceInstall(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.marketplace.preview(
      c.principal,
      c.body as { namespace: string; name: string; range: string },
    ),
  );
}
async function listMarketplaceInstalls(c: Ctx): Promise<HandlerResult> {
  return ok({ items: await c.deps.marketplace.installs(c.principal) });
}
async function installMarketplaceListing(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.marketplace.install(
      c.principal,
      c.body as Parameters<Ctx["deps"]["marketplace"]["install"]>[1],
    ),
    201,
  );
}
async function uninstallMarketplaceListing(c: Ctx): Promise<HandlerResult> {
  await c.deps.marketplace.uninstall(c.principal, str(c.params["namespace"]), regName(c));
  return ok({ ok: true });
}

// ---- compliance -------------------------------------------------------------------------------------------------------------------

const optStr = (c: Ctx, k: string): string | undefined =>
  c.query[k] === undefined ? undefined : str(c.query[k]);
const optInt = (c: Ctx, k: string): number | undefined =>
  c.query[k] === undefined ? undefined : Number(c.query[k]);
/** The body without `expected_version` (the optimistic-concurrency token travels separately). */
function withoutVersion(body: unknown): { expected: number; rest: Record<string, unknown> } {
  const { expected_version, ...rest } = body as { expected_version: number } & Record<
    string,
    unknown
  >;
  return { expected: expected_version, rest };
}

async function listComplianceSystems(c: Ctx): Promise<HandlerResult> {
  const risk = optStr(c, "risk_level");
  const stage = optStr(c, "lifecycle_stage");
  return ok({
    items: await c.deps.compliance.listSystems(c.principal, {
      ...(risk ? { risk_level: risk } : {}),
      ...(stage ? { lifecycle_stage: stage } : {}),
    }),
  });
}
async function createComplianceSystem(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.createSystem(c.principal, c.body as Record<string, unknown>),
    201,
  );
}
async function getComplianceSystem(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.getSystem(c.principal, str(c.params["systemId"]), optInt(c, "version")),
  );
}
async function updateComplianceSystem(c: Ctx): Promise<HandlerResult> {
  const { expected, rest } = withoutVersion(c.body);
  return ok(
    await c.deps.compliance.updateSystem(c.principal, str(c.params["systemId"]), expected, rest),
  );
}
async function listComplianceImpactAssessments(c: Ctx): Promise<HandlerResult> {
  const system = optStr(c, "system_id");
  const state = optStr(c, "state");
  const overdue = c.query["overdue"];
  return ok({
    items: await c.deps.compliance.listAssessments(c.principal, {
      ...(system ? { system_id: system } : {}),
      ...(state ? { state } : {}),
      ...(overdue !== undefined ? { overdue: overdue === true || overdue === "true" } : {}),
    }),
  });
}
async function createComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.createAssessment(c.principal, c.body as Record<string, unknown>),
    201,
  );
}
async function getComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.getAssessment(
      c.principal,
      str(c.params["assessmentId"]),
      optInt(c, "version"),
    ),
  );
}
async function reviseComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  const { expected, rest } = withoutVersion(c.body);
  return ok(
    await c.deps.compliance.reviseAssessment(
      c.principal,
      str(c.params["assessmentId"]),
      expected,
      rest,
    ),
  );
}
async function submitComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.submitAssessment(
      c.principal,
      str(c.params["assessmentId"]),
      (c.body as { expected_version: number }).expected_version,
    ),
  );
}
async function withdrawComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.withdrawAssessment(
      c.principal,
      str(c.params["assessmentId"]),
      (c.body as { expected_version: number }).expected_version,
    ),
  );
}
async function reviewComplianceImpactAssessment(c: Ctx): Promise<HandlerResult> {
  return ok(
    await c.deps.compliance.reviewAssessment(
      c.principal,
      str(c.params["assessmentId"]),
      c.body as { expected_version: number; decision: "approve" | "reject"; comment?: string },
    ),
  );
}
async function listComplianceDocuments(c: Ctx): Promise<HandlerResult> {
  const name = optStr(c, "blueprint_name");
  const version = optStr(c, "blueprint_version");
  return ok({
    items: await c.deps.compliance.listDocuments(c.principal, {
      ...(name ? { blueprint_name: name } : {}),
      ...(version ? { blueprint_version: version } : {}),
    }),
  });
}
async function generateComplianceDocument(c: Ctx): Promise<HandlerResult> {
  const r = await c.deps.compliance.generateDocument(
    c.principal,
    (c.body as { blueprint: { name: string; version: string } }).blueprint,
  );
  return ok(r, r.created ? 201 : 200);
}
async function getComplianceDocument(c: Ctx): Promise<HandlerResult> {
  return ok(await c.deps.compliance.getDocument(c.principal, str(c.params["documentId"])));
}

export const ROUTES: Record<string, Route> = {
  listBlueprints: { action: "api.blueprints.read", handler: listBlueprints, mutation: false },
  publishBlueprintVersion: {
    action: "api.blueprints.publish",
    handler: publishBlueprintVersion,
    mutation: true,
  },
  getBlueprintVersion: {
    action: "api.blueprints.read",
    handler: getBlueprintVersion,
    mutation: false,
  },
  listRuns: { action: "api.runs.read", handler: listRuns, mutation: false },
  startRun: { action: "api.runs.start", handler: startRun, mutation: true },
  getRun: { action: "api.runs.read", handler: getRun, mutation: false },
  signalRun: { action: "api.runs.signal", handler: signalRun, mutation: true },
  listRunEvents: { action: "api.events.read", handler: listRunEvents, mutation: false },
  listApprovals: { action: "api.approvals.read", handler: listApprovals, mutation: false },
  decideApproval: { action: "api.approvals.decide", handler: decideApproval, mutation: true },
  listPolicyPacks: { action: "api.policies.read", handler: listPolicyPacks, mutation: false },
  publishPolicyPack: { action: "api.policies.publish", handler: publishPolicyPack, mutation: true },
  testPolicy: { action: "api.policies.test", handler: testPolicy, mutation: false },
  listAuditEvents: { action: "api.audit.read", handler: listAuditEvents, mutation: false },
  verifyAuditChain: { action: "api.audit.verify", handler: verifyAuditChain, mutation: false },
  listKillSwitches: { action: "api.killswitch.read", handler: listKillSwitches, mutation: false },
  setKillSwitch: { action: "api.killswitch.write", handler: setKillSwitch, mutation: true },
  getUsage: { action: "api.usage.read", handler: getUsage, mutation: false },
  startEvalRun: { action: "api.evals.run", handler: startEvalRun, mutation: true },
  listEvalRuns: { action: "api.evals.read", handler: listEvalRuns, mutation: false },
  getEvalRun: { action: "api.evals.read", handler: getEvalRun, mutation: false },
  getEvalRunComparison: {
    action: "api.evals.read",
    handler: getEvalRunComparison,
    mutation: false,
  },
  gateEvalRelease: { action: "api.evals.read", handler: gateEvalRelease, mutation: false },
  listEvalDatasets: { action: "api.evals.read", handler: listEvalDatasets, mutation: false },
  createEvalDataset: { action: "api.evals.write", handler: createEvalDataset, mutation: true },
  getEvalDatasetVersion: {
    action: "api.evals.read",
    handler: getEvalDatasetVersion,
    mutation: false,
  },
  listEvalSuites: { action: "api.evals.read", handler: listEvalSuites, mutation: false },
  createEvalSuite: { action: "api.evals.write", handler: createEvalSuite, mutation: true },
  getEvalSuite: { action: "api.evals.read", handler: getEvalSuite, mutation: false },
  listEvalBaselines: { action: "api.evals.read", handler: listEvalBaselines, mutation: false },
  setEvalBaseline: { action: "api.evals.admin", handler: setEvalBaseline, mutation: true },
  listEvalReviewTasks: {
    action: "api.evals.review",
    handler: listEvalReviewTasks,
    mutation: false,
  },
  claimEvalReviewTask: { action: "api.evals.review", handler: claimEvalReviewTask, mutation: true },
  gradeEvalReviewTask: { action: "api.evals.review", handler: gradeEvalReviewTask, mutation: true },
  skipEvalReviewTask: { action: "api.evals.review", handler: skipEvalReviewTask, mutation: true },
  listEvalSamplingConfigs: {
    action: "api.evals.read",
    handler: listEvalSamplingConfigs,
    mutation: false,
  },
  putEvalSamplingConfig: {
    action: "api.evals.admin",
    handler: putEvalSamplingConfig,
    mutation: true,
  },
  getEvalOnlineSummary: {
    action: "api.evals.read",
    handler: getEvalOnlineSummary,
    mutation: false,
  },
  listEvalRunners: { action: "api.evals.read", handler: listEvalRunners, mutation: false },
  registerEvalRunner: { action: "api.evals.admin", handler: registerEvalRunner, mutation: true },
  revokeEvalRunner: { action: "api.evals.admin", handler: revokeEvalRunner, mutation: true },
  explainRun: { action: "api.explanations.read", handler: explainRun, mutation: false },
  explainAuditEvent: { action: "api.audit.read", handler: explainAuditEvent, mutation: false },
  getMe: { action: null, handler: getMe, mutation: false },
  getApproval: { action: "api.approvals.read", handler: getApproval, mutation: false },
  activatePolicyPack: {
    action: "api.policies.activate",
    handler: activatePolicyPack,
    mutation: true,
  },
  listRegistryNamespaces: {
    action: "api.registry.read",
    handler: listRegistryNamespaces,
    mutation: false,
  },
  claimRegistryNamespace: {
    action: "api.registry.write",
    handler: claimRegistryNamespace,
    mutation: true,
  },
  listRegistryKeys: { action: "api.registry.read", handler: listRegistryKeys, mutation: false },
  addRegistryKey: { action: "api.registry.write", handler: addRegistryKey, mutation: true },
  publishRegistryBlueprint: {
    action: "api.registry.write",
    handler: publishRegistryBlueprint,
    mutation: true,
  },
  listRegistryVersions: {
    action: "api.registry.read",
    handler: listRegistryVersions,
    mutation: false,
  },
  listRegistryEvalAttestations: {
    action: "api.registry.read",
    handler: listRegistryEvalAttestations,
    mutation: false,
  },
  yankRegistryVersion: {
    action: "api.registry.write",
    handler: yankRegistryVersion,
    mutation: true,
  },
  resolveRegistryBlueprint: {
    action: "api.registry.read",
    handler: resolveRegistryBlueprint,
    mutation: false,
  },
  listMarketplaceListings: {
    action: "api.marketplace.read",
    handler: listMarketplaceListings,
    mutation: false,
  },
  getMarketplaceListing: {
    action: "api.marketplace.read",
    handler: getMarketplaceListing,
    mutation: false,
  },
  previewMarketplaceInstall: {
    action: "api.marketplace.install",
    handler: previewMarketplaceInstall,
    mutation: false,
  },
  listMarketplaceInstalls: {
    action: "api.marketplace.read",
    handler: listMarketplaceInstalls,
    mutation: false,
  },
  installMarketplaceListing: {
    action: "api.marketplace.install",
    handler: installMarketplaceListing,
    mutation: true,
  },
  uninstallMarketplaceListing: {
    action: "api.marketplace.install",
    handler: uninstallMarketplaceListing,
    mutation: true,
  },
  listComplianceSystems: {
    action: "api.compliance.read",
    handler: listComplianceSystems,
    mutation: false,
  },
  createComplianceSystem: {
    action: "api.compliance.write",
    handler: createComplianceSystem,
    mutation: true,
  },
  getComplianceSystem: {
    action: "api.compliance.read",
    handler: getComplianceSystem,
    mutation: false,
  },
  updateComplianceSystem: {
    action: "api.compliance.write",
    handler: updateComplianceSystem,
    mutation: true,
  },
  listComplianceImpactAssessments: {
    action: "api.compliance.read",
    handler: listComplianceImpactAssessments,
    mutation: false,
  },
  createComplianceImpactAssessment: {
    action: "api.compliance.write",
    handler: createComplianceImpactAssessment,
    mutation: true,
  },
  getComplianceImpactAssessment: {
    action: "api.compliance.read",
    handler: getComplianceImpactAssessment,
    mutation: false,
  },
  reviseComplianceImpactAssessment: {
    action: "api.compliance.write",
    handler: reviseComplianceImpactAssessment,
    mutation: true,
  },
  submitComplianceImpactAssessment: {
    action: "api.compliance.write",
    handler: submitComplianceImpactAssessment,
    mutation: true,
  },
  withdrawComplianceImpactAssessment: {
    action: "api.compliance.write",
    handler: withdrawComplianceImpactAssessment,
    mutation: true,
  },
  reviewComplianceImpactAssessment: {
    action: "api.compliance.review",
    handler: reviewComplianceImpactAssessment,
    mutation: true,
  },
  listComplianceDocuments: {
    action: "api.compliance.read",
    handler: listComplianceDocuments,
    mutation: false,
  },
  generateComplianceDocument: {
    action: "api.compliance.write",
    handler: generateComplianceDocument,
    mutation: true,
  },
  getComplianceDocument: {
    action: "api.compliance.read",
    handler: getComplianceDocument,
    mutation: false,
  },
};

export { PortConflict };
