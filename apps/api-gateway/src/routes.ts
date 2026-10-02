import { randomUUID } from "node:crypto";
import { compileAbl, type AblIssue } from "@axis/abl";
import type { AuditEvent } from "@axis/contracts";
import type { Ctx, HandlerResult, Route } from "./context.js";
import { PortConflict, PortNotFound, type BlueprintVersionDto, type RunEventDto } from "./ports.js";
import { internal, notFound, notImplemented, validation, type ValidationIssue } from "./problem.js";

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

async function startEvalRun(): Promise<HandlerResult> {
  throw notImplemented(
    "Eval Hub runs arrive in Phase 8; this operation is part of the v1 contract but has no implementation yet.",
  );
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
  startEvalRun: { action: "api.evals.run", handler: startEvalRun, mutation: false },
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
};

export { PortConflict };
