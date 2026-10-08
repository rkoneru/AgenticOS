import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compilePolicySet, opaBuildWasm } from "@axis/policy";
import { parse } from "yaml";
import type { Classification, Environment } from "./types.js";
import { isRole, withinCeiling, type Role } from "./roles.js";
import { WasmPolicyEngine, type PolicyEngine } from "./wasm.js";

/** An authenticated caller. Built only by `SessionService` / `ApiKeyService`; the tenant is NEVER taken from a request. */
export interface Principal {
  readonly tenantId: string;
  readonly memberId: string;
  readonly role: Role;
  readonly credential: "session" | "api_key";
  readonly sessionId?: string;
  readonly apiKeyId?: string;
  readonly scopes?: readonly string[];
}

export const ACTIONS = [
  "tenant.read",
  "tenant.close",
  "members.read",
  "members.invite",
  "members.update_role",
  "members.remove",
  "apikeys.read",
  "apikeys.create",
  "apikeys.rotate",
  "apikeys.revoke",
  "modelkeys.read",
  "modelkeys.write",
  "modelkeys.delete",
  "policies.read",
  "policies.publish",
  "policies.activate",
  "budgets.read",
  "budgets.write",
  "settings.read",
  "settings.write",
  "audit.read",
  "billing.read",
  "billing.write",
  "directories.read",
  "directories.manage",
  "sso.manage",
  "domains.manage",
  "sessions.revoke",
] as const;
export type ControlAction = (typeof ACTIONS)[number];

/**
 * The `api` namespace (ADR 0024): one action per public `/v1` operation family, decided by the SAME pack by the API gateway
 * (`apps/api-gateway`). `api.<resource>.<verb>`; an API key needs the scope `<resource>:read|write` (see `requiredScope`).
 */
export const API_ACTIONS = [
  "api.blueprints.read",
  "api.blueprints.publish",
  "api.runs.read",
  "api.runs.start",
  "api.runs.signal",
  "api.events.read",
  "api.approvals.read",
  "api.approvals.decide",
  "api.policies.read",
  "api.policies.publish",
  "api.policies.test",
  "api.policies.activate",
  "api.registry.read",
  "api.registry.write",
  "api.marketplace.read",
  "api.marketplace.install",
  "api.audit.read",
  "api.audit.verify",
  "api.killswitch.read",
  "api.killswitch.write",
  "api.usage.read",
  "api.evals.run",
  "api.evals.read",
  "api.evals.write",
  "api.evals.admin",
  "api.evals.review",
  "api.explanations.read",
  "api.compliance.read",
  "api.compliance.write",
  "api.compliance.review",
] as const;
export type ApiAction = (typeof API_ACTIONS)[number];
export type Action = ControlAction | ApiAction;

/** Actions that never change state. Everything else is a mutation and is always audited (allow and deny). */
const READS = new Set<string>([
  ...ACTIONS.filter((a) => a.endsWith(".read")),
  ...API_ACTIONS.filter((a) => a.endsWith(".read")),
  "api.policies.test", // evaluates a hypothetical request; changes nothing
  "api.audit.verify", // recomputes hashes; changes nothing
]);
export const isRead = (a: string): boolean => READS.has(a);

export interface AuthzRequest {
  principal: Principal;
  action: Action;
  resource?: {
    /** Tenant that owns the resource as the STORE reports it (not as the caller claims). Defaults to the principal's tenant. */
    tenantId?: string;
    ownerMemberId?: string;
    environment?: Environment;
    classification?: Classification;
  };
  /** Role being granted (members.invite / update_role). */
  targetRole?: Role;
  /** Role the affected member holds now. */
  currentTargetRole?: Role;
}

export interface AuthzDecision {
  allowed: boolean;
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
  reason: string;
  policyVersion: string;
  winners: string[];
}

const DENY = (reason: string, policyVersion: string): AuthzDecision => ({
  allowed: false,
  decision: "DENY",
  reason,
  policyVersion,
  winners: [],
});

export const DEFAULT_PACK = fileURLToPath(
  new URL("../../../policies/control-plane/pack.yaml", import.meta.url),
);

/** The scope an API key needs for an action: `<resource>:read|write`. A scope of `*` or `<resource>:*` also satisfies it. */
export function requiredScope(action: string): string {
  const parts = action.split(".");
  // `api.<resource>.<verb>` is scoped by its resource (`runs:write`), the others by their first segment.
  const resource =
    parts[0] === "api" && parts.length === 3 ? (parts[1] as string) : (parts[0] as string);
  return `${resource}:${isRead(action) ? "read" : "write"}`;
}
export function scopeAllows(scopes: readonly string[] | undefined, action: string): boolean {
  if (!scopes) return false;
  const need = requiredScope(action);
  const res = need.split(":")[0] as string;
  return scopes.some((s) => s === "*" || s === need || s === `${res}:*`);
}

export interface AuthorizerOptions {
  engine: PolicyEngine;
  policyVersion: string;
  /** Evaluation budget; an over-budget evaluation is DENY (the engine is synchronous and cannot be pre-empted). Default 250 ms. */
  timeoutMs?: number;
  clock?: () => number;
}

/**
 * RBAC + ABAC decision point. Backed by OPA (policy DSL -> Rego -> Wasm, the Risk Kernel's toolchain). FAIL-CLOSED: a missing
 * engine, an evaluation error, a timeout, a malformed result or anything other than an exact ALLOW is DENY. `decide` never throws.
 * Hard invariants that must not depend on policy text (tenant match, role ceiling, API-key scopes) are ALSO computed here and are
 * passed to the policy as attributes; a request whose computed attribute is false is denied before the engine is asked.
 */
export class Authorizer {
  private readonly timeoutMs: number;
  private readonly clock: () => number;
  constructor(private readonly o: AuthorizerOptions | undefined) {
    this.timeoutMs = o?.timeoutMs ?? 250;
    this.clock = o?.clock ?? (() => performance.now());
  }

  static async fromPackFile(
    path: string = DEFAULT_PACK,
    opts: { timeoutMs?: number } = {},
  ): Promise<Authorizer> {
    const doc = parse(readFileSync(path, "utf8")) as unknown;
    const c = compilePolicySet([doc]);
    if (!c.ok)
      throw new Error(
        `control-plane policy does not compile: ${c.issues.map((i) => i.code).join(",")}`,
      );
    const engine = await WasmPolicyEngine.fromBundle(opaBuildWasm(c.rego));
    return new Authorizer({ engine, policyVersion: c.policyVersion, ...opts });
  }

  /** An Authorizer with no policy loaded: denies everything (the "missing policy" case). */
  static missing(): Authorizer {
    return new Authorizer(undefined);
  }

  async decide(req: AuthzRequest): Promise<AuthzDecision> {
    const version = this.o?.policyVersion ?? "none";
    try {
      if (!this.o) return DENY("no policy loaded", version);
      const p = req.principal;
      if (!isRole(p.role)) return DENY("unknown role", version);
      const sameTenant = (req.resource?.tenantId ?? p.tenantId) === p.tenantId;
      const ceiling =
        (req.targetRole === undefined || withinCeiling(p.role, req.targetRole)) &&
        (req.currentTargetRole === undefined || withinCeiling(p.role, req.currentTargetRole));
      if (!sameTenant) return DENY("resource belongs to another tenant", version);
      if (!ceiling) return DENY("role above the caller's own", version);
      if (p.credential === "api_key" && !scopeAllows(p.scopes, req.action))
        return DENY("api key scope does not allow this action", version);
      const input = {
        enforcement_point: "tool_call",
        tool: { name: req.action, side_effects: isRead(req.action) ? "read" : "write" },
        actor: { id: p.memberId, role: p.role, credential: p.credential },
        tenant: { id: p.tenantId },
        args: {
          same_tenant: sameTenant,
          within_ceiling: ceiling,
          owner_is_actor:
            req.resource?.ownerMemberId === undefined || req.resource.ownerMemberId === p.memberId,
          environment: req.resource?.environment ?? "dev",
        },
        data: { classification: req.resource?.classification ?? "internal" },
      };
      const t0 = this.clock();
      const raw = await this.o.engine.evaluate(input);
      if (this.clock() - t0 > this.timeoutMs)
        return DENY("policy evaluation exceeded its time budget", version);
      return this.interpret(raw, version);
    } catch {
      return DENY("policy evaluation error", version);
    }
  }

  private interpret(raw: unknown, version: string): AuthzDecision {
    if (typeof raw !== "object" || raw === null) return DENY("malformed policy result", version);
    const r = raw as { decision?: unknown; reason?: unknown; winners?: unknown };
    if (r.decision !== "ALLOW")
      return DENY(
        typeof r.reason === "string" ? r.reason.slice(0, 200) : "denied by policy",
        version,
      );
    const winners = Array.isArray(r.winners)
      ? r.winners.filter((w): w is string => typeof w === "string")
      : [];
    return {
      allowed: true,
      decision: "ALLOW",
      reason: "allowed by policy",
      policyVersion: version,
      winners,
    };
  }
}
