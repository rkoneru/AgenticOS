import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AdminAudit,
  type AdminService,
  CpError,
  MAX_PACK_RULES,
  MAX_PACK_VALUES,
  packWeight,
  type ApiKeyService,
  type Authorizer,
  type ControlPlaneStore,
  type PolicyPackService,
  type SessionService,
} from "@axis/control-plane";
import { compilePolicySet } from "@axis/policy";
import type { PolicyMetadataSource, RuleMetadata } from "@axis/agil";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type ApiAudit,
  type Authenticator,
  type Authz,
  type GateDecisionDto,
  type IdentityDto,
  type IdentityPort,
  type Page,
  type PolicyPackDto,
  type PolicyPort,
  type Principal,
} from "../ports.js";

/** Translates the control plane's refusals into the gateway's port errors (the control plane's messages are caller-safe by contract). */
export function fromCpError(e: unknown): never {
  if (!(e instanceof CpError)) throw e;
  switch (e.code) {
    case "not_found":
      throw new PortNotFound(e.message);
    case "conflict":
      throw new PortConflict(e.message);
    case "forbidden":
      throw new PortForbidden(e.message);
    case "invalid":
      throw new PortInvalid(e.message, [{ path: "/", message: e.message }]);
    default:
      throw new PortUnavailable(e.message);
  }
}

/** Bearer `axk_...` -> API key; any other bearer -> session access token; `X-Axis-Api-Key` -> API key. */
export class ControlPlaneAuthenticator implements Authenticator {
  constructor(
    private readonly o: {
      apiKeys: Pick<ApiKeyService, "verify">;
      sessions: Pick<SessionService, "authenticate">;
    },
  ) {}

  async authenticate(c: { bearer?: string; apiKey?: string }): Promise<Principal | undefined> {
    if (c.apiKey !== undefined) return this.o.apiKeys.verify(c.apiKey);
    if (c.bearer === undefined) return undefined;
    return c.bearer.startsWith("axk_")
      ? this.o.apiKeys.verify(c.bearer)
      : this.o.sessions.authenticate(c.bearer);
  }
}

/** `GET /v1/me`: the credential's own tenant and member, read from the control-plane store by the principal's ids (never from the request). */
export class ControlPlaneIdentity implements IdentityPort {
  constructor(private readonly store: Pick<ControlPlaneStore, "getTenant" | "getMember">) {}

  async me(p: Principal): Promise<IdentityDto> {
    const [t, m] = await Promise.all([
      this.store.getTenant(p.tenantId),
      this.store.getMember(p.tenantId, p.memberId),
    ]);
    return {
      tenant: {
        id: p.tenantId,
        ...(t ? { name: t.name, region: t.region } : {}),
      },
      member: {
        id: p.memberId,
        role: p.role,
        ...(m?.email ? { email: m.email } : {}),
        ...(m?.displayName ? { display_name: m.displayName } : {}),
      },
      credential: {
        kind: p.credential,
        ...(p.scopes ? { scopes: [...p.scopes] } : {}),
      },
    };
  }
}

export class ControlPlaneAuthz implements Authz {
  constructor(private readonly authorizer: Pick<Authorizer, "decide">) {}
  async decide(
    p: Principal,
    action: string,
  ): Promise<{ allowed: boolean; reason: string; policyVersion: string }> {
    const d = await this.authorizer.decide({ principal: p, action: action as never });
    return { allowed: d.allowed, reason: d.reason, policyVersion: d.policyVersion };
  }
}

/** The tenant's chain gets the API mutation (enforcement point `admin`), exactly like the admin API's own events. */
export class ControlPlaneApiAudit implements ApiAudit {
  constructor(private readonly audit: Pick<AdminAudit, "record">) {}
  record(e: Parameters<ApiAudit["record"]>[0]): Promise<unknown> {
    return this.audit.record({
      tenantId: e.tenantId,
      actor: e.actor,
      action: e.action,
      decision: e.decision,
      policyVersion: e.policyVersion,
      reason: e.reason,
      inputs: e.inputs,
      outputs: e.outputs,
      traceId: e.traceId,
    });
  }
}

// ---- policies ------------------------------------------------------------------------------------------------------------------

export interface PolicyTester {
  evaluate(doc: unknown, input: Record<string, unknown>): Promise<GateDecisionDto>;
}

/**
 * Evaluates a hypothetical request with the REAL OPA binary on the policy the compiler produced from the caller's document. The
 * `opa` process is spawned asynchronously (the control plane's own validator is synchronous and blocks the event loop), bounded by a
 * timeout, a global concurrency limit and the same size limits as a publish. Gates (kill-switch, caps, budgets) are NOT evaluated:
 * they need live state; the response says which gates the winning rule would add.
 */
export class OpaCliPolicyTester implements PolicyTester {
  private running = 0;
  private waiting = 0;
  constructor(
    private readonly o: {
      bin?: string;
      timeoutMs?: number;
      maxConcurrent?: number;
      maxQueued?: number;
    } = {},
  ) {}

  async evaluate(doc: unknown, input: Record<string, unknown>): Promise<GateDecisionDto> {
    const w = packWeight(doc);
    if (w.rules > MAX_PACK_RULES || w.values > MAX_PACK_VALUES)
      throw new PortInvalid(
        `policy too large: at most ${MAX_PACK_RULES} rules and ${MAX_PACK_VALUES} values`,
        [{ path: "/policy", message: "too large" }],
      );
    const c = compilePolicySet([doc]);
    if (!c.ok)
      throw new PortInvalid(
        "the policy does not compile",
        c.issues.slice(0, 20).map((i) => ({
          path: `/policy${i.path === "/" ? "" : i.path}`,
          keyword: i.code,
          message: i.message,
        })),
      );
    const max = this.o.maxConcurrent ?? 2;
    if (this.running >= max) {
      if (this.waiting >= (this.o.maxQueued ?? 8))
        throw new PortUnavailable("policy evaluation is busy; retry");
      this.waiting++;
      while (this.running >= max) await new Promise((r) => setTimeout(r, 10));
      this.waiting--;
    }
    this.running++;
    try {
      const out = await this.opa(c.rego, input);
      return {
        decision: out.decision as GateDecisionDto["decision"],
        policy_version: String(out.policy_version ?? c.policyVersion),
        reason: String(out.reason ?? ""),
        matched_rule_ids: (out.matched as string[] | undefined) ?? [],
        redact_fields: (out.redact as string[] | undefined) ?? [],
      };
    } finally {
      this.running--;
    }
  }

  private async opa(
    rego: string,
    input: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const dir = await mkdtemp(join(tmpdir(), "axis-gw-opa-"));
    try {
      await writeFile(join(dir, "policy.rego"), rego);
      const stdout = await new Promise<string>((resolve, reject) => {
        const child = execFile(
          this.o.bin ?? process.env["OPA_BIN"] ?? "opa",
          [
            "eval",
            "--v1-compatible",
            "-d",
            join(dir, "policy.rego"),
            "--stdin-input",
            "--format",
            "json",
            "data.axis.policy.result",
          ],
          {
            timeout: this.o.timeoutMs ?? 10_000,
            maxBuffer: 1 << 20,
            // The child evaluates a tenant-supplied policy: it gets a PATH and nothing else (not the gateway's secrets, token files, URLs).
            env: { PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin" },
          },
          (err, out) => (err ? reject(err) : resolve(out)),
        );
        // The child may exit before reading stdin (bad binary, timeout kill): that is the callback's failure, not an unhandled EPIPE.
        child.stdin?.on("error", () => undefined);
        child.stdin?.end(JSON.stringify(input));
      });
      const parsed = JSON.parse(stdout) as {
        result?: { expressions: { value: Record<string, unknown> }[] }[];
      };
      const v = parsed.result?.[0]?.expressions[0]?.value;
      if (!v) throw new Error("no result");
      return v;
    } catch {
      // Fail closed: an evaluation that cannot complete is never reported as an allow.
      throw new PortUnavailable("the policy could not be evaluated; retry");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}

export class ControlPlanePolicies implements PolicyPort {
  constructor(
    private readonly o: {
      packs: Pick<PolicyPackService, "list" | "publish">;
      tester: PolicyTester;
      /** Activation goes through the admin API's own guarded path (authorization, audit, kernel bundle publication). */
      admin?: Pick<AdminService, "activatePolicy">;
    },
  ) {}

  async list(p: Principal, q: { limit: number; after?: string }): Promise<Page<PolicyPackDto>> {
    const all = (await this.o.packs.list(p))
      .map((v) => ({ key: `${v.createdAt.toISOString()}|${v.versionId}`, v }))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .filter((x) => q.after === undefined || x.key > q.after);
    const slice = all.slice(0, q.limit);
    const items = slice.map(({ v }) => ({
      name: v.pack,
      version: v.version,
      content_hash: v.contentHash,
      created_at: v.createdAt.toISOString(),
      version_id: v.versionId,
      active: v.active,
    }));
    return {
      items,
      next: all.length > q.limit ? (slice[slice.length - 1] as { key: string }).key : undefined,
    };
  }

  async publish(p: Principal, doc: unknown): Promise<PolicyPackDto> {
    try {
      const v = await this.o.packs.publish(p, doc);
      return {
        name: v.pack,
        version: v.version,
        content_hash: v.contentHash,
        created_at: v.createdAt.toISOString(),
        version_id: v.versionId,
        active: v.active,
      };
    } catch (e) {
      return fromCpError(e);
    }
  }

  async activate(p: Principal, versionId: string): Promise<PolicyPackDto> {
    if (!this.o.admin) throw new PortUnavailable("policy activation is not configured");
    try {
      await this.o.admin.activatePolicy(p, versionId);
      // The tenant's own listing is the source of truth for what is active now (never a caller-supplied echo).
      const v = (await this.o.packs.list(p)).find((x) => x.versionId === versionId);
      if (!v) throw new PortNotFound("policy version not found");
      return {
        name: v.pack,
        version: v.version,
        content_hash: v.contentHash,
        created_at: v.createdAt.toISOString(),
        version_id: v.versionId,
        active: v.active,
      };
    } catch (e) {
      return fromCpError(e);
    }
  }

  async test(
    _p: Principal,
    q: {
      policy: unknown;
      request: { enforcement_point: string; action?: string; context: Record<string, unknown> };
    },
  ): Promise<GateDecisionDto> {
    // The kernel owns these fields of the context (docs/spec/risk-kernel.md): a tested request cannot override them.
    const input = {
      ...q.request.context,
      enforcement_point: q.request.enforcement_point,
      ...(q.request.action ? { action: q.request.action } : {}),
    };
    return this.o.tester.evaluate(q.policy, input);
  }
}

/** Read-only rule metadata (the tenant's own packs) to phrase AGIL hints. Never decides anything. */
export class StorePolicyMetadata implements PolicyMetadataSource {
  constructor(private readonly store: Pick<ControlPlaneStore, "listPackVersions">) {}

  async describeRules(tenantId: string, ruleIds: readonly string[]): Promise<RuleMetadata[]> {
    const want = new Set(ruleIds);
    const out = new Map<string, RuleMetadata>();
    for (const v of await this.store.listPackVersions(tenantId)) {
      const spec = (v.source as { spec?: { rules?: unknown[] } } | undefined)?.spec;
      for (const r of spec?.rules ?? []) {
        const rule = r as {
          id?: string;
          description?: string;
          decision?: string;
          approval?: { roles?: string[]; slaSeconds?: number };
        };
        const id = `${v.packName}/${rule.id}`;
        if (!want.has(id)) continue;
        out.set(id, {
          id,
          ...(rule.decision ? { decision: rule.decision } : {}),
          ...(rule.description ? { description: rule.description } : {}),
          ...(rule.approval?.roles
            ? {
                approval: {
                  roles: rule.approval.roles,
                  ...(rule.approval.slaSeconds !== undefined
                    ? { slaSeconds: rule.approval.slaSeconds }
                    : {}),
                },
              }
            : {}),
        });
      }
    }
    return [...out.values()];
  }
}
